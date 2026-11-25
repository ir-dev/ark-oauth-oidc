using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// The <c>ark_oauth_server</c> section, bound once per configuration reload.
    ///
    /// Every endpoint used to bind it afresh on each read — <c>ServerConfig</c>, <c>Options</c>
    /// and <c>Endpoints()</c> each did, so one authorization request bound the whole section a
    /// dozen times over. The binder walks every configuration provider by reflection, which under
    /// load was a measurable share of the server's CPU for a value that changes only when
    /// configuration does.
    ///
    /// The snapshot is replaced when the configuration's reload token fires — a changed
    /// appsettings file, or the setup wizard's <c>Reload()</c> — so a server configured after it
    /// started still picks the new values up without a restart. Treat the returned object as
    /// read-only: it is shared by every request until the next reload.
    /// </summary>
    public static class ArkConfigSnapshot
    {
        private sealed class Holder
        {
            public Snapshot? Current;
        }

        private sealed record Snapshot(IChangeToken Token, ArkAuthServerConfig? Value);

        private static readonly ConditionalWeakTable<IConfiguration, Holder> Holders = new();

        /// <summary>The bound section, or null when it is absent.</summary>
        public static ArkAuthServerConfig? Server(IConfiguration config)
        {
            var holder = Holders.GetValue(config, _ => new Holder());
            var current = Volatile.Read(ref holder.Current);
            if (current != null && !current.Token.HasChanged) return current.Value;

            // The token is taken before binding: a reload that lands in between leaves a snapshot
            // whose token has already fired, so the next read binds again rather than keeping it.
            var token = config.GetReloadToken();
            var value = config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>();
            Volatile.Write(ref holder.Current, new Snapshot(token, value));
            return value;
        }

        /// <summary>The <c>Oidc</c> options, defaults when the section is absent.</summary>
        public static ArkOidcOptions Oidc(IConfiguration config) => Server(config)?.Oidc ?? DefaultOidc;

        private static readonly ArkOidcOptions DefaultOidc = new();
    }

    /// <summary>
    /// Short-lived, in-process copies of the rows every request reads and almost nothing writes:
    /// tenants, clients, the scope catalogue and the signing keys.
    ///
    /// A token request used to fetch all four from the database — five or six round trips before
    /// it touched anything that belongs to the user — and with thirty thousand people signed in
    /// that is most of the database traffic the server generates. They are a few dozen rows in
    /// total and change when an operator edits something.
    ///
    /// Two rules keep this from changing what an operator's switch means:
    ///
    ///   * <b>A write on this instance is seen at once.</b> <see cref="ArkDataContext"/> calls
    ///     <see cref="Reset"/> after any save that touched one of these tables, so deactivating a
    ///     client or rotating a key takes effect on the next request here.
    ///   * <b>A write on another instance is seen within the time-to-live</b>
    ///     (<see cref="ArkOidcOptions.ReferenceCacheSeconds"/>, 30 seconds by default, 0 to turn
    ///     the cache off). That is the only window this adds, and it is far shorter than the hour
    ///     an already-issued access token stays valid whatever the server does.
    ///
    /// Only rows that exist are kept: an unknown client is looked up every time, so one registered
    /// a moment ago on another instance is found straight away. Nothing about a user — the
    /// account, its access mappings, its sessions — is ever cached; those are indexed lookups.
    ///
    /// The entities handed out are shared between requests and are not tracked by any context.
    /// Read them; to change one, load it through the context.
    /// </summary>
    public static class ArkIdpCache
    {
        private sealed record Entry(object Value, long ExpiresAt);

        private static readonly ConcurrentDictionary<string, Entry> Items = new(StringComparer.Ordinal);
        private static long _generation;

        /// <summary>Drops everything held. Called after any write to a cached table.</summary>
        public static void Reset()
        {
            Interlocked.Increment(ref _generation);
            Items.Clear();
            SigningKeys.Clear();
            ValidationKeys.Clear();
            UnknownKids.Clear();
        }

        private static int TtlSeconds(ArkDataContext ctx) =>
            Math.Max(0, ArkConfigSnapshot.Oidc(ctx.Configuration).ReferenceCacheSeconds);

        /// <summary>
        /// One database is one cache: the setup wizard and the data tools open contexts on other
        /// databases from inside the same process, and a row from one must never answer for another.
        /// </summary>
        private static string Key(ArkDataContext ctx, string kind, string id) =>
            $"{kind}\n{id}\n{ctx.CacheScope}";

        internal static async Task<T?> GetOrLoadAsync<T>(ArkDataContext ctx, string kind, string id, Func<Task<T?>> load)
            where T : class
        {
            var ttl = TtlSeconds(ctx);
            if (ttl == 0) return await load();

            var key = Key(ctx, kind, id);
            var now = Environment.TickCount64;
            if (Items.TryGetValue(key, out var entry) && entry.ExpiresAt > now) return (T)entry.Value;

            var generation = Interlocked.Read(ref _generation);
            var value = await load();
            // A load that straddles a Reset read the rows the reset was announcing the end of.
            if (value != null && generation == Interlocked.Read(ref _generation))
                Items[key] = new Entry(value, now + ttl * 1000L);
            return value;
        }

        // ------------------------------------------------------------ reference rows

        /// <summary>A tenant by id, case-insensitively. Null when there is none.</summary>
        public static Task<ArkTenant?> TenantAsync(ArkDataContext ctx, string? tenantId)
        {
            var id = (tenantId ?? "").Trim();
            if (id.Length == 0) return Task.FromResult<ArkTenant?>(null);
            return GetOrLoadAsync(ctx, "tenant", id.ToLowerInvariant(), () => ArkLookup.TenantAsync(ctx, id));
        }

        /// <summary>A client by (tenant, client_id), case-insensitively. Null when there is none.</summary>
        public static Task<ArkClient?> ClientAsync(ArkDataContext ctx, string? tenantId, string? clientId)
        {
            var tenant = (tenantId ?? "").Trim();
            var client = (clientId ?? "").Trim();
            if (tenant.Length == 0 || client.Length == 0) return Task.FromResult<ArkClient?>(null);
            return GetOrLoadAsync(ctx, "client", $"{tenant.ToLowerInvariant()}\n{client.ToLowerInvariant()}",
                () => ArkLookup.ClientAsync(ctx, tenant, client));
        }

        /// <summary>
        /// The client as the database has it now, when that differs from <paramref name="held"/>;
        /// otherwise <paramref name="held"/> itself.
        ///
        /// Call this before refusing a request because of something a client record says — a wrong
        /// secret, an unregistered redirect URI, a scope or grant it may not use, a deactivated
        /// client. The copy held here can be up to <see cref="ArkOidcOptions.ReferenceCacheSeconds"/>
        /// old when the change was made through another instance or another process, and an
        /// operator who has just issued a secret or added a redirect URI expects it to work on the
        /// next request, wherever that lands. Checking before every refusal is what makes the cache
        /// invisible in that direction: nothing is ever refused on stale data. (A change that takes
        /// something <i>away</i> still reaches other instances within the time-to-live.)
        ///
        /// It costs one indexed read, and only on a request that is about to be refused — which is
        /// what every request cost before there was a cache. It is deliberately not rate-limited: a
        /// limit would be a window in which a change just made is still refused.
        /// </summary>
        public static async Task<ArkClient> ClientIfChangedAsync(ArkDataContext ctx, ArkClient held)
        {
            if (TtlSeconds(ctx) == 0) return held;
            var id = $"{(held.tenant_id ?? "").ToLowerInvariant()}\n{(held.client_id ?? "").ToLowerInvariant()}";
            var key = Key(ctx, "client", id);
            var now = Environment.TickCount64;
            var generation = Interlocked.Read(ref _generation);
            var fresh = await ArkLookup.ClientAsync(ctx, held.tenant_id ?? "", held.client_id ?? "");
            if (fresh == null) return held; // deleted meanwhile: the refusal stands
            if (generation == Interlocked.Read(ref _generation))
                Items[key] = new Entry(fresh, now + TtlSeconds(ctx) * 1000L);
            return SameRegistration(held, fresh) ? held : fresh;
        }

        private static bool SameRegistration(ArkClient a, ArkClient b) =>
            a.at == b.at && a.is_active == b.is_active
            && a.client_secret_hash == b.client_secret_hash && a.client_secret_expires_at == b.client_secret_expires_at
            && a.token_endpoint_auth_method == b.token_endpoint_auth_method
            && a.redirect_uris_ == b.redirect_uris_ && a.redirect_url == b.redirect_url
            && a.post_logout_redirect_uris_ == b.post_logout_redirect_uris_ && a.logout_url == b.logout_url
            && a.scopes_ == b.scopes_ && a.grant_types_ == b.grant_types_
            && a.require_pkce == b.require_pkce && a.require_par == b.require_par && a.jwks_uri == b.jwks_uri
            && a.a2a_callers_ == b.a2a_callers_;

        /// <summary>The scope catalogue. Shared: do not add to or reorder the list.</summary>
        public static async Task<IReadOnlyList<ArkScope>> ScopesAsync(ArkDataContext ctx) =>
            await GetOrLoadAsync<List<ArkScope>>(ctx, "scopes", "*",
                async () => await ctx.scopes.AsNoTracking().ToListAsync())
            ?? new List<ArkScope>();

        // ------------------------------------------------------------ signing keys

        private sealed record KeyMaterial(string Source, SecurityKey Key, SigningCredentials? Credentials);

        private static readonly ConcurrentDictionary<string, KeyMaterial> SigningKeys = new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, KeyMaterial> ValidationKeys = new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, long> UnknownKids = new(StringComparer.Ordinal);

        /// <summary>
        /// The credentials a key signs with, built once per key.
        ///
        /// Each token used to import the PKCS#8 private key into a new <see cref="RSA"/> that
        /// nothing disposed — two imports per token response, and two native key handles left for
        /// the finalizer. One <see cref="RsaSecurityKey"/> per key is how the framework's own
        /// handlers sign, and it lets IdentityModel keep its signature provider between tokens.
        /// </summary>
        public static SigningCredentials SigningCredentialsFor(ArkSigningKey key)
        {
            if (SigningKeys.TryGetValue(key.kid, out var held) && string.Equals(held.Source, key.private_key, StringComparison.Ordinal))
                return held.Credentials!;

            var security = new RsaSecurityKey(ArkCrypto.ImportPrivateKey(key.private_key)) { KeyId = key.kid };
            var credentials = new SigningCredentials(security, SecurityAlgorithms.RsaSha256);
            SigningKeys[key.kid] = new KeyMaterial(key.private_key, security, credentials);
            return credentials;
        }

        /// <summary>The public half of a key, for validating tokens this server issued.</summary>
        public static SecurityKey ValidationKeyFor(ArkSigningKey key)
        {
            if (ValidationKeys.TryGetValue(key.kid, out var held) && string.Equals(held.Source, key.public_key, StringComparison.Ordinal))
                return held.Key;

            var security = new RsaSecurityKey(ArkCrypto.ImportPublicKey(key.public_key)) { KeyId = key.kid };
            ValidationKeys[key.kid] = new KeyMaterial(key.public_key, security, null);
            return security;
        }

        /// <summary>
        /// Whether a key id that is not among the cached published keys is worth a trip to the
        /// database. Once per kid every few seconds: a token signed by a key another instance has
        /// just rotated in has to validate here straight away, but a stream of made-up kids must
        /// not turn every request into a query.
        /// </summary>
        internal static bool ShouldRecheckUnknownKid(string tenantId, string kid)
        {
            // Off a token nothing has been verified about. No key of this server has a long one, and
            // what is remembered here is the kid itself: bounded in number, so bounded in size too.
            if (kid.Length > 128) return false;
            var now = Environment.TickCount64;
            var key = $"{tenantId}\n{kid}";
            if (UnknownKids.TryGetValue(key, out var until) && until > now) return false;
            if (UnknownKids.Count > 2048) UnknownKids.Clear();
            UnknownKids[key] = now + 5000;
            return true;
        }
    }

    /// <summary>
    /// Verifies client secrets, remembering the ones that were right.
    ///
    /// A client secret is stored as a 210,000-iteration PBKDF2 hash, and a confidential client
    /// presents it on <i>every</i> token, introspection and revocation request — so each of those
    /// spent some 40 ms of one core proving again what it proved a second earlier. That, not
    /// anything a user does, was the largest single cost of a token request, and it capped a whole
    /// instance at a few dozen token requests per second per core.
    ///
    /// A secret that verified is remembered for a few minutes as an HMAC, under a key generated
    /// when the process starts, of the stored hash and the presented value. Nothing reversible is
    /// kept, a wrong secret is never remembered — guessing costs exactly what it did — and
    /// replacing the secret changes the stored hash and so retires the entry.
    /// </summary>
    public static class ArkSecretVerifier
    {
        private static readonly byte[] ProcessKey = RandomNumberGenerator.GetBytes(32);
        private static readonly ConcurrentDictionary<string, long> Verified = new(StringComparer.Ordinal);
        private const int MaxEntries = 4096;

        /// <param name="secret">The value presented.</param>
        /// <param name="stored">The PBKDF2 hash on record (<see cref="ArkCrypto.HashSecret(string)"/>).</param>
        /// <param name="cacheSeconds">How long a success is remembered; 0 verifies every time.</param>
        /// <param name="cancellation">Stops waiting for a hashing slot when the caller has gone.</param>
        public static async Task<bool> VerifyAsync(string? secret, string? stored, int cacheSeconds, CancellationToken cancellation = default)
        {
            if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(stored)) return false;

            string? digest = null;
            var now = Environment.TickCount64;
            if (cacheSeconds > 0)
            {
                digest = Convert.ToBase64String(HMACSHA256.HashData(ProcessKey, Encoding.UTF8.GetBytes($"{stored}\n{secret}")));
                if (Verified.TryGetValue(digest, out var until) && until > now) return true;
            }

            var ok = await ArkHashGate.RunAsync(() => ArkCrypto.VerifySecret(secret, stored), cancellation);
            if (ok && digest != null)
            {
                if (Verified.Count >= MaxEntries) Verified.Clear();
                Verified[digest] = now + cacheSeconds * 1000L;
            }
            return ok;
        }
    }

    /// <summary>
    /// Bounds how many password-grade hashes run at once.
    ///
    /// PBKDF2 at 210,000 iterations holds a core for tens of milliseconds, and it is the one thing
    /// here that cannot be made cheaper without making passwords cheaper to guess. When a few
    /// hundred people sign in in the same second — the start of a shift, or somebody replaying a
    /// credential list — every thread the pool has ends up inside it, and the requests that cost
    /// almost nothing (a refresh, a userinfo call for someone already signed in) wait behind them.
    ///
    /// Sign-ins queue for a slot instead, without holding a thread while they wait, so a storm
    /// slows sign-in down and leaves everyone who is already signed in alone.
    ///
    /// Measured on a 10-core machine with 6,000 people signing in at once while 1,000 signed-in
    /// users carried on: with nine slots a refresh took 76 ms at the median and 216 ms at the
    /// 95th percentile; with five, 12 ms and 42 ms, for a sign-in rate of 163 a second in place of
    /// 182. Hence the default of half the cores.
    /// </summary>
    public static class ArkHashGate
    {
        private static SemaphoreSlim _gate = new(DefaultSlots, DefaultSlots);
        private static int _slots = DefaultSlots;

        /// <summary>Half the cores hash; the other half is left for everything else.</summary>
        public static int DefaultSlots => Math.Max(1, Environment.ProcessorCount / 2);

        private static int _maxWaitSeconds;

        /// <summary>
        /// Applies <see cref="ArkOidcOptions.MaxConcurrentPasswordHashes"/> (0 or less means
        /// <see cref="DefaultSlots"/>) and <see cref="ArkOidcOptions.MaxPasswordHashWaitSeconds"/>.
        /// </summary>
        public static void Configure(int slots, int maxWaitSeconds = 0)
        {
            Volatile.Write(ref _maxWaitSeconds, Math.Max(0, maxWaitSeconds));
            if (slots <= 0) slots = DefaultSlots;
            if (slots == Volatile.Read(ref _slots)) return;
            // Hashes already running finish against the gate they entered.
            Volatile.Write(ref _gate, new SemaphoreSlim(slots, slots));
            Volatile.Write(ref _slots, slots);
        }

        /// <exception cref="ArkBusyException">
        /// A wait limit is configured (<see cref="ArkOidcOptions.MaxPasswordHashWaitSeconds"/>) and
        /// no slot came free within it. With no limit, the default, a sign-in waits for as long as
        /// it takes — slower under a storm, never refused, which is how the server always behaved.
        /// </exception>
        public static async Task<T> RunAsync<T>(Func<T> hash, CancellationToken cancellation = default)
        {
            var gate = Volatile.Read(ref _gate);
            var limit = Volatile.Read(ref _maxWaitSeconds);
            if (limit <= 0) await gate.WaitAsync(cancellation);
            else if (!await gate.WaitAsync(TimeSpan.FromSeconds(limit), cancellation)) throw new ArkBusyException();
            try
            {
                return hash();
            }
            finally
            {
                gate.Release();
            }
        }
    }

    /// <summary>
    /// The server has more sign-ins queued than it can verify within the configured wait
    /// (<see cref="ArkOidcOptions.MaxPasswordHashWaitSeconds"/>; off by default, so this is only
    /// ever thrown where an operator asked for it). Not a credentials failure: nothing was checked, so it is not
    /// counted against the account and the person is told to try again, not that they mistyped.
    /// </summary>
    public class ArkBusyException : ApplicationException
    {
        public const string FriendlyMessage =
            "The server is busy signing other people in. Please try again in a moment.";

        public ArkBusyException() : base(FriendlyMessage)
        {
        }
    }

    /// <summary>
    /// The lookups every sign-in and token request makes, written so the database can answer them
    /// from an index.
    ///
    /// They were all written as <c>lower(column) = lower(value)</c>, which is correct and which no
    /// ordinary index can serve: each one read its whole table. With thirty thousand accounts a
    /// single sign-in read the user table three times and the access-mapping table four, and the
    /// database spent its time doing that for everyone at once.
    ///
    /// Each lookup here asks the exact question first — the value as stored, which is what a
    /// session's subject, a foreign key or a login id normalised on the way in already is, and
    /// which the unique index answers in one step. Only when that finds nothing does it ask the
    /// case-insensitive one, so a row written in another case by an older version or by hand is
    /// still found; <see cref="ArkSchemaUpdater"/> adds a <c>lower()</c> index for that second
    /// question where the provider has one.
    /// </summary>
    public static class ArkLookup
    {
        public static async Task<ArkTenant?> TenantAsync(ArkDataContext ctx, string tenantId)
        {
            var exact = await ctx.tenants.AsNoTracking().FirstOrDefaultAsync(t => t.tenant_id == tenantId);
            if (exact != null) return exact;
            var lowered = tenantId.ToLower();
            return await ctx.tenants.AsNoTracking().FirstOrDefaultAsync(t => t.tenant_id.ToLower() == lowered);
        }

        public static async Task<ArkClient?> ClientAsync(ArkDataContext ctx, string tenantId, string clientId)
        {
            var exact = await ctx.clients.AsNoTracking()
                .FirstOrDefaultAsync(c => c.tenant_id == tenantId && c.client_id == clientId);
            if (exact != null) return exact;
            var tenant = tenantId.ToLower();
            var client = clientId.ToLower();
            return await ctx.clients.AsNoTracking()
                .FirstOrDefaultAsync(c => c.tenant_id.ToLower() == tenant && c.client_id.ToLower() == client);
        }

        /// <summary>An account by login id or token subject. Never cached: deactivation has to bite at once.</summary>
        public static async Task<ArkUser?> UserAsync(ArkDataContext ctx, string? loginOrSubject)
        {
            var id = (loginOrSubject ?? "").Trim();
            if (id.Length == 0) return null;
            var lowered = id.ToLower();

            // Stored lower-case by every write path this server has, so this is the one that hits.
            var user = await ctx.users.AsNoTracking().FirstOrDefaultAsync(u => u.email == lowered);
            if (user != null) return user;
            if (!string.Equals(id, lowered, StringComparison.Ordinal))
            {
                user = await ctx.users.AsNoTracking().FirstOrDefaultAsync(u => u.email == id);
                if (user != null) return user;
            }
            return await ctx.users.AsNoTracking().FirstOrDefaultAsync(u => u.email.ToLower() == lowered);
        }

        /// <summary>
        /// The access mapping between an account and a client — the row that both admits the user
        /// to the client and carries their <c>ark_claims</c>. <paramref name="clientRowId"/> is
        /// <see cref="ArkClient.id"/>, not the client_id.
        /// </summary>
        public static async Task<ArkUserClientClaim?> MappingAsync(ArkDataContext ctx, string? subject, string? tenantId, string? clientRowId)
        {
            var email = (subject ?? "").Trim();
            var tenant = tenantId ?? "";
            var client = clientRowId ?? "";
            if (email.Length == 0 || client.Length == 0) return null;

            var mapping = await ctx.user_client_claims.AsNoTracking()
                .FirstOrDefaultAsync(m => m.email == email && m.tenant_id == tenant && m.client_id == client);
            if (mapping != null) return mapping;

            var loweredEmail = email.ToLower();
            if (!string.Equals(email, loweredEmail, StringComparison.Ordinal))
            {
                mapping = await ctx.user_client_claims.AsNoTracking()
                    .FirstOrDefaultAsync(m => m.email == loweredEmail && m.tenant_id == tenant && m.client_id == client);
                if (mapping != null) return mapping;
            }

            // lower(email) leads, so the index on it narrows this to one person's handful of rows
            // before the other two columns are compared.
            var loweredTenant = tenant.ToLower();
            var loweredClient = client.ToLower();
            return await ctx.user_client_claims.AsNoTracking().FirstOrDefaultAsync(m =>
                m.email.ToLower() == loweredEmail &&
                (m.tenant_id ?? "").ToLower() == loweredTenant &&
                m.client_id.ToLower() == loweredClient);
        }
    }
}
