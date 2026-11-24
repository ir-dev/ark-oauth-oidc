using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>An agent-to-agent token, and what the audit line says about it.</summary>
    public class AgentTokenResult
    {
        public string AccessToken { get; set; } = default!;
        public DateTime ExpiresAt { get; set; }
        public List<string> Scopes { get; set; } = new();
        /// <summary>The token's <c>sub</c>: the calling agent, or the user it acts for.</summary>
        public string Subject { get; set; } = default!;
        /// <summary>The token's <c>aud</c>: the client_id of the agent being called.</summary>
        public string Audience { get; set; } = default!;
        /// <summary>The <c>act</c> chain, newest first. Empty when the agent called as itself.</summary>
        public List<string> Actors { get; set; } = new();
    }

    /// <summary>
    /// Agent-to-agent (A2A) tokens: an access token addressed to one named agent and good nowhere
    /// else.
    ///
    /// An agent is an ordinary confidential client; nothing about a client record makes it one
    /// except that another client lists it as a caller. Two requests end here, both at the token
    /// endpoint:
    ///
    ///  * <b>as itself</b> — <c>client_credentials</c> with <c>audience</c> naming the agent to
    ///    call. <c>sub</c> is the caller, and <c>ark_claims</c> are what the target granted it.
    ///  * <b>on behalf of a user</b> — token exchange (RFC 8693): the caller presents a user's
    ///    access token it legitimately holds and names the next agent. <c>sub</c> stays the user,
    ///    <c>ark_claims</c> are the user's own at the target, and <c>act</c> records every agent
    ///    the user was handed through.
    ///
    /// Both are refused unless the target's <see cref="ArkClient.a2a_callers"/> names the caller,
    /// so with no list anywhere — every existing deployment — nothing here can issue a token.
    /// </summary>
    public class ArkAgentTokens
    {
        public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
        public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
        /// <summary>RFC 8693 §2.2.2 / RFC 8707 §2: the named audience cannot be issued for.</summary>
        public const string InvalidTarget = "invalid_target";

        private readonly ArkDataContext _ctx;
        private readonly ArkTokenService _tokens;
        private readonly ArkClaimsService _claims;
        private readonly ArkGrantStore _grants;

        public ArkAgentTokens(ArkDataContext ctx, ArkTokenService tokens, ArkClaimsService claims, ArkGrantStore grants)
        {
            _ctx = ctx;
            _tokens = tokens;
            _claims = claims;
            _grants = grants;
        }

        /// <summary>
        /// The agent a token request names, or null when it names none. <c>audience</c> is the
        /// RFC 8693 spelling and <c>resource</c> the RFC 8707 one; either is read, and the value
        /// is the target's client_id. One token is for one agent, so a second value is refused.
        /// </summary>
        public static string? RequestedAudience(IFormCollection form)
        {
            var values = form["audience"].Concat(form["resource"])
                .Select(v => (v ?? "").Trim()).Where(v => v.Length > 0)
                .Distinct(StringComparer.Ordinal).ToList();
            if (values.Count > 1)
                throw new OAuthException(InvalidTarget, "a token is addressed to exactly one agent: send a single audience.");
            return values.Count == 1 ? values[0] : null;
        }

        /// <summary>
        /// Whether a requested audience is the one every ordinary token of this tenant already
        /// carries. Asking for it by name is not an A2A request, and is answered as it always was.
        /// </summary>
        public static bool IsTenantAudience(string? audience, ArkTenant tenant, string issuer) =>
            !string.IsNullOrEmpty(audience)
            && (string.Equals(audience, tenant.audience, StringComparison.Ordinal)
                || string.Equals(audience, issuer, StringComparison.Ordinal));

        // -----------------------------------------------------------------
        // the agent as itself
        // -----------------------------------------------------------------

        public async Task<AgentTokenResult> AsItselfAsync(
            ArkTenant tenant, string issuer, ArkClient caller, string audience, List<string> scopes)
        {
            var options = ArkConfigSnapshot.Oidc(_ctx.Configuration);
            var (target, entry) = await ResolveTargetAsync(tenant, issuer, caller, audience, forUser: false);

            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = caller,
                Issuer = issuer,
                Audience = target.client_id,
                Subject = caller.client_id,
                Scopes = scopes,
                LifetimeSeconds = Lifetime(options, caller),
                AuthorizationClaims = entry.claims ?? new List<string>()
            };
            var (token, expiresAt, _) = await _tokens.IssueAccessTokenAsync(ctx);
            return new AgentTokenResult
            {
                AccessToken = token, ExpiresAt = expiresAt, Scopes = scopes,
                Subject = caller.client_id, Audience = target.client_id
            };
        }

        // -----------------------------------------------------------------
        // the agent on behalf of a user (RFC 8693)
        // -----------------------------------------------------------------

        public async Task<AgentTokenResult> OnBehalfOfAsync(
            ArkTenant tenant, string issuer, ArkClient actor, IFormCollection form)
        {
            var options = ArkConfigSnapshot.Oidc(_ctx.Configuration);

            var subjectToken = form["subject_token"].ToString();
            if (string.IsNullOrWhiteSpace(subjectToken))
                throw OAuthException.InvalidRequest("subject_token is required.");
            if (!string.Equals(form["subject_token_type"].ToString(), AccessTokenType, StringComparison.Ordinal))
                throw OAuthException.InvalidRequest($"subject_token_type must be {AccessTokenType}.");
            var requestedType = form["requested_token_type"].ToString();
            if (!string.IsNullOrEmpty(requestedType) && !string.Equals(requestedType, AccessTokenType, StringComparison.Ordinal))
                throw OAuthException.InvalidRequest($"requested_token_type must be {AccessTokenType}; nothing else is issued here.");
            // The actor is whoever authenticated this request. A second, separately presented
            // identity would be one more thing to get wrong and adds nothing to that.
            if (!string.IsNullOrEmpty(form["actor_token"].ToString()))
                throw OAuthException.InvalidRequest("actor_token is not supported: the authenticated client is the actor.");

            var audience = RequestedAudience(form)
                ?? throw OAuthException.InvalidRequest("audience is required: the client_id of the agent the token is for.");
            if (IsTenantAudience(audience, tenant, issuer))
                throw new OAuthException(InvalidTarget, "token exchange issues a token addressed to an agent; name the agent's client_id as the audience.");

            // --- the token being exchanged ---

            var validated = await _tokens.ValidateAccessTokenAnyAudienceAsync(subjectToken, tenant, issuer);
            if (!validated.IsValid || validated.SecurityToken is not JsonWebToken jwt)
                throw OAuthException.InvalidGrant("subject_token is not a live access token from this issuer.");

            using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(jwt.EncodedPayload));
            var claims = payload.RootElement;
            string? Text(string name) =>
                claims.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            var subject = Text("sub");
            var issuedTo = Text("client_id");
            var audiences = jwt.Audiences.ToList();

            // Who may exchange a token: the agent it is addressed to, or the client it was issued
            // to in the first place. Any API in the tenant is handed ordinary access tokens all
            // day; without this, each of them could turn a caller's token into one for somewhere
            // else. A token this client itself obtained for another agent is not re-exchanged —
            // the one it was exchanged from is.
            var addressedToActor = audiences.Count > 0 && audiences.All(a => Same(a, actor.client_id));
            var issuedToActor = Same(issuedTo, actor.client_id) && audiences.All(a => IsTenantAudience(a, tenant, issuer));
            if (!addressedToActor && !issuedToActor)
                throw OAuthException.InvalidGrant("subject_token was neither issued to this client nor addressed to it.");

            if (claims.TryGetProperty("service_role", out _))
                throw OAuthException.InvalidGrant("a service account token cannot be exchanged.");

            // Delegation carries a person. A client's own token (sub is the client) has nobody to
            // carry, and the agent that holds one calls the next agent as itself instead.
            var previous = claims.TryGetProperty("act", out var act) ? ActorChain(act) : new List<string>();
            if (string.IsNullOrEmpty(subject) || (previous.Count == 0 && Same(subject, issuedTo)))
                throw OAuthException.InvalidGrant(
                    "subject_token carries no user: it is a client's own token. To call an agent as yourself, use client_credentials with audience.");

            var user = await _claims.FindUserAsync(subject);
            if (user == null)
                throw OAuthException.InvalidGrant("the subject of subject_token is not a user account here.");
            if (!user.is_active)
                throw OAuthException.InvalidGrant("the account subject_token belongs to has been deactivated.");

            // Signing out ends the session; it ends what agents may do in that user's name too.
            var sessionId = Text("sid");
            if (!string.IsNullOrEmpty(sessionId) && await _grants.GetSessionAsync(sessionId) == null)
                throw OAuthException.InvalidGrant("the session behind subject_token has ended.");

            if (previous.Count + 1 > Math.Max(1, options.A2AMaxDelegationDepth))
                throw OAuthException.InvalidGrant(
                    $"the delegation chain is too long: {previous.Count + 1} agents, and at most {Math.Max(1, options.A2AMaxDelegationDepth)} are allowed.");

            // --- the agent it is for ---

            var (target, _) = await ResolveTargetAsync(tenant, issuer, actor, audience, forUser: true);

            // The user's own standing at the target decides what the token may do there. An agent
            // cannot carry somebody to an application they were never given access to.
            if (!await _claims.HasClientAccessAsync(subject!, tenant.tenant_id, target))
                throw new OAuthException(InvalidTarget, $"the user subject_token belongs to has no access to '{target.client_id}'.");
            var granted = await _claims.GetAuthorizationClaimsAsync(subject!, tenant.tenant_id, target);

            // --- scope: what the presented token held, narrowed on request, never widened ---

            var scopes = (Text("scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(s => !IsIdentityScope(s)).ToList();
            var wanted = form["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (wanted.Count > 0)
            {
                var widened = wanted.Where(s => !scopes.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
                if (widened.Count > 0)
                    throw OAuthException.InvalidScope($"scope cannot be widened on exchange: {string.Join(", ", widened)}.");
                scopes = wanted;
            }

            // --- the token ---

            // Never past the token it stands on: when the user's token dies, so does everything
            // that was exchanged from it, however many agents down the line.
            var remaining = (int)Math.Floor((DateTime.SpecifyKind(jwt.ValidTo, DateTimeKind.Utc) - DateTime.UtcNow).TotalSeconds);
            if (remaining <= 0)
                throw OAuthException.InvalidGrant("subject_token has expired.");

            var actors = new List<string> { actor.client_id };
            actors.AddRange(previous);

            var ctx = new TokenRequestContext
            {
                Tenant = tenant,
                Client = actor,
                Issuer = issuer,
                Audience = target.client_id,
                Subject = subject!,
                Scopes = scopes,
                SessionId = sessionId,
                Actor = ActorClaim(actors),
                LifetimeSeconds = Math.Min(Lifetime(options, actor), remaining),
                AuthorizationClaims = granted
            };
            var (token, expiresAt, _) = await _tokens.IssueAccessTokenAsync(ctx);
            return new AgentTokenResult
            {
                AccessToken = token, ExpiresAt = expiresAt, Scopes = scopes,
                Subject = subject!, Audience = target.client_id, Actors = actors
            };
        }

        // -----------------------------------------------------------------

        /// <summary>
        /// The agent named by <paramref name="audience"/> and the entry in its caller list for
        /// <paramref name="caller"/>, or <c>invalid_target</c>. An agent that does not exist, one
        /// that is switched off and one that has not listed this caller are told the same thing:
        /// the token endpoint is not a way to find out which client_ids are agents.
        /// </summary>
        private async Task<(ArkClient target, ArkAgentCaller entry)> ResolveTargetAsync(
            ArkTenant tenant, string issuer, ArkClient caller, string audience, bool forUser)
        {
            var target = await ArkIdpCache.ClientAsync(_ctx, tenant.tenant_id, audience);
            var entry = Entry(target, caller);
            // Nothing is refused on a copy another instance may have changed since it was read.
            if (target != null && (entry == null || !target.is_active || (forUser && !entry.delegate_users)))
            {
                target = await ArkIdpCache.ClientIfChangedAsync(_ctx, target);
                entry = Entry(target, caller);
            }

            if (target == null || !target.is_active || entry == null
                // A client named after the tenant's audience would make "addressed to this agent"
                // and "good at every API of the tenant" the same token.
                || IsTenantAudience(target.client_id, tenant, issuer))
                throw new OAuthException(InvalidTarget,
                    $"'{audience}' is not an agent this client may call. The target client lists its callers (a2a_callers).");

            if (forUser && !entry.delegate_users)
                throw new OAuthException(InvalidTarget,
                    $"this client may call '{target.client_id}' as itself, but not on behalf of a user (delegate_users is off for it there).");

            return (target, entry);
        }

        private static ArkAgentCaller? Entry(ArkClient? target, ArkClient caller) =>
            target?.a2a_callers.FirstOrDefault(c => Same(c.client_id, caller.client_id));

        private static bool Same(string? a, string? b) =>
            !string.IsNullOrEmpty(a) && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        private static bool IsIdentityScope(string scope) =>
            string.Equals(scope, "openid", StringComparison.OrdinalIgnoreCase)
            || string.Equals(scope, "offline_access", StringComparison.OrdinalIgnoreCase);

        private static int Lifetime(ArkOidcOptions options, ArkClient client)
        {
            var cap = options.A2ATokenLifetimeSeconds > 0 ? options.A2ATokenLifetimeSeconds : 300;
            return client.access_token_lifetime_seconds > 0 ? Math.Min(cap, client.access_token_lifetime_seconds) : cap;
        }

        /// <summary>The subjects of an <c>act</c> claim, newest first. Reads no further than 32 deep.</summary>
        internal static List<string> ActorChain(JsonElement act)
        {
            var chain = new List<string>();
            var current = act;
            while (current.ValueKind == JsonValueKind.Object && chain.Count < 32)
            {
                if (current.TryGetProperty("sub", out var sub) && sub.ValueKind == JsonValueKind.String
                    && !string.IsNullOrEmpty(sub.GetString()))
                    chain.Add(sub.GetString()!);
                if (!current.TryGetProperty("act", out var next)) break;
                current = next;
            }
            return chain;
        }

        /// <summary>The <c>act</c> claim for a chain, newest first: each earlier actor nested in the next.</summary>
        internal static Dictionary<string, object> ActorClaim(IReadOnlyList<string> actors)
        {
            Dictionary<string, object>? inner = null;
            for (var i = actors.Count - 1; i >= 0; i--)
            {
                var level = new Dictionary<string, object> { ["sub"] = actors[i] };
                if (inner != null) level["act"] = inner;
                inner = level;
            }
            return inner ?? new Dictionary<string, object>();
        }
    }
}
