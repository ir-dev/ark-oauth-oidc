using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Ark.oAuth.Oidc
{
    public class ArkClientValidationException : ApplicationException
    {
        public string Code { get; }
        public int StatusCode { get; }
        public object? DataPayload { get; }

        public ArkClientValidationException(string code, string message, int statusCode = 400, object? data = null)
            : base(message)
        {
            Code = code;
            StatusCode = statusCode;
            DataPayload = data;
        }
    }

    public class DataAccess
    {
        ArkDataContext _ctx;
        ArkUtil _util;
        ArkAuditWriter? _audit;
        ArkWatchAudit? _watch;
        public DataAccess(ArkDataContext ctx, ArkUtil util)
        {
            _ctx = ctx;
            _util = util;
        }
        /// <summary>
        /// The constructor the container uses: <paramref name="audit"/> takes the audit trail off
        /// the request path (see <see cref="ArkAuditWriter"/>). Without it every row is written
        /// inline, as it was.
        /// </summary>
        public DataAccess(ArkDataContext ctx, ArkUtil util, ArkAuditWriter audit) : this(ctx, util)
        {
            _audit = audit;
        }
        /// <summary>
        /// ...and <paramref name="watch"/> sends the same trail, structured, to an ARK-RAPID Watch
        /// node when one is configured (see <see cref="ArkWatchAudit"/>). It does nothing when
        /// none is.
        /// </summary>
        public DataAccess(ArkDataContext ctx, ArkUtil util, ArkAuditWriter audit, ArkWatchAudit watch) : this(ctx, util, audit)
        {
            _watch = watch;
        }
        public ArkDataContext GetCtx()
        {
            return _ctx; 
        }
        public async Task<ArkTenant?> GetTenant(string tenant_id)
        {
            // The id as stored first — an index lookup — and only then the forgiving comparison,
            // which reads the table. Tracked, as before: callers go on to change what they get.
            var id = (tenant_id ?? "").Trim();
            return await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id == id)
                ?? await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id.ToLower().Trim() == id.ToLower());
        }
        public async Task<List<ArkTenant>> GetTenants()
        {
            return await _ctx.tenants.ToListAsync();
        }
        public async Task<ArkClient?> GetClient(string tenant_id, string client_id) //cmposite key
        {
            var tenant = (tenant_id ?? "").Trim();
            var client = (client_id ?? "").Trim();
            return await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id == tenant && t.client_id == client)
                ?? await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id.ToLower().Trim() == tenant.ToLower() && t.client_id.ToLower().Trim() == client.ToLower());
        }
        public async Task<ArkTenant> UpsertTenant(ArkTenant tenant)
        {
            if (string.IsNullOrWhiteSpace(tenant?.tenant_id)) throw new ApplicationException("tenant_id is required.");
            tenant.tenant_id = tenant.tenant_id.Trim();
            // name/display/issuer/audience are NOT NULL columns, and the console adds a blank row
            // for the operator to fill in — so anything left empty is defaulted here rather than
            // failing the insert with a constraint violation the operator cannot act on.
            var root = $"{_util.ServerConfig.BaseUrl}{(string.IsNullOrWhiteSpace(_util.ServerConfig.BasePath) ? "" : $"/{_util.ServerConfig.BasePath.Trim('/')}")}";
            tenant.name = string.IsNullOrWhiteSpace(tenant.name) ? tenant.tenant_id : tenant.name.Trim();
            tenant.display = string.IsNullOrWhiteSpace(tenant.display) ? tenant.name : tenant.display.Trim();
            tenant.issuer = string.IsNullOrWhiteSpace(tenant.issuer) ? $"{root}/ark/oauth/v1/iss" : tenant.issuer.Trim();
            tenant.audience = string.IsNullOrWhiteSpace(tenant.audience) ? $"{root}/ark/oauth/v1/aud" : tenant.audience.Trim();
            if (tenant.expire_mins <= 0) tenant.expire_mins = 480;

            var tt = await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id == tenant.tenant_id);

            // rsa_public/rsa_private are NOT NULL. A caller that omits them means "leave the key
            // alone" — never "rotate it", which would invalidate every token and JWKS entry the
            // tenant has already issued — so an existing pair is carried over and a new tenant
            // gets a freshly minted one.
            if (string.IsNullOrEmpty(tenant.rsa_private) || string.IsNullOrEmpty(tenant.rsa_public))
            {
                if (tt != null && !string.IsNullOrEmpty(tt.rsa_private))
                {
                    tenant.rsa_private = tt.rsa_private;
                    tenant.rsa_public = tt.rsa_public;
                }
                else
                {
                    var (pub, priv) = Protocol.ArkCrypto.GenerateRsaKeyPair();
                    tenant.rsa_private = priv;
                    tenant.rsa_public = pub;
                }
            }

            if (tt == null)
            {
                tenant.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.tenants.Add(tenant);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                tenant.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.tenants.Update(tenant);
            }
            await _ctx.SaveChangesAsync();
            return tenant;
        }
        public async Task<List<ArkClient>> GetClients()
        {
            return await _ctx.clients.ToListAsync();
        }
        public async Task<ArkClient> UpsertClient(ArkClient client)
        {
            if (string.IsNullOrEmpty((client?.id ?? "").Trim())) client.id = null;
            await NormaliseClient(client);
            var tt = (await _ctx.clients.FirstOrDefaultAsync(t => t.id.ToLower() == (client.id ?? "").ToLower())) ?? (await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id.ToLower() == (client.tenant_id ?? "").ToLower() && t.client_id.ToLower() == (client.client_id ?? "").ToLower()));
            await EnsureUniqueClientName(client.tenant_id, client.client_name ?? client.display ?? client.name ?? client.client_id, tt?.id);
            // As they stood before this save, for the audit line below.
            var callersBefore = tt?.a2a_callers ?? new List<ArkAgentCaller>();
            var wasAgent = tt?.is_agent == true;
            if (tt == null)
            {
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Add(client);
            }
            else
            {
                client.id = tt.id;
                // The hashes are never serialised (ArkClient), so a row posted from the console
                // arrives without them — which means "unchanged", not "remove the secret".
                if (string.IsNullOrEmpty(client.client_secret_hash)) client.client_secret_hash = tt.client_secret_hash;
                if (string.IsNullOrEmpty(client.registration_access_token_hash)) client.registration_access_token_hash = tt.registration_access_token_hash;
                // The A2A caller list likewise: a save that does not carry it (provisioning,
                // onboarding, an older console script) leaves it as it was. "[]" clears it.
                if (client.a2a_callers_ == null) client.a2a_callers_ = tt.a2a_callers_;
                // ...and the agent mark.
                if (client.is_agent == null) client.is_agent = tt.is_agent;
                _ctx.ChangeTracker.Clear();
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Update(client);
            }
            await _ctx.SaveChangesAsync();
            // The client editor has an is_active checkbox, so deactivation can arrive through a
            // plain save as well as through the activation endpoint. Both have to revoke, or
            // which control the operator happened to use decides whether the switch takes effect.
            if (tt != null && tt.is_active && !client.is_active)
                await RevokeRefreshTokensForClient(client.tenant_id, client.client_id);
            RecordAgentChanges(client, callersBefore, wasAgent);
            return client;
        }

        /// <summary>
        /// Records a change to who may call an agent, or to whether a client is marked as one.
        ///
        /// Written whatever <c>EnableLogTrace</c> says, like an import or a reset: "who allowed
        /// this agent to act for users at that one, and when" is the question an audit of
        /// agent-to-agent access starts with, and every path that can change the list — the
        /// console, the management API — ends in <see cref="UpsertClient"/>. A save that changes
        /// neither writes nothing.
        /// </summary>
        internal void RecordAgentChanges(ArkClient client, List<ArkAgentCaller> before, bool wasAgent)
        {
            try
            {
                static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
                static Dictionary<string, object?> Describe(ArkAgentCaller c) => new()
                {
                    ["client_id"] = c.client_id,
                    ["claims"] = (c.claims ?? new List<string>()).ToList(),
                    ["delegate_users"] = c.delegate_users
                };
                static string Text(ArkAgentCaller c) =>
                    $"{c.client_id} [{string.Join(" ", c.claims ?? new List<string>())}]{(c.delegate_users ? " +users" : "")}";

                var after = client.a2a_callers;
                var added = after.Where(a => !before.Any(b => Same(b.client_id, a.client_id))).ToList();
                var removed = before.Where(b => !after.Any(a => Same(a.client_id, b.client_id))).ToList();
                var changed = after
                    .Select(a => (after: a, before: before.FirstOrDefault(b => Same(b.client_id, a.client_id))))
                    .Where(p => p.before != null && (p.before.delegate_users != p.after.delegate_users
                        || !new HashSet<string>(p.before.claims ?? new List<string>(), StringComparer.Ordinal)
                            .SetEquals(p.after.claims ?? new List<string>())))
                    .ToList();
                var isAgent = client.is_agent == true;
                if (added.Count + removed.Count + changed.Count == 0 && wasAgent == isAgent) return;

                var (who, ip) = _watch?.Caller() ?? (null, null);
                var reference = $"{client.tenant_id}/{client.client_id}";

                if (added.Count + removed.Count + changed.Count > 0)
                {
                    var parts = new List<string>();
                    if (added.Count > 0) parts.Add("added: " + string.Join("; ", added.Select(Text)));
                    if (removed.Count > 0) parts.Add("removed: " + string.Join("; ", removed.Select(Text)));
                    if (changed.Count > 0) parts.Add("changed: " + string.Join("; ", changed.Select(p => $"{Text(p.before!)} -> {Text(p.after)}")));

                    var e = new ArkWatchEvent
                    {
                        Action = "agent_callers.update",
                        Domain = ArkWatchDomains.Agents,
                        System = "management-api",
                        Level = Ark.Watch.Core.AuditLevel.Security,
                        Outcome = Ark.Watch.Core.Outcome.Success,
                        Tenant = client.tenant_id,
                        ResourceType = "agent",
                        ResourceId = client.client_id,
                        Message = $"who may call agent '{client.client_id}' changed: {added.Count} added, {removed.Count} removed, {changed.Count} changed"
                    };
                    e.With("target", client.client_id)
                        .With("added", added.Select(Describe).ToList())
                        .With("removed", removed.Select(Describe).ToList())
                        .With("changed", changed.Select(p => new Dictionary<string, object?>
                        {
                            ["client_id"] = p.after.client_id,
                            ["before"] = Describe(p.before!),
                            ["after"] = Describe(p.after)
                        }).ToList())
                        .With("callers", after.Select(c => c.client_id).ToList())
                        .With("delegating_callers", after.Where(c => c.delegate_users).Select(c => c.client_id).ToList());
                    // Granting an agent the right to act for users is the change to look for.
                    if (added.Any(c => c.delegate_users) || changed.Any(p => p.after.delegate_users && !p.before!.delegate_users))
                        e.With("delegation_granted", true);
                    WriteAudit("a2a_callers", reference, "a2a caller list changed", string.Join(" | ", parts), who, ip, e);
                }

                if (wasAgent != isAgent)
                {
                    var e = new ArkWatchEvent
                    {
                        Action = isAgent ? "agent.mark" : "agent.unmark",
                        Domain = ArkWatchDomains.Agents,
                        System = "management-api",
                        Level = Ark.Watch.Core.AuditLevel.Notice,
                        Outcome = Ark.Watch.Core.Outcome.Success,
                        Tenant = client.tenant_id,
                        ResourceType = "agent",
                        ResourceId = client.client_id,
                        Message = isAgent ? $"client '{client.client_id}' marked as an agent" : $"client '{client.client_id}' is no longer marked as an agent"
                    };
                    e.With("is_agent", isAgent);
                    WriteAudit("a2a_agent", reference, isAgent ? "client marked as an agent" : "agent mark removed", "", who, ip, e);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        /// <summary>
        /// An audit row that is always written, queued behind the request like the trace when the
        /// writer is running. <see cref="Record"/> clears the change tracker first, which is right
        /// for an import and wrong in the middle of a save other code is still building on.
        /// </summary>
        internal void WriteAudit(string ref_key, string ref_val, string message, string details, string? by, string? ip, ArkWatchEvent? watch)
        {
            if (_watch is { Enabled: true })
            {
                try { _watch.Log(null, watch ?? ArkWatchMap.FromRow(ref_key, ref_val, message, details, "audit", by)); }
                catch { /* the trail is never a reason to fail */ }
            }
            var row = ArkAuditWriter.Storable(new ArkAudit()
            {
                ref_key = ref_key,
                ref_val = ref_val,
                log_type = "audit",
                message = message,
                details = details,
                by = string.IsNullOrWhiteSpace(by) ? "ark_admin" : by,
                ip = ip ?? "",
                at = DateTime.UtcNow
            });
            if (_audit != null && _audit.TryEnqueue(row)) return;
            _ctx.audit_trace.Add(row);
            _ctx.SaveChanges();
        }
        /// <summary>
        /// Fills in the v1 single-valued columns a client row still requires from the RFC 7591
        /// metadata the console actually edits.
        ///
        /// name, display, domain, redirect_url and logout_url are NOT NULL, but the client drawer
        /// posts null for every text box left blank — so registering a client the standard way
        /// (client_name + redirect_uris, no legacy fields) failed on
        /// "NOT NULL constraint failed: clients.name" with nothing on screen to say which box to
        /// fill. Deriving them keeps both styles of payload valid and keeps the two
        /// representations consistent, which is what EffectiveRedirectUris et al. assume.
        /// </summary>
        async Task NormaliseClient(ArkClient client)
        {
            if (string.IsNullOrWhiteSpace(client?.client_id)) throw new ApplicationException("client_id is required.");
            if (string.IsNullOrWhiteSpace(client.tenant_id)) throw new ApplicationException("tenant_id is required.");
            client.client_id = client.client_id.Trim();
            client.tenant_id = client.tenant_id.Trim();

            // A missing tenant otherwise surfaces as a bare "FOREIGN KEY constraint failed".
            if (await GetTenant(client.tenant_id) == null)
                throw new ApplicationException($"unknown tenant '{client.tenant_id}' - create the tenant first.");

            var label = new[] { client.client_name, client.display, client.name, client.client_id }
                .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? client.client_id;
            client.client_name = string.IsNullOrWhiteSpace(client.client_name) ? label : client.client_name;
            client.name = string.IsNullOrWhiteSpace(client.name) ? label : client.name;
            client.display = string.IsNullOrWhiteSpace(client.display) ? label : client.display;

            // The plural forms win when populated, so fall back to the first of each list.
            client.redirect_url = string.IsNullOrWhiteSpace(client.redirect_url)
                ? (client.redirect_uris.FirstOrDefault(u => !string.IsNullOrWhiteSpace(u)) ?? "")
                : client.redirect_url.Trim();
            client.logout_url = string.IsNullOrWhiteSpace(client.logout_url)
                ? (client.post_logout_redirect_uris.FirstOrDefault(u => !string.IsNullOrWhiteSpace(u)) ?? "")
                : client.logout_url.Trim();

            // A redirect URI ends up as the action of the form_post page and as a Location header,
            // and client_uri as a link on the consent page — all on this server's origin. A
            // javascript: or data: value in any of them is script running as the identity
            // provider, so they are refused here as well as at dynamic registration.
            foreach (var uri in client.redirect_uris.Concat(client.post_logout_redirect_uris)
                         .Append(client.redirect_url).Append(client.logout_url)
                         .Append(client.client_uri).Append(client.policy_uri).Append(client.tos_uri).Append(client.jwks_uri))
            {
                if (!string.IsNullOrWhiteSpace(uri) && Protocol.RedirectUriValidator.CarriesScript(uri.Trim()))
                    throw new ApplicationException($"'{uri}' is not an acceptable URI: javascript:, data:, file: and values containing whitespace are refused.");
            }

            if (string.IsNullOrWhiteSpace(client.domain))
            {
                var source = new[] { client.redirect_url, client.logout_url, client.client_uri, _util.ServerConfig.BaseUrl }
                    .FirstOrDefault(u => !string.IsNullOrWhiteSpace(u));
                client.domain = Uri.TryCreate(source, UriKind.Absolute, out var uri) ? uri.Host : "";
            }

            if (client.expire_mins <= 0) client.expire_mins = 480;

            // A2A callers: one tidy entry per calling client, so the token endpoint compares
            // against exactly what the console shows.
            if (client.a2a_callers_ != null)
            {
                client.a2a_callers = client.a2a_callers
                    .Where(c => !string.IsNullOrWhiteSpace(c.client_id))
                    .GroupBy(c => c.client_id.Trim(), StringComparer.OrdinalIgnoreCase)
                    .Select(g => new ArkAgentCaller
                    {
                        client_id = g.Key,
                        claims = g.SelectMany(c => c.claims ?? new List<string>())
                            .Select(v => (v ?? "").Trim()).Where(v => v.Length > 0)
                            .Distinct(StringComparer.Ordinal).ToList(),
                        delegate_users = g.Any(c => c.delegate_users)
                    }).ToList();
            }
        }
        public async Task<ArkClient?> FindClientByName(string tenant_id, string client_name, string? excludeClientRowId = null)
        {
            var tenantId = (tenant_id ?? "").Trim().ToLower();
            var clientName = (client_name ?? "").Trim().ToLower();
            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(clientName))
                return null;

            var rowId = (excludeClientRowId ?? "").Trim().ToLower();
            return await _ctx.clients.FirstOrDefaultAsync(c =>
                c.tenant_id.ToLower().Trim() == tenantId
                && (rowId == "" || c.id.ToLower() != rowId)
                && ((c.client_name ?? c.display ?? c.name ?? "").ToLower().Trim() == clientName));
        }
        public async Task EnsureUniqueClientName(string tenant_id, string client_name, string? excludeClientRowId = null)
        {
            var normalisedName = (client_name ?? "").Trim();
            if (string.IsNullOrWhiteSpace(normalisedName)) return;

            var existing = await FindClientByName(tenant_id, normalisedName, excludeClientRowId);
            if (existing == null) return;

            throw new ArkClientValidationException(
                "client_exists",
                $"an application named '{existing.client_name ?? existing.display ?? existing.client_id}' is already registered in tenant '{existing.tenant_id}'. Choose a different client name.",
                409,
                new
                {
                    tenant_id = existing.tenant_id,
                    client_id = existing.client_id,
                    client_name = existing.client_name ?? existing.display ?? existing.name ?? existing.client_id
                });
        }
        public async Task<ArkClient> DeleteClient(ArkClient client)
        {
            if (string.IsNullOrEmpty(client.id)) return client; //added on the UI, delete before even saving
            var tt = await _ctx.clients.FirstOrDefaultAsync(t => t.id.ToLower() == client.id.ToLower());
            if (tt == null) return client;

            var forgotten = await ForgetAgentCaller(tt);
            _ctx.clients.Remove(tt);
            await _ctx.SaveChangesAsync();
            foreach (var (agent, before) in forgotten) RecordAgentChanges(agent, before, agent.is_agent == true);
            return client;
        }
        /// <summary>
        /// Takes a client that is going away off the caller lists it is on (A2A.md), and returns
        /// the clients that had listed it, with their lists as they were. The caller saves.
        ///
        /// A list names its callers by client_id, and a client_id is free again once its client is
        /// gone: whoever registered it next would have been let in as the agent that used to have
        /// it, acting for users included.
        /// </summary>
        internal async Task<List<(ArkClient Agent, List<ArkAgentCaller> Before)>> ForgetAgentCaller(ArkClient gone)
        {
            var tenant = (gone.tenant_id ?? "").ToLower();
            var listing = await _ctx.clients
                .Where(c => c.tenant_id.ToLower() == tenant && c.id != gone.id && c.a2a_callers_ != null && c.a2a_callers_ != "[]")
                .ToListAsync();
            var changed = new List<(ArkClient, List<ArkAgentCaller>)>();
            foreach (var agent in listing)
            {
                var before = agent.a2a_callers;
                var after = before.Where(c => !string.Equals(c.client_id.Trim(), gone.client_id, StringComparison.OrdinalIgnoreCase)).ToList();
                if (after.Count == before.Count) continue;
                agent.a2a_callers = after;
                _ctx.clients.Update(agent);
                changed.Add((agent, before));
            }
            return changed;
        }
        public async Task<List<ArkClaim>> GetClaims()
        {
            return await _ctx.claims.ToListAsync();
        }
        public async Task<ArkClaim?> GetClaim(string key)
        {
            return await _ctx.claims.FirstOrDefaultAsync(t => t.key.ToLower().Trim() == key.ToLower().Trim());
        }
        public async Task<ArkClaim> UpsertClaim(ArkClaim claim)
        {
            // Refused here because every caller ends here. A refusal the provisioning API answers
            // as one (400 invalid_claim) rather than as a fault of the server.
            if (ArkText.ClaimKeyProblem(claim.key) is { } problem)
                throw new ArkProvisionException("invalid_claim", problem);
            var tt = await _ctx.claims.FirstOrDefaultAsync(t => t.key == claim.key);
            if (tt == null)
            {
                _ctx.claims.Add(claim);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                _ctx.claims.Update(claim);
            }
            await _ctx.SaveChangesAsync();
            return claim;
        }
        public async Task<ArkClaim> DeleteClaim(ArkClaim claim)
        {
            var tt = await _ctx.claims.FirstOrDefaultAsync(t => t.key == claim.key);
            if (tt != null)
            {
                _ctx.claims.Remove(tt);
                await _ctx.SaveChangesAsync();
            }
            return claim;
        }
        public async Task<List<ArkScope>> GetScopes()
        {
            return await _ctx.scopes.ToListAsync();
        }
        public async Task<ArkScope> UpsertScope(ArkScope scope)
        {
            if (string.IsNullOrWhiteSpace(scope?.name)) throw new ApplicationException("empty scope name");
            scope.name = scope.name.Trim();
            var tt = await _ctx.scopes.FirstOrDefaultAsync(t => t.name == scope.name);
            if (tt == null)
            {
                _ctx.scopes.Add(scope);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                _ctx.scopes.Update(scope);
            }
            await _ctx.SaveChangesAsync();
            return scope;
        }
        public async Task<ArkScope> DeleteScope(ArkScope scope)
        {
            var tt = await _ctx.scopes.FirstOrDefaultAsync(t => t.name == (scope.name ?? "").Trim());
            if (tt == null) return scope; // added on the UI, deleted before ever being saved
            // Removing a protocol scope (openid, offline_access) breaks the authorization and
            // token endpoints for every client on the deployment, so it is refused here rather
            // than left as a one-click way to take the server down.
            if (tt.is_protocol) throw new ApplicationException($"'{tt.name}' is a protocol scope and cannot be deleted.");
            _ctx.scopes.Remove(tt);
            await _ctx.SaveChangesAsync();
            return scope;
        }
        public async Task<List<ArkUser>> GetUsers()
        {
            return await _ctx.users.ToListAsync();
        }
        public async Task<ArkUser> GetUser(string email)
        {
            return await _ctx.users.FirstOrDefaultAsync(t => t.email == email);
        }
        public async Task<dynamic> GetUserInfo(string email, string tenant_id, string client_id)
        {
            var cc = await GetClient(tenant_id, client_id);
            var usr = await Protocol.ArkLookup.UserAsync(_ctx, email);
            var clms = await GetUsersClientClaims(email, tenant_id);
            return new
            {
                claims = clms.Find(t => t.client_id?.ToLower() == cc.id.ToLower())?.claims,
                client_guid = cc.id,
                client_id = cc.client_id,
                client_name = cc.name,
                user = new
                {
                    usr.email, usr.name, usr.type
                }
            };
        }
        public async Task<List<ArkUserClientClaim>> GetUsersClientClaims(string email, string tenatn_id)
        {
            // lower(email) on its own, so the index ArkSchemaUpdater adds on that expression
            // finds this person's rows; the tenant is then compared on those few.
            var login = (email ?? "").ToLower();
            var tenant = (tenatn_id ?? "").ToLower();
            return await _ctx.user_client_claims.Where(t1 =>
                    t1.email.ToLower() == login && (t1.tenant_id ?? "").ToLower() == tenant).ToListAsync();
        }
        public async Task<ArkUserClientClaim> UpsertUsersClientClaims(ArkUserClientClaim us_cl)
        {
            if (string.IsNullOrEmpty((us_cl?.id ?? "").Trim())) us_cl.id = null;
            var tt = (await _ctx.user_client_claims.FirstOrDefaultAsync(t => (t.id ?? "").ToLower().Trim() == (us_cl.id ?? "").ToLower().Trim())) 
                ?? (await _ctx.user_client_claims.FirstOrDefaultAsync(t => 
                                (t.tenant_id ?? "").ToLower().Trim() == (us_cl.tenant_id ?? "").ToLower().Trim() 
                            &&  (t.client_id ?? "").ToLower().Trim() == (us_cl.client_id ?? "").ToLower().Trim() 
                            &&  (t.email ?? "").ToLower().Trim() == (us_cl.email ?? "").ToLower().Trim()));
            if (tt == null)
            {
                us_cl.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.user_client_claims.Add(us_cl);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                us_cl.id = tt.id;
                us_cl.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.user_client_claims.Update(us_cl);
            }
            await _ctx.SaveChangesAsync();
            return us_cl;
        }
        public async Task<ArkUserClientClaim> DeleteUsersClientClaims(ArkUserClientClaim us_cl)
        {
            if (string.IsNullOrEmpty(us_cl?.id)) return us_cl; //added on the UI, delete before even saving
            var tt = await _ctx.user_client_claims.FirstOrDefaultAsync(t => t.id.ToLower() == us_cl.id.ToLower());
            if (tt == null)
            {

            }
            else
            {
                _ctx.user_client_claims.Remove(tt);
            }
            await _ctx.SaveChangesAsync();
            return us_cl;
        }
        /// <summary>
        /// A login identifier is either an email address or a plain username.
        ///
        /// The sign-in screen has always posted a free-text "Username", and the bootstrap seed
        /// creates `admin` and `service_account_{tenant}` — neither of which is an email. Only
        /// account *creation* insisted on an address, so those accounts could not be reproduced
        /// through the console. Usernames are kept to characters that survive a URL path segment
        /// unescaped, since they travel in the claims-mapping routes.
        /// </summary>
        internal static bool IsValidLoginId(string id) =>
            ark.net.util.EmailUtil.IsValidFormat(id) ||
            System.Text.RegularExpressions.Regex.IsMatch(id, @"^[a-z0-9][a-z0-9._-]{1,63}$");

        /// <param name="user">The account to create or update. <c>email</c> is the login identifier.</param>
        /// <param name="sendActivationEmail">
        /// Whether the caller is asking for the email activation flow for a brand-new account.
        /// The host configuration (<c>ark_oauth_server:UserPasswordMode</c>) can still force the
        /// decision either way so the deployment behaves consistently.
        ///
        /// Provisioning passes false: it is driven by another system that has just told somebody
        /// "your account is ready", and an account in reset_mode cannot sign in at all — it
        /// answers the default password with "this account needs its password set", which is not
        /// a message the caller can do anything about. False creates the account on the
        /// configured default password instead, usable immediately.
        /// </param>
        public async Task<ArkUser> UpsertUser(ArkUser user, bool sendActivationEmail = true)
        {
            if (string.IsNullOrEmpty(user?.email)) throw new ApplicationException("a username or email is required.");
            user.email = user.email.ToLower().Trim();
            if (!IsValidLoginId(user.email))
                throw new ApplicationException("invalid username - use an email address, or 2-64 characters of letters, digits, dot, dash or underscore.");
            if (string.IsNullOrWhiteSpace(user.name)) user.name = user.email;
            if (string.IsNullOrWhiteSpace(user.type)) user.type = "user";
            var tt = await _ctx.users.FirstOrDefaultAsync(t => t.email == user.email);
            if (tt == null)
            {
                user.ref_uid = Guid.NewGuid().ToString();
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");

                // The host decides whether this deployment uses email activation or an
                // admin-managed/default-password flow. An email-shaped login id no longer forces
                // one on its own, which is what trapped accounts in reset_mode when SMTP had not
                // been configured.
                var emailFlow = _util.ServerConfig.ShouldUseEmailPasswordFlow(user.email, sendActivationEmail);
                // An account waiting on its activation link cannot sign in at all (reset_mode), so
                // it starts on a random password nobody knows rather than the shared default.
                if (string.IsNullOrEmpty(user.hash_pw))
                    user.hash_pw = _util.HashPasswordPBKDF2(emailFlow
                        ? Protocol.ArkCrypto.RandomToken(32)
                        : _util.ServerConfig.RequireDefaultPw());
                if (emailFlow)
                {
                    user.reset_mode = true;
                    // Creating the account is the operation being asked for; a template that
                    // cannot be read or an SMTP host that is down must not roll it back. The
                    // account is left in reset_mode and `emailed` false, which is what
                    // "Reset password" in the console retries.
                    try
                    {
                        string email_content = await _util.GetActivationEmail(_util.ServerConfig.TenantId, user.ref_uid);
                        user.emailed = await _util.SendMail(user.email, email_content, $"{_util.ServerConfig.EmailConfig?.subject} Activation Link", this);
                    }
                    catch (Exception ex)
                    {
                        LogError(ex, "user_activation_email", user.email, "activation email could not be built or sent; account still created");
                        user.emailed = false;
                    }
                }
                else
                {
                    user.reset_mode = false;
                    user.emailed = false;
                }
                _ctx.users.Add(user);
            }
            else
            {
                // Same contract as the client hashes: hash_pw and ref_uid are not serialised, so
                // a posted row without them leaves the stored ones alone. Passwords change through
                // SetUserPassword / UpdatePassword, never through a row save.
                if (string.IsNullOrEmpty(user.hash_pw)) user.hash_pw = tt.hash_pw;
                if (string.IsNullOrEmpty(user.ref_uid)) user.ref_uid = tt.ref_uid;
                // Which tenant manages the account is not the console's to drop, either.
                if (string.IsNullOrEmpty(user.home_tenant_id)) user.home_tenant_id = tt.home_tenant_id;
                _ctx.ChangeTracker.Clear();
                user.id = tt.id;
                // While a password link is out, `at` is when it was issued (see UpdatePassword).
                // Stamping it on any other save gave an expired link its whole life back.
                user.at = tt.reset_mode == true && user.reset_mode == true && !string.IsNullOrEmpty(tt.at)
                    ? tt.at
                    : DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(user);
            }
            await _ctx.SaveChangesAsync();
            // Same reasoning as UpsertClient: an account switched off through a plain save has to
            // lose its live sessions and refresh tokens too, not only one switched off through
            // the activation endpoint.
            if (tt != null && tt.is_active && !user.is_active)
                await RevokeAccessForSubject(user.email);
            return user;
        }
        public Task<ArkUser> UserResetPw(ArkUser user) => UserResetPw(user, endAccess: true);

        /// <param name="user">The account, by its login id.</param>
        /// <param name="endAccess">
        /// Ends what the account has open (<see cref="EndAccessAsync"/>). False only for a caller
        /// that does that itself and reports on it.
        /// </param>
        public async Task<ArkUser> UserResetPw(ArkUser user, bool endAccess)
        {
            var login_id = (user?.email ?? "").ToLower().Trim();
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.email == login_id)
                ?? throw new ApplicationException($"unknown user '{login_id}'.");
            if (_util.ServerConfig.EffectiveUserPasswordMode == ArkUserPasswordMode.AdminManaged)
                throw new ApplicationException(
                    "password-reset emails are disabled by ark_oauth_server:UserPasswordMode; set a new password directly instead.");
            // A reset link can only be delivered to an address; a username account has no mailbox.
            if (!ark.net.util.EmailUtil.IsValidFormat(uu.email))
                throw new ApplicationException($"'{uu.email}' is a username, not an email address - it has no mailbox to send a reset link to. Set a new password directly instead.");

            var tnt = await _ctx.tenants.FirstOrDefaultAsync();
            _ctx.ChangeTracker.Clear();
            uu.reset_mode = true;
            uu.ref_uid = Guid.NewGuid().ToString();
            string email_content = await _util.GetActivationEmail(tnt.tenant_id, uu.ref_uid);
            uu.emailed = await _util.SendMail(uu.email, email_content, $"{_util.ServerConfig.EmailConfig?.subject} Reset Password", this);
            uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            _ctx.users.Update(uu);
            await _ctx.SaveChangesAsync();
            if (endAccess) await EndAccessAsync(uu.email, "password_reset");
            return uu;
        }
        /// <summary>
        /// Puts an account in the state an activation email does — it cannot sign in until its
        /// password has been set through a one-time link — and returns that link instead of
        /// mailing it, for whoever is to hand it over. An earlier link stops working.
        /// </summary>
        internal async Task<string> IssuePasswordLinkAsync(string email, string tenantId)
        {
            var login = (email ?? "").ToLower().Trim();
            var uid = Protocol.ArkCrypto.RandomToken(32);
            // values, not expressions: EF cannot translate the ToString into SQL
            var at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            var updated = await _ctx.users.Where(u => u.email == login).ExecuteUpdateAsync(s => s
                .SetProperty(u => u.ref_uid, uid)
                .SetProperty(u => u.reset_mode, true)
                .SetProperty(u => u.emailed, false)
                .SetProperty(u => u.at, at));
            if (updated == 0) throw new ApplicationException($"unknown user '{login}'.");
            _ctx.ChangeTracker.Clear();

            var format = _util.ServerConfig.EmailConfig?.activation_link;
            if (!string.IsNullOrWhiteSpace(format) && format.Contains("{1}"))
            {
                try { return string.Format(format, tenantId, uid); }
                catch (FormatException) { }
            }
            return $"{Protocol.ArkOidcEndpoints.PublicRoot(_util.ServerConfig)}/oauth/{tenantId}/v1/password/reset/{uid}";
        }
        public async Task<bool> UpdatePassword(string uq_refid, string pw)
        {
            if (string.IsNullOrEmpty(uq_refid)) throw new ApplicationException("invalid reference id, pls contact support.");
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.ref_uid == uq_refid);
            if (uu == null) throw new ApplicationException("invalid reference id, pls contact support.");
            else if (uu.reset_mode.HasValue && uu.reset_mode.Value)
            {
                // `at` is stamped when the link is issued (account creation, or UserResetPw).
                // Unreadable counts as expired: failing closed costs one re-sent email.
                var hours = _util.ServerConfig.PasswordLinkLifetimeHours;
                if (hours > 0)
                {
                    var issued = DateTime.TryParse(uu.at, System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                        out var at) ? at : DateTime.MinValue;
                    if (DateTime.UtcNow - issued > TimeSpan.FromHours(hours))
                        throw new ApplicationException("this link has expired - ask your administrator to send a new one.");
                }
                _ctx.ChangeTracker.Clear();
                uu.reset_mode = false;
                // Spent: the link that set this password must not be the key to the next reset.
                uu.ref_uid = Guid.NewGuid().ToString();
                uu.hash_pw = _util.HashPasswordPBKDF2(pw);
                uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(uu);
                await _ctx.SaveChangesAsync();
                await EndAccessAsync(uu.email, "password_change");
            }
            else throw new ApplicationException("reset request expired, pls contact support.");
            return true;
        }
        /// <summary>Stores a service account's token digest (<see cref="ArkUtil.ServiceTokenDigest"/>).</summary>
        public async Task SetServiceToken(string email, string digest)
        {
            // a value, not an expression: EF cannot translate the ToString into SQL
            var at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            var updated = await _ctx.users.Where(t => t.email == email && t.type == "service")
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.hash_pw, digest)
                    .SetProperty(t => t.at, at));
            if (updated == 0) throw new ApplicationException($"'{email}' is not a service account.");
        }
        public Task<ArkUser> SetUserPassword(string email, string pw) => SetUserPassword(email, pw, endAccess: true);

        /// <param name="email">The account's login id.</param>
        /// <param name="pw">The new password.</param>
        /// <param name="endAccess">As on <see cref="UserResetPw(ArkUser, bool)"/>.</param>
        public async Task<ArkUser> SetUserPassword(string email, string pw, bool endAccess)
        {
            var login_id = (email ?? "").ToLower().Trim();
            if (string.IsNullOrWhiteSpace(login_id)) throw new ApplicationException("a username or email is required.");
            if (string.IsNullOrWhiteSpace(pw)) throw new ApplicationException("empty password.");

            var uu = await _ctx.users.FirstOrDefaultAsync(t => (t.email ?? "") == login_id)
                ?? throw new ApplicationException($"unknown user '{login_id}'.");

            _ctx.ChangeTracker.Clear();
            uu.hash_pw = _util.HashPasswordPBKDF2(pw);
            uu.reset_mode = false;
            uu.emailed = false;
            uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            _ctx.users.Update(uu);
            await _ctx.SaveChangesAsync();
            if (endAccess) await EndAccessAsync(uu.email, "password_change");
            return uu;
        }
        /// <summary>
        /// Verifies a sign-in and, separately, that both the account and the application it is
        /// signing in to are still active.
        ///
        /// The order of the checks is the whole point. Every credentials failure — unknown user,
        /// wrong password, no access mapping — throws the same
        /// <see cref="ApplicationException"/> and the sign-in page renders one message for all of
        /// them, so the form cannot be used to work out which usernames exist. Deactivation is
        /// different: it is not something a password can fix, and leaving the user to retype
        /// credentials that are actually correct is the kind of "gentle" failure that costs a
        /// support call. So the two activation switches are reported by their own exception type
        /// (<see cref="ArkAccountInactiveException"/>) with the level that is off — but only
        /// <b>after</b> the password has been verified, which is what keeps the distinction from
        /// becoming an account oracle for anyone who does not already hold the credentials.
        ///
        /// A deactivated <i>client</i> never reaches here: the authorization endpoint refuses it
        /// before the sign-in page is drawn at all. The check below is the backstop for the v1
        /// endpoint, which posts credentials straight in.
        /// </summary>
        public async Task<ArkUser> ValidateUserCreds(string un, string pw, string client, string tenant_id)
        {
            if ((un ?? "").Length > MaxLoginLength || (pw ?? "").Length > MaxPasswordLength)
                throw new ApplicationException("invalid creds");
            var login_id = (un ?? "").ToLower().Trim();
            // Three index lookups. These were three synchronous reads of whole tables — every
            // account, then every access mapping — once per sign-in, on a request thread.
            var usr = await Protocol.ArkLookup.UserAsync(_ctx, login_id);
            var clnt = await Protocol.ArkIdpCache.ClientAsync(_ctx, tenant_id, client);
            var usr_cl_cl = usr == null || clnt == null ? null
                : await Protocol.ArkLookup.MappingAsync(_ctx, usr.email, clnt.tenant_id, clnt.id);
            // One hash on every path. Returning before it for an unknown account or a missing
            // mapping answered in a fraction of the time a wrong password took, which named the
            // accounts that exist even though the message is the same.
            //
            // Through the gate: this is the expensive step of a sign-in, and a few hundred of them
            // arriving together must not take every thread the server has (ArkHashGate).
            Protocol.ArkHashGate.Configure(_util.ServerConfig.Oidc?.MaxConcurrentPasswordHashes ?? 0,
                _util.ServerConfig.Oidc?.MaxPasswordHashWaitSeconds ?? 0);
            var stored = usr_cl_cl != null ? usr!.hash_pw ?? "" : ArkUtil.DummyPasswordHash.Value;
            // Attempts at one login take turns, and the count is read again when the turn comes: read
            // only before the queue, it is the same for every attempt of a burst (ArkSignInQueue).
            using var turn = await Protocol.ArkSignInQueue.EnterAsync(login_id);
            var limits = _util.ServerConfig.Oidc ?? new Protocol.ArkOidcOptions();
            if (limits.MaxFailedSignIns > 0 && await GetAuthStatus(login_id) is { } status
                && status.retry_count >= limits.MaxFailedSignIns && (DateTime.UtcNow - status.at).TotalMinutes < limits.LockoutMinutes)
                throw new Protocol.ArkAccountLockedException(limits.LockoutMinutes);
            var verified = await Protocol.ArkHashGate.RunAsync(() => _util.VerifyPasswordPBKDF2(pw, stored));
            // Every failure counts towards the lockout, not only a wrong password for an account
            // that exists and is mapped. Counting only those made the lockout message itself the
            // account oracle the single error message exists to prevent: ten bad tries named a
            // real, mapped account ("Too many failed attempts") and left an unknown one on
            // "not recognised" for ever.
            if (usr == null || clnt == null || usr_cl_cl == null || !verified)
                await UpdateStatus(login_id, retry: "increment");
            if (usr == null) throw new ApplicationException("invalid creds");
            if (clnt == null) throw new ApplicationException("invalid creds client");
            if (usr_cl_cl == null) throw new ApplicationException("invalid creds client.");
            if (!verified) throw new ApplicationException("invalid creds.");
            await UpdateStatus(login_id, retry: "reset");
            if (ArkUtil.IsLegacyPasswordHash(usr.hash_pw))
            {
                // The password is in hand only now, so this is the one place the original
                // 100,000-iteration hash can be rewritten. Best effort: it never fails a sign-in.
                try
                {
                    var upgraded = _util.HashPasswordPBKDF2(pw);
                    await _ctx.users.Where(t => t.email == usr.email)
                        .ExecuteUpdateAsync(s => s.SetProperty(t => t.hash_pw, upgraded));
                }
                catch (Exception ex)
                {
                    LogError(ex, "password_rehash", "signin", $"user: {login_id}");
                }
            }
            if (!clnt.is_active)
                throw new ArkAccountInactiveException(ArkActivationLevel.Client,
                    string.IsNullOrWhiteSpace(clnt.display) ? clnt.client_id : clnt.display);
            if (!usr.is_active)
                throw new ArkAccountInactiveException(ArkActivationLevel.User, usr.name ?? usr.email);
            return usr;
        }
        /// <summary>
        /// Turns a client on or off, and — when turning it off — stops the access it has already
        /// handed out.
        ///
        /// Flipping the flag alone only closes the front door: existing refresh tokens keep
        /// minting access tokens for as long as they live (14 days by default), so an application
        /// "deactivated" in the console would carry on working for a fortnight. Revoking the
        /// client's refresh-token families is what makes the switch mean what it reads like.
        /// Access tokens already issued are self-contained and stay valid until they expire —
        /// an hour by default — which is the normal bound on any JWT-based revocation.
        /// </summary>
        public async Task<ArkClient> SetClientActive(string tenant_id, string client_id, bool active)
        {
            var cc = await GetClient(tenant_id, client_id)
                ?? throw new ApplicationException($"unknown client '{client_id}' in tenant '{tenant_id}'.");
            if (cc.is_active == active) return cc;

            _ctx.ChangeTracker.Clear();
            cc.is_active = active;
            cc.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            _ctx.clients.Update(cc);
            await _ctx.SaveChangesAsync();

            if (!active) await RevokeRefreshTokensForClient(cc.tenant_id, cc.client_id);
            return cc;
        }
        /// <summary>
        /// Turns an account on or off across every client on the server.
        ///
        /// Deactivating also ends the user's IdP sessions and revokes their refresh tokens, for
        /// the same reason as <see cref="SetClientActive"/>: a signed-in browser holds a session
        /// cookie that skips the sign-in page entirely, so without this the switch would not take
        /// effect until that session aged out.
        /// </summary>
        public async Task<ArkUser> SetUserActive(string email, bool active)
        {
            var login_id = (email ?? "").ToLower().Trim();
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.email == login_id)
                ?? throw new ApplicationException($"unknown user '{login_id}'.");
            if (uu.is_active == active) return uu;

            _ctx.ChangeTracker.Clear();
            uu.is_active = active;
            // Not while a password link is out: there `at` is the link's clock (UpsertUser).
            if (uu.reset_mode != true) uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            _ctx.users.Update(uu);
            await _ctx.SaveChangesAsync();

            if (!active) await RevokeAccessForSubject(uu.email);
            return uu;
        }
        /// <summary>
        /// Ends what an account has open after its password changed, and tells the applications
        /// that asked to be told.
        ///
        /// A password is changed because somebody else may know it. Whoever signed in with the old
        /// one kept a session and refresh tokens that never ask for a password again, so changing
        /// it shut out nobody until those ran out.
        /// </summary>
        async Task EndAccessAsync(string subject, string reason)
        {
            var now = DateTime.UtcNow;
            _ctx.ChangeTracker.Clear();
            var open = await _ctx.sessions.AsNoTracking()
                .Where(s => s.subject == subject && !s.revoked && s.expires_at > now).ToListAsync();
            await RevokeAccessForSubject(subject);
            if (open.Count == 0) return;
            try
            {
                var http = _watch?.Request();
                if (http?.RequestServices.GetService(typeof(Protocol.ArkBackChannelLogout)) is Protocol.ArkBackChannelLogout logout)
                    await logout.NotifyAsync(open, tid => Protocol.ArkOidcEndpoints.For(http.Request, _util.ServerConfig, tid).Issuer, reason);
            }
            catch (Exception ex)
            {
                // The access is already gone; that some application could not be told is all that
                // is left to record.
                LogError(ex, "backchannel_logout_failed", subject, $"applications could not be notified of a {reason}");
            }
        }
        /// <summary>Ends every live session for a subject and revokes the refresh tokens issued under them.</summary>
        async Task RevokeAccessForSubject(string subject)
        {
            _ctx.ChangeTracker.Clear();
            // Two UPDATEs, each by an index on subject. Loading the rows first to flip a flag on
            // each is what this did, and one account's rotated tokens run to hundreds of rows.
            await _ctx.sessions.Where(s => s.subject == subject && !s.revoked)
                .ExecuteUpdateAsync(u => u.SetProperty(s => s.revoked, true));
            await _ctx.refresh_tokens.Where(t => t.subject == subject && !t.revoked)
                .ExecuteUpdateAsync(u => u.SetProperty(t => t.revoked, true));
        }
        /// <summary>Revokes every live refresh token issued to one client.</summary>
        async Task RevokeRefreshTokensForClient(string tenant_id, string client_id)
        {
            _ctx.ChangeTracker.Clear();
            // One UPDATE. Deactivating an application everybody uses would otherwise pull a row
            // per signed-in user, per refresh, into memory to write each one back.
            await _ctx.refresh_tokens
                .Where(t => t.tenant_id == tenant_id && t.client_id == client_id && !t.revoked)
                .ExecuteUpdateAsync(u => u.SetProperty(t => t.revoked, true));
        }
        public async Task<PkceCodeFlow?> GetPkceCode(string code, bool invalidate = false)
        {
            var tt = await _ctx.pkce_code_flow.FirstOrDefaultAsync(t => t.code == code && !t.inactivate);
            if (invalidate)
            {
                tt.inactivate = true;
                _ctx.pkce_code_flow.Update(tt);
                await _ctx.SaveChangesAsync();
            }
            return tt;
        }
        public async Task UpsertPkceCode(string token, ArkTenant tenant, string code, string code_challenge, string code_challenge_method, string state, string scopes, string claims, DateTime expires_at, string redirect_uri, string response_type)
        {
            _ctx.pkce_code_flow.Add(new PkceCodeFlow()
            {
                access_token = token,
                audience = tenant.audience,
                client_id = tenant.tenant_id,
                code = code,
                code_challenge = code_challenge,
                code_challenge_method = code_challenge_method,
                state = state,
                refresh_token = Guid.NewGuid().ToString(),
                scopes = scopes,
                claims = claims,
                expires_at = expires_at,
                created_at = DateTime.UtcNow,
                redirect_uri = redirect_uri,
                response_type = response_type
            });
            await _ctx.SaveChangesAsync();
        }
        public async Task ExecuteRaw(string sql)
        {
            _ctx.Database.ExecuteSqlRaw(sql);
        }
        public async Task EnsureCreatedAsync()
        {
            await _ctx.Database.EnsureCreatedAsync();
        }
        public void Log(string? ref_key, string? ref_val, string? message, string? details, string? log_type = "trace") =>
            Log(ref_key, ref_val, message, details, log_type, null);

        /// <summary>
        /// The same line, with the event to send to the audit server in its place. A site that
        /// knows more than a sentence can say — who called whom, for which user, with which
        /// token — passes <paramref name="watch"/>; without one the event is derived from the
        /// line (see <see cref="ArkWatchMap"/>). The audit server is sent the event whatever
        /// <c>EnableLogTrace</c> says: that switch is about this database's own trace.
        /// </summary>
        public void Log(string? ref_key, string? ref_val, string? message, string? details, string? log_type, ArkWatchEvent? watch)
        {
            if (_watch is { Enabled: true })
            {
                try { _watch.Log(null, watch ?? ArkWatchMap.FromRow(ref_key, ref_val, message, details, log_type)); }
                catch { /* the trail is never a reason to fail */ }
            }
            try
            {
                if (!_util.IsTraceEnabled) return;
                var row = ArkAuditWriter.Storable(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = log_type,
                    message = message,
                    details = details,
                    by = "ark_admin",
                    ip = "",
                    at = DateTime.UtcNow
                });
                // Queued and written in batches off the request path when the writer is running.
                if (_audit != null && _audit.TryEnqueue(row)) return;
                _ctx.audit_trace.Add(row);
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        /// <summary>
        /// An audit row written whatever <c>EnableLogTrace</c> says, naming who did it.
        ///
        /// For the operations that change the deployment as a whole — an import, a factory reset.
        /// <see cref="Log"/> is a trace and is off on most production servers, which would leave
        /// "who emptied the database" with no answer at exactly the moment it is asked.
        /// </summary>
        public void Record(string? ref_key, string? ref_val, string? message, string? details, string? by, string? ip) =>
            Record(ref_key, ref_val, message, details, by, ip, null);

        /// <summary>The same row, with the event to send to the audit server in its place.</summary>
        public void Record(string? ref_key, string? ref_val, string? message, string? details, string? by, string? ip, ArkWatchEvent? watch)
        {
            if (_watch is { Enabled: true })
            {
                try { _watch.Log(null, watch ?? ArkWatchMap.FromRow(ref_key, ref_val, message, details, "audit", by)); }
                catch { /* the trail is never a reason to fail */ }
            }
            try
            {
                _ctx.ChangeTracker.Clear();
                _ctx.audit_trace.Add(ArkAuditWriter.Storable(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = "audit",
                    message = message,
                    details = details,
                    by = string.IsNullOrWhiteSpace(by) ? "ark_admin" : by,
                    ip = ip ?? "",
                    at = DateTime.UtcNow
                }));
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        public void LogError(Exception exp, string? ref_key, string? ref_val, string? message)
        {
            if (_watch is { Enabled: true })
            {
                try { _watch.Log(null, ArkWatchMap.FromError(exp, ref_key, ref_val, message)); }
                catch { /* the trail is never a reason to fail */ }
            }
            try
            {
                var row = ArkAuditWriter.Storable(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = "error",
                    message = message,
                    details = exp.ToString(),
                    by = "ark_admin",
                    ip = "",
                    at = DateTime.UtcNow
                });
                if (_audit != null && _audit.TryEnqueue(row)) return;
                // Cleared first, then added. It was the other way round, which threw the error row
                // away with everything else in the tracker: no error was ever written.
                _ctx.ChangeTracker.Clear();
                _ctx.audit_trace.Add(row);
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        /// <summary>Longer than any login id or password there is: an email address has at most 320 characters.</summary>
        internal const int MaxLoginLength = 320, MaxPasswordLength = 1024;

        /// <summary>The failed-sign-in counter for a login id, or null when it has never failed.</summary>
        public async Task<ArkAuthStatusTrace?> GetAuthStatus(string? email)
        {
            var login = (email ?? "").ToLower().Trim();
            if (login.Length == 0) return null;
            // Written lower-case and trimmed by UpdateStatus, so the unique index answers this.
            return await _ctx.auth_status.AsNoTracking().FirstOrDefaultAsync(s => s.email == login);
        }

        /// <summary>
        /// Counts a failed sign-in ("increment") or clears the count after a good one ("reset").
        ///
        /// Each is one statement the database applies atomically. The count used to be read,
        /// changed in memory and written back, so a burst of concurrent guesses at one account —
        /// which is what a password-guessing run is — all read the same number and the lockout
        /// counted a fraction of them. And a successful sign-in used to insert or rewrite a row
        /// for every user every time; now it touches nothing unless there is a count to clear.
        /// </summary>
        public async Task UpdateStatus(string email, string retry = "reset")
        {
            try
            {
                var login = (email ?? "").ToLower().Trim();
                if (login.Length == 0) return;
                var now = DateTime.UtcNow;

                if (retry != "increment")
                {
                    await _ctx.auth_status.Where(t => t.email == login && t.retry_count != 0)
                        .ExecuteUpdateAsync(s => s.SetProperty(t => t.retry_count, 0).SetProperty(t => t.at, now));
                    return;
                }

                var counted = await _ctx.auth_status.Where(t => t.email == login)
                    .ExecuteUpdateAsync(s => s.SetProperty(t => t.retry_count, t => t.retry_count + 1).SetProperty(t => t.at, now));
                if (counted > 0) return;

                var first = new ArkAuthStatusTrace()
                {
                    email = login,
                    retry_count = 1,
                    complex_policy = true,
                    ip = "IP",
                    at = now
                };
                _ctx.auth_status.Add(first);
                try
                {
                    await _ctx.SaveChangesAsync();
                }
                catch (DbUpdateException)
                {
                    // Two first failures for one login raced and the other insert won (email is
                    // unique). Count this one against the row that is now there.
                    _ctx.Entry(first).State = EntityState.Detached;
                    await _ctx.auth_status.Where(t => t.email == login)
                        .ExecuteUpdateAsync(s => s.SetProperty(t => t.retry_count, t => t.retry_count + 1).SetProperty(t => t.at, now));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
