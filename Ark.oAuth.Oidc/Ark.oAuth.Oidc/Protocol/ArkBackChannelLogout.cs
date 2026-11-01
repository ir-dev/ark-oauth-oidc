using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// What one round of back-channel logout delivery achieved, so the caller can log it and the
    /// signed-out page can say how much was actually ended.
    /// </summary>
    public class BackChannelLogoutReport
    {
        /// <summary>Sessions that were live and have now been ended.</summary>
        public int SessionsEnded { get; set; }
        /// <summary>Distinct users signed out — more than one when several people shared the browser.</summary>
        public int SubjectsEnded { get; set; }
        /// <summary>Clients that accepted their logout token.</summary>
        public int Notified { get; set; }
        /// <summary>Clients that were registered for notification and could not be reached.</summary>
        public int Failed { get; set; }
        /// <summary>Clients that took part but have no backchannel_logout_uri registered.</summary>
        public int NotRegistered { get; set; }

        public bool AnyDelivery => Notified > 0 || Failed > 0;
    }

    /// <summary>
    /// Delivers logout tokens to the clients that were logged in under a session (OIDC
    /// Back-Channel Logout 1.0).
    ///
    /// The contract this class exists to keep is that a client which is down cannot stop a user
    /// signing out. Every delivery is attempted in parallel behind its own timeout, every failure
    /// is recorded rather than raised, and the sessions are already revoked at this server before
    /// the first request goes out — so the worst outcome of an unreachable client is an
    /// application cookie that outlives the IdP session, which is exactly the state the deployment
    /// was in before this existed. It is never a user who cannot log out.
    ///
    /// Logging is deliberately done after the parallel phase, on the calling thread: the audit
    /// trail goes through the same scoped <see cref="ArkDataContext"/> as everything else here,
    /// and a DbContext written from several tasks at once corrupts its change tracker.
    /// </summary>
    public class ArkBackChannelLogout
    {
        private readonly ArkDataContext _ctx;
        private readonly ArkGrantStore _grants;
        private readonly ArkTokenService _tokens;
        private readonly IHttpClientFactory _httpFactory;
        private readonly DataAccess _da;
        private readonly IConfiguration _config;

        public ArkBackChannelLogout(ArkDataContext ctx, ArkGrantStore grants, ArkTokenService tokens,
            IHttpClientFactory httpFactory, DataAccess da, IConfiguration config)
        {
            _ctx = ctx;
            _grants = grants;
            _tokens = tokens;
            _httpFactory = httpFactory;
            _da = da;
            _config = config;
        }

        private ArkOidcOptions Options =>
            (_config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? new ArkAuthServerConfig()).Oidc
            ?? new ArkOidcOptions();

        /// <summary>
        /// Notifies every client that took part in any of <paramref name="sessions"/>.
        /// </summary>
        /// <param name="sessions">Sessions that have already been revoked at this server.</param>
        /// <param name="issuerForTenant">
        /// Resolves a tenant id to the issuer its logout tokens assert. Supplied by the caller
        /// because the issuer is derived from the incoming request when no BaseUrl is configured,
        /// and this class has no request to read.
        /// </param>
        /// <param name="reason">Recorded in the audit trail: rp_logout, user_deactivated, ...</param>
        public async Task<BackChannelLogoutReport> NotifyAsync(
            IReadOnlyCollection<ArkSession> sessions, Func<string, string> issuerForTenant, string reason)
        {
            var report = new BackChannelLogoutReport
            {
                SessionsEnded = sessions.Count,
                SubjectsEnded = sessions.Select(s => s.subject.ToLowerInvariant()).Distinct().Count()
            };
            if (sessions.Count == 0 || !Options.EnableBackChannelLogout) return report;

            var participations = await _grants.GetSessionClientsAsync(sessions.Select(s => s.session_id));
            if (participations.Count == 0) return report;

            // One query for the clients, one for the tenants, then no database work until the
            // deliveries are all in. Signing needs the tenant's active key, and ArkKeyService
            // reads it through the same context.
            var clientIds = participations.Select(p => p.client_id).Distinct().ToList();
            var clients = await _ctx.clients.AsNoTracking()
                .Where(c => clientIds.Contains(c.client_id))
                .ToListAsync();

            var tenantIds = sessions.Select(s => s.tenant_id).Distinct().ToList();
            var tenants = await _ctx.tenants.AsNoTracking()
                .Where(t => tenantIds.Contains(t.tenant_id))
                .ToListAsync();

            var sessionById = sessions.ToDictionary(s => s.session_id, StringComparer.Ordinal);
            var deliveries = new List<(ArkClient client, ArkSession session, string token)>();

            foreach (var participation in participations)
            {
                if (!sessionById.TryGetValue(participation.session_id, out var session)) continue;

                var client = clients.FirstOrDefault(c =>
                    string.Equals(c.tenant_id, session.tenant_id, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(c.client_id, participation.client_id, StringComparison.OrdinalIgnoreCase));
                if (client == null) continue;
                if (!client.SupportsBackChannelLogout) { report.NotRegistered++; continue; }

                var tenant = tenants.FirstOrDefault(t =>
                    string.Equals(t.tenant_id, session.tenant_id, StringComparison.OrdinalIgnoreCase));
                if (tenant == null) continue;

                // sid is omitted only for a client that asked not to receive one; the spec then
                // has it end every session it holds for sub.
                var sid = client.backchannel_logout_session_required ? session.session_id : null;
                var token = await _tokens.IssueLogoutTokenAsync(
                    tenant, client, issuerForTenant(session.tenant_id), session.subject, sid,
                    Options.LogoutTokenLifetimeSeconds);

                deliveries.Add((client, session, token));
            }

            if (deliveries.Count == 0) return report;

            var timeout = TimeSpan.FromSeconds(Options.BackChannelLogoutTimeoutSeconds > 0
                ? Options.BackChannelLogoutTimeoutSeconds : 5);
            var http = _httpFactory.CreateClient("ark-oidc");

            var results = await Task.WhenAll(deliveries.Select(d => PostAsync(http, d.client, d.token, timeout)));

            for (var i = 0; i < results.Length; i++)
            {
                var (client, session, _) = deliveries[i];
                var outcome = results[i];
                if (outcome.ok)
                {
                    report.Notified++;
                    _da.Log("backchannel_logout", $"{session.tenant_id}/oauth2/logout",
                        $"logout token delivered to {client.client_id}",
                        $"sid: {session.session_id}, sub: {session.subject}, reason: {reason}, status: {outcome.detail}");
                }
                else
                {
                    report.Failed++;
                    // A warning, not an error: the sign-out itself succeeded. What this records is
                    // that one application still believes the user is signed in, which is the thing
                    // an operator has to be able to find afterwards.
                    _da.Log("backchannel_logout_failed", $"{session.tenant_id}/oauth2/logout",
                        $"logout token not accepted by {client.client_id}",
                        $"sid: {session.session_id}, sub: {session.subject}, reason: {reason}, " +
                        $"uri: {client.backchannel_logout_uri}, detail: {outcome.detail}", "warn");
                }
            }

            return report;
        }

        /// <summary>
        /// POSTs one logout token, per §2.5: form-encoded, a single <c>logout_token</c> parameter,
        /// no cookies and no credentials of any kind. Never throws.
        /// </summary>
        private static async Task<(bool ok, string detail)> PostAsync(
            HttpClient http, ArkClient client, string token, TimeSpan timeout)
        {
            try
            {
                using var cts = new CancellationTokenSource(timeout);
                using var request = new HttpRequestMessage(HttpMethod.Post, client.backchannel_logout_uri)
                {
                    Content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("logout_token", token)
                    })
                };
                request.Headers.TryAddWithoutValidation("Cache-Control", "no-cache, no-store");
                request.Headers.TryAddWithoutValidation("Pragma", "no-cache");

                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

                // §2.8: 200 or 204. Anything else — including a redirect, which the spec tells the
                // client not to issue — is a failed delivery.
                var ok = response.StatusCode == System.Net.HttpStatusCode.OK
                         || response.StatusCode == System.Net.HttpStatusCode.NoContent;
                return (ok, ((int)response.StatusCode).ToString());
            }
            catch (OperationCanceledException)
            {
                return (false, $"timed out after {timeout.TotalSeconds:0.#}s");
            }
            catch (Exception ex)
            {
                return (false, ex.GetBaseException().Message);
            }
        }
    }
}
