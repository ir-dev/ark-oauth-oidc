using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// Access tokens for endpoints that authenticate with OAuth 2.0 — a refresh token or client
    /// credentials exchanged at the receiver's token endpoint.
    ///
    /// The token is kept on the endpoint row (encrypted) as well as in memory, and a refresh is
    /// taken under a lease on that row. Both matter once there is more than one instance: a
    /// refresh token that rotates can be spent exactly once, so two instances refreshing at the
    /// same time would leave one of them — and, at a server with reuse detection, both — holding a
    /// revoked token. With the lease, one instance refreshes and writes the new pair; the rest read it.
    /// </summary>
    public sealed class ArkWebhookTokenManager
    {
        private static readonly TimeSpan EarlyRefresh = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan LockFor = TimeSpan.FromSeconds(30);

        private readonly ArkWebhookDatabases _dbs;
        private readonly ArkWebhookSecrets _secrets;
        private readonly IHttpClientFactory _http;
        private readonly ArkWebhookRegistry _registry;
        private readonly ILogger<ArkWebhookTokenManager> _log;
        private readonly ConcurrentDictionary<string, (string Token, DateTime ExpiresAt)> _memory = new();
        private readonly ConcurrentDictionary<string, string> _rejected = new();

        public ArkWebhookTokenManager(ArkWebhookDatabases dbs, ArkWebhookSecrets secrets, IHttpClientFactory http,
            ArkWebhookRegistry registry, ILogger<ArkWebhookTokenManager> log)
        {
            _dbs = dbs;
            _secrets = secrets;
            _http = http;
            _registry = registry;
            _log = log;
        }

        public string Worker { get; set; } = Environment.MachineName;

        /// <summary>The receiver refused this token: never hand it out again.</summary>
        public void Reject(string endpointId, string token)
        {
            _rejected[endpointId] = token;
            _memory.TryRemove(endpointId, out _);
        }

        /// <summary>Forgets everything about an endpoint's token (its credentials changed).</summary>
        public void Forget(string endpointId)
        {
            _memory.TryRemove(endpointId, out _);
            _rejected.TryRemove(endpointId, out _);
        }

        private bool Usable(string endpointId, string? token, DateTime expiresAt) =>
            !string.IsNullOrEmpty(token)
            && expiresAt - EarlyRefresh > DateTime.UtcNow
            && !(_rejected.TryGetValue(endpointId, out var bad) && bad == token);

        public async Task<string> GetAsync(ArkWebhookEndpointView ep, ArkWebhookSecretBag bag, CancellationToken ct)
        {
            if (_memory.TryGetValue(ep.Id, out var cached) && Usable(ep.Id, cached.Token, cached.ExpiresAt))
                return cached.Token;

            for (var round = 0; round < 40; round++)
            {
                await using var ctl = _dbs.Control();
                var row = await ctl.endpoints.AsNoTracking().Where(e => e.id == ep.Id)
                    .Select(e => new { e.token_state_, e.token_lock_until })
                    .FirstOrDefaultAsync(ct)
                    ?? throw new ArkWebhookException("endpoint_gone", "the endpoint no longer exists.");
                var state = _secrets.UnprotectToken(row.token_state_);
                if (state != null && Usable(ep.Id, state.access_token, state.expires_at))
                {
                    _memory[ep.Id] = (state.access_token!, state.expires_at);
                    return state.access_token!;
                }

                var now = DateTime.UtcNow;
                var until = now + LockFor;
                var worker = Worker;
                var taken = await ctl.endpoints
                    .Where(e => e.id == ep.Id && (e.token_lock_until == null || e.token_lock_until < now))
                    .ExecuteUpdateAsync(s => s.SetProperty(e => e.token_lock_by, worker).SetProperty(e => e.token_lock_until, until), ct);
                if (taken == 1)
                {
                    try
                    {
                        // Read again under the lease: the previous holder may have just written one.
                        var fresh = await ctl.endpoints.AsNoTracking().Where(e => e.id == ep.Id)
                            .Select(e => e.token_state_).FirstOrDefaultAsync(ct);
                        var current = _secrets.UnprotectToken(fresh);
                        if (current != null && Usable(ep.Id, current.access_token, current.expires_at))
                        {
                            _memory[ep.Id] = (current.access_token!, current.expires_at);
                            return current.access_token!;
                        }

                        var next = await RequestAsync(ep.Auth, bag, current?.refresh_token ?? bag.oauth_refresh_token, ct);
                        var blob = _secrets.ProtectToken(next);
                        await ctl.endpoints.Where(e => e.id == ep.Id && e.token_lock_by == worker)
                            .ExecuteUpdateAsync(s => s.SetProperty(e => e.token_state_, blob), ct);
                        _memory[ep.Id] = (next.access_token!, next.expires_at);
                        _rejected.TryRemove(ep.Id, out _);
                        return next.access_token!;
                    }
                    finally
                    {
                        try
                        {
                            await ctl.endpoints.Where(e => e.id == ep.Id && e.token_lock_by == worker)
                                .ExecuteUpdateAsync(s => s.SetProperty(e => e.token_lock_by, (string?)null).SetProperty(e => e.token_lock_until, (DateTime?)null), CancellationToken.None);
                        }
                        catch (Exception ex) { _log.LogDebug(ex, "Ark webhooks could not release a token lease; it lapses by itself."); }
                    }
                }

                // Another instance is refreshing: its token will be on the row shortly.
                await Task.Delay(500, ct);
            }
            throw new ArkWebhookException("token_busy", "another instance is still refreshing the access token.", 503);
        }

        /// <summary>One call to the token endpoint.</summary>
        internal async Task<ArkWebhookTokenState> RequestAsync(ArkWebhookAuthConfig auth, ArkWebhookSecretBag bag, string? refreshToken, CancellationToken ct)
        {
            var problem = ArkWebhookSender.UrlProblem(auth.oauth_token_url, _registry.Options.AllowInsecureHttp);
            if (problem != null) throw new ArkWebhookException("auth_incomplete", $"token endpoint: {problem}");
            var grant = string.Equals(auth.oauth_grant, "client_credentials", StringComparison.OrdinalIgnoreCase) ? "client_credentials" : "refresh_token";

            var form = new List<KeyValuePair<string, string>> { new("grant_type", grant) };
            if (grant == "refresh_token")
            {
                if (string.IsNullOrEmpty(refreshToken))
                    throw new ArkWebhookException("auth_incomplete", "no refresh token is stored.");
                form.Add(new("refresh_token", refreshToken));
            }
            if (!string.IsNullOrWhiteSpace(auth.oauth_scope)) form.Add(new("scope", auth.oauth_scope.Trim()));
            if (!string.IsNullOrWhiteSpace(auth.oauth_audience)) form.Add(new("audience", auth.oauth_audience.Trim()));

            using var request = new HttpRequestMessage(HttpMethod.Post, auth.oauth_token_url!.Trim());
            var basic = string.Equals(auth.oauth_client_auth, "client_secret_basic", StringComparison.OrdinalIgnoreCase);
            if (basic && !string.IsNullOrEmpty(bag.oauth_client_secret))
            {
                // RFC 6749 §2.3.1: both halves form-urlencoded before they are joined.
                var raw = $"{Uri.EscapeDataString(auth.oauth_client_id ?? "")}:{Uri.EscapeDataString(bag.oauth_client_secret)}";
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(auth.oauth_client_id)) form.Add(new("client_id", auth.oauth_client_id.Trim()));
                if (!string.IsNullOrEmpty(bag.oauth_client_secret)) form.Add(new("client_secret", bag.oauth_client_secret));
            }
            request.Content = new FormUrlEncodedContent(form);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            HttpResponseMessage response;
            try
            {
                response = await _http.CreateClient(ArkWebhookSender.HttpClientName)
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
            {
                throw new ArkWebhookException("token_failed", $"the token endpoint could not be reached: {ex.GetBaseException().Message}");
            }
            using (response)
            {
                string text;
                try
                {
                    text = await ReadAnswerAsync(response, cts.Token);
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or OperationCanceledException && !ct.IsCancellationRequested)
                {
                    throw new ArkWebhookException("token_failed", $"the token endpoint's answer could not be read: {ex.GetBaseException().Message}");
                }
                JsonElement json;
                try { json = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text).RootElement.Clone(); }
                catch (JsonException) { json = default; }

                if (!response.IsSuccessStatusCode || json.ValueKind != JsonValueKind.Object || !json.TryGetProperty("access_token", out var at) || at.ValueKind != JsonValueKind.String)
                {
                    var error = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("error", out var e) ? e.ToString() : "";
                    var description = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("error_description", out var d) ? d.ToString() : "";
                    var hint = error == "invalid_grant" && grant == "refresh_token"
                        ? " - the refresh token is no longer valid; enter a new one on the endpoint."
                        : "";
                    // invalid_grant on a refresh token will not heal by itself; everything else may.
                    throw new ArkWebhookException(error == "invalid_grant" ? "token_invalid" : "token_failed",
                        $"the token endpoint answered {(int)response.StatusCode} {error} {description}".Trim() + hint);
                }

                var lifetime = json.TryGetProperty("expires_in", out var ei) && ei.ValueKind == JsonValueKind.Number && ei.TryGetInt32(out var secs) ? secs
                    : json.TryGetProperty("expires_in", out var eis) && int.TryParse(eis.ToString(), out var parsed) ? parsed
                    : 300;
                string? rotated = json.TryGetProperty("refresh_token", out var rt) && rt.ValueKind == JsonValueKind.String ? rt.GetString() : null;
                return new ArkWebhookTokenState
                {
                    access_token = at.GetString(),
                    expires_at = DateTime.UtcNow.AddSeconds(Math.Clamp(lifetime, 30, 86_400)),
                    // A server that does not rotate keeps answering to the token we already hold.
                    refresh_token = rotated ?? (grant == "refresh_token" ? refreshToken : null)
                };
            }
        }

        /// <summary>The most of a token endpoint's answer that is read. One is a few KB.</summary>
        private const int MaxAnswerBytes = 64 * 1024;

        /// <summary>
        /// The body, as the UTF-8 JSON is in whatever the answer calls itself, and no more of it
        /// than an answer can be: what arrives compressed is counted as it unpacks, so a small
        /// answer cannot become a large one in this process.
        /// </summary>
        private static async Task<string> ReadAnswerAsync(HttpResponseMessage response, CancellationToken ct)
        {
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var kept = new MemoryStream();
            var buffer = new byte[8192];
            int n;
            while ((n = await stream.ReadAsync(buffer, ct)) > 0)
            {
                if (kept.Length + n > MaxAnswerBytes)
                    throw new ArkWebhookException("token_failed", $"the token endpoint answered with more than {MaxAnswerBytes / 1024} KB.");
                kept.Write(buffer, 0, n);
            }
            return Encoding.UTF8.GetString(kept.GetBuffer(), 0, (int)kept.Length).TrimStart('﻿');
        }
    }
}
