using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Persistence and lifecycle rules for every short-lived grant artefact: authorization codes,
    /// refresh tokens, device codes, pushed authorization requests, consent and sessions.
    ///
    /// Codes and tokens are stored as SHA-256 hashes, never in the clear, so read access to the
    /// database does not yield redeemable credentials.
    /// </summary>
    public class ArkGrantStore
    {
        private readonly ArkDataContext _ctx;

        public ArkGrantStore(ArkDataContext ctx)
        {
            _ctx = ctx;
        }

        private static string Hash(string value) => ArkCrypto.Sha256Base64Url(value);

        // -----------------------------------------------------------------
        // Authorization codes
        // -----------------------------------------------------------------

        public async Task<string> CreateAuthCodeAsync(ArkClient client, string tenantId, string subject,
            string redirectUri, List<string> scopes, string? codeChallenge, string? codeChallengeMethod,
            string? nonce, string? sessionId, DateTime authTime)
        {
            var code = ArkCrypto.RandomToken(32);
            _ctx.auth_codes.Add(new ArkAuthCode
            {
                code_hash = Hash(code),
                tenant_id = tenantId,
                client_id = client.client_id,
                subject = subject,
                session_id = sessionId,
                redirect_uri = redirectUri,
                scope = string.Join(" ", scopes),
                code_challenge = codeChallenge,
                code_challenge_method = codeChallengeMethod,
                nonce = nonce,
                auth_time = authTime,
                created_at = DateTime.UtcNow,
                expires_at = DateTime.UtcNow.AddSeconds(client.authorization_code_lifetime_seconds)
            });
            await _ctx.SaveChangesAsync();
            return code;
        }

        /// <summary>
        /// Redeems an authorization code, enforcing single use, expiry, client binding,
        /// redirect_uri binding and — the part that was previously missing entirely — PKCE.
        /// </summary>
        /// <param name="enforceVerifierFormat">
        /// Set false only by the /v1 compatibility endpoint. Clients built against the original
        /// Ark client library send a short, non-conforming verifier; the challenge is still
        /// checked, only the RFC 7636 §4.1 length/charset rule is skipped so those deployments
        /// keep working while they upgrade.
        /// </param>
        public async Task<ArkAuthCode> ConsumeAuthCodeAsync(string code, ArkClient client, string? redirectUri,
            string? codeVerifier, bool enforceVerifierFormat = true)
        {
            var hash = Hash(code);
            var entry = await _ctx.auth_codes.FirstOrDefaultAsync(c => c.code_hash == hash)
                ?? throw OAuthException.InvalidGrant("authorization code is invalid.");

            if (entry.consumed)
            {
                // A code replay means the code leaked. Everything issued from it is suspect.
                await RevokeTokensForSessionAsync(entry.session_id);
                await _ctx.SaveChangesAsync();
                throw OAuthException.InvalidGrant("authorization code has already been used.");
            }
            if (entry.expires_at <= DateTime.UtcNow)
                throw OAuthException.InvalidGrant("authorization code has expired.");
            if (!string.Equals(entry.client_id, client.client_id, StringComparison.OrdinalIgnoreCase))
                throw OAuthException.InvalidGrant("authorization code was issued to a different client.");

            // RFC 6749 §4.1.3: redirect_uri is required at the token endpoint when it was
            // present in the authorization request, and must match.
            if (!string.IsNullOrEmpty(entry.redirect_uri))
            {
                if (string.IsNullOrEmpty(redirectUri))
                    throw OAuthException.InvalidGrant("redirect_uri is required.");
                if (!string.Equals(entry.redirect_uri, redirectUri, StringComparison.Ordinal))
                    throw OAuthException.InvalidGrant("redirect_uri does not match the authorization request.");
            }

            VerifyPkce(entry, client, codeVerifier, enforceVerifierFormat);

            entry.consumed = true;
            _ctx.auth_codes.Update(entry);
            await _ctx.SaveChangesAsync();
            return entry;
        }

        /// <summary>
        /// PKCE verification (RFC 7636 §4.6). A public client must always present a verifier;
        /// a confidential client must too whenever it sent a challenge.
        /// </summary>
        private static void VerifyPkce(ArkAuthCode entry, ArkClient client, string? codeVerifier, bool enforceFormat)
        {
            if (string.IsNullOrEmpty(entry.code_challenge))
            {
                if (client.require_pkce || client.IsPublicClient)
                    throw OAuthException.InvalidGrant("PKCE is required for this client but no code_challenge was sent.");
                return;
            }

            if (string.IsNullOrEmpty(codeVerifier))
                throw OAuthException.InvalidGrant("code_verifier is required.");

            if (enforceFormat)
            {
                // RFC 7636 §4.1: 43..128 characters from the unreserved set.
                if (codeVerifier.Length < 43 || codeVerifier.Length > 128)
                    throw OAuthException.InvalidGrant("code_verifier must be between 43 and 128 characters.");
                foreach (var ch in codeVerifier)
                {
                    var ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                             || ch == '-' || ch == '.' || ch == '_' || ch == '~';
                    if (!ok) throw OAuthException.InvalidGrant("code_verifier contains characters outside the unreserved set.");
                }
            }

            var method = string.IsNullOrEmpty(entry.code_challenge_method) ? "plain" : entry.code_challenge_method;
            string computed = method.ToUpperInvariant() switch
            {
                "S256" => ArkCrypto.Sha256Base64Url(codeVerifier),
                "PLAIN" => codeVerifier,
                _ => throw OAuthException.InvalidGrant($"unsupported code_challenge_method '{method}'.")
            };

            if (!ArkCrypto.FixedTimeEquals(computed, entry.code_challenge))
                throw OAuthException.InvalidGrant("code_verifier does not match the code_challenge.");
        }

        // -----------------------------------------------------------------
        // Refresh tokens
        // -----------------------------------------------------------------

        public async Task<string> CreateRefreshTokenAsync(ArkClient client, string tenantId, string subject,
            List<string> scopes, string? sessionId, string? familyId = null)
        {
            var token = ArkCrypto.RandomToken(32);
            _ctx.refresh_tokens.Add(new ArkRefreshToken
            {
                token_hash = Hash(token),
                family_id = familyId ?? Guid.NewGuid().ToString("N"),
                tenant_id = tenantId,
                client_id = client.client_id,
                subject = subject,
                session_id = sessionId,
                scope = string.Join(" ", scopes),
                created_at = DateTime.UtcNow,
                expires_at = DateTime.UtcNow.AddSeconds(client.refresh_token_lifetime_seconds)
            });
            await _ctx.SaveChangesAsync();
            return token;
        }

        /// <summary>
        /// Redeems a refresh token.
        ///
        /// Replay handling is the important behaviour: presenting a token that has already been
        /// rotated away means either the client or an attacker holds a stale copy, and there is no
        /// way to tell which. Per OAuth 2.1 §4.14.2 the whole family is revoked, which logs the
        /// attacker out along with the legitimate client rather than letting theft persist.
        /// </summary>
        public async Task<ArkRefreshToken> RedeemRefreshTokenAsync(string token, ArkClient client)
        {
            var hash = Hash(token);
            var entry = await _ctx.refresh_tokens.FirstOrDefaultAsync(t => t.token_hash == hash)
                ?? throw OAuthException.InvalidGrant("refresh token is invalid.");

            if (entry.consumed_at != null)
            {
                await RevokeFamilyAsync(entry.family_id);
                throw OAuthException.InvalidGrant("refresh token has already been used; the token family has been revoked.");
            }
            if (entry.revoked)
                throw OAuthException.InvalidGrant("refresh token has been revoked.");
            if (entry.expires_at <= DateTime.UtcNow)
                throw OAuthException.InvalidGrant("refresh token has expired.");
            if (!string.Equals(entry.client_id, client.client_id, StringComparison.OrdinalIgnoreCase))
                throw OAuthException.InvalidGrant("refresh token was issued to a different client.");

            if (client.refresh_token_rotation)
            {
                entry.consumed_at = DateTime.UtcNow;
                _ctx.refresh_tokens.Update(entry);
                await _ctx.SaveChangesAsync();
            }
            return entry;
        }

        public async Task RevokeFamilyAsync(string familyId)
        {
            var family = await _ctx.refresh_tokens.Where(t => t.family_id == familyId && !t.revoked).ToListAsync();
            foreach (var t in family) t.revoked = true;
            if (family.Count > 0)
            {
                _ctx.refresh_tokens.UpdateRange(family);
                await _ctx.SaveChangesAsync();
            }
        }

        /// <summary>Revokes a refresh token by value. Returns false when the token is unknown.</summary>
        public async Task<bool> RevokeRefreshTokenAsync(string token, string? clientId = null)
        {
            var hash = Hash(token);
            var entry = await _ctx.refresh_tokens.FirstOrDefaultAsync(t => t.token_hash == hash);
            if (entry == null) return false;
            if (clientId != null && !string.Equals(entry.client_id, clientId, StringComparison.OrdinalIgnoreCase))
                return false;
            await RevokeFamilyAsync(entry.family_id);
            return true;
        }

        public async Task<ArkRefreshToken?> FindRefreshTokenAsync(string token)
        {
            var hash = Hash(token);
            return await _ctx.refresh_tokens.AsNoTracking().FirstOrDefaultAsync(t => t.token_hash == hash);
        }

        public async Task RevokeTokensForSessionAsync(string? sessionId)
        {
            if (string.IsNullOrEmpty(sessionId)) return;
            var tokens = await _ctx.refresh_tokens.Where(t => t.session_id == sessionId && !t.revoked).ToListAsync();
            foreach (var t in tokens) t.revoked = true;
            if (tokens.Count > 0) _ctx.refresh_tokens.UpdateRange(tokens);
        }

        // -----------------------------------------------------------------
        // Device authorization grant (RFC 8628)
        // -----------------------------------------------------------------

        public async Task<(string deviceCode, string userCode, ArkDeviceCode entry)> CreateDeviceCodeAsync(
            ArkClient client, string tenantId, List<string> scopes, int lifetimeSeconds, int intervalSeconds)
        {
            var deviceCode = ArkCrypto.RandomToken(32);
            string userCode;
            var attempts = 0;
            do
            {
                userCode = ArkCrypto.NewUserCode();
                attempts++;
            }
            while (attempts < 10 && await _ctx.device_codes.AnyAsync(d => d.user_code == userCode));

            var entry = new ArkDeviceCode
            {
                device_code_hash = Hash(deviceCode),
                user_code = userCode,
                tenant_id = tenantId,
                client_id = client.client_id,
                scope = string.Join(" ", scopes),
                status = "pending",
                interval_seconds = intervalSeconds,
                created_at = DateTime.UtcNow,
                expires_at = DateTime.UtcNow.AddSeconds(lifetimeSeconds)
            };
            _ctx.device_codes.Add(entry);
            await _ctx.SaveChangesAsync();
            return (deviceCode, userCode, entry);
        }

        /// <summary>
        /// Polls a device code. Returns the approved entry, or throws the RFC 8628 §3.5 signal
        /// the device is expected to act on (authorization_pending / slow_down / expired_token).
        /// </summary>
        public async Task<ArkDeviceCode> PollDeviceCodeAsync(string deviceCode, ArkClient client)
        {
            var hash = Hash(deviceCode);
            var entry = await _ctx.device_codes.FirstOrDefaultAsync(d => d.device_code_hash == hash)
                ?? throw OAuthException.InvalidGrant("device_code is invalid.");

            if (!string.Equals(entry.client_id, client.client_id, StringComparison.OrdinalIgnoreCase))
                throw OAuthException.InvalidGrant("device_code was issued to a different client.");
            if (entry.expires_at <= DateTime.UtcNow)
                throw new OAuthException(OAuthErrorCodes.ExpiredToken, "device_code has expired.");

            // enforce the polling interval; polling too fast earns a slow_down and a wider interval
            var now = DateTime.UtcNow;
            if (entry.last_polled_at != null && (now - entry.last_polled_at.Value).TotalSeconds < entry.interval_seconds)
            {
                entry.interval_seconds += 5;
                entry.last_polled_at = now;
                _ctx.device_codes.Update(entry);
                await _ctx.SaveChangesAsync();
                throw new OAuthException(OAuthErrorCodes.SlowDown, "polling too frequently; increase the interval.");
            }
            entry.last_polled_at = now;
            _ctx.device_codes.Update(entry);
            await _ctx.SaveChangesAsync();

            if (entry.status == "denied")
                throw new OAuthException(OAuthErrorCodes.AccessDenied, "the user denied the request.");
            if (entry.status != "approved")
                throw new OAuthException(OAuthErrorCodes.AuthorizationPending, "the user has not yet approved the request.");

            _ctx.device_codes.Remove(entry); // single use
            await _ctx.SaveChangesAsync();
            return entry;
        }

        public async Task<ArkDeviceCode?> FindDeviceCodeByUserCodeAsync(string userCode)
        {
            var normalized = ArkCrypto.NormalizeUserCode(userCode);
            var formatted = normalized.Length == 8 ? $"{normalized[..4]}-{normalized[4..]}" : normalized;
            return await _ctx.device_codes.FirstOrDefaultAsync(d => d.user_code == formatted || d.user_code == normalized);
        }

        public async Task SetDeviceCodeStatusAsync(ArkDeviceCode entry, string status, string? subject, string? sessionId)
        {
            entry.status = status;
            entry.subject = subject;
            entry.session_id = sessionId;
            _ctx.device_codes.Update(entry);
            await _ctx.SaveChangesAsync();
        }

        // -----------------------------------------------------------------
        // Pushed authorization requests (RFC 9126)
        // -----------------------------------------------------------------

        public async Task<(string requestUri, DateTime expiresAt)> CreateParRequestAsync(
            ArkClient client, string tenantId, Dictionary<string, string> parameters, int lifetimeSeconds)
        {
            // RFC 9126 §2.2 mandates the urn:ietf:params:oauth:request_uri: prefix.
            var requestUri = $"urn:ietf:params:oauth:request_uri:{ArkCrypto.RandomToken(32)}";
            var expiresAt = DateTime.UtcNow.AddSeconds(lifetimeSeconds);
            _ctx.par_requests.Add(new ArkParRequest
            {
                request_uri = requestUri,
                tenant_id = tenantId,
                client_id = client.client_id,
                payload = System.Text.Json.JsonSerializer.Serialize(parameters),
                created_at = DateTime.UtcNow,
                expires_at = expiresAt
            });
            await _ctx.SaveChangesAsync();
            return (requestUri, expiresAt);
        }

        /// <summary>
        /// How long a started PAR request stays readable while the user signs in and consents.
        ///
        /// ParLifetimeSeconds bounds how long the *client* has to send the browser to /authorize
        /// — a short window, since nothing is happening in it. Once the browser has arrived, the
        /// request has to survive a human typing a password and reading a consent screen, which
        /// routinely takes longer than that.
        /// </summary>
        private static readonly TimeSpan ParInteractiveWindow = TimeSpan.FromMinutes(15);

        /// <summary>
        /// Reads a pushed authorization request without spending it.
        ///
        /// The authorization endpoint re-enters with the same request_uri on every step of the
        /// interactive round-trip: it renders the sign-in page, the browser posts back, it renders
        /// consent, the browser posts back again. Marking the request used on the first read — as
        /// this did — meant PAR could only ever complete for a user who already had a session and
        /// had already consented to every scope; any first-time authorization died on the consent
        /// post with `invalid_request_uri: request_uri has already been used`.
        ///
        /// Single use is still enforced, just at the point the request actually finishes: see
        /// <see cref="MarkParConsumedAsync"/>.
        /// </summary>
        public async Task<Dictionary<string, string>> ReadParRequestAsync(string requestUri, string clientId)
        {
            var entry = await _ctx.par_requests.FirstOrDefaultAsync(p => p.request_uri == requestUri)
                ?? throw new OAuthException(OAuthErrorCodes.InvalidRequestUri, "request_uri is unknown.");
            if (entry.consumed)
                throw new OAuthException(OAuthErrorCodes.InvalidRequestUri, "request_uri has already been used.");
            if (entry.expires_at <= DateTime.UtcNow)
                throw new OAuthException(OAuthErrorCodes.InvalidRequestUri, "request_uri has expired.");
            if (!string.Equals(entry.client_id, clientId, StringComparison.OrdinalIgnoreCase))
                throw new OAuthException(OAuthErrorCodes.InvalidRequestUri, "request_uri belongs to a different client.");

            // The browser is here, so switch from the client's delivery window to the user's
            // interactive one. Guessing is unaffected — reaching this line already required
            // knowing the URN, and the entry is still single-use.
            var interactiveUntil = DateTime.UtcNow.Add(ParInteractiveWindow);
            if (entry.expires_at < interactiveUntil)
            {
                entry.expires_at = interactiveUntil;
                _ctx.par_requests.Update(entry);
                await _ctx.SaveChangesAsync();
            }

            return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(entry.payload)
                   ?? new Dictionary<string, string>();
        }

        /// <summary>
        /// Spends a pushed authorization request. Called once the authorization request has
        /// reached a terminal outcome — a code returned to the client, or an error returned in
        /// its place — so the same request_uri cannot drive a second authorization.
        /// </summary>
        public async Task MarkParConsumedAsync(string requestUri)
        {
            if (string.IsNullOrEmpty(requestUri)) return;
            var entry = await _ctx.par_requests.FirstOrDefaultAsync(p => p.request_uri == requestUri);
            if (entry == null || entry.consumed) return;
            entry.consumed = true;
            _ctx.par_requests.Update(entry);
            await _ctx.SaveChangesAsync();
        }

        // -----------------------------------------------------------------
        // Consent
        // -----------------------------------------------------------------

        public async Task<ArkConsent?> GetConsentAsync(string tenantId, string clientId, string subject)
        {
            var consent = await _ctx.consents.AsNoTracking().FirstOrDefaultAsync(c =>
                c.tenant_id == tenantId && c.client_id == clientId && c.subject == subject);
            if (consent == null) return null;
            if (consent.expires_at != null && consent.expires_at <= DateTime.UtcNow) return null;
            return consent;
        }

        public async Task SaveConsentAsync(string tenantId, string clientId, string subject, List<string> scopes)
        {
            var existing = await _ctx.consents.FirstOrDefaultAsync(c =>
                c.tenant_id == tenantId && c.client_id == clientId && c.subject == subject);
            if (existing == null)
            {
                _ctx.consents.Add(new ArkConsent
                {
                    tenant_id = tenantId,
                    client_id = clientId,
                    subject = subject,
                    scopes = scopes,
                    granted_at = DateTime.UtcNow
                });
            }
            else
            {
                var merged = existing.scopes.Union(scopes, StringComparer.OrdinalIgnoreCase).ToList();
                existing.scopes = merged;
                existing.granted_at = DateTime.UtcNow;
                _ctx.consents.Update(existing);
            }
            await _ctx.SaveChangesAsync();
        }

        public async Task RevokeConsentAsync(string tenantId, string clientId, string subject)
        {
            var existing = await _ctx.consents.FirstOrDefaultAsync(c =>
                c.tenant_id == tenantId && c.client_id == clientId && c.subject == subject);
            if (existing != null)
            {
                _ctx.consents.Remove(existing);
                await _ctx.SaveChangesAsync();
            }
        }

        // -----------------------------------------------------------------
        // Sessions
        // -----------------------------------------------------------------

        public async Task<ArkSession> CreateSessionAsync(string tenantId, string subject, int lifetimeMinutes,
            string? browserId = null)
        {
            var session = new ArkSession
            {
                session_id = ArkCrypto.RandomToken(16),
                tenant_id = tenantId,
                subject = subject,
                browser_id = string.IsNullOrWhiteSpace(browserId) ? null : browserId,
                auth_time = DateTime.UtcNow,
                created_at = DateTime.UtcNow,
                expires_at = DateTime.UtcNow.AddMinutes(lifetimeMinutes)
            };
            _ctx.sessions.Add(session);
            await _ctx.SaveChangesAsync();
            return session;
        }

        public async Task<ArkSession?> GetSessionAsync(string? sessionId)
        {
            if (string.IsNullOrEmpty(sessionId)) return null;
            var session = await _ctx.sessions.AsNoTracking().FirstOrDefaultAsync(s => s.session_id == sessionId);
            if (session == null || session.revoked || session.expires_at <= DateTime.UtcNow) return null;
            return session;
        }

        /// <summary>Ends a session and revokes every refresh token issued under it.</summary>
        public async Task RevokeSessionAsync(string sessionId)
        {
            var session = await _ctx.sessions.FirstOrDefaultAsync(s => s.session_id == sessionId);
            if (session != null)
            {
                session.revoked = true;
                _ctx.sessions.Update(session);
            }
            await RevokeTokensForSessionAsync(sessionId);
            await _ctx.SaveChangesAsync();
        }

        /// <summary>
        /// Every live session that belongs to one browser, newest first.
        ///
        /// This is the set signing out has to close. A browser holds one session cookie but can
        /// have accumulated any number of live sessions behind it — each sign-in creates one and
        /// replaces the cookie, so the earlier ones become unreachable from the browser while
        /// staying perfectly valid at the token endpoint.
        /// </summary>
        public async Task<List<ArkSession>> GetBrowserSessionsAsync(string? browserId, string? tenantId = null)
        {
            if (string.IsNullOrEmpty(browserId)) return new List<ArkSession>();
            var now = DateTime.UtcNow;
            var query = _ctx.sessions.AsNoTracking()
                .Where(s => s.browser_id == browserId && !s.revoked && s.expires_at > now);
            if (!string.IsNullOrEmpty(tenantId))
                query = query.Where(s => s.tenant_id.ToLower() == tenantId!.ToLower());
            return await query.OrderByDescending(s => s.created_at).ToListAsync();
        }

        /// <summary>
        /// Ends several sessions at once, returning the ones that were actually live.
        ///
        /// The return value is what back-channel logout notifies on: a session already revoked or
        /// already expired must not produce a second round of logout tokens, so a double submit
        /// of the logout form does not re-notify every client.
        /// </summary>
        public async Task<List<ArkSession>> RevokeSessionsAsync(IEnumerable<string> sessionIds)
        {
            var ids = sessionIds.Where(id => !string.IsNullOrEmpty(id)).Distinct().ToList();
            if (ids.Count == 0) return new List<ArkSession>();

            var now = DateTime.UtcNow;
            var sessions = await _ctx.sessions
                .Where(s => ids.Contains(s.session_id) && !s.revoked && s.expires_at > now)
                .ToListAsync();

            foreach (var session in sessions)
            {
                session.revoked = true;
                await RevokeTokensForSessionAsync(session.session_id);
            }
            if (sessions.Count > 0)
            {
                _ctx.sessions.UpdateRange(sessions);
                await _ctx.SaveChangesAsync();
            }
            return sessions;
        }

        /// <summary>
        /// Records that a client was logged in under a session, so it can be told when that
        /// session ends. Called the first time a session hands the client a code or approves its
        /// device request; recording the same pair again is a no-op.
        /// </summary>
        public async Task TrackSessionClientAsync(string tenantId, string? sessionId, string clientId, string subject)
        {
            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(clientId)) return;

            var id = ArkSessionClient.KeyFor(sessionId!, clientId);
            if (await _ctx.session_clients.AsNoTracking().AnyAsync(sc => sc.id == id)) return;

            _ctx.session_clients.Add(new ArkSessionClient
            {
                id = id,
                tenant_id = tenantId,
                session_id = sessionId!,
                client_id = clientId,
                subject = subject,
                created_at = DateTime.UtcNow
            });
            try
            {
                await _ctx.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // Two tabs finishing the same authorization at once both pass the check above and
                // both insert the same key. Losing that race costs nothing — the row the winner
                // wrote is the row this call wanted — but letting it surface would fail an
                // authorization that had otherwise succeeded.
                _ctx.ChangeTracker.Clear();
            }
        }

        /// <summary>The client ids that were logged in under the given sessions, per session.</summary>
        public async Task<List<ArkSessionClient>> GetSessionClientsAsync(IEnumerable<string> sessionIds)
        {
            var ids = sessionIds.Where(id => !string.IsNullOrEmpty(id)).Distinct().ToList();
            if (ids.Count == 0) return new List<ArkSessionClient>();
            return await _ctx.session_clients.AsNoTracking()
                .Where(sc => ids.Contains(sc.session_id))
                .ToListAsync();
        }

        // -----------------------------------------------------------------
        // Housekeeping
        // -----------------------------------------------------------------

        /// <summary>Deletes expired protocol state. Safe to call periodically.</summary>
        public async Task<int> CleanupExpiredAsync()
        {
            var now = DateTime.UtcNow;
            var removed = 0;

            var codes = await _ctx.auth_codes.Where(c => c.expires_at <= now).ToListAsync();
            _ctx.auth_codes.RemoveRange(codes); removed += codes.Count;

            var refresh = await _ctx.refresh_tokens.Where(t => t.expires_at <= now).ToListAsync();
            _ctx.refresh_tokens.RemoveRange(refresh); removed += refresh.Count;

            var devices = await _ctx.device_codes.Where(d => d.expires_at <= now).ToListAsync();
            _ctx.device_codes.RemoveRange(devices); removed += devices.Count;

            var pars = await _ctx.par_requests.Where(p => p.expires_at <= now).ToListAsync();
            _ctx.par_requests.RemoveRange(pars); removed += pars.Count;

            var sessions = await _ctx.sessions.Where(s => s.expires_at <= now).ToListAsync();
            _ctx.sessions.RemoveRange(sessions); removed += sessions.Count;

            // The participation rows outlive nothing: once the session is gone there is nobody
            // left to notify, and leaving them behind is what turns this table into the largest
            // one in the database.
            var expiredSessionIds = sessions.Select(s => s.session_id).ToList();
            if (expiredSessionIds.Count > 0)
            {
                var orphaned = await _ctx.session_clients
                    .Where(sc => expiredSessionIds.Contains(sc.session_id)).ToListAsync();
                _ctx.session_clients.RemoveRange(orphaned); removed += orphaned.Count;
            }

            if (removed > 0) await _ctx.SaveChangesAsync();
            return removed;
        }
    }
}
