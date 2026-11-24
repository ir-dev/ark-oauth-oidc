using Ark.Watch.Core;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// The audit record of agent-to-agent (A2A) activity: every token the server issues for one
    /// agent to call another, every one it refuses, and every time an agent asks whether a token
    /// it was handed is still good.
    ///
    /// These are the events an auditor reads to answer "which agent acted, for which person,
    /// against which agent, and was it allowed". They are written so the answer can be followed
    /// without the tokens themselves:
    ///
    ///  * a token is named by its <c>jti</c> (<c>token_id</c>), never carried;
    ///  * a delegated token names the token it was exchanged from (<c>subject_token_id</c>), so
    ///    each hop of a chain points at the one before it, back to the user's own sign-in;
    ///  * the whole <c>act</c> chain is on every hop (<c>actors</c>, newest first), with its depth;
    ///  * a refusal carries the error the caller was sent and everything established before it.
    ///
    /// The participant is always the agent that made the request — it is the one that acted. The
    /// person it acted for is <c>on_behalf_of</c>, and the agent it wanted to reach is the
    /// resource.
    /// </summary>
    internal static class ArkAgentAudit
    {
        public const string SystemName = "token-endpoint";

        /// <summary>A token was issued for <paramref name="caller"/> to call another agent.</summary>
        public static ArkWatchEvent Issued(ArkTenant tenant, ArkClient caller, AgentTokenResult issued, AgentTokenTrace trace, string authMethod)
        {
            var delegated = trace.Mode == AgentTokenTrace.OnBehalfOf;
            var e = Base(tenant, caller, trace, authMethod);
            e.Action = delegated ? "agent_token.exchange" : "agent_token.issue";
            // Acting in a person's name is the security-relevant case; an agent calling another
            // as itself is ordinary business between two services.
            e.Level = delegated ? AuditLevel.Security : AuditLevel.Notice;
            e.Outcome = Outcome.Success;
            e.ResourceType = "agent";
            e.ResourceId = issued.Audience;
            e.Message = delegated
                ? $"agent '{caller.client_id}' may call agent '{issued.Audience}' on behalf of '{issued.Subject}'"
                : $"agent '{caller.client_id}' may call agent '{issued.Audience}' as itself";

            e.With("target", issued.Audience)
                .With("token_id", issued.TokenId)
                .With("scopes", issued.Scopes)
                .With("claims", issued.Claims)
                .With("expires_at", issued.ExpiresAt.ToString("O"))
                .With("lifetime_seconds", Math.Max(0, (int)Math.Round((issued.ExpiresAt - DateTime.UtcNow).TotalSeconds)));
            if (delegated)
            {
                e.With("on_behalf_of", issued.Subject)
                    .With("actors", issued.Actors)
                    .With("delegation_depth", issued.Actors.Count);
            }
            return e;
        }

        /// <summary>A request for an agent token was turned down.</summary>
        public static ArkWatchEvent Refused(ArkTenant tenant, ArkClient caller, AgentTokenTrace trace, OAuthException ex, string authMethod)
        {
            var delegated = trace.Mode == AgentTokenTrace.OnBehalfOf;
            var e = Base(tenant, caller, trace, authMethod);
            e.Action = delegated ? "agent_token.exchange" : "agent_token.issue";
            e.Level = AuditLevel.Security;
            // A request that was understood and not allowed is Denied; one that was malformed is
            // a Failure. The first is what an access review counts.
            e.Outcome = ex.Error is OAuthErrorCodes.InvalidRequest or OAuthErrorCodes.UnsupportedGrantType
                ? Outcome.Failure
                : Outcome.Denied;
            e.ResourceType = "agent";
            e.ResourceId = trace.Target ?? trace.RequestedAudience;
            e.Message = delegated
                ? $"agent '{caller.client_id}' was refused a token for '{trace.Target ?? trace.RequestedAudience}' on behalf of '{trace.Subject ?? "an unverified subject"}': {ex.ErrorDescription ?? ex.Error}"
                : $"agent '{caller.client_id}' was refused a token for '{trace.Target ?? trace.RequestedAudience}': {ex.ErrorDescription ?? ex.Error}";

            e.With("error", ex.Error)
                .With("error_description", ex.ErrorDescription)
                .With("status", ex.StatusCode)
                // Only set once the caller was found on the target's list; until then the server
                // will not say, here or to the caller, whether the audience names an agent at all.
                .With("target", trace.Target);
            if (delegated)
            {
                e.With("on_behalf_of", trace.Subject)
                    .With("actors", trace.PreviousActors)
                    .With("delegation_depth", trace.PreviousActors.Count + 1);
            }
            return e;
        }

        /// <summary>An agent asked the server about a token addressed to an agent.</summary>
        public static ArkWatchEvent Introspected(
            ArkTenant tenant, string caller, bool active, string relation, string? reason,
            string? tokenId, string? subject, string? issuedTo, List<string> audiences, List<string> actors, string? sessionId)
        {
            var e = new ArkWatchEvent
            {
                Action = "agent_token.introspect",
                Domain = ArkWatchDomains.Agents,
                System = "introspection-endpoint",
                Level = active ? AuditLevel.Info : AuditLevel.Security,
                Outcome = active ? Outcome.Success : Outcome.Denied,
                Tenant = tenant.tenant_id,
                ParticipantId = caller,
                ParticipantType = ParticipantTypes.Service,
                ResourceType = "agent_token",
                ResourceId = tokenId,
                Message = active
                    ? $"agent '{caller}' was told token '{tokenId}' is active"
                    : $"agent '{caller}' was told token '{tokenId}' is not active: {reason}"
            };
            e.With("token_id", tokenId)
                .With("active", active)
                .With("reason", reason)
                // Why this caller was answered at all: the token is addressed to it, it obtained
                // the token, or it is a configured resource server.
                .With("relation", relation)
                .With("issued_to", issuedTo)
                .With("target", audiences.Count == 1 ? audiences[0] : null)
                .With("audiences", audiences.Count > 1 ? audiences : null)
                .With("session", sessionId);
            if (actors.Count > 0 && !string.IsNullOrEmpty(subject))
            {
                e.With("mode", AgentTokenTrace.OnBehalfOf)
                    .With("on_behalf_of", subject)
                    .With("actors", actors)
                    .With("delegation_depth", actors.Count);
            }
            else
            {
                e.With("mode", AgentTokenTrace.AsItself);
            }
            return e;
        }

        /// <summary>The sentence the database trace keeps for the same event.</summary>
        public static string Details(ArkClient caller, AgentTokenTrace trace, AgentTokenResult? issued = null, OAuthException? refused = null)
        {
            var parts = new List<string> { $"client: {caller.client_id}" };
            var subject = issued?.Subject ?? trace.Subject;
            if (trace.Mode == AgentTokenTrace.OnBehalfOf && !string.IsNullOrEmpty(subject)) parts.Add($"sub: {subject}");
            var audience = issued?.Audience ?? trace.Target ?? trace.RequestedAudience;
            if (!string.IsNullOrEmpty(audience)) parts.Add($"audience: {audience}");
            var actors = issued?.Actors ?? trace.PreviousActors;
            if (actors.Count > 0) parts.Add($"act: {string.Join(" < ", actors)}");
            if (!string.IsNullOrEmpty(issued?.TokenId)) parts.Add($"jti: {issued!.TokenId}");
            if (refused != null) parts.Add($"reason: {refused.ErrorDescription ?? refused.Error}");
            return string.Join(", ", parts);
        }

        private static ArkWatchEvent Base(ArkTenant tenant, ArkClient caller, AgentTokenTrace trace, string authMethod)
        {
            var delegated = trace.Mode == AgentTokenTrace.OnBehalfOf;
            var e = new ArkWatchEvent
            {
                Domain = ArkWatchDomains.Agents,
                System = SystemName,
                Tenant = tenant.tenant_id,
                ParticipantId = caller.client_id,
                ParticipantType = ParticipantTypes.Service,
                ParticipantName = caller.client_name ?? caller.display ?? caller.name
            };
            e.With("mode", trace.Mode)
                .With("grant_type", delegated ? ArkAgentTokens.TokenExchangeGrant : "client_credentials")
                .With("caller", caller.client_id)
                .With("caller_is_agent", caller.is_agent == true ? true : null)
                .With("client_auth_method", authMethod)
                .With("requested_audience", trace.RequestedAudience)
                .With("requested_scopes", trace.RequestedScopes)
                .With("target_name", trace.TargetName);
            if (delegated)
            {
                e.With("subject_token_id", trace.SubjectTokenId)
                    .With("subject_token_issued_to", trace.SubjectTokenIssuedTo)
                    .With("subject_token_audiences", trace.SubjectTokenAudiences)
                    .With("subject_token_expires_at", trace.SubjectTokenExpiresAt?.ToString("O"))
                    .With("subject_token_held_as", trace.SubjectTokenHeldAs)
                    .With("session", trace.SessionId)
                    .With("delegate_users", trace.DelegateUsers);
            }
            return e;
        }
    }
}
