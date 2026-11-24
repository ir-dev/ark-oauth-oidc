using Ark.Watch.Core;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>
    /// One line per tool call: who called what, at which endpoint, on what, and how it ended.
    ///
    /// A call that changes something is written to <c>audit_trace</c> whatever
    /// <c>EnableLogTrace</c> says, beside the line the change itself leaves; so is one that was
    /// refused. A call that only looked is trace. Arguments are never recorded — some are
    /// passwords — only the names of what the call touched, and a token by its <c>jti</c>.
    /// </summary>
    internal static class ArkMcpAudit
    {
        public static void Called(ArkMcpCall call, bool ok, string? reason)
        {
            var caller = call.Caller;
            var tool = call.Tool;
            var changes = tool.Access == ArkMcpAccess.Manage;
            var denied = !ok && reason is "not_permitted" or "insufficient_scope" or "read_only";

            var e = new ArkWatchEvent
            {
                Action = "mcp.tool_call",
                Domain = ArkWatchDomains.Administration,
                System = "mcp",
                Level = changes || denied ? AuditLevel.Security : AuditLevel.Info,
                Outcome = ok ? Outcome.Success : denied ? Outcome.Denied : Outcome.Failure,
                Tenant = call.Endpoint.Tenant?.tenant_id ?? (call.Endpoint.OperatorTenantId.Length > 0 ? call.Endpoint.OperatorTenantId : null),
                ParticipantId = caller.Subject,
                ParticipantType = caller.IsUser ? ParticipantTypes.User : ParticipantTypes.Service,
                ResourceType = call.Subjects.Keys.FirstOrDefault() ?? "mcp",
                ResourceId = call.Subjects.Values.FirstOrDefault() ?? call.Endpoint.Reference,
                Message = ok ? $"mcp tool '{tool.Name}' called at {call.Endpoint.Reference}"
                    : $"mcp tool '{tool.Name}' refused at {call.Endpoint.Reference}: {reason}",
                ProtocolTrace = ok && !changes
            };
            e.With("tool", tool.Name).With("level", call.Endpoint.Level.ToString().ToLowerInvariant())
                .With("access", tool.Access.ToString().ToLowerInvariant())
                .With("caller_kind", caller.Kind).With("credential", caller.Credential)
                .With("client_id", caller.ClientId).With("issuer_tenant", caller.TenantId)
                .With("actors", caller.Actors).With("jti", caller.TokenId).With("reason_code", reason);
            foreach (var (what, which) in call.Subjects) e.With($"target_{what}", which);

            // Setup has no database to write to; its own record is made when it finishes.
            if (call.Endpoint.Setup)
            {
                ArkWatch.Record(call.Http, e);
                return;
            }

            var details = $"client: {caller.ClientId}, sub: {caller.Subject}, tool: {tool.Name}"
                + (caller.Actors.Count > 0 ? $", act: {string.Join(" < ", caller.Actors)}" : "")
                + (call.Subjects.Count > 0 ? ", on: " + string.Join(" ", call.Subjects.Select(s => $"{s.Key}={s.Value}")) : "")
                + (caller.TokenId != null ? $", jti: {caller.TokenId}" : "")
                + (ok ? "" : $", reason: {reason}");
            var message = ok ? $"mcp tool called: {tool.Name}" : $"mcp tool refused: {tool.Name}";
            if (changes || denied)
                call.Da.WriteAudit(ok ? "mcp_call" : "mcp_refused", call.Endpoint.Reference, message, details,
                    caller.IsUser ? caller.Subject : caller.ClientId, ArkWatchAudit.Address(call.Http), e);
            else
                call.Da.Log(ok ? "mcp_call" : "mcp_refused", call.Endpoint.Reference, message, details, ok ? "trace" : "warn", e);
        }
    }
}
