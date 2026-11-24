using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>
    /// The Model Context Protocol, as these endpoints speak it: JSON-RPC over HTTP POST, one
    /// request answered with one JSON document, nothing kept between requests.
    ///
    /// Two generations of clients are served at the same address. A request that names its
    /// protocol version in <c>_meta</c> (revision 2026-07-28 and later) is complete in itself. A
    /// client of an earlier revision opens with <c>initialize</c>; it is answered, and no session
    /// follows, so its next request may land on any instance. The endpoint never sends a request
    /// of its own and offers no event stream, which is what lets it answer inside the setup gate,
    /// before there is a database, and behind any load balancer.
    ///
    /// Written out rather than taken from the MCP SDK because of where it has to run. A host that
    /// embeds this server may carry its own MCP server, and the SDK has one set of tools per
    /// application; the setup endpoint answers before routing and authentication exist; and a
    /// token short of a scope has to be answered with HTTP 403 naming that scope, which is decided
    /// from the tool named in the body.
    /// </summary>
    internal static class ArkMcpServer
    {
        public const string Modern = "2026-07-28";
        /// <summary>The revisions served with the <c>initialize</c> handshake, newest first.</summary>
        static readonly string[] Legacy = { "2025-11-25", "2025-06-18", "2025-03-26" };
        static readonly string[] Supported = new[] { Modern }.Concat(Legacy).ToArray();

        const string MetaVersion = "io.modelcontextprotocol/protocolVersion";
        const string MetaCapabilities = "io.modelcontextprotocol/clientCapabilities";
        const string MetaClientInfo = "io.modelcontextprotocol/clientInfo";
        const string MetaServerInfo = "io.modelcontextprotocol/serverInfo";

        const int ParseError = -32700, InvalidRequest = -32600, MethodNotFound = -32601, InvalidParams = -32602, InternalError = -32603;
        const int HeaderMismatch = -32020, UnsupportedVersion = -32022;

        /// <summary>The endpoint's side of a request: who is calling, and what they may call.</summary>
        public sealed class Binding
        {
            public ArkMcpEndpoint Endpoint { get; init; } = default!;
            public Func<Task<ArkMcpCaller>> Authenticate { get; init; } = default!;
            public IReadOnlyList<ArkMcpTool> Tools { get; init; } = Array.Empty<ArkMcpTool>();
            public string Instructions { get; init; } = "";
            /// <summary>The scopes to name in a 401, or null at an endpoint that takes no OAuth token.</summary>
            public string? ChallengeScope { get; init; }
            public Action<ArkMcpCall, bool, string?>? OnCalled { get; init; }
        }

        public static async Task HandleAsync(HttpContext http, Binding binding)
        {
            var request = http.Request;
            var response = http.Response;
            response.Headers.CacheControl = "no-store";
            response.Headers.XContentTypeOptions = "nosniff";

            if (!OriginAllowed(request, binding.Endpoint))
            {
                await Error(http, 403, null, InvalidRequest, "this Origin may not call the MCP endpoint. List it in ark_oauth_server:Oidc:CorsOrigins.");
                return;
            }
            if (!(request.ContentType ?? "").StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
            {
                await Error(http, 415, null, InvalidRequest, "send Content-Type: application/json.");
                return;
            }
            var accept = request.Headers.Accept.ToString();
            if (accept.Length > 0 && !accept.Contains("application/json", StringComparison.OrdinalIgnoreCase)
                && !accept.Contains("*/*", StringComparison.Ordinal) && !accept.Contains("application/*", StringComparison.OrdinalIgnoreCase))
            {
                await Error(http, 406, null, InvalidRequest, "the answer is application/json; include it in Accept.");
                return;
            }

            // Before the body is read: an unauthenticated caller costs a header, not a parse.
            ArkMcpCaller caller;
            try
            {
                caller = await binding.Authenticate();
            }
            catch (ArkMcpAuthException ex)
            {
                await Challenge(http, binding, ex, null);
                return;
            }
            catch (ArkBusyException)
            {
                await Error(http, 503, null, InternalError, "the server is busy; try again shortly.");
                return;
            }
            http.User = caller.ToPrincipal();

            var limit = Math.Max(16, binding.Endpoint.Config.Mcp?.MaxRequestKilobytes ?? 1536) * 1024L;
            JsonDocument document;
            try
            {
                var body = await ReadAsync(request, limit, http.RequestAborted);
                if (body == null)
                {
                    await Error(http, 413, null, InvalidRequest, $"the request is larger than {limit / 1024} KB.");
                    return;
                }
                document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 32 });
            }
            catch (JsonException)
            {
                await Error(http, 400, null, ParseError, "the body is not JSON.");
                return;
            }

            using (document)
            {
                var message = document.RootElement;
                if (message.ValueKind != JsonValueKind.Object
                    || !message.TryGetProperty("jsonrpc", out var rpc) || rpc.ValueKind != JsonValueKind.String || rpc.GetString() != "2.0"
                    || !message.TryGetProperty("method", out var methodNode) || methodNode.ValueKind != JsonValueKind.String)
                {
                    await Error(http, 400, null, InvalidRequest, "send one JSON-RPC 2.0 request or notification.");
                    return;
                }
                var method = methodNode.GetString()!;
                var hasId = message.TryGetProperty("id", out var id) && id.ValueKind is JsonValueKind.String or JsonValueKind.Number;
                if (message.TryGetProperty("id", out var given) && !hasId)
                {
                    await Error(http, 400, null, InvalidRequest, $"id must be a string or a number, not {given.ValueKind.ToString().ToLowerInvariant()}.");
                    return;
                }
                if (!hasId)
                {
                    // A notification. None asks anything of a server that keeps nothing.
                    response.StatusCode = StatusCodes.Status202Accepted;
                    return;
                }
                JsonElement? parameters = message.TryGetProperty("params", out var p) && p.ValueKind == JsonValueKind.Object ? p : null;

                try
                {
                    await DispatchAsync(http, binding, caller, id, method, parameters);
                }
                catch (ArkMcpAuthException ex)
                {
                    await Challenge(http, binding, ex, id);
                }
                catch (RpcException ex)
                {
                    await Error(http, ex.Status, id, ex.Code, ex.Message, ex.Payload);
                }
                catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
                {
                    // The client closed the request, which over HTTP is how a call is cancelled.
                }
            }
        }

        // ---------------------------------------------------------------- dispatch

        static async Task DispatchAsync(HttpContext http, Binding binding, ArkMcpCaller caller, JsonElement id, string method, JsonElement? parameters)
        {
            var header = http.Request.Headers["MCP-Protocol-Version"].ToString().Trim();
            var meta = parameters is { } ps && ps.TryGetProperty("_meta", out var m) && m.ValueKind == JsonValueKind.Object ? m : (JsonElement?)null;
            var metaVersion = meta is { } mm && mm.TryGetProperty(MetaVersion, out var mv) && mv.ValueKind == JsonValueKind.String ? mv.GetString() : null;

            var legacyOpening = method == "initialize" && metaVersion == null;
            if (!legacyOpening)
            {
                foreach (var asked in new[] { metaVersion, header.Length > 0 ? header : null })
                    if (asked != null && !Supported.Contains(asked, StringComparer.Ordinal))
                        throw new RpcException(400, UnsupportedVersion, "Unsupported protocol version",
                            new JsonObject { ["supported"] = Strings(Supported), ["requested"] = asked });
            }

            // Version 2026-07-28 and later: everything a request needs is in the request.
            var modern = !legacyOpening && (metaVersion != null || string.CompareOrdinal(header, Modern) >= 0);
            if (modern) CheckEnvelope(http.Request, method, parameters, meta, metaVersion, header);

            switch (method)
            {
                case "server/discover" when modern:
                    await Result(http, id, new JsonObject
                    {
                        ["resultType"] = "complete",
                        ["supportedVersions"] = Strings(Supported),
                        ["capabilities"] = Capabilities(),
                        ["instructions"] = binding.Instructions,
                        ["ttlMs"] = 0,
                        ["cacheScope"] = "private",
                        ["_meta"] = new JsonObject { [MetaServerInfo] = ServerInfo(binding.Endpoint) }
                    });
                    return;

                case "initialize" when !modern:
                    var wanted = parameters is { } ip && ip.TryGetProperty("protocolVersion", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                    await Result(http, id, new JsonObject
                    {
                        ["protocolVersion"] = Legacy.Contains(wanted, StringComparer.Ordinal) ? wanted : Legacy[0],
                        ["capabilities"] = Capabilities(),
                        ["serverInfo"] = ServerInfo(binding.Endpoint),
                        ["instructions"] = binding.Instructions
                    });
                    return;

                case "ping" when !modern:
                    await Result(http, id, new JsonObject());
                    return;

                case "tools/list":
                    var list = new JsonObject
                    {
                        ["tools"] = new JsonArray(Offered(http, binding, caller).Select(t => (JsonNode?)t.Describe()).ToArray())
                    };
                    if (modern)
                    {
                        list["resultType"] = "complete";
                        // What is offered depends on who asks, and changes when setup finishes.
                        list["ttlMs"] = binding.Endpoint.Setup ? 0 : 60000;
                        list["cacheScope"] = "private";
                    }
                    await Result(http, id, list);
                    return;

                case "tools/call":
                    await CallAsync(http, binding, caller, id, parameters, modern);
                    return;

                default:
                    throw new RpcException(modern ? 404 : 200, MethodNotFound, $"Method not found: {method}");
            }
        }

        /// <summary>
        /// The request headers mirror the body (2026-07-28, "Standard request headers"), so a
        /// gateway can route and log without parsing it. A mismatch means one of the two has been
        /// tampered with or rewritten, and the request is refused rather than half believed.
        /// </summary>
        static void CheckEnvelope(HttpRequest request, string method, JsonElement? parameters, JsonElement? meta, string? metaVersion, string header)
        {
            if (metaVersion == null)
                throw new RpcException(400, InvalidParams, $"params._meta[\"{MetaVersion}\"] is required.");
            if (meta is not { } body || !body.TryGetProperty(MetaCapabilities, out var capabilities) || capabilities.ValueKind != JsonValueKind.Object)
                throw new RpcException(400, InvalidParams, $"params._meta[\"{MetaCapabilities}\"] is required.");
            if (header.Length == 0)
                throw new RpcException(400, HeaderMismatch, "Header mismatch: the MCP-Protocol-Version header is required.");
            if (!string.Equals(header, metaVersion, StringComparison.Ordinal))
                throw new RpcException(400, HeaderMismatch, $"Header mismatch: MCP-Protocol-Version header value '{header}' does not match body value '{metaVersion}'");

            var named = Decode(request.Headers["Mcp-Method"].ToString());
            if (!string.Equals(named, method, StringComparison.Ordinal))
                throw new RpcException(400, HeaderMismatch, $"Header mismatch: Mcp-Method header value '{named}' does not match body value '{method}'");

            if (method is not "tools/call") return;
            var tool = parameters is { } ps && ps.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : "";
            var headerName = Decode(request.Headers["Mcp-Name"].ToString());
            if (!string.Equals(headerName, tool, StringComparison.Ordinal))
                throw new RpcException(400, HeaderMismatch, $"Header mismatch: Mcp-Name header value '{headerName}' does not match body value '{tool}'");
        }

        /// <summary>A header value that could not be sent as plain ASCII travels as <c>=?base64?…?=</c>.</summary>
        static string Decode(string value)
        {
            value = value.Trim();
            if (!value.StartsWith("=?base64?", StringComparison.Ordinal) || !value.EndsWith("?=", StringComparison.Ordinal) || value.Length < 11) return value;
            try { return Encoding.UTF8.GetString(Convert.FromBase64String(value[9..^2])); }
            catch (FormatException) { return value; }
        }

        // ---------------------------------------------------------------- tools

        /// <summary>
        /// The tools this caller is offered. Filtered by who the caller is and not by the scopes
        /// the token carries: a tool it could call with a wider scope is listed, and answers with
        /// the scope it needs when it is called without it.
        /// </summary>
        static IEnumerable<ArkMcpTool> Offered(HttpContext http, Binding binding, ArkMcpCaller caller)
        {
            var readOnly = !binding.Endpoint.Setup && binding.Endpoint.Config.Mcp is { ReadOnly: true };
            foreach (var tool in binding.Tools)
            {
                if (!tool.Allows(caller)) continue;
                if (readOnly && tool.Access == ArkMcpAccess.Manage) continue;
                if (tool.When != null && !tool.When(new ArkMcpCall { Http = http, Endpoint = binding.Endpoint, Caller = caller, Tool = tool })) continue;
                yield return tool;
            }
        }

        static async Task CallAsync(HttpContext http, Binding binding, ArkMcpCaller caller, JsonElement id, JsonElement? parameters, bool modern)
        {
            var name = parameters is { } ps && ps.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : "";
            var tool = binding.Tools.FirstOrDefault(t => t.Name == name)
                ?? throw new RpcException(200, InvalidParams, $"Unknown tool: {name}");
            var call = new ArkMcpCall { Http = http, Endpoint = binding.Endpoint, Caller = caller, Tool = tool };

            try
            {
                if (!tool.Allows(caller) || (tool.When != null && !tool.When(call)))
                    throw new ArkMcpToolException("not_permitted", NotPermitted(tool, call));
                if (tool.Access == ArkMcpAccess.Manage && !binding.Endpoint.Setup && binding.Endpoint.Config.Mcp is { ReadOnly: true })
                    throw new ArkMcpToolException("read_only", "this server's MCP endpoints are read-only (ark_oauth_server:Mcp:ReadOnly).");
                // Short of a scope: HTTP 403 naming it, which an MCP client answers by asking for
                // a token that has it (step-up) and calling again.
                if (tool.Access == ArkMcpAccess.Manage && !caller.CanManage)
                    throw new ArkMcpAuthException(403, OAuthErrorCodes.InsufficientScope, $"'{name}' changes something and needs the scope {ArkMcpScopes.Manage}.",
                        $"{ArkMcpScopes.Read} {ArkMcpScopes.Manage}");
                if (tool.Access == ArkMcpAccess.Read && !caller.CanRead)
                    throw new ArkMcpAuthException(403, OAuthErrorCodes.InsufficientScope, $"'{name}' needs the scope {ArkMcpScopes.Read}.", ArkMcpScopes.Read);

                call.Args = tool.Params.Read(parameters is { } pp && pp.TryGetProperty("arguments", out var a) ? a : null);
                var value = ArkMcpJson.Node(await tool.Run(call)) as JsonObject ?? new JsonObject();
                Report(binding, call, true, null);
                await Result(http, id, ToolResult(value, false, modern));
            }
            catch (ArkMcpAuthException ex)
            {
                Report(binding, call, false, ex.Error);
                throw;
            }
            catch (ArkMcpToolException ex)
            {
                // A problem the model can put right is a result, not a protocol error: the model
                // is shown results.
                Report(binding, call, false, ex.Code);
                await Result(http, id, ToolResult(Failure(ex.Code, ex.Message, ex.Details), true, modern));
            }
            catch (ArkProvisionException ex)
            {
                Report(binding, call, false, ex.Code);
                await Result(http, id, ToolResult(Failure(ex.Code, ex.Message, ex.Data), true, modern));
            }
            catch (ArkClientValidationException ex)
            {
                Report(binding, call, false, ex.Code);
                await Result(http, id, ToolResult(Failure(ex.Code, ex.Message, ex.DataPayload), true, modern));
            }
            catch (Webhooks.ArkWebhookException ex)
            {
                Report(binding, call, false, ex.Code);
                await Result(http, id, ToolResult(Failure(ex.Code, ex.Message, null), true, modern));
            }
            catch (ApplicationException ex)
            {
                // What this codebase throws for a request it will not carry out, with a message
                // written for whoever made it.
                Report(binding, call, false, "refused");
                await Result(http, id, ToolResult(Failure("refused", ex.Message, null), true, modern));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Report(binding, call, false, "internal_error");
                try { http.RequestServices.GetService<DataAccess>()?.LogError(ex, "mcp_error", binding.Endpoint.Reference, name); }
                catch { /* unconfigured, or the database is what failed: the host's log has it below */ }
                http.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("Ark.oAuth.Oidc.Mcp").LogError(ex, "MCP tool {Tool} failed", name);
                await Result(http, id, ToolResult(Failure("internal_error", "the server could not carry that out; the reason is in its log.", null), true, modern));
            }
        }

        static void Report(Binding binding, ArkMcpCall call, bool ok, string? reason)
        {
            try { binding.OnCalled?.Invoke(call, ok, reason); }
            catch { /* the record of a call is never a reason for it to fail */ }
        }

        static string NotPermitted(ArkMcpTool tool, ArkMcpCall call) => tool.Role switch
        {
            ArkMcpRole.Operator => $"'{tool.Name}' is for the operator of this server: the machine client of the operator tenant, or a person " +
                                   $"whose access mapping there carries {ArkMcpClaims.HostAdmin}.",
            ArkMcpRole.TenantAdmin when call.Endpoint.IsOperatorTenant =>
                $"'{tool.Name}' is for the operator here, because this is the operator tenant: its machine client, or a person whose access " +
                $"mapping in it carries {ArkMcpClaims.HostAdmin}.",
            ArkMcpRole.TenantAdmin => $"'{tool.Name}' is for an administrator of this tenant: its machine client " +
                                      $"({ArkManagementAuth.MachineClientId(call.Tenant.tenant_id)}), or a person whose access mapping carries {ArkMcpClaims.TenantAdmin}.",
            ArkMcpRole.ClientAdmin => $"'{tool.Name}' is for the application itself (client_credentials), or a person whose access mapping to it carries {ArkMcpClaims.ClientAdmin}.",
            ArkMcpRole.Person => $"'{tool.Name}' is about a signed-in person, and this token is for a client.",
            _ => $"'{tool.Name}' is not offered to this caller."
        };

        static JsonObject Failure(string code, string message, object? details)
        {
            var body = new JsonObject { ["error"] = code, ["message"] = message };
            if (details != null) body["details"] = ArkMcpJson.Node(details);
            return body;
        }

        static JsonObject ToolResult(JsonObject value, bool isError, bool modern)
        {
            var result = new JsonObject();
            if (modern) result["resultType"] = "complete";
            result["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = value.ToJsonString(ArkMcpJson.Options) });
            result["structuredContent"] = value;
            result["isError"] = isError;
            return result;
        }

        // ---------------------------------------------------------------- pieces

        static JsonObject Capabilities() => new() { ["tools"] = new JsonObject { ["listChanged"] = false } };

        public static JsonObject ServerInfo(ArkMcpEndpoint endpoint) => new()
        {
            ["name"] = endpoint.Level switch
            {
                ArkMcpLevel.Host => endpoint.Setup ? "ark-idp-setup" : "ark-idp",
                ArkMcpLevel.Tenant => $"ark-idp-{endpoint.Tenant!.tenant_id}",
                _ => $"ark-idp-{endpoint.Tenant!.tenant_id}-app"
            },
            ["title"] = endpoint.Level switch
            {
                ArkMcpLevel.Host => endpoint.Setup ? "Ark identity server: setup" : "Ark identity server",
                ArkMcpLevel.Tenant => $"Ark identity server: tenant {endpoint.Tenant!.tenant_id}",
                _ => $"Ark identity server: {endpoint.Client!.client_name ?? endpoint.Client.client_id}"
            },
            ["version"] = ArkWatchAudit.PackageVersion
        };

        static JsonArray Strings(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());

        /// <summary>
        /// DNS rebinding (MCP transport, "Security warning"): a page open in somebody's browser
        /// must not reach this endpoint under a name that resolves here. A client that is not a
        /// browser sends no Origin.
        /// </summary>
        static bool OriginAllowed(HttpRequest request, ArkMcpEndpoint endpoint)
        {
            var origin = request.Headers.Origin.ToString().Trim();
            if (origin.Length == 0) return true;
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var from) || from.Scheme is not ("http" or "https")) return false;
            var left = from.GetLeftPart(UriPartial.Authority);
            if (Uri.TryCreate(endpoint.Root, UriKind.Absolute, out var own)
                && string.Equals(left, own.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase)
                // Before setup the root is whatever the request was sent to, so it proves nothing.
                && !endpoint.Setup) return true;
            return (endpoint.Config.Oidc?.CorsOrigins ?? new List<string>())
                .Any(o => string.Equals((o ?? "").Trim().TrimEnd('/'), left, StringComparison.OrdinalIgnoreCase));
        }

        static async Task<byte[]?> ReadAsync(HttpRequest request, long limit, CancellationToken cancel)
        {
            if (request.ContentLength > limit) return null;
            using var buffer = new MemoryStream();
            var chunk = new byte[16 * 1024];
            int read;
            while ((read = await request.Body.ReadAsync(chunk, cancel)) > 0)
            {
                if (buffer.Length + read > limit) return null;
                buffer.Write(chunk, 0, read);
            }
            return buffer.ToArray();
        }

        sealed class RpcException : Exception
        {
            public int Status { get; }
            public int Code { get; }
            public JsonNode? Payload { get; }
            public RpcException(int status, int code, string message, JsonNode? payload = null) : base(message)
            {
                Status = status;
                Code = code;
                Payload = payload;
            }
        }

        static Task Result(HttpContext http, JsonElement id, JsonObject result) =>
            Write(http, 200, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = IdNode(id), ["result"] = result });

        static Task Error(HttpContext http, int status, JsonElement? id, int code, string message, JsonNode? data = null)
        {
            var error = new JsonObject { ["code"] = code, ["message"] = message };
            if (data != null) error["data"] = data;
            var body = new JsonObject { ["jsonrpc"] = "2.0" };
            if (id is { } known) body["id"] = IdNode(known);
            body["error"] = error;
            return Write(http, status, body);
        }

        static JsonNode? IdNode(JsonElement id) => JsonNode.Parse(id.GetRawText());

        static async Task Write(HttpContext http, int status, JsonObject body)
        {
            http.Response.StatusCode = status;
            http.Response.ContentType = "application/json; charset=utf-8";
            await http.Response.WriteAsync(body.ToJsonString(ArkMcpJson.Options), http.RequestAborted);
        }

        /// <summary>RFC 6750 §3 and RFC 9728 §5.1: what was wrong, and where to find out how to get a token.</summary>
        static Task Challenge(HttpContext http, Binding binding, ArkMcpAuthException ex, JsonElement? id)
        {
            // A header is ASCII, and a quoted string ends at a quote.
            static string Quote(string value) =>
                "\"" + new string(value.Select(c => c is '"' ? '\'' : c is '\\' or < ' ' or > '~' ? '?' : c).ToArray()) + "\"";
            var parts = new List<string>();
            if (ex.Error != null) parts.Add($"error={Quote(ex.Error)}");
            parts.Add($"error_description={Quote(ex.Message)}");
            var scope = ex.Scope ?? (ex.Status == 401 ? binding.ChallengeScope : null);
            if (!string.IsNullOrEmpty(scope)) parts.Add($"scope={Quote(scope!)}");
            if (!binding.Endpoint.Setup) parts.Add($"resource_metadata={Quote(binding.Endpoint.MetadataUrl)}");
            else parts.Insert(0, "realm=\"ark-idp-setup\"");
            http.Response.Headers.WWWAuthenticate = "Bearer " + string.Join(", ", parts);
            return Error(http, ex.Status, id, ex.Status == 401 ? -32001 : -32003, ex.Message);
        }
    }
}
