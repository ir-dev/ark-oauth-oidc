using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace Ark.Agents.TenantOnboarding.Mcp
{
    /// <summary>What a tool answered: its structured content, and whether the tool called it a failure.</summary>
    internal sealed record McpResult(bool IsError, JsonObject Content)
    {
        public string? Error => IsError ? Content["error"]?.GetValue<string>() ?? "error" : null;
        public string Message => Content["message"]?.GetValue<string>() ?? "";
    }

    /// <summary>The endpoint did not take the credential: for setup, the code is wrong or setup has finished.</summary>
    internal sealed class McpUnauthorizedException : Exception
    {
        public McpUnauthorizedException(string message) : base(message) { }
    }

    internal sealed class McpException : Exception
    {
        public McpException(string message, Exception? inner = null) : base(message, inner) { }
    }

    /// <summary>
    /// A Model Context Protocol client for one endpoint: JSON-RPC over HTTP POST, with a bearer
    /// token, which for the setup endpoint is the setup code. The identity server keeps nothing
    /// between requests, so neither does this.
    /// </summary>
    internal sealed class McpClient
    {
        const string ProtocolVersion = "2025-06-18";

        readonly HttpClient _http;
        readonly Func<string?> _url;
        readonly Func<string?> _bearer;
        long _id;

        public McpClient(HttpClient http, Func<string?> url, Func<string?> bearer)
        {
            _http = http;
            _url = url;
            _bearer = bearer;
        }

        public string? Url => _url();

        /// <summary>The handshake. Returns the server's instructions for whoever uses its tools.</summary>
        public async Task<(string Name, string Version, string Instructions)> InitializeAsync(CancellationToken cancel)
        {
            var result = await SendAsync("initialize", new JsonObject
            {
                ["protocolVersion"] = ProtocolVersion,
                ["capabilities"] = new JsonObject(),
                ["clientInfo"] = new JsonObject { ["name"] = "ark-onboarding-agent", ["version"] = "0.1.0" }
            }, cancel, versionHeader: false);
            return (result["serverInfo"]?["name"]?.GetValue<string>() ?? "",
                result["serverInfo"]?["version"]?.GetValue<string>() ?? "",
                result["instructions"]?.GetValue<string>() ?? "");
        }

        public async Task<JsonArray> ListToolsAsync(CancellationToken cancel) =>
            (await SendAsync("tools/list", new JsonObject(), cancel))["tools"] as JsonArray ?? new JsonArray();

        public async Task<McpResult> CallAsync(string tool, JsonObject? arguments, CancellationToken cancel)
        {
            var result = await SendAsync("tools/call", new JsonObject { ["name"] = tool, ["arguments"] = arguments ?? new JsonObject() }, cancel);
            var content = result["structuredContent"] as JsonObject;
            if (content == null && result["content"] is JsonArray { Count: > 0 } parts && parts[0]?["text"]?.GetValue<string>() is { } text)
                content = JsonNode.Parse(text) as JsonObject;
            return new McpResult(result["isError"]?.GetValue<bool>() == true, (JsonObject)(content ?? new JsonObject()).DeepClone());
        }

        async Task<JsonObject> SendAsync(string method, JsonObject parameters, CancellationToken cancel, bool versionHeader = true)
        {
            var url = _url() ?? throw new McpException("the identity server's MCP address is not known yet.");
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(new JsonObject
                {
                    ["jsonrpc"] = "2.0",
                    ["id"] = Interlocked.Increment(ref _id),
                    ["method"] = method,
                    ["params"] = parameters
                }.ToJsonString(), Encoding.UTF8, "application/json")
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (versionHeader) request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", ProtocolVersion);
            if (_bearer() is { Length: > 0 } token) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request, cancel);
            }
            catch (HttpRequestException ex)
            {
                throw new McpException($"the identity server did not answer at {url}: {ex.Message}", ex);
            }
            using (response)
            {
                var body = await response.Content.ReadAsStringAsync(cancel);
                JsonObject? message = null;
                try { message = JsonNode.Parse(body.Length == 0 ? "{}" : body) as JsonObject; }
                catch (System.Text.Json.JsonException) { /* not JSON: the status says what happened */ }

                // A JSON-RPC error is an object. What answers in the server's place (its 503 while the
                // settings cannot be read, a proxy) has an "error" of its own, usually a word.
                var said = message?["error"] is JsonObject error && error["message"] is JsonValue words && words.TryGetValue<string>(out var why) ? why : null;
                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                    throw new McpUnauthorizedException(said ?? $"the identity server refused the credential ({(int)response.StatusCode}).");
                if (message?["error"] != null || !response.IsSuccessStatusCode)
                    throw new McpException(said ?? $"the identity server answered {(int)response.StatusCode} at {url}.");
                return message?["result"] as JsonObject ?? new JsonObject();
            }
        }
    }
}
