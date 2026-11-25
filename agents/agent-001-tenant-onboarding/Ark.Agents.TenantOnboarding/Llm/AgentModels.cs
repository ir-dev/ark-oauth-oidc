using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ark.Agents.TenantOnboarding.Llm
{
    /// <summary>
    /// A language model, reduced to what every gateway can do: instructions and one message in,
    /// text out. The harness never relies on a provider's own tool calling, so the same agent runs
    /// on a gateway that takes a single string and on one that takes a conversation.
    ///
    /// A host that already has a model client registers its own implementation, and the agent
    /// uses that instead of the ones below.
    /// </summary>
    public interface IArkAgentModel
    {
        /// <summary>Shown beside the agent's name, so people know what is reading their words.</summary>
        string Label { get; }

        /// <summary>
        /// Not null: a small model, whose whole prompt has to fit in this many characters. The
        /// harness then does what it can in code, asks the model only to read free text, one short
        /// question per turn and never a second time, and keeps nothing it read until the person
        /// has looked at it. Null: a capable model, given the whole situation.
        /// </summary>
        int? SmallPromptChars => null;

        Task<string> CompleteAsync(string instructions, string message, CancellationToken cancel);
    }

    /// <summary>The model said no, or the gateway did, in words worth showing.</summary>
    public sealed class ArkAgentModelException : Exception
    {
        public ArkAgentModelException(string message, Exception? inner = null) : base(message, inner) { }
    }

    internal static class AgentModelFactory
    {
        /// <summary>The configured model, or null: the agent then runs in guided mode.</summary>
        public static IArkAgentModel? Create(ArkOnboardingAgentOptions options, HttpClient http)
        {
            var llm = options.Llm;
            switch (Provider(options))
            {
                case "genericllm":
                    return string.IsNullOrWhiteSpace(llm.GenericLLM.Url) ? null : new GenericLlmModel(llm.GenericLLM, http);
                case "arkllm":
                    return string.IsNullOrWhiteSpace(llm.ArkLLM.Url) || string.IsNullOrWhiteSpace(llm.ArkLLM.ApiKey) ? null
                        : new ArkLlmModel(llm.ArkLLM, http);
                case "azurefoundry" or "azure" or "foundry":
                    return string.IsNullOrWhiteSpace(llm.AzureFoundry.Deployment)
                           || (string.IsNullOrWhiteSpace(llm.AzureFoundry.Endpoint) && string.IsNullOrWhiteSpace(llm.AzureFoundry.Url))
                        ? null : new AzureFoundryModel(llm.AzureFoundry, llm.MaxTokens, options.AzureTokenProvider, http);
                case "bedrock" or "awsbedrock" or "aws":
                    return string.IsNullOrWhiteSpace(llm.Bedrock.ModelId) ? null
                        : new BedrockModel(llm.Bedrock, llm.MaxTokens, options.AwsCredentialsProvider, http);
                default:
                    return null;
            }
        }

        /// <summary>Why <see cref="Create"/> returned nothing, for the start-up log.</summary>
        public static string WhyNot(ArkOnboardingAgentOptions options) => Provider(options) switch
        {
            "" or "none" => "no model is configured (ark_onboarding_agent:Llm:Provider)",
            "genericllm" => "Llm:GenericLLM:Url is not set",
            "arkllm" => "Llm:ArkLLM needs Url and ApiKey",
            "azurefoundry" or "azure" or "foundry" => "Llm:AzureFoundry needs Endpoint and Deployment",
            "bedrock" or "awsbedrock" or "aws" => "Llm:Bedrock:ModelId is not set",
            _ => $"'{options.Llm.Provider}' is not a provider this agent knows (generic_llm, ark_llm, azure_foundry, bedrock, none)"
        };

        /// <summary><c>generic_llm</c>, <c>generic-llm</c> and <c>GenericLLM</c> are one name.</summary>
        static string Provider(ArkOnboardingAgentOptions options) =>
            (options.Llm.Provider ?? "").Trim().ToLowerInvariant().Replace("-", "").Replace("_", "").Replace(" ", "");

        internal static async Task<JsonNode> PostAsync(HttpClient http, HttpRequestMessage request, string provider, CancellationToken cancel)
        {
            HttpResponseMessage response;
            try
            {
                response = await http.SendAsync(request, cancel);
            }
            catch (HttpRequestException ex)
            {
                throw new ArkAgentModelException($"{provider} could not be reached: {ex.Message}", ex);
            }
            catch (TaskCanceledException ex) when (!cancel.IsCancellationRequested)
            {
                throw new ArkAgentModelException($"{provider} did not answer in time.", ex);
            }
            using (response)
            {
                var body = await response.Content.ReadAsStringAsync(cancel);
                if (!response.IsSuccessStatusCode)
                    throw new ArkAgentModelException($"{provider} answered {(int)response.StatusCode}: {Short(body)}");
                try
                {
                    return JsonNode.Parse(body) ?? throw new JsonException("empty");
                }
                catch (JsonException)
                {
                    throw new ArkAgentModelException($"{provider} answered with something that is not JSON: {Short(body)}");
                }
            }
        }

        internal static string Short(string text) => text.Length <= 300 ? text : text[..300] + "…";

        internal static StringContent Json(JsonObject body) => new(body.ToJsonString(), Encoding.UTF8, "application/json");

        /// <summary>Whether an OpenAI-style answer stopped at the length limit.</summary>
        internal static bool CutOff(JsonNode? node) =>
            node is JsonObject o && o["choices"] is JsonArray { Count: > 0 } choices
            && choices[0]?["finish_reason"] is JsonValue reason && reason.TryGetValue<string>(out var why) && why is "length" or "max_tokens";

        /// <summary>The text of an OpenAI-style answer, wherever the gateway wrapped it.</summary>
        internal static string? ChatText(JsonNode? node)
        {
            if (node is not JsonObject o) return null;
            if (o["choices"] is JsonArray { Count: > 0 } choices && choices[0]?["message"]?["content"] is { } content)
            {
                if (content is JsonValue v && v.TryGetValue<string>(out var text)) return text;
                // Content as parts: [{ "type": "text", "text": "…" }]
                if (content is JsonArray parts)
                    return string.Concat(parts.Select(p => p?["text"]?.GetValue<string>() ?? ""));
            }
            return null;
        }
    }

    /// <summary>
    /// GenericLLM: <c>{ name, email, query, model }</c> in, an OpenAI-style completion
    /// under <c>result</c> out. It takes one string, so instructions and message travel as one.
    /// </summary>
    internal sealed class GenericLlmModel : IArkAgentModel
    {
        readonly GenericLlmOptions _o;
        readonly HttpClient _http;

        public GenericLlmModel(GenericLlmOptions options, HttpClient http)
        {
            _o = options;
            _http = http;
        }

        public string Label => $"GenericLLM · {_o.Model.Split(':')[0]}";

        public async Task<string> CompleteAsync(string instructions, string message, CancellationToken cancel)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, _o.Url)
            {
                Content = AgentModelFactory.Json(new JsonObject
                {
                    ["name"] = _o.Name ?? "",
                    ["email"] = _o.Email ?? "",
                    ["query"] = instructions + "\n\n=====\n\n" + message,
                    ["model"] = _o.Model
                })
            };
            if (!string.IsNullOrWhiteSpace(_o.ApiKey)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _o.ApiKey);

            var answer = await AgentModelFactory.PostAsync(_http, request, "GenericLLM", cancel);
            var text = AgentModelFactory.ChatText(answer["result"]) ?? AgentModelFactory.ChatText(answer);
            // The gateway allows about 1,000 tokens for thinking and answer together, and a model
            // that thinks first can use them all up. That is an answer cut off before its first
            // word, not a failure: the harness asks again.
            if (string.IsNullOrEmpty(text) && AgentModelFactory.CutOff(answer["result"] ?? answer)) return "";
            if (text == null)
                foreach (var key in new[] { "result", "answer", "output", "response", "content" })
                    if (answer[key] is JsonValue v && v.TryGetValue<string>(out var plain)) { text = plain; break; }
            return text ?? throw new ArkAgentModelException("GenericLLM answered without any text: " + AgentModelFactory.Short(answer.ToJsonString()));
        }
    }

    /// <summary>
    /// A deployment in Azure AI Foundry. Two request shapes, because Foundry serves two: the
    /// OpenAI-compatible chat completions route for every model, and the Messages route for
    /// Claude deployments.
    /// </summary>
    internal sealed class AzureFoundryModel : IArkAgentModel
    {
        readonly AzureFoundryOptions _o;
        readonly int _maxTokens;
        readonly Func<CancellationToken, ValueTask<string>>? _token;
        readonly HttpClient _http;

        public AzureFoundryModel(AzureFoundryOptions options, int maxTokens, Func<CancellationToken, ValueTask<string>>? token, HttpClient http)
        {
            _o = options;
            _maxTokens = maxTokens;
            _token = token;
            _http = http;
        }

        public string Label => $"Azure Foundry · {_o.Deployment}";

        bool Anthropic => (_o.Api ?? "auto").Trim().ToLowerInvariant() switch
        {
            "anthropic" or "messages" => true,
            "chat" or "openai" => false,
            _ => (_o.Deployment ?? "").StartsWith("claude", StringComparison.OrdinalIgnoreCase)
                 || (_o.Url ?? "").Contains("/anthropic/", StringComparison.OrdinalIgnoreCase)
        };

        public async Task<string> CompleteAsync(string instructions, string message, CancellationToken cancel)
        {
            var root = (_o.Endpoint ?? "").TrimEnd('/');
            var anthropic = Anthropic;
            var url = !string.IsNullOrWhiteSpace(_o.Url) ? _o.Url!
                : anthropic ? $"{root}/anthropic/v1/messages" : $"{root}/openai/v1/chat/completions";

            JsonObject body = anthropic
                ? new JsonObject
                {
                    ["model"] = _o.Deployment,
                    ["max_tokens"] = _maxTokens,
                    ["system"] = instructions,
                    ["messages"] = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = message })
                }
                // No sampling settings and no output limit: what each is called, and whether it is
                // accepted at all, differs between the models Foundry hosts.
                : new JsonObject
                {
                    ["model"] = _o.Deployment,
                    ["messages"] = new JsonArray(
                        new JsonObject { ["role"] = "system", ["content"] = instructions },
                        new JsonObject { ["role"] = "user", ["content"] = message })
                };

            var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = AgentModelFactory.Json(body) };
            if (_token != null)
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await _token(cancel));
            else if (!string.IsNullOrWhiteSpace(_o.ApiKey))
            {
                request.Headers.TryAddWithoutValidation("api-key", _o.ApiKey);
                if (anthropic) request.Headers.TryAddWithoutValidation("x-api-key", _o.ApiKey);
            }
            if (anthropic) request.Headers.TryAddWithoutValidation("anthropic-version", "2023-06-01");

            var answer = await AgentModelFactory.PostAsync(_http, request, "Azure Foundry", cancel);
            if (!anthropic)
                return AgentModelFactory.ChatText(answer) is { Length: > 0 } chat ? chat
                    : AgentModelFactory.CutOff(answer) ? ""
                    : throw new ArkAgentModelException("Azure Foundry answered without any text: " + AgentModelFactory.Short(answer.ToJsonString()));

            // A refusal is a 200 with nothing usable in it: say so instead of parsing air.
            if (answer["stop_reason"]?.GetValue<string>() == "refusal")
                throw new ArkAgentModelException("the model declined to answer that.");
            var text = string.Concat((answer["content"] as JsonArray ?? new JsonArray())
                .Where(b => b?["type"]?.GetValue<string>() == "text").Select(b => b!["text"]?.GetValue<string>() ?? ""));
            return text.Length > 0 || answer["stop_reason"]?.GetValue<string>() == "max_tokens" ? text
                : throw new ArkAgentModelException("Azure Foundry answered without any text: " + AgentModelFactory.Short(answer.ToJsonString()));
        }
    }

    /// <summary>
    /// A model in Amazon Bedrock through the Converse API, which is the same request for every
    /// model Bedrock hosts. Authenticated with a Bedrock API key when there is one, otherwise
    /// signed with SigV4.
    /// </summary>
    internal sealed class BedrockModel : IArkAgentModel
    {
        readonly BedrockOptions _o;
        readonly int _maxTokens;
        readonly Func<CancellationToken, ValueTask<AwsCredentials>>? _credentials;
        readonly HttpClient _http;

        public BedrockModel(BedrockOptions options, int maxTokens, Func<CancellationToken, ValueTask<AwsCredentials>>? credentials, HttpClient http)
        {
            _o = options;
            _maxTokens = maxTokens;
            _credentials = credentials;
            _http = http;
        }

        public string Label => $"Amazon Bedrock · {_o.ModelId}";

        static string? Env(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null;

        string Region => _o.Region ?? Env("AWS_REGION") ?? Env("AWS_DEFAULT_REGION")
            ?? throw new ArkAgentModelException("Bedrock needs a region: set Llm:Bedrock:Region or AWS_REGION.");

        public async Task<string> CompleteAsync(string instructions, string message, CancellationToken cancel)
        {
            var region = Region;
            var root = (_o.Endpoint ?? $"https://bedrock-runtime.{region}.amazonaws.com").TrimEnd('/');
            var uri = new Uri($"{root}/model/{Uri.EscapeDataString(_o.ModelId!)}/converse");
            var payload = Encoding.UTF8.GetBytes(new JsonObject
            {
                ["system"] = new JsonArray(new JsonObject { ["text"] = instructions }),
                ["messages"] = new JsonArray(new JsonObject
                {
                    ["role"] = "user",
                    ["content"] = new JsonArray(new JsonObject { ["text"] = message })
                }),
                ["inferenceConfig"] = new JsonObject { ["maxTokens"] = _maxTokens }
            }.ToJsonString());

            var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new ByteArrayContent(payload) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var apiKey = _o.ApiKey ?? Env("AWS_BEARER_TOKEN_BEDROCK");
            if (!string.IsNullOrWhiteSpace(apiKey))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            else
            {
                var credentials = _credentials != null ? await _credentials(cancel)
                    : (_o.AccessKeyId ?? Env("AWS_ACCESS_KEY_ID")) is { } id && (_o.SecretAccessKey ?? Env("AWS_SECRET_ACCESS_KEY")) is { } secret
                        ? new AwsCredentials(id, secret, _o.SessionToken ?? Env("AWS_SESSION_TOKEN"))
                        : throw new ArkAgentModelException(
                            "Bedrock needs a credential: an API key (Llm:Bedrock:ApiKey or AWS_BEARER_TOKEN_BEDROCK), access keys, or AwsCredentialsProvider.");
                AwsSigV4.Sign(request, payload, credentials, region, "bedrock", DateTime.UtcNow);
            }

            var answer = await AgentModelFactory.PostAsync(_http, request, "Bedrock", cancel);
            var text = string.Concat((answer["output"]?["message"]?["content"] as JsonArray ?? new JsonArray())
                .Select(b => b?["text"]?.GetValue<string>() ?? ""));
            return text.Length > 0 || answer["stopReason"]?.GetValue<string>() == "max_tokens" ? text
                : throw new ArkAgentModelException("Bedrock answered without any text: " + AgentModelFactory.Short(answer.ToJsonString()));
        }
    }
}
