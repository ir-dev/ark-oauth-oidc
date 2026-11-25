namespace Ark.Agents.TenantOnboarding
{
    /// <summary>
    /// Settings of the onboarding agent, bound from the <c>ark_onboarding_agent</c> section.
    /// Nothing is required: with no model configured the agent still works, in guided mode.
    /// </summary>
    public sealed class ArkOnboardingAgentOptions
    {
        public const string Section = "ark_onboarding_agent";

        public bool Enabled { get; set; } = true;

        /// <summary>Where the agent's page and API live in the host.</summary>
        public string PathPrefix { get; set; } = "/ark-agent";

        /// <summary>The name the agent introduces itself with.</summary>
        public string AgentName { get; set; } = "Ark Pilot";

        /// <summary>
        /// The identity server's setup MCP endpoint. Not set: this same app, at
        /// <c>/ark-idp/mcp</c> on the address it listens on.
        /// </summary>
        public string? McpUrl { get; set; }

        /// <summary>
        /// The setup code. Not set: captured from this app's start-up log, or read from
        /// <c>setup-code.txt</c> in the identity server's data directory.
        /// </summary>
        public string? SetupCode { get; set; }

        /// <summary>
        /// While the server is not set up, send a browser that opens <c>/</c> to the agent instead of the
        /// wizard. Off: it meets the wizard, whose first page links here.
        /// </summary>
        public bool GreetAtRoot { get; set; }

        /// <summary>How long a link handed to a colleague works.</summary>
        public int InviteLifetimeHours { get; set; } = 72;

        /// <summary>After this many hours without an answer, the board says a colleague has gone quiet.</summary>
        public int QuietAfterHours { get; set; } = 4;

        /// <summary>
        /// Look in the host application's <c>ConnectionStrings</c> for a database server identity could
        /// share. The kind of server, its host, database and account name are then part of what the
        /// language model is told on the lead's turns; passwords never are. Off, which is the default because
        /// the agent comes with every identity server and nobody asked for this: nothing is read.
        /// </summary>
        public bool LookForDatabases { get; set; }

        /// <summary>
        /// Send a browser that arrives over plain http to this server's https address, when it has one.
        /// The agent answers before the host's own redirect could. Loopback addresses are left alone.
        /// </summary>
        public bool RedirectToHttps { get; set; } = true;

        public LlmOptions Llm { get; set; } = new();

        /// <summary>
        /// A bearer token for Azure AI Foundry, in place of an API key: plug in
        /// <c>DefaultAzureCredential</c> here and the library needs no Azure package of its own.
        /// </summary>
        public Func<CancellationToken, ValueTask<string>>? AzureTokenProvider { get; set; }

        /// <summary>AWS credentials from the host's own chain (profile, instance role), in place of static keys.</summary>
        public Func<CancellationToken, ValueTask<AwsCredentials>>? AwsCredentialsProvider { get; set; }
    }

    public sealed record AwsCredentials(string AccessKeyId, string SecretAccessKey, string? SessionToken = null);

    public sealed class LlmOptions
    {
        /// <summary><c>generic_llm</c>, <c>ark_llm</c>, <c>azure_foundry</c>, <c>bedrock</c> or <c>none</c> (guided mode only).</summary>
        public string Provider { get; set; } = "none";
        public int TimeoutSeconds { get; set; } = 90;
        /// <summary>Upper bound on one answer. The answers are small; this is room for a model that thinks first.</summary>
        public int MaxTokens { get; set; } = 8192;

        public GenericLlmOptions GenericLLM { get; set; } = new();
        public ArkLlmOptions ArkLLM { get; set; } = new();
        public AzureFoundryOptions AzureFoundry { get; set; } = new();
        public BedrockOptions Bedrock { get; set; } = new();
    }

    /// <summary>GenericLLM: a flow gateway taking one JSON POST with <c>name</c>, <c>email</c>, <c>query</c> and <c>model</c>.</summary>
    public sealed class GenericLlmOptions
    {
        public string? Url { get; set; }
        /// <summary>The caller the gateway bills and audits. Keep both in user secrets or the environment.</summary>
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string Model { get; set; } = "eu.anthropic.claude-sonnet-4-6:aws-anthropic";
        /// <summary>Sent as a bearer token, for a gateway that asks for one.</summary>
        public string? ApiKey { get; set; }
    }

    /// <summary>
    /// ARK-LLM: a small open-weight model on a very small server. One JSON POST with the context in
    /// <c>message</c>, an <c>X-API-Key</c> header, and the answer as server-sent events.
    ///
    /// The server runs one inference at a time on a CPU, so everything here is a limit on what the
    /// agent may ask of it. Raise them only for a bigger server.
    /// </summary>
    public sealed class ArkLlmOptions
    {
        public string? Url { get; set; }
        /// <summary>Keep it in user secrets or the environment.</summary>
        public string? ApiKey { get; set; }
        /// <summary>The header the key travels in.</summary>
        public string ApiKeyHeader { get; set; } = "X-API-Key";
        /// <summary>The longest prompt sent, in characters (about four to a token). Nothing is cached between calls, so this is the cost of each.</summary>
        public int MaxPromptChars { get; set; } = 3600;
        /// <summary>The longest answer asked for, in tokens.</summary>
        public int MaxAnswerTokens { get; set; } = 200;
        /// <summary>How long one call may take altogether.</summary>
        public int TimeoutSeconds { get; set; } = 150;
        /// <summary>Quiet time left to the server between two calls.</summary>
        public int PauseSeconds { get; set; } = 3;
        /// <summary>How long a turn waits for another one's call to finish before it goes on without the model.</summary>
        public int MaxWaitSeconds { get; set; } = 60;
        /// <summary>Calls in any hour, from everybody in this process together. Past it the agent goes on without the model.</summary>
        public int MaxCallsPerHour { get; set; } = 40;
    }

    /// <summary>A model deployed in Azure AI Foundry (Microsoft Foundry).</summary>
    public sealed class AzureFoundryOptions
    {
        /// <summary>The resource, e.g. <c>https://my-resource.services.ai.azure.com</c>.</summary>
        public string? Endpoint { get; set; }
        /// <summary>The deployment name: what the request names as its model.</summary>
        public string? Deployment { get; set; }
        public string? ApiKey { get; set; }
        /// <summary>
        /// <c>chat</c>: the OpenAI-compatible chat completions route every Foundry model serves.
        /// <c>anthropic</c>: the Messages route Claude deployments serve. <c>auto</c> picks the
        /// second when the deployment's name starts with <c>claude</c>.
        /// </summary>
        public string Api { get; set; } = "auto";
        /// <summary>The whole request URL, for a deployment that is not at the standard path.</summary>
        public string? Url { get; set; }
    }

    /// <summary>A model in Amazon Bedrock, through the Converse API.</summary>
    public sealed class BedrockOptions
    {
        public string? Region { get; set; }
        /// <summary>A model id or inference profile, e.g. <c>eu.anthropic.claude-sonnet-4-6</c>.</summary>
        public string? ModelId { get; set; }
        /// <summary>A Bedrock API key (also read from <c>AWS_BEARER_TOKEN_BEDROCK</c>). Otherwise the request is signed (SigV4).</summary>
        public string? ApiKey { get; set; }
        /// <summary>Static keys (also read from the standard <c>AWS_*</c> environment variables).</summary>
        public string? AccessKeyId { get; set; }
        public string? SecretAccessKey { get; set; }
        public string? SessionToken { get; set; }
        /// <summary>The whole endpoint, for a VPC endpoint or a proxy.</summary>
        public string? Endpoint { get; set; }
    }
}
