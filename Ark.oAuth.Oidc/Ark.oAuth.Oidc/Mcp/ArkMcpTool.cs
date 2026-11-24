using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Ark.oAuth.Oidc.Mcp
{
    /// <summary>What a tool does to what it reaches, and so which scope a token needs for it.</summary>
    internal enum ArkMcpAccess
    {
        /// <summary>About the caller alone. Any token addressed to the endpoint may call it.</summary>
        Self,
        /// <summary>Looks. Needs <see cref="ArkMcpScopes.Read"/>.</summary>
        Read,
        /// <summary>Changes. Needs <see cref="ArkMcpScopes.Manage"/>.</summary>
        Manage
    }

    /// <summary>Who may call a tool.</summary>
    internal enum ArkMcpRole
    {
        Anyone,
        /// <summary>A person, or an agent carrying one.</summary>
        Person,
        ClientAdmin,
        TenantAdmin,
        Operator,
        Setup
    }

    internal sealed class ArkMcpTool
    {
        public string Name { get; init; } = "";
        public string Title { get; init; } = "";
        public string Description { get; init; } = "";
        public ArkMcpAccess Access { get; init; } = ArkMcpAccess.Read;
        public ArkMcpRole Role { get; init; } = ArkMcpRole.Anyone;
        public ArkMcpParams Params { get; init; } = new();
        /// <summary>Takes something away, or cannot be undone.</summary>
        public bool Destructive { get; init; }
        /// <summary>Calling it again with the same arguments changes nothing more.</summary>
        public bool Idempotent { get; init; }
        /// <summary>Reaches beyond this server: sends mail, contacts an audit node.</summary>
        public bool OpenWorld { get; init; }
        /// <summary>Answered with something shown once: a secret or a link that sets a password.</summary>
        public bool ReturnsSecret { get; init; }
        /// <summary>Offered only when this holds: a module the host did not add, say.</summary>
        public Func<ArkMcpCall, bool>? When { get; init; }
        public Func<ArkMcpCall, Task<object>> Run { get; init; } = _ => Task.FromResult<object>(new { });

        public bool Allows(ArkMcpCaller caller) => Role switch
        {
            ArkMcpRole.Anyone => caller.Kind != "setup" || Access == ArkMcpAccess.Self,
            ArkMcpRole.Person => caller.IsUser,
            ArkMcpRole.ClientAdmin => caller.ClientAdmin,
            ArkMcpRole.TenantAdmin => caller.TenantAdmin,
            ArkMcpRole.Operator => caller.Operator,
            ArkMcpRole.Setup => caller.Kind == "setup",
            _ => false
        };

        public JsonObject Describe()
        {
            var tool = new JsonObject
            {
                ["name"] = Name,
                ["title"] = Title,
                ["description"] = Description,
                ["inputSchema"] = Params.Schema(),
                ["annotations"] = new JsonObject
                {
                    ["title"] = Title,
                    ["readOnlyHint"] = Access != ArkMcpAccess.Manage,
                    ["destructiveHint"] = Destructive,
                    ["idempotentHint"] = Idempotent || Access != ArkMcpAccess.Manage,
                    ["openWorldHint"] = OpenWorld
                }
            };
            return tool;
        }
    }

    /// <summary>A tool could not do what was asked, for a reason the caller can act on.</summary>
    internal sealed class ArkMcpToolException : Exception
    {
        public string Code { get; }
        public object? Details { get; }

        public ArkMcpToolException(string code, string message, object? details = null) : base(message)
        {
            Code = code;
            Details = details;
        }
    }

    // -------------------------------------------------------------------- parameters

    internal sealed class ArkMcpParam
    {
        public string Name { get; init; } = "";
        /// <summary><c>string</c>, <c>integer</c>, <c>boolean</c>, <c>array</c> (of strings), <c>object</c> or <c>objects</c> (an array of them).</summary>
        public string Type { get; init; } = "string";
        public string Description { get; init; } = "";
        public bool Required { get; init; }
        public string[]? Values { get; init; }
        public string? Pattern { get; init; }
        public int? MaxLength { get; init; }
        public int? Min { get; init; }
        public int? Max { get; init; }
        /// <summary>A secret: never echoed back, never written to the audit trail.</summary>
        public bool Sensitive { get; init; }
        public ArkMcpParams? Nested { get; init; }
    }

    /// <summary>
    /// A tool's parameters: the JSON Schema it publishes and the check its arguments go through,
    /// from one definition, so the two cannot say different things.
    /// </summary>
    internal sealed class ArkMcpParams
    {
        public List<ArkMcpParam> Items { get; } = new();

        public ArkMcpParams Add(ArkMcpParam p) { Items.Add(p); return this; }

        public ArkMcpParams Text(string name, string description, bool required = false, string[]? values = null,
            string? pattern = null, int maxLength = 2000, bool sensitive = false) =>
            Add(new ArkMcpParam { Name = name, Type = "string", Description = description, Required = required, Values = values, Pattern = pattern, MaxLength = maxLength, Sensitive = sensitive });

        public ArkMcpParams Int(string name, string description, bool required = false, int? min = null, int? max = null) =>
            Add(new ArkMcpParam { Name = name, Type = "integer", Description = description, Required = required, Min = min, Max = max });

        public ArkMcpParams Flag(string name, string description, bool required = false) =>
            Add(new ArkMcpParam { Name = name, Type = "boolean", Description = description, Required = required });

        public ArkMcpParams List(string name, string description, bool required = false, string[]? values = null) =>
            Add(new ArkMcpParam { Name = name, Type = "array", Description = description, Required = required, Values = values, MaxLength = 2000, Max = 200 });

        public ArkMcpParams Object(string name, string description, ArkMcpParams nested, bool required = false) =>
            Add(new ArkMcpParam { Name = name, Type = "object", Description = description, Required = required, Nested = nested });

        public ArkMcpParams Objects(string name, string description, ArkMcpParams nested, bool required = false, int max = 100) =>
            Add(new ArkMcpParam { Name = name, Type = "objects", Description = description, Required = required, Nested = nested, Max = max });

        public JsonObject Schema()
        {
            var schema = new JsonObject { ["type"] = "object" };
            var properties = new JsonObject();
            foreach (var p in Items) properties[p.Name] = SchemaOf(p);
            schema["properties"] = properties;
            var required = Items.Where(p => p.Required).Select(p => (JsonNode?)JsonValue.Create(p.Name)).ToArray();
            if (required.Length > 0) schema["required"] = new JsonArray(required);
            schema["additionalProperties"] = false;
            return schema;
        }

        static JsonObject SchemaOf(ArkMcpParam p)
        {
            JsonObject schema;
            switch (p.Type)
            {
                case "array":
                    var item = new JsonObject { ["type"] = "string" };
                    if (p.Values != null) item["enum"] = Strings(p.Values);
                    schema = new JsonObject { ["type"] = "array", ["items"] = item };
                    break;
                case "object":
                    schema = p.Nested!.Schema();
                    break;
                case "objects":
                    schema = new JsonObject { ["type"] = "array", ["items"] = p.Nested!.Schema() };
                    break;
                default:
                    schema = new JsonObject { ["type"] = p.Type };
                    if (p.Values != null) schema["enum"] = Strings(p.Values);
                    if (p.Pattern != null) schema["pattern"] = p.Pattern;
                    if (p.Min != null) schema["minimum"] = p.Min;
                    if (p.Max != null) schema["maximum"] = p.Max;
                    break;
            }
            schema["description"] = p.Description;
            return schema;
        }

        static JsonArray Strings(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());

        /// <summary>Checks arguments against the definition. Every problem at once, so one retry can fix them all.</summary>
        public ArkMcpArgs Read(JsonElement? arguments)
        {
            var problems = new List<string>();
            var args = Read(arguments, "", problems);
            if (problems.Count > 0)
                throw new ArkMcpToolException("invalid_arguments", string.Join(" ", problems), new { problems });
            return args;
        }

        ArkMcpArgs Read(JsonElement? element, string at, List<string> problems)
        {
            var values = new Dictionary<string, object?>(StringComparer.Ordinal);
            if (element is { ValueKind: not (JsonValueKind.Object or JsonValueKind.Null or JsonValueKind.Undefined) })
            {
                problems.Add($"{(at.Length == 0 ? "arguments" : at)} must be an object.");
                return new ArkMcpArgs(values);
            }
            if (element is { ValueKind: JsonValueKind.Object } obj)
            {
                foreach (var property in obj.EnumerateObject())
                {
                    var p = Items.FirstOrDefault(i => i.Name == property.Name);
                    if (p == null)
                    {
                        problems.Add($"'{at}{property.Name}' is not a parameter here; there are: {(Items.Count == 0 ? "none" : string.Join(", ", Items.Select(i => i.Name)))}.");
                        continue;
                    }
                    if (property.Value.ValueKind == JsonValueKind.Null) continue;
                    var value = ReadOne(p, property.Value, at, problems);
                    if (value != null) values[p.Name] = value;
                }
            }
            foreach (var p in Items.Where(p => p.Required && !values.ContainsKey(p.Name)))
                if (!problems.Any(m => m.StartsWith($"'{at}{p.Name}'", StringComparison.Ordinal)))
                    problems.Add($"'{at}{p.Name}' is required: {p.Description}");
            return new ArkMcpArgs(values);
        }

        object? ReadOne(ArkMcpParam p, JsonElement value, string at, List<string> problems)
        {
            var name = $"'{at}{p.Name}'";
            object? Wrong(string expected) { problems.Add($"{name} must be {expected}."); return null; }

            switch (p.Type)
            {
                case "string":
                    if (value.ValueKind != JsonValueKind.String) return Wrong("a string");
                    var text = value.GetString()!.Trim();
                    if (p.MaxLength is { } max && text.Length > max) return Wrong($"at most {max} characters");
                    if (text.Length == 0 && p.Required) return Wrong("given");
                    if (p.Values != null && text.Length > 0 && !p.Values.Contains(text, StringComparer.Ordinal))
                        return Wrong($"one of: {string.Join(", ", p.Values)}");
                    if (p.Pattern != null && text.Length > 0 && !Regex.IsMatch(text, p.Pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)))
                        return Wrong($"of the form {p.Pattern}");
                    return text;
                case "integer":
                    if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number)) return Wrong("a whole number");
                    if (number < (p.Min ?? int.MinValue) || number > (p.Max ?? int.MaxValue))
                        return Wrong($"between {p.Min ?? int.MinValue} and {p.Max ?? int.MaxValue}");
                    return number;
                case "boolean":
                    if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return Wrong("true or false");
                    return value.GetBoolean();
                case "array":
                    if (value.ValueKind != JsonValueKind.Array) return Wrong("a list of strings");
                    var list = new List<string>();
                    foreach (var item in value.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.String) return Wrong("a list of strings");
                        var entry = item.GetString()!.Trim();
                        if (entry.Length == 0) continue;
                        if (entry.Length > (p.MaxLength ?? 2000)) return Wrong($"a list of strings of at most {p.MaxLength} characters");
                        if (p.Values != null && !p.Values.Contains(entry, StringComparer.Ordinal))
                            return Wrong($"a list of: {string.Join(", ", p.Values)}");
                        if (!list.Contains(entry, StringComparer.Ordinal)) list.Add(entry);
                    }
                    if (p.Max is { } most && list.Count > most) return Wrong($"a list of at most {most}");
                    return list;
                case "object":
                    return value.ValueKind != JsonValueKind.Object ? Wrong("an object") : p.Nested!.Read(value, $"{at}{p.Name}.", problems);
                default:
                    if (value.ValueKind != JsonValueKind.Array) return Wrong("a list of objects");
                    if (value.GetArrayLength() > (p.Max ?? 100)) return Wrong($"a list of at most {p.Max ?? 100}");
                    var i = 0;
                    return value.EnumerateArray().Select(e => p.Nested!.Read(e, $"{at}{p.Name}[{i++}].", problems)).ToList();
            }
        }
    }

    /// <summary>Arguments that have passed their tool's definition.</summary>
    internal sealed class ArkMcpArgs
    {
        readonly Dictionary<string, object?> _values;
        public ArkMcpArgs(Dictionary<string, object?> values) => _values = values;

        public IEnumerable<string> Names => _values.Keys;
        public bool Has(string name) => _values.ContainsKey(name);
        /// <summary>The text given, or null when it was left out or blank.</summary>
        public string? Text(string name) => _values.GetValueOrDefault(name) is string { Length: > 0 } s ? s : null;
        /// <summary>The text given, blank included: how a field is cleared.</summary>
        public string? Raw(string name) => _values.GetValueOrDefault(name) as string;
        public string Required(string name) => Text(name)
            ?? throw new ArkMcpToolException("invalid_arguments", $"'{name}' is required.");
        public int? Int(string name) => _values.GetValueOrDefault(name) as int?;
        public bool? Flag(string name) => _values.GetValueOrDefault(name) as bool?;
        public List<string>? List(string name) => _values.GetValueOrDefault(name) as List<string>;
        public ArkMcpArgs? Object(string name) => _values.GetValueOrDefault(name) as ArkMcpArgs;
        public List<ArkMcpArgs>? Objects(string name) => _values.GetValueOrDefault(name) as List<ArkMcpArgs>;
    }

    // -------------------------------------------------------------------- a call

    /// <summary>One tool call: who, where, with what.</summary>
    internal sealed class ArkMcpCall
    {
        public HttpContext Http { get; init; } = default!;
        public ArkMcpEndpoint Endpoint { get; init; } = default!;
        public ArkMcpCaller Caller { get; init; } = default!;
        public ArkMcpTool Tool { get; init; } = default!;
        public ArkMcpArgs Args { get; set; } = new(new());
        /// <summary>Who or what the call acted on, for the audit trail: client, user, tenant.</summary>
        public Dictionary<string, string> Subjects { get; } = new(StringComparer.Ordinal);

        public IServiceProvider Services => Http.RequestServices;
        public T Get<T>() where T : notnull => Services.GetRequiredService<T>();
        public ArkDataContext Db => Get<ArkDataContext>();
        public DataAccess Da => Get<DataAccess>();
        public ArkAuthServerConfig Config => Endpoint.Config;
        public ArkTenant Tenant => Endpoint.Tenant ?? throw new InvalidOperationException("no tenant at this level.");
        public ArkClient Client => Endpoint.Client ?? throw new InvalidOperationException("no application at this level.");

        public void Touches(string what, string? which)
        {
            if (!string.IsNullOrWhiteSpace(which)) Subjects[what] = which!;
        }

        /// <summary>
        /// The caller repeats the name of what it is about to take away. An agent that got the
        /// wrong identifier from somewhere is stopped by having to write it twice.
        /// </summary>
        public void Confirm(string expected, string effect)
        {
            if (!string.Equals(Args.Text("confirm"), expected, StringComparison.Ordinal))
                throw new ArkMcpToolException("confirmation_required",
                    $"{effect} To go ahead, call again with confirm set to \"{expected}\".", new { confirm = expected });
        }
    }

    /// <summary>JSON as these endpoints write it.</summary>
    internal static class ArkMcpJson
    {
        public static readonly JsonSerializerOptions Options = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        /// <summary>For the public documents: people open those in a browser tab as well.</summary>
        public static readonly JsonSerializerOptions Indented = new(Options) { WriteIndented = true };

        public static JsonNode? Node(object? value) => JsonSerializer.SerializeToNode(value, Options);
    }
}
