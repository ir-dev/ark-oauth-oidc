using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Ark.Agents.TenantOnboarding.Brain
{
    /// <summary>
    /// What can be worked out without asking anybody: from where the server runs, from the
    /// application it shares a process with, and from what has been said so far. Everything it
    /// produces is a proposal a person accepts with a click. Nothing here stores a value.
    /// </summary>
    internal static class Advisor
    {
        /// <summary>Looks at the host before anyone arrives. No secret leaves this method except into the vault.</summary>
        public static JsonObject Scout(IConfiguration config, IHostEnvironment env, Vault vault, bool databasesToo = true)
        {
            static string? Var(string name) => System.Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null;

            var facts = new JsonObject { ["environment"] = env.EnvironmentName };
            var advice = new JsonArray();

            if (Var("WEBSITE_SITE_NAME") != null)
            {
                facts["hosting"] = "Azure App Service";
                if (Var("WEBSITE_HOSTNAME") is { } host) facts["public_address_hint"] = $"https://{host}";
                advice.Add("On App Service only /home survives a restart: the data directory has to be under it (ark_oauth_server__Setup__DataPath), set before setup is finished.");
            }
            else if (Var("KUBERNETES_SERVICE_HOST") != null)
            {
                facts["hosting"] = "Kubernetes";
                advice.Add("In a pod the data directory needs a persistent volume, and more than one replica needs PostgreSQL or MySQL.");
            }
            else if (string.Equals(Var("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase))
            {
                facts["hosting"] = "a container";
                advice.Add("In a container the data directory has to be a mounted volume, or the settings are gone at the next start.");
            }
            else facts["hosting"] = "a server or workstation, directly";

            // The application this agent lives in very often has a database already. Knowing which
            // kind, and where, turns "which database?" into "the same server as your app?".
            var databases = new JsonArray();
            foreach (var entry in databasesToo ? config.GetSection("ConnectionStrings").GetChildren() : Enumerable.Empty<IConfigurationSection>())
            {
                if (entry.Key.Equals("ArkAuthConnection", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(entry.Value)) continue;
                if (Scrubber.Classify(entry.Value, vault) is not { } found) continue;
                // The password stays in the vault: what is kept here is its placeholder.
                found["configured_as"] = $"ConnectionStrings:{entry.Key}";
                databases.Add(found);
            }
            if (databases.Count > 0) facts["application_databases"] = databases;
            if (advice.Count > 0) facts["advice"] = advice;
            return facts;
        }

        static readonly Regex CompanySuffix = new(
            @"\b(incorporated|inc|corp|corporation|company|co|ltd|limited|llc|llp|plc|gmbh|ag|sa|sas|bv|nv|ab|oy|pty|pvt|private|group|holdings)\b\.?",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>A tenant id for an organization: its name, short and lower-case, without the legal form.</summary>
        public static string? TenantIdFor(string company)
        {
            var name = CompanySuffix.Replace(company, " ");
            name = Regex.Replace(name.ToLowerInvariant().Normalize(System.Text.NormalizationForm.FormD), @"\p{Mn}", "");
            name = Regex.Replace(name, @"[^a-z0-9]+", "-").Trim('-');
            if (name.Length > 40) name = name[..40].Trim('-');
            return name.Length >= 2 ? name : null;
        }

        /// <summary>
        /// Proposals that follow from what is known now, for one person. Only for values that are
        /// still missing and that nobody has been asked to confirm already.
        /// </summary>
        /// <param name="guided">
        /// No model is reading the conversation. With one, "the address you are on" is its call to
        /// make for a loopback address: the person may just have said where the server will live.
        /// </param>
        public static List<Proposal> Infer(Workspace ws, Participant p, bool guided)
        {
            var proposals = new List<Proposal>();
            if (!p.IsLead) return proposals;

            bool Open(string section, string field) =>
                !ws.Has($"{section}.{field}") && !ws.Proposals.Any(x => x.Section == section && x.Field == field && x.State != "accepted");

            lock (ws.Sync)
            {
                if (ws.ValueText("organization.company_name") is { } company && Open("server", "tenant_id") && TenantIdFor(company) is { } tenant)
                    proposals.Add(New(p, "server", "tenant_id", tenant,
                        $"A short form of “{company}”. It becomes part of every token's issuer and cannot be renamed later."));

                if (Open("server", "base_url"))
                {
                    var hint = ws.Environment["public_address_hint"]?.GetValue<string>();
                    var origin = hint ?? p.Origin;
                    if (!string.IsNullOrEmpty(origin) && Uri.TryCreate(origin, UriKind.Absolute, out var uri) && (uri.Scheme == "https" || uri.IsLoopback)
                        && (guided || hint != null || !uri.IsLoopback))
                        proposals.Add(New(p, "server", "base_url", origin.TrimEnd('/'), hint != null
                            ? "The address this App Service answers on. Use your own domain instead if people will reach it under one."
                            : uri.IsLoopback
                                ? "The address you are using right now. Right for a trial on this machine; a server other people use needs its public https address."
                                : "The address your browser reached me at, so it certainly leads here. It becomes part of every token's issuer."));
                }
            }
            return proposals;
        }

        static Proposal New(Participant p, string section, string field, JsonNode value, string why) => new()
        {
            Id = Workspace.NewId(), Section = section, Field = field, Value = value, Why = why, ParticipantId = p.Id
        };

        // ------------------------------------------------------------ advice that needs no model

        /// <summary>What the greeting offers as places to start. Choosing one is never the answer to a question.</summary>
        public const string Trial = "Just trying it out on this machine", Production = "Production, for my organization",
            Regulated = "A regulated or high-security environment", Others = "Other people have some of the answers";

        public static bool IsStart(string text) => text.Trim() is Trial or Production or Regulated or Others;

        const RegexOptions Flags = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        static readonly Regex RegulatedWords = new(
            @"(?<!\b(?:not|isn't|aren't|no|never)\b[^.]{0,24})\b(?:regulated|regulator|high-security|bank(?:ing)?|payments?|fintech|pci(?:[- ]dss)?|hipaa|health ?care|hospital|insurance|insurer|government|public sector|defen[cs]e|fca|sox|gxp)\b", Flags);
        static readonly Regex ProductionWords = new(@"(?<!\b(?:not|isn't|no|non)\b[^.]{0,16})\b(?:production|prod|go[- ]live)\b", Flags);

        /// <summary>
        /// What follows from the kind of organization somebody describes: the part of an
        /// architect's advice that is a rule rather than a judgement. Proposals, each with its
        /// reason, for settings nobody has chosen yet.
        /// </summary>
        public static (string? Say, List<Proposal> Proposals) Posture(Workspace ws, Participant p, string message)
        {
            var proposals = new List<Proposal>();
            if (!p.IsLead) return (null, proposals);
            var regulated = RegulatedWords.IsMatch(message);
            var production = regulated || ProductionWords.IsMatch(message);
            lock (ws.Sync)
            {
                void Suggest(string section, string field, JsonNode value, string why)
                {
                    if (ws.Section(section)?.Field(field) == null || ws.Has($"{section}.{field}")) return;
                    if (ws.Proposals.Any(x => x.ParticipantId == p.Id && x.Section == section && x.Field == field && x.State != "accepted")) return;
                    proposals.Add(New(p, section, field, value, why));
                }

                if (production) Suggest("database", "provider", "postgres", "Production belongs on PostgreSQL or MySQL: SQLite is one file on one machine, and a second instance is impossible with it.");
                if (regulated)
                {
                    Suggest("signing_key", "key_size", 3072, "Regulated environments usually ask for at least 3072-bit keys.");
                    Suggest("protocol", "session_lifetime_minutes", 90, "Shorter sessions limit what an unattended browser is worth.");
                    Suggest("protocol", "max_failed_sign_ins", 5, "Five attempts is what auditors expect.");
                    Suggest("protocol", "lockout_minutes", 30, "Long enough to make guessing pointless.");
                    Suggest("protocol", "always_require_consent", true, "People see what each application is given, first-party ones included.");
                }
            }
            return (proposals.Count == 0 ? null
                : regulated ? "For a regulated organization I would tighten these. Accept the ones you want."
                : "For production I would not stay on the default here.", proposals);
        }
    }
}
