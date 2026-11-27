using Ark.Agents.TenantOnboarding.Brain;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ark.Agents.TenantOnboarding.Hosting
{
    /// <summary>
    /// Where the conversation stands, for the page that links to it: the setup wizard's. Counts, and
    /// who is being waited for. No value anybody gave, no message, no secret.
    /// </summary>
    internal sealed record AgentStatus
    {
        public required string Name { get; init; }
        /// <summary>The agent's page, below the application's path base.</summary>
        public required string Path { get; init; }
        /// <summary><c>starting</c>: not connected to the setup tools yet. <c>collecting</c>: at work.</summary>
        public required string Phase { get; init; }
        /// <summary>While starting: what it is waiting for.</summary>
        public string? Why { get; init; }
        public bool Started { get; init; }
        public int EssentialsDone { get; init; }
        public int EssentialsTotal { get; init; }
        public bool ReadyForReview { get; init; }
        /// <summary>Confirmations and suggestions open on the lead's side of the conversation.</summary>
        public int WaitingForLead { get; init; }
        /// <summary>Colleagues who were asked and have not answered yet, by name and team.</summary>
        public IReadOnlyList<string> WaitingForColleagues { get; init; } = Array.Empty<string>();
        public DateTime? LastMessageAt { get; init; }
    }

    internal sealed class AgentStatusReader
    {
        readonly IServiceProvider _services;

        public AgentStatusReader(IServiceProvider services) => _services = services;

        /// <summary>Null when there is no agent view to link to: switched off, nothing to set up, or finished.</summary>
        public AgentStatus? Read()
        {
            var options = _services.GetRequiredService<IOptions<ArkOnboardingAgentOptions>>().Value;
            if (!AgentGate.HasWork(_services.GetRequiredService<IConfiguration>(), options)) return null;
            var rt = _services.GetRequiredService<AgentRuntime>();
            // Pointed at a server elsewhere, it is not this server's agent.
            if (!rt.SameProcess) return null;
            var ws = rt.Workspace;
            lock (ws.Sync)
            {
                if (ws.Phase is not (AgentPhase.Starting or AgentPhase.Collecting)) return null;
                var now = DateTime.UtcNow;
                var essentials = ws.EssentialKeys();
                return new AgentStatus
                {
                    Name = options.AgentName,
                    Path = rt.Prefix,
                    Phase = ws.Phase == AgentPhase.Collecting ? "collecting" : "starting",
                    Why = ws.Phase == AgentPhase.Starting ? ws.StartingWhy : null,
                    Started = ws.Conversations.Count > 0,
                    EssentialsDone = essentials.Count(ws.Values.ContainsKey),
                    EssentialsTotal = essentials.Length,
                    ReadyForReview = ws.ReadyForReview,
                    WaitingForLead = ws.Proposals.Count(x => x.State == "open" && ws.People.TryGetValue(x.ParticipantId, out var p) && p.IsLead),
                    WaitingForColleagues = ws.Invites.Where(i => i.Status(now, options.QuietAfterHours) is "sent" or "opened" or "quiet")
                        .Select(i => string.IsNullOrWhiteSpace(i.Name) ? i.Department : $"{i.Name} ({i.Department})").Distinct(StringComparer.Ordinal).ToArray(),
                    LastMessageAt = ws.Conversations.Values.SelectMany(c => c).Select(m => (DateTime?)m.At).Max()
                };
            }
        }
    }
}
