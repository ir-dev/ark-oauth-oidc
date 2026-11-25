using Ark.Agents.TenantOnboarding.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ark.Agents.TenantOnboarding
{
    public static class ArkOnboardingAgentExtensions
    {
        /// <summary>
        /// Adds the onboarding agent to an ASP.NET Core application.
        ///
        /// An application that is the identity server has it already: <c>AddArkOidcServer</c> (and so
        /// <c>AddArkIdp</c>) registers it, and the setup wizard links to its page. Calling this there
        /// as well only adds to its settings. The call is for an application that is <em>not</em> the
        /// server it sets up (<c>McpUrl</c> and <c>SetupCode</c>):
        ///
        /// <code>
        /// builder.Services.AddArkOnboardingAgent(builder.Configuration);
        /// </code>
        ///
        /// It registers a background service, which works the server's MCP setup tools with the setup
        /// code, and puts the agent's page (<c>/ark-agent</c>) at the front of the request pipeline.
        /// Settings come from the <c>ark_onboarding_agent</c> section; none is required.
        /// </summary>
        public static IServiceCollection AddArkOnboardingAgent(this IServiceCollection services, IConfiguration configuration,
            Action<ArkOnboardingAgentOptions>? configure = null)
        {
            AddCore(services);
            services.AddOptions<ArkOnboardingAgentOptions>().Bind(configuration.GetSection(ArkOnboardingAgentOptions.Section));
            if (configure != null) services.Configure(configure);
            services.TryAddEnumerable(ServiceDescriptor.Transient<IStartupFilter, AgentStartupFilter>());
            return services;
        }

        /// <summary>
        /// The identity server's own registration: the same agent, whose page the server places itself
        /// with <see cref="UseBuiltIn"/>, beside its setup wizard and behind whatever the host put first.
        /// </summary>
        internal static IServiceCollection AddBuiltIn(IServiceCollection services)
        {
            // Bound once: a host that has already called AddArkOnboardingAgent has the last word.
            if (AddCore(services)) services.AddOptions<ArkOnboardingAgentOptions>().BindConfiguration(ArkOnboardingAgentOptions.Section);
            services.TryAddSingleton<AgentBuiltInMarker>();
            return services;
        }

        /// <summary>
        /// Puts the agent's page here in the pipeline. Does nothing when there is no setup for the agent
        /// to do: a server that is set up has no route of the agent's, not even one that answers 404.
        /// </summary>
        internal static IApplicationBuilder UseBuiltIn(this IApplicationBuilder app)
        {
            var services = app.ApplicationServices;
            if (services.GetService<SetupCodeBox>() == null) return app;
            var options = services.GetRequiredService<IOptions<ArkOnboardingAgentOptions>>().Value;
            return AgentGate.HasWork(services.GetRequiredService<IConfiguration>(), options) ? app.UseMiddleware<AgentMiddleware>() : app;
        }

        static bool AddCore(IServiceCollection services)
        {
            if (services.Any(d => d.ServiceType == typeof(SetupCodeBox))) return false;
            services.AddSingleton<SetupCodeBox>();
            // In the logging pipeline from the first line: the setup code is announced once, early.
            services.AddSingleton<ILoggerProvider, SetupCodeLoggerProvider>();
            // Only built when there is a setup to do: see AgentGate.
            services.AddSingleton<AgentRuntime>();
            services.AddSingleton<AgentAccess>();
            services.AddSingleton<AgentStatusReader>();
            services.AddHostedService<OnboardingAgentService>();
            return true;
        }

        /// <summary>Puts the agent first in the pipeline, in an application that does not place it itself.</summary>
        sealed class AgentStartupFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
            {
                // The identity server places the page itself, where its own wizard is.
                if (app.ApplicationServices.GetService<AgentBuiltInMarker>() == null) app.UseBuiltIn();
                next(app);
            };
        }
    }

    /// <summary>The identity server in this application brought the agent, and places its page.</summary>
    internal sealed class AgentBuiltInMarker
    {
    }
}
