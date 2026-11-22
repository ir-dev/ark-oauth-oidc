using System.Net;
using Microsoft.AspNetCore.DataProtection;

namespace Ark.oAuth.Oidc.Webhooks
{
    public static class ArkWebhookExtensions
    {
        /// <summary>
        /// Adds the webhook subsystem: the Webhooks page in the admin console, its management API
        /// under /api/oauth/v1/webhooks, and the background services that queue, store and send
        /// events. Call it beside <c>AddArkOidcServer</c> or <c>AddArkIdp</c>, in either order.
        ///
        /// Opt-in by design. Without this call nothing of the module runs, its routes answer 404,
        /// the console shows no link and the IdP's events go nowhere — so upgrading the package
        /// changes nothing for a host until it asks for webhooks. With it, the control tables
        /// (ark_wh_endpoints, ark_wh_shards) are created on first use, beside but never inside the
        /// IdP's own schema; configuration is under <c>ark_oauth_server:Webhooks</c>.
        /// </summary>
        public static IServiceCollection AddArkWebhooks(this IServiceCollection services)
        {
            if (services.Any(d => d.ServiceType == typeof(ArkWebhookRegistry))) return services;

            services.AddDataProtection();
            services.AddSingleton<ArkWebhookDatabases>();
            services.AddSingleton<ArkWebhookSecrets>();
            services.AddSingleton<ArkWebhookSignal>();

            services.AddSingleton<ArkWebhookRegistry>();
            services.AddHostedService(sp => sp.GetRequiredService<ArkWebhookRegistry>());

            services.AddSingleton<ArkWebhookFanout>();
            services.AddSingleton<ArkWebhookPublisher>();
            services.AddSingleton<IArkWebhookPublisher>(sp => sp.GetRequiredService<ArkWebhookPublisher>());
            services.AddSingleton<ArkWebhookIngestor>();
            services.AddHostedService(sp => sp.GetRequiredService<ArkWebhookIngestor>());

            services.AddSingleton<ArkWebhookTokenManager>();
            services.AddSingleton<ArkWebhookSender>();
            services.AddSingleton<ArkWebhookDispatcher>();
            services.AddHostedService(sp => sp.GetRequiredService<ArkWebhookDispatcher>());

            services.AddScoped<ArkWebhookService>();

            // Its own client: no redirects (a 3xx is an answer), no cookies (nothing a receiver
            // sets may ride on the next receiver's request), and pooled connections recycled so a
            // receiver that moves to another address is found again.
            // Its per-request log lines are removed too: they carry the full URL, and some receivers
            // keep their secret in the path. Attempts are recorded in the delivery history instead.
            services.AddHttpClient(ArkWebhookSender.HttpClientName, c => c.Timeout = Timeout.InfiniteTimeSpan)
                .RemoveAllLoggers()
                .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    AutomaticDecompression = DecompressionMethods.All,
                    ConnectTimeout = TimeSpan.FromSeconds(10),
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                    MaxConnectionsPerServer = 64
                });
            return services;
        }
    }
}
