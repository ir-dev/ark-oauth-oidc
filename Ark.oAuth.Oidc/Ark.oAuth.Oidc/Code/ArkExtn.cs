using Microsoft.EntityFrameworkCore;
using System.Reflection;
using ark.net.util;

namespace Ark.oAuth.Oidc
{
    public class EmbeddedResourceUnpacker
    {
        /// <summary>
        /// Examines the Foundation DLL and creates files on disk for each of them
        /// </summary>
        /// <returns></returns>
        public async Task UnpackFiles(IWebHostEnvironment env)
        {
            // We only need to do this in Development mode.  The assumption being that the developer will have unpacked the correct Foundation
            // version and these files will be committed to source control etc, just like normal files
            if (!env.IsDevelopment()) return;

            var foundationAssembly = typeof(Ark.oAuth.Oidc.EmbeddedResourceUnpacker).GetTypeInfo().Assembly;
            var assemblyName = foundationAssembly.GetName().Name;

            // Iterate over each embedded resource
            var names = foundationAssembly.GetManifestResourceNames();
            foreach (var name in names)
            {
                var ext = System.IO.Path.GetExtension(name);
                var filePath = System.IO.Path.GetFileNameWithoutExtension(name);
                // Embedded files are prefixed with the full namespace of the assembly, so your file is stored at wwwroot/foundation.css, then
                // Here, we strip the assembly name from the start - note the following '.' too
                filePath = filePath.Replace(assemblyName + ".", "");

                // Parse file path
                filePath = filePath.Replace('.', Path.DirectorySeparatorChar) + ext;

                // Reset files - order is important!!
                // filePath = this.ResetFileExtension(filePath, ".cshtml");
                // filePath = this.ResetFileExtension(filePath, ".min.css");
                // filePath = this.ResetFileExtension(filePath, ".css");
                // filePath = this.ResetFileExtension(filePath, ".d.ts");
                // filePath = this.ResetFileExtension(filePath, ".min.js");
                // filePath = this.ResetFileExtension(filePath, ".js");
                // filePath = this.ResetFileExtension(filePath, ".otf");
                // filePath = this.ResetFileExtension(filePath, ".eot");
                // filePath = this.ResetFileExtension(filePath, ".svg");
                // filePath = this.ResetFileExtension(filePath, ".ttf");
                // filePath = this.ResetFileExtension(filePath, ".woff");
                // filePath = this.ResetFileExtension(filePath, ".png");
                // filePath = this.ResetFileExtension(filePath, ".jpg");
                // filePath = this.ResetFileExtension(filePath, ".gif");
                // filePath = this.ResetFileExtension(filePath, ".ico");
                // filePath = this.ResetFileExtension(filePath, ".html");

                // Now prepend the root path of this application, on disk
                filePath = System.IO.Path.Combine(env.ContentRootPath, filePath);
                var directory = System.IO.Path.GetDirectoryName(filePath);
                System.IO.Directory.CreateDirectory(directory);
                // Copy
                using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
                {
                    using (var file = new FileStream(filePath, FileMode.Create, FileAccess.ReadWrite))
                    {
                        resource.CopyTo(file);
                    }
                }
            }
        }

        /// <summary>
        /// Helper routine
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="requiredExtension"></param>
        /// <returns></returns>
        private string ResetFileExtension(string fileName, string requiredExtension)
        {
            var encodedExtension = requiredExtension.Replace(".", "\\");
            if (!fileName.EndsWith(encodedExtension)) return fileName;
            fileName = fileName.Substring(0, fileName.Length - encodedExtension.Length) + requiredExtension;
            return fileName;
        }
    }
    public static class ArkExtn
    {
        // Database initialisation only ever needs to happen once per process. Previously this
        // ran on every single request — opening a scope, querying pending migrations and
        // probing the connection before the real work could start.
        private static int _dataInitialized;

        public static void UseArkAuthData(this IApplicationBuilder builder)
        {
            builder.Use(async (context, next) =>
            {
                if (Interlocked.CompareExchange(ref _dataInitialized, 1, 0) != 0)
                {
                    await next();
                    return;
                }
                using (var scope = builder.ApplicationServices.CreateScope())
                {
                    try
                    {
                        var dbContext = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
                        if (dbContext.Database.GetPendingMigrations().Any())
                        {
                            dbContext.Database.Migrate();
                        }
                        else if (!dbContext.Database.CanConnect())
                        {
                            var conf = scope.ServiceProvider.GetRequiredService<IConfiguration>();
                            var ser = conf.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
                            // Resolved before the schema is created, not after. Seeding is only ever
                            // attempted against a database that does not exist yet, so a failure once
                            // the file is on disk would leave an empty schema behind that every later
                            // start treats as already initialised — no tenant, no client, no admin,
                            // and no second attempt.
                            var admin = ResolveAdminUser(ser);
                            dbContext.Database.EnsureCreated();
                            var htp = scope.ServiceProvider.GetService<IHttpContextAccessor>();
                            var util = scope.ServiceProvider.GetRequiredService<ArkUtil>();
                            // Signing keys are generated here, in this process. They used to be
                            // fetched from an external HTTPS service, which put the tenant's
                            // private key on the wire and on someone else's machine.
                            var (publicKey, privateKey) = Protocol.ArkCrypto.GenerateRsaKeyPair();
                            var baseurl = !string.IsNullOrEmpty(ser.BaseUrl) ? ser.BaseUrl : $"{htp.HttpContext.Request.Scheme}://{htp.HttpContext.Request.Host}";
                            var domain = new Uri(baseurl).Host;
                            // Every URL registered below has to be built from the same public root
                            // the client will actually call back to, BasePath included.
                            var approot = Protocol.ArkOidcEndpoints.PublicRoot(
                                new ArkAuthServerConfig { BaseUrl = baseurl, BasePath = ser.BasePath });
                            //1st time -> create client for server to manage users
                            var tt = new ArkTenant()
                            {
                                tenant_id = ser.TenantId,
                                name = ser.TenantId,
                                display = $"{ser.TenantId} Admin Console",
                                audience = $"{baseurl}/ark/oauth/v1/aud",
                                issuer = $"{baseurl}/ark/oauth/v1/iss",
                                expire_mins = 480,
                                rsa_private = privateKey,
                                rsa_public = publicKey,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
                            };
                            dbContext.tenants.Add(tt);
                            dbContext.signing_keys.Add(new ArkSigningKey()
                            {
                                // kid == tenant_id keeps tokens verifiable by clients that were
                                // configured against the pre-JWKS key layout
                                kid = ser.TenantId,
                                tenant_id = ser.TenantId,
                                alg = "RS256",
                                usage = "sig",
                                public_key = publicKey,
                                private_key = privateKey,
                                status = "active",
                                created_at = DateTime.UtcNow
                            });
                            foreach (var sc in Protocol.ArkClaimsService.DefaultScopes())
                                dbContext.scopes.Add(sc);
                            var cll = new ArkClient()
                            {
                                tenant_id = ser.TenantId,
                                client_id = $"{ser.TenantId}_client", //same as server id
                                display = $"{ser.TenantId} Client App (Display)",
                                domain = $"{domain}",
                                expire_mins = 480,
                                name = $"{ser.TenantId} name",
                                redirect_relative = $"{(ser.BasePath.AnyNull() ? "" : $"/{ser.BasePath}")}/oauth/{ser.TenantId}/v1/server/{ser.TenantId}_client/manage",
                                //redirect_relative = $"/auth/oauth/{ser.TenantId}/v1/server/{{0}}/manage",
                                redirect_url = $"{approot}/oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/callback",
                                logout_url = $"{approot}/oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/logoff",
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),

                                // standard registration metadata for the admin console client.
                                // It runs in a browser, so it is public and must use PKCE.
                                client_name = $"{ser.TenantId} Admin Console",
                                application_type = "web",
                                token_endpoint_auth_method = "none",
                                require_pkce = true,
                                refresh_token_rotation = true,
                                is_active = true,
                                grant_types = new List<string>() { "authorization_code", "refresh_token" },
                                response_types = new List<string>() { "code" },
                                scopes = new List<string>() { "openid", "profile", "email", "offline_access" },
                                redirect_uris = new List<string>()
                                {
                                    // the v1 callback, kept so existing deployments keep working
                                    $"{approot}/oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/callback",
                                    // the standard callback used by the ASP.NET Core OIDC handler
                                    $"{approot}/signin-oidc"
                                },
                                post_logout_redirect_uris = new List<string>()
                                {
                                    $"{approot}/oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/logoff",
                                    $"{approot}/signout-callback-oidc"
                                }
                            };
                            dbContext.clients.Add(cll);
                            dbContext.clients.Add(BuildMachineClient(ser.TenantId, domain));
                            var lls = new List<string>()
                            {
                                "sub",
                                "iss",
                                "aud",
                                "exp",
                                "iat",
                                "name",
                                "family_name",
                                "given_name",
                                "email",
                                "email_verified",
                                "gender",
                                "phone_number",
                                "address"
                            };
                            foreach (var item in lls)
                            {
                                dbContext.claims.Add(new ArkClaim() { key = item, display = item });
                            }
                            //admin user — credentials come from configuration, see ResolveAdminUser
                            dbContext.users.Add(new ArkUser()
                            {
                                //claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                //client_id = $"{ser.TenantId}_client",
                                email = admin.Username,
                                emailed = false,
                                hash_pw = util.HashPasswordPBKDF2(admin.Password),
                                reset_mode = false,
                                type = "user",
                                name = admin.Name
                            });
                            dbContext.user_client_claims.Add(new ArkUserClientClaim()
                            {
                                claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                client_id = $"{cll.id}",
                                tenant_id = $"{ser.TenantId}",
                                // no mapping row for this client means the admin cannot sign in to
                                // the console at all — the username here has to be the seeded one
                                email = admin.Username
                            });
                            var ts = scope.ServiceProvider.GetRequiredService<TokenServer>();
                            //service user service_user
                            dbContext.users.Add(new ArkUser()
                            {
                                //claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                //client_id = $"{ser.TenantId}_client",
                                email = $"service_account_{ser.TenantId}",
                                emailed = false,
                                hash_pw = (await ts.BuildAsymmetric_AccessToken(tt, new System.Security.Claims.Claim[] { new System.Security.Claims.Claim("service_role", "service_role") }, 525600)).Item1, // secret
                                reset_mode = false,
                                type = "service",
                                name = "Service Account (Default)"
                            });
                            dbContext.user_client_claims.Add(new ArkUserClientClaim()
                            {
                                claims = new List<string>() { "service_role" },
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                client_id = $"{cll.id}",
                                tenant_id = $"{ser.TenantId}",
                                email = $"service_account_{ser.TenantId}"
                            });
                            dbContext.SaveChanges();
                        }

                        // Schema updates for a database that already exists. Additive scripts
                        // only, recorded so none of them runs twice — see ArkSchemaUpdater. This
                        // used to be an operator's job after every upgrade, and skipping it left
                        // the entities describing columns the tables did not have: the management
                        // API then answered a bare 500 that named nothing.
                        ApplySchemaUpdates(scope.ServiceProvider);

                        ReconcileAdminConsoleClient(scope.ServiceProvider);
                        ReconcileScopeCatalogue(scope.ServiceProvider);
                        ReconcileMachineClient(scope.ServiceProvider);
                    }
                    catch (Exception ex)
                    {
                        // A bootstrap that threw has not happened. Releasing the latch lets the next
                        // request try again once the cause is fixed — leaving it set would have the
                        // process serve requests against a database it never finished creating,
                        // failing later with errors that say nothing about the real cause.
                        Interlocked.Exchange(ref _dataInitialized, 0);
                        throw new Exception("Database initialization failed", ex);
                    }
                }
                await next();
            });
        }

        /// <summary>
        /// Resolves the administrator account to seed from <c>ark_oauth_server:AdminUser</c>.
        ///
        /// The password is the one value with no default. It used to be the literal "admin",
        /// compiled in beside the username — every deployment of this server therefore started
        /// with the same credentials on the one account that administers every tenant, and the
        /// only thing standing between a fresh install and a stranger was whether anyone had
        /// read the release notes. Refusing to seed is louder than seeding something guessable:
        /// this runs once, while the database is being created, so the message lands in front of
        /// whoever is installing the server rather than months later.
        ///
        /// <c>DefaultPw</c> is accepted as the fallback because it already means "the initial
        /// password for an account created without one", which is exactly what this is.
        /// </summary>
        private static (string Username, string Password, string Name) ResolveAdminUser(ArkAuthServerConfig ser)
        {
            var cfg = ser.AdminUser ?? new ArkAdminUserConfig();

            var username = string.IsNullOrWhiteSpace(cfg.Username) ? "admin" : cfg.Username.Trim();
            var name = string.IsNullOrWhiteSpace(cfg.Name) ? "Admin User" : cfg.Name.Trim();
            var password = Configured(cfg.Password) ?? Configured(ser.DefaultPw);

            if (string.IsNullOrWhiteSpace(password))
                throw new ApplicationException(
                    $"no password is configured for the administrator account '{username}', so the " +
                    "database cannot be seeded. Set 'ark_oauth_server:AdminUser:Password' (or " +
                    "'ark_oauth_server:DefaultPw'); a value still left as a '<<placeholder>>' counts " +
                    "as unset. Prefer a secret store or an environment variable — " +
                    "ark_oauth_server__AdminUser__Password — over appsettings.json. This server no " +
                    "longer falls back to seeding a well-known 'admin' / 'admin' account.");

            return (username, password, name);
        }

        /// <summary>
        /// A configured secret, or null when the setting is empty or still holds one of the
        /// <c>&lt;&lt;placeholder&gt;&gt;</c> markers the sample configuration files ship with.
        /// Treating <c>&lt;&lt;change-me&gt;&gt;</c> as a real password would put a value published
        /// in this repository on the administrator account of anyone who ran the sample unedited.
        /// </summary>
        private static string? Configured(string? value)
        {
            var trimmed = (value ?? "").Trim();
            if (trimmed.Length == 0) return null;
            return trimmed.StartsWith("<<") && trimmed.EndsWith(">>") ? null : value;
        }

        /// <summary>
        /// The machine-to-machine client: <c>client_credentials</c> only, no user, no redirect.
        ///
        /// It is created without a secret, so it cannot authenticate until an operator presses
        /// <b>Regenerate secret</b> on it in the admin console. That is the point — a secret
        /// seeded in source would be the same secret on every deployment of this server, and a
        /// client that can mint tokens is exactly the wrong place to keep a well-known default.
        /// </summary>
        private static ArkClient BuildMachineClient(string tenantId, string domain) => new()
        {
            tenant_id = tenantId,
            client_id = $"{tenantId}_machine",
            display = $"{tenantId} Machine Client (Display)",
            name = $"{tenantId} machine",
            client_name = $"{tenantId} Machine-to-Machine",
            domain = domain,
            expire_mins = 60,
            at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),

            application_type = "web",
            // confidential: the client_credentials grant has no user to authenticate, so the
            // secret is the whole of the client's identity
            token_endpoint_auth_method = "client_secret_post",
            require_pkce = false,
            is_active = true,
            grant_types = new List<string> { "client_credentials" },
            response_types = new List<string>(),
            // client.register is what an initial access token needs to create clients through
            // the RFC 7591 endpoint; drop it if you do not use dynamic registration
            scopes = new List<string> { "client.register" },
            redirect_uris = new List<string>(),
            post_logout_redirect_uris = new List<string>(),
            redirect_url = "",
            logout_url = ""
        };

        /// <summary>
        /// Creates the machine client on a database that predates it.
        ///
        /// Seeding only runs when the database is created, so an existing deployment would
        /// otherwise have no client_credentials client at all. The record it adds cannot obtain a
        /// token until someone gives it a secret, so adding it is inert.
        /// </summary>
        private static void ReconcileMachineClient(IServiceProvider services)
        {
            var conf = services.GetRequiredService<IConfiguration>();
            var ser = conf.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>();
            if (ser == null || string.IsNullOrWhiteSpace(ser.TenantId)) return;

            var dbContext = services.GetRequiredService<ArkDataContext>();
            var clientId = $"{ser.TenantId}_machine";
            if (dbContext.clients.Any(c => c.tenant_id == ser.TenantId && c.client_id == clientId)) return;

            var domain = Uri.TryCreate(ser.BaseUrl, UriKind.Absolute, out var baseUri) ? baseUri.Host : "";
            dbContext.clients.Add(BuildMachineClient(ser.TenantId, domain));
            dbContext.SaveChanges();
        }

        /// <summary>
        /// Adds scopes this version knows about that an older database was never seeded with.
        ///
        /// The catalogue is written once, when the database is created, so a scope introduced
        /// later — <c>client.register</c>, say — simply does not exist on an existing deployment,
        /// and every request for it is rejected with `invalid_scope` for a reason nothing in the
        /// error explains. Only missing rows are inserted; an operator's edits to an existing
        /// scope are never overwritten.
        /// </summary>
        private static void ReconcileScopeCatalogue(IServiceProvider services)
        {
            var dbContext = services.GetRequiredService<ArkDataContext>();
            var existing = dbContext.scopes.Select(s => s.name).ToList();
            var missing = Protocol.ArkClaimsService.DefaultScopes()
                .Where(s => !existing.Contains(s.name, StringComparer.OrdinalIgnoreCase))
                .ToList();
            if (missing.Count == 0) return;

            dbContext.scopes.AddRange(missing);
            dbContext.SaveChanges();
        }

        /// <summary>
        /// Runs the schema scripts this build needs and the database has not had yet.
        ///
        /// Reported through the audit trail rather than thrown away, because "the console shows
        /// no users" and "00004 was never run" have to be connectable after the fact. A failure
        /// is fatal for the bootstrap on purpose: the alternative is a process serving requests
        /// against a schema its entities do not match, which is the exact failure this removes.
        /// </summary>
        private static void ApplySchemaUpdates(IServiceProvider services)
        {
            var da = services.GetRequiredService<DataAccess>();
            try
            {
                var result = ArkSchemaUpdater.Apply(services.GetRequiredService<ArkDataContext>());
                if (result.Applied.Count > 0)
                    da.Log("schema_update", string.Join(", ", result.Applied),
                        $"{result.Applied.Count} schema script(s) applied", "");
                if (result.Baselined.Count > 0)
                    da.Log("schema_baseline", string.Join(", ", result.Baselined),
                        "schema already current; scripts recorded without running", "");
            }
            catch (Exception ex)
            {
                da.LogError(ex, "schema_update", "ArkSchemaUpdater.Apply", "schema update failed");
                throw;
            }
        }

        /// <summary>
        /// Keeps the admin console client's own callback URLs in step with the configured
        /// BaseUrl / BasePath.
        ///
        /// The console signs in through this same server, so its registration has to match the
        /// redirect_uri the OIDC handler actually sends. Those URLs are seeded once at database
        /// creation, which means a database created under a different BaseUrl — or before the
        /// standard callbacks were seeded with BasePath at all — leaves the console unable to
        /// sign in, failing with `invalid_request: redirect_uri does not match a registered
        /// value`. Adding the missing entries on start-up removes a footgun that is otherwise
        /// only fixable by hand-editing the database.
        ///
        /// Only the two entries this server owns are added. Anything an operator registered by
        /// hand is left alone.
        /// </summary>
        private static void ReconcileAdminConsoleClient(IServiceProvider services)
        {
            var conf = services.GetRequiredService<IConfiguration>();
            var ser = conf.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>();
            if (ser == null || string.IsNullOrWhiteSpace(ser.TenantId) || string.IsNullOrWhiteSpace(ser.BaseUrl)) return;

            var dbContext = services.GetRequiredService<ArkDataContext>();
            var clientId = $"{ser.TenantId}_client";
            var client = dbContext.clients.FirstOrDefault(c => c.tenant_id == ser.TenantId && c.client_id == clientId);
            if (client == null) return;

            var approot = Protocol.ArkOidcEndpoints.PublicRoot(ser);

            var expected = new[]
            {
                $"{approot}/oauth/{ser.TenantId}/v1/client/{clientId}/callback",
                $"{approot}/signin-oidc"
            };
            var expectedLogout = new[]
            {
                $"{approot}/oauth/{ser.TenantId}/v1/client/{clientId}/logoff",
                $"{approot}/signout-callback-oidc"
            };

            var changed = false;

            var redirects = client.EffectiveRedirectUris.ToList();
            foreach (var uri in expected)
            {
                if (redirects.Contains(uri, StringComparer.OrdinalIgnoreCase)) continue;
                redirects.Add(uri);
                changed = true;
            }

            var logouts = client.EffectivePostLogoutRedirectUris.ToList();
            foreach (var uri in expectedLogout)
            {
                if (logouts.Contains(uri, StringComparer.OrdinalIgnoreCase)) continue;
                logouts.Add(uri);
                changed = true;
            }

            if (!changed) return;

            client.redirect_uris = redirects;
            client.post_logout_redirect_uris = logouts;
            dbContext.SaveChanges();
        }
        //all server config is taken from database
        public static void AddArkOidcServer(this IServiceCollection services, IWebHostEnvironment environment)
        {
            var unpack = new EmbeddedResourceUnpacker();
            var task = unpack.UnpackFiles(environment);
            Task.WaitAll(task);
            services.AddDbContext<ArkDataContext>();
            services.AddScoped<DataAccess>();
            services.AddScoped<TokenServer>();
            services.AddSingleton<ArkUtil>();
            services.AddScoped<Onboard>();
            services.AddScoped<ArkProvisioning>();

            // standard OAuth 2.1 / OIDC protocol services
            services.AddMemoryCache();
            services.AddHttpClient("ark-oidc", c => c.Timeout = TimeSpan.FromSeconds(10));
            services.AddScoped<Protocol.ArkKeyService>();
            services.AddScoped<Protocol.ArkClaimsService>();
            services.AddScoped<Protocol.ArkTokenService>();
            services.AddScoped<Protocol.ArkGrantStore>();
            services.AddScoped<Protocol.ArkClientAuthenticator>();
            services.AddScoped<Protocol.ArkBackChannelLogout>();

            // browser clients (SPAs) redeem their code from the page itself, so the token and
            // userinfo endpoints need a CORS policy — see ark_oauth_server:Oidc:CorsOrigins
            services.AddCors();
            services.AddSingleton<Microsoft.Extensions.Options.IConfigureOptions<Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>,
                ArkCorsConfigurator>();

            // the interactive endpoints render Razor views shipped inside this package
            services.AddControllersWithViews();
            services.AddAntiforgery(o => o.Cookie.Name = "ark_idp_csrf");
        }

        /// <summary>
        /// Enables the CORS middleware for the endpoints marked with
        /// <c>[EnableCors(ArkCors.PolicyName)]</c>.
        ///
        /// Call it after <c>UseRouting</c> and before <c>UseAuthorization</c>: the middleware
        /// reads the policy off the selected endpoint, so with no endpoint selected yet it has
        /// nothing to apply, and after authorization has run a rejected preflight never gets its
        /// headers. A cross-origin token request that arrives without these headers fails in the
        /// browser rather than at the server, which makes it look like the client is misconfigured.
        /// </summary>
        public static void UseArkOidcCors(this IApplicationBuilder builder) => builder.UseCors();
    }

    /// <summary>
    /// Builds the browser policy from configuration.
    ///
    /// Done as an <c>IConfigureOptions</c> rather than inline in <c>AddArkOidcServer</c> so the
    /// policy can read <c>IConfiguration</c> out of the container — the registration method takes
    /// only the environment, and hosts should not have to pass configuration twice.
    /// </summary>
    internal sealed class ArkCorsConfigurator
        : Microsoft.Extensions.Options.IConfigureOptions<Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>
    {
        private readonly IConfiguration _configuration;

        public ArkCorsConfigurator(IConfiguration configuration) => _configuration = configuration;

        public void Configure(Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions options)
        {
            var origins = (_configuration.GetSection("ark_oauth_server:Oidc:CorsOrigins").Get<string[]>()
                    ?? Array.Empty<string>())
                .Where(o => !string.IsNullOrWhiteSpace(o))
                .Select(o => o.Trim().TrimEnd('/'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            options.AddPolicy(Protocol.ArkCors.PolicyName, policy =>
            {
                if (origins.Length == 0)
                {
                    // Configured with no origins means cross-origin access is off, not open.
                    policy.SetIsOriginAllowed(_ => false);
                    return;
                }

                policy
                    .WithOrigins(origins)
                    .WithMethods("GET", "POST", "OPTIONS")
                    .WithHeaders("Authorization", "Content-Type", "Accept")
                    // the reason a 401 from /userinfo is legible in a browser console
                    .WithExposedHeaders("WWW-Authenticate")
                    .SetPreflightMaxAge(TimeSpan.FromMinutes(10));

                // Deliberately no AllowCredentials(). A browser client authenticates with a bearer
                // token in the Authorization header; letting it send cookies cross-origin would
                // put the server's own session cookie on requests it did not initiate.
            });
        }
    }
    public static class ExtnUtil
    {
        public static byte[] ToByteArray(this string x) => Convert.FromBase64String(x);
        public static string ToHex(this byte[] x) => BitConverter.ToString(x).Replace("-", "").ToLower();
    }
}
