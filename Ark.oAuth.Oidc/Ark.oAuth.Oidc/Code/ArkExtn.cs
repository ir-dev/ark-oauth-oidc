﻿using Microsoft.EntityFrameworkCore;
using System.Reflection;

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
                var filePath = name;

                // Embedded files are prefixed with the full namespace of the assembly, so your file is stored at wwwroot/foundation.css, then
                // Here, we strip the assembly name from the start - note the following '.' too
                filePath = filePath.Replace(assemblyName + ".", "");

                // Parse file path
                filePath = filePath.Replace(".", "\\");

                // Reset files - order is important!!
                filePath = this.ResetFileExtension(filePath, ".cshtml");
                filePath = this.ResetFileExtension(filePath, ".min.css");
                filePath = this.ResetFileExtension(filePath, ".css");
                filePath = this.ResetFileExtension(filePath, ".d.ts");
                filePath = this.ResetFileExtension(filePath, ".min.js");
                filePath = this.ResetFileExtension(filePath, ".js");
                filePath = this.ResetFileExtension(filePath, ".otf");
                filePath = this.ResetFileExtension(filePath, ".eot");
                filePath = this.ResetFileExtension(filePath, ".svg");
                filePath = this.ResetFileExtension(filePath, ".ttf");
                filePath = this.ResetFileExtension(filePath, ".woff");
                filePath = this.ResetFileExtension(filePath, ".png");
                filePath = this.ResetFileExtension(filePath, ".jpg");
                filePath = this.ResetFileExtension(filePath, ".gif");
                filePath = this.ResetFileExtension(filePath, ".ico");
                filePath = this.ResetFileExtension(filePath, ".html");

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
        public static void UseArkAuthData(this IApplicationBuilder builder)
        {
            builder.Use(async (context, next) =>
            {
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
                            dbContext.Database.EnsureCreated();
                            var conf = scope.ServiceProvider.GetRequiredService<IConfiguration>();
                            var ser = conf.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
                            var htp = scope.ServiceProvider.GetService<IHttpContextAccessor>();
                            var util = scope.ServiceProvider.GetRequiredService<ArkUtil>();
                            dynamic dd = util.GetKeys().Result;
                            var baseurl = !string.IsNullOrEmpty(ser.BaseUrl) ? ser.BaseUrl : $"{htp.HttpContext.Request.Scheme}://{htp.HttpContext.Request.Host}";
                            var domain = new Uri(baseurl).Host;
                            //1st time -> create client for server to manage users
                            var tt = new ArkTenant()
                            {
                                tenant_id = ser.TenantId,
                                name = ser.TenantId,
                                display = $"{ser.TenantId} Admin Console",
                                audience = $"{baseurl}/ark/oauth/v1/aud",
                                issuer = $"{baseurl}/ark/oauth/v1/iss",
                                expire_mins = 480,
                                rsa_private = dd.private_key,
                                rsa_public = dd.public_key,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
                            };
                            dbContext.tenants.Add(tt);
                            var cll = new ArkClient()
                            {
                                tenant_id = ser.TenantId,
                                client_id = $"{ser.TenantId}_client", //same as server id
                                display = $"{ser.TenantId} Client App (Display)",
                                domain = $"{domain}",
                                expire_mins = 480,
                                name = $"{ser.TenantId} name",
                                redirect_relative = $"/auth/oauth/{ser.TenantId}/v1/server/{ser.TenantId}_client/manage",
                                //redirect_relative = $"/auth/oauth/{ser.TenantId}/v1/server/{{0}}/manage",
                                redirect_url = $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/callback",
                                //redirect_url = $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{{0}}/callback",
                                logout_url = $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/logoff",
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
                            };
                            dbContext.clients.Add(cll);
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
                            //admin user
                            dbContext.users.Add(new ArkUser()
                            {
                                //claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                //client_id = $"{ser.TenantId}_client",
                                email = "admin",
                                emailed = false,
                                hash_pw = util.HashPasswordPBKDF2("admin"),
                                reset_mode = false,
                                type = "user",
                                name = "Admin User"
                            });
                            dbContext.user_client_claims.Add(new ArkUserClientClaim()
                            {
                                claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                client_id = $"{cll.id}",
                                tenant_id = $"{ser.TenantId}",
                                email = "admin"
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
                    }
                    catch (Exception ex)
                    {
                        // Log error
                        throw new Exception("Database initialization failed", ex);
                    }
                }
                await next();
            });
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
        }
    }
    public static class ExtnUtil
    {
        public static byte[] ToByteArray(this string x) => Convert.FromBase64String(x);
        public static string ToHex(this byte[] x) => BitConverter.ToString(x).Replace("-", "").ToLower();
    }
}
