using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// The ASP.NET Core data-protection key ring, kept in the server's own database
    /// (<see cref="ArkDataProtectionKey"/>).
    ///
    /// Data protection encrypts the sign-in form's anti-forgery token, the admin console's cookie
    /// and the OIDC handler's correlation state. Its keys default to a folder on the machine. That
    /// is right for one machine and wrong for two: each instance behind a load balancer makes its
    /// own ring, so the form one instance draws is refused by the instance it is posted to, and
    /// the failure — a 400 on an otherwise correct sign-in, some of the time — points at nothing.
    /// In a container the folder is also gone at every restart.
    ///
    /// Every instance already shares one thing, the database, so the ring goes there.
    /// </summary>
    internal sealed class ArkKeyRingRepository : IXmlRepository
    {
        private readonly IServiceScopeFactory _scopes;

        public ArkKeyRingRepository(IServiceScopeFactory scopes) => _scopes = scopes;

        private volatile bool _tableReady;

        /// <summary>
        /// The ring is first read as the application starts — before the first request, and so
        /// before the bootstrap that request triggers. On the first start after an upgrade the
        /// database is there and this table is not, so it is added here. On a brand-new database
        /// nothing is there yet: that start-up read fails with the message below, which the
        /// framework notes and moves on from, and the ring is read again when it is first needed —
        /// by which time the bootstrap has run.
        /// </summary>
        private void EnsureTable(ArkDataContext ctx)
        {
            if (_tableReady) return;
            if (!ArkSchemaUpdater.EnsureTable(ctx, typeof(ArkDataProtectionKey)))
                throw new InvalidOperationException(
                    "The Ark IdP database has not been created yet, so the data-protection key ring kept in it " +
                    "cannot be read. This is expected on the very first start; the first request creates the database.");
            _tableReady = true;
        }

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            using var scope = _scopes.CreateScope();
            var ctx = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
            EnsureTable(ctx);
            var stored = ctx.data_protection_keys.AsNoTracking().Select(k => k.xml).ToList();
            if (stored.Count == 0 && !_localKeysImported)
            {
                _localKeysImported = true;
                ImportLocalKeys(ctx);
                stored = ctx.data_protection_keys.AsNoTracking().Select(k => k.xml).ToList();
            }
            return stored.Select(xml => XElement.Parse(xml)).ToList();
        }

        private volatile bool _localKeysImported;

        /// <summary>
        /// The first time the ring is read from the database and found empty, the keys this
        /// machine was using until now are copied in.
        ///
        /// Without this, moving the ring into the database is an upgrade people can feel: every
        /// console cookie and every sign-in form already drawn was protected with a key in the
        /// old folder, so each operator is signed out and each open form fails once. Carried
        /// across, those keep working and nobody notices the move. Each key is stored under its
        /// own id, so several instances importing the same folder, or their own, cannot store a
        /// key twice.
        ///
        /// Best effort: a folder that is not there or cannot be read simply means a new ring.
        /// </summary>
        private static void ImportLocalKeys(ArkDataContext ctx)
        {
            try
            {
                foreach (var directory in LocalKeyDirectories())
                {
                    if (!directory.Exists) continue;
                    var local = new FileSystemXmlRepository(directory, Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);
                    foreach (var element in local.GetAllElements())
                    {
                        var row = Row(element, $"imported from {directory.Name}");
                        if (ctx.data_protection_keys.AsNoTracking().Any(k => k.id == row.id)) continue;
                        ctx.data_protection_keys.Add(row);
                        try
                        {
                            ctx.SaveChanges();
                        }
                        catch (DbUpdateException)
                        {
                            ctx.Entry(row).State = EntityState.Detached; // another instance stored it first
                        }
                    }
                }
            }
            catch
            {
                // Never a reason not to start: the framework makes a new key when it finds none.
            }
        }

        /// <summary>Where ASP.NET Core keeps the ring when nothing says otherwise, most specific first.</summary>
        private static IEnumerable<DirectoryInfo> LocalKeyDirectories()
        {
            // Azure App Service: a folder under %HOME% that every instance of the site shares.
            var home = Environment.GetEnvironmentVariable("HOME");
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")) && !string.IsNullOrEmpty(home))
                yield return new DirectoryInfo(Path.Combine(home, "ASP.NET", "DataProtection-Keys"));
            var profile = FileSystemXmlRepository.DefaultKeyStorageDirectory;
            if (profile != null) yield return profile;
        }

        /// <summary>A key is stored under its own id; anything else (a revocation) under a digest of itself.</summary>
        private static ArkDataProtectionKey Row(XElement element, string friendlyName)
        {
            var xml = element.ToString(SaveOptions.DisableFormatting);
            var keyId = element.Name.LocalName == "key" ? element.Attribute("id")?.Value : null;
            return new ArkDataProtectionKey
            {
                id = string.IsNullOrWhiteSpace(keyId) ? Protocol.ArkCrypto.Sha256Base64Url(xml) : keyId!,
                friendly_name = friendlyName,
                xml = xml,
                created_at = DateTime.UtcNow
            };
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            using var scope = _scopes.CreateScope();
            var ctx = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
            EnsureTable(ctx);
            var row = Row(element, friendlyName);
            if (ctx.data_protection_keys.AsNoTracking().Any(k => k.id == row.id)) return;
            ctx.data_protection_keys.Add(row);
            ctx.SaveChanges();
        }
    }

    /// <summary>
    /// Decides where the key ring lives — <c>ark_oauth_server:DataProtectionKeys</c>:
    ///
    ///   * <c>auto</c> (the default) — in the database when the server is on PostgreSQL, MySQL or
    ///     SQL Server, which are the deployments that can have a second instance. On SQLite the
    ///     framework default is left alone: a database file is one machine by nature.
    ///   * <c>database</c> — in the database whatever the provider.
    ///   * <c>off</c> — never; the host arranges its own.
    ///
    /// Applied after every other configuration of the key ring and only when none of it chose a
    /// store, so a host that calls <c>PersistKeysToAzureBlobStorage</c>, <c>PersistKeysToFileSystem</c>
    /// or anything else keeps exactly what it asked for. Not applied while the server is
    /// unconfigured: the setup wizard has no database yet.
    /// </summary>
    internal sealed class ArkKeyRingConfigurator : IPostConfigureOptions<KeyManagementOptions>
    {
        private readonly IConfiguration _config;
        private readonly IServiceScopeFactory _scopes;

        public ArkKeyRingConfigurator(IConfiguration config, IServiceScopeFactory scopes)
        {
            _config = config;
            _scopes = scopes;
        }

        public void PostConfigure(string? name, KeyManagementOptions options)
        {
            if (options.XmlRepository != null) return;
            if (UsesDatabase(_config)) options.XmlRepository = new ArkKeyRingRepository(_scopes);
        }

        internal static bool UsesDatabase(IConfiguration config)
        {
            var ser = Protocol.ArkConfigSnapshot.Server(config);
            var mode = (ser?.DataProtectionKeys ?? "").Trim().ToLowerInvariant();
            if (mode is "off" or "false" or "none" or "host") return false;

            if (string.IsNullOrWhiteSpace(ser?.TenantId) ||
                string.IsNullOrWhiteSpace(config.GetConnectionString("ArkAuthConnection")))
                return false;

            if (mode is "database" or "db" or "true") return true;
            var sqlite = string.IsNullOrWhiteSpace(ser!.Provider) ||
                         ser.Provider.Trim().Equals("sqlite", StringComparison.OrdinalIgnoreCase);
            return !sqlite;
        }
    }
}
