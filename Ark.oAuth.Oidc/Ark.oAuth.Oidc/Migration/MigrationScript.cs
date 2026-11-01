using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Ark.oAuth.Oidc
{
    public class MigrationScript
    {
        public static string[] GetEmbeddedResources()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            var nn = assembly.GetManifestResourceNames();
            return nn;
        }
        public static string ReadEmbeddedResource(string resourceName)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    Console.WriteLine($"Error: Embedded resource '{resourceName}' not found.");
                    Console.WriteLine("Available resources:");
                    foreach (string name in assembly.GetManifestResourceNames())
                    {
                        Console.WriteLine($"- {name}");
                    }
                    return null;
                }
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }
        /// <summary>The reason a run failed, for the caller to report. Null after a run that worked.</summary>
        public string? Error { get; private set; }

        public bool Rollback(DataAccess da, string name)
        {
            try
            {
                Down(da, name).GetAwaiter().GetResult(); //Ark.oAuth.Oidc.Migration.Sql.down.00001_sql.sql - rollback embedded name
                da.Log("migration_rollback", $"{name}", "rollback successful", "");
                return true;
            }
            catch (Exception exp)
            {
                Error = exp.Message;
                da.LogError(exp, "migration_rollback", $"{name}", "rollback failed with exception.");
                return false;
            }
        }
        public bool Migrate(DataAccess da, string name)
        {
            try
            {
                // Awaited. Up() is async, and firing it without awaiting meant the caller was told
                // the migration had run while the statements were still on their way to the
                // database — and a failure surfaced on a thread nobody was watching.
                //name = "Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql"; //embedded file name
                Up(da, name).GetAwaiter().GetResult();
                da.Log("migration", $"{name}", $"migration successful", "");
                return true;
            }
            catch (Exception exp)
            {
                Error = exp.Message;
                da.LogError(exp, "migration_failed", $"{name}", $"migration failed with exception.");
                return false;
            }
        }
        string sqlScript;
        protected async Task Up(DataAccess da, string name)
        {
            var pn = da.GetCtx().Database.ProviderName;
            // Same provider-to-folder mapping the start-up updater uses, so a script run by hand
            // and the same script run automatically can never come from different folders.
            var folder = ArkSchemaUpdater.ProviderFolder(pn) ?? throw new NotSupportedException($"Up failed: {pn}, {name}");
            sqlScript = ReadEmbeddedResource($"Ark.oAuth.Oidc.Migration.{folder}.up.{name}")
                ?? throw new FileNotFoundException($"no embedded script '{name}' for provider {pn}.");
            await da.ExecuteRaw(sqlScript);
        }

        protected async Task Down(DataAccess da, string name)
        {
            var pn = da.GetCtx().Database.ProviderName;
            var folder = ArkSchemaUpdater.ProviderFolder(pn) ?? throw new NotSupportedException($"Down failed: {pn}, {name}");
            sqlScript = ReadEmbeddedResource($"Ark.oAuth.Oidc.Migration.{folder}.down.{name}")
                ?? throw new FileNotFoundException($"no embedded rollback script '{name}' for provider {pn}.");
            await da.ExecuteRaw(sqlScript);
        }
    }
}
