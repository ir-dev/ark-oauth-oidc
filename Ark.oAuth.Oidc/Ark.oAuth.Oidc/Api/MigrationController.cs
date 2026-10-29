/*********************
 * Migration script — operator only, POST only
 * 1. up        : POST auth/api/migration/v1/sql?action=up&name=00001_sql.sql
 *    rollback  : POST auth/api/migration/v1/sql?action=down&name=00001_sql.sql
 *    details: base start with - adding client_logo column
 * 2. up        : POST auth/api/migration/v1/sql?action=up&name=00002_sql.sql
 *    rollback  : POST auth/api/migration/v1/sql?action=down&name=00002_sql.sql
 *    details: created new ark_status table to get user retry attempt
 *
 * Since 2.0.2 these run by themselves: AddArkOidcServer's bootstrap applies every script the
 * database has not had yet and records it in ark_schema_history, so this endpoint is only needed
 * to roll one back, or to drive a provider whose scripts are not embedded here. See
 * ArkSchemaUpdater.
 *
 * This used to be an anonymous GET. A rollback script drops tables and columns, so anyone who
 * could reach the server could wipe it with one link — and as a GET, a signed-in operator could
 * be made to do it by any page that navigated them there. It now needs the operator account
 * (ArkOperator) and a POST.
 *********************/
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    [Authorize]
    [Route("api/migration")]
    [ApiController]
    public class MigrationController : ControllerBase
    {
        [Route("v1/sql")]
        [HttpPost]
        public async Task<dynamic> ExexuteMigration([FromServices] DataAccess da, [FromServices] IConfiguration config,
            [FromQuery] string action, [FromQuery] string name)
        {
            if (!ArkOperator.IsOperator(User, config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()))
                return StatusCode(403, new { error = true, msg = "migrations are restricted to the administrator account." });

            //name: "00001_sql.sql"; //file name inside Migration/{provider}/{up|down}
            try
            {
                // The result is read now. Both calls catch their own exceptions and report through
                // a bool, so ignoring it meant a failed migration answered "executed." — which is
                // how a database ends up one script behind while its operator believes otherwise.
                var runner = new MigrationScript();
                var verb = (action ?? "").ToLower().Trim();
                var ok = verb switch
                {
                    "up" => runner.Migrate(da, name),
                    "down" => runner.Rollback(da, name),
                    _ => throw new ApplicationException($"unknown action '{action}' - use 'up' or 'down'.")
                };
                return new
                {
                    error = !ok,
                    msg = ok
                        ? $"migration {name} executed."
                        : $"migration {name} failed. {runner.Error}"
                };
            }
            catch (Exception ex)
            {
                // The message only: a stack trace tells the caller about the server, not the migration.
                return new
                {
                    error = true,
                    msg = $"migration {name} failed. {ex.Message}"
                };
            }
        }
        [Route("v1/embeded/list")]
        [HttpGet]
        public async Task<dynamic> GetEmbeds([FromServices] IConfiguration config)
        {
            if (!ArkOperator.IsOperator(User, config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()))
                return StatusCode(403, new { error = true, msg = "restricted to the administrator account." });

            return new
            {
                msg = "list of embedded resource",
                list = MigrationScript.GetEmbeddedResources()
            };
        }
    }
}