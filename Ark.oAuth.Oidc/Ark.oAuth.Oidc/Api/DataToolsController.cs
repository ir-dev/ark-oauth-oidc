using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Export, import and factory reset — the API behind /{tenant}/admin/data.
    ///
    /// Every route is restricted to the operator account (<see cref="ArkOperator"/>), not merely to
    /// a signed-in user: between them they can read every private key and password hash on the
    /// server and delete everything on it. They answer 404 when
    /// <c>ark_oauth_server:Admin:DataTools:Enabled</c> is false, so a deployment that switches the
    /// page off does not advertise it.
    ///
    /// Everything that changes data is a POST with a JSON body. That is deliberate rather than
    /// incidental: a browser sends <c>application/json</c> cross-origin only after a CORS
    /// preflight this server never grants, so a page elsewhere cannot make a signed-in operator's
    /// browser post an import or a reset. A multipart file upload would have been a "simple"
    /// request with no such protection — the console reads the file in the page and posts it as
    /// JSON instead.
    ///
    /// Responses use the provisioning API's shape — <c>{ error, code, msg, data }</c> with a real
    /// HTTP status — except export, which answers with the file itself.
    /// </summary>
    [Authorize]
    [Route("api/oauth")]
    [ApiController]
    public class DataToolsController : ControllerBase
    {
        private readonly ArkDataTools _tools;
        private readonly ArkUtil _util;
        private readonly DataAccess _da;

        public DataToolsController(ArkDataTools tools, ArkUtil util, DataAccess da)
        {
            _tools = tools;
            _util = util;
            _da = da;
        }

        private ArkDataToolsConfig Cfg => _util.ServerConfig.Admin?.DataTools ?? new ArkDataToolsConfig();

        /// <summary>Counts per table, the categories, what is switched on, and whether a reset can seed.</summary>
        [HttpGet]
        [Route("v1/data/summary")]
        public IActionResult Summary()
        {
            if (Refuse() is { } refused) return refused;
            var ser = _util.ServerConfig;
            return Ok(new
            {
                error = false,
                code = "summary",
                msg = "data summary",
                data = new
                {
                    counts = _tools.Counts(),
                    categories = _tools.TableCategories(),
                    operator_tenant = ser.TenantId,
                    admin_user = string.IsNullOrWhiteSpace(ser.AdminUser?.Username) ? "admin" : ser.AdminUser.Username,
                    package_version = ArkDataTools.PackageVersion,
                    format_version = ArkDataTools.FormatVersion,
                    allow_reset = Cfg.AllowReset,
                    allow_import = Cfg.AllowImport,
                    allow_replace = Cfg.AllowImport && Cfg.AllowReplace,
                    max_import_mb = Cfg.MaxImportMegabytes,
                    seed_problem = _tools.SeedProblem()
                }
            });
        }

        /// <summary>Every table and column, as one JSON file. Optionally encrypted.</summary>
        [HttpPost]
        [Route("v1/data/export")]
        public IActionResult Export([FromBody] ArkExportRequest? request)
        {
            if (Refuse() is { } refused) return refused;
            return Run("export", () =>
            {
                var (content, name) = _tools.Export(request, Who());
                _da.Record("data_export", name,
                    $"export downloaded{(string.IsNullOrEmpty(request?.passphrase) ? " (not encrypted)" : " (encrypted)")}",
                    request?.include_setting_secrets == true ? "settings secrets included" : "settings secrets redacted",
                    Who(), Ip());
                return File(content, "application/json", name);
            });
        }

        /// <summary>What each import mode would do with the file, without writing anything.</summary>
        [HttpPost]
        [Route("v1/data/import/analyze")]
        [RequestSizeLimit(ArkDataTools.MaxImportBytesCeiling)]
        public IActionResult Analyze([FromBody] ArkImportRequest request)
        {
            if (Refuse(import: true) is { } refused) return refused;
            return Run("import_analyze", () =>
            {
                var analysis = _tools.Analyze(request);
                return Ok(new
                {
                    error = false,
                    code = analysis.blockers.Count > 0 ? "file_blocked" : "analysed",
                    msg = analysis.blockers.Count > 0
                        ? analysis.blockers[0].msg
                        : $"analysed - recommended mode: {analysis.recommended_mode}.",
                    data = analysis
                });
            });
        }

        /// <summary>Runs one mode of an analysed import, in one transaction.</summary>
        [HttpPost]
        [Route("v1/data/import/apply")]
        [RequestSizeLimit(ArkDataTools.MaxImportBytesCeiling)]
        public IActionResult Apply([FromBody] ArkImportRequest request)
        {
            if (Refuse(import: true) is { } refused) return refused;
            return Run("import_apply", () =>
            {
                var result = _tools.Apply(request, Who(), Ip());
                return Ok(new
                {
                    error = false,
                    code = "imported",
                    msg = $"imported ({result.mode}): {result.summary.GetValueOrDefault(ArkDataTools.Insert)} inserted, " +
                          $"{result.summary.GetValueOrDefault(ArkDataTools.Update)} updated, " +
                          $"{result.summary.GetValueOrDefault(ArkDataTools.Excluded)} excluded.",
                    data = result
                });
            });
        }

        /// <summary>Empties every table and seeds the server as if it had just been installed.</summary>
        [HttpPost]
        [Route("v1/data/reset")]
        public async Task<IActionResult> Reset([FromBody] ArkResetRequest request)
        {
            if (Refuse() is { } refused) return refused;
            if (!Cfg.AllowReset)
                return StatusCode(403, new { error = true, code = "reset_disabled", msg = "factory reset is switched off by ark_oauth_server:Admin:DataTools:AllowReset.", data = (object?)null });
            try
            {
                var result = await _tools.ResetAsync(request, HttpContext, Who(), Ip());
                return Ok(new
                {
                    error = false,
                    code = "reset",
                    msg = $"the server has been reset and re-seeded - sign in again as '{result.admin_user}'.",
                    data = result
                });
            }
            catch (ArkDataToolsException ex)
            {
                return StatusCode(ex.StatusCode, new { error = true, code = ex.Code, msg = ex.Message, data = ex.Payload });
            }
            catch (Exception ex)
            {
                _da.LogError(ex, "data_reset", "v1/data/reset", "factory reset failed; the transaction was rolled back");
                return StatusCode(500, new { error = true, code = "reset_failed", msg = $"the reset failed and was rolled back - nothing was changed. {ex.GetBaseException().Message}", data = (object?)null });
            }
        }

        // ------------------------------------------------------------------ helpers

        /// <summary>The 404 / 403 every route starts with, or null when the caller may proceed.</summary>
        private IActionResult? Refuse(bool import = false)
        {
            if (!Cfg.Enabled) return NotFound();
            if (!ArkOperator.IsOperator(User, _util.ServerConfig))
                return StatusCode(403, new { error = true, code = "operator_only", msg = "export, import and reset are restricted to the administrator account.", data = (object?)null });
            if (import && !Cfg.AllowImport)
                return StatusCode(403, new { error = true, code = "import_disabled", msg = "import is switched off by ark_oauth_server:Admin:DataTools:AllowImport.", data = (object?)null });
            if (import && Request.ContentLength is long length && length > (long)Math.Max(1, Cfg.MaxImportMegabytes) * 1024 * 1024)
                return StatusCode(413, new { error = true, code = "file_too_large", msg = $"the file is larger than the {Cfg.MaxImportMegabytes} MB allowed by ark_oauth_server:Admin:DataTools:MaxImportMegabytes.", data = (object?)null });
            return null;
        }

        private IActionResult Run(string operation, Func<IActionResult> action)
        {
            try
            {
                return action();
            }
            catch (ArkDataToolsException ex)
            {
                return StatusCode(ex.StatusCode, new { error = true, code = ex.Code, msg = ex.Message, data = ex.Payload });
            }
            catch (Exception ex)
            {
                _da.LogError(ex, $"data_{operation}", $"v1/data/{operation}", $"{operation} failed");
                return StatusCode(500, new { error = true, code = $"{operation}_failed", msg = $"{operation.Replace('_', ' ')} failed - nothing was changed. {ex.GetBaseException().Message}", data = (object?)null });
            }
        }

        private string Who() =>
            User.FindFirst("email")?.Value ?? User.FindFirst("preferred_username")?.Value
            ?? User.FindFirst("sub")?.Value ?? User.Identity?.Name ?? "operator";

        private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
    }
}
