using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

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
    [ArkDataToolsGate]
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
        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Route("v1/data/export")]
        [Consumes("application/json")]
        public IActionResult Export([FromBody] ArkExportRequest? request)
        {
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
        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Route("v1/data/import/analyze")]
        [Consumes("application/json")]
        [ArkImportGate]
        public IActionResult Analyze([FromBody] ArkImportRequest request)
        {
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
        // CSRF: JSON-only ([Consumes]) and no CORS grant, so a cross-site page cannot send it; operator-only.
        [HttpPost]  // nosemgrep: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
        [Route("v1/data/import/apply")]
        [Consumes("application/json")]
        [ArkImportGate]
        public IActionResult Apply([FromBody] ArkImportRequest request)
        {
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
        [Consumes("application/json")]
        public async Task<IActionResult> Reset([FromBody] ArkResetRequest request)
        {
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

    /// <summary>
    /// The 404 / 403 every data route starts with: the tools switched on, and the operator, as of
    /// now, on the other end.
    ///
    /// A filter rather than the first line of each action, because the body is bound before an
    /// action runs: any signed-in console user could have the server read a whole import, up to
    /// its gigabyte, only to be told afterwards that they may not import anything.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class)]
    internal sealed class ArkDataToolsGateAttribute : Attribute, IAsyncResourceFilter
    {
        public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            var http = context.HttpContext;
            var ser = http.RequestServices.GetRequiredService<ArkUtil>().ServerConfig;
            if (!(ser.Admin?.DataTools ?? new ArkDataToolsConfig()).Enabled)
                context.Result = new NotFoundResult();
            else if (!await ArkOperator.IsOperatorNowAsync(http, http.User, ser))
                context.Result = Refusal(403, "operator_only", "export, import and reset are restricted to the administrator account.");
            else
                await next();
        }

        internal static ObjectResult Refusal(int status, string code, string msg) =>
            new(new { error = true, code, msg, data = (object?)null }) { StatusCode = status };
    }

    /// <summary>
    /// What the two import routes add: import switched on, and a body no larger than
    /// <c>MaxImportMegabytes</c>. The server is told the limit as well as the length being looked
    /// at, since a body sent in chunks does not say how long it is going to be.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    internal sealed class ArkImportGateAttribute : Attribute, IResourceFilter
    {
        public void OnResourceExecuting(ResourceExecutingContext context)
        {
            var http = context.HttpContext;
            var cfg = http.RequestServices.GetRequiredService<ArkUtil>().ServerConfig.Admin?.DataTools ?? new ArkDataToolsConfig();
            if (!cfg.AllowImport)
            {
                context.Result = ArkDataToolsGateAttribute.Refusal(403, "import_disabled",
                    "import is switched off by ark_oauth_server:Admin:DataTools:AllowImport.");
                return;
            }

            var limit = Math.Min((long)Math.Max(1, cfg.MaxImportMegabytes) * 1024 * 1024, ArkDataTools.MaxImportBytesCeiling);
            if (http.Request.ContentLength > limit)
            {
                context.Result = ArkDataToolsGateAttribute.Refusal(413, "file_too_large",
                    $"the file is larger than the {cfg.MaxImportMegabytes} MB allowed by ark_oauth_server:Admin:DataTools:MaxImportMegabytes.");
                return;
            }
            if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size)
                size.MaxRequestBodySize = limit;
        }

        public void OnResourceExecuted(ResourceExecutedContext context) { }
    }
}
