using Ark.oAuth;
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);

// The identity provider. Everything it serves is tenant-scoped under the issuer
// {BaseUrl}/{TenantId} — see /{tenant}/.well-known/openid-configuration.
builder.Services.AddArkOidcServer(builder.Environment);

// The admin console signs in through this same server, so the host is also an OIDC client.
// This is the standard ASP.NET Core handler: real PKCE, state, nonce and JWKS rollover.
builder.Services.AddArkOidcClient(builder.Configuration);

builder.Services.AddControllersWithViews();

var app = builder.Build();

// SQLite will not create the directory holding the database file, and `data/` is gitignored —
// so a fresh clone has nowhere to put it and the first request fails on "unable to open
// database file". Creating it here keeps `dotnet run` working straight out of the repository.
EnsureSqliteDirectory(app.Configuration);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// No UsePathBase here. This host is served from the root, so the issuer is
// https://host/{tenant} and BasePath in appsettings.json is left empty. If you move the app
// under a sub-path, set ark_oauth_server:BasePath and add app.UsePathBase to match — both have
// to agree or the registered redirect URIs will not line up with the ones actually sent.
app.UseHttpsRedirection();
app.UseStaticFiles();

// UseRouting has to run before UseAuthentication/UseAuthorization: without a selected endpoint
// the authorization middleware cannot see the [Authorize] metadata it is meant to enforce.
app.UseRouting();
app.UseArkOidcCors();   // token/userinfo/discovery for the origins in Oidc:CorsOrigins
app.UseArkAuthData();   // one-time database bootstrap, seeds tenant/client/scopes/admin user
app.UseArkOidcClient(); // no-op unless ark_oauth_client:UseLegacyFlow is set
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static void EnsureSqliteDirectory(IConfiguration configuration)
{
    var provider = configuration["ark_oauth_server:Provider"];
    if (!string.IsNullOrEmpty(provider) && !provider.Equals("sqlite", StringComparison.OrdinalIgnoreCase)) return;

    var connection = configuration.GetConnectionString("ArkAuthConnection");
    if (string.IsNullOrWhiteSpace(connection)) return;

    var source = connection
        .Split(';', StringSplitOptions.RemoveEmptyEntries)
        .Select(part => part.Split('=', 2))
        .Where(part => part.Length == 2 && part[0].Trim().Replace(" ", "")
            .Equals("DataSource", StringComparison.OrdinalIgnoreCase))
        .Select(part => part[1].Trim())
        .FirstOrDefault();
    if (string.IsNullOrWhiteSpace(source)) return;

    var directory = Path.GetDirectoryName(Path.GetFullPath(source));
    if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
}
