using Ark.oAuth;

// ---------------------------------------------------------------------------------------------
// A client-only ASP.NET Core web application.
//
// It contains no identity provider, no database and no protocol code of its own. Sign-in,
// PKCE, `state`, `nonce`, JWKS rollover and silent token refresh all come from
// AddArkOidcClient, which configures ASP.NET Core's own OpenID Connect handler against the
// provider's discovery document.
//
// Everything this app needs to know about the provider is one URL — the issuer, configured as
// `ark_oauth_client:Authority`. Point it at a different compliant provider (Entra ID, Okta,
// Auth0, Keycloak) and the code below is unchanged.
// ---------------------------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

// Reads the `ark_oauth_client` section, then wires up the cookie + OpenID Connect handlers.
builder.Services.AddArkOidcClient(builder.Configuration);

builder.Services.AddControllersWithViews();

// Used by the "call a downstream API" demo on /home/downstream.
builder.Services.AddHttpClient("downstream", c => c.Timeout = TimeSpan.FromSeconds(15));

// Used by /flows/register to look up, remove and map clients through the IdP's management API.
builder.Services.AddHttpClient("ark-management", c => c.Timeout = TimeSpan.FromSeconds(15));

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Middleware order matters, and this is the part most integrations get wrong.
//
// UseRouting() must run before UseAuthentication()/UseAuthorization(): without a selected
// endpoint the authorization middleware cannot see the [Authorize] metadata it is meant to
// enforce, so protected pages silently render for anonymous callers.
app.UseRouting();
app.UseArkOidcClient(); // no-op unless ark_oauth_client:UseLegacyFlow is set
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
