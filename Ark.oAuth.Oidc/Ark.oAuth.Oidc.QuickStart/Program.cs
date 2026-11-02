using Ark.oAuth.Oidc;

// The whole identity provider. Nothing has to be configured first: started with no tenant and no
// database, it serves a setup wizard at /ark-idp/setup, and once that is finished this same
// process is the IdP — / leads to the admin console's sign-in page. No restart.
var builder = WebApplication.CreateBuilder(args);
builder.AddArkIdp();

var app = builder.Build();

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();

app.UseArkIdp();
app.Run();
