using Ark.oAuth.Oidc;

// The whole identity provider. Nothing has to be configured first: started with no tenant and no
// database, it serves a setup wizard at /ark-idp/setup, and once that is finished this same
// process is the IdP — / leads to sign-in, then to the landing page the wizard asked for (the
// admin console unless another page was chosen). No restart.
var builder = WebApplication.CreateBuilder(args);
builder.AddArkIdp();

var app = builder.Build();

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();

app.UseArkIdp();
app.Run();
