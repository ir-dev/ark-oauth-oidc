using Ark.oAuth.Oidc;

// An identity server with nothing configured, opened on the agent that sets it up.
//
// The agent is part of the server (AddArkIdp brings it). What this sample adds is its settings:
// appsettings.json has it greet at the root, where an ordinary server shows its wizard with a link
// to it, and user secrets say which model it talks through.
//
// Started like this it has no tenant and no database. Open it in a browser and Ark Pilot is
// there: tell it about your organization, paste what you have, hand the parts you do not know to
// the colleagues who do, read the plan, press Install. The same process is then the identity
// provider. The setup wizard is still at /ark-idp/setup for anyone who prefers a form.
//
// Which model the agent talks through, and as whom, comes from user secrets or the environment
// (ark_onboarding_agent:Llm, see the README). With none it still works, in guided mode.
var builder = WebApplication.CreateBuilder(args);

builder.AddArkIdp();

var app = builder.Build();

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();

app.UseArkIdp();
app.Run();
