
using Ark.oAuth;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddArkOidcClient(builder.Configuration);
// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseArkOidcClient(); //cleint -- position mandatory
app.UseAuthentication(); // needed for ark-oidc in this seqquence
app.UseAuthorization(); // needed for ark-oidc in this seqquence

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
