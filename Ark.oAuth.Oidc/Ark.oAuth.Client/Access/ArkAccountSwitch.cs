using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ark.oAuth
{
    /// <summary>
    /// Account switching, and the page a user lands on when they are signed in as somebody who
    /// cannot use this application.
    ///
    /// The problem it solves is a shared browser. Single sign-on is a browser-wide session: once
    /// one person signs in to client-a, the identity provider's session cookie answers for every
    /// other tab. When a second person opens client-b, the authorize request is satisfied
    /// silently by the first person's session, client-b receives a perfectly valid token for an
    /// account that has no mapping to client-b, and the second person is shown "you do not have
    /// access to this application" for an account that is not even theirs. Nothing on that page
    /// helps, because the sign-in link goes back to the same silent session and returns the same
    /// answer — the loop only ends when somebody knows to clear cookies.
    ///
    /// Breaking that loop needs two things, and both live here:
    ///
    ///  * A dead end that is honest about whose session it is. The user is told which account is
    ///    signed in, and given a button rather than a link, because the way out is an action.
    ///  * A challenge that says <c>prompt=login</c>. That is the one parameter the provider must
    ///    honour by ignoring the existing session and drawing the sign-in form (OIDC Core
    ///    §3.1.2.1), which is what lets the second person enter their own credentials.
    ///
    /// Everything is opt-in and overridable: paths, wording, whether the previous account is
    /// named, whether switching also ends the provider session, and — for hosts that want their
    /// own page — an event that takes the whole thing over.
    /// </summary>
    public sealed class ArkAccountSwitchOptions
    {
        /// <summary>Serve the endpoints below. Off leaves the extension methods usable from your own actions.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Put the endpoints into the pipeline automatically, so an existing Program.cs needs no
        /// edit. Turn it off to place them yourself with <c>UseArkAccountEndpoints()</c> — behind
        /// forwarded headers or an HTTPS redirect, for instance.
        /// </summary>
        public bool AutoRegisterEndpoints { get; set; } = true;

        /// <summary>
        /// Refuse the sign-in when the provider issues no <c>ark_claims</c> for this client.
        ///
        /// This is the check that turns the shared-browser case into something recoverable. Left
        /// off (the default, so an upgrade changes no behaviour) the wrong account is signed in
        /// and every protected page answers 403. Turned on, the callback is stopped before the
        /// cookie is written — the wrong person never gets a session here at all — and the user is
        /// sent to <see cref="AccessDeniedPath"/> where they can switch accounts.
        /// </summary>
        public bool RequireArkClaims { get; set; }

        /// <summary>
        /// Narrow the check further: the user must carry at least one of these claim values.
        /// Empty means any <c>ark_claims</c> value will do. Ignored unless
        /// <see cref="RequireArkClaims"/> is set.
        /// </summary>
        public List<string>? RequiredClaims { get; set; }

        /// <summary>Where a denied user lands. Point it at your own page to take the UI over.</summary>
        public string AccessDeniedPath { get; set; } = "/ark/no-access";

        /// <summary>Accepts the POST that abandons the current account and asks for the sign-in form.</summary>
        public string SwitchUserPath { get; set; } = "/ark/switch-user";

        /// <summary>Accepts the POST that ends this application's session and the provider's.</summary>
        public string SignOutPath { get; set; } = "/ark/sign-out";

        /// <summary>
        /// Render the built-in access-denied page at <see cref="AccessDeniedPath"/>. Set false
        /// when that path is one of your own routes — the library then leaves the request alone.
        /// </summary>
        public bool ServeDefaultPage { get; set; } = true;

        /// <summary>Name of this application as the user knows it. Defaults to the client id.</summary>
        public string? AppDisplayName { get; set; }

        /// <summary>
        /// Show which account is currently signed in. On a shared browser that is somebody else's
        /// address; it is what makes the page make sense, but a deployment that would rather not
        /// print it can turn it off and still get the button.
        /// </summary>
        public bool ShowSignedInAccount { get; set; } = true;

        /// <summary>Offer "sign out completely" alongside "sign in as a different user".</summary>
        public bool AllowFullSignOut { get; set; } = true;

        /// <summary>
        /// Make switching a full RP-initiated logout instead of a re-prompt.
        ///
        /// Off (the default) the switch is local: this application drops its cookie and challenges
        /// with <c>prompt=login</c>, so the person at the keyboard signs in as themselves while
        /// the other applications the previous user has open are left alone. On, the provider
        /// session is ended too, which signs the previous user out of everything — correct for a
        /// kiosk or a shared terminal, heavy-handed for a laptop.
        /// </summary>
        public bool EndProviderSessionOnSwitch { get; set; }

        /// <summary>Sent as the <c>prompt</c> parameter when switching. <c>login</c> is the one every provider honours.</summary>
        public string Prompt { get; set; } = "login";

        /// <summary>Where "back to safety" goes, and the fallback for an absent or non-local return URL.</summary>
        public string HomePath { get; set; } = "/";

        /// <summary>Optional "who can give me access" link on the page.</summary>
        public string? SupportUrl { get; set; }

        /// <summary>Optional support address on the page.</summary>
        public string? SupportEmail { get; set; }
    }

    /// <summary>Why a user was sent to the access-denied page.</summary>
    public static class ArkAccessDeniedReasons
    {
        /// <summary>The provider authenticated them, but they hold no authorization claims for this client.</summary>
        public const string NoAppAccess = "no_app_access";

        /// <summary>They are signed in here, but an [Authorize] policy refused the page they asked for.</summary>
        public const string Forbidden = "forbidden";
    }

    /// <summary>What the library knows about a denial. Handed to <see cref="ArkClientEvents.OnAccessDenied"/>.</summary>
    public sealed class ArkAccessDeniedContext
    {
        public ArkAccessDeniedContext(HttpContext httpContext) => HttpContext = httpContext;

        public HttpContext HttpContext { get; }

        /// <summary>One of <see cref="ArkAccessDeniedReasons"/>.</summary>
        public string Reason { get; set; } = ArkAccessDeniedReasons.NoAppAccess;

        public string? Subject { get; set; }
        public string? Email { get; set; }
        public string? Name { get; set; }

        /// <summary>The authorization claims the provider did issue — empty in the usual case.</summary>
        public IReadOnlyList<string> ArkClaims { get; set; } = Array.Empty<string>();

        /// <summary>Where the user was trying to go, when that is known.</summary>
        public string? ReturnUrl { get; set; }

        /// <summary>
        /// Set from the handler to keep the library from redirecting — you have written the
        /// response yourself.
        /// </summary>
        public bool Handled { get; set; }
    }

    /// <summary>The decision the library is about to make about a completed sign-in.</summary>
    public sealed class ArkAccessEvaluationContext
    {
        public ArkAccessEvaluationContext(HttpContext httpContext) => HttpContext = httpContext;

        public HttpContext HttpContext { get; }
        public System.Security.Claims.ClaimsPrincipal? Principal { get; set; }
        public IReadOnlyList<string> ArkClaims { get; set; } = Array.Empty<string>();

        /// <summary>What the configured rules concluded, before your handler ran.</summary>
        public bool AllowedByConfiguration { get; set; }
    }

    /// <summary>Hooks for hosts that need more than configuration. All are optional.</summary>
    public sealed class ArkClientEvents
    {
        /// <summary>
        /// Decide entitlement yourself — a group claim, a licence lookup, a row in your own
        /// database. Return true to let the sign-in complete. Runs only when
        /// <see cref="ArkAccountSwitchOptions.RequireArkClaims"/> is on.
        /// </summary>
        public Func<ArkAccessEvaluationContext, Task<bool>>? OnEvaluateAccess { get; set; }

        /// <summary>
        /// Called before the user is redirected to the access-denied page. Log it, raise a
        /// request-access ticket, or write your own response and set
        /// <see cref="ArkAccessDeniedContext.Handled"/>.
        /// </summary>
        public Func<ArkAccessDeniedContext, Task>? OnAccessDenied { get; set; }
    }

    /// <summary>Passed to the <see cref="ArkExtn.AddArkOidcClient(IServiceCollection, IConfiguration, Action{ArkClientOptions})"/> overload.</summary>
    public sealed class ArkClientOptions
    {
        internal ArkClientOptions(ArkAuthConfig config) => Config = config;

        /// <summary>The bound <c>ark_oauth_client</c> section, mutable before anything reads it.</summary>
        public ArkAuthConfig Config { get; }

        public ArkClientEvents Events { get; } = new();
    }

    /// <summary>
    /// Authentication properties that carry the OIDC request parameters the framework has no
    /// first-class API for.
    ///
    /// The OpenID Connect handler builds the authorize request itself, so a caller cannot append
    /// <c>prompt</c> to it. What a caller can do is put a value in the properties and have
    /// <c>OnRedirectToIdentityProvider</c> copy it onto the outgoing message, which is what the
    /// client does with the three keys below.
    /// </summary>
    public static class ArkChallengeProperties
    {
        public const string PromptItem = "ark:prompt";
        public const string LoginHintItem = "ark:login_hint";
        public const string MaxAgeItem = "ark:max_age";

        /// <summary>
        /// A challenge that refuses to be answered by the existing session: <c>prompt=login</c>
        /// makes the provider draw the sign-in form even though its cookie is still valid.
        /// </summary>
        public static AuthenticationProperties SwitchUser(
            string? returnUrl = null, string? loginHint = null, string prompt = "login")
        {
            var properties = new AuthenticationProperties { RedirectUri = returnUrl ?? "/" };
            properties.Items[PromptItem] = string.IsNullOrWhiteSpace(prompt) ? "login" : prompt;
            if (!string.IsNullOrWhiteSpace(loginHint)) properties.Items[LoginHintItem] = loginHint;
            return properties;
        }

        /// <summary>
        /// Asks the provider for its account picker. Providers that do not implement one fall back
        /// to their sign-in form, so this is only preferable where you know the picker exists.
        /// </summary>
        public static AuthenticationProperties SelectAccount(string? returnUrl = null) =>
            SwitchUser(returnUrl, null, "select_account");

        public static AuthenticationProperties WithArkPrompt(this AuthenticationProperties properties, string prompt)
        {
            properties.Items[PromptItem] = prompt;
            return properties;
        }

        public static AuthenticationProperties WithArkLoginHint(this AuthenticationProperties properties, string loginHint)
        {
            properties.Items[LoginHintItem] = loginHint;
            return properties;
        }

        /// <summary>
        /// Adds <c>max_age</c>. Zero is a second way of saying "authenticate again now", useful
        /// against a provider that ignores <c>prompt</c>.
        /// </summary>
        public static AuthenticationProperties WithArkMaxAge(this AuthenticationProperties properties, int seconds)
        {
            properties.Items[MaxAgeItem] = seconds.ToString();
            return properties;
        }
    }

    /// <summary>The operations the access-denied page performs, callable from your own controllers.</summary>
    public static class ArkAccountExtensions
    {
        /// <summary>
        /// Abandons the account this application is signed in as and asks the provider for the
        /// sign-in form, so the person at the keyboard can enter their own credentials.
        ///
        /// The local cookie is dropped first. Without that, a user who abandons the sign-in at the
        /// provider comes back to a browser still holding the previous person's session.
        /// </summary>
        public static async Task ArkSwitchUserAsync(
            this HttpContext context, string? returnUrl = null, string? loginHint = null)
        {
            var config = context.RequestServices.GetService<ArkAuthConfig>();
            var options = config?.AccountSwitch ?? new ArkAccountSwitchOptions();
            var target = ArkAccountEndpoints.LocalOrDefault(returnUrl, options.HomePath);

            ArkAccessDeniedState.Clear(context);

            if (options.EndProviderSessionOnSwitch)
            {
                // Ends the provider session as well, which signs the previous user out of every
                // application they had open. They land back here unauthenticated, and the next
                // protected page draws the sign-in form because there is no session left to
                // answer it.
                await context.SignOutAsync(ArkOidcClient.CookieScheme);
                await context.SignOutAsync(ArkOidcClient.OidcScheme,
                    new AuthenticationProperties { RedirectUri = target });
                return;
            }

            await context.SignOutAsync(ArkOidcClient.CookieScheme);
            await context.ChallengeAsync(ArkOidcClient.OidcScheme,
                ArkChallengeProperties.SwitchUser(target, loginHint, options.Prompt));
        }

        /// <summary>
        /// RP-initiated logout: this application's session and the provider's. Other applications
        /// signed in through the same provider session are told through back-channel logout.
        /// </summary>
        public static async Task ArkSignOutEverywhereAsync(this HttpContext context, string? returnUrl = null)
        {
            var config = context.RequestServices.GetService<ArkAuthConfig>();
            var options = config?.AccountSwitch ?? new ArkAccountSwitchOptions();
            var target = ArkAccountEndpoints.LocalOrDefault(returnUrl, options.HomePath);

            ArkAccessDeniedState.Clear(context);
            await context.SignOutAsync(ArkOidcClient.CookieScheme);
            await context.SignOutAsync(ArkOidcClient.OidcScheme,
                new AuthenticationProperties { RedirectUri = target });
        }

        /// <summary>Ends this application's session only, leaving the provider session intact.</summary>
        public static async Task ArkSignOutLocallyAsync(this HttpContext context, string? returnUrl = null)
        {
            var config = context.RequestServices.GetService<ArkAuthConfig>();
            var options = config?.AccountSwitch ?? new ArkAccountSwitchOptions();

            ArkAccessDeniedState.Clear(context);
            await context.SignOutAsync(ArkOidcClient.CookieScheme);
            context.Response.Redirect(ArkAccountEndpoints.LocalOrDefault(returnUrl, options.HomePath));
        }

        /// <summary>
        /// What the last denial was about, for a host rendering its own access-denied page. Null
        /// when the user did not arrive from one — read the current principal instead.
        /// </summary>
        public static ArkDeniedAccount? ArkDeniedAccount(this HttpContext context) =>
            ArkAccessDeniedState.Read(context);
    }

    /// <summary>The account that was refused, as recorded when the denial happened.</summary>
    public sealed class ArkDeniedAccount
    {
        public string? subject { get; set; }
        public string? email { get; set; }
        public string? name { get; set; }
        public string? reason { get; set; }
        public string? return_url { get; set; }
    }

    /// <summary>
    /// Carries the refused identity from the callback to the access-denied page.
    ///
    /// The denial happens before any session is written — that is the point of it — so there is no
    /// principal on the next request to read the account off. A short-lived, encrypted, HttpOnly
    /// cookie carries just enough to name it, and is spent on first read.
    /// </summary>
    internal static class ArkAccessDeniedState
    {
        private const string CookieName = "ark_denied";
        private const string Purpose = "Ark.oAuth.Client.AccessDenied.v1";

        public static void Write(HttpContext context, ArkDeniedAccount account)
        {
            var protector = context.RequestServices.GetService<IDataProtectionProvider>()?.CreateProtector(Purpose);
            if (protector == null) return; // no data protection: the page still works, just unnamed

            var payload = protector.Protect(JsonSerializer.Serialize(account));
            context.Response.Cookies.Append(CookieName, payload, new CookieOptions
            {
                HttpOnly = true,
                IsEssential = true,
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Expires = DateTimeOffset.UtcNow.AddMinutes(5)
            });
        }

        public static ArkDeniedAccount? Read(HttpContext context)
        {
            var payload = context.Request.Cookies[CookieName];
            if (string.IsNullOrEmpty(payload)) return null;
            try
            {
                var protector = context.RequestServices.GetService<IDataProtectionProvider>()?.CreateProtector(Purpose);
                if (protector == null) return null;
                return JsonSerializer.Deserialize<ArkDeniedAccount>(protector.Unprotect(payload!));
            }
            catch
            {
                // Tampered, or protected by keys this instance no longer holds. Either way the
                // page falls back to the unnamed wording rather than failing.
                return null;
            }
        }

        public static void Clear(HttpContext context)
        {
            if (context.Request.Cookies.ContainsKey(CookieName))
                context.Response.Cookies.Delete(CookieName, new CookieOptions { Path = "/" });
        }
    }
}
