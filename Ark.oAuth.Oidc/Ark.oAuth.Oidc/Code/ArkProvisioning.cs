using System.Text.RegularExpressions;

namespace Ark.oAuth.Oidc
{
    /// <summary>Which of the two independent activation switches a message is about.</summary>
    public enum ArkActivationLevel
    {
        /// <summary>The account itself, across every application on the server.</summary>
        User,
        /// <summary>The application being signed in to.</summary>
        Client
    }

    /// <summary>
    /// Raised when credentials were correct but the account or the application has been switched
    /// off. Deliberately a distinct type: every other sign-in failure is reported with one
    /// deliberately vague message so the form cannot be used to enumerate accounts, and this is
    /// the one case where saying exactly what is wrong helps the person signing in without
    /// telling an attacker anything they could not already work out from holding the password.
    /// </summary>
    public class ArkAccountInactiveException : ApplicationException
    {
        public ArkActivationLevel Level { get; }
        /// <summary>The account or application name, for the message shown on screen.</summary>
        public string Subject { get; }

        public ArkAccountInactiveException(ArkActivationLevel level, string subject)
            : base(level == ArkActivationLevel.User
                ? $"the account '{subject}' has been deactivated."
                : $"the application '{subject}' has been deactivated.")
        {
            Level = level;
            Subject = subject;
        }

        /// <summary>The wording shown to the user. Says which level is off and what to do next.</summary>
        public string FriendlyMessage => Level == ArkActivationLevel.User
            ? "Your account has been deactivated, so you cannot sign in at the moment. Please contact your administrator to have it reactivated."
            : $"{Subject} has been deactivated, so it is not accepting sign-ins at the moment. Please contact your administrator.";
    }

    /// <summary>
    /// What a caller asks for when provisioning an application and its first user in one call.
    /// Only <see cref="client_name"/> and <see cref="user_name"/> are required; everything else
    /// takes the same defaults a client created through the console would get.
    /// </summary>
    public class ArkProvisionRequest
    {
        /// <summary>Defaults to <c>ark_oauth_server:TenantId</c>.</summary>
        public string? tenant_id { get; set; }
        /// <summary>Required. The display name of the application.</summary>
        public string? client_name { get; set; }
        /// <summary>Optional. Derived from <see cref="client_name"/> when omitted.</summary>
        public string? client_id { get; set; }
        /// <summary>Optional. A URL or a data: URI; shown on the sign-in page beside the host logo.</summary>
        public string? client_logo { get; set; }
        public List<string>? redirect_uris { get; set; }
        public List<string>? post_logout_redirect_uris { get; set; }
        /// <summary>
        /// Optional. Where to POST a logout token when a session this application took part in
        /// ends (OIDC Back-Channel Logout 1.0). Leave it unset and the application is never
        /// notified, so its own session outlives the one at the IdP.
        /// </summary>
        public string? backchannel_logout_uri { get; set; }
        /// <summary>Defaults to openid / profile / email / offline_access.</summary>
        public List<string>? scopes { get; set; }
        /// <summary>web | spa | native | service. Defaults to web.</summary>
        public string? application_type { get; set; }
        /// <summary>
        /// client_secret_basic | client_secret_post | private_key_jwt | none.
        /// Defaults to <c>none</c> — a provisioned client is a browser application until told
        /// otherwise, and a secret this endpoint invented would have to be returned in the
        /// response, where it would end up in a log.
        /// </summary>
        public string? token_endpoint_auth_method { get; set; }

        /// <summary>Required. An email address, or a plain username.</summary>
        public string? user_name { get; set; }
        /// <summary>Optional display name for a user this call has to create.</summary>
        public string? user_display_name { get; set; }
        /// <summary>Claims to put on the user-client mapping. Defaults to the identity claims.</summary>
        public List<string>? claims { get; set; }
        /// <summary>
        /// Email a new user an activation link instead of giving them the configured default
        /// password. Off by default: provisioning is usually driven by another system that
        /// expects the account to be usable the moment the call returns.
        /// </summary>
        public bool send_activation_email { get; set; }
    }

    /// <summary>What provisioning actually did, field by field, so a caller can tell a fresh
    /// tenant-and-user from a user who was simply granted access to a new application.</summary>
    public class ArkProvisionResult
    {
        public string tenant_id { get; set; } = default!;
        public string client_id { get; set; } = default!;
        public string client_name { get; set; } = default!;
        public bool client_created { get; set; }
        public string user_name { get; set; } = default!;
        public bool user_created { get; set; }
        /// <summary>default_password | activation_email | existing_account</summary>
        public string user_credential { get; set; } = default!;
        public bool mapping_created { get; set; }
        public List<string> claims { get; set; } = new();
        public List<string> redirect_uris { get; set; } = new();
        public string issuer { get; set; } = default!;
        public string discovery { get; set; } = default!;
        public string setup_url { get; set; } = default!;
    }

    /// <summary>
    /// Raised for a provisioning request that cannot be carried out for a reason the caller can
    /// act on — the client already exists, the tenant does not. Carries a stable
    /// <see cref="Code"/> so the caller can branch on it without matching on prose, and an HTTP
    /// status so the endpoint does not have to map one.
    /// </summary>
    public class ArkProvisionException : ApplicationException
    {
        public string Code { get; }
        public int StatusCode { get; }
        public object? Data { get; }

        public ArkProvisionException(string code, string message, int statusCode = 400, object? data = null)
            : base(message)
        {
            Code = code;
            StatusCode = statusCode;
            Data = data;
        }
    }

    /// <summary>
    /// Creates an application and its first user in one call, idempotently where it safely can be.
    ///
    /// This exists because standing up a new application by hand is four separate operations in a
    /// fixed order — register the client, register its redirect URIs, create the account, add the
    /// user-client access mapping — and missing the last one produces a sign-in failure that
    /// reads exactly like a wrong password. A single call that either does all four or explains
    /// which one it could not do is the difference between a self-service onboarding flow and a
    /// support ticket.
    ///
    /// The one thing it will not do is reuse a name: a client whose name is already taken is
    /// refused rather than updated, because silently rewriting the redirect URIs of a live
    /// application is how an onboarding script becomes an account-takeover primitive. A user who
    /// already exists is reused, which is the point — that is how a person gets access to their
    /// second application.
    /// </summary>
    public class ArkProvisioning
    {
        readonly DataAccess _da;
        readonly ArkUtil _util;

        public ArkProvisioning(DataAccess da, ArkUtil util)
        {
            _da = da;
            _util = util;
        }

        /// <summary>The claims a mapping gets when the caller does not name any.</summary>
        public static readonly string[] DefaultClaims =
            { "sub", "name", "email", "email_verified" };

        /// <param name="req">What to provision.</param>
        /// <param name="endpoints">
        /// The tenant's endpoint set, for the issuer and setup URL in the response. A caller that
        /// has an <c>HttpRequest</c> should build it from that, so a deployment which derives its
        /// public address from the request rather than configuring <c>BaseUrl</c> still gets
        /// usable URLs back. Omitted, it is built from configuration alone.
        /// </param>
        public async Task<ArkProvisionResult> ProvisionAsync(ArkProvisionRequest req, Protocol.ArkOidcEndpoints? endpoints = null)
        {
            if (req == null) throw new ArkProvisionException("invalid_request", "a request body is required.");

            var clientName = (req.client_name ?? "").Trim();
            var userName = (req.user_name ?? "").ToLower().Trim();
            if (string.IsNullOrWhiteSpace(clientName))
                throw new ArkProvisionException("invalid_request", "client_name is required.");
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArkProvisionException("invalid_request", "user_name is required.");

            var tenantId = string.IsNullOrWhiteSpace(req.tenant_id)
                ? _util.ServerConfig.TenantId
                : req.tenant_id!.Trim();
            var tenant = await _da.GetTenant(tenantId)
                ?? throw new ArkProvisionException("unknown_tenant",
                    $"no tenant '{tenantId}' exists on this server - create it before provisioning into it.");

            var clientId = string.IsNullOrWhiteSpace(req.client_id) ? Slug(clientName) : Slug(req.client_id!);
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArkProvisionException("invalid_request",
                    $"'{clientName}' contains no characters usable in a client_id - pass client_id explicitly.");

            // Both identifiers are checked, because either one colliding means an operator would
            // not be able to tell the two apart in the console afterwards.
            var existing = (await _da.GetClients()).FirstOrDefault(c =>
                string.Equals(c.tenant_id, tenant.tenant_id, StringComparison.OrdinalIgnoreCase)
                && (string.Equals(c.client_id, clientId, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(c.client_name ?? c.display ?? c.name, clientName, StringComparison.OrdinalIgnoreCase)));
            if (existing != null)
                throw new ArkProvisionException("client_exists",
                    $"an application named '{existing.client_name ?? existing.display ?? existing.client_id}' " +
                    $"(client_id '{existing.client_id}') is already registered in tenant '{tenant.tenant_id}'. " +
                    "Choose a different name, or map the user to the existing application instead.",
                    409,
                    new { tenant_id = existing.tenant_id, client_id = existing.client_id, client_name = existing.client_name });

            var ep = endpoints ?? Protocol.ArkOidcEndpoints.For(_util.ServerConfig, tenant.tenant_id);
            var redirects = Clean(req.redirect_uris);
            var logouts = Clean(req.post_logout_redirect_uris);
            var scopes = Clean(req.scopes);
            if (scopes.Count == 0) scopes = new List<string> { "openid", "profile", "email", "offline_access" };

            var authMethod = string.IsNullOrWhiteSpace(req.token_endpoint_auth_method)
                ? "none" : req.token_endpoint_auth_method!.Trim();

            var client = await _da.UpsertClient(new ArkClient
            {
                tenant_id = tenant.tenant_id,
                client_id = clientId,
                client_name = clientName,
                display = clientName,
                name = clientName,
                client_logo = string.IsNullOrWhiteSpace(req.client_logo) ? null : req.client_logo!.Trim(),
                application_type = string.IsNullOrWhiteSpace(req.application_type) ? "web" : req.application_type!.Trim(),
                token_endpoint_auth_method = authMethod,
                require_pkce = true,
                refresh_token_rotation = true,
                is_active = true,
                expire_mins = 480,
                grant_types = new List<string> { "authorization_code", "refresh_token" },
                response_types = new List<string> { "code" },
                scopes = scopes,
                redirect_uris = redirects,
                post_logout_redirect_uris = logouts,
                backchannel_logout_uri = string.IsNullOrWhiteSpace(req.backchannel_logout_uri)
                    ? null : req.backchannel_logout_uri!.Trim(),
                backchannel_logout_session_required = true
            });

            // The account is looked up before the upsert so the response can say whether this call
            // created it — which decides what the caller has to tell the person about their password.
            var existingUser = await _da.GetUser(userName);
            var userCreated = existingUser == null;
            var user = existingUser;
            if (userCreated)
            {
                user = await _da.UpsertUser(new ArkUser
                {
                    email = userName,
                    name = string.IsNullOrWhiteSpace(req.user_display_name) ? userName : req.user_display_name!.Trim(),
                    type = "user",
                    is_active = true,
                    hash_pw = _util.HashPasswordPBKDF2(_util.ServerConfig.DefaultPw)
                }, sendActivationEmail: req.send_activation_email);
            }

            var claims = Clean(req.claims);
            if (claims.Count == 0) claims = DefaultClaims.ToList();
            foreach (var key in claims)
                if (await _da.GetClaim(key) == null)
                    await _da.UpsertClaim(new ArkClaim { key = key, display = key });

            // The mapping stores the client's surrogate id, not its client_id string - that is
            // what ValidateUserCreds joins on, and getting it wrong is invisible until sign-in.
            var mappings = await _da.GetUsersClientClaims(userName, tenant.tenant_id);
            var mappingExisted = mappings.Any(m => string.Equals(m.client_id, client.id, StringComparison.OrdinalIgnoreCase));
            await _da.UpsertUsersClientClaims(new ArkUserClientClaim
            {
                email = userName,
                tenant_id = tenant.tenant_id,
                client_id = client.id,
                claims = claims
            });

            _da.Log("provision", $"{tenant.tenant_id}/{client.client_id}", "client and user provisioned",
                $"client: {client.client_id}, user: {userName}, user_created: {userCreated}");

            return new ArkProvisionResult
            {
                tenant_id = tenant.tenant_id,
                client_id = client.client_id,
                client_name = client.client_name ?? clientName,
                client_created = true,
                user_name = userName,
                user_created = userCreated,
                user_credential = !userCreated
                    ? "existing_account"
                    : ((user?.reset_mode ?? false) ? "activation_email" : "default_password"),
                mapping_created = !mappingExisted,
                claims = claims,
                redirect_uris = client.EffectiveRedirectUris,
                issuer = ep.Issuer,
                discovery = ep.Discovery,
                setup_url = $"{ep.Issuer}/oauth2/integrate/{client.client_id}"
            };
        }

        static List<string> Clean(List<string>? values) =>
            (values ?? new List<string>())
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

        /// <summary>
        /// Turns a display name into a client_id: lowercase, and everything outside
        /// [a-z0-9._-] folded to a single underscore. client_id travels in URLs and route
        /// segments, so it is kept to characters that survive both unescaped.
        /// </summary>
        public static string Slug(string value)
        {
            var slug = Regex.Replace((value ?? "").Trim().ToLowerInvariant(), @"[^a-z0-9._-]+", "_");
            return slug.Trim('_', '.', '-');
        }
    }
}
