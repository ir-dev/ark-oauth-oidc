namespace Ark.oAuth.Oidc.Webhooks
{
    /// <summary>
    /// The events the IdP raises, and the one call it raises them with.
    ///
    /// <see cref="Raise"/> is what the IdP's controllers call. It resolves the publisher from the
    /// request's services, so a host that never called <c>AddArkWebhooks()</c> gets a null back
    /// and nothing else happens; it cannot throw; and the publisher it reaches only ever writes to
    /// an in-memory queue. That is the whole of the module's footprint on a sign-in or a token
    /// request.
    /// </summary>
    public static class ArkWebhookEvents
    {
        public sealed record EventInfo(string Type, string Group, string Description);

        public const string UserSignedIn = "user.signed_in";
        public const string UserSignInFailed = "user.signin_failed";
        public const string UserLockedOut = "user.locked_out";
        public const string UserSignInRefused = "user.signin_refused";
        public const string UserSignedOut = "user.signed_out";
        public const string UserUpdated = "user.updated";
        public const string UserPasswordChanged = "user.password_changed";
        public const string UserAccessChanged = "user.access_changed";
        public const string UserActivationChanged = "user.activation_changed";
        public const string UserProvisioned = "user.provisioned";
        public const string TokenIssued = "token.issued";
        public const string TokenRevoked = "token.revoked";
        public const string DeviceApproved = "device.approved";
        public const string ClientUpdated = "client.updated";
        public const string ClientDeleted = "client.deleted";
        public const string ClientRegistered = "client.registered";
        public const string ClientSecretReset = "client.secret_reset";
        public const string ClientActivationChanged = "client.activation_changed";
        public const string ClientProvisioned = "client.provisioned";
        public const string TenantUpdated = "tenant.updated";
        public const string WebhookTest = "webhook.test";

        /// <summary>What the console offers to subscribe to.</summary>
        public static readonly IReadOnlyList<EventInfo> Catalogue = new List<EventInfo>
        {
            new(UserSignedIn, "Sign-in", "A user signed in with a password."),
            new(UserSignInFailed, "Sign-in", "A sign-in was refused: wrong password, unknown user or no access."),
            new(UserLockedOut, "Sign-in", "A sign-in was blocked by the failed-attempt lockout."),
            new(UserSignInRefused, "Sign-in", "A verified user was refused: account or application deactivated, or no access mapping."),
            new(UserSignedOut, "Sign-in", "A session ended through RP-initiated logout."),
            new(TokenIssued, "Tokens", "Tokens were issued for an authorization code or client credentials."),
            new(TokenRevoked, "Tokens", "A client revoked a token."),
            new(DeviceApproved, "Tokens", "A user approved a device authorization request."),
            new(UserUpdated, "Users", "A user was created or changed in the console or the management API."),
            new(UserPasswordChanged, "Users", "An administrator set a user's password."),
            new(UserAccessChanged, "Users", "A user's access mapping to an application was added, changed or removed."),
            new(UserActivationChanged, "Users", "A user was activated or deactivated."),
            new(UserProvisioned, "Users", "A user was provisioned onto an application."),
            new(ClientUpdated, "Applications", "An application was created or changed in the console or the management API."),
            new(ClientDeleted, "Applications", "An application was deleted."),
            new(ClientRegistered, "Applications", "An application registered itself (dynamic client registration)."),
            new(ClientSecretReset, "Applications", "An application's client secret was regenerated."),
            new(ClientActivationChanged, "Applications", "An application was activated or deactivated."),
            new(ClientProvisioned, "Applications", "An application was provisioned with its first user."),
            new(TenantUpdated, "Tenants", "A tenant was created or changed."),
            new(WebhookTest, "Webhooks", "Sent by the console's Test button; always delivered to the endpoint tested."),
        };

        /// <summary>
        /// Raises an event from inside a request. Never throws, never blocks, and does nothing at
        /// all when the webhook module is not registered or nothing subscribes to the event.
        /// </summary>
        public static void Raise(HttpContext? http, string? tenantId, string type, object? data = null, string? subject = null)
        {
            try
            {
                if (http == null || string.IsNullOrWhiteSpace(tenantId)) return;
                if (http.RequestServices.GetService(typeof(ArkWebhookPublisher)) is not ArkWebhookPublisher publisher) return;
                publisher.Publish(tenantId, type, data, subject);
            }
            catch
            {
                // A webhook is never a reason for the IdP to fail.
            }
        }

        /// <summary>The caller's address, for the security events.</summary>
        public static string? Ip(HttpContext? http)
        {
            try { return http?.Connection.RemoteIpAddress?.ToString(); }
            catch { return null; }
        }

        /// <summary>The operator tenant: where server-wide events (users, tenants) are raised.</summary>
        public static string? OperatorTenant(HttpContext? http)
        {
            try
            {
                var config = http?.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration;
                return config?["ark_oauth_server:TenantId"]?.Trim();
            }
            catch { return null; }
        }
    }
}
