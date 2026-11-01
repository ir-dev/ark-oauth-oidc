namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>Error codes defined by RFC 6749 §4.1.2.1/§5.2, RFC 8628 §3.5 and OIDC Core §3.1.2.6.</summary>
    public static class OAuthErrorCodes
    {
        // shared
        public const string InvalidRequest = "invalid_request";
        public const string InvalidClient = "invalid_client";
        public const string InvalidGrant = "invalid_grant";
        public const string UnauthorizedClient = "unauthorized_client";
        public const string UnsupportedGrantType = "unsupported_grant_type";
        public const string InvalidScope = "invalid_scope";
        public const string ServerError = "server_error";
        public const string TemporarilyUnavailable = "temporarily_unavailable";

        // authorization endpoint
        public const string AccessDenied = "access_denied";
        public const string UnsupportedResponseType = "unsupported_response_type";
        public const string InteractionRequired = "interaction_required";
        public const string LoginRequired = "login_required";
        public const string ConsentRequired = "consent_required";
        public const string AccountSelectionRequired = "account_selection_required";
        public const string InvalidRequestUri = "invalid_request_uri";
        public const string InvalidRequestObject = "invalid_request_object";
        public const string RequestNotSupported = "request_not_supported";
        public const string RegistrationNotSupported = "registration_not_supported";

        // device grant (RFC 8628 §3.5)
        public const string AuthorizationPending = "authorization_pending";
        public const string SlowDown = "slow_down";
        public const string ExpiredToken = "expired_token";

        // dynamic client registration (RFC 7591 §3.2.2)
        public const string InvalidRedirectUri = "invalid_redirect_uri";
        public const string InvalidClientMetadata = "invalid_client_metadata";

        // resource server (RFC 6750)
        public const string InvalidToken = "invalid_token";
        public const string InsufficientScope = "insufficient_scope";
    }

    /// <summary>
    /// A protocol-level failure that must be surfaced to the client in the shape the spec
    /// requires, rather than as a stack trace or an HTTP 200 with an error string in the body.
    /// </summary>
    public class OAuthException : Exception
    {
        public string Error { get; }
        public string? ErrorDescription { get; }
        public string? ErrorUri { get; }
        public int StatusCode { get; }

        public OAuthException(string error, string? description = null, int statusCode = 400, string? errorUri = null)
            : base(description ?? error)
        {
            Error = error;
            ErrorDescription = description;
            ErrorUri = errorUri;
            StatusCode = statusCode;
        }

        public static OAuthException InvalidRequest(string description) =>
            new(OAuthErrorCodes.InvalidRequest, description);

        /// <summary>invalid_client is a 401 when the request carried client credentials (RFC 6749 §5.2).</summary>
        public static OAuthException InvalidClient(string description, bool viaAuthorizationHeader = false) =>
            new(OAuthErrorCodes.InvalidClient, description, viaAuthorizationHeader ? 401 : 400);

        public static OAuthException InvalidGrant(string description) =>
            new(OAuthErrorCodes.InvalidGrant, description);

        public static OAuthException InvalidScope(string description) =>
            new(OAuthErrorCodes.InvalidScope, description);

        public static OAuthException UnauthorizedClient(string description) =>
            new(OAuthErrorCodes.UnauthorizedClient, description);

        public static OAuthException UnsupportedGrantType(string grantType) =>
            new(OAuthErrorCodes.UnsupportedGrantType, $"grant_type '{grantType}' is not supported by this client.");

        public static OAuthException ServerError(string description) =>
            new(OAuthErrorCodes.ServerError, description, 500);

        /// <summary>The body of an RFC 6749 §5.2 error response.</summary>
        public Dictionary<string, object> ToResponseBody()
        {
            var body = new Dictionary<string, object> { ["error"] = Error };
            if (!string.IsNullOrEmpty(ErrorDescription)) body["error_description"] = ErrorDescription!;
            if (!string.IsNullOrEmpty(ErrorUri)) body["error_uri"] = ErrorUri!;
            return body;
        }
    }
}
