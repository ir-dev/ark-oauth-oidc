using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ark.oAuth
{
    /// <summary>
    /// Dynamic client registration (RFC 7591) and registration management (RFC 7592).
    ///
    /// Registration is how a client stops being something a human types into an admin console: the
    /// application posts its own metadata — redirect URIs, grant types, scopes — and the provider
    /// answers with a client_id, optionally a client_secret, and a <c>registration_access_token</c>
    /// that is the only credential able to read or delete that registration afterwards.
    ///
    /// Two consequences are easy to miss and expensive to discover later:
    ///  * The <b>registration access token is shown once</b>. Lose it and the registration can
    ///    only be cleaned up by an operator with database access.
    ///  * Registration is <b>not authentication</b>. A newly registered client can ask for tokens,
    ///    but on Ark a user still has to be mapped to it before anyone can sign in.
    ///
    /// The endpoint comes from the provider's discovery document. Its absence there is the
    /// provider saying dynamic registration is switched off — which this class reports rather than
    /// guessing at a URL.
    /// </summary>
    public sealed class ArkRegistration
    {
        private readonly ArkSetupProbe _probe;
        private readonly IHttpClientFactory _http;

        public ArkRegistration(ArkSetupProbe probe, IHttpClientFactory http)
        {
            _probe = probe;
            _http = http;
        }

        /// <summary>
        /// Registers a new client (RFC 7591 §3.1).
        /// </summary>
        /// <param name="metadata">Client metadata; <c>redirect_uris</c> is required for any grant that returns through a browser.</param>
        /// <param name="initialAccessToken">
        /// The token authorising registration. Required unless the provider has been configured to
        /// accept open registration — on Ark it must carry the <c>client.register</c> scope, which
        /// is what the client_credentials grant is for.
        /// </param>
        public async Task<ArkRegistrationResult> RegisterAsync(
            JsonObject metadata, string? initialAccessToken = null,
            string? authority = null, CancellationToken cancellationToken = default)
        {
            return await SendAsync(HttpMethod.Post, endpoint => endpoint, initialAccessToken,
                metadata, authority, cancellationToken);
        }

        /// <summary>Reads a registration back (RFC 7592 §2.1), using its registration access token.</summary>
        public Task<ArkRegistrationResult> ReadAsync(
            string clientId, string registrationAccessToken,
            string? authority = null, CancellationToken cancellationToken = default) =>
            SendAsync(HttpMethod.Get, endpoint => $"{endpoint.TrimEnd('/')}/{clientId}",
                registrationAccessToken, null, authority, cancellationToken);

        /// <summary>Deletes a registration (RFC 7592 §2.3). The client stops existing immediately.</summary>
        public Task<ArkRegistrationResult> DeleteAsync(
            string clientId, string registrationAccessToken,
            string? authority = null, CancellationToken cancellationToken = default) =>
            SendAsync(HttpMethod.Delete, endpoint => $"{endpoint.TrimEnd('/')}/{clientId}",
                registrationAccessToken, null, authority, cancellationToken);

        private async Task<ArkRegistrationResult> SendAsync(
            HttpMethod method, Func<string, string> url, string? bearerToken,
            JsonObject? body, string? authority, CancellationToken cancellationToken)
        {
            var result = new ArkRegistrationResult();

            try
            {
                var metadata = await _probe.ReadMetadataAsync(authority, cancellationToken);
                if (string.IsNullOrEmpty(metadata.RegistrationEndpoint))
                {
                    result.Error = "registration_not_supported";
                    result.ErrorDescription =
                        "the provider does not advertise a registration_endpoint, which means dynamic " +
                        "registration is disabled. Set ark_oauth_server:Oidc:EnableDynamicRegistration.";
                    return result;
                }

                result.Endpoint = url(metadata.RegistrationEndpoint!);
                result.RequestBody = body == null ? null : ArkJson.Prettify(body.ToJsonString());

                using var request = new HttpRequestMessage(method, result.Endpoint);
                if (!string.IsNullOrWhiteSpace(bearerToken))
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
                if (body != null)
                    request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

                var client = _http.CreateClient("ark-oidc-client");
                using var response = await client.SendAsync(request, cancellationToken);

                var payload = await response.Content.ReadAsStringAsync(cancellationToken);
                result.StatusCode = (int)response.StatusCode;
                result.RawResponse = ArkJson.Prettify(payload);

                if (string.IsNullOrWhiteSpace(payload))
                {
                    // 204 from a delete: no body is the successful answer.
                    if (!response.IsSuccessStatusCode)
                    {
                        result.Error = "request_failed";
                        result.ErrorDescription = $"the provider answered {(int)response.StatusCode} {response.ReasonPhrase}.";
                    }
                    return result;
                }

                using var doc = JsonDocument.Parse(payload);
                var root = doc.RootElement;
                string? Str(string name) =>
                    root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

                if (!response.IsSuccessStatusCode)
                {
                    result.Error = Str("error") ?? "request_failed";
                    result.ErrorDescription = Str("error_description");
                    return result;
                }

                result.ClientId = Str("client_id");
                result.ClientSecret = Str("client_secret");
                result.RegistrationAccessToken = Str("registration_access_token");
                result.RegistrationClientUri = Str("registration_client_uri");
                result.ClientName = Str("client_name");
            }
            catch (Exception ex)
            {
                result.Error = "request_failed";
                result.ErrorDescription = ex.Message;
            }

            return result;
        }
    }

    /// <summary>The result of a registration call, including the credentials shown only once.</summary>
    public class ArkRegistrationResult
    {
        public string Endpoint { get; set; } = "";
        public int StatusCode { get; set; }

        public string? ClientId { get; set; }
        public string? ClientName { get; set; }

        /// <summary>Returned once, for confidential clients. Store it now or regenerate it later.</summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Returned once. It is the only credential that can read, update or delete this
        /// registration afterwards — it is not the client's access token and cannot be re-derived.
        /// </summary>
        public string? RegistrationAccessToken { get; set; }

        public string? RegistrationClientUri { get; set; }

        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }

        public string? RequestBody { get; set; }
        public string? RawResponse { get; set; }

        public bool Succeeded => string.IsNullOrEmpty(Error);
    }
}
