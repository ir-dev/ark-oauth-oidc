using System.Text;
using System.Text.Json;

namespace Ark.oAuth
{
    /// <summary>
    /// Display helpers for tokens and JSON. Neither is a security boundary.
    /// </summary>
    public static class ArkJwt
    {
        /// <summary>
        /// Renders a JWT payload for a page or a log line.
        ///
        /// It deliberately does not validate the token. Validation belongs to the handler that
        /// received it, and re-checking a signature here would suggest an application is supposed
        /// to inspect its own access token — which it is not: the access token is for the API that
        /// receives it, and an application that reasons about its contents is coupling itself to a
        /// format the provider is free to change.
        /// </summary>
        public static string? DecodePayload(string? jwt)
        {
            if (string.IsNullOrEmpty(jwt)) return null;

            var parts = jwt.Split('.');
            if (parts.Length < 2) return "(not a JWT — the provider issued an opaque token)";

            try
            {
                var payload = parts[1].Replace('-', '+').Replace('_', '/');
                payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
                return ArkJson.Prettify(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
            }
            catch
            {
                return "(could not decode)";
            }
        }
    }

    public static class ArkJson
    {
        /// <summary>Indents JSON for display, returning the input unchanged if it is not JSON.</summary>
        public static string Prettify(string? json)
        {
            if (string.IsNullOrWhiteSpace(json)) return "";
            try
            {
                using var doc = JsonDocument.Parse(json);
                return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
            }
            catch
            {
                return json!;
            }
        }
    }
}
