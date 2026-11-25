using System.Security.Cryptography;
using System.Text;

namespace Ark.Agents.TenantOnboarding.Llm
{
    /// <summary>
    /// AWS Signature Version 4, for the one request this library sends to AWS. Written out so the
    /// library carries no AWS package; checked against the example in the AWS documentation
    /// (see the Checks project).
    /// </summary>
    internal static class AwsSigV4
    {
        public static void Sign(HttpRequestMessage request, byte[] payload, AwsCredentials credentials, string region, string service, DateTime utcNow)
        {
            var uri = request.RequestUri!;
            var amzDate = utcNow.ToString("yyyyMMdd'T'HHmmss'Z'");
            request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);
            if (!string.IsNullOrEmpty(credentials.SessionToken))
                request.Headers.TryAddWithoutValidation("x-amz-security-token", credentials.SessionToken);

            var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                ["host"] = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}",
                ["x-amz-date"] = amzDate
            };
            if (request.Content?.Headers.ContentType is { } type) headers["content-type"] = type.ToString();
            if (!string.IsNullOrEmpty(credentials.SessionToken)) headers["x-amz-security-token"] = credentials.SessionToken!;

            request.Headers.TryAddWithoutValidation("Authorization",
                Authorization(request.Method.Method, uri, headers, payload, credentials, region, service, amzDate));
        }

        /// <summary>The Authorization header value for a request with exactly these signed headers.</summary>
        internal static string Authorization(string method, Uri uri, SortedDictionary<string, string> headers, byte[] payload,
            AwsCredentials credentials, string region, string service, string amzDate)
        {
            var date = amzDate[..8];
            var signedHeaders = string.Join(';', headers.Keys);
            var canonical = new StringBuilder()
                .Append(method).Append('\n')
                .Append(CanonicalPath(uri.AbsolutePath)).Append('\n')
                .Append(CanonicalQuery(uri.Query)).Append('\n');
            foreach (var (name, value) in headers) canonical.Append(name).Append(':').Append(value.Trim()).Append('\n');
            canonical.Append('\n').Append(signedHeaders).Append('\n').Append(Hex(SHA256.HashData(payload)));

            var scope = $"{date}/{region}/{service}/aws4_request";
            var toSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{scope}\n{Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())))}";

            var key = Hmac(Encoding.UTF8.GetBytes("AWS4" + credentials.SecretAccessKey), date);
            key = Hmac(key, region);
            key = Hmac(key, service);
            key = Hmac(key, "aws4_request");
            var signature = Hex(Hmac(key, toSign));
            return $"AWS4-HMAC-SHA256 Credential={credentials.AccessKeyId}/{scope}, SignedHeaders={signedHeaders}, Signature={signature}";
        }

        /// <summary>
        /// Every service but S3 signs the path encoded once more than it is sent: a model id with a
        /// ':' travels as %3A and is signed as %253A.
        /// </summary>
        internal static string CanonicalPath(string absolutePath)
        {
            if (string.IsNullOrEmpty(absolutePath)) return "/";
            return string.Join('/', absolutePath.Split('/').Select(Encode));
        }

        static string CanonicalQuery(string query)
        {
            if (string.IsNullOrEmpty(query) || query == "?") return "";
            var pairs = query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p =>
            {
                var at = p.IndexOf('=');
                var name = Uri.UnescapeDataString(at < 0 ? p : p[..at]);
                var value = at < 0 ? "" : Uri.UnescapeDataString(p[(at + 1)..]);
                return (Name: Encode(name), Value: Encode(value));
            });
            return string.Join('&', pairs.OrderBy(p => p.Name, StringComparer.Ordinal).ThenBy(p => p.Value, StringComparer.Ordinal)
                .Select(p => $"{p.Name}={p.Value}"));
        }

        /// <summary>RFC 3986: everything but the unreserved characters, as upper-case percent escapes.</summary>
        static string Encode(string value)
        {
            var text = new StringBuilder();
            foreach (var b in Encoding.UTF8.GetBytes(value))
            {
                var c = (char)b;
                if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_' or '~') text.Append(c);
                else text.Append('%').Append(b.ToString("X2"));
            }
            return text.ToString();
        }

        static byte[] Hmac(byte[] key, string data) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(data));
        static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
