using System.Security.Cryptography;
using System.Text;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Cryptographic primitives for the authorization server.
    ///
    /// Two things here matter more than the rest:
    ///  * <see cref="GenerateRsaKeyPair"/> creates signing keys locally. Earlier versions fetched
    ///    them from an external HTTP service, which meant the tenant's private key existed off-box.
    ///  * every secret comparison goes through <see cref="FixedTimeEquals"/> so that verifying a
    ///    code, secret or PKCE verifier does not leak its content through response timing.
    /// </summary>
    public static class ArkCrypto
    {
        // --- base64url (RFC 7515 §2) ---

        public static string Base64UrlEncode(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static byte[] Base64UrlDecode(string value)
        {
            var s = value.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }

        /// <summary>A cryptographically random, URL-safe token. 32 bytes = 256 bits of entropy.</summary>
        public static string RandomToken(int byteLength = 32) =>
            Base64UrlEncode(RandomNumberGenerator.GetBytes(byteLength));

        public static string Sha256Base64Url(string value) =>
            Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

        /// <summary>
        /// The at_hash / c_hash construction (OIDC Core §3.1.3.6): left-most half of the
        /// SHA-256 of the ASCII value, base64url encoded.
        /// </summary>
        public static string LeftHalfHash(string value)
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(value));
            return Base64UrlEncode(hash.Take(hash.Length / 2).ToArray());
        }

        /// <summary>Constant-time string comparison. Returns false for null on either side.</summary>
        public static bool FixedTimeEquals(string? a, string? b)
        {
            if (a is null || b is null) return false;
            var ba = Encoding.UTF8.GetBytes(a);
            var bb = Encoding.UTF8.GetBytes(b);
            if (ba.Length != bb.Length) return false;
            return CryptographicOperations.FixedTimeEquals(ba, bb);
        }

        // --- signing keys ---

        /// <summary>
        /// Generates an RSA key pair locally and returns it as (base64 SPKI public, base64 PKCS#8 private).
        /// </summary>
        public static (string publicKey, string privateKey) GenerateRsaKeyPair(int keySize = 2048)
        {
            using var rsa = RSA.Create(keySize);
            return (
                Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
                Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())
            );
        }

        /// <summary>Rehydrates an RSA instance from a base64 PKCS#8 private key.</summary>
        public static RSA ImportPrivateKey(string base64Pkcs8)
        {
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(base64Pkcs8), out _);
            return rsa;
        }

        /// <summary>Rehydrates an RSA instance from a base64 SubjectPublicKeyInfo public key.</summary>
        public static RSA ImportPublicKey(string base64Spki)
        {
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(base64Spki), out _);
            return rsa;
        }

        /// <summary>
        /// A stable key id derived from the public key itself (RFC 7638 JWK thumbprint).
        /// Deriving rather than assigning means the same key always presents the same kid.
        /// </summary>
        public static string ComputeKid(string base64Spki)
        {
            using var rsa = ImportPublicKey(base64Spki);
            var p = rsa.ExportParameters(false);
            var n = Base64UrlEncode(p.Modulus!);
            var e = Base64UrlEncode(p.Exponent!);
            // canonical JWK member ordering per RFC 7638 §3.3
            var canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
            return Sha256Base64Url(canonical);
        }

        // --- client secrets ---

        private const int SecretSaltBytes = 16;
        private const int SecretHashBytes = 32;
        private const int SecretIterations = 210_000; // OWASP 2023 guidance for PBKDF2-SHA256

        /// <summary>Hashes a client secret with PBKDF2-SHA256. Format: {iterations}.{salt}.{hash}</summary>
        public static string HashSecret(string secret)
        {
            var salt = RandomNumberGenerator.GetBytes(SecretSaltBytes);
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(secret), salt, SecretIterations, HashAlgorithmName.SHA256, SecretHashBytes);
            return $"{SecretIterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
        }

        /// <summary>Verifies a client secret against a stored PBKDF2 hash, in constant time.</summary>
        public static bool VerifySecret(string? secret, string? stored)
        {
            if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(stored)) return false;
            var parts = stored.Split('.');
            if (parts.Length != 3) return false;
            if (!int.TryParse(parts[0], out var iterations)) return false;
            try
            {
                var salt = Convert.FromBase64String(parts[1]);
                var expected = Convert.FromBase64String(parts[2]);
                var actual = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(secret), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch
            {
                return false;
            }
        }

        // --- device flow user codes ---

        // Base20 alphabet: no vowels (avoids accidental words) and no 0/1/I/O lookalikes.
        private const string UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";

        /// <summary>A user code for the device grant, formatted "XXXX-XXXX" (RFC 8628 §6.1).</summary>
        public static string NewUserCode()
        {
            var chars = new char[8];
            for (int i = 0; i < chars.Length; i++)
                chars[i] = UserCodeAlphabet[RandomNumberGenerator.GetInt32(UserCodeAlphabet.Length)];
            return $"{new string(chars, 0, 4)}-{new string(chars, 4, 4)}";
        }

        /// <summary>Strips formatting so "wdjb-mjht" and "WDJBMJHT" both match the stored code.</summary>
        public static string NormalizeUserCode(string? input) =>
            new string((input ?? "").Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
    }
}
