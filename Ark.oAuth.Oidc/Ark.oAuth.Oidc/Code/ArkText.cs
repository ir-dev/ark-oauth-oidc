using System.Diagnostics.CodeAnalysis;

namespace Ark.oAuth.Oidc
{
    /// <summary>
    /// Text that came from outside, made fit for where it is kept.
    ///
    /// PostgreSQL refuses a NUL in a text column, and its driver refuses half of a surrogate pair.
    /// The refusal takes the whole statement with it, and the audit trail and the webhook queue
    /// are written in batches: one value typed into an anonymous form used to cost every row that
    /// happened to share its batch. SQLite and MySQL store both, so nothing here shows up on them.
    /// </summary>
    internal static class ArkText
    {
        /// <summary>The value with each NUL and each unpaired surrogate replaced by U+FFFD. Same length.</summary>
        [return: NotNullIfNotNull(nameof(value))]
        public static string? Storable(string? value)
        {
            if (value == null) return null;
            // Nearly every value is clean, so it is looked over before it is copied.
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != '\0' && !char.IsSurrogate(value[i])) continue;
                if (char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1])) { i++; continue; }
                return Replace(value, i);
            }
            return value;
        }

        private static string Replace(string value, int from)
        {
            var chars = value.ToCharArray();
            for (var i = from; i < chars.Length; i++)
            {
                if (chars[i] != '\0' && !char.IsSurrogate(chars[i])) continue;
                if (char.IsHighSurrogate(chars[i]) && i + 1 < chars.Length && char.IsLowSurrogate(chars[i + 1])) { i++; continue; }
                chars[i] = '�';
            }
            return new string(chars);
        }

        /// <summary>
        /// At most <paramref name="max"/> characters of a <see cref="Storable"/> value, cut between
        /// characters: a cut through a surrogate pair is how a well-formed value became one that
        /// could not be stored.
        /// </summary>
        [return: NotNullIfNotNull(nameof(value))]
        public static string? Truncate(string? value, int max)
        {
            value = Storable(value);
            if (value == null || value.Length <= max) return value;
            return value[..(max > 0 && char.IsHighSurrogate(value[max - 1]) ? max - 1 : max)];
        }

        /// <summary>
        /// Why a claim key may not be saved, or null when it may. The one rule for every way a key
        /// reaches the catalogue: the console, the management and provisioning APIs, MCP, an import.
        ///
        /// The catalogue belongs to the whole server, and somebody who administers one application
        /// adds to it by granting a claim. What is drawn from it is encoded, but a key is a name
        /// such as <c>billing.admin</c>: one that carries markup is not a name anybody meant.
        /// </summary>
        public static string? ClaimKeyProblem(string? key)
        {
            if (string.IsNullOrWhiteSpace(key)) return "a claim needs a key.";
            return key.Any(c => char.IsControl(c) || c is '<' or '>' or '"' or '\'' or '`')
                ? "a claim key may not contain <, >, quotes or control characters."
                : null;
        }
    }
}
