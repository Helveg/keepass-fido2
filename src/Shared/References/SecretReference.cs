using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KeePassFido2.References
{
    /// <summary>
    /// A reference to a KeePass entry field, as written into .env files:
    /// <c>kp://Group/Sub/Entry</c> (password), <c>kp://Group/Entry#UserName</c>, or
    /// <c>kp://uuid/0123…cdef#Field</c>. Path segments are percent-encoded when they contain
    /// '/', '#', '%', quotes, backslashes or whitespace.
    /// </summary>
    /// <remarks>The syntax ends up in users' files, so it stays backwards compatible.</remarks>
    internal sealed class SecretReference
    {
        public const string Scheme = "kp://";
        public const string DefaultField = "Password";
        private const string UuidPrefix = "uuid/";

        private static readonly Dictionary<string, string> StandardFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["title"] = "Title",
            ["username"] = "UserName",
            ["user"] = "UserName",
            ["password"] = "Password",
            ["url"] = "URL",
            ["notes"] = "Notes",
        };

        private SecretReference(IList<string> groupPath, string entryTitle, string entryUuid, string field)
        {
            GroupPath = groupPath;
            EntryTitle = entryTitle;
            EntryUuid = entryUuid;
            Field = field;
        }

        /// <summary>Group names below the root group; empty for entries in the root group.</summary>
        public IList<string> GroupPath { get; }

        /// <summary>Null when the reference uses a UUID.</summary>
        public string EntryTitle { get; }

        /// <summary>32 lowercase hex digits, or null when the reference uses a path.</summary>
        public string EntryUuid { get; }

        /// <summary>KeePass string field name, e.g. Password, UserName or a custom field.</summary>
        public string Field { get; }

        public static bool LooksLikeReference(string value) =>
            value != null && value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase);

        public static SecretReference ForEntry(IEnumerable<string> groupPath, string entryTitle, string field = DefaultField) =>
            new SecretReference(groupPath.ToList(), entryTitle, null, NormalizeField(field));

        /// <param name="entryUuid">32 hex digits, e.g. from KeePass's PwUuid.ToHexString().</param>
        public static SecretReference ForUuid(string entryUuid, string field = DefaultField) =>
            new SecretReference(new List<string>(), null, entryUuid.ToLowerInvariant(), NormalizeField(field));

        public static bool TryParse(string text, out SecretReference reference, out string error)
        {
            reference = null;
            error = null;
            if (!LooksLikeReference(text))
            {
                error = $"'{text}' does not start with {Scheme}";
                return false;
            }

            string body = text.Substring(Scheme.Length).Trim();
            string field = DefaultField;
            int hash = body.IndexOf('#');
            if (hash >= 0)
            {
                field = Decode(body.Substring(hash + 1));
                body = body.Substring(0, hash);
                if (field.Length == 0)
                {
                    error = $"'{text}' has an empty field name after '#'";
                    return false;
                }
            }

            if (body.StartsWith(UuidPrefix, StringComparison.OrdinalIgnoreCase))
            {
                string uuid = body.Substring(UuidPrefix.Length).Replace("-", string.Empty).ToLowerInvariant();
                if (uuid.Length != 32 || !uuid.All(Uri.IsHexDigit))
                {
                    error = $"'{text}' does not contain a 32-digit entry UUID";
                    return false;
                }
                reference = new SecretReference(new List<string>(), null, uuid, NormalizeField(field));
                return true;
            }

            List<string> segments = body.Split('/').Select(Decode).ToList();
            if (segments.Count == 0 || segments.Any(s => s.Length == 0))
            {
                error = $"'{text}' has an empty group or entry name";
                return false;
            }

            string title = segments[segments.Count - 1];
            segments.RemoveAt(segments.Count - 1);
            reference = new SecretReference(segments, title, null, NormalizeField(field));
            return true;
        }

        public override string ToString()
        {
            var builder = new StringBuilder(Scheme);
            if (EntryUuid != null)
            {
                builder.Append(UuidPrefix).Append(EntryUuid);
            }
            else
            {
                foreach (string group in GroupPath) builder.Append(Encode(group)).Append('/');
                builder.Append(Encode(EntryTitle));
            }
            if (!string.Equals(Field, DefaultField, StringComparison.Ordinal))
                builder.Append('#').Append(Encode(Field));
            return builder.ToString();
        }

        private static string NormalizeField(string field) =>
            StandardFields.TryGetValue(field, out string standard) ? standard : field;

        private static string Encode(string segment)
        {
            var builder = new StringBuilder();
            foreach (char c in segment)
            {
                if (c == '%' || c == '/' || c == '#' || c == '"' || c == '\'' || c == '\\' || char.IsWhiteSpace(c) || char.IsControl(c))
                    foreach (byte b in Encoding.UTF8.GetBytes(c.ToString())) builder.Append('%').Append(b.ToString("X2"));
                else
                    builder.Append(c);
            }
            return builder.ToString();
        }

        private static string Decode(string segment) => Uri.UnescapeDataString(segment);
    }
}
