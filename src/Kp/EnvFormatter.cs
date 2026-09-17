using System;
using System.Collections.Generic;
using System.Text;

namespace KeePassFido2.Kp
{
    /// <summary>Prints resolved variables for shells that cannot be started by kp.exe itself.</summary>
    internal static class EnvFormatter
    {
        public static readonly string[] Formats = { "dotenv", "export", "powershell", "null" };

        public static string Format(IEnumerable<KeyValuePair<string, string>> variables, string format)
        {
            var builder = new StringBuilder();
            foreach (var pair in variables)
            {
                switch (format)
                {
                    case "dotenv":
                        builder.Append(pair.Key).Append("=\"").Append(EscapeDoubleQuoted(pair.Value)).Append("\"\n");
                        break;
                    case "export":
                        builder.Append("export ").Append(pair.Key).Append("='").Append(pair.Value.Replace("'", "'\\''")).Append("'\n");
                        break;
                    case "powershell":
                        builder.Append("$env:").Append(pair.Key).Append(" = '").Append(pair.Value.Replace("'", "''")).Append("'\n");
                        break;
                    case "null":
                        // For `mapfile -d ''` in bash: values may contain newlines but never NUL.
                        builder.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
                        break;
                    default:
                        throw new KpException($"Unknown format '{format}'. Use one of: {string.Join(", ", Formats)}.");
                }
            }
            return builder.ToString();
        }

        private static string EscapeDoubleQuoted(string value) =>
            value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
    }
}
