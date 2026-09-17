using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KeePassFido2.Kp
{
    /// <summary>
    /// A .env file parsed with the common dotenv rules, keeping the original text so values can
    /// be replaced without disturbing comments, order or formatting.
    /// </summary>
    /// <remarks>
    /// Supported: <c>KEY=value</c>, an optional <c>export </c> prefix, full-line and inline
    /// (<c> #</c>) comments, single-quoted literal values, and double-quoted values with
    /// <c>\n \r \t \" \\</c> escapes that may span lines. Variable expansion (<c>${OTHER}</c>) is
    /// left to the program reading the environment.
    /// </remarks>
    internal sealed class DotEnvFile
    {
        private DotEnvFile(string path, string text, Encoding encoding, List<DotEnvAssignment> assignments)
        {
            Path = path;
            Text = text;
            Encoding = encoding;
            Assignments = assignments;
        }

        public string Path { get; }
        public string Text { get; }
        public Encoding Encoding { get; }
        public IReadOnlyList<DotEnvAssignment> Assignments { get; }

        public static DotEnvFile Load(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            bool bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            var encoding = new UTF8Encoding(bom);
            string text = Encoding.UTF8.GetString(bytes, bom ? 3 : 0, bytes.Length - (bom ? 3 : 0));
            return Parse(path, text, encoding);
        }

        public static DotEnvFile Parse(string path, string text, Encoding encoding = null)
        {
            var assignments = new List<DotEnvAssignment>();
            int position = 0;
            int lineNumber = 1;
            while (position < text.Length)
            {
                int lineEnd = IndexOfLineEnd(text, position);
                int startLine = lineNumber;
                int next = ParseLine(text, position, lineEnd, startLine, assignments);
                lineNumber += CountNewlines(text, position, next);
                position = next;
            }
            return new DotEnvFile(path, text, encoding ?? new UTF8Encoding(false), assignments);
        }

        /// <summary>Returns the text with each listed assignment's value replaced, unquoted.</summary>
        public string WithValues(IDictionary<DotEnvAssignment, string> replacements)
        {
            var builder = new StringBuilder(Text);
            foreach (var pair in replacements.OrderByDescending(p => p.Key.ValueStart))
            {
                builder.Remove(pair.Key.ValueStart, pair.Key.ValueEnd - pair.Key.ValueStart);
                builder.Insert(pair.Key.ValueStart, pair.Value);
            }
            return builder.ToString();
        }

        /// <summary>Writes through a temporary file so a failure never leaves a half-written .env.</summary>
        public void Save(string text)
        {
            string temp = Path + ".kp-tmp";
            File.WriteAllText(temp, text, Encoding);
            File.Replace(temp, Path, null);
        }

        private static int ParseLine(string text, int start, int lineEnd, int lineNumber, List<DotEnvAssignment> assignments)
        {
            int i = SkipSpaces(text, start, lineEnd);
            if (i >= lineEnd || text[i] == '#') return NextLine(text, lineEnd);

            if (string.CompareOrdinal(text, i, "export ", 0, 7) == 0) i = SkipSpaces(text, i + 7, lineEnd);

            int keyStart = i;
            while (i < lineEnd && (char.IsLetterOrDigit(text[i]) || text[i] == '_' || text[i] == '.' || text[i] == '-')) i++;
            string key = text.Substring(keyStart, i - keyStart);
            i = SkipSpaces(text, i, lineEnd);
            if (key.Length == 0 || i >= lineEnd || text[i] != '=') return NextLine(text, lineEnd);
            i = SkipSpaces(text, i + 1, lineEnd);

            if (i < text.Length && (text[i] == '"' || text[i] == '\''))
            {
                char quote = text[i];
                int close = FindClosingQuote(text, i + 1, quote);
                if (close >= 0)
                {
                    string raw = text.Substring(i + 1, close - i - 1);
                    string value = quote == '"' ? Unescape(raw) : raw;
                    assignments.Add(new DotEnvAssignment(key, value, lineNumber, i, close + 1));
                    return NextLine(text, IndexOfLineEnd(text, close + 1));
                }
            }

            int valueEnd = lineEnd;
            for (int j = i; j < lineEnd; j++)
            {
                if (text[j] == '#' && j > i && char.IsWhiteSpace(text[j - 1]))
                {
                    valueEnd = j;
                    break;
                }
            }
            while (valueEnd > i && char.IsWhiteSpace(text[valueEnd - 1])) valueEnd--;
            assignments.Add(new DotEnvAssignment(key, text.Substring(i, valueEnd - i), lineNumber, i, valueEnd));
            return NextLine(text, lineEnd);
        }

        private static int FindClosingQuote(string text, int from, char quote)
        {
            for (int i = from; i < text.Length; i++)
            {
                if (quote == '"' && text[i] == '\\') i++;
                else if (text[i] == quote) return i;
            }
            return -1;
        }

        private static string Unescape(string raw)
        {
            var builder = new StringBuilder(raw.Length);
            for (int i = 0; i < raw.Length; i++)
            {
                if (raw[i] != '\\' || i + 1 == raw.Length)
                {
                    builder.Append(raw[i]);
                    continue;
                }
                char next = raw[++i];
                switch (next)
                {
                    case 'n': builder.Append('\n'); break;
                    case 'r': builder.Append('\r'); break;
                    case 't': builder.Append('\t'); break;
                    case '"': builder.Append('"'); break;
                    case '\\': builder.Append('\\'); break;
                    default: builder.Append('\\').Append(next); break;
                }
            }
            return builder.ToString();
        }

        private static int IndexOfLineEnd(string text, int from)
        {
            int end = text.IndexOf('\n', from);
            if (end < 0) return text.Length;
            return end > from && text[end - 1] == '\r' ? end - 1 : end;
        }

        private static int NextLine(string text, int lineEnd)
        {
            if (lineEnd < text.Length && text[lineEnd] == '\r') lineEnd++;
            if (lineEnd < text.Length && text[lineEnd] == '\n') lineEnd++;
            return Math.Max(lineEnd, 0);
        }

        private static int SkipSpaces(string text, int i, int end)
        {
            while (i < end && (text[i] == ' ' || text[i] == '\t')) i++;
            return i;
        }

        private static int CountNewlines(string text, int from, int to)
        {
            int count = 0;
            for (int i = from; i < to && i < text.Length; i++)
                if (text[i] == '\n') count++;
            return count;
        }
    }

    internal sealed class DotEnvAssignment
    {
        public DotEnvAssignment(string key, string value, int line, int valueStart, int valueEnd)
        {
            Key = key;
            Value = value;
            Line = line;
            ValueStart = valueStart;
            ValueEnd = valueEnd;
        }

        public string Key { get; }
        public string Value { get; }
        public int Line { get; }

        /// <summary>Span of the value in the file text, including quotes.</summary>
        public int ValueStart { get; }
        public int ValueEnd { get; }
    }
}
