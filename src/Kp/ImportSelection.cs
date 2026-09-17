using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using KeePassFido2.References;

namespace KeePassFido2.Kp
{
    /// <summary>Chooses which .env variables an import moves into KeePass.</summary>
    internal static class ImportSelection
    {
        private static readonly Regex SecretLikeName = new Regex(
            "(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|DSN|DATABASE_URL|PRIVATE|CREDENTIAL|AUTH|SIGNING|WEBHOOK)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>
        /// Variables worth importing: the last assignment of each name that has a value and is not
        /// already a reference.
        /// </summary>
        public static List<DotEnvAssignment> Candidates(DotEnvFile file) =>
            file.Assignments
                .GroupBy(a => a.Key, StringComparer.Ordinal)
                .Select(g => g.Last())
                .Where(a => a.Value.Length > 0 && !SecretReference.LooksLikeReference(a.Value))
                .ToList();

        public static bool LooksSecret(string name) => SecretLikeName.IsMatch(name);

        public static List<DotEnvAssignment> ByPatterns(IEnumerable<DotEnvAssignment> candidates, IList<string> patterns)
        {
            List<Regex> regexes = patterns.Select(GlobToRegex).ToList();
            return candidates.Where(a => regexes.Any(r => r.IsMatch(a.Key))).ToList();
        }

        /// <summary>'*' matches any run of characters, '?' one character; case-insensitive.</summary>
        public static Regex GlobToRegex(string glob) =>
            new Regex("^" + Regex.Escape(glob).Replace("\\*", ".*").Replace("\\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public static List<DotEnvAssignment> Interactive(IList<DotEnvAssignment> candidates, TextReader input, TextWriter output)
        {
            output.WriteLine("Variables in the file (values hidden). [x] = looks like a secret:");
            for (int i = 0; i < candidates.Count; i++)
                output.WriteLine($"  {(LooksSecret(candidates[i].Key) ? "[x]" : "[ ]")} {i + 1,3}. {candidates[i].Key}");

            while (true)
            {
                output.Write("Import which? Enter = the marked ones, 'all', 'none', or numbers like 1,3-5: ");
                string answer = input.ReadLine();
                if (answer == null) return new List<DotEnvAssignment>();
                answer = answer.Trim();

                if (answer.Length == 0) return candidates.Where(c => LooksSecret(c.Key)).ToList();
                if (answer.Equals("all", StringComparison.OrdinalIgnoreCase)) return candidates.ToList();
                if (answer.Equals("none", StringComparison.OrdinalIgnoreCase)) return new List<DotEnvAssignment>();
                if (TryParseRanges(answer, candidates.Count, out List<int> indexes))
                    return indexes.Select(i => candidates[i - 1]).ToList();
                output.WriteLine("  Could not read that selection.");
            }
        }

        public static bool TryParseRanges(string text, int max, out List<int> indexes)
        {
            indexes = new List<int>();
            foreach (string part in text.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] bounds = part.Split('-');
                if (bounds.Length > 2
                    || !int.TryParse(bounds[0], out int from)
                    || !int.TryParse(bounds[bounds.Length - 1], out int to)
                    || from < 1 || to > max || from > to)
                    return false;
                for (int i = from; i <= to; i++)
                    if (!indexes.Contains(i)) indexes.Add(i);
            }
            return indexes.Count > 0;
        }
    }
}
