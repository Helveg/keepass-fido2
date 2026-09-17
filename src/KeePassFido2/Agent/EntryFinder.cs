using System;
using System.Collections.Generic;
using System.Linq;
using KeePassFido2.References;
using KeePassLib;

namespace KeePassFido2.Agent
{
    /// <summary>Finds the entry a <see cref="SecretReference"/> points to in the open databases.</summary>
    internal static class EntryFinder
    {
        public static bool TryFind(IList<PwDatabase> databases, SecretReference reference, out PwDatabase database, out PwEntry entry, out string error)
        {
            var matches = new List<(PwDatabase Database, PwEntry Entry)>();
            foreach (PwDatabase candidate in databases)
            {
                if (reference.EntryUuid != null)
                {
                    PwEntry byUuid = candidate.RootGroup.FindEntry(new PwUuid(HexToBytes(reference.EntryUuid)), true);
                    if (byUuid != null) matches.Add((candidate, byUuid));
                    continue;
                }

                PwGroup group = FindGroup(candidate, reference.GroupPath);
                if (group == null) continue;
                matches.AddRange(FindEntries(group, reference.EntryTitle).Select(e => (candidate, e)));
            }

            database = null;
            entry = null;
            error = null;
            if (matches.Count == 0)
            {
                error = $"{reference}: no such entry in the unlocked databases.";
                return false;
            }
            if (matches.Count > 1)
            {
                error = $"{reference}: {matches.Count} entries match; rename one or use kp://uuid/<entry UUID>.";
                return false;
            }

            database = matches[0].Database;
            entry = matches[0].Entry;
            if (!entry.Strings.Exists(reference.Field))
            {
                error = $"{reference}: the entry has no field '{reference.Field}'.";
                return false;
            }
            return true;
        }

        /// <summary>
        /// Walks group names below the root. A leading segment naming the root group itself is
        /// accepted too, since KeePass shows the root in its group tree.
        /// </summary>
        public static PwGroup FindGroup(PwDatabase database, IList<string> path)
        {
            PwGroup group = Walk(database.RootGroup, path, 0);
            if (group == null && path.Count > 0 && Matches(database.RootGroup.Name, path[0]))
                group = Walk(database.RootGroup, path, 1);
            return group;
        }

        /// <summary>Entries directly in <paramref name="group"/> with this title; exact case preferred.</summary>
        public static List<PwEntry> FindEntries(PwGroup group, string title)
        {
            List<PwEntry> exact = group.Entries.Where(e => string.Equals(e.Strings.ReadSafe(PwDefs.TitleField), title, StringComparison.Ordinal)).ToList();
            return exact.Count > 0
                ? exact
                : group.Entries.Where(e => Matches(e.Strings.ReadSafe(PwDefs.TitleField), title)).ToList();
        }

        private static PwGroup Walk(PwGroup group, IList<string> path, int start)
        {
            for (int i = start; i < path.Count && group != null; i++)
            {
                List<PwGroup> children = group.Groups.Where(g => string.Equals(g.Name, path[i], StringComparison.Ordinal)).ToList();
                if (children.Count == 0) children = group.Groups.Where(g => Matches(g.Name, path[i])).ToList();
                group = children.Count == 1 ? children[0] : null;
            }
            return group;
        }

        private static bool Matches(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        private static byte[] HexToBytes(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
    }
}
