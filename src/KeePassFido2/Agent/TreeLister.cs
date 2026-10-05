using System.Collections.Generic;
using System.Linq;
using KeePassFido2.Ipc;
using KeePassLib;

namespace KeePassFido2.Agent
{
    /// <summary>
    /// Lists the names below a group for <see cref="KpRequestKind.Tree"/>: group names, entry
    /// titles and, when asked, the names of fields that hold a value. Never a value itself.
    /// </summary>
    internal static class TreeLister
    {
        /// <param name="startPath">Group names from the root to <paramref name="start"/>.</param>
        /// <param name="depth">Levels below <paramref name="start"/> to list; 0 for all.</param>
        public static List<KpTreeNode> List(PwDatabase database, string databaseName, PwGroup start, IList<string> startPath,
            int depth, bool includeEntries, bool includeFields)
        {
            var nodes = new List<KpTreeNode>();
            Walk(database, databaseName, start, startPath.ToList(), 0, depth, includeEntries, includeFields, nodes);
            return nodes;
        }

        /// <summary>Group names from below the root down to <paramref name="group"/>; names may contain '/'.</summary>
        public static List<string> PathOf(PwDatabase database, PwGroup group)
        {
            var path = new List<string>();
            for (PwGroup g = group; g != null && g != database.RootGroup; g = g.ParentGroup)
                path.Insert(0, g.Name);
            return path;
        }

        private static void Walk(PwDatabase database, string databaseName, PwGroup group, List<string> path, int level,
            int depth, bool includeEntries, bool includeFields, List<KpTreeNode> nodes)
        {
            if (depth > 0 && level >= depth) return;

            if (includeEntries)
            {
                foreach (PwEntry entry in group.Entries.OrderBy(e => e.Strings.ReadSafe(PwDefs.TitleField), System.StringComparer.OrdinalIgnoreCase))
                {
                    nodes.Add(new KpTreeNode
                    {
                        Database = databaseName,
                        GroupPath = path.ToList(),
                        Entry = entry.Strings.ReadSafe(PwDefs.TitleField),
                        Fields = includeFields ? FieldNames(entry) : new List<string>(),
                    });
                }
            }

            foreach (PwGroup child in group.Groups.OrderBy(g => g.Name, System.StringComparer.OrdinalIgnoreCase))
            {
                // Deleted entries wait in the recycle bin; nothing new belongs there.
                if (database.RecycleBinEnabled && child.Uuid.Equals(database.RecycleBinUuid)) continue;

                var childPath = new List<string>(path) { child.Name };
                nodes.Add(new KpTreeNode { Database = databaseName, GroupPath = childPath });
                Walk(database, databaseName, child, childPath, level + 1, depth, includeEntries, includeFields, nodes);
            }
        }

        /// <summary>Standard fields first in KeePass's order, then custom ones; the title is the entry's name, so left out.</summary>
        private static List<string> FieldNames(PwEntry entry)
        {
            var standard = new[] { PwDefs.UserNameField, PwDefs.PasswordField, PwDefs.UrlField, PwDefs.NotesField };
            var present = entry.Strings.Where(s => !s.Value.IsEmpty).Select(s => s.Key).ToList();
            return standard.Where(present.Contains)
                .Concat(present.Where(k => k != PwDefs.TitleField && !standard.Contains(k)).OrderBy(k => k, System.StringComparer.OrdinalIgnoreCase))
                .ToList();
        }
    }
}
