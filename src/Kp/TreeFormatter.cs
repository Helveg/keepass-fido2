using System.Collections.Generic;
using System.Linq;
using System.Text;
using KeePassFido2.Ipc;
using KeePassFido2.References;

namespace KeePassFido2.Kp
{
    /// <summary>Prints a <see cref="KpRequestKind.Tree"/> response, one database after another.</summary>
    internal static class TreeFormatter
    {
        public static readonly string[] Formats = { "tree", "references" };

        public static string Format(IList<KpTreeNode> nodes, string format)
        {
            var output = new StringBuilder();
            foreach (IGrouping<string, KpTreeNode> database in nodes.GroupBy(n => n.Database))
            {
                if (format == "references")
                {
                    foreach (KpTreeNode node in database)
                        foreach (string line in References(node)) output.Append(line).Append('\n');
                    continue;
                }

                // The listed group's own depth: its entries sit at it, its subgroups one below.
                // Taken from the nodes, since the path typed may include the root group's name.
                int startDepth = database.Min(n => n.Entry == null ? n.GroupPath.Count - 1 : n.GroupPath.Count);
                output.Append(database.Key).Append('\n');
                foreach (KpTreeNode node in database)
                {
                    int level = node.GroupPath.Count - startDepth + (node.Entry == null ? 0 : 1);
                    output.Append(' ', 2 * level);
                    if (node.Entry == null)
                        output.Append(node.GroupPath.Last()).Append('/');
                    else
                    {
                        output.Append(node.Entry);
                        if (node.Fields.Count > 0) output.Append("  [").Append(string.Join(", ", node.Fields)).Append(']');
                    }
                    output.Append('\n');
                }
            }
            return output.ToString();
        }

        /// <summary>A group as the prefix its references share; an entry as one reference per field, or its password reference.</summary>
        private static IEnumerable<string> References(KpTreeNode node)
        {
            if (node.Entry == null) return new[] { SecretReference.GroupPrefix(node.GroupPath) };
            IEnumerable<string> fields = node.Fields.Count > 0 ? node.Fields : new List<string> { SecretReference.DefaultField };
            return fields.Select(field => SecretReference.ForEntry(node.GroupPath, node.Entry, field).ToString());
        }
    }
}
