using System;
using System.Collections.Generic;
using System.Linq;
using KeePassFido2.Storage;

namespace KeePassFido2.Agent
{
    /// <summary>What an approval is remembered for, as the user ticked it in the dialog.</summary>
    internal enum RememberScope
    {
        /// <summary>Ask again next time.</summary>
        None,

        /// <summary>The same program, folder and values (or names).</summary>
        TheseValues,

        /// <summary>The same program and folder, any value or name in the same database.</summary>
        WholeDatabase,
    }

    /// <summary>
    /// Approvals remembered for a while. A grant is keyed on the program and the folder it
    /// runs in, and then either on the exact values asked for, or on a database file, which
    /// covers anything read from that database. Writes (imports) are never remembered.
    /// </summary>
    internal sealed class ApprovalGrants
    {
        private readonly TimeSpan _lifetime;
        private readonly Func<DateTime> _now;
        private readonly Dictionary<string, DateTime> _grants = new Dictionary<string, DateTime>(StringComparer.Ordinal);

        public ApprovalGrants(TimeSpan lifetime, Func<DateTime> now = null)
        {
            _lifetime = lifetime;
            _now = now ?? (() => DateTime.UtcNow);
        }

        /// <param name="program">The requesting program's path.</param>
        /// <param name="folder">Its working directory.</param>
        /// <param name="keys">What it asked for: references, or a description of a listing.</param>
        /// <param name="databasePaths">The databases those come from.</param>
        public void Remember(RememberScope scope, string program, string folder, IEnumerable<string> keys, IEnumerable<string> databasePaths)
        {
            DateTime expires = _now() + _lifetime;
            lock (_grants)
            {
                if (scope == RememberScope.TheseValues)
                    _grants[ValuesKey(program, folder, keys)] = expires;
                else if (scope == RememberScope.WholeDatabase)
                    foreach (string database in databasePaths)
                        _grants[DatabaseKey(program, folder, database)] = expires;
            }
        }

        /// <summary>
        /// Whether a remembered approval covers this request: one for exactly these values, or
        /// one for every database they come from.
        /// </summary>
        public bool Covers(string program, string folder, IEnumerable<string> keys, IEnumerable<string> databasePaths)
        {
            List<string> databases = databasePaths.ToList();
            lock (_grants)
            {
                if (IsLive(ValuesKey(program, folder, keys))) return true;
                return databases.Count > 0 && databases.All(db => IsLive(DatabaseKey(program, folder, db)));
            }
        }

        public void Clear()
        {
            lock (_grants) _grants.Clear();
        }

        private bool IsLive(string key)
        {
            if (!_grants.TryGetValue(key, out DateTime expires)) return false;
            if (expires > _now()) return true;
            _grants.Remove(key);
            return false;
        }

        private static string Prefix(string program, string folder) =>
            (program ?? string.Empty) + "\n" + UnlockStore.NormalizePath(folder ?? string.Empty);

        private static string ValuesKey(string program, string folder, IEnumerable<string> keys) =>
            Prefix(program, folder) + "\nvalues\n" + string.Join("\n", keys.Distinct(StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal));

        private static string DatabaseKey(string program, string folder, string databasePath) =>
            Prefix(program, folder) + "\ndatabase\n" + UnlockStore.NormalizePath(databasePath ?? string.Empty);
    }
}
