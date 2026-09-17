using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassFido2.Ipc;
using KeePassFido2.References;
using KeePassFido2.Storage;
using KeePassFido2.UI;
using KeePassFido2.Unlock;
using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Serialization;

namespace KeePassFido2.Agent
{
    /// <summary>
    /// Answers kp.exe requests on KeePass's UI thread: resolves entry references and imports
    /// values, each after the user approves in <see cref="ApprovalDialog"/>.
    /// </summary>
    /// <remarks>
    /// When the database has Windows Hello or a security key set up, approving requires that
    /// method, so a click injected by another program is not enough. Approvals remembered for a
    /// folder cover the same program and the same references, and end when a database is closed
    /// or locked.
    /// </remarks>
    internal sealed class SecretBroker
    {
        private static readonly TimeSpan GrantLifetime = TimeSpan.FromHours(8);

        private readonly IPluginHost _host;
        private readonly UnlockService _unlock;
        private readonly ContextStore _contexts;
        private readonly Dictionary<string, DateTime> _grants = new Dictionary<string, DateTime>();

        public SecretBroker(IPluginHost host, UnlockService unlock, ContextStore contexts)
        {
            _host = host;
            _unlock = unlock;
            _contexts = contexts;
        }

        /// <summary>Called on the pipe thread; runs the request on KeePass's UI thread.</summary>
        public KpResponse Handle(KpRequest request, ClientProcess client)
        {
            Form main = _host.MainWindow;
            if (main.IsDisposed) return KpResponse.Failure("KeePass is closing.");
            try
            {
                switch (request.Kind)
                {
                    case KpRequestKind.Context:
                        return HandleContext(request, client);
                    case KpRequestKind.ContextList:
                        return ListContexts();
                    case KpRequestKind.ContextRemove:
                        return _contexts.Remove(request.Context)
                            ? new KpResponse { Ok = true }
                            : KpResponse.Failure($"There is no context '{request.Context}'.");
                }
                return (KpResponse)main.Invoke(new Func<KpResponse>(() => HandleOnUiThread(request, client)));
            }
            catch (Exception ex)
            {
                return KpResponse.Failure(ex.InnerException?.Message ?? ex.Message);
            }
        }

        public void ForgetApprovals()
        {
            lock (_grants) _grants.Clear();
        }

        private KpResponse HandleOnUiThread(KpRequest request, ClientProcess client)
        {
            switch (request.Kind)
            {
                case KpRequestKind.Ping:
                    return new KpResponse { Ok = true };
                case KpRequestKind.Resolve:
                case KpRequestKind.Import:
                    KpResponse notReady = EnsureDatabaseOpen(request.DatabasePath, out List<PwDatabase> databases);
                    if (notReady != null) return notReady;
                    return request.Kind == KpRequestKind.Resolve
                        ? Resolve(request, client, databases)
                        : Import(request, client, databases);
                default:
                    return KpResponse.Failure($"Unknown request '{request.Kind}'.");
            }
        }

        /// <summary>
        /// Makes sure the requested database, or else any database, is unlocked, showing KeePass's
        /// own unlock prompt when needed. Returns null with the databases to use, or the response
        /// to send instead.
        /// </summary>
        private KpResponse EnsureDatabaseOpen(string databasePath, out List<PwDatabase> databases)
        {
            MainForm main = _host.MainWindow;
            databases = OpenDatabasesMatching(databasePath);
            if (databases.Count > 0) return null;

            // An unlock prompt is already up, e.g. KeePass was just started with a database. A
            // second prompt would stack on top of it, so let kp.exe ask again once it closes.
            if (Application.OpenForms.OfType<KeyPromptForm>().Any())
                return KpResponse.Busy("Waiting for the database to be unlocked in KeePass.");

            // KeePass is still loading a database whose prompt was just answered: this request
            // runs in the message loop KeePass pumps while decrypting, and opening now is refused.
            if (main.UIIsInteractionBlocked())
                return KpResponse.Busy("Waiting for KeePass to finish opening the database.");

            IOConnectionInfo target = databasePath != null
                ? IOConnectionInfo.FromPath(databasePath)
                : main.DocumentManager.Documents.Where(d => main.IsFileLocked(d)).Select(d => d.LockedIoc).FirstOrDefault()
                  ?? NonEmpty(KeePass.Program.Config.Application.LastUsedFile);
            if (target == null)
                return KpResponse.Failure("KeePass has no database open. Open one, or pass --database PATH.");
            if (target.IsLocalFile() && !System.IO.File.Exists(target.Path))
                return KpResponse.Failure($"{target.Path} does not exist.");

            main.EnsureVisibleForegroundWindow(true, true);
            bool prompted = false;
            EventHandler<GwmWindowEventArgs> watchPrompt = (s, e) => prompted |= e.Form is KeyPromptForm;
            GlobalWindowManager.WindowAdded += watchPrompt;
            try
            {
                main.OpenDatabase(target, null, false);
            }
            finally
            {
                GlobalWindowManager.WindowAdded -= watchPrompt;
            }

            databases = OpenDatabasesMatching(databasePath ?? target.Path);
            if (databases.Count > 0) return null;

            // No prompt appeared, so KeePass did not take the request (for instance while it
            // finishes loading); a dismissed prompt, on the other hand, is a real refusal.
            if (!prompted)
                return KpResponse.Busy("Waiting for KeePass to finish opening the database.");
            List<string> open = main.DocumentManager.GetOpenDatabases().Select(db => db.IOConnectionInfo.Path).ToList();
            return KpResponse.Failure(open.Count == 0
                ? "The database was not unlocked."
                : $"{target.Path} is not among the unlocked databases: {string.Join(", ", open)}.");
        }

        private List<PwDatabase> OpenDatabasesMatching(string databasePath)
        {
            List<PwDatabase> open = _host.MainWindow.DocumentManager.GetOpenDatabases();
            if (databasePath == null) return open;
            string wanted = UnlockStore.NormalizePath(databasePath);
            return open.Where(db => UnlockStore.NormalizePath(db.IOConnectionInfo.Path) == wanted).ToList();
        }

        private static IOConnectionInfo NonEmpty(IOConnectionInfo ioc) =>
            ioc == null || string.IsNullOrEmpty(ioc.Path) ? null : ioc;

        private KpResponse Resolve(KpRequest request, ClientProcess client, List<PwDatabase> databases) =>
            ResolveReferences(client, request.WorkingDirectory, request.Command, request.References, databases, null);

        /// <summary>
        /// Opens the picker for a new context (or a repick) without blocking KeePass, so the user
        /// can select entries in the main window; an existing context is resolved directly.
        /// Called on the pipe thread.
        /// </summary>
        private KpResponse HandleContext(KpRequest request, ClientProcess client)
        {
            if (!ContextStore.IsValidName(request.Context))
                return KpResponse.Failure("Context names are 1-64 letters, digits, '.', '-' or '_', starting with a letter or digit.");

            string invalidSlot = request.Slots.FirstOrDefault(s => !ContextStore.IsValidVariableName(s));
            if (invalidSlot != null)
                return KpResponse.Failure($"'{invalidSlot}' is not a valid environment variable name.");

            MainForm main = _host.MainWindow;
            SavedContext existing = _contexts.Find(request.Context);
            bool coversSlots = existing != null && request.Slots.All(slot =>
                existing.Variables.Any(v => string.Equals(v.Name, slot, StringComparison.OrdinalIgnoreCase)));
            SavedContext saved = !request.Repick && coversSlots ? existing : null;
            if (saved != null)
                return (KpResponse)main.Invoke(new Func<KpResponse>(() => ResolveContext(request, client, saved)));

            KpResponse result = null;
            using (var done = new ManualResetEvent(false))
            {
                main.Invoke(new Action(() =>
                {
                    KpResponse notReady = EnsureDatabaseOpen(request.DatabasePath, out _);
                    if (notReady != null)
                    {
                        result = notReady;
                        done.Set();
                        return;
                    }

                    ContextPickerDialog.Open(main, new ContextPickerRequest
                    {
                        ContextName = request.Context,
                        Client = client,
                        WorkingDirectory = request.WorkingDirectory,
                        Command = request.Command,
                        Slots = request.Slots,
                        Previous = existing,
                        MethodsFor = MethodsFor,
                        Complete = picked => CompletePick(request, client, picked),
                        Finished = response =>
                        {
                            result = response;
                            done.Set();
                        },
                    });
                }));
                done.WaitOne();
            }
            return result;
        }

        private KpResponse ResolveContext(KpRequest request, ClientProcess client, SavedContext context)
        {
            // Prefer whatever is unlocked; only fall back to the context's database file when
            // nothing is, since synced folders can show the same file under another drive letter.
            string databasePath = request.DatabasePath;
            if (databasePath == null && _host.MainWindow.DocumentManager.GetOpenDatabases().Count == 0 && System.IO.File.Exists(context.DatabasePath))
                databasePath = context.DatabasePath;

            KpResponse notReady = EnsureDatabaseOpen(databasePath, out List<PwDatabase> databases);
            if (notReady != null) return notReady;

            List<string> references = context.Variables.Select(v => v.Reference).ToList();
            KpResponse resolved = ResolveReferences(client, request.WorkingDirectory, request.Command, references, databases,
                $"A program wants the values of context \"{context.Name}\"");
            if (!resolved.Ok)
            {
                if (!resolved.Retry && resolved.Error.Contains("no such entry"))
                    resolved.Error += Environment.NewLine + "An entry of the context was deleted; run again with --repick to choose the entries anew.";
                return resolved;
            }

            Dictionary<string, string> values = resolved.Values.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
            var response = new KpResponse { Ok = true };
            foreach (ContextVariable variable in context.Variables)
            {
                response.Values.Add(new KpPair(variable.Name, values[variable.Reference]));
                response.Labels.Add(new KpPair(variable.Name, variable.Label));
            }
            return response;
        }

        /// <summary>
        /// Runs when the user clicks Share in the picker: verifies presence, saves the context and
        /// returns its values. Null keeps the picker open, e.g. when the Windows Hello prompt was
        /// dismissed.
        /// </summary>
        private KpResponse CompletePick(KpRequest request, ClientProcess client, PickedContext picked)
        {
            List<PwDatabase> databases = picked.Rows.Select(r => r.Database).Distinct().ToList();
            if (!Verify(new ApprovalResult { Choice = picked.Choice }, databases)) return null;

            var context = new SavedContext
            {
                Name = request.Context,
                DatabasePath = databases[0].IOConnectionInfo.Path,
                UpdatedUtc = DateTime.UtcNow,
            };
            var response = new KpResponse { Ok = true };
            foreach (PickedRow row in picked.Rows)
            {
                context.Variables.Add(new ContextVariable
                {
                    Name = row.VariableName,
                    Reference = SecretReference.ForUuid(row.Entry.Uuid.ToHexString(), row.Field).ToString(),
                    Label = row.Label,
                });
                response.Values.Add(new KpPair(row.VariableName, row.Entry.Strings.ReadSafe(row.Field)));
                response.Labels.Add(new KpPair(row.VariableName, row.Label));
                row.Entry.Touch(false);
            }
            _contexts.Save(context);

            if (picked.Remember)
            {
                string grantKey = GrantKey(client, request.WorkingDirectory, context.Variables.Select(v => v.Reference).Distinct(StringComparer.Ordinal));
                lock (_grants) _grants[grantKey] = DateTime.UtcNow + GrantLifetime;
            }
            return response;
        }

        private KpResponse ListContexts()
        {
            var response = new KpResponse { Ok = true };
            foreach (SavedContext context in _contexts.All())
            {
                response.Values.Add(new KpPair(context.Name, string.Join(", ", context.Variables.Select(v => v.Name))));
                foreach (ContextVariable variable in context.Variables)
                    response.Labels.Add(new KpPair(context.Name + "/" + variable.Name, variable.Label));
            }
            return response;
        }

        private KpResponse ResolveReferences(ClientProcess client, string workingDirectory, string command, IEnumerable<string> requested, List<PwDatabase> databases, string heading)
        {
            List<string> references = requested.Distinct(StringComparer.Ordinal).ToList();
            if (references.Count == 0) return new KpResponse { Ok = true };

            var resolved = new List<ResolvedReference>();
            var problems = new List<string>();
            foreach (string text in references)
            {
                if (!SecretReference.TryParse(text, out SecretReference reference, out string parseError))
                {
                    problems.Add(parseError);
                    continue;
                }
                if (EntryFinder.TryFind(databases, reference, out PwDatabase database, out PwEntry entry, out string findError))
                    resolved.Add(new ResolvedReference(text, reference, database, entry));
                else
                    problems.Add(findError);
            }
            if (problems.Count > 0)
                return KpResponse.Failure(string.Join(Environment.NewLine, problems));

            string grantKey = GrantKey(client, workingDirectory, references);
            if (!HasGrant(grantKey))
            {
                var approval = ApprovalDialog.Ask(new ApprovalRequest
                {
                    Heading = heading ?? (references.Count == 1
                        ? "A program wants to read 1 value from KeePass"
                        : $"A program wants to read {references.Count} values from KeePass"),
                    Client = client,
                    WorkingDirectory = workingDirectory,
                    Command = command,
                    DatabaseName = string.Join(", ", resolved.Select(r => DatabaseName(r.Database)).Distinct()),
                    Items = resolved.Select(r => DescribeEntry(r)).ToList(),
                    CanRemember = true,
                    Methods = MethodsFor(resolved.Select(r => r.Database)),
                });
                if (!Verify(approval, resolved.Select(r => r.Database)))
                    return KpResponse.Failure("Access was denied in KeePass.");
                if (approval.Remember)
                    lock (_grants) _grants[grantKey] = DateTime.UtcNow + GrantLifetime;
            }

            var response = new KpResponse { Ok = true };
            foreach (ResolvedReference item in resolved)
            {
                ProtectedString value = item.Entry.Strings.GetSafe(item.Reference.Field);
                response.Values.Add(new KpPair(item.Text, value.ReadString()));
                item.Entry.Touch(false);
            }
            return response;
        }

        private KpResponse Import(KpRequest request, ClientProcess client, List<PwDatabase> databases)
        {
            KpImport import = request.Import;
            if (import == null || import.Items.Count == 0) return KpResponse.Failure("Nothing to import.");

            PwDatabase active = _host.MainWindow.ActiveDatabase;
            PwDatabase database = databases.Contains(active) ? active : databases.Count == 1 ? databases[0] : null;
            if (database == null)
                return KpResponse.Failure("Several databases are unlocked. Select the target database in KeePass, or pass --database PATH.");

            string[] groupPath = (import.GroupPath ?? string.Empty)
                .Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => s.Length > 0)
                .ToArray();
            PwGroup existingGroup = EntryFinder.FindGroup(database, groupPath);

            var conflicts = import.Items
                .Where(item => existingGroup != null && EntryFinder.FindEntries(existingGroup, item.Key).Count > 0)
                .Select(item => item.Key)
                .ToList();
            if (conflicts.Count > 0 && import.OnConflict == KpConflict.Fail)
                return KpResponse.Failure(
                    $"Entries already exist in '{string.Join("/", groupPath)}': {string.Join(", ", conflicts)}. " +
                    "Use --on-conflict skip or --on-conflict overwrite.");

            string groupDisplay = groupPath.Length == 0 ? database.RootGroup.Name : string.Join(" / ", groupPath);
            var approval = ApprovalDialog.Ask(new ApprovalRequest
            {
                Heading = $"A program wants to add {import.Items.Count} values to KeePass",
                Client = client,
                WorkingDirectory = request.WorkingDirectory,
                Command = request.Command,
                DatabaseName = DatabaseName(database) + "  →  " + groupDisplay + (existingGroup == null ? "  (new group)" : string.Empty),
                Items = import.Items.Select(item => conflicts.Contains(item.Key)
                    ? $"{item.Key}  ({(import.OnConflict == KpConflict.Overwrite ? "replaces existing entry" : "already exists, skipped")})"
                    : item.Key).ToList(),
                CanRemember = false,
                Methods = MethodsFor(new[] { database }),
            });
            if (!Verify(approval, new[] { database }))
                return KpResponse.Failure("The import was denied in KeePass.");

            PwGroup group = groupPath.Length == 0 ? database.RootGroup : database.RootGroup.FindCreateSubTree(string.Join("/", groupPath), new[] { '/' }, true);
            var response = new KpResponse { Ok = true };
            string notes = $"Imported from {import.SourceFile} on {DateTime.Now:yyyy-MM-dd HH:mm} by kp.";

            foreach (KpPair item in import.Items)
            {
                List<PwEntry> existing = EntryFinder.FindEntries(group, item.Key);
                PwEntry entry;
                if (existing.Count > 0 && import.OnConflict == KpConflict.Skip)
                {
                    entry = existing[0];
                }
                else if (existing.Count > 0)
                {
                    entry = existing[0];
                    entry.CreateBackup(database);
                    entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(database.MemoryProtection.ProtectPassword, item.Value));
                    entry.Strings.Set(PwDefs.NotesField, new ProtectedString(database.MemoryProtection.ProtectNotes, notes));
                    entry.Touch(true, false);
                }
                else
                {
                    entry = new PwEntry(true, true);
                    entry.Strings.Set(PwDefs.TitleField, new ProtectedString(database.MemoryProtection.ProtectTitle, item.Key));
                    entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(database.MemoryProtection.ProtectPassword, item.Value));
                    entry.Strings.Set(PwDefs.NotesField, new ProtectedString(database.MemoryProtection.ProtectNotes, notes));
                    group.AddEntry(entry, true);
                }
                response.Values.Add(new KpPair(item.Key, SecretReference.ForEntry(groupPath, item.Key).ToString()));
            }

            database.Modified = true;
            _host.MainWindow.UpdateUI(false, null, true, group, true, null, true);
            _host.MainWindow.SaveDatabase(database, null);
            if (database.Modified)
                return KpResponse.Failure("The values were added in KeePass, but saving the database failed. Save it in KeePass, then run the import again with --on-conflict skip.");
            return response;
        }

        private IList<UnlockMethodKind> MethodsFor(IEnumerable<PwDatabase> databases) =>
            databases
                .SelectMany(db => _unlock.GetMethods(db.IOConnectionInfo.Path))
                .Select(m => m.Kind)
                .Where(kind => kind == UnlockMethodKind.WindowsHello ? WindowsHelloAuthenticator.IsAvailable : Fido2Authenticator.IsAvailable)
                .Distinct()
                .ToList();

        /// <summary>
        /// Runs the method the user picked against a database that has it set up; a plain
        /// "Allow" is only offered when none of the databases has any method.
        /// </summary>
        private bool Verify(ApprovalResult approval, IEnumerable<PwDatabase> databases)
        {
            if (approval.Choice == ApprovalChoice.Denied) return false;
            if (approval.Choice == ApprovalChoice.Allowed) return true;

            UnlockMethodKind kind = approval.Choice == ApprovalChoice.WindowsHello ? UnlockMethodKind.WindowsHello : UnlockMethodKind.Fido2;
            PwDatabase database = databases.FirstOrDefault(db => _unlock.GetMethods(db.IOConnectionInfo.Path).Any(m => m.Kind == kind));
            if (database == null) return false;

            IntPtr hwnd = _host.MainWindow.Handle;
            string path = database.IOConnectionInfo.Path;
            try
            {
                BackgroundCall.Run(() => _unlock.VerifyPresence(hwnd, path, kind));
                return true;
            }
            catch (UnlockCancelledException)
            {
                return false;
            }
        }

        private bool HasGrant(string key)
        {
            lock (_grants)
            {
                if (!_grants.TryGetValue(key, out DateTime expires)) return false;
                if (expires > DateTime.UtcNow) return true;
                _grants.Remove(key);
                return false;
            }
        }

        private static string GrantKey(ClientProcess client, string workingDirectory, IEnumerable<string> references) =>
            string.Join("\n", new[] { client.ImagePath ?? string.Empty, UnlockStore.NormalizePath(workingDirectory ?? string.Empty) }
                .Concat(references.OrderBy(r => r, StringComparer.Ordinal)));

        private static string DatabaseName(PwDatabase database) =>
            string.IsNullOrEmpty(database.Name) ? System.IO.Path.GetFileName(database.IOConnectionInfo.Path) : database.Name;

        private static string DescribeEntry(ResolvedReference item)
        {
            string path = item.Entry.ParentGroup?.GetFullPath(" / ", false);
            string title = item.Entry.Strings.ReadSafe(PwDefs.TitleField);
            string location = string.IsNullOrEmpty(path) ? title : path + " / " + title;
            return item.Reference.Field == SecretReference.DefaultField ? location : $"{location}  ({item.Reference.Field})";
        }

        private sealed class ResolvedReference
        {
            public ResolvedReference(string text, SecretReference reference, PwDatabase database, PwEntry entry)
            {
                Text = text;
                Reference = reference;
                Database = database;
                Entry = entry;
            }

            public string Text { get; }
            public SecretReference Reference { get; }
            public PwDatabase Database { get; }
            public PwEntry Entry { get; }
        }
    }
}
