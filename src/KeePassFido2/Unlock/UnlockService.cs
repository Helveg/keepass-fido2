using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using KeePassFido2.Crypto;
using KeePassFido2.Storage;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Security;

namespace KeePassFido2.Unlock
{
    /// <summary>
    /// Enrollment and unlock logic, independent of KeePass's UI.
    /// </summary>
    /// <remarks>
    /// Data keys are kept in memory per database path in three states:
    /// <list type="bullet">
    /// <item><b>injected</b>: a key was handed to KeePass's key prompt and the database has not opened yet.</item>
    /// <item><b>session</b>: the database is open and its data key is known, so methods can be added without a prompt.</item>
    /// <item><b>stale</b>: KeePass re-prompted after an injected key, i.e. the master key changed. The next
    /// successful open with a typed key re-encrypts the snapshot, which repairs every method at once.</item>
    /// </list>
    /// </remarks>
    internal sealed class UnlockService
    {
        private readonly UnlockStore _store;
        private readonly Dictionary<string, PendingUnlock> _injected = new Dictionary<string, PendingUnlock>();
        private readonly Dictionary<string, ProtectedBinary> _session = new Dictionary<string, ProtectedBinary>();
        private readonly Dictionary<string, PendingUnlock> _stale = new Dictionary<string, PendingUnlock>();

        public UnlockService(UnlockStore store)
        {
            _store = store;
        }

        public DatabaseRecord FindRecord(string databasePath) =>
            UnlockStore.Find(_store.Load(), databasePath, out _);

        /// <summary>
        /// Called whenever KeePass shows its key prompt for a database with a record. Returns
        /// false when a key injected for this path was just rejected.
        /// </summary>
        public bool OnKeyPrompt(string databasePath)
        {
            string path = UnlockStore.NormalizePath(databasePath);
            if (_injected.TryGetValue(path, out PendingUnlock rejected))
            {
                _injected.Remove(path);
                _stale[path] = rejected;
            }
            return !_stale.ContainsKey(path);
        }

        public bool IsStale(string databasePath) => _stale.ContainsKey(UnlockStore.NormalizePath(databasePath));

        public CompositeKey UnlockWithWindowsHello(IntPtr hwnd, string databasePath)
        {
            DatabaseRecord record = RequireRecord(databasePath, out bool exactMatch);
            UnlockMethod method = record.Methods.FirstOrDefault(m => m.Kind == UnlockMethodKind.WindowsHello)
                ?? throw new UnlockFailedException("Windows Hello is not set up for this database.");

            byte[] dataKey = WindowsHelloAuthenticator.Unprotect(hwnd, method.WrappedKey, "Unlock " + DisplayName(databasePath));
            return Inject(databasePath, record, exactMatch, dataKey);
        }

        public CompositeKey UnlockWithSecurityKey(IntPtr hwnd, string databasePath)
        {
            DatabaseRecord record = RequireRecord(databasePath, out bool exactMatch);
            if (!record.Methods.Any(m => m.Kind == UnlockMethodKind.Fido2))
                throw new UnlockFailedException("No security key is set up for this database.");

            byte[] dataKey = ReleaseWithSecurityKey(hwnd, record);
            return Inject(databasePath, record, exactMatch, dataKey);
        }

        /// <summary>
        /// Lets whichever enrolled security key is presented release the record's data key.
        /// </summary>
        /// <remarks>
        /// A key's hmac-secret differs with and without PIN verification, so the secret has to be
        /// fetched in the mode the key was enrolled with. When any touch-only key is enrolled the
        /// first request does not demand a PIN; if a PIN-enrolled key answers it without
        /// verification, a second request with PIN follows for that key only.
        /// </remarks>
        private static byte[] ReleaseWithSecurityKey(IntPtr hwnd, DatabaseRecord record)
        {
            List<UnlockMethod> methods = record.Methods.Where(m => m.Kind == UnlockMethodKind.Fido2).ToList();
            bool anyTouchOnly = methods.Any(m => !m.RequiresPin);

            Fido2Secret secret = Fido2Authenticator.GetSecret(hwnd, methods.Select(m => m.CredentialId).ToList(), record.Fido2Salt, requirePin: !anyTouchOnly);
            UnlockMethod method = methods.FirstOrDefault(m => m.CredentialId.SequenceEqual(secret.CredentialId))
                ?? throw new UnlockFailedException("The security key answered with a credential this database does not know.");

            if (method.RequiresPin && !secret.UserVerified)
            {
                Array.Clear(secret.Secret, 0, secret.Secret.Length);
                secret = Fido2Authenticator.GetSecret(hwnd, new[] { method.CredentialId }, record.Fido2Salt, requirePin: true);
                if (!secret.UserVerified)
                    throw new UnlockFailedException("This security key must verify its PIN to unlock the database.");
            }
            else if (!method.RequiresPin && secret.UserVerified)
            {
                // Windows asks for the PIN whenever the key has one; the touch-only secret is out of reach.
                try
                {
                    return UnwrapWithFido2Secret(record, method, secret.Secret);
                }
                catch (UnlockFailedException)
                {
                    throw new UnlockFailedException(
                        "This security key was added for touch-only unlock, but it now requires its PIN. Remove it and add it again.");
                }
            }

            return UnwrapWithFido2Secret(record, method, secret.Secret);
        }

        /// <summary>
        /// Proves the user is present with a method set up for this database: the method has to
        /// release the data key, and the data key has to authenticate the stored snapshot.
        /// </summary>
        public void VerifyPresence(IntPtr hwnd, string databasePath, UnlockMethodKind kind)
        {
            DatabaseRecord record = FindExactRecord(_store.Load(), databasePath)
                ?? throw new UnlockFailedException("No unlock methods are set up for this database.");

            byte[] dataKey;
            if (kind == UnlockMethodKind.WindowsHello)
            {
                UnlockMethod hello = record.Methods.FirstOrDefault(m => m.Kind == UnlockMethodKind.WindowsHello)
                    ?? throw new UnlockFailedException("Windows Hello is not set up for this database.");
                dataKey = WindowsHelloAuthenticator.Unprotect(hwnd, hello.WrappedKey, "Allow access to " + DisplayName(databasePath));
            }
            else
            {
                dataKey = ReleaseWithSecurityKey(hwnd, record);
            }

            try
            {
                byte[] snapshot = Envelope.Open(dataKey, record.Payload, PayloadContext(record));
                Array.Clear(snapshot, 0, snapshot.Length);
            }
            catch (CryptographicException)
            {
                throw new UnlockFailedException("The stored unlock data for this database is damaged.");
            }
            finally
            {
                Array.Clear(dataKey, 0, dataKey.Length);
            }
        }

        /// <summary>Called by KeePass's FileOpened event.</summary>
        public void OnDatabaseOpened(PwDatabase database)
        {
            string databasePath = database.IOConnectionInfo.Path;
            string path = UnlockStore.NormalizePath(databasePath);

            if (_injected.TryGetValue(path, out PendingUnlock injected))
            {
                _injected.Remove(path);
                if (!injected.ExactMatch)
                    UpdateRecord(injected.RecordId, record => record.Path = databasePath);
                _session[path] = injected.DataKey;
                return;
            }

            if (_stale.TryGetValue(path, out PendingUnlock stale))
            {
                _stale.Remove(path);
                // A key matched only by file name belongs to another database; never overwrite it.
                if (!stale.ExactMatch) return;

                byte[] dataKey = stale.DataKey.ReadData();
                try
                {
                    UpdateRecord(stale.RecordId, record =>
                        record.Payload = Envelope.Seal(dataKey, MasterKeySnapshot.Capture(database.MasterKey), PayloadContext(record)));
                }
                finally
                {
                    Array.Clear(dataKey, 0, dataKey.Length);
                }
                _session[path] = stale.DataKey;
            }
        }

        public void OnDatabaseClosed(string databasePath)
        {
            string path = UnlockStore.NormalizePath(databasePath);
            _session.Remove(path);
            _injected.Remove(path);
        }

        public void AddWindowsHello(IntPtr hwnd, PwDatabase database)
        {
            WithDataKey(hwnd, database, (document, record, dataKey) =>
            {
                byte[] wrapped = WindowsHelloAuthenticator.Protect(hwnd, dataKey);
                record.Methods.RemoveAll(m => m.Kind == UnlockMethodKind.WindowsHello);
                record.Methods.Add(new UnlockMethod
                {
                    Id = Guid.NewGuid().ToString("N"),
                    Kind = UnlockMethodKind.WindowsHello,
                    Label = "Windows Hello",
                    CreatedUtc = DateTime.UtcNow,
                    WrappedKey = wrapped,
                });
            });
        }

        /// <summary>Enrolls a security key and returns the method as stored.</summary>
        /// <param name="requirePin">
        /// Requested mode. The stored <see cref="UnlockMethod.RequiresPin"/> reflects what the key
        /// actually did, which is PIN + touch whenever Windows insists on the PIN.
        /// </param>
        public UnlockMethod AddSecurityKey(IntPtr hwnd, PwDatabase database, bool requirePin)
        {
            string userName = "KeePass: " + DisplayName(database.IOConnectionInfo.Path);
            UnlockMethod added = null;
            WithDataKey(hwnd, database, (document, record, dataKey) =>
            {
                byte[] credentialId = Fido2Authenticator.CreateCredential(hwnd, userName);
                Fido2Secret secret = Fido2Authenticator.GetSecret(hwnd, new[] { credentialId }, record.Fido2Salt, requirePin);
                if (requirePin && !secret.UserVerified)
                    throw new UnlockFailedException("The security key did not verify its PIN. Set a PIN on the key and try again.");

                var method = new UnlockMethod
                {
                    Id = Guid.NewGuid().ToString("N"),
                    Kind = UnlockMethodKind.Fido2,
                    Label = $"Security key {record.Methods.Count(m => m.Kind == UnlockMethodKind.Fido2) + 1}",
                    CreatedUtc = DateTime.UtcNow,
                    CredentialId = credentialId,
                    RequiresPin = secret.UserVerified,
                };
                added = method;
                byte[] wrapKey = Envelope.DeriveKey(secret.Secret, Protocol.Fido2WrapKeyLabel);
                try
                {
                    method.WrappedKey = Envelope.Seal(wrapKey, dataKey, WrapContext(record, method));
                }
                finally
                {
                    Array.Clear(wrapKey, 0, wrapKey.Length);
                    Array.Clear(secret.Secret, 0, secret.Secret.Length);
                }
                record.Methods.Add(method);
            });
            return added;
        }

        /// <summary>
        /// Removes one method. The last method takes the whole record with it, including the
        /// encrypted snapshot.
        /// </summary>
        /// <remarks>
        /// This does not revoke a lost key against an older copy of the store, which still holds
        /// a wrapped data key for it; changing the database's master key does.
        /// </remarks>
        public void RemoveMethod(string databasePath, string methodId)
        {
            StoreDocument document = _store.Load();
            DatabaseRecord record = FindExactRecord(document, databasePath);
            if (record == null || record.Methods.RemoveAll(m => m.Id == methodId) == 0) return;

            if (record.Methods.Count == 0)
            {
                document.Databases.Remove(record);
                OnDatabaseClosed(databasePath);
                _stale.Remove(UnlockStore.NormalizePath(databasePath));
            }
            _store.Save(document);
        }

        public void RenameMethod(string databasePath, string methodId, string label)
        {
            if (string.IsNullOrWhiteSpace(label)) return;
            StoreDocument document = _store.Load();
            UnlockMethod method = FindExactRecord(document, databasePath)?.Methods.FirstOrDefault(m => m.Id == methodId);
            if (method == null) return;
            method.Label = label.Trim();
            _store.Save(document);
        }

        public IList<UnlockMethod> GetMethods(string databasePath) =>
            FindExactRecord(_store.Load(), databasePath)?.Methods ?? new List<UnlockMethod>();

        private CompositeKey Inject(string databasePath, DatabaseRecord record, bool exactMatch, byte[] dataKey)
        {
            try
            {
                byte[] snapshot = Envelope.Open(dataKey, record.Payload, PayloadContext(record));
                CompositeKey compositeKey = MasterKeySnapshot.Restore(snapshot);
                Array.Clear(snapshot, 0, snapshot.Length);

                _injected[UnlockStore.NormalizePath(databasePath)] =
                    new PendingUnlock(record.Id, exactMatch, new ProtectedBinary(true, dataKey));
                return compositeKey;
            }
            catch (CryptographicException ex)
            {
                throw new UnlockFailedException("The stored unlock data for this database is damaged: " + ex.Message);
            }
            finally
            {
                Array.Clear(dataKey, 0, dataKey.Length);
            }
        }

        /// <summary>
        /// Runs <paramref name="change"/> with the database's data key, creating the record if
        /// needed, then saves. The snapshot is refreshed from the open database, whose master key
        /// is authoritative.
        /// </summary>
        private void WithDataKey(IntPtr hwnd, PwDatabase database, Action<StoreDocument, DatabaseRecord, byte[]> change)
        {
            if (database == null || !database.IsOpen)
                throw new UnlockFailedException("Open the database first.");

            string databasePath = database.IOConnectionInfo.Path;
            string path = UnlockStore.NormalizePath(databasePath);
            StoreDocument document = _store.Load();
            DatabaseRecord record = FindExactRecord(document, databasePath);

            byte[] dataKey;
            if (record == null)
            {
                record = new DatabaseRecord
                {
                    Id = Guid.NewGuid().ToString("N"),
                    Path = databasePath,
                    CreatedUtc = DateTime.UtcNow,
                    Fido2Salt = Envelope.RandomBytes(32),
                };
                document.Databases.Add(record);
                dataKey = Envelope.RandomBytes(32);
            }
            else if (_session.TryGetValue(path, out ProtectedBinary known))
            {
                dataKey = known.ReadData();
            }
            else
            {
                dataKey = RecoverDataKey(hwnd, record, databasePath);
            }

            try
            {
                record.Payload = Envelope.Seal(dataKey, MasterKeySnapshot.Capture(database.MasterKey), PayloadContext(record));
                change(document, record, dataKey);
                _store.Save(document);
                _session[path] = new ProtectedBinary(true, dataKey);
                _stale.Remove(path);
            }
            finally
            {
                Array.Clear(dataKey, 0, dataKey.Length);
            }
        }

        /// <summary>
        /// The database was opened with a typed master key but already has unlock methods: one
        /// of them has to release the data key so the new method shares it.
        /// </summary>
        private static byte[] RecoverDataKey(IntPtr hwnd, DatabaseRecord record, string databasePath)
        {
            UnlockMethod hello = record.Methods.FirstOrDefault(m => m.Kind == UnlockMethodKind.WindowsHello);
            if (hello != null)
                return WindowsHelloAuthenticator.Unprotect(hwnd, hello.WrappedKey, "Confirm with Windows Hello to add an unlock method to " + DisplayName(databasePath));

            if (!record.Methods.Any(m => m.Kind == UnlockMethodKind.Fido2))
                return Envelope.RandomBytes(32);

            return ReleaseWithSecurityKey(hwnd, record);
        }

        private static byte[] UnwrapWithFido2Secret(DatabaseRecord record, UnlockMethod method, byte[] secret)
        {
            byte[] wrapKey = Envelope.DeriveKey(secret, Protocol.Fido2WrapKeyLabel);
            try
            {
                return Envelope.Open(wrapKey, method.WrappedKey, WrapContext(record, method));
            }
            catch (CryptographicException)
            {
                throw new UnlockFailedException("The security key's unlock data for this database is damaged.");
            }
            finally
            {
                Array.Clear(wrapKey, 0, wrapKey.Length);
                Array.Clear(secret, 0, secret.Length);
            }
        }

        private DatabaseRecord RequireRecord(string databasePath, out bool exactMatch) =>
            UnlockStore.Find(_store.Load(), databasePath, out exactMatch)
            ?? throw new UnlockFailedException("No unlock methods are set up for this database.");

        private static DatabaseRecord FindExactRecord(StoreDocument document, string databasePath)
        {
            DatabaseRecord record = UnlockStore.Find(document, databasePath, out bool exactMatch);
            return exactMatch ? record : null;
        }

        private void UpdateRecord(string recordId, Action<DatabaseRecord> change)
        {
            StoreDocument document = _store.Load();
            DatabaseRecord record = document.Databases.FirstOrDefault(r => r.Id == recordId);
            if (record == null) return;
            change(record);
            _store.Save(document);
        }

        private static string PayloadContext(DatabaseRecord record) => Protocol.PayloadContext + "|" + record.Id;

        private static string WrapContext(DatabaseRecord record, UnlockMethod method) =>
            Protocol.WrapContext + "|" + record.Id + "|" + method.Id;

        private static string DisplayName(string databasePath)
        {
            try
            {
                return System.IO.Path.GetFileName(databasePath);
            }
            catch (ArgumentException)
            {
                return databasePath;
            }
        }

        private sealed class PendingUnlock
        {
            public PendingUnlock(string recordId, bool exactMatch, ProtectedBinary dataKey)
            {
                RecordId = recordId;
                ExactMatch = exactMatch;
                DataKey = dataKey;
            }

            public string RecordId { get; }
            public bool ExactMatch { get; }
            public ProtectedBinary DataKey { get; }
        }
    }
}
