using System;
using System.IO;
using KeePassFido2.Unlock;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using Xunit;

namespace KeePassFido2.Tests
{
    public class MasterKeySnapshotTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "keepass-fido2-tests-" + Guid.NewGuid().ToString("N"));

        public MasterKeySnapshotTests()
        {
            Directory.CreateDirectory(_directory);
        }

        public void Dispose()
        {
            Directory.Delete(_directory, true);
        }

        [Fact]
        public void RestoredKeyOpensTheDatabase()
        {
            var original = new CompositeKey();
            original.AddUserKey(new KcpPassword("correct horse battery staple"));
            string path = CreateDatabase(original, "secret value");

            CompositeKey restored = MasterKeySnapshot.Restore(MasterKeySnapshot.Capture(original));

            var database = new PwDatabase();
            database.Open(IOConnectionInfo.FromPath(path), restored, null);
            try
            {
                PwEntry entry = database.RootGroup.GetEntries(true).GetAt(0);
                Assert.Equal("secret value", entry.Strings.ReadSafe(PwDefs.PasswordField));
            }
            finally
            {
                database.Close();
            }
        }

        [Fact]
        public void SnapshotDoesNotContainPasswordText()
        {
            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword("correct horse battery staple"));

            string snapshot = System.Text.Encoding.UTF8.GetString(MasterKeySnapshot.Capture(key));

            Assert.DoesNotContain("correct horse", snapshot);
        }

        [Fact]
        public void KeepsKeyOrderAndSourceTypes()
        {
            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword("pw"));
            key.AddUserKey(new StoredUserKey("KeePassLib.Keys.KcpKeyFile", new byte[32]));

            CompositeKey restored = MasterKeySnapshot.Restore(MasterKeySnapshot.Capture(key));

            var sources = new System.Collections.Generic.List<string>();
            foreach (IUserKey userKey in restored.UserKeys) sources.Add(((StoredUserKey)userKey).SourceType);
            Assert.Equal(new[] { typeof(KcpPassword).FullName, "KeePassLib.Keys.KcpKeyFile" }, sources);
        }

        private string CreateDatabase(CompositeKey key, string password)
        {
            string path = Path.Combine(_directory, "test.kdbx");
            var database = new PwDatabase();
            database.New(IOConnectionInfo.FromPath(path), key);
            var entry = new PwEntry(true, true);
            entry.Strings.Set(PwDefs.PasswordField, new KeePassLib.Security.ProtectedString(true, password));
            database.RootGroup.AddEntry(entry, true);
            database.Save(null);
            database.Close();
            return path;
        }
    }
}
