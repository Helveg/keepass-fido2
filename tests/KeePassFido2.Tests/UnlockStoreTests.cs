using System;
using System.IO;
using KeePassFido2.Storage;
using Xunit;

namespace KeePassFido2.Tests
{
    public class UnlockStoreTests : IDisposable
    {
        private readonly string _file = Path.Combine(Path.GetTempPath(), "keepass-fido2-store-" + Guid.NewGuid().ToString("N") + ".xml");

        public void Dispose()
        {
            if (File.Exists(_file)) File.Delete(_file);
        }

        [Fact]
        public void MissingFileLoadsEmpty()
        {
            Assert.Empty(new UnlockStore(_file).Load().Databases);
        }

        [Fact]
        public void SavesAndLoads()
        {
            var store = new UnlockStore(_file);
            var document = new StoreDocument();
            document.Databases.Add(new DatabaseRecord
            {
                Id = "r1",
                Path = @"G:\Shared drives\Team\vault.kdbx",
                Payload = new byte[] { 1, 2, 3 },
                Fido2Salt = new byte[32],
                Methods = { new UnlockMethod { Id = "m1", Kind = UnlockMethodKind.Fido2, CredentialId = new byte[] { 9 }, WrappedKey = new byte[] { 4 } } },
            });
            store.Save(document);
            store.Save(document);

            DatabaseRecord loaded = store.Load().Databases[0];
            Assert.Equal(new byte[] { 1, 2, 3 }, loaded.Payload);
            Assert.Equal(UnlockMethodKind.Fido2, loaded.Methods[0].Kind);
            Assert.Equal(new byte[] { 9 }, loaded.Methods[0].CredentialId);
        }

        [Fact]
        public void MethodsWithoutPinFlagRequirePin()
        {
            File.WriteAllText(_file,
                "<KeePassFido2 version=\"1\"><Database><Id>r1</Id>" +
                "<Method><Id>m1</Id><Kind>Fido2</Kind></Method>" +
                "</Database></KeePassFido2>");

            Assert.True(new UnlockStore(_file).Load().Databases[0].Methods[0].RequiresPin);
        }

        [Fact]
        public void KeepsTouchOnlyFlag()
        {
            var store = new UnlockStore(_file);
            var document = new StoreDocument();
            document.Databases.Add(new DatabaseRecord { Id = "r1", Methods = { new UnlockMethod { Id = "m1", Kind = UnlockMethodKind.Fido2, RequiresPin = false } } });
            store.Save(document);

            Assert.False(store.Load().Databases[0].Methods[0].RequiresPin);
        }

        [Fact]
        public void FindsExactPathCaseInsensitively()
        {
            var document = DocumentWith(@"G:\Shared drives\Team\vault.kdbx");
            Assert.NotNull(UnlockStore.Find(document, @"g:\shared drives\team\VAULT.kdbx", out bool exact));
            Assert.True(exact);
        }

        [Fact]
        public void FallsBackToUniqueFileName()
        {
            var document = DocumentWith(@"G:\Shared drives\Team\vault.kdbx");
            Assert.NotNull(UnlockStore.Find(document, @"E:\Shared drives\Team\vault.kdbx", out bool exact));
            Assert.False(exact);
        }

        [Fact]
        public void IgnoresAmbiguousFileName()
        {
            var document = DocumentWith(@"G:\a\vault.kdbx", @"C:\Users\alice\Sync\vault.kdbx");
            Assert.Null(UnlockStore.Find(document, @"E:\b\vault.kdbx", out _));
        }

        private static StoreDocument DocumentWith(params string[] paths)
        {
            var document = new StoreDocument();
            foreach (string path in paths)
                document.Databases.Add(new DatabaseRecord { Id = Guid.NewGuid().ToString("N"), Path = path });
            return document;
        }
    }
}
