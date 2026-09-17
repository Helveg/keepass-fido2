using System;
using System.IO;
using KeePassFido2.Storage;
using KeePassFido2.Unlock;
using Xunit;

namespace KeePassFido2.Tests
{
    public class UnlockServiceTests : IDisposable
    {
        private const string DatabasePath = @"C:\vaults\team.kdbx";
        private readonly string _file = Path.Combine(Path.GetTempPath(), "keepass-fido2-service-" + Guid.NewGuid().ToString("N") + ".xml");
        private readonly UnlockStore _store;
        private readonly UnlockService _service;

        public UnlockServiceTests()
        {
            _store = new UnlockStore(_file);
            var document = new StoreDocument();
            document.Databases.Add(new DatabaseRecord
            {
                Id = "r1",
                Path = DatabasePath,
                Payload = new byte[] { 1 },
                Methods =
                {
                    new UnlockMethod { Id = "hello", Kind = UnlockMethodKind.WindowsHello, Label = "Windows Hello" },
                    new UnlockMethod { Id = "key1", Kind = UnlockMethodKind.Fido2, Label = "Security key 1" },
                },
            });
            _store.Save(document);
            _service = new UnlockService(_store);
        }

        public void Dispose()
        {
            if (File.Exists(_file)) File.Delete(_file);
        }

        [Fact]
        public void RemovesOneMethod()
        {
            _service.RemoveMethod(DatabasePath, "key1");

            var methods = _service.GetMethods(DatabasePath);
            Assert.Single(methods);
            Assert.Equal("hello", methods[0].Id);
        }

        [Fact]
        public void RemovingTheLastMethodDeletesTheRecord()
        {
            _service.RemoveMethod(DatabasePath, "key1");
            _service.RemoveMethod(DatabasePath, "hello");

            Assert.Empty(_store.Load().Databases);
        }

        [Fact]
        public void IgnoresUnknownMethod()
        {
            _service.RemoveMethod(DatabasePath, "nope");
            Assert.Equal(2, _service.GetMethods(DatabasePath).Count);
        }

        [Fact]
        public void RenamesAndTrims()
        {
            _service.RenameMethod(DatabasePath, "key1", "  Desk key  ");
            Assert.Equal("Desk key", _service.GetMethods(DatabasePath)[1].Label);
        }

        [Fact]
        public void IgnoresBlankRename()
        {
            _service.RenameMethod(DatabasePath, "key1", "   ");
            Assert.Equal("Security key 1", _service.GetMethods(DatabasePath)[1].Label);
        }
    }
}
