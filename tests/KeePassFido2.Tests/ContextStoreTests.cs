using System;
using System.Collections.Generic;
using System.IO;
using KeePassFido2.Storage;
using Xunit;

namespace KeePassFido2.Tests
{
    public class ContextStoreTests : IDisposable
    {
        private readonly string _file = Path.Combine(Path.GetTempPath(), "keepass-fido2-contexts-" + Guid.NewGuid().ToString("N") + ".xml");

        public void Dispose()
        {
            if (File.Exists(_file)) File.Delete(_file);
        }

        [Theory]
        [InlineData("Tablet account", "UserName", "TABLET_ACCOUNT_USERNAME")]
        [InlineData("  Wi-Fi (guest) ", "Password", "WI_FI_GUEST_PASSWORD")]
        [InlineData("2FA backup", "Notes", "KP_2FA_BACKUP_NOTES")]
        [InlineData("Café", "URL", "CAF_URL")]
        public void DerivesEnvironmentVariableNames(string title, string field, string expected)
        {
            Assert.Equal(expected, ContextStore.VariableName(title, field, new List<string>()));
        }

        [Fact]
        public void MakesVariableNamesUnique()
        {
            var taken = new List<string> { "LOGIN_PASSWORD", "LOGIN_PASSWORD_2" };
            Assert.Equal("LOGIN_PASSWORD_3", ContextStore.VariableName("Login", "Password", taken));
        }

        [Theory]
        [InlineData("adb_values", true)]
        [InlineData("tablet-login.v2", true)]
        [InlineData("-leading-dash", false)]
        [InlineData("has space", false)]
        [InlineData("", false)]
        public void ValidatesContextNames(string name, bool valid)
        {
            Assert.Equal(valid, ContextStore.IsValidName(name));
        }

        [Fact]
        public void SavesReplacesAndRemovesCaseInsensitively()
        {
            var store = new ContextStore(_file);
            store.Save(new SavedContext { Name = "Tablet", Variables = { new ContextVariable { Name = "A", Reference = "kp://uuid/00000000000000000000000000000001" } } });
            store.Save(new SavedContext { Name = "tablet", Variables = { new ContextVariable { Name = "B", Reference = "kp://uuid/00000000000000000000000000000002" } } });

            SavedContext found = store.Find("TABLET");
            Assert.Equal("B", found.Variables[0].Name);
            Assert.Single(store.All());

            Assert.True(store.Remove("TaBlEt"));
            Assert.Null(store.Find("tablet"));
            Assert.False(store.Remove("tablet"));
        }
    }
}
