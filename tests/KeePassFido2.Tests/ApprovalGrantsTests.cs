using System;
using KeePassFido2.Agent;
using Xunit;

namespace KeePassFido2.Tests
{
    public class ApprovalGrantsTests
    {
        private const string Kp = @"C:\Program Files\KeePass FIDO2\kp.exe";
        private const string Folder = @"C:\work\project";
        private const string Db = @"G:\Shared drives\Business\alexandria.kdbx";
        private const string OtherDb = @"C:\Users\me\personal.kdbx";

        private DateTime _now = new DateTime(2026, 10, 5, 12, 0, 0, DateTimeKind.Utc);

        private ApprovalGrants Grants() => new ApprovalGrants(TimeSpan.FromHours(8), () => _now);

        private static string[] Refs(params string[] r) => r;

        [Fact]
        public void NothingIsCoveredUntilRemembered()
        {
            Assert.False(Grants().Covers(Kp, Folder, Refs("kp://A/B"), new[] { Db }));
        }

        [Fact]
        public void NoneRemembersNothing()
        {
            var grants = Grants();
            grants.Remember(RememberScope.None, Kp, Folder, Refs("kp://A/B"), new[] { Db });
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://A/B"), new[] { Db }));
        }

        [Fact]
        public void TheseValuesCoverExactlyTheseValues()
        {
            var grants = Grants();
            grants.Remember(RememberScope.TheseValues, Kp, Folder, Refs("kp://A/B", "kp://A/C"), new[] { Db });

            Assert.True(grants.Covers(Kp, Folder, Refs("kp://A/C", "kp://A/B"), new[] { Db }));
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://A/B"), new[] { Db }));
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://A/D"), new[] { Db }));
        }

        [Fact]
        public void WholeDatabaseCoversAnyValueFromThatDatabase()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });

            Assert.True(grants.Covers(Kp, Folder, Refs("kp://A/B"), new[] { Db }));
            Assert.True(grants.Covers(Kp, Folder, Refs("kp://X/Y", "kp://Z/W"), new[] { Db }));
            Assert.True(grants.Covers(Kp, Folder, Refs("tree:Alexandria:0:True:False"), new[] { Db }));
        }

        [Fact]
        public void WholeDatabaseDoesNotCoverAnotherDatabase()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });

            Assert.False(grants.Covers(Kp, Folder, Refs("kp://P/Q"), new[] { OtherDb }));
            // Values from two databases need both.
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://A/B", "kp://P/Q"), new[] { Db, OtherDb }));
        }

        [Fact]
        public void NeitherCoversAnotherFolderOrProgram()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });
            grants.Remember(RememberScope.TheseValues, Kp, Folder, Refs("kp://A/B"), new[] { Db });

            Assert.False(grants.Covers(Kp, @"C:\work\other", Refs("kp://A/B"), new[] { Db }));
            Assert.False(grants.Covers(@"C:\Temp\kp.exe", Folder, Refs("kp://A/B"), new[] { Db }));
        }

        [Fact]
        public void FolderAndDatabasePathsCompareAsWindowsDoes()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });
            Assert.True(grants.Covers(Kp, @"c:\WORK\Project", Refs("kp://X/Y"), new[] { Db.ToLowerInvariant() }));
        }

        [Fact]
        public void GrantsEndAfterTheirLifetime()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });
            grants.Remember(RememberScope.TheseValues, Kp, Folder, Refs("kp://C/D"), new[] { OtherDb });

            _now = _now.AddHours(8).AddSeconds(-1);
            Assert.True(grants.Covers(Kp, Folder, Refs("kp://X/Y"), new[] { Db }));
            Assert.True(grants.Covers(Kp, Folder, Refs("kp://C/D"), new[] { OtherDb }));

            _now = _now.AddSeconds(2);
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://X/Y"), new[] { Db }));
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://C/D"), new[] { OtherDb }));
        }

        [Fact]
        public void ClearForgetsEverything()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });
            grants.Clear();
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://A/B"), new[] { Db }));
        }

        [Fact]
        public void NoDatabaseMeansNoWholeDatabaseCover()
        {
            var grants = Grants();
            grants.Remember(RememberScope.WholeDatabase, Kp, Folder, Refs("kp://A/B"), new[] { Db });
            Assert.False(grants.Covers(Kp, Folder, Refs("kp://A/B"), new string[0]));
        }
    }
}
