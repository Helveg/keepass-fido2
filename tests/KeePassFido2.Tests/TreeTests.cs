extern alias kp;

using System.Collections.Generic;
using System.Linq;
using KeePassFido2.Agent;
using KeePassFido2.Ipc;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Xunit;
using KpTreeFormatter = kp::KeePassFido2.Kp.TreeFormatter;
using KpTreeNodeForKp = kp::KeePassFido2.Ipc.KpTreeNode;

namespace KeePassFido2.Tests
{
    public class TreeTests
    {
        [Fact]
        public void ListsNamesBelowAGroupAndNeverValues()
        {
            PwDatabase database = Sample(out PwGroup work);

            List<KpTreeNode> nodes = TreeLister.List(database, "sample", work, TreeLister.PathOf(database, work), 0, true, true);

            Assert.Equal(new[] { "Work/GitHub", "Work/athena/", "Work/athena/STRIPE_KEY", "Work/my project/" }, nodes.Select(Describe));
            Assert.Equal(new[] { "UserName", "Password", "Token" }, nodes[0].Fields);
            Assert.DoesNotContain(nodes.SelectMany(n => n.Fields.Append(n.Entry ?? string.Empty)), s => s.Contains("secret"));
        }

        [Fact]
        public void StopsAtTheDepthAndLeavesOutTheRecycleBinAndEntriesWhenAsked()
        {
            PwDatabase database = Sample(out _);

            List<KpTreeNode> nodes = TreeLister.List(database, "sample", database.RootGroup, new List<string>(), 1, false, false);

            Assert.Equal(new[] { "Work/" }, nodes.Select(Describe));
        }

        [Fact]
        public void PrintsATreeIndentedFromTheListedGroup()
        {
            var nodes = new List<KpTreeNodeForKp>
            {
                Node(new[] { "Work" }, "GitHub", "UserName", "Password"),
                Node(new[] { "Work", "athena" }, null),
                Node(new[] { "Work", "athena" }, "STRIPE_KEY"),
            };

            Assert.Equal("sample\n  GitHub  [UserName, Password]\n  athena/\n    STRIPE_KEY\n", KpTreeFormatter.Format(nodes, "tree"));
        }

        [Fact]
        public void PrintsReferencesThatKpRunAccepts()
        {
            var nodes = new List<KpTreeNodeForKp>
            {
                Node(new[] { "Work", "my project" }, null),
                Node(new[] { "Work", "my project" }, "API_KEY"),
                Node(new[] { "Work" }, "GitHub", "UserName", "Password"),
            };

            Assert.Equal(
                "kp://Work/my%20project/\nkp://Work/my%20project/API_KEY\nkp://Work/GitHub#UserName\nkp://Work/GitHub\n",
                KpTreeFormatter.Format(nodes, "references"));
        }

        private static string Describe(KpTreeNode node) =>
            string.Join("/", node.GroupPath) + "/" + (node.Entry ?? string.Empty);

        private static KpTreeNodeForKp Node(string[] groupPath, string entry, params string[] fields) =>
            new KpTreeNodeForKp { Database = "sample", GroupPath = groupPath.ToList(), Entry = entry, Fields = fields.ToList() };

        /// <summary>Root / Work / {GitHub, athena / STRIPE_KEY, my project}, plus a recycle bin holding a deleted group.</summary>
        private static PwDatabase Sample(out PwGroup work)
        {
            var database = new PwDatabase();
            database.New(new IOConnectionInfo(), new CompositeKey());

            work = new PwGroup(true, true, "Work", PwIcon.Folder);
            database.RootGroup.AddGroup(work, true);
            var athena = new PwGroup(true, true, "athena", PwIcon.Folder);
            work.AddGroup(athena, true);
            work.AddGroup(new PwGroup(true, true, "my project", PwIcon.Folder), true);

            var github = new PwEntry(true, true);
            github.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "GitHub"));
            github.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "octocat"));
            github.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "secret-password"));
            github.Strings.Set(PwDefs.UrlField, new ProtectedString(false, string.Empty));
            github.Strings.Set("Token", new ProtectedString(true, "secret-token"));
            work.AddEntry(github, true);

            var stripe = new PwEntry(true, true);
            stripe.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "STRIPE_KEY"));
            stripe.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "secret-stripe"));
            athena.AddEntry(stripe, true);

            var bin = new PwGroup(true, true, "Recycle Bin", PwIcon.TrashBin);
            database.RootGroup.AddGroup(bin, true);
            database.RecycleBinEnabled = true;
            database.RecycleBinUuid = bin.Uuid;
            bin.AddGroup(new PwGroup(true, true, "Deleted", PwIcon.Folder), true);
            return database;
        }
    }
}
