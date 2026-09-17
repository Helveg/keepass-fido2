extern alias kp;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using kp::KeePassFido2.Kp;
using Xunit;

namespace KeePassFido2.Tests
{
    public class KpToolTests
    {
        [Theory]
        [InlineData("plain", "plain")]
        [InlineData("", "\"\"")]
        [InlineData("with space", "\"with space\"")]
        [InlineData("say \"hi\"", "\"say \\\"hi\\\"\"")]
        [InlineData(@"C:\dir with space\", "\"C:\\dir with space\\\\\"")]
        [InlineData(@"a\\""b", "\"a\\\\\\\\\\\"b\"")]
        public void QuotesArgumentsForWindows(string argument, string expected)
        {
            Assert.Equal(expected, CommandLauncher.QuoteArgument(argument));
        }

        [Fact]
        public void FormatsExportAndPowerShellSafely()
        {
            var variables = new Dictionary<string, string> { ["A"] = "it's $HOME" };

            Assert.Equal("export A='it'\\''s $HOME'\n", EnvFormatter.Format(variables, "export"));
            Assert.Equal("$env:A = 'it''s $HOME'\n", EnvFormatter.Format(variables, "powershell"));
            Assert.Equal("A=it's $HOME\0", EnvFormatter.Format(variables, "null"));
        }

        [Fact]
        public void CandidatesSkipEmptyAndReferencedValues()
        {
            var file = DotEnvFile.Parse(".env", "A=1\nB=\nC=kp://Work/C\nA=2\n");
            var candidates = ImportSelection.Candidates(file);

            Assert.Equal(new[] { "A" }, candidates.Select(c => c.Key));
            Assert.Equal("2", candidates[0].Value);
        }

        [Fact]
        public void MatchesGlobPatternsCaseInsensitively()
        {
            var file = DotEnvFile.Parse(".env", "STRIPE_KEY=1\nstripe_webhook=2\nPORT=3\nDB_PASSWORD=4\n");
            var selected = ImportSelection.ByPatterns(ImportSelection.Candidates(file), new[] { "STRIPE_*", "*password" });

            Assert.Equal(new[] { "STRIPE_KEY", "stripe_webhook", "DB_PASSWORD" }, selected.Select(s => s.Key));
        }

        [Fact]
        public void InteractiveDefaultPicksSecretLookingNames()
        {
            var candidates = ImportSelection.Candidates(DotEnvFile.Parse(".env", "PORT=3000\nJWT_SECRET=x\nAPI_TOKEN=y\n"));
            var selected = ImportSelection.Interactive(candidates, new StringReader("\n"), TextWriter.Null);

            Assert.Equal(new[] { "JWT_SECRET", "API_TOKEN" }, selected.Select(s => s.Key));
        }

        [Fact]
        public void InteractiveAcceptsRanges()
        {
            var candidates = ImportSelection.Candidates(DotEnvFile.Parse(".env", "A=1\nB=2\nC=3\nD=4\n"));
            var selected = ImportSelection.Interactive(candidates, new StringReader("bogus\n1,3-4\n"), TextWriter.Null);

            Assert.Equal(new[] { "A", "C", "D" }, selected.Select(s => s.Key));
        }
    }
}
