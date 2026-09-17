extern alias kp;

using System.Collections.Generic;
using System.Linq;
using kp::KeePassFido2.Kp;
using Xunit;

namespace KeePassFido2.Tests
{
    public class DotEnvFileTests
    {
        private static Dictionary<string, string> Values(string text) =>
            DotEnvFile.Parse(".env", text).Assignments.ToDictionary(a => a.Key, a => a.Value);

        [Fact]
        public void ParsesCommonForms()
        {
            var values = Values(
                "# comment\n" +
                "PLAIN=abc\n" +
                "export EXPORTED=1\n" +
                "  SPACED = value with spaces  \n" +
                "INLINE=abc # trailing comment\n" +
                "HASH=abc#not-a-comment\n" +
                "SINGLE='raw \\n $x'\n" +
                "DOUBLE=\"line1\\nline2 \\\"q\\\"\"\n" +
                "EMPTY=\n" +
                "not a variable\n");

            Assert.Equal("abc", values["PLAIN"]);
            Assert.Equal("1", values["EXPORTED"]);
            Assert.Equal("value with spaces", values["SPACED"]);
            Assert.Equal("abc", values["INLINE"]);
            Assert.Equal("abc#not-a-comment", values["HASH"]);
            Assert.Equal("raw \\n $x", values["SINGLE"]);
            Assert.Equal("line1\nline2 \"q\"", values["DOUBLE"]);
            Assert.Equal("", values["EMPTY"]);
            Assert.Equal(8, values.Count);
        }

        [Fact]
        public void ParsesMultilineQuotedValues()
        {
            var file = DotEnvFile.Parse(".env", "KEY=\"-----BEGIN KEY-----\nabc\n-----END KEY-----\"\r\nNEXT=1\r\n");

            Assert.Equal("-----BEGIN KEY-----\nabc\n-----END KEY-----", file.Assignments[0].Value);
            Assert.Equal("NEXT", file.Assignments[1].Key);
            Assert.Equal(4, file.Assignments[1].Line);
        }

        [Fact]
        public void ReplacesValuesAndKeepsEverythingElse()
        {
            const string text = "# Stripe\r\nSTRIPE_KEY=\"sk_test_123\" # live soon\r\nPORT=3000\r\nexport TOKEN='abc'\r\n";
            var file = DotEnvFile.Parse(".env", text);
            var replacements = file.Assignments
                .Where(a => a.Key != "PORT")
                .ToDictionary(a => a, a => "kp://Work/" + a.Key);

            Assert.Equal(
                "# Stripe\r\nSTRIPE_KEY=kp://Work/STRIPE_KEY # live soon\r\nPORT=3000\r\nexport TOKEN=kp://Work/TOKEN\r\n",
                file.WithValues(replacements));
        }
    }
}
