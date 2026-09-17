using KeePassFido2.References;
using Xunit;

namespace KeePassFido2.Tests
{
    public class SecretReferenceTests
    {
        [Fact]
        public void ParsesPathWithDefaultField()
        {
            Assert.True(SecretReference.TryParse("kp://Work/my-project/STRIPE_API_KEY", out SecretReference reference, out _));
            Assert.Equal(new[] { "Work", "my-project" }, reference.GroupPath);
            Assert.Equal("STRIPE_API_KEY", reference.EntryTitle);
            Assert.Equal("Password", reference.Field);
        }

        [Fact]
        public void ParsesFieldAndNormalizesStandardNames()
        {
            Assert.True(SecretReference.TryParse("kp://Entry#username", out SecretReference reference, out _));
            Assert.Empty(reference.GroupPath);
            Assert.Equal("UserName", reference.Field);

            Assert.True(SecretReference.TryParse("kp://Entry#Custom Field", out reference, out _));
            Assert.Equal("Custom Field", reference.Field);
        }

        [Fact]
        public void ParsesUuid()
        {
            Assert.True(SecretReference.TryParse("kp://uuid/0123456789ABCDEF0123456789abcdef#URL", out SecretReference reference, out _));
            Assert.Equal("0123456789abcdef0123456789abcdef", reference.EntryUuid);
            Assert.Equal("URL", reference.Field);
        }

        [Theory]
        [InlineData("kp://")]
        [InlineData("kp://Work//Entry")]
        [InlineData("kp://Entry#")]
        [InlineData("kp://uuid/1234")]
        [InlineData("https://example.com")]
        public void RejectsMalformed(string text)
        {
            Assert.False(SecretReference.TryParse(text, out _, out string error));
            Assert.NotNull(error);
        }

        [Fact]
        public void RoundTripsSpecialCharacters()
        {
            var reference = SecretReference.ForEntry(new[] { "Shared drives", "a/b" }, "API #1 100%", "User Name");
            string text = reference.ToString();

            Assert.Equal("kp://Shared%20drives/a%2Fb/API%20%231%20100%25#User%20Name", text);
            Assert.True(SecretReference.TryParse(text, out SecretReference parsed, out _));
            Assert.Equal(new[] { "Shared drives", "a/b" }, parsed.GroupPath);
            Assert.Equal("API #1 100%", parsed.EntryTitle);
            Assert.Equal("User Name", parsed.Field);
        }

        [Fact]
        public void OmitsDefaultField()
        {
            Assert.Equal("kp://Work/KEY", SecretReference.ForEntry(new[] { "Work" }, "KEY").ToString());
        }
    }
}
