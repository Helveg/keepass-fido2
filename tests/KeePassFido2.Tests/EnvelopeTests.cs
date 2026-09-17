using System.Security.Cryptography;
using System.Text;
using KeePassFido2.Crypto;
using Xunit;

namespace KeePassFido2.Tests
{
    public class EnvelopeTests
    {
        private static readonly byte[] Key = Envelope.RandomBytes(32);
        private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("master key snapshot");

        [Fact]
        public void RoundTrips()
        {
            byte[] box = Envelope.Seal(Key, Plaintext, "ctx");
            Assert.Equal(Plaintext, Envelope.Open(Key, box, "ctx"));
        }

        [Fact]
        public void UsesFreshIvPerSeal()
        {
            Assert.NotEqual(Envelope.Seal(Key, Plaintext, "ctx"), Envelope.Seal(Key, Plaintext, "ctx"));
        }

        [Fact]
        public void RejectsTamperedCiphertext()
        {
            byte[] box = Envelope.Seal(Key, Plaintext, "ctx");
            box[20] ^= 1;
            Assert.Throws<CryptographicException>(() => Envelope.Open(Key, box, "ctx"));
        }

        [Fact]
        public void RejectsOtherContext()
        {
            byte[] box = Envelope.Seal(Key, Plaintext, "record-a");
            Assert.Throws<CryptographicException>(() => Envelope.Open(Key, box, "record-b"));
        }

        [Fact]
        public void RejectsOtherKey()
        {
            byte[] box = Envelope.Seal(Key, Plaintext, "ctx");
            Assert.Throws<CryptographicException>(() => Envelope.Open(Envelope.RandomBytes(32), box, "ctx"));
        }
    }
}
