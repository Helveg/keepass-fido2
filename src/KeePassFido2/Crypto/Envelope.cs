using System;
using System.Security.Cryptography;
using System.Text;

namespace KeePassFido2.Crypto
{
    /// <summary>
    /// Authenticated encryption for .NET Framework 4.8, which has no AES-GCM:
    /// AES-256-CBC, then HMAC-SHA256 over version, IV, ciphertext and a caller-supplied context
    /// string. The context binds a blob to its purpose and record, so blobs cannot be swapped
    /// between records or between payload and wrap slots.
    /// </summary>
    /// <remarks>Layout: [version:1][iv:16][ciphertext][mac:32].</remarks>
    internal static class Envelope
    {
        private const byte FormatVersion = 1;
        private const int IvLength = 16;
        private const int MacLength = 32;

        public static byte[] Seal(byte[] key, byte[] plaintext, string context)
        {
            RequireKey(key);
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));

            byte[] encKey = DeriveKey(key, "enc");
            byte[] macKey = DeriveKey(key, "mac");
            try
            {
                byte[] iv = RandomBytes(IvLength);
                byte[] ciphertext;
                using (var aes = CreateAes(encKey, iv))
                using (var encryptor = aes.CreateEncryptor())
                    ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

                var box = new byte[1 + IvLength + ciphertext.Length + MacLength];
                box[0] = FormatVersion;
                Buffer.BlockCopy(iv, 0, box, 1, IvLength);
                Buffer.BlockCopy(ciphertext, 0, box, 1 + IvLength, ciphertext.Length);

                int macOffset = 1 + IvLength + ciphertext.Length;
                byte[] mac = ComputeMac(macKey, context, box, macOffset);
                Buffer.BlockCopy(mac, 0, box, macOffset, MacLength);
                return box;
            }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        public static byte[] Open(byte[] key, byte[] box, string context)
        {
            RequireKey(key);
            if (box == null || box.Length < 1 + IvLength + 16 + MacLength || box[0] != FormatVersion)
                throw new CryptographicException("Encrypted data is truncated or has an unsupported format.");

            byte[] encKey = DeriveKey(key, "enc");
            byte[] macKey = DeriveKey(key, "mac");
            try
            {
                int macOffset = box.Length - MacLength;
                byte[] expected = ComputeMac(macKey, context, box, macOffset);
                if (!FixedTimeEquals(expected, box, macOffset))
                    throw new CryptographicException("Encrypted data failed its integrity check.");

                var iv = new byte[IvLength];
                Buffer.BlockCopy(box, 1, iv, 0, IvLength);
                using (var aes = CreateAes(encKey, iv))
                using (var decryptor = aes.CreateDecryptor())
                    return decryptor.TransformFinalBlock(box, 1 + IvLength, macOffset - 1 - IvLength);
            }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        /// <summary>HMAC-SHA256(key, label): domain-separated 32-byte subkey.</summary>
        public static byte[] DeriveKey(byte[] key, string label)
        {
            using (var hmac = new HMACSHA256(key))
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(label));
        }

        public static byte[] RandomBytes(int count)
        {
            var bytes = new byte[count];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(bytes);
            return bytes;
        }

        private static void RequireKey(byte[] key)
        {
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        }

        private static Aes CreateAes(byte[] key, byte[] iv) =>
            new AesCryptoServiceProvider { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = 256, Key = key, IV = iv };

        private static byte[] ComputeMac(byte[] macKey, string context, byte[] data, int count)
        {
            byte[] contextBytes = Encoding.UTF8.GetBytes(context ?? string.Empty);
            byte[] contextLength = BitConverter.GetBytes(contextBytes.Length);
            using (var hmac = new HMACSHA256(macKey))
            {
                hmac.TransformBlock(contextLength, 0, contextLength.Length, null, 0);
                hmac.TransformBlock(contextBytes, 0, contextBytes.Length, null, 0);
                hmac.TransformFinalBlock(data, 0, count);
                return hmac.Hash;
            }
        }

        private static bool FixedTimeEquals(byte[] expected, byte[] data, int offset)
        {
            int diff = 0;
            for (int i = 0; i < MacLength; i++)
                diff |= expected[i] ^ data[offset + i];
            return diff == 0;
        }
    }
}
