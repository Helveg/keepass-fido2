using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using KeePassLib.Keys;
using KeePassLib.Security;

namespace KeePassFido2.Unlock
{
    /// <summary>
    /// Captures the derived key data of a database's composite key (password hash, key file
    /// data, Windows account key) and rebuilds an equivalent composite key from it. The
    /// master password text is never captured: KcpPassword.KeyData is already SHA-256 of it.
    /// </summary>
    internal static class MasterKeySnapshot
    {
        private const int FormatVersion = 1;

        public static byte[] Capture(CompositeKey compositeKey)
        {
            if (compositeKey == null) throw new ArgumentNullException(nameof(compositeKey));

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream, Encoding.UTF8))
            {
                var keys = new List<IUserKey>(compositeKey.UserKeys);
                writer.Write(FormatVersion);
                writer.Write(keys.Count);
                foreach (IUserKey key in keys)
                {
                    string source = key is StoredUserKey stored ? stored.SourceType : key.GetType().FullName;
                    byte[] data = key.KeyData.ReadData();
                    writer.Write(source);
                    writer.Write(data.Length);
                    writer.Write(data);
                    Array.Clear(data, 0, data.Length);
                }
                writer.Flush();
                return stream.ToArray();
            }
        }

        public static CompositeKey Restore(byte[] snapshot)
        {
            if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));

            using (var reader = new BinaryReader(new MemoryStream(snapshot, false), Encoding.UTF8))
            {
                if (reader.ReadInt32() != FormatVersion)
                    throw new InvalidDataException("Unsupported master key snapshot format.");

                var compositeKey = new CompositeKey();
                int count = reader.ReadInt32();
                for (int i = 0; i < count; i++)
                {
                    string source = reader.ReadString();
                    byte[] data = reader.ReadBytes(reader.ReadInt32());
                    compositeKey.AddUserKey(new StoredUserKey(source, data));
                    Array.Clear(data, 0, data.Length);
                }
                return compositeKey;
            }
        }
    }

    /// <summary>A user key whose key data was restored from a snapshot.</summary>
    internal sealed class StoredUserKey : IUserKey
    {
        public StoredUserKey(string sourceType, byte[] keyData)
        {
            SourceType = sourceType;
            KeyData = new ProtectedBinary(true, keyData);
        }

        /// <summary>Full type name of the original user key, e.g. KeePassLib.Keys.KcpPassword.</summary>
        public string SourceType { get; }

        public ProtectedBinary KeyData { get; }
    }
}
