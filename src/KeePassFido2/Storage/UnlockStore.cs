using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Serialization;

namespace KeePassFido2.Storage
{
    [XmlRoot("KeePassFido2")]
    public sealed class StoreDocument
    {
        [XmlAttribute("version")]
        public int Version { get; set; } = Protocol.StoreVersion;

        [XmlElement("Database")]
        public List<DatabaseRecord> Databases { get; set; } = new List<DatabaseRecord>();
    }

    /// <summary>
    /// Everything needed to unlock one database. The master key snapshot is encrypted under a
    /// random data key; each unlock method holds its own wrapped copy of that data key, so
    /// methods can be added or removed without touching the others.
    /// </summary>
    public sealed class DatabaseRecord
    {
        public string Id { get; set; }

        /// <summary>Database path as KeePass reported it when the record was last updated.</summary>
        public string Path { get; set; }

        public DateTime CreatedUtc { get; set; }

        /// <summary>Envelope(data key, master key snapshot).</summary>
        public byte[] Payload { get; set; }

        /// <summary>PRF input shared by this record's FIDO2 methods.</summary>
        public byte[] Fido2Salt { get; set; }

        [XmlElement("Method")]
        public List<UnlockMethod> Methods { get; set; } = new List<UnlockMethod>();
    }

    public enum UnlockMethodKind
    {
        WindowsHello,
        Fido2,
    }

    public sealed class UnlockMethod
    {
        public string Id { get; set; }
        public UnlockMethodKind Kind { get; set; }
        public string Label { get; set; }
        public DateTime CreatedUtc { get; set; }

        /// <summary>FIDO2 credential id; empty for Windows Hello.</summary>
        public byte[] CredentialId { get; set; }

        /// <summary>
        /// FIDO2 only: whether the wrapping key came from the key's PIN-verified hmac-secret.
        /// Records what the key reported at enrollment, not what was requested.
        /// </summary>
        public bool RequiresPin { get; set; } = true;

        /// <summary>
        /// The record's data key: RSA-encrypted by the Windows Hello key, or
        /// Envelope(wrap key derived from the FIDO2 hmac-secret, data key).
        /// </summary>
        public byte[] WrappedKey { get; set; }
    }

    internal sealed class UnlockStore
    {
        /// <summary>Overrides the store location, e.g. for a development copy of KeePass.</summary>
        public const string PathEnvironmentVariable = "KEEPASS_FIDO2_STORE";

        private static readonly XmlSerializer Serializer = new XmlSerializer(typeof(StoreDocument));

        public UnlockStore(string filePath)
        {
            FilePath = filePath;
        }

        public string FilePath { get; }

        /// <summary>
        /// Local (non-roaming) app data: Windows Hello keys are bound to this machine, so the
        /// store must not follow the user to another one.
        /// </summary>
        public static string DefaultFilePath
        {
            get
            {
                string overridden = Environment.GetEnvironmentVariable(PathEnvironmentVariable);
                if (!string.IsNullOrEmpty(overridden)) return overridden;
                return System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "keepass-fido2", "unlock.xml");
            }
        }

        public StoreDocument Load()
        {
            if (!File.Exists(FilePath)) return new StoreDocument();
            using (var stream = File.OpenRead(FilePath))
            {
                var document = (StoreDocument)Serializer.Deserialize(stream);
                if (document.Version != Protocol.StoreVersion)
                    throw new InvalidDataException($"Unlock store version {document.Version} is not supported.");
                return document;
            }
        }

        public void Save(StoreDocument document)
        {
            string directory = System.IO.Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            string temp = FilePath + ".tmp";
            using (var stream = File.Create(temp))
                Serializer.Serialize(stream, document);

            if (File.Exists(FilePath))
                File.Replace(temp, FilePath, null);
            else
                File.Move(temp, FilePath);
        }

        /// <summary>
        /// Finds the record for a database path. Falls back to a unique file-name match, because
        /// synced folders such as Google Drive can mount under a different drive letter.
        /// </summary>
        public static DatabaseRecord Find(StoreDocument document, string databasePath, out bool exactMatch)
        {
            exactMatch = false;
            if (string.IsNullOrEmpty(databasePath)) return null;

            string normalized = NormalizePath(databasePath);
            DatabaseRecord exact = document.Databases.FirstOrDefault(r => NormalizePath(r.Path) == normalized);
            if (exact != null)
            {
                exactMatch = true;
                return exact;
            }

            string fileName = SafeFileName(databasePath);
            var byName = document.Databases.Where(r => SafeFileName(r.Path) == fileName).ToList();
            return byName.Count == 1 ? byName[0] : null;
        }

        public static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;
            try
            {
                return System.IO.Path.GetFullPath(path).ToUpperInvariant();
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                return path.ToUpperInvariant();
            }
        }

        private static string SafeFileName(string path)
        {
            try
            {
                return System.IO.Path.GetFileName(path ?? string.Empty).ToUpperInvariant();
            }
            catch (ArgumentException)
            {
                return string.Empty;
            }
        }
    }
}
