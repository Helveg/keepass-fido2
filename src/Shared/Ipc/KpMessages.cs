using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Principal;
using System.Text;

namespace KeePassFido2.Ipc
{
    /// <summary>
    /// Messages between kp.exe and the plugin over a per-user named pipe. Each connection carries
    /// one request and one response, each framed as a little-endian int32 length and UTF-8 JSON.
    /// </summary>
    internal static class KpPipe
    {
        public const int ProtocolVersion = 1;
        private const int MaxMessageBytes = 16 * 1024 * 1024;

        /// <summary>Per user, so two people signed in to one machine never reach each other's KeePass.</summary>
        public static string Name => "keepass-fido2-" + WindowsIdentity.GetCurrent().User.Value;

        public static void Write<T>(Stream stream, T message)
        {
            byte[] json;
            using (var buffer = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(T)).WriteObject(buffer, message);
                json = buffer.ToArray();
            }
            stream.Write(BitConverter.GetBytes(json.Length), 0, 4);
            stream.Write(json, 0, json.Length);
            stream.Flush();
            Array.Clear(json, 0, json.Length);
        }

        public static T Read<T>(Stream stream)
        {
            int length = BitConverter.ToInt32(ReadExactly(stream, 4), 0);
            if (length < 0 || length > MaxMessageBytes)
                throw new InvalidDataException($"Message of {length} bytes rejected.");
            byte[] json = ReadExactly(stream, length);
            try
            {
                using (var buffer = new MemoryStream(json, false))
                    return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(buffer);
            }
            finally
            {
                Array.Clear(json, 0, json.Length);
            }
        }

        private static byte[] ReadExactly(Stream stream, int count)
        {
            var bytes = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = stream.Read(bytes, read, count - read);
                if (n == 0) throw new EndOfStreamException("The connection closed before the message was complete.");
                read += n;
            }
            return bytes;
        }
    }

    internal static class KpRequestKind
    {
        public const string Ping = "ping";
        public const string Resolve = "resolve";
        public const string Import = "import";

        /// <summary>
        /// Values of a named context: environment variable names mapped to entry fields. When the
        /// context does not exist, lacks a requested slot, or Repick is set, the user assigns
        /// entries in KeePass first.
        /// </summary>
        public const string Context = "context";

        public const string ContextList = "context-list";
        public const string ContextRemove = "context-remove";
    }

    [DataContract]
    internal sealed class KpRequest
    {
        [DataMember] public int ProtocolVersion { get; set; } = KpPipe.ProtocolVersion;
        [DataMember] public string Kind { get; set; }

        /// <summary>Shown in the approval dialog; supplied by the client.</summary>
        [DataMember] public string WorkingDirectory { get; set; }

        /// <summary>Shown in the approval dialog; supplied by the client.</summary>
        [DataMember] public string Command { get; set; }

        /// <summary>
        /// Full path of the database to use. When it is not unlocked, KeePass asks to unlock it.
        /// Null means any unlocked database, or else the locked or last used one.
        /// </summary>
        [DataMember] public string DatabasePath { get; set; }

        [DataMember] public List<string> References { get; set; } = new List<string>();
        [DataMember] public KpImport Import { get; set; }

        /// <summary>Context name for Context and ContextRemove requests.</summary>
        [DataMember] public string Context { get; set; }

        /// <summary>Open the picker even when the context exists, replacing its selection.</summary>
        [DataMember] public bool Repick { get; set; }

        /// <summary>
        /// Environment variable names the context must provide. Missing ones open the picker so
        /// the user can assign entry fields to them.
        /// </summary>
        [DataMember] public List<string> Slots { get; set; } = new List<string>();
    }

    internal static class KpConflict
    {
        public const string Fail = "fail";
        public const string Skip = "skip";
        public const string Overwrite = "overwrite";
    }

    [DataContract]
    internal sealed class KpImport
    {
        /// <summary>Slash-separated group path below the root group; created when missing.</summary>
        [DataMember] public string GroupPath { get; set; }

        [DataMember] public string SourceFile { get; set; }
        [DataMember] public string OnConflict { get; set; } = KpConflict.Fail;
        [DataMember] public List<KpPair> Items { get; set; } = new List<KpPair>();
    }

    [DataContract]
    internal sealed class KpPair
    {
        public KpPair() { }

        public KpPair(string key, string value)
        {
            Key = key;
            Value = value;
        }

        [DataMember] public string Key { get; set; }
        [DataMember] public string Value { get; set; }
    }

    [DataContract]
    internal sealed class KpResponse
    {
        [DataMember] public bool Ok { get; set; }
        [DataMember] public string Error { get; set; }

        /// <summary>KeePass is waiting for the user (e.g. an unlock prompt is open); ask again shortly.</summary>
        [DataMember] public bool Retry { get; set; }

        /// <summary>
        /// Resolve: reference → value. Import: variable name → reference, for every imported or
        /// skipped name. Context: variable name → value. ContextList: context name
        /// → summary.
        /// </summary>
        [DataMember] public List<KpPair> Values { get; set; } = new List<KpPair>();

        /// <summary>Context: variable name → "Group / Entry / Field", which is not secret, for display.</summary>
        [DataMember] public List<KpPair> Labels { get; set; } = new List<KpPair>();

        public static KpResponse Failure(string error) => new KpResponse { Ok = false, Error = error };

        public static KpResponse Busy(string reason) => new KpResponse { Ok = false, Retry = true, Error = reason };
    }
}
