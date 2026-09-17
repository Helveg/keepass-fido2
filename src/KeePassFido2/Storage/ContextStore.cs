using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Serialization;

namespace KeePassFido2.Storage
{
    [XmlRoot("KeePassFido2Contexts")]
    public sealed class ContextDocument
    {
        [XmlAttribute("version")]
        public int Version { get; set; } = 1;

        [XmlElement("Context")]
        public List<SavedContext> Contexts { get; set; } = new List<SavedContext>();
    }

    /// <summary>
    /// Environment variable names mapped to entry fields. It holds references only; the values are read
    /// from KeePass, after approval, every time the context is used.
    /// </summary>
    public sealed class SavedContext
    {
        [XmlAttribute("name")]
        public string Name { get; set; }

        /// <summary>Database the entries were picked from, so KeePass can open it when locked.</summary>
        public string DatabasePath { get; set; }

        public DateTime UpdatedUtc { get; set; }

        [XmlElement("Variable")]
        public List<ContextVariable> Variables { get; set; } = new List<ContextVariable>();
    }

    public sealed class ContextVariable
    {
        [XmlAttribute("name")]
        public string Name { get; set; }

        /// <summary>kp://uuid/… reference, so renaming or moving the entry keeps the context working.</summary>
        [XmlAttribute("reference")]
        public string Reference { get; set; }

        /// <summary>"Group / Entry / Field" when the context was saved, for display.</summary>
        [XmlAttribute("label")]
        public string Label { get; set; }
    }

    /// <summary>Contexts of this computer, kept next to the unlock store.</summary>
    internal sealed class ContextStore
    {
        private static readonly XmlSerializer Serializer = new XmlSerializer(typeof(ContextDocument));
        private static readonly Regex ValidName = new Regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$");
        private readonly object _lock = new object();

        public ContextStore(string filePath)
        {
            FilePath = filePath;
        }

        public string FilePath { get; }

        public static bool IsValidName(string name) => name != null && ValidName.IsMatch(name);

        /// <summary>A name usable as an environment variable in Windows and POSIX shells.</summary>
        public static bool IsValidVariableName(string name) => name != null && Regex.IsMatch(name, "^[A-Za-z_][A-Za-z0-9_]{0,127}$");

        public SavedContext Find(string name)
        {
            lock (_lock)
                return Load().Contexts.FirstOrDefault(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        public List<SavedContext> All()
        {
            lock (_lock)
                return Load().Contexts.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        public void Save(SavedContext context)
        {
            lock (_lock)
            {
                ContextDocument document = Load();
                document.Contexts.RemoveAll(c => string.Equals(c.Name, context.Name, StringComparison.OrdinalIgnoreCase));
                document.Contexts.Add(context);
                Write(document);
            }
        }

        public bool Remove(string name)
        {
            lock (_lock)
            {
                ContextDocument document = Load();
                if (document.Contexts.RemoveAll(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase)) == 0) return false;
                Write(document);
                return true;
            }
        }

        /// <summary>
        /// An environment variable name from a label such as "Tablet account / Password":
        /// uppercase letters, digits and underscores, not starting with a digit, unique among
        /// <paramref name="taken"/>.
        /// </summary>
        public static string VariableName(string entryTitle, string field, ICollection<string> taken)
        {
            var builder = new StringBuilder();
            foreach (char c in (entryTitle + "_" + field).ToUpperInvariant())
                builder.Append(c < 128 && char.IsLetterOrDigit(c) ? c : '_');
            string name = Regex.Replace(builder.ToString(), "_+", "_").Trim('_');
            if (name.Length == 0 || char.IsDigit(name[0])) name = "KP_" + name;

            string unique = name;
            for (int i = 2; taken.Contains(unique); i++) unique = name + "_" + i;
            return unique;
        }

        private ContextDocument Load()
        {
            if (!File.Exists(FilePath)) return new ContextDocument();
            using (var stream = File.OpenRead(FilePath))
                return (ContextDocument)Serializer.Deserialize(stream);
        }

        private void Write(ContextDocument document)
        {
            string directory = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            string temp = FilePath + ".tmp";
            using (var stream = File.Create(temp))
                Serializer.Serialize(stream, document);
            if (File.Exists(FilePath)) File.Replace(temp, FilePath, null);
            else File.Move(temp, FilePath);
        }
    }
}
