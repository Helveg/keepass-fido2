using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using KeePassFido2.Ipc;
using KeePassFido2.References;

namespace KeePassFido2.Kp
{
    internal static class Program
    {
        private const string Usage =
@"kp - use KeePass entries in .env files

  kp run [-f FILE]... [--context NAME] -- COMMAND [ARGS...]
      Run COMMAND with the variables from the .env files (default: .env), kp:// references
      filled in from KeePass after you approve in KeePass.
        --context NAME     also set the variables of a named context: environment variables
                           you assigned entry fields to in KeePass. Reference them in COMMAND
                           with your shell's syntax, quoted so that shell expands them, e.g.
                             kp run --context tablet --slot WIFI_PASSWORD --
                               pwsh -c 'adb shell input text $env:WIFI_PASSWORD'
        --slot NAME        a variable COMMAND needs; if the context lacks it, KeePass opens the
                           picker to assign it. Repeatable.
        --repick           open the picker even when the context has every slot

  kp env [-f FILE]... [--context NAME] [--format dotenv|export|powershell|null]
      Print the variables with references filled in, e.g. for WSL (see kp-run) or
      `kp env --format powershell | Invoke-Expression`.

  kp get REFERENCE
      Print one value, e.g. kp get kp://Work/Stripe/Live#Password

  kp import [-f FILE] --group GROUP [--all | --match PATTERN...] [options]
      Move values from a .env file into entries in GROUP (created if missing) of the database
      selected in KeePass, then replace them in the file with kp:// references.
      Without --all or --match you pick the variables interactively.
        --match PATTERN     variable names to import, '*' and '?' wildcards; repeatable
        --on-conflict MODE  fail (default), skip or overwrite existing entries
        --no-rewrite        leave the .env file unchanged
        --dry-run           show what would happen

  kp context list | show NAME | remove NAME
      Manage the contexts saved on this computer (names and entry references, no values).

Options for every command:
  --database PATH   use this database; KeePass asks to unlock it when needed (or set KP_DATABASE)
  --keepass PATH    KeePass.exe to start when KeePass is not running (or set KP_KEEPASS)

References: kp://Group/Sub/Entry (password), kp://Group/Entry#UserName, kp://uuid/<32 hex>#Field.
Values that are not references are passed through unchanged.";

        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h")
                {
                    Console.WriteLine(Usage);
                    return args.Length == 0 ? 64 : 0;
                }
                if (args[0] == "--version")
                {
                    Console.WriteLine("kp " + Assembly.GetExecutingAssembly().GetName().Version);
                    return 0;
                }

                var options = new Options(args.Skip(1).ToList());
                switch (args[0])
                {
                    case "run": return Run(options);
                    case "env": return Env(options);
                    case "get": return Get(options);
                    case "import": return Import(options);
                    case "context": return ContextCommand(options);
                    default: throw new KpException($"Unknown command '{args[0]}'. Run 'kp help'.");
                }
            }
            catch (KpException ex)
            {
                Console.Error.WriteLine("kp: " + ex.Message);
                return 1;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                Console.Error.WriteLine("kp: " + ex.Message);
                return 1;
            }
        }

        private static int Run(Options options)
        {
            if (options.Rest.Count == 0) throw new KpException("Nothing to run. Usage: kp run [-f FILE]... -- COMMAND [ARGS...]");
            string command = CommandLauncher.JoinArguments(options.Rest);
            IDictionary<string, string> variables = LoadVariables(options, command);
            return CommandLauncher.Run(options.Rest, variables);
        }

        private static int Env(Options options)
        {
            string format = options.Single("--format") ?? "dotenv";
            if (!EnvFormatter.Formats.Contains(format)) throw new KpException($"Unknown format '{format}'.");
            string command = options.Single("--command") ?? "kp env";
            IDictionary<string, string> variables = LoadVariables(options, command);
            WriteStdout(EnvFormatter.Format(variables, format));
            return 0;
        }

        private static int Get(Options options)
        {
            if (options.Rest.Count != 1) throw new KpException("Usage: kp get REFERENCE");
            string reference = options.Rest[0];
            RequireValidReference(reference);
            string value = KpClient.Resolve(new[] { reference }, "kp get " + reference, Target(options))[reference];
            WriteStdout(Console.IsOutputRedirected ? value : value + Environment.NewLine);
            return 0;
        }

        private static int Import(Options options)
        {
            string group = options.Single("--group") ?? throw new KpException("--group is required, e.g. --group Work/my-project");
            if (options.Files.Count > 1) throw new KpException("kp import takes one -f FILE.");
            string path = Path.GetFullPath(options.Files.Count == 0 ? ".env" : options.Files[0]);
            if (!File.Exists(path)) throw new KpException($"{path} does not exist.");
            string onConflict = options.Single("--on-conflict") ?? KpConflict.Fail;
            if (onConflict != KpConflict.Fail && onConflict != KpConflict.Skip && onConflict != KpConflict.Overwrite)
                throw new KpException("--on-conflict must be fail, skip or overwrite.");

            DotEnvFile file = DotEnvFile.Load(path);
            List<DotEnvAssignment> candidates = ImportSelection.Candidates(file);
            if (candidates.Count == 0)
            {
                Console.WriteLine("No values to import: every variable is empty or already a kp:// reference.");
                return 0;
            }

            List<DotEnvAssignment> selected;
            if (options.Flag("--all"))
                selected = candidates;
            else if (options.Many("--match").Count > 0)
                selected = ImportSelection.ByPatterns(candidates, options.Many("--match"));
            else if (Console.IsInputRedirected)
                throw new KpException("Pass --all or --match PATTERN when input is not interactive.");
            else
                selected = ImportSelection.Interactive(candidates, Console.In, Console.Out);

            if (selected.Count == 0)
            {
                Console.WriteLine("Nothing selected.");
                return 0;
            }

            Console.WriteLine($"{(options.Flag("--dry-run") ? "Would import" : "Importing")} {selected.Count} value(s) into '{group}':");
            foreach (DotEnvAssignment assignment in selected) Console.WriteLine("  " + assignment.Key);
            if (options.Flag("--dry-run")) return 0;

            Console.WriteLine("Approve the import in KeePass...");
            IDictionary<string, string> references = KpClient.Import(new KpImport
            {
                GroupPath = group,
                SourceFile = path,
                OnConflict = onConflict,
                Items = selected.Select(a => new KpPair(a.Key, a.Value)).ToList(),
            }, "kp import " + Path.GetFileName(path), Target(options));

            if (options.Flag("--no-rewrite"))
            {
                Console.WriteLine($"Saved in KeePass. {Path.GetFileName(path)} was left unchanged; replace the values with:");
                foreach (var pair in references) Console.WriteLine($"  {pair.Key}={pair.Value}");
                return 0;
            }

            var replacements = file.Assignments
                .Where(a => references.ContainsKey(a.Key))
                .ToDictionary(a => a, a => references[a.Key]);
            file.Save(file.WithValues(replacements));
            Console.WriteLine($"Saved in KeePass and replaced {replacements.Count} value(s) in {Path.GetFileName(path)} with kp:// references.");

            Console.WriteLine();
            Console.WriteLine("The old values can still exist elsewhere: editor backups, sync history (Dropbox, OneDrive,");
            Console.WriteLine("Google Drive), or git history. Rotate any secret that was ever committed or shared.");
            if (IsTrackedByGit(path))
                Console.WriteLine($"Warning: {Path.GetFileName(path)} is tracked by git, so its old values are in the repository history.");
            return 0;
        }

        /// <summary>
        /// Merges the .env files in order (later assignments win), resolves their references, then
        /// adds the context's values, which override same-named file variables.
        /// </summary>
        private static IDictionary<string, string> LoadVariables(Options options, string command)
        {
            KeePassTarget target = Target(options);
            string context = options.Single("--context");
            if (context == null && (options.Many("--slot").Count > 0 || options.Flag("--repick")))
                throw new KpException("--slot and --repick need --context NAME.");
            IList<string> files = options.Files;
            if (files.Count == 0 && File.Exists(".env"))
                files = new[] { ".env" };
            else if (files.Count == 0 && context == null)
                throw new KpException("No .env file in this folder. Pass -f FILE or --context NAME.");

            IDictionary<string, string> variables = LoadFiles(files, command, target);
            if (context == null) return variables;

            KpResponse response = KpClient.Context(context, options.Flag("--repick"), options.Many("--slot"), command, target);
            foreach (KpPair pair in response.Values) variables[pair.Key] = pair.Value;
            return variables;
        }

        private static int ContextCommand(Options options)
        {
            string action = options.Rest.FirstOrDefault();
            KeePassTarget target = Target(options);
            switch (action)
            {
                case "list":
                {
                    KpResponse response = KpClient.ListContexts(target);
                    if (response.Values.Count == 0) Console.WriteLine("No contexts saved. Create one with kp run --context NAME -- COMMAND.");
                    foreach (KpPair context in response.Values) Console.WriteLine($"{context.Key}: {context.Value}");
                    return 0;
                }
                case "show":
                {
                    string name = options.Rest.ElementAtOrDefault(1) ?? throw new KpException("Usage: kp context show NAME");
                    KpResponse response = KpClient.ListContexts(target);
                    if (!response.Values.Any(c => string.Equals(c.Key, name, StringComparison.OrdinalIgnoreCase)))
                        throw new KpException($"There is no context '{name}'.");
                    string prefix = response.Values.First(c => string.Equals(c.Key, name, StringComparison.OrdinalIgnoreCase)).Key + "/";
                    int index = 1;
                    foreach (KpPair variable in response.Labels.Where(l => l.Key.StartsWith(prefix, StringComparison.Ordinal)))
                        Console.WriteLine($"{index++,2}. {variable.Key.Substring(prefix.Length)} = {variable.Value}");
                    return 0;
                }
                case "remove":
                {
                    string name = options.Rest.ElementAtOrDefault(1) ?? throw new KpException("Usage: kp context remove NAME");
                    KpClient.RemoveContext(name, target);
                    Console.WriteLine($"Removed context '{name}'.");
                    return 0;
                }
                default:
                    throw new KpException("Usage: kp context list | show NAME | remove NAME");
            }
        }

        private static IDictionary<string, string> LoadFiles(IList<string> files, string command, KeePassTarget target)
        {

            var variables = new Dictionary<string, string>(StringComparer.Ordinal);
            var order = new List<string>();
            foreach (string file in files)
            {
                if (!File.Exists(file)) throw new KpException($"{file} does not exist.");
                foreach (DotEnvAssignment assignment in DotEnvFile.Load(file).Assignments)
                {
                    if (!variables.ContainsKey(assignment.Key)) order.Add(assignment.Key);
                    variables[assignment.Key] = assignment.Value;
                }
            }

            List<string> references = variables.Values.Where(SecretReference.LooksLikeReference).Distinct().ToList();
            foreach (string reference in references) RequireValidReference(reference);
            if (references.Count > 0)
            {
                IDictionary<string, string> values = KpClient.Resolve(references, command, target);
                foreach (string key in order.Where(k => SecretReference.LooksLikeReference(variables[k])))
                    variables[key] = values[variables[key]];
            }

            var ordered = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string key in order) ordered[key] = variables[key];
            return ordered;
        }

        private static KeePassTarget Target(Options options)
        {
            string database = options.Single("--database") ?? Environment.GetEnvironmentVariable("KP_DATABASE");
            string keePass = options.Single("--keepass") ?? Environment.GetEnvironmentVariable("KP_KEEPASS");
            return new KeePassTarget
            {
                DatabasePath = string.IsNullOrWhiteSpace(database) ? null : Path.GetFullPath(database),
                KeePassExe = string.IsNullOrWhiteSpace(keePass) ? null : Path.GetFullPath(keePass),
            };
        }

        private static void RequireValidReference(string reference)
        {
            if (!SecretReference.TryParse(reference, out _, out string error)) throw new KpException(error);
        }

        /// <summary>Writes UTF-8 bytes directly, so NUL separators and non-ASCII values survive redirection.</summary>
        private static void WriteStdout(string text)
        {
            byte[] bytes = new UTF8Encoding(false).GetBytes(text);
            using (Stream stdout = Console.OpenStandardOutput())
                stdout.Write(bytes, 0, bytes.Length);
        }

        private static bool IsTrackedByGit(string path)
        {
            try
            {
                var start = new ProcessStartInfo("git", "ls-files --error-unmatch -- " + CommandLauncher.QuoteArgument(Path.GetFileName(path)))
                {
                    WorkingDirectory = Path.GetDirectoryName(path),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                using (Process git = Process.Start(start))
                {
                    git.StandardOutput.ReadToEnd();
                    git.StandardError.ReadToEnd();
                    git.WaitForExit(5000);
                    return git.HasExited && git.ExitCode == 0;
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
        }

        /// <summary>Options before "--" (or before the first non-option word for run), then the rest.</summary>
        private sealed class Options
        {
            private static readonly HashSet<string> Flags = new HashSet<string> { "--all", "--dry-run", "--no-rewrite", "--repick" };
            private static readonly HashSet<string> Valued = new HashSet<string> { "-f", "--file", "--format", "--command", "--group", "--match", "--on-conflict", "--database", "--keepass", "--context", "--slot" };
            private readonly List<KeyValuePair<string, string>> _values = new List<KeyValuePair<string, string>>();

            public Options(IList<string> args)
            {
                int i = 0;
                for (; i < args.Count; i++)
                {
                    string arg = args[i];
                    if (arg == "--")
                    {
                        i++;
                        break;
                    }
                    if (Flags.Contains(arg))
                    {
                        _values.Add(new KeyValuePair<string, string>(arg, null));
                    }
                    else if (Valued.Contains(arg))
                    {
                        if (i + 1 >= args.Count) throw new KpException($"{arg} needs a value.");
                        _values.Add(new KeyValuePair<string, string>(arg == "--file" ? "-f" : arg, args[++i]));
                    }
                    else if (arg.StartsWith("-", StringComparison.Ordinal))
                    {
                        throw new KpException($"Unknown option '{arg}'.");
                    }
                    else
                    {
                        break;
                    }
                }
                Rest = args.Skip(i).ToList();
            }

            public List<string> Rest { get; }
            public IList<string> Files => Many("-f");
            public bool Flag(string name) => _values.Any(v => v.Key == name);
            public IList<string> Many(string name) => _values.Where(v => v.Key == name).Select(v => v.Value).ToList();
            public string Single(string name) => _values.LastOrDefault(v => v.Key == name).Value;
        }
    }
}
