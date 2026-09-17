using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace KeePassFido2.Kp
{
    /// <summary>Starts a command the way a Windows shell would, with extra environment variables.</summary>
    internal static class CommandLauncher
    {
        public static int Run(IList<string> command, IDictionary<string, string> environment)
        {
            string executable = FindExecutable(command[0])
                ?? throw new KpException($"'{command[0]}' was not found on PATH.");

            var start = new ProcessStartInfo { UseShellExecute = false };
            string extension = Path.GetExtension(executable);
            if (extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase))
            {
                // Batch files need cmd.exe; /s keeps the outer quotes of the whole command line intact.
                start.FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
                start.Arguments = "/d /s /c \"" + QuoteArgument(executable) + " " + JoinArguments(command.Skip(1)) + "\"";
            }
            else
            {
                start.FileName = executable;
                start.Arguments = JoinArguments(command.Skip(1));
            }
            foreach (var pair in environment) start.EnvironmentVariables[pair.Key] = pair.Value;

            // The child shares this console and receives Ctrl+C itself; kp waits for it to exit.
            Console.CancelKeyPress += (s, e) => e.Cancel = true;
            using (Process process = Process.Start(start))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        public static string FindExecutable(string name)
        {
            IEnumerable<string> extensions = Path.HasExtension(name)
                ? new[] { string.Empty }
                : (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

            IEnumerable<string> directories = name.IndexOfAny(new[] { '\\', '/' }) >= 0 || Path.IsPathRooted(name)
                ? new[] { string.Empty }
                : new[] { Environment.CurrentDirectory }.Concat((Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries));

            foreach (string directory in directories)
            foreach (string extension in extensions)
            {
                string candidate;
                try
                {
                    candidate = Path.GetFullPath(Path.Combine(directory.Trim('"'), name + extension));
                }
                catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
                {
                    continue;
                }
                if (File.Exists(candidate)) return candidate;
            }
            return null;
        }

        public static string JoinArguments(IEnumerable<string> arguments) => string.Join(" ", arguments.Select(QuoteArgument));

        /// <summary>Quotes one argument so CommandLineToArgvW and the C runtime read it back unchanged.</summary>
        public static string QuoteArgument(string argument)
        {
            if (argument.Length > 0 && argument.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return argument;

            var builder = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char c in argument)
            {
                if (c == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (c == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1).Append('"');
                }
                else
                {
                    builder.Append('\\', backslashes).Append(c);
                }
                backslashes = 0;
            }
            builder.Append('\\', backslashes * 2).Append('"');
            return builder.ToString();
        }
    }
}
