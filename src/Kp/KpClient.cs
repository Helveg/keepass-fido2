using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using KeePassFido2.Ipc;
using Microsoft.Win32;

namespace KeePassFido2.Kp
{
    internal sealed class KpException : Exception
    {
        public KpException(string message) : base(message) { }
    }

    /// <summary>Where and how to reach KeePass.</summary>
    internal sealed class KeePassTarget
    {
        /// <summary>Full path of the database to use, or null for whichever is unlocked.</summary>
        public string DatabasePath { get; set; }

        /// <summary>KeePass.exe to start when KeePass is not running; null to look it up.</summary>
        public string KeePassExe { get; set; }
    }

    /// <summary>Talks to the KeePass FIDO2 plugin over its named pipe, starting KeePass when needed.</summary>
    internal static class KpClient
    {
        private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan UserWaitTimeout = TimeSpan.FromMinutes(10);

        public static IDictionary<string, string> Resolve(IEnumerable<string> references, string command, KeePassTarget target)
        {
            KpResponse response = Send(new KpRequest
            {
                Kind = KpRequestKind.Resolve,
                WorkingDirectory = Environment.CurrentDirectory,
                Command = command,
                DatabasePath = target.DatabasePath,
                References = references.Distinct(StringComparer.Ordinal).ToList(),
            }, target);
            return response.Values.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        }

        /// <returns>Variable name → reference.</returns>
        public static IDictionary<string, string> Import(KpImport import, string command, KeePassTarget target)
        {
            KpResponse response = Send(new KpRequest
            {
                Kind = KpRequestKind.Import,
                WorkingDirectory = Environment.CurrentDirectory,
                Command = command,
                DatabasePath = target.DatabasePath,
                Import = import,
            }, target);
            return response.Values.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        }

        /// <summary>
        /// The variables of a named context; KeePass shows the picker first when the context
        /// does not exist, lacks one of <paramref name="slots"/>, or <paramref name="repick"/> is set.
        /// </summary>
        public static KpResponse Context(string name, bool repick, IList<string> slots, string command, KeePassTarget target) =>
            Send(new KpRequest
            {
                Kind = KpRequestKind.Context,
                WorkingDirectory = Environment.CurrentDirectory,
                Command = command,
                DatabasePath = target.DatabasePath,
                Context = name,
                Repick = repick,
                Slots = slots.ToList(),
            }, target);

        public static KpResponse ListContexts(KeePassTarget target) =>
            Send(new KpRequest { Kind = KpRequestKind.ContextList }, target);

        public static void RemoveContext(string name, KeePassTarget target) =>
            Send(new KpRequest { Kind = KpRequestKind.ContextRemove, Context = name }, target);

        private static KpResponse Send(KpRequest request, KeePassTarget target)
        {
            bool started = false;
            bool announced = false;
            DateTime deadline = DateTime.UtcNow + UserWaitTimeout;
            while (true)
            {
                KpResponse response;
                using (NamedPipeClientStream pipe = Connect(target, ref started))
                {
                    RequireKeePassServer(pipe);
                    KpPipe.Write(pipe, request);
                    try
                    {
                        response = KpPipe.Read<KpResponse>(pipe);
                    }
                    catch (EndOfStreamException)
                    {
                        throw new KpException("KeePass closed the connection without answering.");
                    }
                }

                if (response.Ok) return response;
                if (!response.Retry) throw new KpException(response.Error ?? "KeePass refused the request.");
                if (DateTime.UtcNow > deadline) throw new KpException("Gave up waiting for KeePass: " + response.Error);
                if (!announced)
                {
                    Console.Error.WriteLine("kp: " + response.Error);
                    announced = true;
                }
                Thread.Sleep(1000);
            }
        }

        private static NamedPipeClientStream Connect(KeePassTarget target, ref bool started)
        {
            DateTime deadline = DateTime.UtcNow + StartupTimeout;
            while (true)
            {
                var pipe = new NamedPipeClientStream(".", KpPipe.Name, PipeDirection.InOut);
                try
                {
                    pipe.Connect(started ? 1000 : 500);
                    return pipe;
                }
                catch (TimeoutException)
                {
                    pipe.Dispose();
                }

                if (!started)
                {
                    StartKeePass(target);
                    started = true;
                    Console.Error.WriteLine("kp: started KeePass; unlock the database to continue.");
                }
                else if (DateTime.UtcNow > deadline)
                {
                    throw new KpException("KeePass did not become reachable. Is the KeePass FIDO2 plugin installed?");
                }
            }
        }

        private static void StartKeePass(KeePassTarget target)
        {
            if (Process.GetProcessesByName("KeePass").Length > 0)
                throw new KpException("KeePass is running, but the KeePass FIDO2 plugin does not answer. Is the plugin installed?");

            string exe = target.KeePassExe ?? FindKeePass()
                ?? throw new KpException("KeePass is not running and KeePass.exe was not found. Pass --keepass PATH or set KP_KEEPASS.");

            // Shell execute: KeePass must not inherit kp's stdout/stderr, or whoever reads kp's
            // output (a script, `$(kp env)`) would wait until KeePass exits.
            var start = new ProcessStartInfo(exe) { UseShellExecute = true };
            if (target.DatabasePath != null) start.Arguments = CommandLauncher.QuoteArgument(target.DatabasePath);
            Process.Start(start)?.Dispose();
        }

        private static string FindKeePass()
        {
            const string uninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassPasswordSafe2_is1";
            foreach (RegistryKey root in new[] { Registry.LocalMachine, Registry.CurrentUser })
            foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(root == Registry.LocalMachine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, view))
                using (RegistryKey key = baseKey.OpenSubKey(uninstallKey))
                {
                    if (key?.GetValue("InstallLocation") is string location)
                    {
                        string exe = Path.Combine(location, "KeePass.exe");
                        if (File.Exists(exe)) return exe;
                    }
                }
            }

            string programFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "KeePass Password Safe 2", "KeePass.exe");
            return File.Exists(programFiles) ? programFiles : null;
        }

        /// <summary>
        /// Imports send secrets to the server, so refuse to talk to a process other than KeePass
        /// that happens to hold the pipe name. Also lets that process bring its dialogs to the
        /// foreground, which Windows otherwise blocks.
        /// </summary>
        private static void RequireKeePassServer(NamedPipeClientStream pipe)
        {
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid))
                throw new KpException("Could not identify the process serving the KeePass pipe.");

            string name;
            try
            {
                name = Process.GetProcessById((int)pid).ProcessName;
            }
            catch (ArgumentException)
            {
                throw new KpException("The process serving the KeePass pipe exited.");
            }
            if (!string.Equals(name, "KeePass", StringComparison.OrdinalIgnoreCase))
                throw new KpException($"The KeePass pipe is served by '{name}' (process {pid}), not KeePass. Refusing to continue.");

            AllowSetForegroundWindow(pid);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

        [DllImport("user32.dll")]
        private static extern bool AllowSetForegroundWindow(uint processId);
    }
}
