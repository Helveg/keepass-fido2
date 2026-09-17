using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using KeePassFido2.Ipc;

namespace KeePassFido2.Agent
{
    /// <summary>
    /// Accepts kp.exe connections on a named pipe that only the current Windows user (and not
    /// network logons) may open, and hands each request to <see cref="SecretBroker"/>.
    /// </summary>
    internal sealed class SecretServer : IDisposable
    {
        private const int MaxInstances = 4;

        private readonly Func<KpRequest, ClientProcess, KpResponse> _handler;
        private readonly ManualResetEvent _stop = new ManualResetEvent(false);
        private Thread _thread;

        public SecretServer(Func<KpRequest, ClientProcess, KpResponse> handler)
        {
            _handler = handler;
        }

        public void Start()
        {
            _thread = new Thread(AcceptLoop) { IsBackground = true, Name = "KeePassFido2 pipe server" };
            _thread.Start();
        }

        public void Dispose()
        {
            _stop.Set();
            _thread?.Join(2000);
        }

        private void AcceptLoop()
        {
            while (!_stop.WaitOne(0))
            {
                NamedPipeServerStream pipe;
                try
                {
                    pipe = CreatePipe();
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    // Another KeePass instance owns the pipe; retry in case it exits.
                    Debug.WriteLine("KeePassFido2: pipe unavailable: " + ex.Message);
                    if (_stop.WaitOne(5000)) return;
                    continue;
                }

                IAsyncResult pending = pipe.BeginWaitForConnection(null, null);
                if (WaitHandle.WaitAny(new[] { pending.AsyncWaitHandle, _stop }) == 1)
                {
                    pipe.Dispose();
                    return;
                }

                try
                {
                    pipe.EndWaitForConnection(pending);
                }
                catch (IOException)
                {
                    pipe.Dispose();
                    continue;
                }

                ThreadPool.QueueUserWorkItem(_ => Serve(pipe));
            }
        }

        private void Serve(NamedPipeServerStream pipe)
        {
            using (pipe)
            {
                try
                {
                    var request = KpPipe.Read<KpRequest>(pipe);
                    KpResponse response = request.ProtocolVersion == KpPipe.ProtocolVersion
                        ? _handler(request, ClientProcess.FromPipe(pipe))
                        : KpResponse.Failure($"kp.exe speaks protocol {request.ProtocolVersion}, the plugin speaks {KpPipe.ProtocolVersion}. Update both.");
                    KpPipe.Write(pipe, response);
                }
                catch (Exception ex) when (ex is IOException || ex is InvalidDataException || ex is System.Runtime.Serialization.SerializationException)
                {
                    Debug.WriteLine("KeePassFido2: request failed: " + ex.Message);
                }
            }
        }

        private static NamedPipeServerStream CreatePipe()
        {
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
            return new NamedPipeServerStream(KpPipe.Name, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
        }
    }

    /// <summary>The process on the other end of a pipe connection, as seen by Windows.</summary>
    internal sealed class ClientProcess
    {
        public int ProcessId { get; private set; }
        public string ImagePath { get; private set; }
        public int ParentProcessId { get; private set; }
        public string ParentImagePath { get; private set; }

        public string DisplayName => Path.GetFileName(ImagePath ?? "unknown");
        public string ParentDisplayName => ParentImagePath == null ? null : Path.GetFileName(ParentImagePath);

        public static ClientProcess FromPipe(NamedPipeServerStream pipe)
        {
            var client = new ClientProcess();
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid)) return client;

            client.ProcessId = (int)pid;
            client.ImagePath = TryGetImagePath((int)pid);
            client.ParentProcessId = TryGetParentId((int)pid);
            if (client.ParentProcessId != 0) client.ParentImagePath = TryGetImagePath(client.ParentProcessId);
            return client;
        }

        private static string TryGetImagePath(int pid)
        {
            IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (process == IntPtr.Zero) return null;
            try
            {
                var buffer = new System.Text.StringBuilder(1024);
                int size = buffer.Capacity;
                return QueryFullProcessImageName(process, 0, buffer, ref size) ? buffer.ToString() : null;
            }
            finally
            {
                CloseHandle(process);
            }
        }

        private static int TryGetParentId(int pid)
        {
            IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (process == IntPtr.Zero) return 0;
            try
            {
                var info = new ProcessBasicInformation();
                int status = NtQueryInformationProcess(process, 0, ref info, Marshal.SizeOf(info), out _);
                return status == 0 ? (int)info.InheritedFromUniqueProcessId : 0;
            }
            finally
            {
                CloseHandle(process);
            }
        }

        private const int ProcessQueryLimitedInformation = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessBasicInformation
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr process, int flags, System.Text.StringBuilder name, ref int size);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, ref ProcessBasicInformation info, int size, out int returnLength);
    }
}
