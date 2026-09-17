using System;

namespace KeePassFido2.Unlock
{
    /// <summary>The user dismissed the Windows Hello or security key prompt.</summary>
    internal sealed class UnlockCancelledException : Exception
    {
        public UnlockCancelledException() : base("The prompt was cancelled.") { }
    }

    internal sealed class UnlockFailedException : Exception
    {
        public UnlockFailedException(string message) : base(message) { }

        public UnlockFailedException(string message, int hresult) : base($"{message} (0x{hresult:X8})")
        {
            HResult = hresult;
        }
    }
}
