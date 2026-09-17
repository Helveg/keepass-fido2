using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KeePassFido2.Unlock
{
    /// <summary>
    /// Windows Hello through the Microsoft Passport key storage provider: an RSA key in the TPM
    /// whose private operations require a Hello gesture (face, fingerprint or Hello PIN) on every
    /// use. Encrypting needs only the public key and never prompts.
    /// </summary>
    /// <remarks>
    /// webauthn.dll is not used for Windows Hello: creating a Windows Hello credential with
    /// hmac-secret for this plugin's relying party fails with NTE_NOT_SUPPORTED.
    /// </remarks>
    internal static class WindowsHelloAuthenticator
    {
        private const string PassportProvider = "Microsoft Passport Key Storage Provider";
        private const string WindowHandleProperty = "HWND Handle";
        private const string UseContextProperty = "Use Context";
        private const string LengthProperty = "Length";
        private const string KeyUsageProperty = "Key Usage";
        private const string NgcCacheTypeProperty = "NgcCacheType";
        private const string NgcCacheTypePropertyLegacy = "NgcCacheTypeProperty";
        private const string PinCacheIsGestureRequiredProperty = "PinCacheIsGestureRequired";

        private const int AllowDecrypt = 0x1;
        private const int AllowSigning = 0x2;
        private const int AllowKeyImport = 0x8;
        private const int NgcCacheAuthMandatory = 0x1;
        private const int PadPkcs1 = 0x2;

        private const int NteBadData = unchecked((int)0x80090005);
        private const int NteNoKey = unchecked((int)0x8009000D);
        private const int NteUserCancelled = unchecked((int)0x80090036);
        private const int ErrorCancelled = unchecked((int)0x800704C7);

        public static bool IsAvailable
        {
            get
            {
                try
                {
                    return NgcGetDefaultDecryptionKeyName(CurrentSid, 0, 0, out string name) >= 0 && !string.IsNullOrEmpty(name);
                }
                catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException)
                {
                    return false;
                }
            }
        }

        /// <summary>Encrypts <paramref name="data"/> (at most 245 bytes) to the Hello key, creating the key if needed.</summary>
        public static byte[] Protect(IntPtr hwnd, byte[] data)
        {
            using (SafeNCryptKeyHandle key = OpenOrCreateKey(hwnd))
            {
                Check(NCryptEncrypt(key, data, data.Length, IntPtr.Zero, null, 0, out int size, PadPkcs1), "NCryptEncrypt");
                var output = new byte[size];
                Check(NCryptEncrypt(key, data, data.Length, IntPtr.Zero, output, output.Length, out size, PadPkcs1), "NCryptEncrypt");
                return output;
            }
        }

        /// <summary>Decrypts <paramref name="data"/>; shows the Windows Hello prompt.</summary>
        public static byte[] Unprotect(IntPtr hwnd, byte[] data, string message)
        {
            using (SafeNCryptKeyHandle key = OpenKey())
            {
                if (key == null)
                    throw new UnlockFailedException("The Windows Hello key for KeePass FIDO2 no longer exists. Add Windows Hello again.");
                RequireTrustedKey(key);
                ApplyUiContext(key, hwnd, message);
                SetInt(key, PinCacheIsGestureRequiredProperty, 1);

                var output = new byte[data.Length * 2];
                Check(NCryptDecrypt(key, data, data.Length, IntPtr.Zero, output, output.Length, out int size, PadPkcs1), "NCryptDecrypt");
                var result = new byte[size];
                Buffer.BlockCopy(output, 0, result, 0, size);
                Array.Clear(output, 0, output.Length);
                return result;
            }
        }

        private static string CurrentSid => WindowsIdentity.GetCurrent().User.Value;

        private static string KeyName => CurrentSid + Protocol.HelloKeySuffix;

        private static SafeNCryptKeyHandle OpenKey()
        {
            Check(NCryptOpenStorageProvider(out SafeNCryptProviderHandle provider, PassportProvider, 0), "NCryptOpenStorageProvider");
            using (provider)
            {
                int status = NCryptOpenKey(provider, out SafeNCryptKeyHandle key, KeyName, 0, 0);
                if (status == NteNoKey) return null;
                Check(status, "NCryptOpenKey");
                return key;
            }
        }

        private static SafeNCryptKeyHandle OpenOrCreateKey(IntPtr hwnd)
        {
            SafeNCryptKeyHandle existing = OpenKey();
            if (existing != null)
            {
                RequireTrustedKey(existing);
                return existing;
            }

            Check(NCryptOpenStorageProvider(out SafeNCryptProviderHandle provider, PassportProvider, 0), "NCryptOpenStorageProvider");
            using (provider)
            {
                Check(NCryptCreatePersistedKey(provider, out SafeNCryptKeyHandle key, "RSA", KeyName, 0, 0), "NCryptCreatePersistedKey");
                try
                {
                    SetInt(key, LengthProperty, 2048);
                    SetInt(key, KeyUsageProperty, AllowDecrypt | AllowSigning);
                    if (NCryptSetProperty(key, NgcCacheTypeProperty, BitConverter.GetBytes(NgcCacheAuthMandatory), sizeof(int), 0) < 0)
                        SetInt(key, NgcCacheTypePropertyLegacy, NgcCacheAuthMandatory);
                    ApplyUiContext(key, hwnd, "Set up Windows Hello for KeePass FIDO2");
                    Check(NCryptFinalizeKey(key, 0), "NCryptFinalizeKey");
                    return key;
                }
                catch
                {
                    key.Dispose();
                    throw;
                }
            }
        }

        /// <summary>
        /// Refuses a key that could have been planted with weaker settings under our key name:
        /// an importable key, or one that does not demand a Hello gesture for every use.
        /// </summary>
        private static void RequireTrustedKey(SafeNCryptKeyHandle key)
        {
            int usage = GetInt(key, KeyUsageProperty);
            int cacheType;
            try
            {
                cacheType = GetInt(key, NgcCacheTypeProperty);
            }
            catch (UnlockFailedException)
            {
                cacheType = GetInt(key, NgcCacheTypePropertyLegacy);
            }

            if ((usage & AllowKeyImport) != 0 || cacheType != NgcCacheAuthMandatory)
                throw new UnlockFailedException("The Windows Hello key has unexpected settings and was not used.");
        }

        private static void ApplyUiContext(SafeNCryptKeyHandle key, IntPtr hwnd, string message)
        {
            if (hwnd != IntPtr.Zero)
            {
                byte[] handle = IntPtr.Size == 8 ? BitConverter.GetBytes(hwnd.ToInt64()) : BitConverter.GetBytes(hwnd.ToInt32());
                int status = NCryptSetProperty(key, WindowHandleProperty, handle, handle.Length, 0);
                if (status != NteBadData) Check(status, WindowHandleProperty);
            }
            if (!string.IsNullOrEmpty(message))
            {
                byte[] text = Encoding.Unicode.GetBytes(message + "\0");
                Check(NCryptSetProperty(key, UseContextProperty, text, text.Length, 0), UseContextProperty);
            }
        }

        private static void SetInt(SafeNCryptKeyHandle key, string property, int value) =>
            Check(NCryptSetProperty(key, property, BitConverter.GetBytes(value), sizeof(int), 0), property);

        private static int GetInt(SafeNCryptKeyHandle key, string property)
        {
            int value = 0;
            Check(NCryptGetProperty(key, property, ref value, sizeof(int), out _, 0), property);
            return value;
        }

        private static void Check(int status, string operation)
        {
            if (status >= 0) return;
            if (status == NteUserCancelled || status == ErrorCancelled) throw new UnlockCancelledException();
            throw new UnlockFailedException($"Windows Hello failed during {operation}", status);
        }

        [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
        private static extern int NgcGetDefaultDecryptionKeyName(string sid, int reserved1, int reserved2, out string keyName);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenStorageProvider(out SafeNCryptProviderHandle provider, string providerName, int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenKey(SafeNCryptProviderHandle provider, out SafeNCryptKeyHandle key, string keyName, int legacyKeySpec, int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptCreatePersistedKey(SafeNCryptProviderHandle provider, out SafeNCryptKeyHandle key, string algorithm, string keyName, int legacyKeySpec, int flags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFinalizeKey(SafeNCryptKeyHandle key, int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptGetProperty(SafeNCryptHandle handle, string property, ref int output, int outputSize, out int resultSize, int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptSetProperty(SafeNCryptHandle handle, string property, byte[] input, int inputSize, int flags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptEncrypt(SafeNCryptKeyHandle key, byte[] input, int inputSize, IntPtr padding, byte[] output, int outputSize, out int resultSize, int flags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptDecrypt(SafeNCryptKeyHandle key, byte[] input, int inputSize, IntPtr padding, byte[] output, int outputSize, out int resultSize, int flags);
    }
}
