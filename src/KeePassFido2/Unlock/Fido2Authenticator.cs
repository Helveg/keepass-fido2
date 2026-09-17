using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using KeePassFido2.Crypto;
using KeePassFido2.Interop;

namespace KeePassFido2.Unlock
{
    /// <summary>
    /// FIDO2 security keys through webauthn.dll, which is the only way a non-elevated process
    /// on Windows can reach them. webauthn.dll silently drops the hmac-secret extension for
    /// non-resident credentials, so every credential is created as a resident (discoverable) one.
    /// </summary>
    internal static unsafe class Fido2Authenticator
    {
        private const int ErrorCancelled = unchecked((int)0x800704C7);
        private const uint Timeout = 120000;

        /// <summary>API version 4 is the first with hmac-secret salt values on assertions.</summary>
        public static bool IsAvailable
        {
            get
            {
                try
                {
                    return WebAuthnNative.WebAuthNGetApiVersionNumber() >= 4;
                }
                catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException)
                {
                    return false;
                }
            }
        }

        /// <summary>Creates a resident credential with hmac-secret enabled and returns its id.</summary>
        /// <param name="userName">Shown by Windows and by credential managers on the key.</param>
        public static byte[] CreateCredential(IntPtr hwnd, string userName)
        {
            using (var mem = new NativeArena())
            {
                var rp = new RpEntity { dwVersion = 1, pwszId = mem.String(Protocol.RpId), pwszName = mem.String(Protocol.RpName) };
                // A random user id per enrollment: a second credential with the same rp and user id
                // would overwrite the first on the key.
                byte[] userId = Envelope.RandomBytes(16);
                var user = new UserEntity
                {
                    dwVersion = 1,
                    cbId = (uint)userId.Length,
                    pbId = mem.Bytes(userId),
                    pwszName = mem.String(userName),
                    pwszDisplayName = mem.String(userName),
                };
                var param = new CoseParam { dwVersion = 1, pwszCredentialType = mem.String("public-key"), lAlg = WebAuthnNative.CoseAlgorithmEs256 };
                var pars = new CoseParams { cCredentialParameters = 1, pCredentialParameters = &param };
                var clientData = CreateClientData(mem, "webauthn.create");

                int enabled = 1;
                var hmacSecret = new Extension { pwszExtensionIdentifier = mem.String("hmac-secret"), cbExtension = sizeof(int), pvExtension = (IntPtr)(&enabled) };
                var options = new MakeCredentialOptions
                {
                    dwVersion = WebAuthnNative.MakeCredentialOptionsVersion,
                    dwTimeoutMilliseconds = Timeout,
                    Extensions = new Extensions { cExtensions = 1, pExtensions = &hmacSecret },
                    dwAuthenticatorAttachment = WebAuthnNative.AttachmentCrossPlatform,
                    bRequireResidentKey = 1,
                    dwUserVerificationRequirement = WebAuthnNative.UserVerificationRequired,
                    dwAttestationConveyancePreference = WebAuthnNative.AttestationNone,
                };

                int hr = WebAuthnNative.WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &pars, &clientData, &options, out IntPtr result);
                ThrowOnError(hr, "Creating a credential on the security key failed");
                try
                {
                    var attestation = (CredentialAttestation*)result;
                    if (!HasHmacSecretOutput(attestation->Extensions))
                        throw new UnlockFailedException("This security key does not support the FIDO2 hmac-secret extension.");
                    return Copy(attestation->pbCredentialId, attestation->cbCredentialId);
                }
                finally
                {
                    WebAuthnNative.WebAuthNFreeCredentialAttestation(result);
                }
            }
        }

        /// <summary>
        /// Asks whichever allowed security key is presented for its hmac-secret output for
        /// <paramref name="prfInput"/>. Windows applies the WebAuthn PRF transform to the input.
        /// </summary>
        /// <remarks>
        /// Authenticators keep separate hmac-secrets for assertions with and without user
        /// verification, so <see cref="Fido2Secret.UserVerified"/> tells which one was returned.
        /// Requesting no PIN is only a preference: Windows still asks for it on keys that have a
        /// PIN set.
        /// </remarks>
        public static Fido2Secret GetSecret(IntPtr hwnd, IList<byte[]> allowedCredentialIds, byte[] prfInput, bool requirePin)
        {
            if (allowedCredentialIds == null || allowedCredentialIds.Count == 0)
                throw new ArgumentException("At least one credential id is required.", nameof(allowedCredentialIds));

            using (var mem = new NativeArena())
            {
                var credentials = (Credential*)mem.Allocate(sizeof(Credential) * allowedCredentialIds.Count);
                IntPtr publicKey = mem.String("public-key");
                for (int i = 0; i < allowedCredentialIds.Count; i++)
                {
                    credentials[i] = new Credential
                    {
                        dwVersion = 1,
                        cbId = (uint)allowedCredentialIds[i].Length,
                        pbId = mem.Bytes(allowedCredentialIds[i]),
                        pwszCredentialType = publicKey,
                    };
                }

                var clientData = CreateClientData(mem, "webauthn.get");
                var salt = new HmacSecretSalt { cbFirst = (uint)prfInput.Length, pbFirst = mem.Bytes(prfInput) };
                var saltValues = new HmacSecretSaltValues { pGlobalHmacSalt = &salt };
                var options = new GetAssertionOptions
                {
                    dwVersion = WebAuthnNative.GetAssertionOptionsVersion,
                    dwTimeoutMilliseconds = Timeout,
                    CredentialList = new Credentials { cCredentials = (uint)allowedCredentialIds.Count, pCredentials = credentials },
                    dwAuthenticatorAttachment = WebAuthnNative.AttachmentCrossPlatform,
                    dwUserVerificationRequirement = requirePin ? WebAuthnNative.UserVerificationRequired : WebAuthnNative.UserVerificationDiscouraged,
                    pHmacSecretSaltValues = &saltValues,
                };

                int hr = WebAuthnNative.WebAuthNAuthenticatorGetAssertion(hwnd, Protocol.RpId, &clientData, &options, out IntPtr result);
                ThrowOnError(hr, "The security key could not be used");
                try
                {
                    var assertion = (Assertion*)result;
                    if (assertion->pHmacSecret == null || assertion->pHmacSecret->cbFirst == 0)
                        throw new UnlockFailedException("The security key did not return an hmac-secret.");

                    if (assertion->cbAuthenticatorData < 33)
                        throw new UnlockFailedException("The security key returned malformed authenticator data.");
                    byte flags = Marshal.ReadByte(assertion->pbAuthenticatorData, 32);

                    return new Fido2Secret(
                        Copy(assertion->Credential.pbId, assertion->Credential.cbId),
                        Copy(assertion->pHmacSecret->pbFirst, assertion->pHmacSecret->cbFirst),
                        (flags & WebAuthnNative.AuthenticatorDataUserVerified) != 0);
                }
                finally
                {
                    WebAuthnNative.WebAuthNFreeAssertion(result);
                }
            }
        }

        private static ClientData CreateClientData(NativeArena mem, string type)
        {
            // Nothing verifies the signature, so the challenge carries no meaning; the client
            // data only has to be well-formed.
            string challenge = Convert.ToBase64String(Envelope.RandomBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            byte[] json = Encoding.UTF8.GetBytes(
                "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + Protocol.RpId + "\"}");
            return new ClientData
            {
                dwVersion = 1,
                cbClientDataJSON = (uint)json.Length,
                pbClientDataJSON = mem.Bytes(json),
                pwszHashAlgId = mem.String("SHA-256"),
            };
        }

        private static bool HasHmacSecretOutput(Extensions extensions)
        {
            for (int i = 0; i < extensions.cExtensions; i++)
            {
                Extension extension = extensions.pExtensions[i];
                if (Marshal.PtrToStringUni(extension.pwszExtensionIdentifier) == "hmac-secret"
                    && extension.cbExtension == sizeof(int)
                    && *(int*)extension.pvExtension != 0)
                    return true;
            }
            return false;
        }

        private static void ThrowOnError(int hr, string message)
        {
            if (hr == 0) return;
            // webauthn.dll reports a dismissed prompt, a timeout and an unrecognised key all as
            // NotAllowedError; none of them warrant an error dialog.
            if (hr == ErrorCancelled) throw new UnlockCancelledException();
            string name = Marshal.PtrToStringUni(WebAuthnNative.WebAuthNGetErrorName(hr));
            throw new UnlockFailedException($"{message}: {name}", hr);
        }

        private static byte[] Copy(IntPtr pointer, uint length)
        {
            var bytes = new byte[length];
            Marshal.Copy(pointer, bytes, 0, (int)length);
            return bytes;
        }
    }

    internal sealed class Fido2Secret
    {
        public Fido2Secret(byte[] credentialId, byte[] secret, bool userVerified)
        {
            CredentialId = credentialId;
            Secret = secret;
            UserVerified = userVerified;
        }

        public byte[] CredentialId { get; }
        public byte[] Secret { get; }

        /// <summary>Whether the key checked its PIN (or built-in biometric) for this secret.</summary>
        public bool UserVerified { get; }
    }

    /// <summary>Unmanaged allocations that live for the duration of one native call.</summary>
    internal sealed class NativeArena : IDisposable
    {
        private readonly List<IntPtr> _allocations = new List<IntPtr>();

        public IntPtr String(string value) => Track(Marshal.StringToHGlobalUni(value));

        public IntPtr Bytes(byte[] value)
        {
            IntPtr pointer = Allocate(value.Length);
            Marshal.Copy(value, 0, pointer, value.Length);
            return pointer;
        }

        public IntPtr Allocate(int size)
        {
            IntPtr pointer = Marshal.AllocHGlobal(size);
            for (int i = 0; i < size; i++) Marshal.WriteByte(pointer, i, 0);
            return Track(pointer);
        }

        public void Dispose()
        {
            foreach (IntPtr pointer in _allocations) Marshal.FreeHGlobal(pointer);
            _allocations.Clear();
        }

        private IntPtr Track(IntPtr pointer)
        {
            _allocations.Add(pointer);
            return pointer;
        }
    }
}
