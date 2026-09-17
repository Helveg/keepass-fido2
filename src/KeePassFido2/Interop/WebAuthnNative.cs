using System;
using System.Runtime.InteropServices;

namespace KeePassFido2.Interop
{
    // Layouts mirror microsoft/webauthn webauthn.h (API version 9). Only fields up to the ones
    // this plugin reads are declared on output structs; input structs are declared in full
    // because dwVersion tells webauthn.dll how far it may read.

    internal static unsafe class WebAuthnNative
    {
        public const uint AttachmentCrossPlatform = 2;
        public const uint UserVerificationRequired = 1;
        public const uint UserVerificationDiscouraged = 3;
        /// <summary>"UV" bit in the flags byte of authenticator data (offset 32, after the rpId hash).</summary>
        public const byte AuthenticatorDataUserVerified = 0x04;
        public const uint AttestationNone = 1;
        public const uint MakeCredentialOptionsVersion = 9;
        public const uint GetAssertionOptionsVersion = 9;
        public const int CoseAlgorithmEs256 = -7;

        [DllImport("webauthn.dll")]
        public static extern uint WebAuthNGetApiVersionNumber();

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNAuthenticatorMakeCredential(IntPtr hWnd, RpEntity* rp, UserEntity* user,
            CoseParams* pubKeyCredParams, ClientData* clientData, MakeCredentialOptions* options, out IntPtr attestation);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNAuthenticatorGetAssertion(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] string rpId,
            ClientData* clientData, GetAssertionOptions* options, out IntPtr assertion);

        [DllImport("webauthn.dll")]
        public static extern void WebAuthNFreeCredentialAttestation(IntPtr attestation);

        [DllImport("webauthn.dll")]
        public static extern void WebAuthNFreeAssertion(IntPtr assertion);

        [DllImport("webauthn.dll")]
        public static extern IntPtr WebAuthNGetErrorName(int hr);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RpEntity { public uint dwVersion; public IntPtr pwszId, pwszName, pwszIcon; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UserEntity { public uint dwVersion; public uint cbId; public IntPtr pbId, pwszName, pwszIcon, pwszDisplayName; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ClientData { public uint dwVersion; public uint cbClientDataJSON; public IntPtr pbClientDataJSON, pwszHashAlgId; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CoseParam { public uint dwVersion; public IntPtr pwszCredentialType; public int lAlg; }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct CoseParams { public uint cCredentialParameters; public CoseParam* pCredentialParameters; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Credential { public uint dwVersion; public uint cbId; public IntPtr pbId, pwszCredentialType; }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct Credentials { public uint cCredentials; public Credential* pCredentials; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Extension { public IntPtr pwszExtensionIdentifier; public uint cbExtension; public IntPtr pvExtension; }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct Extensions { public uint cExtensions; public Extension* pExtensions; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct HmacSecretSalt { public uint cbFirst; public IntPtr pbFirst; public uint cbSecond; public IntPtr pbSecond; }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct HmacSecretSaltValues { public HmacSecretSalt* pGlobalHmacSalt; public uint cCredWithHmacSecretSaltList; public IntPtr pCredWithHmacSecretSaltList; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MakeCredentialOptions
    {
        public uint dwVersion, dwTimeoutMilliseconds;
        public Credentials CredentialList;
        public Extensions Extensions;
        public uint dwAuthenticatorAttachment;
        public int bRequireResidentKey;
        public uint dwUserVerificationRequirement, dwAttestationConveyancePreference, dwFlags;
        public IntPtr pCancellationId, pExcludeCredentialList;
        public uint dwEnterpriseAttestation, dwLargeBlobSupport;
        public int bPreferResidentKey, bBrowserInPrivateMode, bEnablePrf;
        public IntPtr pLinkedDevice;
        public uint cbJsonExt; public IntPtr pbJsonExt;
        public IntPtr pPRFGlobalEval;
        public uint cCredentialHints; public IntPtr ppwszCredentialHints;
        public int bThirdPartyPayment;
        public IntPtr pwszRemoteWebOrigin;
        public uint cbPublicKeyCredentialCreationOptionsJSON; public IntPtr pbPublicKeyCredentialCreationOptionsJSON;
        public uint cbAuthenticatorId; public IntPtr pbAuthenticatorId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct GetAssertionOptions
    {
        public uint dwVersion, dwTimeoutMilliseconds;
        public Credentials CredentialList;
        public Extensions Extensions;
        public uint dwAuthenticatorAttachment, dwUserVerificationRequirement, dwFlags;
        public IntPtr pwszU2fAppId, pbU2fAppId, pCancellationId, pAllowCredentialList;
        public uint dwCredLargeBlobOperation, cbCredLargeBlob; public IntPtr pbCredLargeBlob;
        public HmacSecretSaltValues* pHmacSecretSaltValues;
        public int bBrowserInPrivateMode;
        public IntPtr pLinkedDevice;
        public int bAutoFill;
        public uint cbJsonExt; public IntPtr pbJsonExt;
        public uint cCredentialHints; public IntPtr ppwszCredentialHints;
        public IntPtr pwszRemoteWebOrigin;
        public uint cbPublicKeyCredentialRequestOptionsJSON; public IntPtr pbPublicKeyCredentialRequestOptionsJSON;
        public uint cbAuthenticatorId; public IntPtr pbAuthenticatorId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CredentialAttestation
    {
        public uint dwVersion; public IntPtr pwszFormatType;
        public uint cbAuthenticatorData; public IntPtr pbAuthenticatorData;
        public uint cbAttestation; public IntPtr pbAttestation;
        public uint dwAttestationDecodeType; public IntPtr pvAttestationDecode;
        public uint cbAttestationObject; public IntPtr pbAttestationObject;
        public uint cbCredentialId; public IntPtr pbCredentialId;
        public Extensions Extensions;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct Assertion
    {
        public uint dwVersion;
        public uint cbAuthenticatorData; public IntPtr pbAuthenticatorData;
        public uint cbSignature; public IntPtr pbSignature;
        public Credential Credential;
        public uint cbUserId; public IntPtr pbUserId;
        public Extensions Extensions;
        public uint cbCredLargeBlob; public IntPtr pbCredLargeBlob; public uint dwCredLargeBlobStatus;
        public HmacSecretSalt* pHmacSecret;
    }
}
