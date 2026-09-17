// Spike: can a non-admin process derive a stable secret from a USB FIDO2 key
// via webauthn.dll's hmac-secret / PRF support?
//
//   HmacSpike make [platform]  create a resident credential with hmac-secret enabled
//                           ("platform" targets Windows Hello instead of an external key)
//   HmacSpike assert [platform] [raw] [touch-only] [salt=<label>]
//                           get an assertion with a salt (default fixed) and print a
//                           fingerprint of the derived secret ("raw" passes the salt as
//                           a raw hmac-secret salt instead of a PRF input)
//
// Struct layouts mirror microsoft/webauthn webauthn.h (API version 9).

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

unsafe
{
    const string RpId = "keepass-agent-bridge";
    bool platform = args.Contains("platform");
    string credFile = Path.Combine(AppContext.BaseDirectory, platform ? "credential-platform.id" : "credential.id");
    string? saltLabel = args.FirstOrDefault(x => x.StartsWith("salt="))?[5..];
    byte[] salt = SHA256.HashData(Encoding.UTF8.GetBytes(saltLabel ?? "keepass-agent-bridge spike salt v1"));

    Console.WriteLine($"webauthn API version: {Native.WebAuthNGetApiVersionNumber()}");
    string mode = args.Length > 0 ? args[0] : "";

    if (mode == "make")
    {
        using var mem = new Arena();
        var rp = new RpEntity { dwVersion = 1, pwszId = mem.Str(RpId), pwszName = mem.Str("KeePass Agent Bridge (test)") };
        byte[] userId = "spike"u8.ToArray();
        var user = new UserEntity { dwVersion = 1, cbId = (uint)userId.Length, pbId = mem.Bytes(userId),
            pwszName = mem.Str("keepass-agent-bridge-test"), pwszDisplayName = mem.Str("keepass-agent-bridge-test") };
        var param = new CoseParam { dwVersion = 1, pwszCredentialType = mem.Str("public-key"), lAlg = -7 };
        var pars = new CoseParams { cCredentialParameters = 1, pCredentialParameters = &param };
        byte[] cdj = Encoding.UTF8.GetBytes("{\"type\":\"webauthn.create\",\"challenge\":\"c3Bpa2U\",\"origin\":\"keepass-agent-bridge\"}");
        var cd = new ClientData { dwVersion = 1, cbClientDataJSON = (uint)cdj.Length, pbClientDataJSON = mem.Bytes(cdj), pwszHashAlgId = mem.Str("SHA-256") };

        int bTrue = 1;
        var ext = new Extension { pwszExtensionIdentifier = mem.Str("hmac-secret"), cbExtension = 4, pvExtension = (IntPtr)(&bTrue) };
        var opts = new MakeCredentialOptions
        {
            dwVersion = 9,
            dwTimeoutMilliseconds = 120_000,
            Extensions = new Extensions { cExtensions = 1, pExtensions = &ext },
            dwAuthenticatorAttachment = platform ? 1u : 2u, // 1 = Windows Hello, 2 = external key
            bRequireResidentKey = 1,                // webauthn.dll drops hmac-secret for non-resident credentials
            dwUserVerificationRequirement = 1,      // PIN required
            dwAttestationConveyancePreference = 1,  // none
        };

        IntPtr att;
        int hr = Native.WebAuthNAuthenticatorMakeCredential(Native.GetForegroundWindow(), &rp, &user, &pars, &cd, &opts, out att);
        if (hr != 0) { Fail("MakeCredential", hr); return 1; }
        var a = (CredentialAttestation*)att;
        byte[] credId = new ReadOnlySpan<byte>((void*)a->pbCredentialId, (int)a->cbCredentialId).ToArray();
        File.WriteAllText(credFile, Convert.ToHexString(credId));
        Console.WriteLine($"OK  attestation v{a->dwVersion}, credential id {credId.Length} bytes, residentKey={a->bResidentKey}, prfEnabled={a->bPrfEnabled}");
        for (int i = 0; i < a->Extensions.cExtensions; i++)
        {
            var e = a->Extensions.pExtensions[i];
            string val = e.cbExtension == 4 ? (*(int*)e.pvExtension).ToString() : $"{e.cbExtension} bytes";
            Console.WriteLine($"    extension output: {Marshal.PtrToStringUni(e.pwszExtensionIdentifier)} = {val}");
        }
        var authData = new ReadOnlySpan<byte>((void*)a->pbAuthenticatorData, (int)a->cbAuthenticatorData);
        Console.WriteLine($"    authData ED flag={(authData[32] & 0x80) != 0}, contains \"hmac-secret\": {authData.IndexOf("hmac-secret"u8) >= 0}");
        Native.WebAuthNFreeCredentialAttestation(att);
        return 0;
    }

    if (mode == "assert")
    {
        bool raw = args.Contains("raw");
        bool touchOnly = args.Contains("touch-only");
        byte[] credId = Convert.FromHexString(File.ReadAllText(credFile).Trim());
        using var mem = new Arena();
        byte[] cdj = Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":\"c3Bpa2U\",\"origin\":\"keepass-agent-bridge\"}");
        var cd = new ClientData { dwVersion = 1, cbClientDataJSON = (uint)cdj.Length, pbClientDataJSON = mem.Bytes(cdj), pwszHashAlgId = mem.Str("SHA-256") };

        var cred = new Credential { dwVersion = 1, cbId = (uint)credId.Length, pbId = mem.Bytes(credId), pwszCredentialType = mem.Str("public-key") };
        var hsalt = new HmacSecretSalt { cbFirst = (uint)salt.Length, pbFirst = mem.Bytes(salt) };
        var saltValues = new HmacSecretSaltValues { pGlobalHmacSalt = &hsalt };
        var opts = new GetAssertionOptions
        {
            dwVersion = 9,
            dwTimeoutMilliseconds = 120_000,
            CredentialList = new Credentials { cCredentials = 1, pCredentials = &cred },
            dwAuthenticatorAttachment = platform ? 1u : 2u,
            dwUserVerificationRequirement = touchOnly ? 3u : 1u, // 3 = discouraged: touch only
            dwFlags = raw ? 0x00100000u : 0u,       // WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG
            pHmacSecretSaltValues = &saltValues,
        };

        IntPtr asr;
        int hr = Native.WebAuthNAuthenticatorGetAssertion(Native.GetForegroundWindow(), mem.Str(RpId), &cd, &opts, out asr);
        if (hr != 0) { Fail("GetAssertion", hr); return 1; }
        var s = (Assertion*)asr;
        byte flags = Marshal.ReadByte(s->pbAuthenticatorData, 32);
        Console.WriteLine($"OK  assertion v{s->dwVersion} ({(raw ? "raw salt" : "PRF salt")}, requested {(touchOnly ? "touch only" : "PIN + touch")}, user verified={(flags & 0x04) != 0})");
        if (s->pHmacSecret == null || s->pHmacSecret->cbFirst == 0)
        {
            Console.WriteLine("    NO hmac-secret output returned");
            Native.WebAuthNFreeAssertion(asr);
            return 2;
        }
        var secret = new ReadOnlySpan<byte>((void*)s->pHmacSecret->pbFirst, (int)s->pHmacSecret->cbFirst);
        // Only a fingerprint is printed; the derived secret itself never leaves the process.
        Console.WriteLine($"    hmac-secret: {secret.Length} bytes, fingerprint {Convert.ToHexString(SHA256.HashData(secret))[..16]}");
        Native.WebAuthNFreeAssertion(asr);
        return 0;
    }

    Console.WriteLine("usage: HmacSpike make [platform] | assert [platform] [raw] [touch-only] [salt=<label>]");
    return 64;
}

static void Fail(string op, int hr) =>
    Console.WriteLine($"FAIL {op}: 0x{hr:X8} {Marshal.PtrToStringUni(Native.WebAuthNGetErrorName(hr))}");

sealed class Arena : IDisposable
{
    private readonly List<IntPtr> _allocs = new();
    public IntPtr Str(string s) { var p = Marshal.StringToHGlobalUni(s); _allocs.Add(p); return p; }
    public IntPtr Bytes(byte[] b) { var p = Marshal.AllocHGlobal(b.Length); Marshal.Copy(b, 0, p, b.Length); _allocs.Add(p); return p; }
    public void Dispose() { foreach (var p in _allocs) Marshal.FreeHGlobal(p); }
}

static unsafe class Native
{
    [DllImport("webauthn.dll")] public static extern uint WebAuthNGetApiVersionNumber();
    [DllImport("webauthn.dll")] public static extern int WebAuthNAuthenticatorMakeCredential(IntPtr hWnd, RpEntity* rp, UserEntity* user, CoseParams* pars, ClientData* cd, MakeCredentialOptions* opts, out IntPtr attestation);
    [DllImport("webauthn.dll")] public static extern int WebAuthNAuthenticatorGetAssertion(IntPtr hWnd, IntPtr rpId, ClientData* cd, GetAssertionOptions* opts, out IntPtr assertion);
    [DllImport("webauthn.dll")] public static extern void WebAuthNFreeCredentialAttestation(IntPtr p);
    [DllImport("webauthn.dll")] public static extern void WebAuthNFreeAssertion(IntPtr p);
    [DllImport("webauthn.dll")] public static extern IntPtr WebAuthNGetErrorName(int hr);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}

[StructLayout(LayoutKind.Sequential)] struct RpEntity { public uint dwVersion; public IntPtr pwszId, pwszName, pwszIcon; }
[StructLayout(LayoutKind.Sequential)] struct UserEntity { public uint dwVersion; public uint cbId; public IntPtr pbId, pwszName, pwszIcon, pwszDisplayName; }
[StructLayout(LayoutKind.Sequential)] struct ClientData { public uint dwVersion; public uint cbClientDataJSON; public IntPtr pbClientDataJSON, pwszHashAlgId; }
[StructLayout(LayoutKind.Sequential)] struct CoseParam { public uint dwVersion; public IntPtr pwszCredentialType; public int lAlg; }
[StructLayout(LayoutKind.Sequential)] unsafe struct CoseParams { public uint cCredentialParameters; public CoseParam* pCredentialParameters; }
[StructLayout(LayoutKind.Sequential)] struct Credential { public uint dwVersion; public uint cbId; public IntPtr pbId, pwszCredentialType; }
[StructLayout(LayoutKind.Sequential)] unsafe struct Credentials { public uint cCredentials; public Credential* pCredentials; }
[StructLayout(LayoutKind.Sequential)] struct Extension { public IntPtr pwszExtensionIdentifier; public uint cbExtension; public IntPtr pvExtension; }
[StructLayout(LayoutKind.Sequential)] unsafe struct Extensions { public uint cExtensions; public Extension* pExtensions; }
[StructLayout(LayoutKind.Sequential)] struct HmacSecretSalt { public uint cbFirst; public IntPtr pbFirst; public uint cbSecond; public IntPtr pbSecond; }
[StructLayout(LayoutKind.Sequential)] unsafe struct HmacSecretSaltValues { public HmacSecretSalt* pGlobalHmacSalt; public uint cCredWithHmacSecretSaltList; public IntPtr pCredWithHmacSecretSaltList; }

[StructLayout(LayoutKind.Sequential)]
struct MakeCredentialOptions
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
unsafe struct GetAssertionOptions
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
struct CredentialAttestation
{
    public uint dwVersion; public IntPtr pwszFormatType;
    public uint cbAuthenticatorData; public IntPtr pbAuthenticatorData;
    public uint cbAttestation; public IntPtr pbAttestation;
    public uint dwAttestationDecodeType; public IntPtr pvAttestationDecode;
    public uint cbAttestationObject; public IntPtr pbAttestationObject;
    public uint cbCredentialId; public IntPtr pbCredentialId;
    public Extensions Extensions;
    public uint dwUsedTransport;
    public int bEpAtt, bLargeBlobSupported, bResidentKey, bPrfEnabled;
    // Later fields are not read.
}

[StructLayout(LayoutKind.Sequential)]
unsafe struct Assertion
{
    public uint dwVersion;
    public uint cbAuthenticatorData; public IntPtr pbAuthenticatorData;
    public uint cbSignature; public IntPtr pbSignature;
    public Credential Credential;
    public uint cbUserId; public IntPtr pbUserId;
    public Extensions Extensions;
    public uint cbCredLargeBlob; public IntPtr pbCredLargeBlob; public uint dwCredLargeBlobStatus;
    public HmacSecretSalt* pHmacSecret;
    // Later fields are not read.
}
