namespace KeePassFido2
{
    /// <summary>
    /// Identifiers that end up in credentials on users' authenticators, in the Windows Hello
    /// key store and in the unlock store. Changing any of them makes existing enrollments
    /// unusable, so they stay fixed even if the project or plugin is renamed.
    /// </summary>
    internal static class Protocol
    {
        /// <summary>WebAuthn relying party id of every credential this plugin creates.</summary>
        public const string RpId = "keepass-fido2";

        public const string RpName = "KeePass FIDO2";

        /// <summary>Windows Hello (Microsoft Passport KSP) key name, after the user's SID.</summary>
        public const string HelloKeySuffix = "//keepass-fido2//unlock";

        /// <summary>Derives the wrapping key from a FIDO2 hmac-secret (PRF) output.</summary>
        public const string Fido2WrapKeyLabel = "keepass-fido2/fido2-wrap-key/v1";

        /// <summary>Authenticated context of the encrypted master key snapshot.</summary>
        public const string PayloadContext = "keepass-fido2/payload/v1";

        /// <summary>Authenticated context of a data key wrapped for one unlock method.</summary>
        public const string WrapContext = "keepass-fido2/wrap/v1";

        public const int StoreVersion = 1;
    }
}
