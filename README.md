# KeePass FIDO2

Unlock [KeePass 2](https://keepass.info) databases with **FIDO2 security keys** and **Windows Hello**, with as many backup keys as you like, while the master key keeps working exactly as before.

> **Status: early development (0.1).** Try it on a copy of a database, and keep your master key at hand.

## Why

People have asked for FIDO2 support in KeePass for years. Existing options either replace the master password with a single key, need a YubiKey-specific challenge-response mode, or only work in other KeePass ports. This plugin:

- works with **any FIDO2 key that supports `hmac-secret`** (tested on a NEOWAVE Winkeo FIDO2), through Windows' own WebAuthn API: no admin rights, no vendor tools;
- supports **several keys per database**, so a backup key can stay at home;
- supports **Windows Hello** (face, fingerprint or Hello PIN) as a day-to-day method;
- does **not change the database**: the master key stays valid, and people who share the database without the plugin are not affected.

## How it works

When you add an unlock method to an open database, the plugin:

1. captures the database's **derived key data**: for a master password that is KeePass's SHA-256 hash of it, never the password text;
2. encrypts that snapshot with a random **data key** (AES-256-CBC + HMAC-SHA256);
3. stores a copy of the data key **wrapped by each unlock method**:
   - **security key**: a resident FIDO2 credential with the `hmac-secret` extension; the key's HMAC output for a per-database salt derives the wrapping key. Requires the key's PIN and a touch.
   - **Windows Hello**: an RSA key in the TPM via the Microsoft Passport key storage provider, created so that every use requires a Hello gesture.

When KeePass asks for the master key, the plugin adds *Windows Hello* and *Security key* buttons to the prompt; typing the master key works as usual. *Tools → KeePass FIDO2 → Start Windows Hello automatically* starts Windows Hello as soon as the prompt opens instead. The released snapshot is handed to KeePass as if you had typed the master key.

If the master key changes, the stored snapshot stops working. Enter the master key once and the plugin updates the snapshot for every method at the same time.

Unlock data lives in `%LOCALAPPDATA%\keepass-fido2\unlock.xml`. It holds only ciphertext and FIDO2 credential ids.

### Security model

| Attacker has | Result |
|---|---|
| A copy of `unlock.xml` | Nothing usable without one of your security keys (with its PIN) or your Windows Hello on this PC. |
| Your laptop, without your face/Hello PIN or security key | Cannot unlock through the plugin. |
| Your laptop **and** your Windows Hello PIN | Can unlock databases that have Windows Hello set up. Use a strong Hello PIN, or set up security keys only. |
| Code running as you while the database is open | Out of scope: it can read KeePass's memory anyway. |

The derived key is equivalent to the master key **for this database file and its copies**, but does not reveal the password text, so it cannot be reused to sign in elsewhere. A weak master password can still be brute-forced from it.

## Stable identifiers

These are baked into credentials on users' keys and in the unlock store. They never change, even if the project is renamed (see `src/KeePassFido2/Protocol.cs`):

- WebAuthn relying party id: `keepass-fido2`
- Windows Hello key name: `<user SID>//keepass-fido2//unlock`
- Key derivation and authentication labels: `keepass-fido2/*/v1`

## Requirements

- Windows 10 or 11, KeePass 2.x (developed against 2.61), .NET Framework 4.8
- A FIDO2 key with `hmac-secret` and a PIN, and/or Windows Hello
- *Enter master key on secure desktop* must be **off**: Windows cannot show Hello or security key prompts there.

## Installing (development builds)

Build `src/KeePassFido2`, copy `KeePassFido2.dll` into KeePass's `Plugins` folder and restart KeePass. Then use **Tools → KeePass FIDO2** with a database open.

## Development

```powershell
.\scripts\dev-setup.ps1   # isolated KeePass copy in .dev\ plus .dev\test.kdbx (password: test)
.\scripts\dev-run.ps1     # build, install into the copy, start it with its own unlock store
dotnet test tests\KeePassFido2.Tests
```

`tools/HmacSpike` is a small command-line tool that checks whether a security key returns a stable `hmac-secret` through `webauthn.dll`.

## Roadmap

- Option to require the master key once after every reboot
- Manage and remove individual unlock methods
- `kp run -- <command>`: fill `kp://Group/Entry/Field` references in `.env` files for any process, after a Windows Hello or security key approval
- Release packaging (`.plgx`) and a listing on the KeePass plugin page

## License

[GPL-3.0-or-later](LICENSE). KeePass is © Dominik Reichl, GPL-2.0-or-later.
