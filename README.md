# KeePass FIDO2

Unlock [KeePass 2](https://keepass.info) databases with **FIDO2 security keys** and **Windows Hello**, with as many backup keys as you like, while the master key keeps working exactly as before. And keep secrets out of `.env` files: **`kp run`** fills `kp://` references from KeePass after you approve with Windows Hello or a security key.

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
   - **security key**: a resident FIDO2 credential with the `hmac-secret` extension; the key's HMAC output for a per-database salt derives the wrapping key. Requires the key's PIN and a touch by default; touch-only is available for keys without a PIN (Windows always asks for the PIN on keys that have one).
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
| Another user on the same PC, or the network | Cannot reach `kp`'s named pipe: it only accepts the current Windows user and refuses network logons. |
| A program running as you asks `kp` for secrets | Gets nothing until you approve in KeePass, with Windows Hello or a security key when the database has one set up. |
| Code running as you while the database is open | Out of scope: it can read KeePass's memory, or wait for an approved command's environment. |

The derived key is equivalent to the master key **for this database file and its copies**, but does not reveal the password text, so it cannot be reused to sign in elsewhere. A weak master password can still be brute-forced from it.

## Secrets for programs: `kp`

`kp.exe` keeps secrets out of `.env` files. A `.env` holds references instead of values:

```dotenv
PORT=3000
DATABASE_URL=kp://Work/my-project/DATABASE_URL
STRIPE_API_KEY=kp://Work/my-project/STRIPE_API_KEY
GITHUB_USER=kp://Work/GitHub#UserName
```

```powershell
kp run -- docker compose up        # starts the command with the values filled in
kp run -f .env -f .env.local -- npm run dev
kp get kp://Work/GitHub#UserName   # one value
kp env --format powershell | Invoke-Expression
```

Each request opens an approval window in KeePass showing the program, the process that started it, the command, the folder and the entries. When the database has Windows Hello or a security key set up, approving requires it; you can let KeePass remember the approval for that program, folder and set of values for 8 hours (until the database is locked). If KeePass is not running, `kp` starts it; if the database is locked, KeePass asks to unlock it first. Use `--database PATH` (or `KP_DATABASE`) to pick a database and `--keepass PATH` (or `KP_KEEPASS`) for a portable KeePass.

Tools such as Docker Compose, Node's `dotenv` and `python-dotenv` give variables already in the environment precedence over the `.env` file, so they see the real values even though the file only contains references.

### Moving existing values into KeePass

```powershell
kp import --group Work/my-project                      # pick variables interactively
kp import --group Work/my-project --match "*SECRET*" --match "STRIPE_*"
kp import -f .env.production --group Work/my-project --all --on-conflict skip --dry-run
```

`kp import` creates one entry per variable (title = variable name, value in the password field) in the group, after an approval in KeePass, saves the database and then replaces the values in the file with references. Old values can still live in editor backups, sync history or git history; rotate secrets that were ever committed or shared.

### WSL

`kp.exe` cannot start Linux programs, so `kp-run` (next to `kp.exe`) asks it for the variables and starts the command itself:

```bash
KP_EXE=/mnt/c/Tools/kp.exe kp-run -- docker compose up
```

### References

| Form | Meaning |
|---|---|
| `kp://Group/Sub/Entry` | Password of the entry titled *Entry* in *Group / Sub* (the root group's name may be included or left out) |
| `kp://Group/Entry#UserName` | Another field: `Title`, `UserName`, `URL`, `Notes` or a custom field |
| `kp://uuid/<32 hex digits>#Field` | An entry by UUID, independent of renames |

Names containing `/`, `#`, `%`, quotes, backslashes or spaces are percent-encoded (`kp://Shared%20drives/…`).

## Stable identifiers

These are baked into credentials on users' keys and in the unlock store. They never change, even if the project is renamed (see `src/KeePassFido2/Protocol.cs`):

- WebAuthn relying party id: `keepass-fido2`
- Windows Hello key name: `<user SID>//keepass-fido2//unlock`
- Key derivation and authentication labels: `keepass-fido2/*/v1`
- Reference syntax in `.env` files: `kp://…` (see `src/Shared/References/SecretReference.cs`)

## Requirements

- Windows 10 or 11, KeePass 2.x (developed against 2.61), .NET Framework 4.8
- A FIDO2 key with `hmac-secret` and a PIN, and/or Windows Hello
- *Enter master key on secure desktop* must be **off**: Windows cannot show Hello or security key prompts there.

## Installing (development builds)

Build `src/KeePassFido2`, copy `KeePassFido2.dll` into KeePass's `Plugins` folder and restart KeePass. Then use **Tools → KeePass FIDO2 → Manage unlock methods** with a database open.

For `kp`, build `src/Kp` and put `kp.exe` (and `kp-run` for WSL) in a folder on your `PATH`. It needs only .NET Framework 4.8, which ships with Windows 10 and 11.

## Development

```powershell
.\scripts\dev-setup.ps1   # isolated KeePass copy in .dev\, .dev\test.kdbx (password: test), .dev\sample-project\.env (fake values)
.\scripts\dev-run.ps1     # build, install plugin into the copy and kp.exe into .dev\bin, start KeePass with its own unlock store
dotnet test tests\KeePassFido2.Tests
```

`tools/HmacSpike` is a small command-line tool that checks whether a security key returns a stable `hmac-secret` through `webauthn.dll`.

## Roadmap

- Option to require the master key once after every reboot
- Release packaging (`.plgx`, `kp.exe`) and a listing on the KeePass plugin page

## License

[GPL-3.0-or-later](LICENSE). KeePass is © Dominik Reichl, GPL-2.0-or-later.
