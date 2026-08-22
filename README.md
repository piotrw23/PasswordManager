# pass-mgr

A local, offline password manager for the command line, written in Java.

Everything stays in a single SQLite file on your own machine — there is no server, no sync and no
network access anywhere in the code. The vault is unlocked with one master password, which is never
stored: it only ever exists as a key derived on the fly with Argon2id.

> **Status: work in progress.** This is a learning project and it has not been audited by anyone.
> The `generate` command works; the vault itself (`init`, storing and reading entries) is still
> being built. Don't put passwords you actually rely on in it yet.

## Requirements

- **JDK 21 or newer** (`maven.compiler.release` is set to 21)
- **A POSIX filesystem** — Linux or macOS. The vault directory is created as `rwx------` and
  `VaultPaths` refuses to run where POSIX permissions are unavailable, rather than silently leaving
  the vault readable by other accounts on the machine.
- Maven is not needed separately; the repository ships the Maven wrapper (`./mvnw`).

## Build and test

```bash
./mvnw test        # runs the full suite
./mvnw package     # compiles and produces target/PasswordManager-1.0-SNAPSHOT.jar
```

## Running

Executable packaging (a jar with a `Main-Class` and the dependencies bundled) isn't set up yet, so
for now run the app off the compiled classes and the resolved dependency classpath:

```bash
./mvnw -q compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes:$(cat target/cp.txt)" cli.PassMgrApp generate --length 20
```

```
Generated password:
L8+:W}KnrCT.pZ/5@QE(
Password's entropy: 129.51466861932795
```

### Commands

| Command | Description |
| --- | --- |
| `generate` | Generates a strong random password and reports its entropy. |
| `init` | Creates a new vault. **Not implemented yet.** |

`generate` takes `-l` / `--length` (default 16, allowed range 8–256). Passwords are drawn from
`SecureRandom` over lowercase, uppercase, digits and punctuation, and are re-drawn until they
contain at least one digit and one special character. The generated password is held in a `char[]`
and wiped with `Arrays.fill` as soon as it has been printed, so it isn't left sitting in the string
pool.

Appending `--help` — to the app itself or to any command — prints the usual picocli usage text.

## How the vault is protected

These are the pieces already implemented, under `src/main/java/crypto/`.

**Key derivation — `KeyDerivation`, `KdfParams`.** The master password is stretched into the vault
key with Argon2id (Bouncy Castle), by default 64 MiB of memory, 3 iterations, 1 lane, producing a
32-byte key for AES-256. Every intermediate buffer is wiped; the caller's own password array is
left alone, because only the caller knows when it is done with it.

The cost settings are not hardcoded into the unlock path. They are encoded as
`argon2id$v=19$m=65536,t=3,p=1,k=32` and stored alongside the vault, so raising the defaults later
doesn't lock anyone out of a vault created under the old ones.

**Encryption — `CryptoService`, `EncryptedData`.** One class does all encryption and decryption:
AES-256-GCM with a fresh 12-byte IV drawn from `SecureRandom` for every single call and a 128-bit
authentication tag. GCM is an AEAD mode, so it both hides the contents and detects tampering — no
separate MAC is involved. `EncryptedData` carries an IV together with its ciphertext, validates
their lengths when constructed and copies both arrays in and out so a stored record can't be
mutated behind its own back.

A failed tag check surfaces as `AEADBadTagException` and is deliberately left to propagate: only
the caller has the context to tell "wrong master password" apart from "damaged vault".

**Location — `VaultPaths`.** The vault lives in `$PASS_MGR_HOME`, falling back to `~/.pass-mgr/`,
with the database at `vault.db` inside it. The directory is created owner-only in a single call, so
there is no window in which it exists with looser permissions, and `hasSecurePermissions()` can
check a pre-existing directory before it gets used.

## Project layout

```
src/main/java/
├── cli/        picocli entry point (PassMgrApp) and commands
├── core/       vault-independent logic: PasswordGenerator, VaultPaths
└── crypto/     KdfParams, KeyDerivation, CryptoService, EncryptedData
```

Tests mirror this layout under `src/test/java/`. `PASS_MGR_HOME` also makes the vault easy to point
at a `@TempDir` in tests instead of a real home directory.

## Roadmap

- [x] Password generator and the `generate` command
- [x] Vault location and owner-only directory handling
- [x] Argon2id key derivation with stored, versioned parameters
- [x] AES-GCM encryption service
- [ ] SQLite storage layer and schema (`vault_meta`, `entries`)
- [ ] `VaultInitializer` — salt, wrapped data key, encrypted canary, written in one transaction
- [ ] The `init` command: password prompt with confirmation, `--force`, meaningful exit codes
- [ ] `add`, `get`, `list` and `remove` for entries

## Design notes

The vault key derived from the master password is not used to encrypt entries directly. It wraps a
separate randomly generated data key, which is what the entries are encrypted under. That extra
step is what makes changing the master password a matter of re-wrapping one key instead of
re-encrypting the whole vault.

Unlocking is verified with a *canary*: a known value encrypted at init time. If it decrypts, the
password was right; if the tag check fails, it wasn't. This means a wrong password is detected
without ever storing the password or a hash of it.
