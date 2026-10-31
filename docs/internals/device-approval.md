# Device approval

When an agent that T3 started runs `sudo`, a phone approves that one command with
a hardware-backed key. Four components share the formats below: the root-owned
PAM module and `t3-elevation` helper (Rust), the T3 server (TypeScript), the
Android signer (Kotlin), and the clients. Every format here is versioned; a
change that an older peer would misread needs a new version number.

## Trust model

- The PAM module runs as root inside `sudo`. It builds the payload, keeps the
  nonce in its own memory, and verifies the signature itself.
- The T3 server runs as the user, the same uid as every agent. It is an
  untrusted relay: it can delay, drop, or deny, but it cannot approve.
- The phone holds the private key and signs exactly the payload bytes it
  rendered. No component re-serializes the payload, so there is no
  canonicalization.
- Thread attribution, the explanation, and every display field outside the
  payload are UX only.

## Encodings

- Binary values are base64url without padding (RFC 4648 §5). Decoders reject
  padding and characters outside `A-Z a-z 0-9 - _`.
- Times in the payload and socket messages are integer Unix seconds. Times in
  files are RFC 3339 UTC with a `Z` suffix.
- **keyId** = base64url of the first 16 bytes of `SHA-256(SPKI DER)`, 22
  characters. A keyId that does not match `^[A-Za-z0-9_-]{22}$` is rejected
  before it is used in a path.

## Signed payload (v1)

The module emits one compact JSON object, UTF-8, no BOM, no trailing newline,
at most **16384 bytes**. Keys appear in this order, with no others:

| Field                   | Type                               | Meaning                                                                                                                                                            |
| ----------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `v`                     | `1`                                | Payload version.                                                                                                                                                   |
| `kind`                  | `"sudo"`                           | Closed enum. Clients refuse kinds they don't know.                                                                                                                 |
| `nonce`                 | base64url, 32 bytes                | Fresh per request.                                                                                                                                                 |
| `issuedAt`, `expiresAt` | int                                | Module clock. `0 < expiresAt − issuedAt ≤ 300`.                                                                                                                    |
| `host`                  | `{ name, machineId }`              | `name` is `gethostname()`. `machineId` is base64url `SHA-256` of `/etc/machine-id` without its trailing newline (Linux) or of the `IOPlatformUUID` string (macOS). |
| `user`, `uid`           | string, int ≥ 0                    | The requesting user (real uid).                                                                                                                                    |
| `runAs`                 | string                             | Target user (`-u`, default `root`). An id names its user: `#0 (root)`.                                                                                             |
| `runAsGroup`            | string \| null                     | Target group from `-g`, else `null`. An id names its group: `#0 (wheel)`.                                                                                          |
| `argv`                  | string[]                           | sudo's own argv, unchanged.                                                                                                                                        |
| `command`               | `{ argv, resolvedPath, warnings }` | What sudo will run, from the module's parse of sudo's options.                                                                                                     |
| `cwd`                   | string                             | The caller's working directory.                                                                                                                                    |
| `service`               | string                             | `PAM_SERVICE` (`sudo`, `sudo-i`).                                                                                                                                  |
| `keyIds`                | string[]                           | keyIds enrolled for `user`, sorted.                                                                                                                                |

`command`:

- `argv`: the program and its arguments. `-s` and `-i` resolve to the shell
  (`$SHELL`, or the target user's login shell). `-e` gives
  `["sudoedit", ...files]`. If sudo's argv has any option the module does not
  fully understand, `argv` is sudo's argv without `argv[0]`, unparsed.
- `resolvedPath`: absolute path of the program sudo will execute, resolved with
  sudo's own PATH and `secure_path` rules, or `null` (unparsed, `-e`, not found,
  or not certain). sudo.ws searches relative PATH entries against the cwd and
  reads the last `PATH=` in its environment; sudo-rs skips relative entries and
  reads the first. On Linux either may be installed, so the module resolves
  with both and shows a path only when they agree.
- `warnings`: objects `{ "code": string, "arg"?: int }`. `arg` indexes
  `command.argv`. Codes in v1:

  | Code                     | When                                                                                                    |
  | ------------------------ | ------------------------------------------------------------------------------------------------------- |
  | `user_writable_program`  | `resolvedPath` is writable by the requesting user.                                                      |
  | `user_writable_argument` | `command.argv[arg]` is a path the user can change before it is used: one entry per argument. See below. |
  | `shell`                  | `-s`, `-i`, or the program is a shell.                                                                  |
  | `unparsed_options`       | sudo's options were not understood; `command.argv` is raw.                                              |
  | `edit`                   | `-e` / sudoedit.                                                                                        |
  | `unresolved_program`     | The module can't tell which file sudo will run; `resolvedPath` is `null`.                               |
  | `dev_attestation`        | `command.argv[arg]` is `--allow-dev-attestation`: a debug build of the app may enroll.                  |
  | `test_attestation`       | `command.argv[arg]` is `--allow-test-attestation`: an emulator or unverified device may enroll.         |

  An argument gets `user_writable_argument` when it exists and the user can
  write it, replace it (a writable directory on the way), or change what it
  points to (a symlink whose target is replaceable), or when it doesn't exist,
  contains `/` or `.`, and the user can create it (its nearest existing
  ancestor is replaceable). Missing bare words are skipped, so
  `systemctl restart nginx` from a project directory stays clean.

  Clients render an unknown code as a generic red warning showing the code. A
  warning only adds caution, so this is safe without a version bump.

Decoding (clients, `decodeElevationPayload` in contracts) checks, in order, and
returns the first failure: `too_large` (over 16384 bytes), `invalid_json`
(invalid UTF-8, BOM, not a single JSON object), `unsupported_version`
(`v` ≠ 1), `unknown_kind`, then `invalid` (missing or extra keys, wrong types,
bad lengths, the time rule). Clients that sign must decode the bytes they sign
and render only from the result.

Argv or cwd bytes that are not valid UTF-8 can't be shown faithfully, so the
module fails the stack with `invalid_encoding` instead of building a payload.

### Signature

- Context: the 16 ASCII bytes `t3-elevation-v1` followed by one `0x00`.
- Signed message: `context || payload`.
- Response object, identical on the RPC and on the socket:
  `{ keyId, alg, signature, webauthn? }`.
  - `es256-der`: ECDSA P-256 with SHA-256 over the message; `signature` is the
    DER `SEQUENCE { r, s }`. Android `SHA256withECDSA` produces this directly.
    High-S signatures are accepted; signatures are never used as identifiers.
  - `webauthn-es256`: reserved. The challenge will be `SHA-256(context || payload)`
    and `webauthn` carries `authenticatorData` and `clientDataJSON` (base64url).
    The v1 module returns `unsupported_alg`.

The module verifies in this order and stops at the first failure:
`unsupported_alg` → `unknown_key` (keyId not enrolled) → `expired` (module clock
`now ≥ expiresAt`) → `bad_signature` (anything else, including non-DER input).
The server runs the same signature check before forwarding an approval, so a
bad answer from one client doesn't consume the request.

### Display escaping

Every string from the payload is shown through `escapeElevationDisplayText`. It maps each
code point and leaves everything else unchanged:

- `\` → `\\`; LF → `\n`; CR → `\r`; TAB → `\t`;
- every other code point in general category Cc, Cf, Cs, Zl, Zp, or Zs except
  U+0020, every `Default_Ignorable_Code_Point`, and U+2800 (braille blank) →
  `\u{HEX}`, uppercase hex without leading zeros (`\u{1B}`, `\u{202E}`).

That covers ANSI escapes, bidi controls, zero-width characters, line separators,
look-alike spaces, and blank letters such as U+3164 that make an argument look
empty or two arguments look the same. Clients show the whole argv, one element per entry, and
never truncate it silently.

## Enrollment and the comparison code

**Comparison code**: take the first 50 bits of `SHA-256(SPKI DER)`, most
significant bit first, as ten 5-bit groups; map each through Crockford base32
(`0123456789ABCDEFGHJKMNPQRSTVWXYZ`); format as `XXXXX-XXXXX`.

**Enroll argv.** The helper accepts exactly this grammar, and clients show
"Add device" with the comparison code exactly when `command.argv` matches it,
`resolvedPath` is the installed helper `/usr/local/lib/t3-elevation/t3-elevation`,
and there is no `user_writable_program` warning (`parseElevationEnrollCommand`).
A helper its owner can replace after approval could enroll any key, so it shows
as a plain command:

```
<path>/t3-elevation enroll --user <user> --label <label> --public-key <b64url SPKI>
                           --challenge <b64url>
                           [--allow-dev-attestation | --allow-test-attestation]
```

Each value is its own argv element; options may come in any order, each at
most once, and nothing else is allowed. The basename of `argv[0]` is
`t3-elevation`. Clients still show the full argv and warnings, and flag
either attestation option.

**Attestation trust.** Release builds of the helper pin the Google attestation
roots, the app package, and the app's signing digests
(`T3_ELEVATION_ANDROID_SIGNING_DIGESTS` at build time). `--allow-dev-attestation`
is for debug builds of the app on real phones: it keeps the root, hardware and
verified-boot checks and only widens the app pins to the dev packages and the
digests in `T3_ELEVATION_ANDROID_DEV_SIGNING_DIGESTS`.
`--allow-test-attestation` drops the device checks for emulators and the VM
fixture chains, so a key enrolled with it proves nothing about the device. The
module warns on both in the approval itself.

**Attestation challenge.** The phone draws 32 random bytes, uses them as the
key's attestation challenge, and they travel in the enrollment object and the
enroll argv. The helper requires the attested challenge to equal them and the
attested key creation time to be within 10 minutes of its clock. Freshness
comes from the device's attestation, so no root state is needed between
requesting a challenge and enrolling.

**Enrollment object** (helper stdin with `--key -`, or a file path):

```json
{
  "label": "Pixel 9 Pro Fold",
  "publicKey": "<b64url SPKI DER>",
  "challenge": "<b64url 32 bytes>",
  "attestationChain": ["<b64url DER, leaf first>", "..."]
}
```

For `enroll`, `label`, `publicKey` and `challenge` must equal the argv values.

## Socket protocol

- Unix stream socket at `<T3 stateDir>/elevation.sock`, mode 0600, path at most
  100 bytes. One connection per sudo invocation.
- NDJSON: one UTF-8 JSON object per `\n`-terminated line, at most 262144 bytes
  per line. Every message has a `type`. Unknown fields are ignored. An unknown
  `type`, an over-long line, or invalid JSON ends the connection.
- There are no error messages. Either side closes; the module treats any close
  or protocol violation as `expired` (fail closed).

Before connecting, the module `lstat`s the path: it must be a socket, not a
symlink, owned by the requesting uid, in a directory owned by that uid or root
and not group- or world-writable. After connecting, the peer uid
(`SO_PEERCRED` / `getpeereid`) must equal the requesting uid. Any failure is
handled like "T3 down".

| Direction   | Message                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------- |
| module → T3 | `{"type":"hello","v":1,"user","uid","service","host":{"name","machineId"},"argv":[...],"cwd","chain":[...]}`                |
| T3 → module | `{"type":"hello_reply","v":1,"decision":"mine"\|"not_mine"}`                                                                |
| module → T3 | `{"type":"request","payload":"<b64url payload bytes>"}`                                                                     |
| T3 → module | `{"type":"response","decision":"approve","keyId","alg","signature","webauthn"?}` or `{"type":"response","decision":"deny"}` |
| T3 → module | `{"type":"cancel","reason":"shutdown"\|"interrupted"}`                                                                      |
| module → T3 | `{"type":"result","outcome":"approved"\|"denied"\|"expired"\|"bad_signature"\|"too_large"\|"invalid_encoding"}`             |

- `chain[0]` is sudo's parent, then each ancestor up to 32 entries or pid 1:
  `{ "pid", "ppid", "startTime", "exe": string|null, "argv": string[]|null, "argvTruncated": bool }`.
  `startTime` is field 22 of `/proc/<pid>/stat` (clock ticks since boot) on
  Linux and `p_starttime.tv_sec` (Unix seconds) on macOS; the server records
  the same value for processes it spawns. `argv` holds at most 16 KiB per
  entry, invalid UTF-8 replaced with U+FFFD. Hello strings are for
  attribution only.
- `hello_reply` carries no thread or explanation; attribution stays inside the
  server. A server that doesn't speak the hello's `v` answers `not_mine`.
- After `mine`, the module either sends `request`, or sends `result` with
  `too_large` / `invalid_encoding` and closes.
- The module sends one `result` after the single `response` it accepts, then
  closes. On `cancel` it closes without a result.

Timeouts:

- Module: connect plus `hello_reply` within 3 s, otherwise "T3 down". A
  `response` until `expiresAt` on its own clock.
- Server: `request` within 5 s of `mine`, otherwise close. With no `result` by
  `expiresAt + 5 s` on its clock, mark the request `expired` and close.

Outcomes map to PAM results as in the spec: approve → `PAM_SUCCESS`; every
failure after `mine` → `PAM_CRED_INSUFFICIENT`; `not_mine`, "T3 down", and
unsafe config → `PAM_IGNORE`, or `PAM_CRED_INSUFFICIENT` when sudo's argv has
`-n`. The module can't ask sudo how it parsed its argv, so it scans it with the
option table, arity and long-option prefix rules of each sudo that may be
running (sudo.ws, and sudo-rs on Linux). A sudo that would reject the argv
can't be the caller; `-n` counts only when every other one sees it. Anything
less certain stays `PAM_IGNORE`, so an interactive sudo never fails early.

## Root-owned state

All directories are root-owned 0755 and files root-owned 0644. The module
returns `PAM_IGNORE` (or `PAM_CRED_INSUFFICIENT` with `-n`) if any component of
a path it reads is not root-owned or is group- or world-writable.

`/etc/t3-elevation/users/<user>.toml`. Without it, the module returns
`PAM_IGNORE` before any IPC.

```toml
version = 1
enabled = true
socket = "/Users/kgriset/.t3/userdata/elevation.sock"
approval_window_seconds = 100 # optional; default 100, clamped to 10..300
```

Unknown keys are ignored; `version` other than 1 or `enabled = false` means
`PAM_IGNORE`.

`/etc/t3-elevation/keys/<user>/<keyId>.json`:

```json
{ "version": 1, "keyId": "<22 chars>", "alg": "es256", "publicKey": "<b64url SPKI DER>",
  "label": "Pixel 9 Pro Fold", "securityLevel": "strongbox" | "tee" | "software",
  "enrolledAt": "2026-10-30T12:00:00Z",
  "attestationSummary": { "packageName": "...", "signingCertDigest": "<b64url SHA-256>", "devAttestation": false, "testAttestation": false } }
```

The module ignores a key file whose name, `keyId`, and derived keyId disagree.
`devAttestation` is set by either option and `testAttestation` only by
`--allow-test-attestation`; `software` only appears with the latter. Last-used times are
the server's own state, never written here.

`/etc/t3-elevation/installed-by-t3.json`, read and written only by the helper:

```json
{
  "version": 1,
  "installedAt": "...",
  "helperVersion": "0.1.0",
  "changes": [
    {
      "path": "/etc/pam.d/sudo",
      "action": "modified",
      "backup": "/etc/t3-elevation/backup/etc/pam.d/sudo",
      "sha256Before": "<hex>",
      "sha256After": "<hex>"
    },
    { "path": "/etc/sudoers.d/t3-elevation", "action": "created", "sha256After": "<hex>" },
    { "path": "/etc/t3-elevation/keys/kgriset", "action": "created_dir" }
  ]
}
```

Backups keep mode and owner. Uninstall walks `changes` in reverse and touches a
path only if its current hash still equals `sha256After`.

## Installed state (§7.1 of the design)

Any tool may produce this state; T3 verifies it whoever installed it.

- **PAM.** Linux-PAM: the first `auth` line of `/etc/pam.d/sudo`, and of
  `/etc/pam.d/sudo-i` when it exists and doesn't include `sudo`, is
  `auth [success=done ignore=ignore default=die] <abs path>/pam_t3_elevation.so`.
  macOS: `/etc/pam.d/sudo_local` begins with
  `auth sufficient <abs path>/pam_t3_elevation.so` then
  `auth requisite <abs path>/pam_t3_elevation.so mode=gate`. Any path works,
  including a Nix store path.
- **Protocol marker.** The module binary contains the bytes
  `\0t3-elevation-module protocol=1\0`. Verification reads the file and parses
  the decimal after `protocol=`; it never loads the library.
- **sudoers** (any file under `/etc/sudoers.d`, validated with `visudo -cf`):
  `Defaults:<user> noninteractive_auth`, `Defaults:<user> !requiretty`,
  `Defaults:<user> timestamp_timeout=0`, `Defaults:<user> always_set_home`,
  `Defaults:<user> !env_editor`, and
  `Defaults:<user> env_keep -= "HOME EDITOR VISUAL SUDO_EDITOR PATH KDEDIR QTDIR"`.
  The payload can't show the environment, so an approved command must not
  inherit variables that point root's code at the user's files: macOS keeps
  HOME, the editors and PATH (it has no `secure_path`), Fedora keeps KDEDIR and
  QTDIR. `!env_editor` also covers command-specific keeps such as Arch's
  `Defaults!/usr/bin/visudo env_keep += "SUDO_EDITOR EDITOR VISUAL"`, which
  sudo applies after user Defaults.
- **Config** `users/<user>.toml` pointing at the owning server's socket.
- **Keys dir** `keys/<user>/` exists, root-owned. External tools create it but
  never manage its contents; the helper writes keys.

Static checks cover the PAM line, the marker, the config, and the keys dir. The
rest is proven by a live `sudo -n true` approved on a device.

## Helper CLI

Every subcommand prints one JSON object on stdout and exits 0 on success:
`{ "ok": true, ... }`, or `{ "ok": false, "error": { "code": string, "message": string } }`
with a non-zero exit. `status` runs unprivileged; the rest need root.

Install copies the helper to `/usr/local/lib/t3-elevation/t3-elevation`. From
then on the server runs only that copy as root (`enroll`, `revoke`,
`uninstall`), and only while it and every folder above it are root-owned and
not group- or world-writable; anything the user can write could be swapped
between approval and sudo's exec. The first install has no such copy, so it
runs a helper this OS account could have changed, the same trust as typing the
sudo password into T3.

| Command                                                                                                                       | Result                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `t3-elevation version`                                                                                                        | `{ ok, protocol: 1, version }`                                                                                                                                                              |
| `t3-elevation status --user U`                                                                                                | `{ ok, protocol, platform, checks: [{ id, ok, message }], config \| null, keys: [{ keyId, label, securityLevel, enrolledAt }], plannedChanges: [{ path, summary }], setupOutsideT3: bool }` |
| `t3-elevation install --user U --socket P --key <-\|file> [--window S] [--allow-dev-attestation \| --allow-test-attestation]` | Writes missing files, enrolls the first key. On a TTY it prints the label and comparison code and asks to confirm.                                                                          |
| `t3-elevation enroll ...`                                                                                                     | See the grammar above; enrollment object on stdin.                                                                                                                                          |
| `t3-elevation revoke --user U (--key-id ID \| --all)`                                                                         | Removes key files.                                                                                                                                                                          |
| `t3-elevation uninstall --user U`                                                                                             | Reverts `installed-by-t3.json`.                                                                                                                                                             |

## Server and clients

- The `elevation_request` turn item and the `elevation_request.record` /
  `elevation_request.resolve` internal commands live in
  `packages/contracts/src/orchestrationV2.ts`. They emit `turn-item.updated`,
  like `secret_request`. `resolve` fails unless the item is `pending`, so the
  first answer wins. A waiting item in a live run shows as the thread's
  `pendingRuntimeRequest` with kind `command`.
- A request attributed to no thread has no turn item. Clients get every
  pending request, with its payload, from the `elevationSubscribe` stream,
  which also drives the cross-environment banner.
- RPC schemas and helpers: `packages/contracts/src/elevation.ts`. Clients
  check the `deviceApproval` environment capability before showing anything.
- Test vectors shared by the Rust, TypeScript and Kotlin tests:
  [`packages/contracts/test-vectors/device-approval.json`](../../packages/contracts/test-vectors/device-approval.json).
