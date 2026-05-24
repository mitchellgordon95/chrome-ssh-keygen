# chrome-ssh-keygen v2

Building on v1 (see SPEC.md + PROGRESS.md). All v1 tests must continue to pass.

## In scope

### 1. Passphrase encryption (the main feature)

Optional passphrase field in the popup. When set, encrypt the OpenSSH private key block with:
- **KDF:** `bcrypt_pbkdf` — port the algorithm (no WebCrypto primitive). Reference impls: OpenSSH `openbsd-compat/bcrypt_pbkdf.c`, npm package `bcrypt-pbkdf` (audited, Node-targeted but should adapt). Output: 48 bytes (32 for AES key, 16 for IV).
- **Cipher:** `aes256-ctr` via WebCrypto `AES-CTR`.
- **Format:** Same OpenSSH key envelope, but `ciphername` = `"aes256-ctr"`, `kdfname` = `"bcrypt"`, `kdfoptions` = `<string salt><uint32 rounds>` (salt = 16 random bytes, rounds = 16 by default — match OpenSSH defaults). Private key block is encrypted as a whole AFTER serializing the inner fields and padding to a 16-byte boundary.
- **Validate with ground truth:** `ssh-keygen -y -P <passphrase> -f <key>` must successfully read the file and emit the matching public key. Add a Vitest test for this.

### 2. ECDSA support

NIST curves: `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`. WebCrypto supports all three (`ECDSA` with `P-256` / `P-384` / `P-521`). Serialization in the OpenSSH key format follows the same envelope; the inner blob has:
```
string  key type (e.g. "ecdsa-sha2-nistp256")
string  curve identifier (e.g. "nistp256")
string  uncompressed public point (0x04 || X || Y)
```
Private block adds a single `mpint` for the private scalar. Validate with `ssh-keygen -y` for all three curves.

### 3. Icons + manifest cleanup

- Generate **16x16, 48x48, 128x128** PNG icons for the extension. A clean key-shape SVG rendered via ImageMagick (`convert`) or rsvg-convert is fine; `which convert` to confirm. Avoid AI art — keep it geometric, monochrome, looks like a key.
- Update `manifest.json` to reference the icons (`icons` and `action.default_icon`).
- Add `homepage_url`, `author` fields to the manifest.

### 4. Privacy policy + CWS listing prep

- Create `PRIVACY.md` in the repo with a privacy policy: explicitly state that no data leaves the device, all crypto runs locally via WebCrypto, no telemetry, no third-party scripts. Reference Chrome Web Store privacy requirements.
- Create `LISTING.md` with:
  - Short description (132 char max)
  - Detailed description (Markdown ok)
  - Category recommendation: "Developer Tools"
  - Permission justifications (currently no special permissions; explain why no permissions are needed)
- Don't actually submit to CWS — just have these ready.

### 5. Secure Shell App integration instructions

This is documentation, not code. Add a section to the popup UI (visible after key generation) and to README.md with step-by-step instructions for importing the downloaded keypair into Google's Secure Shell App. Steps roughly:

> 1. Make sure both files have matching base names (private = `id_ed25519`, public = `id_ed25519.pub`).
> 2. Open Secure Shell App and click the gear/Options icon to open the preferences tab.
> 3. Click **Identity** in the left sidebar.
> 4. Click **Import...** and in the file picker, select BOTH the private key and the `.pub` file at once (Ctrl/Cmd-click to multi-select). The import will fail if you upload only one.
> 5. The identity now appears in the list.
> 6. In a connection profile, set **Identity** to the imported key. Connect.
> 7. The matching public key must already be in the remote server's `~/.ssh/authorized_keys` for auth to succeed.

Inline this in the popup as a collapsed details/summary block titled "Importing into Secure Shell App" so users see it right after they download.

## Out of scope (still)

- SSH certificate inspection
- Deriving a public key from an existing private key
- Direct message-passing handoff to Secure Shell App (complex, brittle, the manual import is fine)
- Cloud sync / multi-device

## Testing requirements (hard stop)

ALL of these must pass before declaring done:

- All existing v1 unit + E2E tests still pass
- New unit tests for:
  - bcrypt_pbkdf KDF (test vector against a known input/output)
  - Encrypted Ed25519 + RSA + ECDSA private key serialization, each validated by `ssh-keygen -y -P <passphrase>`
  - Unencrypted ECDSA serialization, validated by `ssh-keygen -y`
- New E2E tests for:
  - Generate Ed25519 with passphrase, parse + verify with sshpk, also run `ssh-keygen -y -P` against the saved file
  - Generate ECDSA P-256, P-384, P-521 — all validate
- `npm run build` clean, `dist/` updated and committed
- README.md updated with: passphrase usage, ECDSA option, the Secure Shell App import instructions
- Clean working tree on main, all commits pushed to origin

## Operational notes for the agent

- You're on the same VPS as last time. `npm`, Playwright, `ssh-keygen`, `convert` (ImageMagick) all available.
- Commit progress frequently with conventional commit messages (`feat:`, `test:`, `docs:`, `chore:`).
- The remote `origin` is configured and works via SSH key. Push after major milestones.
- If you hit a blocker, write BLOCKED-v2.md and stop. Otherwise iterate.
- Don't break v1 — keep the simple "generate, no passphrase" path working as the default.
- When done, append a v2 section to PROGRESS.md describing what was added and what tests pass.
