# chrome-ssh-keygen

A Manifest V3 Chrome extension that generates SSH keypairs in the browser using the WebCrypto API. Closes the long-standing gap in Google's Secure Shell App, which can import but not generate SSH keys.

## Goal

When the user clicks the extension icon, a popup appears. They pick an algorithm (Ed25519 or RSA-3072), optionally set a passphrase and a comment, click Generate. The extension produces a valid SSH keypair entirely client-side and offers both files for download in standard formats:

- **Public key:** `authorized_keys` format — `<type> <base64-blob> <comment>`
- **Private key:** OpenSSH private key format (the modern `-----BEGIN OPENSSH PRIVATE KEY-----` PEM block, *not* legacy PEM)

The generated keys must be byte-for-byte compatible with what `ssh-keygen` produces. A user must be able to add the public key to a remote server's `authorized_keys` and then ssh in using the private key from a real OpenSSH client.

## Scope (v1)

- Manifest V3, no remote code, all crypto runs locally.
- Two algorithms: **Ed25519** (preferred, default) and **RSA-3072**.
- Optional passphrase encryption of the private key (use `bcrypt_pbkdf` KDF + AES-256-CTR cipher, matching what OpenSSH does by default).
- Optional comment field (default: empty).
- No persistent storage of keys in the extension (security/scope reasons) — user downloads files and manages them themselves. v1 just generates and hands the files over.
- No Secure Shell App integration in v1. (Stretch goal, possibly v2.)

## Non-goals (v1)

- ECDSA keys
- Hosting an SSH agent
- Integrating with Secure Shell App's identity registration
- Cloud sync, multi-device key management
- Reading existing keys (only generation)

## Tech stack

- **Manifest V3** with action popup (`action.default_popup`)
- **TypeScript** + **Vite** for build (HMR during dev, single bundle output for the popup)
- **WebCrypto API** for crypto primitives (Ed25519 natively supported in Chrome 113+, RSA always supported)
- **Vitest** for unit tests of the OpenSSH serialization functions
- **Playwright** for E2E: launch Chromium with the extension loaded, click through the UI, capture downloads, validate them with `sshpk` (Node SSH key parser)

## Key implementation details

### Ed25519 keygen
```ts
const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)); // 32 bytes
const pkcs8Priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
// Extract 32-byte seed from PKCS8 (last 32 bytes of the PrivateKey OCTET STRING per RFC 8410)
```

### OpenSSH private key format (the gnarly part)

The PEM block decodes to a binary structure:
```
"openssh-key-v1\0"
string  ciphername          ("none" or e.g. "aes256-ctr")
string  kdfname             ("none" or "bcrypt")
string  kdfoptions          (empty if no passphrase, else: string salt + uint32 rounds)
uint32  number of keys      (always 1 for our use)
string  public key blob     (concatenation of length-prefixed fields, per algorithm)
string  encrypted block     (containing checkint*2, private key fields, comment, padding)
```

For Ed25519 unencrypted, the public key blob is:
```
string  "ssh-ed25519"
string  32-byte public key
```

And the private block (before encryption) is:
```
uint32  checkint
uint32  checkint   (same value, integrity check on decrypt)
string  "ssh-ed25519"
string  32-byte public key
string  64-byte private key (32-byte seed concatenated with 32-byte public key)
string  comment
byte    padding (1,2,3,... up to cipher block size; "none" cipher uses block size 8)
```

Then base64-encode and wrap in `-----BEGIN OPENSSH PRIVATE KEY-----` / `-----END OPENSSH PRIVATE KEY-----` with 70-char line breaks.

Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key

### RSA
- Generate via WebCrypto `RSASSA-PKCS1-v1_5` with 3072-bit modulus, SHA-256.
- Export to JWK, transcribe to OpenSSH RSA wire format (mpint n, e, d, iqmp, p, q).
- Same outer OpenSSH private key envelope, just different inner blob and key-type string `ssh-rsa`.

### Passphrase encryption
Skip in initial milestones; add after unencrypted Ed25519/RSA both round-trip cleanly. When you do tackle it:
- KDF: bcrypt_pbkdf (port the algorithm — no WebCrypto built-in). There are clean reference implementations in JS.
- Cipher: AES-256-CTR via WebCrypto.

## File layout (suggested)

```
src/
  popup/
    index.html
    popup.ts          // UI handlers
    style.css
  lib/
    keygen.ts         // WebCrypto wrappers
    openssh.ts        // OpenSSH key format serialization (the meaty part)
    base64.ts         // small utilities
manifest.json
vite.config.ts
package.json
tsconfig.json
tests/
  unit/
    openssh.test.ts   // golden-output tests vs known-good ssh-keygen samples
  e2e/
    generate.spec.ts  // Playwright: load extension, click, validate download
```

## Testing requirements (this is the hard stop — do not call yourself done without these)

### Unit tests
1. **OpenSSH serialization golden tests.** Hand-construct an Ed25519 keypair from a fixed 32-byte seed, serialize, and assert byte equality against a known-good `ssh-keygen` output for the same seed. If you can't find a published vector, generate one once with real `ssh-keygen` (it's installed on the system), commit it as a test fixture, and verify against it.
2. Same for RSA with fixed `n`, `e`, `d`.
3. Round-trip: serialize then parse with `sshpk` (node lib) and verify the parsed fields match the originals.

### E2E tests
1. Launch Chromium via Playwright with the built extension loaded (via `--load-extension`).
2. Click the extension icon, fill in fields, click Generate.
3. Capture the downloaded files.
4. Parse each file with `sshpk` and assert:
   - Public key parses as the expected type
   - Private key parses as a matching keypair
   - Sign a test message with the private key, verify with the public key — confirms they actually work
5. Repeat for both Ed25519 and RSA.

### Pass criteria for "done"
- `npm test` (Vitest) is all green
- `npm run e2e` (Playwright) is all green
- `npm run build` produces a clean dist/
- A manually loaded extension (load-unpacked from dist/) actually generates a key, downloads it, and that key works with real `ssh` (`ssh-add` or similar). You can validate this from a shell on the VM where you're running by invoking the OpenSSH client tools after writing the downloaded key to disk.
- README.md exists with install + usage instructions
- Final commit on the `main` branch, clean working tree

## Iteration rules

- You are running with `--dangerously-skip-permissions` and have full system access. Use it.
- Do NOT stop until all tests pass and the extension actually works. If a test fails, fix it. If a dependency is broken, swap libs.
- If you hit a hard blocker (e.g. WebCrypto Ed25519 not available in your version of Node/Chromium for testing), document it in BLOCKED.md and stop. Otherwise keep going.
- Commit progress frequently with descriptive messages. Do NOT push (no remote configured).
- The repo lives at `/home/node/projects/chrome-ssh-keygen/`. Work only inside it (or globally-install npm packages as needed).
- Use real `ssh-keygen` (installed at `/usr/bin/ssh-keygen`) and `ssh-keygen -y` to validate your work. That's the ground truth.
- When done, write a short PROGRESS.md describing what was built, what tests pass, and any known issues.
