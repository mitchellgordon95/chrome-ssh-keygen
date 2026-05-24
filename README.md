# chrome-ssh-keygen

A Manifest V3 Chrome extension that generates SSH keypairs entirely in-browser using the WebCrypto API.

## Features

- **Ed25519** (recommended), **ECDSA** (P-256, P-384, P-521), and **RSA-3072** key generation
- **Passphrase encryption** using bcrypt_pbkdf + AES-256-CTR (same as OpenSSH)
- Standard OpenSSH private key format (`-----BEGIN OPENSSH PRIVATE KEY-----`)
- Standard `authorized_keys` public key format
- Optional comment field
- No data leaves the browser -- all crypto runs locally via WebCrypto
- Download both private and public key files

## Install

### From source

```bash
npm install
npm run build
```

Then load the extension in Chrome:

1. Open `chrome://extensions`
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `dist/` directory

### Development

```bash
npm run dev    # Vite dev server with HMR
npm test       # Run Vitest unit tests
npm run e2e    # Run Playwright E2E tests
```

## Usage

1. Click the extension icon in the Chrome toolbar
2. Select algorithm: **Ed25519** (default), **ECDSA P-256/P-384/P-521**, or **RSA-3072**
3. Optionally enter a comment (e.g., `user@hostname`)
4. Optionally enter a passphrase to encrypt the private key
5. Click **Generate Key Pair**
6. Download the private key and public key files
7. Copy the public key to your server's `~/.ssh/authorized_keys`

### Passphrase encryption

When a passphrase is provided, the private key is encrypted using:
- **KDF**: bcrypt_pbkdf (16 rounds, 16-byte random salt)
- **Cipher**: AES-256-CTR

This matches OpenSSH's default encryption. The encrypted key can be used directly with `ssh-add` or `ssh` (you'll be prompted for the passphrase).

## Importing into Secure Shell App

After generating and downloading your keypair:

1. Make sure both files have matching base names (e.g., private = `id_ed25519`, public = `id_ed25519.pub`).
2. Open Secure Shell App and click the gear/Options icon to open the preferences tab.
3. Click **Identity** in the left sidebar.
4. Click **Import...** and in the file picker, select BOTH the private key and the `.pub` file at once (Ctrl/Cmd-click to multi-select). The import will fail if you upload only one.
5. The identity now appears in the list.
6. In a connection profile, set **Identity** to the imported key. Connect.
7. The matching public key must already be in the remote server's `~/.ssh/authorized_keys` for auth to succeed.

## Key formats

- **Private key**: OpenSSH format (`openssh-key-v1`), compatible with `ssh`, `ssh-add`, and all modern OpenSSH tools
- **Public key**: `authorized_keys` format (`ssh-ed25519 AAAA... comment`, `ecdsa-sha2-nistp256 AAAA... comment`, or `ssh-rsa AAAA... comment`)

Generated keys are validated against `/usr/bin/ssh-keygen` to ensure byte-level compatibility.

## Testing

```bash
# Unit tests (Vitest) -- OpenSSH serialization, wire format, round-trip, passphrase encryption
npm test

# E2E tests (Playwright) -- full browser extension workflow
npm run e2e
```

## Tech stack

- TypeScript (strict mode)
- Vite (build + dev server)
- WebCrypto API (Ed25519, ECDSA, RSA, AES-CTR)
- Vitest (unit tests)
- Playwright (E2E tests)
- sshpk (test validation)

## Privacy

No data ever leaves your device. See [PRIVACY.md](PRIVACY.md) for details.
