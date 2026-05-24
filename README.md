# chrome-ssh-keygen

A Manifest V3 Chrome extension that generates SSH keypairs entirely in-browser using the WebCrypto API.

## Features

- **Ed25519** (recommended) and **RSA-3072** key generation
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
2. Select algorithm: **Ed25519** (default, recommended) or **RSA-3072**
3. Optionally enter a comment (e.g., `user@hostname`)
4. Click **Generate Key Pair**
5. Download the private key and public key files
6. Copy the public key to your server's `~/.ssh/authorized_keys`

## Key formats

- **Private key**: OpenSSH format (`openssh-key-v1`), compatible with `ssh`, `ssh-add`, and all modern OpenSSH tools
- **Public key**: `authorized_keys` format (`ssh-ed25519 AAAA... comment` or `ssh-rsa AAAA... comment`)

Generated keys are validated against `/usr/bin/ssh-keygen` to ensure byte-level compatibility.

## Testing

```bash
# Unit tests (Vitest) -- OpenSSH serialization, wire format, round-trip with sshpk
npm test

# E2E tests (Playwright) -- full browser extension workflow
npm run e2e
```

## Tech stack

- TypeScript (strict mode)
- Vite (build + dev server)
- WebCrypto API (Ed25519 + RSA)
- Vitest (unit tests)
- Playwright (E2E tests)
- sshpk (test validation)
