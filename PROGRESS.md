# Progress

## What was built

A complete Manifest V3 Chrome extension that generates SSH keypairs (Ed25519 and RSA-3072) in-browser using the WebCrypto API, with proper OpenSSH key format serialization.

### Components

- **Core library** (`src/lib/`): Base64 utilities, OpenSSH wire format serialization (mpint, string, uint32), key generation wrappers around WebCrypto
- **Popup UI** (`src/popup/`): Clean form with algorithm selection, comment field, generate button, and download buttons for both key files
- **Build system**: Vite + TypeScript with manifest and service worker copying

### Tests passing

- **17 Vitest unit tests**: Wire format primitives, base64 round-trip, Ed25519 serialization (validated by `/usr/bin/ssh-keygen -y`), RSA serialization (validated by `/usr/bin/ssh-keygen -y`), sshpk round-trip for both key types
- **2 Playwright E2E tests**: Full browser extension flow for Ed25519 and RSA -- generates keys through the popup UI, validates with sshpk (parse + sign/verify), validates with `/usr/bin/ssh-keygen` ground truth

### Validation

Generated private keys pass `ssh-keygen -y -f <key>` and correctly emit the matching public key. Sign/verify round-trips confirmed via sshpk in both unit and E2E tests.

## Known limitations

- No passphrase encryption (bcrypt_pbkdf KDF + AES-256-CTR) -- deferred to v2 per SPEC.md
- No Secure Shell App integration
- Ed25519 requires Chrome 113+ (WebCrypto Ed25519 support)
