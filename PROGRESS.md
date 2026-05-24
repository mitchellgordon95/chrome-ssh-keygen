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

## Known limitations (v1)

- No passphrase encryption (bcrypt_pbkdf KDF + AES-256-CTR) -- deferred to v2 per SPEC.md
- No Secure Shell App integration
- Ed25519 requires Chrome 113+ (WebCrypto Ed25519 support)

---

## v2 - Passphrase encryption, ECDSA, CWS prep

### What was added

- **Passphrase encryption**: bcrypt_pbkdf KDF (pure JS port, no dependencies) + AES-256-CTR via WebCrypto. Matches OpenSSH's default encryption format exactly.
- **ECDSA support**: P-256, P-384, P-521 curves via WebCrypto ECDSA. Full OpenSSH key format serialization.
- **Icons**: 16x16, 48x48, 128x128 PNG icons (geometric key shape, rendered from SVG)
- **Updated popup UI**: passphrase field, ECDSA algorithm options, Secure Shell App import instructions (collapsible details block)
- **Manifest v2.0.0**: icons referenced in `icons` and `action.default_icon`, added `author` and `homepage_url`
- **PRIVACY.md**: privacy policy stating no data collection
- **LISTING.md**: Chrome Web Store listing description, category, permission justifications
- **README.md**: updated with passphrase usage, ECDSA options, Secure Shell App import instructions

### Tests passing

- **28 Vitest unit tests** (17 v1 + 11 v2):
  - bcrypt_pbkdf known test vector
  - Encrypted Ed25519 key validated by `ssh-keygen -y -P`
  - Encrypted RSA key validated by `ssh-keygen -y -P`
  - Encrypted ECDSA P-256 validated by `ssh-keygen -y -P`
  - Unencrypted ECDSA P-256/P-384/P-521 validated by `ssh-keygen -y`
  - ECDSA public key format tests
- **6 Playwright E2E tests** (2 v1 + 4 v2):
  - Ed25519 unencrypted (v1)
  - RSA-3072 unencrypted (v1)
  - Ed25519 with passphrase (v2) -- validated by `ssh-keygen -y -P`
  - ECDSA P-256 (v2)
  - ECDSA P-384 (v2)
  - ECDSA P-521 (v2)

### Validation

All generated private keys pass `ssh-keygen -y -f` (unencrypted) or `ssh-keygen -y -P <passphrase> -f` (encrypted) and emit the matching public key. Sign/verify round-trips confirmed via sshpk in E2E tests.
