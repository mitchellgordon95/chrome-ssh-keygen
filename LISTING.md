# Chrome Web Store Listing

## Short Description (132 chars max)

Generate SSH keypairs (Ed25519, ECDSA, RSA) locally in your browser. No data leaves your device. Optional passphrase encryption.

## Detailed Description

SSH Key Generator creates SSH keypairs entirely in your browser using the Web Crypto API. No data ever leaves your device.

### Features

- **Ed25519** (recommended) - fast, modern, compact keys
- **ECDSA** - P-256, P-384, and P-521 curves
- **RSA-3072** - broad compatibility with older systems
- **Passphrase encryption** - protect private keys with bcrypt_pbkdf + AES-256-CTR (same as OpenSSH)
- **Standard formats** - OpenSSH private key format and authorized_keys public key format
- **Secure Shell App compatible** - includes import instructions

### How it works

1. Click the extension icon
2. Choose algorithm, optional comment, optional passphrase
3. Click Generate
4. Download both key files
5. Add the public key to your server's `~/.ssh/authorized_keys`

All cryptography uses the browser's native WebCrypto API. Keys are generated in memory and never stored or transmitted.

## Category

Developer Tools

## Permission Justifications

This extension requires **no special permissions**.

- No `activeTab` - does not interact with page content
- No `storage` - does not persist any data
- No `networking` / `host_permissions` - makes no network requests
- No `clipboardWrite` - user copies manually from textarea

The extension operates entirely within its popup using only the standard WebCrypto API available to all web pages.
