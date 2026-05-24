# chrome-ssh-keygen — project conventions

## What this is

A Manifest V3 Chrome extension that generates SSH keypairs in-browser using the WebCrypto API. Read SPEC.md before doing anything.

## Conventions

- TypeScript strict mode
- Prefer WebCrypto primitives over bundling crypto libraries when possible (smaller bundle, audited by the platform)
- All bytes go through `Uint8Array` — no Buffer (this is browser code)
- Tests are mandatory, not optional. SPEC.md defines the hard stop.
- Commit small, often, with conventional commit messages: `feat:`, `fix:`, `test:`, `chore:`, `docs:`.
- Don't push to a remote — none is configured.

## Validation ground truth

`/usr/bin/ssh-keygen` and `/usr/bin/ssh-keygen -y` are the authority on whether your output is correct. If `ssh-keygen -y -f mykey` doesn't successfully read your generated private key and emit the matching public key, your serialization is wrong.

## When stuck

- Read https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key for the OpenSSH key format
- Cross-reference with `sshpk` source on npm for how they parse it
- For Ed25519 PKCS8 layout, see RFC 8410 (specifically the CurvePrivateKey extracting the 32-byte seed)
