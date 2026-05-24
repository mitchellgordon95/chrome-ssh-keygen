import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  serializeEd25519PrivateKey,
  serializeEd25519PublicKey,
  serializeRSAPrivateKey,
  serializeRSAPublicKey,
  encodeUint32,
  encodeString,
  encodeMpint,
  concat,
  type Ed25519KeyData,
  type RSAKeyData,
} from '../../src/lib/openssh.js';
import { base64Encode, base64Decode, wrapBase64 } from '../../src/lib/base64.js';

// Helper to create a temp file, run a command, and clean up
function withTempFile(content: string, fn: (path: string) => void, mode = 0o600) {
  const path = join(tmpdir(), `sshtest_${Date.now()}_${Math.random().toString(36).slice(2)}`);
  writeFileSync(path, content, { mode });
  try {
    fn(path);
  } finally {
    try { unlinkSync(path); } catch {}
    try { unlinkSync(path + '.pub'); } catch {}
  }
}

describe('Wire format primitives', () => {
  it('encodeUint32 encodes big-endian', () => {
    const result = encodeUint32(0x01020304);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it('encodeUint32 encodes zero', () => {
    const result = encodeUint32(0);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it('encodeString encodes length-prefixed bytes', () => {
    const result = encodeString('ssh-ed25519');
    const expected = new Uint8Array([
      0, 0, 0, 11,  // length = 11
      ...new TextEncoder().encode('ssh-ed25519'),
    ]);
    expect(result).toEqual(expected);
  });

  it('encodeString encodes empty data', () => {
    const result = encodeString(new Uint8Array(0));
    expect(result).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it('encodeMpint adds leading zero for high bit set', () => {
    const data = new Uint8Array([0x80, 0x01]);
    const result = encodeMpint(data);
    // length 3, then 0x00 0x80 0x01
    expect(result).toEqual(new Uint8Array([0, 0, 0, 3, 0, 0x80, 0x01]));
  });

  it('encodeMpint does not add leading zero when high bit clear', () => {
    const data = new Uint8Array([0x7f, 0x01]);
    const result = encodeMpint(data);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 2, 0x7f, 0x01]));
  });

  it('encodeMpint strips leading zeros', () => {
    const data = new Uint8Array([0, 0, 0x01, 0x02]);
    const result = encodeMpint(data);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 2, 0x01, 0x02]));
  });

  it('concat joins arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const result = concat(a, b);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });
});

describe('Base64 utilities', () => {
  it('round-trips encode/decode', () => {
    const data = new Uint8Array([0, 1, 2, 255, 128, 64]);
    expect(base64Decode(base64Encode(data))).toEqual(data);
  });

  it('wraps at specified line length', () => {
    const long = 'A'.repeat(200);
    const wrapped = wrapBase64(long, 70);
    const lines = wrapped.split('\n');
    expect(lines[0].length).toBe(70);
    expect(lines[1].length).toBe(70);
    expect(lines[2].length).toBe(60);
  });
});

describe('Ed25519 OpenSSH serialization', () => {
  it('produces a valid private key accepted by ssh-keygen', () => {
    // Generate a deterministic keypair using crypto
    // We'll use WebCrypto to generate, serialize, and then validate with ssh-keygen
    // But for unit tests, let's use a fixed seed
    const seed = new Uint8Array(32);
    // Fill with a known pattern
    for (let i = 0; i < 32; i++) seed[i] = i;

    // We need the public key derived from this seed. Use ssh-keygen to get it,
    // or we can use Node's crypto. Let's use Node's crypto for Ed25519.
    const nodeCrypto = require('crypto');
    const privateKeyObj = nodeCrypto.createPrivateKey({
      key: Buffer.concat([
        // Ed25519 PKCS8 DER prefix
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(seed),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const publicKeyObj = nodeCrypto.createPublicKey(privateKeyObj);
    const rawPub = new Uint8Array(publicKeyObj.export({ type: 'spki', format: 'der' }).slice(-32));

    const fullPrivate = new Uint8Array(64);
    fullPrivate.set(seed, 0);
    fullPrivate.set(rawPub, 32);

    const keyData: Ed25519KeyData = {
      publicKey: rawPub,
      privateKey: fullPrivate,
      comment: 'test@example.com',
    };

    const pem = serializeEd25519PrivateKey(keyData);
    expect(pem).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(pem).toContain('-----END OPENSSH PRIVATE KEY-----');

    // Validate with ssh-keygen
    withTempFile(pem, (path) => {
      const result = execSync(`/usr/bin/ssh-keygen -y -f ${path} 2>&1`).toString().trim();
      expect(result).toContain('ssh-ed25519');

      // Also verify the public key matches
      const expectedPub = serializeEd25519PublicKey(rawPub, '');
      const pubParts = expectedPub.split(' ');
      expect(result).toContain(pubParts[1]); // base64 blob should match
    });
  });

  it('serializes public key in authorized_keys format', () => {
    const pub = new Uint8Array(32).fill(0xab);
    const line = serializeEd25519PublicKey(pub, 'user@host');
    expect(line).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+ user@host$/);
  });

  it('public key without comment has no trailing space', () => {
    const pub = new Uint8Array(32).fill(0xab);
    const line = serializeEd25519PublicKey(pub, '');
    expect(line).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+$/);
    expect(line).not.toMatch(/ $/);
  });
});

describe('RSA OpenSSH serialization', () => {
  it('produces a valid private key accepted by ssh-keygen', () => {
    // Generate RSA key with Node crypto and serialize using our code
    const nodeCrypto = require('crypto');
    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicExponent: 65537,
    });

    const jwk = privateKey.export({ format: 'jwk' });

    function jwkToBytes(field: string): Uint8Array {
      let b64 = field.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      return new Uint8Array(Buffer.from(b64, 'base64'));
    }

    const keyData: RSAKeyData = {
      n: jwkToBytes(jwk.n),
      e: jwkToBytes(jwk.e),
      d: jwkToBytes(jwk.d),
      iqmp: jwkToBytes(jwk.qi),
      p: jwkToBytes(jwk.p),
      q: jwkToBytes(jwk.q),
      comment: 'test@rsa',
    };

    const pem = serializeRSAPrivateKey(keyData);
    expect(pem).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    // Validate with ssh-keygen
    withTempFile(pem, (path) => {
      const result = execSync(`/usr/bin/ssh-keygen -y -f ${path} 2>&1`).toString().trim();
      expect(result).toContain('ssh-rsa');

      // Verify public key blob matches
      const expectedPub = serializeRSAPublicKey(keyData.n, keyData.e, '');
      const pubParts = expectedPub.split(' ');
      expect(result).toContain(pubParts[1]);
    });
  });

  it('serializes public key in authorized_keys format', () => {
    const n = new Uint8Array(384).fill(0x01);
    n[0] = 0x00; // Ensure it doesn't have leading high bit issues
    const e = new Uint8Array([0x01, 0x00, 0x01]);
    const line = serializeRSAPublicKey(n, e, 'admin@server');
    expect(line).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ admin@server$/);
  });
});

describe('Round-trip with sshpk', () => {
  it('Ed25519 key round-trips through sshpk', () => {
    const sshpk = require('sshpk');
    const nodeCrypto = require('crypto');

    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = i + 42;

    const privateKeyObj = nodeCrypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(seed),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const publicKeyObj = nodeCrypto.createPublicKey(privateKeyObj);
    const rawPub = new Uint8Array(publicKeyObj.export({ type: 'spki', format: 'der' }).slice(-32));

    const fullPrivate = new Uint8Array(64);
    fullPrivate.set(seed, 0);
    fullPrivate.set(rawPub, 32);

    const keyData: Ed25519KeyData = {
      publicKey: rawPub,
      privateKey: fullPrivate,
      comment: 'roundtrip@test',
    };

    const pem = serializeEd25519PrivateKey(keyData);
    const pubLine = serializeEd25519PublicKey(rawPub, 'roundtrip@test');

    // Parse with sshpk
    const parsedPriv = sshpk.parsePrivateKey(pem, 'ssh');
    const parsedPub = sshpk.parseKey(pubLine, 'ssh');

    expect(parsedPriv.type).toBe('ed25519');
    expect(parsedPub.type).toBe('ed25519');
    expect(parsedPriv.comment).toBe('roundtrip@test');

    // Verify the public key from private matches
    const derivedPub = parsedPriv.toPublic();
    expect(derivedPub.toString('ssh')).toContain(pubLine.split(' ')[1]);
  });

  it('RSA key round-trips through sshpk', () => {
    const sshpk = require('sshpk');
    const nodeCrypto = require('crypto');

    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicExponent: 65537,
    });

    const jwk = privateKey.export({ format: 'jwk' });

    function jwkToBytes(field: string): Uint8Array {
      let b64 = field.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      return new Uint8Array(Buffer.from(b64, 'base64'));
    }

    const keyData: RSAKeyData = {
      n: jwkToBytes(jwk.n),
      e: jwkToBytes(jwk.e),
      d: jwkToBytes(jwk.d),
      iqmp: jwkToBytes(jwk.qi),
      p: jwkToBytes(jwk.p),
      q: jwkToBytes(jwk.q),
      comment: 'rsa-roundtrip@test',
    };

    const pem = serializeRSAPrivateKey(keyData);
    const pubLine = serializeRSAPublicKey(keyData.n, keyData.e, 'rsa-roundtrip@test');

    const parsedPriv = sshpk.parsePrivateKey(pem, 'ssh');
    const parsedPub = sshpk.parseKey(pubLine, 'ssh');

    expect(parsedPriv.type).toBe('rsa');
    expect(parsedPub.type).toBe('rsa');
    expect(parsedPriv.comment).toBe('rsa-roundtrip@test');
  });
});
