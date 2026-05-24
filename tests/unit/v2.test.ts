import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import { writeFileSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  serializeEd25519PrivateKey,
  serializeEd25519PublicKey,
  serializeRSAPrivateKey,
  serializeECDSAPrivateKey,
  serializeECDSAPublicKey,
  type Ed25519KeyData,
  type RSAKeyData,
  type ECDSAKeyData,
} from '../../src/lib/openssh.js';
import { bcryptPbkdf } from '../../src/lib/bcrypt_pbkdf.js';

function withTempFile(content: string, fn: (path: string) => void) {
  const path = join(tmpdir(), `sshtest_${Date.now()}_${Math.random().toString(36).slice(2)}`);
  writeFileSync(path, content, { mode: 0o600 });
  try {
    fn(path);
  } finally {
    try { unlinkSync(path); } catch {}
    try { unlinkSync(path + '.pub'); } catch {}
  }
}

function makeEd25519Key(seed?: Uint8Array): Ed25519KeyData {
  const nodeCrypto = require('crypto');
  const s = seed ?? new Uint8Array(32).fill(0x42);
  const privateKeyObj = nodeCrypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(s),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKeyObj = nodeCrypto.createPublicKey(privateKeyObj);
  const rawPub = new Uint8Array(publicKeyObj.export({ type: 'spki', format: 'der' }).slice(-32));
  const fullPrivate = new Uint8Array(64);
  fullPrivate.set(s, 0);
  fullPrivate.set(rawPub, 32);
  return { publicKey: rawPub, privateKey: fullPrivate, comment: 'test@passphrase' };
}

function makeRSAKey(): RSAKeyData {
  const nodeCrypto = require('crypto');
  const { privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 65537,
  });
  const jwk = privateKey.export({ format: 'jwk' });
  function jwkToBytes(field: string): Uint8Array {
    let b64 = field.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  return {
    n: jwkToBytes(jwk.n),
    e: jwkToBytes(jwk.e),
    d: jwkToBytes(jwk.d),
    iqmp: jwkToBytes(jwk.qi),
    p: jwkToBytes(jwk.p),
    q: jwkToBytes(jwk.q),
    comment: 'rsa@passphrase',
  };
}

function makeECDSAKey(curve: 'P-256' | 'P-384' | 'P-521'): ECDSAKeyData {
  const nodeCrypto = require('crypto');
  const curveName = curve === 'P-256' ? 'prime256v1' : curve === 'P-384' ? 'secp384r1' : 'secp521r1';
  const { privateKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: curveName });
  const jwk = privateKey.export({ format: 'jwk' });
  function jwkToBytes(field: string): Uint8Array {
    let b64 = field.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const x = jwkToBytes(jwk.x);
  const y = jwkToBytes(jwk.y);
  // Uncompressed point: 0x04 || X || Y
  const publicPoint = new Uint8Array(1 + x.length + y.length);
  publicPoint[0] = 0x04;
  publicPoint.set(x, 1);
  publicPoint.set(y, 1 + x.length);
  return {
    curve,
    publicPoint,
    privateScalar: jwkToBytes(jwk.d),
    comment: `ecdsa-${curve}@test`,
  };
}

describe('bcrypt_pbkdf', () => {
  it('produces correct output for known test vector', () => {
    const pass = new Uint8Array(Buffer.from('test passphrase'));
    const salt = new Uint8Array(16).fill(0xab);
    const key = bcryptPbkdf(pass, salt, 48, 16);
    expect(Buffer.from(key).toString('hex')).toBe(
      '02ce8e8243c118d2cb0823e38c0622ba7358f978dde7a2e93cc74353fc0af9b1b3e949127387a758b6951651da07ee06'
    );
  });

  it('throws on invalid inputs', () => {
    expect(() => bcryptPbkdf(new Uint8Array(0), new Uint8Array(16), 32, 16)).toThrow();
    expect(() => bcryptPbkdf(new Uint8Array(8), new Uint8Array(16), 32, 0)).toThrow();
  });
});

describe('Passphrase-encrypted Ed25519', () => {
  it('produces a key accepted by ssh-keygen -y -P', async () => {
    const keyData = makeEd25519Key();
    const pem = await serializeEd25519PrivateKey(keyData, { passphrase: 'hello123' });
    expect(pem).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    withTempFile(pem, (path) => {
      const result = execSync(`/usr/bin/ssh-keygen -y -P hello123 -f ${path} 2>&1`).toString().trim();
      expect(result).toContain('ssh-ed25519');
      // Match public key blob
      const expectedPub = serializeEd25519PublicKey(keyData.publicKey, '');
      expect(result).toContain(expectedPub.split(' ')[1]);
    });
  });
});

describe('Passphrase-encrypted RSA', () => {
  it('produces a key accepted by ssh-keygen -y -P', async () => {
    const keyData = makeRSAKey();
    const pem = await serializeRSAPrivateKey(keyData, { passphrase: 'rsapass!' });
    expect(pem).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

    withTempFile(pem, (path) => {
      const result = execSync(`/usr/bin/ssh-keygen -y -P "rsapass!" -f ${path} 2>&1`).toString().trim();
      expect(result).toContain('ssh-rsa');
    });
  });
});

describe('ECDSA serialization (unencrypted)', () => {
  const curves: Array<'P-256' | 'P-384' | 'P-521'> = ['P-256', 'P-384', 'P-521'];
  const identifiers = { 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' };

  for (const curve of curves) {
    it(`${curve} produces a valid private key accepted by ssh-keygen`, () => {
      const keyData = makeECDSAKey(curve);
      const pem = serializeECDSAPrivateKey(keyData) as string;
      expect(pem).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');

      withTempFile(pem, (path) => {
        const result = execSync(`/usr/bin/ssh-keygen -y -f ${path} 2>&1`).toString().trim();
        expect(result).toContain(`ecdsa-sha2-${identifiers[curve]}`);
      });
    });

    it(`${curve} public key serializes correctly`, () => {
      const keyData = makeECDSAKey(curve);
      const pubLine = serializeECDSAPublicKey(curve, keyData.publicPoint, 'comment');
      expect(pubLine).toMatch(new RegExp(`^ecdsa-sha2-${identifiers[curve]} [A-Za-z0-9+/=]+ comment$`));
    });
  }
});

describe('Passphrase-encrypted ECDSA', () => {
  it('P-256 encrypted key accepted by ssh-keygen -y -P', async () => {
    const keyData = makeECDSAKey('P-256');
    const pem = await serializeECDSAPrivateKey(keyData, { passphrase: 'ecpass' });

    withTempFile(pem, (path) => {
      const result = execSync(`/usr/bin/ssh-keygen -y -P ecpass -f ${path} 2>&1`).toString().trim();
      expect(result).toContain('ecdsa-sha2-nistp256');
    });
  });
});
