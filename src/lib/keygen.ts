import {
  serializeEd25519PrivateKey,
  serializeEd25519PublicKey,
  serializeRSAPrivateKey,
  serializeRSAPublicKey,
  type Ed25519KeyData,
  type RSAKeyData,
} from './openssh.js';

export interface GeneratedKeyPair {
  privateKeyPEM: string;
  publicKeyLine: string;
  algorithm: 'ed25519' | 'rsa';
}

/** Generate an Ed25519 SSH keypair */
export async function generateEd25519(comment: string = ''): Promise<GeneratedKeyPair> {
  const kp = await crypto.subtle.generateKey(
    { name: 'Ed25519' } as any,
    true,
    ['sign', 'verify'],
  );

  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));

  // Extract 32-byte seed from PKCS8 per RFC 8410
  // PKCS8 for Ed25519: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { OCTET STRING { seed } } }
  // The seed is the last 32 bytes of the inner OCTET STRING
  const seed = pkcs8.slice(pkcs8.length - 32);

  // OpenSSH Ed25519 private key is seed || publicKey (64 bytes)
  const fullPrivate = new Uint8Array(64);
  fullPrivate.set(seed, 0);
  fullPrivate.set(rawPub, 32);

  const keyData: Ed25519KeyData = {
    publicKey: rawPub,
    privateKey: fullPrivate,
    comment,
  };

  return {
    privateKeyPEM: serializeEd25519PrivateKey(keyData),
    publicKeyLine: serializeEd25519PublicKey(rawPub, comment),
    algorithm: 'ed25519',
  };
}

/** Convert a base64url-encoded JWK field to Uint8Array */
function jwkFieldToBytes(field: string): Uint8Array {
  // base64url -> base64
  let b64 = field.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Compute modular inverse: a^(-1) mod m using extended Euclidean algorithm (BigInt) */
function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }

  return ((old_s % m) + m) % m;
}

/** Convert Uint8Array to BigInt (big-endian unsigned) */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/** Convert BigInt to Uint8Array (big-endian unsigned, minimal length) */
function bigIntToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0]);
  const hex = n.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex;
  const bytes = new Uint8Array(paddedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(paddedHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Generate an RSA-3072 SSH keypair */
export async function generateRSA(comment: string = ''): Promise<GeneratedKeyPair> {
  const kp = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 3072,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);

  const n = jwkFieldToBytes(jwk.n!);
  const e = jwkFieldToBytes(jwk.e!);
  const d = jwkFieldToBytes(jwk.d!);
  const p = jwkFieldToBytes(jwk.p!);
  const q = jwkFieldToBytes(jwk.q!);

  // Compute iqmp = q^(-1) mod p (OpenSSH uses this, JWK gives dp/dq/qi differently)
  // JWK qi = q^(-1) mod p — actually this is the same as iqmp!
  const iqmp = jwkFieldToBytes(jwk.qi!);

  const keyData: RSAKeyData = { n, e, d, iqmp, p, q, comment };

  return {
    privateKeyPEM: serializeRSAPrivateKey(keyData),
    publicKeyLine: serializeRSAPublicKey(n, e, comment),
    algorithm: 'rsa',
  };
}
