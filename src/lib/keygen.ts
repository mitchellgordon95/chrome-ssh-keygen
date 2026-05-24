import {
  serializeEd25519PrivateKey,
  serializeEd25519PublicKey,
  serializeRSAPrivateKey,
  serializeRSAPublicKey,
  serializeECDSAPrivateKey,
  serializeECDSAPublicKey,
  type Ed25519KeyData,
  type RSAKeyData,
  type ECDSAKeyData,
  type ECDSACurve,
  type EncryptionOptions,
} from './openssh.js';

export type Algorithm = 'ed25519' | 'rsa' | 'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521';

export interface GeneratedKeyPair {
  privateKeyPEM: string;
  publicKeyLine: string;
  algorithm: Algorithm;
}

export interface KeygenOptions {
  comment?: string;
  passphrase?: string;
}

/** Generate an Ed25519 SSH keypair */
export async function generateEd25519(opts: KeygenOptions = {}): Promise<GeneratedKeyPair> {
  const comment = opts.comment ?? '';
  const kp = await crypto.subtle.generateKey(
    { name: 'Ed25519' } as any,
    true,
    ['sign', 'verify'],
  );

  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));

  // Extract 32-byte seed from PKCS8 per RFC 8410
  const seed = pkcs8.slice(pkcs8.length - 32);

  // OpenSSH Ed25519 private key is seed || publicKey (64 bytes)
  const fullPrivate = new Uint8Array(64);
  fullPrivate.set(seed, 0);
  fullPrivate.set(rawPub, 32);

  const keyData: Ed25519KeyData = { publicKey: rawPub, privateKey: fullPrivate, comment };

  let privateKeyPEM: string;
  if (opts.passphrase) {
    privateKeyPEM = await serializeEd25519PrivateKey(keyData, { passphrase: opts.passphrase });
  } else {
    privateKeyPEM = serializeEd25519PrivateKey(keyData);
  }

  return {
    privateKeyPEM,
    publicKeyLine: serializeEd25519PublicKey(rawPub, comment),
    algorithm: 'ed25519',
  };
}

/** Convert a base64url-encoded JWK field to Uint8Array */
function jwkFieldToBytes(field: string): Uint8Array {
  let b64 = field.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Generate an RSA-3072 SSH keypair */
export async function generateRSA(opts: KeygenOptions = {}): Promise<GeneratedKeyPair> {
  const comment = opts.comment ?? '';
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
  const iqmp = jwkFieldToBytes(jwk.qi!);

  const keyData: RSAKeyData = { n, e, d, iqmp, p, q, comment };

  let privateKeyPEM: string;
  if (opts.passphrase) {
    privateKeyPEM = await serializeRSAPrivateKey(keyData, { passphrase: opts.passphrase });
  } else {
    privateKeyPEM = serializeRSAPrivateKey(keyData);
  }

  return {
    privateKeyPEM,
    publicKeyLine: serializeRSAPublicKey(n, e, comment),
    algorithm: 'rsa',
  };
}

const CURVE_MAP: Record<string, ECDSACurve> = {
  'ecdsa-p256': 'P-256',
  'ecdsa-p384': 'P-384',
  'ecdsa-p521': 'P-521',
};

/** Generate an ECDSA SSH keypair */
export async function generateECDSA(algorithm: 'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521', opts: KeygenOptions = {}): Promise<GeneratedKeyPair> {
  const comment = opts.comment ?? '';
  const curve = CURVE_MAP[algorithm];

  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: curve },
    true,
    ['sign', 'verify'],
  );

  // Export public key as raw (uncompressed point)
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));

  // Export private key as JWK to get the scalar d
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const privateScalar = jwkFieldToBytes(jwk.d!);

  const keyData: ECDSAKeyData = { curve, publicPoint: rawPub, privateScalar, comment };

  let privateKeyPEM: string;
  if (opts.passphrase) {
    privateKeyPEM = await serializeECDSAPrivateKey(keyData, { passphrase: opts.passphrase });
  } else {
    privateKeyPEM = serializeECDSAPrivateKey(keyData);
  }

  return {
    privateKeyPEM,
    publicKeyLine: serializeECDSAPublicKey(curve, rawPub, comment),
    algorithm,
  };
}
