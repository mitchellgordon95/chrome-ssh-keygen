import { base64Encode, wrapBase64 } from './base64.js';
import { bcryptPbkdf } from './bcrypt_pbkdf.js';

// ---- Wire format primitives ----

/** Write a uint32 big-endian */
export function encodeUint32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer);
  view.setUint32(0, n, false);
  return buf;
}

/** Write a length-prefixed string/bytes (uint32 length + data) */
export function encodeString(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const len = encodeUint32(bytes.length);
  const result = new Uint8Array(4 + bytes.length);
  result.set(len, 0);
  result.set(bytes, 4);
  return result;
}

/** Encode an SSH mpint (big-endian integer with leading zero if high bit set) */
export function encodeMpint(data: Uint8Array): Uint8Array {
  // Strip leading zeros
  let start = 0;
  while (start < data.length - 1 && data[start] === 0) start++;
  const trimmed = data.subarray(start);

  // If high bit is set, prepend a zero byte
  if (trimmed[0] & 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded[0] = 0;
    padded.set(trimmed, 1);
    return encodeString(padded);
  }
  return encodeString(trimmed);
}

/** Concatenate multiple Uint8Arrays */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// ---- OpenSSH private key format ----

const AUTH_MAGIC = new TextEncoder().encode('openssh-key-v1\0');
const BLOCK_SIZE_NONE = 8; // for "none" cipher
const BLOCK_SIZE_AES = 16; // for aes256-ctr
const DEFAULT_ROUNDS = 16;
const SALT_LENGTH = 16;

export interface EncryptionOptions {
  passphrase: string;
  rounds?: number;
}

/** Encrypt the private section using aes256-ctr with bcrypt_pbkdf KDF */
async function encryptPrivateSection(
  data: Uint8Array,
  opts: EncryptionOptions,
): Promise<{ encrypted: Uint8Array; salt: Uint8Array; rounds: number }> {
  const rounds = opts.rounds ?? DEFAULT_ROUNDS;
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const passBytes = new TextEncoder().encode(opts.passphrase);

  // Derive 48 bytes: 32 for AES key, 16 for IV
  const derived = bcryptPbkdf(passBytes, salt, 48, rounds);
  const aesKey = derived.slice(0, 32);
  const iv = derived.slice(32, 48);

  const key = await crypto.subtle.importKey(
    'raw', aesKey, { name: 'AES-CTR' }, false, ['encrypt'],
  );

  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter: iv, length: 128 },
    key,
    data,
  ));

  return { encrypted, salt, rounds };
}

/** Generate padding bytes 1,2,3,...,n up to block size */
function generatePadding(dataLen: number, blockSize: number): Uint8Array {
  const padLen = blockSize - (dataLen % blockSize);
  if (padLen === blockSize) return new Uint8Array(0);
  const pad = new Uint8Array(padLen);
  for (let i = 0; i < padLen; i++) {
    pad[i] = (i + 1) & 0xff;
  }
  return pad;
}

export interface Ed25519KeyData {
  publicKey: Uint8Array;   // 32 bytes
  privateKey: Uint8Array;  // 64 bytes (seed || pubkey)
  comment: string;
}

export interface RSAKeyData {
  n: Uint8Array;
  e: Uint8Array;
  d: Uint8Array;
  iqmp: Uint8Array;  // q^-1 mod p
  p: Uint8Array;
  q: Uint8Array;
  comment: string;
}

/** Serialize Ed25519 keypair to OpenSSH private key PEM */
export function serializeEd25519PrivateKey(key: Ed25519KeyData, encryption?: EncryptionOptions): Promise<string>;
export function serializeEd25519PrivateKey(key: Ed25519KeyData): string;
export function serializeEd25519PrivateKey(key: Ed25519KeyData, encryption?: EncryptionOptions): string | Promise<string> {
  if (encryption) {
    return serializeEd25519PrivateKeyAsync(key, encryption);
  }
  return serializeEd25519PrivateKeySync(key);
}

function serializeEd25519PrivateKeySync(key: Ed25519KeyData): string {
  const { publicKey, privateKey, comment } = key;
  const pubBlob = concat(encodeString('ssh-ed25519'), encodeString(publicKey));

  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  const privateSection = concat(
    encodeUint32(checkInt), encodeUint32(checkInt),
    encodeString('ssh-ed25519'), encodeString(publicKey),
    encodeString(privateKey), encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE_NONE);
  const paddedPrivate = concat(privateSection, padding);

  const binary = concat(
    AUTH_MAGIC,
    encodeString('none'), encodeString('none'),
    encodeString(new Uint8Array(0)),
    encodeUint32(1), encodeString(pubBlob), encodeString(paddedPrivate),
  );

  const b64 = wrapBase64(base64Encode(binary));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

async function serializeEd25519PrivateKeyAsync(key: Ed25519KeyData, encryption: EncryptionOptions): Promise<string> {
  const { publicKey, privateKey, comment } = key;
  const pubBlob = concat(encodeString('ssh-ed25519'), encodeString(publicKey));

  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  const privateSection = concat(
    encodeUint32(checkInt), encodeUint32(checkInt),
    encodeString('ssh-ed25519'), encodeString(publicKey),
    encodeString(privateKey), encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE_AES);
  const paddedPrivate = concat(privateSection, padding);

  const { encrypted, salt, rounds } = await encryptPrivateSection(paddedPrivate, encryption);

  const kdfoptions = concat(encodeString(salt), encodeUint32(rounds));

  const binary = concat(
    AUTH_MAGIC,
    encodeString('aes256-ctr'), encodeString('bcrypt'),
    encodeString(kdfoptions),
    encodeUint32(1), encodeString(pubBlob), encodeString(encrypted),
  );

  const b64 = wrapBase64(base64Encode(binary));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/** Serialize Ed25519 public key to authorized_keys format */
export function serializeEd25519PublicKey(publicKey: Uint8Array, comment: string): string {
  const blob = concat(
    encodeString('ssh-ed25519'),
    encodeString(publicKey),
  );
  const b64 = base64Encode(blob);
  return comment ? `ssh-ed25519 ${b64} ${comment}` : `ssh-ed25519 ${b64}`;
}

/** Serialize RSA keypair to OpenSSH private key PEM */
export function serializeRSAPrivateKey(key: RSAKeyData, encryption?: EncryptionOptions): Promise<string>;
export function serializeRSAPrivateKey(key: RSAKeyData): string;
export function serializeRSAPrivateKey(key: RSAKeyData, encryption?: EncryptionOptions): string | Promise<string> {
  if (encryption) return serializeRSAPrivateKeyAsync(key, encryption);
  return serializeRSAPrivateKeySync(key);
}

function serializeRSAPrivateKeySync(key: RSAKeyData): string {
  const { n, e, d, iqmp, p, q, comment } = key;
  const pubBlob = concat(encodeString('ssh-rsa'), encodeMpint(e), encodeMpint(n));

  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  const privateSection = concat(
    encodeUint32(checkInt), encodeUint32(checkInt),
    encodeString('ssh-rsa'),
    encodeMpint(n), encodeMpint(e), encodeMpint(d),
    encodeMpint(iqmp), encodeMpint(p), encodeMpint(q),
    encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE_NONE);
  const paddedPrivate = concat(privateSection, padding);

  const binary = concat(
    AUTH_MAGIC, encodeString('none'), encodeString('none'),
    encodeString(new Uint8Array(0)),
    encodeUint32(1), encodeString(pubBlob), encodeString(paddedPrivate),
  );

  const b64 = wrapBase64(base64Encode(binary));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

async function serializeRSAPrivateKeyAsync(key: RSAKeyData, encryption: EncryptionOptions): Promise<string> {
  const { n, e, d, iqmp, p, q, comment } = key;
  const pubBlob = concat(encodeString('ssh-rsa'), encodeMpint(e), encodeMpint(n));

  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  const privateSection = concat(
    encodeUint32(checkInt), encodeUint32(checkInt),
    encodeString('ssh-rsa'),
    encodeMpint(n), encodeMpint(e), encodeMpint(d),
    encodeMpint(iqmp), encodeMpint(p), encodeMpint(q),
    encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE_AES);
  const paddedPrivate = concat(privateSection, padding);

  const { encrypted, salt, rounds } = await encryptPrivateSection(paddedPrivate, encryption);
  const kdfoptions = concat(encodeString(salt), encodeUint32(rounds));

  const binary = concat(
    AUTH_MAGIC, encodeString('aes256-ctr'), encodeString('bcrypt'),
    encodeString(kdfoptions),
    encodeUint32(1), encodeString(pubBlob), encodeString(encrypted),
  );

  const b64 = wrapBase64(base64Encode(binary));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/** Serialize RSA public key to authorized_keys format */
export function serializeRSAPublicKey(n: Uint8Array, e: Uint8Array, comment: string): string {
  const blob = concat(
    encodeString('ssh-rsa'),
    encodeMpint(e),
    encodeMpint(n),
  );
  const b64 = base64Encode(blob);
  return comment ? `ssh-rsa ${b64} ${comment}` : `ssh-rsa ${b64}`;
}

// ---- ECDSA ----

export type ECDSACurve = 'P-256' | 'P-384' | 'P-521';

const CURVE_INFO: Record<ECDSACurve, { identifier: string; keyType: string }> = {
  'P-256': { identifier: 'nistp256', keyType: 'ecdsa-sha2-nistp256' },
  'P-384': { identifier: 'nistp384', keyType: 'ecdsa-sha2-nistp384' },
  'P-521': { identifier: 'nistp521', keyType: 'ecdsa-sha2-nistp521' },
};

export interface ECDSAKeyData {
  curve: ECDSACurve;
  publicPoint: Uint8Array;  // uncompressed: 0x04 || X || Y
  privateScalar: Uint8Array; // big-endian scalar
  comment: string;
}

/** Serialize ECDSA keypair to OpenSSH private key PEM */
export function serializeECDSAPrivateKey(key: ECDSAKeyData, encryption?: EncryptionOptions): Promise<string>;
export function serializeECDSAPrivateKey(key: ECDSAKeyData): string;
export function serializeECDSAPrivateKey(key: ECDSAKeyData, encryption?: EncryptionOptions): string | Promise<string> {
  if (encryption) return serializeECDSAPrivateKeyAsync(key, encryption);
  return serializeECDSAPrivateKeySync(key);
}

function serializeECDSAPrivateKeySync(key: ECDSAKeyData): string {
  const { curve, publicPoint, privateScalar, comment } = key;
  const { identifier, keyType } = CURVE_INFO[curve];

  const pubBlob = concat(
    encodeString(keyType),
    encodeString(identifier),
    encodeString(publicPoint),
  );

  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  const privateSection = concat(
    encodeUint32(checkInt), encodeUint32(checkInt),
    encodeString(keyType),
    encodeString(identifier),
    encodeString(publicPoint),
    encodeMpint(privateScalar),
    encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE_NONE);
  const paddedPrivate = concat(privateSection, padding);

  const binary = concat(
    AUTH_MAGIC, encodeString('none'), encodeString('none'),
    encodeString(new Uint8Array(0)),
    encodeUint32(1), encodeString(pubBlob), encodeString(paddedPrivate),
  );

  const b64 = wrapBase64(base64Encode(binary));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

async function serializeECDSAPrivateKeyAsync(key: ECDSAKeyData, encryption: EncryptionOptions): Promise<string> {
  const { curve, publicPoint, privateScalar, comment } = key;
  const { identifier, keyType } = CURVE_INFO[curve];

  const pubBlob = concat(
    encodeString(keyType),
    encodeString(identifier),
    encodeString(publicPoint),
  );

  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  const privateSection = concat(
    encodeUint32(checkInt), encodeUint32(checkInt),
    encodeString(keyType),
    encodeString(identifier),
    encodeString(publicPoint),
    encodeMpint(privateScalar),
    encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE_AES);
  const paddedPrivate = concat(privateSection, padding);

  const { encrypted, salt, rounds } = await encryptPrivateSection(paddedPrivate, encryption);
  const kdfoptions = concat(encodeString(salt), encodeUint32(rounds));

  const binary = concat(
    AUTH_MAGIC, encodeString('aes256-ctr'), encodeString('bcrypt'),
    encodeString(kdfoptions),
    encodeUint32(1), encodeString(pubBlob), encodeString(encrypted),
  );

  const b64 = wrapBase64(base64Encode(binary));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/** Serialize ECDSA public key to authorized_keys format */
export function serializeECDSAPublicKey(curve: ECDSACurve, publicPoint: Uint8Array, comment: string): string {
  const { identifier, keyType } = CURVE_INFO[curve];
  const blob = concat(
    encodeString(keyType),
    encodeString(identifier),
    encodeString(publicPoint),
  );
  const b64 = base64Encode(blob);
  return comment ? `${keyType} ${b64} ${comment}` : `${keyType} ${b64}`;
}
