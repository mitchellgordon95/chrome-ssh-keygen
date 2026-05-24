import { base64Encode, wrapBase64 } from './base64.js';

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
const BLOCK_SIZE = 8; // for "none" cipher

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
export function serializeEd25519PrivateKey(key: Ed25519KeyData): string {
  const { publicKey, privateKey, comment } = key;

  // Public key blob
  const pubBlob = concat(
    encodeString('ssh-ed25519'),
    encodeString(publicKey),
  );

  // Generate random check int
  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  // Private section (before padding)
  const privateSection = concat(
    encodeUint32(checkInt),
    encodeUint32(checkInt),
    encodeString('ssh-ed25519'),
    encodeString(publicKey),
    encodeString(privateKey),
    encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE);
  const paddedPrivate = concat(privateSection, padding);

  // Full binary
  const binary = concat(
    AUTH_MAGIC,
    encodeString('none'),       // ciphername
    encodeString('none'),       // kdfname
    encodeString(new Uint8Array(0)), // kdfoptions (empty)
    encodeUint32(1),            // number of keys
    encodeString(pubBlob),      // public key
    encodeString(paddedPrivate), // private section
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
export function serializeRSAPrivateKey(key: RSAKeyData): string {
  const { n, e, d, iqmp, p, q, comment } = key;

  // Public key blob
  const pubBlob = concat(
    encodeString('ssh-rsa'),
    encodeMpint(e),
    encodeMpint(n),
  );

  // Generate random check int
  const checkBytes = crypto.getRandomValues(new Uint8Array(4));
  const checkInt = new DataView(checkBytes.buffer).getUint32(0, false);

  // Private section
  const privateSection = concat(
    encodeUint32(checkInt),
    encodeUint32(checkInt),
    encodeString('ssh-rsa'),
    encodeMpint(n),
    encodeMpint(e),
    encodeMpint(d),
    encodeMpint(iqmp),
    encodeMpint(p),
    encodeMpint(q),
    encodeString(comment),
  );

  const padding = generatePadding(privateSection.length, BLOCK_SIZE);
  const paddedPrivate = concat(privateSection, padding);

  const binary = concat(
    AUTH_MAGIC,
    encodeString('none'),
    encodeString('none'),
    encodeString(new Uint8Array(0)),
    encodeUint32(1),
    encodeString(pubBlob),
    encodeString(paddedPrivate),
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
