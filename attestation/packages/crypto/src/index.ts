import {
  KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
export const MAX_CANONICAL_DEPTH = 8;
export const MAX_CANONICAL_ITEMS = 256;
export const MAX_CANONICAL_STRING_BYTES = 16_384;

function compareUnicodeCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (character) => character.codePointAt(0)!);
  const rightPoints = Array.from(right, (character) => character.codePointAt(0)!);
  const sharedLength = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const leftPoint = leftPoints[index]!;
    const rightPoint = rightPoints[index]!;
    if (leftPoint !== rightPoint) return leftPoint - rightPoint;
  }
  return leftPoints.length - rightPoints.length;
}

function normalize(value: unknown, depth = 0, active: Set<object> = new Set()): JsonValue {
  if (depth > MAX_CANONICAL_DEPTH) throw new TypeError('canonical value exceeds nesting limit');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.normalize('NFC') !== value) throw new TypeError('strings must already be Unicode NFC');
    if (Buffer.byteLength(value, 'utf8') > MAX_CANONICAL_STRING_BYTES) {
      throw new TypeError('string exceeds canonical byte limit');
    }
    return value;
  }
  if (typeof value === 'number') {
    // Protocol numbers are integer-only, mirroring the Python canonicalizer:
    // floating-point forms (including 1.0, exponent forms, and negative zero)
    // can serialize differently across languages and are therefore rejected.
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON rejects non-finite numbers');
    if (!Number.isInteger(value)) throw new TypeError('floating-point values are not permitted');
    if (Object.is(value, -0)) throw new TypeError('negative zero is not permitted');
    if (Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new TypeError('integer exceeds the interoperable exact range');
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_CANONICAL_ITEMS) throw new TypeError('array exceeds canonical item limit');
    if (active.has(value)) throw new TypeError('cyclic values are not permitted');
    active.add(value);
    try {
      return value.map((item) => normalize(item, depth + 1, active));
    } finally {
      active.delete(value);
    }
  }
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>;
    const prototype = Object.getPrototypeOf(object);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('unsupported canonical JSON object');
    }
    if (active.has(object)) throw new TypeError('cyclic values are not permitted');
    const keys = Object.keys(object);
    if (keys.length > MAX_CANONICAL_ITEMS) throw new TypeError('object exceeds canonical item limit');
    active.add(object);
    const output: Record<string, JsonValue> = {};
    try {
      for (const key of keys.sort(compareUnicodeCodePoints)) {
        normalize(key, depth + 1, active);
        const item = object[key];
        if (item === undefined) throw new TypeError(`canonical JSON rejects undefined at ${key}`);
        output[key] = normalize(item, depth + 1, active);
      }
      return output;
    } finally {
      active.delete(object);
    }
  }
  throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
}

function serialize(value: JsonValue): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
  return `{${Object.keys(value)
    .sort(compareUnicodeCodePoints)
    .map((key) => `${JSON.stringify(key)}:${serialize(value[key]!)}`)
    .join(',')}}`;
}

export function canonicalize(value: unknown): string {
  return serialize(normalize(value));
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

export function sha256(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function base64urlEncode(data: string | Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

export function base64urlDecode(data: string): Buffer {
  return Buffer.from(data, 'base64url');
}

export interface Ed25519KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  return generateKeyPairSync('ed25519');
}

export function ed25519KeyPairFromSeed(seed: string | Uint8Array): Ed25519KeyPair {
  const seedBytes = createHash('sha256').update(seed).digest();
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seedBytes]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

export function exportPublicKeyPem(key: KeyObject): string {
  return key.export({ format: 'pem', type: 'spki' }).toString();
}

export function exportPrivateKeyPem(key: KeyObject): string {
  return key.export({ format: 'pem', type: 'pkcs8' }).toString();
}

export function importPublicKeyPem(pem: string): KeyObject {
  return createPublicKey(pem);
}

export function importPrivateKeyPem(pem: string): KeyObject {
  return createPrivateKey(pem);
}

export function keyIdFromPublicKey(key: KeyObject | string): string {
  // Unified Event Horizon key-ID scheme: ed25519:<sha256(rawPublicKey)[:32]>.
  // The Ed25519 SubjectPublicKeyInfo DER ends with the 32-byte raw key.
  const publicKey = typeof key === 'string' ? createPublicKey(key) : key;
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const raw = der.subarray(der.length - 32);
  return `ed25519:${sha256(raw).slice(0, 32)}`;
}

export function signDetached(payload: Uint8Array, privateKey: KeyObject | string): string {
  const key = typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey;
  return nodeSign(null, Buffer.from(payload), key).toString('base64url');
}

export function verifyDetached(payload: Uint8Array, signature: string, publicKey: KeyObject | string): boolean {
  try {
    const key = typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey;
    return nodeVerify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}
