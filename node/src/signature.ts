import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { decodeBase64Any, decodeBase64Url } from './encoding.js';
import { VelsigilError } from './errors.js';

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

/** Public keys of the SDK test vectors; their private keys are published, so anyone can forge answers. */
export const PUBLISHED_TEST_PUBLIC_KEYS: readonly string[] = Object.freeze([
  'I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=',
  'b/OKSQM/kKwu80PNfHkda3EM9dk1/ZmNKkQz/1azw/Q=',
]);

export const PUBLISHED_TEST_KEY_MESSAGE =
  'This is the public test key from the Velsigil SDK test vectors, whose private key is published: anyone could ' +
  "forge license answers for it. Use your product's public key (panel: Products > your product > Integration).";

const PUBLISHED_TEST_KEY_BYTES: readonly Buffer[] = PUBLISHED_TEST_PUBLIC_KEYS.map((key) => Buffer.from(key, 'base64'));

/** Compares raw key bytes, not text, so no other encoding of a test key slips through. */
export function isPublishedTestKey(key: KeyObject): boolean {
  const x = key.export({ format: 'jwk' }).x;
  if (typeof x !== 'string') return false;
  const raw = Buffer.from(x, 'base64url');
  return PUBLISHED_TEST_KEY_BYTES.some((testKey) => testKey.equals(raw));
}

export function refusePublishedTestKey(key: KeyObject): KeyObject {
  if (isPublishedTestKey(key)) throw new VelsigilError('invalid_public_key', PUBLISHED_TEST_KEY_MESSAGE);
  return key;
}

/** Imports the product's base64 Ed25519 public key; throws `invalid_public_key` if invalid or a test key. */
export function parsePublicKey(publicKeyBase64: string): KeyObject {
  return refusePublishedTestKey(parsePublicKeyAllowingTestKeys(publicKeyBase64));
}

/** Internal: the client constructor applies its own loopback rule to the test keys. */
export function parsePublicKeyAllowingTestKeys(publicKeyBase64: string): KeyObject {
  const raw = typeof publicKeyBase64 === 'string' ? decodeBase64Any(publicKeyBase64) : null;
  if (raw === null || raw.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new VelsigilError(
      'invalid_public_key',
      'publicKey must be the base64-encoded 32-byte Ed25519 public key of the product',
    );
  }
  try {
    return createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
      format: 'jwk',
    });
  } catch {
    throw new VelsigilError('invalid_public_key', 'publicKey is not a valid Ed25519 public key');
  }
}

/** Does not refuse the published test keys; public helpers wrap it in {@link refusePublishedTestKey}. */
export function resolvePublicKey(key: string | KeyObject): KeyObject {
  if (typeof key === 'string') return parsePublicKeyAllowingTestKeys(key);
  if (
    typeof key === 'object' &&
    key !== null &&
    key.type === 'public' &&
    key.asymmetricKeyType === 'ed25519'
  ) {
    return key;
  }
  throw new VelsigilError('invalid_public_key', 'Expected an Ed25519 public key');
}

/** Verifies a base64url Ed25519 signature; false for any malformed input. Never throws. */
export function verifySignature(key: KeyObject, message: Uint8Array, signatureB64Url: unknown): boolean {
  if (typeof signatureB64Url !== 'string') return false;
  const signature = decodeBase64Url(signatureB64Url);
  if (signature === null || signature.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}
