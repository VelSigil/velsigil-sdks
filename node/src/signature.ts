import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { decodeBase64Any, decodeBase64Url } from './encoding.js';
import { VelsigilError } from './errors.js';

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

/**
 * The two Ed25519 public keys of the SDK test vectors (`keys.publicKey` and `keys.wrongPublicKey` in
 * sdks/test-vectors.json). Their private seeds are published in the same file, so anyone can sign answers
 * that verify with them. Internal (not exported from the package): the client constructor refuses these keys
 * outside loopback hosts, and the public low-level helpers (`parsePublicKey`, `verifyEnvelope`, `verifyLease`),
 * which have no API URL to judge by, refuse them always.
 */
export const PUBLISHED_TEST_PUBLIC_KEYS: readonly string[] = Object.freeze([
  'I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=',
  'b/OKSQM/kKwu80PNfHkda3EM9dk1/ZmNKkQz/1azw/Q=',
]);

/**
 * The `invalid_public_key` message for a published test key, thrown by the client constructor (outside loopback)
 * and by the public low-level helpers. The same text in every Velsigil SDK.
 */
export const PUBLISHED_TEST_KEY_MESSAGE =
  'This is the public test key from the Velsigil SDK test vectors, whose private key is published: anyone could ' +
  "forge license answers for it. Use your product's public key (panel: Products > your product > Integration).";

const PUBLISHED_TEST_KEY_BYTES: readonly Buffer[] = PUBLISHED_TEST_PUBLIC_KEYS.map((key) => Buffer.from(key, 'base64'));

/**
 * True when `key` is one of {@link PUBLISHED_TEST_PUBLIC_KEYS}. Compares the raw 32 key bytes (exported
 * from the imported key), never the text, so no other encoding of the same key can slip through.
 */
export function isPublishedTestKey(key: KeyObject): boolean {
  const x = key.export({ format: 'jwk' }).x;
  if (typeof x !== 'string') return false;
  const raw = Buffer.from(x, 'base64url');
  return PUBLISHED_TEST_KEY_BYTES.some((testKey) => testKey.equals(raw));
}

/**
 * Returns `key`, or throws `VelsigilError('invalid_public_key', PUBLISHED_TEST_KEY_MESSAGE)` when it is a published
 * test key. The guard of the public low-level helpers: they know no API URL, so there is no loopback exception.
 */
export function refusePublishedTestKey(key: KeyObject): KeyObject {
  if (isPublishedTestKey(key)) throw new VelsigilError('invalid_public_key', PUBLISHED_TEST_KEY_MESSAGE);
  return key;
}

/**
 * Imports the product's Ed25519 public key (standard base64 of the raw 32-byte key, as shown in the
 * Velsigil panel). Throws `VelsigilError('invalid_public_key')` when it is not a valid key, and also for the
 * public test keys of the SDK test vectors, whose private keys are published (in any base64 form).
 */
export function parsePublicKey(publicKeyBase64: string): KeyObject {
  return refusePublishedTestKey(parsePublicKeyAllowingTestKeys(publicKeyBase64));
}

/**
 * Internal (not exported from the package): {@link parsePublicKey} without the published-test-key refusal. For
 * the client constructor, which applies its own loopback rule to those keys, and for the SDK's own tests.
 */
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

/**
 * Internal: accepts either a base64 public key string or an already imported Ed25519 `KeyObject`. Does not refuse
 * the published test keys; the public helpers pass the result through {@link refusePublishedTestKey}.
 */
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

/**
 * Verifies an Ed25519 signature (base64url, padding optional) over the exact bytes of `message`.
 * Returns false for any malformed input; never throws.
 */
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
