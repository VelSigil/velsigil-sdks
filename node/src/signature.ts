import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { decodeBase64Any, decodeBase64Url } from './encoding.js';
import { VelsigilError } from './errors.js';

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

/**
 * Imports the product's Ed25519 public key (standard base64 of the raw 32-byte key, as shown in the
 * Velsigil panel). Throws `VelsigilError('invalid_public_key')` when it is not a valid key.
 */
export function parsePublicKey(publicKeyBase64: string): KeyObject {
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

/** Accepts either a base64 public key string or an already imported Ed25519 `KeyObject`. */
export function resolvePublicKey(key: string | KeyObject): KeyObject {
  if (typeof key === 'string') return parsePublicKey(key);
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
