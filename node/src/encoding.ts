import { createHash, randomBytes } from 'node:crypto';
import { TextDecoder } from 'node:util';

const BASE64URL_RE = /^[A-Za-z0-9_-]*={0,2}$/;
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Decodes base64url (RFC 4648 section 5). Missing padding is tolerated; present padding must be
 * correct. Returns `null` for anything that is not well-formed. Unlike `Buffer.from(s, 'base64url')`
 * this never silently skips invalid characters.
 */
export function decodeBase64Url(input: string): Buffer | null {
  if (typeof input !== 'string' || !BASE64URL_RE.test(input)) return null;
  const unpadded = input.replace(/=+$/, '');
  const remainder = unpadded.length % 4;
  if (remainder === 1) return null;
  if (unpadded.length !== input.length) {
    // Padding present: it must complete the last quantum exactly.
    if (remainder === 0 || unpadded.length + (4 - remainder) !== input.length) return null;
  }
  return Buffer.from(unpadded, 'base64url');
}

/**
 * Decodes standard base64 (the public-key format) or base64url, padded or not. Surrounding
 * whitespace is ignored. Returns `null` when malformed.
 */
export function decodeBase64Any(input: string): Buffer | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  const hasStandard = /[+/]/.test(trimmed);
  const hasUrl = /[-_]/.test(trimmed);
  if (hasStandard && hasUrl) return null;
  return decodeBase64Url(trimmed.replace(/\+/g, '-').replace(/\//g, '_'));
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/** Lowercase hex SHA-256 of the UTF-8 encoding of `text`. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Fresh request nonce: 32 CSPRNG bytes, base64url without padding (43 characters). */
export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

/** Sentinel-based result so that a JSON `null` body is distinguishable from a decode failure. */
export type JsonDecodeResult = { ok: true; value: unknown } | { ok: false };

/** base64url -> strict UTF-8 -> JSON. Never throws. */
export function decodeJsonSegment(segment: string): JsonDecodeResult {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) return { ok: false };
  return parseJsonBytes(bytes);
}

/** Strict UTF-8 -> JSON. Never throws. */
export function parseJsonBytes(bytes: Uint8Array): JsonDecodeResult {
  try {
    const text = STRICT_UTF8.decode(bytes);
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

/** Strict JSON parse of a string. Never throws. */
export function parseJsonText(text: string): JsonDecodeResult {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}
