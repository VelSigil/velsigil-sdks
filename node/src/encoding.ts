import { createHash, randomBytes } from 'node:crypto';
import { TextDecoder } from 'node:util';

const BASE64URL_RE = /^[A-Za-z0-9_-]*={0,2}$/;
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

/** Strict base64url decode; unlike Buffer.from it rejects invalid characters. Null if malformed. */
export function decodeBase64Url(input: string): Buffer | null {
  if (typeof input !== 'string' || !BASE64URL_RE.test(input)) return null;
  const unpadded = input.replace(/=+$/, '');
  const remainder = unpadded.length % 4;
  if (remainder === 1) return null;
  if (unpadded.length !== input.length) {
    if (remainder === 0 || unpadded.length + (4 - remainder) !== input.length) return null;
  }
  return Buffer.from(unpadded, 'base64url');
}

/** Decodes standard base64 or base64url, padded or not. Null if malformed. */
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

export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

/** Wrapped so a JSON `null` body differs from a decode failure. */
export type JsonDecodeResult = { ok: true; value: unknown } | { ok: false };

export function decodeJsonSegment(segment: string): JsonDecodeResult {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) return { ok: false };
  return parseJsonBytes(bytes);
}

export function parseJsonBytes(bytes: Uint8Array): JsonDecodeResult {
  try {
    const text = STRICT_UTF8.decode(bytes);
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

export function parseJsonText(text: string): JsonDecodeResult {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}
