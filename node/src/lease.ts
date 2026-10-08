import type { KeyObject } from 'node:crypto';
import { decodeJsonSegment, sha256Hex } from './encoding.js';
import {
  isHex64,
  isNonEmptyString,
  isObject,
  isString,
  isStringArray,
  isUnixTime,
  sameId,
} from './guards.js';
import { resolvePublicKey, verifySignature } from './signature.js';
import type { LeasePayload } from './types.js';

const MAX_TOKEN_LENGTH = 16 * 1024;
const SEGMENT_RE = /^[A-Za-z0-9_-]+={0,2}$/;

export type LeaseStatus =
  | 'valid'
  | 'expired'
  | 'invalid_signature'
  | 'product_mismatch'
  | 'hwid_mismatch'
  | 'malformed';

export type LeaseVerification =
  | { status: 'valid'; payload: LeasePayload }
  | { status: 'expired'; reason: string; payload: LeasePayload }
  | { status: 'product_mismatch' | 'hwid_mismatch'; reason: string; payload: LeasePayload }
  | { status: 'invalid_signature' | 'malformed'; reason: string };

export interface LeaseExpectations {
  /** The product this client is configured for. */
  productId: string;
  /** The hardware id string of this machine (as sent to the server); its SHA-256 must match. */
  hwid: string;
  /** Current time in unix seconds. */
  now: number;
}

/**
 * Verifies an offline lease token `base64url(JSON) "." base64url(Ed25519 signature)`.
 *
 * The signature over the ASCII bytes of the first segment is checked with ONLY the given public key
 * before the payload is decoded. Afterwards: `typ === 'lease'`, matching productId, matching
 * `hwidHash = sha256(hwid)`, and `now < exp`. A lease never outlives the license itself.
 */
export function verifyLease(
  publicKey: string | KeyObject,
  token: unknown,
  expected: LeaseExpectations,
): LeaseVerification {
  const key = resolvePublicKey(publicKey);
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    return { status: 'malformed', reason: 'Lease token is missing or too long' };
  }
  const parts = token.split('.');
  if (parts.length !== 2) return { status: 'malformed', reason: 'Lease token must have two segments' };
  const [body, signature] = parts as [string, string];
  if (!SEGMENT_RE.test(body) || !SEGMENT_RE.test(signature)) {
    return { status: 'malformed', reason: 'Lease token segments are not base64url' };
  }

  if (!verifySignature(key, Buffer.from(body, 'ascii'), signature)) {
    return { status: 'invalid_signature', reason: 'Lease signature verification failed' };
  }

  const decoded = decodeJsonSegment(body);
  if (!decoded.ok) return { status: 'malformed', reason: 'Lease payload is not valid JSON' };
  const payload = parseLeasePayload(decoded.value);
  if (payload === null) return { status: 'malformed', reason: 'Lease payload has an unexpected shape' };

  if (!sameId(payload.productId, expected.productId)) {
    return { status: 'product_mismatch', reason: 'Lease belongs to a different product', payload };
  }
  if (payload.hwidHash.toLowerCase() !== sha256Hex(expected.hwid)) {
    return { status: 'hwid_mismatch', reason: 'Lease was issued for a different device', payload };
  }
  const now = expected.now;
  if (!Number.isFinite(now) || now >= payload.exp) {
    return { status: 'expired', reason: 'Offline lease has expired', payload };
  }
  if (payload.licenseExpiresAt !== null && now >= payload.licenseExpiresAt) {
    return { status: 'expired', reason: 'License has expired', payload };
  }
  return { status: 'valid', payload };
}

function parseLeasePayload(value: unknown): LeasePayload | null {
  if (!isObject(value)) return null;
  if (value.v !== 1 || value.typ !== 'lease') return null;
  if (!isNonEmptyString(value.productId, 64)) return null;
  if (!isNonEmptyString(value.licenseId, 64)) return null;
  if (!isNonEmptyString(value.activationId, 64)) return null;
  if (!isHex64(value.hwidHash)) return null;
  if (!isString(value.plan, 256)) return null;
  if (!isStringArray(value.features)) return null;
  const licenseExpiresAt = value.licenseExpiresAt ?? null;
  if (!(licenseExpiresAt === null || isUnixTime(licenseExpiresAt))) return null;
  if (!isUnixTime(value.iat) || !isUnixTime(value.exp)) return null;
  // Optional free-trial flag (SPEC 9.7): absent/null = not a trial; any other non-boolean is malformed.
  const trial = value.trial;
  if (!(trial === null || trial === undefined || typeof trial === 'boolean')) return null;
  return {
    v: 1,
    typ: 'lease',
    productId: value.productId,
    licenseId: value.licenseId,
    activationId: value.activationId,
    hwidHash: value.hwidHash,
    plan: value.plan,
    features: [...value.features],
    licenseExpiresAt,
    iat: value.iat,
    exp: value.exp,
    ...(trial === true ? { trial: true } : {}),
  };
}
