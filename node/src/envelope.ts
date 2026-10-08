import type { KeyObject } from 'node:crypto';
import { decodeJsonSegment, sha256Hex } from './encoding.js';
import { VelsigilError } from './errors.js';
import {
  isCode,
  isCount,
  isHex64,
  isNonEmptyString,
  isObject,
  isOneOf,
  isString,
  isStringArray,
  isUnixTime,
  sameId,
  type JsonObject,
} from './guards.js';
import { verifyLease } from './lease.js';
import { resolvePublicKey, verifySignature } from './signature.js';
import { isTrialRef } from './trial-ref.js';
import type {
  LicenseStatus,
  ProtocolActivation,
  ProtocolDownload,
  ProtocolLease,
  ProtocolLicense,
  ProtocolTrial,
  ProtocolUpdate,
  RequestType,
  ResponsePayload,
} from './types.js';

/** Upper bound for the `data` string of an envelope (the HTTP layer caps whole bodies as well). */
const MAX_DATA_LENGTH = 1024 * 1024;

const REQUEST_TYPES: readonly RequestType[] = ['validate', 'deactivate', 'update_check', 'download', 'trial'];
/** A license key as the server issues it (and as every SDK sends it): 1-64 printable ASCII characters. */
const TRIAL_KEY_RE = /^[\x21-\x7e]{1,64}$/;
const LICENSE_STATUSES: readonly LicenseStatus[] = [
  'pending',
  'active',
  'suspended',
  'expired',
  'revoked',
  'banned',
];

export type EnvelopeStatus =
  | 'valid'
  | 'invalid_signature'
  | 'nonce_mismatch'
  | 'product_mismatch'
  | 'type_mismatch'
  | 'hwid_mismatch'
  | 'malformed';

export type EnvelopeVerification =
  | { status: 'valid'; payload: ResponsePayload }
  | { status: Exclude<EnvelopeStatus, 'valid'>; reason: string };

export interface EnvelopeExpectations {
  /** The nonce sent with the request; the signed payload must echo it exactly. */
  nonce: string;
  /** The product this client is configured for. */
  productId: string;
  /**
   * The endpoint the request went to (`validate`, `deactivate`, `update_check`, `download` or `trial`).
   * Required: the payload `type` must match it, otherwise a genuinely signed answer to another endpoint
   * (e.g. an `update_check` answer, which is `ok` without any license) would pass as a validation.
   */
  type: RequestType;
  /**
   * The hwid sent with a device-bound request (validate, deactivate, download, trial). When given, the
   * payload's `lease` and `activation.hwidHash` (if present) must belong to this hwid and product.
   */
  hwid?: string;
}

/**
 * Verifies and decodes a signed response envelope.
 *
 * Order of checks (security relevant):
 * 1. the Ed25519 signature over the exact ASCII bytes of the `data` string, using ONLY the given
 *    public key (`kid` is informational and never used for key selection);
 * 2. only then base64url-decode, UTF-8-decode and JSON-parse `data`, and validate its shape;
 * 3. productId, nonce and type must match what this client sent;
 * 4. with `hwid`: the signed lease and `activation.hwidHash` must be bound to that device. The
 *    signature binds the payload to the request only via nonce/product/type, so a response for
 *    another device (the request's hwid and device secret rewritten in transit, e.g. by a
 *    license-sharing proxy) would otherwise pass.
 *
 * Throws `VelsigilError('invalid_argument')` when `expected.type` is not a request type (a
 * programming error: the type check cannot be skipped), and `VelsigilError('invalid_public_key')`.
 */
export function verifyEnvelope(
  publicKey: string | KeyObject,
  envelope: unknown,
  expected: EnvelopeExpectations,
): EnvelopeVerification {
  // JavaScript callers (or casts) can omit `type`: refuse instead of silently skipping the check.
  if (!isObject(expected) || !isOneOf(expected.type, REQUEST_TYPES)) {
    throw new VelsigilError(
      'invalid_argument',
      'expected.type must be the request type: validate, deactivate, update_check, download or trial',
    );
  }
  const key = resolvePublicKey(publicKey);
  if (!isObject(envelope)) return { status: 'malformed', reason: 'Response is not a signed envelope' };

  const { data, sig } = envelope;
  if (typeof data !== 'string' || data.length === 0 || data.length > MAX_DATA_LENGTH) {
    return { status: 'malformed', reason: 'Envelope data is missing' };
  }
  if (typeof sig !== 'string' || sig.length === 0) {
    return { status: 'invalid_signature', reason: 'Envelope signature is missing' };
  }
  // A valid `data` string is pure ASCII, for which UTF-8 and ASCII bytes are identical; UTF-8 keeps
  // the mapping lossless for hostile non-ASCII input (which then fails verification or decoding).
  if (!verifySignature(key, Buffer.from(data, 'utf8'), sig)) {
    return { status: 'invalid_signature', reason: 'Envelope signature verification failed' };
  }

  const decoded = decodeJsonSegment(data);
  if (!decoded.ok) return { status: 'malformed', reason: 'Envelope data is not valid base64url JSON' };
  const payload = parseResponsePayload(decoded.value);
  if (payload === null) return { status: 'malformed', reason: 'Envelope payload has an unexpected shape' };

  if (!sameId(payload.productId, expected.productId)) {
    return { status: 'product_mismatch', reason: 'Response is for a different product' };
  }
  if (payload.nonce !== expected.nonce) {
    return { status: 'nonce_mismatch', reason: 'Response nonce does not match the request' };
  }
  if (payload.type !== expected.type) {
    return { status: 'type_mismatch', reason: 'Response type does not match the request' };
  }
  if (expected.hwid !== undefined) {
    const binding = checkDeviceBinding(key, payload, expected.productId, expected.hwid);
    if (binding !== null) return binding;
  }
  return { status: 'valid', payload };
}

/**
 * A verified payload of a device-bound request must describe THIS device: its signed lease (issued
 * for `sha256(hwid)`) and the optional `activation.hwidHash`. Returns the failure, or null.
 * Other lease defects (expired, ...) are not a binding failure; such a lease is just never stored.
 */
function checkDeviceBinding(
  key: KeyObject,
  payload: ResponsePayload,
  productId: string,
  hwid: string,
): Exclude<EnvelopeVerification, { status: 'valid' }> | null {
  const activationHash = payload.activation?.hwidHash;
  if (activationHash !== undefined && activationHash !== sha256Hex(hwid)) {
    return { status: 'hwid_mismatch', reason: 'Response activation belongs to a different device' };
  }
  if (payload.lease !== null) {
    const lease = verifyLease(key, payload.lease.token, { productId, hwid, now: payload.serverTime });
    if (lease.status === 'hwid_mismatch') {
      return { status: 'hwid_mismatch', reason: 'Response lease was issued for a different device' };
    }
    if (lease.status === 'product_mismatch') {
      return { status: 'product_mismatch', reason: 'Response lease belongs to a different product' };
    }
  }
  return null;
}

/** Validates the decoded payload shape and copies known fields into fresh objects. */
export function parseResponsePayload(value: unknown): ResponsePayload | null {
  if (!isObject(value)) return null;
  if (value.v !== 1) return null;
  if (!isOneOf(value.type, REQUEST_TYPES)) return null;
  if (typeof value.ok !== 'boolean') return null;
  if (!isCode(value.code)) return null;
  // Seller-authored text (pause messages, changelogs) is only bounded by the response size cap.
  if (!isString(value.message, MAX_DATA_LENGTH)) return null;
  if (!isNonEmptyString(value.nonce, 256)) return null;
  if (!isString(value.requestId, 128)) return null;
  if (!isUnixTime(value.serverTime)) return null;
  if (!isNonEmptyString(value.productId, 64)) return null;

  const license = parseNullable(value.license, parseLicense);
  const activation = parseNullable(value.activation, parseActivation);
  const lease = parseNullable(value.lease, parseLease);
  const update = parseNullable(value.update, parseUpdate);
  const download = parseNullable(value.download, parseDownload);
  if (
    license === undefined ||
    activation === undefined ||
    lease === undefined ||
    update === undefined ||
    download === undefined
  ) {
    return null;
  }
  // A started trial (SPEC 10.1): an `ok` answer of type `trial` must carry a well-formed key. The field is read on no
  // other answer (ignored like any unknown field), so no other answer can hand the app a key.
  const startedTrial = value.type === 'trial' && value.ok;
  const trial = startedTrial ? parseNullable(value.trial, parseTrial) : null;
  if (startedTrial && (trial === null || trial === undefined)) return null;

  return {
    v: 1,
    type: value.type,
    ok: value.ok,
    code: value.code,
    message: value.message,
    nonce: value.nonce,
    requestId: value.requestId,
    serverTime: value.serverTime,
    productId: value.productId,
    license,
    activation,
    lease,
    update,
    download,
    ...(trial ? { trial } : {}),
  };
}

function parseTrial(o: JsonObject): ProtocolTrial | null {
  if (typeof o.key !== 'string' || !TRIAL_KEY_RE.test(o.key)) return null;
  return { key: o.key };
}

/** `null`/absent -> null, valid object -> parsed, anything else -> undefined (invalid). */
function parseNullable<T>(value: unknown, parse: (obj: JsonObject) => T | null): T | null | undefined {
  if (value === null || value === undefined) return null;
  if (!isObject(value)) return undefined;
  const parsed = parse(value);
  return parsed === null ? undefined : parsed;
}

function parseLicense(o: JsonObject): ProtocolLicense | null {
  if (!isNonEmptyString(o.id, 64)) return null;
  if (!isString(o.plan, 256)) return null;
  if (!isOneOf(o.status, LICENSE_STATUSES)) return null;
  if (!isStringArray(o.features)) return null;
  if (!(o.expiresAt === null || isUnixTime(o.expiresAt))) return null;
  if (!isCount(o.maxDevices) || !isCount(o.devicesUsed)) return null;
  if (!isUnixTime(o.createdAt)) return null;
  // Optional free-trial flag (SPEC 9.7): absent/null = not a trial; any other non-boolean is malformed.
  const trial = o.trial;
  if (!(trial === null || trial === undefined || typeof trial === 'boolean')) return null;
  // Optional trial conversion reference (SPEC 9.7): absent/null = none; anything but a well-formed string is malformed.
  const trialRef = o.trialRef;
  if (!(trialRef === null || trialRef === undefined || isTrialRef(trialRef))) return null;
  return {
    id: o.id,
    plan: o.plan,
    status: o.status,
    features: [...o.features],
    expiresAt: o.expiresAt,
    maxDevices: o.maxDevices,
    devicesUsed: o.devicesUsed,
    createdAt: o.createdAt,
    ...(typeof trialRef === 'string' ? { trialRef } : {}),
    ...(trial === true ? { trial: true } : {}),
  };
}

function parseActivation(o: JsonObject): ProtocolActivation | null {
  if (!isNonEmptyString(o.id, 64)) return null;
  if (o.status !== 'active' && o.status !== 'revoked') return null;
  if (!isUnixTime(o.firstSeenAt)) return null;
  const secret = o.deviceSecret;
  if (!(secret === null || secret === undefined || isDeviceSecret(secret))) return null;
  const hwidHash = o.hwidHash;
  if (!(hwidHash === null || hwidHash === undefined || isHex64(hwidHash))) return null;
  return {
    id: o.id,
    status: o.status,
    firstSeenAt: o.firstSeenAt,
    deviceSecret: secret ?? null,
    // Optional device binding (see checkDeviceBinding); omitted when the server does not send it.
    ...(typeof hwidHash === 'string' ? { hwidHash: hwidHash.toLowerCase() } : {}),
  };
}

function parseLease(o: JsonObject): ProtocolLease | null {
  if (!isNonEmptyString(o.token, 16 * 1024)) return null;
  if (!isUnixTime(o.expiresAt)) return null;
  return { token: o.token, expiresAt: o.expiresAt };
}

function parseUpdate(o: JsonObject): ProtocolUpdate | null {
  if (!isString(o.latestVersion, 64)) return null;
  if (!(o.minVersion === null || o.minVersion === undefined || isString(o.minVersion, 64))) return null;
  if (typeof o.updateAvailable !== 'boolean' || typeof o.mandatory !== 'boolean') return null;
  if (!isString(o.changelog, MAX_DATA_LENGTH)) return null;
  return {
    latestVersion: o.latestVersion,
    minVersion: o.minVersion ?? null,
    updateAvailable: o.updateAvailable,
    mandatory: o.mandatory,
    changelog: o.changelog,
  };
}

function parseDownload(o: JsonObject): ProtocolDownload | null {
  if (!isNonEmptyString(o.url, 4096)) return null;
  if (!isUnixTime(o.expiresAt)) return null;
  if (!isString(o.fileName, 255)) return null;
  if (!isCount(o.size)) return null;
  if (!isHex64(o.sha256)) return null;
  if (!isString(o.version, 64)) return null;
  return {
    url: o.url,
    expiresAt: o.expiresAt,
    fileName: o.fileName,
    size: o.size,
    sha256: o.sha256.toLowerCase(),
    version: o.version,
  };
}

/** Device secrets are opaque printable ASCII tokens. */
export function isDeviceSecret(value: unknown): value is string {
  return typeof value === 'string' && /^[\x21-\x7e]{16,256}$/.test(value);
}
