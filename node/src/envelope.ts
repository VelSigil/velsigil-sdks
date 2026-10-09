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
import { verifyLeaseAllowingTestKeys } from './lease.js';
import { refusePublishedTestKey, resolvePublicKey, verifySignature } from './signature.js';
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

const MAX_DATA_LENGTH = 1024 * 1024;

const REQUEST_TYPES: readonly RequestType[] = ['validate', 'deactivate', 'update_check', 'download', 'trial'];
const TRIAL_KEY_RE = /^[\x21-\x7e]{1,64}$/;
const LICENSE_STATUSES: readonly LicenseStatus[] = [
  'pending',
  'active',
  'suspended',
  'expired',
  'revoked',
  'banned',
];

/** Outcome of a response envelope check. */
export type EnvelopeStatus =
  | 'valid'
  | 'invalid_signature'
  | 'nonce_mismatch'
  | 'product_mismatch'
  | 'type_mismatch'
  | 'hwid_mismatch'
  | 'malformed';

/** Result of {@link verifyEnvelope}. */
export type EnvelopeVerification =
  | { status: 'valid'; payload: ResponsePayload }
  | { status: Exclude<EnvelopeStatus, 'valid'>; reason: string };

/** What a signed response must match. */
export interface EnvelopeExpectations {
  /** The nonce sent with the request. */
  nonce: string;
  productId: string;
  /** Required: otherwise a signed answer from another endpoint could pass as a validation. */
  type: RequestType;
  /** The hwid of a device-bound request; the signed lease and activation must belong to it. */
  hwid?: string;
}

/** Verifies the signature first, then decodes the payload and checks it against `expected`. */
export function verifyEnvelope(
  publicKey: string | KeyObject,
  envelope: unknown,
  expected: EnvelopeExpectations,
): EnvelopeVerification {
  return verifyEnvelopeWith(publicKey, envelope, expected, true);
}

/** Internal: the client constructor has already applied its test-key rule. */
export function verifyEnvelopeAllowingTestKeys(
  publicKey: string | KeyObject,
  envelope: unknown,
  expected: EnvelopeExpectations,
): EnvelopeVerification {
  return verifyEnvelopeWith(publicKey, envelope, expected, false);
}

function verifyEnvelopeWith(
  publicKey: string | KeyObject,
  envelope: unknown,
  expected: EnvelopeExpectations,
  refuseTestKeys: boolean,
): EnvelopeVerification {
  // JavaScript callers can omit `type`; refuse rather than skip the check.
  if (!isObject(expected) || !isOneOf(expected.type, REQUEST_TYPES)) {
    throw new VelsigilError(
      'invalid_argument',
      'expected.type must be the request type: validate, deactivate, update_check, download or trial',
    );
  }
  const resolved = resolvePublicKey(publicKey);
  const key = refuseTestKeys ? refusePublishedTestKey(resolved) : resolved;
  if (!isObject(envelope)) return { status: 'malformed', reason: 'Response is not a signed envelope' };

  const { data, sig } = envelope;
  if (typeof data !== 'string' || data.length === 0 || data.length > MAX_DATA_LENGTH) {
    return { status: 'malformed', reason: 'Envelope data is missing' };
  }
  if (typeof sig !== 'string' || sig.length === 0) {
    return { status: 'invalid_signature', reason: 'Envelope signature is missing' };
  }
  // UTF-8, not ASCII, so hostile non-ASCII input is not silently mapped to other bytes.
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

/** The signature alone does not bind a response to this device, so a sharing proxy could swap it. */
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
    const lease = verifyLeaseAllowingTestKeys(key, payload.lease.token, { productId, hwid, now: payload.serverTime });
    if (lease.status === 'hwid_mismatch') {
      return { status: 'hwid_mismatch', reason: 'Response lease was issued for a different device' };
    }
    if (lease.status === 'product_mismatch') {
      return { status: 'product_mismatch', reason: 'Response lease belongs to a different product' };
    }
  }
  return null;
}

/** Validates the payload shape and copies known fields into fresh objects. */
export function parseResponsePayload(value: unknown): ResponsePayload | null {
  if (!isObject(value)) return null;
  if (value.v !== 1) return null;
  if (!isOneOf(value.type, REQUEST_TYPES)) return null;
  if (typeof value.ok !== 'boolean') return null;
  if (!isCode(value.code)) return null;
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
  // Only an `ok` trial answer may carry a key.
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

/** Absent gives null, a valid object the parsed value, anything else undefined. */
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
  const trial = o.trial;
  if (!(trial === null || trial === undefined || typeof trial === 'boolean')) return null;
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

export function isDeviceSecret(value: unknown): value is string {
  return typeof value === 'string' && /^[\x21-\x7e]{16,256}$/.test(value);
}
