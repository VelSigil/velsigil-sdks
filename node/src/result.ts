import type { VelsigilCode } from './codes.js';
import { withTrialRef } from './trial-ref.js';
import type { ActivationStatus, LicenseStatus, ProtocolDownload, ProtocolUpdate, RequestType } from './types.js';

/**
 * License details. Times are unix seconds. When the result comes from an offline lease,
 * `maxDevices`, `devicesUsed` and `createdAt` are unknown and therefore `null`.
 */
export interface LicenseInfo {
  readonly id: string;
  readonly plan: string;
  readonly status: LicenseStatus;
  readonly features: readonly string[];
  readonly expiresAt: number | null;
  readonly maxDevices: number | null;
  readonly devicesUsed: number | null;
  readonly createdAt: number | null;
  /**
   * True for a free-trial license (SPEC 9.7: the signed `trial` field, also in offline leases). The SDK always sets it;
   * optional only so that objects built by older code still type-check.
   */
  readonly isTrial?: boolean;
  /**
   * The trial's conversion reference (SPEC 9.7): set for a free trial a purchase can still convert (servers since
   * 2026-10-06), null otherwise and for offline results. See {@link VelsigilResult.trialRef}.
   */
  readonly trialRef?: string | null;
}

/**
 * The server-side device record. The device secret itself is never exposed on results (it is
 * persisted by the SDK); `deviceSecretIssued` tells whether this response issued a new one.
 */
export interface ActivationInfo {
  readonly id: string;
  readonly status: ActivationStatus;
  readonly firstSeenAt: number | null;
  readonly deviceSecretIssued: boolean;
}

/** Offline lease: a signed token that lets {@link VelsigilClient.validateOffline} work until `expiresAt`. */
export interface LeaseInfo {
  readonly token: string;
  readonly expiresAt: number;
}

export type UpdateInfo = Readonly<ProtocolUpdate>;

/** A short-lived download link. `url` is absolute. */
export type DownloadInfo = Readonly<ProtocolDownload>;

export interface ResultInit {
  ok: boolean;
  code: VelsigilCode;
  message: string;
  type?: RequestType | null;
  license?: LicenseInfo | null;
  activation?: ActivationInfo | null;
  lease?: LeaseInfo | null;
  update?: UpdateInfo | null;
  download?: DownloadInfo | null;
  requestId?: string | null;
  serverTime?: number | null;
  offline?: boolean;
  retryAfter?: number | null;
  trialKey?: string | null;
  /**
   * Unix seconds the result refers to when it has no `serverTime` (offline results: the time of the check, local clock
   * plus the learned server offset). The default `now` of {@link VelsigilResult.daysRemaining}; null = the local clock.
   */
  referenceTime?: number | null;
}

const DAY_SECONDS = 86_400;

/**
 * Immutable outcome of an SDK call. Business failures, network errors and invalid responses are
 * all represented here with `ok === false`; only configuration mistakes throw.
 */
export class VelsigilResult {
  /** True only for a verified, signed success (or a valid offline lease). */
  readonly ok: boolean;
  /** Server code (e.g. `ok`, `license_expired`) or SDK code (`network_error`, `invalid_response`, ...). */
  readonly code: VelsigilCode;
  /** Human readable message (server text for signed responses, SDK text otherwise). */
  readonly message: string;
  /** Which request produced this result (`null` for locally generated results without a request). */
  readonly type: RequestType | null;
  readonly license: LicenseInfo | null;
  readonly activation: ActivationInfo | null;
  readonly lease: LeaseInfo | null;
  readonly update: UpdateInfo | null;
  readonly download: DownloadInfo | null;
  /** Server request id (signed payload, or best effort for unsigned errors). Quote it to support. */
  readonly requestId: string | null;
  /** Authoritative server time (unix seconds) from a signed response. */
  readonly serverTime: number | null;
  /** True when the result was produced from a stored offline lease without contacting the server. */
  readonly offline: boolean;
  /**
   * Seconds the server asked to wait before trying again (0..86400, a longer wait reads as one day): the `Retry-After`
   * header (delta-seconds or HTTP date) of every HTTP 429 or 503 answer, whatever code it maps to (`rate_limited`;
   * `network_error` for the empty 503 of a server whose database is unreachable, or a gateway's 503; `internal_error`
   * for 503 `service_busy`). The results of the offline fallback of {@link VelsigilClient.validateWithOfflineFallback} (offline `ok`, `lease_expired`,
   * `lease_invalid`) carry the value of the failed online attempt, so the app knows when to try online again. Null
   * when the header is absent or unparseable, for every other status and for {@link VelsigilClient.validateOffline}.
   */
  readonly retryAfter: number | null;
  /**
   * The license key of the free trial that {@link VelsigilClient.startTrial} just started (`ok` results only; null
   * otherwise). The server sends it exactly once and cannot send it again: store it right away, like a key the user
   * typed, and use it for every later `validate`. The SDK never persists it.
   */
  readonly trialKey: string | null;
  readonly #referenceTime: number | null;

  constructor(init: ResultInit) {
    this.ok = init.ok === true;
    this.code = init.code;
    this.message = init.message;
    this.type = init.type ?? null;
    this.license = freezeLicense(init.license ?? null);
    this.activation = init.activation ? Object.freeze({ ...init.activation }) : null;
    this.lease = init.lease ? Object.freeze({ ...init.lease }) : null;
    this.update = init.update ? Object.freeze({ ...init.update }) : null;
    this.download = init.download ? Object.freeze({ ...init.download }) : null;
    this.requestId = init.requestId ?? null;
    this.serverTime = init.serverTime ?? null;
    this.offline = init.offline === true;
    this.retryAfter = init.retryAfter ?? null;
    this.trialKey = this.ok ? (init.trialKey ?? null) : null;
    this.#referenceTime = init.referenceTime ?? null;
    Object.freeze(this);
  }

  /** True when the result is ok AND the license grants `feature`. Always false for failures. */
  hasFeature(feature: string): boolean {
    return this.ok && this.license !== null && this.license.features.includes(feature);
  }

  /** License expiry as a Date, or null for lifetime licenses / results without a license. */
  get expiresAt(): Date | null {
    const at = this.license?.expiresAt;
    return at === null || at === undefined ? null : new Date(at * 1000);
  }

  /**
   * True when the license is a free trial (SPEC 9.7). Use it for "Trial: N days left" / "Buy now" UI; the license
   * stays the same after a purchase, and this turns false with the next online validation.
   */
  get isTrial(): boolean {
    return this.license?.isTrial === true;
  }

  /**
   * The current trial's conversion reference (SPEC 9.7), or null: present on online results for a free trial a purchase
   * can still convert, also on `license_expired` (the moment to offer "Buy now"). Add it to the "Buy now" link with
   * {@link withTrialRef}: the purchase then converts THIS trial into the paid license (same key) whatever e-mail address
   * the buyer pays with. Opaque; a fresh one comes with every answer; offline results have none.
   */
  get trialRef(): string | null {
    return this.license?.trialRef ?? null;
  }

  /**
   * `buyUrl` with this trial's conversion reference (`velsigil_trial=<ref>`; Stripe Payment Links: `client_reference_id`),
   * or `buyUrl` unchanged when there is none (a paid license, an offline result, an older server).
   */
  withTrialRef(buyUrl: string): string {
    return withTrialRef(buyUrl, this.trialRef);
  }

  /** True when the license has no expiry date. */
  get isLifetime(): boolean {
    return this.license !== null && this.license.expiresAt === null;
  }

  /** Offline lease expiry as a Date, or null when no lease is attached. */
  get leaseExpiresAt(): Date | null {
    return this.lease === null ? null : new Date(this.lease.expiresAt * 1000);
  }

  /**
   * Whole seconds until the license expires (0 when already past), or null for lifetime licenses
   * and results without a license. `nowMs` defaults to the local clock.
   */
  secondsRemaining(nowMs: number = Date.now()): number | null {
    const at = this.license?.expiresAt;
    if (at === null || at === undefined) return null;
    return Math.max(0, at - Math.floor(nowMs / 1000));
  }

  /**
   * Days until the license expires, rounded UP (the "days left" rule of CLIENT_PROTOCOL 5.2, the same in every Velsigil
   * SDK), or null for lifetime licenses and results without a license. Without `nowMs` it measures at the result's own
   * time: the signed `serverTime` of an online answer, the time of the check for an offline result (local clock plus
   * the learned server offset). So right after `startTrial` of an N-day trial it is N; it is 1 throughout the last day
   * and 0 once expired.
   */
  daysRemaining(nowMs?: number): number | null {
    const seconds = this.secondsRemaining(nowMs ?? this.#referenceMs());
    return seconds === null ? null : Math.ceil(seconds / DAY_SECONDS);
  }

  /** The result's own time in milliseconds (see {@link daysRemaining}); the local clock when it has none. */
  #referenceMs(): number {
    const reference = this.serverTime ?? this.#referenceTime;
    return reference === null ? Date.now() : reference * 1000;
  }

  /** True when the license carries an expiry date that has passed. */
  isExpired(nowMs: number = Date.now()): boolean {
    return this.secondsRemaining(nowMs) === 0;
  }

  /** True when the license expires within `days` days (and has not expired yet). */
  expiresWithin(days: number, nowMs: number = Date.now()): boolean {
    const seconds = this.secondsRemaining(nowMs);
    return seconds !== null && seconds > 0 && seconds <= days * DAY_SECONDS;
  }
}

function freezeLicense(license: LicenseInfo | null): LicenseInfo | null {
  if (license === null) return null;
  return Object.freeze({ ...license, features: Object.freeze([...license.features]) });
}
