import type { VelsigilCode } from './codes.js';
import { withTrialRef } from './trial-ref.js';
import type { ActivationStatus, LicenseStatus, ProtocolDownload, ProtocolUpdate, RequestType } from './types.js';

/** License details in unix seconds; device counts and `createdAt` are null on offline results. */
export interface LicenseInfo {
  readonly id: string;
  readonly plan: string;
  readonly status: LicenseStatus;
  readonly features: readonly string[];
  readonly expiresAt: number | null;
  readonly maxDevices: number | null;
  readonly devicesUsed: number | null;
  readonly createdAt: number | null;
  /** True for a free-trial license. */
  readonly isTrial?: boolean;
  /** See {@link VelsigilResult.trialRef}. */
  readonly trialRef?: string | null;
}

/** The server-side device record; the device secret itself is never exposed. */
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

/** Update check details. */
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
  /** Time of an offline check, used by `daysRemaining` when there is no `serverTime`. */
  referenceTime?: number | null;
}

const DAY_SECONDS = 86_400;

/** Immutable outcome of an SDK call; failures have `ok === false` and only configuration mistakes throw. */
export class VelsigilResult {
  /** True only for a verified, signed success or a valid offline lease. */
  readonly ok: boolean;
  /** Server code (e.g. `license_expired`) or SDK code (e.g. `network_error`). */
  readonly code: VelsigilCode;
  readonly message: string;
  /** The request that produced this result, or null for local results. */
  readonly type: RequestType | null;
  readonly license: LicenseInfo | null;
  readonly activation: ActivationInfo | null;
  readonly lease: LeaseInfo | null;
  readonly update: UpdateInfo | null;
  readonly download: DownloadInfo | null;
  /** Server request id; quote it to support. */
  readonly requestId: string | null;
  /** Server time (unix seconds) from a signed response. */
  readonly serverTime: number | null;
  /** True when the result came from the stored offline lease. */
  readonly offline: boolean;
  /** Seconds from the server's `Retry-After` on a 429 or 503 (capped at one day), else null. */
  readonly retryAfter: number | null;
  /** Key of the trial `startTrial` just started. The server sends it only once; store it. */
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

  /** True when the result is ok and the license grants `feature`. */
  hasFeature(feature: string): boolean {
    return this.ok && this.license !== null && this.license.features.includes(feature);
  }

  /** License expiry, or null for lifetime licenses and results without a license. */
  get expiresAt(): Date | null {
    const at = this.license?.expiresAt;
    return at === null || at === undefined ? null : new Date(at * 1000);
  }

  /** True for a free trial; turns false on the next online validation after a purchase. */
  get isTrial(): boolean {
    return this.license?.isTrial === true;
  }

  /** The trial's conversion reference for the "Buy now" link, or null (always null offline). */
  get trialRef(): string | null {
    return this.license?.trialRef ?? null;
  }

  /** `buyUrl` with this trial's conversion reference, or unchanged when there is none. */
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

  /** Seconds until the license expires (0 when past), or null without an expiry. */
  secondsRemaining(nowMs: number = Date.now()): number | null {
    const at = this.license?.expiresAt;
    if (at === null || at === undefined) return null;
    return Math.max(0, at - Math.floor(nowMs / 1000));
  }

  /** Days until expiry, rounded up, measured at the result's own time by default; null without an expiry. */
  daysRemaining(nowMs?: number): number | null {
    const seconds = this.secondsRemaining(nowMs ?? this.#referenceMs());
    return seconds === null ? null : Math.ceil(seconds / DAY_SECONDS);
  }

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
