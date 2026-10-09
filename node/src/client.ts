import type { KeyObject } from 'node:crypto';
import { LEASE_REVOKING_CODES, UNSIGNED_ERROR_CODES, type VelsigilCode } from './codes.js';
import { downloadToFile, type DownloadFileOptions, type DownloadFileResult } from './download.js';
import { generateNonce, parseJsonBytes } from './encoding.js';
import { verifyEnvelopeAllowingTestKeys } from './envelope.js';
import { VelsigilError } from './errors.js';
import { isObject, isOneOf, UUID_RE } from './guards.js';
import { parseRetryAfter, postJson, type FetchFunction, type HttpOutcome } from './http.js';
import { getHardwareId } from './hwid.js';
import { verifyLeaseAllowingTestKeys } from './lease.js';
import { Mutex } from './mutex.js';
import {
  VelsigilResult,
  type ActivationInfo,
  type DownloadInfo,
  type LicenseInfo,
  type ResultInit,
} from './result.js';
import { isPublishedTestKey, parsePublicKeyAllowingTestKeys, PUBLISHED_TEST_KEY_MESSAGE } from './signature.js';
import { emptyState, MemoryStore, sanitizeState, type StoredState, type VelsigilStore } from './store.js';
import type { LeasePayload, ProtocolLicense, RequestType, ResponsePayload } from './types.js';
import { SDK_VERSION } from './version.js';

/** Options of {@link VelsigilClient}. */
export interface VelsigilClientOptions {
  /** Request timeout in milliseconds (default 15 000, max 600 000). */
  timeout?: number;
  /** Hardware id override (8-256 characters); must be stable or every run is a new activation. */
  hwid?: string;
  /** Persistence for the device secret and offline lease (default: in-memory {@link MemoryStore}). */
  store?: VelsigilStore;
  /** Allow plain `http://` to non-loopback hosts. Never enable this in production. */
  allowInsecureHttp?: boolean;
  /** Custom fetch implementation, e.g. one with a proxy. */
  fetch?: FetchFunction;
  /** Clock in milliseconds since the epoch (default `Date.now`). */
  clock?: () => number;
  /** Called when the store fails to load or save; the SDK keeps working from memory. */
  onStoreError?: (error: unknown) => void;
  /** Maximum accepted response size in bytes (default 1 MiB). */
  maxResponseBytes?: number;
}

/** Per-call options of {@link VelsigilClient.validate}. */
export interface ValidateOptions {
  /** Your application version (max 32 chars); enables `outdated_version` and update info. */
  version?: string;
  /** Device name shown to the seller and customer (max 255 chars). */
  deviceName?: string;
}

/** Per-call options of {@link VelsigilClient.startTrial}. */
export interface StartTrialOptions extends ValidateOptions {
  /** Customer e-mail (max 254 chars), used only when the trial offer requires e-mail confirmation. */
  email?: string;
}

const CLIENT_API_PATH = '/api/client/v1';
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 600_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_LICENSE_KEY_LENGTH = 64;
const MAX_VERSION_LENGTH = 32;
const MAX_DEVICE_NAME_LENGTH = 255;
const MAX_EMAIL_LENGTH = 254;
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** Unsigned responses carry no trustworthy text, so the SDK supplies its own. */
const UNSIGNED_MESSAGES: Record<string, string> = {
  validation_error: 'The license server rejected the request as invalid.',
  ip_blocked: 'Requests from this network are blocked by the license server.',
  unknown_product: 'The license server does not know this product.',
  rate_limited: 'Too many requests. Please try again later.',
  internal_error: 'The license server encountered an internal error.',
  payload_too_large: 'The request was too large.',
  unsupported_media_type: 'The license server rejected the request format.',
};

const PANEL_TOO_OLD_MESSAGE =
  'The license server does not support starting free trials from the app yet. The seller needs to update the Velsigil panel.';

const ALREADY_LICENSED_MESSAGE =
  'This device already holds a license for this product (a stored device secret or offline lease); a free trial cannot ' +
  'replace it. Validate the saved license key instead, or call deactivate() or clearStoredState() first. No request was sent.';

const STORE_UNAVAILABLE_MESSAGE =
  'The license store could not be read, so it is unknown whether this device already holds a license for this product; ' +
  'a free trial was not started. Try again once the store can be read. No request was sent.';

interface Exchange {
  result: VelsigilResult;
  payload: ResponsePayload | null;
  /** No HTTP response or an unsigned 5xx; this triggers the offline fallback. */
  unavailable: boolean;
}

interface OnlineValidation {
  result: VelsigilResult;
  unavailable: boolean;
}

function localValidationFailure(message: string): OnlineValidation {
  return { result: localFailure('validation_error', message, 'validate'), unavailable: false };
}

/** When `fresh` is false the store could not be read; never treat `state` as "nothing stored". */
interface LoadedState {
  state: StoredState;
  fresh: boolean;
}

type RequestFields = Record<string, string | undefined>;

/** Velsigil license client; verifies every response's signature and never throws for licensing failures. */
export class VelsigilClient {
  /** The product id (lowercased). */
  readonly productId: string;
  /** The hardware id sent to the server. */
  readonly hardwareId: string;

  readonly #publicKey: KeyObject;
  readonly #base: URL;
  readonly #allowInsecureHttp: boolean;
  readonly #timeout: number;
  readonly #maxResponseBytes: number;
  readonly #store: VelsigilStore;
  readonly #fetch: FetchFunction;
  readonly #clock: () => number;
  readonly #onStoreError: ((error: unknown) => void) | undefined;
  readonly #userAgent = `velsigil-client-node/${SDK_VERSION}`;
  readonly #deviceLock = new Mutex();
  #clockOffset = 0;
  /** Authoritative while `#unsaved` (a store write failed). */
  #memoryState: StoredState = emptyState();
  /** Until the store was read or written once, `#memoryState` is only a placeholder. */
  #memoryKnown = false;
  #unsaved = false;

  /**
   * @param apiUrl Your Velsigil server URL; HTTPS is required except for loopback hosts.
   * @param productId The product UUID from the Velsigil panel.
   * @param publicKeyBase64 The product's public key; ship it inside your app, never load it from config.
   * @throws {VelsigilError} for invalid configuration or when no hardware id can be determined.
   */
  constructor(apiUrl: string, productId: string, publicKeyBase64: string, options: VelsigilClientOptions = {}) {
    if (options === null || typeof options !== 'object') {
      throw new VelsigilError('invalid_configuration', 'options must be an object');
    }
    this.#allowInsecureHttp = options.allowInsecureHttp === true;
    this.#base = resolveApiBase(apiUrl, this.#allowInsecureHttp);

    if (typeof productId !== 'string' || !UUID_RE.test(productId.trim())) {
      throw new VelsigilError('invalid_configuration', 'productId must be the product UUID from the Velsigil panel');
    }
    this.productId = productId.trim().toLowerCase();
    // The only test-key check: later verifications use the `...AllowingTestKeys` paths.
    this.#publicKey = parsePublicKeyAllowingTestKeys(publicKeyBase64);
    if (isPublishedTestKey(this.#publicKey) && !isLoopbackHost(this.#base.hostname)) {
      throw new VelsigilError('invalid_public_key', PUBLISHED_TEST_KEY_MESSAGE);
    }

    const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout <= 0 || timeout > MAX_TIMEOUT_MS) {
      throw new VelsigilError('invalid_configuration', `timeout must be between 1 and ${MAX_TIMEOUT_MS} milliseconds`);
    }
    this.#timeout = timeout;

    const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024) {
      throw new VelsigilError('invalid_configuration', 'maxResponseBytes must be an integer >= 1024');
    }
    this.#maxResponseBytes = maxBytes;

    const store = options.store ?? new MemoryStore();
    if (
      typeof store !== 'object' ||
      store === null ||
      typeof store.load !== 'function' ||
      typeof store.save !== 'function' ||
      typeof store.clear !== 'function'
    ) {
      throw new VelsigilError('invalid_configuration', 'store must implement load, save and clear');
    }
    this.#store = store;

    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
      throw new VelsigilError('invalid_configuration', 'No fetch implementation available (Node.js >= 22 required)');
    }
    this.#fetch = fetchImpl;

    if (options.clock !== undefined && typeof options.clock !== 'function') {
      throw new VelsigilError('invalid_configuration', 'clock must be a function returning milliseconds');
    }
    this.#clock = options.clock ?? Date.now;
    this.#onStoreError = typeof options.onStoreError === 'function' ? options.onStoreError : undefined;

    if (options.hwid !== undefined) {
      if (typeof options.hwid !== 'string' || !/^[\x21-\x7e]{8,256}$/.test(options.hwid)) {
        throw new VelsigilError('invalid_configuration', 'hwid must be 8-256 printable ASCII characters');
      }
      this.hardwareId = options.hwid;
    } else {
      this.hardwareId = getHardwareId();
    }
  }

  /** This machine's hardware id, cached per process. */
  static getHardwareId(): string {
    return getHardwareId();
  }

  /** Learned `serverTime - localTime` in seconds (0 until a clock_skew response). */
  get clockOffset(): number {
    return this.#clockOffset;
  }

  /** Validates (and on first use activates) the license on this device. Never throws. */
  async validate(licenseKey: string, options: ValidateOptions = {}): Promise<VelsigilResult> {
    return (await this.#validateOnline(licenseKey, options)).result;
  }

  /** Starts a free trial without a key. The server sends `result.trialKey` only once; store it. Never throws. */
  startTrial(options: StartTrialOptions = {}): Promise<VelsigilResult> {
    return this.#deviceLock.run(async () => {
      const version = optionalText(options?.version, MAX_VERSION_LENGTH);
      const deviceName = optionalText(options?.deviceName, MAX_DEVICE_NAME_LENGTH);
      const email = optionalText(options?.email, MAX_EMAIL_LENGTH);
      if (version === null) return localFailure('validation_error', 'version is too long.', 'trial');
      if (deviceName === null) return localFailure('validation_error', 'deviceName is too long.', 'trial');
      if (email === null) return localFailure('validation_error', 'email is too long.', 'trial');

      const loaded = await this.#loadState();
      // Fail closed: an unreadable store may hold a paid license.
      if (!loaded.fresh) return localFailure('store_unavailable', STORE_UNAVAILABLE_MESSAGE, 'trial');
      // A trial must not overwrite this device's license; the device lock keeps validate out meanwhile.
      if (loaded.state.deviceSecret !== null || loaded.state.lease !== null) {
        return localFailure('already_licensed', ALREADY_LICENSED_MESSAGE, 'trial');
      }
      const { result, payload } = await this.#exchange('trial', 'trial', {
        hwid: this.hardwareId,
        deviceName,
        version,
        email,
      });
      if (payload !== null) await this.#applyPayload(loaded, payload);
      return result;
    });
  }

  /** Removes this device's activation from the license. Clears local device state on success. */
  deactivate(licenseKey: string): Promise<VelsigilResult> {
    return this.#deviceLock.run(async () => {
      const key = normalizeKey(licenseKey);
      if (key === null) return localFailure('validation_error', 'License key is missing or too long.', 'deactivate');
      const loaded = await this.#loadState();
      const { result, payload } = await this.#exchange('deactivate', 'deactivate', {
        licenseKey: key,
        hwid: this.hardwareId,
        deviceSecret: loaded.state.deviceSecret ?? undefined,
      });
      if (payload !== null && (payload.code === 'ok' || payload.code === 'device_not_found')) {
        await this.#saveState(emptyState());
      } else if (payload !== null) {
        await this.#applyPayload(loaded, payload);
      }
      return result;
    });
  }

  /** Asks for the latest published release; details are in `result.update`. */
  async checkUpdate(currentVersion?: string): Promise<VelsigilResult> {
    const version = optionalText(currentVersion, MAX_VERSION_LENGTH);
    if (version === null) return localFailure('validation_error', 'version is too long.', 'update_check');
    const { result } = await this.#exchange('update_check', 'update-check', { version });
    return result;
  }

  /** Requests a short-lived download link for the latest or given release; needs an activated device. */
  getDownload(licenseKey: string, version?: string): Promise<VelsigilResult> {
    return this.#deviceLock.run(async () => {
      const key = normalizeKey(licenseKey);
      if (key === null) return localFailure('validation_error', 'License key is missing or too long.', 'download');
      const requestedVersion = optionalText(version, MAX_VERSION_LENGTH);
      if (requestedVersion === null) return localFailure('validation_error', 'version is too long.', 'download');
      const loaded = await this.#loadState();
      const { result, payload } = await this.#exchange('download', 'download', {
        licenseKey: key,
        hwid: this.hardwareId,
        deviceSecret: loaded.state.deviceSecret ?? undefined,
        version: requestedVersion,
      });
      if (payload !== null) await this.#applyPayload(loaded, payload);
      return result;
    });
  }

  /** Downloads a release and verifies its signed size and SHA-256 before it appears at `destination`. */
  async downloadRelease(
    download: DownloadInfo,
    destination: string,
    options: DownloadFileOptions = {},
  ): Promise<DownloadFileResult> {
    if (
      !isObject(download) ||
      typeof download.url !== 'string' ||
      typeof download.sha256 !== 'string' ||
      !/^[0-9a-fA-F]{64}$/.test(download.sha256) ||
      !Number.isSafeInteger(download.size) ||
      download.size < 0
    ) {
      return Object.freeze({
        ok: false,
        code: 'validation_error' as const,
        message: 'Invalid download info (use result.download from getDownload)',
        path: null,
        bytes: 0,
        sha256: null,
      });
    }
    const url = this.#resolveDownloadUrl(download.url);
    if (url === null) {
      return Object.freeze({
        ok: false,
        code: 'download_failed' as const,
        message: 'The download URL is not allowed (HTTPS is required)',
        path: null,
        bytes: 0,
        sha256: null,
      });
    }
    return downloadToFile({ ...download, url }, destination, { fetch: this.#fetch, userAgent: this.#userAgent }, options);
  }

  /** Validates the stored offline lease without contacting the server. Never throws. */
  validateOffline(): Promise<VelsigilResult> {
    return this.#deviceLock.run(() => this.#validateOfflineUnlocked());
  }

  /** Validates online; uses the offline lease only if there is no response or an unsigned 5xx. */
  async validateWithOfflineFallback(licenseKey: string, options: ValidateOptions = {}): Promise<VelsigilResult> {
    const online = await this.#validateOnline(licenseKey, options);
    if (!online.unavailable) return online.result;
    const offline = await this.#deviceLock.run(() => this.#validateOfflineUnlocked(online.result.retryAfter));
    return offline.code === 'no_lease' ? online.result : offline;
  }

  /** Forgets the stored device secret and offline lease for this product. */
  clearStoredState(): Promise<void> {
    return this.#deviceLock.run(() => this.#saveState(emptyState()));
  }

  #localNowSeconds(): number {
    return Math.floor(this.#clock() / 1000);
  }

  #serverNowSeconds(): number {
    return this.#localNowSeconds() + this.#clockOffset;
  }

  #validateOnline(licenseKey: string, options: ValidateOptions): Promise<OnlineValidation> {
    return this.#deviceLock.run(async () => {
      const local = localValidationFailure;
      const key = normalizeKey(licenseKey);
      if (key === null) return local('License key is missing or too long.');
      const version = optionalText(options?.version, MAX_VERSION_LENGTH);
      const deviceName = optionalText(options?.deviceName, MAX_DEVICE_NAME_LENGTH);
      if (version === null) return local('version is too long.');
      if (deviceName === null) return local('deviceName is too long.');

      const loaded = await this.#loadState();
      const { result, payload, unavailable } = await this.#exchange('validate', 'validate', {
        licenseKey: key,
        hwid: this.hardwareId,
        deviceSecret: loaded.state.deviceSecret ?? undefined,
        deviceName,
        version,
      });
      if (payload !== null) await this.#applyPayload(loaded, payload);
      return { result, unavailable };
    });
  }

  /** Sends one request; a signed `clock_skew` sets the clock offset and retries once. */
  async #exchange(type: RequestType, endpoint: string, fields: RequestFields): Promise<Exchange> {
    const url = new URL(endpoint, this.#base).toString();
    let exchange: Exchange | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const nonce = generateNonce();
      const body: Record<string, string | number> = { productId: this.productId };
      for (const [name, value] of Object.entries(fields)) {
        if (value !== undefined) body[name] = value;
      }
      body.nonce = nonce;
      body.timestamp = this.#serverNowSeconds();

      const outcome = await postJson(url, body, {
        fetch: this.#fetch,
        timeoutMs: this.#timeout,
        maxResponseBytes: this.#maxResponseBytes,
        userAgent: this.#userAgent,
      });
      exchange = this.#interpret(outcome, type, nonce, fields.hwid);
      const payload = exchange.payload;
      if (payload !== null && payload.code === 'clock_skew' && !payload.ok) {
        this.#clockOffset = payload.serverTime - this.#localNowSeconds();
        continue;
      }
      return exchange;
    }
    return exchange as Exchange;
  }

  #interpret(outcome: HttpOutcome, type: RequestType, nonce: string, hwid: string | undefined): Exchange {
    if (outcome.kind === 'network_error') {
      return {
        payload: null,
        result: localFailure(
          'network_error',
          outcome.timedOut ? 'The license server did not respond in time.' : 'Could not reach the license server.',
          type,
        ),
        unavailable: true,
      };
    }
    if (outcome.kind === 'too_large') {
      return {
        payload: null,
        result: new VelsigilResult({
          ok: false,
          code: 'invalid_response',
          message: 'The server response is too large.',
          type,
          retryAfter: this.#retryAfter(outcome.status, outcome.headers),
        }),
        unavailable: isServerErrorStatus(outcome.status),
      };
    }

    const { status, headers, body } = outcome;
    if (status === 200) {
      const json = parseJsonBytes(body);
      if (!json.ok) {
        return {
          payload: null,
          result: localFailure('invalid_response', 'The server response is not valid JSON.', type),
          unavailable: false,
        };
      }
      const verification = verifyEnvelopeAllowingTestKeys(this.#publicKey, json.value, {
        nonce,
        productId: this.productId,
        type,
        hwid,
      });
      if (verification.status !== 'valid') {
        return {
          payload: null,
          result: localFailure('invalid_response', `Untrusted server response: ${verification.reason}.`, type),
          unavailable: false,
        };
      }
      return { payload: verification.payload, result: this.#resultFromPayload(verification.payload), unavailable: false };
    }

    if ((status >= 300 && status < 400) || status === 0) {
      return {
        payload: null,
        result: localFailure('invalid_response', 'Unexpected redirect from the license server.', type),
        unavailable: false,
      };
    }
    return {
      payload: null,
      result: this.#unsignedError(status, headers, body, type),
      unavailable: isServerErrorStatus(status),
    };
  }

  /** Unsigned errors can never produce `ok === true`. */
  #unsignedError(status: number, headers: Headers, body: Uint8Array, type: RequestType): VelsigilResult {
    let code: VelsigilCode | null = null;
    let requestId: string | null = null;
    let velsigilBody = false;
    const json = parseJsonBytes(body);
    if (json.ok && isObject(json.value) && isObject(json.value.error) && typeof json.value.error.code === 'string') {
      const error = json.value.error;
      velsigilBody = true;
      if (isOneOf(error.code, UNSIGNED_ERROR_CODES)) code = error.code;
      // Servers without the trial endpoint answer a generic 404.
      else if (type === 'trial' && status === 404 && error.code === 'not_found') code = 'panel_too_old';
      if (typeof error.requestId === 'string' && isSafeRequestId(error.requestId)) requestId = error.requestId;
    }
    if (code === null) code = codeForStatus(status, velsigilBody);
    if (requestId === null) {
      const header = headers.get('x-request-id');
      if (header !== null && isSafeRequestId(header)) requestId = header;
    }
    const message =
      code === 'network_error'
        ? 'The license server is temporarily unavailable.'
        : code === 'invalid_response'
          ? `Unexpected HTTP status ${status} from the license server.`
          : code === 'panel_too_old'
            ? PANEL_TOO_OLD_MESSAGE
            : (UNSIGNED_MESSAGES[code] ?? 'The license server rejected the request.');
    return new VelsigilResult({
      ok: false,
      code,
      message,
      type,
      requestId,
      retryAfter: this.#retryAfter(status, headers),
    });
  }

  #retryAfter(status: number, headers: Headers): number | null {
    if (status !== 429 && status !== 503) return null;
    return parseRetryAfter(headers.get('retry-after'), this.#clock());
  }

  #resultFromPayload(payload: ResponsePayload): VelsigilResult {
    const init: ResultInit = {
      ok: payload.ok,
      code: payload.code,
      message: payload.message,
      type: payload.type,
      requestId: payload.requestId || null,
      serverTime: payload.serverTime,
      license: payload.license === null ? null : licenseInfo(payload.license),
      activation:
        payload.activation === null
          ? null
          : {
              id: payload.activation.id,
              status: payload.activation.status,
              firstSeenAt: payload.activation.firstSeenAt,
              deviceSecretIssued: payload.activation.deviceSecret !== null,
            },
      lease: payload.lease,
      update: payload.update,
      download: null,
      trialKey: payload.trial?.key ?? null,
    };
    if (payload.download !== null) {
      const url = this.#resolveDownloadUrl(payload.download.url);
      if (url === null) {
        return localFailure('invalid_response', 'The server returned an insecure download URL.', payload.type);
      }
      init.download = { ...payload.download, url };
    }
    return new VelsigilResult(init);
  }

  /** Merges a verified answer into the stored state; a failed read must never wipe the stored secret. */
  async #applyPayload(loaded: LoadedState, payload: ResponsePayload): Promise<void> {
    const issued = payload.activation?.deviceSecret ?? null;
    let state = loaded.state;
    if (!loaded.fresh) {
      const again = await this.#loadState();
      // Store still unknown: only a newly issued secret is safe to write.
      if (!again.fresh && !this.#memoryKnown && issued === null) return;
      state = again.state;
    }
    const next: StoredState = { deviceSecret: state.deviceSecret, lease: state.lease };
    if (issued !== null) next.deviceSecret = issued;

    if (payload.ok && (payload.type === 'validate' || payload.type === 'trial')) {
      next.lease = null;
      if (payload.lease !== null) {
        const check = verifyLeaseAllowingTestKeys(this.#publicKey, payload.lease.token, {
          productId: this.productId,
          hwid: this.hardwareId,
          now: payload.serverTime,
        });
        if (check.status === 'valid') {
          next.lease = { token: payload.lease.token, expiresAt: check.payload.exp };
        }
      }
    } else if (!payload.ok && LEASE_REVOKING_CODES.has(payload.code)) {
      next.lease = null;
    }

    const changed =
      next.deviceSecret !== state.deviceSecret ||
      next.lease?.token !== state.lease?.token ||
      next.lease?.expiresAt !== state.lease?.expiresAt;
    if (changed) await this.#saveState(next);
  }

  /** `retryAfter` comes from the failed online attempt when this is the fallback. */
  async #validateOfflineUnlocked(retryAfter: number | null = null): Promise<VelsigilResult> {
    const { state } = await this.#loadState();
    if (state.lease === null) {
      return new VelsigilResult({ ok: false, code: 'no_lease', message: 'No offline lease is stored.', offline: true });
    }
    const now = this.#serverNowSeconds();
    const check = verifyLeaseAllowingTestKeys(this.#publicKey, state.lease.token, {
      productId: this.productId,
      hwid: this.hardwareId,
      now,
    });
    if (check.status === 'valid') {
      return leaseResult(check.payload, state.lease.token, now, retryAfter);
    }
    if (check.status === 'expired') {
      return new VelsigilResult({
        ok: false,
        code: 'lease_expired',
        message: 'The offline lease has expired. Connect to the internet to validate the license.',
        offline: true,
        lease: { token: state.lease.token, expiresAt: check.payload.exp },
        retryAfter,
      });
    }
    // Tampered, foreign or corrupt: drop it.
    await this.#saveState({ deviceSecret: state.deviceSecret, lease: null });
    return new VelsigilResult({
      ok: false,
      code: 'lease_invalid',
      message: `The stored offline lease is not valid: ${check.reason}.`,
      offline: true,
      retryAfter,
    });
  }

  async #loadState(): Promise<LoadedState> {
    let fresh = true;
    if (this.#unsaved) {
      // The last save failed, so memory is newer than the store.
      await this.#saveState(this.#memoryState);
    } else {
      try {
        const loaded = await this.#store.load(this.productId);
        this.#memoryState = loaded === null || loaded === undefined ? emptyState() : sanitizeState(loaded);
        this.#memoryKnown = true;
      } catch (error) {
        this.#reportStoreError(error);
        fresh = false;
      }
    }
    return { state: { deviceSecret: this.#memoryState.deviceSecret, lease: this.#memoryState.lease }, fresh };
  }

  async #saveState(state: StoredState): Promise<void> {
    this.#memoryState = { deviceSecret: state.deviceSecret, lease: state.lease };
    this.#memoryKnown = true;
    try {
      if (state.deviceSecret === null && state.lease === null) {
        await this.#store.clear(this.productId);
      } else {
        await this.#store.save(this.productId, state);
      }
      this.#unsaved = false;
    } catch (error) {
      this.#unsaved = true;
      this.#reportStoreError(error);
    }
  }

  #reportStoreError(error: unknown): void {
    if (this.#onStoreError === undefined) return;
    try {
      this.#onStoreError(error);
    } catch {
      // A failing error callback must not break license checks.
    }
  }

  #resolveDownloadUrl(raw: string): string | null {
    let url: URL;
    try {
      url = new URL(raw, this.#base);
    } catch {
      return null;
    }
    if (url.username || url.password) return null;
    if (url.protocol === 'https:') return url.toString();
    if (url.protocol === 'http:' && (this.#allowInsecureHttp || isLoopbackHost(url.hostname))) {
      return url.toString();
    }
    return null;
  }
}

/** Shared by the plain-http rule and the test-key rule so they cannot drift apart. */
function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname);
}

function resolveApiBase(apiUrl: string, allowInsecureHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(typeof apiUrl === 'string' ? apiUrl.trim() : '');
  } catch {
    throw new VelsigilError('invalid_configuration', 'apiUrl must be an absolute URL such as https://licenses.example.com');
  }
  if (url.username || url.password) {
    throw new VelsigilError('invalid_configuration', 'apiUrl must not contain credentials');
  }
  if (url.search || url.hash) {
    throw new VelsigilError('invalid_configuration', 'apiUrl must not contain a query string or fragment');
  }
  if (url.protocol === 'http:') {
    if (!allowInsecureHttp && !isLoopbackHost(url.hostname)) {
      throw new VelsigilError(
        'invalid_configuration',
        'apiUrl must use https:// (plain http is only allowed for localhost unless allowInsecureHttp is set)',
      );
    }
  } else if (url.protocol !== 'https:') {
    throw new VelsigilError('invalid_configuration', 'apiUrl must use https://');
  }
  let path = url.pathname.replace(/\/+$/, '');
  if (!path.endsWith(CLIENT_API_PATH)) path += CLIENT_API_PATH;
  url.pathname = `${path}/`;
  return url;
}

function normalizeKey(licenseKey: unknown): string | null {
  if (typeof licenseKey !== 'string') return null;
  const key = licenseKey.trim();
  return key.length === 0 || key.length > MAX_LICENSE_KEY_LENGTH ? null : key;
}

/** Empty gives undefined (omitted); too long or not a string gives null (invalid). */
function optionalText(value: unknown, maxLength: number): string | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed.length > maxLength ? null : trimmed;
}

function isSafeRequestId(value: string): boolean {
  return /^[A-Za-z0-9._:-]{1,128}$/.test(value);
}

/** Used when an unsigned error body has no known code; the same mapping in every Velsigil SDK. */
function codeForStatus(status: number, velsigilBody: boolean): VelsigilCode {
  switch (status) {
    case 400:
      return 'validation_error';
    case 413:
      return 'payload_too_large';
    case 415:
      return 'unsupported_media_type';
    case 429:
      return 'rate_limited';
    case 502:
    case 503:
    case 504:
      // Without a Velsigil error body this is a gateway that cannot reach the server.
      return velsigilBody ? 'internal_error' : 'network_error';
    default:
      return status >= 500 ? 'internal_error' : 'invalid_response';
  }
}

/** Unsigned 5xx triggers the offline fallback; safe, as an attacker could just drop the connection. */
function isServerErrorStatus(status: number): boolean {
  return status >= 500 && status <= 599;
}

function localFailure(code: VelsigilCode, message: string, type: RequestType | null): VelsigilResult {
  return new VelsigilResult({ ok: false, code, message, type });
}

function licenseInfo(license: ProtocolLicense): LicenseInfo {
  return {
    id: license.id,
    plan: license.plan,
    status: license.status,
    features: license.features,
    expiresAt: license.expiresAt,
    maxDevices: license.maxDevices,
    devicesUsed: license.devicesUsed,
    createdAt: license.createdAt,
    isTrial: license.trial === true,
    trialRef: license.trialRef ?? null,
  };
}

function leaseResult(payload: LeasePayload, token: string, now: number, retryAfter: number | null): VelsigilResult {
  const license: LicenseInfo = {
    id: payload.licenseId,
    plan: payload.plan,
    status: 'active',
    features: payload.features,
    expiresAt: payload.licenseExpiresAt,
    maxDevices: null,
    devicesUsed: null,
    createdAt: null,
    isTrial: payload.trial === true,
    trialRef: null,
  };
  const activation: ActivationInfo = {
    id: payload.activationId,
    status: 'active',
    firstSeenAt: null,
    deviceSecretIssued: false,
  };
  return new VelsigilResult({
    ok: true,
    code: 'ok',
    message: 'License is valid (offline lease).',
    type: 'validate',
    license,
    activation,
    lease: { token, expiresAt: payload.exp },
    offline: true,
    retryAfter,
    referenceTime: now,
  });
}
