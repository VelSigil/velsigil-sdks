/** Request/response types of the Velsigil client protocol (SPEC section 10). */

/** The endpoint a request went to; `trial` = an in-app free-trial start (`POST /trial`, SPEC 9.7). */
export type RequestType = 'validate' | 'deactivate' | 'update_check' | 'download' | 'trial';

export type LicenseStatus = 'pending' | 'active' | 'suspended' | 'expired' | 'revoked' | 'banned';

export type ActivationStatus = 'active' | 'revoked';

/** `license` object of a signed response payload. Times are unix seconds. */
export interface ProtocolLicense {
  id: string;
  plan: string;
  status: LicenseStatus;
  features: string[];
  expiresAt: number | null;
  maxDevices: number;
  devicesUsed: number;
  createdAt: number;
  /**
   * Optional: the trial's conversion reference (SPEC 9.7, servers since 2026-10-06), only on a free trial a purchase
   * can still convert. An opaque string of 1-200 characters of `[A-Za-z0-9_-]` the app adds to its "Buy now" link.
   */
  trialRef?: string;
  /** Optional: `true` for a free-trial license (SPEC 9.7). Left out by the server otherwise (and by older servers). */
  trial?: boolean;
}

/** `activation` object of a signed response payload. `deviceSecret` is only present when newly issued. */
export interface ProtocolActivation {
  id: string;
  status: ActivationStatus;
  firstSeenAt: number;
  deviceSecret: string | null;
  /**
   * Optional lowercase hex SHA-256 of the hwid the activation belongs to. When present it must equal
   * SHA-256 of the hwid this client sent, otherwise the response is rejected (`hwid_mismatch`).
   */
  hwidHash?: string;
}

export interface ProtocolLease {
  token: string;
  expiresAt: number;
}

export interface ProtocolUpdate {
  latestVersion: string;
  minVersion: string | null;
  updateAvailable: boolean;
  mandatory: boolean;
  changelog: string;
}

export interface ProtocolDownload {
  url: string;
  expiresAt: number;
  fileName: string;
  size: number;
  sha256: string;
  version: string;
}

/** The started free trial of an `ok` answer of type `trial` (SPEC 10.1): the new license key. */
export interface ProtocolTrial {
  key: string;
}

/** Decoded `data` of a verified envelope. */
export interface ResponsePayload {
  v: 1;
  type: RequestType;
  ok: boolean;
  code: string;
  message: string;
  nonce: string;
  requestId: string;
  serverTime: number;
  productId: string;
  license: ProtocolLicense | null;
  activation: ProtocolActivation | null;
  lease: ProtocolLease | null;
  update: ProtocolUpdate | null;
  download: ProtocolDownload | null;
  /**
   * Present only on an `ok` answer of type `trial` (an in-app trial start): the key of the new trial license. The
   * parser drops the field from every other answer.
   */
  trial?: ProtocolTrial;
}

/** Decoded first segment of an offline lease token (SPEC section 10.4). */
export interface LeasePayload {
  v: 1;
  typ: 'lease';
  productId: string;
  licenseId: string;
  activationId: string;
  hwidHash: string;
  plan: string;
  features: string[];
  licenseExpiresAt: number | null;
  iat: number;
  exp: number;
  /** Optional: `true` when the lease belongs to a free-trial license (SPEC 9.7); left out otherwise. */
  trial?: boolean;
}

/** Signed response envelope as received over HTTP. */
export interface SignedEnvelope {
  data: string;
  sig: string;
  kid?: string;
}
