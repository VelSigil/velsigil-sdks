/** The endpoint a request went to. */
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
  /** Conversion reference of a free trial; add it to the "Buy now" link with `withTrialRef`. */
  trialRef?: string;
  /** `true` for a free-trial license. */
  trial?: boolean;
}

/** `activation` object of a signed response payload. `deviceSecret` is only present when newly issued. */
export interface ProtocolActivation {
  id: string;
  status: ActivationStatus;
  firstSeenAt: number;
  deviceSecret: string | null;
  /** SHA-256 of the hwid; the response is rejected if it does not match this device. */
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

/** The started free trial: the new license key. */
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
  /** Only on an `ok` answer of type `trial`. */
  trial?: ProtocolTrial;
}

/** Decoded payload of an offline lease token. */
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
  /** `true` when the lease belongs to a free-trial license. */
  trial?: boolean;
}

/** Signed response envelope as received over HTTP. */
export interface SignedEnvelope {
  data: string;
  sig: string;
  kid?: string;
}
