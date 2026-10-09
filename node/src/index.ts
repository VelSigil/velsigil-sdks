/** Node.js SDK for the Velsigil license server. */
export { VelsigilClient, type StartTrialOptions, type ValidateOptions, type VelsigilClientOptions } from './client.js';
export {
  VelsigilResult,
  type ActivationInfo,
  type DownloadInfo,
  type LeaseInfo,
  type LicenseInfo,
  type UpdateInfo,
} from './result.js';
export {
  LEASE_REVOKING_CODES,
  SDK_CODES,
  SERVER_CODES,
  UNSIGNED_ERROR_CODES,
  type SdkCode,
  type ServerCode,
  type UnsignedErrorCode,
  type VelsigilCode,
} from './codes.js';
export { VelsigilError, type VelsigilErrorCode } from './errors.js';
export {
  FileStore,
  MemoryStore,
  defaultStoreDirectory,
  type StoredLease,
  type StoredState,
  type VelsigilStore,
} from './store.js';
export {
  verifyEnvelope,
  type EnvelopeExpectations,
  type EnvelopeStatus,
  type EnvelopeVerification,
} from './envelope.js';
export { verifyLease, type LeaseExpectations, type LeaseStatus, type LeaseVerification } from './lease.js';
export { HWID_PREFIX, getHardwareId, hwidFromMachineId } from './hwid.js';
export { parsePublicKey } from './signature.js';
export { TRIAL_REF_PARAM, withTrialRef } from './trial-ref.js';
export type { DownloadFileCode, DownloadFileOptions, DownloadFileResult } from './download.js';
export type { FetchFunction } from './http.js';
export type {
  ActivationStatus,
  LeasePayload,
  LicenseStatus,
  ProtocolActivation,
  ProtocolDownload,
  ProtocolLease,
  ProtocolLicense,
  ProtocolTrial,
  ProtocolUpdate,
  RequestType,
  ResponsePayload,
  SignedEnvelope,
} from './types.js';
export { SDK_VERSION } from './version.js';
