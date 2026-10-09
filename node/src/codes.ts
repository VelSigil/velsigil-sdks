/** Result codes carried in signed server responses. */
export const SERVER_CODES = [
  'ok',
  'invalid_key',
  'license_expired',
  'license_suspended',
  'license_revoked',
  'license_banned',
  'device_limit_reached',
  'device_revoked',
  'device_verification_failed',
  'device_not_found',
  'device_not_activated',
  'activation_rate_limited',
  'activation_cooldown',
  'activations_disabled',
  'downloads_disabled',
  'blacklisted',
  'outdated_version',
  'product_paused',
  'product_disabled',
  'clock_skew',
  'replay_detected',
  'no_release',
  'release_not_found',
  'trial_already_used',
  // `trial_confirmation_sent`: tell the user to check their inbox; the key arrives by e-mail.
  'trial_unavailable',
  'trial_email_required',
  'trial_email_invalid',
  'trial_email_not_accepted',
  'trial_confirmation_sent',
] as const;

/** Codes of unsigned HTTP error responses; these never yield `ok === true`. */
export const UNSIGNED_ERROR_CODES = [
  'validation_error',
  'ip_blocked',
  'unknown_product',
  'rate_limited',
  'internal_error',
  'payload_too_large',
  'unsupported_media_type',
] as const;

/** Codes produced by the SDK itself; the same in every Velsigil SDK. */
export const SDK_CODES = [
  'invalid_response',
  'network_error',
  'validation_error',
  'invalid_configuration',
  'no_lease',
  'lease_expired',
  'lease_invalid',
  'download_failed',
  'integrity_mismatch',
  'io_error',
  'panel_too_old',
  'already_licensed',
  'store_unavailable',
] as const;

export type ServerCode = (typeof SERVER_CODES)[number];
export type UnsignedErrorCode = (typeof UNSIGNED_ERROR_CODES)[number];
export type SdkCode = (typeof SDK_CODES)[number];

/** Every code a result can carry; open to codes added by newer servers. */
export type VelsigilCode = ServerCode | UnsignedErrorCode | SdkCode | (string & Record<never, never>);

/** Signed denials after which the stored offline lease is no longer honoured. */
export const LEASE_REVOKING_CODES: ReadonlySet<string> = new Set([
  'invalid_key',
  'license_expired',
  'license_suspended',
  'license_revoked',
  'license_banned',
  'device_revoked',
  'device_verification_failed',
  'device_limit_reached',
  'device_not_activated',
  'device_not_found',
  'blacklisted',
  'product_disabled',
]);
