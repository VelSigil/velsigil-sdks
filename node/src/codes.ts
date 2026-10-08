/** Result codes carried in signed server responses (SPEC section 10.3). */
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
  // Free trials (SPEC 9.7): this device already used a free trial of the product. Not lease-revoking.
  'trial_already_used',
  // In-app free trials (`startTrial`, SPEC 9.7): signed failures, none lease-revoking. `trial_confirmation_sent` means
  // the offer confirms an e-mail address first: tell the user to check the inbox; the key arrives by e-mail.
  'trial_unavailable',
  'trial_email_required',
  'trial_email_invalid',
  'trial_email_not_accepted',
  'trial_confirmation_sent',
] as const;

/** Codes of unsigned HTTP error responses (SPEC section 10.1). These can never yield `ok === true`. */
export const UNSIGNED_ERROR_CODES = [
  'validation_error',
  'ip_blocked',
  'unknown_product',
  'rate_limited',
  'internal_error',
  'payload_too_large',
  'unsupported_media_type',
] as const;

/**
 * Codes produced by the SDK itself (SPEC section 14, identical in every Velsigil SDK):
 * - `invalid_response`: unsigned 200, bad signature, nonce/productId/type mismatch, malformed payload,
 *   redirect or oversized response;
 * - `network_error`: no HTTP response (DNS, connect, TLS, timeout, reset) or a 502/503/504 without a
 *   Velsigil error body (a proxy in front of an unreachable server), so the offline fallback applies. The fallback
 *   ({@link VelsigilClient.validateWithOfflineFallback}) also applies to every other unsigned HTTP 5xx, which
 *   `validate` reports as `internal_error` (or the code of its Velsigil error body);
 * - `validation_error`: local argument checks (the request is never sent);
 * - `invalid_configuration`: the code of {@link VelsigilError} thrown by the constructor;
 * - `no_lease` / `lease_expired` / `lease_invalid`: offline validation;
 * - `download_failed` / `integrity_mismatch` / `io_error`: {@link VelsigilClient.downloadRelease};
 * - `panel_too_old`: {@link VelsigilClient.startTrial} reached a Velsigil server that does not have the in-app trial
 *   endpoint yet (HTTP 404 with the Velsigil error code `not_found`): the seller must update the panel;
 * - `already_licensed`: {@link VelsigilClient.startTrial} refused locally because a device secret or an offline lease
 *   is already stored for the product (this device holds a license; a trial must not replace it). Nothing is sent
 *   and the stored state is untouched: validate the saved key, or deactivate / `clearStoredState()` first.
 * - `store_unavailable`: {@link VelsigilClient.startTrial} refused locally because the store could not be read, so it
 *   cannot tell whether this device already holds a license (a failed read is never "nothing stored"). Nothing is
 *   sent; try again once the store can be read.
 */
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

/**
 * Every code a result can carry. Future server versions may add codes, so the type stays open
 * (`string & Record<never, never>`) while still offering auto-completion for the known ones.
 */
export type VelsigilCode = ServerCode | UnsignedErrorCode | SdkCode | (string & Record<never, never>);

/**
 * Signed denials after which a stored offline lease must no longer be honoured: the server has
 * definitively said this license/device is not (or no longer) entitled. This exact set is binding
 * for every Velsigil SDK (SPEC section 14); other signed failures (e.g. `product_paused`,
 * `outdated_version`, `activation_rate_limited`, `clock_skew`, `replay_detected`) keep the lease.
 */
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
