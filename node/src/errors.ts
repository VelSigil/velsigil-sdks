/**
 * Reasons for which the SDK throws. Only programmer/configuration mistakes throw;
 * licensing outcomes (including network and server failures) are always returned as results.
 * `invalid_configuration` is the cross-SDK configuration code (SPEC section 14).
 */
export type VelsigilErrorCode =
  | 'invalid_configuration'
  | 'invalid_public_key'
  | 'invalid_argument'
  | 'hwid_unavailable';

/**
 * Thrown for configuration errors (bad API URL, malformed public key, invalid options) and
 * when no hardware id can be determined on this machine. Never carries secrets.
 */
export class VelsigilError extends Error {
  readonly code: VelsigilErrorCode;

  constructor(code: VelsigilErrorCode, message: string) {
    super(message);
    this.name = 'VelsigilError';
    this.code = code;
  }
}
