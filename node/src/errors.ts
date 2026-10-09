/** Reasons the SDK throws; licensing outcomes are always returned as results instead. */
export type VelsigilErrorCode =
  | 'invalid_configuration'
  | 'invalid_public_key'
  | 'invalid_argument'
  | 'hwid_unavailable';

/** Thrown for configuration errors or when no hardware id can be determined. */
export class VelsigilError extends Error {
  readonly code: VelsigilErrorCode;

  constructor(code: VelsigilErrorCode, message: string) {
    super(message);
    this.name = 'VelsigilError';
    this.code = code;
  }
}
