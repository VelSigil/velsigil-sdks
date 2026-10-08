/** Small structural validators for decoded JSON. They never trust the input's prototype. */

export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isString(value: unknown, maxLength = 4096): value is string {
  return typeof value === 'string' && value.length <= maxLength;
}

export function isNonEmptyString(value: unknown, maxLength = 4096): value is string {
  return isString(value, maxLength) && value.length > 0;
}

/** Unix seconds (or another non-negative integer quantity). */
export function isUnixTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function isStringArray(value: unknown, maxItems = 1000, maxLength = 256): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maxItems &&
    value.every((item) => typeof item === 'string' && item.length <= maxLength)
  );
}

export function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

/** Server result codes are short snake_case identifiers. */
export function isCode(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value);
}

export function isHex64(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value);
}

/** UUIDs are compared case-insensitively. */
export function sameId(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

export const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
