/** A `fetch`-compatible function. */
export type FetchFunction = typeof fetch;

export interface HttpResponse {
  kind: 'response';
  status: number;
  headers: Headers;
  body: Uint8Array;
}

export interface HttpTooLarge {
  kind: 'too_large';
  status: number;
  /** Kept so an oversized 429/503 still yields its `Retry-After`. */
  headers: Headers;
}

export interface HttpNetworkError {
  kind: 'network_error';
  timedOut: boolean;
}

export type HttpOutcome = HttpResponse | HttpTooLarge | HttpNetworkError;

export interface PostJsonOptions {
  fetch: FetchFunction;
  timeoutMs: number;
  maxResponseBytes: number;
  userAgent: string;
}

/** POSTs JSON without following redirects, so an answer can't come from another origin. Never throws. */
export async function postJson(url: string, body: unknown, options: PostJsonOptions): Promise<HttpOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    let response: Response;
    try {
      response = await options.fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          'user-agent': options.userAgent,
        },
        body: JSON.stringify(body),
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      return { kind: 'network_error', timedOut: controller.signal.aborted };
    }
    try {
      const bytes = await readBody(response, options.maxResponseBytes);
      if (bytes === null) return { kind: 'too_large', status: response.status, headers: response.headers };
      return { kind: 'response', status: response.status, headers: response.headers, body: bytes };
    } catch {
      return { kind: 'network_error', timedOut: controller.signal.aborted };
    }
  } finally {
    clearTimeout(timer);
  }
}

/** Reads the body up to `maxBytes`; null when it is larger. */
export async function readBody(response: Response, maxBytes: number): Promise<Uint8Array | null> {
  const declared = response.headers.get('content-length');
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    return null;
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks, total);
}

/** Same cap in every Velsigil SDK. */
export const MAX_RETRY_AFTER_SECONDS = 86_400;

/** Parses `Retry-After` (seconds or HTTP date) into whole seconds, capped at one day. */
export function parseRetryAfter(value: string | null, nowMs: number): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    const digits = trimmed.replace(/^0+(?=\d)/, '');
    return digits.length > 6 ? MAX_RETRY_AFTER_SECONDS : Math.min(Number(digits), MAX_RETRY_AFTER_SECONDS);
  }
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return null;
  return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(0, Math.ceil((date - nowMs) / 1000)));
}
