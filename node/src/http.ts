/** Minimal HTTP transport on top of the global `fetch` with a hard timeout and response size cap. */

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

/**
 * POSTs `body` as JSON. Redirects are not followed (`redirect: 'manual'`) so a response can never
 * silently come from another origin or be downgraded to plain HTTP. The timeout covers connecting,
 * sending and reading the whole response. Never throws.
 */
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
      if (bytes === null) return { kind: 'too_large', status: response.status };
      return { kind: 'response', status: response.status, headers: response.headers, body: bytes };
    } catch {
      return { kind: 'network_error', timedOut: controller.signal.aborted };
    }
  } finally {
    clearTimeout(timer);
  }
}

/** Reads the body up to `maxBytes`; returns null (and cancels the stream) when it is larger. */
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

/** Parses `Retry-After` (delta-seconds or HTTP date) into whole seconds. */
export function parseRetryAfter(value: string | null, nowMs: number): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d{1,9}$/.test(trimmed)) return Number(trimmed);
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return null;
  return Math.max(0, Math.ceil((date - nowMs) / 1000));
}
