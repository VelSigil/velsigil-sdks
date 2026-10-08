import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, rm, type FileHandle } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { renameWithRetry, syncDirectory } from './fsutil.js';
import type { FetchFunction } from './http.js';
import type { DownloadInfo } from './result.js';

/**
 * Download outcome codes (SPEC section 14 SDK-side codes, identical in every Velsigil SDK):
 * download_failed (non-200 status incl. an expired link (410), or a URL rejected by the HTTPS
 * policy), integrity_mismatch (size or SHA-256 differs from the signed values), io_error (the
 * destination could not be written), network_error (transport failure) and validation_error (bad
 * arguments).
 */
export type DownloadFileCode =
  | 'ok'
  | 'network_error'
  | 'download_failed'
  | 'integrity_mismatch'
  | 'io_error'
  | 'validation_error';

/** Outcome of {@link downloadToFile}. Never thrown; check `ok`. */
export interface DownloadFileResult {
  readonly ok: boolean;
  readonly code: DownloadFileCode;
  readonly message: string;
  /** Absolute destination path when `ok`. */
  readonly path: string | null;
  /** Bytes received. */
  readonly bytes: number;
  /** Verified SHA-256 (lowercase hex) when `ok`. */
  readonly sha256: string | null;
}

export interface DownloadFileOptions {
  /** Abort when no data arrives for this many milliseconds (default 60 000). */
  idleTimeout?: number;
  /** External cancellation. */
  signal?: AbortSignal;
  /** Progress callback: bytes received so far and the expected total. */
  onProgress?: (received: number, total: number) => void;
}

export interface DownloadContext {
  fetch: FetchFunction;
  userAgent: string;
}

const DEFAULT_IDLE_TIMEOUT_MS = 60_000;

function failure(code: DownloadFileCode, message: string, bytes = 0): DownloadFileResult {
  return Object.freeze({ ok: false, code, message, path: null, bytes, sha256: null });
}

/**
 * Streams a release to `destination`, verifying the signed `size` and `sha256` from the download
 * info while writing. Data goes to a temporary file next to the destination which is renamed into
 * place only after both checks pass; on any failure the partial file is removed.
 */
export async function downloadToFile(
  download: DownloadInfo,
  destination: string,
  context: DownloadContext,
  options: DownloadFileOptions = {},
): Promise<DownloadFileResult> {
  const idleTimeout = options.idleTimeout ?? DEFAULT_IDLE_TIMEOUT_MS;
  if (!Number.isFinite(idleTimeout) || idleTimeout <= 0) {
    return failure('validation_error', 'idleTimeout must be a positive number of milliseconds');
  }
  if (typeof destination !== 'string' || destination.length === 0) {
    return failure('validation_error', 'A destination path is required');
  }

  const target = resolve(destination);
  const controller = new AbortController();
  let timer = setTimeout(() => controller.abort(), idleTimeout);
  const touch = (): void => {
    clearTimeout(timer);
    timer = setTimeout(() => controller.abort(), idleTimeout);
  };
  const onExternalAbort = (): void => controller.abort();
  if (options.signal?.aborted) controller.abort();
  options.signal?.addEventListener('abort', onExternalAbort, { once: true });

  let handle: FileHandle | null = null;
  let temp: string | null = null;
  let received = 0;
  try {
    let response: Response;
    try {
      response = await context.fetch(download.url, {
        method: 'GET',
        headers: { accept: '*/*', 'user-agent': context.userAgent },
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      return failure('network_error', 'Could not reach the download server');
    }

    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      if (response.status === 410) return failure('download_failed', 'The download link has expired; request a new one');
      return failure('download_failed', `Download failed with HTTP status ${response.status}`);
    }
    const declared = response.headers.get('content-length');
    if (declared !== null && /^\d+$/.test(declared) && Number(declared) !== download.size) {
      await response.body?.cancel().catch(() => undefined);
      return failure('integrity_mismatch', 'Download size does not match the signed release size');
    }

    const directory = dirname(target);
    try {
      await mkdir(directory, { recursive: true });
      temp = join(directory, `.${basename(target)}.${randomBytes(6).toString('hex')}.part`);
      handle = await open(temp, 'wx', 0o600);
    } catch {
      return failure('io_error', 'Could not create the destination file');
    }

    const hash = createHash('sha256');
    const reader = response.body?.getReader() ?? null;
    if (reader !== null) {
      for (;;) {
        let chunk: Awaited<ReturnType<typeof reader.read>>;
        try {
          chunk = await reader.read();
        } catch {
          return failure('network_error', 'The download was interrupted', received);
        }
        if (chunk.done) break;
        touch();
        received += chunk.value.byteLength;
        if (received > download.size) {
          await reader.cancel().catch(() => undefined);
          return failure('integrity_mismatch', 'Download is larger than the signed release size', received);
        }
        hash.update(chunk.value);
        try {
          await handle.write(chunk.value);
        } catch {
          await reader.cancel().catch(() => undefined);
          return failure('io_error', 'Could not write the downloaded data', received);
        }
        options.onProgress?.(received, download.size);
      }
    }

    if (received !== download.size) {
      return failure('integrity_mismatch', 'Download size does not match the signed release size', received);
    }
    const digest = hash.digest('hex');
    if (digest !== download.sha256.toLowerCase()) {
      return failure('integrity_mismatch', 'Download checksum does not match the signed SHA-256', received);
    }

    try {
      await handle.sync();
      await handle.close();
      handle = null;
      await renameWithRetry(temp, target);
      temp = null;
      await syncDirectory(directory);
    } catch {
      return failure('io_error', 'Could not move the download into place', received);
    }
    return Object.freeze({
      ok: true,
      code: 'ok' as const,
      message: 'Download complete and verified.',
      path: target,
      bytes: received,
      sha256: digest,
    });
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onExternalAbort);
    if (handle !== null) await handle.close().catch(() => undefined);
    if (temp !== null) await rm(temp, { force: true }).catch(() => undefined);
  }
}
