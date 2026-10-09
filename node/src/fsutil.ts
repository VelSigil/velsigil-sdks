import { open, rename } from 'node:fs/promises';

const RENAME_RETRIES = 5;

export function isErrno(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === code;
}

/** Retries renames that fail while antivirus or the indexer briefly locks the file on Windows. */
export async function renameWithRetry(from: string, to: string): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      await rename(from, to);
      return;
    } catch (error) {
      const transient = isErrno(error, 'EPERM') || isErrno(error, 'EBUSY') || isErrno(error, 'EACCES');
      if (!transient || attempt >= RENAME_RETRIES) throw error;
      await new Promise((resolve) => setTimeout(resolve, 20 * (attempt + 1)));
    }
  }
}

/** Best-effort fsync of a directory so a rename survives a crash; skipped on Windows. */
export async function syncDirectory(directory: string): Promise<void> {
  if (process.platform === 'win32') return;
  try {
    const handle = await open(directory, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // Some file systems do not support fsync on directories.
  }
}
