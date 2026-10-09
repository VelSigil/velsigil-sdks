import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rm, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { isDeviceSecret } from './envelope.js';
import { VelsigilError } from './errors.js';
import { isErrno, renameWithRetry, syncDirectory } from './fsutil.js';
import { isNonEmptyString, isObject, isUnixTime } from './guards.js';

/** Offline lease as persisted by the SDK. */
export interface StoredLease {
  token: string;
  expiresAt: number;
}

/** Per-product client state. Never contains license keys. */
export interface StoredState {
  deviceSecret: string | null;
  lease: StoredLease | null;
}

/** Persistence for the device secret and offline lease; keep it readable by the current OS user only. */
export interface VelsigilStore {
  load(productId: string): StoredState | null | Promise<StoredState | null>;
  save(productId: string, state: StoredState): void | Promise<void>;
  clear(productId: string): void | Promise<void>;
}

export function emptyState(): StoredState {
  return { deviceSecret: null, lease: null };
}

/** Drops invalid fields from untrusted persisted data. */
export function sanitizeState(value: unknown): StoredState {
  if (!isObject(value)) return emptyState();
  const deviceSecret = isDeviceSecret(value.deviceSecret) ? value.deviceSecret : null;
  let lease: StoredLease | null = null;
  const rawLease = value.lease;
  if (isObject(rawLease) && isNonEmptyString(rawLease.token, 16 * 1024) && isUnixTime(rawLease.expiresAt)) {
    lease = { token: rawLease.token, expiresAt: rawLease.expiresAt };
  }
  return { deviceSecret, lease };
}

function cloneState(state: StoredState): StoredState {
  return {
    deviceSecret: state.deviceSecret,
    lease: state.lease === null ? null : { token: state.lease.token, expiresAt: state.lease.expiresAt },
  };
}

/** In-memory store (the default). State is lost when the process exits. */
export class MemoryStore implements VelsigilStore {
  readonly #states = new Map<string, StoredState>();

  load(productId: string): StoredState | null {
    const state = this.#states.get(productId);
    return state === undefined ? null : cloneState(state);
  }

  save(productId: string, state: StoredState): void {
    this.#states.set(productId, cloneState(sanitizeState(state)));
  }

  clear(productId: string): void {
    this.#states.delete(productId);
  }
}

const MAX_STATE_FILE_BYTES = 64 * 1024;
const STORE_KEY_RE = /^[A-Za-z0-9-]{1,64}$/;
// Windows strips trailing dots and spaces from directory names.
const APP_NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,62}[A-Za-z0-9_-])?$/;
const STORE_DIR_NAME = 'velsigil';
// Pre-rename (Veltrix) names, read as a fallback so existing installs keep their state.
const LEGACY_FILE_PREFIX = 'veltrix-';
const LEGACY_DIR_NAME = 'veltrix';

/** One JSON file per product, written atomically; files are 0600 on POSIX, per-user ACLs on Windows. */
export class FileStore implements VelsigilStore {
  readonly directory: string;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(directory: string) {
    if (typeof directory !== 'string' || directory.length === 0) {
      throw new VelsigilError('invalid_argument', 'FileStore requires a directory path');
    }
    this.directory = directory;
  }

  /** Absolute path of the state file for `productId`. */
  filePath(productId: string): string {
    if (!STORE_KEY_RE.test(productId)) {
      throw new VelsigilError('invalid_argument', 'productId contains characters not allowed in a file name');
    }
    return join(this.directory, `velsigil-${productId.toLowerCase()}.json`);
  }

  async load(productId: string): Promise<StoredState | null> {
    const file = this.filePath(productId);
    await this.#queue.catch(() => undefined);
    const state = await readStateFile(file);
    if (state !== undefined) return state;
    for (const legacy of this.#legacyFilePaths(productId)) {
      const legacyState = await readStateFile(legacy);
      if (legacyState !== undefined) return legacyState;
    }
    return null;
  }

  save(productId: string, state: StoredState): Promise<void> {
    const file = this.filePath(productId);
    const json = `${JSON.stringify(sanitizeState(state), null, 2)}\n`;
    return this.#enqueue(() => this.#writeAtomic(file, json));
  }

  clear(productId: string): Promise<void> {
    const files = [this.filePath(productId), ...this.#legacyFilePaths(productId)];
    // Remove the legacy file too, or `load` would fall back to it.
    return this.#enqueue(async () => {
      for (const file of files) await removeIfPresent(file);
    });
  }

  #legacyFilePaths(productId: string): string[] {
    const name = `${LEGACY_FILE_PREFIX}${productId.toLowerCase()}.json`;
    const paths = [join(this.directory, name)];
    if (basename(this.directory) === STORE_DIR_NAME) {
      paths.push(join(dirname(this.directory), LEGACY_DIR_NAME, name));
    }
    return paths;
  }

  #enqueue(task: () => Promise<void>): Promise<void> {
    const run = this.#queue.then(task, task);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #writeAtomic(file: string, contents: string): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const temp = join(this.directory, `.velsigil-${randomBytes(8).toString('hex')}.tmp`);
    const handle = await open(temp, 'wx', 0o600);
    try {
      try {
        await handle.writeFile(contents, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await renameWithRetry(temp, file);
    } catch (error) {
      await rm(temp, { force: true }).catch(() => undefined);
      throw error;
    }
    await syncDirectory(this.directory);
  }
}

/** Undefined when the file is missing, null when it is unusable. */
async function readStateFile(file: string): Promise<StoredState | null | undefined> {
  try {
    const info = await stat(file);
    if (!info.isFile() || info.size > MAX_STATE_FILE_BYTES) return null;
    const text = await readFile(file, 'utf8');
    return sanitizeState(JSON.parse(text) as unknown);
  } catch (error) {
    if (isErrno(error, 'ENOENT') || isErrno(error, 'ENOTDIR')) return undefined;
    if (error instanceof SyntaxError) return null;
    throw error;
  }
}

async function removeIfPresent(file: string): Promise<void> {
  try {
    await rm(file, { force: true });
  } catch (error) {
    if (!isErrno(error, 'ENOENT') && !isErrno(error, 'ENOTDIR')) throw error;
  }
}

/** Recommended per-user directory for a {@link FileStore}, e.g. `%LOCALAPPDATA%\<appName>\velsigil`. */
export function defaultStoreDirectory(appName: string): string {
  if (typeof appName !== 'string' || !APP_NAME_RE.test(appName)) {
    throw new VelsigilError('invalid_argument', 'appName must be 1-64 characters of [A-Za-z0-9._ -]');
  }
  const home = homedir();
  let base: string;
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA;
    base = local && isAbsolute(local) ? local : join(home, 'AppData', 'Local');
  } else if (process.platform === 'darwin') {
    base = join(home, 'Library', 'Application Support');
  } else {
    const xdg = process.env.XDG_DATA_HOME;
    base = xdg && isAbsolute(xdg) ? xdg : join(home, '.local', 'share');
  }
  return join(base, appName, STORE_DIR_NAME);
}

