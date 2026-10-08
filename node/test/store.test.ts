import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { defaultStoreDirectory, FileStore, MemoryStore, VelsigilError } from '../src/index.js';
import { PRODUCT_ID } from './helpers/mock-server.js';

const SECRET = 'dsk_Xq3vR9mT2pL8wN5kJ7hG4fD1sA6zC0bV9yU2iO3eW4r';

describe('MemoryStore', () => {
  it('round-trips and isolates copies', () => {
    const store = new MemoryStore();
    expect(store.load(PRODUCT_ID)).toBeNull();
    const state = { deviceSecret: SECRET, lease: { token: 'a.b', expiresAt: 10 } };
    store.save(PRODUCT_ID, state);
    state.lease.expiresAt = 99;
    expect(store.load(PRODUCT_ID)).toEqual({ deviceSecret: SECRET, lease: { token: 'a.b', expiresAt: 10 } });
    store.clear(PRODUCT_ID);
    expect(store.load(PRODUCT_ID)).toBeNull();
  });
});

describe('FileStore', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'velsigil-store-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('persists state atomically without leaving temp files', async () => {
    const store = new FileStore(join(dir, 'nested', 'state'));
    expect(await store.load(PRODUCT_ID)).toBeNull();
    await store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: { token: 'a.b', expiresAt: 10 } });
    await store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: { token: 'c.d', expiresAt: 20 } });

    const reopened = new FileStore(join(dir, 'nested', 'state'));
    expect(await reopened.load(PRODUCT_ID)).toEqual({ deviceSecret: SECRET, lease: { token: 'c.d', expiresAt: 20 } });
    const files = await readdir(join(dir, 'nested', 'state'));
    expect(files).toEqual([`velsigil-${PRODUCT_ID}.json`]);
  });

  it('serializes concurrent writes (last call wins)', async () => {
    const store = new FileStore(dir);
    await Promise.all(
      Array.from({ length: 20 }, (_, i) => store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: { token: `t.${i}`, expiresAt: i } })),
    );
    expect((await store.load(PRODUCT_ID))?.lease).toEqual({ token: 't.19', expiresAt: 19 });
    expect(await readdir(dir)).toHaveLength(1);
  });

  it.skipIf(process.platform === 'win32')('uses owner-only permissions on POSIX', async () => {
    const stateDir = join(dir, 'private');
    const store = new FileStore(stateDir);
    await store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: null });
    expect((await stat(stateDir)).mode & 0o777).toBe(0o700);
    expect((await stat(store.filePath(PRODUCT_ID))).mode & 0o777).toBe(0o600);
  });

  it('treats corrupt or foreign data as empty and drops invalid fields', async () => {
    const store = new FileStore(dir);
    await writeFile(store.filePath(PRODUCT_ID), '{ not json');
    expect(await store.load(PRODUCT_ID)).toBeNull();
    await writeFile(store.filePath(PRODUCT_ID), JSON.stringify({ deviceSecret: 42, lease: { token: 'x.y', expiresAt: -1 } }));
    expect(await store.load(PRODUCT_ID)).toEqual({ deviceSecret: null, lease: null });
  });

  it('clear removes the file', async () => {
    const store = new FileStore(dir);
    await store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: null });
    await store.clear(PRODUCT_ID);
    expect(await store.load(PRODUCT_ID)).toBeNull();
    await store.clear(PRODUCT_ID);
  });

  it('refuses product ids that are not safe file names', () => {
    const store = new FileStore(dir);
    expect(() => store.filePath('../../etc/passwd')).toThrow(VelsigilError);
    expect(() => store.filePath('a/b')).toThrow(VelsigilError);
  });

  it('stores only the device secret and lease', async () => {
    const store = new FileStore(dir);
    await store.save(PRODUCT_ID, {
      deviceSecret: SECRET,
      lease: null,
      licenseKey: 'VSG-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE',
    } as never);
    const text = await readFile(store.filePath(PRODUCT_ID), 'utf8');
    expect(text).not.toContain('VSG-');
    expect(JSON.parse(text)).toEqual({ deviceSecret: SECRET, lease: null });
  });

  describe('legacy (pre-rename) state files', () => {
    const LEGACY_FILE = `veltrix-${PRODUCT_ID}.json`;
    const NEW_FILE = `velsigil-${PRODUCT_ID}.json`;
    const legacyState = { deviceSecret: SECRET, lease: { token: 'old.lease', expiresAt: 10 } };

    it('reads veltrix-<id>.json from the same directory until the next save writes the new file', async () => {
      await writeFile(join(dir, LEGACY_FILE), JSON.stringify(legacyState));
      const store = new FileStore(dir);
      expect(await store.load(PRODUCT_ID)).toEqual(legacyState);

      await store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: { token: 'new.lease', expiresAt: 20 } });
      expect(store.filePath(PRODUCT_ID)).toBe(join(dir, NEW_FILE));
      expect(await new FileStore(dir).load(PRODUCT_ID)).toEqual({
        deviceSecret: SECRET,
        lease: { token: 'new.lease', expiresAt: 20 },
      });
    });

    it('falls back to the former default directory <app>/veltrix', async () => {
      const legacyDir = join(dir, 'My App', 'veltrix');
      await mkdir(legacyDir, { recursive: true });
      await writeFile(join(legacyDir, LEGACY_FILE), JSON.stringify(legacyState));

      const newDir = join(dir, 'My App', 'velsigil');
      const store = new FileStore(newDir);
      expect(await store.load(PRODUCT_ID)).toEqual(legacyState);
      await store.save(PRODUCT_ID, legacyState);
      expect(await readdir(newDir)).toEqual([NEW_FILE]);
      expect(await new FileStore(newDir).load(PRODUCT_ID)).toEqual(legacyState);
    });

    it('prefers the new file and does not fall back when the new file is unusable', async () => {
      await writeFile(join(dir, LEGACY_FILE), JSON.stringify(legacyState));
      const store = new FileStore(dir);
      await store.save(PRODUCT_ID, { deviceSecret: SECRET, lease: null });
      expect(await store.load(PRODUCT_ID)).toEqual({ deviceSecret: SECRET, lease: null });
      await writeFile(store.filePath(PRODUCT_ID), '{ not json');
      expect(await store.load(PRODUCT_ID)).toBeNull();
    });

    it('clear removes the legacy file too, so cleared state never comes back', async () => {
      const legacyDir = join(dir, 'App', 'veltrix');
      await mkdir(legacyDir, { recursive: true });
      await writeFile(join(legacyDir, LEGACY_FILE), JSON.stringify(legacyState));
      const newDir = join(dir, 'App', 'velsigil');
      await mkdir(newDir, { recursive: true });
      await writeFile(join(newDir, LEGACY_FILE), JSON.stringify(legacyState));

      const store = new FileStore(newDir);
      await store.save(PRODUCT_ID, legacyState);
      await store.clear(PRODUCT_ID);
      expect(await store.load(PRODUCT_ID)).toBeNull();
      expect(await readdir(legacyDir)).toEqual([]);
      expect(await readdir(newDir)).toEqual([]);
    });
  });
});

describe('defaultStoreDirectory', () => {
  it('builds a per-user path ending in <app>/velsigil', () => {
    const path = defaultStoreDirectory('My App');
    expect(path.endsWith(join('My App', 'velsigil'))).toBe(true);
  });

  it('rejects unsafe application names', () => {
    expect(() => defaultStoreDirectory('..')).toThrow(VelsigilError);
    expect(() => defaultStoreDirectory('a/b')).toThrow(VelsigilError);
    expect(() => defaultStoreDirectory('')).toThrow(VelsigilError);
    expect(() => defaultStoreDirectory('trailing.')).toThrow(VelsigilError);
  });
});
