import { describe, expect, it } from 'vitest';
import { decodeBase64Any, decodeBase64Url, generateNonce } from '../src/encoding.js';
import { getHardwareId, parsePublicKey, VelsigilError, VelsigilResult } from '../src/index.js';
import { parseIoregOutput, parseRegQueryOutput, readMachineId, usableLinuxMachineId } from '../src/hwid.js';
import { parsePublicKeyAllowingTestKeys } from '../src/signature.js';
import { randomPublicKey } from './helpers/mock-server.js';
import { vectors } from './helpers/vectors.js';

describe('base64url decoding', () => {
  it('accepts unpadded and correctly padded input', () => {
    expect(decodeBase64Url('QQ')?.toString()).toBe('A');
    expect(decodeBase64Url('QQ==')?.toString()).toBe('A');
    expect(decodeBase64Url('QUI')?.toString()).toBe('AB');
    expect(decodeBase64Url('QUI=')?.toString()).toBe('AB');
    expect(decodeBase64Url('QUJD')?.toString()).toBe('ABC');
    expect(decodeBase64Url('')?.length).toBe(0);
    expect(decodeBase64Url('-_8')).toEqual(Buffer.from([0xfb, 0xff]));
  });

  it('rejects malformed input instead of skipping characters', () => {
    expect(decodeBase64Url('QQ=')).toBeNull();
    expect(decodeBase64Url('QUJD=')).toBeNull();
    expect(decodeBase64Url('Q')).toBeNull();
    expect(decodeBase64Url('QU JD')).toBeNull();
    expect(decodeBase64Url('QU+D')).toBeNull();
    expect(decodeBase64Url('QU/D')).toBeNull();
    expect(decodeBase64Url('QU*D')).toBeNull();
  });

  it('decodes the standard-base64 public key format (padded or not)', () => {
    const key = vectors.keys.publicKey;
    expect(decodeBase64Any(key)?.length).toBe(32);
    expect(decodeBase64Any(key.replace(/=+$/, ''))?.length).toBe(32);
    expect(decodeBase64Any(` ${key}\n`)?.length).toBe(32);
    expect(decodeBase64Any('ab+c-d')).toBeNull();
  });
});

describe('public key parsing', () => {
  it('imports a product key', () => {
    const key = parsePublicKey(randomPublicKey());
    expect(key.asymmetricKeyType).toBe('ed25519');
    expect(key.type).toBe('public');
  });

  it('imports the vector key only through the internal path (the public parser refuses it)', () => {
    const key = parsePublicKeyAllowingTestKeys(vectors.keys.publicKey);
    expect(key.asymmetricKeyType).toBe('ed25519');
    expect(key.type).toBe('public');
    expect(() => parsePublicKey(vectors.keys.publicKey)).toThrow(VelsigilError);
  });

  it('rejects keys of the wrong size or encoding', () => {
    for (const parse of [parsePublicKey, parsePublicKeyAllowingTestKeys]) {
      expect(() => parse('')).toThrow(VelsigilError);
      expect(() => parse('AAAA')).toThrow(VelsigilError);
      expect(() => parse(Buffer.alloc(33).toString('base64'))).toThrow(VelsigilError);
      expect(() => parse('not base64 at all!')).toThrow(VelsigilError);
    }
  });
});

describe('nonces', () => {
  it('are 43 base64url characters (32 random bytes) and unique', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const nonce = generateNonce();
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(decodeBase64Url(nonce)?.length).toBe(32);
      seen.add(nonce);
    }
    expect(seen.size).toBe(200);
  });
});

describe('hardware id', () => {
  it('parses reg.exe output', () => {
    const output =
      '\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    4C4C4544-0042-3510-8051-B4C04F4E4B32\r\n\r\n';
    expect(parseRegQueryOutput(output)).toBe('4C4C4544-0042-3510-8051-B4C04F4E4B32');
    expect(parseRegQueryOutput('ERROR: The system was unable to find the specified registry key')).toBeNull();
  });

  it('parses ioreg output', () => {
    const output = '+-o J314sAP  <class IOPlatformExpertDevice>\n    {\n      "IOPlatformUUID" = "F3E2D1C0-B9A8-7766-5544-332211009988"\n    }';
    expect(parseIoregOutput(output)).toBe('F3E2D1C0-B9A8-7766-5544-332211009988');
    expect(parseIoregOutput('nothing here')).toBeNull();
  });

  it('skips an empty Linux machine-id file and the systemd placeholder "uninitialized"', () => {
    expect(usableLinuxMachineId('  4c4c4544004235108051b4c04f4e4b32\n')).toBe('4c4c4544004235108051b4c04f4e4b32');
    expect(usableLinuxMachineId('uninitialized\n')).toBeNull();
    expect(usableLinuxMachineId(' UNINITIALIZED ')).toBeNull();
    expect(usableLinuxMachineId(' \n')).toBeNull();
  });

  it('computes a stable 64-hex hwid for this machine', () => {
    let machineId: string | null = null;
    try {
      machineId = readMachineId();
    } catch {
      machineId = null;
    }
    if (machineId === null) {
      expect(() => getHardwareId()).toThrow(VelsigilError);
      return;
    }
    const hwid = getHardwareId();
    expect(hwid).toMatch(/^[0-9a-f]{64}$/);
    expect(getHardwareId()).toBe(hwid);
  });
});

describe('VelsigilResult helpers', () => {
  const base = {
    id: 'lic',
    plan: 'Monthly',
    status: 'active' as const,
    features: ['pro'],
    maxDevices: 1,
    devicesUsed: 1,
    createdAt: 0,
  };

  it('hasFeature is false unless the result is ok', () => {
    const ok = new VelsigilResult({ ok: true, code: 'ok', message: '', license: { ...base, expiresAt: null } });
    const denied = new VelsigilResult({
      ok: false,
      code: 'license_suspended',
      message: '',
      license: { ...base, expiresAt: null },
    });
    expect(ok.hasFeature('pro')).toBe(true);
    expect(ok.hasFeature('enterprise')).toBe(false);
    expect(denied.hasFeature('pro')).toBe(false);
  });

  it('computes expiry helpers', () => {
    const now = 1_767_225_600_000;
    const expiresAt = now / 1000 + 3 * 86_400 + 60;
    const result = new VelsigilResult({ ok: true, code: 'ok', message: '', license: { ...base, expiresAt } });
    expect(result.expiresAt?.getTime()).toBe(expiresAt * 1000);
    expect(result.isLifetime).toBe(false);
    expect(result.secondsRemaining(now)).toBe(3 * 86_400 + 60);
    expect(result.daysRemaining(now)).toBe(4);
    expect(result.expiresWithin(7, now)).toBe(true);
    expect(result.expiresWithin(2, now)).toBe(false);
    expect(result.isExpired(now)).toBe(false);
    expect(result.isExpired(now + 4 * 86_400_000)).toBe(true);

    const lifetime = new VelsigilResult({ ok: true, code: 'ok', message: '', license: { ...base, expiresAt: null } });
    expect(lifetime.isLifetime).toBe(true);
    expect(lifetime.expiresAt).toBeNull();
    expect(lifetime.secondsRemaining(now)).toBeNull();
    expect(lifetime.isExpired(now)).toBe(false);
    expect(lifetime.daysRemaining()).toBeNull();
  });

  it('daysRemaining rounds up and measures at the signed serverTime (or the offline check time) by default', () => {
    const serverTime = 1_767_225_600;
    const trial = new VelsigilResult({
      ok: true,
      code: 'ok',
      message: '',
      serverTime,
      license: { ...base, expiresAt: serverTime + 14 * 86_400 },
    });
    expect(trial.daysRemaining()).toBe(14);
    expect(trial.daysRemaining((serverTime + 1) * 1000)).toBe(14);
    expect(trial.daysRemaining((serverTime + 13 * 86_400) * 1000)).toBe(1);
    expect(trial.daysRemaining((serverTime + 14 * 86_400 - 1) * 1000)).toBe(1);
    expect(trial.daysRemaining((serverTime + 14 * 86_400) * 1000)).toBe(0);
    const offline = new VelsigilResult({
      ok: true,
      code: 'ok',
      message: '',
      offline: true,
      referenceTime: serverTime + 86_400,
      license: { ...base, expiresAt: serverTime + 14 * 86_400 },
    });
    expect(offline.daysRemaining()).toBe(13);
  });

  it('is immutable', () => {
    const result = new VelsigilResult({ ok: false, code: 'invalid_key', message: 'x' });
    expect(Object.isFrozen(result)).toBe(true);
    expect(() => {
      (result as { ok: boolean }).ok = true;
    }).toThrow(TypeError);
  });
});
