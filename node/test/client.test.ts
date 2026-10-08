import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  FileStore,
  LEASE_REVOKING_CODES,
  MemoryStore,
  SDK_CODES,
  SERVER_CODES,
  TRIAL_REF_PARAM,
  VelsigilClient,
  VelsigilError,
  VelsigilResult,
  withTrialRef,
  type StoredState,
  type VelsigilClientOptions,
} from '../src/index.js';
import {
  makeLease,
  MockServer,
  type MockReply,
  payloadFor,
  PRODUCT_ID,
  PUBLIC_KEY,
  TEST_HWID,
  WRONG_KEY,
  signEnvelope,
} from './helpers/mock-server.js';

const LICENSE_KEY = 'VSG-23456-789AB-CDEFG-HJKLM-NPQRS';
const SECRET_1 = `dsk_${'A1b2C3d4'.repeat(5)}xyz`;
const T0 = 1_767_225_600; // fixed "now" (unix seconds) for fake-clock tests

let server: MockServer;

beforeEach(async () => {
  server = new MockServer();
  await server.start();
});

afterEach(async () => {
  await server.stop();
  vi.restoreAllMocks();
});

function makeClient(options: VelsigilClientOptions = {}, url = server.url): VelsigilClient {
  return new VelsigilClient(url, PRODUCT_ID, PUBLIC_KEY, { hwid: TEST_HWID, ...options });
}

/** A loopback port with nothing listening on it. */
async function closedPort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

describe('configuration', () => {
  it('requires HTTPS except for loopback hosts', () => {
    expect(() => new VelsigilClient('http://licenses.example.com', PRODUCT_ID, PUBLIC_KEY, { hwid: TEST_HWID })).toThrow(
      VelsigilError,
    );
    for (const url of ['https://licenses.example.com', 'http://localhost:3000', 'http://127.0.0.1', 'http://[::1]:3000']) {
      expect(() => new VelsigilClient(url, PRODUCT_ID, PUBLIC_KEY, { hwid: TEST_HWID })).not.toThrow();
    }
    expect(
      () =>
        new VelsigilClient('http://licenses.example.com', PRODUCT_ID, PUBLIC_KEY, {
          hwid: TEST_HWID,
          allowInsecureHttp: true,
        }),
    ).not.toThrow();
  });

  it('rejects unusable URLs, product ids, keys and options', () => {
    const create = (url: string, productId = PRODUCT_ID, key = PUBLIC_KEY, options: VelsigilClientOptions = {}) =>
      () => new VelsigilClient(url, productId, key, { hwid: TEST_HWID, ...options });
    expect(create('ftp://licenses.example.com')).toThrow(VelsigilError);
    expect(create('https://user:pass@licenses.example.com')).toThrow(VelsigilError);
    expect(create('https://licenses.example.com/?x=1')).toThrow(VelsigilError);
    expect(create('licenses.example.com')).toThrow(VelsigilError);
    expect(create('https://licenses.example.com', 'not-a-uuid')).toThrow(VelsigilError);
    expect(create('https://licenses.example.com', PRODUCT_ID, 'AAAA')).toThrow(VelsigilError);
    expect(create('https://licenses.example.com', PRODUCT_ID, PUBLIC_KEY, { timeout: 0 })).toThrow(VelsigilError);
    expect(create('https://licenses.example.com', PRODUCT_ID, PUBLIC_KEY, { hwid: 'short' })).toThrow(VelsigilError);
    try {
      create('http://licenses.example.com')();
    } catch (error) {
      expect((error as VelsigilError).code).toBe('invalid_configuration');
    }
  });

  it('accepts an API URL that already contains /api/client/v1', async () => {
    const client = makeClient({}, `${server.url}/api/client/v1/`);
    const result = await client.validate(LICENSE_KEY);
    expect(result.ok).toBe(true);
    expect(server.requests[0]?.path).toBe('/api/client/v1/validate');
  });

  it('exposes the static hardware id helper', () => {
    try {
      expect(VelsigilClient.getHardwareId()).toMatch(/^[0-9a-f]{64}$/);
    } catch (error) {
      expect((error as VelsigilError).code).toBe('hwid_unavailable');
    }
  });
});

describe('validate', () => {
  it('returns a verified success and sends the documented request fields', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        update: {
          latestVersion: '1.4.0',
          minVersion: null,
          updateAvailable: true,
          mandatory: false,
          changelog: 'Fixes',
        },
      }),
    });
    const client = makeClient();
    const before = Math.floor(Date.now() / 1000);
    const result = await client.validate(`  ${LICENSE_KEY}  `, { version: '1.2.0', deviceName: 'Build agent' });

    expect(result.ok).toBe(true);
    expect(result.code).toBe('ok');
    expect(result.offline).toBe(false);
    expect(result.type).toBe('validate');
    expect(result.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.license?.plan).toBe('Monthly');
    expect(result.license?.status).toBe('active');
    expect(result.activation).toEqual({
      id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
      status: 'active',
      firstSeenAt: expect.any(Number),
      deviceSecretIssued: false,
    });
    expect(result.update?.latestVersion).toBe('1.4.0');
    expect(result.hasFeature('pro')).toBe(true);
    expect(result.hasFeature('enterprise')).toBe(false);
    expect(result.daysRemaining()).toBeGreaterThanOrEqual(29);

    expect(server.requests).toHaveLength(1);
    const request = server.requests[0]!;
    expect(request.method).toBe('POST');
    expect(request.path).toBe('/api/client/v1/validate');
    expect(request.headers['content-type']).toBe('application/json');
    expect(request.headers['user-agent']).toMatch(/^velsigil-client-node\//);
    expect(request.body).toEqual({
      productId: PRODUCT_ID,
      licenseKey: LICENSE_KEY,
      hwid: TEST_HWID,
      deviceName: 'Build agent',
      version: '1.2.0',
      nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      timestamp: expect.any(Number),
    });
    expect(Math.abs((request.body.timestamp as number) - before)).toBeLessThanOrEqual(5);
  });

  it('uses a fresh nonce for every request', async () => {
    const client = makeClient();
    await client.validate(LICENSE_KEY);
    await client.validate(LICENSE_KEY);
    await client.checkUpdate('1.0.0');
    const nonces = server.requests.map((request) => request.body.nonce);
    expect(new Set(nonces).size).toBe(3);
  });

  it('returns signed business failures without throwing', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        ok: false,
        code: 'license_suspended',
        message: 'This license is suspended.',
        activation: null,
      }),
    });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('license_suspended');
    expect(result.message).toBe('This license is suspended.');
    expect(result.license?.status).toBe('active');
    expect(result.hasFeature('pro')).toBe(false);
  });

  it('rejects a response whose nonce does not match the request', async () => {
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request, { nonce: 'replayed-nonce-0000000000' }) });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('invalid_response');
    expect(result.license).toBeNull();
  });

  it('rejects a response for another product', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { productId: '7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6' }),
    });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.code).toBe('invalid_response');
    expect(result.ok).toBe(false);
  });

  it('rejects a response signed with another key', async () => {
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request), key: WRONG_KEY });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('invalid_response');
  });

  it('rejects tampered data and unsigned 200 bodies', async () => {
    server.handler = (request) => {
      const envelope = signEnvelope(payloadFor(request, { ok: false, code: 'license_banned' }));
      const forged = Buffer.from(
        Buffer.from(envelope.data, 'base64url').toString('utf8').replace('"ok":false', '"ok":true '),
        'utf8',
      ).toString('base64url');
      return { kind: 'json', status: 200, body: { ...envelope, data: forged } };
    };
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('invalid_response');

    server.handler = () => ({ kind: 'json', status: 200, body: { ok: true, code: 'ok' } });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('invalid_response');

    server.handler = () => ({ kind: 'raw', status: 200, body: '<html>hello</html>' });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('invalid_response');
  });

  it('rejects a signed payload of the wrong type', async () => {
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request, { type: 'deactivate' }) });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.code).toBe('invalid_response');
  });

  it('learns the server clock offset from a signed clock_skew and retries once', async () => {
    const realNow = () => Math.floor(Date.now() / 1000);
    server.handler = (request) => {
      const timestamp = request.body.timestamp as number;
      if (Math.abs(timestamp - realNow()) > 300) {
        return {
          kind: 'signed',
          payload: payloadFor(request, {
            ok: false,
            code: 'clock_skew',
            message: 'Request timestamp is outside the allowed window.',
            serverTime: realNow(),
            license: null,
            activation: null,
          }),
        };
      }
      return { kind: 'signed', payload: payloadFor(request) };
    };
    const client = makeClient({ clock: () => Date.now() - 3_600_000 });
    const result = await client.validate(LICENSE_KEY);

    expect(result.ok).toBe(true);
    expect(server.requests).toHaveLength(2);
    const [first, second] = server.requests;
    expect(first!.body.nonce).not.toBe(second!.body.nonce);
    expect(Math.abs((second!.body.timestamp as number) - realNow())).toBeLessThanOrEqual(5);
    expect(Math.abs(client.clockOffset - 3600)).toBeLessThanOrEqual(5);

    // The learned offset is reused: the next request is accepted first time.
    await client.validate(LICENSE_KEY);
    expect(server.requests).toHaveLength(3);
  });

  it('retries a clock_skew only once', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: false, code: 'clock_skew', message: 'skew', license: null, activation: null }),
    });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('clock_skew');
    expect(server.requests).toHaveLength(2);
  });

  it('does not learn a clock offset from an unsigned clock_skew', async () => {
    server.handler = (request) => ({
      kind: 'json',
      status: 200,
      body: { data: Buffer.from(JSON.stringify(payloadFor(request, { code: 'clock_skew', ok: false, serverTime: 1 }))).toString('base64url') },
    });
    const client = makeClient();
    const result = await client.validate(LICENSE_KEY);
    expect(result.code).toBe('invalid_response');
    expect(client.clockOffset).toBe(0);
    expect(server.requests).toHaveLength(1);
  });

  it('persists an issued device secret and sends it on every later request', async () => {
    server.handler = (request) => {
      const issue = request.body.deviceSecret === undefined;
      return {
        kind: 'signed',
        payload: payloadFor(request, {
          activation: {
            id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
            status: 'active',
            firstSeenAt: 1,
            deviceSecret: issue ? SECRET_1 : null,
          },
        }),
      };
    };
    const store = new MemoryStore();
    const client = makeClient({ store });
    const first = await client.validate(LICENSE_KEY);
    expect(first.ok).toBe(true);
    expect(first.activation?.deviceSecretIssued).toBe(true);
    expect(JSON.stringify(first)).not.toContain(SECRET_1);
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(SECRET_1);

    await client.validate(LICENSE_KEY);
    await client.getDownload(LICENSE_KEY);
    await client.deactivate(LICENSE_KEY);
    expect(server.requests[0]!.body.deviceSecret).toBeUndefined();
    expect(server.requests[1]!.body.deviceSecret).toBe(SECRET_1);
    expect(server.requests[2]!.body.deviceSecret).toBe(SECRET_1);
    expect(server.requests[3]!.body.deviceSecret).toBe(SECRET_1);
  });

  it('persists the device secret through a FileStore across client instances', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'velsigil-client-'));
    try {
      server.handler = (request) => ({
        kind: 'signed',
        payload: payloadFor(request, {
          activation: {
            id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
            status: 'active',
            firstSeenAt: 1,
            deviceSecret: request.body.deviceSecret === undefined ? SECRET_1 : null,
          },
        }),
      });
      await makeClient({ store: new FileStore(dir) }).validate(LICENSE_KEY);
      await makeClient({ store: new FileStore(dir) }).validate(LICENSE_KEY);
      expect(server.requests[1]!.body.deviceSecret).toBe(SECRET_1);

      const files = await readdir(dir);
      expect(files).toEqual([`velsigil-${PRODUCT_ID}.json`]);
      const contents = await readFile(join(dir, files[0]!), 'utf8');
      expect(contents).toContain(SECRET_1);
      expect(contents).not.toContain(LICENSE_KEY);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('serializes concurrent device-bound calls so a fresh secret is re-sent', async () => {
    let issued = false;
    server.handler = async (request) => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      const issue = !issued;
      issued = true;
      return {
        kind: 'signed',
        payload: payloadFor(request, {
          activation: { id: 'act', status: 'active', firstSeenAt: 1, deviceSecret: issue ? SECRET_1 : null },
        }),
      };
    };
    const client = makeClient();
    const results = await Promise.all([client.validate(LICENSE_KEY), client.validate(LICENSE_KEY)]);
    expect(results.every((result) => result.ok)).toBe(true);
    expect(server.requests[0]!.body.deviceSecret).toBeUndefined();
    expect(server.requests[1]!.body.deviceSecret).toBe(SECRET_1);
  });

  it('rejects invalid input locally without contacting the server', async () => {
    const client = makeClient();
    expect((await client.validate('   ')).code).toBe('validation_error');
    expect((await client.validate('X'.repeat(65))).code).toBe('validation_error');
    expect((await client.validate(LICENSE_KEY, { version: '1'.repeat(33) })).code).toBe('validation_error');
    expect((await client.validate(undefined as unknown as string)).code).toBe('validation_error');
    expect(server.requests).toHaveLength(0);
  });

  it('never writes to the console', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug', 'trace'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        activation: { id: 'act', status: 'active', firstSeenAt: 1, deviceSecret: SECRET_1 },
      }),
    });
    const client = makeClient();
    await client.validate(LICENSE_KEY);
    server.handler = () => ({ kind: 'json', status: 500, body: { error: { code: 'internal_error' } } });
    await client.validate(LICENSE_KEY);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });
});

describe('unsigned HTTP errors', () => {
  const cases: Array<[number, unknown, string]> = [
    [429, { error: { code: 'rate_limited', message: 'Slow down', requestId: 'req-429' } }, 'rate_limited'],
    [400, { error: { code: 'validation_error', message: 'Bad', requestId: 'req-400' } }, 'validation_error'],
    [403, { error: { code: 'ip_blocked', message: 'Blocked', requestId: 'req-403' } }, 'ip_blocked'],
    [404, { error: { code: 'unknown_product', message: 'Unknown', requestId: 'req-404' } }, 'unknown_product'],
    [500, { error: { code: 'internal_error', message: 'Oops', requestId: 'req-500' } }, 'internal_error'],
    [413, null, 'payload_too_large'],
    [401, { error: { code: 'unauthorized', message: 'No' } }, 'invalid_response'],
  ];

  for (const [status, body, code] of cases) {
    it(`HTTP ${status} -> ${code}`, async () => {
      const headers: Record<string, string> = status === 429 ? { 'retry-after': '30' } : {};
      server.handler = (): MockReply =>
        body === null ? { kind: 'raw', status, body: '' } : { kind: 'json', status, body, headers };
      const result = await makeClient().validate(LICENSE_KEY);
      expect(result.ok).toBe(false);
      expect(result.code).toBe(code);
      expect(result.license).toBeNull();
      if (status === 429) expect(result.retryAfter).toBe(30);
      if (body !== null && status !== 401) expect(result.requestId).toBe(`req-${status}`);
    });
  }

  it('can never succeed, even when the body is a validly signed success', async () => {
    for (const status of [400, 403, 404, 429, 500]) {
      server.handler = (request) => ({ kind: 'signed', status, payload: payloadFor(request) });
      const result = await makeClient().validate(LICENSE_KEY);
      expect(result.ok).toBe(false);
      expect(result.hasFeature('pro')).toBe(false);
    }
  });

  it('maps gateway errors without a Velsigil body to network_error', async () => {
    server.handler = () => ({ kind: 'raw', status: 502, body: '<html>Bad gateway</html>', headers: { 'content-type': 'text/html' } });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('network_error');
    // A proxy's own JSON error page is not a Velsigil error body either.
    server.handler = () => ({ kind: 'json', status: 503, body: { message: 'Service Unavailable' } });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('network_error');
    server.handler = () => ({ kind: 'raw', status: 504, body: '' });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('network_error');
  });

  it('maps gateway statuses with a Velsigil error body to the body code or internal_error', async () => {
    server.handler = () => ({ kind: 'json', status: 503, body: { error: { code: 'internal_error', message: 'x' } } });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('internal_error');
    server.handler = () => ({ kind: 'json', status: 502, body: { error: { code: 'something_new', message: 'x' } } });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('internal_error');
  });

  it('maps bodiless 413/415 to payload_too_large / unsupported_media_type', async () => {
    server.handler = () => ({ kind: 'raw', status: 415, body: '' });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('unsupported_media_type');
    server.handler = () => ({ kind: 'raw', status: 413, body: '<html>Too large</html>' });
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('payload_too_large');
  });

  it('treats redirects as invalid responses', async () => {
    server.handler = () => ({ kind: 'raw', status: 302, body: '', headers: { location: 'http://evil.example.com/' } });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.code).toBe('invalid_response');
    expect(server.requests).toHaveLength(1);
  });

  it('caps the response size', async () => {
    server.handler = () => ({ kind: 'raw', status: 200, body: 'x'.repeat(8 * 1024) });
    const result = await makeClient({ maxResponseBytes: 4096 }).validate(LICENSE_KEY);
    expect(result.code).toBe('invalid_response');
  });
});

describe('transport failures', () => {
  it('times out -> network_error', async () => {
    server.handler = () => ({ kind: 'hang' });
    const started = Date.now();
    const result = await makeClient({ timeout: 300 }).validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('network_error');
    expect(result.message).toMatch(/did not respond/);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('connection refused -> network_error', async () => {
    const port = await closedPort();
    const result = await makeClient({}, `http://127.0.0.1:${port}`).validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('network_error');
  });

  it('connection reset -> network_error', async () => {
    server.handler = () => ({ kind: 'destroy' });
    const result = await makeClient().validate(LICENSE_KEY);
    expect(result.code).toBe('network_error');
  });
});

describe('offline leases', () => {
  function leaseHandler(exp: number) {
    return (request: Parameters<MockServer['handler']>[0]) => ({
      kind: 'signed' as const,
      payload: payloadFor(request, {
        lease: { token: makeLease({ iat: T0, exp, licenseExpiresAt: T0 + 30 * 86_400 }), expiresAt: exp },
      }),
    });
  }

  it('stores the lease from a successful validation and falls back to it on network errors only', async () => {
    let nowMs = T0 * 1000;
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => nowMs });
    server.handler = leaseHandler(T0 + 3600);

    const online = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(online.ok).toBe(true);
    expect(online.offline).toBe(false);
    expect(online.lease?.expiresAt).toBe(T0 + 3600);
    expect(store.load(PRODUCT_ID)?.lease?.expiresAt).toBe(T0 + 3600);

    // Server unreachable: the stored lease keeps the app working until it expires.
    server.handler = () => ({ kind: 'destroy' });
    nowMs = (T0 + 1800) * 1000;
    const offline = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(offline.ok).toBe(true);
    expect(offline.offline).toBe(true);
    expect(offline.code).toBe('ok');
    expect(offline.license?.id).toBe('5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f');
    expect(offline.hasFeature('export')).toBe(true);
    expect(offline.leaseExpiresAt?.getTime()).toBe((T0 + 3600) * 1000);

    nowMs = (T0 + 3600) * 1000;
    const expired = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(expired.ok).toBe(false);
    expect(expired.offline).toBe(true);
    expect(expired.code).toBe('lease_expired');
    expect(expired.hasFeature('export')).toBe(false);
  });

  it('does not fall back when the server answers with a denial, and drops the lease', async () => {
    const nowMs = T0 * 1000;
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => nowMs });
    server.handler = leaseHandler(T0 + 3600);
    expect((await client.validate(LICENSE_KEY)).ok).toBe(true);

    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: false, code: 'license_revoked', message: 'Revoked.', activation: null }),
    });
    const denied = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(denied.ok).toBe(false);
    expect(denied.code).toBe('license_revoked');
    expect(denied.offline).toBe(false);
    expect(store.load(PRODUCT_ID)?.lease ?? null).toBeNull();

    server.handler = () => ({ kind: 'destroy' });
    const afterwards = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(afterwards.ok).toBe(false);
    expect(afterwards.code).toBe('network_error');
  });

  it('does not fall back on unsigned server errors', async () => {
    const nowMs = T0 * 1000;
    const client = makeClient({ clock: () => nowMs });
    server.handler = leaseHandler(T0 + 3600);
    await client.validate(LICENSE_KEY);
    server.handler = () => ({ kind: 'json', status: 500, body: { error: { code: 'internal_error' } } });
    const result = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(result.code).toBe('internal_error');
    expect(result.ok).toBe(false);
  });

  it('removes the stored lease when a later success carries none', async () => {
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => T0 * 1000 });
    server.handler = leaseHandler(T0 + 3600);
    await client.validate(LICENSE_KEY);
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request) });
    await client.validate(LICENSE_KEY);
    expect(store.load(PRODUCT_ID)?.lease ?? null).toBeNull();
    expect((await client.validateOffline()).code).toBe('no_lease');
  });

  it('rejects a signed success whose lease belongs to another device and keeps the local state', async () => {
    // A license-sharing proxy rewrites hwid + deviceSecret to those of one real activation: the
    // server's signed answer (lease) then describes that device, not this one.
    const store = new MemoryStore();
    const ownLease = makeLease({ iat: T0, exp: T0 + 3600 });
    store.save(PRODUCT_ID, { deviceSecret: SECRET_1, lease: { token: ownLease, expiresAt: T0 + 3600 } });
    const client = makeClient({ store, clock: () => T0 * 1000 });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        activation: { id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d', status: 'active', firstSeenAt: T0, deviceSecret: `dsk_${'Z9y8X7w6'.repeat(5)}abc` },
        lease: { token: makeLease({ iat: T0, exp: T0 + 7200, hwid: 'another-device-hwid' }), expiresAt: T0 + 7200 },
      }),
    });
    const result = await client.validate(LICENSE_KEY);
    expect(result).toMatchObject({ ok: false, code: 'invalid_response', license: null, lease: null });
    expect(result.message).toContain('different device');
    expect(result.hasFeature('pro')).toBe(false);
    // Nothing from the foreign response is used: no secret, no lease, the own lease survives.
    expect(store.load(PRODUCT_ID)).toEqual({ deviceSecret: SECRET_1, lease: { token: ownLease, expiresAt: T0 + 3600 } });
    // invalid_response never triggers the offline fallback.
    expect((await client.validateWithOfflineFallback(LICENSE_KEY)).code).toBe('invalid_response');
  });

  it('rejects a signed success whose lease belongs to another product', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        lease: {
          token: makeLease({ iat: T0, exp: T0 + 3600, productId: '7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6' }),
          expiresAt: T0 + 3600,
        },
      }),
    });
    expect(await client.validate(LICENSE_KEY)).toMatchObject({ ok: false, code: 'invalid_response' });
  });

  it('still accepts (but never stores) an own lease that is unusable for other reasons', async () => {
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => T0 * 1000 });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        lease: { token: makeLease({ iat: T0 - 7200, exp: T0 - 3600 }), expiresAt: T0 - 3600 },
      }),
    });
    expect((await client.validate(LICENSE_KEY)).ok).toBe(true);
    expect(store.load(PRODUCT_ID)).toBeNull();
  });

  it('rejects and forgets a tampered stored lease', async () => {
    const store = new MemoryStore();
    const forged = makeLease({ iat: T0, exp: T0 + 10 * 86_400 }, WRONG_KEY);
    store.save(PRODUCT_ID, { deviceSecret: SECRET_1, lease: { token: forged, expiresAt: T0 + 10 * 86_400 } });
    const client = makeClient({ store, clock: () => T0 * 1000 });
    const result = await client.validateOffline();
    expect(result.ok).toBe(false);
    expect(result.offline).toBe(true);
    expect(result.code).toBe('lease_invalid');
    expect(store.load(PRODUCT_ID)).toEqual({ deviceSecret: SECRET_1, lease: null });
  });

  it('reports no_lease when nothing is stored', async () => {
    const result = await makeClient().validateOffline();
    expect(result).toMatchObject({ ok: false, code: 'no_lease', offline: true });
  });

  it('keeps working from memory and reports store failures', async () => {
    const errors: unknown[] = [];
    const failing = {
      load: () => {
        throw new Error('disk unavailable');
      },
      save: () => {
        throw new Error('disk full');
      },
      clear: () => undefined,
    };
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        activation: {
          id: 'act',
          status: 'active',
          firstSeenAt: 1,
          deviceSecret: request.body.deviceSecret === undefined ? SECRET_1 : null,
        },
      }),
    });
    const client = makeClient({ store: failing, onStoreError: (error) => errors.push(error) });
    expect((await client.validate(LICENSE_KEY)).ok).toBe(true);
    expect((await client.validate(LICENSE_KEY)).ok).toBe(true);
    expect(server.requests[1]!.body.deviceSecret).toBe(SECRET_1);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('prefers unsaved in-memory state over stale data in a read-only store', async () => {
    const staleSecret = `dsk_${'stale'.repeat(8)}`;
    const readOnly = {
      load: () => ({ deviceSecret: staleSecret, lease: null }),
      save: () => {
        throw new Error('read-only');
      },
      clear: () => {
        throw new Error('read-only');
      },
    };
    let calls = 0;
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        activation: { id: 'act', status: 'active', firstSeenAt: 1, deviceSecret: calls++ === 0 ? SECRET_1 : null },
      }),
    });
    const client = makeClient({ store: readOnly });
    await client.validate(LICENSE_KEY);
    await client.validate(LICENSE_KEY);
    expect(server.requests[0]!.body.deviceSecret).toBe(staleSecret);
    expect(server.requests[1]!.body.deviceSecret).toBe(SECRET_1);
  });

  it('drops the lease when a download request is definitively denied', async () => {
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => T0 * 1000 });
    server.handler = leaseHandler(T0 + 3600);
    await client.validate(LICENSE_KEY);
    expect(store.load(PRODUCT_ID)?.lease).not.toBeNull();

    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: false, code: 'license_banned', message: 'Banned.', activation: null }),
    });
    const result = await client.getDownload(LICENSE_KEY);
    expect(result.code).toBe('license_banned');
    expect(store.load(PRODUCT_ID)?.lease ?? null).toBeNull();
    expect((await client.validateOffline()).code).toBe('no_lease');
  });

  it('keeps the lease on transient signed failures', async () => {
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => T0 * 1000 });
    server.handler = leaseHandler(T0 + 3600);
    await client.validate(LICENSE_KEY);
    for (const code of [
      'product_paused',
      'outdated_version',
      'activation_rate_limited',
      'activations_disabled',
      'replay_detected',
      // Free trials (SPEC 9.7): another key's trial refused on this device says nothing about the stored license.
      'trial_already_used',
    ]) {
      server.handler = (request) => ({
        kind: 'signed',
        payload: payloadFor(request, { ok: false, code, message: 'Not now.', activation: null }),
      });
      expect((await client.validate(LICENSE_KEY)).code).toBe(code);
      expect((await client.validateOffline()).ok).toBe(true);
    }
  });

  it('drops the lease for exactly the binding set of definitive denials (SPEC 14)', async () => {
    const revoking = [
      'invalid_key',
      'license_expired',
      'license_suspended',
      'license_revoked',
      'license_banned',
      'device_revoked',
      'device_verification_failed',
      'device_limit_reached',
      'device_not_activated',
      'device_not_found',
      'blacklisted',
      'product_disabled',
    ];
    expect([...LEASE_REVOKING_CODES].sort()).toEqual([...revoking].sort());
    for (const code of revoking) {
      const store = new MemoryStore();
      const client = makeClient({ store, clock: () => T0 * 1000 });
      server.handler = leaseHandler(T0 + 3600);
      await client.validate(LICENSE_KEY);
      expect((await client.validateOffline()).ok).toBe(true);
      server.handler = (request) => ({
        kind: 'signed',
        payload: payloadFor(request, { ok: false, code, message: 'Denied.', activation: null }),
      });
      expect((await client.validate(LICENSE_KEY)).code).toBe(code);
      expect((await client.validateOffline()).code).toBe('no_lease');
    }
  });
});

// Final sweep F-SDK-1: a store read that fails (a file lock, a locked keyring) is not "nothing stored".
describe('store read failures', () => {
  const paidSecret = `dsk_${'P4idL1c3'.repeat(5)}abc`;

  /** A MemoryStore whose loads throw EBUSY: the next `failures` ones, or every one when `failures` is -1. */
  class FlakyStore extends MemoryStore {
    failures: number;
    saves = 0;
    constructor(failures: number) {
      super();
      this.failures = failures;
    }
    override load(productId: string): StoredState | null {
      if (this.failures !== 0) {
        if (this.failures > 0) this.failures--;
        throw Object.assign(new Error('resource busy or locked'), { code: 'EBUSY' });
      }
      return super.load(productId);
    }
    override save(productId: string, state: StoredState): void {
      this.saves++;
      super.save(productId, state);
    }
  }

  function okWithLease(request: Parameters<MockServer['handler']>[0], deviceSecret: string | null = null): MockReply {
    return {
      kind: 'signed',
      payload: payloadFor(request, {
        activation: { id: 'act', status: 'active', firstSeenAt: 1, deviceSecret },
        lease: { token: makeLease({ iat: T0, exp: T0 + 3600 }), expiresAt: T0 + 3600 },
      }),
    };
  }

  it('validate merges the answer into the stored state instead of replacing the device secret with nothing', async () => {
    const store = new FlakyStore(1);
    store.save(PRODUCT_ID, { deviceSecret: paidSecret, lease: null });
    server.handler = (request) => okWithLease(request);
    const result = await makeClient({ store, clock: () => T0 * 1000, onStoreError: () => undefined }).validate(LICENSE_KEY);
    expect(result.ok).toBe(true);
    expect(server.requests[0]!.body.deviceSecret).toBeUndefined(); // the read before the request failed
    expect(store.load(PRODUCT_ID)).toEqual({ deviceSecret: paidSecret, lease: { token: expect.any(String), expiresAt: T0 + 3600 } });
  });

  it('writes nothing while the store stays unreadable, except a newly issued device secret', async () => {
    const store = new FlakyStore(0);
    store.save(PRODUCT_ID, { deviceSecret: paidSecret, lease: null });
    store.failures = -1; // every load fails from now on; saves still work
    store.saves = 0;
    const errors: unknown[] = [];
    server.handler = (request) => okWithLease(request);
    const client = makeClient({ store, clock: () => T0 * 1000, onStoreError: (error) => errors.push(error) });
    expect((await client.validate(LICENSE_KEY)).ok).toBe(true);
    expect(store.saves).toBe(0);
    expect(errors.length).toBeGreaterThan(0);
    store.failures = 0;
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(paidSecret);

    // A secret the server just issued belongs to a new activation: it is kept even though the store is unreadable.
    store.failures = -1;
    server.handler = (request) => okWithLease(request, SECRET_1);
    expect((await client.validate(LICENSE_KEY)).ok).toBe(true);
    store.failures = 0;
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(SECRET_1);
  });

  it('startTrial refuses with store_unavailable when the store cannot be read: nothing sent, nothing changed', async () => {
    const store = new FlakyStore(1);
    store.save(PRODUCT_ID, { deviceSecret: paidSecret, lease: null });
    server.handler = (request) => okWithLease(request, SECRET_1);
    const client = makeClient({ store, clock: () => T0 * 1000, onStoreError: () => undefined });
    const refused = await client.startTrial();
    expect(refused).toMatchObject({ ok: false, code: 'store_unavailable', type: 'trial', trialKey: null });
    expect(refused.message).toMatch(/could not be read/);
    expect(server.requests).toHaveLength(0);
    expect(SDK_CODES).toContain('store_unavailable');
    // Once the store can be read again the guard sees the paid license.
    expect((await client.startTrial()).code).toBe('already_licensed');
    expect(server.requests).toHaveLength(0);
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(paidSecret);
  });
});

describe('free trials (SPEC 9.7)', () => {
  it('reports isTrial from the signed license and from the offline lease', async () => {
    let nowMs = T0 * 1000;
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => nowMs });
    server.handler = (request) => {
      const payload = payloadFor(request, {
        lease: { token: makeLease({ iat: T0, exp: T0 + 3600, licenseExpiresAt: T0 + 14 * 86_400, plan: 'Trial', trial: true }), expiresAt: T0 + 3600 },
      });
      return { kind: 'signed', payload: { ...payload, license: { ...(payload.license as object), plan: 'Trial', trial: true } } };
    };
    const online = await client.validate(LICENSE_KEY);
    expect(online.ok).toBe(true);
    expect(online.isTrial).toBe(true);
    expect(online.license?.isTrial).toBe(true);

    server.handler = () => ({ kind: 'destroy' });
    nowMs = (T0 + 60) * 1000;
    const offline = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(offline.offline).toBe(true);
    expect(offline.isTrial).toBe(true);
  });

  it('is false when the field is absent (paid licenses, older servers)', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request) });
    const result = await client.validate(LICENSE_KEY);
    expect(result.ok).toBe(true);
    expect(result.isTrial).toBe(false);
    expect(result.license?.isTrial).toBe(false);
    expect(new VelsigilResult({ ok: false, code: 'network_error', message: 'x' }).isTrial).toBe(false);
  });

  it('rejects a non-boolean trial field as an invalid response', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => {
      const payload = payloadFor(request);
      return { kind: 'signed', payload: { ...payload, license: { ...(payload.license as object), trial: 'yes' } } };
    };
    expect((await client.validate(LICENSE_KEY)).code).toBe('invalid_response');
  });

  it('exposes the trial conversion reference (also on license_expired) and builds the "Buy now" link with it; none offline or when absent; malformed → invalid_response', async () => {
    const REF = `vtr1_${'Ab3_-'.repeat(14)}`;
    let nowMs = T0 * 1000;
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => nowMs });
    server.handler = (request) => {
      const payload = payloadFor(request, {
        lease: { token: makeLease({ iat: T0, exp: T0 + 3600, licenseExpiresAt: T0 + 14 * 86_400, plan: 'Trial', trial: true }), expiresAt: T0 + 3600 },
      });
      return { kind: 'signed', payload: { ...payload, license: { ...(payload.license as object), plan: 'Trial', trialRef: REF, trial: true } } };
    };
    const online = await client.validate(LICENSE_KEY);
    expect(online.ok).toBe(true);
    expect(online.trialRef).toBe(REF);
    expect(online.license?.trialRef).toBe(REF);
    expect(online.withTrialRef('https://shop.example.com/buy')).toBe(`https://shop.example.com/buy?velsigil_trial=${REF}`);
    expect(online.withTrialRef('https://shop.example.com/buy?plan=pro#top')).toBe(`https://shop.example.com/buy?plan=pro&velsigil_trial=${REF}#top`);
    expect(online.withTrialRef('https://buy.stripe.com/test_abc')).toBe(`https://buy.stripe.com/test_abc?client_reference_id=${REF}`);
    expect(withTrialRef('mailto:sales@example.com', REF)).toBe('mailto:sales@example.com');
    expect(TRIAL_REF_PARAM).toBe('velsigil_trial');

    // The offline lease carries none.
    server.handler = () => ({ kind: 'destroy' });
    nowMs = (T0 + 60) * 1000;
    const offline = await client.validateWithOfflineFallback(LICENSE_KEY);
    expect(offline.offline).toBe(true);
    expect(offline.trialRef).toBeNull();
    expect(offline.withTrialRef('https://shop.example.com/buy')).toBe('https://shop.example.com/buy');

    // An expired trial: a denial that still carries the reference (the moment to offer "Buy now").
    const plain = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => {
      const payload = payloadFor(request, { ok: false, code: 'license_expired', message: 'This license has expired.', activation: null, lease: null });
      return { kind: 'signed', payload: { ...payload, license: { ...(payload.license as object), status: 'expired', features: [], trialRef: REF, trial: true } } };
    };
    const expired = await plain.validate(LICENSE_KEY);
    expect([expired.ok, expired.code, expired.trialRef]).toEqual([false, 'license_expired', REF]);

    // Absent (paid licenses, older servers): null.
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request) });
    expect((await plain.validate(LICENSE_KEY)).trialRef).toBeNull();
    // Malformed: the answer is refused.
    for (const bad of [42, '', 'has space', 'x'.repeat(201), 'ünïcode']) {
      server.handler = (request) => {
        const payload = payloadFor(request);
        return { kind: 'signed', payload: { ...payload, license: { ...(payload.license as object), trialRef: bad, trial: true } } };
      };
      expect((await plain.validate(LICENSE_KEY)).code, String(bad)).toBe('invalid_response');
    }
  });

  it('returns trial_already_used as a signed failure', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => {
      const payload = payloadFor(request, {
        ok: false,
        code: 'trial_already_used',
        message: 'This device has already used a free trial of this product.',
        activation: null,
      });
      return { kind: 'signed', payload: { ...payload, license: { ...(payload.license as object), status: 'pending', trial: true } } };
    };
    const result = await client.validate(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('trial_already_used');
    expect(result.hasFeature('pro')).toBe(false);
    expect(SERVER_CODES).toContain('trial_already_used');
    expect(LEASE_REVOKING_CODES.has('trial_already_used')).toBe(false);
  });
});

describe('in-app free trials: startTrial (SPEC 9.7)', () => {
  const TRIAL_KEY = 'DEMO-7K3QM-P9XWD-R4TNB-H2CFY-M8LJV';
  const hwidHash = createHash('sha256').update(TEST_HWID, 'utf8').digest('hex');

  /** A signed trial start for `request`: the trial license, a new device secret, the trial lease and the key. */
  function startedPayload(request: Parameters<typeof payloadFor>[0], overrides: Record<string, unknown> = {}): Record<string, unknown> {
    const base = payloadFor(request, {
      message: 'Your free trial has started.',
      activation: { id: '2c4e6a8b-1d3f-4b5a-9c7e-0f1a2b3c4d5e', status: 'active', firstSeenAt: T0, deviceSecret: SECRET_1, hwidHash },
      lease: { token: makeLease({ iat: T0, exp: T0 + 3600, licenseExpiresAt: T0 + 14 * 86_400, plan: 'Trial', trial: true }), expiresAt: T0 + 3600 },
    });
    return { ...base, license: { ...(base.license as object), plan: 'Trial', trial: true }, trial: { key: TRIAL_KEY }, ...overrides };
  }

  it('posts to /trial without a key, returns the trial key, and persists the device secret and lease like a validation', async () => {
    let nowMs = T0 * 1000;
    const store = new MemoryStore();
    const client = makeClient({ store, clock: () => nowMs });
    server.handler = (request) => ({ kind: 'signed', payload: startedPayload(request) });
    const result = await client.startTrial({ version: '1.2.0', deviceName: 'Laptop' });
    expect(result.ok).toBe(true);
    expect(result.type).toBe('trial');
    expect(result.trialKey).toBe(TRIAL_KEY);
    expect(result.isTrial).toBe(true);
    expect(result.activation?.deviceSecretIssued).toBe(true);
    expect(server.requests.at(-1)!.path).toBe('/api/client/v1/trial');
    expect(server.requests.at(-1)!.body).toEqual({
      productId: PRODUCT_ID,
      hwid: TEST_HWID,
      deviceName: 'Laptop',
      version: '1.2.0',
      nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      timestamp: expect.any(Number),
    });
    expect(store.load(PRODUCT_ID)).toEqual({ deviceSecret: SECRET_1, lease: { token: expect.any(String), expiresAt: T0 + 3600 } });
    // The key is never stored by the SDK.
    expect(JSON.stringify(store.load(PRODUCT_ID))).not.toContain(TRIAL_KEY);
    // Offline works from the trial lease; the next validate (with the key the app stored) sends the device secret.
    server.handler = () => ({ kind: 'destroy' });
    nowMs = (T0 + 60) * 1000;
    const offline = await makeClient({ store, clock: () => nowMs }).validateOffline();
    expect(offline.ok).toBe(true);
    expect(offline.isTrial).toBe(true);
    expect(offline.trialKey).toBeNull();
    server.handler = (request) => ({ kind: 'signed', payload: payloadFor(request) });
    await client.validate(TRIAL_KEY);
    expect(server.requests.at(-1)!.body.deviceSecret).toBe(SECRET_1);
  });

  // Review finding 7: a trial answer would overwrite the device secret and lease of the license this device holds.
  const paidSecret = `dsk_${'P4idL1c3'.repeat(5)}abc`;
  const paidLease = { token: makeLease({ iat: T0, exp: T0 + 7200, licenseExpiresAt: T0 + 365 * 86_400 }), expiresAt: T0 + 7200 };
  it.each([
    { name: 'a device secret', state: { deviceSecret: paidSecret, lease: null } },
    { name: 'a lease', state: { deviceSecret: null, lease: paidLease } },
    { name: 'a device secret and a lease', state: { deviceSecret: paidSecret, lease: paidLease } },
  ])('refuses locally with already_licensed when the store holds $name: nothing sent, nothing changed', async ({ state }) => {
    // If anything were sent, the server would start a trial whose secret and lease replace the stored ones.
    server.handler = (request) => ({ kind: 'signed', payload: startedPayload(request) });
    const store = new MemoryStore();
    store.save(PRODUCT_ID, state);
    const result = await makeClient({ store, clock: () => T0 * 1000 }).startTrial({ version: '1.2.0' });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('already_licensed');
    expect(result.type).toBe('trial');
    expect(result.message).toMatch(/already holds a license for this product/);
    expect(result.message).toMatch(/trial cannot replace it/);
    expect(result.message).toMatch(/clearStoredState\(\)/);
    expect(result.trialKey).toBeNull();
    expect(server.requests).toHaveLength(0);
    expect(store.load(PRODUCT_ID)).toEqual(state);
    expect(SDK_CODES).toContain('already_licensed');
  });

  // Final sweep F-SDK-4: one "days left" rule in every SDK (CLIENT_PROTOCOL 5.2), N right after an N-day trial starts.
  it('reports the full trial length as days left right after the start, online and offline', async () => {
    const clockMs = (T0 + 1) * 1000; // the local clock is a second past the signed serverTime
    const store = new MemoryStore();
    server.handler = (request) => {
      const started = startedPayload(request);
      const license = { ...(started.license as object), expiresAt: T0 + 14 * 86_400 };
      return { kind: 'signed', payload: { ...started, serverTime: T0, license } };
    };
    const trial = await makeClient({ store, clock: () => clockMs }).startTrial();
    expect(trial.ok).toBe(true);
    expect(trial.daysRemaining()).toBe(14);
    expect(trial.daysRemaining((T0 + 14 * 86_400 - 1) * 1000)).toBe(1);
    expect(trial.daysRemaining((T0 + 14 * 86_400) * 1000)).toBe(0);
    const offline = await makeClient({ store, clock: () => clockMs }).validateOffline();
    expect(offline.ok).toBe(true);
    expect(offline.daysRemaining()).toBe(14);
  });

  it('starts the trial once the stored state is cleared (the documented way out of already_licensed)', async () => {
    server.handler = (request) => ({ kind: 'signed', payload: startedPayload(request) });
    const store = new MemoryStore();
    store.save(PRODUCT_ID, { deviceSecret: paidSecret, lease: paidLease });
    const client = makeClient({ store, clock: () => T0 * 1000 });
    expect((await client.startTrial()).code).toBe('already_licensed');
    await client.clearStoredState();
    const result = await client.startTrial();
    expect(result.ok).toBe(true);
    expect(server.requests).toHaveLength(1);
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(SECRET_1);
  });

  it('sends the e-mail address only when given, and reports the signed trial failures', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    for (const code of ['trial_already_used', 'trial_unavailable', 'trial_email_required', 'trial_email_invalid', 'trial_email_not_accepted', 'trial_confirmation_sent']) {
      server.handler = (request) => ({
        kind: 'signed',
        payload: payloadFor(request, { ok: false, code, message: `server text for ${code}`, license: null, activation: null }),
      });
      const result = await client.startTrial({ email: '  jane@example.com ' });
      expect(result.ok).toBe(false);
      expect(result.code).toBe(code);
      expect(result.message).toBe(`server text for ${code}`);
      expect(result.trialKey).toBeNull();
      expect(SERVER_CODES).toContain(code);
      expect(LEASE_REVOKING_CODES.has(code)).toBe(false);
    }
    expect(server.requests.at(-1)!.body.email).toBe('jane@example.com');
    await client.startTrial();
    expect('email' in server.requests.at(-1)!.body).toBe(false);
    expect((await client.startTrial({ email: `${'a'.repeat(250)}@x.io` })).code).toBe('validation_error');
  });

  it('reports panel_too_old when the server has no trial endpoint (404 not_found); unknown_product stays itself', async () => {
    server.handler = () => ({ kind: 'json', status: 404, body: { error: { code: 'not_found', message: 'Not found.', requestId: 'req-old' } } });
    const old = await makeClient().startTrial();
    expect(old.ok).toBe(false);
    expect(old.code).toBe('panel_too_old');
    expect(old.message).toMatch(/update the Velsigil panel/);
    expect(old.requestId).toBe('req-old');
    // Only the trial endpoint maps a 404 like this.
    expect((await makeClient().validate(LICENSE_KEY)).code).toBe('invalid_response');
    server.handler = () => ({ kind: 'json', status: 404, body: { error: { code: 'unknown_product', message: 'Unknown product.' } } });
    expect((await makeClient().startTrial()).code).toBe('unknown_product');
  });

  it('rejects a started trial without a well-formed key, an answer of another type, and one bound to another device', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => {
      const payload = startedPayload(request);
      delete payload.trial;
      return { kind: 'signed', payload };
    };
    expect((await client.startTrial()).code).toBe('invalid_response');
    server.handler = (request) => ({ kind: 'signed', payload: startedPayload(request, { trial: { key: 'bad key\n' } }) });
    expect((await client.startTrial()).code).toBe('invalid_response');
    server.handler = (request) => ({ kind: 'signed', payload: startedPayload(request, { type: 'validate' }) });
    expect((await client.startTrial()).code).toBe('invalid_response');
    server.handler = (request) => ({
      kind: 'signed',
      payload: startedPayload(request, { activation: { id: 'a1', status: 'active', firstSeenAt: T0, deviceSecret: SECRET_1, hwidHash: 'f'.repeat(64) } }),
    });
    const foreign = await client.startTrial();
    expect(foreign.code).toBe('invalid_response');
    expect(foreign.trialKey).toBeNull();
  });

  it('never exposes a key from an answer of another type', async () => {
    const client = makeClient({ clock: () => T0 * 1000 });
    server.handler = (request) => ({ kind: 'signed', payload: { ...payloadFor(request), trial: { key: TRIAL_KEY } } });
    const result = await client.validate(LICENSE_KEY);
    expect(result.ok).toBe(true);
    expect(result.trialKey).toBeNull();
  });
});

describe('deactivate', () => {
  it('clears the stored device state on success', async () => {
    const store = new MemoryStore();
    store.save(PRODUCT_ID, { deviceSecret: SECRET_1, lease: { token: 'a.b', expiresAt: T0 } });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { message: 'Device deactivated.', activation: null, license: null }),
    });
    const result = await makeClient({ store }).deactivate(LICENSE_KEY);
    expect(result.ok).toBe(true);
    expect(result.type).toBe('deactivate');
    expect(server.requests[0]!.path).toBe('/api/client/v1/deactivate');
    expect(server.requests[0]!.body).toEqual({
      productId: PRODUCT_ID,
      licenseKey: LICENSE_KEY,
      hwid: TEST_HWID,
      deviceSecret: SECRET_1,
      nonce: expect.any(String),
      timestamp: expect.any(Number),
    });
    expect(store.load(PRODUCT_ID)).toBeNull();
  });

  it('keeps the stored state when the server refuses', async () => {
    const store = new MemoryStore();
    store.save(PRODUCT_ID, { deviceSecret: SECRET_1, lease: null });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: false, code: 'device_verification_failed', message: 'No.', activation: null }),
    });
    const result = await makeClient({ store }).deactivate(LICENSE_KEY);
    expect(result.code).toBe('device_verification_failed');
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(SECRET_1);
  });

  it('clears the stored device state when the server no longer knows the device', async () => {
    const store = new MemoryStore();
    store.save(PRODUCT_ID, { deviceSecret: SECRET_1, lease: { token: 'a.b', expiresAt: T0 } });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: false, code: 'device_not_found', message: 'Unknown device.', activation: null }),
    });
    const result = await makeClient({ store }).deactivate(LICENSE_KEY);
    expect(result).toMatchObject({ ok: false, code: 'device_not_found' });
    expect(store.load(PRODUCT_ID)).toBeNull();
  });
});

describe('device binding of signed responses (activation.hwidHash)', () => {
  const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
  const activationFor = (hwid: string, deviceSecret: string | null = null) => ({
    id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
    status: 'active',
    firstSeenAt: T0,
    deviceSecret,
    hwidHash: sha256(hwid),
  });

  it('accepts an activation bound to this device (hash compared case-insensitively)', async () => {
    const store = new MemoryStore();
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        activation: { ...activationFor(TEST_HWID, SECRET_1), hwidHash: sha256(TEST_HWID).toUpperCase() },
      }),
    });
    const result = await makeClient({ store }).validate(LICENSE_KEY);
    expect(result).toMatchObject({ ok: true, code: 'ok' });
    expect(result.activation).toEqual({
      id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
      status: 'active',
      firstSeenAt: T0,
      deviceSecretIssued: true,
    });
    expect(store.load(PRODUCT_ID)?.deviceSecret).toBe(SECRET_1);
  });

  it('rejects validate, download and deactivate answers for another device without touching local state', async () => {
    const store = new MemoryStore();
    const ownLease = makeLease({ iat: T0, exp: T0 + 3600 });
    const initial = { deviceSecret: SECRET_1, lease: { token: ownLease, expiresAt: T0 + 3600 } };
    store.save(PRODUCT_ID, initial);
    const client = makeClient({ store, clock: () => T0 * 1000 });
    const download = { url: '/api/download/x', expiresAt: T0 + 600, fileName: 'a.zip', size: 1, sha256: 'a'.repeat(64), version: '1.0.0' };
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        activation: activationFor('another-device-hwid', `dsk_${'Z9y8X7w6'.repeat(5)}abc`),
        ...(request.path.endsWith('/download') ? { download } : {}),
      }),
    });

    for (const call of [() => client.validate(LICENSE_KEY), () => client.getDownload(LICENSE_KEY), () => client.deactivate(LICENSE_KEY)]) {
      const result = await call();
      expect(result).toMatchObject({ ok: false, code: 'invalid_response', activation: null, download: null });
      expect(result.message).toContain('different device');
      // No foreign secret persisted, own lease kept, and a "successful" deactivate clears nothing.
      expect(store.load(PRODUCT_ID)).toEqual(initial);
    }
    expect((await client.validateOffline()).ok).toBe(true);
  });

  it('rejects a malformed activation.hwidHash', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { activation: { ...activationFor(TEST_HWID), hwidHash: 'not-a-hash' } }),
    });
    expect(await makeClient().validate(LICENSE_KEY)).toMatchObject({ ok: false, code: 'invalid_response' });
  });

  it('applies the same check to signed denials', async () => {
    const store = new MemoryStore();
    store.save(PRODUCT_ID, { deviceSecret: SECRET_1, lease: { token: makeLease({ iat: T0, exp: T0 + 3600 }), expiresAt: T0 + 3600 } });
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: false, code: 'device_revoked', message: 'Revoked.', activation: activationFor('another-device-hwid') }),
    });
    const result = await makeClient({ store, clock: () => T0 * 1000 }).validate(LICENSE_KEY);
    expect(result.code).toBe('invalid_response');
    // The denial was about another device: the lease of this one is not revoked by it.
    expect(store.load(PRODUCT_ID)?.lease).not.toBeNull();
  });
});

describe('updates and downloads', () => {
  it('checkUpdate sends only product, version, nonce and timestamp', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        message: 'Update available.',
        license: null,
        activation: null,
        update: { latestVersion: '2.0.0', minVersion: '1.5.0', updateAvailable: true, mandatory: true, changelog: 'Big' },
      }),
    });
    const result = await makeClient().checkUpdate('1.0.0');
    expect(result.ok).toBe(true);
    expect(result.type).toBe('update_check');
    expect(result.update).toEqual({
      latestVersion: '2.0.0',
      minVersion: '1.5.0',
      updateAvailable: true,
      mandatory: true,
      changelog: 'Big',
    });
    expect(server.requests[0]!.path).toBe('/api/client/v1/update-check');
    expect(server.requests[0]!.body).toEqual({
      productId: PRODUCT_ID,
      version: '1.0.0',
      nonce: expect.any(String),
      timestamp: expect.any(Number),
    });
  });

  it('checkUpdate reports no_release (ok, no update) when nothing is published', async () => {
    // Exactly what the server sends (SPEC 10.2).
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, { ok: true, code: 'no_release', message: 'No release has been published yet.', license: null, activation: null, update: null }),
    });
    const result = await makeClient().checkUpdate();
    expect(result).toMatchObject({ ok: true, code: 'no_release', update: null, type: 'update_check' });
  });

  it('getDownload resolves the link and downloadRelease verifies size and SHA-256', async () => {
    const file = Buffer.from('release-binary-contents'.repeat(1000));
    const sha256 = createHash('sha256').update(file).digest('hex');
    server.files.set('/api/download/tok123', file);
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        message: 'Download ready.',
        download: {
          url: '/api/download/tok123',
          expiresAt: T0 + 600,
          fileName: 'app-2.0.0.zip',
          size: file.length,
          sha256,
          version: '2.0.0',
        },
      }),
    });
    const client = makeClient();
    const result = await client.getDownload(LICENSE_KEY, '2.0.0');
    expect(result.ok).toBe(true);
    expect(server.requests[0]!.body).toMatchObject({ licenseKey: LICENSE_KEY, hwid: TEST_HWID, version: '2.0.0' });
    expect(result.download?.url).toBe(`${server.url}/api/download/tok123`);

    const dir = await mkdtemp(join(tmpdir(), 'velsigil-dl-'));
    try {
      const progress: number[] = [];
      const ok = await client.downloadRelease(result.download!, join(dir, 'app.zip'), {
        onProgress: (received) => progress.push(received),
      });
      expect(ok).toMatchObject({ ok: true, code: 'ok', bytes: file.length, sha256 });
      expect(await readFile(join(dir, 'app.zip'))).toEqual(file);
      expect(progress.at(-1)).toBe(file.length);

      const bad = await client.downloadRelease({ ...result.download!, sha256: '0'.repeat(64) }, join(dir, 'bad.zip'));
      expect(bad).toMatchObject({ ok: false, code: 'integrity_mismatch', path: null });
      const wrongSize = await client.downloadRelease({ ...result.download!, size: file.length - 1 }, join(dir, 'bad.zip'));
      expect(wrongSize.code).toBe('integrity_mismatch');
      expect((await readdir(dir)).sort()).toEqual(['app.zip']);

      const insecure = await client.downloadRelease(
        { ...result.download!, url: 'http://downloads.example.com/file' },
        join(dir, 'x.zip'),
      );
      expect(insecure.code).toBe('download_failed');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects a signed download URL that is not HTTPS', async () => {
    server.handler = (request) => ({
      kind: 'signed',
      payload: payloadFor(request, {
        download: {
          url: 'http://downloads.example.com/file',
          expiresAt: T0,
          fileName: 'a.zip',
          size: 1,
          sha256: 'a'.repeat(64),
          version: '1.0.0',
        },
      }),
    });
    const result = await makeClient().getDownload(LICENSE_KEY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe('invalid_response');
  });
});
