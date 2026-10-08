import { createHash, createPrivateKey, randomUUID, sign, type KeyObject } from 'node:crypto';
import { createServer, type IncomingHttpHeaders, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { vectors } from './vectors.js';

/** PKCS#8 DER prefix for a raw 32-byte Ed25519 seed (RFC 8410). */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function privateKeyFromSeed(seedBase64: string): KeyObject {
  const seed = Buffer.from(seedBase64, 'base64');
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}

export const GOOD_KEY = privateKeyFromSeed(vectors.keys.privateSeedBase64);
export const WRONG_KEY = privateKeyFromSeed(vectors.keys.wrongPrivateSeedBase64);
export const PUBLIC_KEY = vectors.keys.publicKey;
export const PRODUCT_ID = '0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b';
export const TEST_HWID = 'test-hwid-0001-abcdef';

/** Signs a payload exactly like the server: base64url(UTF-8 JSON) + Ed25519 over the ASCII data. */
export function signEnvelope(payload: unknown, key: KeyObject = GOOD_KEY): { data: string; sig: string; kid: string } {
  const data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = sign(null, Buffer.from(data, 'ascii'), key).toString('base64url');
  return { data, sig, kid: vectors.keys.keyId };
}

export interface LeaseFields {
  productId?: string;
  hwid?: string;
  licenseId?: string;
  activationId?: string;
  plan?: string;
  features?: string[];
  licenseExpiresAt?: number | null;
  iat: number;
  exp: number;
  typ?: string;
  /** Free-trial lease (SPEC 9.7): adds the optional signed `trial` field. */
  trial?: unknown;
}

/** Builds a lease token `base64url(JSON).base64url(sig)`. */
export function makeLease(fields: LeaseFields, key: KeyObject = GOOD_KEY): string {
  const payload = {
    v: 1,
    typ: fields.typ ?? 'lease',
    productId: fields.productId ?? PRODUCT_ID,
    licenseId: fields.licenseId ?? '5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f',
    activationId: fields.activationId ?? '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
    hwidHash: createHash('sha256').update(fields.hwid ?? TEST_HWID, 'utf8').digest('hex'),
    plan: fields.plan ?? 'Monthly',
    features: fields.features ?? ['pro', 'export'],
    licenseExpiresAt: fields.licenseExpiresAt === undefined ? null : fields.licenseExpiresAt,
    iat: fields.iat,
    exp: fields.exp,
    ...(fields.trial === undefined ? {} : { trial: fields.trial }),
  };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = sign(null, Buffer.from(body, 'ascii'), key).toString('base64url');
  return `${body}.${sig}`;
}

export interface MockRequest {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: Record<string, unknown>;
}

export type MockReply =
  | { kind: 'signed'; payload: Record<string, unknown>; status?: number; key?: KeyObject }
  | { kind: 'json'; status: number; body: unknown; headers?: Record<string, string> }
  | { kind: 'raw'; status: number; body: string | Buffer; headers?: Record<string, string> }
  | { kind: 'hang' }
  | { kind: 'destroy' };

export type MockHandler = (request: MockRequest) => MockReply | Promise<MockReply>;

const TYPE_BY_PATH: Record<string, string> = {
  '/api/client/v1/validate': 'validate',
  '/api/client/v1/deactivate': 'deactivate',
  '/api/client/v1/update-check': 'update_check',
  '/api/client/v1/download': 'download',
  '/api/client/v1/trial': 'trial',
};

/**
 * Builds a signed-response payload for `request` that echoes its nonce and productId.
 * `serverTime` defaults to the request timestamp so tests are independent of the wall clock.
 */
export function payloadFor(request: MockRequest, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const serverTime = typeof request.body.timestamp === 'number' ? request.body.timestamp : Math.floor(Date.now() / 1000);
  return {
    v: 1,
    type: TYPE_BY_PATH[request.path] ?? 'validate',
    ok: true,
    code: 'ok',
    message: 'License is valid.',
    nonce: request.body.nonce,
    requestId: randomUUID(),
    serverTime,
    productId: request.body.productId,
    license: {
      id: '5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f',
      plan: 'Monthly',
      status: 'active',
      features: ['pro', 'export'],
      expiresAt: serverTime + 30 * 86_400,
      maxDevices: 2,
      devicesUsed: 1,
      createdAt: serverTime - 86_400,
    },
    activation: {
      id: '9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d',
      status: 'active',
      firstSeenAt: serverTime,
      deviceSecret: null,
    },
    lease: null,
    update: null,
    ...overrides,
  };
}

/** A local HTTP server that speaks the Velsigil client protocol with scripted replies. */
export class MockServer {
  readonly requests: MockRequest[] = [];
  handler: MockHandler = (request) => ({ kind: 'signed', payload: payloadFor(request) });
  /** Extra plain GET routes (e.g. release files): path -> body. */
  readonly files = new Map<string, Buffer>();
  #server: Server | null = null;
  readonly #sockets = new Set<Socket>();
  #url = '';

  get url(): string {
    return this.#url;
  }

  get port(): number {
    return Number(new URL(this.#url).port);
  }

  async start(): Promise<string> {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        void this.#handle(req.method ?? 'GET', req.url ?? '/', req.headers, Buffer.concat(chunks), res);
      });
    });
    server.on('connection', (socket) => {
      this.#sockets.add(socket);
      socket.on('close', () => this.#sockets.delete(socket));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    this.#server = server;
    this.#url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    return this.#url;
  }

  async stop(): Promise<void> {
    const server = this.#server;
    if (server === null) return;
    this.#server = null;
    for (const socket of this.#sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  async #handle(
    method: string,
    path: string,
    headers: IncomingHttpHeaders,
    raw: Buffer,
    res: ServerResponse,
  ): Promise<void> {
    const file = this.files.get(path);
    if (method === 'GET' && file !== undefined) {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(file.length) });
      res.end(file);
      return;
    }
    let body: Record<string, unknown> = {};
    try {
      body = raw.length > 0 ? (JSON.parse(raw.toString('utf8')) as Record<string, unknown>) : {};
    } catch {
      body = {};
    }
    const request: MockRequest = { method, path, headers, body };
    this.requests.push(request);
    const reply = await this.handler(request);
    switch (reply.kind) {
      case 'signed': {
        const envelope = signEnvelope(reply.payload, reply.key ?? GOOD_KEY);
        res.writeHead(reply.status ?? 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(envelope));
        return;
      }
      case 'json':
        res.writeHead(reply.status, { 'content-type': 'application/json', ...reply.headers });
        res.end(JSON.stringify(reply.body));
        return;
      case 'raw':
        res.writeHead(reply.status, reply.headers ?? {});
        res.end(reply.body);
        return;
      case 'hang':
        return; // never answer; the client must time out
      case 'destroy':
        res.socket?.destroy();
        return;
    }
  }
}
