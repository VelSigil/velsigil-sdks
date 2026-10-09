import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { RequestType } from '../../src/index.js';

export interface EnvelopeVector {
  name: string;
  envelope: { data: string; sig?: string; kid?: string };
  payload?: Record<string, unknown>;
  requestNonce: string;
  requestType: RequestType;
  productId: string;
  hwid?: string;
  expect: 'valid' | 'invalid_signature' | 'nonce_mismatch' | 'product_mismatch' | 'type_mismatch' | 'hwid_mismatch';
  /** Dotted paths of fields a parser must ignore. */
  unknownFields?: string[];
}

export interface LeaseVector {
  name: string;
  token: string;
  now: number;
  hwid: string;
  productId: string;
  expect: 'valid' | 'expired' | 'invalid_signature' | 'product_mismatch' | 'hwid_mismatch' | 'malformed';
  payload?: Record<string, unknown>;
  unknownFields?: string[];
}

/** A deep copy of `payload` without `unknownFields`. */
export function knownPayload(payload: Record<string, unknown>, unknownFields: readonly string[] = []): Record<string, unknown> {
  const copy = JSON.parse(JSON.stringify(payload)) as Record<string, unknown>;
  for (const path of unknownFields) {
    const parts = path.split('.');
    let node: Record<string, unknown> | undefined = copy;
    for (const part of parts.slice(0, -1)) node = node?.[part] as Record<string, unknown> | undefined;
    if (node) delete node[parts.at(-1)!];
  }
  return copy;
}

export interface HwidExample {
  machineIdRaw: string;
  machineIdNormalized: string;
  hwid: string;
  serverHwidHash: string;
}

export interface TestVectors {
  keys: {
    publicKey: string;
    privateSeedBase64: string;
    keyId: string;
    wrongPublicKey: string;
    wrongPrivateSeedBase64: string;
  };
  envelopes: EnvelopeVector[];
  leases: LeaseVector[];
  hwid: {
    prefix: string;
    examples: HwidExample[];
    serverHashOfTestHwid: { hwid: string; hwidHash: string };
  };
}

/** sdks/test-vectors.json, shared by every SDK. */
export const vectors: TestVectors = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../../test-vectors.json', import.meta.url)), 'utf8'),
) as TestVectors;
