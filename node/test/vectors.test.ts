import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { HWID_PREFIX, VelsigilError, hwidFromMachineId, type EnvelopeExpectations } from '../src/index.js';
// The vectors are signed with the published test keys, which the public verifyEnvelope / verifyLease refuse
// (see "published test keys" in client.test.ts): the vectors run through the SDK's internal paths, which differ
// from the public helpers only in that refusal.
import { verifyEnvelopeAllowingTestKeys } from '../src/envelope.js';
import { verifyLeaseAllowingTestKeys } from '../src/lease.js';
import { normalizeMachineId } from '../src/hwid.js';
import { GOOD_KEY, signEnvelope } from './helpers/mock-server.js';
import { knownPayload, vectors } from './helpers/vectors.js';

const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

describe('test-vectors.json: envelopes', () => {
  it('contains every documented envelope case', () => {
    const names = vectors.envelopes.map((vector) => vector.name);
    expect(names).toEqual(
      expect.arrayContaining([
        'validate_ok',
        'clock_skew',
        'unicode_message',
        'tampered_data',
        'tampered_signature',
        'wrong_key',
        'missing_signature',
        'nonce_mismatch',
        'product_mismatch',
        'validate_lease_other_device',
        'validate_activation_other_device',
        'type_mismatch',
        'trial_started',
        'trial_start_already_used',
        'trial_unavailable',
        'trial_confirmation_sent',
        'trial_answer_as_validate',
      ]),
    );
  });

  for (const vector of vectors.envelopes) {
    it(`${vector.name} -> ${vector.expect}`, () => {
      const verification = verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, {
        nonce: vector.requestNonce,
        productId: vector.productId,
        type: vector.requestType,
        hwid: vector.hwid,
      });
      expect(verification.status).toBe(vector.expect);
      if (verification.status === 'valid') {
        // The parser normalizes the optional `download` field to null and drops fields it does not know.
        expect(verification.payload).toEqual({ download: null, ...knownPayload(vector.payload!, vector.unknownFields) });
      }
    });
  }

  it('free-trial vectors: the optional signed trial field and trial_already_used (SPEC 9.7)', () => {
    const verify = (name: string) => {
      const vector = vectors.envelopes.find((v) => v.name === name)!;
      return verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, {
        nonce: vector.requestNonce,
        productId: vector.productId,
        type: vector.requestType,
        hwid: vector.hwid,
      });
    };
    const trial = verify('validate_ok_trial');
    expect(trial.status === 'valid' && trial.payload.license?.trial).toBe(true);
    const used = verify('trial_already_used');
    expect(used.status === 'valid' && used.payload.ok === false && used.payload.code === 'trial_already_used').toBe(true);
    // Paid licenses carry no trial field at all (and the existing vectors stay byte-identical).
    const paid = verify('validate_ok');
    expect(paid.status === 'valid' && 'trial' in (paid.payload.license ?? {})).toBe(false);
    // Unknown fields are ignored, never an error.
    expect(verify('unknown_fields').status).toBe('valid');
    // The trial conversion reference (SPEC 9.7): kept on a valid trial answer, also on license_expired.
    for (const name of ['validate_ok_trial_ref', 'license_expired_trial_ref']) {
      const withRef = verify(name);
      expect(withRef.status, name).toBe('valid');
      expect(withRef.status === 'valid' && withRef.payload.license?.trialRef, name).toMatch(/^vtr1_[A-Za-z0-9_-]{70}$/);
    }
    expect(verify('validate_ok_trial').status === 'valid' && 'trialRef' in (verify('validate_ok_trial') as { payload: { license: object } }).payload.license).toBe(false);
  });

  it('in-app trial vectors: type `trial`, the key only on the started trial, and a trial answer is no validation (SPEC 9.7)', () => {
    const verify = (name: string, type?: EnvelopeExpectations['type']) => {
      const vector = vectors.envelopes.find((v) => v.name === name)!;
      return verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, {
        nonce: vector.requestNonce,
        productId: vector.productId,
        type: type ?? vector.requestType,
        hwid: vector.hwid,
      });
    };
    const started = verify('trial_started');
    expect(started.status).toBe('valid');
    if (started.status === 'valid') {
      expect(started.payload).toMatchObject({ type: 'trial', ok: true, license: { trial: true }, trial: { key: expect.any(String) } });
    }
    for (const name of ['trial_start_already_used', 'trial_unavailable', 'trial_confirmation_sent']) {
      const failure = verify(name);
      expect(failure.status).toBe('valid');
      if (failure.status === 'valid') {
        expect(failure.payload.ok).toBe(false);
        expect('trial' in failure.payload).toBe(false);
      }
    }
    expect(verify('trial_answer_as_validate').status).toBe('type_mismatch');
    expect(verify('trial_started', 'validate').status).toBe('type_mismatch');
    expect(verify('validate_ok_trial', 'trial').status).toBe('type_mismatch');
  });

  it('hwid_mismatch vectors are authentic: only the device binding rejects them', () => {
    const bound = vectors.envelopes.filter((v) => v.expect === 'hwid_mismatch');
    expect(bound.length).toBeGreaterThanOrEqual(2);
    for (const vector of bound) {
      const expectations = { nonce: vector.requestNonce, productId: vector.productId, type: vector.requestType };
      const unbound = verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, expectations);
      expect(unbound.status).toBe('valid');
      if (unbound.status === 'valid') expect(unbound.payload).toEqual({ download: null, ...vector.payload });
      // The same bytes are accepted for the device they were issued to.
      const owner = vector.name === 'validate_lease_other_device' ? 'test-hwid-0001-abcdef' : 'test-hwid-9999-zzzzzz';
      const forOwner = verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, { ...expectations, hwid: owner });
      expect(forOwner.status).toBe('valid');
    }
  });

  it('type_mismatch is authentic: only the type check rejects it, even for a device-bound request', () => {
    // SDK-1: a signed update-check answer (ok: true, no license involved) for this request's nonce and
    // product must not pass as the answer to a validate request.
    const vector = vectors.envelopes.find((v) => v.name === 'type_mismatch')!;
    expect(vector.requestType).toBe('validate');
    expect(vector.payload).toMatchObject({ type: 'update_check', ok: true, license: null, lease: null });
    const expectations = { nonce: vector.requestNonce, productId: vector.productId };
    const verify = (more: Pick<EnvelopeExpectations, 'type' | 'hwid'>) =>
      verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, { ...expectations, ...more }).status;
    expect(verify({ type: 'validate' })).toBe('type_mismatch');
    expect(verify({ type: 'update_check' })).toBe('valid');
    expect(verify({ type: 'update_check', hwid: vector.hwid })).toBe('valid');
  });

  it('requires the expected response type', () => {
    const vector = vectors.envelopes.find((v) => v.name === 'type_mismatch')!;
    const untyped = { nonce: vector.requestNonce, productId: vector.productId };
    // @ts-expect-error - `type` is a required expectation (a missing type must not skip the check).
    const call = (): unknown => verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, untyped);
    expect(call).toThrow(VelsigilError);
    expect(call).toThrow(/expected\.type/);
    for (const type of [undefined, null, '', 'VALIDATE', 'ping']) {
      const expectations = { ...untyped, type } as unknown as EnvelopeExpectations;
      expect(() => verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, expectations)).toThrow(
        VelsigilError,
      );
    }
    expect(() =>
      verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, undefined as unknown as EnvelopeExpectations),
    ).toThrow(VelsigilError);
  });

  it('rejects every vector when verified with the wrong public key', () => {
    for (const vector of vectors.envelopes) {
      const verification = verifyEnvelopeAllowingTestKeys(vectors.keys.wrongPublicKey, vector.envelope, {
        nonce: vector.requestNonce,
        productId: vector.productId,
        type: vector.requestType,
      });
      // wrong_key was signed by the "wrong" key pair, so it is the only one that verifies here.
      if (vector.name === 'wrong_key') {
        expect(verification.status).not.toBe('invalid_signature');
      } else {
        expect(verification.status).toBe('invalid_signature');
      }
    }
  });

  it('ignores kid for key selection', () => {
    const vector = vectors.envelopes.find((v) => v.name === 'validate_ok')!;
    const envelope = { ...vector.envelope, kid: 'ffffffffffffffff' };
    const verification = verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, envelope, {
      nonce: vector.requestNonce,
      productId: vector.productId,
      type: vector.requestType,
    });
    expect(verification.status).toBe('valid');
  });

  it('tolerates padded base64url in data and signature', () => {
    const vector = vectors.envelopes.find((v) => v.name === 'validate_ok')!;
    const sig = `${vector.envelope.sig!}==`;
    const verification = verifyEnvelopeAllowingTestKeys(
      vectors.keys.publicKey,
      { data: vector.envelope.data, sig },
      { nonce: vector.requestNonce, productId: vector.productId, type: vector.requestType },
    );
    expect(verification.status).toBe('valid');
  });

  it('rejects a payload of the wrong type when a type is expected', () => {
    const vector = vectors.envelopes.find((v) => v.name === 'validate_ok')!;
    const verification = verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, vector.envelope, {
      nonce: vector.requestNonce,
      productId: vector.productId,
      type: 'deactivate',
    });
    expect(verification.status).toBe('type_mismatch');
  });

  it('treats non-envelope bodies as malformed and non-JSON data as malformed after verification', () => {
    const expectations: EnvelopeExpectations = { nonce: 'n', productId: 'p', type: 'validate' };
    expect(verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, null, expectations).status).toBe('malformed');
    expect(verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, [], expectations).status).toBe('malformed');
    const unsigned = { error: { code: 'internal_error' } };
    expect(verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, unsigned, expectations).status).toBe('malformed');
    const signedGarbage = signEnvelope('not an object');
    expect(verifyEnvelopeAllowingTestKeys(vectors.keys.publicKey, signedGarbage, expectations).status).toBe('malformed');
  });

  it('the mock signer reproduces every valid vector byte-for-byte', () => {
    for (const vector of vectors.envelopes.filter((v) => v.expect === 'valid')) {
      const envelope = signEnvelope(vector.payload, GOOD_KEY);
      expect(envelope.data).toBe(vector.envelope.data);
      expect(envelope.sig).toBe(vector.envelope.sig);
    }
  });
});

describe('test-vectors.json: leases', () => {
  for (const vector of vectors.leases) {
    it(`${vector.name} -> ${vector.expect}`, () => {
      const verification = verifyLeaseAllowingTestKeys(vectors.keys.publicKey, vector.token, {
        productId: vector.productId,
        hwid: vector.hwid,
        now: vector.now,
      });
      expect(verification.status).toBe(vector.expect);
      if (verification.status === 'valid') {
        expect(verification.payload).toEqual(knownPayload(vector.payload!, vector.unknownFields));
      }
    });
  }

  it('lease_trial carries the signed trial flag', () => {
    const vector = vectors.leases.find((v) => v.name === 'lease_trial')!;
    const verification = verifyLeaseAllowingTestKeys(vectors.keys.publicKey, vector.token, { productId: vector.productId, hwid: vector.hwid, now: vector.now });
    expect(verification.status === 'valid' && verification.payload.trial).toBe(true);
  });

  it('lease_ok is valid right up to (but not at) exp', () => {
    const vector = vectors.leases.find((v) => v.name === 'lease_ok')!;
    const exp = vector.payload!.exp as number;
    const at = (now: number) =>
      verifyLeaseAllowingTestKeys(vectors.keys.publicKey, vector.token, { productId: vector.productId, hwid: vector.hwid, now })
        .status;
    expect(at(exp - 1)).toBe('valid');
    expect(at(exp)).toBe('expired');
  });

  it('rejects tokens with extra segments or bad characters as malformed', () => {
    const vector = vectors.leases.find((v) => v.name === 'lease_ok')!;
    const expectations = { productId: vector.productId, hwid: vector.hwid, now: vector.now };
    for (const token of [`${vector.token}.x`, vector.token.replace('.', '.+'), '', 42]) {
      expect(verifyLeaseAllowingTestKeys(vectors.keys.publicKey, token, expectations).status).toBe('malformed');
    }
  });
});

describe('test-vectors.json: hwid', () => {
  it('uses the shared prefix', () => {
    expect(HWID_PREFIX).toBe(vectors.hwid.prefix);
  });

  for (const example of vectors.hwid.examples) {
    it(`derives ${example.hwid.slice(0, 12)}… from ${JSON.stringify(example.machineIdRaw)}`, () => {
      expect(normalizeMachineId(example.machineIdRaw)).toBe(example.machineIdNormalized);
      expect(hwidFromMachineId(example.machineIdRaw)).toBe(example.hwid);
      expect(sha256(example.hwid)).toBe(example.serverHwidHash);
    });
  }

  it('matches the server hash of the test hwid', () => {
    expect(sha256(vectors.hwid.serverHashOfTestHwid.hwid)).toBe(vectors.hwid.serverHashOfTestHwid.hwidHash);
  });
});
