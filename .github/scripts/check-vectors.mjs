#!/usr/bin/env node
// Shared check of test-vectors.json, independent of the four SDK test suites (which classify every vector
// themselves). The file is generated from the server's signing code in the panel repository and must never be
// edited by hand here. This checks:
//   - canonical form: JSON.stringify(parsed, null, 2) + "\n", UTF-8 without BOM, LF only (a hand edit or an editor
//     re-save almost always breaks it);
//   - the key pair: the private seed derives the published public key, and the "wrong" pair differs;
//   - every envelope's Ed25519 signature (over the ASCII bytes of `data`) verifies with the product key exactly when
//     the vector does not expect invalid_signature; names are unique; expect / requestType values are known;
//   - every SDK test suite still reads this file (so none can silently drop the shared vectors).
// Node.js only (node:crypto), no dependencies. Exit 1 with a list of problems.
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
// The SDK source files that hold the guard constant refusing the published test keys (see the check at the end).
const TEST_KEY_GUARD_FILE_LIST = [
  'node/src/signature.ts',
  'python/velsigil_client/client.py',
  'csharp/src/Velsigil.Client/Internal/PublishedTestKeys.cs',
  'cpp/src/client.cpp',
];
const FILE = join(ROOT, 'test-vectors.json');
const problems = [];

const raw = readFileSync(FILE);
const text = raw.toString('utf8');
if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) problems.push('test-vectors.json starts with a UTF-8 BOM');
if (text.includes('\r')) problems.push('test-vectors.json contains CR characters (must be LF only; see .gitattributes)');
const v = JSON.parse(text.replace(/^﻿/, ''));
if (`${JSON.stringify(v, null, 2)}\n` !== text.replace(/\r\n/g, '\n').replace(/^﻿/, '')) {
  problems.push('test-vectors.json is not in its generated form (JSON.stringify(v, null, 2) + LF): it was edited by hand. Re-export it from the panel.');
}

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64 = (s) => Buffer.from(s, 'base64');
const b64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const publicKeyOf = (raw32) => createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: 'der', type: 'spki' });
const publicFromSeed = (seed) =>
  createPublicKey(createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length);

const pub = b64(v.keys.publicKey);
if (pub.length !== 32) problems.push(`keys.publicKey decodes to ${pub.length} bytes, not 32`);
if (!publicFromSeed(b64(v.keys.privateSeedBase64)).equals(pub)) problems.push('keys.privateSeedBase64 does not derive keys.publicKey');
if (!publicFromSeed(b64(v.keys.wrongPrivateSeedBase64)).equals(b64(v.keys.wrongPublicKey))) problems.push('keys.wrongPrivateSeedBase64 does not derive keys.wrongPublicKey');
if (b64(v.keys.wrongPublicKey).equals(pub)) problems.push('keys.wrongPublicKey equals keys.publicKey');
const productKey = publicKeyOf(pub);

const ENVELOPE_EXPECT = new Set(['valid', 'invalid_signature', 'nonce_mismatch', 'product_mismatch', 'hwid_mismatch', 'type_mismatch']);
const LEASE_EXPECT = new Set(['valid', 'expired', 'invalid_signature', 'product_mismatch', 'hwid_mismatch', 'malformed']);
const REQUEST_TYPES = new Set(['validate', 'deactivate', 'update_check', 'download', 'trial']);

const names = new Set();
function uniqueName(kind, name) {
  if (typeof name !== 'string' || !name) problems.push(`${kind} without a name`);
  else if (names.has(`${kind}:${name}`)) problems.push(`duplicate ${kind} name ${name}`);
  names.add(`${kind}:${name}`);
}

let signed = 0;
for (const e of v.envelopes ?? []) {
  uniqueName('envelope', e.name);
  if (!ENVELOPE_EXPECT.has(e.expect)) problems.push(`envelope ${e.name}: unknown expect "${e.expect}"`);
  if (!REQUEST_TYPES.has(e.requestType)) problems.push(`envelope ${e.name}: unknown requestType "${e.requestType}"`);
  const { data, sig } = e.envelope ?? {};
  let ok = false;
  if (typeof data === 'string' && typeof sig === 'string' && /^[A-Za-z0-9_-]+$/.test(sig)) {
    const sigBytes = b64url(sig);
    ok = sigBytes.length === 64 && verify(null, Buffer.from(data, 'ascii'), productKey, sigBytes);
  }
  if (ok !== (e.expect !== 'invalid_signature')) {
    problems.push(`envelope ${e.name}: the signature ${ok ? 'verifies' : 'does not verify'} but expect is ${e.expect}`);
  }
  if (ok) signed++;
}
for (const l of v.leases ?? []) {
  uniqueName('lease', l.name);
  if (!LEASE_EXPECT.has(l.expect)) problems.push(`lease ${l.name}: unknown expect "${l.expect}"`);
}
if ((v.envelopes ?? []).length === 0 || (v.leases ?? []).length === 0) problems.push('no envelope or lease vectors');
if (!v.hwid?.prefix || !(v.hwid?.examples ?? []).length) problems.push('no hwid examples');

// Every SDK suite must still read the shared file.
const consumers = [
  ['node/test/helpers/vectors.ts', /test-vectors\.json/],
  ['python/tests/mock_server.py', /test-vectors\.json/],
  ['csharp/tests/Velsigil.Client.Tests/Velsigil.Client.Tests.csproj', /test-vectors\.json/],
  ['cpp/CMakeLists.txt', /test-vectors\.json/],
];
for (const [rel, re] of consumers) {
  let src = '';
  try {
    src = readFileSync(join(ROOT, ...rel.split('/')), 'utf8');
  } catch {
    problems.push(`${rel} is missing`);
    continue;
  }
  if (!re.test(src)) problems.push(`${rel} no longer reads test-vectors.json`);
}

// The published test keys (their private seeds are in this file) must never appear where a seller could copy them
// into an application: READMEs, docs, examples, docstrings. They are allowed only in tests, in this file and in the
// SDKs' guard constants that refuse them (TEST_KEY_GUARD_FILES).
const TEST_KEY_GUARD_FILES = new Set(TEST_KEY_GUARD_FILE_LIST);
const testKeyStrings = [v.keys.publicKey, v.keys.wrongPublicKey];
const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT }).toString('utf8').split('\0').filter(Boolean);
for (const rel of tracked) {
  if (rel === 'test-vectors.json' || TEST_KEY_GUARD_FILES.has(rel) || /(^|\/)(test|tests)\//.test(rel)) continue;
  let src;
  try { src = readFileSync(join(ROOT, rel), 'utf8'); } catch { continue; }
  for (const k of testKeyStrings) {
    if (src.includes(k)) problems.push(`${rel} contains the published test key ${k.slice(0, 8)}...: use a placeholder such as "<your product public key>" (only tests and the SDK guard constants may contain it)`);
  }
}
for (const rel of TEST_KEY_GUARD_FILES) {
  if (!tracked.includes(rel)) problems.push(`${rel} (listed in TEST_KEY_GUARD_FILES) is not in the repository: update the list`);
}

if (problems.length) {
  for (const p of problems) console.error(`::error::${p}`);
  process.exitCode = 1;
} else {
  console.log(`test-vectors.json OK: ${v.envelopes.length} envelopes (${signed} correctly signed), ${v.leases.length} leases, ${v.hwid.examples.length} hwid examples; read by all four SDK suites.`);
}
