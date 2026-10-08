#!/usr/bin/env node
// Checks that every SDK carries the same version in every place it is written, and (with --tag) that the
// release tag names exactly that version. All four SDKs share one version and one tag: vX.Y.Z.
//
//   node .github/scripts/check-versions.mjs                       consistency only (CI)
//   node .github/scripts/check-versions.mjs --tag v1.2.3          ... and the tag must be v<version> (release.yml)
//   node .github/scripts/check-versions.mjs --tag v1.2.3 --github-output
//                                                                  also writes version=<x.y.z> to $GITHUB_OUTPUT
//
// No dependencies. Exit 1 with a list of the mismatches.
import { appendFileSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel) => readFileSync(join(ROOT, ...rel.split('/')), 'utf8');
const json = (rel) => JSON.parse(read(rel));
function match(rel, re) {
  const m = re.exec(read(rel));
  return m ? m[1] : null;
}

/** [where, version found (null = not found)] for every place a release version is written. */
export function versionSources() {
  const lock = json('node/package-lock.json');
  return [
    ['node/package.json "version"', json('node/package.json').version ?? null],
    ['node/package-lock.json "version"', lock.version ?? null],
    ['node/package-lock.json packages[""].version', lock.packages?.['']?.version ?? null],
    ['node/src/version.ts SDK_VERSION', match('node/src/version.ts', /export const SDK_VERSION = '([^']+)'/)],
    ['python/pyproject.toml [project] version', match('python/pyproject.toml', /^\[project\][^[]*?^version = "([^"]+)"/ms)],
    ['python/velsigil_client/client.py SDK_VERSION', match('python/velsigil_client/client.py', /^SDK_VERSION = "([^"]+)"/m)],
    ['csharp/src/Velsigil.Client/Velsigil.Client.csproj <Version>', match('csharp/src/Velsigil.Client/Velsigil.Client.csproj', /<Version>([^<]+)<\/Version>/)],
    ['csharp/src/Velsigil.Client/VelsigilClient.cs SdkVersion', match('csharp/src/Velsigil.Client/VelsigilClient.cs', /public const string SdkVersion = "([^"]+)";/)],
    ['cpp/CMakeLists.txt project(velsigil VERSION)', match('cpp/CMakeLists.txt', /project\(\s*velsigil\s+VERSION\s+([0-9A-Za-z.+-]+)/)],
    ['cpp/vcpkg.json "version"', json('cpp/vcpkg.json').version ?? null],
    ['cpp/include/velsigil/client.hpp kSdkVersion', match('cpp/include/velsigil/client.hpp', /kSdkVersion\[\]\s*=\s*"([^"]+)"/)],
  ];
}

function main(argv) {
  const tagAt = argv.indexOf('--tag');
  const tag = tagAt >= 0 ? argv[tagAt + 1] ?? '' : null;
  const sources = versionSources();
  const problems = [];
  for (const [where, v] of sources) if (v === null) problems.push(`${where}: not found (the pattern in .github/scripts/check-versions.mjs no longer matches)`);
  const found = [...new Set(sources.map(([, v]) => v).filter((v) => v !== null))];
  if (found.length > 1) {
    problems.push('the SDK versions differ:');
    for (const [where, v] of sources) problems.push(`  ${String(v).padEnd(12)} ${where}`);
  }
  const version = found[0] ?? null;
  // Plain X.Y.Z only: pre-releases would need a separate npm dist-tag, PyPI spelling (rc1) and vcpkg version-semver.
  if (version !== null && !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) problems.push(`version "${version}" is not a plain X.Y.Z release version`);
  if (tag !== null) {
    if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag)) problems.push(`tag "${tag}" is not of the form vX.Y.Z`);
    else if (version !== null && tag !== `v${version}`) problems.push(`tag ${tag} does not match the SDK version ${version}. Set the new version in every file this script reads (in the panel's sdks/, then export) or tag v${version}.`);
  }
  if (problems.length) {
    for (const p of problems) console.error(p.startsWith('  ') ? p : `::error::${p}`);
    return 1;
  }
  console.log(`All ${sources.length} version fields say ${version}${tag ? ` (tag ${tag})` : ''}.`);
  if (argv.includes('--github-output')) {
    if (!process.env.GITHUB_OUTPUT) throw new Error('--github-output given but GITHUB_OUTPUT is not set');
    appendFileSync(process.env.GITHUB_OUTPUT, `version=${version}\n`);
  }
  return 0;
}

process.exitCode = main(process.argv.slice(2));
