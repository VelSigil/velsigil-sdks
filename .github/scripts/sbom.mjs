#!/usr/bin/env node
// Writes one CycloneDX 1.6 SBOM (JSON) per released package into <dist>, describing the package (name, version,
// purl, MIT license, SHA-256 of the released file(s), source repository and commit) and the runtime dependencies it
// declares, taken from the committed manifests and lock files:
//   npm    node/package.json + node/package-lock.json (runtime dependencies only; the SDK has none)
//   PyPI   python/pyproject.toml [project] dependencies and optional extras (version ranges, as declared)
//   NuGet  csharp/src/Velsigil.Client/packages.lock.json (exact versions + SHA-512 content hashes per target framework;
//          build-only packages such as Microsoft.NET.ILLink.Tasks and the NETStandard.Library framework are left out)
//   C++    cpp/vcpkg.json (declared dependencies and version floors; versions come from the pinned vcpkg baseline)
//
//   node .github/scripts/sbom.mjs <version> <dist-dir>
//
// Deterministic for a commit: timestamp = SOURCE_DATE_EPOCH, serial number derived from the content. No dependencies.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPO = 'https://github.com/VelSigil/velsigil-sdks'; // GitHub's exact spelling of the owner (purls below stay lower case)
const [version, distArg] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+$/.test(version ?? '') || !distArg) {
  console.error('usage: node .github/scripts/sbom.mjs <X.Y.Z> <dist-dir>');
  process.exit(1);
}
const dist = resolve(distArg);
const epoch = Number(process.env.SOURCE_DATE_EPOCH ?? Math.floor(Date.now() / 1000));
const timestamp = new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const commit = process.env.GITHUB_SHA ?? '';
const read = (rel) => readFileSync(join(ROOT, ...rel.split('/')), 'utf8');

function sha256Of(file) {
  const abs = join(dist, file);
  if (!existsSync(abs)) throw new Error(`missing artifact ${file} in ${dist}`);
  return createHash('sha256').update(readFileSync(abs)).digest('hex');
}

function bom(component, components, dependsOn, outName) {
  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: '',
    version: 1,
    metadata: {
      timestamp,
      tools: { components: [{ type: 'application', name: 'velsigil-sdks/.github/scripts/sbom.mjs', version }] },
      component,
      supplier: { name: 'Velsigil', url: ['https://www.velsigil.com'] },
    },
    components,
    dependencies: [{ ref: component['bom-ref'], dependsOn: dependsOn ?? components.map((c) => c['bom-ref']) }],
  };
  // Content-derived serial number (RFC 4122 layout, version nibble 5), so the same inputs give the same file.
  const h = createHash('sha256').update(JSON.stringify(doc)).digest('hex');
  doc.serialNumber = `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
  writeFileSync(join(dist, outName), `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`${outName}: ${components.length} dependency component(s)`);
}

function packageComponent({ name, purl, files, description, folder, note }) {
  return {
    type: 'library',
    'bom-ref': purl,
    supplier: { name: 'Velsigil', url: ['https://www.velsigil.com'] },
    name,
    version,
    description,
    licenses: [{ license: { id: 'MIT' } }],
    purl,
    hashes: files.length === 1 ? [{ alg: 'SHA-256', content: sha256Of(files[0]) }] : undefined,
    externalReferences: [
      { type: 'vcs', url: `${REPO}.git` },
      { type: 'website', url: `${REPO}/tree/main/${folder}` },
      { type: 'security-contact', url: 'https://www.velsigil.com/security.html' },
    ],
    properties: [
      ...files.map((f) => ({ name: 'velsigil:artifact', value: `${f} sha256:${sha256Of(f)}` })),
      ...(commit ? [{ name: 'velsigil:source-commit', value: commit }] : []),
      ...(note ? [{ name: 'velsigil:note', value: note }] : []),
    ],
  };
}

// ---- npm ------------------------------------------------------------------------------------------------------
{
  const pkg = JSON.parse(read('node/package.json'));
  const lock = JSON.parse(read('node/package-lock.json'));
  const runtime = Object.entries(lock.packages ?? {}).filter(([loc, e]) => loc && !e.dev && !e.link);
  const components = runtime.map(([loc, e]) => {
    const name = loc.slice(loc.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const purl = `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${e.version}`;
    const [alg, b64] = (e.integrity ?? '').split('-');
    return {
      type: 'library', 'bom-ref': purl, name, version: e.version, purl,
      ...(e.license ? { licenses: [{ expression: e.license }] } : {}),
      ...(alg === 'sha512' ? { hashes: [{ alg: 'SHA-512', content: Buffer.from(b64, 'base64').toString('hex') }] } : {}),
      scope: e.optional ? 'optional' : 'required',
    };
  });
  const file = `${pkg.name}-${version}.tgz`;
  bom(packageComponent({ name: pkg.name, purl: `pkg:npm/${pkg.name}@${version}`, files: [file], description: pkg.description, folder: 'node' }), components, null, `${pkg.name}-npm-${version}.cdx.json`);
}

// ---- PyPI -----------------------------------------------------------------------------------------------------
{
  const toml = read('python/pyproject.toml');
  const project = /^\[project\]\s*$([\s\S]*?)(?=^\[)/m.exec(toml)?.[1] ?? '';
  const list = (re, src) => [...(re.exec(src)?.[1] ?? '').matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  const deps = list(/^dependencies\s*=\s*\[([^\]]*)\]/m, project).map((d) => [d, 'required']);
  const extrasBlock = /^\[project\.optional-dependencies\]\s*$([\s\S]*?)(?=^\[)/m.exec(toml)?.[1] ?? '';
  for (const m of extrasBlock.matchAll(/^\s*[A-Za-z0-9_-]+\s*=\s*\[([^\]]*)\]/gm)) for (const d of list(/([\s\S]*)/, m[1])) deps.push([d, 'optional']);
  const components = deps.map(([spec, scope]) => {
    const m = /^([A-Za-z0-9._-]+)\s*(.*)$/.exec(spec);
    const name = m[1].toLowerCase().replace(/[._]+/g, '-');
    const range = m[2].replace(/\s+/g, '');
    return { type: 'library', 'bom-ref': `pkg:pypi/${name}`, name, isExternal: true, ...(range ? { versionRange: `vers:pypi/${range}` } : {}), purl: `pkg:pypi/${name}`, scope };
  });
  const name = /^name\s*=\s*"([^"]+)"/m.exec(project)[1];
  const dist = name.replace(/-/g, '_');
  const files = [`${dist}-${version}.tar.gz`, `${dist}-${version}-py3-none-any.whl`];
  bom(packageComponent({ name, purl: `pkg:pypi/${name}@${version}`, files, description: /^description\s*=\s*"([^"]+)"/m.exec(project)?.[1], folder: 'python' }), components, null, `${name}-pypi-${version}.cdx.json`);
}

// ---- NuGet ----------------------------------------------------------------------------------------------------
{
  const lock = JSON.parse(read('csharp/src/Velsigil.Client/packages.lock.json'));
  const BUILD_ONLY = new Set(['Microsoft.NET.ILLink.Tasks', 'NETStandard.Library']);
  const found = new Map(); // "Id@ver" -> { id, ver, hash, tfms:Set }
  for (const [tfm, pkgs] of Object.entries(lock.dependencies ?? {})) {
    const queue = Object.entries(pkgs).filter(([id, e]) => e.type === 'Direct' && !BUILD_ONLY.has(id)).map(([id]) => id);
    const seen = new Set();
    while (queue.length) {
      const id = queue.shift();
      if (seen.has(id)) continue;
      seen.add(id);
      const e = pkgs[id];
      if (!e) throw new Error(`packages.lock.json (${tfm}): ${id} is referenced but not locked`);
      const key = `${id}@${e.resolved}`;
      const entry = found.get(key) ?? { id, ver: e.resolved, hash: e.contentHash, tfms: new Set() };
      entry.tfms.add(tfm);
      found.set(key, entry);
      for (const dep of Object.keys(e.dependencies ?? {})) queue.push(dep);
    }
  }
  const components = [...found.values()].sort((a, b) => a.id.localeCompare(b.id)).map((p) => ({
    type: 'library', 'bom-ref': `pkg:nuget/${p.id}@${p.ver}`, name: p.id, version: p.ver, purl: `pkg:nuget/${p.id}@${p.ver}`,
    hashes: [{ alg: 'SHA-512', content: Buffer.from(p.hash, 'base64').toString('hex') }],
    scope: 'required',
    properties: [{ name: 'nuget:target-frameworks', value: [...p.tfms].sort().join(', ') }],
  }));
  bom(packageComponent({ name: 'Velsigil.Client', purl: `pkg:nuget/Velsigil.Client@${version}`, files: [`Velsigil.Client.${version}.nupkg`, `Velsigil.Client.${version}.snupkg`], description: 'Official .NET client for the Velsigil license server', folder: 'csharp', note: 'The SHA-256 values are of the files as built and uploaded. nuget.org adds its repository signature (.signature.p7s) to every package, so a .nupkg downloaded from nuget.org has a different hash; verify that one with dotnet nuget verify.' }), components, null, `Velsigil.Client-nuget-${version}.cdx.json`);
}

// ---- C++ ------------------------------------------------------------------------------------------------------
{
  const manifest = JSON.parse(read('cpp/vcpkg.json'));
  const components = manifest.dependencies.map((d) => {
    const name = typeof d === 'string' ? d : d.name;
    const floor = typeof d === 'string' ? null : d['version>='];
    return {
      type: 'library', 'bom-ref': `pkg:generic/${name}`, name, isExternal: true,
      ...(floor ? { versionRange: `vers:generic/>=${floor}` } : {}),
      purl: `pkg:generic/${name}`, scope: 'required',
      properties: [{ name: 'vcpkg:builtin-baseline', value: manifest['builtin-baseline'] ?? '' }],
    };
  });
  bom(packageComponent({ name: 'velsigil-cpp', purl: `pkg:github/velsigil/velsigil-sdks@v${version}#cpp`, files: [`velsigil-cpp-${version}.tar.gz`], description: manifest.description, folder: 'cpp' }), components, null, `velsigil-cpp-${version}.cdx.json`);
}
