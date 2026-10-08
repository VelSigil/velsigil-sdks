// Builds the dual package:
//   dist/esm  - ES modules + .d.ts   (tsconfig.esm.json)
//   dist/cjs  - CommonJS   + .d.ts   (tsconfig.cjs.json) with a {"type":"commonjs"} package.json marker
// Runs the TypeScript compiler through the current Node binary (no shell involved).
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');
const require = createRequire(import.meta.url);
const tsc = join(dirname(require.resolve('typescript/package.json')), 'bin', 'tsc');

rmSync(dist, { recursive: true, force: true });

for (const project of ['tsconfig.esm.json', 'tsconfig.cjs.json']) {
  execFileSync(process.execPath, [tsc, '-p', join(root, project)], { cwd: root, stdio: 'inherit' });
}

function writeMarker(dir, type) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify({ type }, null, 2)}\n`);
}

writeMarker(join(dist, 'cjs'), 'commonjs');
writeMarker(join(dist, 'esm'), 'module');

console.log('velsigil-client: built dist/esm and dist/cjs');
