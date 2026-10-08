#!/usr/bin/env node
// Velsigil Node.js SDK - runnable example.
//
// Build the SDK first (in the SDK's node folder):   npm ci --ignore-scripts && npm run build
// Then run (PowerShell):
//   $env:VELSIGIL_API_URL = "https://licenses.example.com"
//   $env:VELSIGIL_PRODUCT_ID = "<product uuid>"
//   $env:VELSIGIL_PUBLIC_KEY = "<product public key (base64)>"
//   $env:VELSIGIL_LICENSE_KEY = "<license key>"
//   node examples/basic.mjs
// or (bash):
//   VELSIGIL_API_URL=... VELSIGIL_PRODUCT_ID=... VELSIGIL_PUBLIC_KEY=... VELSIGIL_LICENSE_KEY=... node examples/basic.mjs
//
// Optional: VELSIGIL_ALLOW_INSECURE_HTTP=1 (plain http to a non-localhost test server),
//           VELSIGIL_DOWNLOAD_DIR=<dir> (also download and verify the latest release).
//
// NOTE: a real application must embed the public key (and API URL / product id) in its code,
// not read them from the environment - otherwise a user could point it at a fake server.
import { hostname } from 'node:os';
import { join } from 'node:path';
import { defaultStoreDirectory, FileStore, VelsigilClient, VelsigilError } from 'velsigil-client';

const APP_NAME = 'VelsigilExample';
const APP_VERSION = '1.0.0';

const required = ['VELSIGIL_API_URL', 'VELSIGIL_PRODUCT_ID', 'VELSIGIL_PUBLIC_KEY', 'VELSIGIL_LICENSE_KEY'];
const missing = required.filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.error(`Missing environment variables: ${missing.join(', ')}`);
  process.exit(2);
}
const { VELSIGIL_API_URL, VELSIGIL_PRODUCT_ID, VELSIGIL_PUBLIC_KEY, VELSIGIL_LICENSE_KEY, VELSIGIL_DOWNLOAD_DIR } = process.env;

let client;
try {
  client = new VelsigilClient(VELSIGIL_API_URL, VELSIGIL_PRODUCT_ID, VELSIGIL_PUBLIC_KEY, {
    // Persist the device secret and offline lease per OS user.
    store: new FileStore(defaultStoreDirectory(APP_NAME)),
    allowInsecureHttp: process.env.VELSIGIL_ALLOW_INSECURE_HTTP === '1',
    onStoreError: () => console.warn('Warning: could not persist license state; continuing in memory.'),
  });
} catch (error) {
  if (error instanceof VelsigilError) {
    console.error(`Configuration error (${error.code}): ${error.message}`);
    process.exit(2);
  }
  throw error;
}

// Online validation; falls back to the stored offline lease ONLY if the server is unreachable.
const result = await client.validateWithOfflineFallback(VELSIGIL_LICENSE_KEY, {
  version: APP_VERSION,
  deviceName: hostname(),
});

// Never print the license key or device secret. Codes and request ids are safe to show.
if (!result.ok) {
  console.error(`License check failed: ${result.code} - ${result.message}`);
  if (result.requestId) console.error(`Request id (for support): ${result.requestId}`);
  if (result.code === 'rate_limited' && result.retryAfter !== null) {
    console.error(`Retry in ${result.retryAfter} s.`);
  }
  process.exit(1);
}

console.log(`License OK${result.offline ? ' (offline lease)' : ''}`);
console.log(`  plan:     ${result.license?.plan ?? 'n/a'}`);
console.log(`  features: ${result.license?.features.join(', ') || '(none)'}`);
if (result.isLifetime) {
  console.log('  expires:  never');
} else if (result.expiresAt) {
  console.log(`  expires:  ${result.expiresAt.toISOString()} (${result.daysRemaining()} days left)`);
}
if (result.leaseExpiresAt) console.log(`  offline until: ${result.leaseExpiresAt.toISOString()}`);

// Gate features on the verified result, at the place where the feature is used.
if (result.hasFeature('pro')) console.log('  -> Pro features enabled');

if (!result.offline) {
  const update = await client.checkUpdate(APP_VERSION);
  if (update.ok && update.update?.updateAvailable) {
    const info = update.update;
    console.log(`Update available: ${info.latestVersion}${info.mandatory ? ' (mandatory)' : ''}`);

    if (VELSIGIL_DOWNLOAD_DIR) {
      const link = await client.getDownload(VELSIGIL_LICENSE_KEY, info.latestVersion);
      if (link.ok && link.download) {
        // Never trust a file name as a path: accept a plain, safe base name only.
        const name = link.download.fileName;
        const safeName = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$/.test(name) ? name : 'release.bin';
        const destination = join(VELSIGIL_DOWNLOAD_DIR, safeName);
        const file = await client.downloadRelease(link.download, destination, {
          onProgress: (received, total) => process.stdout.write(`\r  downloading ${received}/${total} bytes`),
        });
        process.stdout.write('\n');
        console.log(file.ok ? `  saved and verified: ${file.path}` : `  download failed: ${file.code} - ${file.message}`);
      } else {
        console.log(`  no download link: ${link.code} - ${link.message}`);
      }
    }
  } else if (!update.ok) {
    console.log(`Update check: ${update.code}`);
  }
}
