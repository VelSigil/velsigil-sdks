#!/usr/bin/env node
// Velsigil Node.js SDK - runnable example: validate a license (with offline fallback), gate a feature, check for
// updates and optionally download + verify a release.
//
// 1. Set API_URL, PRODUCT_ID and PUBLIC_KEY below to your product's values.
// 2. Build the SDK (in the SDK's node folder):   npm ci --ignore-scripts && npm run build
// 3. Run (PowerShell):   $env:VELSIGIL_LICENSE_KEY = "<license key>"; node examples/basic.mjs
//    or (bash):          VELSIGIL_LICENSE_KEY=<license key> node examples/basic.mjs
//
// Optional: VELSIGIL_DOWNLOAD_DIR=<dir> (also download and verify the latest release).
// Until the three values are set (they are placeholders), it prints a usage message and exits with code 2.
// Never print or log the license key.
import { hostname } from 'node:os';
import { join } from 'node:path';
import { defaultStoreDirectory, FileStore, VelsigilClient, VelsigilError } from 'velsigil-client';

// Replace these with the values from your product's "Integration" tab in the Velsigil panel (Products > your
// product > Integration). Keep them in your code: the public key is the trust anchor that makes forged server
// answers detectable, so never load it (or the API URL / product id) from a file, environment variable or
// setting the user can change - otherwise anyone can point the app at their own key and a fake server.
const API_URL = '<your Velsigil server URL>'; // e.g. 'https://licenses.example.com'
const PRODUCT_ID = '<your product id>'; // the product UUID
const PUBLIC_KEY = "<your product's public key>"; // standard base64 of the 32-byte Ed25519 key

const APP_NAME = 'VelsigilExample';
const APP_VERSION = '1.0.0';

// Local testing ONLY (delete this in a real application): VELSIGIL_API_URL, VELSIGIL_PRODUCT_ID and
// VELSIGIL_PUBLIC_KEY may replace the three values above, but only when the API URL in use is a loopback URL
// (localhost, 127.0.0.1 or [::1]), e.g. a local panel or the SDK's mock server. Any other API URL makes the
// example refuse them, so they can never redirect it to a remote server. The SDK itself accepts the published
// public test key of the SDK test vectors only for such loopback URLs.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const isLoopbackUrl = (value) => {
  try {
    const url = new URL(value);
    return (url.protocol === 'http:' || url.protocol === 'https:') && LOOPBACK_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
};

const USAGE = [
  'usage: VELSIGIL_LICENSE_KEY=<license key> node examples/basic.mjs',
  "Set API_URL, PRODUCT_ID and PUBLIC_KEY in examples/basic.mjs to your product's values from the Velsigil",
  'panel (Products > your product > Integration). For a local server only, VELSIGIL_API_URL=http://127.0.0.1:<port>',
  '(with VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY) may replace them.',
].join('\n');

function exitWithUsage(problem) {
  console.error(`${problem}\n${USAGE}`);
  process.exit(2);
}

const env = process.env;
const apiUrl = env.VELSIGIL_API_URL || API_URL;
const overridden = ['VELSIGIL_API_URL', 'VELSIGIL_PRODUCT_ID', 'VELSIGIL_PUBLIC_KEY'].filter((name) => env[name]);
if (overridden.length > 0 && !isLoopbackUrl(apiUrl)) {
  exitWithUsage(`Refused ${overridden.join(', ')}: environment overrides are accepted only for a loopback API URL.`);
}
const config = {
  API_URL: apiUrl,
  PRODUCT_ID: env.VELSIGIL_PRODUCT_ID || PRODUCT_ID,
  PUBLIC_KEY: env.VELSIGIL_PUBLIC_KEY || PUBLIC_KEY,
};
const placeholders = Object.keys(config).filter((name) => /^<.*>$/.test(config[name]));
if (placeholders.length > 0) exitWithUsage(`Not configured yet (still a placeholder): ${placeholders.join(', ')}.`);

const licenseKey = env.VELSIGIL_LICENSE_KEY;
if (!licenseKey) exitWithUsage('VELSIGIL_LICENSE_KEY is not set.');
const downloadDir = env.VELSIGIL_DOWNLOAD_DIR;

let client;
try {
  client = new VelsigilClient(config.API_URL, config.PRODUCT_ID, config.PUBLIC_KEY, {
    // Persist the device secret and offline lease per OS user.
    store: new FileStore(defaultStoreDirectory(APP_NAME)),
    onStoreError: () => console.warn('Warning: could not persist license state; continuing in memory.'),
  });
} catch (error) {
  if (error instanceof VelsigilError) {
    console.error(`Configuration error (${error.code}): ${error.message}`);
    process.exit(2);
  }
  throw error;
}

// Online validation; falls back to the stored offline lease ONLY if the server is unavailable
// (no HTTP response, or an unsigned HTTP 5xx such as a database outage or a gateway's 502/503/504).
const result = await client.validateWithOfflineFallback(licenseKey, {
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

    if (downloadDir) {
      const link = await client.getDownload(licenseKey, info.latestVersion);
      if (link.ok && link.download) {
        // Never trust a file name as a path: accept a plain, safe base name only.
        const name = link.download.fileName;
        const safeName = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$/.test(name) ? name : 'release.bin';
        const destination = join(downloadDir, safeName);
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
