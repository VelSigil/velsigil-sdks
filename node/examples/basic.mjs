#!/usr/bin/env node
// Example: validate a license, gate a feature, check for updates and optionally download a release.
// Run: VELSIGIL_LICENSE_KEY=<license key> node examples/basic.mjs (set VELSIGIL_DOWNLOAD_DIR to download).
import { hostname } from 'node:os';
import { join } from 'node:path';
import { defaultStoreDirectory, FileStore, VelsigilClient, VelsigilError } from 'velsigil-client';

// Values from Products > your product > Integration. Hard-code them: never load them from user-editable config.
const API_URL = '<your Velsigil server URL>';
const PRODUCT_ID = '<your product id>';
const PUBLIC_KEY = "<your product's public key>";

const APP_NAME = 'VelsigilExample';
const APP_VERSION = '1.0.0';

// Local testing only: env overrides are accepted for a loopback API URL. Remove this in a real app.
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

// Uses the offline lease only when the server is unreachable or answers an unsigned 5xx.
const result = await client.validateWithOfflineFallback(licenseKey, {
  version: APP_VERSION,
  deviceName: hostname(),
});

// Never print the license key or device secret.
if (!result.ok) {
  console.error(`License check failed: ${result.code} - ${result.message}`);
  if (result.requestId) console.error(`Request id (for support): ${result.requestId}`);
  if (result.retryAfter !== null) console.error(`Retry in ${result.retryAfter} s.`);
  process.exit(1);
}

console.log(`License OK${result.offline ? ' (offline lease)' : ''}`);
if (result.offline && result.retryAfter !== null) console.log(`  server asks to retry online in ${result.retryAfter} s`);
console.log(`  plan:     ${result.license?.plan ?? 'n/a'}`);
console.log(`  features: ${result.license?.features.join(', ') || '(none)'}`);
if (result.isLifetime) {
  console.log('  expires:  never');
} else if (result.expiresAt) {
  console.log(`  expires:  ${result.expiresAt.toISOString()} (${result.daysRemaining()} days left)`);
}
if (result.leaseExpiresAt) console.log(`  offline until: ${result.leaseExpiresAt.toISOString()}`);

if (result.hasFeature('pro')) console.log('  -> Pro features enabled');

if (!result.offline) {
  const update = await client.checkUpdate(APP_VERSION);
  if (update.ok && update.update?.updateAvailable) {
    const info = update.update;
    console.log(`Update available: ${info.latestVersion}${info.mandatory ? ' (mandatory)' : ''}`);

    if (downloadDir) {
      const link = await client.getDownload(licenseKey, info.latestVersion);
      if (link.ok && link.download) {
        // Never use the server's file name as a path.
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
