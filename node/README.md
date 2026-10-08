# velsigil-client (Node.js)

Official Node.js SDK for **Velsigil**, the self-hosted license distribution and management platform.

- Every server response is **Ed25519-verified** against your product's public key before it is used.
- Replay protection: a fresh 32-byte nonce and a timestamp on every request, both bound into the signed response.
- **Device binding**: the device secret issued on first activation is stored and sent on every request.
- **Offline leases**: a signed, device-bound lease keeps your app working for a while when the server can't be reached.
- **Update and download flow**: the size and SHA-256 of every download are checked against the signed release info.
- Zero runtime dependencies. TypeScript types included. ESM and CommonJS. Node.js >= 22.

> Licensing code that runs on the customer's machine can always be patched. This SDK makes tampering
> harder and makes forged server responses impossible to accept, but **your server is the security
> boundary**. See [Hardening](#hardening).

---

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Result codes](#result-codes)
- [In-app free trials](#in-app-free-trials)
- [Offline leases](#offline-leases)
- [Device secret persistence](#device-secret-persistence)
- [Updates and downloads](#updates-and-downloads)
- [Clock skew](#clock-skew)
- [Concurrency and thread safety](#concurrency-and-thread-safety)
- [Hardening](#hardening)
- [Protocol notes and test vectors](#protocol-notes-and-test-vectors)
- [Development](#development)

---

## Installation

```bash
npm install velsigil-client
```

Requirements: Node.js 22 or newer (uses the built-in `fetch`, `AbortController` and `node:crypto` Ed25519). Releases are
tested on Node.js 22 and 24; Node.js 18 and 20 have reached their end of life and are not supported.

```js
// ES modules
import { VelsigilClient } from 'velsigil-client';
// CommonJS
const { VelsigilClient } = require('velsigil-client');
```

## Quick start

You need three values from **Master Panel → Products → your product → Integration**: the API URL,
the product id and the product's public key.

```ts
import { hostname } from 'node:os';
import { VelsigilClient, FileStore, defaultStoreDirectory } from 'velsigil-client';

// Embed these in your code. Never load the public key from a file or setting the user can change.
const API_URL = 'https://licenses.example.com';
const PRODUCT_ID = '0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b';
const PUBLIC_KEY = "<your product's public key>"; // base64, from Products → your product → Integration

const client = new VelsigilClient(API_URL, PRODUCT_ID, PUBLIC_KEY, {
  store: new FileStore(defaultStoreDirectory('MyApp')), // persists device secret + offline lease
});

const result = await client.validateWithOfflineFallback(licenseKey, {
  version: '1.2.0',
  deviceName: hostname(),
});

if (!result.ok) {
  // Business failures never throw: inspect result.code / result.message
  showLicenseError(result.code, result.message, result.requestId);
  process.exit(1);
}

if (result.hasFeature('pro')) enableProFeatures();
console.log(`Licensed (${result.license?.plan}), ${result.daysRemaining() ?? '∞'} days left`);
```

A runnable example lives in [`examples/basic.mjs`](https://github.com/VelSigil/velsigil-sdks/blob/main/node/examples/basic.mjs).
Like a real app, it keeps the API URL, product id and public key as constants in its code: set `API_URL`,
`PRODUCT_ID` and `PUBLIC_KEY` at the top of the file (until then it prints a usage message and exits with code 2),
then:

```bash
npm run build
VELSIGIL_LICENSE_KEY=... node examples/basic.mjs
```

For local testing only, `VELSIGIL_API_URL`, `VELSIGIL_PRODUCT_ID` and `VELSIGIL_PUBLIC_KEY` can replace the three
constants, but the example accepts them only when the API URL is a loopback URL (`localhost`, `127.0.0.1` or
`[::1]`), for example a local panel or mock server; with any other URL it refuses them and exits with code 2.
Leave this override out of a real application.

## Configuration

```ts
new VelsigilClient(apiUrl: string, productId: string, publicKeyBase64: string, options?: VelsigilClientOptions)
```

| Argument | Description |
|---|---|
| `apiUrl` | Your Velsigil server, e.g. `https://licenses.example.com`. The SDK appends `/api/client/v1`; a URL that already ends in `/api/client/v1` is accepted as is. **HTTPS is required**, except for `localhost`, `127.0.0.1` and `[::1]`. No credentials, query string or fragment. |
| `productId` | Product UUID. |
| `publicKeyBase64` | The product's Ed25519 public key (standard base64 of the raw 32 bytes, as shown in the panel). It is the **only** key the client trusts; the `kid` field of responses is never used to pick a key. The public test keys of the SDK test vectors are refused outside loopback hosts (see [Protocol notes](#protocol-notes-and-test-vectors)). |

| Option | Default | Description |
|---|---|---|
| `timeout` | `15000` | Request timeout in ms (connect + full response), 1 to 600 000. |
| `hwid` | `VelsigilClient.getHardwareId()` | Hardware id override (8-256 printable ASCII chars). It must be stable per device. |
| `store` | `new MemoryStore()` | Where the device secret and offline lease are kept. Use `FileStore` in real apps. |
| `allowInsecureHttp` | `false` | Allows plain `http://` to non-loopback hosts. For isolated test setups only. |
| `fetch` | global `fetch` | Custom fetch, e.g. one configured with a proxy dispatcher. |
| `clock` | `Date.now` | Millisecond clock. Useful for tests. |
| `onStoreError` | none | Called with the error if the store fails to load or save. The SDK keeps working from memory and never logs by itself. |
| `maxResponseBytes` | `1048576` | Larger responses are rejected as `invalid_response`. |

The constructor **throws** `VelsigilError` (with `code` set to `invalid_configuration`, `invalid_public_key` or
`hwid_unavailable`) for configuration mistakes. That is the only place the client throws (the
[low-level helpers](#low-level-helpers) throw for an invalid or published test key). Every network call resolves to a
result instead.

## API reference

### `VelsigilClient`

| Member | Description |
|---|---|
| `validate(licenseKey, { version?, deviceName? })` → `Promise<VelsigilResult>` | Validates the key on this device. The first successful call activates the device. Stores a newly issued device secret and the offline lease. `version` is up to 32 chars and `deviceName` up to 255. |
| `startTrial({ version?, deviceName?, email? })` → `Promise<VelsigilResult>` | Starts a free trial of the product on this device without a license key (see [In-app free trials](#in-app-free-trials)). On `ok`, `result.trialKey` is the new key: store it, then use `validate`. Stores the device secret and lease like `validate`. `email` (up to 254 chars) is sent only when given. Refuses locally with `already_licensed` (nothing sent, nothing changed) when a device secret or lease is already stored for the product. |
| `deactivate(licenseKey)` → `Promise<VelsigilResult>` | Removes this device from the license. When the server answers `ok` or `device_not_found`, the stored device secret and lease are cleared. |
| `checkUpdate(currentVersion?)` → `Promise<VelsigilResult>` | Latest published release, returned in `result.update`. The answer is `no_release` when nothing is published. No license key is needed. |
| `getDownload(licenseKey, version?)` → `Promise<VelsigilResult>` | A short-lived download link in `result.download`. The device must already be activated (`device_not_activated` otherwise). |
| `downloadRelease(download, destination, { idleTimeout?, signal?, onProgress? })` → `Promise<DownloadFileResult>` | Streams the file and verifies its signed size and SHA-256. The file appears at `destination` only after it passes both checks. |
| `validateOffline()` → `Promise<VelsigilResult>` | Validates the stored lease without contacting the server. Results have `offline: true`. |
| `validateWithOfflineFallback(licenseKey, opts?)` → `Promise<VelsigilResult>` | Validates online first. **Only** on `network_error` does it fall back to `validateOffline()`. If no lease is stored, the original `network_error` result is returned. |
| `clearStoredState()` → `Promise<void>` | Forgets the device secret and lease for this product, e.g. when the user switches license keys. |
| `static getHardwareId()` → `string` | This machine's hardware id (see [HWID](#hardware-id)). |
| `productId`, `hardwareId`, `clockOffset` | Read-only: the normalized product id, the hwid sent to the server, and the learned server-minus-local clock offset in seconds. |

### `VelsigilResult`

Immutable (frozen). Results of failed calls carry `ok === false`. Licensing outcomes never throw.

| Field / method | Type | Description |
|---|---|---|
| `ok` | `boolean` | `true` only for a verified, signed success or a valid offline lease. |
| `code` | `VelsigilCode` | `ok`, a server code, an unsigned HTTP error code, or an SDK code (see the [table](#result-codes)). |
| `message` | `string` | Server text for signed responses; fixed SDK text otherwise. Unsigned text from the network is never shown. |
| `type` | `'validate' \| 'deactivate' \| 'update_check' \| 'download' \| 'trial' \| null` | The request type. |
| `trialKey` | `string \| null` | The key of the trial `startTrial()` just started (`ok` results of `startTrial` only). Sent once: store it immediately. |
| `license` | `LicenseInfo \| null` | `{ id, plan, status, features, expiresAt, maxDevices, devicesUsed, createdAt, isTrial, trialRef }`. Times are unix seconds, and `expiresAt: null` means lifetime. Offline results set the counts and `createdAt` to `null`. On a failed result (`license_revoked`, `license_expired`, ...) `license.features` is informational only (servers since 2026-10-06 send it empty): gate features with `result.hasFeature()`, never with `license.features`. |
| `activation` | `ActivationInfo \| null` | `{ id, status, firstSeenAt, deviceSecretIssued }`. The secret itself is **never** exposed. |
| `lease` | `LeaseInfo \| null` | `{ token, expiresAt }` |
| `update` | `UpdateInfo \| null` | `{ latestVersion, minVersion, updateAvailable, mandatory, changelog }` |
| `download` | `DownloadInfo \| null` | `{ url (absolute), expiresAt, fileName, size, sha256, version }` |
| `requestId` | `string \| null` | Server request id. Quote it when contacting support. |
| `serverTime` | `number \| null` | Authoritative server time from a signed response. |
| `offline` | `boolean` | `true` when the result came from the stored lease. |
| `retryAfter` | `number \| null` | Seconds to wait, for `rate_limited`. |
| `hasFeature(name)` | `boolean` | `ok && license.features.includes(name)`. Always `false` for failures. |
| `expiresAt` | `Date \| null` | License expiry. |
| `isLifetime` | `boolean` | The license has no expiry date. |
| `isTrial` | `boolean` | A free-trial license (the optional signed `trial` field, online and offline). Use it with `daysRemaining()` for "Trial: N days left" and a "Buy now" link; a purchase with the same e-mail keeps the key and turns this `false` at the next online validation. |
| `trialRef` | `string \| null` | The trial's conversion reference (servers since 2026-10-06): set on online results for a free trial a purchase can still convert, also on `license_expired`; `null` otherwise and offline. Put it in your "Buy now" link with `result.withTrialRef(buyUrl)`: the purchase then converts THIS trial (same key) whatever e-mail address the buyer pays with. Opaque; never store it. |
| `withTrialRef(url)` | `string` | `url` with `velsigil_trial=<trialRef>` appended (a Stripe Payment Link gets `client_reference_id=`), or `url` unchanged without a reference. Also exported as `withTrialRef(url, ref)`. How your checkout passes it on: section 11.24 of `docs/OPERATIONS.md` in your Velsigil installation. |
| `leaseExpiresAt` | `Date \| null` | Offline lease expiry. |
| `secondsRemaining(nowMs?)`, `daysRemaining(nowMs?)` | `number \| null` | Time left (never negative), or `null` for lifetime licenses. `secondsRemaining` defaults to the local clock. `daysRemaining` rounds **up** and, without `nowMs`, measures at the result's own time (the signed `serverTime` online, the time of the check offline): an N-day trial shows N right after `startTrial`, 1 on its last day and 0 once expired. The same rule in every Velsigil SDK. |
| `isExpired(nowMs?)`, `expiresWithin(days, nowMs?)` | `boolean` | Expiry checks for UI warnings. |

### Stores

```ts
interface VelsigilStore {
  load(productId: string): StoredState | null | Promise<StoredState | null>;
  save(productId: string, state: StoredState): void | Promise<void>;
  clear(productId: string): void | Promise<void>;
}
interface StoredState { deviceSecret: string | null; lease: { token: string; expiresAt: number } | null }
```

- `MemoryStore`: the default; state is lost when the process exits.
- `FileStore(directory)`: one `velsigil-<productId>.json` per product. Writes are atomic (exclusive temp file with mode 0600, fsync, then rename). The directory is created with mode 0700. Writes from one instance are serialized.
- `defaultStoreDirectory(appName)`: a per-user location. Windows: `%LOCALAPPDATA%\<app>\velsigil`. macOS: `~/Library/Application Support/<app>/velsigil`. Linux: `$XDG_DATA_HOME/<app>/velsigil` (default `~/.local/share/...`).
- Upgrading from an SDK released under the former product name (Veltrix): when `velsigil-<productId>.json` does not exist yet, `FileStore` reads `veltrix-<productId>.json` from the same directory or, for the default directory, from `<app>/veltrix`. The next save writes the new file, and `clear` removes both. Installed apps keep their device secret and offline lease.

You can implement `VelsigilStore` on top of the OS keychain or your own encrypted config. Stores never
receive license keys.

### Low-level helpers

`verifyEnvelope`, `verifyLease` and `parsePublicKey` take the product's public key (`verifyEnvelope` and
`verifyLease` accept the base64 string or an imported `KeyObject`) and throw `VelsigilError('invalid_public_key')`
for an invalid one. They also refuse the two public test keys of the SDK test vectors (`keys.publicKey` and
`keys.wrongPublicKey` in `test-vectors.json`, in any base64 form or as a `KeyObject`), whose private keys are
published, with the same error and message as the `VelsigilClient` constructor. Unlike the constructor they have
no API URL, so there is no loopback exception: they refuse these keys always, before anything is verified.

| Export | Description |
|---|---|
| `verifyEnvelope(publicKey, envelope, { nonce, productId, type, hwid? })` | Returns `{ status: 'valid', payload }` or one of `invalid_signature`, `nonce_mismatch`, `product_mismatch`, `type_mismatch`, `hwid_mismatch`, `malformed`. `type` is required: pass the endpoint the request went to (`validate`, `deactivate`, `update_check`, `download` or `trial`), because the server also signs `ok: true` answers to `update_check`, which needs no license. A missing or unknown `type` throws `VelsigilError('invalid_argument')`. With `hwid` (the hwid the request was sent with), a signed lease or `activation.hwidHash` bound to another device is `hwid_mismatch`. Throws `VelsigilError('invalid_public_key')` for an invalid key or a published test key. |
| `verifyLease(publicKey, token, { productId, hwid, now })` | Returns `valid`, `expired`, `invalid_signature`, `product_mismatch`, `hwid_mismatch` or `malformed`. Throws `VelsigilError('invalid_public_key')` for an invalid key or a published test key. |
| `getHardwareId()`, `hwidFromMachineId(raw)`, `HWID_PREFIX` | Hardware id derivation. |
| `parsePublicKey(base64)` | Imports and validates an Ed25519 public key (throws `VelsigilError('invalid_public_key')` for an invalid key or a published test key). |
| `VelsigilError` | Configuration error with `code`. |
| `SERVER_CODES`, `UNSIGNED_ERROR_CODES`, `SDK_CODES`, `LEASE_REVOKING_CODES` | Code lists. |

### Hardware id

`hwid = lowercase hex SHA-256("vx-hwid-v1:" + machineId.trim().toLowerCase())`. The machine id comes from:

| OS | Source |
|---|---|
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (64-bit registry view, `reg.exe query ... /reg:64`, no shell) |
| Linux | `/etc/machine-id`, then `/var/lib/dbus/machine-id` (a file that is empty or holds systemd's placeholder `uninitialized` is skipped) |
| macOS | `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice` |

The value is cached per process. Every Velsigil SDK derives the same hwid on the same machine. HWIDs can
be spoofed and are not a security boundary; the device secret is what binds a device.

## Result codes

**Signed server codes.** These are authentic; `message` comes from the server.

| Code | Meaning / suggested handling |
|---|---|
| `ok` | Success. |
| `invalid_key` | Unknown key for this product. Ask the user to re-enter it. |
| `license_expired` | Expired. Offer renewal. |
| `license_suspended` | Temporarily suspended by the seller. |
| `license_revoked` / `license_banned` | Permanently invalid. |
| `device_limit_reached` | All device slots are used. The user can free one (customer portal or `deactivate` on another device). |
| `device_revoked` | The seller revoked this device. |
| `device_verification_failed` | The device secret didn't match and the product enforces strict binding. The device must be reset in the portal or panel. |
| `device_not_found` | (`deactivate`) This device isn't registered. |
| `device_not_activated` | (`getDownload`) Call `validate` first. |
| `activation_rate_limited` / `activation_cooldown` | Too many new activations. Try later. |
| `activations_disabled` / `downloads_disabled` | Temporarily switched off by the seller. |
| `blacklisted` | Device, network or customer is blocked. |
| `outdated_version` | This version is below the product minimum; see `result.update`. |
| `product_paused` / `product_disabled` | Maintenance or discontinued; show `message`. |
| `clock_skew` | The local clock is still off after the automatic retry. |
| `replay_detected` | The nonce was already used. This should never happen and may indicate interception. |
| `no_release` / `release_not_found` | (`checkUpdate` / `getDownload`) Nothing to download. |
| `trial_already_used` | This device already used a free trial of the product. Offer to buy; the stored lease (if any) is kept. |
| `trial_unavailable` | (`startTrial`) The seller offers no in-app trial right now (switched off, today's limit, too many trials from this network). Show `message`. |
| `trial_email_required` / `trial_email_invalid` / `trial_email_not_accepted` | (`startTrial`) The offer confirms an e-mail address first: ask for one, a valid one, or a personal / work address (throwaway domains are refused). |
| `trial_confirmation_sent` | (`startTrial`) Not an error of the user: a confirmation link was e-mailed; the key arrives by e-mail and is entered like any key. The same answer for every valid address. |

**Unsigned HTTP errors.** These can never produce `ok === true`, even if the body looks like a signed success.

| Code | HTTP | Meaning |
|---|---|---|
| `validation_error` | 400 | The request was rejected as malformed. The SDK also returns this locally, without a request, for an empty or too-long key, version or device name. |
| `ip_blocked` | 403 | Your network is (temporarily) blocked. |
| `unknown_product` | 404 | Wrong product id or server. |
| `payload_too_large` / `unsupported_media_type` | 413 / 415 | Should not occur with this SDK (also mapped from a bodiless 413/415, e.g. from a proxy). |
| `rate_limited` | 429 | Too many requests; see `result.retryAfter`. |
| `internal_error` | 5xx | Server error (also 502/503/504 **with** a Velsigil error body). |

The unsigned-error mapping is identical in every Velsigil SDK: a known code in a Velsigil error body
(`{ "error": { "code": … } }`) wins; otherwise 400 → `validation_error`, 413 → `payload_too_large`,
415 → `unsupported_media_type`, 429 → `rate_limited`, 502/503/504 → `network_error` without a Velsigil error
body (a reverse proxy in front of an unreachable server, so the offline fallback applies) or
`internal_error` with one, other 5xx → `internal_error`, anything else (3xx, 401, …) → `invalid_response`.

**SDK codes** (the same names in every Velsigil SDK, SPEC section 14).

| Code | Meaning |
|---|---|
| `network_error` | DNS, TCP or TLS failure, connection reset, timeout, or a 502/503/504 gateway error without a Velsigil error body. This is the only code that triggers the offline fallback. |
| `invalid_response` | Bad or missing signature, wrong key, nonce or product mismatch, wrong response `type` for the endpoint, a signed lease or `activation.hwidHash` that belongs to another device (the request was rewritten in transit; nothing from the response is stored), malformed or oversized body, a redirect, an insecure download URL, or an unexpected HTTP status. |
| `validation_error` | Local argument check failed; nothing was sent. |
| `invalid_configuration` | `code` of the `VelsigilError` thrown by the constructor. |
| `no_lease` | (`validateOffline`) No lease is stored. |
| `lease_expired` | (`validateOffline`) The stored lease expired. Connect to the internet. |
| `lease_invalid` | (`validateOffline`) The stored lease failed verification (tampered, other product or device). It is deleted. |
| `download_failed` | (`downloadRelease`) Non-200 status (an expired link answers 410: request a new one) or a download URL rejected by the HTTPS policy. |
| `integrity_mismatch` | (`downloadRelease`) Size or SHA-256 differs from the signed values; the partial file is deleted. |
| `io_error` | (`downloadRelease`) The destination could not be written. |
| `panel_too_old` | (`startTrial`) The Velsigil server has no in-app trial endpoint yet (HTTP 404 with the Velsigil error code `not_found`). The seller must update the panel. |
| `already_licensed` | (`startTrial`) This device already holds a license for the product (a device secret or offline lease is stored), and a trial must not replace it. Nothing was sent and the stored state is unchanged. Validate the saved key instead, or call `deactivate(key)` / `clearStoredState()` first. |
| `store_unavailable` | (`startTrial`) The store could not be read (for example a locked file or keyring), so the SDK cannot tell whether this device already holds a license. Nothing was sent; try again later. |

`downloadRelease` returns `DownloadFileResult { ok, code, message, path, bytes, sha256 }`. Its `code`
is one of `ok`, `network_error`, `download_failed`, `integrity_mismatch`, `io_error` or
`validation_error` (download info not taken from `getDownload`, or no destination).

## In-app free trials

When the seller turns on **In your app** in the product's trial offer (panel → Products → your product →
Trials), an app that has no license key yet can start a free trial for its device:

```ts
const savedKey = loadSavedLicenseKey(); // your own settings storage
if (savedKey === null) {
  const trial = await client.startTrial({ version: '1.2.0', deviceName: hostname() });
  if (trial.ok && trial.trialKey) {
    saveLicenseKey(trial.trialKey); // FIRST: the server can never send this key again
    showTrialBanner(trial.daysRemaining()); // trial.isTrial === true
  } else if (trial.code === 'trial_email_required') {
    // The offer confirms an e-mail address first: ask for it and call startTrial({ email }) again.
  } else {
    showMessage(trial.message); // trial_confirmation_sent, trial_already_used, trial_unavailable, panel_too_old, ...
  }
}
```

- **One trial per device and product.** A device that already had a trial of the product (from the app, the
  seller's website or the customer portal) gets `trial_already_used`; offer to buy.
- **The trial key is an ordinary license key** on the seller's trial plan. Store it like a key the user typed and
  use `validate()` from then on. Show it in your About / License screen: the customer needs it for the customer
  portal, to move the trial to another device and for support. A purchase converts the same key (the seller's staff,
  or a purchase with the e-mail address the trial was confirmed with).
- **E-mail confirmation (optional, the seller's choice).** Then the first answer is `trial_confirmation_sent`; the
  customer confirms the address from the e-mail, gets the key on the confirmation page and by e-mail, and enters it in
  the app (`validate`).
- The SDK stores the trial's device secret and offline lease like after a validation, never the key.
- **Never over an existing license.** When a device secret or an offline lease is already stored for the product
  (the device was activated with a key, paid or trial), `startTrial` returns `already_licensed` without sending
  anything and leaves the stored state as it is, so a trial can never replace the device secret and lease of a paid
  license. Validate the saved key instead; to really start over, call `deactivate(key)` (or `clearStoredState()` when
  the key is gone) first. When the store cannot be read, `startTrial` returns `store_unavailable` and sends nothing:
  a failed read is never taken for "nothing stored".
- The server limits trials per network, per device and per day, and HWIDs are asserted by the client: a user who
  changes the machine id can start another trial within those limits. Treat a trial as a marketing tool, not a
  security boundary.
- `panel_too_old`: the seller's Velsigil server predates in-app trials; nothing else is affected.

## Offline leases

When the product's `offlineLeaseHours` is greater than 0, a successful `validate` (or `startTrial`) returns a lease token:
`base64url(JSON) "." base64url(Ed25519 signature)`. Its payload is
`{ v, typ: 'lease', productId, licenseId, activationId, hwidHash, plan, features, licenseExpiresAt, iat, exp }`,
plus `trial: true` for a free-trial license (left out otherwise). Fields the SDK does not know are ignored.

- The SDK verifies the token (signature, product, `hwidHash = sha256(hwid)`) before storing it. A `validate` answer whose lease is bound to another device or product is rejected as a whole (`invalid_response`), not silently accepted without the lease.
- `validateOffline()` accepts it only if the signature verifies with your public key, `typ` is `lease`, the productId matches, the hwid hash matches this device, and `now < exp`. Here `now` is the local clock plus the learned server offset. A lease never outlives the license (`licenseExpiresAt`).
- The stored lease is **replaced** on every successful validation and **deleted** when a success carries no lease (for example, the seller disabled offline use). It is also deleted on a signed definitive denial: `invalid_key`, `license_expired`, `license_suspended`, `license_revoked`, `license_banned`, `device_revoked`, `device_verification_failed`, `device_limit_reached`, `device_not_activated`, `device_not_found`, `blacklisted` or `product_disabled` (exported as `LEASE_REVOKING_CODES`; the same set in every Velsigil SDK). A successful `deactivate` (or `device_not_found`) clears the lease and the device secret. Other signed failures such as `product_paused`, `outdated_version` or `activation_rate_limited` keep the lease. A revoked license therefore stops working offline as soon as the app talks to the server once.
- `validateWithOfflineFallback` falls back **only** on `network_error`. Any server answer, including unsigned 4xx/5xx errors, is returned as is.
- **Limitation:** offline checks rely on the local clock. A user who sets the clock back can extend a lease. Keep `offlineLeaseHours` as short as your users can tolerate, and validate online whenever possible.

## Device secret persistence

On the first activation of a device the server issues a 32-byte **device secret**
(`payload.activation.deviceSecret`, sent only once). The SDK stores it in the configured `store`, keyed
by productId, and sends it as `deviceSecret` on every later `validate`, `deactivate` and `getDownload`
request. If the server sees the hwid without the matching secret, it records a security event. With
*strict device binding* it refuses the request (`device_verification_failed`) until the device is reset.

- Use a persistent store (`FileStore`). With `MemoryStore`, every process start loses the secret and appears to the server as a mismatch.
- The secret never appears on `VelsigilResult` (only `activation.deviceSecretIssued`), and the SDK never logs.
- If the store fails, the SDK keeps the secret in memory for the life of the client and reports the failure through `onStoreError`.
- Call `clearStoredState()` when the user switches to a different license key, or after a device reset in the portal.

## Updates and downloads

```ts
const update = await client.checkUpdate(APP_VERSION);
if (update.ok && update.update?.updateAvailable) {
  const link = await client.getDownload(licenseKey, update.update.latestVersion);
  if (link.ok && link.download) {
    // Use a safe local name, never the server file name as a path.
    const file = await client.downloadRelease(link.download, join(downloadsDir, 'update.zip'), {
      onProgress: (received, total) => render(received / total),
    });
    if (file.ok) installUpdate(file.path); // size + SHA-256 verified against the signed response
  }
}
```

`update.mandatory` (or `code === 'outdated_version'` from `validate`) means the user must update before
continuing. Download links are short-lived (`download.expiresAt`); request a new one if it expires.
Relative URLs are resolved against your API URL, and non-HTTPS links are refused.

## Clock skew

Each request carries `timestamp = local clock + learned offset` (unix seconds). If the server considers
it out of range, it answers with a **signed** `clock_skew` that includes `serverTime`. The SDK then learns
`offset = serverTime - localTime`, retries **once** with a new nonce and timestamp, and keeps the offset
for later requests (`client.clockOffset`). The offset is only learned from verified responses.

## Concurrency and thread safety

- A `VelsigilClient` is safe to use from concurrent async code. Device-bound calls (`validate`, `startTrial`, `deactivate`, `getDownload`, `validateOffline`, `clearStoredState`) are **serialized per client**, so a freshly issued device secret is persisted before the next request is sent, and the `already_licensed` check of `startTrial` and its request form one step. `checkUpdate` runs unserialized.
- When the store throws on a read (`onStoreError` is called), the SDK keeps working from the last state it read or wrote, but never treats the failed read as "nothing stored": `startTrial` refuses with `store_unavailable`, and an answer is merged into a fresh read of the store. While the store stays unreadable nothing is written except a device secret the server just issued.
- Use **one client per product per process** and share it.
- `worker_threads` do not share memory. Give each thread its own client and preferably let one thread own validation.
- Several **processes** sharing one `FileStore` directory never see torn files (atomic rename), but the last writer wins. Avoid validating the same license from several processes at the same moment on a device's first activation.
- `getHardwareId()` is synchronous (it may spawn `reg.exe` or `ioreg` once) and cached per process.

## Hardening

Client-side licensing is a deterrent, not a vault. Recommended practices:

1. **Keep the public key, product id and API URL in code.** Don't read them from a config file, environment variable or registry key the user controls. Otherwise an attacker can swap in their own key and run a fake server.
2. **Check results in multiple places.** Don't validate once at startup and set a single global flag. Re-check `result.ok` and `result.hasFeature(...)` where features are used, re-validate periodically, and treat non-`ok` results as unlicensed (fail closed).
3. **Server-side enforcement is authoritative.** Anything valuable (downloads, cloud features, content, updates) should be gated by your server, which sees revocations, device limits and abuse detection in real time. The SDK only reports what the server decided.
4. **Obfuscation and packaging help but are not a security boundary.** Bundling, minification, obfuscators or single-executable packaging raise the effort needed to patch your checks. They cannot prevent it, and JavaScript is easy to modify. Plan for that.
5. Use HTTPS (enforced by default). Never enable `allowInsecureHttp` in production.
6. Never log or display license keys or device secrets. The SDK has no logging, and stores never receive the license key. If your app remembers the key, protect it as you would a password (OS keychain or a per-user file).
7. Keep offline leases short and validate online when possible (see the clock limitation above).
8. If you embed the SDK in Electron, run it in the main process (not the renderer) and expose only the verdict.

## Protocol notes and test vectors

- Requests: `POST {apiUrl}/api/client/v1/{validate|deactivate|update-check|download}` with a JSON body. Every request carries `productId`, `nonce` (32 CSPRNG bytes, base64url, 43 chars, unique) and `timestamp` (unix seconds). No cookies. Redirects are not followed.
- Responses: `{ data, sig, kid }`. `sig` is an Ed25519 signature over the **exact ASCII bytes of `data`**. The SDK verifies it with the configured key **before** decoding `data`. It then checks that the payload's `nonce` and `productId` (and request type) match the request.
- base64url decoding tolerates missing padding and rejects any invalid character.
- The shared vectors in [`test-vectors.json`](https://github.com/VelSigil/velsigil-sdks/blob/main/test-vectors.json) (envelopes, leases, HWID examples) are classified exactly as specified by `test/vectors.test.ts`.
- The private keys of the vectors' two test key pairs are published in that file, so the `VelsigilClient` constructor refuses their public keys (`keys.publicKey`, `keys.wrongPublicKey`, compared as raw bytes in any base64 form) with `VelsigilError('invalid_public_key')` unless the API URL's host is `localhost`, `127.0.0.1` or `[::1]`. The low-level helpers `parsePublicKey`, `verifyEnvelope` and `verifyLease` have no API URL and refuse them always (see [Low-level helpers](#low-level-helpers)). The SDK's own vector tests verify the vectors through internal functions that are not exported from the package.

## Development

In the SDK repository ([VelSigil/velsigil-sdks](https://github.com/VelSigil/velsigil-sdks)), from this folder:

```bash
npm ci --ignore-scripts   # exact devDependencies from package-lock.json, no install scripts
npm run typecheck         # tsc --noEmit over src + tests
npm test                  # vitest: vectors, primitives, stores, client vs. a local signing mock server
npm run build             # dist/esm (ESM + .d.ts) and dist/cjs (CommonJS + .d.ts)
```

The test suite runs a local HTTP server that signs responses with the vector key
(`keys.privateSeedBase64`). It covers success, business failures, nonce and product mismatches, bad
signatures, tampered data, `clock_skew` with a single retry, device secret persistence and re-sending,
HTTP 400/403/404/429/500/502, redirects, oversized bodies, timeouts, refused and reset connections, and
offline fallback with a fake clock.

Before a release the dist build is also run against a **real** Velsigil server: activation,
device-secret persistence, offline lease, updates, verified download, clock skew, replay, suspension,
invalid key and deactivation.
## License

MIT
