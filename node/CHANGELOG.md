# Changelog - Velsigil Node.js SDK (`velsigil-client`)

## 1.0.5 (2026-10-09)

### Changed

- Shorter code and doc comments. No behaviour change.

## 1.0.4 (2026-10-08)

### Added

- `result.retryAfter` is now set from the `Retry-After` header of **every** HTTP 429 or 503 answer, whatever code
  it maps to, not only for `rate_limited`: also the empty 503 with `Retry-After: 30` that a self-hosted server
  answers while its database is unreachable (`network_error`), a gateway's 503 (`network_error`), 503
  `service_busy` (`internal_error`) and an oversized 503 (`invalid_response`). Parsed as before (delta-seconds or
  HTTP date, whole seconds); `null` without the header and for every other status (500, 502, 504, …).
  `validateWithOfflineFallback` copies the failed online answer's value onto the result of its fallback (offline
  `ok`, `lease_expired`, `lease_invalid`), so an app running on its lease knows when to try online again;
  `validateOffline()` called directly leaves it `null`. Result codes and the fallback rule are unchanged. The same
  in every Velsigil SDK.

### Changed

- `retryAfter` is capped at one day (86400 seconds), as in the Python, C# and C++ SDKs: a longer delta or a later
  HTTP date reads as 86400. Before, Node.js returned delta-seconds of up to 9 digits unchanged and ignored longer ones.

## 1.0.3 (2026-10-08)

### Fixed

- `validateWithOfflineFallback` now also falls back to the stored offline lease when the license server is
  **unavailable** but still answers HTTP: any unsigned HTTP 5xx (500-599), whatever its body (a Velsigil error body,
  a gateway's HTML page, an empty, non-JSON or oversized body). Until now only `network_error` fell back, so while a
  self-hosted panel was up with its database down (500 `internal_error`, 503 `service_busy`), apps with a valid
  lease stopped working. 502/503/504 without a Velsigil error body already fell back (`network_error`). Signed
  answers, 4xx (`rate_limited`, `validation_error`, …), redirects and `invalid_response` stay final.
  **Behaviour change to check in your app:** for an unsigned 5xx that did not fall back before, the method used to
  return the online error (`internal_error`, or `invalid_response` for an oversized 5xx body); with a stored lease it
  now returns an offline result (`offline: true`): `ok`, or `lease_expired` / `lease_invalid` when the stored lease
  cannot be used, so code that handled `internal_error` from it must handle these codes too. Without any stored
  lease it still returns the original online result (`internal_error`, `network_error`, …). Plain `validate()` and
  the result codes are unchanged; no new code.

## 1.0.2 (2026-10-08)

### Security

- The `VelsigilClient` constructor now refuses the two public test keys of the SDK test vectors
  (`keys.publicKey` and `keys.wrongPublicKey` in `test-vectors.json`), whose private keys are published, so
  anyone could forge license answers for an app that trusts them. It throws `VelsigilError` with code
  `invalid_public_key` (the same error as a malformed key) unless the API URL's host is `localhost`,
  `127.0.0.1` or `[::1]` (the hosts for which plain HTTP is allowed; one helper decides both). Keys are compared
  as raw 32 bytes, so no other base64 encoding of them is accepted.
- The README quick start no longer shows the test key: it uses the placeholder `"<your product's public key>"`.
- The public low-level helpers `parsePublicKey`, `verifyEnvelope` and `verifyLease` now refuse the same two test
  keys always (they have no API URL, so there is no loopback exception), as a base64 string in any form or as an
  imported `KeyObject`. They throw what they already threw for an invalid key, `VelsigilError` with code
  `invalid_public_key`, with the same message as the constructor, before anything is verified. Code that passed a
  test key to these helpers must use the product's own key. The client itself and the SDK's own vector tests
  use internal functions, not exported from the package, that accept the test keys; there is no public opt-out.
- The example (`examples/basic.mjs`) no longer reads the API URL, product id and public key from the environment:
  they are constants in the code with placeholders (`API_URL`, `PRODUCT_ID`, `PUBLIC_KEY`), and while a
  placeholder is still in place the example prints a usage message and exits with code 2. For local testing,
  `VELSIGIL_API_URL`, `VELSIGIL_PRODUCT_ID` and `VELSIGIL_PUBLIC_KEY` replace them only when the API URL is a
  loopback URL (`localhost`, `127.0.0.1`, `[::1]`); with any other URL the example refuses them (exit code 2).
  `VELSIGIL_ALLOW_INSECURE_HTTP` is gone (plain HTTP is allowed for loopback hosts anyway). The license key still
  comes from `VELSIGIL_LICENSE_KEY`.

## 1.0.1 (2026-10-08)

No code changes from 1.0.0. The release workflow of 1.0.0 published only the C++ source release on GitHub: its
nuget.org upload signed in with the organization's name instead of the user who created the trusted-publishing
policy, and its npm upload was not matched by the trusted publisher. 1.0.1 releases all four SDKs together again.

- First stable version on npm (`latest`). 1.0.0 was never published to npm; the earlier `1.0.0-rc.0` release
  candidate is deprecated in favour of this version.

## 1.0.0 (2026-10-08)

### Packaging and distribution (2026-10-07)

- Published from the public repository [VelSigil/velsigil-sdks](https://github.com/VelSigil/velsigil-sdks)
  (`node` folder) through npm trusted publishing: staged, approved with 2FA, with npm provenance.
- `engines.node` is now `>=22` (was `>=18`): Node.js 18 and 20 are past their end of life, and the test
  toolchain needs 22.12+. The runtime code itself is unchanged.
- The package ships `LICENSE` (MIT); `repository`, `homepage`, `bugs` and `publishConfig` (public access,
  provenance) are set. A standalone `package-lock.json` pins the dev toolchain for `npm ci`.

Changes made on 2026-10-06, before the first release (so the version stays 1.0.0; the release candidate
`1.0.0-rc.0` published to npm on 2026-10-07 already contains them), that affect code written against earlier
source snapshots:

### Breaking (low-level API)

- `verifyEnvelope(publicKey, envelope, expected)` now **requires** `expected.type`: the endpoint the
  request went to (`'validate'`, `'deactivate'`, `'update_check'` or `'download'`). The signed payload's
  `type` must match it, otherwise the result is `type_mismatch`. A missing or unknown `type` throws
  `VelsigilError('invalid_argument')` instead of silently skipping the check: the server also signs
  `ok: true` answers to update checks, which need no license, so without the check such an answer would
  pass as a validation (security review SDK-1).
- Migration: pass the type of the request you sent, e.g.
  `verifyEnvelope(key, envelope, { nonce, productId, type: 'validate', hwid })`.

### Added (free trials, SPEC 9.7)

- `result.isTrial` and `license.isTrial`: true for a free-trial license. Read from the optional signed
  `trial` field of the response's `license` and of the offline lease (absent = not a trial, so older servers
  and paid licenses give `false`). A non-boolean `trial` value is an `invalid_response`.
- Result code `trial_already_used`: this device already used a free trial of the product (signed failure,
  `ok: false`; the stored lease is kept). SDKs built before this change see it as an ordinary failure code.
- `ProtocolLicense.trial?` and `LeasePayload.trial?` in the low-level types.

### Added (in-app free trials, SPEC 9.7 "In-app trials")

- `client.startTrial({ version?, deviceName?, email? })`: starts a free trial of the product on this device
  without a license key (`POST /api/client/v1/trial`; the seller turns on the in-app channel of the product's
  trial offer). On success `result.trialKey` is the new license key: store it right away (the server can never
  send it again; the SDK does not persist it) and use it with `validate()` from then on. The device secret and
  the offline lease are stored like after a validation. `email` is sent only when given and read only by offers
  that confirm an address first.
- Result codes: `trial_unavailable`, `trial_email_required`, `trial_email_invalid`, `trial_email_not_accepted`,
  `trial_confirmation_sent` (the key arrives by e-mail) and, for this method, `trial_already_used`. None is
  lease-revoking.
- SDK code `panel_too_old`: `startTrial()` reached a Velsigil server without the endpoint (HTTP 404 with the error
  code `not_found`); the seller must update the panel. Other methods are unaffected.
- Low-level: request type `'trial'` (`verifyEnvelope` accepts it; a trial answer verified as `validate`, or the other
  way round, is `type_mismatch`), `ResponsePayload.trial?` / `ProtocolTrial` (present only on an `ok` answer of
  type `trial`, which must carry a well-formed key: otherwise `malformed`), `result.trialKey`, `StartTrialOptions`.

### Added (trial conversion reference, SPEC 9.7 "Conversion to paid")

- `result.trialRef` and `license.trialRef`: the opaque conversion reference the server signs into a free trial that a
  purchase can still convert (also on `license_expired`); `null` when absent, offline, and for paid licenses.
- `result.withTrialRef(buyUrl)` and the exported `withTrialRef(url, ref)`, `TRIAL_REF_PARAM`: the "Buy now" link with
  `velsigil_trial=<ref>` (Stripe Payment Links: `client_reference_id=<ref>`); a purchase through it converts that trial.
- Low-level: `ProtocolLicense.trialRef?`; a value that is not 1-200 characters of `[A-Za-z0-9_-]` makes the payload
  malformed (`invalid_response`). New vectors `validate_ok_trial_ref`, `license_expired_trial_ref`.

### Fixed (in-app trials never replace a stored license, review finding 7)

- `startTrial()` on a device that already holds a license for the product overwrote the stored device secret and
  offline lease (for example those of a paid license) with the trial's. It now refuses locally with the new SDK
  code `already_licensed` (in `SDK_CODES`) when a device secret or a lease is stored: no request is sent and the
  stored state is unchanged. Validate the saved key instead, or call `deactivate(key)` / `clearStoredState()` first.

### Fixed (final bug sweep, 2026-10-07)

- A store read that failed (for example `EBUSY`/`EPERM` on a locked file) counted as "nothing stored" (F-SDK-1).
  `validate` then saved the answer over the stored state and erased the device secret, and `startTrial` passed its
  `already_licensed` guard. Now `startTrial` refuses with the new SDK code `store_unavailable` (in `SDK_CODES`) and
  sends nothing, and an answer is merged into a fresh read of the store; while the store stays unreadable nothing is
  written except a device secret the server just issued.
- `result.daysRemaining()` rounded down against the local clock, so a 14-day trial showed "13 days left" right after
  `startTrial` (F-SDK-4). It now follows the cross-SDK rule of CLIENT_PROTOCOL 5.2: rounded **up**, measured by default
  at the result's own time (the signed `serverTime`, or the time of the offline check). `daysRemaining(nowMs)` with
  an explicit time still uses that time; `secondsRemaining`, `isExpired` and `expiresWithin` are unchanged.
  `ResultInit.referenceTime` (optional) carries the time of an offline result.
- The Linux machine id placeholder `uninitialized` is now skipped in any letter case (F-SDK-3, the rule every SDK
  follows now).

### Unchanged

- The `VelsigilClient` methods (`validate`, `deactivate`, `checkUpdate`, `getDownload`, ...) always passed
  the type themselves: no change for code that uses only the client.
- Feature gating: `result.hasFeature(name)` was already false for every failed result. Servers since
  2026-10-06 send `license.features: []` on a denial (final exploit check MONEY-V1); never gate features
  with `result.license.features`.
