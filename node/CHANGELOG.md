# Changelog - Velsigil Node.js SDK (`velsigil-client`)

## 1.0.0 (unreleased)

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
