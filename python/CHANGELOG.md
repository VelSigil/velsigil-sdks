# Changelog - Velsigil Python SDK (`velsigil-client`)

## 1.0.0 (unreleased)

### Packaging and distribution (2026-10-07)

- Published from the public repository [VelSigil/velsigil-sdks](https://github.com/VelSigil/velsigil-sdks)
  (`python` folder) through PyPI trusted publishing with PEP 740 attestations.
- `requires-python` is now `>=3.10` (was `>=3.8`); `cryptography>=50.0.0` (was `>=3.4`): the first release
  with no published advisory (the bundled OpenSSL of earlier wheels, and X.509 / PKCS#7 issues in 48.x and 49.x
  that this SDK does not use but would otherwise let an install pull in). The optional `nacl` extra needs
  `PyNaCl>=1.6.2` (libsodium Ed25519 input-validation fix).
- PEP 639 metadata: `license = "MIT"` with `license-files = ["LICENSE"]`; project URLs; the build backend is
  pinned (`setuptools==84.0.0`).

Nothing has been published yet, so the version stays 1.0.0. Changes made on 2026-10-06 that affect code
written against earlier source snapshots:

### Breaking (low-level API)

- `open_envelope(verifier, envelope, expected_nonce, expected_product_id, expected_type, expected_hwid=None)`
  now **requires** `expected_type`: the endpoint the request went to (`"validate"`, `"deactivate"`,
  `"update_check"` or `"download"`). The signed payload's `type` must match it, otherwise
  `EnvelopeError` with reason `type_mismatch` is raised. `None` or an empty value raises `ValueError`
  instead of silently skipping the check: the server also signs `ok: true` answers to update checks, which
  need no license, so without the check such an answer would pass as a validation (security review SDK-1).
- Migration: pass the type of the request you sent as the fifth argument (or `expected_type=...`); the
  hwid moved behind it (`expected_hwid=...`).

### Behaviour change: `LicenseInfo.has_feature`

- `result.license.has_feature(name)` is now `False` unless the result is `ok` (or a valid offline lease) and
  the license status is `active` or `pending` (final exploit check MONEY-V1). Before, it only looked at
  `license.features`, which a signed denial (`license_revoked`, `license_banned`, `license_suspended`,
  `license_expired`, ...) still listed, so code that gated features with it kept unlocking them after a
  refund or revocation. The server no longer lists features on a denial either. A `LicenseInfo` built by
  hand grants nothing. Gate features with `result.has_feature(name)` (unchanged).

### Added (free trials, SPEC 9.7)

- `result.is_trial` and `LicenseInfo.is_trial`: `True` for a free-trial license, read from the optional signed
  `trial` field of the response's `license` and of the offline lease (absent = `False`, so older servers and
  paid licenses are unaffected). A non-boolean `trial` is an `invalid_response` (a stored lease with one is
  `lease_invalid`).
- `Code.TRIAL_ALREADY_USED` (`trial_already_used`): this device already used a free trial of the product. A
  signed failure that keeps the stored lease. SDKs built before this change see it as an ordinary failure code.

### Added (in-app free trials, SPEC 9.7 "In-app trials")

- `client.start_trial(version=None, device_name=None, email=None)`: starts a free trial of the product on this
  device without a license key (`POST /api/client/v1/trial`; the seller turns on the in-app channel of the
  product's trial offer). On success `result.trial_key` is the new license key: store it right away (the server can
  never send it again; the SDK does not persist it; it is kept out of `repr`) and use `validate()` from then on.
  The device secret and the offline lease are stored like after a validation. `email` is sent only when given and
  read only by offers that confirm an address first.
- Codes `Code.TRIAL_UNAVAILABLE`, `TRIAL_EMAIL_REQUIRED`, `TRIAL_EMAIL_INVALID`, `TRIAL_EMAIL_NOT_ACCEPTED`,
  `TRIAL_CONFIRMATION_SENT` (the key arrives by e-mail) and, for this method, `TRIAL_ALREADY_USED`. None is
  lease-revoking.
- SDK code `Code.PANEL_TOO_OLD` (`panel_too_old`): `start_trial()` reached a Velsigil server without the endpoint
  (HTTP 404 with the error code `not_found`); the seller must update the panel. Other methods are unaffected.
- An `ok` answer of type `trial` without a well-formed `trial.key` is an `invalid_response`; a `trial` object on any
  other answer is ignored. `open_envelope` accepts `"trial"` as the expected type.

### Added (trial conversion reference, SPEC 9.7 "Conversion to paid")

- `result.trial_ref` and `LicenseInfo.trial_ref`: the opaque conversion reference the server signs into a free trial
  that a purchase can still convert (also on `license_expired`); `None` when absent, offline, and for paid licenses.
- `result.with_trial_ref(buy_url)` and `velsigil_client.with_trial_ref(url, ref)`, `TRIAL_REF_PARAM`: the "Buy now"
  link with `velsigil_trial=<ref>` (Stripe Payment Links: `client_reference_id=<ref>`).
- A `trialRef` that is not 1-200 characters of `[A-Za-z0-9_-]` makes the payload malformed (`invalid_response`). New
  vectors `validate_ok_trial_ref`, `license_expired_trial_ref`.

### Fixed (in-app trials never replace a stored license, review finding 7)

- `start_trial()` on a device that already holds a license for the product overwrote the stored device secret and
  offline lease (for example those of a paid license) with the trial's. It now refuses locally with the new SDK
  code `Code.ALREADY_LICENSED` (`already_licensed`) when a device secret or a lease is stored: no request is sent
  and the stored state is unchanged. Validate the saved key instead, or call `deactivate(key)` /
  `clear_stored_state()` first.

### Fixed (final bug sweep, 2026-10-07)

- A store read that failed counted as "nothing stored" (F-SDK-1): `start_trial()` passed its `already_licensed`
  guard, and when the store stayed unreadable an answer was saved over it, erasing the device secret. Now
  `start_trial()` refuses with the new SDK code `Code.STORE_UNAVAILABLE` (`store_unavailable`) and sends nothing, and
  an answer is merged into a fresh read of the store; while the store has never been readable nothing is written
  except a device secret the server just issued.
- `FileStore` locked per instance, so two instances on one path (for example one per product, both on
  `default_store_path()`) could lose each other's updates of the shared file (F-SDK-5). All `FileStore` objects on the
  same path now share one process-wide lock; the README documents the cross-process caveat.
- `result.days_remaining()` measured against the raw local clock and showed "15 days left" for a 14-day trial when the
  clock lagged the server (F-SDK-4). Without `now` it now measures at the result's own time (the signed `server_time`,
  or the new field `reference_time` of offline results: the time of the check); still rounded up. The cross-SDK rule
  is in CLIENT_PROTOCOL 5.2.
- The Linux machine id `uninitialized` (systemd's placeholder) was hashed like a real id; it is now skipped like an
  empty file, as in the Node SDK (F-SDK-3).

### Unchanged

- The `VelsigilClient` methods (`validate`, `deactivate`, `check_update`, `get_download`, ...) always passed
  the type themselves: no change for code that uses only the client.
