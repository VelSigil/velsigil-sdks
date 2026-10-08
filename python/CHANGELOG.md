# Changelog - Velsigil Python SDK (`velsigil-client`)

## 1.0.3 (2026-10-08)

### Fixed

- `validate_with_offline_fallback()` now also uses the stored offline lease when the license server is up but
  cannot serve: on **any unsigned HTTP 5xx answer**, whatever its body (a Velsigil `internal_error` while the
  server's database is down, a 503 `service_busy`, a proxy's HTML error page, an empty, garbled or oversized
  body). Before, only `network_error` (no answer, or a 502/503/504 without a Velsigil error body) fell back, so
  an app whose seller's server answered 500 `internal_error` stopped working although it held a valid lease.
  Still final, never falling back: every signed answer (`license_revoked`, `license_expired`, ...), unsigned
  4xx answers (`rate_limited`, `validation_error`, `ip_blocked`, `unknown_product`, ...), redirects and
  `invalid_response` on an HTTP 200 (bad signature, mismatches, unsigned success). Without any stored lease the
  original failure is returned, as for `network_error` (same `code` and `http_status`); for an unusable stored
  lease see the next entry. `validate()` is unchanged and reports the real error; no new result code. An
  oversized response body now keeps its `http_status` on the `invalid_response` result.
- `validate_with_offline_fallback()`: when it falls back (server unavailable) and the stored lease cannot be used,
  it now returns `validate_offline()`'s result, `lease_expired` or `lease_invalid` with `offline=True` (the stored
  lease kept or removed exactly as by `validate_offline()`; an expired one is kept), instead of the original
  `network_error` / `internal_error` with the lease status appended to its message. Only when no lease is stored
  at all is the original online result returned, now unchanged (its message no longer names `no_lease`). This is
  the cross-SDK rule (CLIENT_PROTOCOL section 9), as in the Node and C# SDKs. `validate()` is unchanged.

## 1.0.2 (2026-10-08)

### Security

- `VelsigilClient` now refuses the two public keys of the shared SDK test vectors (`keys.publicKey` and
  `keys.wrongPublicKey` in `test-vectors.json`, whose private keys are published there, so anyone could forge
  license answers for an app that trusts them) unless `api_url` is a loopback host (`localhost`, `127.0.0.1`,
  `::1`: the hosts that may use plain HTTP). The decoded 32 key bytes are compared, so another spelling of the same
  key (no padding, surrounding whitespace, non-zero unused bits in the last base64 character) is refused too. The constructor raises `ConfigurationError` (code
  `invalid_configuration`), as for an invalid public key. The README, the package docstring and
  `examples/basic.py` now show the placeholder `"<your product's public key>"` instead of the test key; the example
  exits with a usage message until a key is set.
- The public low-level helpers refuse the same two keys too, on every host: they have no server URL, so they
  make no loopback exception. `Ed25519Verifier`, `key_id_for` and `velsigil_client.crypto.decode_public_key`
  refuse the key itself (compared as decoded bytes, so in any accepted spelling); `open_envelope` and
  `verify_lease` refuse a verifier that holds it, before checking anything else. Each raises
  `ConfigurationError` (code `invalid_configuration`), the error it raises for an invalid key, with the
  constructor's message. There is no opt-out argument: `VelsigilClient` (for a loopback `api_url`) and the SDK's
  own test-vector suite use internal, unguarded equivalents. Code that verified with a test key through these
  helpers must use its product's own public key.
- `examples/basic.py`: `API_URL`, `PRODUCT_ID` and `PUBLIC_KEY` are now constants in code with clear placeholders
  (`<your Velsigil server URL>`, `<your product id>`, `<your product's public key>`) instead of values read from
  the environment; while any placeholder is still in place the example prints a usage message and exits with
  code 2. For local testing only, `VELSIGIL_API_URL`, `VELSIGIL_PRODUCT_ID` and `VELSIGIL_PUBLIC_KEY` still
  override them, but only when the API URL is loopback (`localhost`, `127.0.0.1`, `[::1]`); for any other server
  they are ignored, with a note on stderr. `VELSIGIL_ALLOW_INSECURE_HTTP` was removed: loopback hosts may use
  plain HTTP anyway.

## 1.0.1 (2026-10-08)

No code changes from 1.0.0. The release workflow of 1.0.0 published only the C++ source release on GitHub: its
nuget.org upload signed in with the organization's name instead of the user who created the trusted-publishing
policy, and its npm upload was not matched by the trusted publisher. 1.0.1 releases all four SDKs together again.

- First version on PyPI (published once PyPI has approved the project). 1.0.0 was not uploaded to PyPI.

## 1.0.0 (2026-10-08)

### Packaging and distribution (2026-10-07)

- Published from the public repository [VelSigil/velsigil-sdks](https://github.com/VelSigil/velsigil-sdks)
  (`python` folder) through PyPI trusted publishing with PEP 740 attestations.
- `requires-python` is now `>=3.10` (was `>=3.8`); `cryptography>=50.0.0` (was `>=3.4`): the first release
  with no published advisory (the bundled OpenSSL of earlier wheels, and X.509 / PKCS#7 issues in 48.x and 49.x
  that this SDK does not use but would otherwise let an install pull in). The optional `nacl` extra needs
  `PyNaCl>=1.6.2` (libsodium Ed25519 input-validation fix).
- PEP 639 metadata: `license = "MIT"` with `license-files = ["LICENSE"]`; project URLs; the build backend is
  pinned (`setuptools==84.0.0`).

Changes made on 2026-10-06, before the first release (so the version stays 1.0.0), that affect code
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
