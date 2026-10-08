# Changelog - Velsigil C++ SDK (`velsigil`)

## 1.0.2 (2026-10-08)

### Security

- The `Client` constructor refuses the two public keys of the shared SDK test vectors (`keys.publicKey` and
  `keys.wrongPublicKey` of `test-vectors.json`), whose private keys are published, so anyone could forge license
  answers for an application that trusts them. The decoded key bytes are compared, so no other base64 encoding of
  them slips through. The refusal takes the path of an invalid public key: `is_configured()` is false,
  `configuration_error()` explains it and every call returns `invalid_configuration`. They stay accepted when the
  API URL's host is `localhost`, `127.0.0.1` or `[::1]` (a local test server; the hosts that may also use plain
  `http://`, decided by the same helper). `allow_insecure_http` does not extend this: a test key with any other
  host (a LAN dev server such as `http://192.168.x.x` included) is refused. The low-level helpers refuse them
  always (see below).
- The README quick start and `examples/basic.cpp` now use the placeholder `<your product's public key>` instead of
  the test key; the example prints a usage message and exits until it is set. An application that copied the old
  value must switch to its product's public key (panel: Products > your product > Integration).
- The public low-level helpers `verify_envelope_typed` and `verify_lease`, and the opt-in type-less
  `verify_envelope` overloads (`VELSIGIL_ALLOW_UNTYPED_ENVELOPE`), refuse the same two test-vector keys, in any
  base64 spelling, **always**: unlike the `Client` they have no API URL that could show a local test server. The
  refusal takes the path of an invalid public key: status `invalid_signature`, no payload, no claims (these
  helpers return a status, not a message). A custom integration that verified answers or leases with a test key
  must use its product's public key. There is no public opt-out: the SDK's own tests verify the shared vectors
  through internal entry points (`src/detail.hpp`, not installed and not part of the API).
- `examples/basic.cpp`: the API URL and the product id are compiled-in placeholders now too
  (`<your Velsigil server URL, e.g. https://licenses.example.com>`, `<your product id>`; the product id was the
  mock server's). While any placeholder is in place it prints a short usage message and exits with code 2. Values
  on the command line (the API URL, optionally followed by a product id and a public key) are for local testing
  only and are accepted only with a `localhost`, `127.0.0.1` or `[::1]` API URL; any other URL is refused with
  exit code 2 (before, any API URL was accepted there). The example reads none of these values from the
  environment.

## 1.0.1 (2026-10-08)

No code changes from 1.0.0. The release workflow of 1.0.0 published only the C++ source release on GitHub: its
nuget.org upload signed in with the organization's name instead of the user who created the trusted-publishing
policy, and its npm upload was not matched by the trusted publisher. 1.0.1 releases all four SDKs together again.

- Same sources as 1.0.0, which stays available as its own GitHub release; released again so that all four SDKs
  share one version.

## 1.0.0 (2026-10-08)

### Packaging and distribution (2026-10-07)

- Released as an immutable GitHub release of [VelSigil/velsigil-sdks](https://github.com/VelSigil/velsigil-sdks):
  `velsigil-cpp-<version>.tar.gz` (the `cpp` folder plus `test-vectors.json`), `SHA256SUMS`, a CycloneDX SBOM
  and a build-provenance attestation.
- `vcpkg.json`: `builtin-baseline` (vcpkg release 2026.07.29), `license`, `homepage`, `libsodium >= 1.0.21`.
- CMake: `VX_TEST_VECTORS` defaults to a `test-vectors.json` next to `CMakeLists.txt` (release tarball) before
  `../test-vectors.json`; `cmake --install` also installs `LICENSE`, `README.md` and `CHANGELOG.md` to the doc
  directory. `tests/package_consumer` checks `find_package` and `FetchContent` consumption in CI.

Changes made on 2026-10-06, before the first release (so the version stays 1.0.0), that affect code
written against earlier source snapshots:

### Breaking (low-level API)

- New: `verify_envelope_typed(envelope_json, public_key_base64, expected_nonce, expected_product_id,
  expected_type, expected_hwid)`. `expected_type` is the endpoint the request went to (`"validate"`,
  `"deactivate"`, `"update_check"` or `"download"`); a payload of another type yields `type_mismatch`, an
  empty `expected_type` never matches. Exactly one signature, no default arguments (security review SDK-1).
- **Removed:** the type-less overloads `verify_envelope(envelope_json, public_key_base64, expected_nonce,
  expected_product_id[, expected_hwid])`. They did not check the payload `type`, so a signed update-check
  answer (which needs no license) passed as a validation, and a fifth argument meant as the type was taken
  as the hwid. They are now deleted: every call is a compile error (final review S8).
- Migration: call `verify_envelope_typed` with the type of the request you sent. Code that cannot be
  changed yet can get the old overloads back, still `[[deprecated]]` and still unsafe, by defining
  `VELSIGIL_ALLOW_UNTYPED_ENVELOPE` for the whole program (for example
  `target_compile_definitions(app PUBLIC VELSIGIL_ALLOW_UNTYPED_ENVELOPE)`), never for single files.

### Added (free trials, SPEC 9.7)

- `LicenseInfo::is_trial`, `LeaseClaims::is_trial` and `ValidationResult::is_trial()`: true for a free-trial
  license, read from the optional signed `trial` field of the license and of the offline lease (absent =
  false, so older servers and paid licenses are unaffected; a non-boolean value makes the response
  `invalid_response` / the lease `malformed`). The new members come last, so aggregate initialisation of
  these structs keeps compiling.
- `codes::kTrialAlreadyUsed` (`trial_already_used`): this device already used a free trial of the product. A
  signed failure that keeps the stored lease; SDKs built before this change see an ordinary failure code.
- Not compiled or run locally for this change (no C++ toolchain on the build machine): CI must build and
  run `vector_tests` and `client_tests`.

### Added (in-app free trials, SPEC 9.7 "In-app trials")

- `Client::start_trial(const StartTrialOptions& = {})` starts a free trial of the product on this device
  without a license key (`POST /api/client/v1/trial`; the seller turns on the in-app channel of the product's
  trial offer). On success `result.trial_key` is the new license key: store it right away (the server can never
  send it again; the SDK does not persist it) and use `validate()` from then on. The device secret and the
  offline lease are stored like after a validation. `StartTrialOptions { version, device_name, email }`: the
  e-mail is sent only when set and read only by offers that confirm an address first. The answer is
  device-bound (signed lease / `activation.hwidHash` of this device) although no device secret is sent.
- Codes `codes::kTrialUnavailable`, `kTrialEmailRequired`, `kTrialEmailInvalid`, `kTrialEmailNotAccepted`,
  `kTrialConfirmationSent` (the key arrives by e-mail; none clears the stored lease) and the SDK code
  `codes::kPanelTooOld` (`panel_too_old`: `start_trial` reached a Velsigil server without the endpoint, HTTP 404
  with the error code `not_found`; other methods are unaffected).
- `ValidationResult::trial_key` (last member) and `StartTrialOptions`; `verify_envelope_typed` accepts
  `"trial"` as the expected type. An ok answer of type `trial` without a well-formed `trial.key` is an
  `invalid_response`; a `trial` object on any other answer is ignored.
- Not compiled or run locally either (no C++ toolchain): CI must build and run `vector_tests` (5 new vectors)
  and `client_tests` (`test_start_trial`).

### Added (trial conversion reference, SPEC 9.7 "Conversion to paid")

- `LicenseInfo::trial_ref` (last member) and `ValidationResult::trial_ref()`: the opaque reference the server signs
  into a free trial that a purchase can still convert (also on `license_expired`); nullopt when absent, offline, and
  for paid licenses. `ValidationResult::with_trial_ref(buy_url)`, the free functions `velsigil::with_trial_ref(url,
  ref)` and `velsigil::is_trial_ref(text)`, and `kTrialRefParam`: the "Buy now" link with `velsigil_trial=<ref>`
  (Stripe Payment Links: `client_reference_id=<ref>`). A `trialRef` that is not 1-200 characters of `[A-Za-z0-9_-]`
  is an `invalid_response`.
- Not compiled or run locally (no C++ toolchain): CI must build and run `vector_tests` (2 new vectors,
  `run_trial_ref_checks`) and `client_tests` (the `test_start_trial` additions).

### Fixed (in-app trials never replace a stored license, review finding 7)

- `Client::start_trial()` on a device that already holds a license for the product overwrote the stored device
  secret and offline lease (for example those of a paid license) with the trial's. It now refuses locally with the
  new SDK code `codes::kAlreadyLicensed` (`already_licensed`) when a device secret or a lease is stored: no request
  is sent and the stored state is unchanged. Validate the saved key instead, or call `deactivate(key)` /
  `clear_local_state()` first.
- Not compiled or run locally (no C++ toolchain): CI must build and run `client_tests` (`test_start_trial`: the
  `already_licensed` cases; the signed-failure cases now start from an empty store).

### Fixed (final bug sweep, 2026-10-07)

- Device-bound calls are serialized per `Client` (F-SDK-2, F-CLIENT-4): `validate`, `start_trial`, `deactivate`,
  `get_download` and `clear_local_state` hold a per-client mutex from reading the stored state through the request
  to persisting the answer. Before, two threads activating at once both sent no device secret (the second got a
  secret mismatch, under strict binding `device_verification_failed`), and a `validate` running next to
  `start_trial` could store the paid license between the `already_licensed` check and the trial request, whose
  answer then replaced it. Custom stores and transports must not call back into the `Client`.
- A store read that threw counted as "nothing stored" (F-SDK-1): `start_trial` passed its `already_licensed` guard.
  It now refuses with the new SDK code `codes::kStoreUnavailable` (`store_unavailable`) and sends nothing.
  `FileStore` no longer reads a file that exists but cannot be read as empty: `get` throws `std::runtime_error`, and
  `set` / `erase` return false instead of rebuilding the file from nothing (which erased every product's device
  secret). `IStore::get` documents that contract for custom stores.
- `days_until_expiry()` rounded down against the system clock, so a 14-day trial showed 13 days right after
  `start_trial` and 0 throughout the last day (F-SDK-4). It now rounds up (the cross-SDK rule of CLIENT_PROTOCOL
  5.2) and, without an argument, measures at `server_time`, else at the new `ValidationResult::reference_time` (last
  member; set on offline results to the time of the check), else the system clock. `days_until_expiry(now)` rounds
  up too.
- The Linux machine id `uninitialized` (systemd's placeholder) was hashed like a real id; it is now skipped like an
  empty file, as in the Node SDK (F-SDK-3).
- Not compiled or run locally (no C++ toolchain): CI must build and run `client_tests`
  (`test_store_read_failures_fail_closed`, `test_device_calls_are_serialized`, `test_machine_id_placeholder`, and the
  additions to `test_file_store` (POSIX, non-root) and `test_result_helpers`).

### Unchanged

- The `Client` methods (`validate`, `deactivate`, `check_update`, `get_download`, ...) always checked the
  type themselves: no change for code that uses only the client.
- Feature gating: `result.has_feature(name)` was already false for every failed result. Servers since
  2026-10-06 send `license.features: []` on a denial (final exploit check MONEY-V1); never gate features
  with `result.license->features`.
