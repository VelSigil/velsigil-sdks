# Changelog - Velsigil .NET SDK (`Velsigil.Client`)

## 1.0.5 (2026-10-09)

### Changed

- Shorter code and doc comments. No behaviour change.

## 1.0.4 (2026-10-08)

### Added

- `VelsigilResult.RetryAfter` is now set from the `Retry-After` header of **every** HTTP 429 or 503 answer,
  whatever code it maps to, not only for `rate_limited`: also the empty 503 with `Retry-After: 30` that a
  self-hosted server answers while its database is unreachable (`network_error`), a gateway's 503
  (`network_error`), 503 `service_busy` (`internal_error`) and a 503 of `DownloadFileAsync` (`network_error`; it
  already set it for a 429). Parsed as before (delta-seconds or HTTP date, capped at one day); null without the
  header and for every other status (500, 502, 504, ...). `ValidateWithOfflineFallbackAsync` copies the failed
  online answer's value onto the result of its fallback (offline `ok`, `lease_expired`, `lease_invalid`), so an app
  running on its lease knows when to try online again; `ValidateOffline()` called directly leaves it null. The type
  stays `TimeSpan?`; result codes and the fallback rule are unchanged. The same in every Velsigil SDK.

## 1.0.3 (2026-10-08)

### Fixed

- `ValidateWithOfflineFallbackAsync` now also falls back to the stored offline lease when the license server is
  up but cannot answer: every **unsigned HTTP 5xx** answer (500, 502, 503, 504 and any other 5xx), whatever its
  body (a Velsigil error body, a reverse proxy's HTML page, an empty or garbled body). Before, it fell back only on
  `network_error` (no response, or a gateway 502/503/504 without a Velsigil error body), so a self-hosted server
  whose database was down answered 500 / 503 `internal_error` and the app failed although it held a valid lease.
  The HTTP status decides, not the code: signed answers (revoked, expired, banned, ...), 4xx answers (`rate_limited`,
  `validation_error`, ..., even one whose body says `internal_error`) and `invalid_response` stay final. Without a
  stored lease the original result (`internal_error` or `network_error`, with its `HttpStatus` and `RequestId`) is
  returned; an expired or invalid lease gives `lease_expired` / `lease_invalid`, as for `network_error`.
  **Behaviour change to check in your app:** for an unsigned 5xx that did not fall back before, the method used to
  return `internal_error`; with a stored lease it now returns an offline result (`Offline` is true): `ok`, or
  `lease_expired` / `lease_invalid` when the stored lease cannot be used, so code that handled `internal_error` from
  it must handle these codes too.
  `ValidateAsync` and the result codes are unchanged (no new code): it still reports `internal_error` for these
  answers. Falling back on an unsigned 5xx is as safe as on a dropped connection, which an attacker can cause
  just as easily; the lease is signed, bound to the device and time-limited.

## 1.0.2 (2026-10-08)

### Security

- The `VelsigilClient` constructor now refuses the two public keys of the SDK test vectors (`keys.publicKey` and
  `keys.wrongPublicKey` in `test-vectors.json`), whose private keys are published, so anyone could forge license
  answers for an app that trusts them. It throws the same `ArgumentException` (parameter `publicKeyBase64`) as for
  an invalid key, unless the API URL's host is `localhost`, `127.0.0.1` or `::1` (the hosts plain http is allowed
  for). Keys are compared as decoded bytes, so no other encoding of them gets through.
- `LeaseVerifier.Verify(token, publicKeyBase64, productId, hwid, now)`, the public low-level helper that takes a
  public key (the only one in this SDK; envelope verification is internal), now refuses the same two test keys, in
  any encoding, with the same `ArgumentException` (parameter `publicKeyBase64`) and message as the constructor.
  It has no server URL, so there is no loopback exception and no opt-out, and the key is checked before the token.
  Before, it accepted them, so an app that verified its own stored leases with a test key accepted leases anyone
  could sign. Pass your product's public key. `ValidateOffline()` is unchanged (it uses the key the constructor
  accepted); the SDK's own lease-vector tests use an internal overload that is not part of the public API.
- The README quick start used the test public key as its example value; it now shows a placeholder
  (`<your product's public key>`). An app that copied the old value must switch to its product's key from the
  panel (Products > your product > Integration).
- The console example (`examples/ConsoleExample`) no longer reads the API URL, product id and public key from the
  environment: they are compiled-in constants (`ApiUrl`, `ProductId`, `PublicKey` in `Program.cs`) with
  placeholders, as in a real application. While a placeholder is still in place it prints a usage message and
  exits with code 2. For local testing, `VELSIGIL_URL`, `VELSIGIL_PRODUCT_ID` and `VELSIGIL_PUBLIC_KEY` still
  override the constants, but only when the API URL is loopback (`localhost`, `127.0.0.1` or `[::1]`); with any
  other URL the example refuses to start (exit code 2). A refused or otherwise invalid key is reported as
  `Invalid configuration` (exit code 2). `VELSIGIL_LICENSE_KEY` and `VELSIGIL_APP_VERSION` are unchanged.

### Fixed

- On .NET Framework (the `netstandard2.0` asset), `[::1]` was not recognised as loopback: its `Uri.Host` is
  spelled `[0000:0000:0000:0000:0000:0000:0000:0001]` there, so plain `http://[::1]` was rejected (and the test
  keys would have been refused for it). The loopback check now compares an IPv6 host as an address: exactly `::1`
  (not `::ffff:127.0.0.1`). Behaviour on .NET Core / .NET 5+ is unchanged.

## 1.0.1 (2026-10-08)

No code changes from 1.0.0. The release workflow of 1.0.0 published only the C++ source release on GitHub: its
nuget.org upload signed in with the organization's name instead of the user who created the trusted-publishing
policy, and its npm upload was not matched by the trusted publisher. 1.0.1 releases all four SDKs together again.

- First version on nuget.org, under the reserved `Velsigil` prefix. The 1.0.0 upload failed before anything
  was pushed.

## 1.0.0 (2026-10-08)

### Packaging and distribution (2026-10-07)

- Published to nuget.org from the public repository [VelSigil/velsigil-sdks](https://github.com/VelSigil/velsigil-sdks)
  (`csharp` folder) through NuGet trusted publishing, with a symbol package (`.snupkg`) and Source Link.
- Package metadata: repository URL and commit, project URL, release notes link, copyright; the `LICENSE` text
  ships in the package. Deterministic builds; `ContinuousIntegrationBuild` on CI.
- Committed `packages.lock.json` files (restored with `--locked-mode` in CI), `nuget.config` with package
  source mapping to nuget.org only, and `global.json` pinning the .NET SDK the lock files were made with.

Changes made on 2026-10-06, before the first release (so the version stays 1.0.0):

- Response envelopes are verified against the type of the request (`validate`, `deactivate`,
  `update_check`, `download`); a payload of another type yields `TypeMismatch` (security review SDK-1).
  Envelope verification is internal in this SDK (`Internal/EnvelopeVerifier`), so the public API is
  unchanged: no migration is needed.
- `LicenseInfo.HasFeature(name)` is now false unless the response was ok and the license status is
  `active` or `pending`, and `LeaseClaims.HasFeature(name)` is false unless the lease verified as `Valid`
  (final exploit check MONEY-V1). Before, both only looked at `Features`, which a signed denial
  (`license_revoked`, `license_expired`, ...) or the diagnostic claims of an expired lease still listed, so
  code that gated features with them kept unlocking them after a refund or revocation. The server no longer
  lists features on a denial either. Gate features with `result.HasFeature(name)` (unchanged).
- Free trials (SPEC 9.7): `VelsigilResult.IsTrial`, `LicenseInfo.IsTrial` and `LeaseClaims.IsTrial`, read from
  the optional signed `trial` field of the license and of the offline lease (absent = false, so older servers
  and paid licenses are unaffected; a non-boolean value is an `invalid_response` / malformed lease). New
  `ResultCodes.TrialAlreadyUsed` (`trial_already_used`): this device already used a free trial of the product;
  a signed failure that keeps the stored lease. SDKs built before this change see it as an ordinary failure.
- In-app free trials (SPEC 9.7 "In-app trials"): `StartTrialAsync(StartTrialOptions? options = null,
  CancellationToken ct = default)` starts a free trial of the product on this device without a license key
  (`POST /api/client/v1/trial`; the seller turns on the in-app channel of the product's trial offer). On success
  `VelsigilResult.TrialKey` is the new license key: store it right away (the server can never send it again; the
  SDK does not persist it; `ToString()` never shows it) and use `ValidateAsync` from then on. The device secret and
  the offline lease are stored like after a validation. `StartTrialOptions { Version, DeviceName, Email }`: the
  e-mail is sent only when set and read only by offers that confirm an address first. New codes
  `ResultCodes.TrialUnavailable`, `TrialEmailRequired`, `TrialEmailInvalid`, `TrialEmailNotAccepted`,
  `TrialConfirmationSent` (the key arrives by e-mail; none of them is lease-revoking) and the SDK code
  `ResultCodes.PanelTooOld` (`panel_too_old`: `StartTrialAsync` reached a Velsigil server without the endpoint,
  HTTP 404 with the error code `not_found`; other methods are unaffected). An ok answer of type `trial` without a
  well-formed `trial.key` is an `invalid_response`; a `trial` object on any other answer is ignored.
- Trial conversion reference (SPEC 9.7 "Conversion to paid"): `VelsigilResult.TrialRef` and `LicenseInfo.TrialRef`,
  the opaque reference the server signs into a free trial that a purchase can still convert (also on
  `license_expired`; null when absent, offline, and for paid licenses); `VelsigilResult.WithTrialRef(buyUrl)` and the
  new static class `TrialReference` (`Parameter`, `Append(url, reference)`, `IsWellFormed`): the "Buy now" link with
  `velsigil_trial=<ref>` (Stripe Payment Links: `client_reference_id=<ref>`). A `trialRef` that is not 1-200
  characters of `[A-Za-z0-9_-]` is an `invalid_response`. New vectors `validate_ok_trial_ref`,
  `license_expired_trial_ref`.
- Fixed (review finding 7): `StartTrialAsync` on a device that already holds a license for the product overwrote the
  stored device secret and offline lease (for example those of a paid license) with the trial's. It now refuses
  locally with the new SDK code `ResultCodes.AlreadyLicensed` (`already_licensed`) when a device secret or a lease is
  stored: no request is sent and the stored state is unchanged. Validate the saved key instead, or call
  `DeactivateAsync(key)` / `ClearStoredState()` first.

Fixed in the final bug sweep (2026-10-07):

- Device-bound calls are serialized per client (F-SDK-2, F-CLIENT-4). `ValidateAsync`, `StartTrialAsync`,
  `DeactivateAsync` and `GetDownloadAsync` hold a per-client lock from reading the stored state through the request to
  persisting the answer, and `ClearStoredState` waits for it. Before, two concurrent first activations both sent no
  device secret (the second got a secret mismatch, under strict binding `device_verification_failed`, and its lease was
  dropped), and a validation running next to `StartTrialAsync` could store the paid license between the
  `already_licensed` check and the trial request, whose answer then replaced it. Argument checks still fail
  synchronously; a cancelled token while waiting for the lock throws `OperationCanceledException`.
- A store read that threw counted as "nothing stored", so `StartTrialAsync` passed its `already_licensed` guard
  (F-SDK-1). It now refuses with the new SDK code `ResultCodes.StoreUnavailable` (`store_unavailable`) and sends
  nothing.
- `VelsigilResult.DaysRemaining` rounded down, so it showed 0 throughout the last day of a license (F-SDK-4). It now
  rounds up (the cross-SDK rule of CLIENT_PROTOCOL 5.2), still measured at `ReferenceTimeUnix`.
- The Linux machine id `uninitialized` (systemd's placeholder) was hashed like a real id; it is now skipped like an
  empty file, as in the Node SDK (F-SDK-3).
