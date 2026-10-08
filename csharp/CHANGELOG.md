# Changelog - Velsigil .NET SDK (`Velsigil.Client`)

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
