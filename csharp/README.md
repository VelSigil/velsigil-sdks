# Velsigil.Client for .NET

Official .NET client for the [Velsigil](https://www.velsigil.com) license server. It validates license keys online,
binds activations to the device with a server-issued device secret, keeps a signed offline lease for when
the server is unreachable, checks for updates and downloads releases with integrity verification.

Every success the SDK reports is backed by an **Ed25519 signature** made with your product key: the
signature is checked over the exact bytes received, before anything is parsed, and the response must echo
the fresh nonce of the request and name your product. Unsigned or tampered responses can never produce
`Ok == true`.

| | |
|---|---|
| Package | `Velsigil.Client` |
| Targets | `net8.0` and `netstandard2.0` (.NET Framework 4.7.2+, .NET Core 3.1+/.NET 5+, Mono, Unity 2021.3+) |
| Dependencies | `BouncyCastle.Cryptography` 2.x; on netstandard2.0 also `System.Text.Json` 8.x and `Microsoft.Win32.Registry` |
| Threading | One long-lived, thread-safe client per product |
| Reflection | None: JSON is read with `JsonDocument` and written with `Utf8JsonWriter`, so the SDK is trimming, Native AOT and IL2CPP friendly |

---

## Contents

1. [Installation](#installation)
2. [Quick start](#quick-start)
3. [API reference](#api-reference)
4. [Result codes](#result-codes)
5. [In-app free trials](#in-app-free-trials)
6. [Offline leases](#offline-leases)
7. [Device secret persistence](#device-secret-persistence)
8. [Updates and downloads](#updates-and-downloads)
9. [Thread-safety and lifetime](#thread-safety-and-lifetime)
10. [Platform notes](#platform-notes) (WinForms / WPF, console and services, Unity / IL2CPP, .NET Framework)
11. [Hardening notes](#hardening-notes)
12. [Building and testing the SDK](#building-and-testing-the-sdk)

---

## Installation

### Option A: nuget.org (recommended)

```powershell
dotnet add package Velsigil.Client
```

The official package is owned by the nuget.org account `velsigil-client`, which holds the reserved `Velsigil.`
package-id prefix: the official package shows the verified checkmark, and no one else can publish a `Velsigil.*`
package. For a locked, source-mapped restore and signature checks see
[VERIFYING.md](https://github.com/VelSigil/velsigil-sdks/blob/main/docs/VERIFYING.md).

### Option B: local NuGet feed built from source

```powershell
# In the csharp folder of the SDK repository (https://github.com/VelSigil/velsigil-sdks)
dotnet pack src/Velsigil.Client -c Release -o ./nupkgs

# In your application
dotnet add package Velsigil.Client --version 1.0.0 --source ../path/to/nupkgs
```

Or register the folder once as a feed: `dotnet nuget add source C:\path\to\nupkgs -n velsigil-local`.

### Option C: project reference

```xml
<ItemGroup>
  <ProjectReference Include="..\velsigil-sdks\csharp\src\Velsigil.Client\Velsigil.Client.csproj" />
</ItemGroup>
```

---
## Quick start

Copy the **product id** and **public key** from the panel (Products, then your product, then the
*Integration* tab) and compile them into your application.

```csharp
using Velsigil.Client;
using Velsigil.Client.Storage;

public static class Licensing
{
    // Compiled-in constants. Never load the public key from a file, the registry or the network.
    private const string ApiUrl = "https://licenses.example.com";
    private const string ProductId = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b";
    private const string PublicKey = "<your product's public key>"; // base64, from the panel's Integration tab

    // One long-lived client per product.
    public static readonly VelsigilClient Client = new VelsigilClient(ApiUrl, ProductId, PublicKey,
        new VelsigilClientOptions { Store = FileStore.CreateDefault("MyApp") });
}

var result = await Licensing.Client.ValidateWithOfflineFallbackAsync(
    licenseKey,
    new ValidateOptions { Version = "1.2.0", DeviceName = Environment.MachineName });

if (!result.Ok)
{
    // Business failures never throw: show result.Message, branch on result.Code.
    Console.WriteLine($"License problem: {result.Message} ({result.Code})");
    return;
}

if (result.HasFeature("export")) EnableExport();
Console.WriteLine(result.IsLifetime ? "Lifetime license" : $"{result.DaysRemaining} days left");
if (result.Offline) Console.WriteLine("Validated offline with the stored lease.");
```

A runnable walkthrough lives in [`examples/ConsoleExample`](https://github.com/VelSigil/velsigil-sdks/blob/main/csharp/examples/ConsoleExample/Program.cs).
Like a real application, it takes the API URL, product id and public key from compiled-in constants (`ApiUrl`,
`ProductId`, `PublicKey` at the top of `Program.cs`): replace their placeholders with your product's values, then run

```powershell
dotnet run --project examples/ConsoleExample -- validate      # or: offline | update | download <file> | deactivate
```

While a placeholder is still in place it prints a usage message and exits with code 2. The license key is read from
`VELSIGIL_LICENSE_KEY` or prompted for, and never printed. For local testing only, `VELSIGIL_URL`,
`VELSIGIL_PRODUCT_ID` and `VELSIGIL_PUBLIC_KEY` override the three constants, and only when the API URL is loopback
(`localhost`, `127.0.0.1` or `[::1]`, e.g. `$env:VELSIGIL_URL = "http://localhost:3000"`); with any other URL the
example refuses to start (exit code 2).

---

## API reference

All types live in the `Velsigil.Client` namespace (stores in `Velsigil.Client.Storage`).

### `VelsigilClient`

```csharp
public VelsigilClient(string apiUrl, string productId, string publicKeyBase64, VelsigilClientOptions? options = null)
```

| Parameter | Description |
|---|---|
| `apiUrl` | Server URL, e.g. `https://licenses.example.com` (a URL ending in `/api/client/v1` and sub-path deployments such as `https://example.com/licensing` work too). Must be **https**; plain http is accepted only for `localhost`, `127.0.0.1` and `::1` unless `AllowInsecureHttp` is set. No credentials, query or fragment. |
| `productId` | Product UUID (normalised to lowercase). |
| `publicKeyBase64` | The product's raw 32-byte Ed25519 public key, standard base64. The **only** key whose signatures are trusted; the envelope `kid` is never used to pick a key. The public keys of the SDK test vectors are refused (`ArgumentException`) unless the API URL's host is `localhost`, `127.0.0.1` or `::1`: their private keys are published. |
| `options` | Optional `VelsigilClientOptions` (copied at construction). |

The constructor throws `ArgumentException` / `ArgumentOutOfRangeException` for invalid configuration and
`PlatformNotSupportedException` when no machine id can be read and no `HardwareId` override is given.

| Member | Description |
|---|---|
| `Task<VelsigilResult> ValidateAsync(string licenseKey, ValidateOptions? options = null, CancellationToken ct = default)` | Validates the key for this device, activating it if a slot is free. Persists a newly issued device secret and the offline lease. `ValidateOptions { Version (≤ 32), DeviceName (≤ 255) }`. |
| `Task<VelsigilResult> ValidateWithOfflineFallbackAsync(string licenseKey, ValidateOptions? options = null, CancellationToken ct = default)` | Online first; falls back to `ValidateOffline()` **only** when the server is unavailable: `network_error` (no response) or any unsigned HTTP 5xx answer (`internal_error`, or `network_error` for a gateway 502/503/504 without a Velsigil error body), see [Offline leases](#offline-leases). Signed answers, 4xx answers and `invalid_response` are returned as is. If no lease is stored, the original `network_error` / `internal_error` result is returned (not `no_lease`), as in every Velsigil SDK. |
| `VelsigilResult ValidateOffline()` | Verifies the stored lease (signature, type, product, this device, expiry). Never touches the network. |
| `Task<VelsigilResult> StartTrialAsync(StartTrialOptions? options = null, CancellationToken ct = default)` | Starts a free trial of the product on this device without a license key (see [In-app free trials](#in-app-free-trials)). On `Ok`, `result.TrialKey` is the new key: store it, then use `ValidateAsync`. Persists the device secret and lease like `ValidateAsync`. `StartTrialOptions { Version (≤ 32), DeviceName (≤ 255), Email (≤ 254, sent only when set) }`. Returns `already_licensed` locally (nothing sent, nothing changed) when a device secret or lease is already stored for the product, and `store_unavailable` when the store cannot be read. |
| `Task<VelsigilResult> DeactivateAsync(string licenseKey, CancellationToken ct = default)` | Frees this device's slot. On success the stored device secret and lease are deleted. |
| `Task<VelsigilResult> CheckUpdateAsync(string? currentVersion = null, CancellationToken ct = default)` | Release information in `result.Update` (`no_release` when nothing is published). Sends no license data. |
| `Task<VelsigilResult> GetDownloadAsync(string licenseKey, string? version = null, CancellationToken ct = default)` | Short-lived download grant in `result.Download` for a release (latest when `version` is null). Requires an activated device. A grant whose URL is not https (plain http only for loopback or with `AllowInsecureHttp`) or carries credentials is rejected as `invalid_response`. |
| `Task<VelsigilResult> DownloadFileAsync(DownloadInfo download, string destinationPath, IProgress<long>? progress = null, CancellationToken ct = default)` | Streams the grant to a temporary file, verifies size and SHA-256 against the signed values, then atomically moves it to `destinationPath`. |
| `void ClearStoredState()` | Deletes the stored device secret and lease for this product (e.g. "sign out"). Waits for a device-bound call in progress to finish first. |
| `static string GetHardwareId()` | This machine's hardware id (see [HardwareId](#hardwareid)). |
| `string ProductId`, `string HardwareId`, `string KeyId`, `Uri ApiBaseUrl`, `long ClockOffsetSeconds` | Diagnostics: normalised product id, the hwid sent, key id of the pinned key (first 16 hex chars of SHA-256 of the key, matches the panel's key id), resolved client API base, learned server clock offset. |
| `void Dispose()` | Disposes the internally created `HttpClient` (an injected one is left alone). |

What throws: invalid arguments (`ArgumentException`), use after `Dispose` (`ObjectDisposedException`) and
cancellation through **your** `CancellationToken` (`OperationCanceledException`). Everything else,
including timeouts, DNS/TLS/connection errors, HTTP errors, bad signatures and license failures, is a
`VelsigilResult` with `Ok == false`.

### `VelsigilClientOptions`

| Property | Default | Description |
|---|---|---|
| `Timeout` | 15 s | Per request (1 s to 10 min). Timeouts are `network_error`. For downloads it applies to the response headers and as an inactivity timeout between reads. |
| `HardwareId` | derived | Override of the hardware id (8..256 chars). Keep it stable: a new value is a new device. |
| `Store` | `FileStore` in the per-user data dir | Where the device secret and lease are kept, see [Device secret persistence](#device-secret-persistence). |
| `AllowInsecureHttp` | `false` | Permit `http://` to non-loopback hosts. Never in production. |
| `HttpClient` | internal | Inject your own (proxy, certificate pinning, Unity handler). Not disposed by the SDK. The internal one never follows redirects and has cookies disabled. Build an injected one on a handler with `AllowAutoRedirect = false` (the .NET default is `true`): the SDK rejects an answer that does not come from the URI it requested (`invalid_response`, `download_failed` for downloads), but a handler that follows a 307/308 has already re-sent the license key and device secret to the new location. |
| `Clock` | `DateTimeOffset.UtcNow` | Time source for request timestamps and lease expiry (tests, trusted time sources). |
| `StoreErrorHandler` | none | Called when the store throws; store failures never fail a validation. |

#### Injecting an `HttpClient`

* **Its handler must set `AllowAutoRedirect = false`** (`HttpClientHandler` and `SocketsHttpHandler` default
  to `true`). This is required, not optional: the SDK can only notice a followed redirect afterwards, when a
  307/308 has already re-sent the request body (license key, device secret) to the new location. A custom
  handler that wraps another HTTP stack must not follow redirects either.
* The SDK compares `response.RequestMessage.RequestUri` with the URI it requested and treats any difference
  as a followed redirect: `invalid_response` (`download_failed` for `DownloadFileAsync`). A custom
  `DelegatingHandler` / `HttpMessageHandler` that **rewrites `request.RequestUri`** (a URL-rewriting proxy or
  gateway handler, host or path remapping) or returns a response whose `RequestMessage` is another request
  therefore fails every call, although nothing was redirected. Leave `RequestUri` unchanged (route through a
  proxy with the handler's `Proxy` property instead) and return responses whose `RequestMessage` is the
  request the handler received.

### `VelsigilResult`

| Member | Description |
|---|---|
| `bool Ok` | Success. True only for a verified signed response (signature, nonce, product, request type) or a verified, unexpired offline lease for this device. |
| `string Code` | See [Result codes](#result-codes) and the `ResultCodes` constants. |
| `string Message` | Signed server message, or a fixed SDK message (text from unsigned responses is never surfaced). |
| `LicenseInfo? License` | `Id`, `Plan`, `Status` (`LicenseStatuses`), `Features`, `ExpiresAt`/`ExpiresAtUnix` (null = lifetime), `IsLifetime`, `MaxDevices`, `DevicesUsed`, `CreatedAt`, `IsTrial`, `TrialRef`, `HasFeature()`. On a failed result (`license_revoked`, `license_expired`, ...) `License.Features` is informational only (servers since 2026-10-06 send it empty) and `License.HasFeature()` is false; gate features with `result.HasFeature()`. |
| `ActivationInfo? Activation` | `Id`, `Status`, `FirstSeenAt`, `DeviceSecretIssued`. The secret itself is never exposed. |
| `LeaseInfo? Lease` | `Token`, `ExpiresAt`. Online: the lease just issued. Offline: the stored lease. |
| `LeaseClaims? LeaseClaims` | Offline results: verified lease claims (`LicenseId`, `ActivationId`, `Plan`, `Features`, `LicenseExpiresAt`, `IssuedAt`, `ExpiresAt`, `HwidHash`, `HasFeature()`). For an expired or mismatched lease they are diagnostics only: `LeaseClaims.HasFeature()` is false. |
| `UpdateInfo? Update` | `LatestVersion`, `MinVersion`, `UpdateAvailable`, `Mandatory`, `Changelog`. |
| `DownloadInfo? Download` | `Url` (treat as a secret), `ExpiresAt`, `FileName`, `Size`, `Sha256`, `Version`. |
| `string? RequestId` | Server request id; quote it to support. |
| `bool Offline` | Produced from the stored lease. |
| `LeaseStatus? LeaseStatus` | Offline results: detailed lease verification outcome (`Valid`, `Expired`, `InvalidSignature`, `ProductMismatch`, `HwidMismatch`, `Malformed`). |
| `bool Verified` | Backed by a verified signature. |
| `long? ServerTimeUnix`, `int? HttpStatus`, `TimeSpan? RetryAfter` | Authoritative server time; HTTP status of unsigned errors; wait time for `rate_limited`. |
| `string? TrialKey` | The key of the trial `StartTrialAsync` just started (`Ok` results of that method only; never in `ToString()`). Sent once: store it immediately. |
| `IReadOnlyList<string> Features`, `bool HasFeature(string name)` | `HasFeature` is **false whenever `Ok` is false**, so a failed or forged response can never unlock a feature. Ordinal, case-sensitive. |
| `DateTimeOffset? ExpiresAt`, `bool IsLifetime`, `TimeSpan? TimeRemaining`, `int? DaysRemaining`, `TimeSpan? GetTimeRemaining(DateTimeOffset now)`, `bool IsExpiringWithin(TimeSpan window)` | Expiry helpers (license expiry from the response, or from the lease when offline). `TimeRemaining`/`DaysRemaining` are measured at `ReferenceTimeUnix` (server time for signed responses, the time of the check offline). `DaysRemaining` rounds **up**: an N-day trial shows N right after `StartTrialAsync`, 1 on its last day and 0 once expired (the same rule in every Velsigil SDK). |
| `bool IsTrial` | A free-trial license: the optional signed `trial` field (from the response, or from the stored lease when offline; `LeaseClaims.IsTrial`). Pair it with `DaysRemaining` for "Trial: N days left" and a "Buy now" link; a purchase with the same e-mail keeps the key and turns it false at the next online validation. |
| `string? TrialRef` | The trial's conversion reference (servers since 2026-10-06; also `License.TrialRef`): set on online results for a free trial a purchase can still convert, also on `license_expired`; null otherwise and offline. Put it in your "Buy now" link with `result.WithTrialRef(buyUrl)` (or `TrialReference.Append(url, reference)`): it appends `velsigil_trial=<ref>` (a Stripe Payment Link gets `client_reference_id=`), and the purchase then converts THIS trial (same key) whatever e-mail address the buyer pays with. Opaque; never store it. |
| `ToString()` | Diagnostic summary that never contains keys, secrets or tokens. |

### `LeaseVerifier`

`LeaseVerifier.Verify(string? token, string publicKeyBase64, string productId, string hwid, DateTimeOffset now)`
returns a `LeaseVerification { Status, IsValid, Claims }` with `LeaseStatus` = `Valid`, `Expired`,
`InvalidSignature`, `ProductMismatch`, `HwidMismatch` or `Malformed`. `ValidateOffline()` uses the same
verification with the pinned key; it is public for applications that keep leases themselves. It throws
`ArgumentException` (parameter `publicKeyBase64`) for an invalid key, and also for the two public keys of the SDK
test vectors (`keys.publicKey`, `keys.wrongPublicKey` in `test-vectors.json`), in any encoding: their private keys
are published, so anyone could sign a lease for them. This helper has no server URL, so unlike the
`VelsigilClient` constructor it refuses them always, with the same message; there is no opt-out.

There is no public envelope verifier: response envelopes are only verified inside `VelsigilClient`, which
always requires the signed `type` to match the endpoint (the server also signs `ok` answers to
update checks, which need no license). A custom integration must check `type` the same way
(CLIENT_PROTOCOL section 6).

### `HardwareId`

`hwid = lowercase hex SHA-256("vx-hwid-v1:" + machineId)` with `machineId` trimmed and lowercased,
identical in every Velsigil SDK:

| OS | Source |
|---|---|
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, always the 64-bit registry view |
| Linux | `/etc/machine-id`, then `/var/lib/dbus/machine-id` (a file that is empty or holds systemd's placeholder `uninitialized` is skipped) |
| macOS | `IOPlatformUUID` from `/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice` (absolute path, no shell) |

`HardwareId.Get()` (cached), `TryGet(out string)`, `ReadMachineId()`, `NormalizeMachineId()`,
`FromMachineId()`, and `HashHwid(hwid)` (the server-side hash carried in leases). Only the hash ever
leaves the machine. Hardware ids are spoofable, which is why the server pairs them with a device secret.

---

## Result codes

`Code` is a stable snake_case string; compare against the `ResultCodes` constants.

### Signed server outcomes (`Verified == true`)

| Code | Meaning | Typical handling |
|---|---|---|
| `ok` | Success | Continue. |
| `invalid_key` | Key not found for this product | Ask for the key again. Clears the stored lease. |
| `license_expired` | License expired | Offer renewal. Clears the stored lease. |
| `license_suspended` | Suspended by the seller | Contact support. Clears the stored lease. |
| `license_revoked` | Revoked (e.g. refund) | Block. Clears the stored lease. |
| `license_banned` | Banned for abuse | Block. Clears the stored lease. |
| `device_limit_reached` | No free device slot | Deactivate another device or reset devices in the customer portal. |
| `device_revoked` | This device was revoked | Contact support. Clears the stored lease. |
| `device_verification_failed` | Device secret mismatch (strict device binding) | Seller or customer must reset the device. Clears the stored lease. |
| `device_not_found` | Deactivate: device not activated | Nothing to do. Clears the stored lease. |
| `device_not_activated` | Download: validate first | Call `ValidateAsync`. |
| `activation_rate_limited` / `activation_cooldown` | Too many new devices recently | Retry later. |
| `activations_disabled` | Seller paused new activations | Retry later. |
| `downloads_disabled` | Seller paused downloads | Retry later. |
| `blacklisted` | Device, IP or customer blacklisted | Block. Clears the stored lease. |
| `outdated_version` | Below the minimum version | Update (`result.Update`). |
| `product_paused` | Maintenance (`Message` has the seller's text) | Retry later. |
| `product_disabled` | Product disabled | Block. Clears the stored lease. |
| `clock_skew` | Clock too far from the server | Already corrected and retried once automatically; if it persists, fix the system clock. |
| `replay_detected` | Nonce reused | Should not happen (fresh nonces); retry. |
| `no_release` / `release_not_found` | Nothing published / version unknown | Inform the user. |
| `trial_already_used` | This device already used a free trial of the product (`ResultCodes.TrialAlreadyUsed`) | Offer to buy. Keeps the stored lease. |
| `trial_unavailable` | `StartTrialAsync`: no in-app trial right now (switched off, today's limit, too many trials from this network) | Show `Message`. |
| `trial_email_required` / `trial_email_invalid` / `trial_email_not_accepted` | `StartTrialAsync`: the offer confirms an e-mail address first | Ask for an address, a valid one, or a personal / work one (throwaway domains are refused). |
| `trial_confirmation_sent` | `StartTrialAsync`: a confirmation link was e-mailed (the same answer for every valid address) | Not an error: the key arrives by e-mail and is entered like any key. |

### Unsigned HTTP errors (`Verified == false`, never `Ok`)

| Code | HTTP | Meaning |
|---|---|---|
| `validation_error` | 400 | Request rejected by the server's schema (also returned locally, without a request, for an empty key or over-long `Version`/`DeviceName`). |
| `ip_blocked` | 403 | Network temporarily blocked by the server. |
| `unknown_product` | 404 | Wrong product id or server URL. |
| `payload_too_large` | 413 | Request too large. |
| `unsupported_media_type` | 415 | Content type rejected. |
| `rate_limited` | 429 | Slow down; honour `RetryAfter`. |
| `internal_error` | 5xx | Server error or temporarily unavailable (for example its database is down); retry later. Also 502/503/504 **with** a Velsigil error body. Triggers the offline fallback. |

The mapping is identical in every Velsigil SDK (SPEC section 14): a known code in a Velsigil error body
(`{ "error": { "code" } }`) wins; otherwise 400 → `validation_error`, 413 → `payload_too_large`, 415 →
`unsupported_media_type`, 429 → `rate_limited`, 502/503/504 → `network_error` without a Velsigil error body
(a reverse proxy while the server is down) or `internal_error` with one, other 5xx → `internal_error`.
Anything else unexpected (redirects, 401, 404 without a body) is `invalid_response`. Unsigned message text is
never surfaced. `ValidateAsync` reports exactly this code; `ValidateWithOfflineFallbackAsync` falls back on
every unsigned 5xx, whichever code it maps to (see [Offline leases](#offline-leases)).

### SDK-side codes (same names in every Velsigil SDK)

| Code | Meaning |
|---|---|
| `network_error` | DNS/TCP/TLS failure, timeout, or gateway 502/503/504 without a Velsigil error body (an HTML page, an empty body). Triggers the offline fallback, as does every other unsigned 5xx (`internal_error`). |
| `invalid_response` | Unsigned 200, bad or missing signature, foreign nonce / product / request type (the signed `type` must match the endpoint), a signed lease or `activation.hwidHash` of another device (the request was rewritten in transit; nothing from the response is stored), a download URL outside the https policy, malformed payload, oversized body, redirect. Treat as hostile. |
| `validation_error` | Local argument check failed (key empty or > 64 chars, `Version` > 32, `DeviceName` > 255); nothing was sent. |
| `invalid_configuration` | `ResultCodes.InvalidConfiguration`: the cross-SDK name for constructor argument errors, which .NET reports by throwing `ArgumentException`. |
| `no_lease` | Offline: no lease stored. |
| `lease_expired` | Offline: lease past its `exp`. |
| `lease_invalid` | Offline: signature invalid for the pinned key, lease for another product or device, or not a lease token. `result.LeaseStatus` (`InvalidSignature`, `ProductMismatch`, `HwidMismatch`, `Malformed`) tells which. |
| `integrity_mismatch` | Download: size or SHA-256 differs from the signed values; the file was discarded. |
| `download_failed` | Download: non-200 status (an expired link answers 410: request a new one) or a URL rejected by the HTTPS policy. |
| `io_error` | Download: the destination could not be written. |
| `panel_too_old` | `StartTrialAsync`: the Velsigil server has no in-app trial endpoint yet (HTTP 404 with the Velsigil error code `not_found`). The seller must update the panel. |
| `already_licensed` | `StartTrialAsync` (`ResultCodes.AlreadyLicensed`): this device already holds a license for the product (a device secret or offline lease is stored), and a trial must not replace it. Nothing was sent and the stored state is unchanged. Validate the saved key instead, or call `DeactivateAsync(key)` / `ClearStoredState()` first. |
| `store_unavailable` | `StartTrialAsync` (`ResultCodes.StoreUnavailable`): the store could not be read (for example a locked file), so the SDK cannot tell whether this device already holds a license. Nothing was sent; try again later. |

---

## In-app free trials

When the seller turns on **In your app** in the product's trial offer (panel → Products → your product →
Trials), an app that has no license key yet can start a free trial for its device:

```csharp
var savedKey = LoadSavedLicenseKey(); // your own settings storage
if (savedKey is null)
{
    var trial = await Licensing.Client.StartTrialAsync(new StartTrialOptions { Version = "1.2.0", DeviceName = Environment.MachineName });
    if (trial.Ok && trial.TrialKey != null)
    {
        SaveLicenseKey(trial.TrialKey); // FIRST: the server can never send this key again
        ShowTrialBanner(trial.DaysRemaining); // trial.IsTrial == true
    }
    else if (trial.Code == ResultCodes.TrialEmailRequired)
    {
        // The offer confirms an e-mail address first: ask for it, then StartTrialAsync(new StartTrialOptions { Email = ... }).
    }
    else
    {
        ShowMessage(trial.Message); // trial_confirmation_sent, trial_already_used, trial_unavailable, panel_too_old, ...
    }
}
```

* **One trial per device and product.** A device that already had a trial of the product (from the app, the
  seller's website or the customer portal) gets `trial_already_used`; offer to buy.
* **The trial key is an ordinary license key** on the seller's trial plan. Store it like a key the user typed and
  use `ValidateAsync` from then on. Show it in your About / License screen: the customer needs it for the customer
  portal, to move the trial to another device and for support. A purchase converts the same key (the seller's
  staff, or a purchase with the e-mail address the trial was confirmed with).
* **E-mail confirmation (optional, the seller's choice).** Then the first answer is `trial_confirmation_sent`; the
  customer confirms the address from the e-mail, gets the key on the confirmation page and by e-mail, and enters it
  in the app (`ValidateAsync`).
* The SDK stores the trial's device secret and offline lease like after a validation, never the key.
* **Never over an existing license.** When a device secret or an offline lease is already stored for the product
  (the device was activated with a key, paid or trial), `StartTrialAsync` returns `already_licensed`
  (`ResultCodes.AlreadyLicensed`) without sending anything and leaves the stored state as it is, so a trial can never
  replace the device secret and lease of a paid license. Validate the saved key instead; to really start over, call
  `DeactivateAsync(key)` (or `ClearStoredState()` when the key is gone) first. When the store cannot be read,
  `StartTrialAsync` returns `store_unavailable` and sends nothing: a failed read is never taken for "nothing stored".
  The check runs under the client's device lock, so a validation running at the same time cannot slip in between.
* The server limits trials per network, per device and per day, and hardware ids are asserted by the client: a user
  who changes the machine id can start another trial within those limits. Treat a trial as a marketing tool, not a
  security boundary.
* `panel_too_old`: the seller's Velsigil server predates in-app trials; nothing else is affected.

---

## Offline leases

When the product has *offline lease hours* > 0, every successful validation returns a lease: a token
`base64url(JSON).base64url(Ed25519 signature)` bound to the product, the license, this device
(`hwidHash`) and an expiry `exp = min(now + offlineLeaseHours, licenseExpiresAt)`, plus `trial: true` for a
free-trial license (left out otherwise; fields the SDK does not know are ignored).

* The SDK stores the latest lease automatically, after checking that it verifies for this product and
  device. A validation answer whose lease is bound to another device or product is rejected as a whole
  (`invalid_response`), not accepted without the lease. A successful validation **without** a lease
  removes the stored one; signed denials with one of
  the binding cross-SDK codes (`VelsigilClient.LeaseRevokingCodes`: `invalid_key`, `license_expired`,
  `license_suspended`, `license_revoked`, `license_banned`, `device_revoked`, `device_verification_failed`,
  `device_limit_reached`, `device_not_activated`, `device_not_found`, `blacklisted`, `product_disabled`)
  delete it, so a revoked license cannot keep running offline after the app has talked to the server once.
  A successful `DeactivateAsync` (or `device_not_found`) deletes the lease and the device secret. Other
  signed failures (`product_paused`, `outdated_version`, `activation_rate_limited`, `clock_skew`, ...) keep it.
* `ValidateOffline()` accepts a lease only if the signature verifies with the pinned key, `typ` is
  `lease`, the product and the hardware-id hash match, and `now < exp`.
* `ValidateWithOfflineFallbackAsync()` falls back to the stored lease **only when the server is unavailable**:

  | Online result | Fallback? |
  |---|---|
  | `network_error`: no HTTP response (DNS, connection refused or reset, TLS, timeout) | yes |
  | Any **unsigned HTTP 5xx** (500, 502, 503, 504, other 5xx), whatever its body: a Velsigil error body (`internal_error`, the server is up but its database is not), a reverse proxy's HTML page (IIS ARR, Caddy, nginx while the app is down), an empty or garbled body. Reported as `internal_error`, or `network_error` for 502/503/504 without a Velsigil error body | yes |
  | Every signed answer (`license_revoked`, `license_expired`, `license_banned`, `product_paused`, ...) | no |
  | 4xx answers (`rate_limited` with `RetryAfter`, `validation_error`, `ip_blocked`, `unknown_product`, 404, ...), whatever their body | no |
  | `invalid_response` (bad or missing signature, unsigned 200, redirect, ...) | no |

  The HTTP status decides, not the code: `result.HttpStatus` is 500-599 and `result.Verified` is false. When the
  fallback applies and no lease is stored, the original online result (`network_error` or `internal_error`, with
  its `HttpStatus` and `RequestId`) is returned; a stored lease that is past its `exp` gives `lease_expired`, one
  that does not verify gives `lease_invalid`. `ValidateAsync()` never falls back and always reports the real
  error. Why an unsigned 5xx is safe to fall back on: anyone who can inject one can as well drop the connection,
  which already falls back, and the lease itself is signed, bound to this device and expires. Tampered answers
  stay `invalid_response`, never an offline pass, and a server that answers "revoked" is final.
* `now` is the local clock plus the offset learned from a signed `clock_skew` response. Winding the system
  clock back can stretch a lease up to its `exp`; this is an inherent limitation of offline licensing, so
  keep *offline lease hours* as short as your users can tolerate.

---

## Device secret persistence

On the first activation the server issues a **device secret** (32 random bytes) and stores only its
hash. The SDK persists it per product and sends it with every `validate`, `deactivate` and `download`
request (`update-check` takes no device data). If the secret is lost, the server records a
`device_secret_mismatch` event and, with *strict device binding*, refuses the device
(`device_verification_failed`) until it is reset. The secret is never exposed on results or in
`ToString()`; only `Activation.DeviceSecretIssued` tells you one was issued.

Stores (`Velsigil.Client.Storage`):

* **`FileStore`** (default: `FileStore.CreateDefault()`; `%LOCALAPPDATA%\Velsigil` on Windows,
  `~/.local/share/Velsigil` on Linux, the per-user application-support folder on macOS; pass an
  application name for a sub-folder, or any directory to `new FileStore(dir)`). One JSON file per product
  (`<productId>.json`). Writes go to a temporary file that is flushed and atomically renamed over the
  target. In the net8.0 build the directory it creates and every file get an ACL granting only the
  current user (Windows) or modes 0700/0600 (Linux/macOS). The netstandard2.0 build cannot set permissions
  and relies on the per-user location.
  *Upgrading from a pre-rename SDK:* `FileStore.CreateDefault(...)` also reads the old default folder
  (`%LOCALAPPDATA%\Veltrix`, `~/.local/share/Veltrix`, ... with the same application name) for a product
  that has no file in the new folder yet, so an installed app keeps its device secret and offline lease;
  the next write goes to the new folder (the old file is only removed when the state is cleared, e.g. on
  deactivation). For a custom location use `new FileStore(newDir, legacyDirectory: oldDir)`.
* **`MemoryStore`**: process lifetime only. For tests and short-lived tools.
* **Custom**: implement `IVelsigilStore` (four thread-safe methods) to keep the secret in DPAPI
  (`ProtectedData`), the macOS Keychain, libsecret, an encrypted settings file, etc.

If no per-user directory exists (some containers), the client falls back to `MemoryStore` and reports it
through `StoreErrorHandler`. Store exceptions are reported the same way and never fail a validation. A read that
throws is never taken for "nothing stored": `StartTrialAsync` then answers `store_unavailable`, and the client only
ever writes the fields an answer changes (a newly issued secret, the lease), never a state built on the failed read.

---

## Updates and downloads

```csharp
var check = await client.CheckUpdateAsync(currentVersion: "1.2.0");
if (check.Ok && check.Update is { UpdateAvailable: true } update)
{
    Console.WriteLine($"Version {update.LatestVersion} is available{(update.Mandatory ? " (required)" : "")}.");
    Console.WriteLine(update.Changelog);

    var grant = await client.GetDownloadAsync(licenseKey);          // latest published release
    if (grant.Ok && grant.Download is { } download)
    {
        var target = Path.Combine(Path.GetTempPath(), "MyApp-" + download.Version + ".zip");
        var file = await client.DownloadFileAsync(download, target, new Progress<long>(n => ShowProgress(n, download.Size)));
        if (file.Ok) LaunchInstaller(target);                      // size + SHA-256 verified
        else Console.WriteLine(file.Message);                      // integrity_mismatch, download_failed, io_error, network_error...
    }
}
```

* `ValidateAsync` also returns `result.Update` (when the product has releases) and enforces
  `minVersion` (`outdated_version`) when you pass `ValidateOptions.Version`.
* The download URL is a short-lived bearer link (see `DownloadInfo.ExpiresAt`): do not log or share it.
* `DownloadFileAsync` refuses non-https URLs (except loopback / `AllowInsecureHttp`), never follows
  redirects with the internal `HttpClient` (a redirect followed by an injected one is `download_failed`),
  writes to `.<name>.<random>.part` next to the destination and replaces the destination only after the
  byte count and SHA-256 match the signed grant.
* `DownloadInfo.FileName` is sanitised by the server, but still choose the local path yourself.

---

## Thread-safety and lifetime

* `VelsigilClient` is thread-safe. Create **one per product** and keep it for the lifetime of the app (it
  owns a pooled `HttpClient`; creating one per call wastes sockets). Dispose it on shutdown.
* Device-bound calls (`ValidateAsync`, `StartTrialAsync`, `DeactivateAsync`, `GetDownloadAsync` and
  `ClearStoredState`) are **serialized per client**: each one reads the stored state, sends its request and persists
  the answer before the next one starts. So concurrent first activations send the device secret the first one stored
  (instead of none, which the server counts as a secret mismatch), and the `already_licensed` check of a trial start
  cannot be overtaken by a validation. `CheckUpdateAsync` and `ValidateOffline` are not serialized. Do not call
  client methods from `StoreErrorHandler` or from a custom store (`ClearStoredState` would wait for itself).
* Results and models are immutable.
* `MemoryStore` and `FileStore` are thread-safe; `FileStore` serialises read-modify-write cycles
  process-wide and its atomic renames mean concurrent processes never see torn files (last writer wins).
* The learned clock offset is per client instance (updated atomically).
* All awaits inside the SDK use `ConfigureAwait(false)`; your own continuation returns to your
  synchronisation context as usual.

---

## Platform notes

### WinForms / WPF

```csharp
private async void MainForm_Load(object sender, EventArgs e)
{
    var result = await Licensing.Client.ValidateWithOfflineFallbackAsync(
        storedKey, new ValidateOptions { Version = Application.ProductVersion });

    if (!result.Ok)
    {
        MessageBox.Show(this, result.Message, "License", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        ShowActivationDialog();
        return;
    }
    exportMenuItem.Enabled = result.HasFeature("export");
    statusLabel.Text = result.Offline ? "Licensed (offline)" : "Licensed";
}
```

* Use `async` event handlers and `await`; never block the UI thread with `.Result`/`.Wait()`.
* For WPF use the same pattern in `Application.OnStartup` or the main window's `Loaded` handler.
* Store the license key the user typed with DPAPI (`ProtectedData.Protect(..., DataProtectionScope.CurrentUser)`)
  rather than in plain settings.

### Console apps, services and background workers

Validate at startup and periodically (e.g. every few hours) with `ValidateWithOfflineFallbackAsync`;
honour `RetryAfter` on `rate_limited`. Pass a `CancellationToken` tied to your host's shutdown. See
`examples/ConsoleExample`.

### Unity (Mono and IL2CPP)

* Use the **netstandard2.0** build (Api Compatibility Level ".NET Standard 2.1" or ".NET Framework").
  Either install with NuGetForUnity, or copy `Velsigil.Client.dll`, `BouncyCastle.Cryptography.dll`,
  `System.Text.Json.dll` and its dependencies (`System.Text.Encodings.Web`, `Microsoft.Bcl.AsyncInterfaces`,
  `System.Memory`, `System.Buffers`, `System.Runtime.CompilerServices.Unsafe`,
  `System.Threading.Tasks.Extensions`, `System.Numerics.Vectors`) from the netstandard2.0 package folders
  into `Assets/Plugins`.
* IL2CPP: the SDK uses no reflection-based serialisation. With aggressive managed code stripping add a
  `link.xml` preserving `Velsigil.Client` and `BouncyCastle.Cryptography`.
* Use a store under `Application.persistentDataPath`:
  `new FileStore(Path.Combine(Application.persistentDataPath, "velsigil"))`. An app that already shipped
  with the older `"veltrix"` folder keeps its state with
  `new FileStore(Path.Combine(Application.persistentDataPath, "velsigil"), Path.Combine(Application.persistentDataPath, "veltrix"))`.
* Hardware id: on Windows/macOS/Linux standalone players the default works (on IL2CPP Windows the
  registry is read through `Microsoft.Win32.Registry`). On mobile and consoles there is no machine id:
  set `HardwareId` to a stable per-install value (e.g. `SystemInfo.deviceUniqueIdentifier`).
* WebGL has no sockets: inject an `HttpClient` built on a custom `HttpMessageHandler` that wraps
  `UnityWebRequest`. Set `redirectLimit = 0` on the `UnityWebRequest` so it never follows a redirect, and
  set the returned `HttpResponseMessage.RequestMessage` to the request the handler received (not to a new
  message built from `UnityWebRequest.url`): see [Injecting an `HttpClient`](#injecting-an-httpclient).
* Awaiting from a `MonoBehaviour` resumes on the main thread (Unity's synchronisation context). Dispose the
  client in `OnApplicationQuit`.

### .NET Framework 4.7.2+

Reference the package normally; NuGet selects the netstandard2.0 build (SDK-style projects generate the
needed binding redirects automatically; for legacy `packages.config` projects enable
`AutoGenerateBindingRedirects`). .NET Framework 4.7+ uses the OS TLS defaults (TLS 1.2/1.3); do not pin
`ServicePointManager.SecurityProtocol` to older protocols.

---

## Hardening notes

* **Keep the public key in code.** It is what makes responses trustworthy. Never read it from a config
  file, the registry, an environment variable or the network in production builds.
* **The server is authoritative.** Licenses, devices, expiry, features and limits are enforced
  server-side; the SDK only reports verified decisions. Anything valuable (cloud features, downloads,
  premium content) should also be checked by your own backend.
* **Check results in more than one place.** Validate at startup and periodically, gate individual
  features with `result.HasFeature(...)` where they are used, and keep the `VelsigilResult` rather than a
  copied `bool`, so that a single patched branch does not unlock everything.
* **Treat `invalid_response` as an attack signal**, not as a network glitch.
* **Obfuscation helps, but it is not a security boundary.** Tools such as ConfuserEx, Dotfuscator or
  .NET Reactor and Native AOT raise the cost of patching the client, but anything running on the user's
  machine can ultimately be modified. Design so that a cracked client gains as little as possible.
* **Never log license keys, device secrets, lease tokens or download URLs.** The SDK itself logs nothing
  and keeps secrets out of `ToString()`.
* Keep TLS validation on. If you pin certificates, do it in an injected `HttpClient`'s handler, and set
  `AllowAutoRedirect = false` on that handler (required for every injected handler; a handler must not
  rewrite `RequestUri` either, see [Injecting an `HttpClient`](#injecting-an-httpclient)).

---

## Building and testing the SDK

In the csharp folder of the [SDK repository](https://github.com/VelSigil/velsigil-sdks). `global.json` pins the
.NET SDK version the committed `packages.lock.json` files were generated with:

```powershell
dotnet restore Velsigil.Client.sln --locked-mode                         # exact packages from the lock files, nuget.org only
dotnet build Velsigil.Client.sln -c Release --no-restore                 # netstandard2.0 + net8.0, warnings-as-errors for nullability
dotnet test  tests/Velsigil.Client.Tests -c Release                       # against the net8.0 build
dotnet test  tests/Velsigil.Client.Tests -c Release -p:VelsigilTestNetStandard=true   # against the netstandard2.0 build
dotnet pack  src/Velsigil.Client -c Release -o ./nupkgs                   # .nupkg + .snupkg (Source Link)
```

The tests classify every vector in the shared [`test-vectors.json`](https://github.com/VelSigil/velsigil-sdks/blob/main/test-vectors.json) (envelopes, leases,
hardware ids), reproduce the vector signatures with the vector seed, and drive the client against an
in-process mock server that signs responses with `keys.privateSeedBase64` plus a minimal real HTTP server
on 127.0.0.1: success, business failures, nonce / product / type mismatches, bad and missing signatures,
`clock_skew` with a successful retry, device-secret persistence and re-sending, 400/403/404/413/415/429/500,
gateway errors, timeouts, connection refused, cancellation, offline fallback with a fake clock (on transport
failures and on unsigned 500/502/503/504 answers with JSON, HTML or empty bodies, but not on 4xx or signed answers), verified
downloads and file-store permissions. Because the vector private keys are published, the SDK refuses both vector
public keys (`keys.publicKey`, `keys.wrongPublicKey`): the client unless the API URL is localhost, 127.0.0.1 or ::1,
the public `LeaseVerifier.Verify` always. The lease vectors are therefore checked through the SDK's internal
verification path (not part of the public API).

Before a release this SDK is also run against a **real** Velsigil server: activation, device-secret
persistence, offline lease, updates, verified download, clock skew, replay, suspension, invalid key and
deactivation.