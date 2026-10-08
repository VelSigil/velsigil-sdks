# velsigil-client (Python)

Official Python client for the **Velsigil** license server. It validates license keys,
binds them to the device, keeps an offline lease for when the server can't be reached, and
checks for and downloads updates. Every response that can report success is
**Ed25519-signed by your Velsigil server and verified by the SDK** before it is used.

- Python **3.10+** on Windows, macOS and Linux (releases are tested on 3.10 and 3.14)
- One runtime dependency: [`cryptography`](https://cryptography.io) (≥ 50.0.0, the first release with no published
  advisory). `PyNaCl` (≥ 1.6.2) is an optional fallback.
- HTTP uses the standard library (`urllib`), so there is no `requests` dependency

---

## Contents

1. [Installation](#installation)
2. [Quick start](#quick-start)
3. [How it works](#how-it-works)
4. [API reference](#api-reference)
5. [Result codes](#result-codes)
6. [In-app free trials](#in-app-free-trials)
7. [Offline leases](#offline-leases)
8. [Device secret persistence](#device-secret-persistence)
9. [Updates and downloads](#updates-and-downloads)
10. [Thread safety](#thread-safety)
11. [Hardening your integration](#hardening-your-integration)
12. [Development and tests](#development-and-tests)

---

## Installation

```bash
pip install velsigil-client            # cryptography backend
pip install "velsigil-client[nacl]"    # also install the PyNaCl fallback backend
```

From a checkout of the [SDK repository](https://github.com/VelSigil/velsigil-sdks): `pip install ./python`.

## Quick start

Get the **API URL**, **product id** and **public key** from the product's *Integration* tab in
the Velsigil panel.

```python
from velsigil_client import Code, FileStore, VelsigilClient, default_store_path

# Keep these as constants in your code (see "Hardening").
API_URL = "https://licenses.example.com"
PRODUCT_ID = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b"
PUBLIC_KEY = "<your product's public key>"  # panel: Products > your product > Integration

client = VelsigilClient(
    API_URL,
    PRODUCT_ID,
    PUBLIC_KEY,
    store=FileStore(default_store_path("MyApp")),  # persists device secret + offline lease
)

result = client.validate_with_offline_fallback(license_key, version="1.2.0")
if not result.ok:
    show_error(result.code, result.message)        # e.g. "license_expired"
    raise SystemExit(1)

if result.has_feature("export"):
    enable_export()
print("Plan:", result.license.plan, "- days left:", result.days_remaining())
```

There is a complete, runnable program in [`examples/basic.py`](https://github.com/VelSigil/velsigil-sdks/blob/main/python/examples/basic.py).
Set the constants `API_URL`, `PRODUCT_ID` and `PUBLIC_KEY` at its top to your product's values (they ship as
placeholders; until all three are set it prints a usage message and exits with code 2), then run:

```bash
python examples/basic.py --license-key VSG-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
python examples/basic.py --license-key ... --download ./downloads/app.zip
python examples/basic.py --license-key ... --deactivate
```

The values are constants in code, as in your application, not read from the environment. For local testing
only, the environment variables `VELSIGIL_API_URL`, `VELSIGIL_PRODUCT_ID` and `VELSIGIL_PUBLIC_KEY` override
them when the API URL is loopback (`localhost`, `127.0.0.1`, `[::1]`, for example a panel dev server on
`http://localhost:3000`); for any other server they are ignored.

## How it works

Each request carries the product id, a **fresh 32-byte random nonce** (base64url, 43 characters)
and a **unix timestamp** (local clock plus any offset learned from the server). Requests that
involve a license also send the **hardware id** and, once issued, the **device secret**.

The server answers HTTP 200 with a signed envelope `{ data, sig, kid }`. The SDK:

1. verifies the Ed25519 signature over the **exact ASCII bytes of `data`**, using only the public
   key you passed to the constructor (the `kid` field is ignored, so the key can't be swapped);
2. only then base64url-decodes and parses the JSON payload;
3. rejects the payload unless it echoes **this request's nonce**, **this product id** and the
   expected response type. That stops replayed or redirected responses;
4. returns a `VelsigilResult`. `ok=True` is only possible after all three steps succeed.

Unsigned HTTP errors (rate limiting, validation errors, blocked IPs, server errors) become
failure results and can **never** produce `ok=True`. If the server reports a signed
`clock_skew`, the SDK learns `offset = serverTime - localTime` and retries **once** with a new
nonce.

**Request methods never raise.** Licensing problems and transport failures come back as a result
with `ok=False` and a `code`. Exceptions are only raised by the constructor (bad configuration),
by `download_to_file` (file errors) and by the low-level verification helpers.

## API reference

### `VelsigilClient(api_url, product_id, public_key, *, ...)`

| Parameter | Default | Description |
|---|---|---|
| `api_url` | — | Server origin, e.g. `https://licenses.example.com`. `/api/client/v1` is appended unless already present; a sub-path such as `https://example.com/velsigil` also works. Must be `https://`. Plain `http://` is only accepted for `localhost`, `127.0.0.1` and `::1`. URLs containing credentials, a query string or a fragment are rejected. |
| `product_id` | — | Product UUID (case-insensitive). |
| `public_key` | — | Product Ed25519 public key: standard base64 of the raw 32-byte key. Missing padding is tolerated. The public test keys of the SDK test vectors are refused unless `api_url` is a loopback host. |
| `timeout` | `15.0` | Seconds per request. Applies to connect and read, plus an overall deadline for the response body. |
| `hwid` | auto | Overrides the hardware id (8–256 printable characters). The default comes from `get_hardware_id()`. |
| `store` | `MemoryStore()` | A `LicenseStore` that persists the device secret and offline lease per product. **Use `FileStore` (or your own store) in production.** |
| `allow_insecure_http` | `False` | Allows plain HTTP to non-local hosts. Never enable this in production. |
| `ssl_context` | system CAs | A custom `ssl.SSLContext`, for example one trusting a private CA. It must keep certificate and hostname verification on. |
| `user_agent` | `velsigil-client-python/<v>` | Overrides the `User-Agent` header. |
| `clock` | `time.time` | Callable that returns unix seconds. Useful for tests. |
| `crypto_backend` | `"auto"` | `"auto"` (cryptography, then PyNaCl), `"cryptography"` or `"nacl"`. |

The constructor raises `ConfigurationError` for invalid arguments, `CryptoBackendError` when no
Ed25519 backend is installed, and `HardwareIdError` when the machine id can't be read and no
`hwid` was given.

#### Methods

| Method | Description |
|---|---|
| `validate(license_key, version=None, device_name=None)` | Validates the key and activates this device on first use. On success it stores the newly issued device secret and the offline lease. On a definitive signed denial (see [Offline leases](#offline-leases)) it deletes the stored lease. |
| `start_trial(version=None, device_name=None, email=None)` | Starts a free trial of the product on this device without a license key (see [In-app free trials](#in-app-free-trials)). On `ok`, `result.trial_key` is the new key: store it, then use `validate()`. Stores the device secret and lease like `validate()`. `email` (up to 254 characters) is sent only when given. Returns `already_licensed` locally (nothing sent, nothing changed) when a device secret or lease is already stored for the product, and `store_unavailable` when the store cannot be read. |
| `deactivate(license_key)` | Releases this device's activation slot. On `ok` (or `device_not_found`) it clears the stored device secret and lease. |
| `check_update(current_version=None)` | Returns `result.update` (`UpdateInfo`). The code is `no_release` when nothing is published. |
| `get_download(license_key, version=None)` | Returns `result.download` (`DownloadInfo`) with a short-lived link. The device must already be activated when the product locks HWIDs. |
| `download_to_file(download, destination)` | Streams the release to `destination` and checks its **signed size and SHA-256** before moving it into place. Returns the absolute path; raises `DownloadError` on failure. |
| `validate_offline()` | Checks the stored lease without network access. Result has `offline=True`. |
| `validate_with_offline_fallback(license_key, version=None, device_name=None)` | Calls `validate()` first. **Only if it returns `network_error`** does it fall back to `validate_offline()`. |
| `clear_stored_state()` | Forgets the stored device secret and lease for this product. |
| `VelsigilClient.get_hardware_id()` *(static)* | This machine's HWID (see below). |

Properties: `api_url` (normalised), `product_id`, `hwid`, `clock_offset` (seconds learned from a
signed `clock_skew` response), `key_id` (diagnostics only).

### `VelsigilResult`

| Member | Description |
|---|---|
| `ok: bool` | `True` only for a verified success. |
| `code: str` | `"ok"` or a failure code (see [Result codes](#result-codes)). |
| `message: str` | Server message for signed responses; fixed SDK text otherwise. Unsigned server text is never echoed. |
| `license: LicenseInfo \| None` | `id`, `plan`, `status`, `features`, `expires_at`, `max_devices`, `devices_used`, `created_at`, `has_feature(name)`. On a failed result (`license_revoked`, `license_expired`, ...) `license.features` is informational only (servers since 2026-10-06 send it empty) and `license.has_feature()` is `False`; gate features with `result.has_feature()`. |
| `activation: ActivationInfo \| None` | `id`, `status`, `first_seen_at`, `device_secret_issued`. The secret itself is never exposed. |
| `lease: LeaseInfo \| None` | `token`, `expires_at`. |
| `update: UpdateInfo \| None` | `latest_version`, `min_version`, `update_available`, `mandatory`, `changelog`. |
| `download: DownloadInfo \| None` | `url` (hidden from `repr`), `expires_at`, `file_name`, `size`, `sha256`, `version`. |
| `request_id: str \| None` | Server request id. Quote it in support requests. |
| `offline: bool` | `True` when the result comes from the stored lease. |
| `server_time`, `http_status`, `retry_after` | Diagnostics. `retry_after` is set for `rate_limited`. |
| `trial_key: str \| None` | The key of the trial `start_trial()` just started (`ok` results of `start_trial` only; hidden from `repr`). Sent once: store it immediately. |
| `has_feature(name)` | `True` only if `ok` and the license includes `name`. |
| `features` | Tuple of features; empty unless `ok`. |
| `expires_at`, `expires_at_datetime`, `is_lifetime` | License expiry as unix seconds or an aware UTC datetime. `None` means lifetime or unknown. |
| `is_trial` | `True` for a free-trial license (the optional signed `trial` field, online and offline; also `license.is_trial`). Pair it with `days_remaining()` for "Trial: N days left" and a "Buy now" link; a purchase with the same e-mail keeps the key and turns it `False` at the next online validation. |
| `trial_ref` | The trial's conversion reference (servers since 2026-10-06; also `license.trial_ref`): set on online results for a free trial a purchase can still convert, also on `license_expired`; `None` otherwise and offline. Put it in your "Buy now" link with `result.with_trial_ref(buy_url)` (or `velsigil_client.with_trial_ref(url, ref)`): it appends `velsigil_trial=<ref>` (a Stripe Payment Link gets `client_reference_id=`), and the purchase then converts THIS trial (same key) whatever e-mail address the buyer pays with. Opaque; never store it. |
| `seconds_remaining(now=None)`, `days_remaining(now=None)`, `is_expired(now=None)` | Expiry helpers; remaining time never goes below 0. `seconds_remaining` and `is_expired` default to the local clock. `days_remaining` rounds **up** and, without `now`, measures at the result's own time (the signed `server_time` online, the time of the check offline, kept in `reference_time`): an N-day trial shows N right after `start_trial()`, 1 on its last day and 0 once expired. The same rule in every Velsigil SDK. |

All timestamps are unix seconds in UTC, exactly as signed by the server.

### Stores

| Class | Description |
|---|---|
| `LicenseStore` | Abstract interface: `load(product_id) -> StoredState`, `save(product_id, state)`, `delete(product_id)`. Implementations must be thread-safe. |
| `MemoryStore()` | Keeps state in the process. It is lost on exit. |
| `FileStore(path)` | JSON file holding every product. Atomic writes (temp file, then fsync, then `os.replace`). On POSIX the directory is `0700` and the file `0600`. A corrupt file is treated as empty. Every `FileStore` on the same path in a process shares one lock, so several instances (for example one per product on `default_store_path()`) never lose each other's updates; sharing one instance is still simplest. Separate processes are not coordinated (see [Thread safety](#thread-safety)). |
| `default_store_path(app_name)` | Per-user path: `%LOCALAPPDATA%\<app>\Velsigil\license.json` on Windows, `~/Library/Application Support/<app>/Velsigil/license.json` on macOS, `$XDG_DATA_HOME/<app>/velsigil/license.json` on Linux. Upgrading from an SDK released under the former product name (Veltrix): until the first write, a `FileStore` at this path reads the file left in the old `Veltrix`/`veltrix` directory, so installed apps keep their device secret and offline lease. |
| `StoredState(device_secret=None, lease_token=None)` | Immutable value. Its `repr` hides the secret. |

### Hardware id

`hwid = sha256_hex("vx-hwid-v1:" + machine_id.strip().lower())`. The machine id comes from:

- **Windows**: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, read from the 64-bit registry view
- **Linux**: `/etc/machine-id`, then `/var/lib/dbus/machine-id` (a file that is empty or holds systemd's placeholder
  `uninitialized` is skipped)
- **macOS**: `IOPlatformUUID` from `/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice`, run without a shell

`hwid_from_machine_id(raw)` exposes the derivation, and `get_hardware_id()` /
`velsigil_client.hwid.read_machine_id()` expose the platform lookup. Every Velsigil SDK computes the same value. If you pass your own
`hwid`, derive it from something stable; hashing it with `hwid_from_machine_id` is a good idea.

### Low-level helpers

`Ed25519Verifier(public_key)`, `open_envelope(verifier, envelope, expected_nonce, expected_product_id, expected_type, expected_hwid=None)`,
`verify_lease(verifier, token, product_id, hwid, now)` and `key_id_for(public_key)`. These raise
`EnvelopeError` / `LeaseError`, whose `.reason` is one of `invalid_signature`, `nonce_mismatch`,
`product_mismatch`, `type_mismatch`, `hwid_mismatch`, `expired` or `malformed`. `expected_type` is
required: pass the endpoint the request went to (`validate`, `deactivate`, `update_check`,
`download` or `trial`). The server also signs `ok: true` answers to `update_check`, which needs no license, so
the type must always be checked; `None` or an empty value raises `ValueError`. With `expected_hwid`
(the hwid the request was sent with), a signed lease or `activation.hwidHash` bound to another
device raises `hwid_mismatch`.

These helpers **refuse the two public keys of the SDK test vectors** (`keys.publicKey` and
`keys.wrongPublicKey` in `test-vectors.json`, whose private keys are published there) on every host: they
have no server URL, so unlike `VelsigilClient` they make no loopback exception. `Ed25519Verifier`,
`key_id_for` and `velsigil_client.crypto.decode_public_key` refuse the key itself (in any accepted
spelling), `open_envelope` and `verify_lease` a verifier that holds it, before anything else is checked.
The refusal is a `ConfigurationError` (code `invalid_configuration`, the error of an invalid key) with the
same message as the client constructor's. There is no opt-out argument; the SDK's own test-vector suite
uses internal, unguarded equivalents.

### Exceptions

`VelsigilError` is the base class of `ConfigurationError` (also a `ValueError`), `CryptoBackendError`,
`HardwareIdError`, `StoreError`, `DownloadError`, `EnvelopeError` and `LeaseError`.

`ConfigurationError.code` is `"invalid_configuration"` and `DownloadError.code` is one of
`download_failed` (non-200 status, e.g. an expired link answering 410, or a URL rejected by the HTTPS
policy), `integrity_mismatch` (size or SHA-256 differs from the signed values; the partial file is
deleted), `io_error` (the destination could not be written), `network_error` (transport failure) or
`validation_error` (not a `DownloadInfo`). These are the cross-SDK codes of SPEC section 14.

## Result codes

| Code | Origin | Meaning / suggested handling |
|---|---|---|
| `ok` | signed | Success. |
| `invalid_key` | signed | Key not found for this product. |
| `license_expired` · `license_suspended` · `license_revoked` · `license_banned` | signed | License state does not allow use. Show the message; renewal or support. |
| `device_limit_reached` | signed | All device slots in use. The customer can free one in the portal. |
| `device_revoked` | signed | This device was revoked by the seller. |
| `device_verification_failed` | signed | Device secret mismatch on a strict product. Reset devices in the portal. |
| `device_not_found` | signed | `deactivate`: this device is not registered. |
| `device_not_activated` | signed | `get_download`: validate (activate) first. |
| `activation_rate_limited` · `activation_cooldown` · `activations_disabled` | signed | New activations are temporarily not possible. |
| `downloads_disabled` · `release_not_found` · `no_release` | signed | Download or update not available. |
| `blacklisted` | signed | Device, IP or customer is blocked. |
| `outdated_version` | signed | Version below the product minimum. `result.update` tells you what to install. |
| `product_paused` · `product_disabled` | signed | Product unavailable (the message is set by the seller). |
| `clock_skew` | signed | Clock still too far off after the automatic retry. |
| `replay_detected` | signed | Nonce reuse detected by the server (should not happen with this SDK). |
| `trial_already_used` | signed | This device already used a free trial of the product. Offer to buy; a stored lease is kept. |
| `trial_unavailable` | signed | `start_trial`: the seller offers no in-app trial right now (switched off, today's limit, too many trials from this network). Show the message. |
| `trial_email_required` · `trial_email_invalid` · `trial_email_not_accepted` | signed | `start_trial`: the offer confirms an e-mail address first: ask for one, a valid one, or a personal / work address (throwaway domains are refused). |
| `trial_confirmation_sent` | signed | `start_trial`: not an error of the user. A confirmation link was e-mailed; the key arrives by e-mail and is entered like any key. The same answer for every valid address. |
| `validation_error` | unsigned 400 | Request rejected. Also returned locally, without a request, for an empty or oversized key, version or device name. |
| `ip_blocked` | unsigned 403 | Network temporarily blocked. |
| `unknown_product` | unsigned 404 | Wrong product id or server. |
| `rate_limited` | unsigned 429 | Back off. `result.retry_after` holds seconds when sent. |
| `internal_error` | unsigned 5xx | Server error (also 502/503/504 **with** a Velsigil error body). |
| `payload_too_large` · `unsupported_media_type` | unsigned 413/415 | Should not happen with this SDK (also mapped from a bodiless 413/415, e.g. from a proxy). |
| `network_error` | SDK | DNS, connect, TLS or timeout failure, or an HTTP 502/503/504 without a Velsigil error body (gateway can't reach the server). This is the **only** code that triggers the offline fallback. |
| `invalid_response` | SDK | Signature invalid, nonce/product/type mismatch (the signed `type` must match the endpoint), a signed lease or `activation.hwidHash` that belongs to another device (the request was rewritten in transit; nothing from the response is stored), malformed or oversized body, unsigned success, unexpected status (including redirects, which are never followed). Treat it as a failure. |
| `no_lease` · `lease_expired` · `lease_invalid` | SDK | Offline validation: nothing stored, lease past `exp`, or lease rejected (signature, type, product or HWID). |
| `invalid_configuration` | SDK | `ConfigurationError.code` (the constructor raises). |
| `download_failed` · `integrity_mismatch` · `io_error` | SDK | `DownloadError.code` from `download_to_file()`. |
| `panel_too_old` | SDK | `start_trial`: the Velsigil server has no in-app trial endpoint yet (HTTP 404 with the Velsigil error code `not_found`). The seller must update the panel. |
| `already_licensed` | SDK | `start_trial`: this device already holds a license for the product (a device secret or offline lease is stored), and a trial must not replace it. Nothing was sent and the stored state is unchanged. Validate the saved key instead, or call `deactivate(key)` / `clear_stored_state()` first. |
| `store_unavailable` | SDK | `start_trial`: the store could not be read (for example a locked file or keyring), so the SDK cannot tell whether this device already holds a license (`Code.STORE_UNAVAILABLE`). Nothing was sent; try again later. |

The constants live in `velsigil_client.Code` (for example `Code.LICENSE_EXPIRED`).

Unsigned errors are mapped the same way in every Velsigil SDK: a known code in a Velsigil error body
(`{"error": {"code": ...}}`) wins; otherwise 400 → `validation_error`, 413 → `payload_too_large`,
415 → `unsupported_media_type`, 429 → `rate_limited`, 502/503/504 → `network_error` without a Velsigil
error body or `internal_error` with one, other 5xx → `internal_error`, anything else →
`invalid_response`. The unsigned `message` text is never shown.

## In-app free trials

When the seller turns on **In your app** in the product's trial offer (panel → Products → your product →
Trials), an app that has no license key yet can start a free trial for its device:

```python
saved_key = load_saved_license_key()  # your own settings storage
if saved_key is None:
    trial = client.start_trial(version="1.2.0", device_name=socket.gethostname())
    if trial.ok and trial.trial_key:
        save_license_key(trial.trial_key)  # FIRST: the server can never send this key again
        show_trial_banner(trial.days_remaining())  # trial.is_trial is True
    elif trial.code == Code.TRIAL_EMAIL_REQUIRED:
        pass  # the offer confirms an e-mail address first: ask for it, then start_trial(email=...)
    else:
        show_message(trial.message)  # trial_confirmation_sent, trial_already_used, trial_unavailable, panel_too_old, ...
```

- **One trial per device and product.** A device that already had a trial of the product (from the app, the
  seller's website or the customer portal) gets `trial_already_used`; offer to buy.
- **The trial key is an ordinary license key** on the seller's trial plan. Store it like a key the user typed and
  use `validate()` from then on. Show it in your About / License screen: the customer needs it for the customer
  portal, to move the trial to another device and for support. A purchase converts the same key (the seller's
  staff, or a purchase with the e-mail address the trial was confirmed with).
- **E-mail confirmation (optional, the seller's choice).** Then the first answer is `trial_confirmation_sent`; the
  customer confirms the address from the e-mail, gets the key on the confirmation page and by e-mail, and enters it
  in the app (`validate()`).
- The SDK stores the trial's device secret and offline lease like after a validation, never the key.
- **Never over an existing license.** When a device secret or an offline lease is already stored for the product
  (the device was activated with a key, paid or trial), `start_trial()` returns `already_licensed`
  (`Code.ALREADY_LICENSED`) without sending anything and leaves the stored state as it is, so a trial can never
  replace the device secret and lease of a paid license. Validate the saved key instead; to really start over, call
  `deactivate(key)` (or `clear_stored_state()` when the key is gone) first. When the store cannot be read,
  `start_trial()` returns `store_unavailable` and sends nothing: a failed read is never taken for "nothing stored".
- The server limits trials per network, per device and per day, and HWIDs are asserted by the client: a user who
  changes the machine id can start another trial within those limits. Treat a trial as a marketing tool, not a
  security boundary.
- `panel_too_old`: the seller's Velsigil server predates in-app trials; nothing else is affected.

## Offline leases

When the product's *offline lease hours* is above 0, a successful `validate()` (or `start_trial()`) returns a signed
lease `base64url(JSON).base64url(signature)` bound to the product, this device's HWID hash and an
expiry `exp = min(now + offlineLeaseHours, licenseExpiresAt)` (plus `trial: true` for a free-trial
license; fields the SDK does not know are ignored). The SDK verifies the lease and then stores it. A `validate()` answer whose lease is bound to another device or product is
rejected as a whole (`invalid_response`), not accepted without the lease.

- `validate_offline()` accepts the stored lease only if the signature is valid, `typ` is
  `"lease"`, product id and HWID hash match, and `now < exp`.
- `validate_with_offline_fallback()` uses the lease **only for `network_error`**. A business
  failure, rate limiting or an invalid or unsigned response never falls back, because an
  attacker who can tamper with responses must not be able to switch the app to offline mode.
- A signed, definitive denial **deletes** the stored lease. The set is the same in every Velsigil
  SDK (`velsigil_client.LEASE_REVOKING_CODES`): `invalid_key`, `license_expired`,
  `license_suspended`, `license_revoked`, `license_banned`, `device_revoked`,
  `device_verification_failed`, `device_limit_reached`, `device_not_activated`,
  `device_not_found`, `blacklisted`, `product_disabled`. A success without a lease (offline leases
  disabled) and a successful `deactivate()` also clear it. Any other signed failure
  (`product_paused`, `outdated_version`, `activation_rate_limited`, `clock_skew`,
  `replay_detected`, ...) leaves it alone.
- Known limitation: offline validation trusts the local clock (plus any offset learned online).
  Someone who winds the clock back can extend offline use up to the lease's own expiry. Keep
  lease hours short.

## Device secret persistence

On the first activation the server issues a **device secret** (`activation.deviceSecret`). The
SDK stores it in the configured store, keyed by product id, and sends it with every later
`validate`, `deactivate` and `get_download` call. The server keeps only a hash of it.

- **Use a persistent store.** With the default `MemoryStore` the secret is lost on restart. The
  server then counts a secret mismatch, and products with *strict device binding* refuse the
  device (`device_verification_failed`) until the customer resets their devices.
- `FileStore` writes atomically with owner-only permissions on POSIX. On Windows,
  `default_store_path()` places the file under `%LOCALAPPDATA%`, which only the user (and
  administrators) can read. Implement `LicenseStore` to keep it in the OS keychain or your own
  encrypted settings.
- If saving fails, the SDK logs a warning and keeps the state in memory for the rest of the
  process.
- If loading fails, the SDK logs a warning and keeps working from the last state it read or wrote,
  but never treats the failed read as "nothing stored": `start_trial()` refuses with
  `store_unavailable`, and an answer is merged into a fresh read of the store. While the store stays
  unreadable nothing is written except a device secret the server just issued.
- `deactivate()` (success) and `clear_stored_state()` remove the secret.

## Updates and downloads

```python
update = client.check_update("1.2.0").update
if update and update.update_available:
    link = client.get_download(license_key, update.latest_version)
    if link.ok:
        path = client.download_to_file(link.download, "downloads/app.zip")  # raises DownloadError
```

`get_download` returns a signed link that expires within minutes, plus the file's signed
`size` and `sha256`. `download_to_file` streams to a temporary file next to the destination. It
aborts once the download exceeds the signed size, compares the SHA-256 in constant time, and only
then renames the file into place. A tampered or truncated download therefore never appears at
the destination path. Links must be `https://` (or local `http://`); redirects are not followed.
`update.mandatory` and `outdated_version` tell you when to block the old version.

## Thread safety

A `VelsigilClient` can be shared between threads:

- `validate`, `start_trial`, `deactivate`, `get_download` and `clear_stored_state` are serialised
  per client, because they read and update the device secret and lease. This also guarantees that
  concurrent first activations don't race for the device secret, and that the `already_licensed`
  check of `start_trial` and its request form one step.
- `check_update` and `validate_offline` run concurrently.
- The clock offset and cached state are protected by a lock. `MemoryStore` and `FileStore` are
  thread-safe; `FileStore` objects on the same path share one lock per process.
- Use **one `VelsigilClient` per product** and, ideally, one `FileStore` per file. Separate
  **processes** sharing one `FileStore` file are not coordinated: each write replaces the whole
  file, which holds every product, so a write for one product can drop another product's
  concurrent update. Let one process own the file, or give each product its own file
  (`FileStore(default_store_path("MyApp", "license-<product>.json"))`).

## Hardening your integration

Client-side licensing raises the cost of piracy; it can't make it impossible. Plan with that in
mind:

- **Keep the public key in code** as a constant. Don't load it from a config file, an environment
  variable or the network, or a user can swap in their own key and sign their own "valid"
  responses. Rotating the signing key in the panel requires shipping a new build.
- **Check results in several places**, not with one `if` at start-up that a patch can remove.
  Re-check `result.ok` and `has_feature()` where features are used, and re-validate
  periodically (for example every few hours or on important actions).
- **Server-side enforcement is authoritative.** Revocation, device limits, expiry and downloads
  are enforced by the server. Anything valuable (content, cloud features, updates) should be
  delivered only after a successful server check, ideally gated by the server.
- **Obfuscation helps but is not a security boundary.** Python bytecode is easy to inspect, so
  packers and obfuscators only slow an attacker down.
- Never disable HTTPS (`allow_insecure_http`) or certificate verification in production builds.
- Treat every `ok=False`, and especially `invalid_response`, as "not licensed". Don't add a
  "fail open" path.
- The SDK never logs license keys, device secrets, lease tokens or download URLs, and the
  `repr` of its objects hides them. Keep it that way in your own logging: show users at most the
  last 5 characters of a key.

## Development and tests

In the [SDK repository](https://github.com/VelSigil/velsigil-sdks), from this folder:

```bash
python -m pip install "cryptography>=50.0.0"
python -m unittest discover -s tests -t . -v
```

- `tests/test_vectors.py` classifies every envelope, lease and HWID vector in the shared
  `test-vectors.json` (one folder up) with each installed backend. It also proves that the mock
  server encodes and signs byte-for-byte like the real server. The private keys of the vectors are
  published there, so `VelsigilClient` refuses their two public keys (`ConfigurationError`) unless
  `api_url` is a loopback host (`localhost`, `127.0.0.1` or `::1`), and the public low-level helpers
  refuse them on every host; the suite verifies the vectors through the SDK's internal, unguarded path
  and checks both refusals.
- `tests/test_client.py` drives the client against `tests/mock_server.py`, a threaded local HTTP
  server that signs with the vector key. It covers success, business failure, nonce, product and
  type mismatch, bad signatures, unsigned success, clock skew with a single retry, device secret
  persistence and re-sending, 400/403/404/429/500/502/503, redirects, oversized bodies, timeouts,
  connection refused, offline fallback with a fake clock, deactivation, updates, verified
  downloads, concurrency and log hygiene.

Set `VELSIGIL_TEST_VECTORS` to use a vectors file at another location.

Before a release this SDK is also run against a **real** Velsigil server (activation,
device-secret persistence, offline lease, updates, verified download, clock skew, replay,
suspension, invalid key, deactivation).