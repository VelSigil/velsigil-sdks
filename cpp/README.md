# Velsigil C++ SDK (`velsigil::Client`)

C++17 client for the Velsigil license server. It validates and activates licenses, binds them to the
device, keeps working offline with signed leases, checks for updates and downloads releases with
integrity verification.

Every server response is an **Ed25519-signed envelope**. The SDK verifies the signature over the exact
bytes it received with the public key compiled into your application *before* parsing anything,
checks that the response echoes this request's nonce and your product id, and fails closed on
anything else. Public member functions never throw: every outcome is a result object.

- Dependencies: [libcurl](https://curl.se/libcurl/) (HTTPS), [libsodium](https://libsodium.org) (Ed25519,
  SHA-256, CSPRNG), [nlohmann/json](https://github.com/nlohmann/json) (private, header-only).
- Platforms: Windows 10+ (MSVC 2019+, MinGW-w64), Linux (GCC 9+, Clang 10+), macOS 10.15+ (Apple Clang 12+;
  `std::filesystem` needs a 10.15 deployment target).
- CMake 3.16+. The library is always built as a **static** library (`velsigil::velsigil`).

## Contents

1. [Build and install](#build-and-install)
2. [CMake integration](#cmake-integration)
3. [Quick start](#quick-start)
4. [API reference](#api-reference)
5. [Result codes](#result-codes)
6. [In-app free trials](#in-app-free-trials)
7. [Offline leases](#offline-leases)
8. [Device secret persistence](#device-secret-persistence)
9. [Updates and downloads](#updates-and-downloads)
10. [Thread-safety](#thread-safety)
11. [Hardening notes](#hardening-notes)
12. [Testing](#testing)

## Build and install

Get the source either from a release of the [SDK repository](https://github.com/VelSigil/velsigil-sdks)
(`velsigil-cpp-<version>.tar.gz`, with its SHA-256 in `SHA256SUMS` and a GitHub build-provenance
attestation; see [VERIFYING.md](https://github.com/VelSigil/velsigil-sdks/blob/main/docs/VERIFYING.md)) or
from the repository's `cpp` folder. The commands below run in that folder (the tarball's top-level folder).

### vcpkg (recommended, all platforms)

The SDK ships a `vcpkg.json` manifest (`curl`, `libsodium`, `nlohmann-json`) with a `builtin-baseline`
(a pinned vcpkg commit, so every build resolves the same dependency versions), and vcpkg installs the
dependencies automatically during configuration:

```sh
git clone https://github.com/microsoft/vcpkg "$HOME/vcpkg" && "$HOME/vcpkg/bootstrap-vcpkg.sh"
export VCPKG_ROOT="$HOME/vcpkg"

cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --prefix ./dist      # optional: headers, library, CMake package
```

`CMakePresets.json` wraps the same steps: `cmake --preset vcpkg && cmake --build --preset vcpkg && ctest --preset vcpkg`.
The vcpkg clone must contain the baseline commit (a fresh clone or `git pull` does).

### Windows: fully static binaries (`x64-windows-static`)

To ship a single `.exe` without curl/sodium DLLs and with the static CRT:

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
      -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

(or `cmake --preset vcpkg-windows-static`). With a `*-static` triplet the SDK switches
`CMAKE_MSVC_RUNTIME_LIBRARY` to `MultiThreaded$<$<CONFIG:Debug>:Debug>` (`/MT`); your application must use the
same runtime (set the same variable before declaring your targets). vcpkg's curl uses Schannel on Windows,
so certificate validation uses the Windows certificate store.

### Linux (system packages)

```sh
# Debian / Ubuntu
sudo apt install build-essential cmake pkg-config libcurl4-openssl-dev libsodium-dev nlohmann-json3-dev
# Fedora
sudo dnf install gcc-c++ cmake pkgconf-pkg-config libcurl-devel libsodium-devel json-devel

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build && ctest --test-dir build --output-on-failure
```

libsodium is located with `find_package(unofficial-sodium CONFIG)` (vcpkg) and falls back to
`pkg-config libsodium` (distributions).

### macOS (Homebrew)

```sh
brew install cmake pkg-config libsodium nlohmann-json   # libcurl ships with macOS
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
```

### CMake options

| Option | Default (top-level / subproject) | Meaning |
|---|---|---|
| `VX_BUILD_EXAMPLES` | ON / OFF | build `examples/basic.cpp` |
| `VX_BUILD_TESTS` | ON / OFF | build and register the CTest suites |
| `VX_BUILD_HTTP_TESTS` | OFF | also run libcurl tests against `tests/mock_server/mock_server.py` (Python 3 + `cryptography`) |
| `VX_INSTALL` | ON / OFF | install rules + `velsigilConfig.cmake` package |
| `VX_TEST_VECTORS` | `test-vectors.json` next to `CMakeLists.txt` (release tarball), else `../test-vectors.json` (repository) | path of the shared protocol vectors |

## CMake integration

In every variant the dependencies (libcurl, libsodium, nlohmann/json) must be findable by your project, for
example through your own `vcpkg.json` (`curl`, `libsodium`, `nlohmann-json`) and the vcpkg toolchain, or the
system packages above.

**FetchContent** from a release tarball, pinned by its SHA-256 (copy the hash from the release's `SHA256SUMS`
after verifying it, see VERIFYING.md):

```cmake
include(FetchContent)
FetchContent_Declare(velsigil
  URL      https://github.com/VelSigil/velsigil-sdks/releases/download/v1.0.0/velsigil-cpp-1.0.0.tar.gz
  URL_HASH SHA256=<sha256 from SHA256SUMS>)
FetchContent_MakeAvailable(velsigil)                # examples/tests/install are off for subprojects
target_link_libraries(my_app PRIVATE velsigil::velsigil)
```

**add_subdirectory** of a vendored copy works the same way:

```cmake
add_subdirectory(third_party/velsigil-cpp)
target_link_libraries(my_app PRIVATE velsigil::velsigil)
```

**find_package** after `cmake --install`:

```cmake
find_package(velsigil 1.0 CONFIG REQUIRED)          # also finds Threads, CURL and libsodium
target_link_libraries(my_app PRIVATE velsigil::velsigil)
```

`tests/package_consumer` is a minimal application that CI builds both ways (find_package against an installed
copy, FetchContent from the release tarball). The public header (`#include <velsigil/client.hpp>`) only uses the
standard library; curl, libsodium and nlohmann/json are private link dependencies.

**Upgrading from the former product name (Veltrix):** replace `#include <veltrix/client.hpp>` with
`#include <velsigil/client.hpp>`, the namespace `veltrix::` with `velsigil::`, and the CMake package /
target `veltrix` / `veltrix::veltrix` with `velsigil` / `velsigil::velsigil`. The protocol, the `vx-hwid-v1:`
hardware id and existing on-device stores are unchanged (see `FileStore` below), so installed applications
keep their activation.
## Quick start

```cpp
#include <velsigil/client.hpp>
#include <iostream>
#include <memory>
#include <string>

std::string load_license_key();  // your code
void enable_export();            // your code

int main() {
  velsigil::ClientOptions options;
  // Persist the device secret and the offline lease between runs (owner-only file, atomic writes).
  options.store = std::make_shared<velsigil::FileStore>(velsigil::FileStore::default_path("MyApp"));

  velsigil::Client client("https://licenses.example.com",            // your Velsigil server
                         "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b",    // your product id
                         "<your product's public key>",             // standard base64, compiled in
                         options);

  const std::string license_key = load_license_key();  // from your activation UI / settings
  velsigil::ValidateOptions validate_options;
  validate_options.version = "1.2.0";
  const velsigil::ValidationResult result = client.validate_with_offline_fallback(license_key, validate_options);
  if (!result.ok) {
    std::cerr << "License check failed: " << result.code << " - " << result.message << '\n';
    return 1;
  }
  if (result.has_feature("export")) enable_export();
  if (const auto days = result.days_until_expiry()) std::cout << "License expires in " << *days << " days\n";
}
```

The product id, public key and API URL are on the product's **Integration** tab in the Velsigil panel
(Products > your product > Integration).
`examples/basic.cpp` is a complete, runnable program (validation, feature gate, update check, verified
download). Its `kApiUrl`, `kProductId` and `kPublicKey` are compiled-in constants holding placeholders: replace
them with your product's values and rebuild. While a placeholder is still in place it prints a short usage
message and exits with code 2; it never reads these values from the environment. For local testing only it also
takes `<api-url> [<product id> <public key>]` on the command line, and only when that API URL is on `localhost`,
`127.0.0.1` or `[::1]` (any other URL is refused with exit code 2); `tests/mock_server/README.md` shows how to run
it against the bundled mock server.

## API reference

All symbols live in namespace `velsigil` (`#include <velsigil/client.hpp>`).

### `Client`

```cpp
Client(std::string api_url, std::string product_id, std::string public_key_base64, ClientOptions options = {});
```

| Parameter | Description |
|---|---|
| `api_url` | Origin of your Velsigil server, e.g. `https://licenses.example.com` (a URL ending in `/api/client/v1` is accepted too). Must be `https://`; plain `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]` unless `allow_insecure_http` is set. URLs with credentials, query strings or fragments are rejected. |
| `product_id` | Product UUID. |
| `public_key_base64` | The product's raw 32-byte Ed25519 public key, standard base64 (padding optional). This key is the only key the SDK trusts; the envelope `kid` is never used to choose a key. The public keys of the SDK test vectors are refused like an invalid key unless the host of `api_url` is `localhost`, `127.0.0.1` or `[::1]` (see [Testing](#testing)). |
| `options` | See `ClientOptions`. |

The constructor never throws. Invalid arguments are recorded: `is_configured()` returns false,
`configuration_error()` explains why, and every call returns `invalid_configuration`.

| Member | Description |
|---|---|
| `ValidationResult validate(const std::string& license_key, const ValidateOptions& = {})` | Validates the license for this device; the first successful call activates the device. `ValidateOptions{ version, device_name }` are optional. |
| `ValidationResult start_trial(const StartTrialOptions& = {})` | Starts a free trial of the product on this device without a license key (see [In-app free trials](#in-app-free-trials)). On `ok`, `result.trial_key` is the new key: store it, then use `validate`. Stores the device secret and lease like `validate`. `StartTrialOptions{ version, device_name, email }` (the e-mail, up to 254 characters, is sent only when set). Returns `already_licensed` locally (nothing sent, nothing changed) when a device secret or lease is already stored for the product, and `store_unavailable` when the store cannot be read (`IStore::get` throws). |
| `ValidationResult deactivate(const std::string& license_key)` | Releases this device's activation. On success the stored lease and device secret are removed. |
| `ValidationResult check_update(const std::string& current_version)` | Latest published release in `result.update` (`no_release` when nothing is published). Sends no license data. |
| `ValidationResult get_download(const std::string& license_key, const std::optional<std::string>& version = std::nullopt)` | Short-lived download descriptor in `result.download`. Requires an already activated device; never activates one. A grant whose URL violates the HTTPS policy (see `api_url`) is rejected as `invalid_response`, with no descriptor and nothing stored. |
| `ValidationResult validate_offline()` | Verifies the stored offline lease without network access (`result.offline == true`). |
| `ValidationResult validate_with_offline_fallback(const std::string& license_key, const ValidateOptions& = {})` | Online validation first; the stored lease is used **only** when the server is unavailable: no HTTP response (`network_error`) or an unsigned HTTP 5xx whatever its body (`internal_error`, or `network_error` for a 502/503/504 without a Velsigil error body), e.g. while the server's database is down. Signed answers (`license_revoked`, ...), 4xx answers (`rate_limited`, `validation_error`, ...) and `invalid_response` are never overridden by the lease. When it falls back, the result is that of `validate_offline()` (`offline == true`): `ok`, or `lease_expired` / `lease_invalid` for a stored lease that cannot be used; only when no lease is stored is the original online result returned. A fallback result carries the failed online attempt's `retry_after`. See [When the offline fallback applies](#when-the-offline-fallback-applies). |
| `DownloadFileResult download_release(const DownloadInfo&, const std::filesystem::path& destination)` | Streams the release to a temporary file next to `destination`, verifies size and SHA-256 against the signed descriptor, then renames it into place. |
| `void clear_local_state()` | Forgets the stored device secret and lease for this product. Waits for a device-bound call in progress to finish first. |
| `bool is_configured() const` / `std::string configuration_error() const` | Constructor validation result. |
| `const std::string& hardware_id() const` | The hwid this client sends. |
| `static std::string get_hardware_id()` | This machine's hwid (empty if the machine id cannot be read). |

Each request carries a fresh 32-byte CSPRNG nonce (base64url, 43 characters) and a unix timestamp
(local clock plus the offset learned from the server). When the server answers with a signed
`clock_skew`, the SDK sets `offset = serverTime - localTime` and retries **once** with a new nonce.

### `ClientOptions`

| Field | Default | Description |
|---|---|---|
| `std::chrono::milliseconds timeout` | 15 s | Per-request timeout (connect + transfer). Must be positive. |
| `std::optional<std::string> hwid` | `Client::get_hardware_id()` | Hardware id override (8-256 printable characters). |
| `std::shared_ptr<IStore> store` | `MemoryStore` | Persists the device secret and offline lease per product. Use `FileStore` (or your own store) in production. |
| `bool allow_insecure_http` | `false` | Allow `http://` to non-loopback hosts. Never enable in production. |
| `std::string user_agent` | `velsigil-cpp/1.0.0` | User-Agent header (control characters are rejected). |
| `std::shared_ptr<ITransport> transport` | libcurl | Custom HTTP transport (proxies, tests). |
| `std::function<std::int64_t()> clock` | system clock | Unix-seconds clock (tests, simulations). |

### `ValidationResult`

| Field / member | Description |
|---|---|
| `bool ok` | `true` only for a verified, signed success (`ok == true` and `code == "ok"` in the payload). Also `explicit operator bool`. |
| `std::string code`, `std::string message` | Result code (table below) and display text (server or SDK). |
| `std::optional<LicenseInfo> license` | `id, plan, status, features, expires_at (nullopt = lifetime), max_devices, devices_used, created_at, is_trial, trial_ref`. On a failed result (`license_revoked`, `license_expired`, ...) `license->features` is informational only (servers since 2026-10-06 send it empty): gate features with `result.has_feature()`, never with `license->features`. |
| `std::optional<ActivationInfo> activation` | `id, status, first_seen_at, device_secret_issued`. The secret itself is stored, never exposed. |
| `std::optional<Lease> lease` | `token, expires_at`. |
| `std::optional<UpdateInfo> update` | `latest_version, min_version, update_available, mandatory, changelog`. |
| `std::optional<DownloadInfo> download` | `url, expires_at, file_name, size, sha256, version`. |
| `std::optional<std::string> request_id` | Server request id (quote it in support requests). |
| `std::optional<std::int64_t> server_time` | Authoritative server time from the signed payload. |
| `bool offline` | Result produced from the stored lease. |
| `std::optional<std::int64_t> retry_after` | Seconds to wait before trying the server again (0..86400), from the `Retry-After` header of **every HTTP 429 or 503** answer, whatever its code: `rate_limited`, `network_error` (the server's empty 503 while its database is unreachable, or a gateway's 503) or `internal_error` (503 `service_busy`). Delta-seconds or an HTTP-date (measured from the client's clock); nullopt for other answers and when the header is missing or unreadable. `validate_with_offline_fallback()` copies it to the offline result it falls back to; `validate_offline()` called directly never sets it. |
| `std::optional<std::string> trial_key` | The key of the trial `start_trial` just started (`ok` results of `start_trial` only). Sent once: store it immediately. |
| `bool has_feature(std::string_view) const` | `true` only if `ok` and the license grants the feature. |
| `expires_at()`, `is_lifetime()`, `seconds_until_expiry([now])`, `days_until_expiry([now])` | Expiry helpers. `seconds_until_expiry()` uses the system clock. `days_until_expiry` rounds **up** and, without an argument, measures at the result's own time (`server_time` online, `reference_time` = the time of the check offline): an N-day trial shows N right after `start_trial()`, 1 on its last day and 0 once expired (the same rule in every Velsigil SDK). |
| `is_trial()` | A free-trial license (the optional signed `trial` field, online and offline; `LeaseClaims::is_trial`). Pair it with `days_until_expiry()` for "Trial: N days left"; a purchase with the same e-mail keeps the key and turns it false at the next online validation. |
| `trial_ref()` / `with_trial_ref(buy_url)` | The trial's conversion reference (servers since 2026-10-06; also `license->trial_ref`): set on online results for a free trial a purchase can still convert, also on `license_expired`; nullopt otherwise and offline. `with_trial_ref(buy_url)` (or the free function `velsigil::with_trial_ref(url, ref)`) appends `velsigil_trial=<ref>` (a Stripe Payment Link gets `client_reference_id=`): the purchase then converts THIS trial (same key) whatever e-mail address the buyer pays with. Opaque; never store it. |

### Stores

```cpp
class IStore {
 public:
  virtual std::optional<std::string> get(const std::string& product_id, const std::string& key) = 0;
  virtual bool set(const std::string& product_id, const std::string& key, const std::string& value) = 0;
  virtual bool erase(const std::string& product_id, const std::string& key) = 0;
};
```

Keys used by the client: `store_keys::kDeviceSecret` (`"deviceSecret"`) and `store_keys::kLease` (`"lease"`).
Exceptions and failures from a store are contained by the client (persistence is best effort).

- `MemoryStore`: process-local, internally locked (the default).
- `FileStore(path)`: JSON file `{ "version": 1, "products": { "<productId>": { "deviceSecret": ..., "lease": ... } } }`.
  Writes go to a new temporary file (POSIX `O_EXCL`, mode `0600`, `fsync`; Windows protected DACL for the
  current user and SYSTEM, `FlushFileBuffers`) and are renamed over the target atomically. When the store
  has to create the file's parent directory, that directory gets mode `0700` on POSIX. Missing, oversized
  (> 1 MiB) or corrupt files read as empty.
  `FileStore::default_path("MyApp")` returns `%LOCALAPPDATA%\MyApp\velsigil-license.json`,
  `~/Library/Application Support/MyApp/velsigil-license.json` or `$XDG_DATA_HOME/MyApp/velsigil-license.json`
  (`~/.local/share/...`), or an empty path when it cannot be determined.
  **Upgrading from the former product name (Veltrix):** a `FileStore` whose file is named
  `velsigil-license.json` reads `veltrix-license.json` from the same directory while the new file does not
  exist yet, so an updated application keeps its device secret and offline lease (no re-activation). The
  next write goes to the new file; the legacy file is never modified and can be deleted afterwards.
  `FileStore::legacy_path()` returns that fallback (empty for other file names).

### Transport

`ITransport::post_json(url, body, timeout) -> HttpResponse{ transport_ok, status, body, error, retry_after }`.
`retry_after` is the raw `Retry-After` header value of the response, when it had one; a custom transport should
set it too (without it, results carry no `retry_after`).
`transport_ok == false` means no HTTP response arrived and maps to `network_error`. A custom transport reports
every HTTP answer, 5xx included, with `transport_ok == true` and the real status; an unsigned 5xx then triggers the
offline fallback just like `transport_ok == false`. The default libcurl
transport keeps TLS peer and host verification on, never follows redirects, allows only `http`/`https`,
caps response bodies at 1 MiB, uses `CURLOPT_NOSIGNAL` and initialises libcurl once
(`curl_global_init` via `std::call_once`; it is never cleaned up). A custom transport receives the
request body, which contains the license key and device secret: never log it.

### Low-level helpers

The low-level helpers (`verify_envelope_typed`, `verify_lease` and the opt-in `verify_envelope` overloads)
refuse the two public keys of the shared test vectors (`keys.publicKey` and `keys.wrongPublicKey` of
`test-vectors.json`, in any base64 spelling) **always**, exactly like an invalid public key: the status is
`invalid_signature`, with no payload or claims. Their private keys are published, so anyone could forge answers
and leases that verify with them, and unlike the `Client` (which accepts them for a `localhost`, `127.0.0.1` or
`[::1]` API URL) these helpers have no API URL that could show a local test server. Pass your product's public
key (Products > your product > Integration).

| Function | Description |
|---|---|
| `verify_envelope_typed(envelope_json, public_key_base64, expected_nonce, expected_product_id, expected_type, expected_hwid)` | `EnvelopeVerification{ status, payload_json }` with `status` in `valid, invalid_signature, nonce_mismatch, product_mismatch, type_mismatch, hwid_mismatch, malformed`. `expected_type` is the endpoint the request went to (`"validate"`, `"deactivate"`, `"update_check"`, `"download"` or `"trial"`) and is always checked: the server also signs `ok: true` answers to update checks, which need no license, so an unchecked type lets such an answer pass as a validation. An empty `expected_type` never matches. With a non-empty `expected_hwid` (the hwid a device-bound request was sent with), a signed lease or `activation.hwidHash` of another device yields `hwid_mismatch` (a lease of another product `product_mismatch`); pass `""` for update checks. An invalid public key or a published test-vector key yields `invalid_signature`. It has exactly one signature and no default arguments, so a call that leaves out an argument does not compile. |
| `verify_envelope(envelope_json, public_key_base64, expected_nonce, expected_product_id[, expected_hwid])` | **Removed** (unsafe): these overloads do **not** check the payload `type`, so a signed update-check answer passes as a validation, and the fifth argument is the **hwid**, so `verify_envelope(env, key, nonce, product, "validate")` checks nothing about the type. Every call is now a compile error (*use of deleted function*): use `verify_envelope_typed`. Old code that cannot be changed yet can get them back, still `[[deprecated]]` and still unsafe, by defining `VELSIGIL_ALLOW_UNTYPED_ENVELOPE` for the **whole** program (e.g. `target_compile_definitions(app PUBLIC VELSIGIL_ALLOW_UNTYPED_ENVELOPE)`; never for single files). See [CHANGELOG.md](CHANGELOG.md). |
| `verify_lease(token, public_key_base64, product_id, hwid, now)` | `LeaseVerification{ status, claims }` with `status` in `valid, expired, invalid_signature, product_mismatch, hwid_mismatch, malformed`. An invalid public key or a published test-vector key yields `invalid_signature` without claims. |
| `compute_hardware_id(machine_id)` | `hex(SHA-256("vx-hwid-v1:" + lower(trim(machine_id))))`. |
| `hash_hardware_id(hwid)` | `hex(SHA-256(hwid))`, the device hash used in leases. |
| `to_string(EnvelopeStatus)`, `to_string(LeaseStatus)` | Status names (as in `test-vectors.json`). |

### Hardware id

`hwid = lowercase hex SHA-256("vx-hwid-v1:" + machineId)` with `machineId` trimmed and lowercased:

| Platform | Source |
|---|---|
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, always the 64-bit registry view (`RegGetValueW`, `RRF_SUBKEY_WOW6464KEY`) |
| Linux | `/etc/machine-id`, then `/var/lib/dbus/machine-id` (a file that is empty or holds systemd's placeholder `uninitialized` is skipped) |
| macOS | `IOPlatformUUID` from `/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice` (fixed command, no user input) |

Override it with `ClientOptions::hwid` (e.g. for containers whose machine id changes). The hwid is
spoofable and is not a security boundary; the server-issued device secret and server-side checks are.

## Result codes

| Code | Origin | Meaning / typical reaction |
|---|---|---|
| `ok` | signed | License valid (or action succeeded). |
| `invalid_key` | signed | Key unknown (or regenerated). Ask for a new key. |
| `license_expired` / `license_suspended` / `license_revoked` / `license_banned` | signed | License not usable. |
| `device_limit_reached` | signed | All device slots in use; deactivate another device or reset devices in the customer portal. |
| `device_revoked` | signed | This device was revoked by the seller. |
| `device_verification_failed` | signed | The device secret did not match (strict device binding). Reset the device in the portal. |
| `device_not_found` | signed | `deactivate`: this device is not activated. |
| `device_not_activated` | signed | `get_download`: validate (activate) first. |
| `activation_rate_limited` / `activation_cooldown` / `activations_disabled` | signed | New activations are temporarily not possible. |
| `downloads_disabled` | signed | Downloads are switched off. |
| `blacklisted` | signed | Device, network or customer is blocked. |
| `outdated_version` | signed | Version below the product minimum; `result.update` describes the release. |
| `product_paused` / `product_disabled` | signed | Product is paused (message from the seller) or disabled. |
| `clock_skew` | signed | Clock still outside the window after the automatic retry. |
| `replay_detected` | signed | Nonce reuse detected. |
| `no_release` / `release_not_found` | signed | No (matching) published release. |
| `trial_already_used` | signed | This device already used a free trial of the product (`codes::kTrialAlreadyUsed`). Offer to buy; the stored lease is kept. |
| `trial_unavailable` | signed | `start_trial`: no in-app trial right now (switched off, today's limit, too many trials from this network). Show `message`. |
| `trial_email_required` / `trial_email_invalid` / `trial_email_not_accepted` | signed | `start_trial`: the offer confirms an e-mail address first: ask for one, a valid one, or a personal / work one (throwaway domains are refused). |
| `trial_confirmation_sent` | signed | `start_trial`: not an error of the user. A confirmation link was e-mailed; the key arrives by e-mail and is entered like any key. The same answer for every valid address. |
| `validation_error` | unsigned 400 / SDK | Request rejected (invalid fields). Also returned locally, without a request, for an empty or over-long (> 64) license key, a version > 32, a device name > 255 characters, control characters, or an incomplete `DownloadInfo` / empty destination in `download_release`. |
| `ip_blocked` | unsigned 403 | Your IP is temporarily blocked. |
| `unknown_product` | unsigned 404 | Wrong product id or server URL. |
| `payload_too_large` / `unsupported_media_type` | unsigned 413/415 | Request rejected. |
| `rate_limited` | unsigned 429 | Too many requests; retry later with backoff (`result.retry_after` holds the seconds when sent). |
| `internal_error` | unsigned 5xx | Server error (also 502/503/504 **with** a Velsigil error body, e.g. `503 service_busy` while the database is busy or unreachable). From an HTTP 5xx it triggers the offline fallback. |
| `network_error` | SDK | No HTTP response (DNS, connect, TLS, timeout) or a 502/503/504 gateway response without a Velsigil error body (an empty or HTML body). Always triggers the offline fallback. |
| `invalid_response` | SDK | Unsigned, tampered, mismatched (nonce, product, `type` vs. endpoint, or a signed lease / `activation.hwidHash` of another device: the request was rewritten in transit and nothing from the response is stored) or malformed response, or a download grant whose URL violates the HTTPS policy. Never trust it. |
| `invalid_configuration` | SDK | Constructor arguments rejected; see `configuration_error()`. |
| `no_lease` / `lease_expired` / `lease_invalid` | SDK (offline) | No stored lease / lease past `exp` / signature, product or device check failed. `validate_with_offline_fallback()` returns `lease_expired` / `lease_invalid` when it falls back to an unusable stored lease, never `no_lease` (it returns the online error instead). |
| `download_failed` / `integrity_mismatch` / `io_error` | SDK (`download_release`) | Non-200 status (an expired link answers 410) or URL rejected by the HTTPS policy / size or SHA-256 mismatch / destination not writable. |
| `panel_too_old` | SDK (`start_trial`) | The Velsigil server has no in-app trial endpoint yet (HTTP 404 with the Velsigil error code `not_found`). The seller must update the panel. |
| `already_licensed` | SDK (`start_trial`) | This device already holds a license for the product (a device secret or offline lease is stored; `codes::kAlreadyLicensed`), and a trial must not replace it. Nothing was sent and the stored state is unchanged. Validate the saved key instead, or call `deactivate(key)` / `clear_local_state()` first. |
| `store_unavailable` | SDK (`start_trial`) | The store could not be read (`IStore::get` threw, for example on a locked file; `codes::kStoreUnavailable`), so the SDK cannot tell whether this device already holds a license. Nothing was sent; try again later. |

Unsigned responses can never produce `ok == true`, and their `message` text is never shown (the SDK
uses fixed text; only a well-formed `requestId` is kept). The mapping is identical in every Velsigil SDK
(SPEC section 14): a known code in a Velsigil error body (`{"error":{"code":...}}`) wins; otherwise
400 → `validation_error`, 413 → `payload_too_large`, 415 → `unsupported_media_type`, 429 →
`rate_limited`, 502/503/504 → `network_error` without a Velsigil error body or `internal_error` with one,
other 5xx → `internal_error`, anything else (3xx, 401, ...) → `invalid_response`. `validate()` always reports
this code; whether `validate_with_offline_fallback()` uses the lease depends on the HTTP status, not on the code
(see below).

## In-app free trials

When the seller turns on **In your app** in the product's trial offer (panel → Products → your product →
Trials), an app that has no license key yet can start a free trial for its device:

```cpp
std::optional<std::string> saved_key = load_saved_license_key();  // your own settings storage
if (!saved_key) {
  velsigil::StartTrialOptions trial_options;
  trial_options.version = "1.2.0";
  const velsigil::ValidationResult trial = client.start_trial(trial_options);
  if (trial.ok && trial.trial_key) {
    save_license_key(*trial.trial_key);  // FIRST: the server can never send this key again
    show_trial_banner(trial.days_until_expiry());  // trial.is_trial() == true
  } else if (trial.code == velsigil::codes::kTrialEmailRequired) {
    // The offer confirms an e-mail address first: ask for it, set trial_options.email and call again.
  } else {
    show_message(trial.message);  // trial_confirmation_sent, trial_already_used, trial_unavailable, panel_too_old, ...
  }
}
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
- The SDK stores the trial's device secret and offline lease like after a validation, never the key. The answer is
  device-bound: a signed lease or `activation.hwidHash` of another device makes it `invalid_response`.
- **Never over an existing license.** When a device secret or an offline lease is already stored for the product
  (the device was activated with a key, paid or trial), `start_trial()` returns `already_licensed`
  (`codes::kAlreadyLicensed`) without sending anything and leaves the stored state as it is, so a trial can never
  replace the device secret and lease of a paid license. Validate the saved key instead; to really start over, call
  `deactivate(key)` (or `clear_local_state()` when the key is gone) first. When the store cannot be read,
  `start_trial()` returns `store_unavailable` and sends nothing: a failed read is never taken for "nothing stored".
  The check runs under the client's device lock, so a `validate` on another thread cannot slip in between.
- The server limits trials per network, per device and per day, and hardware ids are asserted by the client: a user
  who changes the machine id can start another trial within those limits. Treat a trial as a marketing tool, not a
  security boundary.
- `panel_too_old`: the seller's Velsigil server predates in-app trials; nothing else is affected.

## Offline leases

A successful `validate` (or `start_trial`) may return a lease (when the product's *offline lease hours* is above 0):
`token = base64url(JSON) "." base64url(Ed25519 signature over the first part)` with claims
`{ v: 1, typ: "lease", productId, licenseId, activationId, hwidHash, plan, features, licenseExpiresAt, iat, exp }`,
plus `trial: true` for a free-trial license (left out otherwise; unknown fields are ignored). The SDK stores the token and, offline, accepts it only if the signature verifies with your public key,
`typ` is `lease`, `productId` matches, `hwidHash` equals `SHA-256(hwid)`, and the current time (plus the
learned offset) is before `exp` (and before `licenseExpiresAt`).

The stored lease is replaced on every successful validation (only after it verifies for this product
and device; an answer whose lease belongs to another device or product is rejected as a whole with
`invalid_response`), removed when a successful validation returns no lease (offline use disabled), and removed
after signed refusals that end offline access. That set is binding for every Velsigil SDK (SPEC section
14): `invalid_key`, `license_expired`, `license_suspended`, `license_revoked`, `license_banned`,
`device_revoked`, `device_verification_failed`, `device_limit_reached`, `device_not_activated`,
`device_not_found`, `blacklisted`, `product_disabled`. Other signed failures (`product_paused`,
`outdated_version`, `activation_rate_limited`, `clock_skew`, ...) keep it. A successful `deactivate` (or
`device_not_found`) clears the lease and the device secret. Rolling the system clock back extends a lease
locally; this is a documented limitation of offline validation, so keep the lease duration short.

### When the offline fallback applies

`validate_with_offline_fallback()` validates online first and uses the stored lease only when the license
server is **unavailable**:

| Online outcome | Code from `validate()` | Fallback |
|---|---|---|
| No HTTP response: DNS, connection refused or reset, TLS failure, timeout | `network_error` | yes |
| Unsigned HTTP 5xx with an empty, HTML or other non-Velsigil body (a reverse proxy such as IIS ARR or Caddy whose app is down: 502/503/504; a gateway timeout) | `network_error` (502/503/504) / `internal_error` (500, 501, other 5xx) | yes |
| Unsigned HTTP 5xx with a Velsigil error body (the app is up but its database is down or busy: `500 internal_error`, `503 service_busy`) | `internal_error` (or the body's known code) | yes |
| Signed answer (`license_revoked`, `license_expired`, `device_revoked`, `product_paused`, ...) | its code | no |
| Unsigned 4xx (`429 rate_limited` with `Retry-After`, `400 validation_error`, `403 ip_blocked`, `404`, ...) | its code | no |
| `invalid_response` (bad signature, nonce or product mismatch, a non-envelope body with HTTP 200, 3xx, ...) | `invalid_response` | no |

Only the HTTP status decides, never the body of an unsigned 5xx: whoever can inject an unsigned 5xx can as well
drop the connection, which allows the fallback anyway, and the lease itself is signed, bound to this device and
time-limited. A signed answer is final, so a revocation still ends offline access as soon as the application
reaches the server once. `validate()` never falls back; it reports the real error.

When the fallback applies and a lease is stored, the result is that of `validate_offline()` as is (code, message,
license and lease), with `offline == true`. Without a stored lease the online result stays:

| Stored lease | Result |
|---|---|
| verifies | `ok`, license and features from the lease |
| past its `exp` | `lease_expired` (the lease stays stored, as with `validate_offline()`) |
| bad signature, another product or device, malformed | `lease_invalid` (the lease stays stored, as with `validate_offline()`) |
| none | the original online result with its own code (`network_error` / `internal_error`), `offline == false`; not `no_lease` |

Each result of the fallback (`ok`, `lease_expired`, `lease_invalid`) carries the `retry_after` of the failed online
attempt: the `Retry-After` of a 503 (for example the server's `Retry-After: 30` while its database is
unreachable), else nullopt. So an application running on its lease knows when to try online again.

So a `lease_expired` or `lease_invalid` from `validate_with_offline_fallback()` also means that the server was
unavailable; `validate()` reports that online error itself.

Since 1.0.3 every unsigned 5xx falls back, including a `500 internal_error` and a 502/503/504 with a Velsigil
error body. Earlier 1.0.x versions fell back only on `network_error`, which already covers an **empty** (or HTML)
502/503/504: they use the lease when the server answers `503` with an empty body while its database is
unreachable, but not on any 500 (or other 5xx outside 502/503/504), nor on a 502/503/504 with a Velsigil error
body such as `503 service_busy`.

## Device secret persistence

On first activation the server issues a device secret (`activation.deviceSecret`). The SDK stores it
through the configured `IStore` (keyed by product id) and sends it with every `validate`, `deactivate`
and `get_download` request. The server compares it with its stored hash: a mismatch is reported to the
seller and, with *strict device binding*, refused (`device_verification_failed`).

Use a persistent store (`FileStore` or your own, e.g. backed by the OS keychain): with the default
`MemoryStore` the secret is lost when the process exits, so the next run looks like a cloned device.
`deactivate` (on success) and `clear_local_state()` remove the secret.

A store that cannot be read must say so: `IStore::get` throws instead of returning nullopt ("nothing stored").
The bundled `FileStore` does this for a file that exists but cannot be read, and then refuses to write (`set` and
`erase` return false) rather than rebuild the file from nothing, which would erase every product's device secret.
A missing, oversized or corrupt file still reads as empty and is replaced by the next write.

## Updates and downloads

```cpp
const auto update = client.check_update("1.2.0");
if (update.ok && update.update && update.update->update_available) {
  const auto link = client.get_download(license_key, update.update->latest_version);
  if (link.ok && link.download) {
    const auto saved = client.download_release(*link.download, "/tmp/myapp-update.zip");
    if (saved.ok) install_update("/tmp/myapp-update.zip");   // size + SHA-256 verified
  }
}
```

`update->mandatory` and `outdated_version` tell you when the current version may no longer be used.
Download URLs expire after a few minutes. `get_download` already rejects a grant whose URL is not
`https://` (plain `http://` only for `localhost`, `127.0.0.1` and `[::1]` or with `allow_insecure_http`)
or contains credentials, with `invalid_response`, as the Node, Python and C# SDKs do. `download_release`
applies the same HTTPS policy again, streams to `<destination>.part-<random>`, aborts as soon as more bytes than announced arrive, and
only renames the file into place when the size and the SHA-256 from the signed descriptor match. Do not
build destination paths from `file_name` without sanitising it.

## Thread-safety

A `Client` can be shared between threads: its configuration is immutable after construction, the clock
offset is atomic, every request uses its own libcurl handle and nonce, and `MemoryStore` / `FileStore`
are internally locked. Custom `IStore`, `ITransport` and `clock` implementations must be thread-safe if
the client is shared, and must not call back into the `Client`. Use one `FileStore` instance per file within a
process. `Client` is movable, not copyable; a moved-from client returns `invalid_configuration`.

Device-bound calls (`validate`, `start_trial`, `deactivate`, `get_download` and `clear_local_state`) are
**serialized per client**: each one reads the stored state, sends its request and persists the answer before the
next one starts. So concurrent first activations send the device secret the first one stored (instead of none,
which the server counts as a secret mismatch), and the `already_licensed` check of `start_trial` cannot be
overtaken by a `validate` on another thread. `check_update` and `validate_offline` are not serialized.

## Hardening notes

- **Server-side enforcement is authoritative.** The SDK makes forged or replayed responses detectable, but
  any check that runs on the customer's machine can be patched out. Device limits, revocation, expiry and
  feature entitlements are enforced by the server; gate valuable functionality on server-side data where
  you can.
- **Keep the public key in code.** Compile it into the binary; never load it from a file, environment
  variable or the network, and never ship a private key. Rotating the signing key in the panel requires a
  release with the new public key.
- **Check results in more than one place.** Validate at start-up and again at a few independent points
  (feature entry points, periodically), keep the `ValidationResult` instead of a single global boolean, and
  check `has_feature()` where the feature is used.
- **Obfuscation helps but is not a security boundary.** Stripping symbols, LTO, control-flow obfuscation
  and integrity checks raise the cost of patching; they do not make client-side checks unbreakable.
- Link statically (the default) and enable your toolchain's hardening for the final binary (MSVC
  `/guard:cf /DYNAMICBASE /HIGHENTROPYVA`; GCC/Clang `-fstack-protector-strong -D_FORTIFY_SOURCE=2
  -fPIE -pie -Wl,-z,relro,-z,now`).
- Never log license keys, device secrets or request bodies; the SDK itself logs nothing.
- Keep `allow_insecure_http` off in production and leave TLS verification to the system trust store.

## Testing

```sh
ctest --test-dir build --output-on-failure
```

The private keys of the shared `test-vectors.json` (`keys.privateSeedBase64`, `keys.wrongPrivateSeedBase64`) are
published, so the `Client` constructor refuses their public keys (`keys.publicKey`, `keys.wrongPublicKey`, in any
base64 encoding) like an invalid public key unless the API URL's host is `localhost`, `127.0.0.1` or `[::1]`,
the hosts that may also use plain `http://` (a local test server such as the bundled mock). The low-level
helpers refuse them always (see [Low-level helpers](#low-level-helpers)), so the SDK's own tests verify the
vectors through internal entry points (`src/detail.hpp`, not installed and not part of the API).

- `velsigil_vector_tests` (mandatory): classifies every envelope and lease in the shared `test-vectors.json`
  exactly as its `expect` field says (through those internal entry points), checks that `verify_envelope_typed`
  and `verify_lease` refuse both published keys, reproduces every HWID example and runs the leases through
  `Client::validate_offline()` (with a `localhost` API URL).
- `velsigil_client_tests`: client behaviour against an in-process signing server (injected transport and
  clock, signing with a key pair generated for the run): ok, business failure, nonce mismatch, bad signature, wrong
  key, `clock_skew` + successful retry, device secret persisted and re-sent, 400/429/500 and other unsigned
  errors, `retry_after` (every 429 and 503, delta-seconds and HTTP-date), timeout, connection refused, offline
  fallback (valid, expired, invalid or no stored lease, carrying the online `retry_after`) and on
  every unsigned 5xx (Velsigil error, HTML, empty or garbled body; never on signed or 4xx answers), the HTTPS
  policy for download
  grants (`get_download`) and `download_release`, configuration hardening (including the refusal of the
  test-vector keys outside loopback hosts), the low-level helpers (a product's own key verifies, the published
  test-vector key is refused), `FileStore` (including the read-only fallback to a legacy
  `veltrix-license.json`), concurrency.
- `velsigil_untyped_optin_tests`: the opt-in type-less `verify_envelope` overloads
  (`VELSIGIL_ALLOW_UNTYPED_ENVELOPE`) compile, fail closed on garbage and refuse the published test-vector keys.
- `velsigil_http_tests` (`-DVX_BUILD_HTTP_TESTS=ON`): the same flows over real HTTP with libcurl against
  `tests/mock_server/mock_server.py`, including verified downloads and the offline fallback on 500/502/503/504
  outages. See `tests/mock_server/README.md`.
