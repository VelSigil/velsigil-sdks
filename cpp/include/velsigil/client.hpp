// Velsigil C++ client SDK - public API.
//
// Every response of the Velsigil client API (SPEC section 10) is an Ed25519-signed envelope. The SDK
// verifies the signature over the exact ASCII bytes of the envelope's `data` string with the public
// key passed to the constructor (the envelope `kid` is never used to pick a key), checks that the
// payload echoes this request's nonce and product id, and only then decodes and parses it.
//
// Error model: public member functions do not throw. Every outcome - success, business failure
// (signed by the server), unsigned HTTP error, transport failure or tampered response - is reported
// through a result object whose `ok` flag is false unless the server's signed payload said ok.
//
// Thread-safety: a Client may be shared between threads. Its configuration is immutable after
// construction, the learned clock offset is atomic, and the bundled stores are internally locked.
// The device-bound calls (validate, start_trial, deactivate, get_download, clear_local_state) are
// serialized per Client: each reads the stored state, sends its request and persists the answer
// before the next one starts. Custom IStore / ITransport implementations must be thread-safe if the
// Client is shared, and must not call back into the Client.
#ifndef VELSIGIL_CLIENT_HPP
#define VELSIGIL_CLIENT_HPP

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace velsigil {

/// SDK version (semantic versioning).
inline constexpr char kSdkVersion[] = "1.0.2";

/// Result codes. Server codes are defined in SPEC section 10.3; the SDK adds a few local ones.
namespace codes {
// Success.
inline constexpr char kOk[] = "ok";

// Signed business results returned by the server.
inline constexpr char kInvalidKey[] = "invalid_key";
inline constexpr char kLicenseExpired[] = "license_expired";
inline constexpr char kLicenseSuspended[] = "license_suspended";
inline constexpr char kLicenseRevoked[] = "license_revoked";
inline constexpr char kLicenseBanned[] = "license_banned";
inline constexpr char kDeviceLimitReached[] = "device_limit_reached";
inline constexpr char kDeviceRevoked[] = "device_revoked";
inline constexpr char kDeviceVerificationFailed[] = "device_verification_failed";
inline constexpr char kDeviceNotFound[] = "device_not_found";
inline constexpr char kDeviceNotActivated[] = "device_not_activated";
inline constexpr char kActivationRateLimited[] = "activation_rate_limited";
inline constexpr char kActivationCooldown[] = "activation_cooldown";
inline constexpr char kActivationsDisabled[] = "activations_disabled";
inline constexpr char kDownloadsDisabled[] = "downloads_disabled";
inline constexpr char kBlacklisted[] = "blacklisted";
inline constexpr char kOutdatedVersion[] = "outdated_version";
inline constexpr char kProductPaused[] = "product_paused";
inline constexpr char kProductDisabled[] = "product_disabled";
inline constexpr char kClockSkew[] = "clock_skew";
inline constexpr char kReplayDetected[] = "replay_detected";
inline constexpr char kNoRelease[] = "no_release";
inline constexpr char kReleaseNotFound[] = "release_not_found";
// Free trials (SPEC 9.7): this device already used a free trial of the product. Keeps the stored lease.
inline constexpr char kTrialAlreadyUsed[] = "trial_already_used";
// In-app free trials (Client::start_trial, SPEC 9.7): signed failures, none of them clears the stored lease.
inline constexpr char kTrialUnavailable[] = "trial_unavailable";              // no in-app trial right now
inline constexpr char kTrialEmailRequired[] = "trial_email_required";         // the offer confirms an e-mail first
inline constexpr char kTrialEmailInvalid[] = "trial_email_invalid";           // not a valid e-mail address
inline constexpr char kTrialEmailNotAccepted[] = "trial_email_not_accepted";  // throwaway or blocked domain
inline constexpr char kTrialConfirmationSent[] = "trial_confirmation_sent";   // the key arrives by e-mail

// Unsigned HTTP errors. They can never produce a successful result.
inline constexpr char kValidationError[] = "validation_error";
inline constexpr char kIpBlocked[] = "ip_blocked";
inline constexpr char kUnknownProduct[] = "unknown_product";
inline constexpr char kPayloadTooLarge[] = "payload_too_large";
inline constexpr char kUnsupportedMediaType[] = "unsupported_media_type";
inline constexpr char kRateLimited[] = "rate_limited";
inline constexpr char kInternalError[] = "internal_error";

// SDK-side codes (SPEC section 14; identical names in every Velsigil SDK). kValidationError above is
// also returned for local argument checks (empty/over-long license key, version > 32, device name > 255).
inline constexpr char kInvalidResponse[] = "invalid_response";            // unsigned, tampered or mismatched response (incl. wrong `type`)
inline constexpr char kNetworkError[] = "network_error";                  // no HTTP response (DNS, connect, TLS, timeout) or 502/503/504 without a Velsigil error body
inline constexpr char kInvalidConfiguration[] = "invalid_configuration";  // constructor arguments were rejected
inline constexpr char kNoLease[] = "no_lease";                            // validate_offline(): nothing stored
inline constexpr char kLeaseExpired[] = "lease_expired";                  // validate_offline(): lease past its exp
inline constexpr char kLeaseInvalid[] = "lease_invalid";                  // validate_offline(): signature/product/device check failed
inline constexpr char kPanelTooOld[] = "panel_too_old";                   // start_trial(): the server has no in-app trial endpoint (404 not_found)
inline constexpr char kAlreadyLicensed[] = "already_licensed";            // start_trial(): refused locally, a device secret or lease is stored (nothing sent)
inline constexpr char kStoreUnavailable[] = "store_unavailable";          // start_trial(): refused locally, the store could not be read (nothing sent)

// download_release() codes.
inline constexpr char kDownloadFailed[] = "download_failed";        // non-200 status or URL rejected by the HTTPS policy
inline constexpr char kIntegrityMismatch[] = "integrity_mismatch";  // size or SHA-256 differs from the signed descriptor
inline constexpr char kIoError[] = "io_error";                      // destination could not be written
}  // namespace codes

/// License details from a signed response (or from an offline lease, see validate_offline()).
struct LicenseInfo {
  std::string id;
  std::string plan;
  std::string status;  // active | pending | suspended | expired | revoked | banned
  std::vector<std::string> features;
  std::optional<std::int64_t> expires_at;  // unix seconds; nullopt = lifetime
  std::int64_t max_devices = 0;
  std::int64_t devices_used = 0;
  std::int64_t created_at = 0;
  /// True for a free-trial license (SPEC 9.7): the optional signed `trial` field (also in offline leases).
  /// Absent (paid licenses, older servers) means false.
  bool is_trial = false;
  /// The trial's conversion reference (SPEC 9.7, servers since 2026-10-06): set for a free trial a purchase
  /// can still convert; nullopt otherwise (paid licenses, offline leases, older servers). Opaque; see
  /// ValidationResult::trial_ref().
  std::optional<std::string> trial_ref;
};

/// URL parameter (and Paddle custom-data key / FastSpring tag) that carries a trial conversion reference.
inline constexpr char kTrialRefParam[] = "velsigil_trial";

/// True for a well-formed trial conversion reference: 1-200 characters of [A-Za-z0-9_-].
bool is_trial_ref(std::string_view text) noexcept;

/// `url` with the trial conversion reference appended to its query as `velsigil_trial=<ref>` (before any
/// `#fragment`; the rest of the URL is kept as it is), or as `client_reference_id=<ref>` for a Stripe
/// Payment Link (https://buy.stripe.com/...). Returns `url` unchanged when the reference is malformed or
/// `url` is not an absolute http(s) URL.
std::string with_trial_ref(std::string_view url, std::string_view ref);

/// The server-side device record ("activation") for this machine.
struct ActivationInfo {
  std::string id;
  std::string status;  // active | revoked
  std::int64_t first_seen_at = 0;
  /// True when this response issued a new device secret. The SDK stores it through the configured
  /// IStore and sends it on every later license request; it is intentionally not exposed here.
  bool device_secret_issued = false;
};

/// Offline lease returned by a successful validation (SPEC 10.4).
struct Lease {
  std::string token;
  std::int64_t expires_at = 0;  // unix seconds
};

/// Release information (validate / update-check responses).
struct UpdateInfo {
  std::string latest_version;
  std::optional<std::string> min_version;
  bool update_available = false;
  bool mandatory = false;
  std::string changelog;
};

/// Short-lived download descriptor returned by get_download().
struct DownloadInfo {
  std::string url;
  std::int64_t expires_at = 0;  // unix seconds
  std::string file_name;
  std::int64_t size = 0;  // bytes
  std::string sha256;     // lowercase hex of the file contents
  std::string version;
};

/// Outcome of every Client call. `ok` is true only for a verified, signed success.
struct ValidationResult {
  bool ok = false;
  std::string code;     // see velsigil::codes
  std::string message;  // human readable (server text or SDK text); safe to display
  std::optional<LicenseInfo> license;
  std::optional<ActivationInfo> activation;
  std::optional<Lease> lease;
  std::optional<UpdateInfo> update;
  std::optional<DownloadInfo> download;
  std::optional<std::string> request_id;    // server request id for support tickets
  std::optional<std::int64_t> server_time;  // unix seconds from the signed payload
  bool offline = false;                     // true when produced from a stored offline lease
  /// The license key of the free trial start_trial() just started (ok results of start_trial only). The
  /// server sends it once and can never send it again: store it right away, like a key the user typed,
  /// and use it with validate() from then on. The SDK never persists it.
  std::optional<std::string> trial_key;
  /// Offline results: the time of the check (unix seconds, clock plus the learned server offset). The default
  /// `now` of days_until_expiry() for results without `server_time`.
  std::optional<std::int64_t> reference_time;

  explicit operator bool() const noexcept { return ok; }

  /// True only when the result is ok and the license grants `feature`.
  bool has_feature(std::string_view feature) const noexcept;
  /// License expiry in unix seconds; nullopt when there is no license or it never expires.
  std::optional<std::int64_t> expires_at() const noexcept;
  /// True when a license is present and has no expiry date.
  bool is_lifetime() const noexcept;
  /// True when a license is present and it is a free trial (SPEC 9.7), online or offline.
  bool is_trial() const noexcept;
  /// The current trial's conversion reference (SPEC 9.7), or nullopt: present on online results for a free
  /// trial a purchase can still convert, also on license_expired (the moment to offer "Buy now"). Add it to
  /// the "Buy now" link with with_trial_ref(): the purchase then converts THIS trial into the paid license
  /// (same key) whatever e-mail address the buyer pays with. Offline results have none.
  std::optional<std::string> trial_ref() const;
  /// `buy_url` with this trial's conversion reference, or `buy_url` unchanged when there is none.
  std::string with_trial_ref(std::string_view buy_url) const;
  /// Seconds left until the license expires (clamped at 0); nullopt for lifetime / no license.
  std::optional<std::int64_t> seconds_until_expiry(std::int64_t now_unix) const noexcept;
  std::optional<std::int64_t> seconds_until_expiry() const noexcept;  // uses the system clock
  /// Days left until the license expires, rounded UP (the "days left" rule of CLIENT_PROTOCOL 5.2, the same in
  /// every Velsigil SDK); nullopt for lifetime / no license. An N-day trial shows N right after start_trial(),
  /// 1 throughout its last day and 0 once expired.
  std::optional<std::int64_t> days_until_expiry(std::int64_t now_unix) const noexcept;
  /// Measured at the result's own time: `server_time` (online answers), else `reference_time` (offline
  /// results), else the system clock.
  std::optional<std::int64_t> days_until_expiry() const noexcept;
};

/// Optional fields for validate() and validate_with_offline_fallback().
struct ValidateOptions {
  std::optional<std::string> version;      // your application version (<= 32 chars)
  std::optional<std::string> device_name;  // friendly device name shown to the customer (<= 255 chars)
};

/// Optional fields for start_trial().
struct StartTrialOptions {
  std::optional<std::string> version;      // your application version (<= 32 chars)
  std::optional<std::string> device_name;  // friendly device name shown to the customer (<= 255 chars)
  /// The customer's e-mail address (<= 254 chars). Sent only when set, and read only when the seller's
  /// trial offer confirms an address first (the answer is then trial_confirmation_sent).
  std::optional<std::string> email;
};

/// Outcome of download_release().
struct DownloadFileResult {
  bool ok = false;
  std::string code;  // ok | network_error | download_failed | integrity_mismatch | io_error | validation_error | invalid_configuration
  std::string message;
  std::uint64_t bytes = 0;
};

// ---------------------------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------------------------

/// Keys the Client reads and writes in its store (values are opaque strings).
namespace store_keys {
inline constexpr char kDeviceSecret[] = "deviceSecret";
inline constexpr char kLease[] = "lease";
}  // namespace store_keys

/// Pluggable key/value store, partitioned by product id. Implementations must be thread-safe when
/// the Client is shared between threads. Exceptions thrown by a store are caught by the Client.
class IStore {
 public:
  virtual ~IStore() = default;
  /// The stored value, or nullopt when there is none. Throw when the store cannot be read (a locked
  /// file, a locked keyring): the Client never takes a failed read for "nothing stored" (start_trial
  /// then answers store_unavailable).
  virtual std::optional<std::string> get(const std::string& product_id, const std::string& key) = 0;
  /// Returns false when the value could not be persisted.
  virtual bool set(const std::string& product_id, const std::string& key, const std::string& value) = 0;
  /// Returns false when the store could not be updated. Erasing a missing key succeeds.
  virtual bool erase(const std::string& product_id, const std::string& key) = 0;
};

/// Process-local store (the default). Nothing survives a restart, so a device secret issued by the
/// server is lost when the application exits - use FileStore (or your own store) in production.
class MemoryStore final : public IStore {
 public:
  std::optional<std::string> get(const std::string& product_id, const std::string& key) override;
  bool set(const std::string& product_id, const std::string& key, const std::string& value) override;
  bool erase(const std::string& product_id, const std::string& key) override;

 private:
  std::mutex mutex_;
  std::map<std::string, std::map<std::string, std::string>> values_;
};

/// JSON file store. Writes are atomic (temporary file + rename) and the file is created with
/// owner-only permissions (POSIX mode 0600; on Windows a protected DACL granting only the current
/// user and SYSTEM). Share one instance per file within a process.
///
/// A missing, oversized or corrupt file reads as empty and is replaced by the next write. A file that
/// exists but cannot be read is never taken for empty: get() throws std::runtime_error, and set() and
/// erase() return false without writing (rebuilding the file from nothing would erase every product's
/// device secret).
///
/// Legacy migration: when the file name is the default `velsigil-license.json` and that file does not
/// exist yet, reads fall back to `veltrix-license.json` in the same directory (the file written by SDK
/// versions released under the former product name), so an updated application keeps its device
/// secret and offline lease. The next write goes to `path()`; the legacy file is never modified.
class FileStore final : public IStore {
 public:
  explicit FileStore(std::filesystem::path path);

  const std::filesystem::path& path() const noexcept { return path_; }
  /// The read-only legacy fallback file (see above); empty when `path()` has another file name.
  const std::filesystem::path& legacy_path() const noexcept { return legacy_path_; }

  /// Per-user default location for `app_name` (1-64 chars of [A-Za-z0-9._ -]):
  ///   Windows: %LOCALAPPDATA%\<app>\velsigil-license.json
  ///   macOS:   ~/Library/Application Support/<app>/velsigil-license.json
  ///   Linux:   $XDG_DATA_HOME (or ~/.local/share)/<app>/velsigil-license.json
  /// Returns an empty path when the app name is invalid or no home directory can be determined.
  static std::filesystem::path default_path(std::string_view app_name);

  std::optional<std::string> get(const std::string& product_id, const std::string& key) override;
  bool set(const std::string& product_id, const std::string& key, const std::string& value) override;
  bool erase(const std::string& product_id, const std::string& key) override;

 private:
  std::filesystem::path path_;
  std::filesystem::path legacy_path_;
  std::mutex mutex_;
};

// ---------------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------------

/// Raw HTTP exchange used by the Client. `transport_ok == false` means no HTTP response was
/// received (DNS, connection, TLS or timeout failure) and maps to `network_error`.
struct HttpResponse {
  bool transport_ok = false;
  long status = 0;
  std::string body;
  std::string error;  // transport error description; must not contain secrets
};

/// HTTP transport abstraction. The default implementation uses libcurl with TLS verification
/// enabled. A custom transport (proxies, tests) receives the full request body, which contains the
/// license key and device secret: never log it.
class ITransport {
 public:
  virtual ~ITransport() = default;
  virtual HttpResponse post_json(const std::string& url, const std::string& body, std::chrono::milliseconds timeout) = 0;
};

/// Client configuration.
struct ClientOptions {
  /// Per-request timeout (connect + transfer).
  std::chrono::milliseconds timeout{15000};
  /// Hardware id override (8..256 chars). Default: Client::get_hardware_id().
  std::optional<std::string> hwid;
  /// Persists the device secret and the offline lease per product. Default: MemoryStore.
  std::shared_ptr<IStore> store;
  /// Allow plain http:// for hosts other than localhost / 127.0.0.1 / [::1]. Never enable in production.
  bool allow_insecure_http = false;
  /// User-Agent header. Default: "velsigil-cpp/<version>".
  std::string user_agent;
  /// Custom HTTP transport. Default: libcurl.
  std::shared_ptr<ITransport> transport;
  /// Clock returning unix seconds (tests, simulations). Default: the system clock.
  std::function<std::int64_t()> clock;
};

// ---------------------------------------------------------------------------------------------
// Low-level verification helpers (exposed for custom integrations)
//
// They refuse the two public keys of the SDK test vectors (test-vectors.json keys.publicKey and
// keys.wrongPublicKey, in any base64 spelling) like an invalid public key, ALWAYS: their private keys are
// published, so anyone could forge answers that verify with them, and unlike the Client (which accepts them
// for a localhost, 127.0.0.1 or [::1] API URL) these helpers have no API URL that could name a local test
// server. Use your product's public key (panel: Products > your product > Integration).
// ---------------------------------------------------------------------------------------------

/// `hwid_mismatch`: the signed lease or `activation.hwidHash` belongs to another device than the one
/// a device-bound request was sent for. `type_mismatch`: the signed payload answers another endpoint
/// than `expected_type` (see `verify_envelope_typed`).
enum class EnvelopeStatus { valid, invalid_signature, nonce_mismatch, product_mismatch, malformed, hwid_mismatch, type_mismatch };

struct EnvelopeVerification {
  EnvelopeStatus status = EnvelopeStatus::invalid_signature;
  std::string payload_json;  // decoded payload; only set when status == valid
};

/// Verifies a signed envelope (`{"data","sig","kid"}` JSON text): the Ed25519 signature over the
/// ASCII bytes of `data` is checked first, then the payload is decoded and its `nonce`, `productId`
/// and `type` are compared with the expected values.
///
/// `expected_type` is the endpoint the request went to: "validate", "deactivate", "update_check",
/// "download" or "trial". It must always be checked: the server also signs `ok: true` answers to update
/// checks, which need no license, so without it such an answer would pass as a validation. An empty
/// `expected_type` never matches (`type_mismatch`).
///
/// `expected_hwid` is the hwid of a device-bound request (validate, deactivate, download, trial): the signed
/// lease and the optional `activation.hwidHash` must also belong to that device, otherwise the status
/// is `hwid_mismatch` (a lease of another product: `product_mismatch`). Pass an empty `expected_hwid`
/// for update checks, which are not device-bound.
///
/// An invalid `public_key_base64` and the published test-vector keys (see above) yield `invalid_signature`
/// with an empty `payload_json`.
///
/// Deliberately a name of its own with exactly one signature and no default arguments: a call that
/// leaves out an argument does not compile, and it can never bind to one of the removed type-less
/// `verify_envelope` overloads below (where a fifth argument meant as the type would be taken as the
/// hwid and the type would go unchecked).
EnvelopeVerification verify_envelope_typed(std::string_view envelope_json, std::string_view public_key_base64,
                                           std::string_view expected_nonce, std::string_view expected_product_id,
                                           std::string_view expected_type, std::string_view expected_hwid) noexcept;

#if defined(VELSIGIL_ALLOW_UNTYPED_ENVELOPE)
// Opt-in for old code only (define VELSIGIL_ALLOW_UNTYPED_ENVELOPE for the WHOLE program, e.g. with
// target_compile_definitions(... PUBLIC ...), never for single files): the type-less overloads of
// releases before 2026-10-06, still [[deprecated]] and still UNSAFE. See CHANGELOG.md.

namespace untyped_detail {
/// Implementation of the opt-in overloads below (no `type` check; refuses the published test-vector keys
/// like verify_envelope_typed). Not part of the API.
EnvelopeVerification verify_envelope_untyped(std::string_view envelope_json, std::string_view public_key_base64,
                                             std::string_view expected_nonce, std::string_view expected_product_id,
                                             std::string_view expected_hwid) noexcept;
}  // namespace untyped_detail

/// Deprecated and UNSAFE: does not check the payload `type`, so a signed answer to another endpoint
/// (e.g. an update check, which needs no license) passes as a validation. Use `verify_envelope_typed`.
[[deprecated("unsafe: does not check the response type; use verify_envelope_typed(envelope_json, public_key_base64, "
             "expected_nonce, expected_product_id, expected_type, expected_hwid)")]]
inline EnvelopeVerification verify_envelope(std::string_view envelope_json, std::string_view public_key_base64,
                                            std::string_view expected_nonce, std::string_view expected_product_id) noexcept {
  return untyped_detail::verify_envelope_untyped(envelope_json, public_key_base64, expected_nonce, expected_product_id,
                                                 std::string_view());
}

/// Deprecated and UNSAFE: like `verify_envelope_typed` WITHOUT the `type` check; the fifth argument is
/// the hwid (an empty one skips the device-binding check), never the type. Use `verify_envelope_typed`.
[[deprecated("unsafe: does not check the response type, and the fifth argument is the hwid; use verify_envelope_typed("
             "envelope_json, public_key_base64, expected_nonce, expected_product_id, expected_type, expected_hwid)")]]
inline EnvelopeVerification verify_envelope(std::string_view envelope_json, std::string_view public_key_base64,
                                            std::string_view expected_nonce, std::string_view expected_product_id,
                                            std::string_view expected_hwid) noexcept {
  return untyped_detail::verify_envelope_untyped(envelope_json, public_key_base64, expected_nonce, expected_product_id,
                                                 expected_hwid);
}
#else
/// REMOVED (unsafe): the type-less `verify_envelope(envelope_json, public_key_base64, expected_nonce,
/// expected_product_id[, expected_hwid])` did not check the payload `type`, so a signed update-check
/// answer passed as a validation, and a fifth argument meant as the type was taken as the hwid. Every
/// call is a compile error ("use of deleted function"): call `verify_envelope_typed` instead. Old code
/// can get the deprecated overloads back by defining VELSIGIL_ALLOW_UNTYPED_ENVELOPE for the whole
/// program (CHANGELOG.md).
template <typename... Args>
EnvelopeVerification verify_envelope(Args&&...) = delete;
#endif

enum class LeaseStatus { valid, expired, invalid_signature, product_mismatch, hwid_mismatch, malformed };

/// Decoded offline-lease claims.
struct LeaseClaims {
  std::string product_id;
  std::string license_id;
  std::string activation_id;
  std::string hwid_hash;
  std::string plan;
  std::vector<std::string> features;
  std::optional<std::int64_t> license_expires_at;
  std::int64_t issued_at = 0;
  std::int64_t expires_at = 0;
  bool is_trial = false;  // the optional signed `trial` claim (SPEC 9.7)
};

struct LeaseVerification {
  LeaseStatus status = LeaseStatus::malformed;
  std::optional<LeaseClaims> claims;  // set for valid and expired leases
};

/// Verifies an offline lease token (SPEC 10.4) for `product_id` and the raw `hwid` string at time
/// `now_unix`. Signature first, then structure/type, product, device and expiry. An invalid
/// `public_key_base64` and the published test-vector keys (see above) yield `invalid_signature` without claims.
LeaseVerification verify_lease(std::string_view token, std::string_view public_key_base64, std::string_view product_id,
                               std::string_view hwid, std::int64_t now_unix) noexcept;

const char* to_string(EnvelopeStatus status) noexcept;
const char* to_string(LeaseStatus status) noexcept;

/// HWID derivation (SPEC 10.6): lowercase hex SHA-256 of "vx-hwid-v1:" + trimmed, lowercased machine id.
std::string compute_hardware_id(std::string_view machine_id);
/// Server-side device hash: lowercase hex SHA-256 of the hwid string (as used in leases).
std::string hash_hardware_id(std::string_view hwid);

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

class Client {
 public:
  /// `api_url`: your Velsigil origin, e.g. "https://licenses.example.com" (a URL that already ends in
  /// "/api/client/v1" is accepted too). `product_id`: the product UUID. `public_key_base64`: the
  /// product's Ed25519 public key (standard base64) - keep it compiled into your binary. The public test
  /// keys of the SDK test vectors, whose private keys are published, are refused like an invalid key unless
  /// the host of `api_url` is localhost, 127.0.0.1 or [::1] (a local test server).
  /// The constructor never throws; invalid arguments make every call return `invalid_configuration`.
  Client(std::string api_url, std::string product_id, std::string public_key_base64, ClientOptions options = {});
  ~Client();

  Client(Client&& other) noexcept;
  Client& operator=(Client&& other) noexcept;
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  /// False when the constructor rejected its arguments (see configuration_error()).
  bool is_configured() const noexcept;
  std::string configuration_error() const;
  /// The hwid this client sends (override or detected); empty when unavailable.
  const std::string& hardware_id() const noexcept;

  /// Validates (and on first use activates) the license on this device.
  ValidationResult validate(const std::string& license_key, const ValidateOptions& options = {});
  /// Starts a free trial of the product on this device without a license key (SPEC 9.7 "In-app trials";
  /// the seller turns on the in-app channel of the product's trial offer). On success `result.trial_key`
  /// holds the new license key: store it right away (the server can never send it again; the SDK does not
  /// persist it) and use validate() from then on. The device secret and the offline lease are stored like
  /// after a validation. Signed failures: trial_already_used, trial_unavailable, trial_email_required,
  /// trial_email_invalid, trial_email_not_accepted, trial_confirmation_sent (the key arrives by e-mail);
  /// panel_too_old when the server predates in-app trials. Call it only when the app has no key yet: when a
  /// device secret or an offline lease is already stored for the product it returns already_licensed without
  /// sending anything and leaves the stored state untouched, so a trial never replaces this device's license
  /// (validate the saved key, or deactivate() / clear_local_state() first). When the store cannot be read
  /// (IStore::get throws) it returns store_unavailable without sending anything.
  ValidationResult start_trial(const StartTrialOptions& options = {});
  /// Releases this device's activation slot. On success the stored lease and device secret are cleared.
  ValidationResult deactivate(const std::string& license_key);
  /// Asks for the latest published release (`result.update`).
  ValidationResult check_update(const std::string& current_version);
  /// Requests a short-lived download URL for a release (`result.download`); never activates a device.
  /// A signed grant whose URL violates the HTTPS policy (https only; plain http only for localhost,
  /// 127.0.0.1 and [::1] or with allow_insecure_http; no credentials) is rejected as `invalid_response`
  /// without a descriptor, and nothing from that response is stored.
  ValidationResult get_download(const std::string& license_key, const std::optional<std::string>& version = std::nullopt);
  /// Validates the stored offline lease without network access (`result.offline == true`).
  ValidationResult validate_offline();
  /// Online validation first; only when it fails with `network_error` the stored lease is used.
  ValidationResult validate_with_offline_fallback(const std::string& license_key, const ValidateOptions& options = {});

  /// Downloads a release described by get_download() to `destination` (streamed to a temporary file
  /// next to it, then renamed) and verifies its size and SHA-256 against the signed descriptor.
  DownloadFileResult download_release(const DownloadInfo& download, const std::filesystem::path& destination);

  /// Forgets the stored device secret and offline lease for this product.
  void clear_local_state();

  /// HWID of this machine (SPEC 10.6); empty string when the machine id cannot be read.
  static std::string get_hardware_id();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace velsigil

#endif  // VELSIGIL_CLIENT_HPP
