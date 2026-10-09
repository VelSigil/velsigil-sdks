// Velsigil C++ client SDK. Calls never throw; only a result with ok == true means licensed.
// A Client is thread-safe; custom IStore/ITransport must be too and must not call back into it.
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

/// SDK version.
inline constexpr char kSdkVersion[] = "1.0.4";

/// Result codes returned in ValidationResult::code.
namespace codes {
inline constexpr char kOk[] = "ok";

// Signed server results.
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
// The device already used a trial of this product; the stored lease is kept.
inline constexpr char kTrialAlreadyUsed[] = "trial_already_used";
// start_trial() failures; none of them clears the stored lease.
inline constexpr char kTrialUnavailable[] = "trial_unavailable";              // no in-app trial right now
inline constexpr char kTrialEmailRequired[] = "trial_email_required";         // the offer confirms an e-mail first
inline constexpr char kTrialEmailInvalid[] = "trial_email_invalid";
inline constexpr char kTrialEmailNotAccepted[] = "trial_email_not_accepted";  // throwaway or blocked domain
inline constexpr char kTrialConfirmationSent[] = "trial_confirmation_sent";   // the key arrives by e-mail

// Unsigned HTTP errors. They can never produce a successful result.
inline constexpr char kValidationError[] = "validation_error";
inline constexpr char kIpBlocked[] = "ip_blocked";
inline constexpr char kUnknownProduct[] = "unknown_product";
inline constexpr char kPayloadTooLarge[] = "payload_too_large";
inline constexpr char kUnsupportedMediaType[] = "unsupported_media_type";
inline constexpr char kRateLimited[] = "rate_limited";
inline constexpr char kInternalError[] = "internal_error";  // an unsigned 5xx triggers the offline fallback

// SDK-side codes, the same in every Velsigil SDK. kValidationError also covers local argument checks.
inline constexpr char kInvalidResponse[] = "invalid_response";            // unsigned, tampered or mismatched response
inline constexpr char kNetworkError[] = "network_error";                  // no HTTP response, or 502/503/504 without a Velsigil body
inline constexpr char kInvalidConfiguration[] = "invalid_configuration";  // constructor arguments were rejected
inline constexpr char kNoLease[] = "no_lease";                            // validate_offline(): nothing stored
inline constexpr char kLeaseExpired[] = "lease_expired";                  // stored lease is past its expiry
inline constexpr char kLeaseInvalid[] = "lease_invalid";                  // stored lease failed signature, product or device checks
inline constexpr char kPanelTooOld[] = "panel_too_old";                   // start_trial(): server has no in-app trial endpoint
inline constexpr char kAlreadyLicensed[] = "already_licensed";            // start_trial(): a device secret or lease is stored
inline constexpr char kStoreUnavailable[] = "store_unavailable";          // start_trial(): the store could not be read

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
  /// True for a free-trial license (also in offline leases).
  bool is_trial = false;
  /// Opaque reference a purchase uses to convert this trial; see ValidationResult::trial_ref().
  std::optional<std::string> trial_ref;
};

/// Query parameter (and Paddle/FastSpring key) that carries a trial conversion reference.
inline constexpr char kTrialRefParam[] = "velsigil_trial";

/// True for a well-formed trial conversion reference: 1-200 characters of [A-Za-z0-9_-].
bool is_trial_ref(std::string_view text) noexcept;

/// `url` with the trial reference added (client_reference_id for Stripe Payment Links); unchanged if invalid.
std::string with_trial_ref(std::string_view url, std::string_view ref);

/// The server-side device record ("activation") for this machine.
struct ActivationInfo {
  std::string id;
  std::string status;  // active | revoked
  std::int64_t first_seen_at = 0;
  /// True when this response issued a new device secret (stored by the SDK, never exposed).
  bool device_secret_issued = false;
};

/// Offline lease returned by a successful validation.
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
  /// Key of the trial start_trial() just started. The server sends it only once; store it.
  std::optional<std::string> trial_key;
  /// Offline results: the time of the check (unix seconds, adjusted by the server offset).
  std::optional<std::int64_t> reference_time;
  /// Seconds to wait before retrying, from the Retry-After header of an HTTP 429 or 503 answer.
  std::optional<std::int64_t> retry_after;

  explicit operator bool() const noexcept { return ok; }

  /// True only when the result is ok and the license grants `feature`.
  bool has_feature(std::string_view feature) const noexcept;
  /// License expiry in unix seconds; nullopt when there is no license or it never expires.
  std::optional<std::int64_t> expires_at() const noexcept;
  /// True when a license is present and has no expiry date.
  bool is_lifetime() const noexcept;
  /// True when a license is present and it is a free trial.
  bool is_trial() const noexcept;
  /// The trial's conversion reference for a "Buy now" link (online results only), or nullopt.
  std::optional<std::string> trial_ref() const;
  /// `buy_url` with this trial's conversion reference, or `buy_url` unchanged when there is none.
  std::string with_trial_ref(std::string_view buy_url) const;
  /// Seconds left until the license expires (clamped at 0); nullopt for lifetime / no license.
  std::optional<std::int64_t> seconds_until_expiry(std::int64_t now_unix) const noexcept;
  std::optional<std::int64_t> seconds_until_expiry() const noexcept;  // uses the system clock
  /// Days left until the license expires, rounded up; nullopt for lifetime / no license.
  std::optional<std::int64_t> days_until_expiry(std::int64_t now_unix) const noexcept;
  /// Measured at server_time, else reference_time, else the system clock.
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
  /// The customer's e-mail (<= 254 chars), used only when the trial offer confirms an address.
  std::optional<std::string> email;
};

/// Outcome of download_release().
struct DownloadFileResult {
  bool ok = false;
  std::string code;  // ok | network_error | download_failed | integrity_mismatch | io_error | validation_error | invalid_configuration
  std::string message;
  std::uint64_t bytes = 0;
};

/// Keys the Client reads and writes in its store (values are opaque strings).
namespace store_keys {
inline constexpr char kDeviceSecret[] = "deviceSecret";
inline constexpr char kLease[] = "lease";
}  // namespace store_keys

/// Key/value store partitioned by product id; must be thread-safe if the Client is shared.
class IStore {
 public:
  virtual ~IStore() = default;
  /// The stored value, or nullopt. Throw when the store cannot be read, never report "nothing stored".
  virtual std::optional<std::string> get(const std::string& product_id, const std::string& key) = 0;
  /// Returns false when the value could not be persisted.
  virtual bool set(const std::string& product_id, const std::string& key, const std::string& value) = 0;
  /// Returns false when the store could not be updated. Erasing a missing key succeeds.
  virtual bool erase(const std::string& product_id, const std::string& key) = 0;
};

/// Process-local store (the default). Nothing survives a restart; use FileStore in production.
class MemoryStore final : public IStore {
 public:
  std::optional<std::string> get(const std::string& product_id, const std::string& key) override;
  bool set(const std::string& product_id, const std::string& key, const std::string& value) override;
  bool erase(const std::string& product_id, const std::string& key) override;

 private:
  std::mutex mutex_;
  std::map<std::string, std::map<std::string, std::string>> values_;
};

/// JSON file store with atomic writes and owner-only permissions. Share one instance per file.
/// An unreadable file is never taken for empty: get() throws and set()/erase() return false.
/// Until the first write, reads fall back to a legacy veltrix-license.json in the same directory.
class FileStore final : public IStore {
 public:
  explicit FileStore(std::filesystem::path path);

  const std::filesystem::path& path() const noexcept { return path_; }
  /// Read-only legacy fallback file; empty unless path() uses the default file name.
  const std::filesystem::path& legacy_path() const noexcept { return legacy_path_; }

  /// Per-user default path for `app_name` (1-64 chars of [A-Za-z0-9._ -]); empty when unavailable.
  static std::filesystem::path default_path(std::string_view app_name);

  std::optional<std::string> get(const std::string& product_id, const std::string& key) override;
  bool set(const std::string& product_id, const std::string& key, const std::string& value) override;
  bool erase(const std::string& product_id, const std::string& key) override;

 private:
  std::filesystem::path path_;
  std::filesystem::path legacy_path_;
  std::mutex mutex_;
};

/// Raw HTTP exchange; `transport_ok == false` means no HTTP response (network_error).
struct HttpResponse {
  bool transport_ok = false;
  long status = 0;
  std::string body;
  std::string error;  // must not contain secrets
  /// Raw Retry-After header value; custom transports should set it too.
  std::optional<std::string> retry_after;
};

/// HTTP transport. The request body holds the license key and device secret: never log it.
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

// Low-level verification helpers. They always refuse the published test-vector public keys.

/// hwid_mismatch: the answer belongs to another device. type_mismatch: it answers another endpoint.
enum class EnvelopeStatus { valid, invalid_signature, nonce_mismatch, product_mismatch, malformed, hwid_mismatch, type_mismatch };

struct EnvelopeVerification {
  EnvelopeStatus status = EnvelopeStatus::invalid_signature;
  std::string payload_json;  // decoded payload; only set when status == valid
};

/// Verifies a signed envelope: the signature first, then `nonce`, `productId` and `type`.
/// Always pass `expected_type`, or an update-check answer could pass as a validation.
/// Pass an empty `expected_hwid` only for update checks, which are not device-bound.
EnvelopeVerification verify_envelope_typed(std::string_view envelope_json, std::string_view public_key_base64,
                                           std::string_view expected_nonce, std::string_view expected_product_id,
                                           std::string_view expected_type, std::string_view expected_hwid) noexcept;

#if defined(VELSIGIL_ALLOW_UNTYPED_ENVELOPE)
// Opt-in for old code: define VELSIGIL_ALLOW_UNTYPED_ENVELOPE for the whole program. Unsafe.

namespace untyped_detail {
/// Implementation of the opt-in overloads below; not part of the API.
EnvelopeVerification verify_envelope_untyped(std::string_view envelope_json, std::string_view public_key_base64,
                                             std::string_view expected_nonce, std::string_view expected_product_id,
                                             std::string_view expected_hwid) noexcept;
}  // namespace untyped_detail

/// Deprecated and unsafe: does not check the payload `type`. Use verify_envelope_typed.
[[deprecated("unsafe: does not check the response type; use verify_envelope_typed(envelope_json, public_key_base64, "
             "expected_nonce, expected_product_id, expected_type, expected_hwid)")]]
inline EnvelopeVerification verify_envelope(std::string_view envelope_json, std::string_view public_key_base64,
                                            std::string_view expected_nonce, std::string_view expected_product_id) noexcept {
  return untyped_detail::verify_envelope_untyped(envelope_json, public_key_base64, expected_nonce, expected_product_id,
                                                 std::string_view());
}

/// Deprecated and unsafe: no `type` check, and the fifth argument is the hwid. Use verify_envelope_typed.
[[deprecated("unsafe: does not check the response type, and the fifth argument is the hwid; use verify_envelope_typed("
             "envelope_json, public_key_base64, expected_nonce, expected_product_id, expected_type, expected_hwid)")]]
inline EnvelopeVerification verify_envelope(std::string_view envelope_json, std::string_view public_key_base64,
                                            std::string_view expected_nonce, std::string_view expected_product_id,
                                            std::string_view expected_hwid) noexcept {
  return untyped_detail::verify_envelope_untyped(envelope_json, public_key_base64, expected_nonce, expected_product_id,
                                                 expected_hwid);
}
#else
/// Removed: the type-less overloads were unsafe. Use verify_envelope_typed.
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
  bool is_trial = false;  // the optional signed `trial` claim
};

struct LeaseVerification {
  LeaseStatus status = LeaseStatus::malformed;
  std::optional<LeaseClaims> claims;  // set for valid and expired leases
};

/// Verifies an offline lease token for `product_id` and the raw `hwid` at `now_unix`.
LeaseVerification verify_lease(std::string_view token, std::string_view public_key_base64, std::string_view product_id,
                               std::string_view hwid, std::int64_t now_unix) noexcept;

const char* to_string(EnvelopeStatus status) noexcept;
const char* to_string(LeaseStatus status) noexcept;

/// HWID derivation: hex SHA-256 of "vx-hwid-v1:" + the trimmed, lowercased machine id.
std::string compute_hardware_id(std::string_view machine_id);
/// Server-side device hash: lowercase hex SHA-256 of the hwid string (as used in leases).
std::string hash_hardware_id(std::string_view hwid);

class Client {
 public:
  /// `api_url` is your Velsigil origin; keep `public_key_base64` compiled into your binary.
  /// Never throws; invalid arguments make every call return invalid_configuration.
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
  /// Starts an in-app free trial without a license key; `result.trial_key` holds the new key.
  /// The server sends the trial key only once; store it. Refused (already_licensed) if a lease is stored.
  ValidationResult start_trial(const StartTrialOptions& options = {});
  /// Releases this device's activation slot. On success the stored lease and device secret are cleared.
  ValidationResult deactivate(const std::string& license_key);
  /// Asks for the latest published release (`result.update`).
  ValidationResult check_update(const std::string& current_version);
  /// Requests a short-lived download URL for a release (`result.download`); never activates a device.
  ValidationResult get_download(const std::string& license_key, const std::optional<std::string>& version = std::nullopt);
  /// Validates the stored offline lease without network access (`result.offline == true`).
  ValidationResult validate_offline();
  /// Online validation, falling back to the stored lease when the server is unreachable or answers 5xx.
  ValidationResult validate_with_offline_fallback(const std::string& license_key, const ValidateOptions& options = {});

  /// Downloads a release from get_download() to `destination` and verifies its size and SHA-256.
  DownloadFileResult download_release(const DownloadInfo& download, const std::filesystem::path& destination);

  /// Forgets the stored device secret and offline lease for this product.
  void clear_local_state();

  /// HWID of this machine; empty when the machine id cannot be read.
  static std::string get_hardware_id();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace velsigil

#endif  // VELSIGIL_CLIENT_HPP
