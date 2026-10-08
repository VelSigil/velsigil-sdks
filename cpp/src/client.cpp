// Velsigil client: request construction, signed-envelope verification, result mapping, clock-skew
// recovery, device-secret persistence and offline leases (SPEC sections 10 and 14).
#include "velsigil/client.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <cctype>
#include <exception>
#include <limits>
#include <mutex>
#include <system_error>
#include <utility>

#include "detail.hpp"

namespace velsigil {
namespace {

using json = nlohmann::json;

constexpr char kApiSuffix[] = "/api/client/v1";
constexpr std::size_t kMaxMessageBytes = 1024;      // cap for server/transport text copied into results
constexpr std::size_t kMaxStoredValueBytes = 16384;  // cap for values persisted from responses
constexpr std::size_t kMaxRequestIdBytes = 128;
constexpr std::size_t kMaxTrialKeyChars = 64;  // a key as the server issues it (= the licenseKeyInput limit)

// ---- small string helpers -----------------------------------------------------------------------

bool is_ascii_space(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

std::string_view trim(std::string_view text) noexcept {
  while (!text.empty() && is_ascii_space(text.front())) text.remove_prefix(1);
  while (!text.empty() && is_ascii_space(text.back())) text.remove_suffix(1);
  return text;
}

std::string ascii_lower(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

bool ends_with(std::string_view text, std::string_view suffix) noexcept {
  return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool has_control_characters(std::string_view text) noexcept {
  for (const char c : text) {
    const auto u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7F) return true;
  }
  return false;
}

// Truncates to at most kMaxMessageBytes without splitting a UTF-8 sequence.
std::string clip(std::string text) {
  if (text.size() <= kMaxMessageBytes) return text;
  std::size_t cut = kMaxMessageBytes;
  while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) --cut;
  text.resize(cut);
  return text;
}

bool is_uuid(std::string_view text) noexcept {
  if (text.size() != 36) return false;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return false;
    } else if (std::isxdigit(static_cast<unsigned char>(c)) == 0) {
      return false;
    }
  }
  return true;
}

bool is_sha256_hex(std::string_view text) noexcept {
  if (text.size() != 64) return false;
  for (const char c : text) {
    if (std::isxdigit(static_cast<unsigned char>(c)) == 0) return false;
  }
  return true;
}

// The key of a started in-app trial: 1-64 printable ASCII characters, like every license key.
bool is_trial_key(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxTrialKeyChars) return false;
  for (const char c : text) {
    const auto u = static_cast<unsigned char>(c);
    if (u < 0x21 || u > 0x7E) return false;
  }
  return true;
}

// "https://host:port" part of an absolute URL (used to resolve relative download URLs).
std::string url_origin(std::string_view url) {
  const std::size_t scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos) return {};
  const std::size_t path_start = url.find_first_of("/?#", scheme_end + 3);
  return std::string(url.substr(0, path_start));
}

// The parts of an absolute URL the transport policy reads: the lowercased scheme and the host of the
// authority (no port; an IPv6 literal keeps its brackets). `error` explains a URL without a usable host.
// `host` views `url`, so it is valid only while `url` is. Shared by url_policy_error and is_loopback_url.
struct UrlTarget {
  std::string scheme;
  std::string_view host;
  std::optional<std::string> error;
};

UrlTarget parse_url_target(std::string_view url) {
  UrlTarget out;
  for (const char c : url) {
    const auto u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u == 0x7F) {
      out.error = std::string("The URL must not contain whitespace or control characters.");
      return out;
    }
  }
  const std::size_t scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos) {
    out.error = std::string("The URL must be absolute (https://...).");
    return out;
  }
  out.scheme = ascii_lower(url.substr(0, scheme_end));
  const std::string_view rest = url.substr(scheme_end + 3);
  const std::string_view authority = rest.substr(0, rest.find_first_of("/?#"));
  if (authority.find('@') != std::string_view::npos) {
    out.error = std::string("The URL must not contain credentials.");
    return out;
  }
  std::string_view host = authority;
  if (!host.empty() && host.front() == '[') {
    const std::size_t close = host.find(']');
    if (close == std::string_view::npos) {
      out.error = std::string("The URL contains an invalid IPv6 address.");
      return out;
    }
    host = host.substr(0, close + 1);
  } else {
    host = host.substr(0, host.find(':'));
  }
  if (host.empty()) {
    out.error = std::string("The URL has no host.");
    return out;
  }
  out.host = host;
  return out;
}

// ---- published test keys ------------------------------------------------------------------------

// The public keys of the shared SDK test vectors (sdks/test-vectors.json: keys.publicKey and
// keys.wrongPublicKey). Their private seeds are published in the same file, so anyone can sign answers
// that verify with them. The Client refuses them unless the API URL's host is loopback (a local test
// server); the public low-level helpers (verify_envelope_typed, verify_lease and the opt-in untyped
// verify_envelope) have no API URL and refuse them always. Internal; not part of the API.
constexpr const char* kPublishedTestPublicKeys[] = {
    "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=",
    "b/OKSQM/kKwu80PNfHkda3EM9dk1/ZmNKkQz/1azw/Q=",
};

constexpr char kPublishedTestKeyError[] =
    "This is the public test key from the Velsigil SDK test vectors, whose private key is published: anyone could "
    "forge license answers for it. Use your product's public key (panel: Products > your product > Integration).";

// Compares the decoded key bytes, so no other encoding of a test key (without padding, with surrounding
// whitespace) slips through.
bool is_published_test_key(const detail::PublicKey& key) {
  for (const char* encoded : kPublishedTestPublicKeys) {
    const auto test_key = detail::parse_public_key(encoded);
    if (test_key && *test_key == key) return true;
  }
  return false;
}

// ---- results ------------------------------------------------------------------------------------

ValidationResult failure(const char* code, std::string message) {
  ValidationResult result;
  result.ok = false;
  result.code = code;
  result.message = std::move(message);
  return result;
}

ValidationResult offline_failure(const char* code, std::string message) {
  ValidationResult result = failure(code, std::move(message));
  result.offline = true;
  return result;
}

ValidationResult not_initialised() {
  return failure(codes::kInvalidConfiguration, "The client is not initialised.");
}

ValidationResult unexpected_failure() {
  return failure(codes::kInvalidResponse, "An unexpected error occurred while processing the response.");
}

// ---- typed JSON field readers -------------------------------------------------------------------
// Each reader returns false when a field is present with an unexpected type (or missing although
// required). Optional fields that are absent or null leave the output untouched / reset.

enum class Need { optional, required };

bool to_int64(const json& value, std::int64_t& out) {
  if (value.is_number_unsigned()) {
    const auto v = value.get<std::uint64_t>();
    if (v > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) return false;
    out = static_cast<std::int64_t>(v);
    return true;
  }
  if (value.is_number_integer()) {
    out = value.get<std::int64_t>();
    return true;
  }
  if (value.is_number_float()) {
    const double d = value.get<double>();
    if (!(d >= -9.0e15 && d <= 9.0e15)) return false;  // also rejects NaN
    const auto i = static_cast<std::int64_t>(d);
    if (static_cast<double>(i) != d) return false;
    out = i;
    return true;
  }
  return false;
}

bool read_string(const json& object, const char* key, std::string& out, Need need) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) return need == Need::optional;
  if (!it->is_string()) return false;
  out = it->get<std::string>();
  return true;
}

bool read_optional_string(const json& object, const char* key, std::optional<std::string>& out) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) {
    out.reset();
    return true;
  }
  if (!it->is_string()) return false;
  out = it->get<std::string>();
  return true;
}

bool read_int(const json& object, const char* key, std::int64_t& out, Need need) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) return need == Need::optional;
  return to_int64(*it, out);
}

bool read_optional_int(const json& object, const char* key, std::optional<std::int64_t>& out) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) {
    out.reset();
    return true;
  }
  std::int64_t value = 0;
  if (!to_int64(*it, value)) return false;
  out = value;
  return true;
}

bool read_bool(const json& object, const char* key, bool& out, Need need) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) return need == Need::optional;
  if (!it->is_boolean()) return false;
  out = it->get<bool>();
  return true;
}

bool read_string_array(const json& object, const char* key, std::vector<std::string>& out) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) {
    out.clear();
    return true;
  }
  if (!it->is_array()) return false;
  std::vector<std::string> values;
  values.reserve(it->size());
  for (const auto& item : *it) {
    if (!item.is_string()) return false;
    values.push_back(item.get<std::string>());
  }
  out = std::move(values);
  return true;
}

// ---- payload sections ---------------------------------------------------------------------------

bool parse_license(const json& j, LicenseInfo& out) {
  return j.is_object() && read_string(j, "id", out.id, Need::required) && read_string(j, "plan", out.plan, Need::optional) &&
         read_string(j, "status", out.status, Need::required) && read_string_array(j, "features", out.features) &&
         read_optional_int(j, "expiresAt", out.expires_at) && read_int(j, "maxDevices", out.max_devices, Need::optional) &&
         read_int(j, "devicesUsed", out.devices_used, Need::optional) &&
         read_int(j, "createdAt", out.created_at, Need::optional) &&
         // Optional free-trial flag (SPEC 9.7): absent/null keeps false; a non-boolean is malformed.
         read_bool(j, "trial", out.is_trial, Need::optional) &&
         // Optional trial conversion reference (SPEC 9.7): absent/null = none; anything but a well-formed
         // string (1-200 characters of [A-Za-z0-9_-]) is malformed.
         read_optional_string(j, "trialRef", out.trial_ref) && (!out.trial_ref.has_value() || is_trial_ref(*out.trial_ref));
}

bool parse_activation(const json& j, ActivationInfo& out, std::optional<std::string>& issued_secret) {
  if (!j.is_object() || !read_string(j, "id", out.id, Need::required) || !read_string(j, "status", out.status, Need::optional) ||
      !read_int(j, "firstSeenAt", out.first_seen_at, Need::optional)) {
    return false;
  }
  std::optional<std::string> secret;
  if (!read_optional_string(j, "deviceSecret", secret)) return false;
  if (secret && !secret->empty()) {
    out.device_secret_issued = true;
    issued_secret = std::move(secret);
  }
  return true;
}

bool parse_lease(const json& j, Lease& out) {
  return j.is_object() && read_string(j, "token", out.token, Need::required) && !out.token.empty() &&
         read_int(j, "expiresAt", out.expires_at, Need::required);
}

bool parse_update(const json& j, UpdateInfo& out) {
  return j.is_object() && read_string(j, "latestVersion", out.latest_version, Need::required) &&
         read_optional_string(j, "minVersion", out.min_version) &&
         read_bool(j, "updateAvailable", out.update_available, Need::optional) &&
         read_bool(j, "mandatory", out.mandatory, Need::optional) && read_string(j, "changelog", out.changelog, Need::optional);
}

bool parse_download(const json& j, DownloadInfo& out) {
  return j.is_object() && read_string(j, "url", out.url, Need::required) &&
         read_int(j, "expiresAt", out.expires_at, Need::optional) && read_string(j, "fileName", out.file_name, Need::optional) &&
         read_int(j, "size", out.size, Need::optional) && read_string(j, "sha256", out.sha256, Need::optional) &&
         read_string(j, "version", out.version, Need::optional);
}

// Maps a verified payload to a result. nullopt when the payload does not have the expected shape.
std::optional<ValidationResult> result_from_payload(const json& payload, std::string_view type,
                                                    std::optional<std::string>& issued_secret) {
  ValidationResult result;
  bool ok_flag = false;
  std::string request_id;
  if (!read_bool(payload, "ok", ok_flag, Need::required) || !read_string(payload, "code", result.code, Need::required) ||
      result.code.empty() || !read_string(payload, "message", result.message, Need::optional) ||
      !read_string(payload, "requestId", request_id, Need::optional) ||
      !read_optional_int(payload, "serverTime", result.server_time)) {
    return std::nullopt;
  }
  // Defence in depth: a signed `ok` must also carry code `ok`. The one documented exception (SPEC 10.2)
  // is an update check with nothing published: `ok: true, code: no_release, update: null`.
  result.ok = ok_flag && (result.code == codes::kOk || (type == "update_check" && result.code == codes::kNoRelease));
  result.message = clip(std::move(result.message));
  if (!request_id.empty() && request_id.size() <= kMaxRequestIdBytes) result.request_id = std::move(request_id);

  if (const auto it = payload.find("license"); it != payload.end() && !it->is_null()) {
    LicenseInfo license;
    if (!parse_license(*it, license)) return std::nullopt;
    result.license = std::move(license);
  }
  if (const auto it = payload.find("activation"); it != payload.end() && !it->is_null()) {
    ActivationInfo activation;
    if (!parse_activation(*it, activation, issued_secret)) return std::nullopt;
    result.activation = std::move(activation);
  }
  if (const auto it = payload.find("lease"); it != payload.end() && !it->is_null()) {
    Lease lease;
    if (!parse_lease(*it, lease)) return std::nullopt;
    result.lease = std::move(lease);
  }
  if (const auto it = payload.find("update"); it != payload.end() && !it->is_null()) {
    UpdateInfo update;
    if (!parse_update(*it, update)) return std::nullopt;
    result.update = std::move(update);
  }
  if (const auto it = payload.find("download"); it != payload.end() && !it->is_null()) {
    DownloadInfo download;
    if (!parse_download(*it, download)) return std::nullopt;
    result.download = std::move(download);
  }
  // A started in-app trial (SPEC 10.1) must carry a well-formed key. The field is read on no other answer
  // (there it is ignored like any unknown field), so no other answer can hand the app a key.
  if (type == "trial" && result.ok) {
    const auto it = payload.find("trial");
    if (it == payload.end() || !it->is_object()) return std::nullopt;
    std::string key;
    if (!read_string(*it, "key", key, Need::required) || !is_trial_key(key)) return std::nullopt;
    result.trial_key = std::move(key);
  }
  return result;
}

// ---- envelope and lease verification ------------------------------------------------------------

struct OpenedEnvelope {
  EnvelopeStatus status = EnvelopeStatus::invalid_signature;
  std::string payload_text;
  json payload;
};

// Defined below; the device-binding check reuses the lease verifier.
LeaseVerification check_lease(std::string_view token, const detail::PublicKey& key, std::string_view product_id,
                              std::string_view hwid, std::int64_t now);

// The signature binds a payload to its request only through nonce, product and type. The answer to a
// device-bound request must also describe the requesting device: its signed lease (issued for
// sha256(hwid)) and the optional activation.hwidHash. A mismatch means the request (hwid, device
// secret) was rewritten in transit, e.g. by a license-sharing proxy. Returns `valid` or the failure;
// other lease defects (expired, ...) are not binding failures, such a lease is just never stored.
EnvelopeStatus check_device_binding(const json& payload, const detail::PublicKey& key, std::string_view product_id,
                                    std::string_view hwid) {
  if (const auto activation = payload.find("activation"); activation != payload.end() && activation->is_object()) {
    if (const auto claimed = activation->find("hwidHash"); claimed != activation->end() && !claimed->is_null()) {
      if (!claimed->is_string() || !is_sha256_hex(claimed->get_ref<const std::string&>())) return EnvelopeStatus::malformed;
      if (!detail::equals_ignore_case(claimed->get_ref<const std::string&>(), detail::sha256_hex(hwid))) {
        return EnvelopeStatus::hwid_mismatch;
      }
    }
  }
  if (const auto lease = payload.find("lease"); lease != payload.end() && lease->is_object()) {
    if (const auto token = lease->find("token"); token != lease->end() && token->is_string()) {
      std::int64_t server_time = 0;
      (void)read_int(payload, "serverTime", server_time, Need::optional);
      const LeaseStatus status = check_lease(token->get_ref<const std::string&>(), key, product_id, hwid, server_time).status;
      if (status == LeaseStatus::hwid_mismatch) return EnvelopeStatus::hwid_mismatch;
      if (status == LeaseStatus::product_mismatch) return EnvelopeStatus::product_mismatch;
    }
  }
  return EnvelopeStatus::valid;
}

// Core of open_envelope_typed and of the opt-in, deprecated public verify_envelope overloads. Call
// open_envelope_typed instead: `expected_type` std::nullopt skips the type check and is passed only
// by those overloads (through verify_envelope_text and untyped_detail::verify_envelope_untyped).
// `expected_type`: the endpoint of the request; the signed `type` must match it (an empty value never
// matches). `expected_hwid`: the hwid of a device-bound request (empty: no device-binding check).
OpenedEnvelope open_envelope_impl(const json& envelope, const detail::PublicKey& key, std::string_view expected_nonce,
                                  std::string_view expected_product_id, std::optional<std::string_view> expected_type,
                                  std::string_view expected_hwid) {
  OpenedEnvelope out;
  if (!envelope.is_object()) return out;
  const auto data_it = envelope.find("data");
  const auto sig_it = envelope.find("sig");
  if (data_it == envelope.end() || sig_it == envelope.end() || !data_it->is_string() || !sig_it->is_string()) return out;
  const std::string& data = data_it->get_ref<const std::string&>();

  // 1. Authenticate the exact ASCII bytes of `data` with the trusted key. Nothing from the payload
  //    is decoded or parsed before this succeeds. `kid` is deliberately ignored.
  const auto signature = detail::base64url_decode(sig_it->get_ref<const std::string&>());
  if (!signature || !detail::ed25519_verify(*signature, data, key)) return out;

  // 2. Decode and parse the authenticated payload.
  out.status = EnvelopeStatus::malformed;
  const auto raw = detail::base64url_decode(data);
  if (!raw) return out;
  out.payload_text.assign(raw->begin(), raw->end());
  json payload = json::parse(out.payload_text, nullptr, false);
  if (payload.is_discarded() || !payload.is_object()) {
    out.payload_text.clear();
    return out;
  }
  std::int64_t version = 0;
  if (!read_int(payload, "v", version, Need::required) || version != 1) {
    out.payload_text.clear();
    return out;
  }

  // 3. Bind the response to this request (nonce echo) and to this product.
  const auto nonce_it = payload.find("nonce");
  if (nonce_it == payload.end() || !nonce_it->is_string() || nonce_it->get_ref<const std::string&>() != expected_nonce) {
    out.status = EnvelopeStatus::nonce_mismatch;
    out.payload_text.clear();
    return out;
  }
  const auto product_it = payload.find("productId");
  if (product_it == payload.end() || !product_it->is_string() ||
      product_it->get_ref<const std::string&>() != expected_product_id) {
    out.status = EnvelopeStatus::product_mismatch;
    out.payload_text.clear();
    return out;
  }

  // 4. ...and to the endpoint it went to: the server signs `ok: true` for an update check (no license
  //    involved), which must never pass as the answer to a validate, deactivate or download request.
  if (expected_type) {
    const auto type_it = payload.find("type");
    if (expected_type->empty() || type_it == payload.end() || !type_it->is_string() ||
        type_it->get_ref<const std::string&>() != *expected_type) {
      out.status = EnvelopeStatus::type_mismatch;
      out.payload_text.clear();
      return out;
    }
  }

  // 5. For a device-bound request: the signed lease / activation must belong to this device.
  if (!expected_hwid.empty()) {
    const EnvelopeStatus binding = check_device_binding(payload, key, expected_product_id, expected_hwid);
    if (binding != EnvelopeStatus::valid) {
      out.status = binding;
      out.payload_text.clear();
      return out;
    }
  }
  out.status = EnvelopeStatus::valid;
  out.payload = std::move(payload);
  return out;
}

// Opens the envelope answering a request to the `expected_type` endpoint ("validate", "deactivate",
// "update_check", "download"): signature, version, nonce, product, type (always checked; an empty value
// never matches) and, with a non-empty `expected_hwid`, the device binding.
OpenedEnvelope open_envelope_typed(const json& envelope, const detail::PublicKey& key, std::string_view expected_nonce,
                                   std::string_view expected_product_id, std::string_view expected_type,
                                   std::string_view expected_hwid) {
  return open_envelope_impl(envelope, key, expected_nonce, expected_product_id,
                            std::optional<std::string_view>(expected_type), expected_hwid);
}

LeaseVerification check_lease(std::string_view token, const detail::PublicKey& key, std::string_view product_id,
                              std::string_view hwid, std::int64_t now) {
  LeaseVerification out;  // malformed
  const std::size_t dot = token.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 >= token.size() ||
      token.find('.', dot + 1) != std::string_view::npos) {
    return out;
  }
  const std::string_view body = token.substr(0, dot);
  const auto signature = detail::base64url_decode(token.substr(dot + 1));
  if (!signature) return out;

  // Signature over the ASCII bytes of the first part, verified before anything is decoded.
  if (!detail::ed25519_verify(*signature, body, key)) {
    out.status = LeaseStatus::invalid_signature;
    return out;
  }

  const auto raw = detail::base64url_decode(body);
  if (!raw) return out;
  const std::string text(raw->begin(), raw->end());
  const json payload = json::parse(text, nullptr, false);
  if (payload.is_discarded() || !payload.is_object()) return out;

  std::int64_t version = 0;
  std::string type;
  if (!read_int(payload, "v", version, Need::required) || version != 1 || !read_string(payload, "typ", type, Need::required) ||
      type != "lease") {
    return out;
  }
  LeaseClaims claims;
  if (!read_string(payload, "productId", claims.product_id, Need::required) ||
      !read_string(payload, "licenseId", claims.license_id, Need::optional) ||
      !read_string(payload, "activationId", claims.activation_id, Need::optional) ||
      !read_string(payload, "hwidHash", claims.hwid_hash, Need::required) ||
      !read_string(payload, "plan", claims.plan, Need::optional) || !read_string_array(payload, "features", claims.features) ||
      !read_optional_int(payload, "licenseExpiresAt", claims.license_expires_at) ||
      !read_int(payload, "iat", claims.issued_at, Need::optional) || !read_int(payload, "exp", claims.expires_at, Need::required) ||
      !read_bool(payload, "trial", claims.is_trial, Need::optional)) {
    return out;
  }
  if (claims.product_id != product_id) {
    out.status = LeaseStatus::product_mismatch;
    return out;
  }
  if (!detail::equals_ignore_case(claims.hwid_hash, detail::sha256_hex(hwid))) {
    out.status = LeaseStatus::hwid_mismatch;
    return out;
  }
  const bool expired = !(now < claims.expires_at) || (claims.license_expires_at && !(now < *claims.license_expires_at));
  out.status = expired ? LeaseStatus::expired : LeaseStatus::valid;
  out.claims = std::move(claims);
  return out;
}

const char* envelope_failure_message(EnvelopeStatus status) noexcept {
  switch (status) {
    case EnvelopeStatus::invalid_signature:
      return "The response signature is missing or invalid.";
    case EnvelopeStatus::nonce_mismatch:
      return "The response does not belong to this request (nonce mismatch).";
    case EnvelopeStatus::product_mismatch:
      return "The response was issued for a different product.";
    case EnvelopeStatus::malformed:
      return "The signed response payload is malformed.";
    case EnvelopeStatus::hwid_mismatch:
      return "The response is for a different device (its lease or activation belongs to another hardware id).";
    case EnvelopeStatus::type_mismatch:
      return "The signed response has an unexpected type.";
    case EnvelopeStatus::valid:
      break;
  }
  return "The response could not be verified.";
}

const char* lease_failure_message(LeaseStatus status) noexcept {
  switch (status) {
    case LeaseStatus::expired:
      return "The offline lease has expired; connect to the license server to renew it.";
    case LeaseStatus::invalid_signature:
      return "The stored offline lease has an invalid signature.";
    case LeaseStatus::product_mismatch:
      return "The stored offline lease was issued for a different product.";
    case LeaseStatus::hwid_mismatch:
      return "The stored offline lease was issued for a different device.";
    case LeaseStatus::malformed:
      return "The stored offline lease is malformed.";
    case LeaseStatus::valid:
      break;
  }
  return "The stored offline lease could not be verified.";
}

bool is_safe_request_id(std::string_view value) noexcept {
  if (value.empty() || value.size() > kMaxRequestIdBytes) return false;
  for (const char c : value) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' ||
                    c == '.' || c == ':';
    if (!ok) return false;
  }
  return true;
}

// Fixed SDK text for unsigned failures: text from an unsigned (attacker-controllable) body is never shown.
std::string unsigned_message(const char* code, long status) {
  const std::string_view c(code);
  if (c == codes::kValidationError) return "The license server rejected the request as invalid.";
  if (c == codes::kIpBlocked) return "Requests from this network are temporarily blocked by the license server.";
  if (c == codes::kUnknownProduct) return "The license server does not know this product.";
  if (c == codes::kRateLimited) return "Too many requests; try again later.";
  if (c == codes::kInternalError) return "The license server encountered an error.";
  if (c == codes::kPayloadTooLarge) return "The request was too large.";
  if (c == codes::kUnsupportedMediaType) return "The license server rejected the request format.";
  if (c == codes::kNetworkError) return "The license server is unavailable (HTTP " + std::to_string(status) + ").";
  if (c == codes::kPanelTooOld) {
    return "The license server does not support starting free trials from the app yet. The seller needs to update the "
           "Velsigil panel.";
  }
  return "Unexpected HTTP " + std::to_string(status) + " response from the license server.";
}

// Unsigned HTTP error (status != 200). Never produces success. The mapping is identical in every
// Velsigil SDK (SPEC section 14): a known code in a Velsigil error body ({"error":{"code":...}}) wins;
// otherwise 400 -> validation_error, 413 -> payload_too_large, 415 -> unsupported_media_type,
// 429 -> rate_limited, 502/503/504 -> network_error without a Velsigil error body (a proxy in front of
// an unreachable server, so the offline fallback applies) or internal_error with one, other 5xx ->
// internal_error, anything else -> invalid_response. `type`: the endpoint of the request; a Velsigil 404
// `not_found` from the in-app trial endpoint means the server predates it (panel_too_old).
ValidationResult unsigned_failure(long status, const json* body, std::string_view type) {
  std::string code;
  std::string request_id;
  bool velsigil_body = false;
  if (body != nullptr) {
    const auto error_it = body->find("error");
    if (error_it != body->end() && error_it->is_object()) {
      const auto code_it = error_it->find("code");
      if (code_it != error_it->end() && code_it->is_string()) {
        velsigil_body = true;
        code = code_it->get<std::string>();
      }
      // Wrong types simply leave the field empty; this response is untrusted either way.
      (void)read_string(*error_it, "requestId", request_id, Need::optional);
    }
  }
  static constexpr const char* kKnownCodes[] = {codes::kValidationError,  codes::kIpBlocked,
                                                codes::kUnknownProduct,   codes::kPayloadTooLarge,
                                                codes::kUnsupportedMediaType, codes::kRateLimited,
                                                codes::kInternalError};
  const char* mapped = nullptr;
  for (const char* known : kKnownCodes) {
    if (code == known) {
      mapped = known;
      break;
    }
  }
  if (mapped == nullptr && type == "trial" && status == 404 && velsigil_body && code == "not_found") {
    mapped = codes::kPanelTooOld;
  }
  if (mapped == nullptr) {
    if (status == 400) {
      mapped = codes::kValidationError;
    } else if (status == 429) {
      mapped = codes::kRateLimited;
    } else if (status == 413) {
      mapped = codes::kPayloadTooLarge;
    } else if (status == 415) {
      mapped = codes::kUnsupportedMediaType;
    } else if (status == 502 || status == 503 || status == 504) {
      mapped = velsigil_body ? codes::kInternalError : codes::kNetworkError;
    } else if (status >= 500 && status <= 599) {
      mapped = codes::kInternalError;
    } else {
      mapped = codes::kInvalidResponse;
    }
  }
  ValidationResult result = failure(mapped, unsigned_message(mapped, status));
  if (is_safe_request_id(request_id)) result.request_id = std::move(request_id);
  return result;
}

// Signed denials after which a stored offline lease must not be used any more. This exact set is
// binding for every Velsigil SDK (SPEC section 14); any other signed failure keeps the lease.
bool revokes_offline_access(const std::string& code) {
  static constexpr const char* kCodes[] = {codes::kInvalidKey,         codes::kLicenseExpired,
                                           codes::kLicenseSuspended,   codes::kLicenseRevoked,
                                           codes::kLicenseBanned,      codes::kDeviceRevoked,
                                           codes::kDeviceVerificationFailed, codes::kDeviceLimitReached,
                                           codes::kDeviceNotActivated, codes::kDeviceNotFound,
                                           codes::kBlacklisted,        codes::kProductDisabled};
  for (const char* candidate : kCodes) {
    if (code == candidate) return true;
  }
  return false;
}

constexpr std::size_t kMaxLicenseKeyChars = 64;   // server-side licenseKeyInput limit
constexpr std::size_t kMaxVersionChars = 32;
constexpr std::size_t kMaxDeviceNameBytes = 255;  // the server counts characters; bytes are a safe upper bound
constexpr std::size_t kMaxEmailBytes = 254;       // the server's e-mail schema limit

// already_licensed (SPEC 14): start_trial() on a device that already holds a license (stored secret or lease).
constexpr char kAlreadyLicensedMessage[] =
    "This device already holds a license for this product (a stored device secret or offline lease); a free trial "
    "cannot replace it. Validate the saved license key instead, or call deactivate() or clear_local_state() first. "
    "No request was sent.";

// store_unavailable (SPEC 14): start_trial() could not read the store, so it cannot tell whether a license is stored.
constexpr char kStoreUnavailableMessage[] =
    "The license store could not be read, so it is unknown whether this device already holds a license for this "
    "product; a free trial was not started. Try again once the store can be read. No request was sent.";

// Local argument checks (SPEC 14 `validation_error`): nothing is sent when they fail.
std::optional<ValidationResult> check_inputs(const std::string* license_key, const std::optional<std::string>& version,
                                             const std::optional<std::string>& device_name) {
  if (license_key != nullptr) {
    const std::string_view key = trim(*license_key);
    if (key.empty()) return failure(codes::kValidationError, "A license key is required.");
    if (key.size() > kMaxLicenseKeyChars || has_control_characters(key)) {
      return failure(codes::kValidationError, "The license key format is invalid.");
    }
  }
  if (version && (version->size() > kMaxVersionChars || has_control_characters(*version))) {
    return failure(codes::kValidationError, "The version must be at most 32 printable characters.");
  }
  if (device_name && (device_name->size() > kMaxDeviceNameBytes || has_control_characters(*device_name))) {
    return failure(codes::kValidationError, "The device name must be at most 255 printable characters.");
  }
  return std::nullopt;
}

struct Interpreted {
  ValidationResult result;
  bool verified = false;  // a valid signed payload bound to this request
  std::optional<std::string> issued_secret;
};

}  // namespace

// ---- detail helpers implemented here --------------------------------------------------------------

namespace detail {

bool is_loopback_host(std::string_view host) noexcept {
  return equals_ignore_case(host, "localhost") || equals_ignore_case(host, "127.0.0.1") || equals_ignore_case(host, "[::1]");
}

std::optional<std::string> url_policy_error(std::string_view url, bool allow_insecure_http) {
  UrlTarget target = parse_url_target(url);
  if (target.error) return std::move(target.error);
  if (target.scheme == "https") return std::nullopt;
  if (target.scheme != "http") return std::string("Only https:// URLs are supported.");
  if (allow_insecure_http || is_loopback_host(target.host)) return std::nullopt;
  return std::string(
      "HTTPS is required; plain http:// is only accepted for localhost, 127.0.0.1 and [::1] unless "
      "allow_insecure_http is set.");
}

bool is_loopback_url(std::string_view url) {
  const UrlTarget target = parse_url_target(url);
  return !target.error && is_loopback_host(target.host);
}

std::int64_t system_unix_time() noexcept {
  using std::chrono::duration_cast;
  using std::chrono::seconds;
  using std::chrono::system_clock;
  return static_cast<std::int64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

}  // namespace detail

// ---- ValidationResult helpers ---------------------------------------------------------------------

bool ValidationResult::has_feature(std::string_view feature) const noexcept {
  if (!ok || !license) return false;
  for (const auto& granted : license->features) {
    if (granted == feature) return true;
  }
  return false;
}

std::optional<std::int64_t> ValidationResult::expires_at() const noexcept {
  if (!license) return std::nullopt;
  return license->expires_at;
}

bool ValidationResult::is_lifetime() const noexcept { return license.has_value() && !license->expires_at.has_value(); }

bool ValidationResult::is_trial() const noexcept { return license.has_value() && license->is_trial; }

std::optional<std::string> ValidationResult::trial_ref() const {
  if (!license) return std::nullopt;
  return license->trial_ref;
}

std::string ValidationResult::with_trial_ref(std::string_view buy_url) const {
  if (!license || !license->trial_ref) return std::string(buy_url);
  // Qualified: the member of the same name would hide the free function.
  return velsigil::with_trial_ref(buy_url, *license->trial_ref);
}

// ---- trial conversion references (SPEC 9.7) --------------------------------------------------------------

bool is_trial_ref(std::string_view text) noexcept {
  if (text.empty() || text.size() > 200) return false;
  for (const char c : text) {
    const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    if (!allowed) return false;
  }
  return true;
}

std::string with_trial_ref(std::string_view url, std::string_view ref) {
  std::string out(url);
  if (!is_trial_ref(ref)) return out;
  // Only absolute http(s) URLs; the host decides the parameter (Stripe Payment Links have their own).
  std::size_t rest_start = 0;
  const std::string lower = ascii_lower(url);
  if (lower.rfind("https://", 0) == 0) {
    rest_start = 8;
  } else if (lower.rfind("http://", 0) == 0) {
    rest_start = 7;
  } else {
    return out;
  }
  const std::size_t host_end = lower.find_first_of("/?#", rest_start);
  std::string authority = host_end == std::string::npos ? lower.substr(rest_start) : lower.substr(rest_start, host_end - rest_start);
  const std::size_t at = authority.rfind('@');
  if (at != std::string::npos) authority = authority.substr(at + 1);
  const std::size_t colon = authority.find(':');
  if (colon != std::string::npos) authority = authority.substr(0, colon);
  if (authority.empty()) return out;
  const std::string param = authority == "buy.stripe.com" ? std::string("client_reference_id") : std::string(kTrialRefParam);
  const std::size_t hash_at = out.find('#');
  const std::string base = hash_at == std::string::npos ? out : out.substr(0, hash_at);
  const std::string fragment = hash_at == std::string::npos ? std::string() : out.substr(hash_at);
  std::string separator = "&";
  if (base.find('?') == std::string::npos) {
    separator = "?";
  } else if (!base.empty() && (base.back() == '?' || base.back() == '&')) {
    separator.clear();
  }
  return base + separator + param + "=" + std::string(ref) + fragment;
}

std::optional<std::int64_t> ValidationResult::seconds_until_expiry(std::int64_t now_unix) const noexcept {
  if (!license || !license->expires_at) return std::nullopt;
  const std::int64_t expiry = *license->expires_at;
  return expiry > now_unix ? expiry - now_unix : 0;
}

std::optional<std::int64_t> ValidationResult::seconds_until_expiry() const noexcept {
  return seconds_until_expiry(detail::system_unix_time());
}

std::optional<std::int64_t> ValidationResult::days_until_expiry(std::int64_t now_unix) const noexcept {
  const auto seconds = seconds_until_expiry(now_unix);
  if (!seconds) return std::nullopt;
  // Rounded up (CLIENT_PROTOCOL 5.2): a part day still counts as a day left. `*seconds` is never negative.
  return *seconds / 86400 + (*seconds % 86400 != 0 ? 1 : 0);
}

std::optional<std::int64_t> ValidationResult::days_until_expiry() const noexcept {
  // The result's own time: the signed server time of an online answer, the time of an offline check.
  if (server_time) return days_until_expiry(*server_time);
  if (reference_time) return days_until_expiry(*reference_time);
  return days_until_expiry(detail::system_unix_time());
}

// ---- free functions -------------------------------------------------------------------------------

namespace {

// Whether a low-level helper refuses the published test-vector keys. The public helpers always pass
// `refuse`: unlike the Client they have no API URL that could name a local test server. Only the internal
// detail::*_unguarded entry points (the SDK's own test-vector conformance tests) pass `accept`.
enum class TestKeys { refuse, accept };

// Shared by verify_envelope_typed, untyped_detail::verify_envelope_untyped (the opt-in, deprecated
// verify_envelope overloads) and detail::verify_envelope_typed_unguarded; `expected_type` is std::nullopt
// only for the untyped one.
EnvelopeVerification verify_envelope_text(std::string_view envelope_json, std::string_view public_key_base64,
                                          std::string_view expected_nonce, std::string_view expected_product_id,
                                          std::optional<std::string_view> expected_type, std::string_view expected_hwid,
                                          TestKeys test_keys) noexcept {
  try {
    EnvelopeVerification verification;
    const auto key = detail::parse_public_key(public_key_base64);
    // A published test-vector key takes the path of an invalid key (invalid_signature, no payload): anyone
    // can sign answers that verify with it.
    if (!key || (test_keys == TestKeys::refuse && is_published_test_key(*key))) return verification;
    const json envelope = json::parse(std::string(envelope_json), nullptr, false);
    if (envelope.is_discarded()) return verification;
    OpenedEnvelope opened =
        open_envelope_impl(envelope, *key, expected_nonce, expected_product_id, expected_type, expected_hwid);
    verification.status = opened.status;
    if (opened.status == EnvelopeStatus::valid) verification.payload_json = std::move(opened.payload_text);
    return verification;
  } catch (...) {
    return EnvelopeVerification{};
  }
}

// Shared by verify_lease and detail::verify_lease_unguarded.
LeaseVerification verify_lease_text(std::string_view token, std::string_view public_key_base64, std::string_view product_id,
                                    std::string_view hwid, std::int64_t now_unix, TestKeys test_keys) noexcept {
  try {
    const auto key = detail::parse_public_key(public_key_base64);
    // A published test-vector key takes the path of an invalid key (see verify_envelope_text).
    if (!key || (test_keys == TestKeys::refuse && is_published_test_key(*key))) {
      LeaseVerification verification;
      verification.status = LeaseStatus::invalid_signature;
      return verification;
    }
    return check_lease(token, *key, product_id, hwid, now_unix);
  } catch (...) {
    return LeaseVerification{};
  }
}

}  // namespace

EnvelopeVerification verify_envelope_typed(std::string_view envelope_json, std::string_view public_key_base64,
                                           std::string_view expected_nonce, std::string_view expected_product_id,
                                           std::string_view expected_type, std::string_view expected_hwid) noexcept {
  return verify_envelope_text(envelope_json, public_key_base64, expected_nonce, expected_product_id,
                              std::optional<std::string_view>(expected_type), expected_hwid, TestKeys::refuse);
}

// Behind the opt-in, deprecated and unsafe `verify_envelope` overloads of client.hpp (no type check),
// which exist only where VELSIGIL_ALLOW_UNTYPED_ENVELOPE is defined (inline wrappers calling this).
// Always compiled, so that the library itself never needs the macro.
namespace untyped_detail {
EnvelopeVerification verify_envelope_untyped(std::string_view envelope_json, std::string_view public_key_base64,
                                             std::string_view expected_nonce, std::string_view expected_product_id,
                                             std::string_view expected_hwid) noexcept {
  return verify_envelope_text(envelope_json, public_key_base64, expected_nonce, expected_product_id, std::nullopt,
                              expected_hwid, TestKeys::refuse);
}
}  // namespace untyped_detail

LeaseVerification verify_lease(std::string_view token, std::string_view public_key_base64, std::string_view product_id,
                               std::string_view hwid, std::int64_t now_unix) noexcept {
  return verify_lease_text(token, public_key_base64, product_id, hwid, now_unix, TestKeys::refuse);
}

// Internal entry points for the SDK's own test-vector conformance tests (declared in detail.hpp, not
// installed): the same verification without the refusal of the published test-vector keys.
namespace detail {
EnvelopeVerification verify_envelope_typed_unguarded(std::string_view envelope_json, std::string_view public_key_base64,
                                                     std::string_view expected_nonce, std::string_view expected_product_id,
                                                     std::string_view expected_type, std::string_view expected_hwid) noexcept {
  return verify_envelope_text(envelope_json, public_key_base64, expected_nonce, expected_product_id,
                              std::optional<std::string_view>(expected_type), expected_hwid, TestKeys::accept);
}

LeaseVerification verify_lease_unguarded(std::string_view token, std::string_view public_key_base64,
                                         std::string_view product_id, std::string_view hwid, std::int64_t now_unix) noexcept {
  return verify_lease_text(token, public_key_base64, product_id, hwid, now_unix, TestKeys::accept);
}
}  // namespace detail

const char* to_string(EnvelopeStatus status) noexcept {
  switch (status) {
    case EnvelopeStatus::valid:
      return "valid";
    case EnvelopeStatus::invalid_signature:
      return "invalid_signature";
    case EnvelopeStatus::nonce_mismatch:
      return "nonce_mismatch";
    case EnvelopeStatus::product_mismatch:
      return "product_mismatch";
    case EnvelopeStatus::malformed:
      return "malformed";
    case EnvelopeStatus::hwid_mismatch:
      return "hwid_mismatch";
    case EnvelopeStatus::type_mismatch:
      return "type_mismatch";
  }
  return "unknown";
}

const char* to_string(LeaseStatus status) noexcept {
  switch (status) {
    case LeaseStatus::valid:
      return "valid";
    case LeaseStatus::expired:
      return "expired";
    case LeaseStatus::invalid_signature:
      return "invalid_signature";
    case LeaseStatus::product_mismatch:
      return "product_mismatch";
    case LeaseStatus::hwid_mismatch:
      return "hwid_mismatch";
    case LeaseStatus::malformed:
      return "malformed";
  }
  return "unknown";
}

std::string compute_hardware_id(std::string_view machine_id) {
  std::string input = "vx-hwid-v1:";
  input += detail::normalize_machine_id(machine_id);
  return detail::sha256_hex(input);
}

std::string hash_hardware_id(std::string_view hwid) { return detail::sha256_hex(hwid); }

// ---- Client::Impl ---------------------------------------------------------------------------------

struct Client::Impl {
  std::string endpoint_base;  // "<origin>/api/client/v1"
  std::string origin;         // "<scheme>://<authority>"
  std::string product_id;
  detail::PublicKey public_key{};
  std::string hwid;
  std::chrono::milliseconds timeout{15000};
  bool allow_insecure_http = false;
  std::string user_agent;
  std::shared_ptr<IStore> store;
  std::shared_ptr<ITransport> transport;
  std::function<std::int64_t()> clock;
  std::string config_error;  // empty when the configuration is valid
  std::atomic<std::int64_t> clock_offset{0};
  // Serializes the device-bound calls (validate, start_trial, deactivate, get_download, clear_local_state):
  // reading the stored state, the request and persisting the answer form one step, as in the Node and Python
  // SDKs. So a device secret issued to the first of two concurrent activations is sent by the second, and
  // start_trial's already_licensed check cannot be overtaken by a concurrent validate. Not recursive: Impl
  // methods never take it; the Client member functions do, once each.
  std::mutex device_mutex;

  void configure(std::string api_url, std::string product, const std::string& public_key_base64, ClientOptions options) {
    auto reject = [this](std::string message) {
      if (config_error.empty()) config_error = std::move(message);
    };

    timeout = options.timeout;
    allow_insecure_http = options.allow_insecure_http;
    clock = std::move(options.clock);
    store = options.store ? std::move(options.store) : std::shared_ptr<IStore>(std::make_shared<MemoryStore>());
    user_agent = options.user_agent.empty() ? std::string("velsigil-cpp/") + kSdkVersion : options.user_agent;
    if (has_control_characters(user_agent)) {
      reject("ClientOptions::user_agent must not contain control characters.");
      user_agent = std::string("velsigil-cpp/") + kSdkVersion;
    }
    transport = options.transport ? std::move(options.transport)
                                  : std::shared_ptr<ITransport>(std::make_shared<detail::CurlTransport>(user_agent));

    if (!detail::crypto_ready()) reject("libsodium could not be initialised.");

    std::string base(trim(api_url));
    while (!base.empty() && base.back() == '/') base.pop_back();
    if (const auto error = detail::url_policy_error(base, allow_insecure_http)) {
      reject("Invalid API URL: " + *error);
    } else if (base.find_first_of("?#") != std::string::npos) {
      reject("Invalid API URL: it must not contain a query string or fragment.");
    }
    if (!ends_with(base, kApiSuffix)) base += kApiSuffix;
    origin = url_origin(base);
    endpoint_base = std::move(base);

    // The server echoes the canonical lowercase id in every signed payload; compare against that form.
    product_id = ascii_lower(trim(product));
    if (!is_uuid(product_id)) reject("The product id must be a UUID.");

    if (const auto key = detail::parse_public_key(public_key_base64)) {
      public_key = *key;
      // A published test-vector key is only good for a local test server: the hosts that may also use plain
      // http:// (the same helper decides both), whatever the scheme. Elsewhere it would accept forged answers.
      if (is_published_test_key(*key) && !detail::is_loopback_url(endpoint_base)) reject(kPublishedTestKeyError);
    } else {
      reject("The public key must be the standard base64 encoding of a raw 32-byte Ed25519 key.");
    }

    if (options.hwid) {
      hwid = *options.hwid;
      if (hwid.size() < 8 || hwid.size() > 256 || has_control_characters(hwid)) {
        reject("ClientOptions::hwid must be 8 to 256 printable characters.");
      }
    } else {
      hwid = Client::get_hardware_id();
      if (hwid.empty()) reject("The hardware id could not be determined; set ClientOptions::hwid.");
    }

    if (timeout.count() <= 0) reject("ClientOptions::timeout must be positive.");
  }

  std::int64_t local_now() const { return clock ? clock() : detail::system_unix_time(); }
  std::int64_t server_now() const { return local_now() + clock_offset.load(std::memory_order_relaxed); }

  // One store read. `readable` is false when the store threw: the value is then unknown, which is not the same
  // as "nothing stored" (start_trial refuses on it).
  struct StoredValue {
    bool readable = true;
    std::optional<std::string> value;
  };

  // Store access never lets an exception or failure escape: persistence is best effort.
  StoredValue read(const char* key) const {
    StoredValue out;
    try {
      out.value = store->get(product_id, key);
      if (out.value && out.value->size() > kMaxStoredValueBytes) out.value.reset();
    } catch (...) {
      out.readable = false;
      out.value.reset();
    }
    return out;
  }

  std::optional<std::string> load(const char* key) const { return read(key).value; }

  void save(const char* key, const std::string& value) const {
    try {
      (void)store->set(product_id, key, value);
    } catch (...) {
    }
  }

  void forget(const char* key) const {
    try {
      (void)store->erase(product_id, key);
    } catch (...) {
    }
  }

  // Absolute form of a download URL: a server-relative URL ("/...") is resolved against the API origin.
  std::string resolve_download_url(const std::string& url) const {
    if (!url.empty() && url.front() == '/') return origin + url;
    return url;
  }

  // `bound_hwid`: the hwid sent with a device-bound request (empty for update checks); the signed
  // lease/activation must then belong to this device, otherwise nothing from the response is used.
  Interpreted interpret(const HttpResponse& response, const std::string& nonce, std::string_view type,
                        std::string_view bound_hwid) const {
    Interpreted out;
    const json body = json::parse(response.body, nullptr, false);
    const bool is_object = !body.is_discarded() && body.is_object();
    if (response.status != 200) {
      out.result = unsigned_failure(response.status, is_object ? &body : nullptr, type);
      return out;
    }
    if (!is_object) {
      out.result = failure(codes::kInvalidResponse, "The license server response is not a signed envelope.");
      return out;
    }
    // Signature, version, nonce, product, type (the endpoint of this request) and device binding.
    OpenedEnvelope opened = open_envelope_typed(body, public_key, nonce, product_id, type, bound_hwid);
    if (opened.status != EnvelopeStatus::valid) {
      out.result = failure(codes::kInvalidResponse, envelope_failure_message(opened.status));
      return out;
    }
    auto parsed = result_from_payload(opened.payload, type, out.issued_secret);
    if (!parsed) {
      out.issued_secret.reset();
      out.result = failure(codes::kInvalidResponse, envelope_failure_message(EnvelopeStatus::malformed));
      return out;
    }
    // A download grant must be usable under the client's HTTPS policy (https; plain http only for
    // localhost / 127.0.0.1 / [::1] or with allow_insecure_http; no credentials). Reject it already
    // here, like the other Velsigil SDKs: the result carries no descriptor and nothing from the
    // response is persisted. download_release() keeps its own check as a second line of defence.
    if (parsed->download) {
      if (const auto error =
              detail::url_policy_error(resolve_download_url(parsed->download->url), allow_insecure_http)) {
        out.issued_secret.reset();
        out.result = failure(codes::kInvalidResponse, "The server returned a download URL that is not allowed: " + *error);
        out.result.request_id = std::move(parsed->request_id);
        out.result.server_time = parsed->server_time;
        return out;
      }
    }
    out.result = std::move(*parsed);
    out.verified = true;
    return out;
  }

  // Persists what a verified response hands out and drops local state the server invalidated.
  void persist(std::string_view type, const Interpreted& interpreted) const {
    const ValidationResult& result = interpreted.result;
    if (interpreted.issued_secret && interpreted.issued_secret->size() <= kMaxStoredValueBytes) {
      save(store_keys::kDeviceSecret, *interpreted.issued_secret);
    }
    // A started in-app trial is a validation of the new license on this device: the same lease rules.
    if (type == "validate" || type == "trial") {
      if (result.ok) {
        // A lease is only issued when the product allows offline use; otherwise drop any old one. A
        // lease that would not verify for this product and device (at the signed server time) is
        // never stored.
        const bool usable = result.lease && result.lease->token.size() <= kMaxStoredValueBytes &&
                            check_lease(result.lease->token, public_key, product_id, hwid,
                                        result.server_time.value_or(server_now()))
                                    .status == LeaseStatus::valid;
        if (usable) {
          save(store_keys::kLease, result.lease->token);
        } else {
          forget(store_keys::kLease);
        }
      } else if (revokes_offline_access(result.code)) {
        forget(store_keys::kLease);
      }
    } else if (type == "deactivate") {
      // ok, or device_not_found (the server no longer knows this device): secret and lease are worthless.
      if (result.ok || result.code == codes::kDeviceNotFound) {
        forget(store_keys::kLease);
        forget(store_keys::kDeviceSecret);
      } else if (revokes_offline_access(result.code)) {
        forget(store_keys::kLease);
      }
    } else if (type == "download") {
      if (!result.ok && revokes_offline_access(result.code)) forget(store_keys::kLease);
    }
  }

  // Configuration first (invalid_configuration), then the local argument checks (validation_error).
  std::optional<ValidationResult> precheck(const std::string* license_key, const std::optional<std::string>& version,
                                           const std::optional<std::string>& device_name) const {
    if (!config_error.empty()) return failure(codes::kInvalidConfiguration, config_error);
    return check_inputs(license_key, version, device_name);
  }

  // Sends one signed-protocol request; on a signed clock_skew it learns the offset and retries once.
  // `device_bound`: the answer must describe this device although no device secret is sent (the in-app
  // trial start, whose strict request schema has no deviceSecret field).
  ValidationResult call(const char* path, std::string_view type, const json& fields, bool attach_device_secret,
                        bool device_bound = false) {
    if (!config_error.empty()) return failure(codes::kInvalidConfiguration, config_error);
    const std::string url = endpoint_base + path;
    for (int attempt = 0; attempt < 2; ++attempt) {
      const auto nonce = detail::random_nonce();
      if (!nonce) return failure(codes::kInvalidConfiguration, "The system random number generator is unavailable.");

      json body = fields;
      body["productId"] = product_id;
      body["nonce"] = *nonce;
      body["timestamp"] = server_now();
      if (attach_device_secret) {
        const auto secret = load(store_keys::kDeviceSecret);
        if (secret && !secret->empty()) body["deviceSecret"] = *secret;
      }
      const std::string request_body = body.dump(-1, ' ', false, json::error_handler_t::replace);

      HttpResponse response;
      try {
        response = transport->post_json(url, request_body, timeout);
      } catch (...) {
        return failure(codes::kNetworkError, "Could not reach the license server: the HTTP transport failed.");
      }
      if (!response.transport_ok) {
        std::string message = "Could not reach the license server";
        if (!response.error.empty() && !has_control_characters(response.error)) {
          message += ": ";
          message += response.error;
        }
        message += '.';
        return failure(codes::kNetworkError, clip(std::move(message)));
      }

      // Device-bound calls: validate, deactivate and download (they attach the secret) and the trial start.
      const bool bound = attach_device_secret || device_bound;
      Interpreted interpreted = interpret(response, *nonce, type, bound ? std::string_view(hwid) : std::string_view());
      if (interpreted.verified && attempt == 0 && interpreted.result.code == codes::kClockSkew &&
          interpreted.result.server_time) {
        // The clock_skew answer is signed and bound to our nonce, so its serverTime is authentic.
        clock_offset.store(*interpreted.result.server_time - local_now(), std::memory_order_relaxed);
        continue;
      }
      if (interpreted.verified) persist(type, interpreted);
      return std::move(interpreted.result);
    }
    return failure(codes::kClockSkew, "The local clock could not be synchronised with the license server.");
  }

  ValidationResult offline() const {
    if (!config_error.empty()) return failure(codes::kInvalidConfiguration, config_error);
    const auto token = load(store_keys::kLease);
    if (!token || token->empty()) return offline_failure(codes::kNoLease, "No offline lease is stored for this product.");

    const std::int64_t now = server_now();
    LeaseVerification verification = check_lease(*token, public_key, product_id, hwid, now);
    if (verification.status != LeaseStatus::valid || !verification.claims) {
      const char* code = verification.status == LeaseStatus::expired ? codes::kLeaseExpired : codes::kLeaseInvalid;
      return offline_failure(code, lease_failure_message(verification.status));
    }
    LeaseClaims& claims = *verification.claims;

    ValidationResult result;
    result.ok = true;
    result.code = codes::kOk;
    result.message = "License validated offline with the stored lease.";
    result.offline = true;
    result.reference_time = now;  // days_until_expiry() measures at the time of this check

    LicenseInfo license;
    license.id = std::move(claims.license_id);
    license.plan = std::move(claims.plan);
    license.status = "active";  // leases are only issued for successful validations
    license.features = std::move(claims.features);
    license.expires_at = claims.license_expires_at;
    license.is_trial = claims.is_trial;
    result.license = std::move(license);

    ActivationInfo activation;
    activation.id = std::move(claims.activation_id);
    activation.status = "active";
    result.activation = std::move(activation);

    Lease lease;
    lease.token = *token;
    lease.expires_at = claims.expires_at;
    result.lease = std::move(lease);
    return result;
  }
};

// ---- Client ---------------------------------------------------------------------------------------

Client::Client(std::string api_url, std::string product_id, std::string public_key_base64, ClientOptions options) {
  try {
    auto impl = std::make_unique<Impl>();
    impl->configure(std::move(api_url), std::move(product_id), public_key_base64, std::move(options));
    impl_ = std::move(impl);
  } catch (...) {
    impl_.reset();  // every call reports invalid_configuration
  }
}

Client::~Client() = default;
Client::Client(Client&& other) noexcept = default;
Client& Client::operator=(Client&& other) noexcept = default;

bool Client::is_configured() const noexcept { return impl_ != nullptr && impl_->config_error.empty(); }

std::string Client::configuration_error() const {
  if (!impl_) return "The client is not initialised.";
  return impl_->config_error;
}

const std::string& Client::hardware_id() const noexcept {
  static const std::string empty;
  return impl_ ? impl_->hwid : empty;
}

namespace {
// Empty optional strings are omitted from requests (the server treats them as absent).
std::optional<std::string> non_empty(const std::optional<std::string>& value) {
  if (value && !value->empty()) return value;
  return std::nullopt;
}
}  // namespace

ValidationResult Client::validate(const std::string& license_key, const ValidateOptions& options) {
  if (!impl_) return not_initialised();
  try {
    const auto version = non_empty(options.version);
    const auto device_name = non_empty(options.device_name);
    if (auto problem = impl_->precheck(&license_key, version, device_name)) return std::move(*problem);
    json fields = json::object();
    fields["licenseKey"] = std::string(trim(license_key));
    fields["hwid"] = impl_->hwid;
    if (device_name) fields["deviceName"] = *device_name;
    if (version) fields["version"] = *version;
    const std::lock_guard<std::mutex> device_lock(impl_->device_mutex);
    return impl_->call("/validate", "validate", fields, true);
  } catch (...) {
    return unexpected_failure();
  }
}

ValidationResult Client::start_trial(const StartTrialOptions& options) {
  if (!impl_) return not_initialised();
  try {
    const auto version = non_empty(options.version);
    const auto device_name = non_empty(options.device_name);
    std::optional<std::string> email;
    if (options.email) {
      const std::string_view trimmed = trim(*options.email);
      if (!trimmed.empty()) email = std::string(trimmed);
    }
    if (auto problem = impl_->precheck(nullptr, version, device_name)) return std::move(*problem);
    if (email && (email->size() > kMaxEmailBytes || has_control_characters(*email))) {
      return failure(codes::kValidationError, "The e-mail address must be at most 254 printable characters.");
    }
    // The trial answer would overwrite the stored device secret and lease of this device's license (a paid one
    // included): refuse locally, before any request and without touching the store. The check and the request
    // run under the device lock, so no concurrent validate can store a license in between.
    const std::lock_guard<std::mutex> device_lock(impl_->device_mutex);
    const auto stored_secret = impl_->read(store_keys::kDeviceSecret);
    const auto stored_lease = impl_->read(store_keys::kLease);
    if (!stored_secret.readable || !stored_lease.readable) {
      // A failed read is not "nothing stored": the store may hold this device's (paid) license. Fail closed.
      return failure(codes::kStoreUnavailable, kStoreUnavailableMessage);
    }
    if ((stored_secret.value && !stored_secret.value->empty()) || (stored_lease.value && !stored_lease.value->empty())) {
      return failure(codes::kAlreadyLicensed, kAlreadyLicensedMessage);
    }
    json fields = json::object();
    fields["hwid"] = impl_->hwid;
    if (device_name) fields["deviceName"] = *device_name;
    if (version) fields["version"] = *version;
    if (email) fields["email"] = *email;
    // No device secret: the trial creates a new activation (the request schema is strict). The answer is
    // still device-bound: its signed lease / activation.hwidHash must belong to this device.
    return impl_->call("/trial", "trial", fields, false, true);
  } catch (...) {
    return unexpected_failure();
  }
}

ValidationResult Client::deactivate(const std::string& license_key) {
  if (!impl_) return not_initialised();
  try {
    if (auto problem = impl_->precheck(&license_key, std::nullopt, std::nullopt)) return std::move(*problem);
    json fields = json::object();
    fields["licenseKey"] = std::string(trim(license_key));
    fields["hwid"] = impl_->hwid;
    const std::lock_guard<std::mutex> device_lock(impl_->device_mutex);
    return impl_->call("/deactivate", "deactivate", fields, true);
  } catch (...) {
    return unexpected_failure();
  }
}

ValidationResult Client::check_update(const std::string& current_version) {
  if (!impl_) return not_initialised();
  try {
    const auto version = non_empty(current_version);
    if (auto problem = impl_->precheck(nullptr, version, std::nullopt)) return std::move(*problem);
    json fields = json::object();
    if (version) fields["version"] = *version;
    return impl_->call("/update-check", "update_check", fields, false);
  } catch (...) {
    return unexpected_failure();
  }
}

ValidationResult Client::get_download(const std::string& license_key, const std::optional<std::string>& version) {
  if (!impl_) return not_initialised();
  try {
    const auto requested = non_empty(version);
    if (auto problem = impl_->precheck(&license_key, requested, std::nullopt)) return std::move(*problem);
    json fields = json::object();
    fields["licenseKey"] = std::string(trim(license_key));
    fields["hwid"] = impl_->hwid;
    if (requested) fields["version"] = *requested;
    const std::lock_guard<std::mutex> device_lock(impl_->device_mutex);
    return impl_->call("/download", "download", fields, true);
  } catch (...) {
    return unexpected_failure();
  }
}

ValidationResult Client::validate_offline() {
  if (!impl_) return not_initialised();
  try {
    return impl_->offline();
  } catch (...) {
    return offline_failure(codes::kLeaseInvalid, "The stored offline lease could not be verified.");
  }
}

ValidationResult Client::validate_with_offline_fallback(const std::string& license_key, const ValidateOptions& options) {
  ValidationResult online = validate(license_key, options);
  if (online.code != codes::kNetworkError || !impl_) return online;
  try {
    ValidationResult offline = impl_->offline();
    if (offline.ok) {
      offline.message = "The license server is unreachable; validated with the stored offline lease.";
      return offline;
    }
    online.message += " Offline fallback unavailable: " + offline.message;
    return online;
  } catch (...) {
    return online;
  }
}

DownloadFileResult Client::download_release(const DownloadInfo& download, const std::filesystem::path& destination) {
  DownloadFileResult result;
  auto fail = [&result](const char* code, std::string message) {
    result.ok = false;
    result.code = code;
    result.message = std::move(message);
    return result;
  };
  if (!impl_) return fail(codes::kInvalidConfiguration, "The client is not initialised.");
  try {
    if (!impl_->config_error.empty()) return fail(codes::kInvalidConfiguration, impl_->config_error);
    // Local argument checks (SPEC 14 validation_error): use the descriptor returned by get_download().
    if (download.size < 0 || !is_sha256_hex(download.sha256) || download.url.empty()) {
      return fail(codes::kValidationError, "The download descriptor is incomplete.");
    }
    if (destination.empty()) return fail(codes::kValidationError, "No destination path was given.");

    const std::string url = impl_->resolve_download_url(download.url);  // server-relative URL -> origin
    if (const auto error = detail::url_policy_error(url, impl_->allow_insecure_http)) {
      return fail(codes::kDownloadFailed, "Invalid download URL: " + *error);
    }

    const auto suffix = detail::random_hex(8);
    if (!suffix) return fail(codes::kIoError, "Could not create a temporary file name.");
    std::filesystem::path temp = destination;
    temp += ".part-" + *suffix;

    const detail::DownloadOutcome outcome = detail::http_download(url, temp, static_cast<std::uint64_t>(download.size),
                                                                  impl_->timeout, impl_->user_agent);
    std::error_code ignored;
    auto discard = [&temp, &ignored] { std::filesystem::remove(temp, ignored); };

    if (outcome.io_error) {
      discard();
      return fail(codes::kIoError, "The download could not be written to disk.");
    }
    if (!outcome.transport_ok) {
      discard();
      std::string message = "The download failed";
      if (!outcome.error.empty()) message += ": " + outcome.error;
      return fail(codes::kNetworkError, clip(std::move(message) + "."));
    }
    if (outcome.status != 200) {
      discard();
      return fail(codes::kDownloadFailed, "The download server returned HTTP " + std::to_string(outcome.status) + ".");
    }
    if (outcome.too_large || outcome.bytes != static_cast<std::uint64_t>(download.size)) {
      discard();
      return fail(codes::kIntegrityMismatch, "The downloaded file size does not match the signed release information.");
    }
    if (!detail::equals_ignore_case(outcome.sha256, download.sha256)) {
      discard();
      return fail(codes::kIntegrityMismatch, "The downloaded file's SHA-256 does not match the signed release information.");
    }
    std::error_code rename_error;
    std::filesystem::rename(temp, destination, rename_error);
    if (rename_error) {
      discard();
      return fail(codes::kIoError, "The downloaded file could not be moved into place.");
    }
    result.ok = true;
    result.code = codes::kOk;
    result.message = "Download complete and verified.";
    result.bytes = outcome.bytes;
    return result;
  } catch (...) {
    return fail(codes::kIoError, "An unexpected error occurred during the download.");
  }
}

void Client::clear_local_state() {
  if (!impl_) return;
  try {
    // Waits for a device-bound call in progress, so its answer cannot store the state again afterwards.
    const std::lock_guard<std::mutex> device_lock(impl_->device_mutex);
    impl_->forget(store_keys::kDeviceSecret);
    impl_->forget(store_keys::kLease);
  } catch (...) {
  }
}

std::string Client::get_hardware_id() {
  try {
    const auto raw = detail::read_machine_id();
    if (!raw) return {};
    const std::string normalized = detail::normalize_machine_id(*raw);
    if (normalized.empty()) return {};
    return compute_hardware_id(normalized);
  } catch (...) {
    return {};
  }
}

}  // namespace velsigil
