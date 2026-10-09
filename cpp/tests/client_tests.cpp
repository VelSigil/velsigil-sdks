// Client behaviour tests against an in-process signing server and an injected clock.
#include <velsigil/client.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>  // geteuid
#endif

#include "detail.hpp"

#ifndef VX_TEST_VECTORS_PATH
#error "VX_TEST_VECTORS_PATH must point to sdks/test-vectors.json"
#endif

namespace {

using json = nlohmann::json;
using velsigil::HttpResponse;

constexpr char kProduct[] = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b";
constexpr char kOtherProduct[] = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6";
constexpr char kHwid[] = "test-hwid-0001-abcdef";
constexpr char kLicenseKey[] = "VSG-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";
constexpr char kApiUrl[] = "https://licenses.example.com";
constexpr char kRequestId[] = "3f2e1d0c-9b8a-4765-a432-10fedcba9876";
constexpr char kDeviceSecret[] = "dsk_Xq3vR9mT2pL8wN5kJ7hG4fD1sA6zC0bV9yU2iO3eW4r";
constexpr char kUnicodeMessage[] = "Wartung \xE2\x80\x94 bitte sp\xC3\xA4ter erneut versuchen \xE2\x9C\x93";
constexpr std::int64_t kStartTime = 1767225600;

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const std::string& what) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL: " << what << '\n';
  }
}

void check_equal(const std::string& actual, const std::string& expected, const std::string& what) {
  ++g_checks;
  if (actual != expected) {
    ++g_failures;
    std::cerr << "FAIL: " << what << ": expected '" << expected << "', got '" << actual << "'\n";
  }
}

bool is_nonce(const std::string& text) {
  if (text.size() != 43) return false;
  for (const char c : text) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) return false;
  }
  return true;
}

bool ends_with(const std::string& text, const std::string& suffix) {
  return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string str(const json& object, const char* key) {
  const auto it = object.find(key);
  return it != object.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::string b64url(std::string_view text) {
  return velsigil::detail::base64url_encode(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

std::string b64_standard(const std::uint8_t* data, std::size_t length) {
  std::string out = velsigil::detail::base64url_encode(data, length);
  for (char& c : out) {
    if (c == '-') c = '+';
    if (c == '_') c = '/';
  }
  while (out.size() % 4 != 0) out.push_back('=');
  return out;
}

struct Keys {
  // This run's signing key pair; the test-vector keys are refused for the non-loopback kApiUrl.
  std::string public_key;
  std::vector<std::uint8_t> seed;
  std::vector<std::uint8_t> wrong_seed;  // another fresh pair: signatures that must not verify
  // The published test-vector keys, refused unless the API host is loopback.
  std::string vector_public_key;
  std::string vector_wrong_public_key;
  std::vector<std::uint8_t> vector_seed;
};

class Signer {
 public:
  explicit Signer(const std::vector<std::uint8_t>& seed) {
    crypto_sign_seed_keypair(public_key_.data(), secret_key_.data(), seed.data());
  }
  ~Signer() { sodium_memzero(secret_key_.data(), secret_key_.size()); }
  Signer(const Signer&) = delete;
  Signer& operator=(const Signer&) = delete;

  std::string sign(std::string_view message) const {
    std::array<unsigned char, crypto_sign_BYTES> signature{};
    crypto_sign_detached(signature.data(), nullptr, reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                         secret_key_.data());
    return velsigil::detail::base64url_encode(signature.data(), signature.size());
  }

  std::string envelope_for_data(const std::string& data, bool tamper = false) const {
    std::string signature = sign(data);
    if (tamper) signature[3] = signature[3] == 'A' ? 'B' : 'A';
    json envelope = json::object();
    envelope["data"] = data;
    envelope["sig"] = signature;
    envelope["kid"] = "c1e9dc98b077ab8b";
    return envelope.dump();
  }

  std::string envelope(const json& payload, bool tamper = false) const { return envelope_for_data(b64url(payload.dump()), tamper); }

  std::string lease(const json& claims) const {
    const std::string body = b64url(claims.dump());
    return body + "." + sign(body);
  }

 private:
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> public_key_{};
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key_{};
};

class FakeServer final : public velsigil::ITransport {
 public:
  using Handler = std::function<HttpResponse(const std::string& endpoint, const json& request)>;

  HttpResponse post_json(const std::string& url, const std::string& body, std::chrono::milliseconds) override {
    const json request = json::parse(body, nullptr, false);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      urls.push_back(url);
      requests.push_back(request);
    }
    const std::size_t slash = url.rfind('/');
    const std::string endpoint = slash == std::string::npos ? url : url.substr(slash + 1);
    if (!handler) {
      HttpResponse response;
      response.error = "no handler";
      return response;
    }
    return handler(endpoint, request);
  }

  std::size_t count() {
    std::lock_guard<std::mutex> lock(mutex_);
    return requests.size();
  }

  Handler handler;
  std::vector<json> requests;
  std::vector<std::string> urls;

 private:
  std::mutex mutex_;
};

HttpResponse http(long status, std::string body) {
  HttpResponse response;
  response.transport_ok = true;
  response.status = status;
  response.body = std::move(body);
  return response;
}

HttpResponse http(long status, std::string body, std::string retry_after) {
  HttpResponse response = http(status, std::move(body));
  response.retry_after = std::move(retry_after);
  return response;
}

HttpResponse unreachable(const std::string& error) {
  HttpResponse response;
  response.transport_ok = false;
  response.error = error;
  return response;
}

json payload(const json& request, const std::string& type, bool ok, const std::string& code, std::int64_t server_time) {
  json p = json::object();
  p["v"] = 1;
  p["type"] = type;
  p["ok"] = ok;
  p["code"] = code;
  p["message"] = ok ? "License is valid." : "Request rejected.";
  p["nonce"] = str(request, "nonce");
  p["requestId"] = kRequestId;
  p["serverTime"] = server_time;
  p["productId"] = str(request, "productId");
  p["license"] = nullptr;
  p["activation"] = nullptr;
  p["lease"] = nullptr;
  p["update"] = nullptr;
  return p;
}

json license_json(std::optional<std::int64_t> expires_at, const std::string& status = "active") {
  json license = json::object();
  license["id"] = "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f";
  license["plan"] = "Monthly";
  license["status"] = status;
  license["features"] = json::array({"pro", "export"});
  license["expiresAt"] = expires_at ? json(*expires_at) : json(nullptr);
  license["maxDevices"] = 2;
  license["devicesUsed"] = 1;
  license["createdAt"] = 1767139200;
  return license;
}

json activation_json(std::int64_t now, bool issue_secret) {
  json activation = json::object();
  activation["id"] = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d";
  activation["status"] = "active";
  activation["firstSeenAt"] = now;
  activation["deviceSecret"] = issue_secret ? json(kDeviceSecret) : json(nullptr);
  return activation;
}

json lease_claims(std::int64_t iat, std::int64_t exp, const std::string& hwid = kHwid) {
  json claims = json::object();
  claims["v"] = 1;
  claims["typ"] = "lease";
  claims["productId"] = kProduct;
  claims["licenseId"] = "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f";
  claims["activationId"] = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d";
  claims["hwidHash"] = velsigil::hash_hardware_id(hwid);
  claims["plan"] = "Monthly";
  claims["features"] = json::array({"pro", "export"});
  claims["licenseExpiresAt"] = exp + 30 * 86400;
  claims["iat"] = iat;
  claims["exp"] = exp;
  return claims;
}

json lease_json(const Signer& signer, std::int64_t now, std::int64_t lifetime_seconds) {
  json lease = json::object();
  lease["token"] = signer.lease(lease_claims(now, now + lifetime_seconds));
  lease["expiresAt"] = now + lifetime_seconds;
  return lease;
}

velsigil::ClientOptions make_options(const std::shared_ptr<velsigil::ITransport>& transport,
                                    const std::shared_ptr<velsigil::IStore>& store, const std::shared_ptr<std::int64_t>& clock) {
  velsigil::ClientOptions options;
  options.hwid = std::string(kHwid);
  options.store = store;
  options.transport = transport;
  options.clock = [clock] { return *clock; };
  return options;
}

struct Harness {
  explicit Harness(const Keys& keys, const std::string& api_url = kApiUrl)
      : signer(keys.seed),
        server(std::make_shared<FakeServer>()),
        store(std::make_shared<velsigil::MemoryStore>()),
        clock(std::make_shared<std::int64_t>(kStartTime)),
        client(api_url, kProduct, keys.public_key, make_options(server, store, clock)) {}

  Signer signer;
  std::shared_ptr<FakeServer> server;
  std::shared_ptr<velsigil::MemoryStore> store;
  std::shared_ptr<std::int64_t> clock;
  velsigil::Client client;
};

std::optional<std::string> stored(const Harness& h, const char* key) { return h.store->get(kProduct, key); }

void test_validate_ok_and_device_secret(const Keys& keys) {
  Harness h(keys);
  const std::int64_t now = kStartTime;
  h.server->handler = [&h, now](const std::string& endpoint, const json& request) {
    json p = payload(request, endpoint, true, "ok", now);
    p["license"] = license_json(now + 30 * 86400);
    p["activation"] = activation_json(now, !request.contains("deviceSecret"));
    p["lease"] = lease_json(h.signer, now, 86400);
    return http(200, h.signer.envelope(p));
  };

  velsigil::ValidateOptions options;
  options.version = "1.2.3";
  options.device_name = "Build agent";
  const velsigil::ValidationResult first = h.client.validate(kLicenseKey, options);
  check(first.ok, "validate ok");
  check_equal(first.code, "ok", "validate ok code");
  check(static_cast<bool>(first), "result converts to true");
  check(!first.offline, "online result is not offline");
  check(first.has_feature("pro") && first.has_feature("export") && !first.has_feature("enterprise"), "features");
  check(first.license && first.license->plan == "Monthly" && first.license->max_devices == 2, "license fields");
  check(first.expires_at() == now + 30 * 86400 && !first.is_lifetime(), "expiry helpers");
  check(first.days_until_expiry(now) == 30, "days until expiry");
  check(first.activation && first.activation->device_secret_issued, "device secret issued");
  check(first.request_id == std::string(kRequestId), "request id");
  check(first.server_time == now, "server time");
  check(first.lease && !first.lease->token.empty() && first.lease->expires_at == now + 86400, "lease returned");
  check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "device secret persisted");
  check(first.lease && stored(h, velsigil::store_keys::kLease) == first.lease->token, "lease persisted");

  check(h.server->requests.size() == 1, "one request");
  const json r1 = h.server->requests.at(0);  // copy: later requests may reallocate the vector
  check_equal(h.server->urls.at(0), "https://licenses.example.com/api/client/v1/validate", "validate URL");
  check_equal(str(r1, "licenseKey"), kLicenseKey, "request licenseKey");
  check_equal(str(r1, "hwid"), kHwid, "request hwid");
  check_equal(str(r1, "productId"), kProduct, "request productId");
  check_equal(str(r1, "version"), "1.2.3", "request version");
  check_equal(str(r1, "deviceName"), "Build agent", "request deviceName");
  check(r1.contains("timestamp") && r1.at("timestamp").get<std::int64_t>() == now, "request timestamp uses the clock");
  check(is_nonce(str(r1, "nonce")), "request nonce is 43 base64url characters");
  check(!r1.contains("deviceSecret"), "no device secret before one is issued");

  const velsigil::ValidationResult second = h.client.validate(kLicenseKey);
  check(second.ok, "second validate ok");
  check(second.activation && !second.activation->device_secret_issued, "no new secret on the second call");
  const json r2 = h.server->requests.at(1);
  check_equal(str(r2, "deviceSecret"), kDeviceSecret, "stored device secret is re-sent");
  check(str(r2, "nonce") != str(r1, "nonce") && is_nonce(str(r2, "nonce")), "fresh nonce per request");
  check(!r2.contains("version") && !r2.contains("deviceName"), "optional fields omitted when unset");
}

void test_business_failures(const Keys& keys) {
  Harness h(keys);
  const std::int64_t now = kStartTime;
  std::string code = "invalid_key";
  std::string message = "License key not found.";
  h.server->handler = [&h, &code, &message, now](const std::string& endpoint, const json& request) {
    json p = payload(request, endpoint, code == "ok", code, now);
    p["message"] = message;
    if (code == "license_revoked") p["license"] = license_json(std::nullopt, "revoked");
    if (code == "ok") p["license"] = license_json(std::nullopt);
    return http(200, h.signer.envelope(p));
  };

  h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
  const auto invalid = h.client.validate(kLicenseKey);
  check(!invalid.ok, "invalid_key is not ok");
  check_equal(invalid.code, "invalid_key", "invalid_key code");
  check_equal(invalid.message, "License key not found.", "invalid_key message");
  check(invalid.request_id == std::string(kRequestId), "failure carries the request id");
  check(!invalid.has_feature("pro"), "failure grants no features");
  check(!stored(h, velsigil::store_keys::kLease), "invalid_key drops the stored lease");

  h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
  code = "product_paused";
  message = kUnicodeMessage;
  const auto paused = h.client.validate(kLicenseKey);
  check_equal(paused.code, "product_paused", "product_paused code");
  check_equal(paused.message, kUnicodeMessage, "UTF-8 message preserved");
  check(stored(h, velsigil::store_keys::kLease) == std::string("previous-lease"), "product_paused keeps the lease");

  code = "license_revoked";
  message = "This license has been revoked.";
  const auto revoked = h.client.validate(kLicenseKey);
  check(!revoked.ok && revoked.code == "license_revoked", "license_revoked");
  check(revoked.license && revoked.license->status == "revoked", "revoked license details");
  check(!revoked.has_feature("pro"), "revoked license grants no features");
  check(!stored(h, velsigil::store_keys::kLease), "license_revoked drops the stored lease");

  // The lease-clearing set ...
  for (const char* revoking : {"license_expired", "license_suspended", "license_banned", "device_revoked",
                               "device_verification_failed", "device_limit_reached", "device_not_activated",
                               "device_not_found", "blacklisted", "product_disabled"}) {
    h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
    code = revoking;
    message = "Denied.";
    const auto denied = h.client.validate(kLicenseKey);
    check(!denied.ok && denied.code == revoking, std::string(revoking) + ": code");
    check(!stored(h, velsigil::store_keys::kLease), std::string(revoking) + " drops the stored lease");
  }
  // ... and every other signed failure keeps it.
  for (const char* transient : {"outdated_version", "activation_rate_limited", "activation_cooldown",
                                "activations_disabled", "replay_detected", "trial_already_used"}) {
    h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
    code = transient;
    message = "Not now.";
    const auto refused = h.client.validate(kLicenseKey);
    check(!refused.ok && refused.code == transient, std::string(transient) + ": code");
    check(stored(h, velsigil::store_keys::kLease) == std::string("previous-lease"), std::string(transient) + " keeps the lease");
  }

  // ok without a lease (offline use disabled) also drops an old lease.
  h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
  code = "ok";
  message = "License is valid.";
  const auto ok = h.client.validate(kLicenseKey);
  check(ok.ok && ok.is_lifetime(), "lifetime license ok");
  check(!stored(h, velsigil::store_keys::kLease), "ok without lease clears the stored lease");

  const std::size_t before = h.server->requests.size();
  check(h.client.validate("").code == "validation_error", "empty key -> validation_error");
  check(h.client.validate("   ").code == "validation_error", "blank key -> validation_error");
  check(h.client.validate(std::string(65, 'K')).code == "validation_error", "key > 64 chars -> validation_error");
  check(h.client.validate(std::string("VSG-\nABC")).code == "validation_error", "control characters -> validation_error");
  velsigil::ValidateOptions long_version;
  long_version.version = std::string(33, '1');
  check(h.client.validate(kLicenseKey, long_version).code == "validation_error", "version > 32 -> validation_error");
  velsigil::ValidateOptions long_name;
  long_name.device_name = std::string(256, 'n');
  check(h.client.validate(kLicenseKey, long_name).code == "validation_error", "device name > 255 -> validation_error");
  check(h.client.check_update(std::string(33, '1')).code == "validation_error", "check_update version -> validation_error");
  check(h.server->requests.size() == before, "local validation failures send nothing");
}

void test_tampered_responses(const Keys& keys) {
  struct Case {
    std::string name;
    std::function<HttpResponse(const Harness&, const json&)> respond;
  };
  const Signer wrong_signer(keys.wrong_seed);
  const std::int64_t now = kStartTime;
  auto ok_payload = [now](const json& request) {
    json p = payload(request, "validate", true, "ok", now);
    p["license"] = license_json(std::nullopt);
    p["activation"] = activation_json(now, true);
    return p;
  };

  const std::vector<Case> cases = {
      {"nonce mismatch",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["nonce"] = "a-different-nonce-0000000000";
         return http(200, h.signer.envelope(p));
       }},
      {"tampered signature", [&](const Harness& h, const json& request) { return http(200, h.signer.envelope(ok_payload(request), true)); }},
      {"wrong signing key", [&](const Harness&, const json& request) { return http(200, wrong_signer.envelope(ok_payload(request))); }},
      {"product mismatch",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["productId"] = kOtherProduct;
         return http(200, h.signer.envelope(p));
       }},
      {"type mismatch",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["type"] = "download";
         return http(200, h.signer.envelope(p));
       }},
      {"unsupported payload version",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["v"] = 2;
         return http(200, h.signer.envelope(p));
       }},
      {"wrong field type",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["license"]["features"] = "pro";
         return http(200, h.signer.envelope(p));
       }},
      {"signed garbage data", [&](const Harness& h, const json&) { return http(200, h.signer.envelope_for_data("!!not-base64!!")); }},
      {"tampered data",
       [&](const Harness& h, const json& request) {
         json envelope = json::parse(h.signer.envelope(ok_payload(request)));
         json forged = ok_payload(request);
         forged["license"]["features"] = json::array({"pro", "export", "enterprise"});
         envelope["data"] = b64url(forged.dump());
         return http(200, envelope.dump());
       }},
      {"missing signature",
       [&](const Harness&, const json& request) {
         json envelope = json::object();
         envelope["data"] = b64url(ok_payload(request).dump());
         envelope["kid"] = "c1e9dc98b077ab8b";
         return http(200, envelope.dump());
       }},
      {"unsigned success body", [&](const Harness&, const json&) {
         return http(200, R"({"ok":true,"code":"ok","license":{"id":"x","status":"active","features":["pro"]}})");
       }},
      {"unsigned error with status 200",
       [&](const Harness&, const json&) { return http(200, R"({"error":{"code":"rate_limited","message":"slow down"}})"); }},
      {"empty body", [&](const Harness&, const json&) { return http(200, ""); }},
      {"not json", [&](const Harness&, const json&) { return http(200, "<html>proxy</html>"); }},
      // Authentic answers about another device (a rewritten request) are rejected as a whole.
      {"lease of another device",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["lease"] = json::object();
         p["lease"]["token"] = h.signer.lease(lease_claims(now, now + 86400, "another-device-hwid"));
         p["lease"]["expiresAt"] = now + 86400;
         return http(200, h.signer.envelope(p));
       }},
      {"lease of another product",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         json claims = lease_claims(now, now + 86400);
         claims["productId"] = kOtherProduct;
         p["lease"] = json::object();
         p["lease"]["token"] = h.signer.lease(claims);
         p["lease"]["expiresAt"] = now + 86400;
         return http(200, h.signer.envelope(p));
       }},
      {"activation of another device",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["activation"]["hwidHash"] = velsigil::hash_hardware_id("another-device-hwid");
         return http(200, h.signer.envelope(p));
       }},
      {"malformed activation hwidHash",
       [&](const Harness& h, const json& request) {
         json p = ok_payload(request);
         p["activation"]["hwidHash"] = 42;
         return http(200, h.signer.envelope(p));
       }},
  };

  for (const Case& c : cases) {
    Harness h(keys);
    h.server->handler = [&h, &c](const std::string&, const json& request) { return c.respond(h, request); };
    const auto result = h.client.validate(kLicenseKey);
    check(!result.ok, c.name + ": not ok");
    check_equal(result.code, "invalid_response", c.name + ": code");
    check(!result.has_feature("pro") && !result.license, c.name + ": no license data");
    check(!stored(h, velsigil::store_keys::kDeviceSecret), c.name + ": nothing persisted");
    check(h.server->requests.size() == 1, c.name + ": no retry");
  }
}

void test_clock_skew(const Keys& keys) {
  {
    Harness h(keys);
    const std::int64_t server_time = kStartTime + 3600;  // server clock one hour ahead
    h.server->handler = [&h, server_time](const std::string&, const json& request) {
      const std::int64_t timestamp = request.at("timestamp").get<std::int64_t>();
      if (timestamp > server_time + 300 || timestamp < server_time - 300) {
        json p = payload(request, "validate", false, "clock_skew", server_time);
        p["message"] = "Request timestamp is outside the allowed window.";
        return http(200, h.signer.envelope(p));
      }
      json p = payload(request, "validate", true, "ok", server_time);
      p["license"] = license_json(std::nullopt);
      return http(200, h.signer.envelope(p));
    };
    const auto result = h.client.validate(kLicenseKey);
    check(result.ok, "clock_skew: retried request succeeds");
    check(h.server->requests.size() == 2, "clock_skew: exactly one retry");
    if (h.server->requests.size() == 2) {
      check(h.server->requests[0].at("timestamp").get<std::int64_t>() == kStartTime, "clock_skew: first timestamp is local");
      check(h.server->requests[1].at("timestamp").get<std::int64_t>() == server_time, "clock_skew: retry uses the learned offset");
      check(str(h.server->requests[0], "nonce") != str(h.server->requests[1], "nonce"), "clock_skew: retry uses a new nonce");
    }
    const auto again = h.client.validate(kLicenseKey);
    check(again.ok && h.server->requests.size() == 3, "clock_skew: offset is remembered");
  }
  {
    Harness h(keys);
    h.server->handler = [&h](const std::string&, const json& request) {
      return http(200, h.signer.envelope(payload(request, "validate", false, "clock_skew", kStartTime + 7200)));
    };
    const auto result = h.client.validate(kLicenseKey);
    check(!result.ok && result.code == "clock_skew", "persistent clock_skew is reported");
    check(h.server->requests.size() == 2, "persistent clock_skew: only one retry");
  }
  {
    // A clock_skew answer that fails verification must not move the clock.
    Harness h(keys);
    h.server->handler = [&h](const std::string&, const json& request) {
      return http(200, h.signer.envelope(payload(request, "validate", false, "clock_skew", kStartTime + 7200), true));
    };
    const auto result = h.client.validate(kLicenseKey);
    check(result.code == "invalid_response" && h.server->requests.size() == 1, "forged clock_skew is rejected without retry");
    (void)h.client.validate(kLicenseKey);
    check(h.server->requests.size() == 2 && h.server->requests[1].at("timestamp").get<std::int64_t>() == kStartTime,
          "forged clock_skew does not change the offset");
  }
}

void test_unsigned_errors(const Keys& keys) {
  struct Case {
    long status;
    std::string body;
    std::string expected;
  };
  const std::vector<Case> cases = {
      {429, R"({"error":{"code":"rate_limited","message":"Too many requests.","requestId":"req-429"}})", "rate_limited"},
      {400, R"({"error":{"code":"validation_error","message":"Invalid request body.","requestId":"req-400"}})", "validation_error"},
      {403, R"({"error":{"code":"ip_blocked","message":"Blocked.","requestId":"req-403"}})", "ip_blocked"},
      {404, R"({"error":{"code":"unknown_product","message":"Unknown product.","requestId":"req-404"}})", "unknown_product"},
      {413, R"({"error":{"code":"payload_too_large","message":"Too large."}})", "payload_too_large"},
      {415, R"({"error":{"code":"unsupported_media_type","message":"JSON only."}})", "unsupported_media_type"},
      {500, R"({"error":{"code":"internal_error","message":"Internal error.","requestId":"req-500"}})", "internal_error"},
      {500, "<html>oops</html>", "internal_error"},
      {502, "<html>bad gateway</html>", "network_error"},
      {503, "", "network_error"},
      {504, R"({"message":"Gateway Timeout"})", "network_error"},  // a proxy's JSON page is not a Velsigil body
      {503, R"({"error":{"code":"something_new"}})", "internal_error"},
      {502, R"({"error":{"code":"internal_error"}})", "internal_error"},
      {400, "", "validation_error"},
      {400, R"({"error":{"code":"ok"}})", "validation_error"},
      {413, "<html>too large</html>", "payload_too_large"},
      {415, "", "unsupported_media_type"},
      {429, R"({"error":{"code":"ok"}})", "rate_limited"},
      {500, R"({"ok":true,"code":"ok"})", "internal_error"},
      {418, "{}", "invalid_response"},
      {401, R"({"ok":true,"code":"ok"})", "invalid_response"},
  };
  for (const Case& c : cases) {
    Harness h(keys);
    h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
    h.server->handler = [&c](const std::string&, const json&) { return http(c.status, c.body); };
    const auto result = h.client.validate(kLicenseKey);
    const std::string name = "HTTP " + std::to_string(c.status) + " " + c.body;
    check(!result.ok, name + ": never ok");
    check_equal(result.code, c.expected, name + ": code");
    check(h.server->requests.size() == 1, name + ": no retry");
    check(stored(h, velsigil::store_keys::kLease) == std::string("previous-lease"), name + ": stored lease untouched");
  }

  Harness h(keys);
  h.server->handler = [](const std::string&, const json&) {
    return http(429, R"({"error":{"code":"rate_limited","message":"Too many requests.","requestId":"req-429"}})");
  };
  const auto limited = h.client.validate(kLicenseKey);
  check(limited.message.find("Too many requests.") == std::string::npos && !limited.message.empty(),
        "unsigned error message is SDK text");
  check(limited.request_id == std::string("req-429"), "unsigned error request id");
  check(!limited.retry_after, "429 without a Retry-After header: no retry_after");
}

void test_retry_after(const Keys& keys) {
  struct Case {
    long status;
    std::string body;
    std::optional<std::string> header;
    std::string expected_code;
    std::optional<std::int64_t> expected;
  };
  const std::string busy = R"({"error":{"code":"service_busy","message":"The service is busy. Please try again shortly."}})";
  const std::vector<Case> cases = {
      {503, "", std::string("30"), "network_error", 30},  // the server's empty 503 while its database is unreachable
      {503, busy, std::string("5"), "internal_error", 5},
      {503, R"({"error":{"code":"internal_error"}})", std::string("7"), "internal_error", 7},
      {503, "<html>Service Unavailable</html>", std::string("120"), "network_error", 120},  // a gateway's 503
      {503, R"({"error":{"code":"rate_limited"}})", std::string("9"), "rate_limited", 9},
      {429, R"({"error":{"code":"rate_limited","message":"Too many requests."}})", std::string("30"), "rate_limited", 30},
      {429, "", std::string("12"), "rate_limited", 12},
      {503, "", std::nullopt, "network_error", std::nullopt},
      {503, "", std::string("soon"), "network_error", std::nullopt},
      {503, "", std::string(""), "network_error", std::nullopt},
      {429, "", std::string("-5"), "rate_limited", std::nullopt},
      {503, "", std::string("999999999999999999999999"), "network_error", 86400},  // capped at one day, no overflow
      {503, "", std::string(" 0 "), "network_error", 0},
      {500, R"({"error":{"code":"internal_error"}})", std::string("30"), "internal_error", std::nullopt},
      {502, "<html>Bad Gateway</html>", std::string("30"), "network_error", std::nullopt},
      {504, "", std::string("30"), "network_error", std::nullopt},
      {400, R"({"error":{"code":"validation_error"}})", std::string("30"), "validation_error", std::nullopt},
      {307, "", std::string("30"), "invalid_response", std::nullopt},
      {200, "<html>proxy</html>", std::string("30"), "invalid_response", std::nullopt},
  };
  for (const Case& c : cases) {
    Harness h(keys);
    h.server->handler = [&c](const std::string&, const json&) {
      HttpResponse response = http(c.status, c.body);
      response.retry_after = c.header;
      return response;
    };
    const auto result = h.client.validate(kLicenseKey);
    const std::string name = "HTTP " + std::to_string(c.status) + " " + c.body + " Retry-After '" + c.header.value_or("<none>") + "'";
    check_equal(result.code, c.expected_code, name + ": code");
    check(result.retry_after == c.expected, name + ": retry_after");
    check(!result.ok && !result.offline, name + ": a failure, not offline");
  }

  // A signed answer never carries one, even with the header.
  {
    Harness h(keys);
    h.server->handler = [&h](const std::string&, const json& request) {
      json p = payload(request, "validate", true, "ok", kStartTime);
      p["license"] = license_json(kStartTime + 30 * 86400);
      return http(200, h.signer.envelope(p), "30");
    };
    const auto result = h.client.validate(kLicenseKey);
    check(result.ok && !result.retry_after, "signed ok with a Retry-After header: no retry_after");
  }

  // HTTP-dates, from the client's clock (kStartTime is Thu, 01 Jan 2026 00:00:00 GMT).
  struct DateCase {
    long status;
    std::string header;
    std::optional<std::int64_t> expected;
  };
  const std::vector<DateCase> dates = {
      {503, "Thu, 01 Jan 2026 00:01:30 GMT", 90},      // IMF-fixdate
      {429, "Thu, 01 Jan 2026 00:00:45 GMT", 45},
      {503, "Thursday, 01-Jan-26 00:02:00 GMT", 120},  // RFC 850
      {503, "Thu Jan  1 00:00:10 2026", 10},           // asctime
      {503, "Wed, 31 Dec 2025 23:59:00 GMT", 0},       // in the past
      {503, "Sat, 03 Jan 2026 00:00:00 GMT", 86400},   // capped at one day
      {503, "Sat, 31 Feb 2026 00:00:00 GMT", std::nullopt},
      {503, "Thu, 01 Jan 2026 nope", std::nullopt},
      {500, "Thu, 01 Jan 2026 00:01:30 GMT", std::nullopt},
  };
  for (const DateCase& d : dates) {
    Harness h(keys);
    h.server->handler = [&d](const std::string&, const json&) { return http(d.status, "", d.header); };
    const auto result = h.client.validate(kLicenseKey);
    check(result.retry_after == d.expected, "HTTP " + std::to_string(d.status) + " Retry-After '" + d.header + "'");
  }
  {
    // Measured from the local clock, not the learned server offset.
    Harness h(keys);
    bool skewed = false;
    h.server->handler = [&h, &skewed](const std::string&, const json& request) {
      if (!skewed) {
        skewed = true;
        return http(200, h.signer.envelope(payload(request, "validate", false, "clock_skew", kStartTime + 3600)));
      }
      return http(503, "", "Thu, 01 Jan 2026 00:01:30 GMT");
    };
    const auto result = h.client.validate(kLicenseKey);
    check_equal(result.code, "network_error", "clock_skew then 503: code");
    check(result.retry_after == std::optional<std::int64_t>(90), "an HTTP-date Retry-After is measured from the local clock");
  }
}

void test_parse_retry_after() {
  using velsigil::detail::parse_retry_after;
  using Seconds = std::optional<std::int64_t>;
  constexpr std::int64_t kRfcExample = 784111777;  // Sun, 06 Nov 1994 08:49:37 GMT
  check(parse_retry_after("30", 0) == Seconds(30), "delta-seconds");
  check(parse_retry_after(" \t30 ", 0) == Seconds(30), "delta-seconds with surrounding whitespace");
  check(parse_retry_after("0", 0) == Seconds(0), "zero");
  check(parse_retry_after("00042", 0) == Seconds(42), "leading zeros");
  check(parse_retry_after("86400", 0) == Seconds(86400), "one day");
  check(parse_retry_after("86401", 0) == Seconds(86400), "more than a day is capped");
  check(parse_retry_after("99999999999999999999999999999999", 0) == Seconds(86400), "a huge number neither overflows nor wraps");
  for (const char* bad : {"", "   ", "+30", "-30", "30s", "1.5", "3 0", "0x10", "soon"}) {
    check(!parse_retry_after(bad, 0), std::string("unparseable: '") + bad + "'");
  }
  check(parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", kRfcExample - 10) == Seconds(10), "IMF-fixdate");
  check(parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", kRfcExample - 10) == Seconds(10), "RFC 850 date");
  check(parse_retry_after("Sun Nov  6 08:49:37 1994", kRfcExample - 10) == Seconds(10), "asctime date");
  check(parse_retry_after("sun, 06 nov 1994 08:49:37 GMT", kRfcExample - 1) == Seconds(1), "names in any case");
  check(parse_retry_after("Sun, 6 Nov 1994 08:49:37 GMT", kRfcExample - 1) == Seconds(1), "a one-digit day");
  check(parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", kRfcExample) == Seconds(0), "now");
  check(parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", kRfcExample + 3600) == Seconds(0), "in the past");
  check(parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", kRfcExample - 86401) == Seconds(86400), "capped at one day");
  check(parse_retry_after("Thu, 29 Feb 2024 00:00:00 GMT", 1709164800 - 5) == Seconds(5), "a leap day");
  check(parse_retry_after("Thu, 01 Jan 1970 00:00:05 GMT", 0) == Seconds(5), "the epoch");
  check(parse_retry_after("Fri, 31 Dec 9999 23:59:59 GMT", (std::numeric_limits<std::int64_t>::min)()) == Seconds(86400),
        "no overflow with a clock far in the past");
  check(parse_retry_after("Thu, 01 Jan 1970 00:00:05 GMT", (std::numeric_limits<std::int64_t>::max)()) == Seconds(0),
        "no overflow with a clock far in the future");
  for (const char* bad : {"Sun, 06 Nov 1994 08:49:37 UTC", "Sun, 06 Nov 1994 08:49:37", "Sun, 06 Nov 1994 08:49:37 GMT extra",
                          "Foo, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Foo 1994 08:49:37 GMT", "Sun, 31 Nov 1994 08:49:37 GMT",
                          "Sun, 29 Feb 2025 08:49:37 GMT", "Sun, 00 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 94 08:49:37 GMT",
                          "Sun, 06 Nov 1994 24:00:00 GMT", "Sun, 06 Nov 1994 08:60:00 GMT", "Sun, 06 Nov 1994 8:49:37 GMT",
                          "Sunday, 06-Nov-1994 08:49:37 GMT", "Sun, 06-Nov-94 08:49:37 GMT", "Sun Nov 6 08:49:37 94",
                          "Sun 06 Nov 1994 08:49:37 GMT", "06 Nov 1994 08:49:37 GMT"}) {
    check(!parse_retry_after(bad, 0), std::string("not an HTTP-date: '") + bad + "'");
  }
}

void test_start_trial(const Keys& keys) {
  const std::string trial_key = "DEMO-7K3QM-P9XWD-R4TNB-H2CFY-M8LJV";
  const std::int64_t now = kStartTime;
  // A signed trial start; `mutate` lets a case break one part of it.
  auto started = [&trial_key, now](const Signer& signer, const json& request, const std::function<void(json&)>& mutate) {
    json p = payload(request, "trial", true, "ok", now);
    json license = license_json(now + 14 * 86400);
    license["plan"] = "Trial";
    license["trial"] = true;
    p["license"] = license;
    json activation = activation_json(now, true);
    activation["hwidHash"] = velsigil::hash_hardware_id(kHwid);
    p["activation"] = activation;
    json claims = lease_claims(now, now + 3600);
    claims["trial"] = true;
    json lease = json::object();
    lease["token"] = signer.lease(claims);
    lease["expiresAt"] = now + 3600;
    p["lease"] = lease;
    json trial = json::object();
    trial["key"] = trial_key;
    p["trial"] = trial;
    if (mutate) mutate(p);
    return http(200, signer.envelope(p));
  };

  {
    Harness h(keys);
    h.server->handler = [&h, &started](const std::string&, const json& request) { return started(h.signer, request, nullptr); };
    velsigil::StartTrialOptions options;
    options.version = "1.2.3";
    options.device_name = "Laptop";
    const auto result = h.client.start_trial(options);
    check(result.ok, "start_trial ok");
    check(result.trial_key == trial_key, "start_trial returns the key");
    check(result.is_trial(), "start_trial result is a trial");
    check(result.activation && result.activation->device_secret_issued, "start_trial issues a device secret");
    check_equal(h.server->urls.at(0), "https://licenses.example.com/api/client/v1/trial", "start_trial URL");
    const json request = h.server->requests.at(0);
    check(!request.contains("licenseKey") && !request.contains("deviceSecret") && !request.contains("email"),
          "start_trial sends no key, no device secret and no e-mail unless given");
    check_equal(str(request, "hwid"), kHwid, "start_trial hwid");
    check_equal(str(request, "deviceName"), "Laptop", "start_trial deviceName");
    check_equal(str(request, "version"), "1.2.3", "start_trial version");
    check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "start_trial persists the device secret");
    check(result.lease && stored(h, velsigil::store_keys::kLease) == result.lease->token, "start_trial persists the lease");
    const auto stored_lease = stored(h, velsigil::store_keys::kLease);
    check(!stored_lease || stored_lease->find(trial_key) == std::string::npos, "the key is never stored");
    *h.clock = now + 60;
    const auto offline = h.client.validate_offline();
    check(offline.ok && offline.is_trial() && !offline.trial_key, "offline result of the trial lease");
  }

  // trialRef is exposed on online results only; a malformed one makes the answer invalid.
  {
    const std::string ref = "vtr1_Ab3_-Ab3_-Ab3_-";
    Harness h(keys);
    h.server->handler = [&h, &started, &ref](const std::string&, const json& request) {
      return started(h.signer, request, [&ref](json& p) { p["license"]["trialRef"] = ref; });
    };
    const auto result = h.client.start_trial();
    check(result.ok && result.trial_ref() == ref, "trial_ref() of an online trial result");
    check_equal(result.with_trial_ref("https://shop.example.com/buy"), "https://shop.example.com/buy?velsigil_trial=" + ref,
                "ValidationResult::with_trial_ref");
    *h.clock = now + 60;
    const auto offline = h.client.validate_offline();
    check(offline.ok && !offline.trial_ref().has_value(), "offline results carry no trial_ref");
    check_equal(offline.with_trial_ref("https://shop.example.com/buy"), "https://shop.example.com/buy", "with_trial_ref without a reference");
  }
  {
    Harness h(keys);
    h.server->handler = [&h, &started](const std::string&, const json& request) {
      return started(h.signer, request, [](json& p) { p["license"]["trialRef"] = "has space"; });
    };
    const auto refused = h.client.start_trial();
    check(!refused.ok, "a malformed trialRef is never ok");
    check_equal(refused.code, velsigil::codes::kInvalidResponse, "a malformed trialRef is an invalid response");
  }

  // Signed trial failures store nothing; the e-mail is sent trimmed, and only when given.
  for (const char* code : {velsigil::codes::kTrialAlreadyUsed, velsigil::codes::kTrialUnavailable,
                           velsigil::codes::kTrialEmailRequired, velsigil::codes::kTrialEmailInvalid,
                           velsigil::codes::kTrialEmailNotAccepted, velsigil::codes::kTrialConfirmationSent}) {
    Harness h(keys);
    const std::string expected = code;
    h.server->handler = [&h, &expected, now](const std::string&, const json& request) {
      return http(200, h.signer.envelope(payload(request, "trial", false, expected, now)));
    };
    velsigil::StartTrialOptions options;
    options.email = " jane@example.com ";
    const auto result = h.client.start_trial(options);
    check(!result.ok && result.code == expected && !result.trial_key, expected + ": a signed failure without a key");
    check(!stored(h, velsigil::store_keys::kLease) && !stored(h, velsigil::store_keys::kDeviceSecret),
          expected + ": stores nothing");
    check_equal(str(h.server->requests.at(0), "email"), "jane@example.com", expected + ": the trimmed e-mail is sent");
  }

  // With a device secret and/or lease stored, start_trial refuses locally and sends nothing.
  {
    const std::string paid_secret = "dsk_P4idL1c3P4idL1c3P4idL1c3P4idL1c3P4idL1c3abc";
    struct StoredCase {
      const char* name;
      bool secret;
      bool lease;
    };
    for (const StoredCase& stored_case : {StoredCase{"device secret stored", true, false}, StoredCase{"lease stored", false, true},
                                          StoredCase{"device secret and lease stored", true, true}}) {
      const std::string name = stored_case.name;
      Harness h(keys);
      // Would replace the stored secret and lease if anything were sent.
      h.server->handler = [&h, &started](const std::string&, const json& request) { return started(h.signer, request, nullptr); };
      const std::string paid_lease = h.signer.lease(lease_claims(now, now + 7200));
      if (stored_case.secret) h.store->set(kProduct, velsigil::store_keys::kDeviceSecret, paid_secret);
      if (stored_case.lease) h.store->set(kProduct, velsigil::store_keys::kLease, paid_lease);
      velsigil::StartTrialOptions options;
      options.version = "1.2.3";
      const auto result = h.client.start_trial(options);
      check(!result.ok && result.code == velsigil::codes::kAlreadyLicensed, name + ": start_trial -> already_licensed");
      check(result.message.find("already holds a license for this product") != std::string::npos &&
                result.message.find("trial cannot replace it") != std::string::npos &&
                result.message.find("clear_local_state()") != std::string::npos,
            name + ": already_licensed message");
      check(!result.trial_key, name + ": no trial key");
      check(h.server->count() == 0, name + ": nothing is sent");
      const std::optional<std::string> expected_secret =
          stored_case.secret ? std::optional<std::string>(paid_secret) : std::optional<std::string>();
      const std::optional<std::string> expected_lease =
          stored_case.lease ? std::optional<std::string>(paid_lease) : std::optional<std::string>();
      check(stored(h, velsigil::store_keys::kDeviceSecret) == expected_secret, name + ": the stored device secret is unchanged");
      check(stored(h, velsigil::store_keys::kLease) == expected_lease, name + ": the stored lease is unchanged");
    }
    check_equal(velsigil::codes::kAlreadyLicensed, "already_licensed", "codes::kAlreadyLicensed");

    // clear_local_state() is the way out.
    Harness h(keys);
    h.server->handler = [&h, &started](const std::string&, const json& request) { return started(h.signer, request, nullptr); };
    h.store->set(kProduct, velsigil::store_keys::kDeviceSecret, paid_secret);
    h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
    check(h.client.start_trial().code == velsigil::codes::kAlreadyLicensed, "a stored license refuses the trial");
    h.client.clear_local_state();
    const auto cleared = h.client.start_trial();
    check(cleared.ok && h.server->count() == 1, "after clear_local_state() the trial starts");
    check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "the trial's device secret is stored");
  }

  // 404 not_found means no trial endpoint (panel_too_old); unknown_product keeps its code.
  {
    Harness h(keys);
    h.server->handler = [](const std::string&, const json&) {
      return http(404, R"({"error":{"code":"not_found","message":"Not found.","requestId":"req-old"}})");
    };
    const auto old = h.client.start_trial();
    check(!old.ok && old.code == velsigil::codes::kPanelTooOld, "404 not_found -> panel_too_old");
    check(old.message.find("update the Velsigil panel") != std::string::npos, "panel_too_old message");
    check(old.request_id == std::string("req-old"), "panel_too_old request id");
    check(h.client.validate(kLicenseKey).code == "invalid_response", "validate keeps the old 404 mapping");
    h.server->handler = [](const std::string&, const json&) {
      return http(404, R"({"error":{"code":"unknown_product","message":"Unknown product."}})");
    };
    check(h.client.start_trial().code == "unknown_product", "unknown_product stays itself on /trial");
  }

  const std::vector<std::pair<std::string, std::function<void(json&)>>> broken = {
      {"no key", [](json& p) { p.erase("trial"); }},
      {"bad key", [](json& p) { p["trial"]["key"] = "bad key\n"; }},
      {"key not a string", [](json& p) { p["trial"]["key"] = 42; }},
      {"another type", [](json& p) { p["type"] = "validate"; }},
      {"another device", [](json& p) { p["activation"]["hwidHash"] = std::string(64, 'f'); }},
  };
  for (const auto& entry : broken) {
    // C++17 lambdas cannot capture structured bindings.
    const std::string& name = entry.first;
    const std::function<void(json&)>& mutate = entry.second;
    Harness h(keys);
    h.server->handler = [&h, &started, &mutate](const std::string&, const json& request) { return started(h.signer, request, mutate); };
    const auto result = h.client.start_trial();
    check(!result.ok && result.code == "invalid_response" && !result.trial_key, "start_trial rejects: " + name);
    check(!stored(h, velsigil::store_keys::kDeviceSecret), "start_trial stores nothing from a rejected answer: " + name);
  }

  {
    Harness h(keys);
    h.server->handler = [&h, now](const std::string& endpoint, const json& request) {
      json p = payload(request, endpoint, true, "ok", now);
      p["license"] = license_json(now + 30 * 86400);
      json trial = json::object();
      trial["key"] = "DEMO-7K3QM-P9XWD-R4TNB-H2CFY-M8LJV";
      p["trial"] = trial;
      return http(200, h.signer.envelope(p));
    };
    const auto validated = h.client.validate(kLicenseKey);
    check(validated.ok && !validated.trial_key, "validate never exposes a trial key");
    const std::size_t before = h.server->requests.size();
    velsigil::StartTrialOptions long_email;
    long_email.email = std::string(250, 'a') + "@x.io";
    check(h.client.start_trial(long_email).code == "validation_error", "e-mail > 254 -> validation_error");
    velsigil::StartTrialOptions long_version;
    long_version.version = std::string(33, '1');
    check(h.client.start_trial(long_version).code == "validation_error", "version > 32 -> validation_error");
    check(h.server->requests.size() == before, "local start_trial failures send nothing");
  }
}

void test_network_errors(const Keys& keys) {
  Harness h(keys);
  h.server->handler = [](const std::string&, const json&) { return unreachable("Couldn't connect to server"); };
  const auto refused = h.client.validate(kLicenseKey);
  check(!refused.ok && refused.code == "network_error", "connection refused -> network_error");
  check(refused.message.find("Couldn't connect to server") != std::string::npos, "transport error text is kept");

  h.server->handler = [](const std::string&, const json&) { return unreachable("the request timed out"); };
  const auto timeout = h.client.validate(kLicenseKey);
  check(!timeout.ok && timeout.code == "network_error", "timeout -> network_error");

  h.server->handler = [](const std::string&, const json&) -> HttpResponse { throw std::runtime_error("socket exploded"); };
  const auto thrown = h.client.validate(kLicenseKey);
  check(!thrown.ok && thrown.code == "network_error", "throwing transport -> network_error");
}

void test_offline_fallback(const Keys& keys) {
  Harness h(keys);
  const std::int64_t now = kStartTime;
  std::string mode = "ok";
  h.server->handler = [&h, &mode, now](const std::string&, const json& request) -> HttpResponse {
    if (mode == "down") return unreachable("Couldn't connect to server");
    if (mode == "limited") return http(429, R"({"error":{"code":"rate_limited","message":"Too many requests."}})");
    if (mode == "revoked") {
      json p = payload(request, "validate", false, "license_revoked", now);
      p["license"] = license_json(std::nullopt, "revoked");
      return http(200, h.signer.envelope(p));
    }
    json p = payload(request, "validate", true, "ok", now);
    p["license"] = license_json(now + 30 * 86400);
    p["activation"] = activation_json(now, true);
    p["lease"] = lease_json(h.signer, now, 86400);
    return http(200, h.signer.envelope(p));
  };

  const auto online = h.client.validate_with_offline_fallback(kLicenseKey);
  check(online.ok && !online.offline, "online validation preferred");

  mode = "down";
  *h.clock = now + 3600;
  const auto plain = h.client.validate(kLicenseKey);
  check(plain.code == "network_error", "validate() itself does not fall back");
  const auto fallback = h.client.validate_with_offline_fallback(kLicenseKey);
  check(fallback.ok && fallback.offline, "network_error falls back to the stored lease");
  check(fallback.has_feature("pro") && !fallback.has_feature("enterprise"), "offline features come from the lease");
  check(fallback.license && fallback.license->id == "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f", "offline license id");
  check(fallback.lease && fallback.lease->expires_at == now + 86400, "offline lease expiry");
  const auto direct = h.client.validate_offline();
  check(direct.ok && direct.offline, "validate_offline with a valid lease");

  mode = "limited";
  const auto limited = h.client.validate_with_offline_fallback(kLicenseKey);
  check(!limited.ok && limited.code == "rate_limited" && !limited.offline, "unsigned 429 never falls back");

  mode = "down";
  *h.clock = now + 86400;  // lease exp reached
  const auto expired = h.client.validate_with_offline_fallback(kLicenseKey);
  check(!expired.ok && expired.code == "lease_expired" && expired.offline, "expired lease + server unavailable: lease_expired");
  check(expired.message.find("lease has expired") != std::string::npos, "expired lease: validate_offline()'s message");
  check(!expired.license && !expired.lease, "expired lease: no license from the lease");
  const auto expired_direct = h.client.validate_offline();
  check(!expired_direct.ok && expired_direct.code == "lease_expired" && expired_direct.offline, "validate_offline: lease_expired");
  check_equal(expired.message, expired_direct.message, "expired lease: the fallback result is validate_offline()'s");
  check(stored(h, velsigil::store_keys::kLease).has_value(), "expired lease: kept");
  const auto expired_plain = h.client.validate(kLicenseKey);
  check(!expired_plain.ok && expired_plain.code == "network_error" && !expired_plain.offline,
        "expired lease: validate() still reports the network error");

  *h.clock = now + 60;
  mode = "revoked";
  const auto revoked = h.client.validate_with_offline_fallback(kLicenseKey);
  check(!revoked.ok && revoked.code == "license_revoked" && !revoked.offline, "signed revocation is not overridden");
  mode = "down";
  const auto after_revoke = h.client.validate_with_offline_fallback(kLicenseKey);
  check(!after_revoke.ok && after_revoke.code == "network_error" && !after_revoke.offline,
        "no offline access after a revocation: no lease, the original network error");
  check(h.client.validate_offline().code == "no_lease", "revocation removed the stored lease");
}

void test_offline_fallback_server_unavailable(const Keys& keys) {
  const std::int64_t now = kStartTime;
  struct Case {
    long status;
    std::string body;
    std::string expected;  // the code validate() reports
  };
  // The first four are also tested without a usable lease (below).
  const std::vector<Case> unavailable = {
      {500, R"({"error":{"code":"internal_error","message":"An unexpected error occurred.","requestId":"req-500"}})",
       "internal_error"},
      {503, "", "network_error"},
      {502, "<html><head><title>502 Bad Gateway</title></head><body><h1>Bad Gateway</h1></body></html>", "network_error"},
      {504, "", "network_error"},
      {503, R"({"error":{"code":"service_busy","message":"The service is busy. Please try again shortly."}})",
       "internal_error"},
      {500, "<html><body>500 - Internal server error.</body></html>", "internal_error"},
      {500, "", "internal_error"},
      {502, R"({"error":{"code":"internal_error"}})", "internal_error"},
      {504, R"({"message":"Gateway Timeout"})", "network_error"},
      {503, R"({"error":{"code":)", "network_error"},  // garbled JSON
      {501, "Not Implemented", "internal_error"},
      {599, "\xff\xfe not json", "internal_error"},
      {500, "[1,2,3]", "internal_error"},
      {500, R"({"ok":true,"code":"ok"})", "internal_error"},           // an unsigned body is never an answer
      {503, R"({"error":{"code":"rate_limited"}})", "rate_limited"},  // the status decides, not the body's code
  };

  for (const Case& c : unavailable) {
    const std::string name = "HTTP " + std::to_string(c.status) + " " + c.body;
    Harness h(keys);
    const std::string lease = h.signer.lease(lease_claims(now, now + 86400));
    h.store->set(kProduct, velsigil::store_keys::kLease, lease);
    h.server->handler = [&c](const std::string&, const json&) { return http(c.status, c.body); };

    const auto plain = h.client.validate(kLicenseKey);
    check(!plain.ok && !plain.offline, name + ": validate() itself does not fall back");
    check_equal(plain.code, c.expected, name + ": validate() reports the real error");

    const auto fallback = h.client.validate_with_offline_fallback(kLicenseKey);
    check(fallback.ok && fallback.offline, name + ": falls back to the stored lease");
    check_equal(fallback.code, velsigil::codes::kOk, name + ": fallback code");
    check(fallback.has_feature("pro") && fallback.lease && fallback.lease->expires_at == now + 86400,
          name + ": the license comes from the lease");
    check_equal(fallback.message, h.client.validate_offline().message, name + ": validate_offline()'s result as is");
    check(h.server->requests.size() == 2, name + ": one request per call, no retry");
    check(stored(h, velsigil::store_keys::kLease) == lease, name + ": the stored lease is kept");
  }

  // An unusable lease gives validate_offline()'s result; no lease gives the original error.
  const Signer wrong_signer(keys.wrong_seed);
  struct Unusable {
    std::string name;
    std::function<std::string(const Harness&)> token;
    std::string expected;      // validate_offline()'s code
    std::string message_part;  // from validate_offline()'s message
  };
  const std::vector<Unusable> unusable = {
      {"expired lease", [now](const Harness& h) { return h.signer.lease(lease_claims(now - 86400, now)); },  // exp reached
       velsigil::codes::kLeaseExpired, "lease has expired"},
      {"lease of another device",
       [now](const Harness& h) { return h.signer.lease(lease_claims(now, now + 86400, "another-device-hwid")); },
       velsigil::codes::kLeaseInvalid, "different device"},
      {"lease of another product",
       [now](const Harness& h) {
         json claims = lease_claims(now, now + 86400);
         claims["productId"] = kOtherProduct;
         return h.signer.lease(claims);
       },
       velsigil::codes::kLeaseInvalid, "different product"},
      {"tampered lease",
       [now](const Harness& h) {
         // Altered claims with the genuine lease's signature.
         const std::string genuine = h.signer.lease(lease_claims(now, now + 86400));
         json claims = lease_claims(now, now + 86400);
         claims["features"].push_back("enterprise");
         return b64url(claims.dump()) + genuine.substr(genuine.find('.'));
       },
       velsigil::codes::kLeaseInvalid, "invalid signature"},
      {"lease signed with another key",
       [now, &wrong_signer](const Harness&) { return wrong_signer.lease(lease_claims(now, now + 86400)); },
       velsigil::codes::kLeaseInvalid, "invalid signature"},
      {"malformed lease", [](const Harness&) { return std::string("not-a-lease"); }, velsigil::codes::kLeaseInvalid,
       "malformed"},
  };
  for (std::size_t i = 0; i < 4; ++i) {
    const Case& c = unavailable[i];
    const std::string name = "HTTP " + std::to_string(c.status) + " " + c.body;
    auto respond = [&c](const std::string&, const json&) { return http(c.status, c.body); };
    {
      Harness h(keys);
      h.server->handler = respond;
      const auto plain = h.client.validate(kLicenseKey);
      const auto none = h.client.validate_with_offline_fallback(kLicenseKey);
      check(!none.ok && !none.offline, name + ", no lease: not ok, not offline");
      check_equal(none.code, c.expected, name + ", no lease: the original error, not no_lease");
      check_equal(none.message, plain.message, name + ", no lease: the original message, nothing appended");
      check(none.request_id == plain.request_id, name + ", no lease: the original request id");
      check_equal(h.client.validate_offline().code, velsigil::codes::kNoLease, name + ", no lease: validate_offline()");
      check(!stored(h, velsigil::store_keys::kLease), name + ", no lease: nothing stored");
    }
    for (const Unusable& u : unusable) {
      const std::string what = name + ", " + u.name;
      Harness h(keys);
      const std::string lease = u.token(h);
      h.store->set(kProduct, velsigil::store_keys::kLease, lease);
      h.server->handler = respond;
      const auto result = h.client.validate_with_offline_fallback(kLicenseKey);
      check(!result.ok && result.offline, what + ": not ok, offline");
      check_equal(result.code, u.expected, what + ": validate_offline()'s code, not the online error");
      check(result.message.find(u.message_part) != std::string::npos, what + ": validate_offline()'s message");
      check(!result.license && !result.lease && !result.request_id, what + ": nothing from the lease or the online answer");
      check(h.server->requests.size() == 1, what + ": one request, no retry");
      check(stored(h, velsigil::store_keys::kLease) == lease, what + ": the stored lease is kept");
      const auto direct = h.client.validate_offline();
      check_equal(direct.code, u.expected, what + ": validate_offline()");
      check_equal(result.message, direct.message, what + ": the same result as validate_offline()");
      const auto plain = h.client.validate(kLicenseKey);
      check_equal(plain.code, c.expected, what + ": validate() still reports the online error");
    }
  }

  // Final answers are never overridden by the lease.
  struct Final {
    std::string name;
    std::function<HttpResponse(const Harness&, const json&)> respond;
    std::string expected;
    bool lease_kept;
  };
  const std::vector<Final> finals = {
      {"429 rate_limited",
       [](const Harness&, const json&) {
         return http(429, R"({"error":{"code":"rate_limited","message":"Too many requests.","requestId":"req-429"}})");
       },
       "rate_limited", true},
      {"429 without a body", [](const Harness&, const json&) { return http(429, ""); }, "rate_limited", true},
      {"400 validation_error",
       [](const Harness&, const json&) {
         return http(400, R"({"error":{"code":"validation_error","message":"Invalid request body."}})");
       },
       "validation_error", true},
      {"403 ip_blocked", [](const Harness&, const json&) { return http(403, R"({"error":{"code":"ip_blocked"}})"); },
       "ip_blocked", true},
      {"404 HTML", [](const Harness&, const json&) { return http(404, "<html>Not Found</html>"); }, "invalid_response", true},
      {"signed license_revoked",
       [now](const Harness& h, const json& request) {
         json p = payload(request, "validate", false, "license_revoked", now);
         p["license"] = license_json(std::nullopt, "revoked");
         return http(200, h.signer.envelope(p));
       },
       "license_revoked", false},
      {"signed product_paused",
       [now](const Harness& h, const json& request) {
         return http(200, h.signer.envelope(payload(request, "validate", false, "product_paused", now)));
       },
       "product_paused", true},
      {"200 with a bad signature",
       [now](const Harness& h, const json& request) {
         return http(200, h.signer.envelope(payload(request, "validate", true, "ok", now), true));
       },
       "invalid_response", true},
      {"200 signed with another key",
       [now, &wrong_signer](const Harness&, const json& request) {
         return http(200, wrong_signer.envelope(payload(request, "validate", true, "ok", now)));
       },
       "invalid_response", true},
      {"200 HTML", [](const Harness&, const json&) { return http(200, "<html>proxy</html>"); }, "invalid_response", true},
      {"200 empty", [](const Harness&, const json&) { return http(200, ""); }, "invalid_response", true},
  };
  for (const Final& f : finals) {
    Harness h(keys);
    const std::string lease = h.signer.lease(lease_claims(now, now + 86400));
    h.store->set(kProduct, velsigil::store_keys::kLease, lease);
    h.server->handler = [&h, &f](const std::string&, const json& request) { return f.respond(h, request); };
    const auto result = h.client.validate_with_offline_fallback(kLicenseKey);
    check(!result.ok && !result.offline, f.name + ": no fallback");
    check_equal(result.code, f.expected, f.name + ": code");
    check(result.message.find("offline lease") == std::string::npos, f.name + ": the online message, no lease consulted");
    check(stored(h, velsigil::store_keys::kLease).has_value() == f.lease_kept, f.name + ": stored lease");
  }
}

void test_offline_fallback_retry_after(const Keys& keys) {
  const std::int64_t now = kStartTime;
  struct Outage {
    std::string name;
    HttpResponse response;
    std::optional<std::int64_t> expected;
  };
  const std::vector<Outage> outages = {
      {"503 empty body", http(503, "", "30"), 30},
      {"503 service_busy", http(503, R"({"error":{"code":"service_busy","message":"Busy."}})", "5"), 5},
      {"503 without Retry-After", http(503, ""), std::nullopt},
      {"500 with Retry-After", http(500, R"({"error":{"code":"internal_error"}})", "30"), std::nullopt},
      {"502 with Retry-After", http(502, "<html>Bad Gateway</html>", "30"), std::nullopt},
      {"no HTTP response", unreachable("Couldn't connect to server"), std::nullopt},
  };
  for (const Outage& o : outages) {
    auto respond = [&o](const std::string&, const json&) { return o.response; };
    {
      Harness h(keys);
      h.store->set(kProduct, velsigil::store_keys::kLease, h.signer.lease(lease_claims(now, now + 86400)));
      h.server->handler = respond;
      const auto result = h.client.validate_with_offline_fallback(kLicenseKey);
      check(result.ok && result.offline, o.name + ", usable lease: offline ok");
      check(result.retry_after == o.expected, o.name + ", usable lease: the online retry_after");
      const auto direct = h.client.validate_offline();
      check(direct.ok && direct.offline && !direct.retry_after, o.name + ", usable lease: validate_offline() has none");
    }
    {
      Harness h(keys);
      h.store->set(kProduct, velsigil::store_keys::kLease, h.signer.lease(lease_claims(now - 86400, now)));  // exp reached
      h.server->handler = respond;
      const auto result = h.client.validate_with_offline_fallback(kLicenseKey);
      check_equal(result.code, velsigil::codes::kLeaseExpired, o.name + ", expired lease: code");
      check(result.retry_after == o.expected, o.name + ", expired lease: the online retry_after");
      const auto direct = h.client.validate_offline();
      check(direct.code == velsigil::codes::kLeaseExpired && !direct.retry_after,
            o.name + ", expired lease: validate_offline() has none");
    }
    {
      Harness h(keys);
      h.store->set(kProduct, velsigil::store_keys::kLease,
                   h.signer.lease(lease_claims(now, now + 86400, "another-device-hwid")));
      h.server->handler = respond;
      const auto result = h.client.validate_with_offline_fallback(kLicenseKey);
      check_equal(result.code, velsigil::codes::kLeaseInvalid, o.name + ", invalid lease: code");
      check(result.retry_after == o.expected, o.name + ", invalid lease: the online retry_after");
    }
    {
      Harness h(keys);  // no lease stored: the online result itself
      h.server->handler = respond;
      const auto result = h.client.validate_with_offline_fallback(kLicenseKey);
      check(!result.ok && !result.offline, o.name + ", no lease: the online failure");
      check(result.retry_after == o.expected, o.name + ", no lease: its retry_after");
    }
  }

  Harness h(keys);
  h.store->set(kProduct, velsigil::store_keys::kLease, h.signer.lease(lease_claims(now, now + 86400)));
  h.server->handler = [](const std::string&, const json&) { return http(429, R"({"error":{"code":"rate_limited"}})", "12"); };
  const auto limited = h.client.validate_with_offline_fallback(kLicenseKey);
  check(!limited.ok && !limited.offline && limited.code == "rate_limited", "429 with a stored lease: no fallback");
  check(limited.retry_after == std::optional<std::int64_t>(12), "429 with a stored lease: the online retry_after");
}

void test_deactivate(const Keys& keys) {
  Harness h(keys);
  std::string code = "ok";
  h.server->handler = [&h, &code](const std::string& endpoint, const json& request) {
    return http(200, h.signer.envelope(payload(request, endpoint, code == "ok", code, kStartTime)));
  };

  h.store->set(kProduct, velsigil::store_keys::kDeviceSecret, "dsk_existing");
  h.store->set(kProduct, velsigil::store_keys::kLease, "lease-token");
  code = "device_verification_failed";
  const auto refused = h.client.deactivate(kLicenseKey);
  check(!refused.ok && refused.code == "device_verification_failed", "deactivate failure");
  check(stored(h, velsigil::store_keys::kDeviceSecret).has_value(), "failed deactivate keeps the device secret");
  check(!stored(h, velsigil::store_keys::kLease), "device_verification_failed drops the lease");

  h.store->set(kProduct, velsigil::store_keys::kLease, "lease-token");
  code = "device_not_found";
  const auto missing = h.client.deactivate(kLicenseKey);
  check(!missing.ok && missing.code == "device_not_found", "deactivate device_not_found");
  check(!stored(h, velsigil::store_keys::kDeviceSecret) && !stored(h, velsigil::store_keys::kLease),
        "device_not_found clears local state");
  h.store->set(kProduct, velsigil::store_keys::kDeviceSecret, "dsk_existing");

  code = "ok";
  const auto result = h.client.deactivate(kLicenseKey);
  check(result.ok, "deactivate ok");
  check(ends_with(h.server->urls.back(), "/api/client/v1/deactivate"), "deactivate URL");
  const json& request = h.server->requests.back();
  check_equal(str(request, "deviceSecret"), "dsk_existing", "deactivate sends the device secret");
  check_equal(str(request, "licenseKey"), kLicenseKey, "deactivate sends the key");
  check_equal(str(request, "hwid"), kHwid, "deactivate sends the hwid");
  check(!stored(h, velsigil::store_keys::kDeviceSecret) && !stored(h, velsigil::store_keys::kLease), "deactivate clears local state");
}

void test_device_binding(const Keys& keys) {
  Harness h(keys);
  const std::int64_t now = kStartTime;
  std::string activation_hwid = kHwid;
  bool upper_case_hash = false;
  h.server->handler = [&h, &activation_hwid, &upper_case_hash, now](const std::string& endpoint, const json& request) {
    const std::string type = endpoint == "update-check" ? "update_check" : endpoint;
    json p = payload(request, type, true, "ok", now);
    p["license"] = license_json(now + 30 * 86400);
    if (type != "update_check") {
      p["activation"] = activation_json(now, false);
      std::string hash = velsigil::hash_hardware_id(activation_hwid);
      if (upper_case_hash) {
        for (char& c : hash) {
          if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');
        }
      }
      p["activation"]["hwidHash"] = hash;
    }
    if (type == "download") {
      json download = json::object();
      download["url"] = "/api/download/abc";
      download["expiresAt"] = now + 600;
      download["fileName"] = "app.zip";
      download["size"] = 1;
      download["sha256"] = std::string(64, 'a');
      download["version"] = "1.4.0";
      p["download"] = download;
    }
    return http(200, h.signer.envelope(p));
  };

  upper_case_hash = true;
  const auto own = h.client.validate(kLicenseKey);
  check(own.ok && own.code == "ok", "activation of this device (hash compared case-insensitively) is accepted");
  upper_case_hash = false;

  h.store->set(kProduct, velsigil::store_keys::kDeviceSecret, "dsk_existing");
  h.store->set(kProduct, velsigil::store_keys::kLease, "lease-token");
  activation_hwid = "another-device-hwid";
  const auto validated = h.client.validate(kLicenseKey);
  check(!validated.ok && validated.code == "invalid_response", "validate answer for another device is rejected");
  const auto download = h.client.get_download(kLicenseKey);
  check(!download.ok && download.code == "invalid_response" && !download.download, "download grant for another device is rejected");
  const auto deactivated = h.client.deactivate(kLicenseKey);
  check(!deactivated.ok && deactivated.code == "invalid_response", "deactivation of another device is rejected");
  check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string("dsk_existing") &&
            stored(h, velsigil::store_keys::kLease) == std::string("lease-token"),
        "answers for another device leave the local state untouched");

  const auto update = h.client.check_update("1.0.0");
  check(update.ok, "update checks are not device-bound");
}

void test_update_and_download(const Keys& keys) {
  Harness h(keys);
  std::string release_code = "ok";
  h.server->handler = [&h, &release_code](const std::string& endpoint, const json& request) {
    if (endpoint == "update-check") {
      // `ok: true` comes with code `ok` or `no_release`; anything else is a refusal.
      const bool signed_ok = release_code == "ok" || release_code == "no_release" || release_code == "forged_ok";
      json p = payload(request, "update_check", signed_ok, release_code == "forged_ok" ? "license_expired" : release_code, kStartTime);
      if (release_code == "ok") {
        json update = json::object();
        update["latestVersion"] = "1.4.0";
        update["minVersion"] = "1.0.0";
        update["updateAvailable"] = true;
        update["mandatory"] = false;
        update["changelog"] = "Bug fixes and improvements.";
        p["update"] = update;
      }
      return http(200, h.signer.envelope(p));
    }
    json p = payload(request, "download", true, "ok", kStartTime);
    json download = json::object();
    download["url"] = "https://licenses.example.com/api/download/token";
    download["expiresAt"] = kStartTime + 600;
    download["fileName"] = "app-1.4.0.zip";
    download["size"] = 1048576;
    download["sha256"] = std::string(64, 'a');
    download["version"] = "1.4.0";
    p["download"] = download;
    return http(200, h.signer.envelope(p));
  };
  h.store->set(kProduct, velsigil::store_keys::kDeviceSecret, "dsk_existing");

  const auto update = h.client.check_update("1.2.0");
  check(update.ok && update.update.has_value(), "check_update ok");
  if (update.update) {
    check_equal(update.update->latest_version, "1.4.0", "latest version");
    check(update.update->min_version == std::string("1.0.0"), "min version");
    check(update.update->update_available && !update.update->mandatory, "update flags");
  }
  const json& update_request = h.server->requests.back();
  check(ends_with(h.server->urls.back(), "/api/client/v1/update-check"), "update-check URL");
  check_equal(str(update_request, "version"), "1.2.0", "update-check version");
  check(!update_request.contains("licenseKey") && !update_request.contains("hwid") && !update_request.contains("deviceSecret"),
        "update-check sends no license data");

  release_code = "no_release";
  const auto none = h.client.check_update("1.2.0");
  check(none.ok && none.code == "no_release" && !none.update, "no_release is a successful update check (SPEC 10.2)");
  release_code = "forged_ok";
  const auto inconsistent = h.client.check_update("1.2.0");
  check(!inconsistent.ok && inconsistent.code == "license_expired", "ok flag with a failure code is not ok");
  release_code = "ok";

  const auto download = h.client.get_download(kLicenseKey, std::string("1.4.0"));
  check(download.ok && download.download.has_value(), "get_download ok");
  if (download.download) {
    check_equal(download.download->file_name, "app-1.4.0.zip", "download file name");
    check(download.download->size == 1048576 && download.download->expires_at == kStartTime + 600, "download size/expiry");
  }
  const json& download_request = h.server->requests.back();
  check(ends_with(h.server->urls.back(), "/api/client/v1/download"), "download URL");
  check_equal(str(download_request, "deviceSecret"), "dsk_existing", "download sends the device secret");
  check_equal(str(download_request, "version"), "1.4.0", "download sends the version");

  velsigil::DownloadInfo info;
  info.url = "http://downloads.example.com/file.zip";
  info.size = 10;
  info.sha256 = std::string(64, 'b');
  const auto temp = std::filesystem::temp_directory_path() / "velsigil-download-test.bin";
  const auto insecure = h.client.download_release(info, temp);
  check(!insecure.ok && insecure.code == "download_failed", "download_release refuses plain http");
  info.sha256 = "not-a-digest";
  const auto incomplete = h.client.download_release(info, temp);
  check(!incomplete.ok && incomplete.code == "validation_error", "download_release requires a SHA-256");
  std::error_code ignored;
  check(!std::filesystem::exists(temp, ignored), "nothing written for rejected downloads");
}

void test_download_url_policy(const Keys& keys) {
  std::string grant_url;
  auto respond = [&grant_url](const Harness& h, const json& request) {
    json p = payload(request, "download", true, "ok", kStartTime);
    p["license"] = license_json(kStartTime + 30 * 86400);
    p["activation"] = activation_json(kStartTime, true);
    json download = json::object();
    download["url"] = grant_url;
    download["expiresAt"] = kStartTime + 600;
    download["fileName"] = "app-1.4.0.zip";
    download["size"] = 1048576;
    download["sha256"] = std::string(64, 'a');
    download["version"] = "1.4.0";
    p["download"] = download;
    return http(200, h.signer.envelope(p));
  };

  const std::vector<std::string> rejected = {
      "http://downloads.example.com/app.zip",
      "HTTP://downloads.example.com/app.zip",
      "http://127.0.0.1.example.com/app.zip",
      "http://localhost@downloads.example.com/app.zip",
      "https://user:secret@downloads.example.com/app.zip",
      "ftp://downloads.example.com/app.zip",
      "file:///etc/passwd",
      "downloads.example.com/app.zip",
      "https:///app.zip",
      "https://downloads.example.com/app zip",
      "",
  };
  for (const std::string& url : rejected) {
    Harness h(keys);
    grant_url = url;
    h.server->handler = [&h, &respond](const std::string&, const json& request) { return respond(h, request); };
    h.store->set(kProduct, velsigil::store_keys::kLease, "previous-lease");
    const auto result = h.client.get_download(kLicenseKey);
    const std::string name = "grant URL '" + url + "'";
    check(!result.ok, name + ": not ok");
    check_equal(result.code, "invalid_response", name + ": code");
    check(!result.download && !result.license, name + ": no descriptor or license data");
    check(result.request_id == std::string(kRequestId), name + ": request id kept");
    check(!stored(h, velsigil::store_keys::kDeviceSecret), name + ": issued device secret not persisted");
    check(stored(h, velsigil::store_keys::kLease) == std::string("previous-lease"), name + ": stored lease untouched");
    check(h.server->requests.size() == 1, name + ": no retry");
  }

  // {API URL, grant URL}: https anywhere, plain http to loopback, server-relative URLs.
  const std::vector<std::pair<std::string, std::string>> accepted = {
      {kApiUrl, "https://downloads.example.com/app.zip"},
      {kApiUrl, "HTTPS://cdn.example.com/app.zip"},
      {kApiUrl, "/api/download/token"},
      {kApiUrl, "http://localhost:8787/api/download/token"},
      {kApiUrl, "http://127.0.0.1/api/download/token"},
      {kApiUrl, "http://[::1]:8787/api/download/token"},
      {"http://127.0.0.1:8787", "/api/download/token"},
  };
  for (const auto& [api_url, url] : accepted) {
    Harness h(keys, api_url);
    grant_url = url;
    h.server->handler = [&h, &respond](const std::string&, const json& request) { return respond(h, request); };
    const auto result = h.client.get_download(kLicenseKey);
    const std::string name = "grant URL '" + url + "' (API " + api_url + ")";
    check(result.ok && result.code == "ok" && result.download.has_value(), name + ": accepted");
    if (result.download) check_equal(result.download->url, url, name + ": descriptor URL as signed");
    check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), name + ": issued device secret persisted");
  }

  {
    Harness h(keys);
    h.server->handler = [&h, &respond](const std::string&, const json& request) { return respond(h, request); };
    auto options = make_options(h.server, h.store, h.clock);
    options.allow_insecure_http = true;
    velsigil::Client insecure(kApiUrl, kProduct, keys.public_key, options);
    grant_url = "http://downloads.example.com/app.zip";
    const auto plain = insecure.get_download(kLicenseKey);
    check(plain.ok && plain.download && plain.download->url == grant_url, "allow_insecure_http accepts a plain http grant");
    grant_url = "http://user:secret@downloads.example.com/app.zip";
    const auto credentials = insecure.get_download(kLicenseKey);
    check(!credentials.ok && credentials.code == "invalid_response" && !credentials.download,
          "allow_insecure_http still rejects a grant with credentials");
    grant_url = "ftp://downloads.example.com/app.zip";
    const auto ftp = insecure.get_download(kLicenseKey);
    check(!ftp.ok && ftp.code == "invalid_response" && !ftp.download, "allow_insecure_http still rejects other schemes");
  }
}

void test_configuration(const Keys& keys) {
  auto server = std::make_shared<FakeServer>();
  server->handler = [](const std::string&, const json&) { return unreachable("offline"); };
  auto store = std::make_shared<velsigil::MemoryStore>();
  auto clock = std::make_shared<std::int64_t>(kStartTime);
  auto options = [&] { return make_options(server, store, clock); };

  struct UrlCase {
    std::string url;
    bool accepted;
    std::string endpoint;
  };
  const std::vector<UrlCase> urls = {
      {"https://licenses.example.com", true, "https://licenses.example.com/api/client/v1/validate"},
      {"https://licenses.example.com/", true, "https://licenses.example.com/api/client/v1/validate"},
      {"https://licenses.example.com/api/client/v1", true, "https://licenses.example.com/api/client/v1/validate"},
      {"https://licenses.example.com/api/client/v1/", true, "https://licenses.example.com/api/client/v1/validate"},
      {"HTTPS://Licenses.Example.com:8443", true, "HTTPS://Licenses.Example.com:8443/api/client/v1/validate"},
      {"http://localhost:3000", true, "http://localhost:3000/api/client/v1/validate"},
      {"http://127.0.0.1:8080/", true, "http://127.0.0.1:8080/api/client/v1/validate"},
      {"http://[::1]:3000", true, "http://[::1]:3000/api/client/v1/validate"},
      {"http://licenses.example.com", false, ""},
      {"http://localhost.evil.example", false, ""},
      {"http://localhost@evil.example", false, ""},
      {"https://user:pass@licenses.example.com", false, ""},
      {"ftp://licenses.example.com", false, ""},
      {"file:///etc/passwd", false, ""},
      {"licenses.example.com", false, ""},
      {"https://licenses.example.com?x=1", false, ""},
      {"https://licenses.example.com/#frag", false, ""},
      {"https://licenses example.com", false, ""},
      {"", false, ""},
  };
  for (const UrlCase& c : urls) {
    const std::size_t before = server->count();
    velsigil::Client client(c.url, kProduct, keys.public_key, options());
    check(client.is_configured() == c.accepted, "URL '" + c.url + "' acceptance");
    const auto result = client.validate(kLicenseKey);
    if (c.accepted) {
      check(result.code == "network_error", "URL '" + c.url + "' reaches the transport");
      check(server->count() == before + 1 && server->urls.back() == c.endpoint, "URL '" + c.url + "' endpoint");
    } else {
      check(!result.ok && result.code == "invalid_configuration", "URL '" + c.url + "' is rejected");
      check(server->count() == before, "URL '" + c.url + "' sends nothing");
    }
  }

  {
    auto insecure = options();
    insecure.allow_insecure_http = true;
    velsigil::Client client("http://licenses.example.com", kProduct, keys.public_key, insecure);
    check(client.is_configured(), "allow_insecure_http permits plain http");
  }
  {
    velsigil::Client client(kApiUrl, kProduct, "not-a-key", options());
    check(!client.is_configured() && client.validate(kLicenseKey).code == "invalid_configuration", "invalid public key");
    check(client.validate_offline().code == "invalid_configuration", "invalid public key: offline too");
  }
  {
    std::string unpadded = keys.public_key;
    while (!unpadded.empty() && unpadded.back() == '=') unpadded.pop_back();
    velsigil::Client client(kApiUrl, kProduct, unpadded, options());
    check(unpadded.size() == 43 && client.is_configured(), "public key without padding is accepted");
  }
  {
    velsigil::Client client(kApiUrl, "not-a-uuid", keys.public_key, options());
    check(!client.is_configured(), "invalid product id");
  }
  {
    auto short_hwid = options();
    short_hwid.hwid = std::string("short");
    velsigil::Client client(kApiUrl, kProduct, keys.public_key, short_hwid);
    check(!client.is_configured(), "hwid shorter than 8 characters");
  }
  {
    auto zero_timeout = options();
    zero_timeout.timeout = std::chrono::milliseconds(0);
    velsigil::Client client(kApiUrl, kProduct, keys.public_key, zero_timeout);
    check(!client.is_configured(), "zero timeout");
  }
  {
    auto bad_agent = options();
    bad_agent.user_agent = "agent\r\nX-Injected: 1";
    velsigil::Client client(kApiUrl, kProduct, keys.public_key, bad_agent);
    check(!client.is_configured(), "user agent with CR/LF");
  }
  {
    velsigil::Client original(kApiUrl, kProduct, keys.public_key, options());
    velsigil::Client moved(std::move(original));
    check(moved.is_configured(), "moved-to client works");
    check(original.validate(kLicenseKey).code == "invalid_configuration", "moved-from client fails closed");  // NOLINT(bugprone-use-after-move)
    check(original.hardware_id().empty(), "moved-from client has no hwid");
  }
  {
    velsigil::ClientOptions detected;
    detected.transport = server;
    velsigil::Client client(kApiUrl, kProduct, keys.public_key, detected);
    const std::string hwid = velsigil::Client::get_hardware_id();
    if (hwid.empty()) {
      check(!client.is_configured(), "no machine id and no override -> invalid_configuration");
    } else {
      check(client.is_configured() && client.hardware_id() == hwid, "detected hardware id is used");
    }
  }
}

void test_published_test_keys(const Keys& keys) {
  auto server = std::make_shared<FakeServer>();
  server->handler = [](const std::string&, const json&) { return unreachable("offline"); };
  auto store = std::make_shared<velsigil::MemoryStore>();
  auto clock = std::make_shared<std::int64_t>(kStartTime);
  auto options = [&] { return make_options(server, store, clock); };
  const std::string expected_error =
      "This is the public test key from the Velsigil SDK test vectors, whose private key is published: anyone could "
      "forge license answers for it. Use your product's public key (panel: Products > your product > Integration).";

  auto unpadded = [](std::string key) {
    while (!key.empty() && key.back() == '=') key.pop_back();
    return key;
  };
  const std::vector<std::pair<std::string, std::string>> test_keys = {
      {"keys.publicKey", keys.vector_public_key},
      {"keys.publicKey without padding", unpadded(keys.vector_public_key)},
      {"keys.publicKey with surrounding whitespace", " \t" + keys.vector_public_key + "\n"},
      {"keys.wrongPublicKey", keys.vector_wrong_public_key},
      {"keys.wrongPublicKey without padding", unpadded(keys.vector_wrong_public_key)},
  };

  // (a) Refused with a non-loopback URL; nothing is ever sent.
  const std::vector<std::string> remote_urls = {
      kApiUrl,
      "https://licenses.example.com/api/client/v1",
      "HTTPS://Licenses.Example.com:8443",
      "https://localhost.example.com",
      "https://127.0.0.1.example.com",
      "https://192.168.1.10",
      "https://[::2]:8443",
      // Look-alikes of the loopback hosts: never exempt.
      "https://localhost.",
      "https://127.1",
      "https://[0:0:0:0:0:0:0:1]",
      "https://127.0.0.1.nip.io",
  };
  for (const auto& [label, key] : test_keys) {
    for (const std::string& url : remote_urls) {
      const std::string name = label + " with API URL '" + url + "'";
      const std::size_t before = server->count();
      velsigil::Client client(url, kProduct, key, options());
      check(!client.is_configured(), name + ": refused");
      check_equal(client.configuration_error(), expected_error, name + ": configuration error");
      const auto result = client.validate(kLicenseKey);
      check(!result.ok && result.code == "invalid_configuration", name + ": validate returns invalid_configuration");
      check_equal(result.message, expected_error, name + ": validate message");
      check(client.validate_offline().code == "invalid_configuration", name + ": validate_offline returns invalid_configuration");
      check(client.check_update("1.0.0").code == "invalid_configuration", name + ": check_update returns invalid_configuration");
      check(server->count() == before, name + ": nothing is sent");
    }
  }
  {
    auto insecure = options();
    insecure.allow_insecure_http = true;
    velsigil::Client client("http://licenses.example.com", kProduct, keys.vector_public_key, insecure);
    check(!client.is_configured() && client.configuration_error() == expected_error,
          "allow_insecure_http does not admit a test key for a non-loopback host");
  }
  {
    std::string url_safe = keys.vector_public_key;
    for (char& c : url_safe) {
      if (c == '+') c = '-';
      if (c == '/') c = '_';
    }
    velsigil::Client client(kApiUrl, kProduct, url_safe, options());
    check(url_safe != keys.vector_public_key && !client.is_configured() &&
              client.validate(kLicenseKey).code == "invalid_configuration",
          "the URL-safe spelling of keys.publicKey is refused");
  }

  // (b) Accepted with a loopback URL, over http or https.
  const std::vector<std::string> loopback_urls = {
      "http://localhost:3000",
      "http://LocalHost:3000/api/client/v1",
      "http://127.0.0.1:8080/",
      "http://[::1]:3000",
      "https://localhost:8443",
      "https://127.0.0.1",
  };
  for (const auto& [label, key] : test_keys) {
    for (const std::string& url : loopback_urls) {
      const std::string name = label + " with API URL '" + url + "'";
      const std::size_t before = server->count();
      velsigil::Client client(url, kProduct, key, options());
      check(client.is_configured(), name + ": accepted (" + client.configuration_error() + ")");
      check(client.validate(kLicenseKey).code == "network_error" && server->count() == before + 1,
            name + ": reaches the transport");
    }
  }
  {
    Keys vector_keys = keys;
    vector_keys.public_key = keys.vector_public_key;
    vector_keys.seed = keys.vector_seed;
    Harness h(vector_keys, "http://localhost:3000");
    h.server->handler = [&h](const std::string& endpoint, const json& request) {
      json p = payload(request, endpoint, true, "ok", kStartTime);
      p["license"] = license_json(kStartTime + 30 * 86400);
      return http(200, h.signer.envelope(p));
    };
    check(h.client.validate(kLicenseKey).ok, "the test-vector key verifies the answers of a local test server");
  }

  // (c) A random product key is still accepted with a non-loopback URL.
  {
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> random_public{};
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> random_secret{};
    crypto_sign_keypair(random_public.data(), random_secret.data());
    sodium_memzero(random_secret.data(), random_secret.size());
    const std::string random_key = b64_standard(random_public.data(), random_public.size());
    for (const std::string& url : remote_urls) {
      velsigil::Client client(url, kProduct, random_key, options());
      check(client.is_configured(), "a random product key with API URL '" + url + "' is accepted (" +
                                        client.configuration_error() + ")");
    }
    velsigil::Client client(kApiUrl, kProduct, keys.public_key, options());
    check(client.is_configured(), "this run's signing key is accepted with a non-loopback URL");
  }

  // A host may use the test keys exactly when it may use plain http://.
  const std::vector<std::string> hosts = {
      "localhost", "LOCALHOST:3000", "127.0.0.1", "127.0.0.1:8080", "[::1]", "[::1]:3000", "localhost.",
      "127.0.0.2", "0.0.0.0", "[::2]", "localhost.example.com", "licenses.example.com", "localhost@evil.example", "[::1",
  };
  for (const std::string& host : hosts) {
    const bool plain_http_allowed = !velsigil::detail::url_policy_error("http://" + host, false).has_value();
    check(velsigil::detail::is_loopback_url("http://" + host) == plain_http_allowed, "loopback rule for http://" + host);
    check(velsigil::detail::is_loopback_url("https://" + host) == plain_http_allowed, "loopback rule for https://" + host);
  }
  check(velsigil::detail::is_loopback_url("http://localhost:3000") && !velsigil::detail::is_loopback_url("https://licenses.example.com"),
        "is_loopback_url sanity");
}

void test_low_level_helpers(const Keys& keys) {
  constexpr char kNonce[] = "low-level-helpers-nonce-0123456789";
  json request = json::object();
  request["nonce"] = kNonce;
  request["productId"] = kProduct;
  json answer = payload(request, "validate", true, "ok", kStartTime);
  answer["license"] = license_json(kStartTime + 30 * 86400);
  const json claims = lease_claims(kStartTime, kStartTime + 86400);
  const std::int64_t now = kStartTime + 60;

  {
    // This run's key pair stands for a product's own key.
    const Signer signer(keys.seed);
    const std::string envelope = signer.envelope(answer);
    const std::string lease = signer.lease(claims);
    const auto verification = velsigil::verify_envelope_typed(envelope, keys.public_key, kNonce, kProduct, "validate", kHwid);
    check(verification.status == velsigil::EnvelopeStatus::valid && !verification.payload_json.empty(),
          "verify_envelope_typed verifies an answer signed with the product's own key");
    const auto lease_verification = velsigil::verify_lease(lease, keys.public_key, kProduct, kHwid, now);
    check(lease_verification.status == velsigil::LeaseStatus::valid && lease_verification.claims.has_value(),
          "verify_lease verifies a lease signed with the product's own key");
  }

  const Signer vector_signer(keys.vector_seed);
  const std::string envelope = vector_signer.envelope(answer);
  const std::string lease = vector_signer.lease(claims);
  std::string unpadded = keys.vector_public_key;
  while (!unpadded.empty() && unpadded.back() == '=') unpadded.pop_back();
  const std::vector<std::pair<std::string, std::string>> spellings = {
      {"keys.publicKey", keys.vector_public_key},
      {"keys.publicKey without padding", unpadded},
      {"keys.publicKey with surrounding whitespace", " " + keys.vector_public_key + "\r\n"},
  };
  for (const auto& [label, key] : spellings) {
    const auto control = velsigil::detail::verify_envelope_typed_unguarded(envelope, key, kNonce, kProduct, "validate", kHwid);
    check(control.status == velsigil::EnvelopeStatus::valid, label + ": the answer verifies through the internal entry point");
    const auto refused = velsigil::verify_envelope_typed(envelope, key, kNonce, kProduct, "validate", kHwid);
    check(refused.status == velsigil::EnvelopeStatus::invalid_signature && refused.payload_json.empty(),
          label + ": verify_envelope_typed refuses it like an invalid key");

    const auto lease_control = velsigil::detail::verify_lease_unguarded(lease, key, kProduct, kHwid, now);
    check(lease_control.status == velsigil::LeaseStatus::valid, label + ": the lease verifies through the internal entry point");
    const auto refused_lease = velsigil::verify_lease(lease, key, kProduct, kHwid, now);
    check(refused_lease.status == velsigil::LeaseStatus::invalid_signature && !refused_lease.claims.has_value(),
          label + ": verify_lease refuses it like an invalid key");
  }
}

class ThrowingStore final : public velsigil::IStore {
 public:
  std::optional<std::string> get(const std::string&, const std::string&) override { throw std::runtime_error("get failed"); }
  bool set(const std::string&, const std::string&, const std::string&) override { throw std::runtime_error("set failed"); }
  bool erase(const std::string&, const std::string&) override { throw std::runtime_error("erase failed"); }
};

void test_store_failures_are_contained(const Keys& keys) {
  const Signer signer(keys.seed);
  auto server = std::make_shared<FakeServer>();
  server->handler = [&signer](const std::string& endpoint, const json& request) {
    json p = payload(request, endpoint, true, "ok", kStartTime);
    p["activation"] = activation_json(kStartTime, true);
    p["lease"] = lease_json(signer, kStartTime, 3600);
    return http(200, signer.envelope(p));
  };
  auto clock = std::make_shared<std::int64_t>(kStartTime);
  velsigil::Client client(kApiUrl, kProduct, keys.public_key, make_options(server, std::make_shared<ThrowingStore>(), clock));
  check(client.validate(kLicenseKey).ok, "a throwing store does not break validation");
  check(client.deactivate(kLicenseKey).ok, "a throwing store does not break deactivation");
  check(client.validate_offline().code == "no_lease", "a throwing store reads as empty");
  client.clear_local_state();
}

// Throws on the next `failing_reads` reads.
class FlakyStore final : public velsigil::IStore {
 public:
  std::optional<std::string> get(const std::string& product_id, const std::string& key) override {
    if (failing_reads.load() > 0) {
      --failing_reads;
      throw std::runtime_error("store busy");
    }
    return inner.get(product_id, key);
  }
  bool set(const std::string& product_id, const std::string& key, const std::string& value) override {
    return inner.set(product_id, key, value);
  }
  bool erase(const std::string& product_id, const std::string& key) override { return inner.erase(product_id, key); }

  std::atomic<int> failing_reads{0};
  velsigil::MemoryStore inner;
};

void test_store_read_failures_fail_closed(const Keys& keys) {
  auto server = std::make_shared<FakeServer>();
  server->handler = [](const std::string&, const json&) { return unreachable("no request may be sent"); };
  auto store = std::make_shared<FlakyStore>();
  const std::string paid_secret = "dsk_P4idL1c3P4idL1c3P4idL1c3P4idL1c3P4idL1c3abc";
  store->inner.set(kProduct, velsigil::store_keys::kDeviceSecret, paid_secret);
  store->failing_reads = 1;
  auto clock = std::make_shared<std::int64_t>(kStartTime);
  velsigil::Client client(kApiUrl, kProduct, keys.public_key, make_options(server, store, clock));

  const auto refused = client.start_trial();
  check(!refused.ok && refused.code == velsigil::codes::kStoreUnavailable, "unreadable store: start_trial -> store_unavailable");
  check_equal(velsigil::codes::kStoreUnavailable, "store_unavailable", "codes::kStoreUnavailable");
  check(refused.message.find("could not be read") != std::string::npos, "store_unavailable message");
  check(!refused.trial_key, "store_unavailable: no trial key");
  check(server->count() == 0, "unreadable store: nothing is sent");
  check(client.start_trial().code == velsigil::codes::kAlreadyLicensed, "readable again: the stored license refuses the trial");
  check(server->count() == 0, "readable again: still nothing is sent");
  check(store->inner.get(kProduct, velsigil::store_keys::kDeviceSecret) == paid_secret, "the stored device secret is unchanged");
}

void test_file_store(const Keys& keys) {
  namespace fs = std::filesystem;
  const auto suffix = velsigil::detail::random_hex(8);
  check(suffix.has_value(), "random suffix");
  const fs::path dir = fs::temp_directory_path() / ("velsigil-test-" + suffix.value_or("fallback"));
  const fs::path file = dir / "nested" / "store.json";
  std::error_code ec;

  {
    velsigil::FileStore store(file);
    check(!store.get(kProduct, velsigil::store_keys::kDeviceSecret), "empty file store");
    check(store.set(kProduct, velsigil::store_keys::kDeviceSecret, "dsk_file_secret"), "file store set");
    check(store.set(kProduct, velsigil::store_keys::kLease, "lease-token"), "file store set lease");
    check(store.set(kOtherProduct, velsigil::store_keys::kLease, "other-lease"), "file store second product");
    check(store.get(kProduct, velsigil::store_keys::kDeviceSecret) == std::string("dsk_file_secret"), "file store get");
  }
  {
    velsigil::FileStore reopened(file);
    check(reopened.get(kProduct, velsigil::store_keys::kDeviceSecret) == std::string("dsk_file_secret"), "file store survives reopen");
    check(reopened.erase(kProduct, velsigil::store_keys::kDeviceSecret), "file store erase");
    check(!reopened.get(kProduct, velsigil::store_keys::kDeviceSecret), "erased value is gone");
    check(reopened.get(kProduct, velsigil::store_keys::kLease) == std::string("lease-token"), "other key kept");
    check(reopened.get(kOtherProduct, velsigil::store_keys::kLease) == std::string("other-lease"), "other product kept");
    check(reopened.erase(kProduct, "missing"), "erasing a missing key succeeds");
  }

  std::size_t entries = 0;
  for (const auto& entry : fs::directory_iterator(file.parent_path(), ec)) {
    (void)entry;
    ++entries;
  }
  check(entries == 1, "no temporary files are left behind");
#if !defined(_WIN32)
  const fs::perms permissions = fs::status(file, ec).permissions();
  check((permissions & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none, "store file is owner-only (0600)");
#endif

  {
    std::ofstream corrupt(file, std::ios::out | std::ios::trunc | std::ios::binary);
    corrupt << "{not json";
  }
  {
    velsigil::FileStore store(file);
    check(!store.get(kProduct, velsigil::store_keys::kLease), "corrupt file reads as empty");
    check(store.set(kProduct, velsigil::store_keys::kLease, "fresh"), "corrupt file is replaced on write");
    check(store.get(kProduct, velsigil::store_keys::kLease) == std::string("fresh"), "replaced file is readable");
  }

  {
    const Signer signer(keys.seed);
    auto server = std::make_shared<FakeServer>();
    server->handler = [&signer](const std::string& endpoint, const json& request) {
      json p = payload(request, endpoint, true, "ok", kStartTime);
      p["activation"] = activation_json(kStartTime, !request.contains("deviceSecret"));
      return http(200, signer.envelope(p));
    };
    auto clock = std::make_shared<std::int64_t>(kStartTime);
    const fs::path app_file = dir / "app.json";
    {
      velsigil::Client first(kApiUrl, kProduct, keys.public_key, make_options(server, std::make_shared<velsigil::FileStore>(app_file), clock));
      check(first.validate(kLicenseKey).ok, "first run validates");
    }
    {
      velsigil::Client second(kApiUrl, kProduct, keys.public_key, make_options(server, std::make_shared<velsigil::FileStore>(app_file), clock));
      check(second.validate(kLicenseKey).ok, "second run validates");
    }
    check(server->requests.size() == 2 && str(server->requests[1], "deviceSecret") == kDeviceSecret,
          "device secret persisted across restarts");
  }

  check(velsigil::FileStore::default_path("../evil").empty(), "default_path rejects traversal");
  check(velsigil::FileStore::default_path("").empty(), "default_path rejects empty names");
  const fs::path default_path = velsigil::FileStore::default_path("Velsigil Example");
  check(default_path.empty() || default_path.filename() == "velsigil-license.json", "default_path file name");

#if !defined(_WIN32)
  // Root can read any file, so the unreadable-file case is skipped.
  if (::geteuid() != 0) {
    const fs::path locked = dir / "locked.json";
    {
      velsigil::FileStore store(locked);
      check(store.set(kProduct, velsigil::store_keys::kDeviceSecret, kDeviceSecret), "locked store: seed secret");
      check(store.set(kOtherProduct, velsigil::store_keys::kLease, "other-lease"), "locked store: seed other product");
    }
    fs::permissions(locked, fs::perms::none, fs::perm_options::replace, ec);
    {
      velsigil::FileStore store(locked);
      bool threw = false;
      try {
        (void)store.get(kProduct, velsigil::store_keys::kDeviceSecret);
      } catch (const std::exception&) {
        threw = true;
      }
      check(threw, "an unreadable store file throws from get() instead of reading as empty");
      check(!store.set(kProduct, velsigil::store_keys::kLease, "new-lease"), "an unreadable store file is never rewritten (set)");
      check(!store.erase(kProduct, velsigil::store_keys::kDeviceSecret), "an unreadable store file is never rewritten (erase)");
    }
    fs::permissions(locked, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
    velsigil::FileStore reopened(locked);
    check(reopened.get(kProduct, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret),
          "the device secret survives an unreadable moment");
    check(reopened.get(kOtherProduct, velsigil::store_keys::kLease) == std::string("other-lease"),
          "other products survive an unreadable moment");
  }
#endif

  fs::remove_all(dir, ec);
}

void test_file_store_legacy_fallback(const Keys& keys) {
  namespace fs = std::filesystem;
  const auto suffix = velsigil::detail::random_hex(8);
  check(suffix.has_value(), "random suffix (legacy store)");
  const fs::path dir = fs::temp_directory_path() / ("velsigil-legacy-test-" + suffix.value_or("fallback"));
  const fs::path file = dir / "velsigil-license.json";
  const fs::path legacy = dir / "veltrix-license.json";
  std::error_code ec;
  fs::create_directories(dir, ec);
  check(!ec, "legacy test directory created");

  auto write_text = [](const fs::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::out | std::ios::trunc | std::ios::binary);
    out << text;
  };
  auto read_text = [](const fs::path& path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
  };
  auto legacy_document = [](const std::string& device_secret, const std::string& lease) {
    json entry = json::object();
    entry["deviceSecret"] = device_secret;
    entry["lease"] = lease;
    json products = json::object();
    products[std::string(kProduct)] = entry;
    json document = json::object();
    document["version"] = 1;
    document["products"] = products;
    return document.dump(2);
  };

  write_text(legacy, legacy_document(kDeviceSecret, "legacy-lease"));
  const std::string legacy_before = read_text(legacy);

  {
    velsigil::FileStore store(file);
    check(store.legacy_path() == legacy, "default file name has a legacy fallback");
    check(store.get(kProduct, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "legacy device secret is read");
    check(store.get(kProduct, velsigil::store_keys::kLease) == std::string("legacy-lease"), "legacy lease is read");
    check(!fs::exists(file, ec), "reading does not create the new file");

    check(store.set(kOtherProduct, velsigil::store_keys::kLease, "other-lease"), "first write after the fallback");
    check(fs::exists(file, ec), "first write creates the new file");
  }
  {
    velsigil::FileStore reopened(file);
    check(reopened.get(kProduct, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "device secret migrated");
    check(reopened.get(kProduct, velsigil::store_keys::kLease) == std::string("legacy-lease"), "lease migrated");
    check(reopened.get(kOtherProduct, velsigil::store_keys::kLease) == std::string("other-lease"), "new value written");
    check(reopened.erase(kProduct, velsigil::store_keys::kDeviceSecret), "erase after migration");
    check(!reopened.get(kProduct, velsigil::store_keys::kDeviceSecret), "legacy file no longer consulted");
  }
  check(read_text(legacy) == legacy_before, "legacy file is never modified");

  {
    velsigil::FileStore custom(dir / "custom.json");
    check(custom.legacy_path().empty(), "custom file name has no legacy fallback");
    check(!custom.get(kProduct, velsigil::store_keys::kLease), "custom file name ignores the legacy file");
  }
  const fs::path default_path = velsigil::FileStore::default_path("Velsigil Example");
  if (!default_path.empty()) {
    check(velsigil::FileStore(default_path).legacy_path() == default_path.parent_path() / "veltrix-license.json",
          "default_path store falls back to the legacy file in the same directory");
  }

  {
    const Signer signer(keys.seed);
    const fs::path app_dir = dir / "app";
    fs::create_directories(app_dir, ec);
    write_text(app_dir / "veltrix-license.json",
               legacy_document(kDeviceSecret, signer.lease(lease_claims(kStartTime, kStartTime + 86400))));

    auto server = std::make_shared<FakeServer>();
    server->handler = [&signer](const std::string& endpoint, const json& request) {
      json p = payload(request, endpoint, true, "ok", kStartTime);
      p["activation"] = activation_json(kStartTime, !request.contains("deviceSecret"));
      return http(200, signer.envelope(p));
    };
    auto clock = std::make_shared<std::int64_t>(kStartTime);
    const fs::path app_file = app_dir / "velsigil-license.json";
    velsigil::Client client(kApiUrl, kProduct, keys.public_key,
                            make_options(server, std::make_shared<velsigil::FileStore>(app_file), clock));
    const auto offline = client.validate_offline();
    check(offline.ok && offline.offline, "legacy lease validates offline after the SDK update");
    check(client.validate(kLicenseKey).ok, "validate with a legacy store");
    check(server->requests.size() == 1 && str(server->requests[0], "deviceSecret") == kDeviceSecret,
          "legacy device secret is re-sent");
    check(fs::exists(app_file, ec), "the client's first write migrates to the new file");
    check(velsigil::FileStore(app_file).get(kProduct, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret),
          "device secret carried over to the new file");
  }

  fs::remove_all(dir, ec);
}

void test_result_helpers() {
  velsigil::ValidationResult result;
  result.ok = true;
  result.code = "ok";
  result.license = velsigil::LicenseInfo{};
  result.license->features = {"pro"};
  result.license->expires_at = 1000000;
  check(result.has_feature("pro") && !result.has_feature("pr"), "has_feature exact match");
  check(result.expires_at() == 1000000 && !result.is_lifetime(), "expires_at");
  check(result.seconds_until_expiry(400000) == 600000, "seconds_until_expiry");
  check(result.seconds_until_expiry(2000000) == 0, "seconds_until_expiry clamps at zero");
  check(result.days_until_expiry(1000000 - 3 * 86400 - 5) == 4, "days_until_expiry rounds up");
  check(result.days_until_expiry(1000000 - 3 * 86400) == 3, "days_until_expiry of whole days");
  check(result.days_until_expiry(1000000 - 1) == 1, "days_until_expiry is 1 throughout the last day");
  check(result.days_until_expiry(1000000) == 0 && result.days_until_expiry(2000000) == 0, "days_until_expiry is 0 once expired");
  result.server_time = 1000000 - 14 * 86400;
  result.reference_time = 1000000 - 86400 + 1;
  check(result.days_until_expiry() == 14, "days_until_expiry() measures at server_time (an N-day trial shows N)");
  result.server_time.reset();
  check(result.days_until_expiry() == 1, "days_until_expiry() of an offline result measures at reference_time");
  result.reference_time.reset();
  result.license->expires_at.reset();
  check(result.is_lifetime() && !result.seconds_until_expiry(0) && !result.expires_at(), "lifetime helpers");
  result.ok = false;
  check(!result.has_feature("pro") && !static_cast<bool>(result), "failed results grant nothing");
  const velsigil::ValidationResult empty{};
  check(!empty.expires_at() && !empty.is_lifetime() && !empty.has_feature("pro"), "empty result");
}

void test_concurrent_use(const Keys& keys) {
  Harness h(keys);
  h.server->handler = [&h](const std::string& endpoint, const json& request) {
    json p = payload(request, endpoint, true, "ok", kStartTime);
    p["license"] = license_json(std::nullopt);
    return http(200, h.signer.envelope(p));
  };
  static constexpr int kThreads = 8;
  static constexpr int kCallsPerThread = 10;
  std::atomic<int> successes{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&h, &successes] {
      for (int i = 0; i < kCallsPerThread; ++i) {
        if (h.client.validate(kLicenseKey).ok) ++successes;
      }
    });
  }
  for (std::thread& thread : threads) thread.join();
  check(successes.load() == kThreads * kCallsPerThread, "concurrent validations succeed");
  std::set<std::string> nonces;
  for (const json& request : h.server->requests) nonces.insert(str(request, "nonce"));
  check(nonces.size() == static_cast<std::size_t>(kThreads * kCallsPerThread), "every concurrent request has a unique nonce");
}

void test_device_calls_are_serialized(const Keys& keys) {
  {
    Harness h(keys);
    std::atomic<bool> issued{false};
    h.server->handler = [&h, &issued](const std::string& endpoint, const json& request) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));  // keep the first call in flight
      json p = payload(request, endpoint, true, "ok", kStartTime);
      p["license"] = license_json(kStartTime + 30 * 86400);
      p["activation"] = activation_json(kStartTime, !issued.exchange(true));
      return http(200, h.signer.envelope(p));
    };
    std::thread other([&h] { (void)h.client.validate(kLicenseKey); });
    (void)h.client.validate(kLicenseKey);
    other.join();
    check(h.server->count() == 2, "two concurrent validations are sent");
    int without_secret = 0;
    for (const json& request : h.server->requests) {
      if (!request.contains("deviceSecret")) ++without_secret;
    }
    check(without_secret == 1, "only the first of two concurrent activations is sent without the device secret");
    check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "the issued device secret is stored");
  }

  {
    Harness h(keys);
    h.server->handler = [&h](const std::string& endpoint, const json& request) {
      if (endpoint != "validate") return unreachable("a trial must not be sent");
      std::this_thread::sleep_for(std::chrono::milliseconds(200));  // start_trial runs meanwhile
      json p = payload(request, endpoint, true, "ok", kStartTime);
      p["license"] = license_json(kStartTime + 30 * 86400);
      p["activation"] = activation_json(kStartTime, true);
      p["lease"] = lease_json(h.signer, kStartTime, 86400);
      return http(200, h.signer.envelope(p));
    };
    std::thread validation([&h] { (void)h.client.validate(kLicenseKey); });
    for (int i = 0; i < 500 && h.server->count() == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    const velsigil::ValidationResult trial = h.client.start_trial();
    validation.join();
    check(trial.code == velsigil::codes::kAlreadyLicensed, "start_trial waits for a validation in progress, then refuses");
    check(h.server->count() == 1 && ends_with(h.server->urls.at(0), "/validate"), "no trial request is sent");
    check(stored(h, velsigil::store_keys::kDeviceSecret) == std::string(kDeviceSecret), "the validation's device secret is kept");
  }
}

void test_machine_id_placeholder() {
  using velsigil::detail::usable_machine_id;
  check(usable_machine_id("4c4c4544004235108051b4c04f4e4b32\n") == std::string("4c4c4544004235108051b4c04f4e4b32\n"),
        "a machine id is usable");
  check(!usable_machine_id("uninitialized\n"), "the systemd placeholder is skipped");
  check(!usable_machine_id(" UNINITIALIZED "), "the placeholder is skipped in any case");
  check(!usable_machine_id(" \n"), "an empty machine-id file is skipped");
}

// Signs with fresh key pairs: the published vector key is refused for the non-loopback kApiUrl.
Keys make_keys(const std::string& vectors_path) {
  std::ifstream in(vectors_path, std::ios::in | std::ios::binary);
  if (!in) throw std::runtime_error("cannot open test vectors: " + vectors_path);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  const json vectors = json::parse(buffer.str());
  Keys keys;
  keys.vector_public_key = vectors.at("keys").at("publicKey").get<std::string>();
  keys.vector_wrong_public_key = vectors.at("keys").at("wrongPublicKey").get<std::string>();
  const auto vector_seed = velsigil::detail::base64_decode(vectors.at("keys").at("privateSeedBase64").get<std::string>());
  if (!vector_seed || vector_seed->size() != crypto_sign_SEEDBYTES) throw std::runtime_error("invalid seed in test vectors");
  keys.vector_seed = *vector_seed;

  keys.seed.resize(crypto_sign_SEEDBYTES);
  keys.wrong_seed.resize(crypto_sign_SEEDBYTES);
  randombytes_buf(keys.seed.data(), keys.seed.size());
  randombytes_buf(keys.wrong_seed.data(), keys.wrong_seed.size());
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> public_key{};
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key{};
  crypto_sign_seed_keypair(public_key.data(), secret_key.data(), keys.seed.data());
  sodium_memzero(secret_key.data(), secret_key.size());
  keys.public_key = b64_standard(public_key.data(), public_key.size());
  return keys;
}

}  // namespace

int main(int argc, char** argv) {
  if (sodium_init() < 0) {
    std::cerr << "libsodium initialisation failed\n";
    return 2;
  }
  try {
    const Keys keys = make_keys(argc > 1 ? std::string(argv[1]) : std::string(VX_TEST_VECTORS_PATH));
    test_validate_ok_and_device_secret(keys);
    test_business_failures(keys);
    test_tampered_responses(keys);
    test_clock_skew(keys);
    test_unsigned_errors(keys);
    test_retry_after(keys);
    test_parse_retry_after();
    test_start_trial(keys);
    test_network_errors(keys);
    test_offline_fallback(keys);
    test_offline_fallback_server_unavailable(keys);
    test_offline_fallback_retry_after(keys);
    test_deactivate(keys);
    test_device_binding(keys);
    test_update_and_download(keys);
    test_download_url_policy(keys);
    test_configuration(keys);
    test_published_test_keys(keys);
    test_low_level_helpers(keys);
    test_store_failures_are_contained(keys);
    test_store_read_failures_fail_closed(keys);
    test_file_store(keys);
    test_file_store_legacy_fallback(keys);
    test_result_helpers();
    test_concurrent_use(keys);
    test_device_calls_are_serialized(keys);
    test_machine_id_placeholder();
  } catch (const std::exception& error) {
    std::cerr << "unexpected exception: " << error.what() << '\n';
    return 2;
  }
  std::cout << g_checks << " checks, " << g_failures << " failures\n";
  return g_failures == 0 ? 0 : 1;
}
