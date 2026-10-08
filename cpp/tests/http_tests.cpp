// Real libcurl round trips against tests/mock_server/mock_server.py (started by run_http_tests.py).
// Arguments: <mock base URL> <URL with nothing listening> <product public key>. Uses only the
// public API. Exit code 0 = all checks passed.
#include <velsigil/client.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>

namespace {

constexpr char kProduct[] = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b";

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const std::string& what) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL: " << what << '\n';
  }
}

void check_code(const velsigil::ValidationResult& result, const std::string& expected, const std::string& what) {
  ++g_checks;
  if (result.code != expected) {
    ++g_failures;
    std::cerr << "FAIL: " << what << ": expected '" << expected << "', got '" << result.code << "' (" << result.message << ")\n";
  }
}

struct Setup {
  std::string base_url;
  std::string refused_url;
  std::string public_key;
};

velsigil::Client make_client(const Setup& setup, const std::string& url, const std::string& hwid,
                            std::shared_ptr<velsigil::IStore> store,
                            std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
  velsigil::ClientOptions options;
  options.hwid = hwid;
  options.store = std::move(store);
  options.timeout = timeout;
  return velsigil::Client(url, kProduct, setup.public_key, options);
}

void run(const Setup& setup) {
  namespace fs = std::filesystem;

  // ok + device secret persistence + strict device binding on the mock.
  auto store = std::make_shared<velsigil::MemoryStore>();
  velsigil::Client client = make_client(setup, setup.base_url, "http-test-hwid-0001", store);
  check(client.is_configured(), "client configured: " + client.configuration_error());
  const auto first = client.validate("VX-OK");
  check(first.ok && first.code == "ok", "validate ok");
  check(first.has_feature("pro") && first.activation && first.activation->device_secret_issued, "first activation");
  check(store->get(kProduct, velsigil::store_keys::kDeviceSecret).has_value(), "device secret stored");
  check(store->get(kProduct, velsigil::store_keys::kLease).has_value(), "lease stored");
  const auto second = client.validate("VX-OK");
  check(second.ok, "second validate re-sends the device secret");

  velsigil::Client stranger = make_client(setup, setup.base_url, "http-test-hwid-0001", std::make_shared<velsigil::MemoryStore>());
  check_code(stranger.validate("VX-OK"), "device_verification_failed", "same hwid without the device secret");

  // Failure scenarios use their own store: a signed invalid_key would (by design) drop the lease
  // that the offline-fallback check below relies on.
  velsigil::Client failing = make_client(setup, setup.base_url, "http-test-hwid-fail", std::make_shared<velsigil::MemoryStore>());
  check_code(failing.validate("VX-INVALID"), "invalid_key", "signed business failure");
  check_code(failing.validate("VX-NONCE"), "invalid_response", "nonce mismatch");
  check_code(failing.validate("VX-BADSIG"), "invalid_response", "bad signature");
  check_code(failing.validate("VX-429"), "rate_limited", "HTTP 429");
  check_code(failing.validate("VX-400"), "validation_error", "HTTP 400");
  check_code(failing.validate("VX-500"), "internal_error", "HTTP 500");

  velsigil::Client skewed = make_client(setup, setup.base_url, "http-test-hwid-skew", std::make_shared<velsigil::MemoryStore>());
  check_code(skewed.validate("VX-SKEW"), "ok", "clock_skew is corrected with one retry");

  velsigil::Client impatient = make_client(setup, setup.base_url, "http-test-hwid-slow", std::make_shared<velsigil::MemoryStore>(),
                                          std::chrono::milliseconds(1000));
  check_code(impatient.validate("VX-SLOW"), "network_error", "timeout");

  velsigil::Client nobody = make_client(setup, setup.refused_url, "http-test-hwid-0001", std::make_shared<velsigil::MemoryStore>());
  check_code(nobody.validate("VX-OK"), "network_error", "connection refused");

  // Offline fallback: same store (lease) and hwid, server unreachable.
  velsigil::Client offline = make_client(setup, setup.refused_url, "http-test-hwid-0001", store);
  const auto fallback = offline.validate_with_offline_fallback("VX-OK");
  check(fallback.ok && fallback.offline && fallback.has_feature("pro"), "offline fallback with the stored lease");

  // The server answers but is unavailable (its database is down) or a gateway cannot reach it: every unsigned
  // 5xx, whatever its body (Velsigil error, HTML, empty), falls back too. validate() reports the real error, and
  // without a lease the fallback returns that error. 4xx answers never fall back.
  velsigil::Client degraded = make_client(setup, setup.base_url, "http-test-hwid-0001", store);
  struct Outage {
    const char* key;
    const char* code;
  };
  for (const Outage& outage : {Outage{"VX-500", "internal_error"}, Outage{"VX-503", "network_error"},
                               Outage{"VX-503J", "internal_error"}, Outage{"VX-502", "network_error"},
                               Outage{"VX-504", "network_error"}}) {
    const std::string key = outage.key;
    check_code(degraded.validate(key), outage.code, key + ": validate() reports the outage");
    const auto result = degraded.validate_with_offline_fallback(key);
    check(result.ok && result.offline && result.has_feature("pro"), key + ": offline fallback with the stored lease");
    const auto no_lease = failing.validate_with_offline_fallback(key);
    check(!no_lease.offline, key + " without a lease: no offline result");
    check_code(no_lease, outage.code, key + " without a lease: the original error");
  }
  const auto limited = degraded.validate_with_offline_fallback("VX-429");
  check(!limited.offline, "HTTP 429 never falls back");
  check_code(limited, "rate_limited", "HTTP 429 with a stored lease");
  const auto bad_request = degraded.validate_with_offline_fallback("VX-400");
  check(!bad_request.offline, "HTTP 400 never falls back");
  check_code(bad_request, "validation_error", "HTTP 400 with a stored lease");
  check(store->get(kProduct, velsigil::store_keys::kLease).has_value(), "outages keep the stored lease");

  // Updates.
  const auto update = client.check_update("1.0.0");
  check(update.ok && update.update && update.update->update_available && update.update->latest_version == "1.4.0", "update available");
  check_code(client.check_update("0.0.0"), "no_release", "no release");

  // Download flow: signed descriptor -> streamed file -> size + SHA-256 verified.
  std::error_code ec;
  const fs::path destination = fs::temp_directory_path() / "velsigil-http-test-release.bin";
  fs::remove(destination, ec);
  const auto download = client.get_download("VX-OK", std::string("1.4.0"));
  check(download.ok && download.download.has_value(), "get_download ok");
  if (download.download) {
    const auto saved = client.download_release(*download.download, destination);
    check(saved.ok && saved.code == "ok", "download_release ok: " + saved.message);
    check(saved.bytes == static_cast<std::uint64_t>(download.download->size), "downloaded size");
    check(fs::exists(destination, ec) && fs::file_size(destination, ec) == static_cast<std::uintmax_t>(download.download->size),
          "downloaded file on disk");
    fs::remove(destination, ec);

    velsigil::DownloadInfo missing = *download.download;
    missing.url = setup.base_url + "/files/missing.bin";
    const auto not_found = client.download_release(missing, destination);
    check(!not_found.ok && not_found.code == "download_failed", "download_release reports HTTP errors");
    check(!fs::exists(destination, ec), "no file after a failed download");
  }

  auto tampered_store = std::make_shared<velsigil::MemoryStore>();
  velsigil::Client tampered = make_client(setup, setup.base_url, "http-test-hwid-dlbad", tampered_store);
  check(tampered.validate("VX-DLBAD").ok, "VX-DLBAD activation");
  const auto bad = tampered.get_download("VX-DLBAD");
  check(bad.ok && bad.download.has_value(), "VX-DLBAD descriptor");
  if (bad.download) {
    const auto rejected = tampered.download_release(*bad.download, destination);
    check(!rejected.ok && rejected.code == "integrity_mismatch", "download with a wrong SHA-256 is rejected");
    check(!fs::exists(destination, ec), "rejected download leaves no file");
  }

  // Deactivation releases the device and clears local state.
  const auto deactivated = client.deactivate("VX-OK");
  check(deactivated.ok, "deactivate ok");
  check(!store->get(kProduct, velsigil::store_keys::kDeviceSecret) && !store->get(kProduct, velsigil::store_keys::kLease),
        "deactivate clears local state");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "usage: velsigil_http_tests <mock base URL> <refused URL> <public key>\n";
    return 2;
  }
  try {
    run(Setup{argv[1], argv[2], argv[3]});
  } catch (const std::exception& error) {
    std::cerr << "unexpected exception: " << error.what() << '\n';
    return 2;
  }
  std::cout << g_checks << " checks, " << g_failures << " failures\n";
  return g_failures == 0 ? 0 : 1;
}
