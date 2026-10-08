// Velsigil C++ SDK example: validate a license (with offline fallback), gate a feature, check for
// updates and download + verify a release.
//
// Build with -DVX_BUILD_EXAMPLES=ON, then run:
//   velsigil_example_basic                          (uses the values below)
//   velsigil_example_basic http://localhost:3000    (override the server URL, e.g. a local dev server)
// The license key is read from standard input and never printed or logged.
#include <velsigil/client.hpp>

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

namespace {

// Replace these with the values from the product's "Integration" tab in the Velsigil panel. The
// defaults are the shared test-vector product, so the example also runs against the bundled mock
// server (tests/mock_server/mock_server.py, license key VX-OK). Keep the public key compiled into
// the binary: it is the trust anchor that makes forged server responses detectable.
constexpr char kApiUrl[] = "https://licenses.example.com";
constexpr char kProductId[] = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b";
constexpr char kPublicKey[] = "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=";
constexpr char kAppVersion[] = "1.2.0";

// Defense in depth: never let a server-provided name choose a directory.
std::string safe_file_name(const std::string& name) {
  std::string out;
  for (const char c : name) {
    const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
    out.push_back(allowed ? c : '_');
  }
  if (out.empty() || out.find_first_not_of('.') == std::string::npos) out = "velsigil-update.bin";
  return out;
}

void print_result(const velsigil::ValidationResult& result) {
  std::cout << "ok=" << (result.ok ? "true" : "false") << " code=" << result.code << (result.offline ? " (offline)" : "") << '\n'
            << "message: " << result.message << '\n';
  if (result.request_id) std::cout << "request id: " << *result.request_id << '\n';
  if (result.license) {
    std::cout << "plan: " << result.license->plan << ", status: " << result.license->status << '\n';
    if (result.is_lifetime()) {
      std::cout << "expires: never\n";
    } else if (const auto days = result.days_until_expiry()) {
      std::cout << "expires in " << *days << " day(s)\n";
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  const std::string api_url = argc > 1 ? std::string(argv[1]) : std::string(kApiUrl);

  // Persist the device secret and offline lease between runs (owner-only file, atomic writes).
  velsigil::ClientOptions options;
  std::filesystem::path store_path = velsigil::FileStore::default_path("Velsigil Example");
  if (store_path.empty()) store_path = "velsigil-license.json";
  options.store = std::make_shared<velsigil::FileStore>(store_path);

  velsigil::Client client(api_url, kProductId, kPublicKey, options);
  if (!client.is_configured()) {
    std::cerr << "configuration error: " << client.configuration_error() << '\n';
    return 2;
  }

  std::cout << "License key: " << std::flush;
  std::string license_key;
  if (!std::getline(std::cin, license_key) || license_key.empty()) {
    std::cerr << "no license key entered\n";
    return 2;
  }

  velsigil::ValidateOptions validate_options;
  validate_options.version = kAppVersion;
  const velsigil::ValidationResult result = client.validate_with_offline_fallback(license_key, validate_options);
  print_result(result);
  if (!result.ok) {
    // Business failures (expired, revoked, device limit, ...) and transport problems all end up
    // here; never treat anything but ok == true as licensed.
    return 1;
  }

  std::cout << "export feature: " << (result.has_feature("export") ? "enabled" : "disabled") << '\n';

  if (result.offline) return 0;  // no update checks without a connection

  const velsigil::ValidationResult update = client.check_update(kAppVersion);
  if (update.ok && update.update && update.update->update_available) {
    std::cout << "update available: " << update.update->latest_version << (update.update->mandatory ? " (mandatory)" : "") << '\n'
              << update.update->changelog << '\n';

    const velsigil::ValidationResult download = client.get_download(license_key, update.update->latest_version);
    if (download.ok && download.download) {
      const std::filesystem::path target = std::filesystem::temp_directory_path() / safe_file_name(download.download->file_name);
      const velsigil::DownloadFileResult saved = client.download_release(*download.download, target);
      if (saved.ok) {
        std::cout << "downloaded and verified " << saved.bytes << " bytes to " << target.string() << '\n';
      } else {
        std::cout << "download failed: " << saved.code << " - " << saved.message << '\n';
      }
    } else {
      std::cout << "download unavailable: " << download.code << '\n';
    }
  } else if (update.ok || update.code == velsigil::codes::kNoRelease) {
    std::cout << "no update available\n";
  }
  return 0;
}
