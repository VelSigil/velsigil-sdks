// Velsigil C++ SDK example: validate a license (with offline fallback), gate a feature, check for
// updates and download + verify a release.
//
// Replace the placeholders kApiUrl, kProductId and kPublicKey below with your product's values, build with
// -DVX_BUILD_EXAMPLES=ON, then run `velsigil_example_basic`. While a placeholder is still in place it prints a
// short usage message and exits with code 2. The license key is read from standard input and never printed or
// logged.
//
// Local testing only: the three values can be given on the command line instead, and ONLY when the API URL given
// there is a loopback URL (http(s)://localhost, 127.0.0.1 or [::1], such as the bundled mock server; see
// tests/mock_server/README.md):
//   velsigil_example_basic http://127.0.0.1:8787 [<product id> <public key>]
// An override with any other URL is refused (exit code 2): a shipped application takes its server, product id and
// public key from its own binary, never from outside it.
#include <velsigil/client.hpp>

#include <cctype>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

namespace {

// Replace these placeholders with the values from your product's "Integration" tab in the Velsigil panel
// (Products > your product > Integration). Keep them compiled into the binary, above all the public key: it is
// the trust anchor that makes forged server responses detectable (never load it from a file, environment
// variable or the network).
constexpr char kApiUrl[] = "<your Velsigil server URL, e.g. https://licenses.example.com>";
constexpr char kProductId[] = "<your product id>";
constexpr char kPublicKey[] = "<your product's public key>";
constexpr char kAppVersion[] = "1.2.0";

constexpr char kUsage[] =
    "usage: velsigil_example_basic\n"
    "       velsigil_example_basic <loopback API URL> [<product id> <public key>]   (local testing only)\n"
    "Set kApiUrl, kProductId and kPublicKey in examples/basic.cpp to your product's values from the Velsigil\n"
    "panel (Products > your product > Integration), then rebuild. Values on the command line are accepted only\n"
    "with an API URL on localhost, 127.0.0.1 or [::1].\n";

// The hosts of a server on this machine (the SDK accepts plain http:// only for them).
constexpr std::string_view kLoopbackHosts[] = {"localhost", "127.0.0.1", "[::1]"};

// A value that still holds its "<...>" placeholder.
bool is_placeholder(std::string_view value) { return value.empty() || value.front() == '<'; }

// True for an http(s) URL whose host is localhost, 127.0.0.1 or [::1] (any port and path).
bool is_loopback_url(std::string_view url) {
  std::string lower(url);
  for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  std::string_view rest(lower);
  if (rest.substr(0, 7) == "http://") {
    rest.remove_prefix(7);
  } else if (rest.substr(0, 8) == "https://") {
    rest.remove_prefix(8);
  } else {
    return false;
  }
  const std::string_view authority = rest.substr(0, rest.find_first_of("/?#"));
  // User info names no host: in "http://localhost:80@evil.example" the host is evil.example.
  if (authority.find('@') != std::string_view::npos) return false;
  for (const std::string_view host : kLoopbackHosts) {
    if (authority == host || (authority.size() > host.size() && authority.substr(0, host.size()) == host &&
                              authority[host.size()] == ':')) {
      return true;
    }
  }
  return false;
}

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
  // The server's Retry-After (HTTP 429 or 503; also on an offline fallback result): when to try online again.
  if (result.retry_after) std::cout << "retry after: " << *result.retry_after << " s\n";
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
  std::string api_url = kApiUrl;
  std::string product_id = kProductId;
  std::string public_key = kPublicKey;
  if (argc == 2 || argc == 4) {
    // Local testing only: values from the command line are accepted ONLY with a loopback API URL (a server on
    // this machine, such as the bundled mock server), never for a remote server.
    if (!is_loopback_url(argv[1])) {
      std::cerr << "Values on the command line are for local testing only: the API URL must be on localhost, "
                   "127.0.0.1 or [::1].\n"
                << kUsage;
      return 2;
    }
    api_url = argv[1];
    if (argc == 4) {
      product_id = argv[2];
      public_key = argv[3];
    }
  } else if (argc != 1) {
    std::cerr << kUsage;
    return 2;
  }
  if (is_placeholder(api_url) || is_placeholder(product_id) || is_placeholder(public_key)) {
    std::cerr << kUsage;
    return 2;
  }

  // Persist the device secret and offline lease between runs (owner-only file, atomic writes).
  velsigil::ClientOptions options;
  std::filesystem::path store_path = velsigil::FileStore::default_path("Velsigil Example");
  if (store_path.empty()) store_path = "velsigil-license.json";
  options.store = std::make_shared<velsigil::FileStore>(store_path);

  velsigil::Client client(api_url, product_id, public_key, options);
  if (!client.is_configured()) {
    std::cerr << "configuration error: " << client.configuration_error() << '\n' << kUsage;
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
