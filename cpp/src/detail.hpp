// Internal helpers shared by the Velsigil SDK translation units. Not part of the public API and not
// installed; the layout of this header may change at any time.
#ifndef VELSIGIL_SRC_DETAIL_HPP
#define VELSIGIL_SRC_DETAIL_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "velsigil/client.hpp"

namespace velsigil::detail {

using Bytes = std::vector<std::uint8_t>;
using PublicKey = std::array<std::uint8_t, 32>;

inline constexpr std::size_t kNonceBytes = 32;  // 32 CSPRNG bytes -> 43 base64url characters

// ---- base64.cpp ---------------------------------------------------------------------------------

/// RFC 4648 section 5 (URL-safe) decoding. Padding is optional; characters outside the URL-safe
/// alphabet, impossible lengths and non-zero trailing bits are rejected.
std::optional<Bytes> base64url_decode(std::string_view input);
/// URL-safe encoding without padding.
std::string base64url_encode(const std::uint8_t* data, std::size_t length);
/// RFC 4648 section 4 (standard alphabet) decoding; surrounding whitespace is ignored and padding is
/// optional. Used for the product public key.
std::optional<Bytes> base64_decode(std::string_view input);

// ---- crypto.cpp (libsodium) ---------------------------------------------------------------------

/// Initialises libsodium exactly once; false when the library cannot be used.
bool crypto_ready() noexcept;
/// Fills `out` from the operating system CSPRNG; false when libsodium is unavailable.
bool random_bytes(std::uint8_t* out, std::size_t length) noexcept;
/// Fresh request nonce: 32 random bytes, base64url without padding (43 characters).
std::optional<std::string> random_nonce();
/// `bytes` random bytes as lowercase hex (temporary file names).
std::optional<std::string> random_hex(std::size_t bytes);
/// Decodes a standard-base64 raw Ed25519 public key (exactly 32 bytes).
std::optional<PublicKey> parse_public_key(std::string_view base64);
/// Ed25519 detached signature check over the exact bytes of `message`.
bool ed25519_verify(const Bytes& signature, std::string_view message, const PublicKey& key) noexcept;
/// Lowercase hex SHA-256.
std::string sha256_hex(std::string_view data);
std::string to_hex(const std::uint8_t* data, std::size_t length);
/// ASCII case-insensitive comparison.
bool equals_ignore_case(std::string_view a, std::string_view b) noexcept;

/// Incremental SHA-256 (download verification).
class Sha256Stream {
 public:
  Sha256Stream();
  ~Sha256Stream();
  Sha256Stream(const Sha256Stream&) = delete;
  Sha256Stream& operator=(const Sha256Stream&) = delete;

  void update(const void* data, std::size_t length) noexcept;
  std::string final_hex();

 private:
  struct State;
  std::unique_ptr<State> state_;
};

// ---- hwid.cpp -----------------------------------------------------------------------------------

/// Trims ASCII whitespace and lowercases ASCII letters (SPEC 10.6).
std::string normalize_machine_id(std::string_view raw);
/// `content` of a Linux machine-id file when it holds a usable id; nullopt when it is empty or systemd's
/// placeholder "uninitialized" (any case), which every Velsigil SDK skips (CLIENT_PROTOCOL 8.1).
std::optional<std::string> usable_machine_id(std::string content);
/// Raw platform machine id: Windows MachineGuid (64-bit registry view), Linux /etc/machine-id or
/// /var/lib/dbus/machine-id, macOS IOPlatformUUID. nullopt when unavailable.
std::optional<std::string> read_machine_id();

// ---- http.cpp (libcurl) -------------------------------------------------------------------------

class CurlTransport final : public ITransport {
 public:
  explicit CurlTransport(std::string user_agent);
  HttpResponse post_json(const std::string& url, const std::string& body, std::chrono::milliseconds timeout) override;

 private:
  std::string user_agent_;
};

struct DownloadOutcome {
  bool transport_ok = false;  // an HTTP status was received
  long status = 0;
  std::string error;       // transport error description
  bool too_large = false;  // more than max_bytes were offered
  bool io_error = false;   // the destination could not be written
  std::uint64_t bytes = 0;
  std::string sha256;  // lowercase hex; only set for a complete 2xx transfer
};

/// Streams `url` into `destination` (created/truncated), hashing on the fly and aborting once more
/// than `max_bytes` arrive. `timeout` bounds connecting and stalls (no progress), not the total time.
DownloadOutcome http_download(const std::string& url, const std::filesystem::path& destination, std::uint64_t max_bytes,
                              std::chrono::milliseconds timeout, const std::string& user_agent);

// ---- client.cpp ---------------------------------------------------------------------------------

/// True for the loopback hosts localhost, 127.0.0.1 and [::1] (ASCII case-insensitive; `host` without a
/// port, an IPv6 literal with its brackets). The one loopback rule of the SDK: url_policy_error allows plain
/// http:// for these hosts, and the Client accepts the published test-vector keys only for them.
bool is_loopback_host(std::string_view host) noexcept;
/// Returns an error message when `url` violates the transport policy: absolute http(s) URL, no
/// credentials or whitespace, and https unless the host is_loopback_host() or `allow_insecure_http` is set.
std::optional<std::string> url_policy_error(std::string_view url, bool allow_insecure_http);
/// True when `url` is an absolute URL (parsed exactly as url_policy_error parses it) whose host
/// is_loopback_host(), whatever its scheme.
bool is_loopback_url(std::string_view url);
/// Current unix time in seconds from the system clock.
std::int64_t system_unix_time() noexcept;

/// velsigil::verify_envelope_typed and velsigil::verify_lease WITHOUT their refusal of the published
/// test-vector keys (test-vectors.json keys.publicKey / keys.wrongPublicKey, whose private seeds are
/// public). The public helpers refuse those keys always (they have no API URL that could name a local test
/// server); these internal entry points exist only so that the SDK's own tests can verify the shared vectors,
/// which are signed with them. Never call them from production code.
EnvelopeVerification verify_envelope_typed_unguarded(std::string_view envelope_json, std::string_view public_key_base64,
                                                     std::string_view expected_nonce, std::string_view expected_product_id,
                                                     std::string_view expected_type, std::string_view expected_hwid) noexcept;
LeaseVerification verify_lease_unguarded(std::string_view token, std::string_view public_key_base64,
                                         std::string_view product_id, std::string_view hwid, std::int64_t now_unix) noexcept;

}  // namespace velsigil::detail

#endif  // VELSIGIL_SRC_DETAIL_HPP
