// Internal helpers shared by the SDK sources; not installed.
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

inline constexpr std::size_t kNonceBytes = 32;  // 43 base64url characters

/// URL-safe decoding; rejects bad characters, impossible lengths and non-zero trailing bits.
std::optional<Bytes> base64url_decode(std::string_view input);
/// URL-safe encoding without padding.
std::string base64url_encode(const std::uint8_t* data, std::size_t length);
/// Standard-alphabet decoding; surrounding whitespace is ignored.
std::optional<Bytes> base64_decode(std::string_view input);

/// Initialises libsodium exactly once; false when the library cannot be used.
bool crypto_ready() noexcept;
/// Fills `out` from the operating system CSPRNG; false when libsodium is unavailable.
bool random_bytes(std::uint8_t* out, std::size_t length) noexcept;
/// 32 random bytes, base64url without padding.
std::optional<std::string> random_nonce();
/// Random lowercase hex (temporary file names).
std::optional<std::string> random_hex(std::size_t bytes);
/// Decodes a standard-base64 raw Ed25519 public key (exactly 32 bytes).
std::optional<PublicKey> parse_public_key(std::string_view base64);
/// Ed25519 detached signature check over the exact bytes of `message`.
bool ed25519_verify(const Bytes& signature, std::string_view message, const PublicKey& key) noexcept;
std::string sha256_hex(std::string_view data);
std::string to_hex(const std::uint8_t* data, std::size_t length);
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

/// Trims ASCII whitespace and lowercases ASCII letters.
std::string normalize_machine_id(std::string_view raw);
/// Linux machine-id content, or nullopt when empty or systemd's "uninitialized" placeholder.
std::optional<std::string> usable_machine_id(std::string content);
/// Raw platform machine id (MachineGuid, machine-id or IOPlatformUUID); nullopt when unavailable.
std::optional<std::string> read_machine_id();

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
  std::string error;
  bool too_large = false;  // more than max_bytes were offered
  bool io_error = false;   // the destination could not be written
  std::uint64_t bytes = 0;
  std::string sha256;  // lowercase hex; only set for a complete 2xx transfer
};

/// Streams `url` into `destination`, hashing on the fly and aborting past `max_bytes`.
/// `timeout` bounds connecting and stalls, not the total time.
DownloadOutcome http_download(const std::string& url, const std::filesystem::path& destination, std::uint64_t max_bytes,
                              std::chrono::milliseconds timeout, const std::string& user_agent);

/// True for localhost, 127.0.0.1 and [::1] (host without port; IPv6 with brackets).
bool is_loopback_host(std::string_view host) noexcept;
/// Error message when `url` breaks the transport policy (https unless loopback or allow_insecure_http).
std::optional<std::string> url_policy_error(std::string_view url, bool allow_insecure_http);
/// True when `url` is an absolute URL with a loopback host, whatever its scheme.
bool is_loopback_url(std::string_view url);
std::int64_t system_unix_time() noexcept;
/// Seconds to wait from a Retry-After value (delta-seconds or HTTP-date), clamped to 0..86400.
std::optional<std::int64_t> parse_retry_after(std::string_view value, std::int64_t now_unix) noexcept;

/// The public verifiers without the test-vector key refusal, for the SDK's own tests only.
EnvelopeVerification verify_envelope_typed_unguarded(std::string_view envelope_json, std::string_view public_key_base64,
                                                     std::string_view expected_nonce, std::string_view expected_product_id,
                                                     std::string_view expected_type, std::string_view expected_hwid) noexcept;
LeaseVerification verify_lease_unguarded(std::string_view token, std::string_view public_key_base64,
                                         std::string_view product_id, std::string_view hwid, std::int64_t now_unix) noexcept;

}  // namespace velsigil::detail

#endif  // VELSIGIL_SRC_DETAIL_HPP
