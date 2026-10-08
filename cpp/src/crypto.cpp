// Cryptographic primitives, all provided by libsodium (no custom cryptography).
#include <sodium.h>

#include <algorithm>
#include <array>

#include "detail.hpp"

namespace velsigil::detail {

static_assert(crypto_sign_PUBLICKEYBYTES == 32, "unexpected Ed25519 public key size");
static_assert(crypto_sign_BYTES == 64, "unexpected Ed25519 signature size");
static_assert(crypto_hash_sha256_BYTES == 32, "unexpected SHA-256 digest size");

bool crypto_ready() noexcept {
  // sodium_init() is thread-safe and idempotent; the function-local static runs it exactly once.
  // It returns 0 on success, 1 when already initialised and -1 on failure.
  static const bool ready = sodium_init() >= 0;
  return ready;
}

bool random_bytes(std::uint8_t* out, std::size_t length) noexcept {
  if (!crypto_ready()) return false;
  if (length > 0) randombytes_buf(out, length);
  return true;
}

std::optional<std::string> random_nonce() {
  std::array<std::uint8_t, kNonceBytes> buffer{};
  if (!random_bytes(buffer.data(), buffer.size())) return std::nullopt;
  return base64url_encode(buffer.data(), buffer.size());
}

std::optional<std::string> random_hex(std::size_t bytes) {
  Bytes buffer(bytes);
  if (!random_bytes(buffer.data(), buffer.size())) return std::nullopt;
  return to_hex(buffer.data(), buffer.size());
}

std::optional<PublicKey> parse_public_key(std::string_view base64) {
  const auto raw = base64_decode(base64);
  if (!raw || raw->size() != crypto_sign_PUBLICKEYBYTES) return std::nullopt;
  PublicKey key{};
  std::copy(raw->begin(), raw->end(), key.begin());
  return key;
}

bool ed25519_verify(const Bytes& signature, std::string_view message, const PublicKey& key) noexcept {
  if (signature.size() != crypto_sign_BYTES) return false;
  if (!crypto_ready()) return false;  // fail closed
  return crypto_sign_verify_detached(signature.data(), reinterpret_cast<const unsigned char*>(message.data()),
                                     static_cast<unsigned long long>(message.size()), key.data()) == 0;
}

std::string sha256_hex(std::string_view data) {
  (void)crypto_ready();
  std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(data.data()),
                     static_cast<unsigned long long>(data.size()));
  return to_hex(digest.data(), digest.size());
}

std::string to_hex(const std::uint8_t* data, std::size_t length) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(length * 2);
  for (std::size_t i = 0; i < length; ++i) {
    out.push_back(kDigits[(data[i] >> 4) & 0x0F]);
    out.push_back(kDigits[data[i] & 0x0F]);
  }
  return out;
}

bool equals_ignore_case(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
    if (x != y) return false;
  }
  return true;
}

struct Sha256Stream::State {
  crypto_hash_sha256_state state;
};

Sha256Stream::Sha256Stream() : state_(std::make_unique<State>()) {
  (void)crypto_ready();
  crypto_hash_sha256_init(&state_->state);
}

Sha256Stream::~Sha256Stream() = default;

void Sha256Stream::update(const void* data, std::size_t length) noexcept {
  crypto_hash_sha256_update(&state_->state, static_cast<const unsigned char*>(data), static_cast<unsigned long long>(length));
}

std::string Sha256Stream::final_hex() {
  std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256_final(&state_->state, digest.data());
  return to_hex(digest.data(), digest.size());
}

}  // namespace velsigil::detail
