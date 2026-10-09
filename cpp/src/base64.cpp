// Base64 helpers: URL-safe for envelopes, signatures and leases; standard for the public key.
#include "detail.hpp"

namespace velsigil::detail {
namespace {

constexpr char kUrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int decode_symbol(char c, bool url_safe) noexcept {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (url_safe) {
    if (c == '-') return 62;
    if (c == '_') return 63;
  } else {
    if (c == '+') return 62;
    if (c == '/') return 63;
  }
  return -1;
}

std::optional<Bytes> decode(std::string_view input, bool url_safe) {
  // At most two '=' and, when present, they must complete a 4-char quantum.
  std::size_t length = input.size();
  std::size_t padding = 0;
  while (length > 0 && padding < 2 && input[length - 1] == '=') {
    --length;
    ++padding;
  }
  if (padding > 0 && (length + padding) % 4 != 0) return std::nullopt;
  if (length % 4 == 1) return std::nullopt;  // a single trailing symbol cannot encode a byte

  Bytes out;
  out.reserve(length / 4 * 3 + 2);
  std::uint32_t accumulator = 0;
  int bits = 0;
  for (std::size_t i = 0; i < length; ++i) {
    const int value = decode_symbol(input[i], url_safe);
    if (value < 0) return std::nullopt;
    accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xFFu));
      accumulator &= (1u << bits) - 1u;
    }
  }
  // Canonical encodings leave the unused low bits of the last symbol at zero.
  if (bits > 0 && accumulator != 0) return std::nullopt;
  return out;
}

bool is_ascii_space(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

}  // namespace

std::optional<Bytes> base64url_decode(std::string_view input) { return decode(input, true); }

std::optional<Bytes> base64_decode(std::string_view input) {
  while (!input.empty() && is_ascii_space(input.front())) input.remove_prefix(1);
  while (!input.empty() && is_ascii_space(input.back())) input.remove_suffix(1);
  return decode(input, false);
}

std::string base64url_encode(const std::uint8_t* data, std::size_t length) {
  std::string out;
  out.reserve((length * 4 + 2) / 3);
  std::size_t i = 0;
  for (; i + 3 <= length; i += 3) {
    const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16) | (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                            static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kUrlAlphabet[(n >> 18) & 63u]);
    out.push_back(kUrlAlphabet[(n >> 12) & 63u]);
    out.push_back(kUrlAlphabet[(n >> 6) & 63u]);
    out.push_back(kUrlAlphabet[n & 63u]);
  }
  const std::size_t remaining = length - i;
  if (remaining == 1) {
    const std::uint32_t n = static_cast<std::uint32_t>(data[i]) << 16;
    out.push_back(kUrlAlphabet[(n >> 18) & 63u]);
    out.push_back(kUrlAlphabet[(n >> 12) & 63u]);
  } else if (remaining == 2) {
    const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16) | (static_cast<std::uint32_t>(data[i + 1]) << 8);
    out.push_back(kUrlAlphabet[(n >> 18) & 63u]);
    out.push_back(kUrlAlphabet[(n >> 12) & 63u]);
    out.push_back(kUrlAlphabet[(n >> 6) & 63u]);
  }
  return out;
}

}  // namespace velsigil::detail
