// Machine id discovery for the hardware id (SPEC 10.6). The resulting hwid is a stable,
// non-reversible identifier; it is spoofable and therefore never treated as a security boundary
// (the server-issued device secret and server-side checks are).
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winreg.h>
#elif defined(__APPLE__)
#include <stdio.h>
#else
#include <fstream>
#endif

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "detail.hpp"

#if defined(_WIN32)
#ifndef RRF_SUBKEY_WOW6464KEY
#define RRF_SUBKEY_WOW6464KEY 0x00010000
#endif
#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif
#endif

namespace velsigil::detail {
namespace {

bool is_ascii_space(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

#if defined(_WIN32)

constexpr wchar_t kCryptographyKey[] = L"SOFTWARE\\Microsoft\\Cryptography";
constexpr wchar_t kMachineGuidValue[] = L"MachineGuid";
constexpr DWORD kMaxValueBytes = 1024;

std::string wide_to_utf8(const wchar_t* text, std::size_t length) {
  if (length == 0 || length > static_cast<std::size_t>(kMaxValueBytes)) return {};
  const int wide_length = static_cast<int>(length);
  const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, wide_length, nullptr, 0, nullptr, nullptr);
  if (needed <= 0) return {};
  std::string out(static_cast<std::size_t>(needed), '\0');
  const int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, wide_length, &out[0], needed, nullptr, nullptr);
  if (written != needed) return {};
  return out;
}

// Reads a REG_SZ value; `key` is either HKEY_LOCAL_MACHINE with `subkey`, or an open key with nullptr.
std::optional<std::string> read_reg_sz(HKEY key, const wchar_t* subkey, DWORD extra_flags) {
  const DWORD flags = RRF_RT_REG_SZ | extra_flags;
  DWORD size = 0;
  LONG status = RegGetValueW(key, subkey, kMachineGuidValue, flags, nullptr, nullptr, &size);
  if (status != ERROR_SUCCESS || size == 0 || size > kMaxValueBytes) return std::nullopt;

  std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
  DWORD buffer_bytes = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
  status = RegGetValueW(key, subkey, kMachineGuidValue, flags, nullptr, buffer.data(), &buffer_bytes);
  if (status != ERROR_SUCCESS) return std::nullopt;

  std::size_t chars = buffer_bytes / sizeof(wchar_t);
  if (chars > buffer.size()) chars = buffer.size();
  while (chars > 0 && buffer[chars - 1] == L'\0') --chars;  // RegGetValueW includes the terminator
  std::string value = wide_to_utf8(buffer.data(), chars);
  if (value.empty()) return std::nullopt;
  return value;
}

std::optional<std::string> read_windows_machine_guid() {
  // Always read the 64-bit registry view so 32-bit and 64-bit builds derive the same hwid.
  if (auto value = read_reg_sz(HKEY_LOCAL_MACHINE, kCryptographyKey, RRF_SUBKEY_WOW6464KEY)) return value;

  // Fallback for systems whose RegGetValueW does not understand RRF_SUBKEY_WOW6464KEY.
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCryptographyKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
    return std::nullopt;
  }
  std::optional<std::string> value = read_reg_sz(key, nullptr, 0);
  RegCloseKey(key);
  return value;
}

#elif defined(__APPLE__)

std::optional<std::string> read_macos_platform_uuid() {
  // Fixed command with an absolute path: no user input ever reaches the shell.
  FILE* pipe = ::popen("/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice", "r");
  if (pipe == nullptr) return std::nullopt;
  std::string output;
  char chunk[4096];
  std::size_t read = 0;
  while ((read = ::fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
    if (output.size() + read > 1024 * 1024) break;
    output.append(chunk, read);
  }
  ::pclose(pipe);

  // Line format:   "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
  const std::size_t key = output.find("\"IOPlatformUUID\"");
  if (key == std::string::npos) return std::nullopt;
  const std::size_t equals = output.find('=', key);
  if (equals == std::string::npos) return std::nullopt;
  const std::size_t open = output.find('"', equals);
  if (open == std::string::npos) return std::nullopt;
  const std::size_t close = output.find('"', open + 1);
  if (close == std::string::npos || close <= open + 1) return std::nullopt;
  const std::size_t line_end = output.find('\n', equals);
  if (line_end != std::string::npos && close > line_end) return std::nullopt;
  return output.substr(open + 1, close - open - 1);
}

#else

std::optional<std::string> read_small_file(const char* path) {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) return std::nullopt;
  std::string content(256, '\0');
  in.read(&content[0], static_cast<std::streamsize>(content.size()));
  content.resize(static_cast<std::size_t>(in.gcount()));
  return usable_machine_id(std::move(content));
}

#endif

}  // namespace

std::string normalize_machine_id(std::string_view raw) {
  while (!raw.empty() && is_ascii_space(raw.front())) raw.remove_prefix(1);
  while (!raw.empty() && is_ascii_space(raw.back())) raw.remove_suffix(1);
  std::string out(raw);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::optional<std::string> usable_machine_id(std::string content) {
  // systemd writes "uninitialized" before the first boot commits an id, and images systemd never booted keep it,
  // so every copy would share one hwid: it is not a machine id.
  const std::string normalized = normalize_machine_id(content);
  if (normalized.empty() || normalized == "uninitialized") return std::nullopt;
  return content;
}

std::optional<std::string> read_machine_id() {
#if defined(_WIN32)
  return read_windows_machine_guid();
#elif defined(__APPLE__)
  return read_macos_platform_uuid();
#else
  if (auto id = read_small_file("/etc/machine-id")) return id;
  return read_small_file("/var/lib/dbus/machine-id");
#endif
}

}  // namespace velsigil::detail
