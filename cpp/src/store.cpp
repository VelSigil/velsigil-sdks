#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#endif

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "detail.hpp"

namespace velsigil {
namespace {

using json = nlohmann::json;

constexpr std::uintmax_t kMaxStoreFileBytes = 1024 * 1024;
constexpr char kStoreFileName[] = "velsigil-license.json";
// Default file name before the rename; only ever read.
constexpr char kLegacyStoreFileName[] = "veltrix-license.json";

#if defined(_WIN32)

std::wstring current_user_sid() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
  std::wstring result;
  DWORD length = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &length);
  if (length > 0) {
    std::vector<unsigned char> buffer(length);
    if (GetTokenInformation(token, TokenUser, buffer.data(), length, &length)) {
      const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
      LPWSTR sid = nullptr;
      if (ConvertSidToStringSidW(user->User.Sid, &sid) && sid != nullptr) {
        result = sid;
        LocalFree(sid);
      }
    }
  }
  CloseHandle(token);
  return result;
}

bool write_file_atomically(const std::filesystem::path& target, const std::filesystem::path& temp, const std::string& content) {
  // Protected DACL: the current user and SYSTEM only, no inherited ACEs.
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = FALSE;
  const std::wstring sid = current_user_sid();
  if (!sid.empty()) {
    const std::wstring sddl = L"D:P(A;;FA;;;" + sid + L")(A;;FA;;;SY)";
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
      attributes.lpSecurityDescriptor = descriptor;
    } else {
      descriptor = nullptr;
    }
  }
  const HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (descriptor != nullptr) LocalFree(descriptor);
  if (file == INVALID_HANDLE_VALUE) return false;

  bool ok = true;
  const char* cursor = content.data();
  std::size_t remaining = content.size();
  while (ok && remaining > 0) {
    const DWORD chunk = remaining > 0x100000 ? 0x100000 : static_cast<DWORD>(remaining);
    DWORD written = 0;
    if (!WriteFile(file, cursor, chunk, &written, nullptr) || written == 0) {
      ok = false;
    } else {
      cursor += written;
      remaining -= written;
    }
  }
  if (ok && !FlushFileBuffers(file)) ok = false;
  CloseHandle(file);
  if (ok && !MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) ok = false;
  if (!ok) DeleteFileW(temp.c_str());
  return ok;
}

#else

bool write_all(int fd, const std::string& content) {
  const char* cursor = content.data();
  std::size_t remaining = content.size();
  while (remaining > 0) {
    const ssize_t written = ::write(fd, cursor, remaining);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (written == 0) return false;
    cursor += written;
    remaining -= static_cast<std::size_t>(written);
  }
  return true;
}

void sync_directory(const std::filesystem::path& directory) {
  const std::string name = directory.empty() ? std::string(".") : directory.string();
  const int fd = ::open(name.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return;
  (void)::fsync(fd);
  (void)::close(fd);
}

bool write_file_atomically(const std::filesystem::path& target, const std::filesystem::path& temp, const std::string& content) {
  // O_EXCL + 0600: a new file only the owner can read and write.
  const int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
  if (fd < 0) return false;
  bool ok = write_all(fd, content) && ::fsync(fd) == 0;
  if (::close(fd) != 0) ok = false;
  if (ok && ::rename(temp.c_str(), target.c_str()) != 0) ok = false;
  if (!ok) {
    (void)::unlink(temp.c_str());
    return false;
  }
  sync_directory(target.parent_path());
  return true;
}

#endif

bool ensure_parent_directory(const std::filesystem::path& target) {
  const std::filesystem::path parent = target.parent_path();
  if (parent.empty()) return true;
  std::error_code ec;
  if (std::filesystem::is_directory(parent, ec)) return true;
  std::filesystem::create_directories(parent, ec);
  if (ec) return false;
#if !defined(_WIN32)
  // A directory we created ourselves holds nothing but this store: keep it private (0700).
  std::filesystem::permissions(parent, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
#endif
  return true;
}

bool save_document(const std::filesystem::path& target, const json& document) {
  if (target.empty() || !ensure_parent_directory(target)) return false;
  const auto suffix = detail::random_hex(8);
  if (!suffix) return false;
  std::filesystem::path temp = target;
  temp += ".tmp-" + *suffix;
  return write_file_atomically(target, temp, document.dump(2, ' ', false, json::error_handler_t::replace));
}

// Missing, oversized or corrupt files read as empty; an unreadable file sets `readable` to false.
json load_document(const std::filesystem::path& path, bool& readable) {
  readable = true;
  std::error_code ec;
  const bool present = std::filesystem::exists(path, ec);
  if (ec) {
    readable = false;
    return json::object();
  }
  if (!present) return json::object();
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    readable = false;
    return json::object();
  }
  if (size > kMaxStoreFileBytes) return json::object();
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) {
    readable = false;
    return json::object();
  }
  std::string text(static_cast<std::size_t>(size), '\0');
  in.read(text.data(), static_cast<std::streamsize>(text.size()));
  if (in.bad()) {
    readable = false;
    return json::object();
  }
  text.resize(static_cast<std::size_t>(in.gcount()));
  json document = json::parse(text, nullptr, false);
  if (document.is_discarded() || !document.is_object()) return json::object();
  return document;
}

// Reads the legacy file while `path` does not exist; the first write migrates the data.
json load_document_or_legacy(const std::filesystem::path& path, const std::filesystem::path& legacy_path, bool& readable) {
  if (!legacy_path.empty()) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) && !ec) return load_document(legacy_path, readable);
  }
  return load_document(path, readable);
}

bool is_valid_app_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 64 || name == "." || name == "..") return false;
  for (const char c : name) {
    const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
                         c == '_' || c == '-' || c == ' ';
    if (!allowed) return false;
  }
  return name.front() != ' ' && name.back() != ' ' && name.back() != '.';
}

}  // namespace

std::optional<std::string> MemoryStore::get(const std::string& product_id, const std::string& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto product = values_.find(product_id);
  if (product == values_.end()) return std::nullopt;
  const auto value = product->second.find(key);
  if (value == product->second.end()) return std::nullopt;
  return value->second;
}

bool MemoryStore::set(const std::string& product_id, const std::string& key, const std::string& value) {
  std::lock_guard<std::mutex> lock(mutex_);
  values_[product_id][key] = value;
  return true;
}

bool MemoryStore::erase(const std::string& product_id, const std::string& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto product = values_.find(product_id);
  if (product == values_.end()) return true;
  product->second.erase(key);
  if (product->second.empty()) values_.erase(product);
  return true;
}

// Layout: { "version": 1, "products": { "<productId>": { "deviceSecret": "...", "lease": "..." } } }

FileStore::FileStore(std::filesystem::path path) : path_(std::move(path)) {
  // Only the default file name migrates from the legacy file next to it.
  try {
    if (path_.filename() == std::filesystem::path(kStoreFileName)) {
      legacy_path_ = path_.parent_path() / kLegacyStoreFileName;
    }
  } catch (...) {
    legacy_path_.clear();  // no fallback rather than a throwing constructor
  }
}

std::filesystem::path FileStore::default_path(std::string_view app_name) {
  try {
    if (!is_valid_app_name(app_name)) return {};
    std::filesystem::path base;
#if defined(_WIN32)
    const DWORD needed = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (needed == 0 || needed > 32767) return {};
    std::wstring value(needed, L'\0');
    const DWORD written = GetEnvironmentVariableW(L"LOCALAPPDATA", &value[0], needed);
    if (written == 0 || written >= needed) return {};
    value.resize(written);
    base = std::filesystem::path(value);
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] != '/') return {};
    base = std::filesystem::path(home) / "Library" / "Application Support";
#else
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg != nullptr && xdg[0] == '/') {
      base = std::filesystem::path(xdg);
    } else {
      const char* home = std::getenv("HOME");
      if (home == nullptr || home[0] != '/') return {};
      base = std::filesystem::path(home) / ".local" / "share";
    }
#endif
    return base / std::filesystem::path(std::string(app_name)) / kStoreFileName;
  } catch (...) {
    return {};
  }
}

std::optional<std::string> FileStore::get(const std::string& product_id, const std::string& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  bool readable = true;
  json document;
  try {
    document = load_document_or_legacy(path_, legacy_path_, readable);
  } catch (...) {
    readable = false;
  }
  // Never report an unreadable file as "nothing stored"; the Client fails closed.
  if (!readable) throw std::runtime_error("the license store file cannot be read");
  try {
    const auto products = document.find("products");
    if (products == document.end() || !products->is_object()) return std::nullopt;
    const auto entry = products->find(product_id);
    if (entry == products->end() || !entry->is_object()) return std::nullopt;
    const auto value = entry->find(key);
    if (value == entry->end() || !value->is_string()) return std::nullopt;
    return value->get<std::string>();
  } catch (...) {
    return std::nullopt;
  }
}

bool FileStore::set(const std::string& product_id, const std::string& key, const std::string& value) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    bool readable = true;
    json document = load_document_or_legacy(path_, legacy_path_, readable);
    // An unreadable file is never rebuilt from nothing: that would erase every product's device secret.
    if (!readable) return false;
    json& products = document["products"];
    if (!products.is_object()) products = json::object();
    json& entry = products[product_id];
    if (!entry.is_object()) entry = json::object();
    entry[key] = value;
    document["version"] = 1;
    return save_document(path_, document);
  } catch (...) {
    return false;
  }
}

bool FileStore::erase(const std::string& product_id, const std::string& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    bool readable = true;
    json document = load_document_or_legacy(path_, legacy_path_, readable);
    if (!readable) return false;
    const auto products = document.find("products");
    if (products == document.end() || !products->is_object()) return true;
    const auto entry = products->find(product_id);
    if (entry == products->end() || !entry->is_object() || !entry->contains(key)) return true;
    entry->erase(key);
    if (entry->empty()) products->erase(entry);
    document["version"] = 1;
    return save_document(path_, document);
  } catch (...) {
    return false;
  }
}

}  // namespace velsigil
