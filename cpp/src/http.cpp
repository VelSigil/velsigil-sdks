// libcurl transport: TLS verification on, no redirects, http/https only, size-capped bodies.
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <curl/curl.h>

#include <fstream>
#include <limits>
#include <mutex>
#include <utility>

#include "detail.hpp"

namespace velsigil::detail {
namespace {

constexpr std::size_t kMaxResponseBytes = 1024 * 1024;  // client API responses are a few KB

bool ensure_curl_global_init() {
  // curl_global_init() is not thread-safe on older libcurl: run it once, never clean up.
  static std::once_flag once;
  static CURLcode result = CURLE_FAILED_INIT;
  std::call_once(once, [] { result = curl_global_init(CURL_GLOBAL_DEFAULT); });
  return result == CURLE_OK;
}

struct EasyDeleter {
  void operator()(CURL* handle) const noexcept {
    if (handle != nullptr) curl_easy_cleanup(handle);
  }
};
using EasyHandle = std::unique_ptr<CURL, EasyDeleter>;

struct SlistDeleter {
  void operator()(curl_slist* list) const noexcept {
    if (list != nullptr) curl_slist_free_all(list);
  }
};
using HeaderList = std::unique_ptr<curl_slist, SlistDeleter>;

long to_curl_millis(std::chrono::milliseconds timeout) noexcept {
  const long long count = static_cast<long long>(timeout.count());
  if (count <= 0) return 1;
  const long long max_long = static_cast<long long>((std::numeric_limits<long>::max)());
  return static_cast<long>(count > max_long ? max_long : count);
}

bool restrict_protocols(CURL* handle) {
#if LIBCURL_VERSION_NUM >= 0x075500  // 7.85.0
  return curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "http,https") == CURLE_OK;
#else
  return curl_easy_setopt(handle, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS)) == CURLE_OK;
#endif
}

// Any option that fails to apply aborts the request (fail closed).
bool configure_common(CURL* handle, const std::string& url, long connect_timeout_ms, const std::string& user_agent) {
  return curl_easy_setopt(handle, CURLOPT_URL, url.c_str()) == CURLE_OK && restrict_protocols(handle) &&
         curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L) == CURLE_OK &&
         curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK &&
         curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK &&
         curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L) == CURLE_OK &&
         curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms) == CURLE_OK &&
         curl_easy_setopt(handle, CURLOPT_USERAGENT, user_agent.c_str()) == CURLE_OK;
}

std::string describe_failure(CURLcode code) {
  if (code == CURLE_OPERATION_TIMEDOUT) return "the request timed out";
  const char* text = curl_easy_strerror(code);
  return text != nullptr ? std::string(text) : std::string("transport error");
}

struct BodySink {
  std::string data;
  bool overflow = false;
};

// Must not let exceptions escape into C code.
std::size_t write_body(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
  auto* sink = static_cast<BodySink*>(userdata);
  if (size != 0 && nmemb > (std::numeric_limits<std::size_t>::max)() / size) return 0;
  const std::size_t length = size * nmemb;
  if (length > kMaxResponseBytes - sink->data.size()) {
    sink->overflow = true;
    return 0;
  }
  try {
    sink->data.append(ptr, length);
  } catch (...) {
    return 0;
  }
  return length;
}

// Valid Retry-After values are at most 33 characters.
constexpr std::size_t kMaxRetryAfterBytes = 128;

// Keeps the final response's Retry-After: each status line (CONNECT, 100 Continue) starts over.
// Must not let exceptions escape into C code.
std::size_t read_header(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
  auto* retry_after = static_cast<std::optional<std::string>*>(userdata);
  if (size != 0 && nitems > (std::numeric_limits<std::size_t>::max)() / size) return 0;
  const std::size_t length = size * nitems;
  const std::string_view line(buffer, length);
  if (line.compare(0, 5, "HTTP/") == 0) {
    retry_after->reset();
    return length;
  }
  const std::size_t colon = line.find(':');
  if (colon == std::string_view::npos || !equals_ignore_case(line.substr(0, colon), "Retry-After")) return length;
  std::string_view value = line.substr(colon + 1);
  auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  while (!value.empty() && is_space(value.front())) value.remove_prefix(1);
  while (!value.empty() && is_space(value.back())) value.remove_suffix(1);
  try {
    // An over-long value is stored empty, so it parses as no retry_after.
    *retry_after = value.size() <= kMaxRetryAfterBytes ? std::string(value) : std::string();
  } catch (...) {
    retry_after->reset();
  }
  return length;
}

struct FileSink {
  std::ofstream* out = nullptr;
  Sha256Stream* hash = nullptr;
  std::uint64_t bytes = 0;
  std::uint64_t max_bytes = 0;
  bool too_large = false;
  bool io_error = false;
};

std::size_t write_file(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
  auto* sink = static_cast<FileSink*>(userdata);
  if (size != 0 && nmemb > (std::numeric_limits<std::size_t>::max)() / size) return 0;
  const std::size_t length = size * nmemb;
  if (static_cast<std::uint64_t>(length) > sink->max_bytes - sink->bytes) {
    sink->too_large = true;
    return 0;
  }
  try {
    sink->out->write(ptr, static_cast<std::streamsize>(length));
    if (!*sink->out) {
      sink->io_error = true;
      return 0;
    }
  } catch (...) {
    sink->io_error = true;
    return 0;
  }
  sink->hash->update(ptr, length);
  sink->bytes += length;
  return length;
}

}  // namespace

CurlTransport::CurlTransport(std::string user_agent) : user_agent_(std::move(user_agent)) {}

HttpResponse CurlTransport::post_json(const std::string& url, const std::string& body, std::chrono::milliseconds timeout) {
  HttpResponse response;
  if (!ensure_curl_global_init()) {
    response.error = "the HTTP library could not be initialised";
    return response;
  }
  EasyHandle handle(curl_easy_init());
  if (!handle) {
    response.error = "the HTTP library could not be initialised";
    return response;
  }

  static const char* const kHeaders[] = {"Content-Type: application/json", "Accept: application/json"};
  curl_slist* raw_headers = nullptr;
  for (const char* header : kHeaders) {
    curl_slist* next = curl_slist_append(raw_headers, header);
    if (next == nullptr) {
      curl_slist_free_all(raw_headers);
      response.error = "out of memory";
      return response;
    }
    raw_headers = next;
  }
  HeaderList headers(raw_headers);

  BodySink sink;
  std::optional<std::string> retry_after;
  const long timeout_ms = to_curl_millis(timeout);
  CURL* h = handle.get();
  const bool configured = configure_common(h, url, timeout_ms, user_agent_) &&
                          curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, timeout_ms) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_POST, 1L) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_POSTFIELDS, body.c_str()) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size())) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers.get()) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, &write_body) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_WRITEDATA, static_cast<void*>(&sink)) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, &read_header) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_HEADERDATA, static_cast<void*>(&retry_after)) == CURLE_OK;
  if (!configured) {
    response.error = "the HTTP request could not be configured";
    return response;
  }

  const CURLcode code = curl_easy_perform(h);
  long status = 0;
  if (curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) status = 0;

  if (code != CURLE_OK) {
    if (sink.overflow && status != 0) {
      // Drop an oversized body (rejected later as invalid) but keep its Retry-After.
      response.transport_ok = true;
      response.status = status;
      response.retry_after = std::move(retry_after);
      return response;
    }
    response.error = describe_failure(code);
    return response;
  }
  response.transport_ok = true;
  response.status = status;
  response.body = std::move(sink.data);
  response.retry_after = std::move(retry_after);
  return response;
}

DownloadOutcome http_download(const std::string& url, const std::filesystem::path& destination, std::uint64_t max_bytes,
                              std::chrono::milliseconds timeout, const std::string& user_agent) {
  DownloadOutcome outcome;
  if (!ensure_curl_global_init()) {
    outcome.error = "the HTTP library could not be initialised";
    return outcome;
  }
  EasyHandle handle(curl_easy_init());
  if (!handle) {
    outcome.error = "the HTTP library could not be initialised";
    return outcome;
  }

  std::ofstream out(destination, std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    outcome.io_error = true;
    outcome.error = "the destination file could not be created";
    return outcome;
  }

  Sha256Stream hash;
  FileSink sink;
  sink.out = &out;
  sink.hash = &hash;
  sink.max_bytes = max_bytes;

  const long timeout_ms = to_curl_millis(timeout);
  const long stall_seconds = timeout_ms / 1000 > 0 ? timeout_ms / 1000 : 1L;
  CURL* h = handle.get();
  const bool configured = configure_common(h, url, timeout_ms, user_agent) &&
                          curl_easy_setopt(h, CURLOPT_HTTPGET, 1L) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_FAILONERROR, 1L) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 1L) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME, stall_seconds) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, &write_file) == CURLE_OK &&
                          curl_easy_setopt(h, CURLOPT_WRITEDATA, static_cast<void*>(&sink)) == CURLE_OK;
  if (!configured) {
    outcome.error = "the HTTP request could not be configured";
    return outcome;
  }

  const CURLcode code = curl_easy_perform(h);
  long status = 0;
  if (curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) status = 0;

  out.close();
  outcome.bytes = sink.bytes;
  outcome.too_large = sink.too_large;
  outcome.io_error = sink.io_error || out.fail();

  if (code == CURLE_OK || code == CURLE_HTTP_RETURNED_ERROR || ((sink.too_large || sink.io_error) && status != 0)) {
    outcome.transport_ok = true;
    outcome.status = status;
    if (code == CURLE_OK && !outcome.too_large && !outcome.io_error) outcome.sha256 = hash.final_hex();
    return outcome;
  }
  outcome.error = describe_failure(code);
  return outcome;
}

}  // namespace velsigil::detail
