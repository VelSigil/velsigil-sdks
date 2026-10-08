// Conformance with the shared protocol vectors (sdks/test-vectors.json, SPEC 10.7). The vectors are signed
// with keys.publicKey / keys.wrongPublicKey, whose private seeds are published, so the public low-level
// helpers refuse those keys (run_published_key_refusal checks that). The envelope and lease vectors are
// therefore verified through the internal entry points of src/detail.hpp, which run the same verification
// without that refusal; everything else uses the public API. Exit code 0 = all checks passed.
#include <velsigil/client.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "detail.hpp"

#ifndef VX_TEST_VECTORS_PATH
#error "VX_TEST_VECTORS_PATH must point to sdks/test-vectors.json"
#endif

// SDK-1: verify_envelope_typed compiles with exactly its six arguments. A call that leaves one out must
// not compile (no overloads, no default arguments): it could otherwise bind to a deprecated verify_envelope
// overload that does not check the type, with the intended type taken as the hwid. (Declarations only,
// used in unevaluated contexts.)
namespace sdk1_compile_checks {
template <typename... Args>
auto accepts_typed_call(int)
    -> decltype((void)velsigil::verify_envelope_typed(std::declval<Args>()...), std::true_type{});
template <typename... Args>
std::false_type accepts_typed_call(...);
template <typename... Args>
constexpr bool kAcceptsTypedCall = decltype(accepts_typed_call<Args...>(0))::value;

using Sv = std::string_view;
static_assert(kAcceptsTypedCall<Sv, Sv, Sv, Sv, Sv, Sv>, "verify_envelope_typed takes six arguments");
static_assert(!kAcceptsTypedCall<Sv, Sv, Sv, Sv, Sv>, "verify_envelope_typed must not compile with five arguments");
static_assert(!kAcceptsTypedCall<Sv, Sv, Sv, Sv>, "verify_envelope_typed must not compile with four arguments");

// S8: without VELSIGIL_ALLOW_UNTYPED_ENVELOPE the type-less verify_envelope overloads are deleted: no call
// compiles, whatever the arguments (tests/untyped_optin_tests.cpp covers the opt-in).
#ifndef VELSIGIL_ALLOW_UNTYPED_ENVELOPE
template <typename... Args>
auto accepts_untyped_call(int)
    -> decltype((void)velsigil::verify_envelope(std::declval<Args>()...), std::true_type{});
template <typename... Args>
std::false_type accepts_untyped_call(...);
template <typename... Args>
constexpr bool kAcceptsUntypedCall = decltype(accepts_untyped_call<Args...>(0))::value;

static_assert(!kAcceptsUntypedCall<Sv, Sv, Sv, Sv>, "verify_envelope (four arguments, no type check) must not compile");
static_assert(!kAcceptsUntypedCall<Sv, Sv, Sv, Sv, Sv>, "verify_envelope (five arguments, the fifth is the hwid) must not compile");
static_assert(!kAcceptsUntypedCall<const char*, const char*, const char*, const char*, const char*>,
              "verify_envelope with string literals must not compile");
static_assert(!kAcceptsUntypedCall<Sv, Sv, Sv, Sv, Sv, Sv>, "verify_envelope (six arguments) must not compile either");
#endif
}  // namespace sdk1_compile_checks

namespace {

using json = nlohmann::json;

// The internal verification entry points (not installed, not part of the API): verify_envelope_typed and
// verify_lease without their refusal of the published test-vector keys.
using velsigil::detail::verify_envelope_typed_unguarded;
using velsigil::detail::verify_lease_unguarded;

// The Client accepts the published test-vector key only for a loopback API URL (a local test server).
constexpr char kLoopbackApiUrl[] = "http://localhost:3000";

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const std::string& what) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL: " << what << '\n';
  }
}

void check_equal(const std::string& actual, const std::string& expected, const std::string& what) {
  ++g_checks;
  if (actual != expected) {
    ++g_failures;
    std::cerr << "FAIL: " << what << ": expected '" << expected << "', got '" << actual << "'\n";
  }
}

bool is_lower_hex64(const std::string& text) {
  if (text.size() != 64) return false;
  for (const char c : text) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

void run_envelope_vectors(const json& vectors, const std::string& public_key, const std::string& wrong_public_key) {
  for (const json& vec : vectors.at("envelopes")) {
    const std::string name = vec.at("name").get<std::string>();
    const std::string expect = vec.at("expect").get<std::string>();
    const std::string nonce = vec.at("requestNonce").get<std::string>();
    // The endpoint the request went to: the signed `type` must match it.
    const std::string type = vec.at("requestType").get<std::string>();
    const std::string product = vec.at("productId").get<std::string>();
    const std::string envelope = vec.at("envelope").dump();
    // Answers to a device-bound request name the hwid that request was sent with (SPEC 14 device binding).
    const std::string hwid = vec.contains("hwid") ? vec.at("hwid").get<std::string>() : std::string();

    const velsigil::EnvelopeVerification verification =
        verify_envelope_typed_unguarded(envelope, public_key, nonce, product, type, hwid);
    check_equal(velsigil::to_string(verification.status), expect, "envelope '" + name + "'");

    if (expect == "hwid_mismatch") {
      // The envelope itself is authentic: only the device binding rejects it.
      check_equal(velsigil::to_string(verify_envelope_typed_unguarded(envelope, public_key, nonce, product, type, "").status), "valid",
                  "envelope '" + name + "' without device binding");
    }

    if (expect == "type_mismatch") {
      // The envelope itself is authentic (SDK-1: a signed update-check answer, ok without any license):
      // only the type check rejects it, also with an empty expected type...
      check_equal(velsigil::to_string(verify_envelope_typed_unguarded(envelope, public_key, nonce, product, "", hwid).status),
                  "type_mismatch", "envelope '" + name + "' with an empty expected type");
      // ...and it is valid as the answer to the endpoint it was signed for.
      const std::string signed_type = vec.at("payload").at("type").get<std::string>();
      const auto as_signed = verify_envelope_typed_unguarded(envelope, public_key, nonce, product, signed_type, hwid);
      check_equal(velsigil::to_string(as_signed.status), "valid", "envelope '" + name + "' as its own type");
      const json payload = json::parse(as_signed.payload_json, nullptr, false);
      check(!payload.is_discarded() && payload == vec.at("payload"), "envelope '" + name + "' decodes as its own type");
    }

    if (expect == "valid") {
      const json payload = json::parse(verification.payload_json, nullptr, false);
      check(!payload.is_discarded() && payload == vec.at("payload"), "envelope '" + name + "' decodes to the expected payload");
      if (name == "trial_already_used") {
        // Free trials (SPEC 9.7): a signed failure with the new code (older SDKs: an ordinary failure code).
        check(!payload.is_discarded() && payload.at("ok") == false &&
                  payload.at("code").get<std::string>() == velsigil::codes::kTrialAlreadyUsed,
              "envelope '" + name + "' carries trial_already_used");
      }
      if (name == "validate_ok_trial_ref" || name == "license_expired_trial_ref") {
        // The trial conversion reference (SPEC 9.7): a well-formed string the app adds to its "Buy now" link.
        const bool has_ref = !payload.is_discarded() && payload.at("license").contains("trialRef") &&
                             payload.at("license").at("trialRef").is_string();
        check(has_ref, "envelope '" + name + "' carries license.trialRef");
        if (has_ref) {
          const std::string ref = payload.at("license").at("trialRef").get<std::string>();
          check(velsigil::is_trial_ref(ref), "envelope '" + name + "' trialRef is well-formed");
          check_equal(velsigil::with_trial_ref("https://shop.example.com/buy", ref), "https://shop.example.com/buy?velsigil_trial=" + ref,
                      "with_trial_ref for '" + name + "'");
        }
      }

      // Only the constructor key is trusted: the same envelope must fail with the other key...
      const auto wrong = verify_envelope_typed_unguarded(envelope, wrong_public_key, nonce, product, type, hwid);
      check_equal(velsigil::to_string(wrong.status), "invalid_signature", "envelope '" + name + "' with the wrong key");
      check(wrong.payload_json.empty(), "envelope '" + name + "' exposes no payload with the wrong key");

      // ...and `kid` must not influence verification.
      json other_kid = vec.at("envelope");
      other_kid["kid"] = "0000000000000000";
      check_equal(velsigil::to_string(verify_envelope_typed_unguarded(other_kid.dump(), public_key, nonce, product, type, hwid).status),
                  "valid", "envelope '" + name + "' ignores kid");

      // base64url decoding tolerates padding on the signature.
      json padded = vec.at("envelope");
      std::string sig = padded.at("sig").get<std::string>();
      while (sig.size() % 4 != 0) sig.push_back('=');
      padded["sig"] = sig;
      check_equal(velsigil::to_string(verify_envelope_typed_unguarded(padded.dump(), public_key, nonce, product, type, hwid).status),
                  "valid", "envelope '" + name + "' with a padded signature");
    } else {
      check(verification.payload_json.empty(), "envelope '" + name + "' exposes no payload");
    }
  }

  // Structural garbage is never accepted.
  check_equal(velsigil::to_string(verify_envelope_typed_unguarded("not json", public_key, "n", "p", "validate", "").status),
              "invalid_signature", "non-JSON envelope");
  check_equal(velsigil::to_string(verify_envelope_typed_unguarded("{\"sig\":\"AAAA\"}", public_key, "n", "p", "validate", "").status),
              "invalid_signature", "envelope without data");
  check_equal(velsigil::to_string(verify_envelope_typed_unguarded("[]", public_key, "n", "p", "validate", "").status),
              "invalid_signature", "array envelope");
  const std::string first = vectors.at("envelopes").front().at("envelope").dump();
  check_equal(velsigil::to_string(verify_envelope_typed_unguarded(first, "not-a-key", "n", "p", "validate", "").status),
              "invalid_signature", "invalid public key");
}

void run_lease_vectors(const json& vectors, const std::string& public_key) {
  for (const json& vec : vectors.at("leases")) {
    const std::string name = vec.at("name").get<std::string>();
    const std::string expect = vec.at("expect").get<std::string>();
    const auto verification =
        verify_lease_unguarded(vec.at("token").get<std::string>(), public_key, vec.at("productId").get<std::string>(),
                              vec.at("hwid").get<std::string>(), vec.at("now").get<std::int64_t>());
    check_equal(velsigil::to_string(verification.status), expect, "lease '" + name + "'");

    if (expect == "valid") {
      const json& payload = vec.at("payload");
      check(verification.claims.has_value(), "lease '" + name + "' exposes claims");
      if (verification.claims) {
        const velsigil::LeaseClaims& claims = *verification.claims;
        check_equal(claims.product_id, payload.at("productId").get<std::string>(), "lease claims productId");
        check_equal(claims.license_id, payload.at("licenseId").get<std::string>(), "lease claims licenseId");
        check_equal(claims.activation_id, payload.at("activationId").get<std::string>(), "lease claims activationId");
        check_equal(claims.hwid_hash, payload.at("hwidHash").get<std::string>(), "lease claims hwidHash");
        check_equal(claims.plan, payload.at("plan").get<std::string>(), "lease claims plan");
        check(claims.features == payload.at("features").get<std::vector<std::string>>(), "lease claims features");
        check(claims.license_expires_at == payload.at("licenseExpiresAt").get<std::int64_t>(), "lease claims licenseExpiresAt");
        check(claims.issued_at == payload.at("iat").get<std::int64_t>(), "lease claims iat");
        check(claims.expires_at == payload.at("exp").get<std::int64_t>(), "lease claims exp");
        // The optional signed `trial` claim (SPEC 9.7): absent means false.
        const bool trial = payload.contains("trial") && payload.at("trial").get<bool>();
        check(claims.is_trial == trial, "lease claims trial");
      }
    }
  }
}

const json& find_vector(const json& list, const std::string& name) {
  for (const json& vec : list) {
    if (vec.at("name").get<std::string>() == name) return vec;
  }
  throw std::runtime_error("test vector '" + name + "' is missing");
}

// The public low-level helpers refuse both published test-vector keys, in every spelling the key decoder
// accepts, like an invalid public key (invalid_signature, no payload / claims): unlike the Client they have no
// API URL that could name a local test server. Each envelope and lease used below verifies with the same key
// through the internal entry point, so the refusal is the only reason for the failure.
void run_published_key_refusal(const json& vectors, const std::string& public_key, const std::string& wrong_public_key) {
  auto check_refused = [](const std::string& label, const std::string& key, const json& envelope_vec, const json& lease_vec) {
    const std::string envelope = envelope_vec.at("envelope").dump();
    const std::string nonce = envelope_vec.at("requestNonce").get<std::string>();
    const std::string product = envelope_vec.at("productId").get<std::string>();
    const std::string type = envelope_vec.at("requestType").get<std::string>();
    const std::string hwid = envelope_vec.contains("hwid") ? envelope_vec.at("hwid").get<std::string>() : std::string();
    const std::string what = label + ", envelope '" + envelope_vec.at("name").get<std::string>() + "'";
    check_equal(velsigil::to_string(verify_envelope_typed_unguarded(envelope, key, nonce, product, type, hwid).status), "valid",
                what + ": verifies through the internal entry point");
    const velsigil::EnvelopeVerification refused = velsigil::verify_envelope_typed(envelope, key, nonce, product, type, hwid);
    check_equal(velsigil::to_string(refused.status), "invalid_signature", what + ": refused by verify_envelope_typed");
    check(refused.payload_json.empty(), what + ": verify_envelope_typed exposes no payload");

    const std::string token = lease_vec.at("token").get<std::string>();
    const std::string lease_product = lease_vec.at("productId").get<std::string>();
    const std::string lease_hwid = lease_vec.at("hwid").get<std::string>();
    const std::int64_t now = lease_vec.at("now").get<std::int64_t>();
    const std::string lease_what = label + ", lease '" + lease_vec.at("name").get<std::string>() + "'";
    check_equal(velsigil::to_string(verify_lease_unguarded(token, key, lease_product, lease_hwid, now).status), "valid",
                lease_what + ": verifies through the internal entry point");
    const velsigil::LeaseVerification refused_lease = velsigil::verify_lease(token, key, lease_product, lease_hwid, now);
    check_equal(velsigil::to_string(refused_lease.status), "invalid_signature", lease_what + ": refused by verify_lease");
    check(!refused_lease.claims.has_value(), lease_what + ": verify_lease exposes no claims");
  };
  auto unpadded = [](std::string key) {
    while (!key.empty() && key.back() == '=') key.pop_back();
    return key;
  };

  // keys.publicKey signs the ordinary vectors; keys.wrongPublicKey is the key the wrong_key / lease_wrong_key
  // vectors are signed with (keys.wrongPrivateSeedBase64).
  const json& validate_ok = find_vector(vectors.at("envelopes"), "validate_ok");
  const json& lease_ok = find_vector(vectors.at("leases"), "lease_ok");
  const json& wrong_key = find_vector(vectors.at("envelopes"), "wrong_key");
  const json& lease_wrong_key = find_vector(vectors.at("leases"), "lease_wrong_key");
  check_refused("keys.publicKey", public_key, validate_ok, lease_ok);
  check_refused("keys.publicKey without padding", unpadded(public_key), validate_ok, lease_ok);
  check_refused("keys.publicKey with surrounding whitespace", " \t" + public_key + "\n", validate_ok, lease_ok);
  check_refused("keys.wrongPublicKey", wrong_public_key, wrong_key, lease_wrong_key);
  check_refused("keys.wrongPublicKey without padding", unpadded(wrong_public_key), wrong_key, lease_wrong_key);

  // No vector gets through the public helpers with a published key, whatever its expected status.
  for (const json& vec : vectors.at("envelopes")) {
    const std::string hwid = vec.contains("hwid") ? vec.at("hwid").get<std::string>() : std::string();
    const auto verification =
        velsigil::verify_envelope_typed(vec.at("envelope").dump(), public_key, vec.at("requestNonce").get<std::string>(),
                                        vec.at("productId").get<std::string>(), vec.at("requestType").get<std::string>(), hwid);
    check(verification.status == velsigil::EnvelopeStatus::invalid_signature && verification.payload_json.empty(),
          "envelope '" + vec.at("name").get<std::string>() + "' is refused by verify_envelope_typed with keys.publicKey");
  }
  for (const json& vec : vectors.at("leases")) {
    const auto verification =
        velsigil::verify_lease(vec.at("token").get<std::string>(), public_key, vec.at("productId").get<std::string>(),
                               vec.at("hwid").get<std::string>(), vec.at("now").get<std::int64_t>());
    check(verification.status == velsigil::LeaseStatus::invalid_signature && !verification.claims.has_value(),
          "lease '" + vec.at("name").get<std::string>() + "' is refused by verify_lease with keys.publicKey");
  }

  // The same outcome as an invalid public key.
  const std::string envelope = validate_ok.at("envelope").dump();
  const std::string token = lease_ok.at("token").get<std::string>();
  check_equal(velsigil::to_string(velsigil::verify_envelope_typed(envelope, "not-a-key", "n", "p", "validate", "").status),
              "invalid_signature", "verify_envelope_typed with an invalid public key");
  check_equal(velsigil::to_string(velsigil::verify_lease(token, "not-a-key", "p", "h", 0).status), "invalid_signature",
              "verify_lease with an invalid public key");
}

// The same leases through the public Client offline path (store + clock injection, no network).
void run_client_offline(const json& vectors, const std::string& public_key) {
  for (const json& vec : vectors.at("leases")) {
    const std::string name = vec.at("name").get<std::string>();
    const std::string expect = vec.at("expect").get<std::string>();
    const std::string product = vec.at("productId").get<std::string>();
    const std::int64_t now = vec.at("now").get<std::int64_t>();

    auto store = std::make_shared<velsigil::MemoryStore>();
    store->set(product, velsigil::store_keys::kLease, vec.at("token").get<std::string>());
    velsigil::ClientOptions options;
    options.hwid = vec.at("hwid").get<std::string>();
    options.store = store;
    options.clock = [now] { return now; };
    velsigil::Client client(kLoopbackApiUrl, product, public_key, options);
    check(client.is_configured(), "offline client '" + name + "' is configured: " + client.configuration_error());

    const velsigil::ValidationResult result = client.validate_offline();
    check(result.offline, "offline result '" + name + "' is marked offline");
    if (expect == "valid") {
      check(result.ok, "offline result '" + name + "' is ok");
      check_equal(result.code, "ok", "offline result '" + name + "' code");
      check(result.has_feature("pro") && result.has_feature("export") && !result.has_feature("enterprise"),
            "offline result '" + name + "' features");
      check(result.expires_at() == vec.at("payload").at("licenseExpiresAt").get<std::int64_t>(),
            "offline result '" + name + "' license expiry");
      check(result.lease.has_value() && result.lease->expires_at == vec.at("payload").at("exp").get<std::int64_t>(),
            "offline result '" + name + "' lease expiry");
      check(result.is_trial() == (name == "lease_trial"), "offline result '" + name + "' trial flag");
    } else {
      check(!result.ok, "offline result '" + name + "' is rejected");
      check_equal(result.code, expect == "expired" ? "lease_expired" : "lease_invalid", "offline result '" + name + "' code");
      check(!result.has_feature("pro"), "offline result '" + name + "' grants no features");
    }
  }

  // Nothing stored -> no_lease.
  velsigil::ClientOptions options;
  options.hwid = "test-hwid-0001-abcdef";
  velsigil::Client client(kLoopbackApiUrl, vectors.at("leases").front().at("productId").get<std::string>(), public_key,
                         options);
  const auto result = client.validate_offline();
  check(!result.ok && result.code == "no_lease" && result.offline, "offline validation without a stored lease");
}

// Trial conversion references (SPEC 9.7): the format check and the "Buy now" link builder.
void run_trial_ref_checks() {
  const std::string ref = "vtr1_Ab3_-Ab3_-Ab3_-";
  check(velsigil::is_trial_ref(ref), "is_trial_ref accepts [A-Za-z0-9_-]");
  check(!velsigil::is_trial_ref(""), "is_trial_ref refuses an empty value");
  check(!velsigil::is_trial_ref("has space"), "is_trial_ref refuses a space");
  check(!velsigil::is_trial_ref(std::string(201, 'x')), "is_trial_ref refuses more than 200 characters");
  check_equal(std::string(velsigil::kTrialRefParam), "velsigil_trial", "kTrialRefParam");
  check_equal(velsigil::with_trial_ref("https://shop.example.com/buy?plan=pro#top", ref),
              "https://shop.example.com/buy?plan=pro&velsigil_trial=" + ref + "#top", "with_trial_ref keeps the query and fragment");
  check_equal(velsigil::with_trial_ref("https://shop.example.com/buy?", ref), "https://shop.example.com/buy?velsigil_trial=" + ref,
              "with_trial_ref after a bare ?");
  check_equal(velsigil::with_trial_ref("HTTPS://Buy.Stripe.com/test_abc", ref), "HTTPS://Buy.Stripe.com/test_abc?client_reference_id=" + ref,
              "with_trial_ref on a Stripe Payment Link");
  check_equal(velsigil::with_trial_ref("mailto:sales@example.com", ref), "mailto:sales@example.com", "with_trial_ref ignores other schemes");
  check_equal(velsigil::with_trial_ref("https://shop.example.com/buy", "has space"), "https://shop.example.com/buy",
              "with_trial_ref ignores a malformed reference");
  check_equal(velsigil::with_trial_ref("https://", ref), "https://", "with_trial_ref needs a host");
}

void run_hwid_vectors(const json& vectors) {
  const json& hwid = vectors.at("hwid");
  check_equal(hwid.at("prefix").get<std::string>(), "vx-hwid-v1:", "hwid prefix");
  for (const json& example : hwid.at("examples")) {
    const std::string expected = example.at("hwid").get<std::string>();
    check_equal(velsigil::compute_hardware_id(example.at("machineIdRaw").get<std::string>()), expected, "hwid from raw machine id");
    check_equal(velsigil::compute_hardware_id(example.at("machineIdNormalized").get<std::string>()), expected,
                "hwid from normalized machine id");
    check_equal(velsigil::hash_hardware_id(expected), example.at("serverHwidHash").get<std::string>(), "server hwid hash");
  }
  const json& server = hwid.at("serverHashOfTestHwid");
  check_equal(velsigil::hash_hardware_id(server.at("hwid").get<std::string>()), server.at("hwidHash").get<std::string>(),
              "server hash of the test hwid");

  const std::string local = velsigil::Client::get_hardware_id();
  check(local.empty() || is_lower_hex64(local), "local hardware id is empty or 64 lowercase hex characters");
  check(local == velsigil::Client::get_hardware_id(), "local hardware id is stable");
}

}  // namespace

int main(int argc, char** argv) {
  const std::string path = argc > 1 ? std::string(argv[1]) : std::string(VX_TEST_VECTORS_PATH);
  try {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) {
      std::cerr << "cannot open test vectors: " << path << '\n';
      return 2;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    const json vectors = json::parse(buffer.str(), nullptr, false);
    if (vectors.is_discarded()) {
      std::cerr << "test vectors are not valid JSON\n";
      return 2;
    }
    const std::string public_key = vectors.at("keys").at("publicKey").get<std::string>();
    const std::string wrong_public_key = vectors.at("keys").at("wrongPublicKey").get<std::string>();

    run_envelope_vectors(vectors, public_key, wrong_public_key);
    run_lease_vectors(vectors, public_key);
    run_published_key_refusal(vectors, public_key, wrong_public_key);
    run_client_offline(vectors, public_key);
    run_hwid_vectors(vectors);
    run_trial_ref_checks();
  } catch (const std::exception& error) {
    std::cerr << "unexpected exception: " << error.what() << '\n';
    return 2;
  }

  std::cout << g_checks << " checks, " << g_failures << " failures\n";
  return g_failures == 0 ? 0 : 1;
}
