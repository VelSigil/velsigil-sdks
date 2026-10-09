// Checks the opt-in untyped verify_envelope overloads compile, fail closed and refuse the test keys.
#ifndef VELSIGIL_ALLOW_UNTYPED_ENVELOPE
#error "untyped_optin_tests.cpp must be compiled with VELSIGIL_ALLOW_UNTYPED_ENVELOPE"
#endif

#include <velsigil/client.hpp>

#include <nlohmann/json.hpp>

#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "detail.hpp"

#ifndef VX_TEST_VECTORS_PATH
#error "VX_TEST_VECTORS_PATH must point to sdks/test-vectors.json"
#endif

#if defined(_MSC_VER)
#pragma warning(disable : 4996)  // deprecated: the point of this test
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace {

using json = nlohmann::json;

int g_checks = 0;
int g_failures = 0;

void check(bool condition, const std::string& what) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL: " << what << '\n';
  }
}

bool refused(const velsigil::EnvelopeVerification& verification) {
  return verification.status == velsigil::EnvelopeStatus::invalid_signature && verification.payload_json.empty();
}

// Both overloads refuse the published keys; the internal entry point is the control.
void check_published_key(const std::string& label, const std::string& key, const json& vec) {
  const std::string envelope = vec.at("envelope").dump();
  const std::string nonce = vec.at("requestNonce").get<std::string>();
  const std::string product = vec.at("productId").get<std::string>();
  const std::string hwid = vec.contains("hwid") ? vec.at("hwid").get<std::string>() : std::string();
  const std::string what = label + ", envelope '" + vec.at("name").get<std::string>() + "'";
  const std::string type = vec.at("requestType").get<std::string>();
  const auto control = velsigil::detail::verify_envelope_typed_unguarded(envelope, key, nonce, product, type, hwid);
  check(control.status == velsigil::EnvelopeStatus::valid, what + ": verifies through the internal entry point");
  check(refused(velsigil::verify_envelope(envelope, key, nonce, product)), what + ": refused by the four-argument verify_envelope");
  check(refused(velsigil::verify_envelope(envelope, key, nonce, product, hwid)),
        what + ": refused by the five-argument verify_envelope");
}

const json& find_vector(const json& list, const std::string& name) {
  for (const json& vec : list) {
    if (vec.at("name").get<std::string>() == name) return vec;
  }
  throw std::runtime_error("test vector '" + name + "' is missing");
}

}  // namespace

int main(int argc, char** argv) {
  const std::string_view garbage = "{\"data\":\"e30\",\"sig\":\"AAAA\",\"kid\":\"k\"}";
  const auto four = velsigil::verify_envelope(garbage, "not-a-public-key", "nonce", "product");
  const auto five = velsigil::verify_envelope(garbage, "not-a-public-key", "nonce", "product", "hwid");
  check(four.status != velsigil::EnvelopeStatus::valid && four.payload_json.empty(),
        "four-argument verify_envelope rejects a garbage envelope");
  check(five.status != velsigil::EnvelopeStatus::valid && five.payload_json.empty(),
        "five-argument verify_envelope rejects a garbage envelope");

  const std::string path = argc > 1 ? std::string(argv[1]) : std::string(VX_TEST_VECTORS_PATH);
  try {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) {
      std::cerr << "cannot open test vectors: " << path << '\n';
      return 2;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    const json vectors = json::parse(buffer.str());
    const std::string public_key = vectors.at("keys").at("publicKey").get<std::string>();
    const std::string wrong_public_key = vectors.at("keys").at("wrongPublicKey").get<std::string>();
    std::string unpadded = public_key;
    while (!unpadded.empty() && unpadded.back() == '=') unpadded.pop_back();
    const json& validate_ok = find_vector(vectors.at("envelopes"), "validate_ok");
    check_published_key("keys.publicKey", public_key, validate_ok);
    check_published_key("keys.publicKey without padding", unpadded, validate_ok);
    check_published_key("keys.wrongPublicKey", wrong_public_key, find_vector(vectors.at("envelopes"), "wrong_key"));
  } catch (const std::exception& error) {
    std::cerr << "unexpected exception: " << error.what() << '\n';
    return 2;
  }

  std::cout << "untyped opt-in: " << g_checks << " checks, " << g_failures << " failures\n";
  return g_failures == 0 ? 0 : 1;
}
