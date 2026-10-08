// S8 (final review 2026-10-06): the type-less verify_envelope overloads exist only where
// VELSIGIL_ALLOW_UNTYPED_ENVELOPE is defined (CMakeLists.txt defines it for this target only; real programs
// define it for every file or not at all). Checks that the opt-in still compiles, links and fails closed
// on garbage. The overloads stay [[deprecated]] and UNSAFE (no `type` check): never use them in new code.
// Exit code 0 = all checks passed.
#ifndef VELSIGIL_ALLOW_UNTYPED_ENVELOPE
#error "untyped_optin_tests.cpp must be compiled with VELSIGIL_ALLOW_UNTYPED_ENVELOPE"
#endif

#include <velsigil/client.hpp>

#include <iostream>
#include <string_view>

#if defined(_MSC_VER)
#pragma warning(disable : 4996)  // deprecated: the point of this test
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

int main() {
  const std::string_view garbage = "{\"data\":\"e30\",\"sig\":\"AAAA\",\"kid\":\"k\"}";
  const auto four = velsigil::verify_envelope(garbage, "not-a-public-key", "nonce", "product");
  const auto five = velsigil::verify_envelope(garbage, "not-a-public-key", "nonce", "product", "hwid");
  int failures = 0;
  if (four.status == velsigil::EnvelopeStatus::valid || !four.payload_json.empty()) {
    std::cerr << "FAIL: four-argument verify_envelope accepted a garbage envelope\n";
    ++failures;
  }
  if (five.status == velsigil::EnvelopeStatus::valid || !five.payload_json.empty()) {
    std::cerr << "FAIL: five-argument verify_envelope accepted a garbage envelope\n";
    ++failures;
  }
  if (failures != 0) return 1;
  std::cout << "untyped opt-in: 2 checks passed\n";
  return 0;
}
