// Links against velsigil::velsigil exactly like an application does and makes one offline call, so a
// missing link dependency (libcurl, libsodium, threads) of the exported/installed target fails here.
#include <velsigil/client.hpp>

#include <iostream>

int main() {
  // A random public key whose private key was never kept: the published test-vector key would be refused for
  // this non-loopback URL (the SDK accepts it only for localhost, 127.0.0.1 and [::1]).
  velsigil::Client client("https://licenses.example.com", "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b",
                          "uhcA7ddUfTb9JYWiduhJnH6MqsBrJ8avgaw4y2FaIdo=");
  if (!client.is_configured()) {
    std::cerr << "client rejected its configuration: " << client.configuration_error() << '\n';
    return 1;
  }
  // No lease is stored (in-memory store), so this must fail locally without touching the network.
  const velsigil::ValidationResult offline = client.validate_offline();
  if (offline.ok) {
    std::cerr << "validate_offline() unexpectedly succeeded without a stored lease\n";
    return 1;
  }
  std::cout << "velsigil " << velsigil::kSdkVersion << " linked; validate_offline() -> " << offline.code << '\n';
  return 0;
}
