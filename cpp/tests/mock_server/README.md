# Mock server for the C++ SDK tests

The C++ SDK ships four test programs (commands below run in the SDK's `cpp` folder):

| Test | Needs | What it covers |
|---|---|---|
| `velsigil_vector_tests` (mandatory) | nothing but the library | every envelope, lease and HWID vector in the shared `test-vectors.json` (verified through the SDK's internal entry points, since the public `verify_envelope_typed` and `verify_lease` refuse the published keys the vectors are signed with; the test checks that refusal too), plus the offline path of `Client` |
| `velsigil_client_tests` | nothing but the library | client behaviour against an in-process signing "server" (an injected `ITransport` that signs with a key pair generated for the run) and a fake clock: ok, business failures, nonce/product/type mismatch, bad signatures, `clock_skew` + one retry, device-secret persistence and re-sending, unsigned 400/403/404/413/415/429/500/502/503, timeouts, connection refused, throwing transports and stores, offline fallback with lease expiry, configuration hardening (including the refusal of the published test-vector keys outside loopback hosts), the low-level helpers (a product's own key verifies, the published test-vector key is refused), `FileStore` (including the legacy `veltrix-license.json` fallback), concurrency |
| `velsigil_untyped_optin_tests` | nothing but the library | the opt-in type-less `verify_envelope` overloads (`VELSIGIL_ALLOW_UNTYPED_ENVELOPE`) compile, fail closed on garbage and refuse the published test-vector keys |
| `velsigil_http_tests` (optional, `-DVX_BUILD_HTTP_TESTS=ON`) | Python 3.10+ with `cryptography` | the same flows over real libcurl HTTP against `mock_server.py`, including the download + SHA-256 verification path |

## Running the HTTP tests

```sh
python3 -m pip install cryptography
cmake -S . -B build -DVX_BUILD_HTTP_TESTS=ON -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
ctest --test-dir build --output-on-failure
```

CTest runs `run_http_tests.py`, which starts `mock_server.py` on a random `127.0.0.1` port, finds a
port with nothing listening (for the connection-refused case) and runs
`velsigil_http_tests <base-url> <refused-url> <public-key>`.

To experiment manually with `examples/basic.cpp`: its `kApiUrl`, `kProductId` and `kPublicKey` are placeholders,
so pass the mock's loopback URL, the mock product id and `keys.publicKey` of `test-vectors.json` on the command
line. The example accepts values on the command line only with a `localhost`, `127.0.0.1` or `[::1]` API URL,
and the SDK accepts that published test key only for those hosts too, so never ship it.

```sh
python3 tests/mock_server/mock_server.py --vectors ../test-vectors.json --port 8787
# in a second shell:
key="$(python3 -c 'import json; print(json.load(open("../test-vectors.json"))["keys"]["publicKey"])')"
./build/velsigil_example_basic http://127.0.0.1:8787 0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b "$key"   # enter the license key VX-OK
```

## Scenarios (selected by the license key)

| Key | Behaviour |
|---|---|
| `VX-OK` | Valid license. Issues a device secret on first activation and then requires it (strict device binding); returns an offline lease; supports deactivate and download. |
| `VX-INVALID` | Signed `invalid_key`. |
| `VX-NONCE` | Signed `ok` with a nonce that does not echo the request. |
| `VX-BADSIG` | `ok` envelope with a corrupted signature. |
| `VX-SKEW` | Server clock two hours ahead: `clock_skew` until the client corrects its offset. |
| `VX-429` / `VX-400` / `VX-500` | Unsigned `rate_limited` / `validation_error` / `internal_error`. |
| `VX-SLOW` | Answers after 3 seconds. |
| `VX-DLBAD` | Download descriptor whose SHA-256 does not match the served file. |

`update-check` with version `0.0.0` returns `no_release`; any other version returns release 1.4.0.
The mock rejects malformed bodies (400), unknown products (404) and replayed nonces
(`replay_detected`) like the real server. It keeps all state in memory and is for tests only:
never expose it to a network.
