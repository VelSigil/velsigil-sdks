# Velsigil client SDKs

Official client libraries for [Velsigil](https://www.velsigil.com), the self-hosted license distribution and
management platform. Your application uses them to validate license keys against your Velsigil server, bind
activations to the device, keep working offline on a signed lease, and check for and download updates.

Every answer from the server is an **Ed25519-signed envelope**. The SDKs verify the signature over the exact bytes
received, with the product public key compiled into your application, before anything is parsed; the answer must
echo the request's fresh nonce, your product id and the request type. Forged, replayed or redirected answers can
never produce a valid result. All four SDKs pass the same protocol test vectors ([`test-vectors.json`](test-vectors.json)).

| SDK | Package | Install | Documentation |
|---|---|---|---|
| Node.js (TypeScript, ESM + CommonJS) | [`velsigil-client`](https://www.npmjs.com/package/velsigil-client) on npm | `npm i velsigil-client` | [node/README.md](node/README.md) |
| Python | [`velsigil-client`](https://pypi.org/project/velsigil-client/) on PyPI | `pip install velsigil-client` | [python/README.md](python/README.md) |
| .NET (C#, Unity) | [`Velsigil.Client`](https://www.nuget.org/packages/Velsigil.Client) on nuget.org | `dotnet add package Velsigil.Client` | [csharp/README.md](csharp/README.md) |
| C++17 | `velsigil-cpp-<version>.tar.gz` on [GitHub releases](https://github.com/VelSigil/velsigil-sdks/releases) | release tarball + CMake | [cpp/README.md](cpp/README.md) |

You need three values from your Velsigil panel (*Products > your product > Integration*): the **API URL**, the
**product id** and the product's **public key**. Compile them into your application; never load the public key
from a file or setting the user can change.

## Quick start

The values below are placeholders. The public key in them is the SDKs' published **test** key (its private half is
in [`test-vectors.json`](test-vectors.json)), so replace it with your own product's public key.

### Node.js

```bash
npm i velsigil-client
```

```ts
import { hostname } from 'node:os';
import { VelsigilClient, FileStore, defaultStoreDirectory } from 'velsigil-client';

const client = new VelsigilClient(
  'https://licenses.example.com',                     // API URL
  '0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b',             // product id
  'I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=',     // product public key
  { store: new FileStore(defaultStoreDirectory('MyApp')) }, // persists device secret + offline lease
);

const result = await client.validateWithOfflineFallback(licenseKey, { version: '1.2.0', deviceName: hostname() });
if (!result.ok) throw new Error(`License problem: ${result.code} - ${result.message}`);
if (result.hasFeature('pro')) enableProFeatures();
```

### Python

```bash
pip install velsigil-client
```

```python
from velsigil_client import FileStore, VelsigilClient, default_store_path

client = VelsigilClient(
    "https://licenses.example.com",                  # API URL
    "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b",          # product id
    "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=",  # product public key
    store=FileStore(default_store_path("MyApp")),    # persists device secret + offline lease
)

result = client.validate_with_offline_fallback(license_key, version="1.2.0")
if not result.ok:
    raise SystemExit(f"License problem: {result.code} - {result.message}")
if result.has_feature("export"):
    enable_export()
```

### .NET

```powershell
dotnet add package Velsigil.Client
```

```csharp
using Velsigil.Client;
using Velsigil.Client.Storage;

// One long-lived, thread-safe client per product.
var client = new VelsigilClient(
    "https://licenses.example.com",                  // API URL
    "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b",          // product id
    "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=",  // product public key
    new VelsigilClientOptions { Store = FileStore.CreateDefault("MyApp") });

var result = await client.ValidateWithOfflineFallbackAsync(
    licenseKey, new ValidateOptions { Version = "1.2.0", DeviceName = Environment.MachineName });
if (!result.Ok) { Console.WriteLine($"License problem: {result.Message} ({result.Code})"); return; }
if (result.HasFeature("export")) EnableExport();
```

### C++

Download `velsigil-cpp-<version>.tar.gz` from the [release](https://github.com/VelSigil/velsigil-sdks/releases),
check it (see [Verifying packages](#verifying-packages)) and pin its SHA-256 from the release's `SHA256SUMS`:

```cmake
include(FetchContent)
FetchContent_Declare(velsigil
  URL      https://github.com/VelSigil/velsigil-sdks/releases/download/v1.0.0/velsigil-cpp-1.0.0.tar.gz
  URL_HASH SHA256=<sha256 from SHA256SUMS>)
FetchContent_MakeAvailable(velsigil)
target_link_libraries(my_app PRIVATE velsigil::velsigil)
```

libcurl, libsodium and nlohmann/json must be findable (vcpkg: `curl`, `libsodium`, `nlohmann-json`; or the system
packages). `cmake --install` followed by `find_package(velsigil 1.0 CONFIG REQUIRED)` works too.

```cpp
#include <velsigil/client.hpp>

velsigil::ClientOptions options;
options.store = std::make_shared<velsigil::FileStore>(velsigil::FileStore::default_path("MyApp"));
velsigil::Client client("https://licenses.example.com",                  // API URL
                        "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b",          // product id
                        "I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI=",  // product public key
                        options);

velsigil::ValidateOptions validate_options;
validate_options.version = "1.2.0";
const auto result = client.validate_with_offline_fallback(license_key, validate_options);
if (!result.ok) { std::cerr << "License problem: " << result.code << " - " << result.message << '\n'; return 1; }
if (result.has_feature("export")) enable_export();
```

Each SDK README covers the full API, result codes, in-app free trials, offline leases, device-secret storage,
updates and verified downloads, thread safety and hardening.

## Supported versions

| SDK | Runtime / toolchain | Tested in CI |
|---|---|---|
| Node.js | Node.js 22 or newer (`engines: >=22`) | 22, 24 |
| Python | CPython 3.10 to 3.14; `cryptography >= 50.0.0` (optional `PyNaCl >= 1.6.2`) | 3.10 with cryptography 50.0.0, 3.14 with the newest |
| .NET | `net8.0` and `netstandard2.0` (.NET 8+, .NET Framework 4.7.2+, Mono, Unity 2021.3+) | Linux and Windows, both builds |
| C++ | C++17, CMake 3.16+; MSVC 2019+, GCC 9+, Clang 10+, Apple Clang 12+ | GCC (Ubuntu, system packages), MSVC (Windows, vcpkg) |

Security fixes go to the latest release of the current major version. All four SDKs share one version number and are
released together (`vX.Y.Z` tags).

## Verifying packages

The SDKs are a license check: a tampered copy could simply skip the signature verification, so check what you
install. Every release is built by [`release.yml`](.github/workflows/release.yml) in this public repository from a
tag on `main` and published through OIDC trusted publishing (no registry tokens exist). In short:

| Package | Check |
|---|---|
| npm | `npm audit signatures` (registry signatures and provenance of your installed tree); the package page shows the provenance linking to this repository and `release.yml` |
| PyPI | `pypi-attestations verify pypi --repository https://github.com/VelSigil/velsigil-sdks pypi:velsigil_client-<version>-py3-none-any.whl` (PEP 740 attestations); install with `pip install --require-hashes` |
| NuGet | the reserved-prefix checkmark next to `Velsigil.Client` on nuget.org (owner `velsigil-client`); `dotnet nuget verify --all <package>.nupkg` (repository signature); lock files + `--locked-mode`; package source mapping `Velsigil.*` to nuget.org |
| C++ | `gh attestation verify velsigil-cpp-<version>.tar.gz --repo VelSigil/velsigil-sdks --signer-workflow VelSigil/velsigil-sdks/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners` and `gh release verify-asset v<version> velsigil-cpp-<version>.tar.gz --repo VelSigil/velsigil-sdks` (immutable release) |

Step-by-step instructions, including lock-file and CI settings for your own project: [docs/VERIFYING.md](docs/VERIFYING.md).

## This repository

The SDKs are developed together with the Velsigil server, which owns the protocol and generates the shared test
vectors, and are exported here for release. Issues are welcome; a pull request is reviewed and merged by applying it
upstream, then exporting it back. CI runs every SDK's test suite, the shared vector check, package builds and
[zizmor](https://docs.zizmor.sh) on the workflows. Releasing: [docs/RELEASING.md](docs/RELEASING.md).

## Security

Please report vulnerabilities privately to **security@velsigil.com**, not in public issues. Policy, scope and safe
harbor: [https://www.velsigil.com/security.html](https://www.velsigil.com/security.html) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE), Copyright (c) 2026 Velsigil.
