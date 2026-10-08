# Verifying the Velsigil SDKs (for sellers)

The SDK inside your application decides whether a license is valid. A tampered copy could simply skip the Ed25519
check of the server's answer, so the integrity of the package you install **is** your license check. Everything
below takes a few minutes to set up and then runs in your own CI.

What every release guarantees:

- It is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) in the public repository
  `VelSigil/velsigil-sdks`, from a tag `vX.Y.Z` on `main`, on GitHub-hosted runners, without any cache.
- It is published through OIDC **trusted publishing**: no npm, PyPI or NuGet token exists that could publish it from
  anywhere else. Every publish (each registry and the GitHub release) needs the owner's approval; npm versions
  additionally need the owner's 2FA.
- Every file gets a **build-provenance attestation** (Sigstore, signed for that workflow, tag and commit), a SHA-256
  in the release's `SHA256SUMS`, and a CycloneDX SBOM attached to the GitHub release. These describe the files as
  built: npm and PyPI serve them byte for byte, while nuget.org adds its own repository signature to the `.nupkg`
  (see [.NET](#net-nugetorg-velsigilclient)).

Replace `X.Y.Z` with the version you use. The commands use the repository name exactly as GitHub spells it
(`VelSigil/velsigil-sdks`); some tools compare it case-sensitively.

## Node.js (npm `velsigil-client`)

1. Pin the version and install from your lock file only:

   ```sh
   npm install --save-exact velsigil-client@X.Y.Z
   npm ci                      # in CI: exact versions and integrity hashes from package-lock.json
   ```

2. Verify registry signatures and provenance of everything installed (the SDK has no runtime dependencies):

   ```sh
   npm audit signatures
   # ... verified registry signatures, ... verified attestations
   ```

   `velsigil-client` must be among the packages with *verified attestations*. On
   [npmjs.com/package/velsigil-client](https://www.npmjs.com/package/velsigil-client) the *Provenance* section links to
   `VelSigil/velsigil-sdks`, `.github/workflows/release.yml` and the exact commit. From the command line:

   ```sh
   npm view velsigil-client@X.Y.Z dist.attestations --json
   ```

   The very first version, `1.0.0-rc.0`, was a bootstrap published by hand without provenance and is deprecated;
   use `1.0.0` or later.

3. Recommended `.npmrc` for the project that ships your application:

   ```ini
   ignore-scripts=true        # velsigil-client needs no install scripts; neither should anything else
   min-release-age=3          # never install a version that is less than 3 days old
   ```

## Python (PyPI `velsigil-client`)

1. Install with hashes from a lock file (pip-tools, uv or Poetry export):

   ```sh
   pip-compile --generate-hashes requirements.in        # velsigil-client==X.Y.Z in requirements.in
   pip install --require-hashes -r requirements.txt
   ```

2. Verify the PEP 740 attestation published with each file (made by `release.yml` of `VelSigil/velsigil-sdks`):

   ```sh
   pip install pypi-attestations
   pypi-attestations verify pypi --repository https://github.com/VelSigil/velsigil-sdks \
     pypi:velsigil_client-X.Y.Z-py3-none-any.whl
   pypi-attestations verify pypi --repository https://github.com/VelSigil/velsigil-sdks \
     pypi:velsigil_client-X.Y.Z.tar.gz
   ```

   pypi.org shows the same under *Verified details* / *Provenance* on the release's files.

## .NET (nuget.org `Velsigil.Client`)

1. Check the owner of `Velsigil.Client` on nuget.org: it is `velsigil-client`. Once nuget.org grants Velsigil's
   request to reserve the `Velsigil.` prefix for that account, the package also shows the **verified checkmark** and
   no one else can publish a package whose ID starts with it.
2. Lock and source-map your restore (in your application's repository):

   ```xml
   <!-- Directory.Build.props -->
   <PropertyGroup>
     <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
   </PropertyGroup>
   ```

   ```xml
   <!-- nuget.config: Velsigil.* only ever comes from nuget.org -->
   <packageSourceMapping>
     <packageSource key="nuget.org">
       <package pattern="Velsigil.*" />
     </packageSource>
   </packageSourceMapping>
   ```

   and restore in CI with `dotnet restore --locked-mode`.
3. Verify the package signature (nuget.org repository signature):

   ```sh
   dotnet nuget verify --all ~/.nuget/packages/velsigil.client/X.Y.Z/velsigil.client.X.Y.Z.nupkg
   ```

   This is the check for a `.nupkg` from nuget.org. nuget.org adds its repository signature (`.signature.p7s`) to
   every package it stores, so that file never has the SHA-256 in `SHA256SUMS`, the SBOM or the build-provenance
   attestation: those describe the package as built, before nuget.org signed it. A hash mismatch there is expected
   and not a failed check.
4. Optional: the `.snupkg` symbols and Source Link map the binaries to the exact source commit on GitHub (the
   `repository` element of the package's `.nuspec` names it).

## C++ (GitHub release `velsigil-cpp-X.Y.Z.tar.gz`)

1. Download the tarball and `SHA256SUMS` from the release
   [vX.Y.Z](https://github.com/VelSigil/velsigil-sdks/releases) and check the hash:

   ```sh
   sha256sum --check --ignore-missing SHA256SUMS       # Windows: (Get-FileHash velsigil-cpp-X.Y.Z.tar.gz).Hash
   ```

2. Verify the build-provenance attestation and the immutable release with the GitHub CLI:

   ```sh
   gh attestation verify velsigil-cpp-X.Y.Z.tar.gz --repo VelSigil/velsigil-sdks \
     --signer-workflow VelSigil/velsigil-sdks/.github/workflows/release.yml \
     --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
   gh release verify vX.Y.Z --repo VelSigil/velsigil-sdks
   gh release verify-asset vX.Y.Z velsigil-cpp-X.Y.Z.tar.gz --repo VelSigil/velsigil-sdks
   ```

   `--source-ref` makes sure the attestation was made by a run for that release tag (release tags can only be created
   by the owner), not by a run on some other branch.

   Offline, the attached `velsigil-sdks-X.Y.Z.sigstore.json` is the same attestation bundle (add
   `--bundle velsigil-sdks-X.Y.Z.sigstore.json` to the `gh attestation verify` command above).

3. Pin the verified hash in your build so it can never change underneath you:

   ```cmake
   FetchContent_Declare(velsigil
     URL      https://github.com/VelSigil/velsigil-sdks/releases/download/vX.Y.Z/velsigil-cpp-X.Y.Z.tar.gz
     URL_HASH SHA256=<the hash you verified>)
   ```

   The C++ SDK's own dependencies come from your package manager; with vcpkg, pin your `builtin-baseline` (the SDK's
   `vcpkg.json` shows the baseline it is tested with) and keep libsodium at 1.0.21 or newer.

## The same check for the npm and Python files

The attestation covers every release file, so you can also verify the npm tarball (`npm pack velsigil-client@X.Y.Z`)
or the wheel/sdist you downloaded from PyPI:

```sh
gh attestation verify <file> --repo VelSigil/velsigil-sdks \
  --signer-workflow VelSigil/velsigil-sdks/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
```

Not for a `.nupkg` from nuget.org: see step 3 of [.NET](#net-nugetorg-velsigilclient).

## If a check fails

Do not ship the build. Report it at once to **security@velsigil.com** (see [SECURITY.md](../SECURITY.md)) with the
package, version, where you got it and the command output. Security fixes are announced as GitHub security advisories
of `VelSigil/velsigil-sdks`, which Dependabot turns into alerts in your repositories.
