# Security policy

## Reporting a vulnerability

Email **security@velsigil.com**. Please do not open a public issue, pull request or discussion for a security
problem. Include what you found and in which SDK and version, the steps to reproduce it, the impact you expect, and
how we can reach you (and whether you would like to be credited).

Our full vulnerability disclosure policy, with scope, rules for testing and safe harbor, is published at
**[https://www.velsigil.com/security.html](https://www.velsigil.com/security.html)** (also linked from
[security.txt](https://www.velsigil.com/.well-known/security.txt)). We aim to acknowledge reports within 3 business
days and agree a disclosure date with you.

## Scope of this repository

- The four client SDKs: Node.js (`velsigil-client` on npm), Python (`velsigil-client` on PyPI), .NET
  (`Velsigil.Client` on nuget.org) and C++ (`velsigil-cpp-<version>.tar.gz` GitHub release assets).
- Their release machinery: the GitHub Actions workflows, the published packages and their provenance, attestations
  and checksums. A package that does not verify as described in [docs/VERIFYING.md](docs/VERIFYING.md) is in scope
  and urgent: please report it at once.

Test against a Velsigil installation you run yourself, never against someone else's server. Licensing code that runs
on a customer's machine can always be patched by that customer; reports that a local attacker can modify their own
copy of an application are out of scope unless the SDK accepts a forged, replayed or redirected server answer, or
leaks a secret.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.x (latest release) | yes |

Fixes are released as a new version of all four SDKs and announced as a GitHub security advisory of this repository,
so Dependabot alerts projects that depend on an affected version.
