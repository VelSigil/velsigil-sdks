# Releasing the Velsigil SDKs (owner guide)

All four SDKs share one version and are released together by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) when a tag `vX.Y.Z` that points to a commit on
`main` is pushed. No registry token exists anywhere: npm, PyPI and nuget.org trust this repository through OIDC
**trusted publishing**, and every publishing job, including the GitHub release, waits for your approval in its GitHub
environment.

| Registry | Package | Trusted publisher / policy | Environment |
|---|---|---|---|
| npm | `velsigil-client` (unscoped) | owner `VelSigil`, repository `velsigil-sdks`, workflow `release.yml`, environment `npm`, **stage publish only** | `npm` |
| PyPI | `velsigil-client` | pending publisher: owner `VelSigil`, repository `velsigil-sdks`, workflow `release.yml`, environment `pypi` | `pypi` |
| nuget.org | `Velsigil.Client` | policy: owner `VelSigil`, repository `velsigil-sdks`, workflow `release.yml`, environment `nuget`; NuGet login user `velsigil-client` | `nuget` |
| GitHub | release `vX.Y.Z` with `velsigil-cpp-X.Y.Z.tar.gz`, SBOMs, `SHA256SUMS`, attestation bundle | `GITHUB_TOKEN` of the `github-release` job (`contents: write`); no registry | `github-release` |

**Spell the owner exactly `VelSigil`.** That is how GitHub spells the account (its login has a capital V and S), and
it is what GitHub puts into the OIDC token. npm compares every trusted-publisher field case-sensitively, and
`repository.url` in `node/package.json` must match the repository exactly, so `velsigil` would make every npm release
fail; some verification tools compare it the same way. Do not rename the GitHub account later without changing the
npm trusted publisher and `repository.url` (in the panel's `sdks/node/package.json`) with it.

The workflow file name, the repository and the environment names are part of every registry's trust configuration:
renaming any of them breaks publishing until the registry side is changed too.

Where the code comes from: the SDK sources are developed in the private panel repository (the source of truth) and
copied here with its `npm run export-sdks -- <path of this checkout>` (only `node/`, `python/`, `csharp/`, `cpp/` and
`test-vectors.json`; the files of this repository such as this guide, `.github/` and `README.md` are maintained here).

Order of the first release: section 1 (claim the names) before the first push, because the README tells everyone
which names to install and a name is only yours once something is published under it; then sections 2 to 6.

---

## 1. Before the first push: claim the names

### 1.1 npm: the bootstrap version from your PC

npm only lets you configure a trusted publisher for a package that already exists, and publishing claims the name,
so the very first version is published by hand once. It is a release candidate of the same code, never the final
`1.0.0`: a prerelease is not matched by `^1.0.0` ranges and makes clear that it is the bootstrap.

1. Requirements on your PC: Node.js >= 22.14 with npm >= 11.15 (`npm --version`), and your npm account
   `velsigil` with two-factor authentication by security key or passkey. (Done on 2026-10-07: `velsigil` published
   `velsigil-client@1.0.0-rc.0`.)
2. Build the package from a **clean export**, never from a working copy with local changes:

   ```sh
   # in the panel repository: export into an empty folder
   npm run export-sdks -- ../velsigil-sdks-bootstrap
   cd ../velsigil-sdks-bootstrap/node
   npm ci --ignore-scripts
   npm test
   npm version 1.0.0-rc.0 --no-git-tag-version   # this throw-away folder only; the repository stays at 1.0.0
   npm pack                                       # runs the build (prepack); writes velsigil-client-1.0.0-rc.0.tgz
   tar -tzf velsigil-client-1.0.0-rc.0.tgz        # package/LICENSE, README.md, CHANGELOG.md, package.json, dist/...
   ```

3. Publish that tarball (npm asks for 2FA). `--provenance=false` is needed because provenance can only be created in
   CI (`publishConfig` asks for it):

   ```sh
   npm login
   npm publish ./velsigil-client-1.0.0-rc.0.tgz --tag next --access public --provenance=false
   ```

4. On npmjs.com, package **velsigil-client > Settings > Publishing access**: **Require two-factor authentication and
   disallow tokens**.
5. Because it is the package's first version, npm makes `1.0.0-rc.0` the `latest` version even though it was
   published with `--tag next`: until `1.0.0` is approved, `npm i velsigil-client` installs the bootstrap. Keep that
   window short (do this step on the day you push and tag), and retire it afterwards (section 6, step 7).

### 1.2 nuget.org: reserve the `Velsigil.` prefix

**Done:** nuget.org approved the reservation on 2026-10-08. The text below is kept for a future prefix.

E-mail account@nuget.org (CC support@nuget.org) **from the e-mail address registered on the nuget.org account**
`velsigil-client` (staff ask for that address), and ask them to reserve the ID prefix **`Velsigil.*`** for that
account. The e-mail must name the owner account and the prefix; also say it is a normal (private, not public)
reservation, list the planned package `Velsigil.Client`, and point to velsigil.com and the GitHub repository as proof
of ownership. The prefix does not cover the bare ID `Velsigil`; ask for that exact ID too if you want it. Once
reserved, nobody else can publish a `Velsigil.*` package and yours shows the verified checkmark, including packages
published before the reservation was granted, so the release does not have to wait for it.

There is no deadline. In 2026 some requests went unanswered for weeks: after 10 to 14 days reply on the same thread,
then resend from the same address to nugetacc@microsoft.com or nuget@microsoft.com (the addresses NuGet staff gave in
NuGet/NuGetGallery#10961). Until the reservation is granted, keep the READMEs saying it is requested, not reserved.

### 1.3 PyPI: waiting for your approval

The PyPI name `velsigil-client` is only claimed by the first upload, which needs the pending publisher of section 4,
and that waits for the PyPI approval you are expecting. Until then the name is unprotected while the README already
names it. Keep that gap short: release on PyPI as soon as the approval arrives, and before adding the pending
publisher check that <https://pypi.org/project/velsigil-client/> still does not exist. If the approval you are waiting
for is a PyPI **organization** request, you do not need it for this: a pending publisher can be added under your
personal PyPI account now (*Your account > Publishing*) and the project moved into the organization later.

## 2. One-time setup of the GitHub repository

1. **Commit identity** (before the first commit): commits are public, so use GitHub's private no-reply address, not a
   personal e-mail address. On github.com, *Settings > Emails*: tick **Keep my email addresses private** and **Block
   command line pushes that expose my email**; the page shows your no-reply address
   (`<number>+VelSigil@users.noreply.github.com`).

2. **First push** (Git for Windows, from a terminal; the folder was prepared without git):

   ```sh
   cd velsigil-sdks      # the prepared folder
   git init -b main
   git config user.name "Velsigil"
   git config user.email "<your no-reply address from step 1>"
   git add -A
   git status            # only sources: no node_modules, bin/obj, dist, .env, *.nupkg (see .gitignore)
   git commit -m "Velsigil SDKs 1.0.0: initial import"
   git remote add origin https://github.com/VelSigil/velsigil-sdks.git
   git push -u origin main   # Git Credential Manager opens the browser to sign in to GitHub
   ```

   With GitHub Desktop instead: *File > Add local repository* > the folder > *create a repository* (leave README,
   .gitignore and license off), set the e-mail under *File > Options > Git*, commit everything, then *Repository >
   Repository settings > Remote*: `https://github.com/VelSigil/velsigil-sdks.git`, and *Push origin*. (Do not use
   *Publish repository*: the repository already exists.)

   Then check that the **CI** workflow passes on `main`. The C++ jobs compile the C++ SDK for the first time ever:
   if they fail, the job logs name the phase (configure, build, test, consumer) and the CMake/CTest/vcpkg logs are
   attached to the run as an artifact.

3. **Settings > Actions > General**
   - Allow GitHub Actions and reusable workflows; tick **Require actions to be pinned to a full-length commit SHA**.
   - Workflow permissions: **Read repository contents and packages permissions**; do not allow GitHub Actions to
     create or approve pull requests.

4. **Settings > General > Releases**: turn on **Enable release immutability**. A published release (its assets and
   its tag) can then no longer be changed, and GitHub attests it (`gh release verify`).

5. **Settings > Code security**: Dependabot **alerts** on; Dependabot **security updates** off (the SDK folders are
   exported from the panel, so a fix merged here would be undone by the next export: fix the dependency in the panel
   and export, see section 7); secret scanning with push protection; private vulnerability reporting (optional;
   SECURITY.md names security@velsigil.com).

6. **Environments** (Settings > Environments): create `npm`, `pypi`, `nuget` and `github-release`, each with
   - **Required reviewers**: you (leave "Prevent self-review" off, or you could not approve your own release);
   - **Allow administrators to bypass configured protection rules**: off, so every release waits for an approval;
   - **Deployment branches and tags**: *Selected branches and tags*, add the **tag** rule `v*` and no branch;
   - no secrets and no variables (nothing is needed).

   `github-release` is not tied to any registry; it is the point where you can still stop the immutable C++ release.

7. **Rulesets** (Settings > Rules > Rulesets)
   - *main* (target: default branch): require a pull request; require the CI status checks (all jobs of `CI`, after
     they ran once); block force pushes and deletion. Leave the approval count at 0 while you are the only maintainer
     (GitHub never lets you approve your own pull request); require code-owner review once a second maintainer exists.
   - *release tags* (target: tags, pattern `v*`): restrict creations, restrict updates, restrict deletions, block
     force pushes; bypass list: *Repository admin* (you). Nobody else can create a release tag, and a tag can never be
     moved to other code.

8. **CODEOWNERS** (`.github/CODEOWNERS`) names `@VelSigil`, your account.

## 3. npm: the trusted publisher

On npmjs.com, package **velsigil-client > Settings > Trusted publisher**: GitHub Actions; organization or user
**`VelSigil`** (exactly), repository `velsigil-sdks`, workflow `release.yml`, environment `npm`; allowed actions:
leave **npm publish** and **npm dist-tag** unticked (`npm stage publish` is always allowed). CI can then only stage;
nothing goes public without your 2FA.

A new trusted publisher **expires if it has not published within 2 days**: add it only when you are ready to tag the
release (section 6). If it expired, delete it and add it again.

## 4. PyPI (waiting for PyPI's approval)

PyPI publishes through a **pending publisher** for the project `velsigil-client` (the project is created by the
first upload). As of 2026-10-07 you are still waiting for an approval on PyPI (section 1.3).

1. When PyPI has approved: *Your account > Publishing > Add a new pending publisher*: PyPI project name
   `velsigil-client`, owner `VelSigil`, repository `velsigil-sdks`, workflow `release.yml`, environment `pypi`.
2. A pending publisher does **not** reserve the name: approve the `pypi` deployment the same day you create it.
3. If `v1.0.0` is tagged before PyPI is ready: **leave the `pypi` deployment waiting** (npm, NuGet and the GitHub
   release are separate jobs and continue). Once the pending publisher exists, open that release run and approve
   `pypi`. GitHub fails a deployment that has waited 30 days (the release files are kept for 35); after that,
   release the next patch version of all SDKs instead.
4. After the first upload: in the project settings, check the publisher is listed as a trusted publisher of
   `velsigil-client`, and that no API token exists for it.

## 5. nuget.org

1. *Your profile > Trusted Publishing*: add a policy, signed in as `velsigil-client`: repository owner `VelSigil`,
   repository `velsigil-sdks`, workflow file `release.yml`, environment `nuget`; scope **Push new packages and
   package versions**, package `Velsigil.Client`; unlisting not allowed. (nuget.org compares these case-insensitively;
   use the same spelling anyway.)
2. The workflow logs in with `NuGet/login` as `user: velsigil-client`. That must be the nuget.org **profile name** (not
   an e-mail address) of the account that **creates** the policy, even if the policy is owned by a nuget.org
   organization. If you ever create the policy from another account, change `user:` in `release.yml`. The key it
   receives is valid for one hour and only for this push.

## 6. Every release

1. **In the panel repository**: set the new version in every place (the panel's OPERATIONS.md section 16.2 lists
   them: `node/package.json` + `node/src/version.ts`, `python/pyproject.toml` + `python/velsigil_client/client.py`,
   the `.csproj` + `VelsigilClient.cs`, `cpp/CMakeLists.txt` + `cpp/vcpkg.json` + `cpp/include/velsigil/client.hpp`,
   and the two `version` fields at the top of `node/package-lock.json`), update the four CHANGELOGs, run the SDK
   tests, then `npm run export-sdks -- <this checkout> --prune`.
2. **Here**: branch, commit, pull request; wait for CI (it also runs `.github/scripts/check-versions.mjs`); merge.
3. **Tag on `main`** (only from an up-to-date `main`):

   ```sh
   git switch main
   git pull --ff-only
   git tag -a v1.0.0 -m "Velsigil SDKs 1.0.0"
   git push origin v1.0.0
   ```

   The `build` job refuses a tag that is not on `main` or does not match every SDK version, before anything is
   published. It builds and tests all packages, writes `SHA256SUMS` and the SBOMs (the job summary shows the hashes),
   and the `attest` job signs build provenance for every file.
4. **Approve the deployments** (Actions > the run > *Review deployments*): `npm`, `nuget`, `github-release`, and
   `pypi` once PyPI is ready (section 4). Each job checks `SHA256SUMS` against the hash the build job passed on, and
   every file against `SHA256SUMS`, before it publishes.
5. **Approve the staged npm package** with 2FA. On npmjs.com: *Staged Packages* > `velsigil-client` > the version >
   *Approve*. Or on your PC:

   ```sh
   npm stage list velsigil-client
   npm stage view <stage-id>
   npm stage download <stage-id>        # optional: compare its SHA-256 with SHA256SUMS of the run
   npm stage approve <stage-id>         # asks for 2FA; the version is public afterwards
   ```

   An unexpected staged version (one you did not start): `npm stage reject <stage-id>` and see section 8.
6. **Check the result**: `npm view velsigil-client@X.Y.Z dist.attestations`; the provenance and attestation panels on
   npmjs.com and pypi.org; the reserved-prefix checkmark on nuget.org; `gh release verify vX.Y.Z --repo
   VelSigil/velsigil-sdks`. [VERIFYING.md](VERIFYING.md) has the commands sellers use.
7. **After `1.0.0` only**: retire the bootstrap version (`latest` already points to `1.0.0` after the approval):

   ```sh
   npm view velsigil-client dist-tags                 # latest: 1.0.0
   npm deprecate velsigil-client@1.0.0-rc.0 "Bootstrap release; use 1.0.0 or later"
   npm dist-tag rm velsigil-client next
   ```

Re-running: a job that failed after its registry accepted the package fails again on the duplicate version (npm,
PyPI and nuget.org versions are immutable; that is intended). Fix forward with the next patch version.

## 7. Keeping the pinned toolchain current

- **Actions** and **`.github/requirements`** (Python build/test tools): Dependabot proposes updates weekly (7-day
  cooldown). Read the release notes before merging.
- **SDK dependencies** (`node/`, `python/`, `csharp/`): not updated here. They are exported from the panel, whose own
  Dependabot updates them; a change merged here would be reverted by the next export (its `--dry-run` lists such
  files as updated `~`). A Dependabot alert in this repository for one of them: fix it in the panel, export, release.
- `setuptools` is pinned twice (`python/pyproject.toml` and `.github/requirements/build-requirements.txt`; Dependabot
  ignores it here): change both together (the build fails otherwise).
- **`node/package-lock.json`** is a standalone lock (the panel installs the SDK through its npm workspace). After a
  devDependency change in the panel, regenerate it outside the workspace: copy `sdks/node` to an empty temporary
  folder, run `npm install --package-lock-only --ignore-scripts` there and copy `package-lock.json` back. The export
  refuses a lock that does not match `package.json`.
- **.NET SDK** (`csharp/global.json`, exact version, no roll-forward): the committed `packages.lock.json` files record
  the trimming-analyzer package of that SDK version, so change both together, in the panel repository: edit
  `global.json`, run `dotnet restore Velsigil.Client.sln --force-evaluate` in `sdks/csharp`, export. **.NET 8 support
  ends on 2026-11-10**: move to the .NET 10 SDK before then.
- **vcpkg baseline** (`cpp/vcpkg.json` `builtin-baseline`, a microsoft/vcpkg release commit): update it in the panel
  repository; CI builds against exactly that commit.
- **Minimum versions** (`.github/requirements-min/`): change them only together with the floors in
  `python/pyproject.toml` (cryptography) and the supported-version table in README.md.

## 8. If something is compromised

Act in this order; most steps take minutes.

1. **Stop publishing**: Settings > Actions > General > *Disable actions* for this repository. Reject every pending
   environment deployment and every unexpected staged npm package (`npm stage reject <stage-id>`).
2. **Cut the trust**: delete the trusted publisher on npm (package settings), PyPI (project > Publishing) and
   nuget.org (Trusted Publishing policy). Nothing else can publish: no tokens exist. If any npm, PyPI or NuGet API
   token was ever created by hand, revoke it now (`npm token list` / `npm token revoke`, PyPI *API tokens*, nuget.org
   *API Keys*).
3. **Secure the accounts** (GitHub, npm, PyPI, Microsoft/nuget.org, the velsigil.com mailbox, the domain registrar):
   sign out all sessions, check and rotate passkeys/security keys and recovery codes, review the audit logs, remove
   unknown collaborators, deploy keys, GitHub Apps, OAuth apps, webhooks and environment reviewers; check that the
   rulesets and environments are unchanged.
4. **Withdraw a bad version**: npm `npm deprecate velsigil-client@X.Y.Z "<reason>"` (an unpublish is possible only
   within npm's unpublish policy; ask npm support for malware); PyPI *yank* the release; nuget.org unlist it and mark
   it deprecated/vulnerable from the website (the trusted-publishing policy cannot unlist) and contact
   support@nuget.org; GitHub: delete the release if it must disappear (its tag stays reserved). Then publish a fixed
   version.
5. **Tell sellers**: a GitHub security advisory in this repository (Security > Advisories) with the affected versions
   and packages, so Dependabot alerts every project that uses them; e-mail customers. A tampered SDK can skip the
   license check, so say which versions to avoid and how to verify the fixed one (VERIFYING.md).
6. **Restore**: re-enable Actions, re-create the trusted publishers (npm: stage-only, within 2 days of the next
   release), release from a verified commit.
