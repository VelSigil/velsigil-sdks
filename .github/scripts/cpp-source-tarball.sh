#!/usr/bin/env bash
# Builds the C++ SDK source release: <out-dir>/velsigil-cpp-<version>.tar.gz with the committed cpp/ folder at its
# top level (velsigil-cpp-<version>/CMakeLists.txt, ...) plus test-vectors.json next to CMakeLists.txt, which the
# CMake project picks up for its tests. Works with FetchContent (URL + URL_HASH) and `cmake --install`.
#
#   .github/scripts/cpp-source-tarball.sh <version> <out-dir>
#
# Deterministic: only committed files (git archive, never build output of the working tree), sorted entries, every
# mtime = SOURCE_DATE_EPOCH (default: the commit time), uid/gid 0, normalised modes, gzip without name or timestamp.
# The same commit therefore always gives the same bytes and the same SHA-256. Needs GNU tar and gzip (Linux runners).
set -euo pipefail

version="${1:?usage: cpp-source-tarball.sh <version> <out-dir>}"
out="${2:?usage: cpp-source-tarball.sh <version> <out-dir>}"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "::error::version '$version' is not X.Y.Z"; exit 1; }

root="$(git rev-parse --show-toplevel)"
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct HEAD)}"
name="velsigil-cpp-${version}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$out" "$work/$name"
git -C "$root" archive --format=tar HEAD cpp test-vectors.json | tar -x -C "$work"
cp -a "$work/cpp/." "$work/$name/"
cp "$work/test-vectors.json" "$work/$name/test-vectors.json"

tar --sort=name --format=pax --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
  --mtime="@${epoch}" --owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' \
  -C "$work" -cf - "$name" | gzip -9 -n > "$out/$name.tar.gz"

echo "$out/$name.tar.gz"
