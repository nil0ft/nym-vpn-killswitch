#!/usr/bin/env bash
# Cut a release.
#
#   scripts/release.sh 0.2.0
#
# Sets the version in Cargo.toml and Cargo.lock, renames the Unreleased section
# of CHANGELOG.md to "0.2.0 - <today>", commits, and tags v0.2.0. Nothing gets
# pushed; the release workflow starts when you push the tag.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
die() {
	echo "release: $*" >&2
	exit 1
}

version=${1:?usage: scripts/release.sh <version>}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 1.2.3"
[[ -z $(git status --porcelain) ]] || die "commit or stash your changes first"
! git rev-parse -q --verify "refs/tags/v$version" >/dev/null || die "tag v$version already exists"
scripts/changelog.sh Unreleased >/dev/null || die "add entries under Unreleased in CHANGELOG.md first"

sed -i "0,/^version = \".*\"\$/s//version = \"$version\"/" Cargo.toml
cargo update --workspace --offline --quiet
sed -i "s/^## \[Unreleased\]\$/## [Unreleased]\n\n## [$version] - $(date -u +%F)/" CHANGELOG.md
scripts/changelog.sh "$version" >/dev/null

git commit --quiet -m "release v$version" Cargo.toml Cargo.lock CHANGELOG.md
git tag -a "v$version" -m "nym-killswitch $version"
echo "Tagged v$version. Publish it with: git push origin HEAD v$version"
