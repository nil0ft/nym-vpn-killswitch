#!/usr/bin/env bash
# Assemble the release files in dist/ from a built binary.
#
#   scripts/package.sh <version> [binary]
#
# Writes:
#   dist/nym-killswitch-v<version>_linux_x86_64.tar.gz   binary, systemd units, docs
#   dist/install                                         install.sh, pinned to <version>
#   dist/checksums.txt                                   sha256 of both
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=${1:?usage: scripts/package.sh <version> [binary]}
bin=${2:-$ROOT/target/release/nym-killswitch}
die() {
	echo "package: $*" >&2
	exit 1
}

cargo_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)
[[ $version == "$cargo_version" ]] || die "asked for $version but Cargo.toml says $cargo_version"
[[ $(readelf -h "$bin" | awk -F: '/Machine/ { gsub(/^ +/, "", $2); print $2 }') == "Advanced Micro Devices X86-64" ]] ||
	die "$bin is not an x86_64 binary"

name=nym-killswitch-v${version}_linux_x86_64
dist=$ROOT/dist
rm -rf "$dist"
mkdir -p "$dist/$name/systemd/nym-vpnd.service.d"
install -m755 "$bin" "$dist/$name/nym-killswitch"
install -m644 "$ROOT/systemd/nym-killswitch.service" "$ROOT/systemd/nym-killswitch.slice" "$dist/$name/systemd/"
install -m644 "$ROOT/systemd/nym-vpnd.service.d/50-killswitch.conf" "$dist/$name/systemd/nym-vpnd.service.d/"
install -m644 "$ROOT/LICENSE" "$ROOT/README.md" "$dist/$name/"

# Same input, same archive: fixed order, owner and times.
mtime=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$mtime" -C "$dist" -cf - "$name" |
	gzip -9n >"$dist/$name.tar.gz"
rm -rf "${dist:?}/$name"

sed "s/^VERSION=@VERSION@\$/VERSION=$version/" "$ROOT/install.sh" >"$dist/install"
grep -qx "VERSION=$version" "$dist/install" || die "could not pin the version in install"
chmod 755 "$dist/install"

(cd "$dist" && sha256sum "$name.tar.gz" install >checksums.txt)
ls -l "$dist"
