#!/usr/bin/env bash
# nym-killswitch installer
#
#   ./install              install, or upgrade to this version
#   ./install update       upgrade to the latest release
#   ./install uninstall    remove everything
#
# Options: --yes   answer yes to every question
#
# Get it from https://github.com/nil0ft/nym-vpn-killswitch/releases. Run as
# ./install.sh inside a source checkout, it builds with cargo instead.
# PREFIX=/usr installs the command to /usr/sbin instead of /usr/local/sbin.
# RELEASES_URL points it at a fork or mirror of the releases page.
set -euo pipefail

REPO=nil0ft/nym-vpn-killswitch
# scripts/package.sh writes the release version here.
VERSION=@VERSION@
RELEASES=${RELEASES_URL:-https://github.com/$REPO/releases}
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PREFIX=${PREFIX:-/usr/local}
BIN=$PREFIX/sbin/nym-killswitch
UNITDIR=/etc/systemd/system
UNIT=nym-killswitch.service
SLICE=nym-killswitch.slice
DROPIN=$UNITDIR/nym-vpnd.service.d/50-killswitch.conf
DAEMON=nym-vpnd.service
STATE=/var/lib/nym-killswitch
YES=0
WORK=

if [[ -t 1 ]]; then
	BLD=$'\e[1m' GRN=$'\e[1;32m' YLW=$'\e[3;33m' MGT=$'\e[1;3;35m' RED=$'\e[1;31m' RS=$'\e[0m'
else
	BLD='' GRN='' YLW='' MGT='' RED='' RS=''
fi
log() { printf '%s\n' "$*"; }
step() { printf '  %s%s%s %s\n' "$GRN" "$1" "$RS" "${*:2}"; }
file() { printf '   %s%s%s\n' "$YLW" "$1" "$RS"; }
die() {
	printf '%s✗%s %s\n' "$RED" "$RS" "$*" >&2
	exit 1
}

SELF=$(readlink -f "${BASH_SOURCE[0]}")

# Run a command as root: directly, through sudo, or through run0 on systems
# without sudo.
as_root() {
	if ((EUID == 0)); then
		"$@"
	elif command -v sudo >/dev/null; then
		sudo -- "$@"
	elif command -v run0 >/dev/null; then
		run0 "$@"
	else
		die "needs root, and neither sudo nor run0 is installed"
	fi
}

need_cmd() {
	local cmd
	for cmd; do
		command -v "$cmd" >/dev/null || die "$cmd is needed but not installed"
	done
}

# ask <question> <default y|n>
ask() {
	local ans hint=y/N
	[[ $2 == y ]] && hint=Y/n
	((YES)) && return 0
	[[ -t 0 ]] || die "no terminal to ask on; rerun with --yes"
	read -r -p "  $1 [$hint] " ans
	ans=${ans:-$2}
	[[ $ans == [yY]* ]]
}

from_source() { [[ $VERSION == "@VERSION@" ]]; }

workdir() {
	WORK=$(mktemp -d)
	trap 'rm -rf "$WORK"' EXIT
}

# Download one file of release $1 into $WORK and check it against that
# release's checksums.txt.
download() { # <version> <file>
	step Downloading "$2"
	curl -fL --progress-bar "$RELEASES/download/v$1/$2" -o "$WORK/$2"
	curl -fsSL "$RELEASES/download/v$1/checksums.txt" -o "$WORK/checksums.txt"
	step Checking "sha256sum"
	(cd "$WORK" && grep -E "^[0-9a-f]{64}  ${2//./\\.}\$" checksums.txt | sha256sum --check --status) ||
		die "$2 does not match checksums.txt"
	log "   ${MGT}ok$RS"
}

# Put the binary and units to install in $WORK/payload.
fetch() {
	mkdir -p "$WORK/payload"
	if from_source; then
		[[ -e $SRC/Cargo.toml ]] || die "this installer has no version; download it from $RELEASES"
		step Building "from $SRC"
		if ((EUID == 0)) && [[ -n ${SUDO_USER:-} ]]; then
			# Build as you, so target/ never belongs to root.
			# shellcheck disable=SC2016 # expanded by the inner login shell
			runuser -u "$SUDO_USER" -- bash -lc 'cd "$1" && cargo build --release --locked' _ "$SRC"
		else
			need_cmd cargo
			cargo build --release --locked --manifest-path "$SRC/Cargo.toml"
		fi
		cp "$SRC/target/release/nym-killswitch" "$WORK/payload/"
		cp -r "$SRC/systemd" "$WORK/payload/"
	else
		[[ $(uname -m) == x86_64 ]] ||
			die "no prebuilt binary for $(uname -m) yet; build from source: https://github.com/$REPO"
		local name=nym-killswitch-v${VERSION}_linux_x86_64
		download "$VERSION" "$name.tar.gz"
		tar -xzf "$WORK/$name.tar.gz" -C "$WORK"
		cp "$WORK/$name/nym-killswitch" "$WORK/payload/"
		cp -r "$WORK/$name/systemd" "$WORK/payload/"
	fi
}

# Download or build as you, then ask for root once for the rest.
do_install() {
	log "${BLD}nym-killswitch$RS installer $(from_source && echo "(source build)" || echo "$VERSION")"
	log ""
	need_cmd curl tar sha256sum install systemctl
	[[ -d /run/systemd/system ]] || die "systemd is not running; nym-killswitch needs it"
	workdir
	fetch
	cp "$SELF" "$WORK/install"
	local -a flags=()
	((YES)) && flags+=(--yes)
	as_root env PREFIX="$PREFIX" bash "$WORK/install" __install-payload "$WORK" "${flags[@]}"
}

# Runs as root, on the payload do_install prepared in $1.
install_payload() {
	local work=$1
	step Checking "this machine"
	if ! "$work/payload/nym-killswitch" check 2>&1 | sed 's/^/    /'; then
		die "fix the FAIL lines above first"
	fi
	if [[ $(systemctl show -p LoadState --value "$DAEMON") != loaded ]]; then
		ask "Install anyway? Nothing can get out until NymVPN is installed." n || exit 1
	fi

	cat <<EOF

  nym-killswitch blocks every connection that does not go through NymVPN,
  including while NymVPN is disconnected and while this machine boots.
  Local network access follows the Allow LAN switch in NymVPN's settings.

EOF
	ask "Install and turn the killswitch on now? NymVPN will reconnect." y || exit 1

	step Installing "nym-killswitch"
	sed "s|@BIN@|$BIN|" "$work/payload/systemd/$UNIT" >"$work/$UNIT"
	install -Dm755 -o root -g root "$work/payload/nym-killswitch" "$BIN"
	install -Dm644 -o root -g root "$work/$UNIT" "$UNITDIR/$UNIT"
	install -Dm644 -o root -g root "$work/payload/systemd/$SLICE" "$UNITDIR/$SLICE"
	install -Dm644 -o root -g root "$work/payload/systemd/nym-vpnd.service.d/50-killswitch.conf" "$DROPIN"
	file "$BIN"
	file "$UNITDIR/$UNIT"
	file "$UNITDIR/$SLICE"
	file "$DROPIN"

	step Starting "the killswitch"
	systemctl daemon-reload
	systemctl enable -q "$UNIT"
	systemctl restart "$UNIT" || die "the guard did not start, see: journalctl -u $UNIT"

	local cg
	cg=$(systemctl show -p ControlGroup --value "$DAEMON" 2>/dev/null) || true
	if [[ -n $cg && $cg != "/$SLICE/"* ]]; then
		step Restarting "$DAEMON so it runs in $SLICE"
		systemctl restart "$DAEMON"
	fi

	log ""
	"$BIN" status | sed 's/^/  /'
	log ""
	log "${MGT}DONE$RS Reconnect NymVPN if it was connected. Run 'nym-killswitch help' for commands."
}

do_update() {
	if from_source; then
		[[ -d $SRC/.git ]] || die "$SRC is not a git checkout"
		need_cmd git
		local owner
		owner=$(stat -c %U "$SRC")
		step Pulling "the latest source"
		if ((EUID == 0)) && [[ $owner != root ]]; then
			runuser -u "$owner" -- git -C "$SRC" pull --ff-only
		else
			git -C "$SRC" pull --ff-only
		fi
		exec "$SRC/install.sh" install --yes
	fi

	need_cmd curl sha256sum
	local latest installed
	latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$RELEASES/latest")
	latest=${latest##*/v}
	[[ $latest =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not find the latest release at $RELEASES"
	installed=$("$BIN" version 2>/dev/null | awk '{ print $2 }') || true
	if [[ $installed == "$latest" ]]; then
		log "${MGT}nym-killswitch $latest is the latest release and already installed$RS"
		return 0
	fi
	log "${BLD}nym-killswitch$RS ${installed:-not installed} -> $latest"
	workdir
	download "$latest" install
	bash "$WORK/install" install "$@"
}

do_uninstall() {
	if ((EUID != 0)); then
		local -a flags=()
		((YES)) && flags+=(--yes)
		as_root env PREFIX="$PREFIX" bash "$SELF" uninstall "${flags[@]}"
		return
	fi
	log "${BLD}nym-killswitch$RS uninstaller"
	log ""
	ask "Remove the killswitch? Traffic will leave outside NymVPN whenever it is disconnected." n || exit 1

	step Stopping "the killswitch"
	if [[ -x $BIN ]]; then
		"$BIN" off || true
	else
		systemctl disable --now -q "$UNIT" 2>/dev/null || true
	fi
	step Removing "files"
	local path
	for path in "$BIN" "$UNITDIR/$UNIT" "$UNITDIR/$SLICE" "$DROPIN" "$STATE"; do
		[[ -e $path ]] || continue
		rm -rf "$path"
		file "$path"
	done
	rmdir --ignore-fail-on-non-empty "${DROPIN%/*}" 2>/dev/null || true
	systemctl daemon-reload
	log ""
	log "${MGT}DONE$RS nym-vpnd moves back to its default slice the next time it restarts."
}

main() {
	local cmd=install payload=
	local -a opts=()
	while (($#)); do
		case $1 in
		install | update | uninstall) cmd=$1 ;;
		__install-payload)
			cmd=$1
			payload=${2:?}
			shift
			;;
		--yes | -y)
			YES=1
			opts+=("$1")
			;;
		-h | --help)
			sed -n '2,13s/^# \{0,1\}//p' "$SELF"
			exit 0
			;;
		*) die "unknown argument: $1" ;;
		esac
		shift
	done
	case $cmd in
	install) do_install ;;
	__install-payload) install_payload "$payload" ;;
	update) do_update "${opts[@]}" ;;
	uninstall) do_uninstall ;;
	esac
}

main "$@"
exit
