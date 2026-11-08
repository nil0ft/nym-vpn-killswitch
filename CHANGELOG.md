# Changelog

Notable changes to nym-killswitch, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Add entries under Unreleased;
`scripts/release.sh` turns that section into the next version, and the release
workflow publishes it as the GitHub release notes.

## [Unreleased]

### Fixed

- The guard did not start: "cgroup nym-killswitch.slice does not exist". systemd nests a slice with a dash in its name, so the slice lives at `nym.slice/nym-killswitch.slice`. The guard now uses the slice it runs in. If 0.1.0 left your machine in the emergency block, run `sudo nym-killswitch off` (or `run0 nym-killswitch off`), then install this version.

## [0.1.0] - 2026-11-08

### Added

- One nftables table that drops all traffic outside NymVPN's tunnel, also after you press Disconnect, at boot before nym-vpnd starts, and when nym-vpnd stops or crashes.
- Only nym-vpnd may use the physical network. It runs in `nym-killswitch.slice` and one rule matches sockets from that cgroup, so any NymVPN server works.
- Apps may use the tun devices nym-vpnd holds open, and no others.
- Local network access follows NymVPN's Allow LAN setting while it changes. The guard keeps the last value for boot. DNS to the LAN stays blocked.
- Tamper protection on Linux 6.9+ with the nftables `owner` and `persist` flags. Older kernels get a guard that restores the rules when another tool removes them.
- An emergency table that blocks everything when the guard can't start.
- Commands: `status`, `check`, `on`, `off`, `rules`.
- `install` script for releases: checks the download against `checksums.txt`, plus `update` and `uninstall`. It asks for root once, through sudo or, on systems without sudo, run0.
- Daily and pre-release checks against the newest NymVPN release, with the real nym-vpnd.
