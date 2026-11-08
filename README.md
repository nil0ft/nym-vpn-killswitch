# nym-vpn-killswitch

[![ci](https://github.com/nil0ft/nym-vpn-killswitch/actions/workflows/ci.yml/badge.svg)](https://github.com/nil0ft/nym-vpn-killswitch/actions/workflows/ci.yml)
[![newest NymVPN](https://github.com/nil0ft/nym-vpn-killswitch/actions/workflows/nym-compat.yml/badge.svg)](https://github.com/nil0ft/nym-vpn-killswitch/actions/workflows/nym-compat.yml)

Blocks all traffic outside NymVPN on Linux, also while NymVPN is disconnected.

> [!WARNING]
> Developed heavily with AI. Read the code and use it at your own risk.

NymVPN's own kill switch only covers connecting and tunnel errors ([#6687](https://github.com/nymtech/nym-vpn-client/issues/6687)). This one also blocks:

- after you press Disconnect
- at boot, before nym-vpnd starts
- when nym-vpnd stops or crashes
- containers and VMs routed through this machine

## Install

```sh
curl -fsSLO https://github.com/nil0ft/nym-vpn-killswitch/releases/latest/download/install
chmod +x install
./install
```

Needs x86_64, systemd, nftables, glibc 2.28+, Linux 5.13+ (6.9+ for tamper protection) and nym-vpnd.
On other CPUs, clone the repo and run `./install.sh`, which builds with cargo.

`./install update` upgrades, `./install uninstall` removes everything.

## Usage

```sh
sudo nym-killswitch status   # what is blocked and what gets through
sudo nym-killswitch off      # turn off; `on` turns it back on
sudo nym-killswitch rules    # show the nftables rules
```

No sudo? Use `run0` instead; `./install` does that on its own.

No config file. LAN access follows the Allow LAN switch in NymVPN; DNS to the LAN stays blocked.

## How it works

- One nftables table drops everything except loopback, the tun devices nym-vpnd holds, and nym-vpnd's own sockets.
- nym-vpnd runs in `nym-killswitch.slice`; a cgroup match lets only that slice reach the network.
- A guard service loads the table before the network starts, follows nym-vpnd's Allow LAN setting, and locks the table against other tools.
- When something breaks, traffic stays blocked.

## Limits

- Root can turn it off.
- NymVPN split tunneling, other VPNs and captive portals don't work while it's on.
- Bridged VMs and macvlan/ipvlan containers bypass the host firewall.

## License

MIT
