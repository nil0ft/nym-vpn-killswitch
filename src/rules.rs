//! The nftables ruleset, as text in nft syntax, and helpers to read it back.

use std::collections::BTreeSet;
use std::fmt::Write;

pub const TABLE: &str = "nym_killswitch";
/// Run before other firewalls' filter chains; NymVPN's own uses plain "filter".
const PRIO: &str = "filter - 10";
/// Interfaces allowed as tunnels. Not "tunnels": newer nft treats that as a keyword.
const SET: &str = "nym_tunnels";

// The ranges NymVPN itself opens for "allow LAN" (nym-firewall-config).
const LAN4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";
const LAN6: &str = "fe80::/10, fc00::/7";
const MCAST4: &str = "224.0.0.0/24, 239.0.0.0/8, 255.255.255.255";
const MCAST6: &str = "ff01::/16, ff02::/16, ff03::/16, ff04::/16, ff05::/16";

/// What the rules let through besides nym-vpnd itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// NymVPN's "Allow LAN" setting.
    pub allow_lan: bool,
    /// Tun devices nym-vpnd holds open.
    pub tunnels: BTreeSet<String>,
}

/// Interface names end up inside nft syntax, so only plain kernel names pass.
pub fn valid_ifname(name: &str) -> bool {
    (1..16).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-@+".contains(&b))
}

/// The full table. `lock` adds the `owner` and `persist` flags; `loaded_flags` are
/// the flags of the table loaded right now, if any.
pub fn render(policy: &Policy, cgroup: &str, lock: bool, loaded_flags: Option<&str>) -> String {
    let level = cgroup.split('/').count();
    let nym = format!(r#"socket cgroupv2 level {level} "{cgroup}" accept comment "nym-vpnd""#);
    let mut s = String::new();

    // Swap the whole table in one transaction: declare it (a no-op when it exists,
    // so the flags have to match the loaded table), delete it, build it fresh.
    match loaded_flags {
        Some(flags) => writeln!(s, "add table inet {TABLE} {{ flags {flags}; }}"),
        None => writeln!(s, "add table inet {TABLE}"),
    }
    .unwrap();
    writeln!(s, "delete table inet {TABLE}\n").unwrap();
    writeln!(s, "table inet {TABLE} {{").unwrap();
    if lock {
        writeln!(s, "\tflags owner, persist").unwrap();
    }
    writeln!(
        s,
        "\tcomment \"nym-killswitch {}\"\n",
        env!("CARGO_PKG_VERSION")
    )
    .unwrap();

    writeln!(s, "\tset {SET} {{\n\t\ttype ifname").unwrap();
    if !policy.tunnels.is_empty() {
        writeln!(s, "\t\telements = {{ {} }}", quoted(&policy.tunnels)).unwrap();
    }
    writeln!(s, "\t}}\n").unwrap();

    let lan_out = if policy.allow_lan {
        format!(
            "\t\tmeta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} reject with icmpx admin-prohibited comment \"no DNS to the LAN\"\n\
             \t\tip daddr {{ {LAN4}, {MCAST4} }} accept comment \"LAN\"\n\
             \t\tip6 daddr {{ {LAN6}, {MCAST6} }} accept comment \"LAN\"\n"
        )
    } else {
        String::new()
    };
    let lan_in = if policy.allow_lan {
        format!(
            "\t\tip saddr {{ {LAN4} }} accept comment \"LAN\"\n\
             \t\tip6 saddr {{ {LAN6} }} accept comment \"LAN\"\n"
        )
    } else {
        String::new()
    };

    write!(
        s,
        r#"	chain output {{
		type filter hook output priority {PRIO}; policy drop;
		oifname "lo" accept
		oifname @{SET} accept comment "tunnel"
		{nym}
		udp sport 68 ip daddr 255.255.255.255 udp dport 67 accept comment "DHCPv4"
		ip6 saddr fe80::/10 udp sport 546 ip6 daddr {{ ff02::1:2, ff05::1:3 }} udp dport 547 accept comment "DHCPv6"
		icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 ip6 daddr {{ fe80::/10, ff02::/16 }} accept comment "IPv6 neighbor discovery"
		icmpv6 type {{ mld-listener-report, mld2-listener-report, mld-listener-done }} ip6 hoplimit 1 ip6 daddr ff02::/16 accept comment "IPv6 multicast membership"
{lan_out}		counter reject with icmpx admin-prohibited comment "blocked"
	}}

	chain input {{
		type filter hook input priority {PRIO}; policy drop;
		iifname "lo" accept
		iifname @{SET} accept comment "tunnel"
		{nym}
		udp sport 67 udp dport 68 accept comment "DHCPv4"
		ip6 saddr fe80::/10 udp sport 547 ip6 daddr fe80::/10 udp dport 546 accept comment "DHCPv6"
		icmpv6 type {{ nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect }} ip6 hoplimit 255 accept comment "IPv6 neighbor discovery"
		icmpv6 type mld-listener-query ip6 hoplimit 1 ip6 saddr fe80::/10 accept comment "IPv6 multicast membership"
{lan_in}		counter drop comment "blocked"
	}}

	chain forward {{
		type filter hook forward priority {PRIO}; policy drop;
		oifname @{SET} accept comment "tunnel"
		iifname @{SET} ct state established,related accept comment "tunnel"
{lan_out}		counter reject with icmpx admin-prohibited comment "blocked"
	}}
}}
"#
    )
    .unwrap();
    s
}

/// Replace the members of the tunnel set, in one transaction.
pub fn set_tunnels(tunnels: &BTreeSet<String>) -> String {
    let mut s = format!("flush set inet {TABLE} {SET}\n");
    if !tunnels.is_empty() {
        writeln!(
            s,
            "add element inet {TABLE} {SET} {{ {} }}",
            quoted(tunnels)
        )
        .unwrap();
    }
    s
}

/// Loaded when the real rules can't be and nothing protects the machine yet.
pub fn emergency() -> String {
    format!(
        r#"table inet {TABLE} {{
	comment "nym-killswitch emergency block"
	chain output {{
		type filter hook output priority {PRIO}; policy drop;
		oifname "lo" accept
		reject with icmpx admin-prohibited
	}}
	chain input {{
		type filter hook input priority {PRIO}; policy drop;
		iifname "lo" accept
	}}
	chain forward {{
		type filter hook forward priority {PRIO}; policy drop;
		reject with icmpx admin-prohibited
	}}
}}
"#
    )
}

/// Creates and deletes a locked table in one transaction. Fails on kernels
/// without the `persist` flag (before Linux 6.9).
pub fn lock_probe() -> String {
    format!(
        "add table inet {TABLE}_probe {{ flags owner, persist; }}\ndelete table inet {TABLE}_probe\n"
    )
}

/// Uses the socket cgroup match (Linux 5.13+). Meant for a dry run.
pub fn socket_probe() -> String {
    format!(
        "table inet {TABLE}_probe {{\n\tchain probe {{\n\t\tsocket cgroupv2 level 1 \"init.scope\" accept\n\t}}\n}}\n"
    )
}

fn quoted(names: &BTreeSet<String>) -> String {
    names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------- reading a listing

/// Table flags, e.g. "persist" for a table whose owner exited.
pub fn flags(listing: &str) -> Option<&str> {
    listing
        .lines()
        .find_map(|l| l.strip_prefix("\tflags "))
        .map(str::trim)
}

pub fn is_owned(listing: &str) -> bool {
    listing
        .lines()
        .next()
        .is_some_and(|l| l.contains("# progname"))
}

pub fn is_emergency(listing: &str) -> bool {
    listing.contains("emergency block")
}

pub fn allows_lan(listing: &str) -> bool {
    listing.contains(r#"comment "LAN""#)
}

/// Members of the tunnel set.
pub fn tunnels(listing: &str) -> Vec<String> {
    let Some(start) = listing.find(&format!("set {SET} {{")) else {
        return Vec::new();
    };
    let set = &listing[start..];
    let set = &set[..set.find('}').unwrap_or(set.len())];
    let Some(elements) = set.find("elements = {") else {
        return Vec::new();
    };
    set[elements + "elements = {".len()..]
        .split(',')
        .map(|e| e.trim().trim_matches('"').to_string())
        .filter(|e| !e.is_empty())
        .collect()
}

/// Packets counted by the rule with this comment in this chain.
pub fn counter(listing: &str, chain: &str, comment: &str) -> u64 {
    let header = format!("\tchain {chain} {{");
    let tag = format!("comment \"{comment}\"");
    listing
        .split(&header)
        .nth(1)
        .and_then(|body| body.split("\n\t}").next())
        .and_then(|body| body.lines().find(|l| l.contains(&tag)))
        .and_then(|line| {
            let mut words = line.split_whitespace();
            words.find(|w| *w == "packets")?;
            words.next()?.parse().ok()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names_cannot_break_out_of_quotes() {
        assert!(valid_ifname("tun0"));
        assert!(valid_ifname("nym-1.a@b+c_d"));
        assert!(!valid_ifname(""));
        assert!(!valid_ifname("sixteen-chars-xx"));
        assert!(!valid_ifname("tun0\" accept"));
        assert!(!valid_ifname("tun 0"));
        assert!(!valid_ifname("tun0;"));
    }

    #[test]
    fn reads_tunnel_set_and_counters_from_nft_output() {
        let listing = "table inet nym_killswitch { # progname nym-killswitch\n\tflags owner,persist\n\
            \tset nym_tunnels {\n\t\ttype ifname\n\t\telements = { \"tun0\",\n\t\t\t     \"tun1\" }\n\t}\n\n\
            \tchain output {\n\t\tcounter packets 12 bytes 900 reject with icmpx admin-prohibited comment \"blocked\"\n\t}\n\n\
            \tchain input {\n\t\tcounter packets 7 bytes 1 drop comment \"blocked\"\n\t}\n}\n";
        assert_eq!(tunnels(listing), ["tun0", "tun1"]);
        assert_eq!(flags(listing), Some("owner,persist"));
        assert!(is_owned(listing));
        assert_eq!(counter(listing, "output", "blocked"), 12);
        assert_eq!(counter(listing, "input", "blocked"), 7);
        assert_eq!(counter(listing, "forward", "blocked"), 0);
    }
}
