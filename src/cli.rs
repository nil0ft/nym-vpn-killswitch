//! The commands people run.

use std::path::Path;
use std::process::Command;

use crate::guard::Settings;
use crate::nft::Nft;
use crate::nym;
use crate::rules::{self, TABLE};
use crate::system::CGROUP_ROOT;

pub const UNIT: &str = "nym-killswitch.service";
const DAEMON_UNIT: &str = "nym-vpnd.service";

fn need_root(command: &str) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(format!("{command} needs root; run it with sudo or run0"))
    }
}

fn systemctl(args: &[&str]) -> Option<String> {
    let out = Command::new("systemctl").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn listing(nft: &mut Nft) -> Option<String> {
    nft.run(&format!("list table inet {TABLE}")).ok()
}

pub fn status() -> Result<(), String> {
    need_root("status")?;
    let settings = Settings::from_env()?;
    let listing = listing(&mut Nft::new()?);
    let guard = systemctl(&["is-active", UNIT]).unwrap_or_default();

    let state = match &listing {
        None => "OFF. Traffic can leave outside NymVPN.".to_string(),
        Some(l) if rules::is_emergency(l) => {
            format!("EMERGENCY BLOCK. Everything is blocked, see: journalctl -u {UNIT}")
        }
        Some(l) if rules::is_owned(l) => "on, locked (only the guard can change the rules)".into(),
        Some(_) if guard == "active" => "on, watched (put back if another tool touches it)".into(),
        Some(_) => format!(
            "on, unguarded (guard is {}; the rules stay loaded)",
            if guard.is_empty() {
                "not installed"
            } else {
                &guard
            }
        ),
    };

    let cgroup =
        systemctl(&["show", "-p", "ControlGroup", "--value", DAEMON_UNIT]).unwrap_or_default();
    let daemon = if cgroup.is_empty() {
        "not running".to_string()
    } else {
        let placement = if cgroup.starts_with(&format!("/{}/", settings.cgroup)) {
            "allowed through".to_string()
        } else {
            format!(
                "outside {} and blocked. Fix: systemctl restart {DAEMON_UNIT}",
                settings.cgroup
            )
        };
        match nym::probe() {
            Ok(version) => format!("{version} running, {placement}"),
            Err(err) => format!("running, {placement}; {err}"),
        }
    };

    println!("killswitch  {state}");
    println!("nym-vpnd    {daemon}");
    let Some(l) = listing.filter(|l| !rules::is_emergency(l)) else {
        return Ok(());
    };
    let tunnels = rules::tunnels(&l);
    println!(
        "tunnel      {}",
        if tunnels.is_empty() {
            "none, so nothing gets out".into()
        } else {
            tunnels.join(" ")
        }
    );
    println!(
        "LAN         {}",
        if rules::allows_lan(&l) {
            "allowed by NymVPN's Allow LAN setting (DNS to the LAN stays blocked)"
        } else {
            "blocked (NymVPN's Allow LAN is off)"
        }
    );
    println!(
        "blocked     {} out, {} in, {} forwarded (packets)",
        rules::counter(&l, "output", "blocked"),
        rules::counter(&l, "input", "blocked"),
        rules::counter(&l, "forward", "blocked"),
    );
    Ok(())
}

pub fn on() -> Result<(), String> {
    need_root("on")?;
    let ok = Command::new("systemctl")
        .args(["enable", "--now", UNIT])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        return Err(format!("could not start {UNIT}"));
    }
    status()
}

pub fn off() -> Result<(), String> {
    need_root("off")?;
    let _ = Command::new("systemctl")
        .args(["disable", "--now", UNIT])
        .status();
    let mut nft = Nft::new()?;
    match listing(&mut nft) {
        Some(l) if rules::is_owned(&l) => {
            return Err(format!(
                "a guard running outside {UNIT} still holds the rules; stop that process first"
            ));
        }
        Some(_) => nft.run(&format!("delete table inet {TABLE}"))?,
        None => String::new(),
    };
    eprintln!("killswitch off. Traffic can leave outside NymVPN until you run: nym-killswitch on");
    Ok(())
}

pub fn rules() -> Result<(), String> {
    need_root("rules")?;
    let listing = listing(&mut Nft::new()?).ok_or("the killswitch is off")?;
    print!("{listing}");
    Ok(())
}

/// Check that this machine can run the killswitch.
pub fn check() -> Result<(), String> {
    need_root("check")?;
    let mut failed = false;
    let mut report = |ok: bool, required: bool, what: &str, hint: &str| {
        let mark = match (ok, required) {
            (true, _) => "ok  ",
            (false, true) => "FAIL",
            (false, false) => "no  ",
        };
        println!(
            "{mark}  {what}{}",
            if ok {
                String::new()
            } else {
                format!(": {hint}")
            }
        );
        failed |= required && !ok;
    };

    report(
        Path::new(CGROUP_ROOT).join("cgroup.controllers").exists(),
        true,
        "cgroup v2",
        "boot with systemd.unified_cgroup_hierarchy=1",
    );
    match Nft::new() {
        Err(err) => report(false, true, "libnftables", &err),
        Ok(nft) => {
            report(true, true, "libnftables", "");
            let socket_match = nft.dry_run().run(&rules::socket_probe()).is_ok();
            report(
                socket_match,
                true,
                "match sockets by cgroup",
                "needs Linux 5.13+ with CONFIG_NFT_SOCKET",
            );
            let lock = Nft::new()?.run(&rules::lock_probe()).is_ok();
            report(
                lock,
                false,
                "tamper protection",
                "needs Linux 6.9+; the guard will watch the rules and put them back instead",
            );
        }
    }
    let installed =
        systemctl(&["show", "-p", "LoadState", "--value", DAEMON_UNIT]).unwrap_or_default();
    report(
        installed == "loaded",
        false,
        "NymVPN daemon (nym-vpnd.service)",
        "not installed; nothing can get out without it",
    );
    // An API change never opens anything; it only stops the LAN following NymVPN.
    match nym::probe() {
        Ok(version) => report(true, false, &format!("nym-vpnd {version} API"), ""),
        Err(err @ nym::Error::Unreachable(_)) => report(
            false,
            false,
            "nym-vpnd API",
            &format!("{err}; start nym-vpnd to check it"),
        ),
        Err(err) => report(
            false,
            false,
            "nym-vpnd API",
            &format!("{err}; Allow LAN won't follow NymVPN until nym-killswitch is updated"),
        ),
    }
    if failed {
        Err("this machine can't run the killswitch".into())
    } else {
        Ok(())
    }
}
