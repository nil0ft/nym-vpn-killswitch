//! Does a NymVPN release still offer what nym-killswitch relies on?
//!
//! Skipped unless NYMKS_COMPAT=1, because it downloads NymVPN. NYMKS_COMPAT_TAG
//! picks a release tag; the default is the newest.
//!
//! 1. Reads NymVPN's source at the newest tag and checks the API declarations
//!    src/nym.rs depends on. This catches a change as soon as Nym tags it.
//! 2. Downloads the newest Linux x86_64 build, checks it against the release's
//!    checksums.txt, runs the real nym-vpnd in throwaway user, network and mount
//!    namespaces, and checks that the guard follows `nym-vpnc lan set
//!    allow|block` and a daemon restart.
//!
//! Needs curl, tar, sha256sum, nft, iproute2 and util-linux. No root.

#[path = "../common/mod.rs"]
mod common;

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};

use common::{Report, need, run, stdout, wait_for};

const KS: &str = env!("CARGO_BIN_EXE_nym-killswitch");
const REPO: &str = "nymtech/nym-vpn-client";
const CORE: &str = "nym-vpn-core/crates";
const INNER: &str = "__live";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(INNER) {
        return live_inside(Path::new(&args[2]), Path::new(&args[3]));
    }
    if std::env::var("NYMKS_COMPAT").as_deref() != Ok("1") {
        println!("skipped: set NYMKS_COMPAT=1 to check against the newest NymVPN release");
        return ExitCode::SUCCESS;
    }
    need(&["curl", "tar", "sha256sum", "nft", "ip", "unshare"]);
    let tag = std::env::var("NYMKS_COMPAT_TAG")
        .ok()
        .filter(|t| !t.is_empty());

    let mut report = Report::default();
    contract(&mut report, tag.clone().unwrap_or_else(newest_tag));
    let contract_ok = report.finish(&[]);
    let live_ok = live(tag.unwrap_or_else(newest_linux_tag));
    if contract_ok && live_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn curl(url: &str) -> String {
    stdout(Command::new("curl").args(["-fsSL", url]))
}

/// The tag GitHub's "latest release" redirect points to.
fn newest_tag() -> String {
    let url = stdout(Command::new("curl").args([
        "-fsSLI",
        "-o",
        "/dev/null",
        "-w",
        "%{url_effective}",
        &format!("https://github.com/{REPO}/releases/latest"),
    ]));
    url.rsplit('/').next().unwrap_or_default().to_string()
}

/// The newest release that ships a Linux x86_64 build. Android-only releases don't.
fn newest_linux_tag() -> String {
    let releases: serde_json::Value = serde_json::from_str(&curl(&format!(
        "https://api.github.com/repos/{REPO}/releases?per_page=30"
    )))
    .expect("GitHub releases");
    releases
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["draft"] == false && r["prerelease"] == false)
        .find(|r| {
            r["assets"].as_array().into_iter().flatten().any(|a| {
                a["name"].as_str().is_some_and(|n| {
                    n.starts_with("nym-vpn-core-v") && n.ends_with("_linux_x86_64.tar.gz")
                })
            })
        })
        .and_then(|r| r["tag_name"].as_str())
        .expect("no NymVPN release with a Linux x86_64 build")
        .to_string()
}

// ---------------------------------------------------------------- source

/// The body of `message NAME { ... }` or `service NAME { ... }`, nested blocks included.
fn block(text: &str, kind: &str, name: &str) -> String {
    let mut out = String::new();
    let mut depth = 0i32;
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if out.is_empty()
            && !(words.len() >= 3 && words[0] == kind && words[1] == name && words[2] == "{")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if depth == 0 {
            break;
        }
    }
    out
}

fn has_line(text: &str, line: &str) -> bool {
    text.lines()
        .any(|l| l.split_whitespace().collect::<Vec<_>>().join(" ") == line)
}

fn contract(report: &mut Report, tag: String) {
    println!("# NymVPN source at {tag}");
    let file = |path: &str| {
        curl(&format!(
            "https://raw.githubusercontent.com/{REPO}/{tag}/{CORE}/{path}"
        ))
    };
    let proto = file("nym-vpn-proto/proto/nym_vpn_service.proto");
    let service = block(&proto, "service", "NymVpnService");
    let checks = [
        ("proto package", proto.clone(), "package nym_vpn_service;"),
        (
            "rpc Info",
            service.clone(),
            "rpc Info(google.protobuf.Empty) returns (InfoResponse) {}",
        ),
        (
            "rpc GetConfig",
            service.clone(),
            "rpc GetConfig(google.protobuf.Empty) returns (GetConfigResponse) {}",
        ),
        (
            "rpc ListenToEvents",
            service,
            "rpc ListenToEvents(google.protobuf.Empty) returns (stream TunnelEvent) {}",
        ),
        (
            "InfoResponse.version",
            block(&proto, "message", "InfoResponse"),
            "string version = 1;",
        ),
        (
            "GetConfigResponse.config",
            block(&proto, "message", "GetConfigResponse"),
            "VpnServiceConfig config = 1;",
        ),
        (
            "VpnServiceConfig.allow_lan",
            block(&proto, "message", "VpnServiceConfig"),
            "bool allow_lan = 4;",
        ),
        (
            "TunnelEvent.config_changed_event",
            block(&proto, "message", "TunnelEvent"),
            "ConfigChangedEvent config_changed_event = 3;",
        ),
        (
            "ConfigChangedEvent.new_config",
            block(&proto, "message", "ConfigChangedEvent"),
            "VpnServiceConfig new_config = 1;",
        ),
    ];
    for (what, text, line) in checks {
        report.check(what, has_line(&text, line));
    }

    let contains = |path: &str, needle: &str| file(path).contains(needle);
    report.check(
        "socket path",
        contains(
            "nym-vpnd/src/command_interface.rs",
            r#""/var/run/nym-vpn.sock""#,
        ),
    );
    let auth = file("nym-ipc/src/auth_result.rs");
    report.check(
        "handshake: client asks with 1",
        auth.contains("Status = 1,"),
    );
    report.check(
        "handshake: daemon accepts with 1",
        auth.contains("Accepted = 1,"),
    );
    report.check(
        "handshake: root is always allowed",
        contains("nym-ipc/src/authentication/linux.rs", "if uid.is_root() {"),
    );
    report.check(
        "systemd unit nym-vpnd.service",
        contains(
            "nym-vpnd/.pkg/aur/nym-vpnd.service",
            "ExecStart=/usr/bin/nym-vpnd",
        ),
    );
}

// ---------------------------------------------------------------- real daemon

fn live(tag: String) -> bool {
    println!("\n# nym-vpnd from {tag}");
    let work = common::temp_dir("nymks-compat");
    let core = format!(
        "nym-vpn-core-v{}_linux_x86_64",
        tag.trim_start_matches("nym-vpn-v")
    );
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    for file in [format!("{core}.tar.gz"), "checksums.txt".into()] {
        run(Command::new("curl")
            .args(["-fsSL", &format!("{base}/{file}"), "-o"])
            .arg(work.join(&file)));
    }
    let sums = fs::read_to_string(work.join("checksums.txt")).unwrap_or_default();
    let line = sums
        .lines()
        .find(|l| l.ends_with(&format!("  {core}.tar.gz")))
        .expect("tarball missing from checksums.txt");
    let mut check = Command::new("sha256sum")
        .args(["--check", "--status"])
        .current_dir(&work)
        .stdin(Stdio::piped())
        .spawn()
        .expect("sha256sum");
    std::io::Write::write_all(
        &mut check.stdin.take().unwrap(),
        format!("{line}\n").as_bytes(),
    )
    .unwrap();
    assert!(
        check.wait().is_ok_and(|s| s.success()),
        "{core}.tar.gz does not match checksums.txt"
    );
    run(Command::new("tar")
        .arg("-xzf")
        .arg(work.join(format!("{core}.tar.gz")))
        .arg("-C")
        .arg(&work));
    let nym = work.join(&core);
    for bin in ["nym-vpnd", "nym-vpnc"] {
        fs::set_permissions(nym.join(bin), fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--mount"])
        .arg(std::env::current_exe().expect("own path"))
        .arg(INNER)
        .arg(&nym)
        .arg(&work)
        .status()
        .expect("unshare");
    let _ = fs::remove_dir_all(&work);
    status.success()
}

/// Runs inside the namespaces, as root of the user namespace.
fn live_inside(nym: &Path, work: &Path) -> ExitCode {
    // nym-vpnd listens on /var/run/nym-vpn.sock.
    run(Command::new("mount").args(["-t", "tmpfs", "tmpfs", "/run"]));
    run(Command::new("ip").args(["link", "set", "lo", "up"]));
    let guard_log = work.join("guard.log");
    let daemon_log = work.join("nym-vpnd.log");
    let check_log = work.join("check.log");
    let mut report = Report::default();

    let start_daemon = || -> Child {
        let log = File::options()
            .create(true)
            .append(true)
            .open(&daemon_log)
            .unwrap();
        let child = Command::new(nym.join("nym-vpnd"))
            .arg("run-with-args")
            .env("NYM_VPND_CONFIG_DIR", work.join("etc"))
            .env("NYM_VPND_DATA_DIR", work.join("data"))
            .env("NYM_VPND_LOG_DIR", work.join("log"))
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("nym-vpnd");
        wait_for(|| Path::new("/var/run/nym-vpn.sock").exists());
        child
    };
    let vpnc = |args: &[&str]| stdout(Command::new(nym.join("nym-vpnc")).args(args));
    let rules = || stdout(Command::new("nft").args(["list", "table", "inet", "nym_killswitch"]));
    let answers = || {
        fs::read_to_string(&guard_log)
            .unwrap_or_default()
            .matches(" answered, ")
            .count()
    };

    let mut daemon = start_daemon();
    report.check(
        "nym-vpnd starts",
        Path::new("/var/run/nym-vpn.sock").exists(),
    );
    let version = vpnc(&["info"])
        .lines()
        .find_map(|l| l.trim().strip_prefix("version: ").map(str::to_string))
        .unwrap_or_default();
    println!("        nym-vpnd {version}");

    let check = Command::new(KS).arg("check").output().expect("check");
    fs::write(&check_log, &check.stdout).unwrap();
    let wanted = format!("ok    nym-vpnd {version} API");
    report.check(
        "nym-killswitch check talks to the daemon",
        String::from_utf8_lossy(&check.stdout)
            .lines()
            .any(|l| l == wanted),
    );

    let mut guard = Command::new(KS)
        .arg("guard")
        .env("NYMKS_CGROUP", common::own_cgroup())
        .env("NYMKS_STATE_DIR", work.join("state"))
        .stderr(File::create(&guard_log).unwrap())
        .spawn()
        .expect("guard");
    report.check(
        "guard reads Allow LAN from nym-vpnd",
        wait_for(|| answers() >= 1),
    );

    vpnc(&["lan", "set", "allow"]);
    report.check(
        "guard follows 'nym-vpnc lan set allow'",
        wait_for(|| rules().contains(r#"comment "LAN""#)),
    );
    vpnc(&["lan", "set", "block"]);
    report.check(
        "guard follows 'nym-vpnc lan set block'",
        wait_for(|| {
            let r = rules();
            !r.is_empty() && !r.contains(r#"comment "LAN""#)
        }),
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = fs::remove_file("/var/run/nym-vpn.sock");
    daemon = start_daemon();
    report.check(
        "guard reconnects after nym-vpnd restarts",
        wait_for(|| answers() >= 2),
    );
    report.check(
        "guard saw no API change",
        !fs::read_to_string(&guard_log)
            .unwrap_or_default()
            .contains("API changed"),
    );

    for child in [&mut guard, &mut daemon] {
        let _ = child.kill();
        let _ = child.wait();
    }
    match report.finish(&[&check_log, &guard_log, &daemon_log]) {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}
