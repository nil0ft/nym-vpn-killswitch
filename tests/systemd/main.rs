//! Runs the shipped unit files on the real service manager and checks that
//! they fit together: the guard finds the slice systemd made, the nym-vpnd
//! drop-in moves nym-vpnd into it, and the hardened guard still sees the tun
//! device nym-vpnd holds. A stand-in plays nym-vpnd, and both units get a
//! private network namespace, so the host keeps its network.
//!
//! Needs root and systemd, as in CI; skipped otherwise. Refuses to run next to
//! an installed nym-killswitch or nym-vpnd.

#[path = "../common/mod.rs"]
mod common;
#[path = "../netns/helpers.rs"]
mod helpers;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::SystemTime;

use common::{Report, need, stdout, succeeds, wait_for};

const KS: &str = env!("CARGO_BIN_EXE_nym-killswitch");
const UNITS: &str = "/run/systemd/system";
const STATE: &str = "/var/lib/nym-killswitch";
const GUARD: &str = "nym-killswitch.service";
const SLICE: &str = "nym-killswitch.slice";
const DAEMON: &str = "nym-vpnd.service";
const TUN: &str = "nymtun0";

fn main() -> ExitCode {
    if let Some(code) = helpers::dispatch() {
        return code;
    }
    if !common::is_root() || !Path::new("/run/systemd/system").is_dir() {
        println!("skipped: needs root and systemd");
        return ExitCode::SUCCESS;
    }
    need(&["systemctl", "journalctl", "nft", "nsenter"]);
    for unit in [GUARD, DAEMON] {
        if show(unit, "LoadState") != "not-found" {
            println!("skipped: {unit} is installed on this machine");
            return ExitCode::SUCCESS;
        }
    }
    if Path::new(STATE).exists() {
        println!("skipped: {STATE} exists on this machine");
        return ExitCode::SUCCESS;
    }
    let since = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let units = Units::install();
    let mut report = Report::default();
    check(&mut report);
    let log = units.tmp.join("journal.log");
    let journal = stdout(
        Command::new("journalctl")
            .args(["--no-pager", "-o", "cat", "-u", GUARD, "-u", DAEMON])
            .arg(format!("--since=@{since}")),
    );
    fs::write(&log, journal).unwrap();
    match report.finish(&[&log]) {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}

fn check(report: &mut Report) {
    report.check(
        "guard starts and tells systemd it is ready",
        succeeds(Command::new("systemctl").args(["start", GUARD])),
    );
    let status = show(GUARD, "StatusText");
    report.check(
        &format!("guard reports the killswitch on ({status})"),
        status.starts_with("on, "),
    );

    let slice = show(SLICE, "ControlGroup");
    let pid = show(GUARD, "MainPID");
    let in_guard_netns = |program: &str| {
        let mut cmd = Command::new("nsenter");
        cmd.args(["-n", "-t", &pid, program]);
        cmd
    };
    let rules = || stdout(in_guard_netns("nft").args(["list", "table", "inet", "nym_killswitch"]));
    report.check(
        &format!("rules let {slice} through"),
        rules().contains(&format!(
            "\"{}\" accept comment \"nym-vpnd\"",
            slice.trim_start_matches('/')
        )),
    );

    report.check(
        "nym-vpnd starts",
        succeeds(Command::new("systemctl").args(["start", DAEMON])),
    );
    report.check(
        "drop-in runs nym-vpnd inside the slice",
        show(DAEMON, "ControlGroup").starts_with(&format!("{slice}/")),
    );
    report.check(
        "guard finds the tun device nym-vpnd holds",
        wait_for(|| rules().contains(TUN)),
    );
    report.check(
        "status says nym-vpnd is allowed through",
        stdout(in_guard_netns(KS).arg("status")).contains("allowed through"),
    );
}

fn show(unit: &str, property: &str) -> String {
    stdout(Command::new("systemctl").args(["show", "-p", property, "--value", unit]))
        .trim()
        .to_string()
}

/// The shipped units plus test drop-ins under /run, removed again on drop.
struct Units {
    tmp: PathBuf,
}

impl Units {
    fn install() -> Self {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd");
        let tmp = common::temp_dir("nymks-systemd");
        // ProtectHome hides a checkout under /home from the guard.
        let bin = tmp.join("nym-killswitch");
        fs::copy(KS, &bin).expect("copy nym-killswitch");
        let units = Units { tmp };

        let guard = fs::read_to_string(repo.join(GUARD)).expect("read unit");
        write(GUARD, &guard.replace("@BIN@", bin.to_str().unwrap()));
        fs::copy(repo.join(SLICE), Path::new(UNITS).join(SLICE)).expect("copy slice");
        write(
            &format!("{GUARD}.d/test.conf"),
            "[Service]\nPrivateNetwork=yes\nRestart=no\n",
        );
        let exe = std::env::current_exe().unwrap();
        write(
            DAEMON,
            &format!(
                "[Unit]\nJoinsNamespaceOf={GUARD}\n\n[Service]\nPrivateNetwork=yes\n\
                 ExecStart={} {} tunhold {TUN} /dev/null\n",
                exe.display(),
                helpers::ARG
            ),
        );
        let dropin = "nym-vpnd.service.d/50-killswitch.conf";
        write(dropin, &fs::read_to_string(repo.join(dropin)).unwrap());
        systemctl(&["daemon-reload"]);
        units
    }
}

impl Drop for Units {
    fn drop(&mut self) {
        systemctl(&["stop", DAEMON, GUARD, SLICE]);
        systemctl(&["reset-failed", DAEMON, GUARD]);
        for path in [
            GUARD,
            SLICE,
            DAEMON,
            &format!("{GUARD}.d"),
            &format!("{DAEMON}.d"),
        ] {
            let path = Path::new(UNITS).join(path);
            let _ = fs::remove_dir_all(&path).or_else(|_| fs::remove_file(&path));
        }
        systemctl(&["daemon-reload"]);
        let _ = fs::remove_dir_all(STATE);
        let _ = fs::remove_dir_all(&self.tmp);
    }
}

fn write(unit: &str, text: &str) {
    let path = Path::new(UNITS).join(unit);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

fn systemctl(args: &[&str]) {
    let _ = succeeds(Command::new("systemctl").args(args));
}
