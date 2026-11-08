//! Leak test for nym-killswitch. Needs no root and leaves the host untouched.
//!
//! It builds a fake machine in throwaway user and network namespaces and runs the
//! real guard on it:
//!
//!   host  eth0     "physical" uplink to a fake internet (198.18.0.5, 2001:db8:ffff::5)
//!                  and a fake LAN (192.168.77.2)
//!         tun7     a real tun device held by a process in the "nym" cgroup, which
//!                  plays nym-vpnd; packets routed to 203.0.113.0/24 end up there
//!         tun8     a tun device held by some other process
//!         docker0  bridge to a container (172.17.0.2) that routes through the host
//!
//! mock.rs stands in for nym-vpnd's API and its Allow LAN setting.
//!
//! Needs nft, iproute2 and util-linux, and either root (as in CI) or a systemd
//! user session to hand out a cgroup.

#[path = "../common/mod.rs"]
mod common;
mod helpers;
mod mock;

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use common::{Report, need, run, stdout, succeeds, wait_for};
use helpers::ARG;
use mock::MockDaemon;

const KS: &str = env!("CARGO_BIN_EXE_nym-killswitch");
const TABLE: &str = "nym_killswitch";
const INET4: &str = "198.18.0.5";
const INET6: &str = "2001:db8:ffff::5";
const TUN4: &str = "203.0.113.5";
const ROGUE4: &str = "198.18.200.5";
const LAN4: &str = "192.168.77.2";
const CTR4: &str = "172.17.0.2";

fn main() -> ExitCode {
    if let Some(code) = helpers::dispatch() {
        return code;
    }
    need(&["nft", "ip", "unshare", "nsenter"]);
    let own = enter_cgroup();
    let mut test = Test::setup(own);
    test.run();
    test.finish()
}

/// Move into a cgroup the test may create children in: a fresh one under the
/// root when running as root (as in CI), a delegated systemd user scope
/// otherwise. Returns the cgroup to remove at the end, if the test made it.
fn enter_cgroup() -> Option<PathBuf> {
    if std::env::var_os("NYMKS_TEST_SCOPE").is_some() {
        return None;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        let own = PathBuf::from(format!("/sys/fs/cgroup/nymks-test.{}", std::process::id()));
        fs::create_dir(&own).expect("create test cgroup");
        fs::write(own.join("cgroup.procs"), std::process::id().to_string()).expect("join it");
        return Some(own);
    }
    let err = Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"])
        .arg(std::env::current_exe().expect("own path"))
        .args(std::env::args_os().skip(1))
        .env("NYMKS_TEST_SCOPE", "1")
        .exec();
    panic!("systemd-run: {err}");
}

fn nsenter(pid: u32, program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new("nsenter");
    cmd.args(["--preserve-credentials", "-U", "-n", "-t"])
        .arg(pid.to_string())
        .arg(program);
    cmd
}

/// Start `sleep infinity` through `cmd`, which unshares a namespace, and wait
/// until the namespace is ready.
fn hold_namespace(mut cmd: Command) -> Child {
    let child = cmd.args(["sleep", "infinity"]).spawn().expect("unshare");
    let comm = format!("/proc/{}/comm", child.id());
    assert!(
        wait_for(|| fs::read_to_string(&comm).is_ok_and(|c| c.trim() == "sleep")),
        "namespace did not come up"
    );
    child
}

#[derive(Clone, Copy)]
enum At {
    /// An app on the host.
    Host,
    /// nym-vpnd on the host, inside the cgroup the killswitch lets through.
    Nym,
    /// The fake internet and LAN.
    Wan,
    /// The container behind docker0.
    Container,
}
use At::*;

struct Test {
    exe: PathBuf,
    tmp: PathBuf,
    cgroup: String,
    own_cgroup: Option<PathBuf>,
    host: u32,
    wan: u32,
    ctr: u32,
    children: Vec<Child>,
    tun7: Option<Child>,
    guard: Option<Child>,
    mock: Option<MockDaemon>,
    report: Report,
}

impl Test {
    fn setup(own_cgroup: Option<PathBuf>) -> Self {
        let cgroup = common::own_cgroup();
        let cgdir = Path::new("/sys/fs/cgroup").join(&cgroup);
        fs::create_dir(cgdir.join("test")).expect("create test cgroup");
        fs::create_dir(cgdir.join("nym")).expect("create nym cgroup");
        fs::write(
            cgdir.join("test/cgroup.procs"),
            std::process::id().to_string(),
        )
        .expect("move");

        let tmp = common::temp_dir("nymks-netns");
        let mut unshare = Command::new("unshare");
        unshare.args(["--user", "--map-root-user", "--net"]);
        let host = hold_namespace(unshare);
        let net_ns = || {
            let mut cmd = nsenter(host.id(), "unshare");
            cmd.arg("--net");
            cmd
        };
        let wan = hold_namespace(net_ns());
        let ctr = hold_namespace(net_ns());

        let mut test = Test {
            exe: std::env::current_exe().expect("own path"),
            mock: Some(MockDaemon::start(&tmp.join("nym.sock"), false, false)),
            tmp,
            cgroup,
            own_cgroup,
            host: host.id(),
            wan: wan.id(),
            ctr: ctr.id(),
            children: vec![host, wan, ctr],
            tun7: None,
            guard: None,
            report: Report::default(),
        };
        test.build_network();
        test
    }

    fn cmd(&self, at: At, program: impl AsRef<OsStr>) -> Command {
        match at {
            Host => nsenter(self.host, program),
            Wan => nsenter(self.wan, program),
            Container => nsenter(self.ctr, program),
            Nym => {
                let mut cmd = Command::new(&self.exe);
                cmd.args([ARG, "in-cgroup"])
                    .arg(self.cgdir().join("nym"))
                    .arg("nsenter")
                    .args(["--preserve-credentials", "-U", "-n", "-t"])
                    .arg(self.host.to_string())
                    .arg(program);
                cmd
            }
        }
    }

    fn cgdir(&self) -> PathBuf {
        Path::new("/sys/fs/cgroup").join(&self.cgroup)
    }

    fn ip(&self, at: At, args: &str) {
        run(self.cmd(at, "ip").args(args.split_whitespace()));
    }

    fn helper(&self, at: At, args: &[&str]) -> Command {
        let mut cmd = self.cmd(at, &self.exe);
        cmd.arg(ARG).args(args).stdin(Stdio::null());
        cmd
    }

    fn build_network(&mut self) {
        for at in [Host, Wan, Container] {
            self.ip(at, "link set lo up");
        }
        self.ip(
            Host,
            &format!("link add eth0 type veth peer name wan netns {}", self.wan),
        );
        self.ip(
            Host,
            &format!(
                "link add docker0 type veth peer name eth0 netns {}",
                self.ctr
            ),
        );

        self.ip(Host, "addr add 198.51.100.1/24 dev eth0");
        self.ip(Host, "addr add 192.168.77.1/24 dev eth0");
        self.ip(Host, "addr add 2001:db8::1/64 dev eth0 nodad");
        self.ip(Host, "addr add 172.17.0.1/16 dev docker0");
        self.ip(Host, "link set eth0 up");
        self.ip(Host, "link set docker0 up");
        self.ip(Host, "route add default via 198.51.100.2");
        self.ip(Host, "-6 route add default via 2001:db8::2");
        run(self
            .cmd(Host, "sysctl")
            .args(["-qw", "net.ipv4.ip_forward=1"]));

        self.ip(Wan, "addr add 198.51.100.2/24 dev wan");
        self.ip(Wan, &format!("addr add {LAN4}/24 dev wan"));
        self.ip(Wan, "addr add 2001:db8::2/64 dev wan nodad");
        self.ip(Wan, &format!("addr add {INET4}/32 dev lo"));
        self.ip(Wan, &format!("addr add {INET6}/128 dev lo"));
        self.ip(Wan, "link set wan up");
        self.ip(Wan, "route add 172.17.0.0/16 via 198.51.100.1");

        self.ip(Container, &format!("addr add {CTR4}/16 dev eth0"));
        self.ip(Container, "link set eth0 up");
        self.ip(Container, "route add default via 172.17.0.1");

        for (at, ports) in [
            (Wan, &["8000", "53"][..]),
            (Host, &["9000"]),
            (Container, &["9000"]),
        ] {
            let mut args = vec!["serve"];
            args.extend(ports);
            self.children
                .push(self.helper(at, &args).spawn().expect("server"));
        }

        // The "VPN tunnel": a tun device nym-vpnd holds, and one it doesn't.
        let log7 = self.tmp.join("tun7.log");
        let log8 = self.tmp.join("tun8.log");
        let tun7 = self
            .helper(Nym, &["tunhold", "tun7", log7.to_str().unwrap()])
            .spawn();
        self.tun7 = Some(tun7.expect("tun7"));
        let tun8 = self
            .helper(Host, &["tunhold", "tun8", log8.to_str().unwrap()])
            .spawn();
        self.children.push(tun8.expect("tun8"));
        assert!(
            wait_for(|| ["tun7", "tun8"]
                .iter()
                .all(|t| succeeds(self.cmd(Host, "ip").args(["link", "show", t])))),
            "tun devices did not come up"
        );
        self.ip(Host, "addr add 10.9.0.1/32 dev tun7");
        self.ip(Host, "addr add 10.9.0.2/32 dev tun8");
        self.ip(Host, "link set tun7 up");
        self.ip(Host, "link set tun8 up");
        self.ip(Host, "route add 203.0.113.0/24 dev tun7");
        self.ip(Host, "route add 198.18.200.0/24 dev tun8");
        std::thread::sleep(Duration::from_millis(500));
    }

    // ------------------------------------------------------------ probes

    fn probe(&self, at: At, proto: &str, host: &str, port: u16) -> String {
        let got = stdout(&mut self.helper(at, &["probe", proto, host, &port.to_string()]));
        match got.trim() {
            "" => "error".into(),
            got => got.into(),
        }
    }

    fn check(&mut self, want: &str, what: &str, at: At, proto: &str, host: &str, port: u16) {
        let got = self.probe(at, proto, host, port);
        self.report.expect(what, want, &got);
    }

    fn assert(&mut self, what: &str, ok: bool) {
        self.report.check(what, ok);
    }

    /// Send UDP into the tunnel and check that the tun holder received it.
    fn via_tunnel(&self, at: At, port: u16) -> bool {
        self.probe(at, "udp", TUN4, port);
        let log = self.tmp.join("tun7.log");
        wait_for(|| fs::read_to_string(&log).is_ok_and(|l| l.contains(&format!(":{port}\n"))))
    }

    fn nft(&self, args: &str) -> Command {
        let mut cmd = self.cmd(Host, "nft");
        cmd.args(args.split_whitespace());
        cmd
    }

    fn listed(&self) -> Option<String> {
        let out = self
            .nft(&format!("list table inet {TABLE}"))
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn lan_rules(&self) -> bool {
        self.listed()
            .is_some_and(|l| l.contains(r#"comment "LAN""#))
    }

    fn no_lan_rules(&self) -> bool {
        self.listed()
            .is_some_and(|l| !l.contains(r#"comment "LAN""#))
    }

    fn in_tunnel_set(&self, name: &str) -> bool {
        let set = stdout(&mut self.nft(&format!("list set inet {TABLE} nym_tunnels")));
        set.contains("elements = {") && set.contains(&format!("\"{name}\""))
    }

    fn guard_log(&self) -> String {
        fs::read_to_string(self.tmp.join("guard.log")).unwrap_or_default()
    }

    // ------------------------------------------------------------ guard

    fn start_guard(&mut self, env: &[(&str, &str)]) -> bool {
        let log = File::create(self.tmp.join("guard.log")).expect("guard log");
        let mut child = self
            .cmd(Nym, KS)
            .arg("guard")
            .env("NYMKS_CGROUP", format!("{}/nym", self.cgroup))
            .env("NYMKS_STATE_DIR", self.tmp.join("state"))
            .env("NYMKS_NYM_SOCKET", self.tmp.join("nym.sock"))
            .envs(env.iter().copied())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("guard");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.guard_log().contains("killswitch on") {
                self.guard = Some(child);
                return true;
            }
            if child.try_wait().is_ok_and(|s| s.is_some()) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.guard = Some(child);
        false
    }

    /// What `systemctl stop` does to the guard.
    fn stop_guard(&mut self) {
        if let Some(mut guard) = self.guard.take() {
            // SAFETY: plain kill(2) on our own child.
            unsafe { libc::kill(guard.id() as i32, libc::SIGTERM) };
            let _ = guard.wait();
        }
    }

    fn set_lan(&self, allow: bool) {
        self.mock.as_ref().expect("mock running").set_lan(allow);
    }

    // ------------------------------------------------------------ the tests

    fn run(&mut self) {
        println!("# without the killswitch");
        self.check("open", "the network works", Host, "tcp", INET4, 8000);
        self.check(
            "open",
            "a container reaches the internet through the host",
            Container,
            "tcp",
            INET4,
            8000,
        );

        println!("# killswitch on, NymVPN's Allow LAN off");
        let started = self.start_guard(&[]);
        self.assert("guard starts", started);
        let locked = self.guard_log().contains("locked");
        println!("        {}", if locked { "locked" } else { "watched" });
        self.check("blocked", "app -> internet, TCP", Host, "tcp", INET4, 8000);
        self.check("blocked", "app -> internet, UDP", Host, "udp", INET4, 8000);
        self.check(
            "blocked",
            "app -> internet, IPv6 TCP",
            Host,
            "tcp",
            INET6,
            8000,
        );
        self.check(
            "blocked",
            "app -> internet, IPv6 UDP",
            Host,
            "udp",
            INET6,
            8000,
        );
        self.check("blocked", "app -> DNS server", Host, "udp", INET4, 53);
        self.check("open", "nym-vpnd -> internet, TCP", Nym, "tcp", INET4, 8000);
        self.check("open", "nym-vpnd -> internet, UDP", Nym, "udp", INET4, 8000);
        self.check(
            "open",
            "nym-vpnd -> internet, IPv6 UDP",
            Nym,
            "udp",
            INET6,
            8000,
        );
        let ok = wait_for(|| self.in_tunnel_set("tun7"));
        self.assert("tun device held by nym-vpnd is allowed", ok);
        let ok = !self.in_tunnel_set("tun8");
        self.assert("tun device held by another process is not", ok);
        let ok = self.via_tunnel(Host, 7001);
        self.assert("app -> tunnel", ok);
        self.check(
            "blocked",
            "app -> other process's tun device",
            Host,
            "udp",
            ROGUE4,
            7002,
        );
        self.check("blocked", "app -> LAN", Host, "tcp", LAN4, 8000);
        self.check("blocked", "app -> container", Host, "tcp", CTR4, 9000);
        // The host's reject message to the container is itself blocked, so the
        // container waits instead of getting an error.
        self.check(
            "timeout",
            "container -> internet (forwarded)",
            Container,
            "tcp",
            INET4,
            8000,
        );
        let ok = self.via_tunnel(Container, 7003);
        self.assert("container -> tunnel (forwarded)", ok);
        self.check(
            "timeout",
            "internet -> listening app",
            Wan,
            "tcp",
            "198.51.100.1",
            9000,
        );

        println!("# LAN follows NymVPN's setting");
        self.set_lan(true);
        let ok = wait_for(|| self.lan_rules());
        self.assert("Allow LAN on in NymVPN opens the LAN", ok);
        self.check("open", "app -> LAN", Host, "tcp", LAN4, 8000);
        self.check("blocked", "app -> DNS on the LAN", Host, "udp", LAN4, 53);
        self.check("blocked", "app -> internet", Host, "tcp", INET4, 8000);
        self.check(
            "open",
            "app -> container (private range)",
            Host,
            "tcp",
            CTR4,
            9000,
        );
        let ok = self.in_tunnel_set("tun7");
        self.assert("tunnel set survives the rebuild", ok);
        self.set_lan(false);
        let ok = wait_for(|| self.no_lan_rules());
        self.assert("Allow LAN off in NymVPN closes it again", ok);
        self.check("blocked", "app -> LAN", Host, "tcp", LAN4, 8000);

        println!("# tampering");
        if locked {
            let ok = !succeeds(&mut self.nft(&format!("delete table inet {TABLE}")));
            self.assert("other processes can't delete the table", ok);
        }
        run(&mut self.nft("flush ruleset"));
        std::thread::sleep(Duration::from_millis(500));
        let ok = self.listed().is_some();
        self.assert("table survives 'nft flush ruleset'", ok);
        self.check(
            "blocked",
            "app -> internet after flush",
            Host,
            "tcp",
            INET4,
            8000,
        );
        self.stop_guard();
        let ok = self.listed().is_some();
        self.assert("table stays loaded when the guard dies", ok);
        self.check(
            "blocked",
            "app -> internet without a guard",
            Host,
            "tcp",
            INET4,
            8000,
        );

        println!("# nym-vpnd down");
        self.set_lan(true);
        let ok = self.start_guard(&[]);
        self.assert("guard takes over the old table", ok);
        let ok = wait_for(|| self.lan_rules());
        self.assert("picks up Allow LAN from nym-vpnd", ok);
        self.mock = None;
        let ok = wait_for(|| self.guard_log().contains("nym-vpnd not reachable"));
        self.assert("guard notices nym-vpnd crashing", ok);
        let ok = !self.guard_log().contains("API changed");
        self.assert("a crash is not reported as an API change", ok);
        self.stop_guard();
        let ok = self.start_guard(&[]);
        self.assert("guard starts without nym-vpnd", ok);
        let ok = self.lan_rules();
        self.assert("uses the last Allow LAN value it saw", ok);
        self.check("open", "app -> LAN", Host, "tcp", LAN4, 8000);
        self.stop_guard();
        let _ = fs::remove_dir_all(self.tmp.join("state"));
        let ok = self.start_guard(&[]);
        self.assert("guard starts with nothing saved", ok);
        let ok = self.no_lan_rules();
        self.assert("blocks the LAN when it never heard from nym-vpnd", ok);
        self.stop_guard();

        println!("# NymVPN release with a changed API");
        self.mock = Some(MockDaemon::start(&self.tmp.join("nym.sock"), true, true));
        let ok = self.start_guard(&[]);
        self.assert("guard starts", ok);
        let ok = wait_for(|| self.guard_log().contains("API changed"));
        self.assert("guard reports the API change", ok);
        let ok = self.no_lan_rules();
        self.assert("LAN stays as it was instead of following NymVPN", ok);
        self.check("blocked", "app -> internet", Host, "tcp", INET4, 8000);
        self.stop_guard();
        self.mock = None;

        println!("# watch mode (kernels before 6.9)");
        let ok = self.start_guard(&[("NYMKS_LOCK", "no")]);
        self.assert("guard starts in watch mode", ok);
        let ok = self.guard_log().contains("watched");
        self.assert("watch mode is used", ok);
        run(&mut self.nft("flush ruleset"));
        let ok = wait_for(|| self.listed().is_some());
        self.assert("guard restores the table after 'nft flush ruleset'", ok);
        self.check(
            "blocked",
            "app -> internet after restore",
            Host,
            "tcp",
            INET4,
            8000,
        );
        self.check(
            "open",
            "nym-vpnd -> internet after restore",
            Nym,
            "tcp",
            INET4,
            8000,
        );
        let ok = self.in_tunnel_set("tun7");
        self.assert("tunnel set restored", ok);
        self.stop_guard();

        println!("# tunnel closes");
        let ok = self.start_guard(&[]);
        self.assert("guard starts", ok);
        if let Some(mut tun7) = self.tun7.take() {
            let _ = tun7.kill();
            let _ = tun7.wait();
        }
        let ok = wait_for(|| self.listed().is_some() && !self.in_tunnel_set("tun7"));
        self.assert("closed tun device leaves the tunnel set", ok);
        self.stop_guard();

        println!("# broken setup fails closed");
        let _ = succeeds(&mut self.nft(&format!("delete table inet {TABLE}")));
        let ok = !self.start_guard(&[("NYMKS_CGROUP", "no/such/cgroup")]);
        self.assert("guard refuses a missing cgroup", ok);
        let ok = self.listed().is_some_and(|l| l.contains("emergency block"));
        self.assert("emergency block is loaded", ok);
        self.check("blocked", "app -> internet", Host, "tcp", INET4, 8000);
        self.check("blocked", "nym-vpnd -> internet", Nym, "tcp", INET4, 8000);
        self.check("blocked", "app -> tunnel address", Host, "udp", TUN4, 7004);
    }

    fn finish(mut self) -> ExitCode {
        let report = std::mem::take(&mut self.report);
        match report.finish(&[&self.tmp.join("guard.log")]) {
            true => ExitCode::SUCCESS,
            false => ExitCode::FAILURE,
        }
    }
}

impl Drop for Test {
    fn drop(&mut self) {
        self.stop_guard();
        self.mock = None;
        for mut child in self.tun7.take().into_iter().chain(self.children.drain(..)) {
            let _ = child.kill();
            let _ = child.wait();
        }
        let cgdir = self.cgdir();
        let _ = fs::write(cgdir.join("nym/cgroup.kill"), "1");
        while fs::read_to_string(cgdir.join("nym/cgroup.procs")).is_ok_and(|p| !p.trim().is_empty())
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = fs::remove_dir(cgdir.join("nym"));
        if let Some(own) = &self.own_cgroup {
            let _ = fs::write(
                "/sys/fs/cgroup/cgroup.procs",
                std::process::id().to_string(),
            );
            let _ = fs::remove_dir(own.join("test"));
            let _ = fs::remove_dir(own);
        }
        let _ = fs::remove_dir_all(&self.tmp);
    }
}
