//! Shared by the namespace tests: pass/fail reporting and process helpers.
#![allow(dead_code)] // each test binary uses a different subset

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Prints one line per check and the totals, like a small TAP report.
#[derive(Default)]
pub struct Report {
    passed: u32,
    failed: u32,
}

impl Report {
    pub fn check(&mut self, what: &str, ok: bool) {
        if ok {
            self.passed += 1;
            println!("ok      {what}");
        } else {
            self.failed += 1;
            println!("FAILED  {what}");
        }
    }

    pub fn expect(&mut self, what: &str, want: &str, got: &str) {
        if want == got {
            self.check(what, true);
        } else {
            self.failed += 1;
            println!("FAILED  {what}: expected {want}, got {got}");
        }
    }

    /// Print the totals, and on failure the end of each log. True when all passed.
    pub fn finish(self, logs: &[&Path]) -> bool {
        println!("\n{} passed, {} failed", self.passed, self.failed);
        if self.failed == 0 {
            return true;
        }
        for log in logs {
            let text = std::fs::read_to_string(log).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            println!("--- {} (last 40 lines)", log.display());
            println!("{}", lines[lines.len().saturating_sub(40)..].join("\n"));
        }
        false
    }
}

/// Retry for up to ten seconds.
pub fn wait_for(mut ok: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ok() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Run quietly; true on exit status 0.
pub fn succeeds(cmd: &mut Command) -> bool {
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run a setup step that has to work.
pub fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Stdout of a command, empty when it fails.
pub fn stdout(cmd: &mut Command) -> String {
    cmd.stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Fail early with a clear message when a tool is missing.
pub fn need(tools: &[&str]) {
    for tool in tools {
        let found = std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()));
        assert!(found, "this test needs {tool}");
    }
}

/// This process's cgroup, relative to the cgroup2 root.
pub fn own_cgroup() -> String {
    std::fs::read_to_string("/proc/self/cgroup")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string()
}

/// A fresh empty directory under the system temp dir.
pub fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("{name}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}
