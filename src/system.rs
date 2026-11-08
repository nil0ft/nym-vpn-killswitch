//! What the guard reads from and tells the system: nym-vpnd's tun devices,
//! kernel change notifications, systemd readiness and the saved LAN setting.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::rules::valid_ifname;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Tun devices held open by any process in the cgroup tree at `cgroup`.
///
/// The kernel shows a tun file descriptor's interface in /proc/PID/fdinfo as
/// "iff:\tNAME". Reading another root process's fdinfo needs CAP_SYS_PTRACE.
pub fn tunnels_held_by(cgroup: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let me = std::process::id().to_string();
    for pid in pids(cgroup) {
        if pid == me {
            continue;
        }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fdinfo")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(info) = fs::read_to_string(fd.path()) else {
                continue;
            };
            if let Some(name) = info.lines().find_map(|l| l.strip_prefix("iff:"))
                && valid_ifname(name.trim())
            {
                names.insert(name.trim().to_string());
            }
        }
    }
    names
}

fn pids(cgroup: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(procs) = fs::read_to_string(cgroup.join("cgroup.procs")) {
        out.extend(procs.lines().map(str::to_string));
    }
    if let Ok(children) = fs::read_dir(cgroup) {
        for child in children.flatten() {
            if child.file_type().is_ok_and(|t| t.is_dir()) {
                out.extend(pids(&child.path()));
            }
        }
    }
    out
}

/// A netlink socket subscribed to kernel notifications. The guard only cares
/// that something changed, never what.
pub struct Events(AsyncFd<OwnedFd>);

/// Network interfaces appearing, disappearing or changing.
pub const ROUTE_LINK: (i32, u32) = (libc::NETLINK_ROUTE, libc::RTNLGRP_LINK);
/// Any change to the nftables ruleset.
pub const NFTABLES: (i32, u32) = (libc::NETLINK_NETFILTER, libc::NFNLGRP_NFTABLES as u32);

impl Events {
    pub fn subscribe((protocol, group): (i32, u32)) -> io::Result<Self> {
        // SAFETY: plain socket calls; the fd is owned right after creation.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            if libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_nl>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                (&raw const group).cast(),
                size_of::<u32>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            // The OwnedFd moves into the AsyncFd and stays open for its whole life.
            Ok(Events(AsyncFd::register_with_interest(
                fd,
                Interest::READABLE,
            )?))
        }
    }

    /// Wait for notifications and drain them.
    pub async fn changed(&self) -> io::Result<()> {
        let mut buf = [0u8; 8192];
        let mut guard = self.0.readable().await?;
        loop {
            // SAFETY: reading into a local buffer of the given size.
            let n =
                unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n >= 0 {
                continue;
            }
            match io::Error::last_os_error() {
                e if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    return Ok(());
                }
                // The kernel dropped notifications; that still means "changed".
                e if e.raw_os_error() == Some(libc::ENOBUFS) => continue,
                e => return Err(e),
            }
        }
    }
}

/// Tell systemd the guard is up (Type=notify).
pub fn notify_ready(status: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let msg = format!("READY=1\nSTATUS={status}\n");
    let send = || -> io::Result<()> {
        let sock = std::os::unix::net::UnixDatagram::unbound()?;
        let path = path.as_encoded_bytes();
        if let Some(name) = path.strip_prefix(b"@") {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(msg.as_bytes(), &addr)?;
        } else {
            sock.send_to(msg.as_bytes(), Path::new(std::ffi::OsStr::from_bytes(path)))?;
        }
        Ok(())
    };
    if let Err(err) = send() {
        eprintln!("could not notify systemd: {err}");
    }
}

/// The last LAN setting nym-vpnd reported, kept across reboots so the LAN works
/// before the daemon answers.
pub struct SavedLan(PathBuf);

impl SavedLan {
    pub fn new(state_dir: PathBuf) -> Self {
        SavedLan(state_dir.join("allow-lan"))
    }

    pub fn load(&self) -> bool {
        fs::read_to_string(&self.0).is_ok_and(|s| s.trim() == "yes")
    }

    pub fn store(&self, allow: bool) {
        let tmp = self.0.with_extension("tmp");
        let result = fs::write(&tmp, if allow { "yes\n" } else { "no\n" })
            .and_then(|()| fs::rename(&tmp, &self.0));
        if let Err(err) = result {
            eprintln!(
                "could not save the LAN setting to {}: {err}",
                self.0.display()
            );
        }
    }
}
