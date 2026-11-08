//! Small programs the test runs inside its namespaces. They are this same test
//! binary, started as `<test> __helper <name> <args>`.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};
use std::time::Duration;

pub const ARG: &str = "__helper";

/// Run a helper if the command line asks for one.
pub fn dispatch() -> Option<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some(ARG) {
        return None;
    }
    let rest = &args[2..];
    Some(match args[1].as_str() {
        "in-cgroup" => in_cgroup(rest),
        "serve" => serve(rest),
        "probe" => {
            println!(
                "{}",
                probe(&rest[0], &rest[1], rest[2].parse().expect("port"))
            );
            ExitCode::SUCCESS
        }
        "tunhold" => tunhold(&rest[0], &rest[1]),
        other => panic!("unknown helper {other}"),
    })
}

/// Join the cgroup at args[0], then become the command in args[1..].
fn in_cgroup(args: &[String]) -> ExitCode {
    std::fs::write(
        format!("{}/cgroup.procs", args[0]),
        std::process::id().to_string(),
    )
    .expect("join cgroup");
    let err = Command::new(&args[1]).args(&args[2..]).exec();
    panic!("exec {}: {err}", args[1]);
}

/// Answer "pong" on TCP and UDP, IPv4 and IPv6, on every given port.
fn serve(ports: &[String]) -> ExitCode {
    for port in ports {
        let addr: SocketAddr = format!("[::]:{port}").parse().unwrap();
        let tcp = TcpListener::bind(addr).expect("bind tcp");
        let udp = UdpSocket::bind(addr).expect("bind udp");
        std::thread::spawn(move || {
            for mut conn in tcp.incoming().flatten() {
                let _ = conn.write_all(b"pong");
            }
        });
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            while let Ok((_, peer)) = udp.recv_from(&mut buf) {
                let _ = udp.send_to(b"pong", peer);
            }
        });
    }
    loop {
        std::thread::park();
    }
}

/// "open" when the server answered, "blocked" when the local firewall refused,
/// "timeout" when nothing came back.
pub fn probe(proto: &str, host: &str, port: u16) -> String {
    let addr = SocketAddr::new(host.parse().expect("ip"), port);
    let wait = Duration::from_secs(2);
    let mut buf = [0u8; 16];
    let answer = if proto == "tcp" {
        TcpStream::connect_timeout(&addr, wait).and_then(|mut s| {
            s.set_read_timeout(Some(wait))?;
            s.read(&mut buf)
        })
    } else {
        let local = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        UdpSocket::bind(local).and_then(|s| {
            s.set_read_timeout(Some(wait))?;
            s.send_to(b"ping", addr)?;
            s.recv(&mut buf)
        })
    };
    match answer {
        Ok(n) if &buf[..n] == b"pong" => "open".into(),
        Ok(_) => "garbage".into(),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            "timeout".into()
        }
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::EHOSTUNREACH)
            ) =>
        {
            "blocked".into()
        }
        Err(e) => e.to_string(),
    }
}

/// Hold tun device args[0] like a VPN client and log every IPv4 packet routed
/// into it to args[1] as "src>dst:port".
fn tunhold(name: &str, log: &str) -> ExitCode {
    // SAFETY: open() of a fixed path; the fd is owned right away.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "open /dev/net/tun: {}", io::Error::last_os_error());
    // SAFETY: fd was just opened and nothing else owns it.
    let tun = unsafe { OwnedFd::from_raw_fd(fd) };

    // struct ifreq: the name, then the flags (IFF_TUN | IFF_NO_PI).
    let mut ifreq = [0u8; 40];
    ifreq[..name.len()].copy_from_slice(name.as_bytes());
    ifreq[16..18].copy_from_slice(&(0x0001u16 | 0x1000).to_ne_bytes());
    // SAFETY: TUNSETIFF reads and writes a struct ifreq, which fits in 40 bytes.
    let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF, ifreq.as_mut_ptr()) };
    assert!(rc == 0, "TUNSETIFF: {}", io::Error::last_os_error());

    let mut out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .expect("log");
    let mut tun = std::fs::File::from(tun);
    let mut pkt = [0u8; 65536];
    loop {
        let n = tun.read(&mut pkt).expect("read tun");
        if n >= 24 && pkt[0] >> 4 == 4 {
            let ihl = usize::from(pkt[0] & 15) * 4;
            let port = if matches!(pkt[9], 6 | 17) {
                u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]])
            } else {
                0
            };
            let ip = |o: usize| format!("{}.{}.{}.{}", pkt[o], pkt[o + 1], pkt[o + 2], pkt[o + 3]);
            writeln!(out, "{}>{}:{port}", ip(12), ip(16)).expect("write log");
        }
    }
}
