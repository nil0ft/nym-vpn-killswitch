//! nym-killswitch: no packet leaves this machine unless it goes through NymVPN.

mod cli;
mod guard;
mod nft;
mod nym;
mod rules;
mod system;

use std::process::ExitCode;

const USAGE: &str = "\
usage: nym-killswitch <command>    (as root: sudo or run0)

  status    what is blocked and what gets through
  check     check that this machine can run the killswitch
  on        turn on now and at boot
  off       turn off and remove the firewall rules
  rules     print the loaded nftables rules
  version   print the version

Local network access follows NymVPN's own Allow LAN setting.
The guard command runs from nym-killswitch.service; you should not need it.
";

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    if command != "guard" {
        // Let `nym-killswitch status | head` end quietly instead of panicking. The
        // guard keeps Rust's default (ignored), since it writes to sockets.
        // SAFETY: setting a signal disposition before any threads exist.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    let result = match command.as_str() {
        "status" => cli::status(),
        "check" => cli::check(),
        "on" => cli::on(),
        "off" => cli::off(),
        "rules" => cli::rules(),
        "guard" => guard::run(),
        "version" | "--version" => {
            println!("nym-killswitch {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print!(
                "nym-killswitch {}: keep every packet inside NymVPN.\n\n{USAGE}",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nym-killswitch: {err}");
            ExitCode::FAILURE
        }
    }
}
