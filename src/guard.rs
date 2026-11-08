//! The long-running guard, started by nym-killswitch.service inside
//! nym-killswitch.slice. It loads the rules, keeps them in line with nym-vpnd
//! (Allow LAN, tun devices) and defends them against other tools.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::nft::Nft;
use crate::nym::{self, Update};
use crate::rules::{self, Policy, TABLE};
use crate::system::{self, CGROUP_ROOT, Events, SavedLan};

pub const DEFAULT_CGROUP: &str = "nym-killswitch.slice";

/// Where things live. The NYMKS_* variables exist for the tests in tests/.
pub struct Settings {
    /// Sockets in this cgroup (relative to the cgroup2 root) may bypass the killswitch.
    pub cgroup: String,
    pub state_dir: PathBuf,
    pub nym_socket: PathBuf,
    /// Take ownership of the table when the kernel supports it.
    pub lock: bool,
}

impl Settings {
    pub fn from_env() -> Result<Self, String> {
        let cgroup = std::env::var("NYMKS_CGROUP").unwrap_or_else(|_| DEFAULT_CGROUP.into());
        let cgroup = cgroup.trim_start_matches('/').to_string();
        if cgroup.is_empty()
            || !cgroup
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-@:/\\".contains(&b))
        {
            return Err(format!("bad cgroup path: {cgroup}"));
        }
        Ok(Settings {
            cgroup,
            state_dir: std::env::var_os("NYMKS_STATE_DIR")
                .map_or_else(|| "/var/lib/nym-killswitch".into(), PathBuf::from),
            nym_socket: nym::socket_path(),
            lock: std::env::var("NYMKS_LOCK").map_or(true, |v| v != "no"),
        })
    }
}

pub fn run() -> Result<(), String> {
    let settings = Settings::from_env()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let result = runtime.block_on(guard(settings));
    if result.is_err() {
        block_if_unprotected();
    }
    result
}

/// Something went wrong before the rules were in place: block everything
/// rather than leave the machine open.
fn block_if_unprotected() {
    let Ok(mut nft) = Nft::new() else { return };
    if nft.run(&format!("list table inet {TABLE}")).is_err() {
        eprintln!(
            "loading the emergency block: all traffic stays blocked until the problem is fixed"
        );
        if let Err(err) = nft.run(&rules::emergency()) {
            eprintln!("emergency block failed: {err}");
        }
    }
}

async fn guard(settings: Settings) -> Result<(), String> {
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
        return Err(format!(
            "needs the unified cgroup v2 hierarchy at {CGROUP_ROOT}"
        ));
    }
    let cgroup_dir = Path::new(CGROUP_ROOT).join(&settings.cgroup);
    if !cgroup_dir.is_dir() {
        return Err(format!(
            "cgroup {} does not exist; start the guard with: systemctl start nym-killswitch",
            settings.cgroup
        ));
    }
    std::fs::create_dir_all(&settings.state_dir).map_err(|e| e.to_string())?;

    let saved = SavedLan::new(settings.state_dir.clone());
    let mut policy = Policy {
        allow_lan: saved.load(),
        tunnels: system::tunnels_held_by(&cgroup_dir),
    };
    let lock = settings.lock && Nft::new()?.run(&rules::lock_probe()).is_ok();
    let mut table = Table::new(lock, settings.cgroup)?;
    table.load(&policy)?;

    let mode = if lock { "locked" } else { "watched" };
    eprintln!("killswitch on, {mode}. {}", describe(&policy));
    system::notify_ready(&format!("on, {mode}"));

    let (updates_tx, mut updates) = mpsc::channel(16);
    tokio::spawn(nym::follow(settings.nym_socket, updates_tx));
    let links = Events::subscribe(system::ROUTE_LINK).map_err(|e| format!("netlink: {e}"))?;
    // Nobody else can touch a locked table, so only a watched one needs this.
    let ruleset = match lock {
        true => None,
        false => Some(Events::subscribe(system::NFTABLES).map_err(|e| format!("netlink: {e}"))?),
    };
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    // A new tun device shows up in netlink a moment before nym-vpnd's fd is
    // attached to it, so look once more shortly after each change.
    let settle = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(settle);
    let mut settling = false;
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;

    loop {
        tokio::select! {
            Some(update) = updates.recv() => match update {
                Update::AllowLan(allow) if allow != policy.allow_lan => {
                    policy.allow_lan = allow;
                    saved.store(allow);
                    table.load(&policy)?;
                    eprintln!("NymVPN's Allow LAN is now {}", if allow { "on" } else { "off" });
                }
                Update::AllowLan(_) => {}
                Update::Activity => {
                    table.rescan(&mut policy, &cgroup_dir)?;
                    settle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(300));
                    settling = true;
                }
            },
            changed = links.changed() => {
                changed.map_err(|e| format!("netlink: {e}"))?;
                table.rescan(&mut policy, &cgroup_dir)?;
                settle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(300));
                settling = true;
            }
            () = &mut settle, if settling => {
                settling = false;
                table.rescan(&mut policy, &cgroup_dir)?;
            }
            _ = tick.tick() => {
                table.rescan(&mut policy, &cgroup_dir)?;
                table.verify(&policy)?;
            }
            changed = ruleset_changed(ruleset.as_ref()) => {
                changed.map_err(|e| format!("netlink: {e}"))?;
                table.verify(&policy)?;
            }
            _ = term.recv() => return Ok(()),
            _ = int.recv() => return Ok(()),
        }
    }
}

async fn ruleset_changed(events: Option<&Events>) -> std::io::Result<()> {
    match events {
        Some(events) => events.changed().await,
        None => std::future::pending().await,
    }
}

fn describe(policy: &Policy) -> String {
    let tunnels = if policy.tunnels.is_empty() {
        "none".to_string()
    } else {
        policy.tunnels.iter().cloned().collect::<Vec<_>>().join(" ")
    };
    let lan = if policy.allow_lan {
        "allowed"
    } else {
        "blocked"
    };
    format!("LAN {lan}, tunnels: {tunnels}")
}

/// The loaded table, through one nftables session that the guard keeps open.
struct Table {
    nft: Nft,
    lister: Nft,
    lock: bool,
    cgroup: String,
    /// In watch mode, the rules as last loaded, without counters.
    expected: String,
}

impl Table {
    fn new(lock: bool, cgroup: String) -> Result<Self, String> {
        Ok(Table {
            nft: Nft::new()?,
            lister: Nft::new()?.stateless(),
            lock,
            cgroup,
            expected: String::new(),
        })
    }

    fn list(&mut self) -> Option<String> {
        self.lister.run(&format!("list table inet {TABLE}")).ok()
    }

    /// Replace the whole table in one transaction.
    fn load(&mut self, policy: &Policy) -> Result<(), String> {
        let loaded = self.list();
        let flags = loaded.as_deref().and_then(rules::flags).map(str::to_string);
        self.nft
            .run(&rules::render(
                policy,
                &self.cgroup,
                self.lock,
                flags.as_deref(),
            ))
            .map_err(|e| format!("could not load the rules: {e}"))?;
        let now = self.list().unwrap_or_default();
        if self.lock && !rules::is_owned(&now) {
            return Err("loaded the rules but could not take ownership of the table".into());
        }
        self.expected = now;
        Ok(())
    }

    /// Bring the tunnel set in line with the tun devices nym-vpnd holds.
    fn rescan(&mut self, policy: &mut Policy, cgroup_dir: &Path) -> Result<(), String> {
        let tunnels = system::tunnels_held_by(cgroup_dir);
        if tunnels == policy.tunnels {
            return Ok(());
        }
        policy.tunnels = tunnels;
        self.nft
            .run(&rules::set_tunnels(&policy.tunnels))
            .map_err(|e| format!("could not update the tunnel set: {e}"))?;
        self.expected = self.list().unwrap_or_default();
        eprintln!("{}", describe(policy));
        Ok(())
    }

    /// Put the rules back if another process changed or removed them.
    fn verify(&mut self, policy: &Policy) -> Result<(), String> {
        if self.lock || self.list().as_deref() == Some(self.expected.as_str()) {
            return Ok(());
        }
        eprintln!("another process changed the rules; restoring them");
        self.load(policy)
    }
}
