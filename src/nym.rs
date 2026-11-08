//! Client for the nym-vpnd API on /var/run/nym-vpn.sock, the one the NymVPN app uses.
//!
//! Only the messages and fields the killswitch reads are declared here. Protobuf
//! skips unknown fields, so the daemon can send its full messages.
//! tests/nym_compat checks these declarations against each NymVPN release.

use std::path::PathBuf;

use http::uri::PathAndQuery;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tonic::client::Grpc;
use tonic::transport::{Channel, Endpoint, Uri};

pub const DEFAULT_SOCKET: &str = "/var/run/nym-vpn.sock";
const ISSUES: &str = "https://github.com/nil0ft/nym-vpn-killswitch/issues";

/// nym_vpn_service.InfoResponse
#[derive(Clone, PartialEq, prost::Message)]
pub struct InfoResponse {
    #[prost(string, tag = "1")]
    pub version: String,
}

/// nym_vpn_service.VpnServiceConfig
#[derive(Clone, PartialEq, prost::Message)]
pub struct VpnServiceConfig {
    #[prost(bool, tag = "4")]
    pub allow_lan: bool,
}

/// nym_vpn_service.GetConfigResponse
#[derive(Clone, PartialEq, prost::Message)]
pub struct GetConfigResponse {
    #[prost(message, optional, tag = "1")]
    pub config: Option<VpnServiceConfig>,
}

/// nym_vpn_service.ConfigChangedEvent
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigChangedEvent {
    #[prost(message, optional, tag = "1")]
    pub new_config: Option<VpnServiceConfig>,
}

/// nym_vpn_service.TunnelEvent. The real message is a oneof; only the
/// config_changed_event variant is declared.
#[derive(Clone, PartialEq, prost::Message)]
pub struct TunnelEvent {
    #[prost(message, optional, tag = "3")]
    pub config_changed_event: Option<ConfigChangedEvent>,
}

#[derive(Debug)]
pub enum Update {
    /// The daemon answered, or its settings changed.
    AllowLan(bool),
    /// Something else happened in the daemon, e.g. the tunnel state changed.
    Activity,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Not running, restarting, or refusing us.
    Unreachable(String),
    /// Running, but its API no longer matches what this build expects.
    Incompatible(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreachable(e) => write!(f, "not reachable: {e}"),
            Error::Incompatible(e) => write!(f, "API changed: {e}"),
        }
    }
}

impl From<tonic::Status> for Error {
    fn from(status: tonic::Status) -> Self {
        use tonic::Code;
        // A status built from a local transport error (the daemon died, the
        // connection broke) carries that error as its source. Answers the
        // daemon itself sent don't.
        if std::error::Error::source(&status).is_some() {
            return Error::Unreachable(chain(&status));
        }
        let text = format!("{:?}: {}", status.code(), status.message());
        match status.code() {
            Code::Unavailable | Code::Cancelled | Code::DeadlineExceeded | Code::Aborted => {
                Error::Unreachable(text)
            }
            _ => Error::Incompatible(text),
        }
    }
}

pub fn socket_path() -> PathBuf {
    std::env::var_os("NYMKS_NYM_SOCKET").map_or_else(|| DEFAULT_SOCKET.into(), PathBuf::from)
}

/// "transport error: No such file or directory" rather than just "transport error".
fn chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        let next = err.to_string();
        if !text.ends_with(&next) {
            text = format!("{text}: {next}");
        }
        source = err.source();
    }
    text
}

/// nym-vpnd checks the peer before it speaks gRPC: the client sends 1 and gets
/// 1 back when allowed. Root always is.
async fn connect(path: PathBuf) -> Result<Grpc<Channel>, Error> {
    let channel = Endpoint::from_static("http://nym-vpnd")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let mut stream = UnixStream::connect(&path).await?;
                stream.write_u8(1).await?;
                match stream.read_u8().await? {
                    1 => Ok::<_, std::io::Error>(TokioIo::new(stream)),
                    2 => Err(std::io::ErrorKind::PermissionDenied.into()),
                    _ => Err(std::io::ErrorKind::ConnectionRefused.into()),
                }
            }
        }))
        .await
        .map_err(|e| Error::Unreachable(chain(&e)))?;
    Ok(Grpc::new(channel))
}

async fn unary<T: prost::Message + Default + 'static>(
    grpc: &mut Grpc<Channel>,
    path: &'static str,
) -> Result<T, Error> {
    grpc.ready()
        .await
        .map_err(|e| Error::Unreachable(chain(&e)))?;
    Ok(grpc
        .unary(
            tonic::Request::new(()),
            PathAndQuery::from_static(path),
            tonic_prost::ProstCodec::default(),
        )
        .await?
        .into_inner())
}

async fn version(grpc: &mut Grpc<Channel>) -> Result<String, Error> {
    let info: InfoResponse = unary(grpc, "/nym_vpn_service.NymVpnService/Info").await?;
    Ok(info.version)
}

async fn allow_lan(grpc: &mut Grpc<Channel>) -> Result<bool, Error> {
    let response: GetConfigResponse =
        unary(grpc, "/nym_vpn_service.NymVpnService/GetConfig").await?;
    response
        .config
        .map(|c| c.allow_lan)
        .ok_or_else(|| Error::Incompatible("GetConfig returned no config".into()))
}

/// Ask the running daemon for its version, and check that the calls the guard
/// relies on still work.
pub fn probe() -> Result<String, Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Unreachable(e.to_string()))?;
    runtime.block_on(async {
        let mut grpc = connect(socket_path()).await?;
        let daemon = version(&mut grpc).await?;
        allow_lan(&mut grpc).await?;
        Ok(daemon)
    })
}

async fn session(
    path: PathBuf,
    updates: &mpsc::Sender<Update>,
    daemon: &mut String,
    answered: &mut bool,
) -> Result<(), Error> {
    let mut grpc = connect(path).await?;
    *daemon = version(&mut grpc).await?;
    let allow = allow_lan(&mut grpc).await?;
    *answered = true;
    eprintln!(
        "nym-vpnd {daemon} answered, Allow LAN is {}",
        if allow { "on" } else { "off" }
    );
    let _ = updates.send(Update::AllowLan(allow)).await;

    grpc.ready()
        .await
        .map_err(|e| Error::Unreachable(chain(&e)))?;
    let mut events = grpc
        .server_streaming::<_, TunnelEvent, _>(
            tonic::Request::new(()),
            PathAndQuery::from_static("/nym_vpn_service.NymVpnService/ListenToEvents"),
            tonic_prost::ProstCodec::default(),
        )
        .await?
        .into_inner();
    while let Some(event) = events.message().await? {
        let update = match event.config_changed_event.and_then(|e| e.new_config) {
            Some(config) => Update::AllowLan(config.allow_lan),
            None => Update::Activity,
        };
        let _ = updates.send(update).await;
    }
    Err(Error::Unreachable(
        "nym-vpnd closed the event stream".into(),
    ))
}

/// Follow nym-vpnd for as long as the guard runs, reconnecting when it restarts.
/// Errors never open anything: the rules keep the last Allow LAN value.
pub async fn follow(path: PathBuf, updates: mpsc::Sender<Update>) {
    let mut last = None;
    let mut daemon = String::new();
    loop {
        let mut answered = false;
        let result = session(path.clone(), &updates, &mut daemon, &mut answered).await;
        if answered {
            // Report the next problem again, even if it looks like the last one.
            last = None;
        }
        if let Err(err) = result
            && last.as_ref() != Some(&err)
        {
            match &err {
                Error::Unreachable(_) => eprintln!("nym-vpnd {err} (retrying)"),
                Error::Incompatible(_) => eprintln!(
                    "nym-vpnd {daemon} {err}. The LAN setting stays where it was; \
                     please report this at {ISSUES}"
                ),
            }
            last = Some(err);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
