//! A stand-in for nym-vpnd's API, served from inside the test process.
//!
//! It speaks nym-vpnd's one-byte handshake, then answers Info, GetConfig and
//! ListenToEvents. Every Allow LAN change also sends an unrelated tunnel-state
//! event first, like the real daemon, to check that the guard skips what it
//! doesn't know. With `changed_api` it answers only Info, like a release that
//! dropped GetConfig. Dropping it acts like a crash: its runtime goes away with
//! every open connection.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::Body;
use tonic::server::{Grpc, NamedService};
use tonic::{Response, Status};

#[derive(Clone, PartialEq, prost::Message)]
struct InfoResponse {
    #[prost(string, tag = "1")]
    version: String,
    #[prost(string, tag = "3")]
    triple: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct VpnServiceConfig {
    #[prost(bool, tag = "4")]
    allow_lan: bool,
    #[prost(bool, tag = "5")]
    enable_two_hop: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetConfigResponse {
    #[prost(message, optional, tag = "1")]
    config: Option<VpnServiceConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TunnelState {
    #[prost(string, tag = "1")]
    note: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ConfigChangedEvent {
    #[prost(message, optional, tag = "1")]
    new_config: Option<VpnServiceConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TunnelEvent {
    #[prost(message, optional, tag = "1")]
    tunnel_state: Option<TunnelState>,
    #[prost(message, optional, tag = "3")]
    config_changed_event: Option<ConfigChangedEvent>,
}

fn config(allow_lan: bool) -> VpnServiceConfig {
    VpnServiceConfig {
        allow_lan,
        enable_two_hop: true,
    }
}

pub struct MockDaemon {
    lan: watch::Sender<bool>,
    rt: Option<Runtime>,
    socket: PathBuf,
}

impl MockDaemon {
    pub fn start(socket: &Path, allow_lan: bool, changed_api: bool) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("mock runtime");
        let (lan, lan_rx) = watch::channel(allow_lan);
        let _ = std::fs::remove_file(socket);
        let listener = rt
            .block_on(async { UnixListener::bind(socket) })
            .expect("bind mock socket");
        rt.spawn(async move {
            let (conns_tx, conns) = mpsc::channel(8);
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    // The client asks (1), the daemon accepts (1).
                    if stream.read_u8().await.ok() == Some(1) && stream.write_u8(1).await.is_ok() {
                        let _ = conns_tx.send(Ok::<_, std::io::Error>(stream)).await;
                    }
                }
            });
            let _ = tonic::transport::Server::builder()
                .serve_with_incoming(
                    Service {
                        lan: lan_rx,
                        changed_api,
                    },
                    ReceiverStream::new(conns),
                )
                .await;
        });
        MockDaemon {
            lan,
            rt: Some(rt),
            socket: socket.to_path_buf(),
        }
    }

    /// Flip Allow LAN, as the NymVPN app would.
    pub fn set_lan(&self, allow: bool) {
        self.lan.send_replace(allow);
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

#[derive(Clone)]
struct Service {
    lan: watch::Receiver<bool>,
    changed_api: bool,
}

impl NamedService for Service {
    const NAME: &'static str = "nym_vpn_service.NymVpnService";
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type Events = Pin<Box<dyn tokio_stream::Stream<Item = Result<TunnelEvent, Status>> + Send>>;

impl tower::Service<http::Request<Body>> for Service {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let lan = self.lan.clone();
        let changed_api = self.changed_api;
        Box::pin(async move {
            let path = req
                .uri()
                .path()
                .trim_start_matches("/nym_vpn_service.NymVpnService/");
            if changed_api && path != "Info" {
                return Ok(Status::unimplemented("gone in this release").into_http());
            }
            Ok(match path {
                "Info" => {
                    let svc = tower::service_fn(|_: tonic::Request<()>| async {
                        Ok::<_, Status>(Response::new(InfoResponse {
                            version: "0.0.0-mock".into(),
                            triple: "x86_64-unknown-linux-gnu".into(),
                        }))
                    });
                    let codec = tonic_prost::ProstCodec::<InfoResponse, ()>::default();
                    Grpc::new(codec).unary(svc, req).await
                }
                "GetConfig" => {
                    let svc = tower::service_fn(move |_: tonic::Request<()>| {
                        let allow_lan = *lan.borrow();
                        async move {
                            Ok::<_, Status>(Response::new(GetConfigResponse {
                                config: Some(config(allow_lan)),
                            }))
                        }
                    });
                    let codec = tonic_prost::ProstCodec::<GetConfigResponse, ()>::default();
                    Grpc::new(codec).unary(svc, req).await
                }
                "ListenToEvents" => {
                    let svc = tower::service_fn(move |_: tonic::Request<()>| {
                        let mut lan = lan.clone();
                        let (tx, rx) = mpsc::channel(8);
                        tokio::spawn(async move {
                            while lan.changed().await.is_ok() {
                                let allow_lan = *lan.borrow_and_update();
                                let activity = TunnelEvent {
                                    tunnel_state: Some(TunnelState {
                                        note: "connected".into(),
                                    }),
                                    config_changed_event: None,
                                };
                                let changed = TunnelEvent {
                                    tunnel_state: None,
                                    config_changed_event: Some(ConfigChangedEvent {
                                        new_config: Some(config(allow_lan)),
                                    }),
                                };
                                if tx.send(Ok(activity)).await.is_err()
                                    || tx.send(Ok(changed)).await.is_err()
                                {
                                    break;
                                }
                            }
                        });
                        let events: Events = Box::pin(ReceiverStream::new(rx));
                        async move { Ok::<_, Status>(Response::new(events)) }
                    });
                    let codec = tonic_prost::ProstCodec::<TunnelEvent, ()>::default();
                    Grpc::new(codec).server_streaming(svc, req).await
                }
                _ => Status::unimplemented("not mocked").into_http(),
            })
        })
    }
}
