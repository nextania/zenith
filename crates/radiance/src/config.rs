use std::{
    collections::{BTreeSet, HashMap},
    net::ToSocketAddrs,
    sync::Arc,
};

use futures_util::FutureExt;
use http::Extensions;
use partially::Partial;
use pingora::{
    connectors::L4Connect,
    protocols::l4::{
        socket::SocketAddr,
        stream::Stream,
        virt::{VirtualSocket, VirtualSocketStream},
    },
};
use pingora_load_balancing::{
    Backend, Backends, LoadBalancer, discovery::Static, prelude::RoundRobin,
};
use rustls::{crypto::ring::sign::any_supported_type, sign::CertifiedKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::outpost::{ACTIVE_TCP_STREAMS, OutpostRequest, OutpostResponse, request};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TlsCertConfig {
    Local {
        id: String,
        cert_file: String,
        key_file: String,
    },
    Vault {
        id: String,
        vault_path: String,
    },
}

impl TlsCertConfig {
    pub fn read_cert(&self) -> anyhow::Result<rustls::sign::CertifiedKey> {
        match self {
            TlsCertConfig::Local {
                cert_file,
                key_file,
                ..
            } => self.read_local_cert(cert_file, key_file),
            TlsCertConfig::Vault { .. } => {
                Err(anyhow::anyhow!("Vault certificate loading not implemented"))
            }
        }
    }
    fn read_local_cert(
        &self,
        cert_file_path: &str,
        key_file_path: &str,
    ) -> anyhow::Result<rustls::sign::CertifiedKey> {
        let cert_file = std::fs::File::open(cert_file_path)?;
        let mut reader = std::io::BufReader::new(cert_file);
        let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
        let certs = certs?;
        let key_file = std::fs::File::open(key_file_path)?;
        let mut reader = std::io::BufReader::new(key_file);
        let keys = rustls_pemfile::private_key(&mut reader)?;
        let key = keys.ok_or(anyhow::anyhow!(
            "No private keys found in {}",
            key_file_path
        ))?;
        let certified_key = rustls::sign::CertifiedKey::new(certs, any_supported_type(&key)?);
        Ok(certified_key)
    }

    pub fn id(&self) -> &str {
        match self {
            TlsCertConfig::Local { id, .. } => id,
            TlsCertConfig::Vault { id, .. } => id,
        }
    }
}

pub struct TlsCertConfigWithKey {
    pub config: TlsCertConfig,
    pub cert: CertifiedKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub tls: bool,
    pub servers: Vec<ServerConfig>,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerConfig {
    Local { address: String },
    Outpost { id: String, address: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, Partial)]
#[partially(derive(Default, Debug, Serialize, Deserialize))]
pub struct HostConfig {
    pub domains: Vec<String>,
    pub enabled: bool,
    pub tls_cert_id: Option<String>,
    pub upstream: UpstreamConfig,
    pub header_rewrites: Option<HashMap<String, String>>,
    pub upgrade_https: Option<bool>,
    pub forward_auth: Option<ForwardAuthConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForwardAuthConfig {
    pub url: String,
    pub response_headers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub outpost_listen_port: Option<u16>,
    pub hosts: HashMap<String, HostConfig>,
    pub certificates: Vec<TlsCertConfig>,
    pub outposts: Option<HashMap<String, OutpostConfig>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutpostConfig {
    pub shared_secret: String,
}

pub struct FullConfig {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub outpost_listen_port: Option<u16>,
    pub hosts: HashMap<String, Arc<HostConfigWithBalancer>>,
    pub certificates: Vec<Arc<TlsCertConfigWithKey>>,
    pub outposts: Option<HashMap<String, OutpostConfig>>,
}

pub struct HostConfigWithBalancer {
    pub config: HostConfig,
    pub load_balancer: LoadBalancer<RoundRobin>,
}

#[derive(Debug)]
pub struct VirtualConnector {
    outpost_id: String,
    address: String,
}

impl VirtualConnector {
    pub fn new(outpost_id: &str, address: &str) -> Self {
        Self {
            outpost_id: outpost_id.to_string(),
            address: address.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl L4Connect for VirtualConnector {
    async fn connect(&self, _addr: &SocketAddr) -> pingora::Result<Stream> {
        let (host, port) = if let Some(colon_pos) = self.address.rfind(':') {
            let host_part = &self.address[..colon_pos];
            let port_part = &self.address[colon_pos + 1..];
            let port = port_part.parse::<u16>().map_err(|e| {
                pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    format!("Invalid port: {}", e),
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid port",
                    )),
                )
            })?;
            (host_part.to_string(), port)
        } else {
            return Err(pingora::Error::because(
                pingora::ErrorType::ConnectError,
                "Invalid address format",
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing port",
                )),
            ));
        };
        let resolved_host = if host.parse::<std::net::IpAddr>().is_err() {
            match request(
                self.outpost_id.clone(),
                OutpostRequest::Dns { host: host.clone() },
            )
            .await
            {
                Ok(OutpostResponse::Dns((_, ip))) => ip,
                Ok(_) => {
                    return Err(pingora::Error::because(
                        pingora::ErrorType::ConnectError,
                        "Unexpected DNS response",
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Unexpected response",
                        )),
                    ));
                }
                Err(e) => {
                    return Err(pingora::Error::because(
                        pingora::ErrorType::ConnectError,
                        format!("DNS resolution failed: {}", e),
                        Box::new(std::io::Error::new(std::io::ErrorKind::Other, "DNS failed")),
                    ));
                }
            }
        } else {
            host
        };
        let connection_id = rand::Rng::random::<u64>(&mut rand::rng());
        match request(
            self.outpost_id.clone(),
            OutpostRequest::TcpConnect {
                destination_host: resolved_host,
                destination_port: port,
                id: connection_id,
            },
        )
        .await
        {
            Ok(OutpostResponse::Ack) => {}
            Ok(_) => {
                return Err(pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    "Unexpected TcpConnect response",
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unexpected response",
                    )),
                ));
            }
            Err(e) => {
                return Err(pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    format!("TcpConnect failed: {}", e),
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "Connection failed",
                    )),
                ));
            }
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        ACTIVE_TCP_STREAMS.insert(connection_id, tx);
        let socket = GenericVirtualSocket::new(rx, self.outpost_id.clone(), connection_id);

        Ok(Stream::from(VirtualSocketStream::new(Box::new(socket))))
    }
}

#[derive(Debug)]
pub struct GenericVirtualSocket {
    receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    outpost_id: String,
    connection_id: u64,
}

impl GenericVirtualSocket {
    pub fn new(
        receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        outpost_id: String,
        connection_id: u64,
    ) -> Self {
        Self {
            receiver,
            outpost_id,
            connection_id,
        }
    }
}

impl VirtualSocket for GenericVirtualSocket {
    fn set_socket_option(
        &self,
        _: pingora::protocols::l4::virt::VirtualSockOpt,
    ) -> std::io::Result<()> {
        // no-op
        Ok(())
    }
}

impl AsyncWrite for GenericVirtualSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        use crate::outpost::{OutpostRequest, request};

        let outpost_id = self.outpost_id.clone();
        let connection_id = self.connection_id;
        let data = buf.to_vec();
        let len = data.len();

        // dispatch data to outpost (non-blocking fire-and-forget)
        tokio::spawn(async move {
            let _ = request(
                outpost_id,
                OutpostRequest::Tcp {
                    data,
                    id: connection_id,
                },
            )
            .await;
        });

        std::task::Poll::Ready(Ok(len))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // nothing to flush
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let outpost_id = self.outpost_id.clone();
        let connection_id = self.connection_id;
        ACTIVE_TCP_STREAMS.remove(&connection_id);

        // dispatch disconnect to outpost (non-blocking fire-and-forget)
        tokio::spawn(async move {
            let _ = request(
                outpost_id,
                OutpostRequest::TcpDisconnect { id: connection_id },
            )
            .await;
        });

        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GenericVirtualSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // channel closed, connection ended
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

fn into_backends(servers: &Vec<ServerConfig>) -> anyhow::Result<Backends> {
    let mut upstreams = BTreeSet::new();
    for server in servers.into_iter() {
        match server {
            ServerConfig::Local { address } => {
                let addrs = address.to_socket_addrs()?.map(|addr| Backend {
                    addr: SocketAddr::Inet(addr),
                    weight: 1,
                    ext: Extensions::new(),
                });
                upstreams.extend(addrs);
            }
            ServerConfig::Outpost { address, id } => {
                upstreams.insert(Backend {
                    addr: SocketAddr::Custom(
                        address.clone(),
                        Arc::new(VirtualConnector::new(id, address)),
                    ),
                    weight: 1,
                    ext: Extensions::new(),
                });
            }
        }
    }
    Ok(Backends::new(Static::new(upstreams)))
}

impl From<HostConfig> for HostConfigWithBalancer {
    fn from(cfg: HostConfig) -> Self {
        let load_balancer = LoadBalancer::<RoundRobin>::from_backends(
            into_backends(&cfg.upstream.servers).expect("Fail to create load balancer"),
        );
        load_balancer
            .update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
        HostConfigWithBalancer {
            config: cfg,
            load_balancer,
        }
    }
}

impl From<Config> for FullConfig {
    fn from(cfg: Config) -> Self {
        FullConfig {
            listen_port: cfg.listen_port,
            listen_port_tls: cfg.listen_port_tls,
            outpost_listen_port: cfg.outpost_listen_port,
            hosts: cfg
                .hosts
                .iter()
                .map(|(k, v)| (k.clone(), Arc::new(HostConfigWithBalancer::from(v.clone()))))
                .collect(),
            certificates: cfg
                .certificates
                .iter()
                .map(|c| {
                    let cert = c.read_cert().expect("Failed to read TLS certificate");
                    Arc::new(TlsCertConfigWithKey {
                        config: c.clone(),
                        cert,
                    })
                })
                .collect(),
            outposts: cfg.outposts,
        }
    }
}

impl From<&FullConfig> for Config {
    fn from(cfg: &FullConfig) -> Self {
        Config {
            listen_port: cfg.listen_port,
            listen_port_tls: cfg.listen_port_tls,
            outpost_listen_port: cfg.outpost_listen_port,
            hosts: cfg
                .hosts
                .iter()
                .map(|(k, v)| (k.clone(), v.config.clone()))
                .collect(),
            certificates: cfg
                .certificates
                .clone()
                .iter()
                .map(|c| c.config.clone())
                .collect(),
            outposts: cfg.outposts.clone(),
        }
    }
}

impl FullConfig {
    pub async fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let contents = tokio::fs::read_to_string(path).await?;
        let full_config: FullConfig = toml::from_str::<Config>(&contents)?.into();

        Ok(full_config)
    }

    pub async fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let toml_string = toml::to_string_pretty(&Config::from(self))?;
        tokio::fs::write(path, toml_string).await?;
        Ok(())
    }

    pub fn listen_address(&self) -> String {
        format!("0.0.0.0:{}", self.listen_port)
    }

    pub fn listen_address_tls(&self) -> Option<String> {
        self.listen_port_tls.map(|port| format!("0.0.0.0:{}", port))
    }

    pub fn outpost_listen_address(&self) -> Option<String> {
        // TODO: QUIC doesn't like 0.0.0.0
        self.outpost_listen_port
            .map(|port| format!("127.0.0.1:{}", port))
    }
}
