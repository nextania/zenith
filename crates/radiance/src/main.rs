mod config;
mod control_socket;
pub mod environment;
pub mod outpost;
mod proxy;
pub mod vault;
pub mod virtual_connector;

use control_socket::ControlSocket;
use pingora::{listeners::tls::TlsSettings, prelude::*, tls::ResolvesServerCert};
use pingora_rustls::ServerConfig;
use proxy::RadianceProxy;
use rustls::{sign::CertifiedKey, version};
use std::{collections::HashMap, sync::Arc, thread};
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{config::FullConfig, environment::CONFIG_FILE, proxy::normalize_match_domain};

#[derive(Debug)]
struct CertifiateWrapper {
    cert: Arc<CertifiedKey>,
}

impl ResolvesServerCert for CertifiateWrapper {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> std::option::Option<Arc<CertifiedKey>> {
        Some(self.cert.clone())
    }
}

async fn get_cert_for_sni(sni: &str, config: Arc<RwLock<FullConfig>>) -> Option<CertifiedKey> {
    info!("Looking up certificate for SNI: {}", sni);
    let config = config.read().await;
    let id = config
        .hosts
        .values()
        .find_map(|host_cfg| {
            if host_cfg
                .config
                .domains
                .iter()
                .any(|d| normalize_match_domain(sni, d))
            {
                Some(host_cfg.config.tls_cert_id.clone())
            } else {
                None
            }
        })
        .flatten()
        .map(|s| config.certificates.iter().find(|c| c.config.id() == s))
        .flatten();
    match id {
        Some(cert_cfg) => Some(cert_cfg.cert.clone()),
        None => None,
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    info!("Starting Radiance reverse proxy");

    if !std::path::Path::new(&*CONFIG_FILE).exists() {
        panic!("Configuration file not found at path: {}", &*CONFIG_FILE);
    }
    let config = FullConfig::load_from_file(&CONFIG_FILE)
        .await
        .expect("Failed to load configuration");
    info!("Configuration loaded");

    let listen_address = config.listen_address();
    let listen_address_tls = config.listen_address_tls();
    let outpost_address = config.outpost_listen_address();
    let shared_config = Arc::new(RwLock::new(config));

    let control_socket_path =
        std::env::var("CONTROL_SOCKET_PATH").unwrap_or_else(|_| "/tmp/radiance.sock".to_string());
    let control_socket = ControlSocket::new(control_socket_path, shared_config.clone());
    tokio::spawn(async move {
        if let Err(e) = control_socket.start().await {
            tracing::error!("Control socket error: {}", e);
        }
    });
    let outposts = shared_config
        .read()
        .await
        .outposts
        .clone()
        .unwrap_or(HashMap::new());
    if !outposts.is_empty() && outpost_address.is_some() {
        info!("Initializing with {} outposts", outposts.len());
        tokio::spawn(async move {
            outpost::initialize_outposts(outpost_address.unwrap().parse().unwrap(), outposts)
                .await
                .expect("Failed to initialize outposts");
        });
    }

    let mut proxy = Server::new(Some(Opt::default())).unwrap();
    proxy.bootstrap();
    let mut proxy_service_http = pingora_proxy::http_proxy_service_with_name(
        &proxy.configuration,
        RadianceProxy::new(shared_config.clone()),
        "Radiance",
    );

    proxy_service_http.add_tcp(&listen_address);
    if let Some(tls_address) = listen_address_tls {
        proxy_service_http.add_tls_with_settings(
            &tls_address,
            None,
            TlsSettings::with_async_callback(Arc::new(move |x| {
                let config = shared_config.clone();
                let info = x.sni.as_deref().unwrap_or_default().to_string();
                Box::pin(async move {
                    let cert = get_cert_for_sni(&info, config).await;
                    let resolver = CertifiateWrapper {
                        cert: Arc::new(cert.ok_or(pingora::Error::new_in(ErrorType::InvalidCert))?),
                    };
                    let config = ServerConfig::builder_with_protocol_versions(&[
                        &version::TLS12,
                        &version::TLS13,
                    ])
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(resolver));
                    Ok(Arc::new(config))
                })
            }))
            .expect("Failed to create TLS settings"),
        );
    }
    proxy.add_service(proxy_service_http);

    info!("Radiance proxy server starting...");
    thread::spawn(|| proxy.run_forever());

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c");
    info!("Shutting down Radiance proxy server");
}
