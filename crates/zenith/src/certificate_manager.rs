use crate::acme::AcmeService;
use crate::acme_provider::AcmeProviderType;
use crate::config::CertificateConfig;
use crate::control_socket::ControlSocket;
use crate::dns_provider::DnsProvider;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::info;

pub struct CertificateManager {
    config: CertificateConfig,
    acme_service: AcmeService,
    socket: Option<ControlSocket>,
}

impl CertificateManager {
    pub fn new(config: CertificateConfig, dns_provider: Option<Arc<dyn DnsProvider>>) -> Result<Self> {
        let acme_provider = AcmeProviderType::from_string(&config.acme_provider)?;
        let socket = config.control_socket.clone().map(|s| ControlSocket::new(s));
        let acme_service =
            AcmeService::new(config.account_email.clone(), acme_provider, dns_provider, socket.clone());

        Ok(Self {
            config,
            acme_service,
            socket,
        })
    }

    pub async fn get_or_create_paths(&self) -> Result<CertificatePaths> {
        let output_dir = PathBuf::from(&self.config.output_dir);
        let paths = CertificatePaths {
            output_dir: output_dir.clone(),
            account_key: output_dir.join("account.key"),
            cert_key: output_dir.join("cert.key"),
            cert: output_dir.join("cert.pem"),
            chain: output_dir.join("chain.pem"),
            fullchain: output_dir.join("fullchain.pem"),
        };

        fs::create_dir_all(&paths.output_dir).await?;
        info!(
            "Certificate '{}': Output directory created: {:?}",
            self.config.name, paths.output_dir
        );
        Ok(paths)
    }

    pub async fn check_and_renew(&self, paths: &CertificatePaths) -> Result<bool> {
        if self.acme_service.needs_renewal(&paths.cert).await? {
            info!("Certificate '{}': Renewal needed", self.config.name);

            let result = self
                .acme_service
                .request_certificate(
                    self.config.domains.clone(),
                    &paths.account_key,
                    &paths.cert_key,
                )
                .await?;

            info!("Certificate '{}': Obtained successfully", self.config.name);

            fs::write(&paths.cert_key, &result.private_key).await?;
            info!(
                "Certificate '{}': Private key saved to: {:?}",
                self.config.name, paths.cert_key
            );

            fs::write(&paths.cert, &result.certificate).await?;
            info!(
                "Certificate '{}': Certificate saved to: {:?}",
                self.config.name, paths.cert
            );

            if !result.chain.is_empty() {
                fs::write(&paths.chain, &result.chain).await?;
                info!(
                    "Certificate '{}': Chain saved to: {:?}",
                    self.config.name, paths.chain
                );

                let fullchain = format!("{}{}", result.certificate, result.chain);
                fs::write(&paths.fullchain, fullchain).await?;
                info!(
                    "Certificate '{}': Full chain saved to: {:?}",
                    self.config.name, paths.fullchain
                );
            }

            if let Some(hot_reload_socket) = &self.socket {
                hot_reload_socket
                    .send_reload_command()
                    .await?;
                info!(
                    "Certificate '{}': Sent reload command to socket: {:?}",
                    self.config.name, hot_reload_socket
                );
            }

            info!("Certificate '{}': Issuance complete", self.config.name);
            Ok(true)
        } else {
            info!(
                "Certificate '{}': Still valid, no renewal needed",
                self.config.name
            );
            Ok(false)
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }
}

pub struct CertificatePaths {
    output_dir: PathBuf,
    account_key: PathBuf,
    cert_key: PathBuf,
    cert: PathBuf,
    chain: PathBuf,
    fullchain: PathBuf,
}
