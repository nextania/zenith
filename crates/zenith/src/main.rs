mod acme;
mod acme_provider;
mod certificate_manager;
mod cloudflare;
mod config;
mod dns_provider;
pub mod control_socket;

use anyhow::{Result, anyhow};
use certificate_manager::CertificateManager;
use cloudflare::CloudflareClient;
use config::Config;
use dns_provider::DnsProvider;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting Zenith ACME certificate service");
    let config = Config::load()?;
    info!(
        "Configuration loaded with {} certificate(s)",
        config.certificates.len()
    );

    let mut dns_providers: std::collections::HashMap<String, Arc<dyn DnsProvider>> =
        std::collections::HashMap::new();

    if let Some(cloudflare_config) = &config.dns_providers.cloudflare {
        let cloudflare = CloudflareClient::new(cloudflare_config.api_key.clone());
        dns_providers.insert("cloudflare".to_string(), Arc::new(cloudflare));
        info!("Cloudflare DNS provider initialized");
    }

    let certificates = config
        .certificates
        .iter()
        .map(|c| {
            let dns_provider = dns_providers
                .get(&c.dns_provider)
                .cloned();
            if dns_provider.is_none() && c.control_socket.is_none() {
                return Err(anyhow!(
                    "Certificate '{}' requires a challenge provider, but none was found",
                    c.name
                ));
            }
            CertificateManager::new(c.clone(), dns_provider)
        })
        .collect::<Result<Vec<_>>>()?;

    if certificates.is_empty() {
        return Err(anyhow!("No certificate managers were successfully created"));
    }

    loop {
        for certificate in &certificates {
            let paths = certificate.get_or_create_paths().await?;
            match certificate.check_and_renew(&paths).await {
                Ok(renewed) => {
                    if renewed {
                        info!("Certificate '{}': Successfully renewed", certificate.name());
                    } else {
                        info!("Certificate '{}': No renewal needed", certificate.name());
                    }
                }
                Err(e) => {
                    error!(
                        "Certificate '{}': Error during renewal check: {}",
                        certificate.name(),
                        e
                    );
                }
            }
        }
        info!("Sleeping for 24 hours before next check");
        tokio::time::sleep(std::time::Duration::from_hours(24)).await;
    }
}
