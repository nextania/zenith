mod acme;
mod cloudflare;
mod config;
mod dns_provider;

use acme::AcmeService;
use cloudflare::CloudflareClient;
use config::Config;
use anyhow::Result;
use std::path::PathBuf;
use tokio::fs;
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting Zenith ACME certificate service");
    let config = Config::from_env()?;
    config.validate()?;
    info!("Configuration loaded");

    let output_dir = PathBuf::from(&config.output_dir);
    fs::create_dir_all(&output_dir).await?;
    info!("Output directory created: {:?}", output_dir);

    let cloudflare_client = CloudflareClient::new(
        config.cloudflare_api_key.clone(),
    );
    let acme_service = AcmeService::new(
        cloudflare_client,
        config.account_email.clone(),
        config.use_production,
    );
    let account_key_path = output_dir.join("account.key");
    let cert_key_path = output_dir.join("cert.key");
    let cert_path = output_dir.join("cert.pem");
    let chain_path = output_dir.join("chain.pem");
    let fullchain_path = output_dir.join("fullchain.pem");
    loop {
        if acme_service.needs_renewal(&cert_path).await? {
            info!("Certificate renewal needed");
            match acme_service
                .request_certificate(config.domains.clone(), &account_key_path, &cert_key_path)
                .await
            {
                Ok(result) => {
                    info!("Certificate obtained successfully");
                    fs::write(&cert_key_path, &result.private_key).await?;
                    info!("Private key saved to: {:?}", cert_key_path);
                    fs::write(&cert_path, &result.certificate).await?;
                    info!("Certificate saved to: {:?}", cert_path);
                    if !result.chain.is_empty() {
                        fs::write(&chain_path, &result.chain).await?;
                        info!("Certificate chain saved to: {:?}", chain_path);
                        let fullchain = format!("{}{}", result.certificate, result.chain);
                        fs::write(&fullchain_path, fullchain).await?;
                        info!("Full chain saved to: {:?}", fullchain_path);
                    }

                    info!("Certificate issuance complete");
                }
                Err(e) => {
                    error!("Failed to obtain certificate: {}", e);
                    return Err(e);
                }
            }
        } else {
            info!("Certificate is still valid, no renewal needed");
        }
        info!("Sleeping for 24 hours before next check");
        tokio::time::sleep(std::time::Duration::from_hours(24)).await;
    }
}

