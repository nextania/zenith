use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub certificates: Vec<CertificateConfig>,
    pub dns_providers: DnsProviders,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateConfig {
    pub name: String,
    pub domains: Vec<String>,
    pub acme_provider: String,
    pub dns_provider: String,
    pub account_email: String,
    pub output_dir: String,
    pub control_socket: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsProviders {
    #[serde(default)]
    pub cloudflare: Option<CloudflareConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareConfig {
    pub api_key: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        if let Ok(config_path) = env::var("CONFIG_FILE") {
            return Self::from_file(&config_path);
        }
        if PathBuf::from("zenith.toml").exists() {
            return Self::from_file("zenith.toml");
        }

        Err(anyhow!(
            "No configuration file found. Please set CONFIG_FILE environment variable or create zenith.toml"
        ))
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.certificates.is_empty() {
            return Err(anyhow!("No certificates configured"));
        }

        for cert in &self.certificates {
            if cert.domains.is_empty() {
                return Err(anyhow!(
                    "Certificate '{}' has no domains specified",
                    cert.name
                ));
            }
            if cert.account_email.is_empty() {
                return Err(anyhow!("Certificate '{}' has no account email", cert.name));
            }
        }

        Ok(())
    }
}
