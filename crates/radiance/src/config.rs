
use std::{collections::HashMap, sync::Arc};

use partially::Partial;
use pingora_load_balancing::{LoadBalancer, prelude::RoundRobin};
use rustls::{crypto::ring::sign::any_supported_type, sign::CertifiedKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
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
            TlsCertConfig::Local { cert_file, key_file, .. } => {
                self.read_local_cert(cert_file, key_file)
            }
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
        let certified_key = rustls::sign::CertifiedKey::new(
            certs,
            any_supported_type(&key)?,
        );
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
    pub servers: Vec<String>,
    pub path: String
}

#[derive(Clone, Debug, Deserialize, Serialize, Partial)]
#[partially(derive(Default, Debug, Serialize, Deserialize))]
pub struct HostConfig  {
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

#[derive(Clone, Debug,Deserialize, Serialize)]
pub struct Config {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub hosts: HashMap<String, HostConfig>,
    pub certificates: Vec<TlsCertConfig>,
}

pub struct FullConfig {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub hosts: HashMap<String, Arc<HostConfigWithBalancer>>,
    pub certificates: Vec<Arc<TlsCertConfigWithKey>>,
}

pub struct HostConfigWithBalancer {
    pub config: HostConfig,
    pub load_balancer: LoadBalancer<RoundRobin>,
}

impl From<HostConfig> for HostConfigWithBalancer {
    fn from(cfg: HostConfig) -> Self {
        let load_balancer = LoadBalancer::<RoundRobin>::try_from_iter(
            cfg.upstream.servers.clone(),
        ).expect("Fail to create load balancer");
        
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
            hosts: cfg.hosts.iter().map(|(k, v)| (k.clone(), Arc::new(HostConfigWithBalancer::from(v.clone())))).collect(),
            certificates: cfg.certificates.iter().map(|c| {
                let cert = c.read_cert().expect("Failed to read TLS certificate");
                Arc::new(TlsCertConfigWithKey {
                    config: c.clone(),
                    cert,
                })
            }).collect(),
        }
    }
}

impl From<&FullConfig> for Config {
    fn from(cfg: &FullConfig) -> Self {
        Config {
            listen_port: cfg.listen_port,
            listen_port_tls: cfg.listen_port_tls,
            hosts: cfg.hosts.iter().map(|(k, v)| (k.clone(), v.config.clone())).collect(),
            certificates: cfg.certificates.clone().iter().map(|c| c.config.clone()).collect(),
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
}
