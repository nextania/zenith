use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub exposed_ports: Vec<PortMapping>,
    pub server_endpoint: SocketAddr,
    // hex
    pub shared_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub protocol: Protocol,
    pub port: u16,
    pub local_addr: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path).context("Failed to read config file")?;
        toml::from_str(&contents).context("Failed to parse TOML config")
    }

    pub fn validate(&self) -> Result<()> {
        if self.exposed_ports.is_empty() {
            anyhow::bail!("No ports configured to expose");
        }
        Ok(())
    }
}
