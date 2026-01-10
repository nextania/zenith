use partially::Partial;
use radiance_types::{ControlCommand, ControlResponse};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{error, info};

use radiance_types::{HostConfig, PartialHostConfig};
use crate::config::{Config, FullConfig, };
use crate::environment::CONFIG_FILE;

pub type SharedConfig = Arc<RwLock<FullConfig>>;

pub struct ControlSocket {
    socket_path: String,
    config: SharedConfig,
}

impl ControlSocket {
    pub fn new(socket_path: String, config: SharedConfig) -> Self {
        Self {
            socket_path,
            config,
        }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let socket_path = Path::new(&self.socket_path);
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Control socket listening on: {}", self.socket_path);

        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o660))?;

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let config = self.config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, config).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(stream: UnixStream, config: SharedConfig) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = match serde_json::from_str::<ControlCommand>(trimmed) {
            Ok(command) => process_command(command, config.clone()).await,
            Err(e) => ControlResponse::Error {
                message: format!("Invalid command format: {}", e),
            },
        };

        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        line.clear();
    }

    Ok(())
}

async fn process_command(command: ControlCommand, config: SharedConfig) -> ControlResponse {
    match command {
        ControlCommand::AddHost { id, host } => add_host(config, id, host).await,
        ControlCommand::UpdateHost { id, host } => update_host(config, id, host).await,
        ControlCommand::RemoveHost { id } => remove_host(config, id).await,
        ControlCommand::ListHosts => list_hosts(config).await,
        ControlCommand::GetHost { id } => get_host(config, id).await,
        ControlCommand::Reload => reload_config(config).await,
        ControlCommand::ClearHttpChallenge { domain, token } => clear_http_challenge(config, domain, token).await,
        ControlCommand::SetHttpChallenge { domain, token, thumbprint } => set_http_challenge(config, domain, token, thumbprint).await,
    }
}

async fn set_http_challenge(config: SharedConfig, domain: String, token: String, thumbprint: String) -> ControlResponse {
    let mut cfg = config.write().await;
    cfg.active_challenges.insert(domain.clone(), (token.clone(), thumbprint.clone()));
    info!("Set HTTP challenge for domain: {}", domain);
    ControlResponse::Success {
        message: format!("HTTP challenge set for domain: {}", domain),
        data: None,
    }
}

async fn clear_http_challenge(config: SharedConfig, domain: String, token: String) -> ControlResponse {
    let mut cfg = config.write().await;
    match cfg.active_challenges.get(&domain) {
        Some((stored_token, _)) if *stored_token == token => {
            cfg.active_challenges.remove(&domain);
            info!("Cleared HTTP challenge for domain: {}", domain);
            ControlResponse::Success {
                message: format!("HTTP challenge cleared for domain: {}", domain),
                data: None,
            }
        }
        _ => ControlResponse::Error {
            message: format!("No matching HTTP challenge found for domain: {}", domain),
        },
    }
}

async fn add_host(config: SharedConfig, id: String, new_host: HostConfig) -> ControlResponse {
    let mut cfg = config.write().await;
    for domain in &new_host.domains {
        if cfg
            .hosts
            .iter()
            .any(|(_, h)| h.config.domains.contains(domain))
        {
            return ControlResponse::Error {
                message: format!("Domain '{}' already exists", domain),
            };
        }
    }
    cfg.hosts.insert(id, Arc::new(new_host.clone().into()));
    if let Err(e) = cfg.save_to_file(&CONFIG_FILE).await {
        return ControlResponse::Error {
            message: format!("Failed to save: {}", e),
        };
    }
    info!("Added new host with domains: {:?}", new_host.domains);
    ControlResponse::Success {
        message: format!(
            "Host added successfully with domains: {:?}",
            new_host.domains
        ),
        data: None,
    }
}

async fn update_host(
    config: SharedConfig,
    id: String,
    updated_host: PartialHostConfig,
) -> ControlResponse {
    let mut cfg = config.write().await;
    let host = cfg.hosts.get_mut(&id);
    match host {
        Some(index) => {
            let mut config = index.config.clone();
            config.apply_some(updated_host);
            *index = Arc::new(config.into());
            if let Err(e) = cfg.save_to_file(&CONFIG_FILE).await {
                return ControlResponse::Error {
                    message: format!("Failed to save: {}", e),
                };
            }

            info!("Updated host for ID: {}", id);
            ControlResponse::Success {
                message: format!("Host updated successfully for ID: {}", id),
                data: None,
            }
        }
        None => ControlResponse::Error {
            message: format!("No host found with ID: {}", id),
        },
    }
}

async fn remove_host(config: SharedConfig, id: String) -> ControlResponse {
    let mut cfg = config.write().await;
    let removed_host = cfg.hosts.remove(&id);
    match removed_host {
        Some(removed_host) => {
            if let Err(e) = cfg.save_to_file(&CONFIG_FILE).await {
                return ControlResponse::Error {
                    message: format!("Failed to save: {}", e),
                };
            }

            info!(
                "Removed host with domains: {:?}",
                removed_host.config.domains
            );
            ControlResponse::Success {
                message: format!(
                    "Host removed successfully with domains: {:?}",
                    removed_host.config.domains
                ),
                data: None,
            }
        }
        None => ControlResponse::Error {
            message: format!("No host found with ID: {}", id),
        },
    }
}

async fn list_hosts(config: SharedConfig) -> ControlResponse {
    let cfg = config.read().await;
    let cfg: Config = (&*cfg).into();
    let hosts_json =
        serde_json::to_value(&cfg.hosts).unwrap_or(serde_json::Value::Null);
    ControlResponse::Success {
        message: format!("Found {} host(s)", cfg.hosts.len()),
        data: Some(hosts_json),
    }
}

async fn get_host(config: SharedConfig, id: String) -> ControlResponse {
    let cfg = config.read().await;
    match cfg.hosts.get(&id) {
        Some(host) => {
            let host_json = serde_json::to_value(&host.config).unwrap_or(serde_json::Value::Null);
            ControlResponse::Success {
                message: format!("Found host for ID: {}", id),
                data: Some(host_json),
            }
        }
        None => ControlResponse::Error {
            message: format!("No host found with ID: {}", id),
        },
    }
}

async fn reload_config(config: SharedConfig) -> ControlResponse {
    match crate::config::FullConfig::load_from_file(&CONFIG_FILE).await {
        Ok(new_config) => {
            let mut cfg = config.write().await;
            *cfg = new_config;
            info!("Configuration reloaded from file");
            ControlResponse::Success {
                message: "Configuration reloaded successfully".to_string(),
                data: None,
            }
        }
        Err(e) => ControlResponse::Error {
            message: format!("Failed to reload configuration: {}", e),
        },
    }
}
