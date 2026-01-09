mod config;
mod protocol;
mod tcp_forwarder;
mod tunnel;
mod udp_forwarder;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use std::path::PathBuf;
use tcp_forwarder::TcpForwarder;
use tokio::signal;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tunnel::Tunnel;
use udp_forwarder::UdpForwarder;

#[derive(Parser, Debug)]
#[command(name = "radiance-outpost")]
#[command(about = "Reverse tunnel client", long_about = None)]
struct Args {
    #[arg(short, long, env = "OUTPOST_CONFIG", default_value = "outpost.toml")]
    config: PathBuf,

    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("Starting Radiance Outpost");
    rustls::crypto::ring::default_provider().install_default().ok();
    let config = Config::from_file(&args.config).context("Failed to load configuration")?;
    config.validate().context("Invalid configuration")?;

    info!("Configuration loaded: {} ports exposed", config.exposed_ports.len());
    for port in &config.exposed_ports {
        info!(
            "  - {:?} port {} -> {}",
            port.protocol,
            port.port,
            port.local_addr.as_ref().unwrap_or(&format!("127.0.0.1:{}", port.port))
        );
    }
    
    let tunnel_task = tokio::spawn(async move {
        // TODO: persist tunnel sessions
        loop {
            let mut tunnel = Tunnel::new(config.server_endpoint, &config.shared_secret)
                .await
                .expect("Failed to create tunnel");
            let tcp = TcpForwarder::new();
            let udp = UdpForwarder::new()
                .await
                .expect("Failed to create UDP forwarder");
            info!("Outpost running, waiting for connections...");
            tokio::select! {
                _ = tunnel.run(tcp, udp) => {}
                _ = signal::ctrl_c() => {
                    info!("Shutdown signal received, closing tunnel...");
                    break;
                }
            }
        }
    });

    signal::ctrl_c().await?;
    info!("Shutdown signal received, cleaning up...");
    tunnel_task.abort();

    Ok(())
}
