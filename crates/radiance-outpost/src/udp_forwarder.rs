use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error};

#[derive(Clone)]
pub struct UdpForwarder {
    socket: Arc<UdpSocket>,
    outgoing_tx: mpsc::UnboundedSender<(Vec<u8>, String, u16)>,
    outgoing_rx: Arc<Mutex<mpsc::UnboundedReceiver<(Vec<u8>, String, u16)>>>,
}

impl UdpForwarder {
    pub async fn new() -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let forwarder = Self {
            socket: Arc::new(socket),
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(outgoing_rx)),
        };

        let socket_clone = forwarder.socket.clone();
        let outgoing_tx_clone = forwarder.outgoing_tx.clone();
        tokio::spawn(async move {
            Self::read_from_socket(socket_clone, outgoing_tx_clone).await;
        });

        Ok(forwarder)
    }

    pub fn delegate(&self, data: &[u8], host: &str, port: u16) {
        let socket = self.socket.clone();
        let data = data.to_vec();
        let host = host.to_string();
        tokio::spawn(async move {
            let addr = format!("{}:{}", host, port);
            match socket.send_to(&data, &addr).await {
                Ok(_) => {
                    debug!("UDP forwarded {} bytes to {}", data.len(), addr);
                }
                Err(e) => {
                    error!("Failed to send UDP data to {}: {}", addr, e);
                }
            }
        });
    }

    pub fn flush(&self) -> Option<(Vec<u8>, String, u16)> {
        self.outgoing_rx.try_lock().ok()?.try_recv().ok()
    }

    async fn read_from_socket(
        socket: Arc<UdpSocket>,
        outgoing_tx: mpsc::UnboundedSender<(Vec<u8>, String, u16)>,
    ) {
        let mut buffer = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((n, addr)) => {
                    let data = buffer[..n].to_vec();
                    let host = addr.ip().to_string();
                    let port = addr.port();

                    if outgoing_tx.send((data, host, port)).is_err() {
                        error!("Failed to send outgoing UDP data");
                        break;
                    }

                    debug!(
                        "UDP read {} bytes from socket (from {}:{})",
                        n,
                        addr.ip(),
                        addr.port()
                    );
                }
                Err(e) => {
                    error!("UDP socket receive error: {}", e);
                    break;
                }
            }
        }
    }
}
