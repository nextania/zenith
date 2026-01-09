use anyhow::{Context, Result};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info};

pub struct TcpOutgoingData {
    pub source_host: String,
    pub source_port: u16,
    pub data: Vec<u8>,
    pub id: u64,
}
#[derive(Debug)]
pub enum TcpEvent {
    Connected { id: u64 },
    Disconnected { id: u64 },
}

#[derive(Clone)]
pub struct TcpForwarder {
    // TODO: manage connection timeouts
    connections: Arc<DashMap<u64, TcpConnection>>,
    outgoing_tx: mpsc::UnboundedSender<TcpOutgoingData>,
    outgoing_rx: Arc<Mutex<mpsc::UnboundedReceiver<TcpOutgoingData>>>,
    event_tx: mpsc::UnboundedSender<TcpEvent>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<TcpEvent>>>,
}

struct TcpConnection {
    write_half: Arc<Mutex<OwnedWriteHalf>>,
    destination_host: String,
    destination_port: u16,
}

impl TcpForwarder {
    pub fn new() -> Self {
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            connections: Arc::new(DashMap::new()),
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(outgoing_rx)),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }
    
    pub fn connect(&self, id: u64, destination_host: &str, destination_port: u16) {
        let outgoing_tx = self.outgoing_tx.clone();
        let event_tx = self.event_tx.clone();
        let connections = self.connections.clone();
        let destination_host = destination_host.to_string();
        tokio::spawn(async move {            
            if connections.contains_key(&id) {
                info!("TCP connection {} already exists", id);
                return;
            }
            info!("Creating new TCP connection {} to {}:{}", id, destination_host, destination_port);
            let target_addr = format!("{}:{}", destination_host, destination_port);
            match TcpStream::connect(&target_addr).await {
                Ok(stream) => {
                    info!("TCP connection {} established to {}", id, target_addr);
                    let (read_half, write_half) = stream.into_split();
                    let connection = TcpConnection {
                        write_half: Arc::new(Mutex::new(write_half)),
                        destination_host: destination_host.clone(),
                        destination_port,
                    };

                    let outgoing_tx_clone = outgoing_tx.clone();
                    let dest_host = destination_host.clone();
                    let connections_clone = connections.clone();
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::read_from_connection(
                            id,
                            read_half,
                            dest_host,
                            destination_port,
                            outgoing_tx_clone,
                        ).await {
                            debug!("TCP connection {} read error: {}", id, e);
                        }

                        connections_clone.remove(&id);
                        let _ = event_tx_clone.send(TcpEvent::Disconnected { id });
                        info!("TCP connection {} closed", id);
                    });
                    connections.insert(id, connection);
                    let _ = event_tx.send(TcpEvent::Connected { id });
                }
                Err(e) => {
                    error!("Failed to connect to {}:{}: {}", destination_host, destination_port, e);
                    return;
                }
            }
        });
    }
    
    pub fn send_data(&self, id: u64, data: &[u8]) {
        let connections = self.connections.clone();
        let data = data.to_vec();
        debug!("Forwarding {} bytes to TCP connection {}", data.len(), id);
        tokio::spawn(async move {
            if let Some(connection) = connections.get(&id) {
                let mut write_half = connection.write_half.lock().await;
                if let Err(e) = write_half.write_all(&data).await {
                    error!("Failed to write to TCP connection {}: {}", id, e);
                    connections.remove(&id);
                } else {
                    debug!("TCP connection {} forwarded {} bytes to destination", id, data.len());
                }
            } else {
                error!("TCP connection {} not found for sending data", id);
            }
        });
    }
    
    pub fn disconnect(&self, id: u64) {
        let connections = self.connections.clone();
        tokio::spawn(async move {
            if let Some((_, connection)) = connections.remove(&id) {
                info!("Disconnecting TCP connection {}", id);
                drop(connection);
            }
        });
    }
    
    pub fn flush(&self) -> Option<TcpOutgoingData> {
        self.outgoing_rx.try_lock().ok()?.try_recv().ok()
    }
    
    pub fn flush_events(&self) -> Option<TcpEvent> {
        self.event_rx.try_lock().ok()?.try_recv().ok()
    }
    
    async fn read_from_connection(
        id: u64,
        mut read_half: OwnedReadHalf,
        source_host: String,
        source_port: u16,
        outgoing_tx: mpsc::UnboundedSender<TcpOutgoingData>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 8192];
        loop {
            let n = read_half
                .read(&mut buffer)
                .await
                .context("Failed to read from connection")?;
            if n == 0 {
                // EOF
                break;
            }
            let outgoing = TcpOutgoingData {
                source_host: source_host.clone(),
                source_port,
                data: buffer[..n].to_vec(),
                id,
            };
            if outgoing_tx.send(outgoing).is_err() {
                error!("Failed to send outgoing TCP data for connection {}", id);
                break;
            }
            debug!("TCP connection {} read {} bytes from destination", id, n);
        }
        Ok(())
    }
}
