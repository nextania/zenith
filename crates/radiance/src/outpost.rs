use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use dashmap::DashMap;
use lazy_static::lazy_static;
use tracing::{debug, error, info, warn};
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use quinn::{ServerConfig, Endpoint, Connection, RecvStream, SendStream};
use rand::RngCore;

use crate::{config::OutpostConfig, protocol::{ArchivedDatagramMessage, ArchivedProtocolC2S, ArchivedStreamC2S, ProtocolS2C, StreamS2C}};

lazy_static! {
    // TODO: cleanup on disconnect
    // (stream id, bytes)
    pub static ref ACTIVE_OUTPOSTS: DashMap<String, UnboundedSender<ProtocolS2C>> = DashMap::new();
    pub static ref ACTIVE_REQUESTS: DashMap<u64, oneshot::Sender<OutpostResponse>> = DashMap::new();
    pub static ref ACTIVE_TCP_STREAMS: DashMap<u64, UnboundedSender<Vec<u8>>> = DashMap::new();
}
#[derive(Debug)]
pub enum OutpostRequest {
    Tcp {
        data: Vec<u8>,
        id: u64,
    },
    TcpConnect {
        destination_host: String,
        destination_port: u16,
        id: u64,
    },
    TcpDisconnect {
        id: u64,
    },
    SignalFwdAdd {
        host: String,
        port: u16,
    },
    SignalFwdRemove {
        host: String,
        port: u16,
    },
    SignalFwdList,
    Dns {
        host: String,
    },
}
#[derive(Debug)]
pub enum OutpostResponse {
    List(Vec<(String, u16)>),
    Dns((String, String)),
    Ack,
    Done,
}

pub async fn request(outpost_id: String, body: OutpostRequest) -> anyhow::Result<OutpostResponse> {
    
    let outpost = ACTIVE_OUTPOSTS.get(&outpost_id);
    if outpost.is_none() {
        error!("Outpost {} not connected", outpost_id);
        return Err(anyhow::anyhow!("Outpost not connected"));
    }
    // gen new req id;
    let req = match body {
        OutpostRequest::SignalFwdAdd { host, port} => {
            ProtocolS2C::SignalFwdAdd { host, port, req: rand::rng().next_u64() }
        }
        OutpostRequest::Dns { host } => {
            ProtocolS2C::Dns { host, req: rand::rng().next_u64() }
        }
        OutpostRequest::SignalFwdRemove { host, port } => {
            ProtocolS2C::SignalFwdRemove { host, port, req: rand::rng().next_u64() }
        }
        OutpostRequest::SignalFwdList => {
            ProtocolS2C::SignalFwdList { req: rand::rng().next_u64() }
        }
        OutpostRequest::Tcp { data, id } => {
            ProtocolS2C::Tcp { data, id }
        }
        OutpostRequest::TcpConnect { destination_host, destination_port, id } => {
            ProtocolS2C::TcpConnect { destination_host, destination_port, id }
        }
        OutpostRequest::TcpDisconnect { id } => {
            ProtocolS2C::TcpDisconnect { id }
        }
    };

    match req {
        ProtocolS2C::SignalFwdAdd { req: req_id, .. } |
        ProtocolS2C::Dns { req: req_id, .. } |
        ProtocolS2C::SignalFwdRemove { req: req_id, .. } |
        ProtocolS2C::SignalFwdList { req: req_id, .. } |
        ProtocolS2C::TcpConnect { id: req_id , .. } => {
            let (tx, rx) = oneshot::channel();
            ACTIVE_REQUESTS.insert(req_id, tx);
            let outpost = outpost.unwrap();
            outpost.send(req).context("Failed to send OutpostRequest")?;
        
            match rx.await {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!("Failed to receive OutpostResponse: {}", e);
                    Err(anyhow::anyhow!("Failed to receive OutpostResponse"))
                }
            }
        }
        _ => {
            let outpost = outpost.unwrap();
            outpost.send(req).context("Failed to send OutpostRequest")?;
            Ok(OutpostResponse::Done)
        }
    }
}

pub fn make_config() -> anyhow::Result<ServerConfig> {
    // Load certificate and private key
    let cert_path = "certs/internal-dns.crt";
    let key_path = "certs/internal-dns.key";

    let cert_data = std::fs::read(cert_path)
        .context("Failed to read certificate file")?;
    let key_data = std::fs::read(key_path)
        .context("Failed to read private key file")?;

    let cert_chain = rustls_pemfile::certs(&mut &cert_data[..])
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate")?;

    let key = rustls_pemfile::private_key(&mut &key_data[..])
        .context("Failed to parse private key")?
        .context("No private key found")?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("Failed to create rustls server config")?;

    crypto.alpn_protocols = vec![b"radiance-outpost".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .context("Failed to create QUIC server config")?
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    transport_config.receive_window(10_000_000u32.into());
    transport_config.send_window(10_000_000u64);
    transport_config.stream_receive_window(1_000_000u32.into());
    transport_config.max_concurrent_bidi_streams(1000000u32.into());
    transport_config.max_concurrent_uni_streams(100u32.into());
    transport_config.datagram_receive_buffer_size(Some(1000));
    transport_config.datagram_send_buffer_size(1000);
    transport_config.keep_alive_interval(Some(Duration::from_secs(30).try_into().unwrap()));

    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

fn handle_protocol_message(msg: &ArchivedProtocolC2S) {
    match msg {
        ArchivedProtocolC2S::Identify => {
            debug!("Outpost identified");
        }
        ArchivedProtocolC2S::Tcp { id, data, .. } => {
            let id = id.to_native();
            if let Some(sender) = ACTIVE_TCP_STREAMS.get(&id) {
                if let Err(e) = sender.send(data.to_vec()) {
                    warn!("Failed to forward TCP data to stream {}: {:?}", id, e);
                    ACTIVE_TCP_STREAMS.remove(&id);
                }
            } else {
                warn!("Received TCP data for unknown stream id: {}", id);
            }
        }
        ArchivedProtocolC2S::TcpConnect { id } => {
            let id = id.to_native();
            if let Some((_, sender)) = ACTIVE_REQUESTS.remove(&id) {
                let _ = sender.send(OutpostResponse::Ack);
            } else {
                warn!("Received TcpConnect for unknown request id: {}", id);
            }
        }
        ArchivedProtocolC2S::TcpDisconnect { id } => {
            let id = id.to_native();
            if ACTIVE_TCP_STREAMS.remove(&id).is_some() {
                debug!("TCP stream {} disconnected", id);
            } else {
                warn!("Received TcpDisconnect for unknown stream id: {}", id);
            }
        }
        ArchivedProtocolC2S::SignalFwdAdd { req } => {
            let req_id = req.to_native();
            if let Some((_, sender)) = ACTIVE_REQUESTS.remove(&req_id) {
                let _ = sender.send(OutpostResponse::Ack);
            } else {
                warn!("Received SignalFwdAdd for unknown request id: {}", req_id);
            }
        }
        ArchivedProtocolC2S::SignalFwdRemove { req } => {
            let req_id = req.to_native();
            if let Some((_, sender)) = ACTIVE_REQUESTS.remove(&req_id) {
                let _ = sender.send(OutpostResponse::Ack);
            } else {
                warn!("Received SignalFwdRemove for unknown request id: {}", req_id);
            }
        }
        ArchivedProtocolC2S::SignalFwdList { entries, req } => {
            let req_id = req.to_native();
            if let Some((_, sender)) = ACTIVE_REQUESTS.remove(&req_id) {
                let entries_vec: Vec<(String, u16)> = entries
                    .iter()
                    .map(|e| (e.0.to_string(), e.1.to_native()))
                    .collect();
                let _ = sender.send(OutpostResponse::List(entries_vec));
            } else {
                warn!("Received SignalFwdList for unknown request id: {}", req_id);
            }
        }
        ArchivedProtocolC2S::Dns { host, ip, req } => {
            let req_id = req.to_native();
            if let Some((_, sender)) = ACTIVE_REQUESTS.remove(&req_id) {
                let response = (host.to_string(), ip.to_string());
                let _ = sender.send(OutpostResponse::Dns(response));
            } else {
                warn!("Received Dns response for unknown request id: {}", req_id);
            }
        }
    }
}

fn validate_cid(
    cid: u128,
    outposts: &HashMap<String, OutpostConfig>,
) -> Option<(String, OutpostConfig)> {
    outposts.iter().find_map(|(id, outpost)| {
        let expected_cid = u128::from_str_radix(&outpost.shared_secret, 16).ok()?;
        if expected_cid == cid {
            Some((id.clone(), outpost.clone()))
        } else {
            None
        }
    })
}

async fn handle_connection(
    connection: Connection,
    outposts: HashMap<String, OutpostConfig>,
) -> anyhow::Result<()> {
    let remote_addr = connection.remote_address();
    info!("New connection from {}", remote_addr);

    let outpost_identity = Arc::new(tokio::sync::RwLock::new(None::<(String, OutpostConfig)>));
    let (streams_tx, mut streams_rx) = tokio::sync::mpsc::unbounded_channel::<ProtocolS2C>();
    let mut tcp_stream_map: HashMap<u64, SendStream> = HashMap::new();

    loop {
        tokio::select! {
            stream_result = connection.accept_bi() => {
                match stream_result {
                    Ok((_send, recv)) => {
                        let outposts = outposts.clone();
                        let identity = outpost_identity.clone();
                        let streams_tx = streams_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_incoming_stream(recv, outposts, identity, streams_tx).await {
                                error!("Error handling incoming stream: {}", e);
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        info!("Connection closed by peer: {}", remote_addr);
                        break;
                    }
                    Err(e) => {
                        error!("Error accepting stream: {}", e);
                        break;
                    }
                }
            }

            datagram_result = connection.read_datagram() => {
                match datagram_result {
                    Ok(data) => {
                        if let Err(e) = handle_datagram(&data, &outposts, &outpost_identity).await {
                            error!("Error handling datagram: {}", e);
                        }
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        info!("Connection closed by peer: {}", remote_addr);
                        break;
                    }
                    Err(e) => {
                        error!("Error reading datagram: {}", e);
                    }
                }
            }

            Some(msg) = streams_rx.recv() => {
                let identity_guard = outpost_identity.read().await;
                if let Some(identity) = identity_guard.as_ref() {
                    if let Err(e) = send_message(&connection, msg, &mut tcp_stream_map, &identity.1.shared_secret).await {
                        error!("Error sending message: {}", e);
                    }
                }
            }
        }

        if connection.close_reason().is_some() {
            warn!("Connection closed: {:?}", connection.close_reason());
            break;
        }
    }

    let final_identity = outpost_identity.read().await;
    if let Some(identity) = final_identity.as_ref() {
        ACTIVE_OUTPOSTS.remove(&identity.0);
        info!("Outpost {} disconnected", identity.0);
    }

    Ok(())
}

async fn handle_incoming_stream(
    mut recv: RecvStream,
    outposts: HashMap<String, OutpostConfig>,
    current_identity: Arc<tokio::sync::RwLock<Option<(String, OutpostConfig)>>>,
    streams_tx: tokio::sync::mpsc::UnboundedSender<ProtocolS2C>,
) -> anyhow::Result<()> {
    let mut buffer = Vec::new();
    
    loop {
        let mut chunk = [0u8; 8192];
        match recv.read(&mut chunk).await {
            Ok(Some(len)) => {
                buffer.extend_from_slice(&chunk[..len]);
                
                while buffer.len() >= 2 {
                    let msg_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                    if buffer.len() < msg_len + 2 {
                        break;
                    }
                    
                    let msg_data: Vec<u8> = buffer.drain(0..msg_len + 2).skip(2).collect();
                    
                    match rkyv::access::<ArchivedStreamC2S, rkyv::rancor::Error>(&msg_data) {
                        Ok(data) => {
                            let cid = data.cid.to_native();
                            if let Some(outpost) = validate_cid(cid, &outposts) {
                                let mut identity_guard = current_identity.write().await;
                                let should_register = identity_guard.is_none();
                                *identity_guard = Some(outpost.clone());
                                drop(identity_guard);
                                
                                if should_register {
                                    ACTIVE_OUTPOSTS.insert(outpost.0.clone(), streams_tx.clone());
                                    info!("Outpost {} registered", outpost.0);
                                }
                                
                                debug!("Received message: {:?}", data.msg);
                                handle_protocol_message(&data.msg);
                            } else {
                                warn!("Received message with invalid cid: {}", cid);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to deserialize message: {:?}", e);
                        }
                    }
                }
            }
            Ok(None) => {
                debug!("Stream finished");
                break;
            }
            Err(e) => {
                error!("Error reading from stream: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

async fn handle_datagram(
    data: &[u8],
    outposts: &HashMap<String, OutpostConfig>,
    current_identity: &Arc<tokio::sync::RwLock<Option<(String, OutpostConfig)>>>,
) -> anyhow::Result<()> {
    match rkyv::access::<ArchivedDatagramMessage, rkyv::rancor::Error>(data) {
        Ok(msg) => {
            if let Some(outpost) = validate_cid(msg.cid.to_native(), outposts) {
                let mut identity_guard = current_identity.write().await;
                *identity_guard = Some(outpost);
                // FIXME: UDP not implemented yet
            } else {
                warn!("Received datagram with invalid cid: {}", msg.cid);
            }
        }
        Err(e) => {
            warn!("Failed to deserialize datagram: {:?}", e);
        }
    }
    Ok(())
}

async fn send_message(
    connection: &Connection,
    msg: ProtocolS2C,
    tcp_stream_map: &mut HashMap<u64, SendStream>,
    shared_secret: &str,
) -> anyhow::Result<()> {
    let tcp_id = match &msg {
        ProtocolS2C::Tcp { id, .. } | ProtocolS2C::TcpDisconnect { id } => Some(*id),
        _ => None,
    };

    let data = StreamS2C {
        cid: u128::from_str_radix(shared_secret, 16).unwrap(),
        msg,
    };
    
    let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&data).unwrap();
    let mut send_buf = Vec::with_capacity(2 + serialized.len());
    let len_bytes = (serialized.len() as u16).to_be_bytes();
    send_buf.extend_from_slice(&len_bytes);
    send_buf.extend_from_slice(&serialized);

    if let Some(id) = tcp_id {
        if !tcp_stream_map.contains_key(&id) {
            let (send, _recv) = connection.open_bi().await
                .context("Failed to open bi-directional stream")?;
            tcp_stream_map.insert(id, send);
        }
        
        if let Some(stream) = tcp_stream_map.get_mut(&id) {
            stream.write_all(&send_buf).await
                .context("Failed to write to stream")?;
            
            if matches!(data.msg, ProtocolS2C::TcpDisconnect { .. }) {
                let _ = stream.finish();
                tcp_stream_map.remove(&id);
            }
        }
    } else {
        let (mut send, _recv) = connection.open_bi().await
            .context("Failed to open bi-directional stream")?;
        send.write_all(&send_buf).await
            .context("Failed to write to stream")?;
    }

    Ok(())
}

pub async fn initialize_outposts(local_addr: SocketAddr, outposts: HashMap<String, OutpostConfig>) -> anyhow::Result<()> {
    let server_config = make_config()?;
    let endpoint = Endpoint::server(server_config, local_addr)?;
    
    info!("Outpost listener bound on {}", local_addr);

    loop {
        match endpoint.accept().await {
            Some(connecting) => {
                let outposts = outposts.clone();
                tokio::spawn(async move {
                    match connecting.await {
                        Ok(connection) => {
                            if let Err(e) = handle_connection(connection, outposts).await {
                                error!("Connection handler error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Connection failed: {}", e);
                        }
                    }
                });
            }
            None => {
                warn!("Endpoint closed");
                break;
            }
        }
    }

    Ok(())
}

