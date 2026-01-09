use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use dashmap::DashMap;
use lazy_static::lazy_static;
use tracing::{debug, error, info, warn};
use quiche::RecvInfo;
use rand::RngCore;
use tokio::{net::UdpSocket, sync::{mpsc::UnboundedSender, oneshot}, time::sleep};

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

const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB max buffer
const MAX_DATAGRAM_SIZE: usize = 1350;

fn flush_quic_packets(
    quic: &mut quiche::Connection,
    out_tx: &UnboundedSender<(Vec<u8>, SocketAddr)>,
) -> Result<(), ()> {
    let mut out_buf = [0u8; 65535];
    loop {
        match quic.send(&mut out_buf) {
            Ok((len, info)) => {
                let packet = out_buf[..len].to_vec();
                if let Err(e) = out_tx.send((packet, info.to)) {
                    error!("Failed to send packet to UDP socket: {}", e);
                    return Err(());
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                error!("Failed to send QUIC packet: {}", e);
                return Err(());
            }
        }
    }
    Ok(())
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
    cid: u64,
    outposts: &HashMap<String, OutpostConfig>,
) -> Option<(String, OutpostConfig)> {
    outposts.iter().find_map(|(id, outpost)| {
        let expected_cid = u64::from_str_radix(&outpost.shared_secret, 16).ok()?;
        if expected_cid == cid {
            Some((id.clone(), outpost.clone()))
        } else {
            None
        }
    })
}

fn process_stream_message(
    msg_data: &[u8],
    outposts: &HashMap<String, OutpostConfig>,
) -> Result<Option<(String, OutpostConfig)>, ()> {
    match rkyv::access::<ArchivedStreamC2S, rkyv::rancor::Error>(msg_data) {
        Ok(data) => {
            let cid = data.cid.to_native();
            let outpost = validate_cid(cid, outposts);
            if outpost.is_none() {
                warn!("Received message with invalid cid: {}", cid);
                return Err(());
            }
            debug!("Received message: {:?}", data.msg);
            handle_protocol_message(&data.msg);
            Ok(outpost)
        }
        Err(e) => {
            warn!("Failed to deserialize message: {:?}", e);
            Err(())
        }
    }
}

fn process_readable_streams(
    quic: &mut quiche::Connection,
    stream_buffers: &mut HashMap<u64, Vec<u8>>,
    outposts: &HashMap<String, OutpostConfig>,
    current_cid: &mut Option<(String, OutpostConfig)>,
) -> Result<(), ()> {
    for stream_id in quic.readable() {
        debug!("Readable stream {}", stream_id);
        loop {
            let mut stream_buf = [0u8; 8192];
            match quic.stream_recv(stream_id, &mut stream_buf) {
                Ok((read_len, fin)) => {
                    let buffer = stream_buffers.entry(stream_id).or_insert_with(Vec::new);
                    if buffer.len() + read_len > MAX_BUFFER_SIZE {
                        warn!("Stream {} buffer size limit exceeded", stream_id);
                        stream_buffers.remove(&stream_id);
                        let _ = quic.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
                        break;
                    }
                    buffer.extend_from_slice(&stream_buf[..read_len]);
                    while buffer.len() >= 2 {
                        let msg_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                        if buffer.len() < msg_len + 2 {
                            // not enough data yet
                            break; 
                        }
                        let msg_data: Vec<u8> = buffer.drain(0..msg_len + 2).skip(2).collect();
                        match process_stream_message(&msg_data, outposts) {
                            Ok(Some(outpost)) => {
                                *current_cid = Some(outpost);
                            }
                            Ok(None) => {}
                            Err(_) => return Err(()),
                        }
                    }
                    if fin {
                        stream_buffers.remove(&stream_id);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Failed to read from stream {}: {:?}", stream_id, e);
                    stream_buffers.remove(&stream_id);
                    break;
                }
            }
        }
    }
    Ok(())
}

fn process_datagrams(
    quic: &mut quiche::Connection,
    outposts: &HashMap<String, OutpostConfig>,
    current_cid: &mut Option<(String, OutpostConfig)>,
) -> Result<(), ()> {
    while quic.dgram_recv_queue_len() > 0 {
        let mut dgram_buf = [0u8; 65535];
        match quic.dgram_recv(&mut dgram_buf) {
            Ok(len) => {
                match rkyv::access::<ArchivedDatagramMessage, rkyv::rancor::Error>(&dgram_buf[..len]) {
                    Ok(data) => {
                        let outpost = validate_cid(data.cid.to_native(), outposts);
                        if outpost.is_none() {
                            warn!("Received datagram with invalid cid: {}", data.cid);
                            return Err(());
                        }
                        *current_cid = outpost;
                        // FIXME: UDP not implemented yet
                    }
                    Err(e) => {
                        warn!("Failed to deserialize datagram: {:?}", e);
                        return Err(());
                    }
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!("Failed to read datagram: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}

fn send_outgoing_messages(
    quic: &mut quiche::Connection,
    streams_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ProtocolS2C>,
    tcp_stream_map: &mut HashMap<u64, u64>,
    next_stream_id: &mut u64,
    shared_secret: &str,
) {
    while let Ok(msg) = streams_rx.try_recv() {
        let mut tcp_id = None;
        
        let stream_id = if let ProtocolS2C::Tcp { id, .. } | ProtocolS2C::TcpDisconnect { id } = &msg {
            tcp_id = Some(*id);
            if let Some(sid) = tcp_stream_map.get(id) {
                *sid
            } else {
                let sid = *next_stream_id;
                tcp_stream_map.insert(*id, sid);
                *next_stream_id += 4; 
                sid
            }
        } else {
            let sid = *next_stream_id;
            *next_stream_id += 4;
            sid
        };

        let data = StreamS2C {
            cid: u64::from_str_radix(shared_secret, 16).unwrap(),
            msg,
        };
        
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&data).unwrap();
        let mut send_buf = Vec::with_capacity(2 + serialized.len());
        let len_bytes = (serialized.len() as u16).to_be_bytes();
        send_buf.extend_from_slice(&len_bytes);
        send_buf.extend_from_slice(&serialized);

        match quic.stream_send(stream_id, &send_buf, false) {
            Ok(written) => {
                if written < send_buf.len() {
                    warn!("Partial write to stream {}: {} < {}", stream_id, written, send_buf.len());
                }
                debug!("Sent {} bytes on stream {}", written, stream_id);
            }
            Err(quiche::Error::Done) => {
                debug!("Stream {} blocked, will retry", stream_id);
            }
            Err(e) => {
                error!("Failed to send message over QUIC: {:?}", e);
                if let Some(id) = tcp_id {
                    tcp_stream_map.remove(&id);
                }
            }
        }
    }
}

pub fn make_config() -> anyhow::Result<quiche::Config> {
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    quic_config.set_application_protos(&[b"radiance-outpost"])?;
    // TODO: load certificates from memory
    // this can only be done with the boringssl-boring-crate
    // but this causes some build issues and unnecessary dependency on openssl
    quic_config.load_cert_chain_from_pem_file("certs/internal-dns.crt")?;
    quic_config.load_priv_key_from_pem_file("certs/internal-dns.key")?;
    quic_config.set_max_idle_timeout(60000); // 60 seconds
    quic_config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_initial_max_data(10_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quic_config.set_initial_max_streams_bidi(1000000);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, 1000, 1000);
    Ok(quic_config)
}

pub async fn initialize_outposts(local_addr: SocketAddr, outposts: HashMap<String, OutpostConfig>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(local_addr).await?;
    info!("Outpost listener bound on {}", local_addr);
    let quic_instances: Arc<DashMap<SocketAddr, UnboundedSender<Vec<u8>>>> = Arc::new(DashMap::new());
    // this socketaddr is for the outpost itself
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
    let mut buf = [0; 65535];   
    loop {
        tokio::select! {
            Ok((i, addr)) = socket.recv_from(&mut buf) => {
                info!("Received packet from {}", addr);
                if !quic_instances.contains_key(&addr) {
                    let hdr = match quiche::Header::from_slice(&mut buf[..i], quiche::MAX_CONN_ID_LEN) {
                        Ok(h) => h,
                        Err(e) => {
                            warn!("Failed to parse QUIC header from {}: {:?}", addr, e);
                            continue;
                        }
                    };
                    let dcid = hdr.dcid.clone();
                    
                    // this channel is for underlying udp socket recv -> quic instance
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    // this channel is for socket proxy (__TCP__) -> quic instance
                    // this socketaddr is for the target on the outpost
                    let (streams_tx, mut streams_rx) = tokio::sync::mpsc::unbounded_channel::<ProtocolS2C>();
                    quic_instances.insert(addr, tx);
                    let quic_instances = quic_instances.clone();
                    let outposts = outposts.clone();
                    let out_tx = out_tx.clone();
                    tokio::spawn(async move {
                        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                        rand::rng().fill_bytes(&mut scid);
                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let mut quic_config = make_config()?;
                        let quic = quiche::accept(&scid, Some(&dcid), local_addr, addr, &mut quic_config)
                            .context("Failed to create QUIC connection");
                        let mut quic = match quic {
                            Ok(q) => q,
                            Err(e) => {
                                error!("Failed to accept QUIC connection: {}", e);
                                quic_instances.remove(&addr);
                                return Ok::<(), anyhow::Error>(());
                            }
                        };
                        
                        let mut stream_buffers: HashMap<u64, Vec<u8>> = HashMap::new();
                        let mut tcp_stream_map: HashMap<u64, u64> = HashMap::new();
                        let mut next_stream_id: u64 = 1; // see also: IETF specification (server-initiated bidirectional streams)
                        let mut outpost_identity: Option<(String, OutpostConfig)> = None;
                        let streams_tx = streams_tx.clone();
                        'connection_loop: loop {
                            let timeout = if let Some(quic_timeout) = quic.timeout() {
                                quic_timeout
                            } else {
                                Duration::from_secs(3600)
                            };
                            tokio::select! {
                                Some(mut packet_buf) = rx.recv() => {
                                    let result = quic.recv(&mut packet_buf, RecvInfo {
                                        from: addr,
                                        to: local_addr,
                                    });
                                    
                                    // if something bad happens here, we drop the connection
                                    if let Err(e) = result {
                                        error!("Failed to process QUIC packet: {}", e);
                                        quic_instances.remove(&addr);
                                        if let Some(identity) = outpost_identity {
                                            ACTIVE_OUTPOSTS.remove(&identity.0);
                                        }
                                        break 'connection_loop;
                                    }
                                    if quic.is_closed() || quic.is_timed_out() {
                                        quic_instances.remove(&addr);
                                        break 'connection_loop;
                                    }
                                    if quic.is_established() {
                                        if process_readable_streams(
                                            &mut quic,
                                            &mut stream_buffers,
                                            &outposts,
                                            &mut outpost_identity,
                                        ).is_err() {
                                            break 'connection_loop;
                                        }
                                        if process_datagrams(
                                            &mut quic,
                                            &outposts,
                                            &mut outpost_identity,
                                        ).is_err() {
                                            break 'connection_loop;
                                        }
                                    }
                                    if flush_quic_packets(&mut quic, &out_tx).is_err() {
                                        break 'connection_loop;
                                    }
                                    
                                    if let Some(identity) = &outpost_identity && !ACTIVE_OUTPOSTS.contains_key(&identity.0) {
                                        ACTIVE_OUTPOSTS.insert(identity.0.clone(), streams_tx.clone());
                                    }
                                }

                                _ = sleep(timeout) => {
                                    debug!("QUIC timeout triggered");
                                    quic.on_timeout();

                                    if quic.is_closed() {
                                        info!("QUIC connection closed (timed out: {})", quic.is_timed_out());
                                        quic_instances.remove(&addr);
                                        if let Some(identity) = outpost_identity {
                                            ACTIVE_OUTPOSTS.remove(&identity.0);
                                        }
                                        break 'connection_loop;
                                    }
                                }

                                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                                    if quic.is_established() {
                                        if let Some(identity) = &outpost_identity {
                                            send_outgoing_messages(
                                                &mut quic,
                                                &mut streams_rx,
                                                &mut tcp_stream_map,
                                                &mut next_stream_id,
                                                &identity.1.shared_secret,
                                            );
                                        }

                                        // TODO: datagrams (future UDP support)
                                    }
                                    
                                    if flush_quic_packets(&mut quic, &out_tx).is_err() {
                                        break 'connection_loop;
                                    }
                                }
                            }
                        }
                        Ok::<(), anyhow::Error>(())
                    });
                }
                // get the quic instance and send to it
                let Some(quic_tx) = quic_instances.get(&addr) else {
                    panic!("This should not happen");
                };
                let data = buf[..i].to_vec();
                if let Err(e) = quic_tx.send(data) {
                    error!("Failed to forward packet to QUIC instance: {}", e);
                }
            }

            result = out_rx.recv() => {
                // read from out_rx and send to udp socket
                if let Some((payload, addr)) = result {
                    socket.send_to(&payload, &addr).await?;
                }
            }
        }
    }
}

