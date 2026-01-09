use anyhow::{Context, Result};
use quiche::Config;
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Sleep};
use tracing::{debug, error, info, warn};

use crate::tcp_forwarder::TcpEvent;
use crate::{
    protocol::{
        ArchivedDatagramMessage, ArchivedProtocolS2C, ArchivedStreamS2C,
        DatagramMessage, ProtocolC2S, StreamC2S,
    },
    tcp_forwarder::TcpForwarder,
    udp_forwarder::UdpForwarder,
};

const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB max buffer
const MAX_DATAGRAM_SIZE: usize = 1350;

// TODO: determine if GSO is needed
// TODO: also put this on the server 
#[cfg(target_os = "linux")]
pub fn try_enable_udp_gro(socket: &UdpSocket) -> Result<()> {
    use nix::sys::socket::{setsockopt, sockopt::UdpGroSegment};

    setsockopt(socket, UdpGroSegment, &true).context("Failed to enable UDP GRO on socket")
}

pub struct Tunnel {
    socket: UdpSocket,
    quic: quiche::Connection,
    server_endpoint: SocketAddr,
    stream_buffers: HashMap<u64, Vec<u8>>,
    tcp_stream_map: HashMap<u64, u64>, // TCP connection ID -> QUIC stream ID
    next_stream_id: u64, // see: IETF specification
    shared_secret: u64,
    is_established: bool,
}

impl Tunnel {
    pub async fn new(server_endpoint: SocketAddr, shared_secret: &str) -> Result<Self> {
        let mut quic_config = Config::new(quiche::PROTOCOL_VERSION)
            .context("Failed to create QUIC config")?;
        quic_config.set_application_protos(&[b"radiance-outpost"])?;
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

        // TODO: proper cert verification
        quic_config.verify_peer(false);

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let socket = UdpSocket::bind(bind_addr).await.context("Failed to bind UDP socket")?;
        #[cfg(target_os = "linux")]
        try_enable_udp_gro(&socket)?;

        info!(
            "Tunnel initialized on {} -> {}",
            socket.local_addr()?,
            server_endpoint
        );

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::rng().fill_bytes(&mut scid);
        let connection_id = quiche::ConnectionId::from_ref(&scid);

        let local_addr = socket.local_addr()?;
        let quic = quiche::connect(None, &connection_id, local_addr, server_endpoint, &mut quic_config)
            .context("Failed to create QUIC connection")?;

        Ok(Self {
            socket,
            quic,
            server_endpoint,
            stream_buffers: HashMap::new(),
            tcp_stream_map: HashMap::new(),
            next_stream_id: 4,
            shared_secret: u64::from_str_radix(shared_secret, 16)
                .context("Invalid shared secret (must be hex)")?,
            is_established: false,
        })
    }
    
    pub async fn run(&mut self, tcp: TcpForwarder, udp: UdpForwarder) -> Result<()> {
        let mut buf = [0; 65535];
        self.flush_egress().await?;
        loop {
            let mut timeout: Pin<Box<Sleep>> = if let Some(quic_timeout) = self.quic.timeout() {
                Box::pin(sleep(quic_timeout))
            } else {
                Box::pin(sleep(Duration::from_secs(3600)))
            };

            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            if addr != self.server_endpoint {
                                warn!("Received packet from unexpected address: {}", addr);
                                continue;
                            }
                            // NOTE: 0.0.0.0 != 127.0.0.1
                            debug!("Received {} bytes from server, is_established: {}, quic.is_established(): {}", 
                                len, self.is_established, self.quic.is_established());
                            if let Err(e) = self.handle_incoming_packet(&mut buf[..len], addr).await {
                                error!("Error handling incoming packet: {}", e);
                            }
                            if !self.is_established && self.quic.is_established() {
                                self.is_established = true;
                                info!("QUIC connection established");
                                let msg = StreamC2S {
                                    cid: self.shared_secret,
                                    msg: ProtocolC2S::Identify,
                                };
                                let buf = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)
                                    .context("Failed to serialize Identify message")?;
                                let mut send_buf = Vec::new();
                                send_buf.extend_from_slice(&(buf.len() as u16).to_be_bytes());
                                send_buf.extend_from_slice(&buf);
                                match self.quic.stream_send(0, &send_buf, false) {
                                    Ok(written) => {
                                        if written < send_buf.len() {
                                            warn!(
                                                "Partial write to stream 0: {} < {}",
                                                written,
                                                send_buf.len()
                                            );
                                        }
                                    }
                                    Err(quiche::Error::Done) => {
                                        debug!("Stream 0 blocked, will retry");
                                    }
                                    Err(e) => {
                                        error!("Failed to send Identify message over QUIC: {:?}", e);
                                    }
                                }
                            }
                            if let Err(e) = self.process_readable_streams(&tcp).await {
                                error!("Error processing streams: {}", e);
                            }
                            if let Err(e) = self.process_datagrams(&udp).await {
                                error!("Error processing datagrams: {}", e);
                            }
                            self.flush_egress().await?;
                        }
                        Err(e) => {
                            error!("UDP socket receive error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                _ = &mut timeout => {
                    debug!("QUIC timeout triggered");
                    self.quic.on_timeout();
                    self.flush_egress().await?;
                }

                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    if self.is_established {
                        if let Err(e) = self.send_tcp_events(&tcp).await {
                            error!("Error sending TCP events: {}", e);
                        }
                        if let Err(e) = self.send_tcp_data(&tcp).await {
                            error!("Error sending TCP data: {}", e);
                        }
                        if let Err(e) = self.send_udp_data(&udp).await {
                            error!("Error sending UDP data: {}", e);
                        }
                    }
                    self.flush_egress().await?;
                }
            }

            if self.quic.is_closed() {
                warn!("QUIC connection closed");
                warn!("Timed out: {:?}", self.quic.is_timed_out());
                return Err(anyhow::anyhow!("QUIC connection closed"));
            }
        }
    }

    async fn handle_incoming_packet(&mut self, packet: &mut [u8], from: SocketAddr) -> Result<()> {
        let local_addr = self.socket.local_addr()?;
        let info = quiche::RecvInfo {
            from,
            to: local_addr,
        };
        self.quic.recv(packet, info).context("Failed to process incoming QUIC packet")?;
        Ok(())
    }

    async fn process_readable_streams(&mut self, tcp: &TcpForwarder) -> Result<()> {
        for stream_id in self.quic.readable() {
            loop {
                let mut stream_buf = [0u8; 8192];
                match self.quic.stream_recv(stream_id, &mut stream_buf) {
                    Ok((read_len, fin)) => {
                        let buffer = self.stream_buffers.entry(stream_id).or_insert_with(Vec::new);
                        if buffer.len() + read_len > MAX_BUFFER_SIZE {
                            warn!(
                                "Stream {} buffer size limit exceeded, dropping connection",
                                stream_id
                            );
                            self.stream_buffers.remove(&stream_id);
                            let _ = self.quic.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
                            break;
                        }
                        buffer.extend_from_slice(&stream_buf[..read_len]);
                        self.process_stream_messages(stream_id, tcp)?;
                        if fin {
                            self.stream_buffers.remove(&stream_id);
                            break;
                        }
                        // TODO: cleanup tcp stream
                    }
                    Err(quiche::Error::Done) => {
                        break;
                    }
                    Err(e) => {
                        error!("Failed to read from stream {}: {:?}", stream_id, e);
                        self.stream_buffers.remove(&stream_id);
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn process_stream_messages(&mut self, stream_id: u64, tcp: &TcpForwarder) -> Result<()> {
        let buffer = match self.stream_buffers.get_mut(&stream_id) {
            Some(b) => b,
            None => return Ok(()),
        };
        while buffer.len() >= 2 {
            let msg_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
            if buffer.len() < msg_len + 2 {
                break;
            }
            let msg_data: Vec<u8> = buffer.drain(0..msg_len + 2).skip(2).collect();
            match rkyv::access::<ArchivedStreamS2C, rkyv::rancor::Error>(&msg_data) {
                Ok(data) => {
                    if data.cid.to_native() != self.shared_secret {
                        warn!("Received message with invalid cid: {}", data.cid);
                        continue;
                    }
                    info!("Processing stream message: {:?}", data.msg);
                    match &data.msg {
                        ArchivedProtocolS2C::Tcp { id, data } => {
                            let tcp_id = id.to_native();
                            self.tcp_stream_map.entry(tcp_id).or_insert(stream_id);
                            tcp.send_data(tcp_id, data.as_slice());
                        }
                        ArchivedProtocolS2C::TcpConnect { id, destination_host, destination_port } => {
                            let tcp_id = id.to_native();
                            self.tcp_stream_map.entry(tcp_id).or_insert(stream_id);
                            tcp.connect(tcp_id, destination_host.as_str(), destination_port.to_native());
                        }
                        ArchivedProtocolS2C::TcpDisconnect { id } => {
                            let tcp_id = id.to_native();
                            self.tcp_stream_map.remove(&tcp_id);
                            tcp.disconnect(tcp_id);
                        }
                        ArchivedProtocolS2C::SignalFwdAdd { host, port, req } => {
                            debug!("TODO: SignalFwdAdd {}:{}", host, port);
                        }
                        ArchivedProtocolS2C::SignalFwdRemove { host, port, req } => {
                            debug!("TODO: SignalFwdRemove {}:{}", host, port);
                        }
                        ArchivedProtocolS2C::SignalFwdList { req } => {
                            debug!("TODO: SignalFwdList");
                        }
                        ArchivedProtocolS2C::Dns { host, req } => {
                            debug!("TODO: DNS query for {}", host);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize message: {:?}", e);
                }
            }
        }

        Ok(())
    }

    async fn process_datagrams(&mut self, udp: &UdpForwarder) -> Result<()> {
        while self.quic.dgram_recv_queue_len() > 0 {
            let mut dgram_buf = [0u8; 65535];
            match self.quic.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    match rkyv::access::<ArchivedDatagramMessage, rkyv::rancor::Error>(
                        &dgram_buf[..len],
                    ) {
                        Ok(data) => {
                            if data.cid.to_native() != self.shared_secret {
                                warn!("Received datagram with invalid cid: {}", data.cid);
                                continue;
                            }
                            udp.delegate(data.data.as_slice(), &data.host, data.port.to_native());
                        }
                        Err(e) => {
                            warn!("Failed to deserialize datagram: {:?}", e);
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

    async fn send_tcp_events(&mut self, tcp: &TcpForwarder) -> Result<()> {
        while let Some(event) = tcp.flush_events() {
            info!("Sending TCP event: {:?}", event);
            match event {
                TcpEvent::Connected { id } => {
                    let msg = StreamC2S {
                        cid: self.shared_secret,
                        msg: ProtocolC2S::TcpConnect { id },
                    };
                    
                    let buf = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)
                        .context("Failed to serialize TcpConnect message")?;
                    let mut send_buf = Vec::new();
                    send_buf.extend_from_slice(&(buf.len() as u16).to_be_bytes());
                    send_buf.extend_from_slice(&buf);
                    
                    let stream_id = if let Some(&sid) = self.tcp_stream_map.get(&id) {
                        sid
                    } else {
                        let sid = self.next_stream_id;
                        self.tcp_stream_map.insert(id, sid);
                        self.next_stream_id += 4;
                        sid
                    };
                    
                    match self.quic.stream_send(stream_id, &send_buf, false) {
                        Ok(written) => {
                            if written < send_buf.len() {
                                warn!("Partial write to stream {}: {} < {}", stream_id, written, send_buf.len());
                            }
                        }
                        Err(quiche::Error::Done) => {
                            debug!("Stream {} blocked, will retry", stream_id);
                        }
                        Err(e) => {
                            error!("Failed to send TcpConnect message over QUIC: {:?}", e);
                        }
                    }
                }
                TcpEvent::Disconnected { id } => {
                    let msg = StreamC2S {
                        cid: self.shared_secret,
                        msg: ProtocolC2S::TcpDisconnect { id },
                    };
                    
                    let buf = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)
                        .context("Failed to serialize TcpDisconnect message")?;
                    let mut send_buf = Vec::new();
                    send_buf.extend_from_slice(&(buf.len() as u16).to_be_bytes());
                    send_buf.extend_from_slice(&buf);
                    
                    if let Some(&stream_id) = self.tcp_stream_map.get(&id) {
                        match self.quic.stream_send(stream_id, &send_buf, false) {
                            Ok(written) => {
                                if written < send_buf.len() {
                                    warn!("Partial write to stream {}: {} < {}", stream_id, written, send_buf.len());
                                }
                            }
                            Err(quiche::Error::Done) => {
                                debug!("Stream {} blocked, will retry", stream_id);
                            }
                            Err(e) => {
                                error!("Failed to send TcpDisconnect message over QUIC: {:?}", e);
                            }
                        }
                        self.tcp_stream_map.remove(&id);
                    }
                }
            }
        }
        Ok(())
    }
    
    async fn send_tcp_data(&mut self, tcp: &TcpForwarder) -> Result<()> {
        while let Some(data) = tcp.flush() {
            let stream_id = if let Some(&sid) = self.tcp_stream_map.get(&data.id) {
                sid
            } else {
                // this shouldn't happen, but create a new stream just in case
                let sid = self.next_stream_id;
                self.tcp_stream_map.insert(data.id, sid);
                self.next_stream_id += 4; 
                sid
            };

            let msg = StreamC2S {
                cid: self.shared_secret,
                msg: ProtocolC2S::Tcp {
                    source_host: data.source_host,
                    source_port: data.source_port,
                    data: data.data,
                    id: data.id,
                },
            };

            let buf = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)
                .context("Failed to serialize TCP message")?;
            let mut send_buf = Vec::new();
            send_buf.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            send_buf.extend_from_slice(&buf);

            match self.quic.stream_send(stream_id, &send_buf, false) {
                Ok(written) => {
                    if written < send_buf.len() {
                        warn!(
                            "Partial write to stream {}: {} < {}",
                            stream_id,
                            written,
                            send_buf.len()
                        );
                    }
                }
                Err(quiche::Error::Done) => {
                    debug!("Stream {} blocked, will retry", stream_id);
                }
                Err(e) => {
                    error!("Failed to send TCP message over QUIC: {:?}", e);
                    self.tcp_stream_map.remove(&data.id);
                }
            }
        }
        Ok(())
    }

    async fn send_udp_data(&mut self, udp: &UdpForwarder) -> Result<()> {
        while let Some((data, host, port)) = udp.flush() {
            let msg = DatagramMessage {
                cid: self.shared_secret,
                data,
                host,
                port,
            };
            let buf = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)
                .context("Failed to serialize datagram")?;

            match self.quic.dgram_send(&buf) {
                Ok(_) => {}
                Err(quiche::Error::Done) => {
                    debug!("Datagram queue full, dropping packet");
                }
                Err(e) => {
                    error!("Failed to send datagram over QUIC: {:?}", e);
                }
            }
        }
        Ok(())
    }

    async fn flush_egress(&mut self) -> Result<()> {
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        loop {
            match self.quic.send(&mut buf) {
                Ok((len, send_info)) => {
                    debug!("Sending {} bytes to server", len);
                    self.socket
                        .send_to(&buf[..len], send_info.to)
                        .await
                        .context("Failed to send QUIC packet")?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Failed to create QUIC packet: {:?}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}
