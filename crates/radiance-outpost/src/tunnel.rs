use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use quinn::{ClientConfig, Endpoint, Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::tcp_forwarder::TcpEvent;
use crate::{
    protocol::{
        ArchivedDatagramMessage, ArchivedProtocolS2C, ArchivedStreamS2C,
        DatagramMessage, ProtocolC2S, StreamC2S,
    },
    tcp_forwarder::TcpForwarder,
    udp_forwarder::UdpForwarder,
};

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub struct Tunnel {
    connection: Connection,
    tcp_stream_map: HashMap<u64, SendStream>, // TCP connection ID -> QUIC send stream
    shared_secret: u128,
}

impl Tunnel {
    pub async fn new(server_endpoint: SocketAddr, shared_secret: &str) -> Result<Self> {
        // TODO: proper server certificate verification
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"radiance-outpost".to_vec()];
        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .context("Failed to create QUIC crypto config")?
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
        client_config.transport_config(Arc::new(transport_config));
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint = Endpoint::client(bind_addr)
            .context("Failed to create QUIC endpoint")?;
        endpoint.set_default_client_config(client_config);
        info!("Tunnel initialized on {} -> {}", endpoint.local_addr()?, server_endpoint);
        let connection = endpoint
            .connect(server_endpoint, "radiance-outpost")
            .context("Failed to initiate connection")?
            .await
            .context("Failed to establish connection")?;
        info!("QUIC connection established to {}", server_endpoint);
        let shared_secret_num = u128::from_str_radix(shared_secret, 16)
            .context("Invalid shared secret (must be hex)")?;
        let msg = StreamC2S {
            cid: shared_secret_num,
            msg: ProtocolC2S::Identify,
        };
        let buf = rkyv::to_bytes::<rkyv::rancor::Error>(&msg)
            .context("Failed to serialize Identify message")?;
        let mut send_buf = Vec::new();
        send_buf.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        send_buf.extend_from_slice(&buf);
        let (mut send, _recv) = connection.open_bi().await.context("Failed to open stream")?;
        send.write_all(&send_buf).await.context("Failed to send identify")?;
        Ok(Self {
            connection,
            tcp_stream_map: HashMap::new(),
            shared_secret: shared_secret_num,
        })
    }
    
    pub async fn run(&mut self, tcp: TcpForwarder, udp: UdpForwarder) -> Result<()> {
        loop {
            tokio::select! {
                stream_result = self.connection.accept_bi() => {
                    match stream_result {
                        Ok((_send, recv)) => {
                            let tcp = tcp.clone();
                            let udp = udp.clone();
                            let shared_secret = self.shared_secret;
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_incoming_stream(recv, tcp, udp, shared_secret).await {
                                    error!("Error handling incoming stream: {}", e);
                                }
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                            info!("Connection closed by peer");
                            return Err(anyhow::anyhow!("Connection closed"));
                        }
                        Err(e) => {
                            error!("Error accepting stream: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                datagram_result = self.connection.read_datagram() => {
                    match datagram_result {
                        Ok(data) => {
                            if let Err(e) = self.handle_datagram(&data, &udp).await {
                                error!("Error handling datagram: {}", e);
                            }
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                            info!("Connection closed by peer");
                            return Err(anyhow::anyhow!("Connection closed"));
                        }
                        Err(e) => {
                            error!("Error reading datagram: {}", e);
                        }
                    }
                }

                _ = tokio::time::sleep(Duration::from_millis(1)) => {
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
            }
            if self.connection.close_reason().is_some() {
                warn!("QUIC connection closed: {:?}", self.connection.close_reason());
                return Err(anyhow::anyhow!("QUIC connection closed"));
            }
        }
    }

    async fn handle_incoming_stream(
        mut recv: RecvStream,
        tcp: TcpForwarder,
        udp: UdpForwarder,
        shared_secret: u128,
    ) -> Result<()> {
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
                        match rkyv::access::<ArchivedStreamS2C, rkyv::rancor::Error>(&msg_data) {
                            Ok(data) => {
                                if data.cid.to_native() != shared_secret {
                                    warn!("Received message with invalid cid: {}", data.cid);
                                    continue;
                                }
                                info!("Processing stream message: {:?}", data.msg);
                                Self::handle_protocol_message(&data.msg, &tcp, &udp);
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

    fn handle_protocol_message(
        msg: &ArchivedProtocolS2C,
        tcp: &TcpForwarder,
        _udp: &UdpForwarder,
    ) {
        match msg {
            ArchivedProtocolS2C::Tcp { id, data } => {
                let tcp_id = id.to_native();
                tcp.send_data(tcp_id, data.as_slice());
            }
            ArchivedProtocolS2C::TcpConnect { id, destination_host, destination_port } => {
                let tcp_id = id.to_native();
                tcp.connect(tcp_id, destination_host.as_str(), destination_port.to_native());
            }
            ArchivedProtocolS2C::TcpDisconnect { id } => {
                let tcp_id = id.to_native();
                tcp.disconnect(tcp_id);
            }
            ArchivedProtocolS2C::SignalFwdAdd { host, port, .. } => {
                debug!("TODO: SignalFwdAdd {}:{}", host, port);
            }
            ArchivedProtocolS2C::SignalFwdRemove { host, port, .. } => {
                debug!("TODO: SignalFwdRemove {}:{}", host, port);
            }
            ArchivedProtocolS2C::SignalFwdList { .. } => {
                debug!("TODO: SignalFwdList");
            }
            ArchivedProtocolS2C::Dns { host, .. } => {
                debug!("TODO: DNS query for {}", host);
            }
        }
    }

    async fn handle_datagram(&self, data: &[u8], udp: &UdpForwarder) -> Result<()> {
        match rkyv::access::<ArchivedDatagramMessage, rkyv::rancor::Error>(data) {
            Ok(msg) => {
                if msg.cid.to_native() != self.shared_secret {
                    warn!("Received datagram with invalid cid: {}", msg.cid);
                    return Ok(());
                }
                udp.delegate(msg.data.as_slice(), &msg.host, msg.port.to_native());
            }
            Err(e) => {
                warn!("Failed to deserialize datagram: {:?}", e);
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
                    if !self.tcp_stream_map.contains_key(&id) {
                        let (send, _recv) = self.connection.open_bi().await
                            .context("Failed to open bi-directional stream")?;
                        self.tcp_stream_map.insert(id, send);
                    }
                    if let Some(stream) = self.tcp_stream_map.get_mut(&id) {
                        stream.write_all(&send_buf).await
                            .context("Failed to write TcpConnect message")?;
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
                    if let Some(mut stream) = self.tcp_stream_map.remove(&id) {
                        let _ = stream.write_all(&send_buf).await;
                        let _ = stream.finish();
                    }
                }
            }
        }
        Ok(())
    }
    
    async fn send_tcp_data(&mut self, tcp: &TcpForwarder) -> Result<()> {
        while let Some(data) = tcp.flush() {
            if !self.tcp_stream_map.contains_key(&data.id) {
                let (send, _recv) = self.connection.open_bi().await
                    .context("Failed to open bi-directional stream")?;
                self.tcp_stream_map.insert(data.id, send);
            }
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
            if let Some(stream) = self.tcp_stream_map.get_mut(&data.id) {
                if let Err(e) = stream.write_all(&send_buf).await {
                    error!("Failed to send TCP data: {}", e);
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
            if let Err(e) = self.connection.send_datagram(buf.to_vec().into()) {
                match e {
                    quinn::SendDatagramError::TooLarge => {
                        debug!("Datagram too large, dropping packet");
                    }
                    quinn::SendDatagramError::ConnectionLost(_) => {
                        error!("Connection lost while sending datagram");
                        return Err(anyhow::anyhow!("Connection lost"));
                    }
                    _ => {
                        error!("Failed to send datagram: {:?}", e);
                    }
                }
            }
        }
        Ok(())
    }
}
