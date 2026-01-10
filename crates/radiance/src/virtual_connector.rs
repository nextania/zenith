use pingora::{connectors::L4Connect, protocols::l4::{socket::SocketAddr, stream::Stream, virt::{VirtualSocket, VirtualSocketStream}}};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::outpost::{ACTIVE_TCP_STREAMS, OutpostRequest, OutpostResponse, request};

#[derive(Debug)]
pub struct VirtualConnector {
    outpost_id: String,
    address: String,
}

impl VirtualConnector {
    pub fn new(outpost_id: &str, address: &str) -> Self {
        Self {
            outpost_id: outpost_id.to_string(),
            address: address.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl L4Connect for VirtualConnector {
    async fn connect(&self, _addr: &SocketAddr) -> pingora::Result<Stream> {
        let (host, port) = if let Some(colon_pos) = self.address.rfind(':') {
            let host_part = &self.address[..colon_pos];
            let port_part = &self.address[colon_pos + 1..];
            let port = port_part.parse::<u16>().map_err(|e| {
                pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    format!("Invalid port: {}", e),
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid port",
                    )),
                )
            })?;
            (host_part.to_string(), port)
        } else {
            return Err(pingora::Error::because(
                pingora::ErrorType::ConnectError,
                "Invalid address format",
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing port",
                )),
            ));
        };
        let resolved_host = if host.parse::<std::net::IpAddr>().is_err() {
            match request(
                self.outpost_id.clone(),
                OutpostRequest::Dns { host: host.clone() },
            )
            .await
            {
                Ok(OutpostResponse::Dns((_, ip))) => ip,
                Ok(_) => {
                    return Err(pingora::Error::because(
                        pingora::ErrorType::ConnectError,
                        "Unexpected DNS response",
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Unexpected response",
                        )),
                    ));
                }
                Err(e) => {
                    return Err(pingora::Error::because(
                        pingora::ErrorType::ConnectError,
                        format!("DNS resolution failed: {}", e),
                        Box::new(std::io::Error::new(std::io::ErrorKind::Other, "DNS failed")),
                    ));
                }
            }
        } else {
            host
        };
        let connection_id = rand::Rng::random::<u64>(&mut rand::rng());
        match request(
            self.outpost_id.clone(),
            OutpostRequest::TcpConnect {
                destination_host: resolved_host,
                destination_port: port,
                id: connection_id,
            },
        )
        .await
        {
            Ok(OutpostResponse::Ack) => {}
            Ok(_) => {
                return Err(pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    "Unexpected TcpConnect response",
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unexpected response",
                    )),
                ));
            }
            Err(e) => {
                return Err(pingora::Error::because(
                    pingora::ErrorType::ConnectError,
                    format!("TcpConnect failed: {}", e),
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "Connection failed",
                    )),
                ));
            }
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        ACTIVE_TCP_STREAMS.insert(connection_id, tx);
        let socket = GenericVirtualSocket::new(rx, self.outpost_id.clone(), connection_id);

        Ok(Stream::from(VirtualSocketStream::new(Box::new(socket))))
    }
}

#[derive(Debug)]
pub struct GenericVirtualSocket {
    receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    outpost_id: String,
    connection_id: u64,
}

impl GenericVirtualSocket {
    pub fn new(
        receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        outpost_id: String,
        connection_id: u64,
    ) -> Self {
        Self {
            receiver,
            outpost_id,
            connection_id,
        }
    }
}

impl VirtualSocket for GenericVirtualSocket {
    fn set_socket_option(
        &self,
        _: pingora::protocols::l4::virt::VirtualSockOpt,
    ) -> std::io::Result<()> {
        // no-op
        Ok(())
    }
}

impl AsyncWrite for GenericVirtualSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        use crate::outpost::{OutpostRequest, request};

        let outpost_id = self.outpost_id.clone();
        let connection_id = self.connection_id;
        let data = buf.to_vec();
        let len = data.len();

        // dispatch data to outpost (non-blocking fire-and-forget)
        tokio::spawn(async move {
            let _ = request(
                outpost_id,
                OutpostRequest::Tcp {
                    data,
                    id: connection_id,
                },
            )
            .await;
        });

        std::task::Poll::Ready(Ok(len))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // nothing to flush
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let outpost_id = self.outpost_id.clone();
        let connection_id = self.connection_id;
        ACTIVE_TCP_STREAMS.remove(&connection_id);

        // dispatch disconnect to outpost (non-blocking fire-and-forget)
        tokio::spawn(async move {
            let _ = request(
                outpost_id,
                OutpostRequest::TcpDisconnect { id: connection_id },
            )
            .await;
        });

        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GenericVirtualSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // channel closed, connection ended
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
