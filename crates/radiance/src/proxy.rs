use async_trait::async_trait;
use http::{Uri, header, uri::{Parts, Scheme}};
use log::{error, info};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora_load_balancing::prelude::RoundRobin;
use pingora_load_balancing::LoadBalancer;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use ulid::Ulid;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::{FullConfig, HostConfig, HostConfigWithBalancer};

pub type SharedConfig = Arc<RwLock<FullConfig>>;

static SERVER_ERROR_TEMPLATE: &str = include_str!("../pages/server_error.html");

pub fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim().to_lowercase();
    domain.split(':').next().unwrap_or("").to_string()
}

pub fn normalize_match_domain(x: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().to_lowercase();    
    if pattern.starts_with("*.") {
        let pat = &pattern[2..].to_lowercase();
        if x.ends_with(&(".".to_owned()+pat)) {
            // ensure only one subdomain level
            let prefix = &x[..x.len()-pat.len()-1];
            return !prefix.contains('.');
        } else {
            return false;
        }
    } else {
        x == pattern.to_lowercase()
    }
}

pub fn error_response(code: u16, request_id: &str) -> (ResponseHeader, Vec<u8>) {
    let mut resp = ResponseHeader::build(code, Some(3)).unwrap();
    resp.insert_header(header::SERVER, "radiance")
        .unwrap();
    resp.insert_header(header::CACHE_CONTROL, "private, no-store")
        .unwrap();
    let template = SERVER_ERROR_TEMPLATE
        .replace("{errorCode}", &code.to_string())
        .replace("{errorText}", http::StatusCode::from_u16(code).map_or("Unknown Error", |sc| sc.canonical_reason().unwrap_or("Unknown Error")))
        .replace("{requestId}", request_id);
    let resp_bytes = template.into_bytes();
    resp.insert_header(header::CONTENT_LENGTH, resp_bytes.len().to_string())
        .unwrap();
    (resp, resp_bytes)
}

pub struct RadianceProxy {
    config: SharedConfig,
}

impl RadianceProxy {
    pub fn new(config: SharedConfig) -> Self {
        Self { config }
    }
    
    // async fn get_host_config(&self, domain: &str) -> Option<&HostConfigWithBalancer> {
    // }
}

#[async_trait]
impl ProxyHttp for RadianceProxy {
    type CTX = ProxyContext;
    
    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::new()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    {
        let host = session.get_header("HOST")
            .map(|h| h.to_str().unwrap())
            .ok_or(pingora::Error::new_down(ErrorType::InvalidHTTPHeader))?;
        info!("Routing request to upstream: {}", host);
        
        let host = normalize_domain(host);
        let config = self.config.read().await;
        
        let host_config = config.hosts.iter().find(|h| {
            h.1.config.enabled && h.1.config.domains.iter().any(|d| normalize_match_domain(d, &host))
        }).map(|host_config| host_config.1)
            .ok_or(pingora::Error::new_down(ErrorType::HTTPStatus(404)))?;
        ctx.host_config = Some(host_config.clone());
        ctx.normalized_host = host;
        if let Some(true) = host_config.config.upgrade_https {
            // redirect to HTTPS
            let proto = session.req_header().uri.scheme().ok_or(
                pingora::Error::new_down(ErrorType::InternalError)
            )?;
            if Scheme::HTTP == *proto {
                let uri_parts = Uri::builder()
                    .path_and_query(session.req_header().uri.path_and_query().unwrap().clone())
                    .authority(session.req_header().uri.authority().unwrap().clone())
                    .scheme("https")
                    .build()
                    .map_err(|_| pingora::Error::new_down(ErrorType::InternalError))?;
                let mut resp = ResponseHeader::build(http::StatusCode::MOVED_PERMANENTLY, Some(4)).unwrap();
                resp.insert_header(header::SERVER, "radiance")
                    .unwrap();
                resp.insert_header(header::CONTENT_LENGTH, 0).unwrap();
                resp.insert_header(header::CACHE_CONTROL, "private, no-store")
                    .unwrap();
                resp.insert_header(header::LOCATION, uri_parts.to_string()).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
            Ok(false)
        } else {
            Ok(false)
        }
    }

    async fn proxy_upstream_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // TODO:
        // Check if this request is to .well-known/acme-challenge/
        // if session.req_header().uri.path().starts_with("/.well-known/acme-challenge/") {
        //     // Handle ACME challenge requests
        // }
        // Check if this request needs to be proxied differently
        // Check forward auth
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host_config = ctx.host_config.as_ref().ok_or(
            pingora::Error::new_up(ErrorType::HTTPStatus(502))
        )?;
        let upstream = host_config.load_balancer.select(b"", 256);
        if let Some(upstream) = upstream {
            info!("Selected upstream: {:?}", upstream);
            
            let sni = if host_config.config.upstream.tls {
                if let Some(rw) = host_config.config.header_rewrites.as_ref()
                && let Some(sni_host) = rw.get("Host") {
                    sni_host.clone()
                } else {
                    ctx.normalized_host.clone()
                }
            } else {
                String::new()
            };
            let peer = Box::new(HttpPeer::new(
                upstream.addr,
                host_config.config.upstream.tls,
                sni,
            ));
            Ok(peer)
        } else {
            Err(pingora::Error::new_up(ErrorType::HTTPStatus(502)))
        }
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(client_addr) = session.client_addr() {
            let existing_xff = upstream_request.headers.get("X-Forwarded-For");
            let ip = client_addr.as_inet().unwrap().ip().to_string();
            upstream_request.insert_header(
                "X-Forwarded-For",
                if let Some(xff) = existing_xff {
                    format!("{}, {}", xff.to_str().unwrap_or(""), ip)
                } else {
                    ip
                }
            )?;
        }
        
        if let Some(host) = upstream_request.headers.get("Host") {
            ctx.original_host = host.to_str().unwrap_or("unknown").to_string();
        }
        let header_rewrites = ctx.host_config.as_ref()
            .and_then(|h| h.config.header_rewrites.as_ref());
        if let Some(rewrites) = header_rewrites {
            for (key, value) in rewrites {
                upstream_request.insert_header(key.clone(), value)?;
            }
        }
        
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // TODO:
        Ok(())
    }
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        
        let client_addr = session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let method = &session.req_header().method;
        let uri = &session.req_header().uri;
        let bytes_sent = session.body_bytes_sent();
        
        if let Some(error) = e {
            error!(
                "{} {} \"{} {}\" {} {} - ERROR: {}",
                ctx.request_id, client_addr, method, uri, response_code, bytes_sent, error
            );
        } else {
            info!(
                "{} {} \"{} {}\" {} {} - Host: {}",
                ctx.request_id, client_addr, method, uri, response_code, bytes_sent, ctx.original_host
            );
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            _ => {
                match e.esource() {
                    ErrorSource::Upstream => 502,
                    ErrorSource::Downstream => {
                        match e.etype() {
                            WriteError | ReadError | ConnectionClosed => {
                                0
                            }
                            _ => 400,
                        }
                    }
                    ErrorSource::Internal | ErrorSource::Unset => 500,
                }
            }
        };
        if code > 0 {
            let (resp, body) = error_response(code, &ctx.request_id);
            session.as_downstream_mut().write_error_response(resp, body.into()).await.unwrap_or_else(|e| {
                error!("failed to send error response to downstream: {e}");
            });
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

pub struct ProxyContext {
    pub original_host: String,
    pub normalized_host: String,
    pub start_time: std::time::Instant,
    pub host_config: Option<Arc<HostConfigWithBalancer>>,
    pub request_id: String,
}

impl ProxyContext {
    pub fn new() -> Self {
        Self {
            original_host: String::new(),
            normalized_host: String::new(),
            start_time: std::time::Instant::now(),
            host_config: None,
            request_id: Ulid::new().to_string(),
        }
    }
}
