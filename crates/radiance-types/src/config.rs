use std::collections::HashMap;

use partially::{Partial};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Partial)]
#[partially(derive(Default, Debug, Serialize, Deserialize))]
pub struct HostConfig {
    pub domains: Vec<String>,
    pub enabled: bool,
    pub tls_cert_id: Option<String>,
    pub upstream: UpstreamConfig,
    pub header_rewrites: Option<HashMap<String, String>>,
    pub upgrade_https: Option<bool>,
    pub forward_auth: Option<ForwardAuthConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub tls: bool,
    pub servers: Vec<ServerConfig>,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerConfig {
    Local { address: String },
    Outpost { id: String, address: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForwardAuthConfig {
    pub url: String,
    pub response_headers: Vec<String>,
}
