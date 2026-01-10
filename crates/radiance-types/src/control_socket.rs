
use serde::{Deserialize, Serialize};

use crate::{HostConfig, PartialHostConfig};

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlCommand {
    AddHost { id: String, host: HostConfig },
    UpdateHost { id: String, host: PartialHostConfig },
    RemoveHost { id: String },
    ListHosts,
    Reload,
    GetHost { id: String },
    SetHttpChallenge { domain: String, token: String, thumbprint: String },
    ClearHttpChallenge { domain: String, token: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Success {
        message: String,
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}