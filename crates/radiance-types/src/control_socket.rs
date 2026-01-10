
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
    // SetHttpChallenge { domain: String, token: String, response: String },
    // ClearHttpChallenge { domain: String, token: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Success {
        message: String,
        data: Option<Vec<u8>>,
    },
    Error {
        message: String,
    },
}