use radiance_types::{ControlCommand, ControlResponse};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, net::UnixStream};

#[derive(Clone, Debug)]
pub struct ControlSocket {
    socket_path: String,
}

impl ControlSocket {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    pub async fn set_http_challenge(
        &self,
        domain: &str,
        token: &str,
        thumbprint: &str,
    ) -> anyhow::Result<()> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let command = ControlCommand::SetHttpChallenge {
            domain: domain.to_string(),
            token: token.to_string(),
            thumbprint: thumbprint.to_string(),
        };
        let command_json = serde_json::to_string(&command)? + "\n";
        stream.write_all(command_json.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response: ControlResponse = serde_json::from_str(&line)?;
        match response {
            ControlResponse::Success { .. } => Ok(()),
            ControlResponse::Error { message } => Err(anyhow::anyhow!(message)),
        }
    }

    pub async fn clear_http_challenge(&self, domain: &str, token: &str) -> anyhow::Result<()> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let command = ControlCommand::ClearHttpChallenge {
            domain: domain.to_string(),
            token: token.to_string(),
        };
        let command_json = serde_json::to_string(&command)? + "\n";
        stream.write_all(command_json.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response: ControlResponse = serde_json::from_str(&line)?;
        match response {
            ControlResponse::Success { .. } => Ok(()),
            ControlResponse::Error { message } => Err(anyhow::anyhow!(message)),
        }
    }

    pub async fn send_reload_command(&self) -> anyhow::Result<()> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let command = ControlCommand::Reload;
        let command_json = serde_json::to_string(&command)? + "\n";
        stream.write_all(command_json.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response: ControlResponse = serde_json::from_str(&line)?;
        match response {
            ControlResponse::Success { .. } => Ok(()),
            ControlResponse::Error { message } => Err(anyhow::anyhow!(message)),
        }
    }
}