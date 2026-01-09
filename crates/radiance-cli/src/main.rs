use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

#[derive(Parser)]
#[command(name = "radiance-cli")]
#[command(about = "CLI tool to manage Radiance reverse proxy", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "/tmp/radiance.sock")]
    socket: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ListHosts,
    GetHost {
        #[arg(short, long)]
        id: String,
    },
    Reload,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ControlCommand {
    ListHosts,
    Reload,
    GetHost { id: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ControlResponse {
    Success {
        message: String,
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run_command(&cli.socket, cli.command) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run_command(socket_path: &str, command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    let control_command = match command {
        Commands::ListHosts => ControlCommand::ListHosts,
        Commands::GetHost { id } => ControlCommand::GetHost { id },
        Commands::Reload => ControlCommand::Reload,
    };
    let mut stream = UnixStream::connect(socket_path)?;
    let command_json = serde_json::to_string(&control_command)?;
    stream.write_all(command_json.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;
    let response: ControlResponse = serde_json::from_str(&response_line)?;
    match response {
        ControlResponse::Success { message, data } => {
            println!("✓ {}", message);
            if let Some(data) = data {
                println!("\n{}", serde_json::to_string_pretty(&data)?);
            }
        }
        ControlResponse::Error { message } => {
            eprintln!("✗ Error: {}", message);
            std::process::exit(1);
        }
    }

    Ok(())
}