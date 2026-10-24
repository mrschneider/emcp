//! EMCP Daemon & Legacy MCP Stdio Proxy.

use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "EMCP Microkernel Relay & Tool Daemon", long_about = None)]
struct Args {
    #[arg(long, default_value = "0.0.0.0", help = "Listen host")]
    host: String,

    #[arg(long, default_value_t = 8995, help = "Listen port")]
    port: u16,

    #[arg(long, help = "Listen on Unix domain socket path")]
    socket: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!(
        host = args.host,
        port = args.port,
        socket = ?args.socket,
        "EMCP Kernel Relay Daemon initializing..."
    );

    Ok(())
}
