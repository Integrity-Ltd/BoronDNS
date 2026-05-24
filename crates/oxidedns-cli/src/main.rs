use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use oxidedns_core::ServerConfig;
use oxidedns_server::Runtime;

#[derive(Debug, Parser)]
#[command(
    name = "oxidedns",
    version,
    about = "Secondary-only authoritative DNS server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    CheckConfig {
        #[arg(short, long, env = "OXIDEDNS_CONFIG")]
        config: PathBuf,
    },
    Serve {
        #[arg(short, long, env = "OXIDEDNS_CONFIG")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Command::CheckConfig { config } => {
            let parsed = ServerConfig::from_path(&config)
                .with_context(|| format!("loading {}", config.display()))?;
            println!(
                "configuration ok: {} zone(s), {} UDP listener(s), {} TCP listener(s)",
                parsed.zones.len(),
                parsed.server.listen_udp.len(),
                parsed.server.listen_tcp.len()
            );
        }
        Command::Serve { config } => {
            let parsed = ServerConfig::from_path(&config)
                .with_context(|| format!("loading {}", config.display()))?;
            Runtime::new(parsed).run().await?;
        }
    }

    Ok(())
}
