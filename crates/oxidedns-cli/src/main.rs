use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use oxidedns_core::{LogFormatConfig, ServerConfig};
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
    match Cli::parse().command {
        Command::CheckConfig { config } => {
            let parsed = load_config(&config)?;
            init_logging(&parsed)?;
            println!(
                "configuration ok: {} zone(s), {} UDP listener(s), {} TCP listener(s)",
                parsed.zones.len(),
                parsed.server.listen_udp.len(),
                parsed.server.listen_tcp.len()
            );
        }
        Command::Serve { config } => {
            let parsed = load_config(&config)?;
            init_logging(&parsed)?;
            Runtime::new(parsed).run().await?;
        }
    }

    Ok(())
}

fn load_config(path: &Path) -> anyhow::Result<ServerConfig> {
    ServerConfig::from_path(path).with_context(|| format!("loading {}", path.display()))
}

fn init_logging(config: &ServerConfig) -> anyhow::Result<()> {
    let filter = log_filter(&config.server.log_level)?;

    match config.server.log_format {
        LogFormatConfig::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow!("initializing logging: {error}"))?,
        LogFormatConfig::Plain => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow!("initializing logging: {error}"))?,
    }

    Ok(())
}

fn log_filter(configured_level: &str) -> anyhow::Result<EnvFilter> {
    let level = std::env::var("OXIDEDNS_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| normalize_log_level(configured_level).to_owned());
    EnvFilter::try_new(level).map_err(|error| anyhow!("invalid log level: {error}"))
}

fn normalize_log_level(level: &str) -> &str {
    match level {
        "warning" => "warn",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_log_level_is_normalized_for_tracing_subscriber() {
        assert_eq!(normalize_log_level("warning"), "warn");
        assert_eq!(normalize_log_level("debug"), "debug");
    }

    #[test]
    fn configured_log_level_builds_env_filter() {
        log_filter("info,oxidedns_server=debug").expect("valid env filter");
        let error = log_filter("oxidedns_server=notalevel").expect_err("invalid env filter");
        assert!(error.to_string().contains("invalid log level"));
    }
}
