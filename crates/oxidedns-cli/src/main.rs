use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use oxidedns_core::{ConfigError, LogFormatConfig, ServerConfig};
use oxidedns_server::Runtime;

const DEFAULT_CONFIG_PATH: &str = "/etc/oxidedns-secondary/config.toml";
const EX_CONFIG_INVALID: u8 = 2;
const EX_USAGE: u8 = 64;
const EX_GENERAL: u8 = 1;
const EX_CONFIG: u8 = 78;
const VERSION_TEXT: &str = concat!(
    "oxidedns ",
    env!("CARGO_PKG_VERSION"),
    "\nSRS: OxideDNS Secondary SRS v0.7",
    "\nRole: secondary-only authoritative DNS server",
    "\nLicense: ",
    env!("CARGO_PKG_LICENSE")
);

#[derive(Debug, Parser)]
#[command(
    name = "oxidedns",
    version = VERSION_TEXT,
    about = "Secondary-only authoritative DNS server",
    arg_required_else_help = true
)]
struct Cli {
    #[arg(
        long,
        value_name = "CONFIG",
        num_args = 0..=1,
        help = "Validate the configuration file and exit"
    )]
    validate_config: Option<Option<PathBuf>>,

    #[arg(
        long,
        value_name = "CONFIG",
        num_args = 0..=1,
        help = "Print the validated effective configuration with secret material redacted"
    )]
    dump_config: Option<Option<PathBuf>>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    CheckConfig {
        #[arg(short, long, env = "OXIDEDNS_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    Serve {
        #[arg(short, long, env = "OXIDEDNS_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { EX_USAGE } else { 0 };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(exit_code_for_error(&error))
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match selected_mode(cli)? {
        Mode::CheckConfig(config) | Mode::ValidateConfig(config) => {
            let parsed = load_config(&config)?;
            init_logging(&parsed)?;
            println!(
                "configuration ok: {} zone(s), {} UDP listener(s), {} TCP listener(s)",
                parsed.zones.len(),
                parsed.server.listen_udp.len(),
                parsed.server.listen_tcp.len()
            );
        }
        Mode::DumpConfig(config) => {
            let parsed = load_config(&config)?;
            print!("{}", parsed.to_redacted_toml()?);
        }
        Mode::Serve(config) => {
            let parsed = load_config(&config)?;
            init_logging(&parsed)?;
            Runtime::new(parsed).run().await?;
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    CheckConfig(PathBuf),
    ValidateConfig(PathBuf),
    DumpConfig(PathBuf),
    Serve(PathBuf),
}

fn selected_mode(cli: Cli) -> anyhow::Result<Mode> {
    let mut selected = Vec::new();

    if let Some(config) = cli.validate_config {
        selected.push(Mode::ValidateConfig(config_path(config)));
    }
    if let Some(config) = cli.dump_config {
        selected.push(Mode::DumpConfig(config_path(config)));
    }
    if let Some(command) = cli.command {
        selected.push(match command {
            Command::CheckConfig { config } => Mode::CheckConfig(config),
            Command::Serve { config } => Mode::Serve(config),
        });
    }

    match selected.len() {
        1 => Ok(selected.pop().expect("selected mode")),
        0 => Err(anyhow!("no command-line mode selected")),
        _ => Err(anyhow!("select exactly one command-line mode")),
    }
}

fn config_path(config: Option<PathBuf>) -> PathBuf {
    config.unwrap_or_else(default_config_path)
}

fn default_config_path() -> PathBuf {
    std::env::var_os("OXIDEDNS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn load_config(path: &Path) -> anyhow::Result<ServerConfig> {
    let config =
        ServerConfig::from_path(path).with_context(|| format!("loading {}", path.display()))?;
    oxidedns_server::validate_runtime_config(&config).context("validating runtime configuration")?;
    Ok(config)
}

fn exit_code_for_error(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(config_error) = cause.downcast_ref::<ConfigError>() {
            return match config_error {
                ConfigError::Invalid(_) => EX_CONFIG_INVALID,
                ConfigError::Read { .. } | ConfigError::Parse(_) => EX_CONFIG,
                ConfigError::Serialize(_) => EX_GENERAL,
            };
        }
    }
    EX_GENERAL
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
    fn commands_default_to_srs_config_path() {
        let cli = Cli::try_parse_from(["oxidedns", "check-config"]).expect("check-config CLI");
        match cli.command.expect("command") {
            Command::CheckConfig { config } => {
                assert_eq!(config, PathBuf::from(DEFAULT_CONFIG_PATH));
            }
            Command::Serve { .. } => panic!("expected check-config command"),
        }

        let cli = Cli::try_parse_from(["oxidedns", "serve"]).expect("serve CLI");
        match cli.command.expect("command") {
            Command::Serve { config } => {
                assert_eq!(config, PathBuf::from(DEFAULT_CONFIG_PATH));
            }
            Command::CheckConfig { .. } => panic!("expected serve command"),
        }
    }

    #[test]
    fn explicit_config_path_overrides_default() {
        let cli = Cli::try_parse_from(["oxidedns", "serve", "--config", "config/oxidedns.example.toml"])
            .expect("serve CLI");
        match cli.command.expect("command") {
            Command::Serve { config } => {
                assert_eq!(config, PathBuf::from("config/oxidedns.example.toml"));
            }
            Command::CheckConfig { .. } => panic!("expected serve command"),
        }
    }

    #[test]
    fn validate_config_flag_accepts_default_or_explicit_path() {
        let cli = Cli::try_parse_from(["oxidedns", "--validate-config"]).expect("validate CLI");
        assert_eq!(
            selected_mode(cli).expect("mode"),
            Mode::ValidateConfig(PathBuf::from(DEFAULT_CONFIG_PATH))
        );

        let cli = Cli::try_parse_from(["oxidedns", "--validate-config", "config/oxidedns.example.toml"])
            .expect("validate CLI");
        assert_eq!(
            selected_mode(cli).expect("mode"),
            Mode::ValidateConfig(PathBuf::from("config/oxidedns.example.toml"))
        );
    }

    #[test]
    fn dump_config_flag_accepts_default_or_explicit_path() {
        let cli = Cli::try_parse_from(["oxidedns", "--dump-config"]).expect("dump CLI");
        assert_eq!(
            selected_mode(cli).expect("mode"),
            Mode::DumpConfig(PathBuf::from(DEFAULT_CONFIG_PATH))
        );

        let cli = Cli::try_parse_from(["oxidedns", "--dump-config", "config/oxidedns.example.toml"])
            .expect("dump CLI");
        assert_eq!(
            selected_mode(cli).expect("mode"),
            Mode::DumpConfig(PathBuf::from("config/oxidedns.example.toml"))
        );
    }

    #[test]
    fn selecting_multiple_modes_is_rejected() {
        let cli = Cli::try_parse_from(["oxidedns", "--dump-config", "--validate-config"])
            .expect("CLI parses before mode validation");
        let error = selected_mode(cli).expect_err("ambiguous mode must fail");

        assert!(error.to_string().contains("select exactly one"));
    }

    #[test]
    fn config_errors_map_to_srs_exit_codes() {
        let invalid = anyhow!(ConfigError::Invalid("bad setting".to_owned()));
        assert_eq!(exit_code_for_error(&invalid), EX_CONFIG_INVALID);

        let parse = ServerConfig::from_toml_str("not = [").expect_err("parse error");
        let parse = anyhow!(parse).context("loading config");
        assert_eq!(exit_code_for_error(&parse), EX_CONFIG);
    }

    #[test]
    fn clap_help_version_and_usage_errors_have_srs_exit_codes() {
        let help = Cli::try_parse_from(["oxidedns", "--help"]).expect_err("help exits");
        assert!(!help.use_stderr());

        let version = Cli::try_parse_from(["oxidedns", "--version"]).expect_err("version exits");
        assert!(!version.use_stderr());

        let unknown = Cli::try_parse_from(["oxidedns", "--definitely-not-valid"])
            .expect_err("unknown flag exits");
        assert!(unknown.use_stderr());
        assert_eq!(EX_USAGE, 64);
    }

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
