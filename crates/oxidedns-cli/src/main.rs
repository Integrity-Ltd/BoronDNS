use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, anyhow};
use clap::{ArgAction, Parser, Subcommand};
use tracing::warn;
use tracing_subscriber::EnvFilter;
use oxidedns_core::{ConfigError, ConfigWarning, LogFormatConfig, ServerConfig};
use oxidedns_server::{
    BUILD_COMMIT, BUILD_RUST_VERSION, BUILD_TIMESTAMP, BUILD_VERSION, Runtime, RuntimeError,
    TransferError,
};

const DEFAULT_CONFIG_PATH: &str = "/etc/oxidedns-secondary/config.toml";
const EX_CONFIG_INVALID: u8 = 2;
const EX_USAGE: u8 = 64;
const EX_GENERAL: u8 = 1;
const EX_OSERR: u8 = 71;
const EX_CANTCREAT: u8 = 73;
const EX_IOERR: u8 = 74;
const EX_CONFIG: u8 = 78;
const HELP_FOOTER: &str = concat!(
    "Configuration: default path /etc/oxidedns-secondary/config.toml",
    "; override subcommands with --config or OXIDEDNS_CONFIG.\n",
    "Operator Deployment Guide: docs/operator-deployment-guide.md\n",
    "Project: internal OxideDNS repository; see README.md and docs/."
);
const EXAMPLE_CONFIG: &str = include_str!("../../../config/oxidedns.example.toml");

#[derive(Debug, Parser)]
#[command(
    name = "oxidedns",
    about = "Secondary-only authoritative DNS server",
    arg_required_else_help = true,
    disable_version_flag = true,
    after_help = HELP_FOOTER
)]
struct Cli {
    #[arg(short = 'V', long, action = ArgAction::SetTrue, help = "Print version information and exit")]
    version: bool,

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

    #[arg(long, action = ArgAction::SetTrue, help = "Print an example configuration and exit")]
    example_config: bool,

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

fn main() -> ExitCode {
    #[cfg(unix)]
    if let Err(error) = oxidedns_server::install_process_signal_dispositions() {
        eprintln!("failed to install process signal dispositions: {error}");
        return ExitCode::from(EX_OSERR);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to initialise async runtime: {error}");
            return ExitCode::from(EX_OSERR);
        }
    };

    runtime.block_on(async_main())
}

async fn async_main() -> ExitCode {
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
        Mode::Version => {
            println!("{}", version_text());
        }
        Mode::CheckConfig(config) | Mode::ValidateConfig(config) => {
            let loaded = load_config(&config)?;
            emit_config_warnings_to_stderr(&loaded.warnings);
            init_logging(&loaded.config)?;
            println!(
                "configuration ok: {} zone(s), {} UDP listener(s), {} TCP listener(s)",
                loaded.config.zones.len(),
                loaded.config.udp_listeners().len(),
                loaded.config.tcp_listeners().len()
            );
        }
        Mode::DumpConfig(config) => {
            let loaded = load_config(&config)?;
            emit_config_warnings_to_stderr(&loaded.warnings);
            print!("{}", loaded.config.to_redacted_toml()?);
        }
        Mode::ExampleConfig => {
            print!("{EXAMPLE_CONFIG}");
        }
        Mode::Serve(config) => {
            let loaded = load_config(&config)?;
            init_logging(&loaded.config)?;
            emit_config_warnings_to_log(&loaded.warnings);
            Runtime::new(loaded.config).run().await?;
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Version,
    CheckConfig(PathBuf),
    ValidateConfig(PathBuf),
    DumpConfig(PathBuf),
    ExampleConfig,
    Serve(PathBuf),
}

fn selected_mode(cli: Cli) -> anyhow::Result<Mode> {
    let mut selected = Vec::new();

    if cli.version {
        selected.push(Mode::Version);
    }
    if let Some(config) = cli.validate_config {
        selected.push(Mode::ValidateConfig(config_path(config)));
    }
    if let Some(config) = cli.dump_config {
        selected.push(Mode::DumpConfig(config_path(config)));
    }
    if cli.example_config {
        selected.push(Mode::ExampleConfig);
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

fn version_text() -> String {
    format!(
        "oxidedns {BUILD_VERSION}\nbuild commit: {BUILD_COMMIT}\nbuild timestamp: {BUILD_TIMESTAMP}\nrustc: {BUILD_RUST_VERSION}\nSRS: OxideDNS Secondary SRS v0.7\nRole: secondary-only authoritative DNS server\nLicense: {}",
        env!("CARGO_PKG_LICENSE")
    )
}

struct LoadedConfig {
    config: ServerConfig,
    warnings: Vec<ConfigWarning>,
}

fn load_config(path: &Path) -> anyhow::Result<LoadedConfig> {
    let mut config =
        ServerConfig::from_path(path).with_context(|| format!("loading {}", path.display()))?;
    let mut warnings =
        apply_environment_overrides(&mut config).context("applying environment overrides")?;
    config
        .validate()
        .context("validating effective configuration")?;
    oxidedns_server::validate_runtime_config(&config).context("validating runtime configuration")?;
    warnings.extend(config.configuration_warnings());
    warnings.extend(
        oxidedns_server::runtime_config_warnings(&config)
            .context("collecting runtime configuration warnings")?,
    );
    Ok(LoadedConfig { config, warnings })
}

fn apply_environment_overrides(
    config: &mut ServerConfig,
) -> Result<Vec<ConfigWarning>, ConfigError> {
    apply_environment_overrides_from(config, std::env::vars_os())
}

fn apply_environment_overrides_from<I>(
    config: &mut ServerConfig,
    vars: I,
) -> Result<Vec<ConfigWarning>, ConfigError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut warnings = Vec::new();
    for (name, value) in vars {
        let Ok(name) = name.into_string() else {
            continue;
        };
        match name.as_str() {
            "ODS_SERVER_HEALTH" => {
                let value = env_value_to_string(&name, value)?;
                config.server.health = Some(parse_env_value(&name, &value)?);
            }
            "ODS_SERVER_LOG_LEVEL" => {
                config.server.log_level = env_value_to_string(&name, value)?;
            }
            "ODS_SERVER_LOG_FORMAT" => {
                let value = env_value_to_string(&name, value)?;
                config.server.log_format = parse_log_format(&name, &value)?;
            }
            "ODS_SERVER_NSID" => {
                config.server.nsid = env_value_to_string(&name, value)?;
            }
            "ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE" => {
                let value = env_value_to_string(&name, value)?;
                config.health.metrics_rate_limit_per_minute = parse_env_value(&name, &value)?;
            }
            "ODS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS" => {
                let value = env_value_to_string(&name, value)?;
                config.health.metrics_rate_limit_idle_seconds = parse_env_value(&name, &value)?;
            }
            "ODS_TSIG_FUDGE_SECONDS" => {
                let value = env_value_to_string(&name, value)?;
                config.tsig.fudge_seconds = parse_env_value(&name, &value)?;
            }
            "ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES" => {
                let value = env_value_to_string(&name, value)?;
                config.limits.max_transfer_ingest_bytes = parse_env_value(&name, &value)?;
            }
            "ODS_LIMITS_ZSM_MAX_INTERVAL_SECS" => {
                let value = env_value_to_string(&name, value)?;
                config.limits.zsm_max_interval_secs = parse_env_value(&name, &value)?;
            }
            _ if name.starts_with("ODS_") => {
                warnings.push(ConfigWarning {
                    code: "unrecognised_rds_environment_variable",
                    parameter: name,
                    message: "unrecognised ODS_* environment variable ignored".to_owned(),
                });
            }
            _ => {}
        }
    }
    Ok(warnings)
}

fn emit_config_warnings_to_stderr(warnings: &[ConfigWarning]) {
    for warning in warnings {
        eprintln!("{}", config_warning_line(warning));
    }
}

fn emit_config_warnings_to_log(warnings: &[ConfigWarning]) {
    for warning in warnings {
        warn!(
            category = "configuration_warning",
            code = warning.code,
            parameter = %warning.parameter,
            message = %warning.message,
            "configuration warning"
        );
    }
}

fn config_warning_line(warning: &ConfigWarning) -> String {
    format!(
        "warning category=configuration_warning code={} parameter={} message=\"{}\"",
        warning.code,
        warning.parameter,
        warning.message.replace('"', "\\\"")
    )
}

fn env_value_to_string(name: &str, value: OsString) -> Result<String, ConfigError> {
    value.into_string().map_err(|_| {
        ConfigError::Invalid(format!(
            "environment variable {name} must contain valid UTF-8"
        ))
    })
}

fn parse_env_value<T>(name: &str, value: &str) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|error| {
        ConfigError::Invalid(format!(
            "environment variable {name} has invalid value: {error}"
        ))
    })
}

fn parse_log_format(name: &str, value: &str) -> Result<LogFormatConfig, ConfigError> {
    match value {
        "json" => Ok(LogFormatConfig::Json),
        "plain" => Ok(LogFormatConfig::Plain),
        _ => Err(ConfigError::Invalid(format!(
            "environment variable {name} must be either json or plain"
        ))),
    }
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
        if let Some(runtime_error) = cause.downcast_ref::<RuntimeError>() {
            return match runtime_error {
                RuntimeError::BindUdp { .. }
                | RuntimeError::BindTcp { .. }
                | RuntimeError::BindHealth { .. } => EX_CANTCREAT,
                RuntimeError::InvalidRuntimeConfig(_) => EX_CONFIG_INVALID,
                RuntimeError::ShutdownSignal(_) | RuntimeError::DnsCookieSecret(_) => EX_OSERR,
                RuntimeError::Udp(_) | RuntimeError::Tcp(_) | RuntimeError::Health(_) => EX_GENERAL,
            };
        }
        if let Some(transfer_error) = cause.downcast_ref::<TransferError>() {
            return match transfer_error {
                TransferError::ReadTlsFile { .. } => EX_IOERR,
                TransferError::XotConfig { .. } => EX_CONFIG_INVALID,
                TransferError::BindUdp { .. } => EX_CANTCREAT,
                TransferError::Io { .. } => EX_IOERR,
                TransferError::ConnectTcp { .. }
                | TransferError::Timeout { .. }
                | TransferError::Axfr(_)
                | TransferError::Ixfr(_)
                | TransferError::Soa(_)
                | TransferError::RandomQueryId(_)
                | TransferError::Tsig(_)
                | TransferError::TlsHandshake { .. }
                | TransferError::IngestSizeLimit { .. }
                | TransferError::XotAlpn { .. } => EX_GENERAL,
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

        let cli = Cli::try_parse_from(["oxidedns", "--example-config", "--version"])
            .expect("CLI parses before mode validation");
        let error = selected_mode(cli).expect_err("ambiguous mode must fail");

        assert!(error.to_string().contains("select exactly one"));
    }

    #[test]
    fn version_flag_selects_version_mode() {
        let cli = Cli::try_parse_from(["oxidedns", "--version"]).expect("version CLI");
        assert_eq!(selected_mode(cli).expect("mode"), Mode::Version);

        let cli = Cli::try_parse_from(["oxidedns", "-V"]).expect("short version CLI");
        assert_eq!(selected_mode(cli).expect("mode"), Mode::Version);
    }

    #[test]
    fn example_config_flag_selects_example_config_mode() {
        let cli = Cli::try_parse_from(["oxidedns", "--example-config"]).expect("example config CLI");
        assert_eq!(selected_mode(cli).expect("mode"), Mode::ExampleConfig);
    }

    #[test]
    fn version_text_contains_srs_build_metadata() {
        let text = version_text();

        assert!(text.starts_with("oxidedns 0.1.0\n"));
        assert!(text.contains("\nbuild commit: "));
        assert!(text.contains("\nbuild timestamp: "));
        assert!(text.contains("\nrustc: rustc "));
        assert!(text.contains("\nSRS: OxideDNS Secondary SRS v0.7"));
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
    fn runtime_bind_errors_map_to_cantcreat() {
        let addr = "127.0.0.1:5300".parse().expect("socket address");
        let source = || std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use");

        let udp = anyhow!(RuntimeError::BindUdp {
            addr,
            source: source(),
        })
        .context("starting runtime");
        assert_eq!(exit_code_for_error(&udp), EX_CANTCREAT);

        let tcp = anyhow!(RuntimeError::BindTcp {
            addr,
            source: source(),
        })
        .context("starting runtime");
        assert_eq!(exit_code_for_error(&tcp), EX_CANTCREAT);

        let health = anyhow!(RuntimeError::BindHealth {
            addr,
            source: source(),
        })
        .context("starting runtime");
        assert_eq!(exit_code_for_error(&health), EX_CANTCREAT);
    }

    #[test]
    fn startup_runtime_validation_errors_map_to_srs_exit_codes() {
        let addr = "127.0.0.1:5300".parse().expect("socket address");

        let invalid_xot = anyhow!(TransferError::XotConfig {
            addr,
            message: "server_name is required".to_owned(),
        })
        .context("validating runtime configuration");
        assert_eq!(exit_code_for_error(&invalid_xot), EX_CONFIG_INVALID);

        let unreadable_tls = anyhow!(TransferError::ReadTlsFile {
            path: "/missing/trust-anchor.pem".to_owned(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        })
        .context("validating runtime configuration");
        assert_eq!(exit_code_for_error(&unreadable_tls), EX_IOERR);

        let startup_os = anyhow!(RuntimeError::ShutdownSignal(std::io::Error::other(
            "signal setup failed",
        )))
        .context("starting runtime");
        assert_eq!(exit_code_for_error(&startup_os), EX_OSERR);
    }

    #[test]
    fn clap_help_version_and_usage_errors_have_srs_exit_codes() {
        let help = Cli::try_parse_from(["oxidedns", "--help"]).expect_err("help exits");
        assert!(!help.use_stderr());

        let version = Cli::try_parse_from(["oxidedns", "--version"]).expect("version parses");
        assert_eq!(selected_mode(version).expect("mode"), Mode::Version);

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

    #[test]
    fn rds_environment_overrides_supported_scalar_config() {
        let mut config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                log_level = "info"
                log_format = "json"
                nsid = "file-nsid"

                [health]
                metrics_rate_limit_per_minute = 60
                metrics_rate_limit_idle_seconds = 300

                [limits]
                max_transfer_ingest_bytes = 4294967296

                [tsig]
                fudge_seconds = 300

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let warnings = apply_environment_overrides_from(
            &mut config,
            [
                ("ODS_SERVER_HEALTH", "127.0.0.1:8081"),
                ("ODS_SERVER_LOG_LEVEL", "debug"),
                ("ODS_SERVER_LOG_FORMAT", "plain"),
                ("ODS_SERVER_NSID", "env-nsid"),
                ("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE", "120"),
                ("ODS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS", "45"),
                ("ODS_TSIG_FUDGE_SECONDS", "30"),
                ("ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES", "104857600"),
                ("ODS_LIMITS_ZSM_MAX_INTERVAL_SECS", "43200"),
            ]
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        )
        .expect("env overrides");
        assert!(warnings.is_empty());
        config.validate().expect("effective config is valid");

        assert_eq!(
            config.server.health,
            Some("127.0.0.1:8081".parse().unwrap())
        );
        assert_eq!(config.server.log_level, "debug");
        assert_eq!(config.server.log_format, LogFormatConfig::Plain);
        assert_eq!(config.server.nsid, "env-nsid");
        assert_eq!(config.health.metrics_rate_limit_per_minute, 120);
        assert_eq!(config.health.metrics_rate_limit_idle_seconds, 45);
        assert_eq!(config.tsig.fudge_seconds, 30);
        assert_eq!(config.limits.max_transfer_ingest_bytes, 104_857_600);
        assert_eq!(config.limits.zsm_max_interval_secs, 43_200);
    }

    #[test]
    fn invalid_rds_environment_override_reports_config_error() {
        let mut config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let error = apply_environment_overrides_from(
            &mut config,
            [(
                OsString::from("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE"),
                OsString::from("not-a-number"),
            )],
        )
        .expect_err("invalid env override must fail");

        assert!(matches!(error, ConfigError::Invalid(_)));
        assert!(
            error
                .to_string()
                .contains("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE")
        );
    }

    #[test]
    fn unrecognised_rds_environment_override_reports_warning() {
        let mut config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let warnings = apply_environment_overrides_from(
            &mut config,
            [
                (
                    OsString::from("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE"),
                    OsString::from("120"),
                ),
                (
                    OsString::from("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUT"),
                    OsString::from("240"),
                ),
                (
                    OsString::from("NOT_ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE"),
                    OsString::from("480"),
                ),
            ],
        )
        .expect("env overrides");

        assert_eq!(config.health.metrics_rate_limit_per_minute, 120);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "unrecognised_rds_environment_variable");
        assert_eq!(
            warnings[0].parameter,
            "ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUT"
        );
        assert!(config_warning_line(&warnings[0]).contains("category=configuration_warning"));
    }
}
