use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, anyhow};
use clap::{ArgAction, Parser, Subcommand};
use oxidedns_core::{ConfigError, ConfigWarning, LogFormatConfig, ServerConfig};
use oxidedns_server::{
    BUILD_COMMIT, BUILD_RUST_VERSION, BUILD_TIMESTAMP, BUILD_VERSION, Runtime, RuntimeError,
    TransferError,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
    warn,
};
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        FmtContext,
        format::{FormatEvent, FormatFields, Writer},
        writer::MakeWriterExt,
    },
    registry::LookupSpan,
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
const LOG_TRUNCATION_MARKER: &str = "...<truncated>";

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
        write_stderr_line(&format!(
            "failed to install process signal dispositions: {error}"
        ));
        return ExitCode::from(EX_OSERR);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            write_stderr_line(&format!("failed to initialise async runtime: {error}"));
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
            write_stderr_line(&format!("{error:#}"));
            ExitCode::from(exit_code_for_error(&error))
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match selected_mode(cli)? {
        Mode::Version => {
            write_stdout_text(&format!("{}\n", version_text()))
                .context("writing version output")?;
        }
        Mode::CheckConfig(config) | Mode::ValidateConfig(config) => {
            let loaded = load_config(&config)?;
            emit_config_warnings_to_stderr(&loaded.warnings);
            init_logging(&loaded.config)?;
            write_stdout_text(&format!(
                "configuration ok: {} zone(s), {} UDP listener(s), {} TCP listener(s)",
                loaded.config.zones.len(),
                loaded.config.udp_listeners().len(),
                loaded.config.tcp_listeners().len()
            ))
            .context("writing validation output")?;
            write_stdout_text("\n").context("writing validation output")?;
        }
        Mode::DumpConfig(config) => {
            let loaded = load_config(&config)?;
            emit_config_warnings_to_stderr(&loaded.warnings);
            write_stdout_text(&loaded.config.to_redacted_toml()?).context("writing config dump")?;
        }
        Mode::ExampleConfig => {
            write_stdout_text(EXAMPLE_CONFIG).context("writing example config")?;
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
    bootstrap_log_info("process started", &bootstrap_build_fields());
    bootstrap_log_info(
        "reading configuration",
        &[("config_path", path.display().to_string())],
    );

    let result = load_config_inner(path);
    match &result {
        Ok(_) => bootstrap_log_info(
            "configuration validation succeeded",
            &[("config_path", path.display().to_string())],
        ),
        Err(error) => bootstrap_log_error(
            "configuration validation failed",
            &[
                ("config_path", path.display().to_string()),
                ("error", format!("{error:#}")),
            ],
        ),
    }
    result
}

fn load_config_inner(path: &Path) -> anyhow::Result<LoadedConfig> {
    let mut config =
        ServerConfig::from_path(path).with_context(|| format!("loading {}", path.display()))?;
    let mut warnings =
        apply_environment_overrides(&mut config).context("applying environment overrides")?;
    config
        .validate()
        .context("validating effective configuration")?;
    oxidedns_server::validate_runtime_config(&config)
        .context("validating runtime configuration")?;
    warnings.extend(config.configuration_warnings());
    warnings.extend(
        oxidedns_server::runtime_config_warnings(&config)
            .context("collecting runtime configuration warnings")?,
    );
    Ok(LoadedConfig { config, warnings })
}

fn bootstrap_build_fields() -> [(&'static str, String); 3] {
    [
        ("version", BUILD_VERSION.to_owned()),
        ("commit", BUILD_COMMIT.to_owned()),
        ("rust_version", BUILD_RUST_VERSION.to_owned()),
    ]
}

fn bootstrap_log_info(message: &str, fields: &[(&str, String)]) {
    bootstrap_log("info", message, fields);
}

fn bootstrap_log_error(message: &str, fields: &[(&str, String)]) {
    bootstrap_log("error", message, fields);
}

fn bootstrap_log(level: &str, message: &str, fields: &[(&str, String)]) {
    write_stderr_line(&bootstrap_log_entry(level, message, fields));
}

fn bootstrap_log_entry(level: &str, message: &str, fields: &[(&str, String)]) -> String {
    let mut entry = format!(
        "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"category\":\"startup\",\"message\":\"{}\"",
        bootstrap_timestamp(),
        json_string(level),
        json_string(message)
    );
    for (name, value) in fields {
        entry.push_str(",\"");
        entry.push_str(&json_string(name));
        entry.push_str("\":\"");
        entry.push_str(&json_string(value));
        entry.push('"');
    }
    entry.push('}');
    entry
}

fn bootstrap_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            _ => escaped.push(character),
        }
    }
    escaped
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
            "ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES" => {
                let value = env_value_to_string(&name, value)?;
                config.logging.max_entry_length_bytes = parse_env_value(&name, &value)?;
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
            "ODS_LIMITS_ZSM_LOADING_WARNING_THRESHOLD_SECS" => {
                let value = env_value_to_string(&name, value)?;
                config.limits.zsm_loading_warning_threshold_secs = parse_env_value(&name, &value)?;
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
        write_stderr_line(&config_warning_line(warning));
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

fn write_stdout_text(text: &str) -> io::Result<()> {
    write_all_ignoring_broken_pipe(io::stdout(), text.as_bytes())
}

fn write_stderr_line(line: &str) {
    let _ = write_all_ignoring_broken_pipe(io::stderr(), format!("{line}\n").as_bytes());
}

fn write_all_ignoring_broken_pipe<W: Write>(mut writer: W, bytes: &[u8]) -> io::Result<()> {
    ignore_broken_pipe(writer.write_all(bytes))?;
    ignore_broken_pipe(writer.flush())
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
        "logfmt" => Ok(LogFormatConfig::Logfmt),
        "plain" => Ok(LogFormatConfig::Plain),
        _ => Err(ConfigError::Invalid(format!(
            "environment variable {name} must be json, logfmt, or plain"
        ))),
    }
}

fn exit_code_for_error(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(config_error) = cause.downcast_ref::<ConfigError>() {
            return match config_error {
                ConfigError::Invalid(_) => EX_CONFIG_INVALID,
                ConfigError::ReadSecretFile { .. } => EX_IOERR,
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
                RuntimeError::ShutdownSignal(_)
                | RuntimeError::DnsCookieSecret(_)
                | RuntimeError::PrimaryRotationRandom(_)
                | RuntimeError::InsufficientFileDescriptorLimit { .. }
                | RuntimeError::FileDescriptorLimit(_)
                | RuntimeError::PrivilegeDrop(_) => EX_OSERR,
                RuntimeError::Udp(_) | RuntimeError::Tcp(_) | RuntimeError::Health(_) => EX_GENERAL,
            };
        }
        if let Some(transfer_error) = cause.downcast_ref::<TransferError>() {
            return match transfer_error {
                TransferError::ReadTlsFile { .. } => EX_IOERR,
                TransferError::XotConfig { .. } => EX_CONFIG_INVALID,
                TransferError::BindUdp { .. } | TransferError::BindTcp { .. } => EX_CANTCREAT,
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
    let max_entry_length_bytes = config.logging.max_entry_length_bytes;
    let log_format = config.server.log_format;

    match config.server.log_format {
        LogFormatConfig::Json => {
            let writer = level_split_log_writer(max_entry_length_bytes, log_format);
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_writer(writer)
                .try_init()
                .map_err(|error| anyhow!("initializing logging: {error}"))?
        }
        LogFormatConfig::Logfmt => {
            let writer = level_split_log_writer(max_entry_length_bytes, log_format);
            tracing_subscriber::fmt()
                .fmt_fields(LogfmtFields)
                .event_format(LogfmtFormatter)
                .with_env_filter(filter)
                .with_writer(writer)
                .try_init()
                .map_err(|error| anyhow!("initializing logging: {error}"))?
        }
        LogFormatConfig::Plain => {
            let writer = level_split_log_writer(max_entry_length_bytes, log_format);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .try_init()
                .map_err(|error| anyhow!("initializing logging: {error}"))?
        }
    }

    Ok(())
}

fn level_split_log_writer(
    max_entry_length_bytes: usize,
    format: LogFormatConfig,
) -> impl for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> {
    let stderr_writer =
        move || LogEntryLimitWriter::new(io::stderr(), max_entry_length_bytes, format);
    let stdout_writer =
        move || LogEntryLimitWriter::new(io::stdout(), max_entry_length_bytes, format);
    stderr_writer
        .with_min_level(Level::WARN)
        .or_else(stdout_writer)
}

struct LogEntryLimitWriter<W> {
    inner: W,
    buffer: Vec<u8>,
    max_entry_length_bytes: usize,
    format: LogFormatConfig,
}

impl<W> LogEntryLimitWriter<W> {
    fn new(inner: W, max_entry_length_bytes: usize, format: LogFormatConfig) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            max_entry_length_bytes,
            format,
        }
    }
}

impl<W: Write> LogEntryLimitWriter<W> {
    fn write_entry(&mut self, entry: &[u8]) -> io::Result<()> {
        if entry.len() <= self.max_entry_length_bytes {
            return ignore_broken_pipe(self.inner.write_all(entry));
        }
        let truncated = truncated_log_entry(self.format, entry, self.max_entry_length_bytes);
        ignore_broken_pipe(self.inner.write_all(&truncated))
    }
}

impl<W: Write> Write for LogEntryLimitWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let entry = self.buffer.drain(..=newline).collect::<Vec<_>>();
            self.write_entry(&entry)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let entry = std::mem::take(&mut self.buffer);
            self.write_entry(&entry)?;
        }
        ignore_broken_pipe(self.inner.flush())
    }
}

fn ignore_broken_pipe(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

fn truncated_log_entry(
    format: LogFormatConfig,
    entry: &[u8],
    max_entry_length_bytes: usize,
) -> Vec<u8> {
    let entry_text = String::from_utf8_lossy(entry);
    match format {
        LogFormatConfig::Json => truncated_json_log_entry(&entry_text, max_entry_length_bytes),
        LogFormatConfig::Logfmt | LogFormatConfig::Plain => {
            truncated_logfmt_log_entry(&entry_text, max_entry_length_bytes)
        }
    }
}

fn truncated_json_log_entry(entry_text: &str, max_entry_length_bytes: usize) -> Vec<u8> {
    truncated_entry_with(entry_text, max_entry_length_bytes, |message| {
        format!(
            "{{\"message\":\"{}\",\"truncated\":true}}\n",
            escape_json_string(message)
        )
        .into_bytes()
    })
}

fn truncated_logfmt_log_entry(entry_text: &str, max_entry_length_bytes: usize) -> Vec<u8> {
    truncated_entry_with(entry_text, max_entry_length_bytes, |message| {
        format!(
            "message=\"{}\" truncated=true\n",
            escape_logfmt_string(message)
        )
        .into_bytes()
    })
}

fn truncated_entry_with<F>(entry_text: &str, max_entry_length_bytes: usize, render: F) -> Vec<u8>
where
    F: Fn(&str) -> Vec<u8>,
{
    let cleaned = entry_text.trim_end_matches(['\r', '\n']);
    let mut low = 0usize;
    let mut high = cleaned.len();
    let mut best = render(LOG_TRUNCATION_MARKER);

    while low <= high {
        let mid = (low + high) / 2;
        let prefix_len = previous_char_boundary(cleaned, mid);
        let message = format!("{}{}", &cleaned[..prefix_len], LOG_TRUNCATION_MARKER);
        let candidate = render(&message);
        if candidate.len() <= max_entry_length_bytes {
            best = candidate;
            low = mid.saturating_add(1);
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }

    best
}

fn previous_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn escape_json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

struct LogfmtFormatter;

impl<S, N> FormatEvent<S, N> for LogfmtFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();
        let mut fields = LogfmtFieldVisitor::default();
        event.record(&mut fields);

        write!(
            writer,
            "timestamp={} level={} target={}",
            logfmt_value(&bootstrap_timestamp()),
            log_level_name(metadata.level()),
            logfmt_value(metadata.target())
        )?;

        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, " span={}", logfmt_value(span.name()))?;
                let extensions = span.extensions();
                if let Some(span_fields) =
                    extensions.get::<tracing_subscriber::fmt::FormattedFields<N>>()
                    && !span_fields.is_empty()
                {
                    write!(writer, " {span_fields}")?;
                }
            }
        }

        if let Some(message) = fields.message {
            write!(writer, " message={}", logfmt_value(&message))?;
        }

        for (name, value) in fields.fields {
            write!(writer, " {name}={}", logfmt_value(&value))?;
        }

        writeln!(writer)
    }
}

struct LogfmtFields;

impl<'writer> FormatFields<'writer> for LogfmtFields {
    fn format_fields<R>(&self, mut writer: Writer<'writer>, fields: R) -> std::fmt::Result
    where
        R: tracing_subscriber::field::RecordFields,
    {
        let mut visitor = LogfmtFieldVisitor::default();
        fields.record(&mut visitor);

        let mut first = true;
        if let Some(message) = visitor.message {
            write_logfmt_pair(&mut writer, &mut first, "message", &message)?;
        }
        for (name, value) in visitor.fields {
            write_logfmt_pair(&mut writer, &mut first, &name, &value)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct LogfmtFieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl LogfmtFieldVisitor {
    fn record_value(&mut self, field: &Field, value: String) {
        let name = canonical_field_name(field.name());
        if name.starts_with("log.") {
            return;
        }
        if name == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((name.to_owned(), value));
        }
    }
}

impl Visit for LogfmtFieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_owned());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_value(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record_value(field, trim_debug_string(format!("{value:?}")));
    }
}

fn write_logfmt_pair(
    writer: &mut Writer<'_>,
    first: &mut bool,
    name: &str,
    value: &str,
) -> std::fmt::Result {
    if *first {
        *first = false;
    } else {
        write!(writer, " ")?;
    }
    write!(writer, "{name}={}", logfmt_value(value))
}

fn log_level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "error",
        Level::WARN => "warning",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

fn canonical_field_name(name: &str) -> &str {
    name.strip_prefix("r#").unwrap_or(name)
}

fn logfmt_value(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
    {
        value.to_owned()
    } else {
        format!("\"{}\"", escape_logfmt_string(value))
    }
}

fn trim_debug_string(value: String) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(&value)
        .to_owned()
}

fn escape_logfmt_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
    use std::sync::{Arc, Mutex};

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
        let cli = Cli::try_parse_from([
            "oxidedns",
            "serve",
            "--config",
            "config/oxidedns.example.toml",
        ])
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

        let cli = Cli::try_parse_from([
            "oxidedns",
            "--validate-config",
            "config/oxidedns.example.toml",
        ])
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

        let cli =
            Cli::try_parse_from(["oxidedns", "--dump-config", "config/oxidedns.example.toml"])
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
        let cli =
            Cli::try_parse_from(["oxidedns", "--example-config"]).expect("example config CLI");
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
    fn bootstrap_log_entry_is_json_startup_record() {
        let entry = bootstrap_log_entry(
            "info",
            "reading configuration",
            &[("config_path", "/tmp/config \"quoted\".toml".to_owned())],
        );

        assert!(entry.starts_with("{\"timestamp\":\""));
        assert!(entry.contains("\"level\":\"info\""));
        assert!(entry.contains("\"category\":\"startup\""));
        assert!(entry.contains("\"message\":\"reading configuration\""));
        assert!(entry.contains("\"config_path\":\"/tmp/config \\\"quoted\\\".toml\""));
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
    fn runtime_non_bind_errors_map_to_srs_exit_codes() {
        let io = || std::io::Error::other("runtime I/O failed");

        let udp = anyhow!(RuntimeError::Udp(io())).context("running runtime");
        assert_eq!(exit_code_for_error(&udp), EX_GENERAL);

        let tcp = anyhow!(RuntimeError::Tcp(io())).context("running runtime");
        assert_eq!(exit_code_for_error(&tcp), EX_GENERAL);

        let health = anyhow!(RuntimeError::Health(io())).context("running runtime");
        assert_eq!(exit_code_for_error(&health), EX_GENERAL);

        let dns_cookie_secret =
            anyhow!(RuntimeError::DnsCookieSecret(getrandom::Error::UNSUPPORTED))
                .context("starting runtime");
        assert_eq!(exit_code_for_error(&dns_cookie_secret), EX_OSERR);

        let file_descriptor_limit =
            anyhow!(RuntimeError::FileDescriptorLimit(io())).context("starting runtime");
        assert_eq!(exit_code_for_error(&file_descriptor_limit), EX_OSERR);
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

        let entropy_failure = anyhow!(RuntimeError::PrimaryRotationRandom(
            getrandom::Error::UNSUPPORTED,
        ))
        .context("starting runtime");
        assert_eq!(exit_code_for_error(&entropy_failure), EX_OSERR);

        let insufficient_rlimit = anyhow!(RuntimeError::InsufficientFileDescriptorLimit {
            current: 128,
            required: 512,
        })
        .context("starting runtime");
        assert_eq!(exit_code_for_error(&insufficient_rlimit), EX_OSERR);

        let privilege_drop = anyhow!(RuntimeError::PrivilegeDrop("setresuid failed".to_owned()))
            .context("starting runtime");
        assert_eq!(exit_code_for_error(&privilege_drop), EX_OSERR);
    }

    #[test]
    fn transfer_runtime_errors_map_to_srs_exit_codes() {
        let addr = "127.0.0.1:5300".parse().expect("socket address");
        let source_addr = "127.0.0.1:0".parse().expect("source socket address");
        let io = || std::io::Error::other("transfer I/O failed");

        let bind_udp =
            anyhow!(TransferError::BindUdp { addr, source: io() }).context("running transfer");
        assert_eq!(exit_code_for_error(&bind_udp), EX_CANTCREAT);

        let bind_tcp = anyhow!(TransferError::BindTcp {
            addr,
            source_addr,
            source: io(),
        })
        .context("running transfer");
        assert_eq!(exit_code_for_error(&bind_tcp), EX_CANTCREAT);

        let transfer_io =
            anyhow!(TransferError::Io { addr, source: io() }).context("running transfer");
        assert_eq!(exit_code_for_error(&transfer_io), EX_IOERR);

        let read_tls = anyhow!(TransferError::ReadTlsFile {
            path: "/missing/trust-anchor.pem".to_owned(),
            source: io(),
        })
        .context("validating runtime configuration");
        assert_eq!(exit_code_for_error(&read_tls), EX_IOERR);

        let xot_config = anyhow!(TransferError::XotConfig {
            addr,
            message: "server_name is required".to_owned(),
        })
        .context("validating runtime configuration");
        assert_eq!(exit_code_for_error(&xot_config), EX_CONFIG_INVALID);
    }

    #[test]
    fn transfer_protocol_errors_default_to_general() {
        let addr = "127.0.0.1:5300".parse().expect("socket address");
        let protocol_errors = [
            anyhow!(TransferError::ConnectTcp {
                addr,
                source: std::io::Error::other("connect failed"),
            }),
            anyhow!(TransferError::Timeout { timeout_secs: 30 }),
            anyhow!(TransferError::Axfr(
                oxidedns_core::axfr::AxfrError::EmptyResponse
            )),
            anyhow!(TransferError::Ixfr(
                oxidedns_core::axfr::IxfrError::EmptyResponse
            )),
            anyhow!(TransferError::Soa(
                oxidedns_core::axfr::SoaQueryError::MissingSoa
            )),
            anyhow!(TransferError::RandomQueryId(getrandom::Error::UNSUPPORTED)),
            anyhow!(TransferError::Tsig(
                oxidedns_core::tsig::TsigError::InvalidKeyName
            )),
            anyhow!(TransferError::TlsHandshake {
                addr,
                source: std::io::Error::other("TLS failed"),
            }),
            anyhow!(TransferError::IngestSizeLimit {
                protocol: "AXFR",
                addr,
                received_bytes: 1024,
                limit_bytes: 512,
            }),
            anyhow!(TransferError::XotAlpn { addr }),
        ];

        for error in protocol_errors {
            let error = error.context("running transfer");
            assert_eq!(exit_code_for_error(&error), EX_GENERAL);
        }
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
                ("ODS_SERVER_LOG_FORMAT", "logfmt"),
                ("ODS_SERVER_NSID", "env-nsid"),
                ("ODS_HEALTH_METRICS_RATE_LIMIT_PER_MINUTE", "120"),
                ("ODS_HEALTH_METRICS_RATE_LIMIT_IDLE_SECONDS", "45"),
                ("ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES", "8192"),
                ("ODS_TSIG_FUDGE_SECONDS", "30"),
                ("ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES", "104857600"),
                ("ODS_LIMITS_ZSM_MAX_INTERVAL_SECS", "43200"),
                ("ODS_LIMITS_ZSM_LOADING_WARNING_THRESHOLD_SECS", "1200"),
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
        assert_eq!(config.server.log_format, LogFormatConfig::Logfmt);
        assert_eq!(config.server.nsid, "env-nsid");
        assert_eq!(config.health.metrics_rate_limit_per_minute, 120);
        assert_eq!(config.health.metrics_rate_limit_idle_seconds, 45);
        assert_eq!(config.logging.max_entry_length_bytes, 8192);
        assert_eq!(config.tsig.fudge_seconds, 30);
        assert_eq!(config.limits.max_transfer_ingest_bytes, 104_857_600);
        assert_eq!(config.limits.zsm_max_interval_secs, 43_200);
        assert_eq!(config.limits.zsm_loading_warning_threshold_secs, 1200);
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

    #[test]
    fn oversized_json_log_entry_is_truncated_to_parseable_structured_entry() {
        let entry = format!("{{\"message\":\"{}\"}}\n", "x".repeat(512));
        let truncated = truncated_log_entry(LogFormatConfig::Json, entry.as_bytes(), 160);
        let text = String::from_utf8(truncated).expect("utf8 log entry");

        assert!(text.len() <= 160);
        assert!(text.ends_with('\n'));
        assert!(text.starts_with("{\"message\":\""));
        assert!(text.contains(LOG_TRUNCATION_MARKER));
        assert!(text.contains("\"truncated\":true"));
    }

    #[test]
    fn oversized_logfmt_entry_is_truncated_to_parseable_entry() {
        let entry = format!("INFO message=\"{}\"\n", "x".repeat(512));
        let truncated = truncated_log_entry(LogFormatConfig::Logfmt, entry.as_bytes(), 160);
        let text = String::from_utf8(truncated).expect("utf8 log entry");

        assert!(text.len() <= 160);
        assert!(text.ends_with('\n'));
        assert!(text.starts_with("message=\""));
        assert!(text.contains(LOG_TRUNCATION_MARKER));
        assert!(text.contains("truncated=true"));
    }

    #[test]
    fn logfmt_helpers_render_canonical_values() {
        assert_eq!(log_level_name(&Level::WARN), "warning");
        assert_eq!(logfmt_value("refresh failed"), "\"refresh failed\"");
        assert_eq!(logfmt_value("example.test."), "example.test.");
        assert_eq!(trim_debug_string("\"192.0.2.53\"".to_owned()), "192.0.2.53");
    }

    #[test]
    fn logfmt_formatter_emits_structured_tracing_events() {
        let output = SharedLogOutput::default();
        let subscriber = tracing_subscriber::fmt()
            .fmt_fields(LogfmtFields)
            .event_format(LogfmtFormatter)
            .with_env_filter(EnvFilter::new("info"))
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "oxidedns_test",
                zone = "example.test.",
                serial = 42_u64,
                r#type = "axfr",
                "refresh complete"
            );
        });

        let text = output.text();
        assert!(text.starts_with("timestamp="));
        assert!(text.contains(" level=warning "));
        assert!(text.contains(" target=oxidedns_test "));
        assert!(text.contains(" message=\"refresh complete\""));
        assert!(text.contains(" zone=example.test."));
        assert!(text.contains(" serial=42"));
        assert!(text.contains(" type=axfr"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn log_entry_limit_writer_preserves_entries_under_limit() {
        let mut output = Vec::new();
        {
            let mut writer = LogEntryLimitWriter::new(&mut output, 128, LogFormatConfig::Json);
            writer
                .write_all(b"{\"message\":\"short\"}\n")
                .expect("write log entry");
            writer.flush().expect("flush log entry");
        }

        assert_eq!(output, b"{\"message\":\"short\"}\n");
    }

    #[test]
    fn log_entry_limit_writer_ignores_broken_pipe() {
        let mut writer = LogEntryLimitWriter::new(BrokenPipeWriter, 128, LogFormatConfig::Json);

        writer
            .write_all(b"{\"message\":\"short\"}\n")
            .expect("broken pipe is non-fatal");
        writer.flush().expect("broken pipe flush is non-fatal");
    }

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
        }
    }

    #[derive(Clone, Default)]
    struct SharedLogOutput(Arc<Mutex<Vec<u8>>>);

    impl SharedLogOutput {
        fn text(&self) -> String {
            let bytes = self.0.lock().expect("log output lock").clone();
            String::from_utf8(bytes).expect("utf8 log output")
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for SharedLogOutput {
        type Writer = SharedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            SharedLogWriter(self.0.clone())
        }
    }

    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log output lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
