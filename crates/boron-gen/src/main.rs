use std::{env, net::SocketAddr};

use anyhow::{Context, Result};
use boron_gen::{
    ContentProfile, Scenario, ScenarioConfig,
    server::{ServerConfig, serve},
};
use borondns_core::tsig::TsigKey;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "boron-gen",
    version,
    about = "Deterministic bounded-memory synthetic DNS primary for BoronDNS load testing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate and print a machine-readable scenario manifest.
    Manifest(ScenarioArgs),
    /// Serve catalog/SOA/AXFR/unchanged-IXFR over UDP and TCP.
    Serve(ServeArgs),
}

#[derive(Debug, Clone, Args)]
struct ScenarioArgs {
    #[arg(long, value_enum, default_value_t = ProfileArg::RegistryNsec3)]
    profile: ProfileArg,

    #[arg(long, default_value = "load.borongen.")]
    origin: String,

    #[arg(long, default_value = "catalog.borongen.")]
    catalog_origin: String,

    #[arg(long, default_value_t = 1)]
    zones: u64,

    #[arg(long, default_value_t = 1_000)]
    names_per_zone: u64,

    #[arg(long, default_value_t = 4)]
    records_per_name: u32,

    #[arg(long, default_value_t = 128)]
    txt_rdata_bytes: u16,

    #[arg(long, default_value_t = 1_000)]
    nsec3_records_per_zone: u64,

    #[arg(long, default_value_t = 0)]
    nsec3_iterations: u16,

    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    nsec3_opt_out: bool,

    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    structural_rrsigs: bool,

    #[arg(long, default_value_t = 20)]
    ds_every: u32,

    #[arg(long, default_value_t = 0x626f_726f_6e67_656e)]
    seed: u64,

    #[arg(long, default_value_t = 1)]
    serial: u32,

    #[arg(long, default_value_t = 300)]
    ttl: u32,
}

#[derive(Debug, Args)]
struct ServeArgs {
    #[command(flatten)]
    scenario: ScenarioArgs,

    #[arg(long, default_value = "127.0.0.1:15353")]
    listen: SocketAddr,

    #[arg(long, default_value_t = 60_000)]
    message_bytes: usize,

    #[arg(long, default_value_t = 4)]
    max_connections: usize,

    #[arg(long, default_value = "transfer-key.")]
    tsig_name: String,

    #[arg(long, default_value = "hmac-sha256")]
    tsig_algorithm: String,

    #[arg(long, default_value_t = false)]
    json_logs: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    RegistryNsec3,
    Mixed,
    LargeRrset,
}

impl From<ProfileArg> for ContentProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::RegistryNsec3 => Self::RegistryNsec3,
            ProfileArg::Mixed => Self::Mixed,
            ProfileArg::LargeRrset => Self::LargeRrset,
        }
    }
}

impl From<ScenarioArgs> for ScenarioConfig {
    fn from(args: ScenarioArgs) -> Self {
        Self {
            profile: args.profile.into(),
            origin: args.origin,
            catalog_origin: args.catalog_origin,
            zones: args.zones,
            names_per_zone: args.names_per_zone,
            records_per_name: args.records_per_name,
            txt_rdata_bytes: args.txt_rdata_bytes,
            nsec3_records_per_zone: args.nsec3_records_per_zone,
            nsec3_iterations: args.nsec3_iterations,
            nsec3_opt_out: args.nsec3_opt_out,
            structural_rrsigs: args.structural_rrsigs,
            ds_every: args.ds_every,
            seed: args.seed,
            serial: args.serial,
            ttl: args.ttl,
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Manifest(args) => {
            let scenario = Scenario::new(args.into()).context("invalid BoronGen scenario")?;
            println!(
                "{}",
                serde_json::to_string_pretty(scenario.manifest())
                    .context("serialize BoronGen manifest")?
            );
        }
        Command::Serve(args) => run_server(args).await?,
    }
    Ok(())
}

async fn run_server(args: ServeArgs) -> Result<()> {
    init_logging(args.json_logs)?;
    let scenario = Scenario::new(args.scenario.into()).context("invalid BoronGen scenario")?;
    let tsig_secret = match env::var("BORON_GEN_TSIG_SECRET") {
        Ok(secret) => Some(secret),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            anyhow::bail!("BORON_GEN_TSIG_SECRET must be valid UTF-8 base64")
        }
    };
    let tsig_key = match tsig_secret {
        Some(secret) => Some(
            TsigKey::from_base64(&args.tsig_name, &args.tsig_algorithm, &secret)
                .context("invalid BoronGen TSIG configuration")?,
        ),
        None => None,
    };

    info!(
        event = "boron_gen_manifest",
        manifest = %serde_json::to_string(scenario.manifest())?,
        "validated deterministic scenario"
    );
    if tsig_key.is_none() {
        info!(
            event = "boron_gen_unsigned_mode",
            "serving unsigned transfers; BoronDNS catalog-zone tests require BORON_GEN_TSIG_SECRET"
        );
    }
    let stats = serve(
        scenario,
        ServerConfig {
            listen: args.listen,
            message_bytes: args.message_bytes,
            max_connections: args.max_connections,
            tsig_key,
        },
    )
    .await?;
    info!(
        event = "boron_gen_final_stats",
        stats = %serde_json::to_string(&stats)?,
        "BoronGen final counters"
    );
    Ok(())
}

fn init_logging(json: bool) -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("boron_gen=info"));
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .map_err(anyhow::Error::msg)?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}
