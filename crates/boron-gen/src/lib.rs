// Cargo exposes package-wide CLI dependencies to this mixed library/binary
// package even though their APIs are consumed only by src/main.rs.
use anyhow as _;
use clap as _;
use serde_json as _;
use tracing_subscriber as _;

pub mod scenario;
pub mod server;
pub mod wire;

pub use scenario::{
    ContentProfile, GeneratedRecord, Manifest, Scenario, ScenarioConfig, ScenarioError, ZoneKind,
    ZoneRecordIter, base32hex_no_padding, synthetic_nsec3_hash,
};
pub use server::{ServerConfig, ServerError, ServerStats, serve};
