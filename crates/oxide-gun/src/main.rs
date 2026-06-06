use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[cfg(feature = "xdp")]
mod xdp_backend;

const DEFAULT_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
const DEFAULT_QNAME: &str = "example.test.";
const DEFAULT_QTYPE: &str = "A";
const DEFAULT_MAX_PACKETS: u64 = 1;
const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 1000;
const DEFAULT_EDNS_PAYLOAD_SIZE: u16 = 1232;
const DEFAULT_SOURCE_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
const DEFAULT_SOURCE_PORT: u16 = 53000;

#[derive(Debug, Parser)]
#[command(
    name = "oxide-gun",
    version,
    about = "OxideDNS UDP DNS load generator and CI-safe self-test harness"
)]
struct Cli {
    /// TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Print the effective TOML configuration and exit.
    #[arg(long)]
    print_config: bool,
    /// Send one DNS query and print the response classification.
    #[arg(long)]
    probe: bool,
    /// Run a local UDP DNS responder and execute an end-to-end tool self-test.
    #[arg(long)]
    self_test: bool,
    /// Target DNS socket address, for example 192.0.2.53:53.
    #[arg(long)]
    target: Option<SocketAddr>,
    /// Packet backend. std-udp is portable; xdp requires --features xdp and Linux AF_XDP privileges.
    #[arg(long, value_enum)]
    backend: Option<Backend>,
    /// Linux network interface used by the XDP backend.
    #[arg(long)]
    interface: Option<String>,
    /// XDP TX queue id.
    #[arg(long)]
    tx_queue: Option<u32>,
    /// XDP RX queue id.
    #[arg(long)]
    rx_queue: Option<u32>,
    /// Number of contiguous XDP queue pairs to bind, starting at --tx-queue/--rx-queue.
    #[arg(long)]
    queue_count: Option<u32>,
    /// XDP bind mode.
    #[arg(long, value_enum)]
    xdp_mode: Option<XdpMode>,
    /// XDP copy policy.
    #[arg(long, value_enum)]
    xdp_zerocopy: Option<XdpZeroCopyMode>,
    /// Compiled Aya eBPF object for kernel reply drop mode.
    #[arg(long)]
    xdp_drop_object: Option<PathBuf>,
    /// Compiled Aya eBPF object for process-mode AF_XDP reply redirects.
    #[arg(long)]
    xdp_redirect_object: Option<PathBuf>,
    /// XDP response accounting detail.
    #[arg(long, value_enum)]
    xdp_reply_tracking: Option<XdpReplyTracking>,
    /// XDP TX/RX batch size.
    #[arg(long)]
    xdp_batch_size: Option<usize>,
    /// Maximum ready RX batches drained after each XDP TX pass.
    #[arg(long)]
    xdp_rx_drain_passes: Option<usize>,
    /// Explicit AF_XDP TX wakeup interval in successful send passes. 0 disables explicit wakeups.
    #[arg(long)]
    xdp_tx_wakeup_interval: Option<usize>,
    /// AF_XDP UMEM frame count.
    #[arg(long)]
    xdp_umem_frame_count: Option<u32>,
    /// AF_XDP TX ring size.
    #[arg(long)]
    xdp_tx_ring_size: Option<u32>,
    /// AF_XDP RX ring size.
    #[arg(long)]
    xdp_rx_ring_size: Option<u32>,
    /// AF_XDP fill ring size.
    #[arg(long)]
    xdp_fill_ring_size: Option<u32>,
    /// AF_XDP completion ring size.
    #[arg(long)]
    xdp_completion_ring_size: Option<u32>,
    /// Source IP address placed into generated XDP packets.
    #[arg(long)]
    source_ip: Option<IpAddr>,
    /// Source UDP port placed into generated XDP packets.
    #[arg(long)]
    source_port: Option<u16>,
    /// Random IPv4 CIDR source strategy, for example 198.18.0.0/24.
    #[arg(long)]
    source_cidr: Option<String>,
    /// Comma-separated round-robin source IP list.
    #[arg(long, value_delimiter = ',')]
    source_list: Vec<IpAddr>,
    /// First source IP for sequential source strategy.
    #[arg(long)]
    source_range_start: Option<IpAddr>,
    /// Number of IPs in sequential source strategy.
    #[arg(long)]
    source_range_count: Option<u64>,
    /// Sequential source IP stride.
    #[arg(long)]
    source_range_stride: Option<u64>,
    /// UDP source port range, for example 53000-53100.
    #[arg(long)]
    source_port_range: Option<String>,
    /// UDP source port selection strategy for --source-port-range.
    #[arg(long, value_enum)]
    source_port_select: Option<PortSelect>,
    /// Source Ethernet MAC for XDP packets, for example 02:00:00:00:00:01.
    #[arg(long)]
    source_mac: Option<MacAddr>,
    /// Target Ethernet MAC for XDP packets, for example aa:bb:cc:dd:ee:ff.
    #[arg(long)]
    target_mac: Option<MacAddr>,
    /// Query name used when no query list is configured.
    #[arg(long)]
    qname: Option<String>,
    /// Query type, for example A, AAAA, MX, ANY, or TYPE65400.
    #[arg(long)]
    qtype: Option<String>,
    /// Query list file. Each non-comment line is: qname QTYPE.
    #[arg(long)]
    query_list: Option<PathBuf>,
    /// Query-name template containing {}, for example host{}.example.test.
    #[arg(long)]
    qname_template: Option<String>,
    /// Number of query names generated from --qname-template.
    #[arg(long)]
    qname_count: Option<usize>,
    /// Query selection strategy when a pool has more than one entry.
    #[arg(long, value_enum)]
    query_select: Option<QuerySelect>,
    /// Maximum packet count. The first reached run limit wins.
    #[arg(long)]
    max_packets: Option<u64>,
    /// Maximum run duration in seconds. The first reached run limit wins.
    #[arg(long)]
    duration_seconds: Option<f64>,
    /// Target send rate. 0 means unlimited for the current backend.
    #[arg(long)]
    target_qps: Option<u64>,
    /// Receive mode. drop mode sends without waiting for replies.
    #[arg(long, value_enum)]
    recv_mode: Option<RecvMode>,
    /// Deterministic seed for query IDs and future randomized selections.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Output format for interval and summary records.
    #[arg(long, value_enum)]
    log_format: Option<LogFormat>,
    /// Periodic flush interval. 0 disables interval records.
    #[arg(long)]
    flush_interval_ms: Option<u64>,
    /// Response timeout used by process/probe mode.
    #[arg(long)]
    response_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum RecvMode {
    Process,
    Drop,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DropImplementation {
    None,
    UserspaceSuppression,
    KernelXdpDrop,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum LogFormat {
    Json,
    Human,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Backend {
    StdUdpSocket,
    Xdp,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum XdpMode {
    Drv,
    Skb,
    Hw,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum XdpZeroCopyMode {
    Auto,
    Force,
    Copy,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum XdpReplyTracking {
    Latency,
    Count,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum QuerySelect {
    #[default]
    Sequential,
    Random,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum PortSelect {
    #[default]
    Sequential,
    Random,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    backend: BackendConfig,
    #[serde(default)]
    interface: InterfaceConfig,
    #[serde(default)]
    target: TargetConfig,
    #[serde(default)]
    source: SourceConfig,
    #[serde(default)]
    query: QueryConfig,
    #[serde(default)]
    rate: RateConfig,
    #[serde(default)]
    run: RunConfig,
    #[serde(default)]
    recv: RecvConfig,
    #[serde(default)]
    xdp: XdpConfig,
    #[serde(default)]
    log: LogConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackendConfig {
    kind: Backend,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            kind: Backend::StdUdpSocket,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct InterfaceConfig {
    nic: Option<String>,
    tx_queue: u32,
    rx_queue: u32,
    #[serde(default = "default_queue_count")]
    queue_count: u32,
}

fn default_queue_count() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    address: Option<SocketAddr>,
    mac: Option<MacAddr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceConfig {
    ip: IpAddr,
    port: u16,
    mac: Option<MacAddr>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    list: Vec<IpAddr>,
    #[serde(default)]
    range_start: Option<IpAddr>,
    #[serde(default)]
    range_count: Option<u64>,
    #[serde(default = "default_source_range_stride")]
    range_stride: u64,
    #[serde(default)]
    port_range: Option<String>,
    #[serde(default)]
    port_select: PortSelect,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            ip: DEFAULT_SOURCE_IPV4,
            port: DEFAULT_SOURCE_PORT,
            mac: None,
            cidr: None,
            list: Vec::new(),
            range_start: None,
            range_count: None,
            range_stride: default_source_range_stride(),
            port_range: None,
            port_select: PortSelect::default(),
        }
    }
}

fn default_source_range_stride() -> u64 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryConfig {
    qname: String,
    qtype: String,
    #[serde(default)]
    list_file: Option<PathBuf>,
    #[serde(default)]
    qname_template: Option<String>,
    #[serde(default)]
    qname_count: Option<usize>,
    #[serde(default)]
    select: QuerySelect,
    edns_enabled: bool,
    edns_payload_size: u16,
    dnssec_ok: bool,
    recursion_desired: bool,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            qname: DEFAULT_QNAME.to_owned(),
            qtype: DEFAULT_QTYPE.to_owned(),
            list_file: None,
            qname_template: None,
            qname_count: None,
            select: QuerySelect::default(),
            edns_enabled: true,
            edns_payload_size: DEFAULT_EDNS_PAYLOAD_SIZE,
            dnssec_ok: false,
            recursion_desired: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct RateConfig {
    target_qps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunConfig {
    max_packets: u64,
    duration_seconds: Option<f64>,
    seed: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            max_packets: DEFAULT_MAX_PACKETS,
            duration_seconds: None,
            seed: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecvConfig {
    mode: RecvMode,
    response_timeout_ms: u64,
}

impl Default for RecvConfig {
    fn default() -> Self {
        Self {
            mode: RecvMode::Process,
            response_timeout_ms: DEFAULT_RESPONSE_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LogConfig {
    format: LogFormat,
    flush_interval_ms: u64,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            flush_interval_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct XdpConfig {
    mode: XdpMode,
    zerocopy: XdpZeroCopyMode,
    drop_object: Option<PathBuf>,
    redirect_object: Option<PathBuf>,
    reply_tracking: XdpReplyTracking,
    batch_size: usize,
    rx_drain_passes: usize,
    tx_wakeup_interval: usize,
    umem_frame_count: u32,
    tx_ring_size: u32,
    rx_ring_size: u32,
    fill_ring_size: u32,
    completion_ring_size: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            mode: XdpMode::Drv,
            zerocopy: XdpZeroCopyMode::Auto,
            drop_object: None,
            redirect_object: None,
            reply_tracking: XdpReplyTracking::Latency,
            batch_size: 64,
            rx_drain_passes: 4,
            tx_wakeup_interval: 1,
            umem_frame_count: 8192,
            tx_ring_size: 4096,
            rx_ring_size: 4096,
            fill_ring_size: 4096,
            completion_ring_size: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
struct MacAddr([u8; 6]);

impl FromStr for MacAddr {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 6];
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 6 {
            bail!("MAC address must contain six colon-separated octets");
        }
        for (index, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                bail!("MAC octet {index} must contain exactly two hex digits");
            }
            bytes[index] = u8::from_str_radix(part, 16)
                .with_context(|| format!("invalid MAC octet {part:?}"))?;
        }
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProbeRecord {
    record_type: &'static str,
    target: SocketAddr,
    qname: String,
    qtype: String,
    response: ResponseClass,
}

#[derive(Debug, Clone, Serialize)]
struct OutputRecord<'a> {
    record_type: &'a str,
    timestamp: String,
    summary: bool,
    backend: &'a str,
    recv_mode: RecvMode,
    drop_implementation: DropImplementation,
    target: SocketAddr,
    qname: &'a str,
    qtype: &'a str,
    query_pool_size: usize,
    query_select: QuerySelect,
    source_strategy: &'a str,
    source_port_strategy: &'a str,
    requested_qps: Option<u64>,
    tx_packets_total: u64,
    tx_bytes_total: u64,
    rx_packets_total: u64,
    rx_bytes_total: u64,
    rx_dns_responses_total: u64,
    rx_dns_unmatched_total: u64,
    rx_truncated_total: u64,
    positive_total: u64,
    nxdomain_total: u64,
    nodata_total: u64,
    servfail_total: u64,
    refused_total: u64,
    other_rcode_total: u64,
    queries_unanswered_total: u64,
    rx_kernel_dropped_total: u64,
    errors_total: u64,
    duration_seconds: f64,
    tx_qps: f64,
    rx_qps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_p50_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_p99_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_p999_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Stats {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    rx_dns_responses: u64,
    rx_dns_unmatched: u64,
    rx_truncated: u64,
    positive: u64,
    nxdomain: u64,
    nodata: u64,
    servfail: u64,
    refused: u64,
    other_rcode: u64,
    queries_unanswered: u64,
    rx_kernel_dropped: u64,
    errors: u64,
    latency: LatencyHistogram,
}

const LATENCY_BUCKETS_US: [u64; 16] = [
    10,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    u64::MAX,
];

#[derive(Debug, Clone, Copy)]
struct LatencyHistogram {
    counts: [u64; LATENCY_BUCKETS_US.len()],
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            counts: [0; LATENCY_BUCKETS_US.len()],
        }
    }
}

impl LatencyHistogram {
    fn record(&mut self, latency: Duration) {
        let micros = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        let bucket = LATENCY_BUCKETS_US
            .iter()
            .position(|edge| micros <= *edge)
            .unwrap_or(LATENCY_BUCKETS_US.len() - 1);
        self.counts[bucket] += 1;
    }

    fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    fn percentile(&self, numerator: u64, denominator: u64) -> Option<u64> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        let rank = total.saturating_mul(numerator).div_ceil(denominator).max(1);
        let mut seen = 0_u64;
        for (count, edge) in self.counts.iter().zip(LATENCY_BUCKETS_US) {
            seen += *count;
            if seen >= rank {
                return Some(edge);
            }
        }
        Some(u64::MAX)
    }

    fn percentiles(&self) -> (Option<u64>, Option<u64>, Option<u64>) {
        (
            self.percentile(50, 100),
            self.percentile(99, 100),
            self.percentile(999, 1000),
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResponseClass {
    Positive,
    Nxdomain,
    Nodata,
    Servfail,
    Refused,
    OtherRcode,
    Truncated,
    Unmatched,
    Timeout,
}

#[derive(Debug, Clone)]
struct QueryTemplate {
    qname: String,
    encoded_qname: Vec<u8>,
    qtype_name: String,
    qtype: u16,
    edns_enabled: bool,
    edns_payload_size: u16,
    dnssec_ok: bool,
    recursion_desired: bool,
}

#[derive(Debug)]
struct QueryPool {
    templates: Vec<QueryTemplate>,
    select: QuerySelect,
}

impl QueryPool {
    fn len(&self) -> usize {
        self.templates.len()
    }

    fn select(&self, rng: &mut XorShift64, index: u64) -> &QueryTemplate {
        &self.templates[self.select_index(rng, index)]
    }

    fn select_index(&self, rng: &mut XorShift64, index: u64) -> usize {
        match self.select {
            QuerySelect::Sequential => index as usize % self.templates.len(),
            QuerySelect::Random => rng.next_index(self.templates.len()),
        }
    }

    fn first(&self) -> &QueryTemplate {
        &self.templates[0]
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
struct SourceEndpoint {
    ip: IpAddr,
    port: u16,
}

#[derive(Debug)]
#[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
enum SourceIpSelector {
    Fixed(IpAddr),
    RoundRobin(Vec<IpAddr>),
    RandomIpv4Cidr { network: u32, host_mask: u32 },
    SequentialIpv4 { start: u32, count: u64, stride: u64 },
}

#[derive(Debug)]
#[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
struct PortSelector {
    first: u16,
    count: u16,
    select: PortSelect,
}

#[derive(Debug)]
#[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
struct SourceSelector {
    ip: SourceIpSelector,
    port: PortSelector,
    rng: XorShift64,
    counter: u64,
    ip_description: String,
    port_description: String,
}

impl SourceSelector {
    #[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
    fn portable_udp() -> Self {
        Self {
            ip: SourceIpSelector::Fixed(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: PortSelector {
                first: 0,
                count: 1,
                select: PortSelect::Sequential,
            },
            rng: XorShift64::new(1),
            counter: 0,
            ip_description: "os_assigned_udp_socket".to_owned(),
            port_description: "os_assigned_udp_socket".to_owned(),
        }
    }

    #[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
    fn new(config: &SourceConfig, seed: u64) -> Result<Self> {
        let strategy_count = usize::from(config.cidr.is_some())
            + usize::from(!config.list.is_empty())
            + usize::from(config.range_start.is_some() || config.range_count.is_some());
        if strategy_count > 1 {
            bail!("configure only one source strategy: cidr, list, or range");
        }
        let (ip, ip_description) = if let Some(cidr) = &config.cidr {
            let (network, host_mask, prefix) = parse_ipv4_cidr(cidr)?;
            (
                SourceIpSelector::RandomIpv4Cidr { network, host_mask },
                format!("random_cidr:{}/{}", Ipv4Addr::from(network), prefix),
            )
        } else if !config.list.is_empty() {
            (
                SourceIpSelector::RoundRobin(config.list.clone()),
                format!("round_robin:{}addrs", config.list.len()),
            )
        } else if config.range_start.is_some() || config.range_count.is_some() {
            let Some(IpAddr::V4(start)) = config.range_start else {
                bail!("source.range_start must be an IPv4 address for MVP sequential ranges");
            };
            let count = config
                .range_count
                .ok_or_else(|| anyhow!("source.range_count is required with source.range_start"))?;
            if count == 0 {
                bail!("source.range_count must be non-zero");
            }
            let stride = config.range_stride.max(1);
            (
                SourceIpSelector::SequentialIpv4 {
                    start: u32::from(start),
                    count,
                    stride,
                },
                format!("sequential:{start}/count={count}/stride={stride}"),
            )
        } else {
            (
                SourceIpSelector::Fixed(config.ip),
                format!("fixed:{}", config.ip),
            )
        };

        let (first_port, last_port) = if let Some(port_range) = &config.port_range {
            parse_port_range(port_range)?
        } else {
            (config.port, config.port)
        };
        let port_count = last_port
            .checked_sub(first_port)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| anyhow!("invalid source port range"))?;
        let port_description = if config.port_range.is_some() {
            format!("{:?}:{}-{}", config.port_select, first_port, last_port).to_ascii_lowercase()
        } else {
            format!("fixed:{first_port}")
        };

        Ok(Self {
            ip,
            port: PortSelector {
                first: first_port,
                count: port_count,
                select: config.port_select,
            },
            rng: XorShift64::new(seed ^ 0xa5a5_5a5a_0123_9876),
            counter: 0,
            ip_description,
            port_description,
        })
    }

    #[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
    fn next(&mut self) -> SourceEndpoint {
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);
        SourceEndpoint {
            ip: self.next_ip(counter),
            port: self.next_port(counter),
        }
    }

    fn ip_description(&self) -> &str {
        &self.ip_description
    }

    fn port_description(&self) -> &str {
        &self.port_description
    }

    #[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
    fn next_ip(&mut self, counter: u64) -> IpAddr {
        match &self.ip {
            SourceIpSelector::Fixed(ip) => *ip,
            SourceIpSelector::RoundRobin(list) => list[counter as usize % list.len()],
            SourceIpSelector::RandomIpv4Cidr { network, host_mask } => IpAddr::V4(Ipv4Addr::from(
                *network | (self.rng.next_u32() & *host_mask),
            )),
            SourceIpSelector::SequentialIpv4 {
                start,
                count,
                stride,
            } => IpAddr::V4(Ipv4Addr::from(
                start.wrapping_add(((counter % *count).saturating_mul(*stride)) as u32),
            )),
        }
    }

    #[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
    fn next_port(&mut self, counter: u64) -> u16 {
        if self.port.count == 1 {
            return self.port.first;
        }
        let offset = match self.port.select {
            PortSelect::Sequential => counter as u16 % self.port.count,
            PortSelect::Random => self.rng.next_bounded(u64::from(self.port.count)) as u16,
        };
        self.port.first + offset
    }
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u16(&mut self) -> u16 {
        (self.next_u64() >> 16) as u16
    }

    #[cfg_attr(not(any(feature = "xdp", test)), allow(dead_code))]
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 16) as u32
    }

    fn next_index(&mut self, len: usize) -> usize {
        self.next_bounded(len as u64) as usize
    }

    fn next_bounded(&mut self, upper_exclusive: u64) -> u64 {
        if upper_exclusive <= 1 {
            return 0;
        }
        self.next_u64() % upper_exclusive
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = load_config(cli.config.as_ref())?;
    apply_cli_overrides(&mut config, &cli);
    validate_config(&config)?;

    if cli.print_config {
        print!("{}", toml::to_string_pretty(&config)?);
        return Ok(());
    }

    if cli.self_test {
        config.backend.kind = Backend::StdUdpSocket;
        run_self_test(config)
    } else if cli.probe {
        run_probe(&config)
    } else {
        run_load(&config)
    }
}

fn load_config(path: Option<&PathBuf>) -> Result<FileConfig> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn apply_cli_overrides(config: &mut FileConfig, cli: &Cli) {
    if let Some(target) = cli.target {
        config.target.address = Some(target);
    }
    if let Some(backend) = cli.backend {
        config.backend.kind = backend;
    }
    if let Some(interface) = &cli.interface {
        config.interface.nic = Some(interface.clone());
    }
    if let Some(tx_queue) = cli.tx_queue {
        config.interface.tx_queue = tx_queue;
    }
    if let Some(rx_queue) = cli.rx_queue {
        config.interface.rx_queue = rx_queue;
    }
    if let Some(queue_count) = cli.queue_count {
        config.interface.queue_count = queue_count;
    }
    if let Some(xdp_mode) = cli.xdp_mode {
        config.xdp.mode = xdp_mode;
    }
    if let Some(xdp_zerocopy) = cli.xdp_zerocopy {
        config.xdp.zerocopy = xdp_zerocopy;
    }
    if let Some(xdp_drop_object) = &cli.xdp_drop_object {
        config.xdp.drop_object = Some(xdp_drop_object.clone());
    }
    if let Some(xdp_redirect_object) = &cli.xdp_redirect_object {
        config.xdp.redirect_object = Some(xdp_redirect_object.clone());
    }
    if let Some(xdp_reply_tracking) = cli.xdp_reply_tracking {
        config.xdp.reply_tracking = xdp_reply_tracking;
    }
    if let Some(xdp_batch_size) = cli.xdp_batch_size {
        config.xdp.batch_size = xdp_batch_size;
    }
    if let Some(xdp_rx_drain_passes) = cli.xdp_rx_drain_passes {
        config.xdp.rx_drain_passes = xdp_rx_drain_passes;
    }
    if let Some(xdp_tx_wakeup_interval) = cli.xdp_tx_wakeup_interval {
        config.xdp.tx_wakeup_interval = xdp_tx_wakeup_interval;
    }
    if let Some(xdp_umem_frame_count) = cli.xdp_umem_frame_count {
        config.xdp.umem_frame_count = xdp_umem_frame_count;
    }
    if let Some(xdp_tx_ring_size) = cli.xdp_tx_ring_size {
        config.xdp.tx_ring_size = xdp_tx_ring_size;
    }
    if let Some(xdp_rx_ring_size) = cli.xdp_rx_ring_size {
        config.xdp.rx_ring_size = xdp_rx_ring_size;
    }
    if let Some(xdp_fill_ring_size) = cli.xdp_fill_ring_size {
        config.xdp.fill_ring_size = xdp_fill_ring_size;
    }
    if let Some(xdp_completion_ring_size) = cli.xdp_completion_ring_size {
        config.xdp.completion_ring_size = xdp_completion_ring_size;
    }
    if let Some(source_ip) = cli.source_ip {
        config.source.ip = source_ip;
    }
    if let Some(source_port) = cli.source_port {
        config.source.port = source_port;
    }
    if let Some(source_cidr) = &cli.source_cidr {
        config.source.cidr = Some(source_cidr.clone());
    }
    if !cli.source_list.is_empty() {
        config.source.list = cli.source_list.clone();
    }
    if let Some(source_range_start) = cli.source_range_start {
        config.source.range_start = Some(source_range_start);
    }
    if let Some(source_range_count) = cli.source_range_count {
        config.source.range_count = Some(source_range_count);
    }
    if let Some(source_range_stride) = cli.source_range_stride {
        config.source.range_stride = source_range_stride;
    }
    if let Some(source_port_range) = &cli.source_port_range {
        config.source.port_range = Some(source_port_range.clone());
    }
    if let Some(source_port_select) = cli.source_port_select {
        config.source.port_select = source_port_select;
    }
    if let Some(source_mac) = cli.source_mac {
        config.source.mac = Some(source_mac);
    }
    if let Some(target_mac) = cli.target_mac {
        config.target.mac = Some(target_mac);
    }
    if let Some(qname) = &cli.qname {
        config.query.qname = qname.clone();
    }
    if let Some(qtype) = &cli.qtype {
        config.query.qtype = qtype.clone();
    }
    if let Some(query_list) = &cli.query_list {
        config.query.list_file = Some(query_list.clone());
    }
    if let Some(qname_template) = &cli.qname_template {
        config.query.qname_template = Some(qname_template.clone());
    }
    if let Some(qname_count) = cli.qname_count {
        config.query.qname_count = Some(qname_count);
    }
    if let Some(query_select) = cli.query_select {
        config.query.select = query_select;
    }
    if let Some(max_packets) = cli.max_packets {
        config.run.max_packets = max_packets;
    }
    if let Some(duration_seconds) = cli.duration_seconds {
        config.run.duration_seconds = Some(duration_seconds);
    }
    if let Some(target_qps) = cli.target_qps {
        config.rate.target_qps = Some(target_qps);
    }
    if let Some(recv_mode) = cli.recv_mode {
        config.recv.mode = recv_mode;
    }
    if let Some(log_format) = cli.log_format {
        config.log.format = log_format;
    }
    if let Some(flush_interval_ms) = cli.flush_interval_ms {
        config.log.flush_interval_ms = flush_interval_ms;
    }
    if let Some(response_timeout_ms) = cli.response_timeout_ms {
        config.recv.response_timeout_ms = response_timeout_ms;
    }
    config.run.seed = cli.seed;
}

fn validate_config(config: &FileConfig) -> Result<()> {
    if config.run.max_packets == 0 && config.run.duration_seconds.is_none() {
        bail!("run.max_packets must be non-zero unless run.duration_seconds is configured");
    }
    if config
        .run
        .duration_seconds
        .is_some_and(|seconds| seconds <= 0.0)
    {
        bail!("run.duration_seconds must be positive when configured");
    }
    if config.query.edns_payload_size < 512 {
        bail!("query.edns_payload_size must be at least 512");
    }
    if config.source.port == 0 {
        bail!("source.port must be non-zero");
    }
    validate_query_config(&config.query)?;
    validate_source_config(&config.source)?;
    if config.backend.kind == Backend::StdUdpSocket
        && (config.source.cidr.is_some()
            || !config.source.list.is_empty()
            || config.source.range_start.is_some()
            || config.source.range_count.is_some()
            || config.source.port_range.is_some())
    {
        bail!("source IP/port strategies require --backend xdp; std-udp uses the OS socket source");
    }
    if config.backend.kind == Backend::Xdp {
        validate_xdp_config(config)?;
    }
    Ok(())
}

fn validate_query_config(config: &QueryConfig) -> Result<()> {
    let pool_modes = usize::from(config.list_file.is_some())
        + usize::from(config.qname_template.is_some() || config.qname_count.is_some());
    if pool_modes > 1 {
        bail!("configure only one query pool mode: list_file or qname_template/qname_count");
    }
    if config.qname_template.is_some() || config.qname_count.is_some() {
        let Some(template) = &config.qname_template else {
            bail!("query.qname_template is required with query.qname_count");
        };
        if !template.contains("{}") {
            bail!("query.qname_template must contain {{}}");
        }
        if config.qname_count.unwrap_or(0) == 0 {
            bail!("query.qname_count must be non-zero with query.qname_template");
        }
    }
    parse_qtype(&config.qtype)?;
    encode_qname(&config.qname)?;
    Ok(())
}

fn validate_source_config(config: &SourceConfig) -> Result<()> {
    let strategy_count = usize::from(config.cidr.is_some())
        + usize::from(!config.list.is_empty())
        + usize::from(config.range_start.is_some() || config.range_count.is_some());
    if strategy_count > 1 {
        bail!("configure only one source strategy: cidr, list, or range");
    }
    if let Some(cidr) = &config.cidr {
        parse_ipv4_cidr(cidr)?;
    }
    if config.range_start.is_some() || config.range_count.is_some() {
        if !matches!(config.range_start, Some(IpAddr::V4(_))) {
            bail!("source.range_start must be IPv4 for MVP sequential ranges");
        }
        if config.range_count.unwrap_or(0) == 0 {
            bail!("source.range_count must be non-zero with source.range_start");
        }
        if config.range_stride == 0 {
            bail!("source.range_stride must be non-zero");
        }
    }
    if let Some(range) = &config.port_range {
        parse_port_range(range)?;
    }
    Ok(())
}

fn validate_xdp_config(config: &FileConfig) -> Result<()> {
    if config.interface.nic.as_deref().is_none_or(str::is_empty) {
        bail!("backend xdp requires interface.nic or --interface");
    }
    if config.source.mac.is_none() {
        bail!("backend xdp requires source.mac or --source-mac");
    }
    if config.target.mac.is_none() {
        bail!("backend xdp requires target.mac or --target-mac");
    }
    if config.interface.rx_queue != config.interface.tx_queue {
        bail!("backend xdp requires interface.rx_queue to match interface.tx_queue");
    }
    if config.interface.queue_count == 0 {
        bail!("backend xdp requires interface.queue_count to be non-zero");
    }
    config
        .interface
        .tx_queue
        .checked_add(config.interface.queue_count.saturating_sub(1))
        .ok_or_else(|| anyhow!("interface.queue_count overflows tx_queue"))?;
    config
        .interface
        .rx_queue
        .checked_add(config.interface.queue_count.saturating_sub(1))
        .ok_or_else(|| anyhow!("interface.queue_count overflows rx_queue"))?;
    if config.interface.queue_count > 1 && config.xdp.drop_object.is_some() {
        bail!("backend xdp multi-queue does not yet support xdp.drop_object reply drops");
    }
    if config.interface.queue_count > 1 && config.source.port_range.is_none() {
        if config.interface.queue_count > u32::from(u16::MAX) {
            bail!("interface.queue_count is too large for automatic source port assignment");
        }
        config
            .source
            .port
            .checked_add((config.interface.queue_count - 1) as u16)
            .ok_or_else(|| anyhow!("source.port plus interface.queue_count overflows u16"))?;
    }
    if !config.xdp.umem_frame_count.is_power_of_two() {
        bail!("xdp.umem_frame_count must be a power of two");
    }
    if config.xdp.batch_size == 0 {
        bail!("xdp.batch_size must be non-zero");
    }
    if config.xdp.rx_drain_passes == 0 {
        bail!("xdp.rx_drain_passes must be non-zero");
    }
    for (name, value) in [
        ("xdp.tx_ring_size", config.xdp.tx_ring_size),
        ("xdp.rx_ring_size", config.xdp.rx_ring_size),
        ("xdp.fill_ring_size", config.xdp.fill_ring_size),
        ("xdp.completion_ring_size", config.xdp.completion_ring_size),
    ] {
        if value != 0 && !value.is_power_of_two() {
            bail!("{name} must be zero or a power of two");
        }
    }
    let target = config.target.address.unwrap_or(DEFAULT_TARGET);
    if config.source.ip.is_ipv4() != target.ip().is_ipv4() {
        bail!("backend xdp requires source.ip and target.address to use the same IP family");
    }
    if target.ip().is_ipv6()
        && (config.source.cidr.is_some()
            || config.source.range_start.is_some()
            || config.source.range_count.is_some())
    {
        bail!("MVP source CIDR and range strategies are IPv4-only");
    }
    if config
        .source
        .list
        .iter()
        .any(|source| source.is_ipv4() != target.ip().is_ipv4())
    {
        bail!("all source.list entries must use the same IP family as target.address");
    }
    Ok(())
}

fn run_self_test(mut config: FileConfig) -> Result<()> {
    let responder = UdpSocket::bind("127.0.0.1:0").context("failed to bind self-test responder")?;
    let target = responder.local_addr()?;
    let handle = thread::spawn(move || serve_self_test_responder(responder));
    config.target.address = Some(target);
    if config.run.max_packets == DEFAULT_MAX_PACKETS {
        config.run.max_packets = 4;
    }
    let result = run_load(&config);
    let _ =
        UdpSocket::bind("127.0.0.1:0").and_then(|socket| socket.send_to(&[0], target).map(|_| ()));
    let responder_result = handle
        .join()
        .map_err(|_| anyhow!("self-test responder thread panicked"))?;
    result.and(responder_result)
}

fn serve_self_test_responder(socket: UdpSocket) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0_u8; 1500];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((1, _)) if buf[0] == 0 => return Ok(()),
            Ok((len, peer)) => {
                if len < 12 {
                    continue;
                }
                if let Ok(response) = build_self_test_response(&buf[..len]) {
                    let _ = socket.send_to(&response, peer);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error).context("self-test responder receive failed"),
        }
    }
}

fn build_self_test_response(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("query too short");
    }
    let question_end = question_end(query)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    response.extend_from_slice(&[0x00, 0x04, 192, 0, 2, 1]);
    Ok(response)
}

fn question_end(query: &[u8]) -> Result<usize> {
    let mut offset = 12;
    loop {
        let len = *query
            .get(offset)
            .ok_or_else(|| anyhow!("qname extends beyond query"))? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            bail!("compressed qname is not accepted in self-test query");
        }
        offset = offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("qname offset overflow"))?;
        if offset > query.len() {
            bail!("qname extends beyond query");
        }
    }
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("question offset overflow"))?;
    if end > query.len() {
        bail!("question extends beyond query");
    }
    Ok(end)
}

fn run_probe(config: &FileConfig) -> Result<()> {
    if config.backend.kind == Backend::Xdp {
        return run_load(config);
    }
    let target = config.target.address.unwrap_or(DEFAULT_TARGET);
    let query = query_pool(config)?.first().clone();
    let mut rng = XorShift64::new(config.run.seed);
    let id = rng.next_u16();
    let packet = build_dns_query(&query, id)?;
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    socket.set_read_timeout(Some(Duration::from_millis(config.recv.response_timeout_ms)))?;
    socket.send_to(&packet, target)?;
    let mut buf = [0_u8; 4096];
    let response = match socket.recv_from(&mut buf) {
        Ok((len, _)) => classify_response(&buf[..len], id),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            ResponseClass::Timeout
        }
        Err(error) => return Err(error).context("failed to receive probe response"),
    };
    let record = ProbeRecord {
        record_type: "probe",
        target,
        qname: query.qname,
        qtype: query.qtype_name,
        response,
    };
    serde_json::to_writer(io::stdout().lock(), &record)?;
    println!();
    Ok(())
}

fn run_load(config: &FileConfig) -> Result<()> {
    if config.backend.kind == Backend::Xdp {
        return run_xdp_load(config);
    }
    run_std_udp_load(config)
}

fn run_xdp_load(config: &FileConfig) -> Result<()> {
    #[cfg(feature = "xdp")]
    {
        xdp_backend::run(config)
    }
    #[cfg(not(feature = "xdp"))]
    {
        let _ = config;
        bail!("backend xdp requires building oxide-gun with --features xdp");
    }
}

fn run_std_udp_load(config: &FileConfig) -> Result<()> {
    let target = config.target.address.unwrap_or(DEFAULT_TARGET);
    let query_pool = query_pool(config)?;
    let source_selector = SourceSelector::portable_udp();
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    socket.set_read_timeout(Some(Duration::from_millis(config.recv.response_timeout_ms)))?;
    let mut rng = XorShift64::new(config.run.seed);
    let mut stats = Stats::default();
    let start = Instant::now();
    let deadline = config
        .run
        .duration_seconds
        .map(|seconds| start + Duration::from_secs_f64(seconds));
    let mut last_flush = start;
    let per_packet_delay = config
        .rate
        .target_qps
        .and_then(|qps| (qps > 0).then(|| Duration::from_secs_f64(1.0 / qps as f64)));
    let max_packets = if config.run.max_packets == 0 {
        u64::MAX
    } else {
        config.run.max_packets
    };

    while stats.tx_packets < max_packets {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let id = rng.next_u16();
        let query = query_pool.select(&mut rng, stats.tx_packets);
        let packet = build_dns_query(query, id)?;
        let sent_at = Instant::now();
        socket.send_to(&packet, target).inspect_err(|_error| {
            stats.errors += 1;
        })?;
        stats.tx_packets += 1;
        stats.tx_bytes += packet.len() as u64;

        if config.recv.mode == RecvMode::Process {
            receive_one(&socket, id, sent_at, &mut stats)?;
        }

        if config.log.flush_interval_ms > 0
            && last_flush.elapsed() >= Duration::from_millis(config.log.flush_interval_ms)
        {
            emit_record(
                config,
                target,
                query_pool.first(),
                &query_pool,
                &source_selector,
                &stats,
                start,
                false,
            )?;
            last_flush = Instant::now();
        }

        if let Some(delay) = per_packet_delay {
            thread::sleep(delay);
        }
    }

    emit_record(
        config,
        target,
        query_pool.first(),
        &query_pool,
        &source_selector,
        &stats,
        start,
        true,
    )
}

fn receive_one(
    socket: &UdpSocket,
    expected_id: u16,
    sent_at: Instant,
    stats: &mut Stats,
) -> Result<()> {
    let mut buf = [0_u8; 4096];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => {
            stats.rx_packets += 1;
            stats.rx_bytes += len as u64;
            let response_class = classify_response(&buf[..len], expected_id);
            match response_class {
                ResponseClass::Positive => {
                    stats.rx_dns_responses += 1;
                    stats.positive += 1;
                }
                ResponseClass::Nxdomain => {
                    stats.rx_dns_responses += 1;
                    stats.nxdomain += 1;
                }
                ResponseClass::Nodata => {
                    stats.rx_dns_responses += 1;
                    stats.nodata += 1;
                }
                ResponseClass::Servfail => {
                    stats.rx_dns_responses += 1;
                    stats.servfail += 1;
                }
                ResponseClass::Refused => {
                    stats.rx_dns_responses += 1;
                    stats.refused += 1;
                }
                ResponseClass::OtherRcode => {
                    stats.rx_dns_responses += 1;
                    stats.other_rcode += 1;
                }
                ResponseClass::Truncated => {
                    stats.rx_dns_responses += 1;
                    stats.rx_truncated += 1;
                }
                ResponseClass::Unmatched => stats.rx_dns_unmatched += 1,
                ResponseClass::Timeout => {}
            }
            if !matches!(
                response_class,
                ResponseClass::Unmatched | ResponseClass::Timeout
            ) {
                stats.latency.record(sent_at.elapsed());
            }
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            stats.queries_unanswered += 1;
            Ok(())
        }
        Err(error) => {
            stats.errors += 1;
            Err(error).context("failed to receive DNS response")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_record(
    config: &FileConfig,
    target: SocketAddr,
    query: &QueryTemplate,
    query_pool: &QueryPool,
    source_selector: &SourceSelector,
    stats: &Stats,
    start: Instant,
    summary: bool,
) -> Result<()> {
    let elapsed = start.elapsed().as_secs_f64().max(0.000_001);
    let (latency_p50_us, latency_p99_us, latency_p999_us) = stats.latency.percentiles();
    let record = OutputRecord {
        record_type: if summary { "summary" } else { "interval" },
        timestamp: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
        summary,
        backend: "std_udp_socket",
        recv_mode: config.recv.mode,
        drop_implementation: drop_implementation(config.recv.mode, false),
        target,
        qname: &query.qname,
        qtype: &query.qtype_name,
        query_pool_size: query_pool.len(),
        query_select: query_pool.select,
        source_strategy: source_selector.ip_description(),
        source_port_strategy: source_selector.port_description(),
        requested_qps: config.rate.target_qps,
        tx_packets_total: stats.tx_packets,
        tx_bytes_total: stats.tx_bytes,
        rx_packets_total: stats.rx_packets,
        rx_bytes_total: stats.rx_bytes,
        rx_dns_responses_total: stats.rx_dns_responses,
        rx_dns_unmatched_total: stats.rx_dns_unmatched,
        rx_truncated_total: stats.rx_truncated,
        positive_total: stats.positive,
        nxdomain_total: stats.nxdomain,
        nodata_total: stats.nodata,
        servfail_total: stats.servfail,
        refused_total: stats.refused,
        other_rcode_total: stats.other_rcode,
        queries_unanswered_total: stats.queries_unanswered,
        rx_kernel_dropped_total: stats.rx_kernel_dropped,
        errors_total: stats.errors,
        duration_seconds: elapsed,
        tx_qps: stats.tx_packets as f64 / elapsed,
        rx_qps: stats.rx_packets as f64 / elapsed,
        latency_p50_us,
        latency_p99_us,
        latency_p999_us,
        note: (config.recv.mode == RecvMode::Drop)
            .then_some("drop mode sends without userspace response classification in this backend"),
    };

    match config.log.format {
        LogFormat::Json => {
            serde_json::to_writer(io::stdout().lock(), &record)?;
            println!();
        }
        LogFormat::Human => {
            println!(
                "{} tx={:.0}qps rx={:.0}qps tx_total={} rx_total={} positive={} errors={} drop={}{}",
                record.timestamp,
                record.tx_qps,
                record.rx_qps,
                record.tx_packets_total,
                record.rx_packets_total,
                record.positive_total,
                record.errors_total,
                serde_plain_drop_implementation(record.drop_implementation),
                if summary { " summary=true" } else { "" }
            );
        }
    }
    io::stdout().lock().flush()?;
    Ok(())
}

fn drop_implementation(mode: RecvMode, kernel_xdp_drop: bool) -> DropImplementation {
    match (mode, kernel_xdp_drop) {
        (RecvMode::Process, _) => DropImplementation::None,
        (RecvMode::Drop, true) => DropImplementation::KernelXdpDrop,
        (RecvMode::Drop, false) => DropImplementation::UserspaceSuppression,
    }
}

fn serde_plain_drop_implementation(value: DropImplementation) -> &'static str {
    match value {
        DropImplementation::None => "none",
        DropImplementation::UserspaceSuppression => "userspace_suppression",
        DropImplementation::KernelXdpDrop => "kernel_xdp_drop",
    }
}

fn query_template(config: &FileConfig) -> Result<QueryTemplate> {
    template_from_parts(&config.query.qname, &config.query.qtype, &config.query)
}

fn query_pool(config: &FileConfig) -> Result<QueryPool> {
    let mut templates = Vec::new();
    if let Some(path) = &config.query.list_file {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read query list {}", path.display()))?;
        for (line_index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let qname = fields.next().ok_or_else(|| {
                anyhow!(
                    "query list {}:{} is missing qname",
                    path.display(),
                    line_index + 1
                )
            })?;
            let qtype = fields.next().ok_or_else(|| {
                anyhow!(
                    "query list {}:{} is missing qtype",
                    path.display(),
                    line_index + 1
                )
            })?;
            if fields.next().is_some() {
                bail!(
                    "query list {}:{} must contain exactly qname and qtype",
                    path.display(),
                    line_index + 1
                );
            }
            templates.push(template_from_parts(qname, qtype, &config.query)?);
        }
        if templates.is_empty() {
            bail!("query list {} did not contain any queries", path.display());
        }
    } else if let Some(template) = &config.query.qname_template {
        let count = config
            .query
            .qname_count
            .ok_or_else(|| anyhow!("query.qname_count is required with query.qname_template"))?;
        for index in 0..count {
            let qname = template.replace("{}", &index.to_string());
            templates.push(template_from_parts(
                &qname,
                &config.query.qtype,
                &config.query,
            )?);
        }
    } else {
        templates.push(query_template(config)?);
    }
    Ok(QueryPool {
        templates,
        select: config.query.select,
    })
}

fn template_from_parts(qname: &str, qtype: &str, config: &QueryConfig) -> Result<QueryTemplate> {
    let qname = normalize_qname(qname)?;
    let encoded_qname = encode_qname(&qname)?;
    Ok(QueryTemplate {
        qname,
        encoded_qname,
        qtype_name: qtype.to_ascii_uppercase(),
        qtype: parse_qtype(qtype)?,
        edns_enabled: config.edns_enabled,
        edns_payload_size: config.edns_payload_size,
        dnssec_ok: config.dnssec_ok,
        recursion_desired: config.recursion_desired,
    })
}

fn normalize_qname(qname: &str) -> Result<String> {
    let trimmed = qname.trim();
    if trimmed.is_empty() {
        bail!("query.qname must not be empty");
    }
    let absolute = if trimmed.ends_with('.') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    };
    encode_qname(&absolute)?;
    Ok(absolute)
}

fn build_dns_query(query: &QueryTemplate, id: u16) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(128);
    build_dns_query_into(&mut packet, query, id)?;
    Ok(packet)
}

fn build_dns_query_into(packet: &mut Vec<u8>, query: &QueryTemplate, id: u16) -> Result<()> {
    packet.clear();
    packet.extend_from_slice(&id.to_be_bytes());
    let flags = if query.recursion_desired {
        0x0100_u16
    } else {
        0_u16
    };
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&(query.edns_enabled as u16).to_be_bytes());
    packet.extend_from_slice(&query.encoded_qname);
    packet.extend_from_slice(&query.qtype.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());

    if query.edns_enabled {
        packet.push(0);
        packet.extend_from_slice(&41_u16.to_be_bytes());
        packet.extend_from_slice(&query.edns_payload_size.to_be_bytes());
        let ttl = if query.dnssec_ok { 0x0000_8000_u32 } else { 0 };
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
    }
    Ok(())
}

fn encode_qname(qname: &str) -> Result<Vec<u8>> {
    let trimmed = qname.trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(vec![0]);
    }
    let mut out = Vec::new();
    for label in trimmed.split('.') {
        if label.is_empty() {
            bail!("empty DNS label in {qname}");
        }
        if label.len() > 63 {
            bail!("DNS label exceeds 63 octets in {qname}");
        }
        if !label.is_ascii() {
            bail!("oxide-gun MVP accepts ASCII qnames only: {qname}");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > 255 {
        bail!("encoded qname exceeds 255 octets: {qname}");
    }
    Ok(out)
}

fn parse_qtype(qtype: &str) -> Result<u16> {
    let upper = qtype.trim().to_ascii_uppercase();
    let code = match upper.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ if upper.starts_with("TYPE") => upper[4..]
            .parse::<u16>()
            .with_context(|| format!("invalid RFC3597 qtype {qtype}"))?,
        _ => bail!("unsupported qtype {qtype}; use a mnemonic or TYPE####"),
    };
    Ok(code)
}

fn parse_ipv4_cidr(cidr: &str) -> Result<(u32, u32, u8)> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("source CIDR must be address/prefix: {cidr}"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid IPv4 CIDR address {cidr}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid IPv4 CIDR prefix {cidr}"))?;
    if prefix > 32 {
        bail!("IPv4 CIDR prefix must be <= 32: {cidr}");
    }
    let host_mask = if prefix == 32 { 0 } else { u32::MAX >> prefix };
    let network = u32::from(addr) & !host_mask;
    Ok((network, host_mask, prefix))
}

fn parse_port_range(range: &str) -> Result<(u16, u16)> {
    let (first, last) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("source port range must be min-max: {range}"))?;
    let first: u16 = first
        .parse()
        .with_context(|| format!("invalid source port range start {range}"))?;
    let last: u16 = last
        .parse()
        .with_context(|| format!("invalid source port range end {range}"))?;
    if first == 0 || last == 0 {
        bail!("source port range cannot include port 0");
    }
    if first > last {
        bail!("source port range start must be <= end: {range}");
    }
    Ok((first, last))
}

fn classify_response(packet: &[u8], expected_id: u16) -> ResponseClass {
    if packet.len() < 12 {
        return ResponseClass::Unmatched;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    if id != expected_id {
        return ResponseClass::Unmatched;
    }
    let flags0 = packet[2];
    let flags1 = packet[3];
    if flags0 & 0x80 == 0 {
        return ResponseClass::Unmatched;
    }
    if flags0 & 0x02 != 0 {
        return ResponseClass::Truncated;
    }
    let rcode = flags1 & 0x0f;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    match (rcode, ancount) {
        (0, 1..) => ResponseClass::Positive,
        (0, 0) => ResponseClass::Nodata,
        (3, _) => ResponseClass::Nxdomain,
        (2, _) => ResponseClass::Servfail,
        (5, _) => ResponseClass::Refused,
        _ => ResponseClass::OtherRcode,
    }
}

#[cfg_attr(not(feature = "xdp"), allow(dead_code))]
fn response_id(packet: &[u8]) -> Option<u16> {
    (packet.len() >= 2).then(|| u16::from_be_bytes([packet[0], packet[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_edns_query_with_do_bit() {
        let query = QueryTemplate {
            qname: "www.example.test.".to_owned(),
            encoded_qname: encode_qname("www.example.test.").expect("qname encodes"),
            qtype_name: "AAAA".to_owned(),
            qtype: 28,
            edns_enabled: true,
            edns_payload_size: 1232,
            dnssec_ok: true,
            recursion_desired: false,
        };
        let packet = build_dns_query(&query, 0x1234).expect("query builds");
        assert_eq!(&packet[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 1);
        assert!(packet.ends_with(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]));
    }

    #[test]
    fn classifies_basic_response_categories() {
        let query = build_dns_query(
            &QueryTemplate {
                qname: "example.test.".to_owned(),
                encoded_qname: encode_qname("example.test.").expect("qname encodes"),
                qtype_name: "A".to_owned(),
                qtype: 1,
                edns_enabled: false,
                edns_payload_size: 1232,
                dnssec_ok: false,
                recursion_desired: false,
            },
            7,
        )
        .expect("query builds");
        let response = build_self_test_response(&query).expect("response builds");
        assert_eq!(classify_response(&response, 7), ResponseClass::Positive);
        assert_eq!(classify_response(&response, 8), ResponseClass::Unmatched);
    }

    #[test]
    fn rejects_invalid_qnames() {
        assert!(encode_qname("bad..example.").is_err());
        assert!(encode_qname(&format!("{}.example.", "a".repeat(64))).is_err());
    }

    #[test]
    fn query_pool_loads_file_and_selects_deterministically() {
        let path = std::env::temp_dir().join(format!(
            "oxide-gun-query-pool-{}-{}.txt",
            std::process::id(),
            1
        ));
        std::fs::write(
            &path,
            "# comment\nwww.example.test. A\nmail.example.test. MX\n",
        )
        .expect("query list written");
        let mut config = FileConfig::default();
        config.query.list_file = Some(path.clone());
        config.query.select = QuerySelect::Sequential;

        let pool = query_pool(&config).expect("query pool loads");
        assert_eq!(pool.len(), 2);
        let mut rng = XorShift64::new(1);
        assert_eq!(pool.select(&mut rng, 0).qname, "www.example.test.");
        assert_eq!(pool.select(&mut rng, 1).qname, "mail.example.test.");
        assert_eq!(pool.select(&mut rng, 2).qname, "www.example.test.");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn source_selector_generates_ipv4_cidr_and_ports() {
        let config = SourceConfig {
            cidr: Some("198.18.7.0/30".to_owned()),
            port_range: Some("53000-53003".to_owned()),
            port_select: PortSelect::Sequential,
            ..SourceConfig::default()
        };
        let mut selector = SourceSelector::new(&config, 7).expect("source selector builds");
        let first = selector.next();
        let second = selector.next();
        assert!(matches!(first.ip, IpAddr::V4(ip) if ip.octets()[0..3] == [198, 18, 7]));
        assert!(matches!(second.ip, IpAddr::V4(ip) if ip.octets()[0..3] == [198, 18, 7]));
        assert_eq!(first.port, 53000);
        assert_eq!(second.port, 53001);
        assert_eq!(selector.ip_description(), "random_cidr:198.18.7.0/30");
    }

    #[test]
    fn std_udp_rejects_xdp_only_source_strategy() {
        let mut config = FileConfig::default();
        config.source.cidr = Some("198.18.0.0/24".to_owned());
        assert!(validate_config(&config).is_err());
    }
}
