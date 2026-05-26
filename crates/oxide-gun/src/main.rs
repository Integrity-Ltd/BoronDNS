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
    /// XDP bind mode.
    #[arg(long, value_enum)]
    xdp_mode: Option<XdpMode>,
    /// XDP copy policy.
    #[arg(long, value_enum)]
    xdp_zerocopy: Option<XdpZeroCopyMode>,
    /// Source IP address placed into generated XDP packets.
    #[arg(long)]
    source_ip: Option<IpAddr>,
    /// Source UDP port placed into generated XDP packets.
    #[arg(long)]
    source_port: Option<u16>,
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
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            ip: DEFAULT_SOURCE_IPV4,
            port: DEFAULT_SOURCE_PORT,
            mac: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryConfig {
    qname: String,
    qtype: String,
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
    target: SocketAddr,
    qname: &'a str,
    qtype: &'a str,
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
    errors_total: u64,
    duration_seconds: f64,
    tx_qps: f64,
    rx_qps: f64,
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
    errors: u64,
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

#[derive(Debug)]
struct QueryTemplate {
    qname: String,
    qtype_name: String,
    qtype: u16,
    edns_enabled: bool,
    edns_payload_size: u16,
    dnssec_ok: bool,
    recursion_desired: bool,
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
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x >> 16) as u16
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
    if let Some(xdp_mode) = cli.xdp_mode {
        config.xdp.mode = xdp_mode;
    }
    if let Some(xdp_zerocopy) = cli.xdp_zerocopy {
        config.xdp.zerocopy = xdp_zerocopy;
    }
    if let Some(source_ip) = cli.source_ip {
        config.source.ip = source_ip;
    }
    if let Some(source_port) = cli.source_port {
        config.source.port = source_port;
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
    if config.backend.kind == Backend::Xdp {
        validate_xdp_config(config)?;
    }
    parse_qtype(&config.query.qtype)?;
    encode_qname(&config.query.qname)?;
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
        bail!("backend xdp currently requires interface.rx_queue to match interface.tx_queue");
    }
    if !config.xdp.umem_frame_count.is_power_of_two() {
        bail!("xdp.umem_frame_count must be a power of two");
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
    match (config.source.ip, target.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => Ok(()),
        _ => bail!("backend xdp requires source.ip and target.address to use the same IP family"),
    }
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
    let query = query_template(config)?;
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
    let query = query_template(config)?;
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
        let packet = build_dns_query(&query, id)?;
        socket.send_to(&packet, target).inspect_err(|_error| {
            stats.errors += 1;
        })?;
        stats.tx_packets += 1;
        stats.tx_bytes += packet.len() as u64;

        if config.recv.mode == RecvMode::Process {
            receive_one(&socket, id, &mut stats)?;
        }

        if config.log.flush_interval_ms > 0
            && last_flush.elapsed() >= Duration::from_millis(config.log.flush_interval_ms)
        {
            emit_record(config, target, &query, &stats, start, false)?;
            last_flush = Instant::now();
        }

        if let Some(delay) = per_packet_delay {
            thread::sleep(delay);
        }
    }

    emit_record(config, target, &query, &stats, start, true)
}

fn receive_one(socket: &UdpSocket, expected_id: u16, stats: &mut Stats) -> Result<()> {
    let mut buf = [0_u8; 4096];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => {
            stats.rx_packets += 1;
            stats.rx_bytes += len as u64;
            match classify_response(&buf[..len], expected_id) {
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
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        Err(error) => {
            stats.errors += 1;
            Err(error).context("failed to receive DNS response")
        }
    }
}

fn emit_record(
    config: &FileConfig,
    target: SocketAddr,
    query: &QueryTemplate,
    stats: &Stats,
    start: Instant,
    summary: bool,
) -> Result<()> {
    let elapsed = start.elapsed().as_secs_f64().max(0.000_001);
    let record = OutputRecord {
        record_type: if summary { "summary" } else { "interval" },
        timestamp: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
        summary,
        backend: "std_udp_socket",
        recv_mode: config.recv.mode,
        target,
        qname: &query.qname,
        qtype: &query.qtype_name,
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
        errors_total: stats.errors,
        duration_seconds: elapsed,
        tx_qps: stats.tx_packets as f64 / elapsed,
        rx_qps: stats.rx_packets as f64 / elapsed,
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
                "{} tx={:.0}qps rx={:.0}qps tx_total={} rx_total={} positive={} errors={}{}",
                record.timestamp,
                record.tx_qps,
                record.rx_qps,
                record.tx_packets_total,
                record.rx_packets_total,
                record.positive_total,
                record.errors_total,
                if summary { " summary=true" } else { "" }
            );
        }
    }
    io::stdout().lock().flush()?;
    Ok(())
}

fn query_template(config: &FileConfig) -> Result<QueryTemplate> {
    Ok(QueryTemplate {
        qname: normalize_qname(&config.query.qname)?,
        qtype_name: config.query.qtype.to_ascii_uppercase(),
        qtype: parse_qtype(&config.query.qtype)?,
        edns_enabled: config.query.edns_enabled,
        edns_payload_size: config.query.edns_payload_size,
        dnssec_ok: config.query.dnssec_ok,
        recursion_desired: config.query.recursion_desired,
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
    packet.extend_from_slice(&encode_qname(&query.qname)?);
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
    Ok(packet)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_edns_query_with_do_bit() {
        let query = QueryTemplate {
            qname: "www.example.test.".to_owned(),
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
}
