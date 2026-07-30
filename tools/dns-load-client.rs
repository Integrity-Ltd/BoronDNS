use std::borrow::Cow;
use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Config {
    transport: Transport,
    server: String,
    port: u16,
    bind: String,
    threads: usize,
    udp_sockets_per_thread: usize,
    duration: Duration,
    window: usize,
    names: usize,
    zones: usize,
    big_zones: usize,
    big_names: usize,
    small_names: usize,
    timeout: Duration,
    target_qps: Option<u64>,
    randomize: bool,
    trace_queries: Option<Arc<Vec<TraceQuery>>>,
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Clone)]
struct TraceQuery {
    qname: String,
    qtype: u16,
    qclass: u16,
    edns: EdnsMode,
    expected_rcode: u8,
    min_answers: u16,
}

#[derive(Clone, Copy)]
enum EdnsMode {
    None,
    Edns,
    Do,
}

#[derive(Default)]
struct WorkerStats {
    sent: u64,
    received: u64,
    errors: u64,
    latencies_ns: Vec<u64>,
}

#[derive(Clone, Copy)]
struct PendingQuery {
    sent: Instant,
    expected_rcode: u8,
    min_answers: u16,
}

struct Pacer {
    started: Instant,
    target_qps: u64,
    next_ticket: Arc<AtomicU64>,
    due: Option<Instant>,
}

impl Pacer {
    fn new(started: Instant, target_qps: u64, next_ticket: Arc<AtomicU64>) -> Self {
        Self {
            started,
            target_qps,
            next_ticket,
            due: None,
        }
    }

    fn ready(&mut self, now: Instant) -> bool {
        let due = *self.due.get_or_insert_with(|| {
            let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
            let offset_ns = (u128::from(ticket) * 1_000_000_000u128) / u128::from(self.target_qps);
            let offset_ns = u64::try_from(offset_ns).unwrap_or(u64::MAX);
            self.started
                .checked_add(Duration::from_nanos(offset_ns))
                .unwrap_or(now)
        });
        now >= due
    }

    fn sent(&mut self) {
        self.due = None;
    }
}

fn main() {
    let config = match parse_args() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            usage();
            std::process::exit(64);
        }
    };

    let started = Instant::now();
    let deadline = started + config.duration;
    let next_ticket = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    for worker_id in 0..config.threads {
        let config = config.clone();
        let tx = tx.clone();
        let next_ticket = next_ticket.clone();
        handles.push(thread::spawn(move || {
            let stats = run_worker(worker_id, config, started, deadline, next_ticket);
            tx.send(stats).expect("stats receiver alive");
        }));
    }
    drop(tx);

    let mut total = WorkerStats::default();
    for stats in rx {
        total.sent += stats.sent;
        total.received += stats.received;
        total.errors += stats.errors;
        total.latencies_ns.extend(stats.latencies_ns);
    }
    for handle in handles {
        handle.join().expect("worker thread should not panic");
    }

    if total.received == 0 {
        eprintln!("no DNS responses received");
        std::process::exit(1);
    }

    total.latencies_ns.sort_unstable();
    let elapsed = started.elapsed().as_secs_f64();
    let received_per_second = total.received as f64 / elapsed;
    let sent_per_second = total.sent as f64 / elapsed;
    let dropped = total.sent.saturating_sub(total.received + total.errors);
    let trace_queries = config
        .trace_queries
        .as_ref()
        .map_or(0, |queries| queries.len());
    let query_mode = if trace_queries == 0 {
        "generated"
    } else {
        "trace"
    };

    println!(
        concat!(
            "dns_load_client_summary ",
            "transport={transport} ",
            "duration_seconds={elapsed:.3} ",
            "server={server} port={port} bind={bind} ",
            "threads={threads} udp_sockets_per_thread={udp_sockets_per_thread} window={window} names={names} ",
            "zones={zones} big_zones={big_zones} big_names={big_names} small_names={small_names} randomize={randomize} ",
            "query_mode={query_mode} trace_queries={trace_queries} ",
            "target_qps={target_qps} ",
            "sent={sent} received={received} errors={errors} dropped={dropped} ",
            "sent_per_second={sent_per_second:.0} ",
            "responses_per_second={received_per_second:.0} ",
            "latency_us_min={lat_min:.1} ",
            "latency_us_p50={lat_p50:.1} ",
            "latency_us_p90={lat_p90:.1} ",
            "latency_us_p99={lat_p99:.1} ",
            "latency_us_p999={lat_p999:.1} ",
            "latency_us_max={lat_max:.1}"
        ),
        transport = config.transport.as_str(),
        elapsed = elapsed,
        server = config.server,
        port = config.port,
        bind = config.bind,
        threads = config.threads,
        udp_sockets_per_thread = config.udp_sockets_per_thread,
        window = config.window,
        names = config.names,
        zones = config.zones,
        big_zones = config.big_zones,
        big_names = config.big_names,
        small_names = config.small_names,
        randomize = config.randomize,
        query_mode = query_mode,
        trace_queries = trace_queries,
        target_qps = config
            .target_qps
            .map_or_else(|| "unlimited".to_owned(), |value| value.to_string()),
        sent = total.sent,
        received = total.received,
        errors = total.errors,
        dropped = dropped,
        sent_per_second = sent_per_second,
        received_per_second = received_per_second,
        lat_min = latency_us(&total.latencies_ns, 0.0),
        lat_p50 = latency_us(&total.latencies_ns, 0.50),
        lat_p90 = latency_us(&total.latencies_ns, 0.90),
        lat_p99 = latency_us(&total.latencies_ns, 0.99),
        lat_p999 = latency_us(&total.latencies_ns, 0.999),
        lat_max = latency_us(&total.latencies_ns, 1.0),
    );
}

fn run_worker(
    worker_id: usize,
    config: Config,
    started: Instant,
    deadline: Instant,
    next_ticket: Arc<AtomicU64>,
) -> WorkerStats {
    let pacer = config
        .target_qps
        .map(|target_qps| Pacer::new(started, target_qps, next_ticket));
    match config.transport {
        Transport::Udp => run_udp_worker(worker_id, config, deadline, pacer),
        Transport::Tcp => run_tcp_worker(worker_id, config, deadline, pacer),
    }
}

fn run_udp_worker(
    worker_id: usize,
    config: Config,
    deadline: Instant,
    mut pacer: Option<Pacer>,
) -> WorkerStats {
    let sockets = (0..config.udp_sockets_per_thread)
        .map(|_| {
            let socket = UdpSocket::bind(&config.bind).expect("bind UDP client socket");
            socket
                .connect((config.server.as_str(), config.port))
                .expect("connect UDP client socket");
            socket
                .set_nonblocking(true)
                .expect("set client socket nonblocking");
            socket
        })
        .collect::<Vec<_>>();

    let mut stats = WorkerStats::default();
    let mut qid = (worker_id as u16).wrapping_mul(997);
    let mut next_name = worker_id;
    let mut next_socket = 0usize;
    let mut rng = XorShift64::new(worker_id as u64 + 0x9e3779b97f4a7c15);
    let mut sent_at: Vec<Option<PendingQuery>> = vec![None; 65536];
    let mut in_flight = 0usize;
    let mut receive_buffer = [0u8; 2048];

    while Instant::now() < deadline {
        while in_flight < config.window && Instant::now() < deadline {
            if pacer
                .as_mut()
                .is_some_and(|pacer| !pacer.ready(Instant::now()))
            {
                break;
            }
            if sent_at[qid as usize].is_some() {
                qid = qid.wrapping_add(1);
                continue;
            }
            let query = query_packet(qid, next_name, &config, &mut rng);
            let socket_index = next_socket % sockets.len();
            match sockets[socket_index].send(&query.bytes) {
                Ok(_) => {
                    sent_at[qid as usize] = Some(PendingQuery {
                        sent: Instant::now(),
                        expected_rcode: query.expected_rcode,
                        min_answers: query.min_answers,
                    });
                    stats.sent += 1;
                    if let Some(pacer) = &mut pacer {
                        pacer.sent();
                    }
                    in_flight += 1;
                    qid = qid.wrapping_add(1);
                    next_name += config.threads;
                    next_socket = next_socket.wrapping_add(1);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    stats.errors += 1;
                    break;
                }
            }
        }

        let mut received_any = false;
        for socket in &sockets {
            received_any |= drain_udp_socket(
                socket,
                &mut receive_buffer,
                &mut sent_at,
                &mut in_flight,
                &mut stats,
            );
        }

        expire_old(&mut sent_at, &mut in_flight, config.timeout);
        if !received_any {
            thread::yield_now();
        }
    }

    let drain_until = Instant::now() + Duration::from_millis(500);
    while in_flight > 0 && Instant::now() < drain_until {
        let mut received_any = false;
        for socket in &sockets {
            received_any |= drain_udp_socket(
                socket,
                &mut receive_buffer,
                &mut sent_at,
                &mut in_flight,
                &mut stats,
            );
        }
        if !received_any {
            thread::yield_now();
        }
        expire_old(&mut sent_at, &mut in_flight, config.timeout);
    }

    stats
}

fn drain_udp_socket(
    socket: &UdpSocket,
    receive_buffer: &mut [u8; 2048],
    sent_at: &mut [Option<PendingQuery>],
    in_flight: &mut usize,
    stats: &mut WorkerStats,
) -> bool {
    let mut received_any = false;
    loop {
        match socket.recv(receive_buffer) {
            Ok(len) => {
                received_any = true;
                if len < 12 {
                    stats.errors += 1;
                    continue;
                }
                handle_response(&receive_buffer[..len], sent_at, in_flight, stats);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                stats.errors += 1;
                break;
            }
        }
    }
    received_any
}

fn run_tcp_worker(
    worker_id: usize,
    config: Config,
    deadline: Instant,
    mut pacer: Option<Pacer>,
) -> WorkerStats {
    let mut stream =
        TcpStream::connect((config.server.as_str(), config.port)).expect("connect TCP client");
    stream.set_nodelay(true).expect("set TCP_NODELAY");
    stream
        .set_nonblocking(true)
        .expect("set TCP client stream nonblocking");

    let mut stats = WorkerStats::default();
    let mut qid = (worker_id as u16).wrapping_mul(997);
    let mut next_name = worker_id;
    let mut rng = XorShift64::new(worker_id as u64 + 0xd1b54a32d192ed03);
    let mut sent_at: Vec<Option<PendingQuery>> = vec![None; 65536];
    let mut in_flight = 0usize;
    let mut write_queue = VecDeque::new();
    let mut read_buffer = Vec::new();
    let mut scratch = [0u8; 8192];

    while Instant::now() < deadline {
        while in_flight < config.window && Instant::now() < deadline {
            if pacer
                .as_mut()
                .is_some_and(|pacer| !pacer.ready(Instant::now()))
            {
                break;
            }
            if sent_at[qid as usize].is_some() {
                qid = qid.wrapping_add(1);
                continue;
            }
            let query = query_packet(qid, next_name, &config, &mut rng);
            let length = u16::try_from(query.bytes.len()).expect("query fits DNS-over-TCP frame");
            write_queue.extend(length.to_be_bytes());
            write_queue.extend(query.bytes);
            sent_at[qid as usize] = Some(PendingQuery {
                sent: Instant::now(),
                expected_rcode: query.expected_rcode,
                min_answers: query.min_answers,
            });
            stats.sent += 1;
            if let Some(pacer) = &mut pacer {
                pacer.sent();
            }
            in_flight += 1;
            qid = qid.wrapping_add(1);
            next_name += config.threads;
        }

        let wrote = flush_tcp_writes(&mut stream, &mut write_queue, &mut stats);
        let received = read_tcp_responses(
            &mut stream,
            &mut read_buffer,
            &mut scratch,
            &mut sent_at,
            &mut in_flight,
            &mut stats,
        );
        expire_old(&mut sent_at, &mut in_flight, config.timeout);
        if !wrote && !received {
            thread::yield_now();
        }
    }

    let drain_until = Instant::now() + Duration::from_millis(500);
    while in_flight > 0 && Instant::now() < drain_until {
        let wrote = flush_tcp_writes(&mut stream, &mut write_queue, &mut stats);
        let received = read_tcp_responses(
            &mut stream,
            &mut read_buffer,
            &mut scratch,
            &mut sent_at,
            &mut in_flight,
            &mut stats,
        );
        expire_old(&mut sent_at, &mut in_flight, config.timeout);
        if !wrote && !received {
            thread::yield_now();
        }
    }

    stats
}

fn flush_tcp_writes(
    stream: &mut TcpStream,
    write_queue: &mut VecDeque<u8>,
    stats: &mut WorkerStats,
) -> bool {
    let mut wrote_any = false;
    while !write_queue.is_empty() {
        let (front, _) = write_queue.as_slices();
        match stream.write(front) {
            Ok(0) => break,
            Ok(count) => {
                wrote_any = true;
                for _ in 0..count {
                    write_queue.pop_front();
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                stats.errors += 1;
                break;
            }
        }
    }
    wrote_any
}

fn read_tcp_responses(
    stream: &mut TcpStream,
    read_buffer: &mut Vec<u8>,
    scratch: &mut [u8; 8192],
    sent_at: &mut [Option<PendingQuery>],
    in_flight: &mut usize,
    stats: &mut WorkerStats,
) -> bool {
    let mut received_any = false;
    loop {
        match stream.read(scratch) {
            Ok(0) => break,
            Ok(count) => {
                received_any = true;
                read_buffer.extend_from_slice(&scratch[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                stats.errors += 1;
                break;
            }
        }
    }

    let mut offset = 0usize;
    while read_buffer.len().saturating_sub(offset) >= 2 {
        let length = u16::from_be_bytes([read_buffer[offset], read_buffer[offset + 1]]) as usize;
        if read_buffer.len().saturating_sub(offset) < 2 + length {
            break;
        }
        handle_response(
            &read_buffer[offset + 2..offset + 2 + length],
            sent_at,
            in_flight,
            stats,
        );
        offset += 2 + length;
    }
    if offset > 0 {
        read_buffer.drain(..offset);
    }

    received_any
}

fn handle_response(
    packet: &[u8],
    sent_at: &mut [Option<PendingQuery>],
    in_flight: &mut usize,
    stats: &mut WorkerStats,
) {
    if packet.len() < 12 {
        stats.errors += 1;
        return;
    }
    let response_qid = u16::from_be_bytes([packet[0], packet[1]]);
    if let Some(pending) = sent_at[response_qid as usize].take() {
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let rcode = (flags & 0x000f) as u8;
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        if rcode != pending.expected_rcode || ancount < pending.min_answers {
            stats.errors += 1;
        }
        *in_flight = in_flight.saturating_sub(1);
        stats.received += 1;
        stats
            .latencies_ns
            .push(pending.sent.elapsed().as_nanos() as u64);
    } else {
        stats.errors += 1;
    }
}

fn expire_old(sent_at: &mut [Option<PendingQuery>], in_flight: &mut usize, timeout: Duration) {
    let now = Instant::now();
    for slot in sent_at.iter_mut().filter(|slot| {
        slot.as_ref()
            .is_some_and(|pending| now.duration_since(pending.sent) > timeout)
    }) {
        *slot = None;
        *in_flight = in_flight.saturating_sub(1);
    }
}

struct QueryPacket {
    bytes: Vec<u8>,
    expected_rcode: u8,
    min_answers: u16,
}

fn query_packet(qid: u16, sequence: usize, config: &Config, rng: &mut XorShift64) -> QueryPacket {
    let query = trace_or_generated_query(sequence, config, rng);
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&qid.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    let arcount_offset = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&name_wire(&query.qname));
    packet.extend_from_slice(&query.qtype.to_be_bytes());
    packet.extend_from_slice(&query.qclass.to_be_bytes());
    if !matches!(query.edns, EdnsMode::None) {
        packet[arcount_offset..arcount_offset + 2].copy_from_slice(&1u16.to_be_bytes());
        packet.push(0);
        packet.extend_from_slice(&41u16.to_be_bytes());
        packet.extend_from_slice(&1232u16.to_be_bytes());
        packet.push(0);
        packet.push(0);
        let flags = match query.edns {
            EdnsMode::None | EdnsMode::Edns => 0u16,
            EdnsMode::Do => 0x8000u16,
        };
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
    }
    QueryPacket {
        bytes: packet,
        expected_rcode: query.expected_rcode,
        min_answers: query.min_answers,
    }
}

struct PacketQuery<'a> {
    qname: Cow<'a, str>,
    qtype: u16,
    qclass: u16,
    edns: EdnsMode,
    expected_rcode: u8,
    min_answers: u16,
}

fn trace_or_generated_query<'a>(
    sequence: usize,
    config: &'a Config,
    rng: &mut XorShift64,
) -> PacketQuery<'a> {
    if let Some(trace_queries) = &config.trace_queries {
        let index = if config.randomize {
            rng.next_usize(trace_queries.len())
        } else {
            sequence % trace_queries.len()
        };
        let query = &trace_queries[index];
        return PacketQuery {
            qname: Cow::Borrowed(&query.qname),
            qtype: query.qtype,
            qclass: query.qclass,
            edns: query.edns,
            expected_rcode: query.expected_rcode,
            min_answers: query.min_answers,
        };
    }

    PacketQuery {
        qname: Cow::Owned(query_name(sequence, config, rng)),
        qtype: 1,
        qclass: 1,
        edns: EdnsMode::None,
        expected_rcode: 0,
        min_answers: 1,
    }
}

fn query_name(sequence: usize, config: &Config, rng: &mut XorShift64) -> String {
    if config.zones == 1 {
        let name_index = if config.randomize {
            rng.next_usize(config.names)
        } else {
            sequence % config.names
        };
        return format!("host{name_index:06}.perf.test.");
    }

    let zone_index = if config.randomize {
        rng.next_usize(config.zones)
    } else {
        (sequence / config.big_names.max(config.small_names)) % config.zones
    };
    let names_in_zone = if zone_index < config.big_zones {
        config.big_names
    } else {
        config.small_names
    };
    let name_index = if config.randomize {
        rng.next_usize(names_in_zone)
    } else {
        sequence % names_in_zone
    };
    format!("host{name_index:08}.zone{zone_index:05}.perf.test.")
}

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        (self.next() as usize) % upper
    }
}

fn latency_us(latencies: &[u64], percentile: f64) -> f64 {
    if latencies.is_empty() {
        return 0.0;
    }
    let index = if percentile >= 1.0 {
        latencies.len() - 1
    } else {
        ((latencies.len() - 1) as f64 * percentile).round() as usize
    };
    latencies[index] as f64 / 1000.0
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config {
        transport: Transport::Udp,
        server: "127.0.0.1".to_owned(),
        port: 5300,
        bind: "127.0.0.1:0".to_owned(),
        threads: 8,
        udp_sockets_per_thread: 1,
        duration: Duration::from_secs(10),
        window: 64,
        names: 10_000,
        zones: 1,
        big_zones: 1,
        big_names: 10_000,
        small_names: 10_000,
        timeout: Duration::from_millis(250),
        target_qps: None,
        randomize: false,
        trace_queries: None,
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("missing value for argument {arg}"))
        };
        match arg.as_str() {
            "--transport" => {
                config.transport = match value()?.as_str() {
                    "udp" => Transport::Udp,
                    "tcp" => Transport::Tcp,
                    value => return Err(format!("invalid value for --transport: {value}")),
                };
            }
            "--server" => config.server = value()?,
            "--port" => config.port = parse_value("--port", &value()?)?,
            "--bind" => config.bind = value()?,
            "--threads" => config.threads = parse_value("--threads", &value()?)?,
            "--udp-sockets-per-thread" => {
                config.udp_sockets_per_thread = parse_value("--udp-sockets-per-thread", &value()?)?;
            }
            "--duration" => {
                let seconds: u64 = parse_value("--duration", &value()?)?;
                config.duration = Duration::from_secs(seconds);
            }
            "--window" => config.window = parse_value("--window", &value()?)?,
            "--names" => config.names = parse_value("--names", &value()?)?,
            "--zones" => config.zones = parse_value("--zones", &value()?)?,
            "--big-zones" => config.big_zones = parse_value("--big-zones", &value()?)?,
            "--big-names" => config.big_names = parse_value("--big-names", &value()?)?,
            "--small-names" => config.small_names = parse_value("--small-names", &value()?)?,
            "--timeout-ms" => {
                let timeout_ms: u64 = parse_value("--timeout-ms", &value()?)?;
                config.timeout = Duration::from_millis(timeout_ms);
            }
            "--target-qps" => {
                let target_qps: u64 = parse_value("--target-qps", &value()?)?;
                if target_qps == 0 {
                    return Err("--target-qps must be greater than zero".to_owned());
                }
                config.target_qps = Some(target_qps);
            }
            "--random" => config.randomize = true,
            "--trace" => config.trace_queries = Some(Arc::new(load_trace(&value()?)?)),
            "--help" | "-h" => {
                usage();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if config.threads == 0 {
        return Err("--threads must be greater than zero".to_owned());
    }
    if config.window == 0 {
        return Err("--window must be greater than zero".to_owned());
    }
    if config.udp_sockets_per_thread == 0 || config.udp_sockets_per_thread > 1024 {
        return Err("--udp-sockets-per-thread must be between 1 and 1024".to_owned());
    }
    if config.names == 0 || config.names > 100_000_000 {
        return Err("--names must be between 1 and 100000000".to_owned());
    }
    if config.zones == 0 || config.zones > 100_000 {
        return Err("--zones must be between 1 and 100000".to_owned());
    }
    if config.big_zones > config.zones {
        return Err("--big-zones must be less than or equal to --zones".to_owned());
    }
    if config.big_names == 0 || config.small_names == 0 {
        return Err("--big-names and --small-names must be greater than zero".to_owned());
    }

    Ok(config)
}

fn load_trace(path: &str) -> Result<Vec<TraceQuery>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read --trace {path}: {error}"))?;
    let mut queries = Vec::new();
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(format!(
                "{path}:{line_number}: expected qname qtype qclass [options...]"
            ));
        }
        let qname = canonical_trace_name(fields[0])
            .ok_or_else(|| format!("{path}:{line_number}: invalid qname {}", fields[0]))?;
        let qtype = parse_rr_type(fields[1])
            .ok_or_else(|| format!("{path}:{line_number}: invalid qtype {}", fields[1]))?;
        let qclass = parse_rr_class(fields[2])
            .ok_or_else(|| format!("{path}:{line_number}: invalid qclass {}", fields[2]))?;
        let mut edns = EdnsMode::None;
        let mut expected_rcode = 0;
        let mut min_answers = 1;
        for field in &fields[3..] {
            if let Some(mode) = parse_edns_mode(field) {
                edns = mode;
                continue;
            }
            if let Some(value) = field.strip_prefix("rcode=") {
                expected_rcode = parse_rcode(value)
                    .ok_or_else(|| format!("{path}:{line_number}: invalid rcode {value}"))?;
                if expected_rcode != 0 && min_answers == 1 {
                    min_answers = 0;
                }
                continue;
            }
            if let Some(value) = field
                .strip_prefix("answers=")
                .or_else(|| field.strip_prefix("min_answers="))
            {
                min_answers = parse_value("answers", value)
                    .map_err(|_| format!("{path}:{line_number}: invalid answers {value}"))?;
                continue;
            }
            if field.contains('=') {
                return Err(format!(
                    "{path}:{line_number}: unsupported trace option {field}"
                ));
            }
        }
        queries.push(TraceQuery {
            qname,
            qtype,
            qclass,
            edns,
            expected_rcode,
            min_answers,
        });
    }
    if queries.is_empty() {
        return Err(format!("{path}: trace did not contain any query rows"));
    }
    Ok(queries)
}

fn canonical_trace_name(value: &str) -> Option<String> {
    let name = if value == "." {
        ".".to_owned()
    } else {
        format!("{}.", value.trim_end_matches('.'))
    };
    let wire_len = if name == "." {
        1
    } else {
        name.trim_end_matches('.')
            .split('.')
            .try_fold(1usize, |total, label| {
                if label.is_empty() || label.len() > 63 || !label.is_ascii() {
                    None
                } else {
                    Some(total + 1 + label.len())
                }
            })?
    };
    if wire_len <= 255 { Some(name) } else { None }
}

fn parse_rr_type(value: &str) -> Option<u16> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "NAPTR" => Some(35),
        "DNAME" => Some(39),
        "SVCB" => Some(64),
        "HTTPS" => Some(65),
        "AXFR" => Some(252),
        "ANY" => Some(255),
        _ => parse_numeric_code(value),
    }
}

fn parse_rr_class(value: &str) -> Option<u16> {
    match value.to_ascii_uppercase().as_str() {
        "IN" => Some(1),
        "CH" => Some(3),
        "HS" => Some(4),
        "ANY" => Some(255),
        _ => parse_numeric_code(value),
    }
}

fn parse_numeric_code(value: &str) -> Option<u16> {
    value.parse::<u16>().ok()
}

fn parse_edns_mode(value: &str) -> Option<EdnsMode> {
    match value.to_ascii_lowercase().as_str() {
        "none" | "-" => Some(EdnsMode::None),
        "edns" => Some(EdnsMode::Edns),
        "do" | "dnssec" => Some(EdnsMode::Do),
        _ => None,
    }
}

fn parse_rcode(value: &str) -> Option<u8> {
    let rcode = match value.to_ascii_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        _ => return value.parse::<u8>().ok().filter(|rcode| *rcode <= 15),
    };
    Some(rcode)
}

fn parse_value<T: std::str::FromStr>(name: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for {name}: {value}"))
}

fn usage() {
    eprintln!(concat!(
        "Usage: dns-load-client [OPTIONS]\n\n",
        "Options:\n",
        "  --transport <udp|tcp>  DNS transport, default udp\n",
        "  --server <IP>       DNS server IP, default 127.0.0.1\n",
        "  --port <PORT>       DNS server UDP port, default 5300\n",
        "  --bind <ADDR:PORT>  UDP client source bind address, default 127.0.0.1:0\n",
        "  --threads <N>       client worker threads, default 8\n",
        "  --udp-sockets-per-thread <N>  UDP source sockets per worker thread, default 1\n",
        "  --duration <SEC>    benchmark duration, default 10\n",
        "  --window <N>        outstanding queries per worker, default 64\n",
        "  --names <N>         host000000..hostNNNNNN names, default 10000\n",
        "  --zones <N>         zone count for zoneNNNNN.perf.test mode, default 1\n",
        "  --big-zones <N>     first N zones use --big-names, default 1\n",
        "  --big-names <N>     names in each big zone, default 10000\n",
        "  --small-names <N>   names in each small zone, default 10000\n",
        "  --timeout-ms <MS>   response timeout before a query is considered dropped, default 250\n",
        "  --target-qps <QPS>  pace total offered load across all workers; default unlimited\n",
        "  --random            choose queried zones and names with deterministic worker-local RNG\n",
        "  --trace <PATH>      replay qname qtype qclass [edns] [rcode=...] [answers=N] rows\n",
    ));
}
