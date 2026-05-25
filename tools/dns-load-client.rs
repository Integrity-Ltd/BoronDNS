use std::env;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Config {
    server: String,
    port: u16,
    threads: usize,
    duration: Duration,
    window: usize,
    names: usize,
    timeout: Duration,
}

#[derive(Default)]
struct WorkerStats {
    sent: u64,
    received: u64,
    errors: u64,
    latencies_ns: Vec<u64>,
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
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    for worker_id in 0..config.threads {
        let config = config.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let stats = run_worker(worker_id, config, deadline);
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

    println!(
        concat!(
            "dns_load_client_summary ",
            "duration_seconds={elapsed:.3} ",
            "server={server} port={port} ",
            "threads={threads} window={window} names={names} ",
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
        elapsed = elapsed,
        server = config.server,
        port = config.port,
        threads = config.threads,
        window = config.window,
        names = config.names,
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

fn run_worker(worker_id: usize, config: Config, deadline: Instant) -> WorkerStats {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client socket");
    socket
        .connect((config.server.as_str(), config.port))
        .expect("connect UDP client socket");
    socket
        .set_nonblocking(true)
        .expect("set client socket nonblocking");

    let mut stats = WorkerStats::default();
    let mut qid = (worker_id as u16).wrapping_mul(997);
    let mut next_name = worker_id;
    let mut sent_at: Vec<Option<Instant>> = vec![None; 65536];
    let mut in_flight = 0usize;
    let mut receive_buffer = [0u8; 2048];

    while Instant::now() < deadline {
        while in_flight < config.window && Instant::now() < deadline {
            if sent_at[qid as usize].is_some() {
                qid = qid.wrapping_add(1);
                continue;
            }
            let packet = query_packet(qid, next_name % config.names);
            match socket.send(&packet) {
                Ok(_) => {
                    sent_at[qid as usize] = Some(Instant::now());
                    stats.sent += 1;
                    in_flight += 1;
                    qid = qid.wrapping_add(1);
                    next_name += config.threads;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    stats.errors += 1;
                    break;
                }
            }
        }

        let mut received_any = false;
        loop {
            match socket.recv(&mut receive_buffer) {
                Ok(len) => {
                    received_any = true;
                    if len < 12 {
                        stats.errors += 1;
                        continue;
                    }
                    let response_qid = u16::from_be_bytes([receive_buffer[0], receive_buffer[1]]);
                    let flags = u16::from_be_bytes([receive_buffer[2], receive_buffer[3]]);
                    let ancount = u16::from_be_bytes([receive_buffer[6], receive_buffer[7]]);
                    if flags & 0x000f != 0 || ancount == 0 {
                        stats.errors += 1;
                    }
                    if let Some(sent) = sent_at[response_qid as usize].take() {
                        in_flight = in_flight.saturating_sub(1);
                        stats.received += 1;
                        stats.latencies_ns.push(sent.elapsed().as_nanos() as u64);
                    } else {
                        stats.errors += 1;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    stats.errors += 1;
                    break;
                }
            }
        }

        expire_old(&mut sent_at, &mut in_flight, config.timeout);
        if !received_any && in_flight >= config.window {
            thread::yield_now();
        }
    }

    let drain_until = Instant::now() + Duration::from_millis(500);
    while in_flight > 0 && Instant::now() < drain_until {
        match socket.recv(&mut receive_buffer) {
            Ok(len) if len >= 12 => {
                let response_qid = u16::from_be_bytes([receive_buffer[0], receive_buffer[1]]);
                if let Some(sent) = sent_at[response_qid as usize].take() {
                    in_flight = in_flight.saturating_sub(1);
                    stats.received += 1;
                    stats.latencies_ns.push(sent.elapsed().as_nanos() as u64);
                } else {
                    stats.errors += 1;
                }
            }
            Ok(_) => stats.errors += 1,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::yield_now(),
            Err(_) => {
                stats.errors += 1;
                break;
            }
        }
        expire_old(&mut sent_at, &mut in_flight, config.timeout);
    }

    stats
}

fn expire_old(sent_at: &mut [Option<Instant>], in_flight: &mut usize, timeout: Duration) {
    let now = Instant::now();
    for slot in sent_at.iter_mut().filter(|slot| {
        slot.as_ref()
            .is_some_and(|sent| now.duration_since(*sent) > timeout)
    }) {
        *slot = None;
        *in_flight = in_flight.saturating_sub(1);
    }
}

fn query_packet(qid: u16, name_index: usize) -> Vec<u8> {
    let qname = format!("host{name_index:06}.perf.test.");
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&qid.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&name_wire(&qname));
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
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
        server: "127.0.0.1".to_owned(),
        port: 5300,
        threads: 8,
        duration: Duration::from_secs(10),
        window: 64,
        names: 10_000,
        timeout: Duration::from_millis(250),
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("missing value for argument {arg}"))
        };
        match arg.as_str() {
            "--server" => config.server = value()?,
            "--port" => config.port = parse_value("--port", &value()?)?,
            "--threads" => config.threads = parse_value("--threads", &value()?)?,
            "--duration" => {
                let seconds: u64 = parse_value("--duration", &value()?)?;
                config.duration = Duration::from_secs(seconds);
            }
            "--window" => config.window = parse_value("--window", &value()?)?,
            "--names" => config.names = parse_value("--names", &value()?)?,
            "--timeout-ms" => {
                let timeout_ms: u64 = parse_value("--timeout-ms", &value()?)?;
                config.timeout = Duration::from_millis(timeout_ms);
            }
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
    if config.names == 0 || config.names > 1_000_000 {
        return Err("--names must be between 1 and 1000000".to_owned());
    }

    Ok(config)
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
        "  --server <IP>       DNS server IP, default 127.0.0.1\n",
        "  --port <PORT>       DNS server UDP port, default 5300\n",
        "  --threads <N>       client worker threads, default 8\n",
        "  --duration <SEC>    benchmark duration, default 10\n",
        "  --window <N>        outstanding UDP queries per worker, default 64\n",
        "  --names <N>         host000000..hostNNNNNN names, default 10000\n",
        "  --timeout-ms <MS>   response timeout before a query is considered dropped, default 250\n",
    ));
}
