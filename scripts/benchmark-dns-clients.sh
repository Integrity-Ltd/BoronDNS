#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_dir="${OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR:-$repo_root/target/evidence/dns-client-benchmark-$timestamp}"
workdir="$repo_root/target/dns-client-benchmark/$timestamp"
mkdir -p "$artifact_dir" "$workdir" "$repo_root/target/benchmark-tools"

records="${OXIDEDNS_BENCH_RECORDS:-10000}"
duration="${OXIDEDNS_BENCH_DURATION_SECONDS:-10}"
server_threads="${OXIDEDNS_BENCH_SERVER_THREADS:-4}"
client_threads="${OXIDEDNS_BENCH_CLIENT_THREADS:-8}"
client_window="${OXIDEDNS_BENCH_CLIENT_WINDOW:-64}"
response_timeout_ms="${OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:-250}"

require_positive_integer() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
    exit 64
  fi
}

for pair in \
  "OXIDEDNS_BENCH_RECORDS:$records" \
  "OXIDEDNS_BENCH_DURATION_SECONDS:$duration" \
  "OXIDEDNS_BENCH_SERVER_THREADS:$server_threads" \
  "OXIDEDNS_BENCH_CLIENT_THREADS:$client_threads" \
  "OXIDEDNS_BENCH_CLIENT_WINDOW:$client_window" \
  "OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:$response_timeout_ms"; do
  require_positive_integer "${pair%%:*}" "${pair#*:}"
done

cleanup() {
  local status=$?
  if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
    kill "$oxidedns_pid" 2>/dev/null || true
    wait "$oxidedns_pid" 2>/dev/null || true
  fi
  if [[ -n "${primary_pid:-}" ]] && kill -0 "$primary_pid" 2>/dev/null; then
    kill "$primary_pid" 2>/dev/null || true
    wait "$primary_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    [[ -f "$artifact_dir/fake-primary.log" ]] && { echo "---- fake-primary.log ----" >&2; tail -120 "$artifact_dir/fake-primary.log" >&2; }
    [[ -f "$artifact_dir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -120 "$artifact_dir/oxidedns.log" >&2; }
    [[ -f "$artifact_dir/client.log" ]] && { echo "---- client.log ----" >&2; tail -120 "$artifact_dir/client.log" >&2; }
  fi
}
trap cleanup EXIT

read -r primary_port dns_port health_port < <(
  python3 - <<'PY'
import socket

sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

fake_primary="$workdir/fake-primary.py"
config="$workdir/oxidedns.toml"
client_bin="$repo_root/target/benchmark-tools/dns-load-client"
primary_log="$artifact_dir/fake-primary.log"
server_log="$artifact_dir/oxidedns.log"
client_log="$artifact_dir/client.log"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
RECORDS = int(sys.argv[3])
ZONE = "perf.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252


def log(message):
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_name(packet, offset):
    labels = []
    consumed = 0
    while True:
        length = packet[offset]
        offset += 1
        consumed += 1
        if length == 0:
            return ".".join(labels) + ".", consumed
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
        consumed += length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass


def rr(owner, rrtype, rdata, ttl=60):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052501):
    return b"".join([
        name_wire("ns1.perf.test."),
        name_wire("hostmaster.perf.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    records = [
        soa,
        rr(ZONE, NS, name_wire("ns1.perf.test.")),
        rr("ns1.perf.test.", A, bytes([127, 0, 0, 1])),
    ]
    for index in range(RECORDS):
        records.append(
            rr(
                f"host{index:06d}.perf.test.",
                A,
                bytes([192, 0, (index // 256) % 256, index % 256]),
            )
        )
    records.append(soa)
    return records


def axfr_response_frames(qid):
    base_question = name_wire(ZONE) + struct.pack("!HH", AXFR, IN)
    base_size = 12 + len(base_question)
    frames = []
    chunk = []
    chunk_size = base_size
    for record in zone_records():
        if chunk and chunk_size + len(record) > 60000:
            frames.append(response_message(qid, base_question, chunk))
            chunk = []
            chunk_size = base_size
        chunk.append(record)
        chunk_size += len(record)
    if chunk:
        frames.append(response_message(qid, base_question, chunk))
    return frames


def response_message(qid, question, answers):
    return struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def handle_tcp(conn):
    with conn:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
        query = read_exact(conn, length)
        qid = struct.unpack("!H", query[:2])[0]
        qname, qtype, qclass = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 0, 0, 0, 0)
            conn.sendall(struct.pack("!H", len(response)) + response)
        else:
            log(f"TCP AXFR served records={RECORDS + 4}")
            for response in axfr_response_frames(qid):
                conn.sendall(struct.pack("!H", len(response)) + response)


def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()
    log(f"READY port={PORT} records={RECORDS}")
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY

cat >"$config" <<EOF
[server]
listen_udp = ["127.0.0.1:$dns_port"]
listen_tcp = ["127.0.0.1:$dns_port"]
health = "127.0.0.1:$health_port"
log_level = "error"
log_format = "plain"

[query]
any_response = "minimal"

[cookie]
policy = "disabled"

[rrl]
enabled = false

[limits]
max_udp_payload = 1232
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "perf.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

cat >"$artifact_dir/run.env" <<EOF
date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
records=$records
server_threads=$server_threads
client_threads=$client_threads
client_window=$client_window
duration_seconds=$duration
response_timeout_ms=$response_timeout_ms
primary_port=$primary_port
dns_port=$dns_port
health_port=$health_port
EOF

rustc --edition=2024 -O "$repo_root/tools/dns-load-client.rs" -o "$client_bin"
cargo build --locked --release -p oxidedns-cli >/dev/null

python3 "$fake_primary" "$primary_port" "$primary_log" "$records" &
primary_pid=$!
for _ in {1..100}; do
  if grep -q "READY" "$primary_log" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if ! grep -q "READY" "$primary_log" 2>/dev/null; then
  echo "benchmark fake primary did not become ready" >&2
  exit 1
fi

server_cmd=("$repo_root/target/release/oxidedns" serve --config "$config")
server_affinity="not-applied"
if command -v taskset >/dev/null 2>&1 && (( server_threads > 0 )); then
  last_cpu=$((server_threads - 1))
  server_cmd=(taskset -c "0-$last_cpu" "${server_cmd[@]}")
  server_affinity="0-$last_cpu"
fi
printf 'server_command=' >"$artifact_dir/server-command.txt"
printf ' %q' "${server_cmd[@]}" >>"$artifact_dir/server-command.txt"
printf '\n' >>"$artifact_dir/server-command.txt"
printf 'server_affinity=%s\n' "$server_affinity" >>"$artifact_dir/run.env"

"${server_cmd[@]}" >"$server_log" 2>&1 &
oxidedns_pid=$!
ready=0
for _ in {1..400}; do
  if curl -fsS "http://127.0.0.1:$health_port/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.05
done
if (( ready != 1 )); then
  echo "OxideDNS did not become ready for DNS client benchmark" >&2
  exit 1
fi

curl -fsS "http://127.0.0.1:$health_port/readyz" >"$artifact_dir/readyz-before.json"
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-before.prom"

"$client_bin" \
  --server 127.0.0.1 \
  --port "$dns_port" \
  --threads "$client_threads" \
  --duration "$duration" \
  --window "$client_window" \
  --names "$records" \
  --timeout-ms "$response_timeout_ms" | tee "$client_log"

curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-after.prom"
cp "$config" "$artifact_dir/oxidedns.toml"

summary="$(tail -1 "$client_log")"
summary_value() {
  local key="$1"
  tr ' ' '\n' <<<"$summary" | awk -F= -v key="$key" '$1 == key { print $2; exit }'
}

responses_per_second="$(summary_value responses_per_second)"
latency_us_p50="$(summary_value latency_us_p50)"
latency_us_p99="$(summary_value latency_us_p99)"
latency_us_p999="$(summary_value latency_us_p999)"
dropped="$(summary_value dropped)"
errors="$(summary_value errors)"
records_served="$(awk -F= '/TCP AXFR served records=/ { print $2; exit }' "$primary_log")"

cat >"$artifact_dir/benchmark-results.tsv" <<EOF
metric	value	unit
records_configured	$records	records
axfr_records_served	${records_served:-unknown}	records
server_threads	$server_threads	cpus
client_threads	$client_threads	threads
client_window	$client_window	queries_per_thread
duration_seconds	$duration	seconds
responses_per_second	$responses_per_second	qps
latency_us_p50	$latency_us_p50	microseconds
latency_us_p99	$latency_us_p99	microseconds
latency_us_p999	$latency_us_p999	microseconds
dropped	$dropped	responses
errors	$errors	responses
EOF

cat >"$artifact_dir/README.md" <<EOF
# OxideDNS DNS Client Benchmark

This artifact was generated by \`scripts/benchmark-dns-clients.sh\`.

The run starts a synthetic TCP AXFR primary, loads \`$records\` A records into
OxideDNS, pins OxideDNS to CPU affinity \`$server_affinity\` when \`taskset\` is
available, then drives UDP direct-hit A queries with the checked-in
\`tools/dns-load-client.rs\` client.

This is a local engineering benchmark, not the full SRS Reference
Hardware/Profile acceptance campaign.
EOF

printf 'dns_client_benchmark_dir=%s\n' "$artifact_dir"
printf 'capability_summary server_threads=%s client_threads=%s records=%s responses_per_second=%s latency_us_p50=%s latency_us_p99=%s latency_us_p999=%s dropped=%s errors=%s\n' \
  "$server_threads" "$client_threads" "$records" "$responses_per_second" "$latency_us_p50" "$latency_us_p99" "$latency_us_p999" "$dropped" "$errors"
