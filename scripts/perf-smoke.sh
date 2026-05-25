#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping performance smoke: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/perf-smoke/$$"
metrics_out="${OXIDEDNS_PERF_SMOKE_METRICS_OUT:-}"
artifact_dir="${OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR:-}"
mkdir -p "$workdir"

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
    [[ -f "$workdir/fake-primary.log" ]] && { echo "---- fake-primary.log ----" >&2; tail -120 "$workdir/fake-primary.log" >&2; }
    [[ -f "$workdir/perf-client.log" ]] && { echo "---- perf-client.log ----" >&2; tail -120 "$workdir/perf-client.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -120 "$workdir/oxidedns.log" >&2; }
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

read -r primary_port oxidedns_dns_port oxidedns_health_port < <(
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
perf_client="$workdir/perf-client.py"
primary_log="$workdir/fake-primary.log"
client_log="$workdir/perf-client.log"
oxidedns_conf="$workdir/oxidedns.toml"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "perf.test."
RECORDS = 1000
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


def soa_rdata(serial=2026052401):
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
        records.append(rr(f"host{index:04d}.perf.test.", A, bytes([192, 0, (index // 256) % 256, index % 256])))
    records.append(soa)
    return records


def axfr_response(qid):
    answers = zone_records()
    question = name_wire(ZONE) + struct.pack("!HH", AXFR, IN)
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
        else:
            log(f"TCP AXFR served records={RECORDS + 4}")
            response = axfr_response(qid)
        conn.sendall(struct.pack("!H", len(response)) + response)


def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()
    log(f"READY port={PORT}")
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY

cat >"$perf_client" <<'PY'
#!/usr/bin/env python3
import socket
import statistics
import struct
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]
QUERIES = 300
A = 1


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


def query_packet(qid, qname):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", A, 1)
    )


def parse_name(packet, offset):
    consumed = 0
    jumped = False
    seen = set()
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("compression loop")
            seen.add(pointer)
            if not jumped:
                consumed += 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if not jumped:
            consumed += 1
        if length == 0:
            return consumed
        offset += length
        if not jumped:
            consumed += length


def answer_count(packet):
    flags, qdcount, ancount = struct.unpack("!HHH", packet[2:8])
    if flags & 0x000F:
        raise AssertionError(f"unexpected rcode={flags & 0x000F}")
    offset = 12
    for _ in range(qdcount):
        offset += parse_name(packet, offset) + 4
    if ancount != 1:
        raise AssertionError(f"expected one answer, got {ancount}")
    return ancount


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
latencies = []
start = time.perf_counter_ns()
for index in range(QUERIES):
    qid = 0x4000 + index
    packet = query_packet(qid, f"host{index % 1000:04d}.perf.test.")
    sent = time.perf_counter_ns()
    sock.sendto(packet, (HOST, PORT))
    response, _ = sock.recvfrom(2048)
    received = time.perf_counter_ns()
    rid = struct.unpack("!H", response[:2])[0]
    if rid != qid:
        raise AssertionError(f"mismatched qid got={rid} expected={qid}")
    answer_count(response)
    latencies.append((received - sent) / 1_000_000)
elapsed = (time.perf_counter_ns() - start) / 1_000_000_000
ordered = sorted(latencies)
p99 = ordered[int((len(ordered) - 1) * 0.99)]
qps = QUERIES / elapsed
summary = (
    f"udp_queries={QUERIES} qps={qps:.0f} "
    f"latency_ms_min={min(latencies):.3f} "
    f"latency_ms_median={statistics.median(latencies):.3f} "
    f"latency_ms_p99={p99:.3f} latency_ms_max={max(latencies):.3f}"
)
log(summary)
print(summary)
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "warn"
log_format = "plain"

[query]
any_response = "minimal"

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

cargo build -p oxidedns-cli >/dev/null

python3 "$fake_primary" "$primary_port" "$primary_log" &
primary_pid=$!

for _ in {1..100}; do
  if grep -q "READY" "$primary_log" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if ! grep -q "READY" "$primary_log" 2>/dev/null; then
  echo "fake performance primary did not become ready" >&2
  exit 1
fi

start_ns="$(python3 - <<'PY'
import time
print(time.perf_counter_ns())
PY
)"

"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=0
for _ in {1..200}; do
  if curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.05
done
if (( ready != 1 )); then
  echo "OxideDNS did not become ready during performance smoke" >&2
  exit 1
fi

ready_ns="$(python3 - <<'PY'
import time
print(time.perf_counter_ns())
PY
)"

startup_ready_ms="$(python3 - <<PY
print(f"{($ready_ns - $start_ns) / 1_000_000:.1f}")
PY
)"

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_zone_soa_serial{zone="perf.test."} 2026052401' \
  'oxidedns_transfer_sessions_completed_total{protocol="axfr"} 1'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected performance smoke line: $expected" >&2
    exit 1
  fi
done

client_summary="$(python3 "$perf_client" 127.0.0.1 "$oxidedns_dns_port" "$client_log")"
summary_metric() {
  local key="$1"
  tr ' ' '\n' <<<"$client_summary" | awk -F= -v key="$key" '$1 == key { print $2; exit }'
}

udp_queries="$(summary_metric udp_queries)"
udp_qps="$(summary_metric qps)"
latency_ms_min="$(summary_metric latency_ms_min)"
latency_ms_median="$(summary_metric latency_ms_median)"
latency_ms_p99="$(summary_metric latency_ms_p99)"
latency_ms_max="$(summary_metric latency_ms_max)"
records_served="$(awk -F= '/TCP AXFR served records=/ { print $2; exit }' "$primary_log")"
if [[ -z "$records_served" ]]; then
  echo "fake performance primary did not serve AXFR" >&2
  exit 1
fi

ingest_records_per_second="$(python3 - <<PY
startup_seconds = float("$startup_ready_ms") / 1000
records = int("$records_served")
print(f"{records / startup_seconds:.0f}" if startup_seconds > 0 else "inf")
PY
)"

metrics_after_client="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
if [[ "$metrics_after_client" != *'oxidedns_secondary_build_info{version="'* ]]; then
  echo "metrics missing oxidedns_secondary_build_info evidence" >&2
  exit 1
fi
if [[ "$metrics_after_client" != *'oxidedns_secondary_query_duration_seconds_bucket{query_category="udp_direct"'* ]]; then
  echo "metrics missing udp_direct query latency histogram buckets" >&2
  exit 1
fi
udp_direct_histogram_count="$(
  awk '$1 == "oxidedns_secondary_query_duration_seconds_count{query_category=\"udp_direct\"}" { print $2; exit }' \
    <<<"$metrics_after_client"
)"
if [[ -z "$udp_direct_histogram_count" || "$udp_direct_histogram_count" == "0" ]]; then
  echo "metrics missing non-zero udp_direct query latency histogram count" >&2
  exit 1
fi

if [[ -n "$metrics_out" ]]; then
  mkdir -p "$(dirname "$metrics_out")"
  cat >"$metrics_out" <<EOF
test_timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
profile=perf_smoke_local
zone=perf.test.
startup_ready_ms=$startup_ready_ms
axfr_records=$records_served
axfr_ready_records_per_second=$ingest_records_per_second
udp_queries=$udp_queries
udp_qps=$udp_qps
udp_latency_ms_min=$latency_ms_min
udp_latency_ms_median=$latency_ms_median
udp_latency_ms_p99=$latency_ms_p99
udp_latency_ms_max=$latency_ms_max
EOF
fi

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  printf '%s\n' "$metrics" >"$artifact_dir/metrics-before-client.prom"
  printf '%s\n' "$metrics_after_client" >"$artifact_dir/metrics-after-client.prom"
  curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" >"$artifact_dir/readyz.json"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$client_log" "$artifact_dir/perf-client.log"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cat >"$artifact_dir/metrics-evidence.env" <<EOF
build_info_present=true
latency_histogram_metric=oxidedns_secondary_query_duration_seconds
udp_direct_histogram_count=$udp_direct_histogram_count
metrics_before_client=metrics-before-client.prom
metrics_after_client=metrics-after-client.prom
readyz_artifact=readyz.json
EOF
fi

echo "Performance smoke passed: startup_ready_ms=$startup_ready_ms axfr_records=$records_served axfr_ready_records_per_second=$ingest_records_per_second $client_summary"
