#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl awk find; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping read-only runtime audit: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/readonly-runtime/$$"
artifact_dir="${OXIDEDNS_READONLY_RUNTIME_ARTIFACT_DIR:-}"
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
  chmod -R u+w "$workdir" 2>/dev/null || true
  if (( status != 0 )); then
    [[ -f "$workdir/fake-primary.log" ]] && { echo "---- fake-primary.log ----" >&2; tail -120 "$workdir/fake-primary.log" >&2; }
    [[ -f "$workdir/client.log" ]] && { echo "---- client.log ----" >&2; tail -120 "$workdir/client.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -120 "$workdir/oxidedns.log" >&2; }
    [[ -f "$workdir/strace.log" ]] && { echo "---- strace.log ----" >&2; tail -120 "$workdir/strace.log" >&2; }
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
client="$workdir/client.py"
primary_log="$workdir/fake-primary.log"
client_log="$workdir/client.log"
oxidedns_conf="$workdir/oxidedns.toml"
proc_status="$workdir/proc-status.txt"
readonly_tmp="$workdir/readonly-tmp"
mkdir "$readonly_tmp"
chmod 0555 "$readonly_tmp"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "readonly.test."
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


def soa_rdata(serial=2026052502):
    return b"".join([
        name_wire("ns1.readonly.test."),
        name_wire("hostmaster.readonly.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.readonly.test.")),
        rr("ns1.readonly.test.", A, bytes([127, 0, 0, 1])),
        rr("www.readonly.test.", A, bytes([192, 0, 2, 25])),
        soa,
    ]


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
            answers = zone_records()
            log(f"TCP AXFR served records={len(answers)}")
            response = struct.pack("!HHHHHH", qid, 0x8000, 0, len(answers), 0, 0) + b"".join(answers)
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

cat >"$client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]


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


query = (
    struct.pack("!HHHHHH", 0x7025, 0x0100, 1, 0, 0, 0)
    + name_wire("www.readonly.test.")
    + struct.pack("!HH", 1, 1)
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.sendto(query, ("127.0.0.1", PORT))
response, _ = sock.recvfrom(2048)
qid, flags, qdcount, ancount = struct.unpack("!HHHH", response[:8])
if qid != 0x7025:
    raise AssertionError(f"mismatched qid={qid}")
if flags & 0x000F:
    raise AssertionError(f"unexpected rcode={flags & 0x000F}")
if qdcount != 1 or ancount != 1:
    raise AssertionError(f"unexpected counts qd={qdcount} an={ancount}")
summary = f"udp_query_answered=1 response_bytes={len(response)}"
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

[rrl]
enabled = false

[limits]
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "readonly.test."
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
  echo "fake readonly primary did not become ready" >&2
  exit 1
fi

oxidedns_cmd=("$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf")
trace_status="not_available"
if command -v strace >/dev/null 2>&1; then
  trace_status="captured"
  TMPDIR="$readonly_tmp" strace -f -e trace=%file -o "$workdir/strace.log" "${oxidedns_cmd[@]}" >"$workdir/oxidedns.log" 2>&1 &
else
  TMPDIR="$readonly_tmp" "${oxidedns_cmd[@]}" >"$workdir/oxidedns.log" 2>&1 &
fi
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
  echo "OxideDNS did not become ready during read-only runtime audit" >&2
  exit 1
fi

if [[ ! -d "/proc/$oxidedns_pid/task" ]]; then
  echo "OxideDNS /proc task view is unavailable during read-only runtime audit" >&2
  exit 1
fi
thread_count="$(find "/proc/$oxidedns_pid/task" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

child_pids=()
if [[ -d /proc ]]; then
  while IFS= read -r status_file; do
    pid="$(awk '/^Pid:/ { print $2 }' "$status_file" 2>/dev/null || true)"
    ppid="$(awk '/^PPid:/ { print $2 }' "$status_file" 2>/dev/null || true)"
    if [[ -n "$pid" && "$ppid" == "$oxidedns_pid" ]]; then
      child_pids+=("$pid")
    fi
  done < <(find /proc -mindepth 2 -maxdepth 2 -path '/proc/[0-9]*/status' -print 2>/dev/null)
fi
child_process_count="${#child_pids[@]}"
{
  printf 'oxidedns_pid=%s\n' "$oxidedns_pid"
  printf 'thread_count=%s\n' "$thread_count"
  printf 'child_process_count=%s\n' "$child_process_count"
  for child_pid in "${child_pids[@]}"; do
    printf 'child_pid=%s\n' "$child_pid"
  done
} >"$proc_status"
if (( child_process_count > 0 )); then
  echo "OxideDNS spawned child processes during read-only runtime audit" >&2
  cat "$proc_status" >&2
  exit 1
fi

client_summary="$(python3 "$client" "$oxidedns_dns_port" "$client_log")"
metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_secondary_queries_total{zone="readonly.test."} 1' \
  'oxidedns_secondary_query_responses_total{zone="readonly.test.",rcode="NOERROR"} 1'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected read-only runtime line: $expected" >&2
    exit 1
  fi
done

write_intent_findings=0
if [[ "$trace_status" == "captured" ]]; then
  if grep -E 'open(at)?\(.*O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)|creat\(|mkdir|mkdirat|rename|renameat|unlink|unlinkat|rmdir' "$workdir/strace.log" >"$workdir/write-intent.log"; then
    write_intent_findings="$(wc -l <"$workdir/write-intent.log" | tr -d ' ')"
  fi
  if (( write_intent_findings > 0 )); then
    echo "runtime file write intent observed under strace" >&2
    cat "$workdir/write-intent.log" >&2
    exit 1
  fi
fi

summary="readonly_tmp=1 readyz=1 ${client_summary} child_processes=${child_process_count} thread_count=${thread_count} strace=${trace_status} write_intent_findings=${write_intent_findings}"
printf '%s\n' "$summary"

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$client_log" "$artifact_dir/client.log"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$proc_status" "$artifact_dir/proc-status.txt"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  printf '%s\n' "$summary" >"$artifact_dir/readonly-runtime-summary.env"
  printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
  if [[ -f "$workdir/strace.log" ]]; then
    cp "$workdir/strace.log" "$artifact_dir/strace.log"
  fi
  if [[ -f "$workdir/write-intent.log" ]]; then
    cp "$workdir/write-intent.log" "$artifact_dir/write-intent.log"
  fi
fi
