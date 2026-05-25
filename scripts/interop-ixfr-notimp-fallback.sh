#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo dig curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping IXFR fallback interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/ixfr-notimp-fallback-$$"
artifact_dir="${OXIDEDNS_IXFR_FALLBACK_ARTIFACT_DIR:-}"
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
    [[ -f "$workdir/fake-primary.log" ]] && { echo "---- fake-primary.log ----" >&2; tail -100 "$workdir/fake-primary.log" >&2; }
    [[ -f "$workdir/fake-primary.stderr" ]] && { echo "---- fake-primary.stderr ----" >&2; tail -100 "$workdir/fake-primary.stderr" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -100 "$workdir/oxidedns.log" >&2; }
    [[ -f "$workdir/primary-soa.out" ]] && { echo "---- primary-soa.out ----" >&2; cat "$workdir/primary-soa.out" >&2; }
    [[ -f "$workdir/initial-a.out" ]] && { echo "---- initial-a.out ----" >&2; cat "$workdir/initial-a.out" >&2; }
    [[ -f "$workdir/final-soa.out" ]] && { echo "---- final-soa.out ----" >&2; cat "$workdir/final-soa.out" >&2; }
    [[ -f "$workdir/final-a.out" ]] && { echo "---- final-a.out ----" >&2; cat "$workdir/final-a.out" >&2; }
    [[ -f "$workdir/metrics.txt" ]] && { echo "---- metrics.txt ----" >&2; tail -100 "$workdir/metrics.txt" >&2; }
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
primary_log="$workdir/fake-primary.log"
oxidedns_conf="$workdir/oxidedns.toml"
summary_env="$workdir/ixfr-fallback-summary.env"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "alpha.test."
IN = 1
SOA = 6
NS = 2
A = 1
AXFR = 252
IXFR = 251
NOTIMP = 4

lock = threading.Lock()
axfr_count = 0
ixfr_count = 0


def log(message):
    with lock:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            print(message, file=handle, flush=True)


def name_wire(name):
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_name(packet, offset):
    labels = []
    jumped = False
    consumed = 0
    seen = set()
    while True:
        if offset >= len(packet):
            raise ValueError("name outside packet")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("compression loop")
            seen.add(pointer)
            if not jumped:
                consumed += 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                consumed += 1
            return ".".join(labels) + ".", consumed
        offset += 1
        label = packet[offset:offset + length].decode("ascii")
        labels.append(label)
        offset += length
        if not jumped:
            consumed += 1 + length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass, packet[12:offset + 4]


def soa_rdata(serial):
    return b"".join([
        name_wire("ns1.alpha.test."),
        name_wire("hostmaster.alpha.test."),
        struct.pack("!IIIII", serial, 1, 1, 30, 5),
    ])


def rr(owner, rrtype, rdata, ttl=1):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def zone_records(serial):
    soa = rr(ZONE, SOA, soa_rdata(serial))
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10 + serial])),
        soa,
    ]


def response_header(qid, flags, qdcount, ancount, nscount=0, arcount=0):
    return struct.pack("!HHHHHH", qid, flags, qdcount, ancount, nscount, arcount)


def soa_response(query):
    qid = struct.unpack("!H", query[:2])[0]
    _, _, _, question = parse_question(query)
    with lock:
        serial = min(axfr_count + 1, 3) if axfr_count else 1
    answer = rr(ZONE, SOA, soa_rdata(serial))
    log(f"UDP SOA serial={serial}")
    return response_header(qid, 0x8400, 1, 1) + question + answer


def axfr_response(qid, serial, question):
    records = zone_records(serial)
    return response_header(qid, 0x8400, 1, len(records)) + question + b"".join(records)


def error_response(qid, rcode, question=b""):
    qdcount = 1 if question else 0
    return response_header(qid, 0x8000 | (rcode & 0x0F), qdcount, 0) + question


def handle_udp(sock):
    while True:
        packet, peer = sock.recvfrom(2048)
        try:
            _, qtype, _, _ = parse_question(packet)
            if qtype == SOA:
                sock.sendto(soa_response(packet), peer)
            else:
                qid = struct.unpack("!H", packet[:2])[0]
                sock.sendto(error_response(qid, NOTIMP), peer)
        except Exception as exc:
            log(f"UDP error={exc}")


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def handle_tcp(conn):
    global axfr_count, ixfr_count
    with conn:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
        query = read_exact(conn, length)
        qid = struct.unpack("!H", query[:2])[0]
        qname, qtype, _, question = parse_question(query)
        if qname.lower() != ZONE:
            response = error_response(qid, NOTIMP, question)
        elif qtype == AXFR:
            with lock:
                axfr_count += 1
                serial = min(axfr_count, 3)
            log(f"TCP AXFR serial={serial}")
            response = axfr_response(qid, serial, question)
        elif qtype == IXFR:
            with lock:
                ixfr_count += 1
                ixfr = ixfr_count
            log(f"TCP IXFR notimp count={ixfr}")
            response = error_response(qid, NOTIMP, question)
        else:
            log(f"TCP qtype={qtype} notimp")
            response = error_response(qid, NOTIMP, question)
        conn.sendall(struct.pack("!H", len(response)) + response)


def handle_tcp_listener(sock):
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


def main():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((HOST, PORT))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()

    threading.Thread(target=handle_udp, args=(udp,), daemon=True).start()
    threading.Thread(target=handle_tcp_listener, args=(tcp,), daemon=True).start()
    log(f"READY port={PORT}")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

[rrl]
enabled = false

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
ixfr_disabled_cooldown_secs = 60
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
notify_sources = ["127.0.0.1"]
EOF

python3 "$fake_primary" "$primary_port" "$primary_log" >"$workdir/fake-primary.stderr" 2>&1 &
primary_pid=$!

for _ in {1..50}; do
  if [[ -f "$primary_log" ]] && grep -F "READY" "$primary_log" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

dig "@127.0.0.1" -p "$primary_port" alpha.test. SOA +time=1 +tries=1 +short \
  >"$workdir/primary-soa.out"
primary_soa="$(<"$workdir/primary-soa.out")"
if [[ "$primary_soa" != *" 1 1 1 30 5"* ]]; then
  echo "fake primary did not answer initial SOA serial 1" >&2
  exit 1
fi

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=""
for _ in {1..100}; do
  if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
    [[ "$ready" == *'"status":"ready"'* ]] && break
  fi
  sleep 0.1
done

if [[ "$ready" != *'"status":"ready"'* ]]; then
  echo "OxideDNS did not become ready after initial fake-primary AXFR" >&2
  exit 1
fi

dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer \
  >"$workdir/initial-a.out"
initial_a="$(<"$workdir/initial-a.out")"
if [[ "$initial_a" != *"192.0.2.11"* ]]; then
  echo "OxideDNS did not serve initial AXFR data" >&2
  exit 1
fi

final_soa=""
metrics=""
for _ in {1..160}; do
  final_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short || true)"
  metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics" 2>/dev/null || true)"
  if [[ "$final_soa" == *" 3 1 1 30 5"* ]] \
    && [[ "$metrics" == *'oxidedns_transfer_sessions_started_total{protocol="axfr"} 3'* ]] \
    && [[ "$metrics" == *'oxidedns_transfer_sessions_completed_total{protocol="axfr"} 3'* ]] \
    && [[ "$metrics" == *'oxidedns_transfer_sessions_started_total{protocol="ixfr"} 1'* ]] \
    && [[ "$metrics" == *'oxidedns_transfer_sessions_completed_total{protocol="ixfr"} 0'* ]] \
    && [[ "$metrics" == *'oxidedns_transfer_sessions_failed_total{protocol="ixfr"} 1'* ]] \
    && grep -F "TCP AXFR serial=3" "$primary_log" >/dev/null 2>&1; then
      break
  fi
  sleep 0.25
done
printf '%s\n' "$final_soa" >"$workdir/final-soa.out"
printf '%s\n' "$metrics" >"$workdir/metrics.txt"

if [[ "$final_soa" != *" 3 1 1 30 5"* ]]; then
  echo "OxideDNS did not publish serial 3 after IXFR NOTIMP fallback/cooldown" >&2
  exit 1
fi

dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer \
  >"$workdir/final-a.out"
final_a="$(<"$workdir/final-a.out")"
if [[ "$final_a" != *"192.0.2.13"* ]]; then
  echo "OxideDNS did not serve final fallback AXFR data" >&2
  exit 1
fi

ixfr_count="$(grep -c "TCP IXFR" "$primary_log" || true)"
if [[ "$ixfr_count" != "1" ]]; then
  echo "expected exactly one IXFR attempt before cooldown, saw $ixfr_count" >&2
  exit 1
fi

for expected in \
  'TCP AXFR serial=1' \
  'TCP AXFR serial=2' \
  'TCP AXFR serial=3' \
  'TCP IXFR notimp count=1'; do
  if ! grep -F "$expected" "$primary_log" >/dev/null 2>&1; then
    echo "fake primary log missing expected event: $expected" >&2
    exit 1
  fi
done

for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_zone_soa_serial{zone="alpha.test."} 3' \
  'oxidedns_transfer_sessions_started_total{protocol="axfr"} 3' \
  'oxidedns_transfer_sessions_completed_total{protocol="axfr"} 3' \
  'oxidedns_transfer_sessions_started_total{protocol="ixfr"} 1' \
  'oxidedns_transfer_sessions_completed_total{protocol="ixfr"} 0' \
  'oxidedns_transfer_sessions_failed_total{protocol="ixfr"} 1'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected line: $expected" >&2
    exit 1
  fi
done

cat >"$summary_env" <<EOF
initial_soa_serial=1
final_soa_serial=3
initial_a=192.0.2.11
final_a=192.0.2.13
axfr_started=3
axfr_completed=3
ixfr_started=1
ixfr_failed=1
ixfr_completed=0
ixfr_notimp_cooldown_observed=1
ixfr_attempts_before_cooldown=$ixfr_count
EOF

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
  cp "$fake_primary" "$artifact_dir/fake-primary.py"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cp "$workdir/primary-soa.out" "$artifact_dir/primary-soa.out"
  cp "$workdir/initial-a.out" "$artifact_dir/initial-a.out"
  cp "$workdir/final-soa.out" "$artifact_dir/final-soa.out"
  cp "$workdir/final-a.out" "$artifact_dir/final-a.out"
  cp "$workdir/metrics.txt" "$artifact_dir/metrics.txt"
  cp "$summary_env" "$artifact_dir/ixfr-fallback-summary.env"
fi

echo "IXFR NOTIMP fallback interop passed"
