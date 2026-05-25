#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping TCP truncation retry interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/tcp-truncation-retry-$$"
artifact_dir="${OXIDEDNS_TCP_TRUNCATION_ARTIFACT_DIR:-}"
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
    [[ -f "$workdir/client.log" ]] && { echo "---- client.log ----" >&2; tail -120 "$workdir/client.log" >&2; }
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
client="$workdir/client.py"
primary_log="$workdir/fake-primary.log"
client_log="$workdir/client.log"
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
ZONE = "tcp.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252
LARGE_RRSET = 96


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
        name_wire("ns1.tcp.test."),
        name_wire("hostmaster.tcp.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    records = [
        soa,
        rr(ZONE, NS, name_wire("ns1.tcp.test.")),
        rr("ns1.tcp.test.", A, bytes([127, 0, 0, 1])),
    ]
    for index in range(LARGE_RRSET):
        records.append(rr("large.tcp.test.", A, bytes([192, 0, 2, index + 1])))
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
            log(f"TCP AXFR served records={len(zone_records())}")
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

cat >"$client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
QNAME = "large.tcp.test."
A = 1
IN = 1


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


def query(qid):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(QNAME)
        + struct.pack("!HH", A, IN)
    )


def skip_name(packet, offset):
    consumed = 0
    jumped = False
    seen = set()
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise AssertionError("compression loop")
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
        offset += skip_name(packet, offset) + 4
    count = 0
    for _ in range(ancount):
        offset += skip_name(packet, offset)
        rrtype, _, _, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if rrtype == A and rdlength == 4:
            count += 1
        offset += rdlength
    return count


udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(2.0)
udp.sendto(query(0x6001), (HOST, PORT))
udp_response, _ = udp.recvfrom(4096)
udp_flags = struct.unpack("!H", udp_response[2:4])[0]
if udp_flags & 0x000F:
    raise AssertionError(f"UDP response rcode={udp_flags & 0x000F}")
if not (udp_flags & 0x0200):
    raise AssertionError(f"UDP response was not truncated length={len(udp_response)}")

tcp = socket.create_connection((HOST, PORT), timeout=2.0)
tcp_query = query(0x6002)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
length = struct.unpack("!H", tcp.recv(2))[0]
chunks = bytearray()
while len(chunks) < length:
    chunk = tcp.recv(length - len(chunks))
    if not chunk:
        raise AssertionError("short TCP response")
    chunks.extend(chunk)
tcp_response = bytes(chunks)
tcp_flags = struct.unpack("!H", tcp_response[2:4])[0]
if tcp_flags & 0x0200:
    raise AssertionError("TCP response unexpectedly had TC=1")
tcp_answers = answer_count(tcp_response)
if tcp_answers < 80:
    raise AssertionError(f"TCP response returned too few A answers: {tcp_answers}")

summary = (
    f"udp_truncated=1 udp_response_bytes={len(udp_response)} "
    f"tcp_truncated=0 tcp_response_bytes={len(tcp_response)} tcp_a_answers={tcp_answers}"
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

[rrl]
enabled = false

[limits]
max_udp_payload = 512
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "tcp.test."
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
  echo "fake TCP truncation primary did not become ready" >&2
  exit 1
fi

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
  echo "OxideDNS did not become ready during TCP truncation retry interop" >&2
  exit 1
fi

client_summary="$(python3 "$client" "$oxidedns_dns_port" "$client_log")"
metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_secondary_queries_total{zone="tcp.test."} 2' \
  'oxidedns_secondary_query_responses_total{zone="tcp.test.",rcode="NOERROR"} 2' \
  'oxidedns_queries_truncated_total 1'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected TCP truncation retry line: $expected" >&2
    exit 1
  fi
done

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$client_log" "$artifact_dir/client.log"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  printf '%s\n' "$client_summary" >"$artifact_dir/client-summary.env"
  printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
fi

printf '%s\n' "$client_summary"
