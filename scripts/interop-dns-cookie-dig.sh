#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl dig; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping DNS Cookie dig interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/dns-cookie-dig-$$"
artifact_dir="${OXIDEDNS_DNS_COOKIE_ARTIFACT_DIR:-}"
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
    [[ -f "$workdir/first-dig.out" ]] && { echo "---- first-dig.out ----" >&2; cat "$workdir/first-dig.out" >&2; }
    [[ -f "$workdir/second-dig.out" ]] && { echo "---- second-dig.out ----" >&2; cat "$workdir/second-dig.out" >&2; }
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
summary_env="$workdir/dns-cookie-summary.env"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "alpha.test."
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
        label = packet[offset:offset + length].decode("ascii")
        labels.append(label)
        offset += length
        consumed += length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass


def rr(owner, rrtype, rdata, ttl=300):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata():
    return b"".join([
        name_wire("ns1.alpha.test."),
        name_wire("hostmaster.alpha.test."),
        struct.pack("!IIIII", 2026052401, 60, 30, 300, 300),
    ])


def axfr_response(qid):
    soa = rr(ZONE, SOA, soa_rdata())
    answers = [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10])),
        soa,
    ]
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
            log("TCP AXFR served")
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

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "debug"

[cookie]
policy = "lenient"

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

python3 "$fake_primary" "$primary_port" "$primary_log" >"$workdir/fake-primary.stderr" 2>&1 &
primary_pid=$!

for _ in {1..50}; do
  if grep -q READY "$primary_log" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

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
  echo "OxideDNS did not become ready after fake-primary AXFR" >&2
  exit 1
fi

client_cookie="0102030405060708"
dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A \
  +norecurse "+cookie=$client_cookie" +noall +comments +answer +time=1 +tries=1 \
  >"$workdir/first-dig.out"

if ! grep -q "www.alpha.test." "$workdir/first-dig.out" || ! grep -q "192.0.2.10" "$workdir/first-dig.out"; then
  echo "dig +cookie did not receive expected answer from OxideDNS" >&2
  exit 1
fi

response_cookie="$(awk '/COOKIE:/ {print $3; exit}' "$workdir/first-dig.out")"
if [[ ! "$response_cookie" =~ ^${client_cookie}[0-9a-fA-F]{32}$ ]]; then
  echo "OxideDNS response did not contain echoed client cookie plus RFC9018 server cookie" >&2
  exit 1
fi

dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A \
  +norecurse "+cookie=$response_cookie" +noall +comments +answer +time=1 +tries=1 \
  >"$workdir/second-dig.out"

if ! grep -q "www.alpha.test." "$workdir/second-dig.out" || ! grep -q "192.0.2.10" "$workdir/second-dig.out"; then
  echo "dig valid-server-cookie retry did not receive expected answer from OxideDNS" >&2
  exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_dns_cookie_queries_total{case="client_only"} 1' \
  'oxidedns_dns_cookie_queries_total{case="valid_server"} 1' \
  'oxidedns_dns_cookie_queries_by_prefix_total{source_prefix="127.0.0.0/24",case="client_only"} 1' \
  'oxidedns_dns_cookie_queries_by_prefix_total{source_prefix="127.0.0.0/24",case="valid_server"} 1'
do
  if [[ "$metrics" != *"$expected"* ]]; then
    printf 'missing expected metric: %s\n' "$expected" >&2
    exit 1
  fi
done

if ! grep -q "DNS Cookie server secret generated" "$workdir/oxidedns.log"; then
  echo "OxideDNS log did not record DNS Cookie startup fingerprint event" >&2
  exit 1
fi

cat >"$summary_env" <<EOF
client_cookie=$client_cookie
response_cookie_bytes=$((${#response_cookie} / 2))
client_only_cookie_response=1
valid_server_cookie_response=1
EOF

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cp "$workdir/first-dig.out" "$artifact_dir/first-dig.out"
  cp "$workdir/second-dig.out" "$artifact_dir/second-dig.out"
  cp "$summary_env" "$artifact_dir/dns-cookie-summary.env"
  printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
fi

printf 'DNS Cookie dig interop passed response_cookie_bytes=%s\n' "$((${#response_cookie} / 2))"
