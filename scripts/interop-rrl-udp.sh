#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping RRL UDP runtime interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/rrl-udp-$$"
artifact_dir="${OXIDEDNS_RRL_UDP_ARTIFACT_DIR:-}"
rm -rf "$workdir"
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
    if ((status != 0)); then
        [[ -f "$workdir/fake-primary.log" ]] && {
            echo "---- fake-primary.log ----" >&2
            tail -100 "$workdir/fake-primary.log" >&2
        }
        [[ -f "$workdir/fake-primary.stderr" ]] && {
            echo "---- fake-primary.stderr ----" >&2
            tail -100 "$workdir/fake-primary.stderr" >&2
        }
        [[ -f "$workdir/rrl-client.log" ]] && {
            echo "---- rrl-client.log ----" >&2
            tail -100 "$workdir/rrl-client.log" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -100 "$workdir/oxidedns.log" >&2
        }
        [[ -f "$workdir/client-summary.env" ]] && {
            echo "---- client-summary.env ----" >&2
            cat "$workdir/client-summary.env" >&2
        }
        [[ -f "$workdir/metrics-summary.env" ]] && {
            echo "---- metrics-summary.env ----" >&2
            cat "$workdir/metrics-summary.env" >&2
        }
        [[ -f "$workdir/metrics.txt" ]] && {
            echo "---- metrics.txt ----" >&2
            tail -100 "$workdir/metrics.txt" >&2
        }
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
rrl_client="$workdir/rrl-client.py"
primary_log="$workdir/fake-primary.log"
oxidedns_conf="$workdir/oxidedns.toml"
metrics_summary="$workdir/metrics-summary.env"

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
    return qname, qtype, qclass, packet[12:offset + 4]


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


def axfr_response(qid, question):
    soa = rr(ZONE, SOA, soa_rdata())
    answers = [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10])),
        rr("child.alpha.test.", NS, name_wire("ns.child.alpha.test.")),
        rr("ns.child.alpha.test.", A, bytes([192, 0, 2, 53])),
        soa,
    ]
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
        qname, qtype, qclass, question = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 1, 0, 0, 0) + question
        else:
            log("TCP AXFR served")
            response = axfr_response(qid, question)
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

cat >"$rrl_client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]
ATTEMPTS_PER_CASE = 8
A = 1
AAAA = 28

CASES = [
    ("positive", "www.alpha.test.", A),
    ("nxdomain", "missing.alpha.test.", A),
    ("nodata", "alpha.test.", AAAA),
    ("referral", "www.child.alpha.test.", A),
    ("error", "outside.test.", A),
]


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


def query(qid, qname, qtype):
    return b"".join([
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0),
        name_wire(qname),
        struct.pack("!HH", qtype, 1),
    ])


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(0.04)

totals = {"attempts": 0, "responses": 0, "truncated": 0, "dropped": 0, "full": 0}
case_totals = {
    name: {"responses": 0, "truncated": 0, "dropped": 0, "full": 0}
    for name, _, _ in CASES
}

for case_index, (case_name, qname, qtype) in enumerate(CASES):
    for attempt_index in range(ATTEMPTS_PER_CASE):
        qid = 0xA000 + case_index * 0x100 + attempt_index
        totals["attempts"] += 1
        sock.sendto(query(qid, qname, qtype), (HOST, PORT))
        try:
            packet, _ = sock.recvfrom(4096)
        except socket.timeout:
            totals["dropped"] += 1
            case_totals[case_name]["dropped"] += 1
            log(f"case={case_name} query={attempt_index} result=timeout")
            continue

        totals["responses"] += 1
        case_totals[case_name]["responses"] += 1
        if len(packet) < 12:
            log(f"case={case_name} query={attempt_index} result=short bytes={len(packet)}")
            continue
        rid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
        if rid != qid:
            log(f"case={case_name} query={attempt_index} result=mismatched-qid got={rid}")
            continue
        tc = bool(flags & 0x0200)
        rcode = flags & 0x000f
        if tc:
            totals["truncated"] += 1
            case_totals[case_name]["truncated"] += 1
        else:
            totals["full"] += 1
            case_totals[case_name]["full"] += 1
        log(
            f"case={case_name} query={attempt_index} result=response tc={int(tc)} "
            f"rcode={rcode} qdcount={qdcount} ancount={ancount} "
            f"nscount={nscount} arcount={arcount}"
        )
        time.sleep(0.005)

summary = [
    f"{key}={value}"
    for key, value in totals.items()
]
for case_name in case_totals:
    summary.extend(
        f"{case_name}_{key}={value}"
        for key, value in case_totals[case_name].items()
    )
print(" ".join(summary))

for case_name, counts in case_totals.items():
    if counts["truncated"] < 3 or counts["dropped"] < 3:
        raise SystemExit(
            f"RRL did not limit {case_name} enough: "
            f"truncated={counts['truncated']} dropped={counts['dropped']}"
        )
    if counts["full"] != 0:
        raise SystemExit(f"RRL emitted unexpected full {case_name} responses")
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

[rrl]
enabled = true
ipv4_prefix_len = 32
positive_per_second = 0
nxdomain_per_second = 0
nodata_per_second = 0
referral_per_second = 0
error_per_second = 0
slip = 2
max_keys = 64
allowlist = []

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 60
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

client_summary="$(python3 "$rrl_client" 127.0.0.1 "$oxidedns_dns_port" "$workdir/rrl-client.log")"
echo "$client_summary"
printf '%s\n' "$client_summary" | tr ' ' '\n' >"$workdir/client-summary.env"

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$workdir/metrics.txt"
for expected in \
    'oxidedns_zones_active 1' \
    'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401' \
    'oxidedns_rrl_keys_tracked 5'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "metrics missing expected line: $expected" >&2
        exit 1
    fi
done

subject="$(awk '$1 == "oxidedns_rrl_responses_subject_total" { print int($2) }' <<<"$metrics")"
dropped="$(awk '$1 == "oxidedns_rrl_responses_dropped_total" { print int($2) }' <<<"$metrics")"
truncated="$(awk '$1 == "oxidedns_rrl_responses_truncated_total" { print int($2) }' <<<"$metrics")"
queries_truncated="$(awk '$1 == "oxidedns_queries_truncated_total" { print int($2) }' <<<"$metrics")"

if ((subject < 40 || dropped < 15 || truncated < 15 || queries_truncated < 15)); then
    echo "RRL metrics did not show expected UDP limiting: subject=$subject dropped=$dropped truncated=$truncated query_tc=$queries_truncated" >&2
    exit 1
fi

cat >"$metrics_summary" <<EOF
rrl_subject_total=$subject
rrl_dropped_total=$dropped
rrl_truncated_total=$truncated
queries_truncated_total=$queries_truncated
rrl_keys_tracked=5
rrl_categories_checked=positive,nxdomain,nodata,referral,error
EOF

if ! grep -F "TCP AXFR served" "$primary_log" >/dev/null 2>&1; then
    echo "fake primary did not serve the initial AXFR" >&2
    exit 1
fi

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
    cp "$fake_primary" "$artifact_dir/fake-primary.py"
    cp "$rrl_client" "$artifact_dir/rrl-client.py"
    cp "$workdir/rrl-client.log" "$artifact_dir/rrl-client.log"
    cp "$workdir/client-summary.env" "$artifact_dir/client-summary.env"
    cp "$workdir/metrics-summary.env" "$artifact_dir/metrics-summary.env"
    cp "$workdir/metrics.txt" "$artifact_dir/metrics.txt"
    cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
fi

echo "RRL UDP runtime interop passed"
