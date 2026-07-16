#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping unknown-RR bad-transfer interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/unknown-rr-bad-transfer-$$"
artifact_dir="${BORONDNS_UNKNOWN_RR_BAD_ARTIFACT_DIR:-}"
fake_primary="$workdir/fake-primary.py"
summary_tsv="$workdir/unknown-rr-bad-transfer-summary.tsv"
traceability_tsv="$workdir/unknown-rr-bad-transfer-traceability.tsv"
mkdir -p "$workdir/cases"

pids=()
cleanup() {
    local status=$?
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if ((status != 0)); then
        find "$workdir/cases" -maxdepth 2 -type f \( -name '*.log' -o -name 'readyz.txt' -o -name 'metrics.txt' \) -print -exec tail -80 {} \; >&2 || true
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = sys.argv[3]
BAD_TYPE = int(sys.argv[4])
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
    return qname, qtype, qclass, packet[12:offset + 4]


def rr(owner, rrtype, rdata, ttl=300):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052501):
    return b"".join([
        name_wire(f"ns1.{ZONE}"),
        name_wire(f"hostmaster.{ZONE}"),
        struct.pack("!IIIII", serial, 60, 30, 300, 300),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata(), ttl=3600)
    return [
        soa,
        rr(ZONE, NS, name_wire(f"ns1.{ZONE}")),
        rr(f"ns1.{ZONE}", A, bytes([127, 0, 0, 1])),
        rr(f"bad.{ZONE}", BAD_TYPE, b"\x00"),
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
        qname, qtype, qclass, question = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 1, 0, 0, 0) + question
        else:
            answers = zone_records()
            log(f"TCP AXFR served bad_type={BAD_TYPE} records={len(answers)}")
            response = struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)
        conn.sendall(struct.pack("!H", len(response)) + response)


def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()
    log(f"READY port={PORT} zone={ZONE} bad_type={BAD_TYPE}")
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY

allocate_ports() {
    python3 - <<'PY'
import socket
sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
}

wait_for_log() {
    local file="$1"
    local needle="$2"
    for _ in {1..80}; do
        if [[ -f "$file" ]] && grep -F "$needle" "$file" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

printf 'case\trr_type\terror_kind\tready_status\taxfr_failed\tactive_zones\tlog_match\n' >"$summary_tsv"

cargo build -p borondns-cli >/dev/null

run_case() {
    local case_name="$1"
    local rr_type="$2"
    local error_kind="$3"
    local expected_error="$4"
    local primary_port borondns_dns_port borondns_health_port
    read -r primary_port borondns_dns_port borondns_health_port < <(allocate_ports)
    local case_dir="$workdir/cases/$case_name"
    local zone="$case_name.unknown-bad.test."
    local primary_log="$case_dir/fake-primary.log"
    local borondns_log="$case_dir/borondns.log"
    local borondns_conf="$case_dir/borondns.toml"
    local readyz_out="$case_dir/readyz.txt"
    local metrics_out="$case_dir/metrics.txt"
    mkdir -p "$case_dir"

    python3 "$fake_primary" "$primary_port" "$primary_log" "$zone" "$rr_type" >"$case_dir/fake-primary.stderr" 2>&1 &
    local primary_pid=$!
    pids+=("$primary_pid")
    wait_for_log "$primary_log" "READY" || {
        echo "bad-transfer primary did not become ready for $case_name" >&2
        return 1
    }

    cat >"$borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "info"
log_format = "logfmt"

[rrl]
enabled = false

[limits]
axfr_timeout_secs = 2
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600
zsm_initial_retry_max_secs = 3600
graceful_shutdown_secs = 1

[[zones]]
name = "$zone"
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
notify_sources = ["127.0.0.1"]
EOF

    "$repo_root/target/debug/borondns" serve --config "$borondns_conf" >"$borondns_log" 2>&1 &
    local borondns_pid=$!
    pids+=("$borondns_pid")

    wait_for_log "$borondns_log" "AXFR failed" || {
        echo "BoronDNS did not log AXFR failure for $case_name" >&2
        return 1
    }
    if ! grep -F "$expected_error" "$borondns_log" >/dev/null 2>&1; then
        echo "BoronDNS log for $case_name missing expected error: $expected_error" >&2
        return 1
    fi

    local ready_body=""
    for _ in {1..50}; do
        ready_body="$(curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" 2>/dev/null || true)"
        if [[ "$ready_body" == *'"status":"not-ready"'* ]]; then
            break
        fi
        sleep 0.1
    done
    printf '%s\n' "$ready_body" >"$readyz_out"
    if [[ "$ready_body" == *'"status":"ready"'* ]]; then
        echo "BoronDNS unexpectedly became ready for prohibited type $case_name" >&2
        return 1
    fi

    local metrics=""
    metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
    printf '%s\n' "$metrics" >"$metrics_out"
    if [[ "$metrics" != *'borondns_transfer_sessions_failed_total{protocol="axfr"} 1'* ]]; then
        echo "BoronDNS metrics missing AXFR failure counter for $case_name" >&2
        return 1
    fi
    if [[ "$metrics" != *'borondns_zones_active 0'* ]]; then
        echo "BoronDNS metrics unexpectedly report active zone for $case_name" >&2
        return 1
    fi

    printf '%s\t%s\t%s\tnot-ready\t1\t0\t1\n' "$case_name" "$rr_type" "$error_kind" >>"$summary_tsv"

    kill "$borondns_pid" 2>/dev/null || true
    wait "$borondns_pid" 2>/dev/null || true
    kill "$primary_pid" 2>/dev/null || true
    wait "$primary_pid" 2>/dev/null || true
}

reserved_error="AXFR response contained a reserved RR type"
prohibited_error="AXFR response contained a pseudo or transfer meta RR type as zone content"

run_case rrtype0 0 reserved "$reserved_error"
run_case opt 41 prohibited "$prohibited_error"
run_case tkey 249 prohibited "$prohibited_error"
run_case tsig 250 prohibited "$prohibited_error"
run_case ixfr 251 prohibited "$prohibited_error"
run_case axfr 252 prohibited "$prohibited_error"
run_case mailb 253 prohibited "$prohibited_error"
run_case maila 254 prohibited "$prohibited_error"
run_case any 255 prohibited "$prohibited_error"
run_case rrtype65535 65535 reserved "$reserved_error"

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_state	runtime_case	artifacts	review_note
BDS-FR-URR-009	retained-runtime	rrtype0; opt; tkey; tsig; ixfr; axfr; mailb; maila; any; rrtype65535	unknown-rr-bad-transfer-summary.tsv; cases/*/borondns.log; cases/*/metrics.txt; cases/*/readyz.txt	Each prohibited pseudo/meta/reserved RR type in SRS v0.9.1 URR-009 is injected into an initial AXFR; BoronDNS logs the AXFR validation failure, increments the AXFR failed counter, remains not-ready, and exposes zero active zones.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$fake_primary" "$artifact_dir/fake-primary.py"
    cp "$summary_tsv" "$artifact_dir/unknown-rr-bad-transfer-summary.tsv"
    cp "$traceability_tsv" "$artifact_dir/unknown-rr-bad-transfer-traceability.tsv"
    cp -R "$workdir/cases" "$artifact_dir/cases"
fi

printf 'unknown_rr_bad_transfer_cases=10\n'
