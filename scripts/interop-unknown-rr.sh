#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping unknown-RR interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/unknown-rr-$$"
artifact_dir="${OXIDEDNS_UNKNOWN_RR_ARTIFACT_DIR:-}"
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
            tail -120 "$workdir/fake-primary.log" >&2
        }
        [[ -f "$workdir/client.log" ]] && {
            echo "---- client.log ----" >&2
            tail -120 "$workdir/client.log" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -120 "$workdir/oxidedns.log" >&2
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
client="$workdir/client.py"
primary_log="$workdir/fake-primary.log"
client_log="$workdir/client.log"
summary_tsv="$workdir/unknown-rr-summary.tsv"
traceability_tsv="$workdir/unknown-rr-traceability.tsv"
metrics_out="$workdir/metrics.txt"
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
ZONE = "unknown.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252
PRIVATE_USE = 65280
FUTURE_TYPE = 65000


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
        name_wire("ns1.unknown.test."),
        name_wire("hostmaster.unknown.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 300),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata(), ttl=3600)
    pointer_like = bytes.fromhex("c00c00ff")
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.unknown.test.")),
        rr("ns1.unknown.test.", A, bytes([127, 0, 0, 1])),
        rr("opaque.unknown.test.", PRIVATE_USE, b""),
        rr("opaque.unknown.test.", PRIVATE_USE, pointer_like),
        rr("opaque.unknown.test.", PRIVATE_USE, b"CaseSensitive"),
        rr("opaque.unknown.test.", PRIVATE_USE, b"casesensitive"),
        rr("future.unknown.test.", FUTURE_TYPE, bytes.fromhex("01020304")),
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
            log(f"TCP AXFR served private_type={PRIVATE_USE} future_type={FUTURE_TYPE} records={len(answers)}")
            response = struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)
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
SUMMARY_PATH = sys.argv[3]
TRACEABILITY_PATH = sys.argv[4]
IN = 1
PRIVATE_USE = 65280
FUTURE_TYPE = 65000
EXPECTED_PRIVATE = {
    "",
    "c00c00ff",
    "4361736553656e736974697665",
    "6361736573656e736974697665",
}
EXPECTED_FUTURE = {"01020304"}


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
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", qtype, IN)
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


def response_records(packet):
    if len(packet) < 12:
        raise AssertionError("short response")
    qid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        offset += skip_name(packet, offset) + 4
    records = []
    for _ in range(ancount):
        offset += skip_name(packet, offset)
        rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlength]
        offset += rdlength
        records.append({
            "type": rrtype,
            "class": rrclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata_hex": rdata.hex(),
        })
    return qid, rcode, records


def exchange(qid, qname, qtype):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(query(qid, qname, qtype), (HOST, PORT))
    packet, _ = sock.recvfrom(4096)
    got_qid, rcode, records = response_records(packet)
    if got_qid != qid:
        raise AssertionError(f"mismatched qid got={got_qid} want={qid}")
    return rcode, records


rows = ["case\tqtype\trcode\tanswer_count\trdata_hex"]

rcode, private_records = exchange(0x7001, "opaque.unknown.test.", PRIVATE_USE)
private_hex = {record["rdata_hex"] for record in private_records}
if rcode != 0 or any(record["type"] != PRIVATE_USE for record in private_records):
    raise AssertionError(f"unexpected private-use response rcode={rcode} records={private_records}")
if private_hex != EXPECTED_PRIVATE:
    raise AssertionError(f"private-use RDATA mismatch got={private_hex} want={EXPECTED_PRIVATE}")
if sorted(record["rdlength"] for record in private_records) != [0, 4, 13, 13]:
    raise AssertionError(f"private-use RDLENGTH mismatch records={private_records}")
rows.append(f"private_use\t{PRIVATE_USE}\tNOERROR\t{len(private_records)}\t{','.join(sorted(private_hex))}")
log(rows[-1])

rcode, future_records = exchange(0x7002, "future.unknown.test.", FUTURE_TYPE)
future_hex = {record["rdata_hex"] for record in future_records}
if rcode != 0 or len(future_records) != 1 or future_records[0]["type"] != FUTURE_TYPE:
    raise AssertionError(f"unexpected future-type response rcode={rcode} records={future_records}")
if future_hex != EXPECTED_FUTURE:
    raise AssertionError(f"future-type RDATA mismatch got={future_hex} want={EXPECTED_FUTURE}")
rows.append(f"future_type\t{FUTURE_TYPE}\tNOERROR\t{len(future_records)}\t{','.join(sorted(future_hex))}")
log(rows[-1])

traceability = [
    "requirement_id\tevidence_state\truntime_case\tartifacts\treview_note",
    "ODS-FR-URR-001\tretained-runtime\tprivate_use; future_type\tunknown-rr-summary.tsv; fake-primary.log\tThe fake primary transfers a private-use RR type and an unassigned future numeric RR type, and OxideDNS publishes the zone.",
    "ODS-FR-URR-002\tretained-runtime\tprivate_use\tunknown-rr-summary.tsv; client.log\tThe private-use RRset is served with the exact transferred RDATA hex values, including pointer-looking opaque bytes.",
    "ODS-FR-URR-003\tretained-runtime\tprivate_use\tunknown-rr-summary.tsv\tThe transferred private-use RRset includes and serves a zero-length RDATA record with RDLENGTH=0.",
    "ODS-FR-URR-004\tretained-runtime\tprivate_use; future_type\tclient.log\tExact numeric QTYPE queries for the unknown RRsets receive authoritative NOERROR answers.",
    "ODS-FR-URR-005\tretained-runtime\tprivate_use; future_type\tunknown-rr-summary.tsv; client.log\tThe response RDLENGTH values match the stored RDATA octet counts and the emitted RDATA hex is verbatim.",
    "ODS-FR-URR-006\tretained-runtime\tprivate_use\tunknown-rr-summary.tsv\tThe pointer-looking c00c00ff RDATA is emitted unchanged rather than compressed or interpreted as a DNS name.",
    "ODS-FR-URR-007\tretained-runtime\tprivate_use\tunknown-rr-summary.tsv\tThe transferred c00c00ff RDATA is consumed as opaque unknown-type RDATA and later served unchanged.",
    "ODS-FR-URR-008\tretained-runtime\tprivate_use\tunknown-rr-summary.tsv\tCaseSensitive and casesensitive RDATA values are retained as distinct RRset members, proving bit-for-bit membership semantics.",
    "ODS-FR-URR-009\tretained-runtime-plus-support\tprivate_use; parser_prohibited_type_tests\tunknown-rr-summary.tsv; crates/oxidedns-core/src/axfr.rs::rejects_axfr_pseudo_and_transfer_meta_record_types; crates/oxidedns-core/src/axfr.rs::rejects_ixfr_reserved_record_type\tThe runtime harness proves private-use types are accepted; focused parser tests cover prohibited pseudo/meta/reserved transfer types.",
]

with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
    print("\n".join(rows), file=handle)
with open(TRACEABILITY_PATH, "w", encoding="utf-8") as handle:
    print("\n".join(traceability), file=handle)

print(f"unknown_rr_cases=2 private_records={len(private_records)} future_records={len(future_records)}")
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"
log_format = "logfmt"

[rrl]
enabled = false

[limits]
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600
graceful_shutdown_secs = 2

[[zones]]
name = "unknown.test."
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
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

printf '%s\n' "$ready" >"$workdir/readyz.txt"
if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after unknown-RR AXFR" >&2
    exit 1
fi

client_summary="$(python3 "$client" "$oxidedns_dns_port" "$client_log" "$summary_tsv" "$traceability_tsv")"

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
for expected in \
    'oxidedns_zones_active 1' \
    'oxidedns_zone_soa_serial{zone="unknown.test."} 2026052501'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "metrics missing expected unknown-RR line: $expected" >&2
        exit 1
    fi
done

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$fake_primary" "$artifact_dir/fake-primary.py"
    cp "$client" "$artifact_dir/client.py"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
    cp "$client_log" "$artifact_dir/client.log"
    cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
    cp "$workdir/readyz.txt" "$artifact_dir/readyz.txt"
    cp "$summary_tsv" "$artifact_dir/unknown-rr-summary.tsv"
    cp "$traceability_tsv" "$artifact_dir/unknown-rr-traceability.tsv"
    cp "$metrics_out" "$artifact_dir/metrics.txt"
fi

printf '%s\n' "$client_summary"
