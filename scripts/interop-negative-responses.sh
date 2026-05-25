#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping negative-response interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/negative-responses-$$"
artifact_dir="${OXIDEDNS_NEGATIVE_RESPONSE_ARTIFACT_DIR:-}"
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
summary_tsv="$workdir/negative-response-summary.tsv"
traceability_tsv="$workdir/negative-response-traceability.tsv"
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
ZONE = "negative.test."
IN = 1
A = 1
NS = 2
CNAME = 5
SOA = 6
DNAME = 39
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
        name_wire("ns1.negative.test."),
        name_wire("hostmaster.negative.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 300),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata(), ttl=3600)
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.negative.test.")),
        rr("ns1.negative.test.", A, bytes([127, 0, 0, 1])),
        rr("www.negative.test.", A, bytes([192, 0, 2, 10])),
        rr("alias.negative.test.", CNAME, name_wire("missing.negative.test.")),
        rr("alias-nodata.negative.test.", CNAME, name_wire("www.negative.test.")),
        rr("deleg.negative.test.", DNAME, name_wire("target.other.test.")),
        rr("child.foo.negative.test.", A, bytes([192, 0, 2, 20])),
        soa,
    ]


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
        qname, qtype, qclass, question = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 1, 0, 0, 0) + question
        else:
            log(f"TCP AXFR served records={len(zone_records())}")
            response = struct.pack("!HHHHHH", qid, 0x8000, 1, len(zone_records()), 0, 0) + question + b"".join(zone_records())
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
A = 1
CNAME = 5
SOA = 6
AAAA = 28
DNAME = 39
RCODES = {0: "NOERROR", 3: "NXDOMAIN", 5: "REFUSED"}
TYPES = {A: "A", CNAME: "CNAME", SOA: "SOA", AAAA: "AAAA", DNAME: "DNAME"}


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


def parse_rrs(packet, offset, count):
    records = []
    for _ in range(count):
        offset += skip_name(packet, offset)
        rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlength]
        offset += rdlength
        records.append((rrtype, rrclass, ttl, rdata))
    return records, offset


def parse_response(packet):
    flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHH", packet[2:12])
    offset = 12
    for _ in range(qdcount):
        offset += skip_name(packet, offset) + 4
    answers, offset = parse_rrs(packet, offset, ancount)
    authority, offset = parse_rrs(packet, offset, nscount)
    additional, offset = parse_rrs(packet, offset, arcount)
    return {
        "rcode": flags & 0x000F,
        "aa": 1 if flags & 0x0400 else 0,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "answer_types": [record[0] for record in answers],
        "answer_soa_ttls": [record[2] for record in answers if record[0] == SOA],
        "authority_types": [record[0] for record in authority],
        "authority_soa_ttls": [record[2] for record in authority if record[0] == SOA],
        "additional_types": [record[0] for record in additional],
    }


def response_for(qid, qname, qtype):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(2.0)
    udp.sendto(query(qid, qname, qtype), (HOST, PORT))
    response, _ = udp.recvfrom(4096)
    return parse_response(response)


def type_names(values):
    return ",".join(TYPES.get(value, str(value)) for value in values) or "-"


cases = [
    {
        "name": "nxdomain",
        "requirements": "ODS-FR-CORE-023,ODS-FR-NRESP-001",
        "qname": "missing.negative.test.",
        "qtype": A,
        "rcode": 3,
        "aa": 1,
        "answers": [],
        "answer_soa_ttls": [],
        "authority": [SOA],
        "soa_ttls": [300],
    },
    {
        "name": "nodata",
        "requirements": "ODS-FR-CORE-022,ODS-FR-NRESP-001",
        "qname": "www.negative.test.",
        "qtype": AAAA,
        "rcode": 0,
        "aa": 1,
        "answers": [],
        "answer_soa_ttls": [],
        "authority": [SOA],
        "soa_ttls": [300],
    },
    {
        "name": "empty_non_terminal",
        "requirements": "ODS-FR-QRY-016,ODS-FR-NRESP-003,ODS-FR-CORE-022,ODS-FR-NRESP-001",
        "qname": "foo.negative.test.",
        "qtype": A,
        "rcode": 0,
        "aa": 1,
        "answers": [],
        "answer_soa_ttls": [],
        "authority": [SOA],
        "soa_ttls": [300],
    },
    {
        "name": "cname_negative_terminal",
        "requirements": "ODS-FR-NRESP-004,ODS-FR-NRESP-001",
        "qname": "alias.negative.test.",
        "qtype": A,
        "rcode": 3,
        "aa": 1,
        "answers": [CNAME],
        "answer_soa_ttls": [],
        "authority": [SOA],
        "soa_ttls": [300],
    },
    {
        "name": "cname_nodata_terminal",
        "requirements": "ODS-FR-NRESP-005,ODS-FR-NRESP-001",
        "qname": "alias-nodata.negative.test.",
        "qtype": AAAA,
        "rcode": 0,
        "aa": 1,
        "answers": [CNAME],
        "answer_soa_ttls": [],
        "authority": [SOA],
        "soa_ttls": [300],
    },
    {
        "name": "dname_out_of_zone_terminal",
        "requirements": "ODS-FR-NRESP-006",
        "qname": "www.deleg.negative.test.",
        "qtype": A,
        "rcode": 0,
        "aa": 1,
        "answers": [DNAME, CNAME],
        "answer_soa_ttls": [],
        "authority": [],
        "soa_ttls": [],
    },
    {
        "name": "outside_served_zone",
        "requirements": "ODS-FR-CORE-019",
        "qname": "outside.example.",
        "qtype": A,
        "rcode": 5,
        "aa": 0,
        "answers": [],
        "answer_soa_ttls": [],
        "authority": [],
        "soa_ttls": [],
    },
    {
        "name": "direct_soa_ttl",
        "requirements": "ODS-FR-NRESP-002",
        "qname": "negative.test.",
        "qtype": SOA,
        "rcode": 0,
        "aa": 1,
        "answers": [SOA],
        "answer_soa_ttls": [3600],
        "authority": [],
        "soa_ttls": [],
    },
]

rows = ["case\tqname\tqtype\trcode\taa\tanswers\tauthority\tsoa_ttls"]
traceability = ["requirement_ids\tcase\tevidence_status\tevidence_summary\tartifact"]
for index, case in enumerate(cases, start=1):
    response = response_for(0x7000 + index, case["qname"], case["qtype"])
    if response["rcode"] != case["rcode"]:
        raise AssertionError(f"{case['name']} rcode {response['rcode']} != {case['rcode']}")
    if response["aa"] != case["aa"]:
        raise AssertionError(f"{case['name']} AA {response['aa']} != {case['aa']}")
    if response["answer_types"] != case["answers"]:
        raise AssertionError(f"{case['name']} answer types {response['answer_types']} != {case['answers']}")
    if response["answer_soa_ttls"] != case["answer_soa_ttls"]:
        raise AssertionError(f"{case['name']} answer SOA TTLs {response['answer_soa_ttls']} != {case['answer_soa_ttls']}")
    if response["authority_types"] != case["authority"]:
        raise AssertionError(f"{case['name']} authority types {response['authority_types']} != {case['authority']}")
    if response["authority_soa_ttls"] != case["soa_ttls"]:
        raise AssertionError(f"{case['name']} SOA TTLs {response['authority_soa_ttls']} != {case['soa_ttls']}")
    row = "\t".join([
        case["name"],
        case["qname"],
        TYPES.get(case["qtype"], str(case["qtype"])),
        RCODES.get(response["rcode"], str(response["rcode"])),
        str(response["aa"]),
        type_names(response["answer_types"]),
        type_names(response["authority_types"]),
        ",".join(str(ttl) for ttl in response["authority_soa_ttls"]) or "-",
    ])
    rows.append(row)
    traceability.append(
        "\t".join([
            case["requirements"],
            case["name"],
            "verified",
            f"rcode={RCODES.get(response['rcode'], response['rcode'])};aa={response['aa']};answers={type_names(response['answer_types'])};authority={type_names(response['authority_types'])};authority_soa_ttls={','.join(str(ttl) for ttl in response['authority_soa_ttls']) or '-'};answer_soa_ttls={','.join(str(ttl) for ttl in response['answer_soa_ttls']) or '-'}",
            "negative-response-summary.tsv",
        ])
    )
    log(row)

with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
    print("\n".join(rows), file=handle)
with open(TRACEABILITY_PATH, "w", encoding="utf-8") as handle:
    print("\n".join(traceability), file=handle)

print(f"negative_response_cases={len(cases)}")
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
max_udp_payload = 1232
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600
graceful_shutdown_secs = 2

[[zones]]
name = "negative.test."
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
    echo "fake negative-response primary did not become ready" >&2
    exit 1
fi

"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=0
for _ in {1..200}; do
    ready_body="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null || true)"
    if [[ "$ready_body" == *'"status":"ready"'* ]]; then
        ready=1
        break
    fi
    sleep 0.05
done
if ((ready != 1)); then
    echo "OxideDNS did not become ready during negative-response interop" >&2
    exit 1
fi

client_summary="$(python3 "$client" "$oxidedns_dns_port" "$client_log" "$summary_tsv" "$traceability_tsv")"
metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
    'oxidedns_zones_active 1' \
    'oxidedns_secondary_queries_total{zone="negative.test."} 7' \
    'oxidedns_secondary_query_responses_total{zone="negative.test.",rcode="NOERROR"} 5' \
    'oxidedns_secondary_query_responses_total{zone="negative.test.",rcode="NXDOMAIN"} 2'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "metrics missing expected negative-response line: $expected" >&2
        exit 1
    fi
done

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$client_log" "$artifact_dir/client.log"
    cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
    cp "$summary_tsv" "$artifact_dir/negative-response-summary.tsv"
    cp "$traceability_tsv" "$artifact_dir/negative-response-traceability.tsv"
    printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
fi

printf '%s\n' "$client_summary"
