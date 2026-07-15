#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping CHAOS query interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi
ulimit -n 65536 2>/dev/null || true

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/chaos-queries-$$"
artifact_dir="${OXIDEDNS_CHAOS_QUERIES_ARTIFACT_DIR:-}"
rm -rf "$workdir"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if ((status != 0)); then
        [[ -f "$workdir/client.log" ]] && {
            echo "---- client.log ----" >&2
            tail -120 "$workdir/client.log" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -120 "$workdir/oxidedns.log" >&2
        }
        for metrics_file in "$workdir"/metrics-*.txt; do
            [[ -f "$metrics_file" ]] || continue
            echo "---- ${metrics_file##*/} ----" >&2
            tail -120 "$metrics_file" >&2
        done
    fi
    if [[ -n "$artifact_dir" ]]; then
        mkdir -p "$artifact_dir"
        cp -a "$workdir"/. "$artifact_dir"/
    fi
    rm -rf "$workdir"
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

client="$workdir/client.py"
client_log="$workdir/client.log"
summary_tsv="$workdir/chaos-query-summary.tsv"
traceability_tsv="$workdir/chaos-query-traceability.tsv"
oxidedns_conf="$workdir/oxidedns.toml"

cat >"$client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
SUMMARY_PATH = sys.argv[3]
TRANSPORT = sys.argv[4]
CH = 3
IN = 1
A = 1
TXT = 16
AXFR = 252
ANY = 255
RCODES = {0: "NOERROR", 5: "REFUSED"}


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
    jumped = False
    seen = set()
    while True:
        if offset >= len(packet):
            raise AssertionError("name offset outside packet")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise AssertionError("truncated compression pointer")
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
            return ".".join(labels) + "." if labels else ".", consumed
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
        if not jumped:
            consumed += length


def query(name, qtype, qclass, qid):
    return b"".join([
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0),
        name_wire(name),
        struct.pack("!HH", qtype, qclass),
    ])


def exchange(packet):
    if TRANSPORT == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(packet, (HOST, PORT))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response
    sock = socket.create_connection((HOST, PORT), timeout=2)
    sock.sendall(struct.pack("!H", len(packet)) + packet)
    length = struct.unpack("!H", read_exact(sock, 2))[0]
    response = read_exact(sock, length)
    sock.close()
    return response


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError("unexpected TCP EOF")
        data.extend(chunk)
    return bytes(data)


def parse_response(packet):
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    for _ in range(qd):
        _, consumed = parse_name(packet, offset)
        offset += consumed + 4
    answers = []
    for _ in range(an):
        owner, consumed = parse_name(packet, offset)
        offset += consumed
        rrtype, rrclass, ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlen]
        offset += rdlen
        text = None
        if rrtype == TXT and rdata:
            text_len = rdata[0]
            text = rdata[1:1 + text_len].decode("ascii")
        answers.append((owner, rrtype, rrclass, ttl, text))
    return {
        "id": qid,
        "rcode": flags & 0xF,
        "aa": bool(flags & 0x0400),
        "answers": answers,
        "authority_count": ns,
        "additional_count": ar,
    }


CASES = [
    ("missing-version", "version.bind.", TXT, CH, "REFUSED", False, None),
    ("nsid-fallback", "id.server.", TXT, CH, "NOERROR", True, "nsid-bud-1"),
    ("unrecognized-name", "authors.bind.", TXT, CH, "REFUSED", False, None),
    ("non-txt-a", "version.bind.", A, CH, "REFUSED", False, None),
    ("non-txt-any", "version.bind.", ANY, CH, "REFUSED", False, None),
    ("non-txt-axfr", "version.bind.", AXFR, CH, "REFUSED", False, None),
    ("in-class-orthogonal", "version.bind.", TXT, IN, "REFUSED", False, None),
]

CONFIGURED_CASES = [
    ("configured-version", "version.server.", TXT, CH, "NOERROR", True, "OxideDNS anycast"),
    ("configured-hostname", "hostname.bind.", TXT, CH, "NOERROR", True, "bud-dns-1"),
]

case_set = CASES if sys.argv[5] == "default" else CONFIGURED_CASES

with open(SUMMARY_PATH, "a", encoding="utf-8") as summary:
    for index, (name, qname, qtype, qclass, expected_rcode, expected_aa, expected_text) in enumerate(case_set, start=1):
        qid = 0x4000 + index
        response = parse_response(exchange(query(qname, qtype, qclass, qid)))
        rcode = RCODES.get(response["rcode"], str(response["rcode"]))
        if response["id"] != qid:
            raise AssertionError(f"{name}: response ID mismatch")
        if rcode != expected_rcode:
            raise AssertionError(f"{name}: expected RCODE {expected_rcode}, got {rcode}")
        if response["aa"] != expected_aa:
            raise AssertionError(f"{name}: expected AA {expected_aa}, got {response['aa']}")
        if expected_rcode == "REFUSED" and response["authority_count"] != 0:
            raise AssertionError(f"{name}: expected no authority records, got {response['authority_count']}")
        if expected_text is None:
            if response["answers"]:
                raise AssertionError(f"{name}: expected no answers, got {response['answers']}")
        else:
            if len(response["answers"]) != 1:
                raise AssertionError(f"{name}: expected one answer, got {response['answers']}")
            owner, rrtype, rrclass, ttl, text = response["answers"][0]
            if owner.lower() != qname.lower() or rrtype != TXT or rrclass != CH or ttl != 0 or text != expected_text:
                raise AssertionError(f"{name}: bad answer {response['answers'][0]}")
        log(f"{TRANSPORT} {name} rcode={rcode} aa={response['aa']} answers={len(response['answers'])}")
        print(f"{TRANSPORT}\t{name}\t{qname}\t{qtype}\t{qclass}\t{rcode}\t{response['aa']}\t{expected_text or ''}", file=summary)
PY
chmod +x "$client"

cargo build -p oxidedns-cli >/dev/null

write_config() {
    local version="$1"
    local hostname="$2"
    cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$dns_port"]
listen_tcp = ["127.0.0.1:$dns_port"]
health = "127.0.0.1:$health_port"
log_level = "debug"
log_format = "json"
nsid = "nsid-bud-1"

[chaos]
version = "$version"
hostname = "$hostname"

[rrl]
enabled = false

[[zones]]
name = "unused.test."
primaries = ["127.0.0.1:$primary_port"]
EOF
}

start_oxidedns() {
    : >"$workdir/oxidedns.log"
    "$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
    oxidedns_pid=$!
    for _ in {1..100}; do
        if curl -fsS "http://127.0.0.1:$health_port/livez" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
    done
    echo "OxideDNS did not become live" >&2
    return 1
}

stop_oxidedns() {
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    oxidedns_pid=""
}

printf 'transport\tcase\tqname\tqtype\tqclass\trcode\taa\ttext\n' >"$summary_tsv"
{
    printf 'requirement_id\tevidence\n'
    printf 'ODS-FR-CHAS-001\tconfigured-version UDP/TCP NOERROR CH/TXT value plus missing-version REFUSED default\n'
    printf 'ODS-FR-CHAS-002\tconfigured-hostname UDP/TCP and nsid-fallback UDP/TCP\n'
    printf 'ODS-FR-CHAS-003\tunrecognized-name UDP/TCP REFUSED with no answers\n'
    printf 'ODS-FR-CHAS-004\tnon-txt-a, non-txt-any, and non-txt-axfr UDP/TCP REFUSED with no authority SOA\n'
    printf 'ODS-FR-CHAS-005\tin-class-orthogonal UDP/TCP follows ordinary IN-class REFUSED path\n'
    printf 'ODS-FR-CHAS-006\tmetrics counters checked for answered, missing_value, unrecognized_name, and non_txt outcomes\n'
    printf 'ODS-IF-CONF-018\t[chaos] version and hostname exercised through runtime config\n'
} >"$traceability_tsv"

write_config "" ""
start_oxidedns
"$client" "$dns_port" "$client_log" "$summary_tsv" udp default
"$client" "$dns_port" "$client_log" "$summary_tsv" tcp default
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$workdir/metrics-default.txt"
grep -F 'oxidedns_chaos_queries_total{outcome="answered"} 2' "$workdir/metrics-default.txt" >/dev/null
grep -F 'oxidedns_chaos_queries_total{outcome="missing_value"} 2' "$workdir/metrics-default.txt" >/dev/null
grep -F 'oxidedns_chaos_queries_total{outcome="unrecognized_name"} 2' "$workdir/metrics-default.txt" >/dev/null
grep -F 'oxidedns_chaos_queries_total{outcome="non_txt"} 6' "$workdir/metrics-default.txt" >/dev/null
stop_oxidedns

write_config "OxideDNS anycast" "bud-dns-1"
start_oxidedns
"$client" "$dns_port" "$client_log" "$summary_tsv" udp configured
"$client" "$dns_port" "$client_log" "$summary_tsv" tcp configured
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$workdir/metrics-configured.txt"
grep -F 'oxidedns_chaos_queries_total{outcome="answered"} 4' "$workdir/metrics-configured.txt" >/dev/null
stop_oxidedns

printf 'CHAOS query interop passed: %s\n' "$summary_tsv"
