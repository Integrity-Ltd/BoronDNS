#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping DNSSEC NSEC3 serve interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/dnssec-nsec3-serve-$$"
artifact_dir="${BORONDNS_DNSSEC_NSEC3_ARTIFACT_DIR:-}"
rm -rf "$workdir"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
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
        [[ -f "$workdir/fake-primary.stderr" ]] && {
            echo "---- fake-primary.stderr ----" >&2
            tail -120 "$workdir/fake-primary.stderr" >&2
        }
        [[ -f "$workdir/nsec3-client.log" ]] && {
            echo "---- nsec3-client.log ----" >&2
            tail -120 "$workdir/nsec3-client.log" >&2
        }
        [[ -f "$workdir/borondns.log" ]] && {
            echo "---- borondns.log ----" >&2
            tail -120 "$workdir/borondns.log" >&2
        }
        [[ -f "$workdir/client-summary.out" ]] && {
            echo "---- client-summary.out ----" >&2
            cat "$workdir/client-summary.out" >&2
        }
        [[ -f "$workdir/metrics.txt" ]] && {
            echo "---- metrics.txt ----" >&2
            tail -120 "$workdir/metrics.txt" >&2
        }
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

read -r primary_port borondns_dns_port borondns_health_port < <(
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
nsec3_client="$workdir/nsec3-client.py"
primary_log="$workdir/fake-primary.log"
borondns_conf="$workdir/borondns.toml"
summary_env="$workdir/dnssec-nsec3-summary.env"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading
import hashlib

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "alpha.test."
IN = 1
A = 1
NS = 2
SOA = 6
RRSIG = 46
DNSKEY = 48
NSEC3 = 50
NSEC3PARAM = 51
AXFR = 252


def base32hex(data):
    alphabet = "0123456789abcdefghijklmnopqrstuv"
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            out.append(alphabet[(buffer >> (bits - 5)) & 0x1F])
            bits -= 5
    if bits:
        out.append(alphabet[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


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


def nsec3_owner(name):
    return f"{base32hex(hashlib.sha1(name_wire(name)).digest())}.{ZONE}"


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


def soa_rdata(serial=2026052403):
    return b"".join([
        name_wire("ns1.alpha.test."),
        name_wire("hostmaster.alpha.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 300),
    ])


def type_bitmap(types):
    by_window = {}
    for rrtype in types:
        window = rrtype // 256
        bit = rrtype % 256
        octet = bit // 8
        by_window.setdefault(window, bytearray(octet + 1))
        if len(by_window[window]) <= octet:
            by_window[window].extend(b"\x00" * (octet + 1 - len(by_window[window])))
        by_window[window][octet] |= 1 << (7 - (bit % 8))
    out = bytearray()
    for window, bitmap in sorted(by_window.items()):
        out.append(window)
        out.append(len(bitmap))
        out.extend(bitmap)
    return bytes(out)


def rrsig_rdata(type_covered, labels):
    signature = bytes((index % 251) + 1 for index in range(160))
    return b"".join([
        struct.pack("!HBBIIIH", type_covered, 253, labels, 300, 4102444800, 1704067200, 12345),
        name_wire("alpha.test."),
        signature,
    ])


def dnskey_rdata():
    return struct.pack("!HBB", 257, 3, 253) + bytes(range(1, 65))


def nsec3_rdata():
    next_hash = bytes.fromhex("deadbeef00112233445566778899aabbccddeeff")
    return b"".join([
        struct.pack("!BBH", 1, 0, 0),
        b"\x00",
        bytes([len(next_hash)]),
        next_hash,
        type_bitmap([RRSIG, NSEC3]),
    ])


def nsec3param_rdata():
    return struct.pack("!BBH", 1, 0, 0) + b"\x00"


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    missing_nsec3_owner = nsec3_owner("missing.alpha.test.")
    wildcard_nsec3_owner = nsec3_owner("*.alpha.test.")
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10])),
        rr(ZONE, DNSKEY, dnskey_rdata()),
        rr(ZONE, NSEC3PARAM, nsec3param_rdata()),
        rr(missing_nsec3_owner, NSEC3, nsec3_rdata()),
        rr(wildcard_nsec3_owner, NSEC3, nsec3_rdata()),
        rr(ZONE, RRSIG, rrsig_rdata(SOA, 2)),
        rr(ZONE, RRSIG, rrsig_rdata(DNSKEY, 2)),
        rr(ZONE, RRSIG, rrsig_rdata(NSEC3PARAM, 2)),
        rr("www.alpha.test.", RRSIG, rrsig_rdata(A, 3)),
        rr(missing_nsec3_owner, RRSIG, rrsig_rdata(NSEC3, 3)),
        rr(wildcard_nsec3_owner, RRSIG, rrsig_rdata(NSEC3, 3)),
        soa,
    ]


def axfr_response(qid, question):
    answers = zone_records()
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
            log("TCP AXFR with DNSSEC NSEC3 records served")
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

cat >"$nsec3_client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import hashlib

HOST = sys.argv[1]
PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]

A = 1
SOA = 6
RRSIG = 46
DNSKEY = 48
NSEC3 = 50
NSEC3PARAM = 51
OPT = 41


def base32hex(data):
    alphabet = "0123456789abcdefghijklmnopqrstuv"
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            out.append(alphabet[(buffer >> (bits - 5)) & 0x1F])
            bits -= 5
    if bits:
        out.append(alphabet[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


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


NSEC3_OWNER = f"{base32hex(hashlib.sha1(name_wire('missing.alpha.test.')).digest())}.alpha.test."


def query(qid, qname, qtype, payload=None, do=False):
    packet = bytearray()
    packet.extend(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1 if payload else 0))
    packet.extend(name_wire(qname))
    packet.extend(struct.pack("!HH", qtype, 1))
    if payload:
        ttl = 0x8000 if do else 0
        packet.extend(b"\x00")
        packet.extend(struct.pack("!HHIH", OPT, payload, ttl, 0))
    return bytes(packet)


def parse_name(packet, offset):
    labels = []
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
            return ".".join(labels) + ".", consumed
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
        if not jumped:
            consumed += length


def skip_questions(packet, offset, count):
    for _ in range(count):
        _, consumed = parse_name(packet, offset)
        offset += consumed + 4
    return offset


def parse_records(packet, offset, count):
    records = []
    for _ in range(count):
        owner, consumed = parse_name(packet, offset)
        offset += consumed
        rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlength]
        offset += rdlength
        records.append({"owner": owner, "type": rrtype, "class": rrclass, "ttl": ttl, "rdata": rdata})
    return records, offset


def exchange(qid, qname, qtype, payload=None, do=False, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(query(qid, qname, qtype, payload=payload, do=do), (HOST, PORT))
    packet, _ = sock.recvfrom(4096)
    header = struct.unpack("!HHHHHH", packet[:12])
    rid, flags, qdcount, ancount, nscount, arcount = header
    if rid != qid:
        raise AssertionError(f"mismatched qid: got {rid} expected {qid}")
    offset = skip_questions(packet, 12, qdcount)
    answers, offset = parse_records(packet, offset, ancount)
    authorities, offset = parse_records(packet, offset, nscount)
    additionals, offset = parse_records(packet, offset, arcount)
    opt_ttls = [record["ttl"] for record in additionals if record["type"] == OPT]
    summary = {
        "flags": flags,
        "rcode": flags & 0x000F,
        "tc": bool(flags & 0x0200),
        "ad": bool(flags & 0x0020),
        "cd": bool(flags & 0x0010),
        "answer_types": [record["type"] for record in answers],
        "authority_types": [record["type"] for record in authorities],
        "additional_types": [record["type"] for record in additionals],
        "opt_ttls": opt_ttls,
        "size": len(packet),
    }
    log(f"{qname} type={qtype} do={int(do)} payload={payload} summary={summary}")
    return summary


nsec3_do = exchange(0xE301, NSEC3_OWNER, NSEC3, payload=4096, do=True)
if nsec3_do["rcode"] != 0 or nsec3_do["tc"]:
    raise AssertionError(f"direct NSEC3 DO response failed: {nsec3_do}")
if nsec3_do["answer_types"] != [NSEC3, RRSIG]:
    raise AssertionError(f"direct NSEC3 DO did not include transferred NSEC3 plus covering RRSIG: {nsec3_do}")
if not nsec3_do["opt_ttls"] or nsec3_do["opt_ttls"][0] & 0x8000 == 0:
    raise AssertionError(f"direct NSEC3 DO response did not copy query DO bit: {nsec3_do}")
if nsec3_do["ad"] or nsec3_do["cd"]:
    raise AssertionError(f"direct NSEC3 DO response set AD/CD unexpectedly: {nsec3_do}")

nsec3_non_do = exchange(0xE302, NSEC3_OWNER, NSEC3, payload=4096, do=False)
if nsec3_non_do["answer_types"] != [NSEC3]:
    raise AssertionError(f"direct non-DO NSEC3 query did not return only transferred NSEC3: {nsec3_non_do}")
if nsec3_non_do["opt_ttls"] and nsec3_non_do["opt_ttls"][0] & 0x8000:
    raise AssertionError(f"direct non-DO NSEC3 query failed to copy cleared query DO bit: {nsec3_non_do}")

nsec3param_do = exchange(0xE303, "alpha.test.", NSEC3PARAM, payload=4096, do=True)
if nsec3param_do["rcode"] != 0 or nsec3param_do["tc"]:
    raise AssertionError(f"direct NSEC3PARAM DO response failed: {nsec3param_do}")
if nsec3param_do["answer_types"] != [NSEC3PARAM, RRSIG]:
    raise AssertionError(f"direct NSEC3PARAM DO did not include transferred NSEC3PARAM plus covering RRSIG: {nsec3param_do}")

dnskey = exchange(0xE304, "alpha.test.", DNSKEY, payload=4096, do=False)
if dnskey["answer_types"] != [DNSKEY]:
    raise AssertionError(f"direct DNSKEY query did not serve transferred DNSKEY: {dnskey}")

nxdomain_do = exchange(0xE305, "missing.alpha.test.", A, payload=4096, do=True)
if nxdomain_do["rcode"] != 3:
    raise AssertionError(f"NXDOMAIN DO did not return NXDOMAIN: {nxdomain_do}")
if SOA not in nxdomain_do["authority_types"]:
    raise AssertionError(f"NXDOMAIN DO lacked SOA authority record: {nxdomain_do}")
if NSEC3 not in nxdomain_do["authority_types"] or RRSIG not in nxdomain_do["authority_types"]:
    raise AssertionError(f"NXDOMAIN DO lacked NSEC3 proof material and covering RRSIG: {nxdomain_do}")

print("DNSSEC NSEC3 serve runtime interop passed")
PY

cat >"$borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "info"

[rrl]
enabled = false

[limits]
max_udp_payload = 1232
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

cargo build -p borondns-cli >/dev/null
"$repo_root/target/debug/borondns" serve --config "$borondns_conf" >"$workdir/borondns.log" 2>&1 &
borondns_pid=$!

ready=""
for _ in {1..100}; do
    if ready="$(curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != *'"status":"ready"'* ]]; then
    echo "BoronDNS did not become ready after fake-primary DNSSEC NSEC3 AXFR" >&2
    exit 1
fi

client_summary="$(python3 "$nsec3_client" 127.0.0.1 "$borondns_dns_port" "$workdir/nsec3-client.log")"
printf '%s\n' "$client_summary" >"$workdir/client-summary.out"
echo "$client_summary"

metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
printf '%s\n' "$metrics" >"$workdir/metrics.txt"
for expected in \
    'borondns_zones_active 1' \
    'borondns_zone_soa_serial{zone="alpha.test."} 2026052403'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "metrics missing expected DNSSEC NSEC3 line: $expected" >&2
        exit 1
    fi
done

if ! grep -F "TCP AXFR with DNSSEC NSEC3 records served" "$primary_log" >/dev/null 2>&1; then
    echo "fake DNSSEC NSEC3 primary did not serve the initial AXFR" >&2
    exit 1
fi

cat >"$summary_env" <<'EOF'
dnssec_nsec3_runtime_interop=1
direct_nsec3_do_rrsig=1
direct_nsec3_non_do_suppresses_rrsig=1
direct_nsec3param_do_rrsig=1
direct_dnskey_served=1
nxdomain_do_nsec3_rrsig=1
ad_cd_cleared_on_representative_nsec3=1
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
    cp "$fake_primary" "$artifact_dir/fake-primary.py"
    cp "$nsec3_client" "$artifact_dir/nsec3-client.py"
    cp "$workdir/nsec3-client.log" "$artifact_dir/nsec3-client.log"
    cp "$workdir/client-summary.out" "$artifact_dir/client-summary.out"
    cp "$workdir/borondns.log" "$artifact_dir/borondns.log"
    cp "$borondns_conf" "$artifact_dir/borondns.toml"
    cp "$workdir/metrics.txt" "$artifact_dir/metrics.txt"
    cp "$summary_env" "$artifact_dir/dnssec-nsec3-summary.env"
fi
