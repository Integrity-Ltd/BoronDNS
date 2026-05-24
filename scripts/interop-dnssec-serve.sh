#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping DNSSEC serve interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/dnssec-serve-$$"
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
    [[ -f "$workdir/fake-primary.stderr" ]] && { echo "---- fake-primary.stderr ----" >&2; tail -120 "$workdir/fake-primary.stderr" >&2; }
    [[ -f "$workdir/dnssec-client.log" ]] && { echo "---- dnssec-client.log ----" >&2; tail -120 "$workdir/dnssec-client.log" >&2; }
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
dnssec_client="$workdir/dnssec-client.py"
primary_log="$workdir/fake-primary.log"
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
ZONE = "alpha.test."
IN = 1
A = 1
NS = 2
SOA = 6
TXT = 16
RRSIG = 46
NSEC = 47
DNSKEY = 48
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


def soa_rdata(serial=2026052401):
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


def nsec_rdata(next_name, types):
    return name_wire(next_name) + type_bitmap(types)


def rrsig_rdata(type_covered, labels):
    signature = bytes((index % 251) + 1 for index in range(720))
    return b"".join([
        struct.pack("!HBBIIIH", type_covered, 253, labels, 300, 4102444800, 1704067200, 12345),
        name_wire("alpha.test."),
        signature,
    ])


def dnskey_rdata():
    return struct.pack("!HBB", 257, 3, 253) + bytes(range(1, 65))


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10])),
        *[
            rr("large.alpha.test.", TXT, bytes([120]) + bytes([65 + (index % 26)]) * 120)
            for index in range(8)
        ],
        rr(ZONE, DNSKEY, dnskey_rdata()),
        rr(ZONE, NSEC, nsec_rdata("www.alpha.test.", [NS, SOA, RRSIG, NSEC, DNSKEY])),
        rr("www.alpha.test.", NSEC, nsec_rdata("alpha.test.", [A, RRSIG, NSEC])),
        rr(ZONE, RRSIG, rrsig_rdata(SOA, 2)),
        rr(ZONE, RRSIG, rrsig_rdata(DNSKEY, 2)),
        rr(ZONE, RRSIG, rrsig_rdata(NSEC, 2)),
        rr("www.alpha.test.", RRSIG, rrsig_rdata(A, 3)),
        rr("www.alpha.test.", RRSIG, rrsig_rdata(NSEC, 3)),
        soa,
    ]


def axfr_response(qid):
    answers = zone_records()
    return struct.pack("!HHHHHH", qid, 0x8000, 0, len(answers), 0, 0) + b"".join(answers)


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
            log("TCP AXFR with DNSSEC records served")
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

cat >"$dnssec_client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]

A = 1
SOA = 6
TXT = 16
RRSIG = 46
NSEC = 47
DNSKEY = 48
OPT = 41


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


positive_do = exchange(0xD001, "www.alpha.test.", A, payload=4096, do=True)
if positive_do["rcode"] != 0 or positive_do["tc"]:
    raise AssertionError(f"positive DO response failed: {positive_do}")
if positive_do["answer_types"] != [A, RRSIG]:
    raise AssertionError(f"positive DO did not include A plus covering RRSIG: {positive_do}")
if not positive_do["opt_ttls"] or positive_do["opt_ttls"][0] & 0x8000 == 0:
    raise AssertionError(f"positive DO response did not set response DO bit: {positive_do}")
if positive_do["ad"] or positive_do["cd"]:
    raise AssertionError(f"positive DO response set AD/CD unexpectedly: {positive_do}")

positive_non_do = exchange(0xD002, "www.alpha.test.", A, payload=4096, do=False)
if positive_non_do["answer_types"] != [A]:
    raise AssertionError(f"non-DO response included DNSSEC augmentation: {positive_non_do}")
if positive_non_do["opt_ttls"] and positive_non_do["opt_ttls"][0] & 0x8000:
    raise AssertionError(f"non-DO response set response DO bit: {positive_non_do}")

nxdomain_do = exchange(0xD003, "missing.alpha.test.", A, payload=4096, do=True)
if nxdomain_do["rcode"] != 3:
    raise AssertionError(f"NXDOMAIN DO did not return NXDOMAIN: {nxdomain_do}")
if SOA not in nxdomain_do["authority_types"] or NSEC not in nxdomain_do["authority_types"] or RRSIG not in nxdomain_do["authority_types"]:
    raise AssertionError(f"NXDOMAIN DO lacked SOA/NSEC/RRSIG proof material: {nxdomain_do}")
if not nxdomain_do["opt_ttls"] or nxdomain_do["opt_ttls"][0] & 0x8000 == 0:
    raise AssertionError(f"NXDOMAIN DO response did not set response DO bit: {nxdomain_do}")

dnskey = exchange(0xD004, "alpha.test.", DNSKEY, payload=4096, do=False)
if dnskey["answer_types"] != [DNSKEY]:
    raise AssertionError(f"direct DNSKEY query did not serve transferred DNSKEY: {dnskey}")

truncated = exchange(0xD005, "www.alpha.test.", A, payload=512, do=True)
if not truncated["tc"]:
    raise AssertionError(f"small-payload DNSSEC response was not truncated: {truncated}")
if RRSIG in truncated["answer_types"] and (not truncated["opt_ttls"] or truncated["opt_ttls"][0] & 0x8000 == 0):
    raise AssertionError(f"truncated response kept DNSSEC records but cleared DO bit: {truncated}")
if RRSIG not in truncated["answer_types"] and truncated["opt_ttls"] and truncated["opt_ttls"][0] & 0x8000:
    raise AssertionError(f"truncated response removed DNSSEC records but kept DO bit: {truncated}")

non_edns_truncated = exchange(0xD006, "large.alpha.test.", TXT, payload=None, do=False)
if not non_edns_truncated["tc"] or non_edns_truncated["size"] > 512:
    raise AssertionError(f"non-EDNS response did not truncate to 512 octets: {non_edns_truncated}")
if OPT in non_edns_truncated["additional_types"] or non_edns_truncated["opt_ttls"]:
    raise AssertionError(f"non-EDNS truncated response unexpectedly included OPT: {non_edns_truncated}")

print("DNSSEC serve runtime interop passed")
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

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=""
for _ in {1..100}; do
  if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
    [[ "$ready" == "ready" ]] && break
  fi
  sleep 0.1
done

if [[ "$ready" != "ready" ]]; then
  echo "OxideDNS did not become ready after fake-primary DNSSEC AXFR" >&2
  exit 1
fi

client_summary="$(python3 "$dnssec_client" 127.0.0.1 "$oxidedns_dns_port" "$workdir/dnssec-client.log")"
echo "$client_summary"

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected DNSSEC line: $expected" >&2
    exit 1
  fi
done

if ! grep -F "TCP AXFR with DNSSEC records served" "$primary_log" >/dev/null 2>&1; then
  echo "fake DNSSEC primary did not serve the initial AXFR" >&2
  exit 1
fi
