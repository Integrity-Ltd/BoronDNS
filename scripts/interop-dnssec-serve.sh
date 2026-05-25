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
artifact_dir="${OXIDEDNS_DNSSEC_SERVE_ARTIFACT_DIR:-}"
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
    [[ -f "$workdir/client-summary.out" ]] && { echo "---- client-summary.out ----" >&2; cat "$workdir/client-summary.out" >&2; }
    [[ -f "$workdir/metrics.txt" ]] && { echo "---- metrics.txt ----" >&2; tail -120 "$workdir/metrics.txt" >&2; }
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
summary_env="$workdir/dnssec-serve-summary.env"

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
DS = 43
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
    return qname, qtype, qclass, packet[12:offset + 4]


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


def rrsig_rdata(type_covered, labels, signature_len=None):
    if signature_len is None:
        signature_len = 160 if type_covered in (NS, DS) else 720
    signature = bytes((index % 251) + 1 for index in range(signature_len))
    return b"".join([
        struct.pack("!HBBIIIH", type_covered, 253, labels, 300, 4102444800, 1704067200, 12345),
        name_wire("alpha.test."),
        signature,
    ])


def dnskey_rdata():
    return struct.pack("!HBB", 257, 3, 253) + bytes(range(1, 65))


def ds_rdata():
    return struct.pack("!HBB", 12345, 253, 2) + bytes(range(32))


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10])),
        rr("child.alpha.test.", NS, name_wire("ns.child.alpha.test.")),
        rr("ns.child.alpha.test.", A, bytes([192, 0, 2, 53])),
        rr("child.alpha.test.", DS, ds_rdata()),
        rr("unsigned.alpha.test.", NS, name_wire("ns.unsigned.alpha.test.")),
        rr("ns.unsigned.alpha.test.", A, bytes([192, 0, 2, 54])),
        rr("unsigned.alpha.test.", NSEC, nsec_rdata("www.alpha.test.", [NS, RRSIG, NSEC])),
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
        rr("sig.alpha.test.", RRSIG, rrsig_rdata(A, 3)),
        rr("child.alpha.test.", RRSIG, rrsig_rdata(NS, 3)),
        rr("child.alpha.test.", RRSIG, rrsig_rdata(DS, 3)),
        rr("unsigned.alpha.test.", RRSIG, rrsig_rdata(NS, 3)),
        rr("unsigned.alpha.test.", RRSIG, rrsig_rdata(NSEC, 3, signature_len=160)),
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
            log("TCP AXFR with DNSSEC records served")
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
NSID = 3
NS = 2
DS = 43
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


def query(qid, qname, qtype, payload=None, do=False, edns_options=b""):
    packet = bytearray()
    packet.extend(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1 if payload is not None else 0))
    packet.extend(name_wire(qname))
    packet.extend(struct.pack("!HH", qtype, 1))
    if payload is not None:
        ttl = 0x8000 if do else 0
        packet.extend(b"\x00")
        packet.extend(struct.pack("!HHIH", OPT, payload, ttl, len(edns_options)))
        packet.extend(edns_options)
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


def edns_option_data(additionals, option_code):
    found = []
    for record in additionals:
        if record["type"] != OPT:
            continue
        offset = 0
        rdata = record["rdata"]
        while offset + 4 <= len(rdata):
            code, length = struct.unpack("!HH", rdata[offset:offset + 4])
            offset += 4
            data = rdata[offset:offset + length]
            offset += length
            if code == option_code:
                found.append(data)
    return found


def exchange(qid, qname, qtype, payload=None, do=False, edns_options=b"", timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(query(qid, qname, qtype, payload=payload, do=do, edns_options=edns_options), (HOST, PORT))
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
        "nsid_options": edns_option_data(additionals, NSID),
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

rrsig_non_do = exchange(0xD00B, "sig.alpha.test.", RRSIG, payload=4096, do=False)
if rrsig_non_do["rcode"] != 0 or rrsig_non_do["tc"] or rrsig_non_do["answer_types"] != [RRSIG]:
    raise AssertionError(f"direct non-DO RRSIG query did not serve only transferred RRSIG records: {rrsig_non_do}")
if rrsig_non_do["opt_ttls"] and rrsig_non_do["opt_ttls"][0] & 0x8000:
    raise AssertionError(f"direct non-DO RRSIG query set response DO bit: {rrsig_non_do}")

nsec_non_do = exchange(0xD00C, "www.alpha.test.", NSEC, payload=4096, do=False)
if nsec_non_do["rcode"] != 0 or nsec_non_do["answer_types"] != [NSEC]:
    raise AssertionError(f"direct non-DO NSEC query did not serve only transferred NSEC records: {nsec_non_do}")
if nsec_non_do["opt_ttls"] and nsec_non_do["opt_ttls"][0] & 0x8000:
    raise AssertionError(f"direct non-DO NSEC query set response DO bit: {nsec_non_do}")

ds_do = exchange(0xD009, "child.alpha.test.", DS, payload=4096, do=True)
if ds_do["rcode"] != 0 or ds_do["answer_types"] != [DS, RRSIG]:
    raise AssertionError(f"direct DS DO query did not serve transferred DS plus covering RRSIG: {ds_do}")
if not ds_do["opt_ttls"] or ds_do["opt_ttls"][0] & 0x8000 == 0:
    raise AssertionError(f"direct DS DO response did not set response DO bit: {ds_do}")
if ds_do["ad"] or ds_do["cd"]:
    raise AssertionError(f"direct DS DO response set AD/CD unexpectedly: {ds_do}")

signed_child_referral_do = exchange(0xD00A, "www.child.alpha.test.", A, payload=4096, do=True)
if signed_child_referral_do["rcode"] != 0 or signed_child_referral_do["answer_types"]:
    raise AssertionError(f"signed-child referral DO response was not a referral: {signed_child_referral_do}")
if signed_child_referral_do["authority_types"] != [NS, DS, RRSIG, RRSIG]:
    raise AssertionError(f"signed-child referral DO lacked NS/DS/RRSIG authority: {signed_child_referral_do}")
if not signed_child_referral_do["opt_ttls"] or signed_child_referral_do["opt_ttls"][0] & 0x8000 == 0:
    raise AssertionError(f"signed-child referral DO response did not set response DO bit: {signed_child_referral_do}")
if signed_child_referral_do["ad"] or signed_child_referral_do["cd"]:
    raise AssertionError(f"signed-child referral DO response set AD/CD unexpectedly: {signed_child_referral_do}")

unsigned_child_referral_do = exchange(0xD00D, "www.unsigned.alpha.test.", A, payload=4096, do=True)
if unsigned_child_referral_do["rcode"] != 0 or unsigned_child_referral_do["answer_types"]:
    raise AssertionError(f"unsigned-child referral DO response was not a referral: {unsigned_child_referral_do}")
if unsigned_child_referral_do["authority_types"] != [NS, NSEC, RRSIG, RRSIG]:
    raise AssertionError(f"unsigned-child referral DO lacked NS/NSEC/RRSIG authority: {unsigned_child_referral_do}")
if DS in unsigned_child_referral_do["authority_types"]:
    raise AssertionError(f"unsigned-child referral DO unexpectedly included DS proof: {unsigned_child_referral_do}")
if not unsigned_child_referral_do["opt_ttls"] or unsigned_child_referral_do["opt_ttls"][0] & 0x8000 == 0:
    raise AssertionError(f"unsigned-child referral DO response did not set response DO bit: {unsigned_child_referral_do}")
if unsigned_child_referral_do["ad"] or unsigned_child_referral_do["cd"]:
    raise AssertionError(f"unsigned-child referral DO response set AD/CD unexpectedly: {unsigned_child_referral_do}")

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

nsid = exchange(0xD007, "www.alpha.test.", A, payload=4096, edns_options=struct.pack("!HH", NSID, 0))
if nsid["rcode"] != 0 or nsid["nsid_options"] != [b"oxidedns-runtime"]:
    raise AssertionError(f"configured NSID response missing expected identifier: {nsid}")

nsid_nonzero = exchange(
    0xD008,
    "www.alpha.test.",
    A,
    payload=4096,
    edns_options=struct.pack("!HH", NSID, 3) + b"bad",
)
if nsid_nonzero["rcode"] != 0 or nsid_nonzero["nsid_options"] != [b"oxidedns-runtime"]:
    raise AssertionError(f"non-zero NSID request data was not treated as a request: {nsid_nonzero}")

print("DNSSEC serve runtime interop passed")
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"
nsid = "oxidedns-runtime"

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
    [[ "$ready" == *'"status":"ready"'* ]] && break
  fi
  sleep 0.1
done

if [[ "$ready" != *'"status":"ready"'* ]]; then
  echo "OxideDNS did not become ready after fake-primary DNSSEC AXFR" >&2
  exit 1
fi

client_summary="$(python3 "$dnssec_client" 127.0.0.1 "$oxidedns_dns_port" "$workdir/dnssec-client.log")"
printf '%s\n' "$client_summary" >"$workdir/client-summary.out"
echo "$client_summary"

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$workdir/metrics.txt"
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

cat >"$summary_env" <<'EOF'
dnssec_serve_runtime_interop=1
positive_do_rrsig=1
positive_non_do_suppresses_rrsig=1
nxdomain_do_nsec_rrsig=1
direct_dnskey_served=1
direct_rrsig_non_do_served=1
direct_nsec_non_do_served=1
direct_ds_do_rrsig=1
signed_child_referral_ds_rrsig=1
unsigned_child_referral_nsec_rrsig=1
dnssec_truncation_checked=1
non_edns_512_truncation_no_opt=1
configured_nsid_empty_request=1
configured_nsid_nonempty_request=1
ad_cd_cleared_on_representative_dnssec=1
EOF

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
  cp "$fake_primary" "$artifact_dir/fake-primary.py"
  cp "$dnssec_client" "$artifact_dir/dnssec-client.py"
  cp "$workdir/dnssec-client.log" "$artifact_dir/dnssec-client.log"
  cp "$workdir/client-summary.out" "$artifact_dir/client-summary.out"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cp "$workdir/metrics.txt" "$artifact_dir/metrics.txt"
  cp "$summary_env" "$artifact_dir/dnssec-serve-summary.env"
fi
