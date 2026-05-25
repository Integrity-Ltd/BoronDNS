#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping negative NOTIFY interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/notify-negative-$$"
artifact_dir="${OXIDEDNS_NOTIFY_NEGATIVE_ARTIFACT_DIR:-}"
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
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -160 "$workdir/oxidedns.log" >&2; }
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

read -r primary_port oxidedns_dns_port oxidedns_notify_port oxidedns_health_port < <(
  python3 - <<'PY'
import socket

sockets = []
for _ in range(4):
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
summary_tsv="$workdir/notify-negative-summary.tsv"
traceability_tsv="$workdir/notify-traceability.tsv"
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
ZONE = "notify-negative.test."
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
    return qname, qtype, qclass


def rr(owner, rrtype, rdata, ttl=300):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052501):
    return b"".join([
        name_wire("ns1.notify-negative.test."),
        name_wire("hostmaster.notify-negative.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 300),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata(), ttl=3600)
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.notify-negative.test.")),
        rr("ns1.notify-negative.test.", A, bytes([127, 0, 0, 1])),
        rr("www.notify-negative.test.", A, bytes([192, 0, 2, 80])),
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
        qname, qtype, qclass = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8005, 0, 0, 0, 0)
        else:
            log(f"TCP AXFR served zone={ZONE} records={len(zone_records())}")
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
import time

DNS_HOST = "127.0.0.1"
DNS_PORT = int(sys.argv[1])
NOTIFY_PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]
SUMMARY_PATH = sys.argv[4]
IN = 1
A = 1
SOA = 6
TSIG = 250
RCODES = {0: "NOERROR", 1: "FORMERR", 5: "REFUSED", 9: "NOTAUTH"}
TSIG_ERRORS = {17: "BADKEY", 18: "BADTIME", 22: "BADTRUNC", 23: "BADALG"}


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


def query_packet(qid, qname, qtype):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", qtype, IN)
    )


def soa_rdata(serial):
    return b"".join([
        name_wire("ns1.notify-negative.test."),
        name_wire("hostmaster.notify-negative.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 300),
    ])


def notify_packet(qid, qname, qtype=SOA, serial=None):
    answer = b""
    ancount = 0
    if serial is not None:
        rdata = soa_rdata(serial)
        answer = (
            name_wire(qname)
            + struct.pack("!HHIH", SOA, IN, 0, len(rdata))
            + rdata
        )
        ancount = 1
    return (
        struct.pack("!HHHHHH", qid, 0x2000, 1, ancount, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", qtype, IN)
        + answer
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


def skip_rrs(packet, offset, count):
    for _ in range(count):
        offset += skip_name(packet, offset)
        rrtype, _rrclass, _ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10 + rdlen
        if rrtype == TSIG:
            raise AssertionError("TSIG appeared before additional section")
    return offset


def parse_name(packet, offset):
    labels = []
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels) + ".", offset
        if length & 0xC0:
            raise AssertionError("unexpected compressed name in TSIG RDATA")
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length


def parse_tsig_error(packet, offset, count):
    for _ in range(count):
        offset += skip_name(packet, offset)
        rrtype, _rrclass, _ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata_offset = offset
        if rrtype == TSIG:
            _algorithm, cursor = parse_name(packet, rdata_offset)
            cursor += 6
            cursor += 2
            mac_len = struct.unpack("!H", packet[cursor:cursor + 2])[0]
            cursor += 2 + mac_len
            original_id, error = struct.unpack("!HH", packet[cursor:cursor + 4])
            return original_id, error
        offset += rdlen
    return None


def response_summary(packet):
    if len(packet) < 12:
        raise AssertionError("short DNS response")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    rcode = flags & 0x000F
    qr = bool(flags & 0x8000)
    aa = bool(flags & 0x0400)
    opcode = (flags >> 11) & 0x0F
    offset = 12
    qname = ""
    qtype = None
    qclass = None
    if qdcount:
        qname, offset = parse_name(packet, offset)
        qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
        offset += 4
    for _ in range(max(0, qdcount - 1)):
        offset += skip_name(packet, offset) + 4
    offset = skip_rrs(packet, offset, ancount)
    offset = skip_rrs(packet, offset, nscount)
    tsig = parse_tsig_error(packet, offset, arcount)
    return {
        "id": qid,
        "qr": qr,
        "aa": aa,
        "opcode": opcode,
        "rcode": rcode,
        "rcode_name": RCODES.get(rcode, str(rcode)),
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
        "tsig": tsig,
    }


def udp_exchange(port, packet, bind_addr="127.0.0.1", timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind((bind_addr, 0))
    try:
        sock.sendto(packet, (DNS_HOST, port))
        return sock.recvfrom(4096)[0]
    except socket.timeout:
        return None
    finally:
        sock.close()


def tcp_exchange(port, packet, bind_addr="127.0.0.1", timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.bind((bind_addr, 0))
    try:
        sock.connect((DNS_HOST, port))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        length_prefix = sock.recv(2)
        if len(length_prefix) != 2:
            raise AssertionError("short TCP length prefix")
        response_len = struct.unpack("!H", length_prefix)[0]
        response = bytearray()
        while len(response) < response_len:
            chunk = sock.recv(response_len - len(response))
            if not chunk:
                raise AssertionError("short TCP response")
            response.extend(chunk)
        return bytes(response)
    except socket.timeout:
        return None
    finally:
        sock.close()


def wait_active():
    deadline = time.monotonic() + 10
    request = query_packet(0x1001, "www.notify-negative.test.", A)
    while time.monotonic() < deadline:
        response = udp_exchange(DNS_PORT, request, timeout=0.25)
        if response is not None:
            summary = response_summary(response)
            if summary["rcode"] == 0:
                log("active zone query succeeded")
                return
        time.sleep(0.05)
    raise AssertionError("OxideDNS did not publish active notify-negative.test zone")


def assert_response(
    case,
    packet,
    expected_rcode,
    *,
    transport="udp",
    bind_addr="127.0.0.1",
    expected_tsig_error=None,
):
    if transport == "tcp":
        response = tcp_exchange(NOTIFY_PORT, packet, bind_addr=bind_addr)
    else:
        response = udp_exchange(NOTIFY_PORT, packet, bind_addr=bind_addr)
    if response is None:
        raise AssertionError(f"{case}: expected response")
    summary = response_summary(response)
    expected_qid = struct.unpack("!H", packet[:2])[0]
    expected_qname, expected_q_offset = parse_name(packet, 12)
    expected_qtype, expected_qclass = struct.unpack("!HH", packet[expected_q_offset:expected_q_offset + 4])
    if not summary["qr"] or summary["opcode"] != 4:
        raise AssertionError(f"{case}: unexpected header {summary}")
    if summary["id"] != expected_qid:
        raise AssertionError(f"{case}: expected qid {expected_qid}, got {summary}")
    if summary["qname"] != expected_qname or summary["qtype"] != expected_qtype or summary["qclass"] != expected_qclass:
        raise AssertionError(f"{case}: response question did not echo request question: {summary}")
    if summary["rcode"] != expected_rcode:
        raise AssertionError(f"{case}: expected rcode {expected_rcode}, got {summary}")
    if expected_rcode == 0 and not summary["aa"]:
        raise AssertionError(f"{case}: successful NOTIFY response did not set AA")
    if expected_tsig_error is not None:
        if summary["tsig"] is None:
            raise AssertionError(f"{case}: expected TSIG error")
        original_id, error = summary["tsig"]
        if original_id != summary["id"] or error != expected_tsig_error:
            raise AssertionError(f"{case}: unexpected TSIG fields {(original_id, error)}")
    return summary


def assert_discard(case, packet, *, bind_addr):
    response = udp_exchange(NOTIFY_PORT, packet, bind_addr=bind_addr, timeout=0.35)
    if response is not None:
        raise AssertionError(f"{case}: expected discard, got {response_summary(response)}")
    return {"rcode_name": "DISCARD"}


def main():
    wait_active()
    cases = [
        ("non_soa_question", "udp", notify_packet(0x2001, "notify-negative.test.", A), 1, None),
        ("unknown_zone", "udp", notify_packet(0x2002, "unknown.notify-negative.test.", SOA), 5, None),
        ("authorized_signalled", "udp", notify_packet(0x2003, "notify-negative.test.", SOA, serial=2026052502), 0, None),
        ("authorized_duplicate", "udp", notify_packet(0x2004, "notify-negative.test.", SOA, serial=2026052502), 0, None),
        ("tcp_authorized_duplicate", "tcp", notify_packet(0x2007, "notify-negative.test.", SOA, serial=2026052502), 0, None),
        ("missing_required_tsig", "udp", notify_packet(0x2005, "notify-signed.test.", SOA), 9, 17),
    ]
    rows = ["case\ttransport\trcode\ttsig_error"]
    for case, transport, packet, rcode, tsig_error in cases:
        summary = assert_response(
            case,
            packet,
            rcode,
            transport=transport,
            expected_tsig_error=tsig_error,
        )
        tsig_name = ""
        if summary["tsig"] is not None:
            tsig_name = TSIG_ERRORS.get(summary["tsig"][1], str(summary["tsig"][1]))
        rows.append(f"{case}\t{transport}\t{summary['rcode_name']}\t{tsig_name}")
        log(f"{case} transport={transport} rcode={summary['rcode_name']} tsig_error={tsig_name}")

    discard = assert_discard(
        "unauthorized_source",
        notify_packet(0x2006, "notify-negative.test.", SOA),
        bind_addr="127.0.0.2",
    )
    rows.append(f"unauthorized_source\tudp\t{discard['rcode_name']}\t")
    log("unauthorized_source discarded")

    with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
        handle.write("\n".join(rows) + "\n")
    print("notify_negative_cases=7")


if __name__ == "__main__":
    main()
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"
log_format = "logfmt"

[interfaces]
notify = ["127.0.0.1:$oxidedns_notify_port"]

[rrl]
enabled = false

[limits]
max_udp_payload = 1232
max_concurrent_transfers = 2
axfr_timeout_secs = 2
ixfr_timeout_secs = 1
notify_dedup_secs = 60
notify_log_rate_window_secs = 60
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600
zsm_initial_retry_max_secs = 3600
graceful_shutdown_secs = 2

[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret = "dG9wc2VjcmV0"

[[zones]]
name = "notify-negative.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
notify_sources = ["127.0.0.1"]

[[zones]]
name = "notify-signed.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
notify_sources = ["127.0.0.1"]
tsig_key = "transfer-key."
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
  echo "fake NOTIFY primary did not become ready" >&2
  exit 1
fi

"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

live=0
for _ in {1..200}; do
  if curl -fsS "http://127.0.0.1:$oxidedns_health_port/livez" >/dev/null 2>&1; then
    live=1
    break
  fi
  sleep 0.05
done
if (( live != 1 )); then
  echo "OxideDNS did not become live during negative NOTIFY interop" >&2
  exit 1
fi

client_summary="$(python3 "$client" "$oxidedns_dns_port" "$oxidedns_notify_port" "$client_log" "$summary_tsv")"
sleep 0.2
metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_notify_messages_received_total 7' \
  'oxidedns_notify_messages_unauthorized_total 1' \
  'oxidedns_notify_refresh_actions_total{action="signalled"} 1' \
  'oxidedns_notify_refresh_actions_total{action="deduplicated"} 2' \
  'oxidedns_tsig_notify_verifications_total{result="badkey"} 1'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected negative NOTIFY line: $expected" >&2
    exit 1
  fi
done

for expected_log in \
  'message="accepted NOTIFY" source=127.0.0.1 zone=notify-negative.test. soa_serial="Some(2026052502)" action=refresh_signalled' \
  'message="accepted NOTIFY" source=127.0.0.1 zone=notify-negative.test. soa_serial="Some(2026052502)" action=deduplicated' \
  'event=notify_unauthorized_discard' \
  'event=notify_tsig_failure'; do
  if ! grep -q "$expected_log" "$workdir/oxidedns.log"; then
    echo "OxideDNS log missing expected negative NOTIFY event: $expected_log" >&2
    exit 1
  fi
done

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_state	runtime_case	artifacts	review_note
ODS-FR-NOTIFY-001	retained-runtime	tcp_and_udp_notify_reception	notify-negative-summary.tsv; oxidedns.toml; crates/oxidedns-server/src/lib.rs::runtime_serves_queries_and_notify_on_configured_notify_interface	This harness receives NOTIFY on a configured notify listener over both UDP and TCP, with focused runtime coverage for the same configured listener.
ODS-FR-NOTIFY-002	retained-runtime	non_soa_question	notify-negative-summary.tsv; client.log	A NOTIFY with QTYPE=A receives FORMERR with QID, opcode, and question echoed.
ODS-FR-NOTIFY-003	retained-runtime	unknown_zone	notify-negative-summary.tsv; client.log	A NOTIFY for an unconfigured zone receives REFUSED and no refresh action is expected.
ODS-FR-NOTIFY-004	retained-runtime	unauthorized_source_discard	notify-negative-summary.tsv; metrics.txt; oxidedns.log	An unauthorized source receives no response, increments unauthorized metrics, and emits the warning log.
ODS-FR-NOTIFY-005	retained-runtime-plus-support	missing_required_tsig	notify-negative-summary.tsv; metrics.txt; oxidedns.log; crates/oxidedns-server/src/lib.rs notify TSIG tests	A signed zone receiving an unsigned authorized NOTIFY returns NOTAUTH with BADKEY TSIG evidence; broader TSIG failure classes are covered by focused tests.
ODS-FR-NOTIFY-006	retained-runtime	accepted_notify_response	notify-negative-summary.tsv; client.log	Accepted and duplicate NOTIFY messages over UDP and TCP receive QR=1, OPCODE=NOTIFY, AA=1, NOERROR responses with QID and question echoed.
ODS-FR-NOTIFY-007	retained-runtime	accepted_refresh_signalled	metrics.txt; oxidedns.log	The first accepted NOTIFY records action=refresh_signalled and increments the refresh signalled metric.
ODS-FR-NOTIFY-008	retained-runtime-plus-support	embedded_soa_serial	notify-negative-summary.tsv; oxidedns.log; crates/oxidedns-core/src/dns.rs notify embedded SOA tests	The accepted NOTIFY carries embedded SOA serial 2026052502 and logs it; malformed owner/class and timer-field isolation remain covered by focused tests.
ODS-FR-NOTIFY-009	retained-runtime	duplicate_deduplicated	notify-negative-summary.tsv; metrics.txt; oxidedns.log	A duplicate well-formed NOTIFY still receives a response but records action=deduplicated and does not create a second signalled metric.
ODS-FR-NOTIFY-010	retained-runtime	notify_logging	oxidedns.log	Accepted, deduplicated, unauthorized, and TSIG-failure paths have retained log evidence with action, source, zone, and serial where applicable.
ODS-FR-NOTIFY-011	retained-runtime-plus-support	first_warning_and_rate_limit_foundation	oxidedns.log; crates/oxidedns-server/src/lib.rs::notify_log_limiter_suppresses_repeats_and_summarizes	This harness retains first warning logs for unauthorized and TSIG-failure cases; suppression and periodic aggregate behavior remain covered by focused log-limiter tests.
EOF

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$client_log" "$artifact_dir/client.log"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cp "$summary_tsv" "$artifact_dir/notify-negative-summary.tsv"
  cp "$traceability_tsv" "$artifact_dir/notify-traceability.tsv"
  printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
fi

printf '%s\n' "$client_summary"
