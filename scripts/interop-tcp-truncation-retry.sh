#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping TCP truncation retry interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/tcp-truncation-retry-$$"
artifact_dir="${BORONDNS_TCP_TRUNCATION_ARTIFACT_DIR:-}"
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
        [[ -f "$workdir/client.log" ]] && {
            echo "---- client.log ----" >&2
            tail -120 "$workdir/client.log" >&2
        }
        [[ -f "$workdir/borondns.log" ]] && {
            echo "---- borondns.log ----" >&2
            tail -120 "$workdir/borondns.log" >&2
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
client="$workdir/client.py"
drain_client="$workdir/drain-client.py"
primary_log="$workdir/fake-primary.log"
client_log="$workdir/client.log"
borondns_conf="$workdir/borondns.toml"
limit_summary_path="$workdir/tcp-limit-summary.env"
pipeline_summary_path="$workdir/tcp-pipeline-summary.env"
timeout_summary_path="$workdir/tcp-timeout-summary.env"
drain_summary_path="$workdir/graceful-drain-summary.env"
readyz_draining_path="$workdir/readyz-draining.txt"
traceability_path="$workdir/tcp-transport-traceability.tsv"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "tcp.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252
LARGE_RRSET = 96


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


def rr(owner, rrtype, rdata, ttl=60):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052501):
    return b"".join([
        name_wire("ns1.tcp.test."),
        name_wire("hostmaster.tcp.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    records = [
        soa,
        rr(ZONE, NS, name_wire("ns1.tcp.test.")),
        rr("ns1.tcp.test.", A, bytes([127, 0, 0, 1])),
    ]
    for index in range(LARGE_RRSET):
        records.append(rr("large.tcp.test.", A, bytes([192, 0, 2, index + 1])))
    records.append(soa)
    return records


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
            response = struct.pack("!HHHHHH", qid, 0x8004, 0, 0, 0, 0)
        else:
            log(f"TCP AXFR served records={len(zone_records())}")
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

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
LIMIT_SUMMARY_PATH = sys.argv[3]
PIPELINE_SUMMARY_PATH = sys.argv[4]
TIMEOUT_SUMMARY_PATH = sys.argv[5]
LARGE_QNAME = "large.tcp.test."
SMALL_QNAME = "ns1.tcp.test."
A = 1
IN = 1


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


def query(qid, qname=LARGE_QNAME):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", A, IN)
    )


def read_tcp_response(tcp):
    header = tcp.recv(2)
    if len(header) != 2:
        raise AssertionError("short TCP length prefix")
    length = struct.unpack("!H", header)[0]
    chunks = bytearray()
    while len(chunks) < length:
        chunk = tcp.recv(length - len(chunks))
        if not chunk:
            raise AssertionError("short TCP response")
        chunks.extend(chunk)
    return bytes(chunks)


def frame(packet):
    return struct.pack("!H", len(packet)) + packet


def response_id(packet):
    return struct.unpack("!H", packet[:2])[0]


def expect_close(tcp, label, timeout=3.0):
    tcp.settimeout(timeout)
    started = time.monotonic()
    try:
        data = tcp.recv(1)
    except ConnectionResetError:
        data = b""
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if data:
        raise AssertionError(f"{label} returned data instead of closing")
    return elapsed_ms


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


def answer_count(packet):
    flags, qdcount, ancount = struct.unpack("!HHH", packet[2:8])
    if flags & 0x000F:
        raise AssertionError(f"unexpected rcode={flags & 0x000F}")
    offset = 12
    for _ in range(qdcount):
        offset += skip_name(packet, offset) + 4
    count = 0
    for _ in range(ancount):
        offset += skip_name(packet, offset)
        rrtype, _, _, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if rrtype == A and rdlength == 4:
            count += 1
        offset += rdlength
    return count


udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(2.0)
udp.sendto(query(0x6001), (HOST, PORT))
udp_response, _ = udp.recvfrom(4096)
udp_flags = struct.unpack("!H", udp_response[2:4])[0]
if udp_flags & 0x000F:
    raise AssertionError(f"UDP response rcode={udp_flags & 0x000F}")
if not (udp_flags & 0x0200):
    raise AssertionError(f"UDP response was not truncated length={len(udp_response)}")

tcp = socket.create_connection((HOST, PORT), timeout=2.0)
tcp_query = query(0x6002)
tcp.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
tcp_response = read_tcp_response(tcp)
tcp_flags = struct.unpack("!H", tcp_response[2:4])[0]
if tcp_flags & 0x0200:
    raise AssertionError("TCP response unexpectedly had TC=1")
tcp_answers = answer_count(tcp_response)
if tcp_answers < 80:
    raise AssertionError(f"TCP response returned too few A answers: {tcp_answers}")
tcp.close()

idle_probe = socket.create_connection((HOST, PORT), timeout=2.0)
idle_close_ms = expect_close(idle_probe, "idle TCP timeout")
idle_probe.close()

read_probe = socket.create_connection((HOST, PORT), timeout=2.0)
read_probe.sendall(struct.pack("!H", 32))
read_close_ms = expect_close(read_probe, "partial-frame TCP read timeout")
read_probe.close()

timeout_summary = (
    "idle_timeout_closed=1 "
    f"idle_timeout_close_ms={idle_close_ms} "
    "partial_frame_read_timeout_closed=1 "
    f"partial_frame_read_timeout_close_ms={read_close_ms}"
)
with open(TIMEOUT_SUMMARY_PATH, "w", encoding="utf-8") as handle:
    print(timeout_summary, file=handle)
log(timeout_summary)

pipeline = socket.create_connection((HOST, PORT), timeout=2.0)
pipeline_queries = [
    query(0x6101, LARGE_QNAME),
    query(0x6102, SMALL_QNAME),
]
pipeline_start = time.monotonic()
pipeline.sendall(b"".join(frame(packet) for packet in pipeline_queries))
first_pipeline_response = read_tcp_response(pipeline)
first_pipeline_ms = int((time.monotonic() - pipeline_start) * 1000)
second_pipeline_response = read_tcp_response(pipeline)
second_pipeline_ms = int((time.monotonic() - pipeline_start) * 1000)
pipeline.close()
pipeline_responses = [first_pipeline_response, second_pipeline_response]
pipeline_ids = [response_id(packet) for packet in pipeline_responses]
if sorted(pipeline_ids) != [0x6101, 0x6102]:
    raise AssertionError(f"pipelined TCP response IDs did not match requests: {pipeline_ids}")
pipeline_answer_counts = {response_id(packet): answer_count(packet) for packet in pipeline_responses}
if pipeline_answer_counts[0x6101] < 80:
    raise AssertionError(f"pipelined large answer too small: {pipeline_answer_counts[0x6101]}")
if pipeline_answer_counts[0x6102] != 1:
    raise AssertionError(f"pipelined small answer count mismatch: {pipeline_answer_counts[0x6102]}")
pipeline_out_of_order = 1 if pipeline_ids == [0x6102, 0x6101] else 0
if pipeline_out_of_order != 1:
    raise AssertionError(f"pipelined responses were not inverted for large-then-small query evidence: {pipeline_ids}")
pipeline_summary = (
    "pipelined_queries=2 pipelined_responses=2 intentional_first_large_second_small=1 "
    f"pipelined_response_ids={','.join(hex(item) for item in pipeline_ids)} "
    f"pipelined_out_of_order={pipeline_out_of_order} "
    f"pipelined_first_response_ms={first_pipeline_ms} "
    f"pipelined_second_response_ms={second_pipeline_ms} "
    f"pipelined_first_response_bytes={len(first_pipeline_response)} "
    f"pipelined_second_response_bytes={len(second_pipeline_response)} "
    f"pipelined_large_a_answers={pipeline_answer_counts[0x6101]} "
    f"pipelined_small_a_answers={pipeline_answer_counts[0x6102]}"
)
with open(PIPELINE_SUMMARY_PATH, "w", encoding="utf-8") as handle:
    print(pipeline_summary, file=handle)
log(pipeline_summary)

holder = socket.create_connection((HOST, PORT), timeout=2.0)
holder_query = query(0x6003)
holder.sendall(struct.pack("!H", len(holder_query)) + holder_query)
holder_response = read_tcp_response(holder)
if struct.unpack("!H", holder_response[2:4])[0] & 0x000F:
    raise AssertionError("holder TCP response had non-zero RCODE")

started = time.monotonic()
overflow = socket.create_connection((HOST, PORT), timeout=2.0)
overflow.settimeout(2.0)
try:
    overflow_data = overflow.recv(1)
except ConnectionResetError:
    overflow_data = b""
elapsed_ms = int((time.monotonic() - started) * 1000)
overflow.close()
holder.close()
if overflow_data:
    raise AssertionError("over-limit TCP connection returned data instead of closing")

limit_summary = f"over_limit_closed=1 over_limit_close_ms={elapsed_ms}"
with open(LIMIT_SUMMARY_PATH, "w", encoding="utf-8") as handle:
    print(limit_summary, file=handle)
log(limit_summary)

summary = (
    f"udp_truncated=1 udp_response_bytes={len(udp_response)} "
    f"tcp_truncated=0 tcp_response_bytes={len(tcp_response)} tcp_a_answers={tcp_answers} "
    f"{timeout_summary} {pipeline_summary} {limit_summary}"
)
log(summary)
print(summary)
PY

cat >"$drain_client" <<'PY'
#!/usr/bin/env python3
import os
import signal
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
HEALTH_PORT = int(sys.argv[2])
BORONDNS_PID = int(sys.argv[3])
DRAIN_SUMMARY_PATH = sys.argv[4]
READYZ_DRAINING_PATH = sys.argv[5]
QNAME = "large.tcp.test."
A = 1
IN = 1


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def query(qid):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(QNAME)
        + struct.pack("!HH", A, IN)
    )


def read_tcp_response(tcp):
    length = struct.unpack("!H", tcp.recv(2))[0]
    chunks = bytearray()
    while len(chunks) < length:
        chunk = tcp.recv(length - len(chunks))
        if not chunk:
            raise AssertionError("short TCP response during drain")
        chunks.extend(chunk)
    return bytes(chunks)


def readyz_body():
    url = f"http://{HOST}:{HEALTH_PORT}/readyz"
    try:
        with urllib.request.urlopen(url, timeout=0.2) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


drain_socket = socket.create_connection((HOST, PORT), timeout=2.0)
drain_query = query(0x6004)
drain_socket.sendall(struct.pack("!H", len(drain_query)) + drain_query)

start = time.monotonic()
os.kill(BORONDNS_PID, signal.SIGTERM)
draining_status = None
draining_body = ""
while time.monotonic() - start < 2.0:
    status, body = readyz_body()
    if status == 503 and '"status":"draining"' in body:
        draining_status = status
        draining_body = body
        break
    time.sleep(0.02)
if draining_status != 503:
    raise AssertionError("readyz did not report draining after SIGTERM")
draining_ms = int((time.monotonic() - start) * 1000)
with open(READYZ_DRAINING_PATH, "w", encoding="utf-8") as handle:
    print(draining_body, file=handle)

connect_start = time.monotonic()
new_connection_closed = 0
try:
    probe = socket.create_connection((HOST, PORT), timeout=0.2)
    probe.settimeout(0.2)
    data = probe.recv(1)
    new_connection_closed = 1 if not data else 0
    probe.close()
except OSError:
    new_connection_closed = 1
new_connection_ms = int((time.monotonic() - connect_start) * 1000)
if new_connection_closed != 1:
    raise AssertionError("new TCP connection stayed open during drain")

drain_response = read_tcp_response(drain_socket)
drain_socket.close()
if struct.unpack("!H", drain_response[2:4])[0] & 0x000F:
    raise AssertionError("drained TCP response had non-zero RCODE")

summary = (
    f"readyz_draining=1 readyz_draining_ms={draining_ms} "
    f"new_tcp_rejected_or_closed=1 new_tcp_rejected_or_closed_ms={new_connection_ms} "
    f"drained_response_bytes={len(drain_response)}"
)
with open(DRAIN_SUMMARY_PATH, "w", encoding="utf-8") as handle:
    print(summary, file=handle)
print(summary)
PY

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
max_udp_payload = 512
max_concurrent_transfers = 1
max_tcp_connections = 1
max_tcp_inflight_queries_per_connection = 64
tcp_inflight_limit_timeout_secs = 1
tcp_idle_timeout_secs = 1
tcp_read_timeout_secs = 1
tcp_write_timeout_secs = 5
tcp_connect_timeout_secs = 10
graceful_shutdown_secs = 2
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "tcp.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

cargo build -p borondns-cli >/dev/null

python3 "$fake_primary" "$primary_port" "$primary_log" &
primary_pid=$!

for _ in {1..100}; do
    if grep -q "READY" "$primary_log" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
if ! grep -q "READY" "$primary_log" 2>/dev/null; then
    echo "fake TCP truncation primary did not become ready" >&2
    exit 1
fi

"$repo_root/target/debug/borondns" serve --config "$borondns_conf" >"$workdir/borondns.log" 2>&1 &
borondns_pid=$!

ready=0
for _ in {1..200}; do
    if curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.05
done
if ((ready != 1)); then
    echo "BoronDNS did not become ready during TCP truncation retry interop" >&2
    exit 1
fi

client_summary="$(python3 "$client" "$borondns_dns_port" "$client_log" "$limit_summary_path" "$pipeline_summary_path" "$timeout_summary_path")"
metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
for expected in \
    'borondns_zones_active 1' \
    'borondns_secondary_queries_total{zone="tcp.test."} 5' \
    'borondns_secondary_query_responses_total{zone="tcp.test.",rcode="NOERROR"} 5' \
    'borondns_queries_truncated_total 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "metrics missing expected TCP truncation retry line: $expected" >&2
        exit 1
    fi
done

drain_summary="$(python3 "$drain_client" "$borondns_dns_port" "$borondns_health_port" "$borondns_pid" "$drain_summary_path" "$readyz_draining_path")"
wait "$borondns_pid"
borondns_pid=""

for expected in \
    'TCP connection limit reached; closing accepted connection' \
    'shutdown signal received; draining runtime' \
    'TCP connection drain completed'; do
    if ! grep -q "$expected" "$workdir/borondns.log"; then
        echo "BoronDNS log missing expected TCP evidence line: $expected" >&2
        exit 1
    fi
done

cat >"$traceability_path" <<'EOF'
requirement_id	evidence_state	runtime_case	artifacts	review_note
ODS-FR-TCP-001	retained-runtime	tcp_framing_and_multi_message_exchange	client-summary.env; tcp-pipeline-summary.env; fake-primary.log	TCP client and fake primary exchange DNS messages using the two-octet length prefix; one connection carries multiple independently framed queries.
ODS-FR-TCP-002	retained-runtime	tcp_persistence_until_shutdown	tcp-pipeline-summary.env; graceful-drain-summary.env; readyz-draining.txt; borondns.log	The pipelined connection remains open for subsequent queries, and an accepted TCP query completes after SIGTERM while new TCP traffic is rejected or closed.
ODS-FR-TCP-003	retained-runtime	idle_timeout_close	tcp-timeout-summary.env; borondns.toml; crates/borondns-server/src/lib.rs::tcp_connection_closes_after_idle_timeout	The retained config applies a one-second idle timeout, and the harness records server-side closure of a TCP connection that sends no data.
ODS-FR-TCP-004	retained-runtime-plus-support	partial_frame_read_timeout_close	tcp-timeout-summary.env; borondns.toml; crates/borondns-server/src/lib.rs::tcp_connection_closes_after_read_timeout_mid_frame; crates/borondns-server/src/lib.rs::tcp_write_times_out_when_backpressured	The runtime harness records closure of a connection stalled after the two-octet length prefix; focused unit tests cover both read-timeout and write-timeout failure paths.
ODS-FR-TCP-005	retained-runtime	over_limit_connection_close	tcp-limit-summary.env; borondns.toml; borondns.log	The retained config sets max_tcp_connections=1; a second accepted connection is promptly closed and the expected warning log is present.
ODS-FR-TCP-006	supporting-unit	optional_per_source_cap	crates/borondns-core/src/config.rs::parses_custom_tcp_connection_limit; crates/borondns-core/src/config.rs::rejects_zero_tcp_connection_limit; crates/borondns-server/src/lib.rs::tcp_listener_closes_connections_over_per_source_limit; docs/engineering-mvp-scope.md; config/borondns.example.toml	The SRS makes per-source TCP connection limits optional with default no per-source cap; focused config and listener tests cover the configured per-source cap path and prompt close behavior.
ODS-FR-TCP-007	retained-runtime	pipelined_large_then_small_out_of_order	tcp-pipeline-summary.env; client.log	Two in-flight queries on one TCP connection return matching QIDs, and the intentionally smaller second query is answered before the larger first query.
ODS-FR-TCP-008	retained-runtime	udp_truncation_tcp_complete_retry	client-summary.env; metrics.txt	For the same large answer, UDP returns TC=1 at the 512-octet ceiling while TCP returns an untruncated response with the complete A RRset.
ODS-FR-TCP-009	retained-runtime	outbound_axfr_tcp_framing	fake-primary.log; borondns.log; client-summary.env	The fake primary accepts only length-framed TCP AXFR; successful load plus served large RRset proves the outbound transfer path used TCP framing.
ODS-FR-TCP-010	supporting-unit-plus-runtime	successful_outbound_tcp_connect_with_configured_timeout	borondns.toml; crates/borondns-core/src/config.rs::parses_custom_tcp_idle_timeout; crates/borondns-core/src/config.rs::rejects_zero_tcp_read_or_write_timeout; crates/borondns-server/src/lib.rs::tcp_connect_timeout_abandons_pending_connect_attempt; docs/engineering-mvp-scope.md	The retained config records tcp_connect_timeout_secs=10 for outbound TCP transfer paths; focused config tests cover parsing/rejection and the pending-connect unit test proves abandoned connect attempts return a transfer timeout.
ODS-FR-TCP-011	supporting-unit-plus-runtime	pipelining_under_configured_cap	borondns.toml; tcp-pipeline-summary.env; crates/borondns-server/src/lib.rs::tcp_connection_closes_when_inflight_limit_stays_saturated; crates/borondns-core/src/config.rs::parses_custom_tcp_connection_limit	The retained config records max_tcp_inflight_queries_per_connection=64 and the harness verifies two concurrent in-flight queries below the cap; the focused saturation test holds the only per-connection permit, lets the configured timeout elapse, and proves the second query is not answered before closure.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$client_log" "$artifact_dir/client.log"
    cp "$workdir/borondns.log" "$artifact_dir/borondns.log"
    cp "$borondns_conf" "$artifact_dir/borondns.toml"
    printf '%s\n' "$client_summary" >"$artifact_dir/client-summary.env"
    cp "$limit_summary_path" "$artifact_dir/tcp-limit-summary.env"
    cp "$pipeline_summary_path" "$artifact_dir/tcp-pipeline-summary.env"
    cp "$timeout_summary_path" "$artifact_dir/tcp-timeout-summary.env"
    cp "$drain_summary_path" "$artifact_dir/graceful-drain-summary.env"
    cp "$readyz_draining_path" "$artifact_dir/readyz-draining.txt"
    cp "$traceability_path" "$artifact_dir/tcp-transport-traceability.tsv"
    printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
fi

printf '%s\n' "$client_summary"
printf '%s\n' "$drain_summary"
