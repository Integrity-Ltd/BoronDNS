#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping malformed-query evidence: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/malformed-query-evidence/$$"
artifact_dir="${BORONDNS_MALFORMED_QUERY_EVIDENCE_DIR:-}"
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
primary_log="$workdir/fake-primary.log"
client_log="$workdir/client.log"
borondns_conf="$workdir/borondns.toml"
summary_env="$workdir/malformed-query-summary.env"
results_tsv="$workdir/malformed-query-results.tsv"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "malformed.test."
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


def rr(owner, rrtype, rdata, ttl=60):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052503):
    return b"".join([
        name_wire("ns1.malformed.test."),
        name_wire("hostmaster.malformed.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.malformed.test.")),
        rr("ns1.malformed.test.", A, bytes([127, 0, 0, 1])),
        rr("www.malformed.test.", A, bytes([192, 0, 2, 44])),
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
            log(f"TCP AXFR served records={len(answers)}")
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
RESULTS_PATH = sys.argv[3]
SUMMARY_PATH = sys.argv[4]
IN = 1
A = 1


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


def query(qid, qname="www.malformed.test.", qtype=A, qclass=IN):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", qtype, qclass)
    )


def append_opt(packet, payload_size, ttl, rdata):
    return packet + b"\x00" + struct.pack("!HHIH", 41, payload_size, ttl, len(rdata)) + rdata


def malformed_cases():
    cases = []
    for length in range(0, 33):
        packet = bytes(((index * 37 + length * 11) & 0xFF) for index in range(length))
        cases.append((f"deterministic-short-{length:02d}", packet))
    cases.extend([
        ("compression-self-pointer", query(0x7101, qname="example.test.")[:12] + b"\xc0\x0c" + struct.pack("!HH", A, IN)),
        ("compression-out-of-range", query(0x7102, qname="example.test.")[:12] + b"\xc0\xff" + struct.pack("!HH", A, IN)),
        ("truncated-label", query(0x7103, qname="example.test.")[:12] + b"\x3ftruncated-label" + struct.pack("!HH", A, IN)),
        ("label-pointer-loop", query(0x7104, qname="example.test.")[:12] + b"\x04loop\xc0\x0c" + struct.pack("!HH", A, IN)),
        ("invalid-label-octet", query(0x7105, qname="example.test.")[:12] + b"\xff" + struct.pack("!HH", A, IN)),
    ])
    qdcount_overflow = bytearray(query(0x7106))
    qdcount_overflow[4:6] = (2).to_bytes(2, "big")
    cases.append(("qdcount-overflow", bytes(qdcount_overflow)))
    truncated_extra = bytearray(query(0x7107))
    truncated_extra[10:12] = (1).to_bytes(2, "big")
    truncated_extra.append(0)
    cases.append(("truncated-extra-section", bytes(truncated_extra)))
    cases.append(("malformed-opt-rdata", append_opt(query(0x7108), 4096, 0, b"\x00\x01\x00")))
    response_packet = bytearray(query(0x7109))
    response_packet[2] = 0x80
    cases.append(("response-on-query-port", bytes(response_packet)))
    unsupported_opcode = bytearray(query(0x710A))
    unsupported_opcode[2] = 0x78
    cases.append(("unsupported-opcode", bytes(unsupported_opcode)))
    return cases


def udp_exchange(packet, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (HOST, PORT))
    try:
        response, _ = sock.recvfrom(4096)
        return response
    except socket.timeout:
        return None
    finally:
        sock.close()


def tcp_exchange(packet, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((HOST, PORT))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        header = sock.recv(2)
        if len(header) != 2:
            return None
        length = struct.unpack("!H", header)[0]
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data) if data else None
    except (ConnectionError, OSError, socket.timeout):
        return None
    finally:
        sock.close()


def classify(response):
    if response is None:
        return "no_response", 0, ""
    if len(response) < 4:
        return "short_response", len(response), ""
    rcode = response[3] & 0x0F
    return "response", len(response), str(rcode)


def assert_valid_query(label):
    response = udp_exchange(query(0x7000), 1.0)
    if response is None:
        raise AssertionError(f"{label}: valid query timed out")
    if len(response) < 12:
        raise AssertionError(f"{label}: valid query returned short response")
    qid, flags, qdcount, ancount = struct.unpack("!HHHH", response[:8])
    if qid != 0x7000 or (flags & 0x000F) != 0 or qdcount != 1 or ancount != 1:
        raise AssertionError(
            f"{label}: unexpected valid response qid={qid} flags=0x{flags:04x} qd={qdcount} an={ancount}"
        )
    return len(response)


before_bytes = assert_valid_query("before-corpus")
rows = ["case\ttransport\tinput_bytes\toutcome\tresponse_bytes\trcode"]
udp_responses = 0
tcp_responses = 0
cases = malformed_cases()
for name, packet in cases:
    udp_response = udp_exchange(packet, 0.05)
    outcome, response_bytes, rcode = classify(udp_response)
    if outcome == "response":
        udp_responses += 1
    rows.append(f"{name}\tudp\t{len(packet)}\t{outcome}\t{response_bytes}\t{rcode}")

    tcp_response = tcp_exchange(packet, 0.05)
    outcome, response_bytes, rcode = classify(tcp_response)
    if outcome == "response":
        tcp_responses += 1
    rows.append(f"{name}\ttcp\t{len(packet)}\t{outcome}\t{response_bytes}\t{rcode}")

after_bytes = assert_valid_query("after-corpus")
with open(RESULTS_PATH, "w", encoding="utf-8") as handle:
    handle.write("\n".join(rows) + "\n")
with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
    handle.write(f"malformed_cases={len(cases)}\n")
    handle.write(f"udp_cases={len(cases)}\n")
    handle.write(f"tcp_cases={len(cases)}\n")
    handle.write(f"udp_responses={udp_responses}\n")
    handle.write(f"tcp_responses={tcp_responses}\n")
    handle.write("valid_query_before=1\n")
    handle.write(f"valid_query_before_bytes={before_bytes}\n")
    handle.write("valid_query_after=1\n")
    handle.write(f"valid_query_after_bytes={after_bytes}\n")
log(f"malformed_cases={len(cases)} udp_responses={udp_responses} tcp_responses={tcp_responses}")
print(f"malformed query evidence passed cases={len(cases)}")
PY

cat >"$borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "warn"
log_format = "plain"

[rrl]
enabled = false

[limits]
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "malformed.test."
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
    echo "malformed-query fake primary did not become ready" >&2
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
    echo "BoronDNS did not become ready for malformed-query evidence" >&2
    exit 1
fi

curl -fsS "http://127.0.0.1:$borondns_health_port/livez" >"$workdir/livez-before.txt"
curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" >"$workdir/readyz-before.txt"
python3 "$client" "$borondns_dns_port" "$client_log" "$results_tsv" "$summary_env"
curl -fsS "http://127.0.0.1:$borondns_health_port/livez" >"$workdir/livez-after.txt"
curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" >"$workdir/readyz-after.txt"
curl -fsS "http://127.0.0.1:$borondns_health_port/metrics" >"$workdir/metrics.txt"

if grep -Ei 'panic|panicked|thread .* panicked' "$workdir/borondns.log" >"$workdir/panic-scan.txt"; then
    echo "BoronDNS log contains panic evidence after malformed query corpus" >&2
    cat "$workdir/panic-scan.txt" >&2
    exit 1
fi
touch "$workdir/panic-scan.txt"

{
    cat "$summary_env"
    printf 'livez_after=1\n'
    printf 'readyz_after=1\n'
    printf 'panic_log_findings=0\n'
} >"$workdir/malformed-query-evidence-summary.env"

cat "$workdir/malformed-query-evidence-summary.env"

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$client_log" "$artifact_dir/client.log"
    cp "$workdir/borondns.log" "$artifact_dir/borondns.log"
    cp "$borondns_conf" "$artifact_dir/borondns.toml"
    cp "$results_tsv" "$artifact_dir/malformed-query-results.tsv"
    cp "$workdir/malformed-query-evidence-summary.env" "$artifact_dir/malformed-query-summary.env"
    cp "$workdir/livez-before.txt" "$artifact_dir/livez-before.txt"
    cp "$workdir/readyz-before.txt" "$artifact_dir/readyz-before.txt"
    cp "$workdir/livez-after.txt" "$artifact_dir/livez-after.txt"
    cp "$workdir/readyz-after.txt" "$artifact_dir/readyz-after.txt"
    cp "$workdir/metrics.txt" "$artifact_dir/metrics.txt"
    cp "$workdir/panic-scan.txt" "$artifact_dir/panic-scan.txt"
fi
