#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping Knot IXFR refresh interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping Knot IXFR refresh interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"
workdir="$repo_root/target/interop/knot-ixfr-refresh-$$"
container="oxidedns-knot-ixfr-refresh-$$"
artifact_dir="${OXIDEDNS_KNOT_IXFR_ARTIFACT_DIR:-}"
knot_image="$(ensure_alpine_knot_image)"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if [[ -n "${proxy_pid:-}" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid" 2>/dev/null || true
        wait "$proxy_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- knot container logs ----" >&2
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if ((status != 0)); then
        [[ -f "$workdir/transfer-proxy.log" ]] && {
            echo "---- transfer-proxy.log ----" >&2
            tail -140 "$workdir/transfer-proxy.log" >&2
        }
        [[ -f "$workdir/transfer-proxy.stderr" ]] && {
            echo "---- transfer-proxy.stderr ----" >&2
            tail -140 "$workdir/transfer-proxy.stderr" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -140 "$workdir/oxidedns.log" >&2
        }
    else
        rm -rf "$workdir"
    fi
}
trap cleanup EXIT

read -r knot_port proxy_port oxidedns_dns_port oxidedns_health_port < <(
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

zone_file="$workdir/alpha.test.zone"
knot_conf="$workdir/knot.conf"
oxidedns_conf="$workdir/oxidedns.toml"
transfer_proxy="$workdir/transfer-proxy.py"
transfer_proxy_log="$workdir/transfer-proxy.log"
primary_initial_soa_out="$workdir/primary-initial-soa.out"
readyz_out="$workdir/readyz.txt"
oxidedns_initial_soa_out="$workdir/oxidedns-initial-soa.out"
primary_updated_soa_out="$workdir/primary-updated-soa.out"
primary_probe_ixfr_out="$workdir/primary-probe-ixfr.out"
oxidedns_updated_answer_out="$workdir/oxidedns-updated-answer-a.out"
oxidedns_updated_soa_out="$workdir/oxidedns-updated-soa.out"
metrics_out="$workdir/metrics.txt"
summary_out="$workdir/knot-ixfr-refresh-summary.env"
knot_log="$workdir/knot.log"

write_zone() {
    local serial="$1"
    local www_addr="$2"
    local txt_value="$3"
    cat >"$zone_file" <<EOF
\$ORIGIN alpha.test.
\$TTL 3600
@ IN SOA ns1.alpha.test. hostmaster.alpha.test. (
    $serial ; serial
    60      ; refresh
    30      ; retry
    300     ; expire
    300     ; minimum
)
  IN NS ns1.alpha.test.
  IN NS ns2.alpha.test.
ns1 IN A 127.0.0.1
ns2 IN A 127.0.0.2
www IN A $www_addr
mail IN A 192.0.2.20
alias IN CNAME www.alpha.test.
txt IN TXT "$txt_value"
_sip._tcp IN SRV 10 20 5060 www.alpha.test.
EOF
}

write_zone 2026052401 192.0.2.10 "knot ixfr interop v1"
cp "$zone_file" "$workdir/alpha.test.initial.zone"

cat >"$knot_conf" <<EOF
server:
    rundir: "/tmp"
    listen: 0.0.0.0@5353
    user: root:root

log:
  - target: stderr
    any: info

database:
    storage: "/tmp/knot-db"

template:
  - id: default
    storage: "/work"
    file: "%s.zone"
    zonefile-load: difference
    journal-content: changes
    journal-max-depth: 20
    provide-ixfr: on

acl:
  - id: transfer_acl
    address: 0.0.0.0/0
    action: transfer

zone:
  - domain: alpha.test.
    acl: transfer_acl
EOF

cat >"$transfer_proxy" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
LISTEN_PORT = int(sys.argv[1])
KNOT_PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]

SOA = 6
IXFR = 251
AXFR = 252

lock = threading.Lock()


def log(message):
    with lock:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            print(message, file=handle, flush=True)


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def parse_name(packet, offset):
    labels = []
    jumped = False
    consumed = 0
    seen = set()
    while True:
        if offset >= len(packet):
            raise ValueError("name outside packet")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("compression loop")
            seen.add(pointer)
            if not jumped:
                consumed += 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                consumed += 1
            return ".".join(labels) + ".", consumed
        offset += 1
        label = packet[offset:offset + length].decode("ascii")
        labels.append(label)
        offset += length
        if not jumped:
            consumed += 1 + length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass


def skip_questions(packet, offset, qdcount):
    for _ in range(qdcount):
        _, consumed = parse_name(packet, offset)
        offset += consumed + 4
    return offset


def soa_serial(packet, rdata_offset):
    _, consumed = parse_name(packet, rdata_offset)
    offset = rdata_offset + consumed
    _, consumed = parse_name(packet, offset)
    offset += consumed
    if offset + 4 > len(packet):
        raise ValueError("truncated SOA serial")
    return struct.unpack("!I", packet[offset:offset + 4])[0]


def parse_answer_records(messages):
    answers = []
    for packet in messages:
        if len(packet) < 12:
            continue
        _qid, _flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
        offset = skip_questions(packet, 12, qdcount)
        for _ in range(ancount):
            owner, consumed = parse_name(packet, offset)
            offset += consumed
            rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata_offset = offset
            serial = None
            if rrtype == SOA:
                serial = soa_serial(packet, rdata_offset)
            answers.append(
                {
                    "owner": owner.lower(),
                    "rrtype": rrtype,
                    "rrclass": rrclass,
                    "ttl": ttl,
                    "serial": serial,
                }
            )
            offset += rdlength
    return answers


def classify_ixfr(messages):
    try:
        answers = parse_answer_records(messages)
    except Exception as exc:
        return f"unclassified parse_error={exc}"
    soa_serials = [
        str(answer["serial"])
        for answer in answers
        if answer["owner"] == "alpha.test." and answer["rrtype"] == SOA and answer["serial"] is not None
    ]
    second_is_soa = len(answers) > 1 and answers[1]["owner"] == "alpha.test." and answers[1]["rrtype"] == SOA
    if len(answers) == 1 and soa_serials:
        mode = "current"
    elif second_is_soa:
        mode = "incremental"
    elif len(answers) > 1:
        mode = "axfr-fallback"
    else:
        mode = "unclassified"
    return f"{mode} answers={len(answers)} soa_serials={','.join(soa_serials)}"


def forward_udp(sock):
    while True:
        packet, peer = sock.recvfrom(65535)
        try:
            qname, qtype, _qclass = parse_question(packet)
            log(f"UDP query qname={qname} qtype={qtype}")
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(3)
            upstream.sendto(packet, (HOST, KNOT_PORT))
            response, _ = upstream.recvfrom(65535)
            sock.sendto(response, peer)
        except Exception as exc:
            log(f"UDP forward_error error={exc}")


def handle_tcp(conn, peer):
    with conn:
        try:
            length = struct.unpack("!H", read_exact(conn, 2))[0]
            query = read_exact(conn, length)
            qname, qtype, _qclass = parse_question(query)
            log(f"TCP query peer={peer[0]}:{peer[1]} qname={qname} qtype={qtype}")
            upstream = socket.create_connection((HOST, KNOT_PORT), timeout=3)
            messages = []
            with upstream:
                upstream.settimeout(3)
                upstream.sendall(struct.pack("!H", len(query)) + query)
                while True:
                    try:
                        prefix = read_exact(upstream, 2)
                        message_len = struct.unpack("!H", prefix)[0]
                        message = read_exact(upstream, message_len)
                    except socket.timeout:
                        break
                    except EOFError:
                        break
                    messages.append(message)
                    conn.sendall(prefix + message)
            if qtype == IXFR:
                log(f"TCP IXFR response_mode={classify_ixfr(messages)}")
            elif qtype == AXFR:
                log(f"TCP AXFR messages={len(messages)}")
        except Exception as exc:
            log(f"TCP forward_error peer={peer[0]}:{peer[1]} error={exc}")


def tcp_listener(sock):
    while True:
        conn, peer = sock.accept()
        threading.Thread(target=handle_tcp, args=(conn, peer), daemon=True).start()


def main():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((HOST, LISTEN_PORT))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, LISTEN_PORT))
    tcp.listen()

    threading.Thread(target=forward_udp, args=(udp,), daemon=True).start()
    threading.Thread(target=tcp_listener, args=(tcp,), daemon=True).start()
    log(f"READY listen_port={LISTEN_PORT} knot_port={KNOT_PORT}")
    threading.Event().wait()


if __name__ == "__main__":
    main()
PY

python3 "$transfer_proxy" "$proxy_port" "$knot_port" "$transfer_proxy_log" >"$workdir/transfer-proxy.stderr" 2>&1 &
proxy_pid=$!

for _ in {1..50}; do
    if [[ -f "$transfer_proxy_log" ]] && grep -F "READY" "$transfer_proxy_log" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

[rrl]
enabled = false

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
notify_dedup_secs = 1
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$proxy_port"]
notify_sources = ["127.0.0.1"]
EOF

set +e
knot_probe="$(
    docker run --rm \
        -v "$workdir:/work:rw" \
        "$knot_image" \
        sh -c 'knotc -c /work/knot.conf conf-check' \
        2>&1
)"
knot_probe_status=$?
set -e

if ((knot_probe_status != 0)); then
    echo "skipping Knot IXFR refresh interop: Alpine/Knot package does not accept deterministic IXFR configuration" >&2
    printf '%s\n' "$knot_probe" >&2
    exit 0
fi

if ! docker run -d --name "$container" \
    -p "127.0.0.1:$knot_port:5353/tcp" \
    -p "127.0.0.1:$knot_port:5353/udp" \
    -v "$workdir:/work:rw" \
    "$knot_image" \
    sh -c 'mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check && knotd -c /work/knot.conf -v' \
    >/dev/null; then
    echo "skipping Knot IXFR refresh interop: failed to start Alpine/Knot container" >&2
    exit 0
fi
record_docker_primary_version "$workdir" "$container" "Knot DNS" "$knot_image" "knot" "knot-ixfr-refresh" "tcp-ixfr+tcp-axfr" "none" "knotd -V" "$workdir/knot.conf" "$workdir/alpha.test.zone"

for _ in {1..50}; do
    if dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

primary_soa="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$primary_soa" >"$primary_initial_soa_out"
if [[ "$primary_soa" != *"2026052401"* ]]; then
    echo "Knot IXFR primary did not answer initial SOA serial" >&2
    exit 1
fi

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

printf '%s\n' "$ready" >"$readyz_out"
if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after initial Knot AXFR through transfer proxy" >&2
    exit 1
fi

initial_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$initial_soa" >"$oxidedns_initial_soa_out"
if [[ "$initial_soa" != *"2026052401"* ]]; then
    echo "OxideDNS did not serve initial SOA serial" >&2
    exit 1
fi

write_zone 2026052402 192.0.2.42 "knot ixfr interop v2"
cp "$zone_file" "$workdir/alpha.test.updated.zone"
docker exec "$container" knotc -c /work/knot.conf -s /tmp/knot.sock -b zone-reload alpha.test. >/dev/null

reloaded_soa=""
for _ in {1..80}; do
    reloaded_soa="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +tcp +time=1 +tries=1 +short || true)"
    if [[ "$reloaded_soa" == *"2026052402"* ]]; then
        break
    fi
    sleep 0.1
done

printf '%s\n' "$reloaded_soa" >"$primary_updated_soa_out"
if [[ "$reloaded_soa" != *"2026052402"* ]]; then
    echo "Knot IXFR primary did not load updated SOA serial" >&2
    exit 1
fi

probe_ixfr="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. IXFR=2026052401 +tcp +time=2 +tries=1 +noall +answer +ttlid)"
printf '%s\n' "$probe_ixfr" >"$primary_probe_ixfr_out"
if [[ "$probe_ixfr" != *"2026052402"* ]] || [[ "$probe_ixfr" != *"2026052401"* ]]; then
    echo "Knot IXFR primary did not expose expected old and new SOA serials" >&2
    printf '%s\n' "$probe_ixfr" >&2
    exit 1
fi

python3 - "$oxidedns_dns_port" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])


def encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


qid = 0xA551
flags = 4 << 11
packet = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
packet += encode_name("alpha.test.")
packet += struct.pack("!HH", 6, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.sendto(packet, ("127.0.0.1", port))
response, _ = sock.recvfrom(4096)
if len(response) < 4:
    raise SystemExit("short NOTIFY response from OxideDNS")
response_id, response_flags = struct.unpack("!HH", response[:4])
rcode = response_flags & 0x0F
qr = response_flags >> 15
if response_id != qid or qr != 1 or rcode != 0:
    raise SystemExit(f"unexpected NOTIFY response id={response_id} qr={qr} rcode={rcode}")
PY

updated_answer=""
for _ in {1..160}; do
    updated_answer="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer || true)"
    if [[ "$updated_answer" == *"192.0.2.42"* ]]; then
        break
    fi
    sleep 0.1
done

printf '%s\n' "$updated_answer" >"$oxidedns_updated_answer_out"
if [[ "$updated_answer" != *"www.alpha.test."* ]] || [[ "$updated_answer" != *"192.0.2.42"* ]]; then
    echo "OxideDNS did not publish updated A response after Knot IXFR refresh" >&2
    exit 1
fi

updated_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$updated_soa" >"$oxidedns_updated_soa_out"
if [[ "$updated_soa" != *"2026052402"* ]]; then
    echo "OxideDNS did not publish updated SOA serial after Knot IXFR refresh" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
ixfr_started="$(awk '$1 == "oxidedns_transfer_sessions_started_total{protocol=\"ixfr\"}" { print $2 }' <<<"$metrics")"
ixfr_succeeded="$(awk '$1 == "oxidedns_transfer_sessions_completed_total{protocol=\"ixfr\"}" { print $2 }' <<<"$metrics")"

if [[ -z "$ixfr_started" ]] || ((ixfr_started < 1)); then
    echo "OxideDNS metrics did not record a Knot IXFR attempt" >&2
    exit 1
fi

if ! grep -q "TCP query .* qtype=251" "$transfer_proxy_log"; then
    echo "transfer proxy did not observe a OxideDNS IXFR query to Knot" >&2
    exit 1
fi

for _ in {1..50}; do
    if grep -q "TCP IXFR response_mode=" "$transfer_proxy_log"; then
        break
    fi
    sleep 0.1
done

if grep -q "TCP IXFR response_mode=incremental" "$transfer_proxy_log"; then
    if [[ -z "$ixfr_succeeded" ]] || ((ixfr_succeeded < 1)); then
        echo "Knot provided a true incremental IXFR response, but OxideDNS rejected it instead of recording IXFR success" >&2
        exit 1
    fi
    if [[ "$metrics" != *'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052402'* ]]; then
        echo "OxideDNS metrics missing updated Knot IXFR SOA serial" >&2
        exit 1
    fi
    docker logs "$container" >"$knot_log" 2>&1 || true
    cat >"$summary_out" <<EOF
primary_initial_serial=2026052401
primary_updated_serial=2026052402
oxidedns_initial_serial=2026052401
oxidedns_updated_serial=2026052402
incremental_ixfr_observed=1
oxidedns_ixfr_attempt_recorded=1
oxidedns_ixfr_success_recorded=1
oxidedns_served_updated_a=1
oxidedns_metrics_checked=1
EOF
    if [[ -n "$artifact_dir" ]]; then
        mkdir -p "$artifact_dir"
        cp "$workdir/primary-version.txt" "$artifact_dir/primary-version.txt"
        cp "$knot_conf" "$artifact_dir/knot.conf"
        cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
        cp "$workdir/alpha.test.initial.zone" "$artifact_dir/alpha.test.initial.zone"
        cp "$workdir/alpha.test.updated.zone" "$artifact_dir/alpha.test.updated.zone"
        cp "$knot_log" "$artifact_dir/knot.log"
        cp "$transfer_proxy_log" "$artifact_dir/transfer-proxy.log"
        cp "$workdir/transfer-proxy.stderr" "$artifact_dir/transfer-proxy.stderr"
        cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
        cp "$primary_initial_soa_out" "$artifact_dir/primary-initial-soa.out"
        cp "$readyz_out" "$artifact_dir/readyz.txt"
        cp "$oxidedns_initial_soa_out" "$artifact_dir/oxidedns-initial-soa.out"
        cp "$primary_updated_soa_out" "$artifact_dir/primary-updated-soa.out"
        cp "$primary_probe_ixfr_out" "$artifact_dir/primary-probe-ixfr.out"
        cp "$oxidedns_updated_answer_out" "$artifact_dir/oxidedns-updated-answer-a.out"
        cp "$oxidedns_updated_soa_out" "$artifact_dir/oxidedns-updated-soa.out"
        cp "$metrics_out" "$artifact_dir/metrics.txt"
        cp "$summary_out" "$artifact_dir/knot-ixfr-refresh-summary.env"
    fi
    echo "Knot IXFR refresh interop passed with true incremental IXFR evidence"
elif grep -q "TCP IXFR response_mode=axfr-fallback" "$transfer_proxy_log"; then
    echo "skipping Knot IXFR refresh interop: Knot answered IXFR with mode 2 AXFR fallback, not a true incremental response"
else
    tail -80 "$transfer_proxy_log" >&2 || true
    echo "skipping Knot IXFR refresh interop: Knot IXFR response was not classifiable as true incremental"
fi
