#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo ip; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping Knot NOTIFY Docker interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "skipping Knot NOTIFY Docker interop: Docker daemon is unavailable" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
workdir="$repo_root/target/interop/knot-notify-refresh-$$"
container="oxidedns-knot-notify-refresh-$$"
mkdir -p "$workdir"

host_notify_ip="$(
  ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }'
)"

if [[ -z "$host_notify_ip" ]]; then
  echo "skipping Knot NOTIFY Docker interop: could not determine host address reachable from Docker" >&2
  exit 0
fi

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
    if (( status != 0 )); then
      echo "---- knot container logs ----" >&2
      docker logs "$container" >&2 || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )); then
    [[ -f "$workdir/notify-proxy.log" ]] && { echo "---- notify-proxy.log ----" >&2; tail -120 "$workdir/notify-proxy.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -120 "$workdir/oxidedns.log" >&2; }
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

read -r knot_port notify_port oxidedns_dns_port oxidedns_health_port < <(
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
notify_proxy="$workdir/notify-proxy.py"
notify_proxy_log="$workdir/notify-proxy.log"

write_zone() {
  local serial="$1"
  local www_addr="$2"
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
txt IN TXT "knot notify interop fixture"
_sip._tcp IN SRV 10 20 5060 www.alpha.test.
EOF
}

write_zone 2026052401 192.0.2.10

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

remote:
  - id: oxidedns_notify
    address: $host_notify_ip@$notify_port

template:
  - id: default
    storage: "/work"
    file: "%s.zone"

acl:
  - id: transfer_acl
    address: 0.0.0.0/0
    action: transfer

zone:
  - domain: alpha.test.
    acl: transfer_acl
    notify: oxidedns_notify
EOF

cat >"$notify_proxy" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

listen_port = int(sys.argv[1])
target_port = int(sys.argv[2])
log_path = sys.argv[3]


def log(message):
    with open(log_path, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def packet_summary(prefix, packet, peer):
    if len(packet) < 12:
        log(f"short_packet transport={prefix} bytes={len(packet)} peer={peer}")
        return None
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    opcode = (flags >> 11) & 0x0F
    log(
        f"notify_from_knot_{prefix} "
        f"peer={peer[0]}:{peer[1]} qid={qid} opcode={opcode} "
        f"qd={qdcount} an={ancount} ns={nscount} ar={arcount}"
    )
    return qid


def response_summary(prefix, response):
    if len(response) >= 4:
        _, response_flags = struct.unpack("!HH", response[:4])
        log(f"response_from_oxidedns transport={prefix} rcode={response_flags & 0x0F} bytes={len(response)}")
    else:
        log(f"short_response_from_oxidedns transport={prefix} bytes={len(response)}")


def read_exact(stream, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", listen_port))
    while True:
        packet, peer = sock.recvfrom(4096)
        if packet_summary("udp", packet, peer) is None:
            continue
        forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward.settimeout(2)
        forward.sendto(packet, ("127.0.0.1", target_port))
        try:
            response, _ = forward.recvfrom(4096)
            response_summary("udp", response)
        except socket.timeout:
            log("response_from_oxidedns transport=udp timeout")


def handle_tcp(conn, peer):
    try:
        conn.settimeout(5)
        length = struct.unpack("!H", read_exact(conn, 2))[0]
        packet = read_exact(conn, length)
        if packet_summary("tcp", packet, peer) is None:
            return
        forward = socket.create_connection(("127.0.0.1", target_port), timeout=5)
        with forward:
            forward.sendall(struct.pack("!H", len(packet)) + packet)
            response_len = struct.unpack("!H", read_exact(forward, 2))[0]
            response = read_exact(forward, response_len)
        response_summary("tcp", response)
        conn.sendall(struct.pack("!H", len(response)) + response)
    except Exception as error:
        log(f"response_from_oxidedns transport=tcp error={error}")
    finally:
        conn.close()


def serve_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", listen_port))
    sock.listen()
    while True:
        conn, peer = sock.accept()
        threading.Thread(target=handle_tcp, args=(conn, peer), daemon=True).start()


threading.Thread(target=serve_udp, daemon=True).start()
serve_tcp()
PY

python3 "$notify_proxy" "$notify_port" "$oxidedns_dns_port" "$notify_proxy_log" &
proxy_pid=$!

set +e
knot_probe="$(
  docker run --rm \
    -v "$workdir:/work:ro" \
    alpine:latest \
    sh -c 'apk add --no-cache knot >/dev/null && knotc -c /work/knot.conf conf-check' \
    2>&1
)"
knot_probe_status=$?
set -e

if (( knot_probe_status != 0 )); then
  if [[ "$knot_probe" == *"host.docker.internal"* ]] || [[ "$knot_probe" == *"unknown"* ]]; then
    echo "skipping Knot NOTIFY Docker interop: Alpine/Knot package does not accept this NOTIFY configuration" >&2
    printf '%s\n' "$knot_probe" >&2
    exit 0
  fi
  echo "Knot NOTIFY configuration probe failed" >&2
  printf '%s\n' "$knot_probe" >&2
  exit 1
fi

if ! docker run -d --name "$container" \
  -p "127.0.0.1:$knot_port:5353/tcp" \
  -p "127.0.0.1:$knot_port:5353/udp" \
  -v "$workdir:/work:rw" \
  alpine:latest \
  sh -c 'apk add --no-cache knot >/dev/null && mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check && knotd -c /work/knot.conf -v' \
  >/dev/null; then
  echo "skipping Knot NOTIFY Docker interop: failed to start Alpine/Knot container" >&2
  exit 0
fi
record_docker_primary_version "$workdir" "$container" "Knot DNS" "alpine:latest" "knot" "knot-notify-refresh" "udp-notify+tcp-axfr" "none" "knotd -V" "$workdir/knot.conf" "$workdir/alpha.test.zone"

for _ in {1..120}; do
  if dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

primary_soa="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +time=1 +tries=1 +short)"
if [[ "$primary_soa" != *"2026052401"* ]]; then
  echo "Knot NOTIFY primary did not answer expected initial SOA serial" >&2
  exit 1
fi

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
notify_dedup_secs = 0
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$knot_port"]
notify_sources = ["127.0.0.1"]
EOF

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
  echo "OxideDNS did not become ready after initial Knot AXFR" >&2
  exit 1
fi

initial_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$initial_soa" != *"2026052401"* ]]; then
  echo "OxideDNS did not serve initial SOA serial" >&2
  exit 1
fi

write_zone 2026052402 192.0.2.42
docker exec "$container" knotc -c /work/knot.conf -s /tmp/knot.sock -b zone-reload alpha.test. >/dev/null

updated_primary_soa=""
for _ in {1..80}; do
  updated_primary_soa="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +time=1 +tries=1 +short)"
  if [[ "$updated_primary_soa" == *"2026052402"* ]]; then
    break
  fi
  sleep 0.1
done

if [[ "$updated_primary_soa" != *"2026052402"* ]]; then
  echo "Knot NOTIFY primary did not publish updated SOA serial after reload" >&2
  exit 1
fi

docker exec "$container" knotc -c /work/knot.conf -s /tmp/knot.sock -b zone-notify alpha.test. >/dev/null

updated_answer=""
for _ in {1..120}; do
  updated_answer="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
  if [[ "$updated_answer" == *"192.0.2.42"* ]]; then
    break
  fi
  sleep 0.1
done

if [[ "$updated_answer" != *"www.alpha.test."* ]] || [[ "$updated_answer" != *"192.0.2.42"* ]]; then
  echo "OxideDNS did not publish updated A response after Knot NOTIFY" >&2
  exit 1
fi

updated_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$updated_soa" != *"2026052402"* ]]; then
  echo "OxideDNS did not publish updated SOA serial after Knot NOTIFY" >&2
  exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
if [[ "$metrics" != *'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052402'* ]]; then
  echo "OxideDNS metrics missing updated Knot NOTIFY SOA serial" >&2
  exit 1
fi

notify_received="$(awk '$1 == "oxidedns_notify_messages_received_total" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_received" ]] || (( notify_received < 1 )); then
  echo "OxideDNS metrics did not record a Knot NOTIFY message" >&2
  exit 1
fi

notify_signalled="$(awk '$1 == "oxidedns_notify_refresh_actions_total{action=\"signalled\"}" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_signalled" ]] || (( notify_signalled < 1 )); then
  echo "OxideDNS metrics did not record a Knot NOTIFY refresh signal" >&2
  exit 1
fi

if ! grep -q "notify_from_knot_.* opcode=4" "$notify_proxy_log"; then
  echo "Knot NOTIFY proxy did not observe a Knot NOTIFY packet" >&2
  exit 1
fi

if ! grep -q "response_from_oxidedns .* rcode=0" "$notify_proxy_log"; then
  echo "Knot NOTIFY proxy did not observe a successful OxideDNS NOTIFY response" >&2
  exit 1
fi

echo "Knot Docker NOTIFY refresh interop passed"
