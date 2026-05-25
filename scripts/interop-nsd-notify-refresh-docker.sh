#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping NSD NOTIFY Docker interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "skipping NSD NOTIFY Docker interop: Docker daemon is unavailable" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
workdir="$repo_root/target/interop/nsd-notify-refresh-$$"
container="oxidedns-nsd-notify-refresh-$$"
mkdir -p "$workdir"

cleanup() {
  local status=$?
  if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
    if (( status != 0 )); then
      echo "---- nsd container logs ----" >&2
      docker logs "$container" >&2 || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )); then
    [[ -f "$workdir/notify-proxy.log" ]] && { echo "---- notify-proxy.log ----" >&2; tail -120 "$workdir/notify-proxy.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -120 "$workdir/oxidedns.log" >&2; }
  fi
}
trap cleanup EXIT

read -r nsd_port notify_port oxidedns_dns_port oxidedns_health_port < <(
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
nsd_conf="$workdir/nsd.conf"
notify_proxy="$workdir/notify-proxy.py"
notify_proxy_log="$workdir/notify-proxy.log"
oxidedns_conf="$workdir/oxidedns.toml"

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
txt IN TXT "nsd notify interop fixture"
_sip._tcp IN SRV 10 20 5060 www.alpha.test.
EOF
}

write_zone 2026052401 192.0.2.10

cat >"$nsd_conf" <<EOF
server:
    do-ip4: yes
    do-ip6: no
    ip-address: 0.0.0.0@$nsd_port
    hide-version: yes
    verbosity: 1
    database: "/tmp/nsd.db"
    pidfile: "/tmp/nsd.pid"
    zonesdir: "/work"

remote-control:
    control-enable: yes
    control-interface: /tmp/nsd.control.sock

zone:
    name: "alpha.test."
    zonefile: "/work/alpha.test.zone"
    notify: 127.0.0.1@$notify_port NOKEY
    notify-retry: 1
    provide-xfr: 0.0.0.0/0 NOKEY
EOF

cat >"$notify_proxy" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

listen_port = int(sys.argv[1])
target_port = int(sys.argv[2])
log_path = sys.argv[3]


def log(message):
    with open(log_path, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", listen_port))

while True:
    packet, peer = sock.recvfrom(4096)
    if len(packet) < 12:
        log(f"short_packet bytes={len(packet)} peer={peer}")
        continue
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    opcode = (flags >> 11) & 0x0F
    log(
        "notify_from_nsd "
        f"peer={peer[0]}:{peer[1]} qid={qid} opcode={opcode} "
        f"qd={qdcount} an={ancount} ns={nscount} ar={arcount}"
    )
    forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward.settimeout(2)
    forward.sendto(packet, ("127.0.0.1", target_port))
    try:
        response, _ = forward.recvfrom(4096)
        if len(response) >= 4:
            _, response_flags = struct.unpack("!HH", response[:4])
            log(f"response_from_oxidedns rcode={response_flags & 0x0F} bytes={len(response)}")
        else:
            log(f"short_response_from_oxidedns bytes={len(response)}")
    except TimeoutError:
        log("response_from_oxidedns timeout")
PY

cargo build -p oxidedns-cli >/dev/null
if ! docker run -d --name "$container" \
  -p "127.0.0.1:$nsd_port:$nsd_port/tcp" \
  -p "127.0.0.1:$nsd_port:$nsd_port/udp" \
  -p "127.0.0.1:$oxidedns_dns_port:$oxidedns_dns_port/tcp" \
  -p "127.0.0.1:$oxidedns_dns_port:$oxidedns_dns_port/udp" \
  -p "127.0.0.1:$oxidedns_health_port:$oxidedns_health_port/tcp" \
  -v "$repo_root:/repo:ro" \
  -v "$workdir:/work:rw" \
  alpine:latest \
  sh -c 'apk add --no-cache gcompat libgcc nsd python3 >/dev/null && nsd-checkzone alpha.test. /work/alpha.test.zone >/dev/null && nsd-checkconf /work/nsd.conf && nsd -c /work/nsd.conf && tail -f /dev/null' \
  >/dev/null; then
  echo "skipping NSD NOTIFY Docker interop: failed to start Alpine/NSD container" >&2
  exit 0
fi
record_docker_primary_version "$workdir" "$container" "NSD" "alpine:latest" "nsd" "nsd-notify-refresh" "udp-notify+tcp-axfr" "none" "nsd -v" "$workdir/nsd.conf" "$workdir/alpha.test.zone"

for _ in {1..120}; do
  if dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

primary_soa="$(dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short)"
if [[ "$primary_soa" != *"2026052401"* ]]; then
  echo "NSD NOTIFY primary did not answer initial SOA serial" >&2
  exit 1
fi

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["0.0.0.0:$oxidedns_dns_port"]
listen_tcp = ["0.0.0.0:$oxidedns_dns_port"]
health = "0.0.0.0:$oxidedns_health_port"
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
primaries = ["127.0.0.1:$nsd_port"]
notify_sources = ["127.0.0.1"]
EOF

docker exec "$container" sh -c "python3 /work/notify-proxy.py '$notify_port' '$oxidedns_dns_port' /work/notify-proxy.log >/work/notify-proxy.stderr 2>&1 &"
docker exec "$container" sh -c '/repo/target/debug/oxidedns serve --config /work/oxidedns.toml >/work/oxidedns.log 2>&1 &'

ready=""
for _ in {1..100}; do
  if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
    [[ "$ready" == "ready" ]] && break
  fi
  sleep 0.1
done

if [[ "$ready" != "ready" ]]; then
  echo "OxideDNS did not become ready after initial NSD AXFR" >&2
  exit 1
fi

initial_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$initial_soa" != *"2026052401"* ]]; then
  echo "OxideDNS did not serve initial SOA serial from NSD" >&2
  exit 1
fi

write_zone 2026052402 192.0.2.42
docker exec "$container" nsd-checkzone alpha.test. /work/alpha.test.zone >/dev/null
docker exec "$container" nsd-control -c /work/nsd.conf reload alpha.test >/dev/null
docker exec "$container" nsd-control -c /work/nsd.conf notify alpha.test >/dev/null

primary_updated_soa=""
for _ in {1..80}; do
  primary_updated_soa="$(dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short)"
  if [[ "$primary_updated_soa" == *"2026052402"* ]]; then
    break
  fi
  sleep 0.1
done

if [[ "$primary_updated_soa" != *"2026052402"* ]]; then
  echo "NSD primary did not publish updated SOA serial" >&2
  exit 1
fi

updated_answer=""
for _ in {1..120}; do
  updated_answer="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
  if [[ "$updated_answer" == *"192.0.2.42"* ]]; then
    break
  fi
  sleep 0.1
done

if [[ "$updated_answer" != *"www.alpha.test."* ]] || [[ "$updated_answer" != *"192.0.2.42"* ]]; then
  echo "OxideDNS did not publish updated A response after NSD NOTIFY" >&2
  exit 1
fi

updated_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$updated_soa" != *"2026052402"* ]]; then
  echo "OxideDNS did not publish updated SOA serial after NSD NOTIFY" >&2
  exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052402' \
  'oxidedns_notify_messages_received_total' \
  'oxidedns_notify_refresh_actions_total{action="signalled"}'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "OxideDNS metrics missing expected NSD NOTIFY evidence: $expected" >&2
    exit 1
  fi
done

notify_received="$(awk '$1 == "oxidedns_notify_messages_received_total" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_received" ]] || (( notify_received < 1 )); then
  echo "OxideDNS metrics did not record NSD NOTIFY receipt" >&2
  exit 1
fi

notify_signalled="$(awk '$1 == "oxidedns_notify_refresh_actions_total{action=\"signalled\"}" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_signalled" ]] || (( notify_signalled < 1 )); then
  echo "OxideDNS metrics did not record NSD NOTIFY refresh signal" >&2
  exit 1
fi

if ! grep -q "notify_from_nsd .* opcode=4" "$notify_proxy_log"; then
  echo "NSD NOTIFY proxy did not observe an NSD NOTIFY packet" >&2
  exit 1
fi

if ! grep -q "response_from_oxidedns rcode=0" "$notify_proxy_log"; then
  echo "NSD NOTIFY proxy did not observe a successful OxideDNS NOTIFY response" >&2
  exit 1
fi

echo "NSD NOTIFY refresh Docker interop passed"
