#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo openssl timeout; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping Knot XoT Docker interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "skipping Knot XoT Docker interop: Docker daemon is unavailable" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
zone_file="$repo_root/tests/interop/bind/alpha.test.zone"
workdir="$repo_root/target/interop/knot-xot-$$"
container="oxidedns-knot-xot-$$"
server_name="primary.alpha.test"
mkdir -p "$workdir"

cleanup() {
  local status=$?
  if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
    kill "$oxidedns_pid" 2>/dev/null || true
    wait "$oxidedns_pid" 2>/dev/null || true
  fi
  if (( status != 0 )) && [[ -f "$workdir/oxidedns.log" ]]; then
    echo "---- oxidedns log ----" >&2
    sed -n '1,220p' "$workdir/oxidedns.log" >&2 || true
  fi
  if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
    if (( status != 0 )); then
      echo "---- knot container logs ----" >&2
      docker logs "$container" >&2 || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

read -r knot_tls_port oxidedns_dns_port oxidedns_health_port < <(
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

cp "$zone_file" "$workdir/alpha.test.zone"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 2 \
  -subj "/CN=OxideDNS test CA" \
  -keyout "$workdir/ca.key" \
  -out "$workdir/ca.crt" \
  >/dev/null 2>&1

openssl req \
  -newkey rsa:2048 \
  -nodes \
  -subj "/CN=$server_name" \
  -keyout "$workdir/server.key" \
  -out "$workdir/server.csr" \
  >/dev/null 2>&1

cat >"$workdir/server.ext" <<EOF
subjectAltName=DNS:$server_name
extendedKeyUsage=serverAuth
EOF

openssl x509 \
  -req \
  -in "$workdir/server.csr" \
  -CA "$workdir/ca.crt" \
  -CAkey "$workdir/ca.key" \
  -CAcreateserial \
  -days 2 \
  -out "$workdir/server.crt" \
  -extfile "$workdir/server.ext" \
  >/dev/null 2>&1

chmod 0644 "$workdir/ca.crt" "$workdir/server.crt"
chmod 0600 "$workdir/ca.key" "$workdir/server.key"

cat >"$workdir/knot.conf" <<EOF
server:
    rundir: "/tmp"
    listen-tls: 0.0.0.0@853
    cert-file: "/work/server.crt"
    key-file: "/work/server.key"
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

acl:
  - id: transfer_acl
    address: 0.0.0.0/0
    action: transfer

zone:
  - domain: alpha.test.
    acl: transfer_acl
EOF

set +e
knot_probe="$(
  docker run --rm \
    -v "$workdir:/work:ro" \
    alpine:latest \
    sh -c 'apk add --no-cache knot >/dev/null && knotd -V && knotc -c /work/knot.conf conf-check' \
    2>&1
)"
knot_probe_status=$?
set -e

if (( knot_probe_status != 0 )); then
  if [[ "$knot_probe" == *"listen-tls"* ]] || [[ "$knot_probe" == *"cert-file"* ]] || [[ "$knot_probe" == *"key-file"* ]] || [[ "$knot_probe" == *"unknown"* ]]; then
    echo "skipping Knot XoT Docker interop: Alpine/Knot package does not accept TLS/XoT server configuration" >&2
    printf '%s\n' "$knot_probe" >&2
    exit 0
  fi
  echo "Knot XoT configuration probe failed" >&2
  printf '%s\n' "$knot_probe" >&2
  exit 1
fi

if ! docker run -d --name "$container" \
  -p "127.0.0.1:$knot_tls_port:853/tcp" \
  -v "$workdir:/work:ro" \
  alpine:latest \
  sh -c 'apk add --no-cache knot >/dev/null && mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check && knotd -c /work/knot.conf -v' \
  >/dev/null; then
  echo "skipping Knot XoT Docker interop: failed to start Alpine/Knot container" >&2
  exit 0
fi
record_docker_primary_version "$workdir" "$container" "Knot DNS" "alpine:latest" "knot" "knot-xot" "tls-xot-axfr" "tls-alpn-dot" "knotd -V" "$workdir/knot.conf" "$zone_file"

alpn_probe=""
for _ in {1..120}; do
  if ! docker ps --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
    echo "Knot XoT container exited before serving TLS" >&2
    exit 1
  fi
  alpn_probe="$(
    timeout 3 openssl s_client \
      -connect "127.0.0.1:$knot_tls_port" \
      -servername "$server_name" \
      -alpn dot \
      -CAfile "$workdir/ca.crt" \
      </dev/null 2>&1 || true
  )"
  if [[ "$alpn_probe" == *"ALPN protocol: dot"* ]]; then
    break
  fi
  sleep 0.25
done

if [[ "$alpn_probe" != *"ALPN protocol: dot"* ]]; then
  echo "skipping Knot XoT Docker interop: Knot TLS listener did not negotiate ALPN dot" >&2
  printf '%s\n' "$alpn_probe" >&2
  exit 0
fi

oxidedns_conf="$workdir/oxidedns.toml"
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
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
notify_sources = ["127.0.0.1"]

[[zones.transfer_primaries]]
addr = "127.0.0.1:$knot_tls_port"
transport = "xot"
server_name = "$server_name"
trust_anchors = ["$workdir/ca.crt"]
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
  echo "OxideDNS did not become ready after Knot XoT AXFR" >&2
  exit 1
fi

answer_a="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
if [[ "$answer_a" != *"www.alpha.test."* ]] || [[ "$answer_a" != *"192.0.2.10"* ]]; then
  echo "OxideDNS did not serve expected A response after Knot XoT AXFR" >&2
  exit 1
fi

answer_cname="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alias.alpha.test. A +norecurse +noall +answer)"
if [[ "$answer_cname" != *"alias.alpha.test."* ]] || [[ "$answer_cname" != *"www.alpha.test."* ]] || [[ "$answer_cname" != *"192.0.2.10"* ]]; then
  echo "OxideDNS did not serve expected CNAME-chain response after Knot XoT AXFR" >&2
  exit 1
fi

tcp_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$tcp_soa" != *"2026052401"* ]]; then
  echo "OxideDNS did not serve expected TCP SOA response after Knot XoT AXFR" >&2
  exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401' \
  'oxidedns_transfer_sessions_started_total{protocol="axfr"} 1' \
  'oxidedns_transfer_sessions_completed_total{protocol="axfr"} 1'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "OxideDNS metrics missing expected line after Knot XoT AXFR: $expected" >&2
    exit 1
  fi
done

if grep -E 'ConnectTcp|TlsHandshake|XotAlpn|did not negotiate ALPN dot' "$workdir/oxidedns.log" >/dev/null 2>&1; then
  echo "OxideDNS log contains an XoT connection failure" >&2
  exit 1
fi

echo "Knot Docker XoT AXFR interop passed"
