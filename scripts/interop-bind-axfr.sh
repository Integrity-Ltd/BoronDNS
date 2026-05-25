#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in named named-checkconf named-checkzone dig curl python3 cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping BIND interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
zone_file="$repo_root/tests/interop/bind/alpha.test.zone"
template_file="$repo_root/tests/interop/bind/named.conf.template"
workdir="$repo_root/target/interop/bind-axfr-$$"
mkdir -p "$workdir"

cleanup() {
  local status=$?
  if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
    kill "$oxidedns_pid" 2>/dev/null || true
    wait "$oxidedns_pid" 2>/dev/null || true
  fi
  if [[ -n "${named_pid:-}" ]] && kill -0 "$named_pid" 2>/dev/null; then
    kill "$named_pid" 2>/dev/null || true
    wait "$named_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    [[ -f "$workdir/named.log" ]] && { echo "---- named.log ----" >&2; tail -100 "$workdir/named.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -100 "$workdir/oxidedns.log" >&2; }
  fi
}
trap cleanup EXIT

read -r bind_port oxidedns_dns_port oxidedns_health_port < <(
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

named_conf="$workdir/named.conf"
oxidedns_conf="$workdir/oxidedns.toml"

named-checkzone alpha.test. "$zone_file" >/dev/null
python3 - "$template_file" "$named_conf" "$workdir" "$bind_port" "$zone_file" <<'PY'
from pathlib import Path
import sys

template, output, workdir, port, zonefile = sys.argv[1:]
text = Path(template).read_text()
text = text.replace("__WORKDIR__", workdir)
text = text.replace("__PORT__", port)
text = text.replace("__ZONEFILE__", zonefile)
Path(output).write_text(text)
PY
named-checkconf -z "$named_conf" >/dev/null
record_bind_primary_version "$workdir" "bind-axfr" "tcp-axfr" "none" "$named_conf" "$zone_file"

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

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
primaries = ["127.0.0.1:$bind_port"]
notify_sources = ["127.0.0.1"]
EOF

named -g -c "$named_conf" -n 1 >"$workdir/named.log" 2>&1 &
named_pid=$!

for _ in {1..50}; do
  if dig "@127.0.0.1" -p "$bind_port" alpha.test. SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

primary_soa="$(dig "@127.0.0.1" -p "$bind_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ -z "$primary_soa" ]]; then
  echo "BIND primary did not answer SOA" >&2
  exit 1
fi

primary_axfr="$(dig "@127.0.0.1" -p "$bind_port" alpha.test. AXFR +time=2 +tries=1)"
if [[ "$primary_axfr" != *"www.alpha.test."* ]] || [[ "$primary_axfr" != *"alias.alpha.test."* ]]; then
  echo "BIND primary AXFR did not include expected fixture records" >&2
  exit 1
fi

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
  echo "OxideDNS did not become ready after BIND AXFR" >&2
  exit 1
fi

answer_a="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
if [[ "$answer_a" != *"www.alpha.test."* ]] || [[ "$answer_a" != *"192.0.2.10"* ]]; then
  echo "OxideDNS did not serve expected A response" >&2
  exit 1
fi

answer_cname="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alias.alpha.test. A +norecurse +noall +answer)"
if [[ "$answer_cname" != *"alias.alpha.test."* ]] || [[ "$answer_cname" != *"www.alpha.test."* ]] || [[ "$answer_cname" != *"192.0.2.10"* ]]; then
  echo "OxideDNS did not serve expected CNAME chain response" >&2
  exit 1
fi

tcp_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$tcp_soa" != *"2026052401"* ]]; then
  echo "OxideDNS did not serve expected TCP SOA response" >&2
  exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
if [[ "$metrics" != *'oxidedns_zones_active 1'* ]] || [[ "$metrics" != *'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401'* ]]; then
  echo "OxideDNS metrics did not expose active BIND-transferred zone" >&2
  exit 1
fi

echo "BIND AXFR interop passed"
