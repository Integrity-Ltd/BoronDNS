#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in named named-checkconf named-checkzone dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping BIND interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi
ulimit -n 65536 2>/dev/null || true

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/axfr-traceability.sh
source "$repo_root/scripts/axfr-traceability.sh"
zone_file="$repo_root/tests/interop/bind/alpha.test.zone"
template_file="$repo_root/tests/interop/bind/named.conf.template"
bind_cache_parent="/var/cache/bind/oxidedns-interop"
if [[ -d "$bind_cache_parent" && -w "$bind_cache_parent" ]]; then
    work_parent="$bind_cache_parent"
else
    work_parent="${TMPDIR:-/tmp}/oxidedns-interop"
fi
mkdir -p "$work_parent"
chmod 1777 "$work_parent"
workdir="$work_parent/bind-axfr-$$"
artifact_dir="${OXIDEDNS_BIND_AXFR_ARTIFACT_DIR:-}"
rm -rf "$workdir"
mkdir -p "$workdir"
chmod 0777 "$workdir"

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
    if ((status != 0)); then
        [[ -f "$workdir/named.log" ]] && {
            echo "---- named.log ----" >&2
            tail -100 "$workdir/named.log" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -100 "$workdir/oxidedns.log" >&2
        }
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
bind_zone_file="$workdir/alpha.test.zone"
oxidedns_conf="$workdir/oxidedns.toml"
primary_soa_out="$workdir/primary-soa.out"
primary_axfr_out="$workdir/primary-axfr.out"
readyz_out="$workdir/readyz.txt"
answer_a_out="$workdir/answer-a.out"
answer_cname_out="$workdir/answer-cname.out"
tcp_soa_out="$workdir/tcp-soa.out"
metrics_out="$workdir/metrics.txt"
traceability_tsv="$workdir/axfr-traceability.tsv"

cp "$zone_file" "$bind_zone_file"
chmod 0644 "$bind_zone_file"
named-checkzone alpha.test. "$bind_zone_file" >/dev/null
python3 - "$template_file" "$named_conf" "$workdir" "$bind_port" "$bind_zone_file" <<'PY'
from pathlib import Path
import sys

template, output, workdir, port, zonefile = sys.argv[1:]
text = Path(template).read_text()
text = text.replace("__WORKDIR__", workdir)
text = text.replace("__PORT__", port)
text = text.replace("__ZONEFILE__", zonefile)
Path(output).write_text(text)
PY
chmod 0644 "$named_conf"
named-checkconf -z "$named_conf" >/dev/null
record_bind_primary_version "$workdir" "bind-axfr" "tcp-axfr" "none" "$named_conf" "$bind_zone_file"

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
printf '%s\n' "$primary_soa" >"$primary_soa_out"
if [[ -z "$primary_soa" ]]; then
    echo "BIND primary did not answer SOA" >&2
    exit 1
fi

primary_axfr="$(dig "@127.0.0.1" -p "$bind_port" alpha.test. AXFR +time=2 +tries=1)"
printf '%s\n' "$primary_axfr" >"$primary_axfr_out"
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
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after BIND AXFR" >&2
    exit 1
fi
printf '%s\n' "$ready" >"$readyz_out"

answer_a="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
printf '%s\n' "$answer_a" >"$answer_a_out"
if [[ "$answer_a" != *"www.alpha.test."* ]] || [[ "$answer_a" != *"192.0.2.10"* ]]; then
    echo "OxideDNS did not serve expected A response" >&2
    exit 1
fi

answer_cname="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alias.alpha.test. A +norecurse +noall +answer)"
printf '%s\n' "$answer_cname" >"$answer_cname_out"
if [[ "$answer_cname" != *"alias.alpha.test."* ]] || [[ "$answer_cname" != *"www.alpha.test."* ]] || [[ "$answer_cname" != *"192.0.2.10"* ]]; then
    echo "OxideDNS did not serve expected CNAME chain response" >&2
    exit 1
fi

tcp_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$tcp_soa" >"$tcp_soa_out"
if [[ "$tcp_soa" != *"2026052401"* ]]; then
    echo "OxideDNS did not serve expected TCP SOA response" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
if [[ "$metrics" != *'oxidedns_zones_active 1'* ]] || [[ "$metrics" != *'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401'* ]]; then
    echo "OxideDNS metrics did not expose active BIND-transferred zone" >&2
    exit 1
fi

write_axfr_traceability_tsv "$traceability_tsv" "BIND" "named.log"

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$named_conf" "$artifact_dir/named.conf"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
    cp "$workdir/named.log" "$artifact_dir/named.log"
    cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
    cp "$workdir/primary-version.txt" "$artifact_dir/primary-version.txt"
    cp "$primary_soa_out" "$artifact_dir/primary-soa.out"
    cp "$primary_axfr_out" "$artifact_dir/primary-axfr.out"
    cp "$readyz_out" "$artifact_dir/readyz.txt"
    cp "$answer_a_out" "$artifact_dir/answer-a.out"
    cp "$answer_cname_out" "$artifact_dir/answer-cname.out"
    cp "$tcp_soa_out" "$artifact_dir/tcp-soa.out"
    cp "$metrics_out" "$artifact_dir/metrics.txt"
    cp "$traceability_tsv" "$artifact_dir/axfr-traceability.tsv"
fi

echo "BIND AXFR interop passed"
