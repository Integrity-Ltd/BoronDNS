#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping NSD Docker interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping NSD Docker interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/axfr-traceability.sh
source "$repo_root/scripts/axfr-traceability.sh"
zone_file="$repo_root/tests/interop/bind/alpha.test.zone"
template_file="$repo_root/tests/interop/nsd/nsd.conf.template"
workdir="$repo_root/target/interop/nsd-axfr-$$"
container="oxidedns-nsd-axfr-$$"
artifact_dir="${OXIDEDNS_NSD_AXFR_ARTIFACT_DIR:-}"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- nsd container logs ----" >&2
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r nsd_port oxidedns_dns_port oxidedns_health_port < <(
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
cp "$template_file" "$workdir/nsd.conf"
primary_soa_out="$workdir/primary-soa.out"
primary_axfr_out="$workdir/primary-axfr.out"
readyz_out="$workdir/readyz.txt"
answer_a_out="$workdir/answer-a.out"
answer_cname_out="$workdir/answer-cname.out"
tcp_soa_out="$workdir/tcp-soa.out"
metrics_out="$workdir/metrics.txt"
traceability_tsv="$workdir/axfr-traceability.tsv"
nsd_log="$workdir/nsd.log"

if ! docker run -d --name "$container" \
    -p "127.0.0.1:$nsd_port:5353/tcp" \
    -p "127.0.0.1:$nsd_port:5353/udp" \
    -v "$workdir:/work:ro" \
    alpine:latest \
    sh -c 'apk add --no-cache nsd >/dev/null && nsd-checkconf /work/nsd.conf && nsd -d -c /work/nsd.conf' \
    >/dev/null; then
    echo "skipping NSD Docker interop: failed to start Alpine/NSD container" >&2
    exit 0
fi
record_docker_primary_version "$workdir" "$container" "NSD" "alpine:latest" "nsd" "nsd-axfr" "tcp-axfr" "none" "nsd -v" "$workdir/nsd.conf" "$workdir/alpha.test.zone"

for _ in {1..120}; do
    if dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

primary_soa="$(dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short)"
printf '%s\n' "$primary_soa" >"$primary_soa_out"
if [[ "$primary_soa" != *"2026052401"* ]]; then
    echo "NSD primary did not answer expected SOA serial" >&2
    exit 1
fi

primary_axfr="$(dig "@127.0.0.1" -p "$nsd_port" alpha.test. AXFR +time=2 +tries=1)"
printf '%s\n' "$primary_axfr" >"$primary_axfr_out"
if [[ "$primary_axfr" != *"www.alpha.test."* ]] || [[ "$primary_axfr" != *"alias.alpha.test."* ]]; then
    echo "NSD primary AXFR did not include expected fixture records" >&2
    exit 1
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
primaries = ["127.0.0.1:$nsd_port"]
notify_sources = ["127.0.0.1"]
EOF

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
    echo "OxideDNS did not become ready after NSD AXFR" >&2
    exit 1
fi
printf '%s\n' "$ready" >"$readyz_out"

answer_a="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
printf '%s\n' "$answer_a" >"$answer_a_out"
if [[ "$answer_a" != *"www.alpha.test."* ]] || [[ "$answer_a" != *"192.0.2.10"* ]]; then
    echo "OxideDNS did not serve expected A response after NSD AXFR" >&2
    exit 1
fi

answer_cname="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alias.alpha.test. A +norecurse +noall +answer)"
printf '%s\n' "$answer_cname" >"$answer_cname_out"
if [[ "$answer_cname" != *"alias.alpha.test."* ]] || [[ "$answer_cname" != *"www.alpha.test."* ]] || [[ "$answer_cname" != *"192.0.2.10"* ]]; then
    echo "OxideDNS did not serve expected CNAME-chain response after NSD AXFR" >&2
    exit 1
fi

tcp_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$tcp_soa" >"$tcp_soa_out"
if [[ "$tcp_soa" != *"2026052401"* ]]; then
    echo "OxideDNS did not serve expected TCP SOA response after NSD AXFR" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
for expected in \
    'oxidedns_zones_active 1' \
    'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401' \
    'oxidedns_transfer_sessions_started_total{protocol="axfr"} 1' \
    'oxidedns_transfer_sessions_completed_total{protocol="axfr"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "OxideDNS metrics missing expected line after NSD AXFR: $expected" >&2
        exit 1
    fi
done

docker logs "$container" >"$nsd_log" 2>&1 || true
write_axfr_traceability_tsv "$traceability_tsv" "NSD" "nsd.log"

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$workdir/nsd.conf" "$artifact_dir/nsd.conf"
    cp "$workdir/alpha.test.zone" "$artifact_dir/alpha.test.zone"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
    cp "$nsd_log" "$artifact_dir/nsd.log"
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

echo "NSD Docker AXFR interop passed"
