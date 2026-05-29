#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
gate_dir="${OXIDEDNS_ZONE_IMAGE_GATE_DIR:-$repo_root/target/evidence/zone-image-evidence-gate-$timestamp}"
current_dir="$gate_dir/current"
zone_image_dir="$gate_dir/zone-image"
comparison_path="$gate_dir/comparison.tsv"
trace_override="${OXIDEDNS_ZONE_IMAGE_GATE_TRACE_FILE:-}"
require_non_loopback="${OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK:-false}"
overwrite="${OXIDEDNS_ZONE_IMAGE_GATE_OVERWRITE:-false}"
preflight_only="${OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY:-false}"
min_qps_ratio="${OXIDEDNS_ZONE_IMAGE_GATE_MIN_QPS_RATIO:-1.0}"
max_p50_ratio="${OXIDEDNS_ZONE_IMAGE_GATE_MAX_P50_RATIO:-}"
max_p99_ratio="${OXIDEDNS_ZONE_IMAGE_GATE_MAX_P99_RATIO:-}"
max_p999_ratio="${OXIDEDNS_ZONE_IMAGE_GATE_MAX_P999_RATIO:-}"
ssh_connect_timeout="${OXIDEDNS_ZONE_IMAGE_GATE_SSH_CONNECT_TIMEOUT_SECONDS:-5}"
remote_client_allow_arch_mismatch="${OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH:-false}"

hash_identity() {
    local identity="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$identity" | sha256sum | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$identity" | shasum -a 256 | awk '{ print $1 }'
    else
        printf 'unknown'
    fi
}

local_host_identity() {
    if [[ -r /proc/sys/kernel/random/boot_id ]]; then
        cat /proc/sys/kernel/random/boot_id
    else
        hostname
    fi
}

case "$require_non_loopback" in
true | false) ;;
*)
    printf 'OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK must be true or false, got %q\n' "$require_non_loopback" >&2
    exit 64
    ;;
esac
case "$overwrite" in
true | false) ;;
*)
    printf 'OXIDEDNS_ZONE_IMAGE_GATE_OVERWRITE must be true or false, got %q\n' "$overwrite" >&2
    exit 64
    ;;
esac
case "$preflight_only" in
true | false) ;;
*)
    printf 'OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY must be true or false, got %q\n' "$preflight_only" >&2
    exit 64
    ;;
esac

if [[ -n "$trace_override" && ! -f "$trace_override" ]]; then
    printf 'OXIDEDNS_ZONE_IMAGE_GATE_TRACE_FILE does not exist: %s\n' "$trace_override" >&2
    exit 64
fi

export OXIDEDNS_BENCH_RECORDS="${OXIDEDNS_BENCH_RECORDS:-1000}"
export OXIDEDNS_BENCH_STRESS_CANDIDATES="${OXIDEDNS_BENCH_STRESS_CANDIDATES:-128}"
export OXIDEDNS_BENCH_DURATION_SECONDS="${OXIDEDNS_BENCH_DURATION_SECONDS:-3}"
export OXIDEDNS_BENCH_TRANSPORT="${OXIDEDNS_BENCH_TRANSPORT:-udp}"
export OXIDEDNS_BENCH_SERVER_THREADS="${OXIDEDNS_BENCH_SERVER_THREADS:-4}"
export OXIDEDNS_BENCH_CLIENT_THREADS="${OXIDEDNS_BENCH_CLIENT_THREADS:-4}"
export OXIDEDNS_BENCH_CLIENT_WINDOW="${OXIDEDNS_BENCH_CLIENT_WINDOW:-16}"
export OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS="${OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:-250}"
export OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED="${OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED:-false}"
export OXIDEDNS_BENCH_LISTEN_ADDRESS="${OXIDEDNS_BENCH_LISTEN_ADDRESS:-127.0.0.1}"
export OXIDEDNS_BENCH_CLIENT_SERVER="${OXIDEDNS_BENCH_CLIENT_SERVER:-$OXIDEDNS_BENCH_LISTEN_ADDRESS}"
client_mode="${OXIDEDNS_BENCH_CLIENT_MODE:-local}"
case "$client_mode" in
local | ssh) ;;
*)
    printf 'OXIDEDNS_BENCH_CLIENT_MODE must be local or ssh, got %q\n' "$client_mode" >&2
    exit 64
    ;;
esac
if [[ "$require_non_loopback" == true ]]; then
    case "$remote_client_allow_arch_mismatch" in
    true | false) ;;
    *)
        printf 'OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH must be true or false, got %q\n' "$remote_client_allow_arch_mismatch" >&2
        exit 64
        ;;
    esac
    if [[ "$client_mode" != ssh ]]; then
        printf 'OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true requires OXIDEDNS_BENCH_CLIENT_MODE=ssh\n' >&2
        exit 64
    fi
    if [[ -z "${OXIDEDNS_BENCH_REMOTE_CLIENT_SSH:-}" ]]; then
        printf 'OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true requires OXIDEDNS_BENCH_REMOTE_CLIENT_SSH\n' >&2
        exit 64
    fi
    if ! [[ "$ssh_connect_timeout" =~ ^[1-9][0-9]*$ ]]; then
        printf 'OXIDEDNS_ZONE_IMAGE_GATE_SSH_CONNECT_TIMEOUT_SECONDS must be a positive integer, got %q\n' "$ssh_connect_timeout" >&2
        exit 64
    fi
    if ! command -v ssh >/dev/null 2>&1; then
        printf 'OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true requires ssh on PATH\n' >&2
        exit 69
    fi
    if ! ssh -o BatchMode=yes -o "ConnectTimeout=$ssh_connect_timeout" "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" true; then
        printf 'remote benchmark client SSH preflight failed for %s\n' "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" >&2
        exit 69
    fi
    local_arch="$(uname -m | tr -d '\r')"
    if ! remote_arch="$(ssh -o BatchMode=yes -o "ConnectTimeout=$ssh_connect_timeout" "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" 'uname -m' | tr -d '\r')"; then
        printf 'remote benchmark client architecture preflight failed for %s\n' "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" >&2
        exit 69
    fi
    if [[ -z "$remote_arch" ]]; then
        printf 'remote benchmark client architecture preflight returned an empty architecture for %s\n' "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" >&2
        exit 69
    fi
    if [[ "$local_arch" != "$remote_arch" && "$remote_client_allow_arch_mismatch" != true ]]; then
        printf 'remote benchmark client architecture mismatch: local=%q remote=%q. The benchmark copies the local dns-load-client binary to the remote host; set OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH=true only if you will replace or run a compatible remote binary manually.\n' "$local_arch" "$remote_arch" >&2
        exit 69
    fi
    local_host_id="$(hash_identity "$(local_host_identity | tr -d '\r')")"
    if ! remote_host_raw="$(ssh -o BatchMode=yes -o "ConnectTimeout=$ssh_connect_timeout" "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" 'if [ -r /proc/sys/kernel/random/boot_id ]; then cat /proc/sys/kernel/random/boot_id; else hostname; fi' | tr -d '\r')"; then
        printf 'remote benchmark client host-identity preflight failed for %s\n' "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" >&2
        exit 69
    fi
    if [[ -z "$remote_host_raw" ]]; then
        printf 'remote benchmark client host-identity preflight returned an empty identity for %s\n' "$OXIDEDNS_BENCH_REMOTE_CLIENT_SSH" >&2
        exit 69
    fi
    remote_host_id="$(hash_identity "$remote_host_raw")"
    if [[ "$local_host_id" == unknown || "$remote_host_id" == unknown ]]; then
        printf 'remote benchmark client host-identity preflight could not compute a host identity digest\n' >&2
        exit 69
    fi
    if [[ "$local_host_id" == "$remote_host_id" ]]; then
        printf 'physical NIC evidence requested, but OXIDEDNS_BENCH_REMOTE_CLIENT_SSH appears to resolve to the local server host\n' >&2
        exit 64
    fi
fi
export OXIDEDNS_BENCH_CLIENT_MODE="$client_mode"
export OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS="${OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS:-$ssh_connect_timeout}"
if [[ "$client_mode" == ssh ]]; then
    export OXIDEDNS_BENCH_CLIENT_BIND="${OXIDEDNS_BENCH_CLIENT_BIND:-0.0.0.0:0}"
else
    export OXIDEDNS_BENCH_CLIENT_BIND="${OXIDEDNS_BENCH_CLIENT_BIND:-127.0.0.1:0}"
fi
export OXIDEDNS_BENCH_NETWORK_DEVICE="${OXIDEDNS_BENCH_NETWORK_DEVICE:-auto}"
if [[ "$require_non_loopback" == true ]]; then
    export OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true
else
    export OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE="${OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE:-false}"
fi

if [[ "$preflight_only" == true ]]; then
    preflight_output="$gate_dir.preflight.env"
    mkdir -p "$(dirname "$preflight_output")"
    OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR="$current_dir" \
        OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false \
        OXIDEDNS_BENCH_PREFLIGHT_ONLY=true \
        "$repo_root/scripts/benchmark-dns-clients.sh" >"$preflight_output"
    printf 'zone_image_evidence_gate_preflight=passed\n'
    printf 'preflight_output=%s\n' "$preflight_output"
    printf 'gate_dir=%s\n' "$gate_dir"
    printf 'require_non_loopback=%s\n' "$require_non_loopback"
    printf 'client_mode=%s\n' "$OXIDEDNS_BENCH_CLIENT_MODE"
    printf 'remote_client_ssh=%s\n' "${OXIDEDNS_BENCH_REMOTE_CLIENT_SSH:-none}"
    printf 'network_device=%s\n' "$OXIDEDNS_BENCH_NETWORK_DEVICE"
    exit 0
fi

if [[ -d "$gate_dir" ]] && [[ -n "$(find "$gate_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    if [[ "$overwrite" != true ]]; then
        printf 'ZoneImage evidence gate directory is not empty: %s\n' "$gate_dir" >&2
        printf 'Set OXIDEDNS_ZONE_IMAGE_GATE_OVERWRITE=true or choose a new OXIDEDNS_ZONE_IMAGE_GATE_DIR.\n' >&2
        exit 64
    fi
    rm -rf "$current_dir" "$zone_image_dir" "$comparison_path" "$gate_dir/README.md"
fi
mkdir -p "$gate_dir"

if [[ -n "$trace_override" ]]; then
    OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR="$current_dir" \
        OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false \
        OXIDEDNS_BENCH_TRACE_FILE="$trace_override" \
        "$repo_root/scripts/benchmark-dns-clients.sh"
else
    OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR="$current_dir" \
        OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false \
        OXIDEDNS_BENCH_TRACE_ENABLED=true \
        "$repo_root/scripts/benchmark-dns-clients.sh"
fi

retained_trace="$current_dir/query-trace.tsv"
if [[ ! -f "$retained_trace" ]]; then
    printf 'current-path benchmark did not retain query-trace.tsv at %s\n' "$retained_trace" >&2
    exit 1
fi

OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR="$zone_image_dir" \
    OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=true \
    OXIDEDNS_BENCH_TRACE_FILE="$retained_trace" \
    "$repo_root/scripts/benchmark-dns-clients.sh"

compare_args=(
    --current "$current_dir"
    --zone-image "$zone_image_dir"
    --min-qps-ratio "$min_qps_ratio"
    --output "$comparison_path"
    --require-direct-and-semantic
)
if [[ -n "$max_p50_ratio" ]]; then
    compare_args+=(--max-p50-ratio "$max_p50_ratio")
fi
if [[ -n "$max_p99_ratio" ]]; then
    compare_args+=(--max-p99-ratio "$max_p99_ratio")
fi
if [[ -n "$max_p999_ratio" ]]; then
    compare_args+=(--max-p999-ratio "$max_p999_ratio")
fi
if [[ "$require_non_loopback" == true ]]; then
    compare_args+=(--require-non-loopback)
fi

"$repo_root/scripts/compare-zone-image-benchmarks.py" "${compare_args[@]}"

cat >"$gate_dir/README.md" <<EOF
# ZoneImage Evidence Gate

This artifact was generated by \`scripts/zone-image-evidence-gate.sh\`.

It contains:

- \`current/\`: live runtime benchmark with \`zone_image_serve_enabled=false\`.
- \`zone-image/\`: live runtime benchmark with \`zone_image_serve_enabled=true\`.
- \`comparison.tsv\`: machine-readable comparison and pass/fail result.

The ZoneImage run replays the exact \`current/query-trace.tsv\` retained by the
current-path run.

Gate configuration:

- records: \`$OXIDEDNS_BENCH_RECORDS\`
- stress candidates: \`$OXIDEDNS_BENCH_STRESS_CANDIDATES\`
- transport: \`$OXIDEDNS_BENCH_TRANSPORT\`
- duration seconds: \`$OXIDEDNS_BENCH_DURATION_SECONDS\`
- server threads: \`$OXIDEDNS_BENCH_SERVER_THREADS\`
- client threads: \`$OXIDEDNS_BENCH_CLIENT_THREADS\`
- client window: \`$OXIDEDNS_BENCH_CLIENT_WINDOW\`
- client mode: \`$OXIDEDNS_BENCH_CLIENT_MODE\`
- remote client ssh: \`${OXIDEDNS_BENCH_REMOTE_CLIENT_SSH:-none}\`
- client bind: \`$OXIDEDNS_BENCH_CLIENT_BIND\`
- network device: \`$OXIDEDNS_BENCH_NETWORK_DEVICE\`
- require non-loopback: \`$require_non_loopback\`
- minimum QPS ratio: \`$min_qps_ratio\`
- maximum p50 ratio: \`${max_p50_ratio:-not-set}\`
- maximum p99 ratio: \`${max_p99_ratio:-not-set}\`
- maximum p999 ratio: \`${max_p999_ratio:-not-set}\`
EOF

printf 'zone_image_evidence_gate_dir=%s\n' "$gate_dir"
