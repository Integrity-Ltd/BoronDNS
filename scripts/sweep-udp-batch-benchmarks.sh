#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
sweep_dir="${BORONDNS_UDP_BATCH_SWEEP_DIR:-$repo_root/target/evidence/udp-batch-sweep-$timestamp}"
batch_sizes_raw="${BORONDNS_UDP_BATCH_SWEEP_SIZES:-1 8 32 64}"
overwrite="${BORONDNS_UDP_BATCH_SWEEP_OVERWRITE:-false}"
preflight_only="${BORONDNS_UDP_BATCH_SWEEP_PREFLIGHT_ONLY:-false}"
trace_override="${BORONDNS_UDP_BATCH_SWEEP_TRACE_FILE:-}"

case "$overwrite" in
true | false) ;;
*)
    printf 'BORONDNS_UDP_BATCH_SWEEP_OVERWRITE must be true or false, got %q\n' "$overwrite" >&2
    exit 64
    ;;
esac
case "$preflight_only" in
true | false) ;;
*)
    printf 'BORONDNS_UDP_BATCH_SWEEP_PREFLIGHT_ONLY must be true or false, got %q\n' "$preflight_only" >&2
    exit 64
    ;;
esac
if [[ -n "$trace_override" && ! -f "$trace_override" ]]; then
    printf 'BORONDNS_UDP_BATCH_SWEEP_TRACE_FILE does not exist: %s\n' "$trace_override" >&2
    exit 64
fi

read -r -a batch_sizes <<<"$batch_sizes_raw"
if ((${#batch_sizes[@]} == 0)); then
    printf 'BORONDNS_UDP_BATCH_SWEEP_SIZES must contain at least one positive integer\n' >&2
    exit 64
fi
for batch_size in "${batch_sizes[@]}"; do
    if ! [[ "$batch_size" =~ ^[1-9][0-9]*$ ]]; then
        printf 'BORONDNS_UDP_BATCH_SWEEP_SIZES contains a non-positive integer: %q\n' "$batch_size" >&2
        exit 64
    fi
done

export BORONDNS_BENCH_TRANSPORT=udp
export BORONDNS_BENCH_RECORDS="${BORONDNS_BENCH_RECORDS:-1000}"
export BORONDNS_BENCH_STRESS_CANDIDATES="${BORONDNS_BENCH_STRESS_CANDIDATES:-128}"
export BORONDNS_BENCH_DURATION_SECONDS="${BORONDNS_BENCH_DURATION_SECONDS:-3}"
export BORONDNS_BENCH_SERVER_THREADS="${BORONDNS_BENCH_SERVER_THREADS:-4}"
export BORONDNS_BENCH_CLIENT_THREADS="${BORONDNS_BENCH_CLIENT_THREADS:-4}"
export BORONDNS_BENCH_CLIENT_WINDOW="${BORONDNS_BENCH_CLIENT_WINDOW:-16}"
export BORONDNS_BENCH_RESPONSE_TIMEOUT_MS="${BORONDNS_BENCH_RESPONSE_TIMEOUT_MS:-250}"
export BORONDNS_BENCH_PIPELINE_TIMING_ENABLED="${BORONDNS_BENCH_PIPELINE_TIMING_ENABLED:-false}"
export BORONDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED="${BORONDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED:-false}"
export BORONDNS_BENCH_PACKET_CAPTURE_ENABLED="${BORONDNS_BENCH_PACKET_CAPTURE_ENABLED:-false}"
export BORONDNS_BENCH_LISTEN_ADDRESS="${BORONDNS_BENCH_LISTEN_ADDRESS:-127.0.0.1}"
export BORONDNS_BENCH_CLIENT_SERVER="${BORONDNS_BENCH_CLIENT_SERVER:-$BORONDNS_BENCH_LISTEN_ADDRESS}"
export BORONDNS_BENCH_CLIENT_MODE="${BORONDNS_BENCH_CLIENT_MODE:-local}"
if [[ "$BORONDNS_BENCH_CLIENT_MODE" == ssh ]]; then
    export BORONDNS_BENCH_CLIENT_BIND="${BORONDNS_BENCH_CLIENT_BIND:-0.0.0.0:0}"
else
    export BORONDNS_BENCH_CLIENT_BIND="${BORONDNS_BENCH_CLIENT_BIND:-127.0.0.1:0}"
fi
export BORONDNS_BENCH_NETWORK_DEVICE="${BORONDNS_BENCH_NETWORK_DEVICE:-auto}"
export BORONDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE="${BORONDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE:-false}"

if [[ "$preflight_only" == true ]]; then
    first_dir="$sweep_dir/batch-${batch_sizes[0]}"
    mkdir -p "$(dirname "$sweep_dir")"
    BORONDNS_DNS_CLIENT_BENCHMARK_DIR="$first_dir" \
        BORONDNS_BENCH_UDP_BATCH_SIZE="${batch_sizes[0]}" \
        BORONDNS_BENCH_PREFLIGHT_ONLY=true \
        "$repo_root/scripts/benchmark-dns-clients.sh" >"$sweep_dir.preflight.env"
    printf 'udp_batch_sweep_preflight=passed\n'
    printf 'preflight_output=%s\n' "$sweep_dir.preflight.env"
    printf 'sweep_dir=%s\n' "$sweep_dir"
    printf 'batch_sizes=%s\n' "$batch_sizes_raw"
    exit 0
fi

if [[ -d "$sweep_dir" ]] && [[ -n "$(find "$sweep_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    if [[ "$overwrite" != true ]]; then
        printf 'UDP batch sweep directory is not empty: %s\n' "$sweep_dir" >&2
        printf 'Set BORONDNS_UDP_BATCH_SWEEP_OVERWRITE=true or choose a new BORONDNS_UDP_BATCH_SWEEP_DIR.\n' >&2
        exit 64
    fi
    rm -rf "$sweep_dir"
fi
mkdir -p "$sweep_dir"

summary_path="$sweep_dir/summary.tsv"
printf 'udp_batch_size\tartifact_dir\tresponses_per_second\tqps_ratio_to_baseline\tlatency_us_p50\tp50_ratio_to_baseline\tlatency_us_p99\tp99_ratio_to_baseline\tdropped\terrors\tudp_receive_batches\tudp_received_datagrams\treceive_datagrams_per_batch\tudp_send_batches\tudp_sent_datagrams\tsend_datagrams_per_batch\tzone_image_serve_hits\tzone_image_serve_direct_hits\tzone_image_serve_semantic_hits\tzone_image_serve_failures\tnetwork_device\tnetwork_rx_packets_delta\tnetwork_tx_packets_delta\n' >"$summary_path"

tsv_value() {
    local path="$1"
    local key="$2"
    awk -F'\t' -v key="$key" '$1 == key { print $2; exit }' "$path"
}

ratio() {
    python3 - "$1" "$2" <<'PY'
import sys
try:
    value = float(sys.argv[1])
    baseline = float(sys.argv[2])
except ValueError:
    print("nan")
else:
    print("nan" if baseline == 0 else f"{value / baseline:.3f}")
PY
}

per_batch() {
    python3 - "$1" "$2" <<'PY'
import sys
try:
    datagrams = float(sys.argv[1])
    batches = float(sys.argv[2])
except ValueError:
    print("nan")
else:
    print("nan" if batches == 0 else f"{datagrams / batches:.3f}")
PY
}

retained_trace="$trace_override"
baseline_qps=""
baseline_p50=""
baseline_p99=""

for index in "${!batch_sizes[@]}"; do
    batch_size="${batch_sizes[$index]}"
    artifact_dir="$sweep_dir/batch-$batch_size"
    if [[ -n "$retained_trace" ]]; then
        BORONDNS_DNS_CLIENT_BENCHMARK_DIR="$artifact_dir" \
            BORONDNS_BENCH_UDP_BATCH_SIZE="$batch_size" \
            BORONDNS_BENCH_TRACE_FILE="$retained_trace" \
            "$repo_root/scripts/benchmark-dns-clients.sh"
    else
        BORONDNS_DNS_CLIENT_BENCHMARK_DIR="$artifact_dir" \
            BORONDNS_BENCH_UDP_BATCH_SIZE="$batch_size" \
            BORONDNS_BENCH_TRACE_ENABLED=true \
            "$repo_root/scripts/benchmark-dns-clients.sh"
        retained_trace="$artifact_dir/query-trace.tsv"
    fi

    results="$artifact_dir/benchmark-results.tsv"
    if [[ ! -f "$results" ]]; then
        printf 'benchmark did not write expected results file: %s\n' "$results" >&2
        exit 1
    fi

    responses_per_second="$(tsv_value "$results" responses_per_second)"
    latency_us_p50="$(tsv_value "$results" latency_us_p50)"
    latency_us_p99="$(tsv_value "$results" latency_us_p99)"
    if [[ "$index" == 0 ]]; then
        baseline_qps="$responses_per_second"
        baseline_p50="$latency_us_p50"
        baseline_p99="$latency_us_p99"
    fi

    udp_receive_batches="$(tsv_value "$results" udp_receive_batches)"
    udp_received_datagrams="$(tsv_value "$results" udp_received_datagrams)"
    udp_send_batches="$(tsv_value "$results" udp_send_batches)"
    udp_sent_datagrams="$(tsv_value "$results" udp_sent_datagrams)"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$batch_size" \
        "$artifact_dir" \
        "$responses_per_second" \
        "$(ratio "$responses_per_second" "$baseline_qps")" \
        "$latency_us_p50" \
        "$(ratio "$latency_us_p50" "$baseline_p50")" \
        "$latency_us_p99" \
        "$(ratio "$latency_us_p99" "$baseline_p99")" \
        "$(tsv_value "$results" dropped)" \
        "$(tsv_value "$results" errors)" \
        "$udp_receive_batches" \
        "$udp_received_datagrams" \
        "$(per_batch "$udp_received_datagrams" "$udp_receive_batches")" \
        "$udp_send_batches" \
        "$udp_sent_datagrams" \
        "$(per_batch "$udp_sent_datagrams" "$udp_send_batches")" \
        "$(tsv_value "$results" zone_image_serve_hits)" \
        "$(tsv_value "$results" zone_image_serve_direct_hits)" \
        "$(tsv_value "$results" zone_image_serve_semantic_hits)" \
        "$(tsv_value "$results" zone_image_serve_failures)" \
        "$(tsv_value "$results" network_device)" \
        "$(tsv_value "$results" network_rx_packets_delta)" \
        "$(tsv_value "$results" network_tx_packets_delta)" \
        >>"$summary_path"
done

cat >"$sweep_dir/README.md" <<EOF
# BoronDNS UDP Batch Sweep

This artifact was generated by \`scripts/sweep-udp-batch-benchmarks.sh\`.

The sweep runs \`scripts/benchmark-dns-clients.sh\` repeatedly with the same UDP
runtime profile and different \`BORONDNS_BENCH_UDP_BATCH_SIZE\` values:
\`$batch_sizes_raw\`.

The first run generates or accepts the retained query trace. Later runs replay
that same \`query-trace.tsv\` through the live always-on ZoneImage serving path,
so \`summary.tsv\` compares UDP adapter batching under the same query mix.

This is local no-XDP evidence. It is not physical NIC promotion evidence unless
the underlying benchmark profile used \`BORONDNS_BENCH_CLIENT_MODE=ssh\`,
\`BORONDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true\`, and a non-loopback client
server/device that satisfy the stricter comparator gates.
EOF

printf 'udp_batch_sweep_dir=%s\n' "$sweep_dir"
printf 'udp_batch_sweep_summary=%s\n' "$summary_path"
