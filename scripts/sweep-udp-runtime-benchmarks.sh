#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
sweep_dir="${OXIDEDNS_UDP_RUNTIME_SWEEP_DIR:-$repo_root/target/evidence/udp-runtime-sweep-$timestamp}"
runtimes_raw="${OXIDEDNS_UDP_RUNTIME_SWEEP_RUNTIMES:-tokio dedicated}"
workers_raw="${OXIDEDNS_UDP_RUNTIME_SWEEP_WORKERS:-1 4}"
batch_sizes_raw="${OXIDEDNS_UDP_RUNTIME_SWEEP_BATCH_SIZES:-32 128 256 512}"
client_sockets_raw="${OXIDEDNS_UDP_RUNTIME_SWEEP_CLIENT_SOCKETS_PER_THREAD:-1 4}"
affinity_modes_raw="${OXIDEDNS_UDP_RUNTIME_SWEEP_AFFINITY_MODES:-none auto}"
overwrite="${OXIDEDNS_UDP_RUNTIME_SWEEP_OVERWRITE:-false}"
preflight_only="${OXIDEDNS_UDP_RUNTIME_SWEEP_PREFLIGHT_ONLY:-false}"
trace_override="${OXIDEDNS_UDP_RUNTIME_SWEEP_TRACE_FILE:-}"

case "$overwrite" in
true | false) ;;
*)
    printf 'OXIDEDNS_UDP_RUNTIME_SWEEP_OVERWRITE must be true or false, got %q\n' "$overwrite" >&2
    exit 64
    ;;
esac
case "$preflight_only" in
true | false) ;;
*)
    printf 'OXIDEDNS_UDP_RUNTIME_SWEEP_PREFLIGHT_ONLY must be true or false, got %q\n' "$preflight_only" >&2
    exit 64
    ;;
esac
if [[ -n "$trace_override" && ! -f "$trace_override" ]]; then
    printf 'OXIDEDNS_UDP_RUNTIME_SWEEP_TRACE_FILE does not exist: %s\n' "$trace_override" >&2
    exit 64
fi

read -r -a runtimes <<<"$runtimes_raw"
read -r -a workers_list <<<"$workers_raw"
read -r -a batch_sizes <<<"$batch_sizes_raw"
read -r -a client_sockets_list <<<"$client_sockets_raw"
read -r -a affinity_modes <<<"$affinity_modes_raw"
if ((${#runtimes[@]} == 0 || ${#workers_list[@]} == 0 || ${#batch_sizes[@]} == 0 || ${#client_sockets_list[@]} == 0 || ${#affinity_modes[@]} == 0)); then
    printf 'runtime, worker, batch-size, and affinity mode lists must not be empty\n' >&2
    exit 64
fi
for runtime in "${runtimes[@]}"; do
    case "$runtime" in
    tokio | dedicated) ;;
    *)
        printf 'unsupported runtime in OXIDEDNS_UDP_RUNTIME_SWEEP_RUNTIMES: %q\n' "$runtime" >&2
        exit 64
        ;;
    esac
done
for workers in "${workers_list[@]}"; do
    if ! [[ "$workers" =~ ^[1-9][0-9]*$ ]]; then
        printf 'worker list contains a non-positive integer: %q\n' "$workers" >&2
        exit 64
    fi
done
for batch_size in "${batch_sizes[@]}"; do
    if ! [[ "$batch_size" =~ ^[1-9][0-9]*$ ]]; then
        printf 'batch-size list contains a non-positive integer: %q\n' "$batch_size" >&2
        exit 64
    fi
done
for client_sockets in "${client_sockets_list[@]}"; do
    if ! [[ "$client_sockets" =~ ^[1-9][0-9]*$ ]]; then
        printf 'client-sockets list contains a non-positive integer: %q\n' "$client_sockets" >&2
        exit 64
    fi
done
for mode in "${affinity_modes[@]}"; do
    case "$mode" in
    none | auto) ;;
    *)
        printf 'unsupported affinity mode: %q\n' "$mode" >&2
        exit 64
        ;;
    esac
done

export OXIDEDNS_BENCH_TRANSPORT=udp
export OXIDEDNS_BENCH_RECORDS="${OXIDEDNS_BENCH_RECORDS:-10000}"
export OXIDEDNS_BENCH_STRESS_CANDIDATES="${OXIDEDNS_BENCH_STRESS_CANDIDATES:-0}"
export OXIDEDNS_BENCH_DURATION_SECONDS="${OXIDEDNS_BENCH_DURATION_SECONDS:-3}"
export OXIDEDNS_BENCH_SERVER_THREADS="${OXIDEDNS_BENCH_SERVER_THREADS:-4}"
export OXIDEDNS_BENCH_CLIENT_THREADS="${OXIDEDNS_BENCH_CLIENT_THREADS:-4}"
export OXIDEDNS_BENCH_CLIENT_WINDOW="${OXIDEDNS_BENCH_CLIENT_WINDOW:-16}"
export OXIDEDNS_BENCH_HOT_PATH_DETAIL="${OXIDEDNS_BENCH_HOT_PATH_DETAIL:-reduced}"
export OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS="${OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:-250}"
export OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED="${OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED:-false}"
export OXIDEDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED="${OXIDEDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED:-false}"
export OXIDEDNS_BENCH_PACKET_CAPTURE_ENABLED="${OXIDEDNS_BENCH_PACKET_CAPTURE_ENABLED:-false}"
export OXIDEDNS_BENCH_LISTEN_ADDRESS="${OXIDEDNS_BENCH_LISTEN_ADDRESS:-127.0.0.1}"
export OXIDEDNS_BENCH_CLIENT_SERVER="${OXIDEDNS_BENCH_CLIENT_SERVER:-$OXIDEDNS_BENCH_LISTEN_ADDRESS}"
export OXIDEDNS_BENCH_CLIENT_MODE="${OXIDEDNS_BENCH_CLIENT_MODE:-local}"
if [[ "$OXIDEDNS_BENCH_CLIENT_MODE" == ssh ]]; then
    export OXIDEDNS_BENCH_CLIENT_BIND="${OXIDEDNS_BENCH_CLIENT_BIND:-0.0.0.0:0}"
else
    export OXIDEDNS_BENCH_CLIENT_BIND="${OXIDEDNS_BENCH_CLIENT_BIND:-127.0.0.1:0}"
fi
export OXIDEDNS_BENCH_NETWORK_DEVICE="${OXIDEDNS_BENCH_NETWORK_DEVICE:-auto}"
export OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE="${OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE:-false}"

if [[ "$preflight_only" == true ]]; then
    mkdir -p "$(dirname "$sweep_dir")"
    OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR="$sweep_dir/preflight" \
        OXIDEDNS_BENCH_UDP_RUNTIME="${runtimes[0]}" \
        OXIDEDNS_BENCH_UDP_REUSEPORT_WORKERS="${workers_list[0]}" \
        OXIDEDNS_BENCH_UDP_BATCH_SIZE="${batch_sizes[0]}" \
        OXIDEDNS_BENCH_UDP_CLIENT_SOCKETS_PER_THREAD="${client_sockets_list[0]}" \
        OXIDEDNS_BENCH_PREFLIGHT_ONLY=true \
        "$repo_root/scripts/benchmark-dns-clients.sh" >"$sweep_dir.preflight.env"
    printf 'udp_runtime_sweep_preflight=passed\n'
    printf 'preflight_output=%s\n' "$sweep_dir.preflight.env"
    printf 'sweep_dir=%s\n' "$sweep_dir"
    exit 0
fi

if [[ -d "$sweep_dir" ]] && [[ -n "$(find "$sweep_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    if [[ "$overwrite" != true ]]; then
        printf 'UDP runtime sweep directory is not empty: %s\n' "$sweep_dir" >&2
        printf 'Set OXIDEDNS_UDP_RUNTIME_SWEEP_OVERWRITE=true or choose a new OXIDEDNS_UDP_RUNTIME_SWEEP_DIR.\n' >&2
        exit 64
    fi
    rm -rf "$sweep_dir"
fi
mkdir -p "$sweep_dir"

summary_path="$sweep_dir/summary.tsv"
printf 'udp_runtime\tudp_reuseport_workers\tudp_batch_size\tudp_client_sockets_per_thread\tudp_worker_cpu_affinity\tartifact_dir\tresponses_per_second\tlatency_us_p50\tlatency_us_p99\tlatency_us_p999\tdropped\terrors\tudp_receive_batches\tudp_received_datagrams\treceive_datagrams_per_batch\tudp_send_batches\tudp_sent_datagrams\tsend_datagrams_per_batch\tudp_mmsg_receive_syscalls\tudp_mmsg_receive_wouldblock_syscalls\tmmsg_receive_datagrams_per_syscall\tudp_mmsg_send_syscalls\tmmsg_send_datagrams_per_syscall\tudp_mmsg_send_partial_syscalls\tudp_mmsg_send_wouldblock_retries\tudp_worker_receive_slots\tudp_worker_received_datagrams_imbalance_ratio\tudp_worker_send_slots\tudp_worker_sent_datagrams_imbalance_ratio\tnetwork_device\tnetwork_rx_packets_delta\tnetwork_tx_packets_delta\tnetwork_rx_gbps\tnetwork_tx_gbps\tnetwork_sum_gbps\tnetwork_rx_gigabytes_per_second\tnetwork_tx_gigabytes_per_second\tnetwork_sum_gigabytes_per_second\tnetwork_rx_bytes_per_response\tnetwork_tx_bytes_per_response\tnetwork_sum_bytes_per_response\tnetwork_throughput_scope\n' >"$summary_path"

tsv_value() {
    local path="$1"
    local key="$2"
    awk -F'\t' -v key="$key" '$1 == key { print $2; exit }' "$path"
}

per_unit() {
    python3 - "$1" "$2" <<'PY'
import sys
try:
    numerator = float(sys.argv[1])
    denominator = float(sys.argv[2])
except ValueError:
    print("nan")
else:
    print("nan" if denominator == 0 else f"{numerator / denominator:.3f}")
PY
}

auto_affinity() {
    local workers="$1"
    local values=()
    local index
    for ((index = 0; index < workers; index++)); do
        values+=("$index")
    done
    local IFS=,
    printf '%s' "${values[*]}"
}

retained_trace="$trace_override"
for runtime in "${runtimes[@]}"; do
    for workers in "${workers_list[@]}"; do
        for batch_size in "${batch_sizes[@]}"; do
            for client_sockets in "${client_sockets_list[@]}"; do
                for affinity_mode in "${affinity_modes[@]}"; do
                    if [[ "$affinity_mode" == auto && "$runtime" != dedicated ]]; then
                        continue
                    fi
                    if [[ "$affinity_mode" == auto && "$workers" == 1 ]]; then
                        continue
                    fi
                    affinity_value=""
                    affinity_label="none"
                    if [[ "$affinity_mode" == auto ]]; then
                        affinity_value="$(auto_affinity "$workers")"
                        affinity_label="${affinity_value//,/-}"
                    fi
                    artifact_dir="$sweep_dir/${runtime}-workers${workers}-batch${batch_size}-client-sockets${client_sockets}-affinity-${affinity_label}"
                    run_env=(
                        OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR="$artifact_dir"
                        OXIDEDNS_BENCH_UDP_RUNTIME="$runtime"
                        OXIDEDNS_BENCH_UDP_REUSEPORT_WORKERS="$workers"
                        OXIDEDNS_BENCH_UDP_BATCH_SIZE="$batch_size"
                        OXIDEDNS_BENCH_UDP_CLIENT_SOCKETS_PER_THREAD="$client_sockets"
                    )
                    if [[ -n "$affinity_value" ]]; then
                        run_env+=(OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY="$affinity_value")
                    else
                        run_env+=(OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY="")
                    fi
                    if [[ -n "$retained_trace" ]]; then
                        run_env+=(OXIDEDNS_BENCH_TRACE_FILE="$retained_trace")
                    else
                        run_env+=(OXIDEDNS_BENCH_TRACE_ENABLED=true)
                    fi
                    env "${run_env[@]}" "$repo_root/scripts/benchmark-dns-clients.sh"
                    if [[ -z "$retained_trace" ]]; then
                        retained_trace="$artifact_dir/query-trace.tsv"
                    fi

                    results="$artifact_dir/benchmark-results.tsv"
                    if [[ ! -f "$results" ]]; then
                        printf 'benchmark did not write expected results file: %s\n' "$results" >&2
                        exit 1
                    fi
                    udp_receive_batches="$(tsv_value "$results" udp_receive_batches)"
                    udp_received_datagrams="$(tsv_value "$results" udp_received_datagrams)"
                    udp_send_batches="$(tsv_value "$results" udp_send_batches)"
                    udp_sent_datagrams="$(tsv_value "$results" udp_sent_datagrams)"
                    udp_mmsg_receive_syscalls="$(tsv_value "$results" udp_mmsg_receive_syscalls)"
                    udp_mmsg_receive_wouldblock_syscalls="$(tsv_value "$results" udp_mmsg_receive_wouldblock_syscalls)"
                    udp_mmsg_received_datagrams="$(tsv_value "$results" udp_mmsg_received_datagrams)"
                    udp_mmsg_send_syscalls="$(tsv_value "$results" udp_mmsg_send_syscalls)"
                    udp_mmsg_sent_datagrams="$(tsv_value "$results" udp_mmsg_sent_datagrams)"
                    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                        "$runtime" \
                        "$workers" \
                        "$batch_size" \
                        "$client_sockets" \
                        "${affinity_value:-none}" \
                        "$artifact_dir" \
                        "$(tsv_value "$results" responses_per_second)" \
                        "$(tsv_value "$results" latency_us_p50)" \
                        "$(tsv_value "$results" latency_us_p99)" \
                        "$(tsv_value "$results" latency_us_p999)" \
                        "$(tsv_value "$results" dropped)" \
                        "$(tsv_value "$results" errors)" \
                        "$udp_receive_batches" \
                        "$udp_received_datagrams" \
                        "$(per_unit "$udp_received_datagrams" "$udp_receive_batches")" \
                        "$udp_send_batches" \
                        "$udp_sent_datagrams" \
                        "$(per_unit "$udp_sent_datagrams" "$udp_send_batches")" \
                        "$udp_mmsg_receive_syscalls" \
                        "${udp_mmsg_receive_wouldblock_syscalls:-0}" \
                        "$(per_unit "$udp_mmsg_received_datagrams" "$udp_mmsg_receive_syscalls")" \
                        "$udp_mmsg_send_syscalls" \
                        "$(per_unit "$udp_mmsg_sent_datagrams" "$udp_mmsg_send_syscalls")" \
                        "$(tsv_value "$results" udp_mmsg_send_partial_syscalls)" \
                        "$(tsv_value "$results" udp_mmsg_send_wouldblock_retries)" \
                        "$(tsv_value "$results" udp_worker_receive_slots)" \
                        "$(tsv_value "$results" udp_worker_received_datagrams_imbalance_ratio)" \
                        "$(tsv_value "$results" udp_worker_send_slots)" \
                        "$(tsv_value "$results" udp_worker_sent_datagrams_imbalance_ratio)" \
                        "$(tsv_value "$results" network_device)" \
                        "$(tsv_value "$results" network_rx_packets_delta)" \
                        "$(tsv_value "$results" network_tx_packets_delta)" \
                        "$(tsv_value "$results" network_rx_gbps)" \
                        "$(tsv_value "$results" network_tx_gbps)" \
                        "$(tsv_value "$results" network_sum_gbps)" \
                        "$(tsv_value "$results" network_rx_gigabytes_per_second)" \
                        "$(tsv_value "$results" network_tx_gigabytes_per_second)" \
                        "$(tsv_value "$results" network_sum_gigabytes_per_second)" \
                        "$(tsv_value "$results" network_rx_bytes_per_response)" \
                        "$(tsv_value "$results" network_tx_bytes_per_response)" \
                        "$(tsv_value "$results" network_sum_bytes_per_response)" \
                        "$(tsv_value "$results" network_throughput_scope)" \
                        >>"$summary_path"
                done
            done
        done
    done
done

python3 - "$summary_path" >"$sweep_dir/best.tsv" <<'PY'
import csv
import sys
from pathlib import Path

summary = Path(sys.argv[1])
with summary.open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
if not rows:
    raise SystemExit("empty UDP runtime sweep summary")
rows.sort(key=lambda row: float(row["responses_per_second"]), reverse=True)
writer = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys(), delimiter="\t", lineterminator="\n")
writer.writeheader()
writer.writerows(rows[: min(10, len(rows))])
PY

cat >"$sweep_dir/README.md" <<EOF
# OxideDNS UDP Runtime Sweep

This artifact was generated by \`scripts/sweep-udp-runtime-benchmarks.sh\`.

The sweep compares UDP runtime, reuseport worker count, batch size, and optional
CPU affinity modes under one retained query trace. \`summary.tsv\` records the
full run matrix; \`best.tsv\` lists the highest-throughput rows.

Runtimes: \`$runtimes_raw\`
Workers: \`$workers_raw\`
Batch sizes: \`$batch_sizes_raw\`
Client sockets per thread: \`$client_sockets_raw\`
Affinity modes: \`$affinity_modes_raw\`

This is local no-XDP evidence. It is not physical NIC promotion evidence unless
the underlying benchmark profile used a separate client and non-loopback device.
EOF

printf 'udp_runtime_sweep_dir=%s\n' "$sweep_dir"
printf 'udp_runtime_sweep_summary=%s\n' "$summary_path"
printf 'udp_runtime_sweep_best=%s\n' "$sweep_dir/best.tsv"
