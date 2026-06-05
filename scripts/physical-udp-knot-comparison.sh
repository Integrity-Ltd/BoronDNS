#!/usr/bin/env bash
# shellcheck disable=SC2029
set -euo pipefail

server_ssh="${OXIDEDNS_PHYSICAL_SERVER_SSH:-oxidedns-1}"
player_ssh="${OXIDEDNS_PHYSICAL_PLAYER_SSH:-oxidegun-1}"
server_root="${OXIDEDNS_PHYSICAL_SERVER_ROOT:-~/oxidedns}"
server_bin="${OXIDEDNS_PHYSICAL_SERVER_BIN:-}"
server_prefix="${OXIDEDNS_PHYSICAL_SERVER_PREFIX:-}"
player_workdir="${OXIDEDNS_PHYSICAL_PLAYER_WORKDIR:-~/oxidedns-tools/bench}"
target_ip="${OXIDEDNS_PHYSICAL_TARGET_IP:-198.18.0.1}"
source_ip="${OXIDEDNS_PHYSICAL_SOURCE_IP:-198.18.0.2}"
interface="${OXIDEDNS_PHYSICAL_INTERFACE:-eno1np0}"
oxidedns_port="${OXIDEDNS_PHYSICAL_OXIDEDNS_PORT:-5300}"
knot_port="${OXIDEDNS_PHYSICAL_KNOT_PORT:-5301}"
duration="${OXIDEDNS_PHYSICAL_DURATION:-5}"
batch="${OXIDEDNS_PHYSICAL_KXDPGUN_BATCH:-10}"
kxdpgun_mode="${OXIDEDNS_PHYSICAL_KXDPGUN_MODE:-generic}"
perf_record="${OXIDEDNS_PHYSICAL_PERF_RECORD:-false}"
perf_frequency="${OXIDEDNS_PHYSICAL_PERF_FREQUENCY:-999}"
perf_report_timeout="${OXIDEDNS_PHYSICAL_PERF_REPORT_TIMEOUT:-30s}"
perf_report_children="${OXIDEDNS_PHYSICAL_PERF_REPORT_CHILDREN:-true}"
socket_sample="${OXIDEDNS_PHYSICAL_SOCKET_SAMPLE:-false}"
socket_sample_interval="${OXIDEDNS_PHYSICAL_SOCKET_SAMPLE_INTERVAL:-0.25}"
include_knot="${OXIDEDNS_PHYSICAL_INCLUDE_KNOT:-false}"
workers_list="${OXIDEDNS_PHYSICAL_WORKERS:-24}"
rates_list="${OXIDEDNS_PHYSICAL_RATES:-2000000}"
hot_path_list="${OXIDEDNS_PHYSICAL_HOT_PATH_DETAILS:-reduced off}"
idle_strategy_list="${OXIDEDNS_PHYSICAL_IDLE_STRATEGIES:-park spin}"
socket_buffer_bytes="${OXIDEDNS_PHYSICAL_SOCKET_BUFFER_BYTES:-}"
socket_receive_buffer_bytes="${OXIDEDNS_PHYSICAL_SOCKET_RECEIVE_BUFFER_BYTES:-$socket_buffer_bytes}"
socket_send_buffer_bytes="${OXIDEDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES:-$socket_buffer_bytes}"
socket_max_pacing_rates_bytes_per_second="${OXIDEDNS_PHYSICAL_SOCKET_MAX_PACING_RATES_BYTES_PER_SECOND:-${OXIDEDNS_PHYSICAL_SOCKET_MAX_PACING_RATE_BYTES_PER_SECOND:-__none__}}"
worker_cpus="${OXIDEDNS_PHYSICAL_WORKER_CPUS:-}"
udp_batch_sizes="${OXIDEDNS_PHYSICAL_UDP_BATCH_SIZES:-staged}"
server_txqueuelen="${OXIDEDNS_PHYSICAL_SERVER_TXQUEUELEN:-}"
server_tx_qdisc="${OXIDEDNS_PHYSICAL_SERVER_TX_QDISC:-}"
server_tx_fq_limit="${OXIDEDNS_PHYSICAL_SERVER_TX_FQ_LIMIT:-10000}"
server_tx_fq_flow_limit="${OXIDEDNS_PHYSICAL_SERVER_TX_FQ_FLOW_LIMIT:-}"
server_tx_fq_quantum="${OXIDEDNS_PHYSICAL_SERVER_TX_FQ_QUANTUM:-}"
server_tx_fq_initial_quantum="${OXIDEDNS_PHYSICAL_SERVER_TX_FQ_INITIAL_QUANTUM:-}"
server_tx_fq_pacing="${OXIDEDNS_PHYSICAL_SERVER_TX_FQ_PACING:-}"
server_tx_ring="${OXIDEDNS_PHYSICAL_SERVER_TX_RING:-}"
server_rmem_max="${OXIDEDNS_PHYSICAL_SERVER_RMEM_MAX:-}"
server_wmem_max="${OXIDEDNS_PHYSICAL_SERVER_WMEM_MAX:-}"
stage_override="${OXIDEDNS_PHYSICAL_STAGE:-}"
original_server_txqueuelen=""
original_server_tx_ring=""
original_server_rmem_max=""
original_server_wmem_max=""

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$1" >&2
        exit 69
    fi
}

require_tool ssh
require_tool base64

ssh_control_dir="$(mktemp -d "${TMPDIR:-/tmp}/oxidedns-physical-ssh.XXXXXX")"
ssh_control_options=(
    -o ControlMaster=auto
    -o ControlPersist=180
    -o ControlPath="$ssh_control_dir/%C"
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=2
)

ssh_control() {
    command ssh "${ssh_control_options[@]}" "$@"
}

close_ssh_control() {
    command ssh "${ssh_control_options[@]}" -O exit "$server_ssh" >/dev/null 2>&1 || true
    command ssh "${ssh_control_options[@]}" -O exit "$player_ssh" >/dev/null 2>&1 || true
    rm -rf "$ssh_control_dir"
}

remote_server_root() {
    ssh_control "$server_ssh" "cd $server_root && pwd"
}

resolve_stage() {
    if [[ -n "$stage_override" ]]; then
        ssh_control "$server_ssh" "cd $server_root && realpath '$stage_override'"
    else
        ssh_control "$server_ssh" "cd $server_root && stage=\$(cat ~/oxidedns-last-benchmark-stage.txt 2>/dev/null || ls -td target/physical-knot-comparison-*/staged | head -1) && realpath \"\$stage\""
    fi
}

remote_player_workdir() {
    ssh_control "$player_ssh" "cd $player_workdir && pwd"
}

cleanup_remote() {
    ssh_control "$server_ssh" "pkill -u codex -x oxidedns 2>/dev/null || true; pkill -u codex -x knotd 2>/dev/null || true" >/dev/null 2>&1 || true
    if [[ -n "$server_tx_qdisc" && -n "${out_abs:-}" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$out_abs/host/server-tx-qdisc-restore.tsv" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
restore_file="$2"
if [[ -f "$restore_file" ]]; then
    while IFS=$'\t' read -r parent kind; do
        [[ -n "$parent" && -n "$kind" ]] || continue
        sudo tc qdisc replace dev "$iface" parent "$parent" "$kind" || true
    done <"$restore_file"
fi
REMOTE
    fi
    if [[ -n "$server_txqueuelen" && -n "$original_server_txqueuelen" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$original_server_txqueuelen" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
txqueuelen="$2"
        sudo ip link set dev "$iface" txqueuelen "$txqueuelen"
REMOTE
    fi
    if [[ -n "$server_tx_ring" && -n "$original_server_tx_ring" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$original_server_tx_ring" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
tx_ring="$2"
sudo ethtool -G "$iface" tx "$tx_ring"
REMOTE
    fi
    if [[ -n "$server_rmem_max" && -n "$original_server_rmem_max" ]]; then
        ssh_control "$server_ssh" "sudo sysctl -w net.core.rmem_max='$original_server_rmem_max'" >/dev/null 2>&1 || true
    fi
    if [[ -n "$server_wmem_max" && -n "$original_server_wmem_max" ]]; then
        ssh_control "$server_ssh" "sudo sysctl -w net.core.wmem_max='$original_server_wmem_max'" >/dev/null 2>&1 || true
    fi
    close_ssh_control
}

trap cleanup_remote EXIT

server_root_abs="$(remote_server_root)"
stage_abs="$(resolve_stage)"
player_workdir_abs="$(remote_player_workdir)"
out_abs="$stage_abs/evidence/physical-udp-knot-comparison-$(date -u +%Y%m%dT%H%M%SZ)"
server_bin_arg="${server_bin:-__default__}"
if [[ -n "$server_prefix" ]]; then
    server_prefix_arg="$(printf '%s' "$server_prefix" | base64 | tr -d '\n')"
else
    server_prefix_arg="__none__"
fi

ssh_control "$server_ssh" "mkdir -p '$out_abs' && printf 'target\\tworkers\\trate\\tkxdpgun_batch\\tkxdpgun_mode\\tudp_batch_size\\thot_path_detail\\tidle_strategy\\tsocket_receive_buffer_bytes\\tsocket_send_buffer_bytes\\tsocket_max_pacing_rate_bytes_per_second\\tserver_txqueuelen\\tserver_tx_ring\\tserver_tx_qdisc\\tserver_tx_fq_limit\\tserver_tx_fq_flow_limit\\tserver_rmem_max\\tserver_wmem_max\\tworker_cpus\\tserver_prefix\\treplies_per_second\\treply_percent\\tdns_reply_size\\tethernet_reply_bps\\tduration_seconds\\tserver_rx_packets_delta\\tserver_tx_packets_delta\\tserver_qdisc_dropped_delta\\tserver_qdisc_requeues_delta\\tserver_udp_in_datagrams_delta\\tserver_udp_out_datagrams_delta\\tserver_udp_in_errors_delta\\tserver_udp_rcvbuf_errors_delta\\tserver_udp_sndbuf_errors_delta\\tserver_udp_mmsg_send_syscalls\\tserver_udp_mmsg_sent_datagrams\\tserver_udp_mmsg_send_partial_syscalls\\tserver_udp_mmsg_send_wouldblock_retries\\tserver_udp_mmsg_receive_syscalls\\tserver_udp_mmsg_received_datagrams\\tsoftnet_dropped_delta\\tsoftnet_time_squeeze_delta\\tserver_qdisc_flows_plimit_delta\\n' > '$out_abs/summary.tsv'"

declare -A run_id_counts=()
run_id=""

select_run_id() {
    local base_run_id="$1"
    local count

    count="${run_id_counts[$base_run_id]:-0}"
    run_id_counts["$base_run_id"]=$((count + 1))
    if ((count == 0)); then
        run_id="$base_run_id"
    else
        run_id="${base_run_id}-repeat${count}"
    fi
}

server_link_txqueuelen() {
    ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
ip -o link show dev "$iface" | sed -n 's/.*qlen \([0-9][0-9]*\).*/\1/p'
REMOTE
}

server_link_tx_ring() {
    ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
ethtool -g "$iface" 2>/dev/null | awk '
    /^Current hardware settings:/ {current = 1; next}
    current && $1 == "TX:" {print $2; exit}
'
REMOTE
}

configure_server_link_tuning() {
    local effective_txqueuelen
    local effective_wmem_max

    ssh_control "$server_ssh" "mkdir -p '$out_abs/host'"
    if [[ -n "$server_tx_qdisc" ]]; then
        case "$server_tx_qdisc" in
        fq | fq_codel | pfifo_fast) ;;
        *)
            printf 'unsupported OXIDEDNS_PHYSICAL_SERVER_TX_QDISC: %s\n' "$server_tx_qdisc" >&2
            exit 64
            ;;
        esac
        case "$server_tx_fq_pacing" in
        "" | pacing | nopacing) ;;
        *)
            printf 'unsupported OXIDEDNS_PHYSICAL_SERVER_TX_FQ_PACING: %s\n' "$server_tx_fq_pacing" >&2
            exit 64
            ;;
        esac
        ssh_control "$server_ssh" bash -s -- "$interface" "$server_tx_qdisc" "$out_abs" "$server_tx_fq_limit" "${server_tx_fq_flow_limit:-__none__}" "${server_tx_fq_quantum:-__none__}" "${server_tx_fq_initial_quantum:-__none__}" "${server_tx_fq_pacing:-__none__}" <<'REMOTE'
set -euo pipefail
iface="$1"
requested_qdisc="$2"
out_abs="$3"
requested_fq_limit="$4"
requested_fq_flow_limit="$5"
requested_fq_quantum="$6"
requested_fq_initial_quantum="$7"
requested_fq_pacing="$8"
restore_file="$out_abs/host/server-tx-qdisc-restore.tsv"
if [[ "$requested_fq_flow_limit" == "__none__" ]]; then
    requested_fq_flow_limit=""
fi
if [[ "$requested_fq_quantum" == "__none__" ]]; then
    requested_fq_quantum=""
fi
if [[ "$requested_fq_initial_quantum" == "__none__" ]]; then
    requested_fq_initial_quantum=""
fi
if [[ "$requested_fq_pacing" == "__none__" ]]; then
    requested_fq_pacing=""
fi
tc qdisc show dev "$iface" >"$out_abs/host/server-tx-qdisc-before.txt" 2>&1 || true
tc qdisc show dev "$iface" |
    awk '$1 == "qdisc" && $4 == "parent" {
        parent = $5
        if (parent ~ /^:/) {
            parent = "0" parent
        }
        print parent "\t" $2
    }' >"$restore_file"
if [[ ! -s "$restore_file" ]]; then
    printf 'no per-queue qdisc children found for %s\n' "$iface" >&2
    exit 65
fi
while IFS=$'\t' read -r parent _kind; do
    case "$requested_qdisc" in
    fq)
        qdisc_args=(fq limit "$requested_fq_limit")
        if [[ -n "$requested_fq_flow_limit" ]]; then
            qdisc_args+=(flow_limit "$requested_fq_flow_limit")
        fi
        if [[ -n "$requested_fq_quantum" ]]; then
            qdisc_args+=(quantum "$requested_fq_quantum")
        fi
        if [[ -n "$requested_fq_initial_quantum" ]]; then
            qdisc_args+=(initial_quantum "$requested_fq_initial_quantum")
        fi
        if [[ -n "$requested_fq_pacing" ]]; then
            qdisc_args+=("$requested_fq_pacing")
        fi
        sudo tc qdisc replace dev "$iface" parent "$parent" "${qdisc_args[@]}"
        ;;
    fq_codel | pfifo_fast)
        sudo tc qdisc replace dev "$iface" parent "$parent" "$requested_qdisc"
        ;;
    esac
done <"$restore_file"
tc qdisc show dev "$iface" >"$out_abs/host/server-tx-qdisc-after.txt" 2>&1 || true
REMOTE
    fi
    original_server_txqueuelen="$(server_link_txqueuelen)"
    if [[ -n "$server_txqueuelen" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$server_txqueuelen" <<'REMOTE'
set -euo pipefail
iface="$1"
txqueuelen="$2"
sudo ip link set dev "$iface" txqueuelen "$txqueuelen"
REMOTE
    fi
    effective_txqueuelen="$(server_link_txqueuelen)"
    original_server_tx_ring="$(server_link_tx_ring)"
    if [[ -n "$server_tx_ring" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$server_tx_ring" <<'REMOTE'
set -euo pipefail
iface="$1"
tx_ring="$2"
sudo ethtool -G "$iface" tx "$tx_ring"
REMOTE
    fi
    effective_tx_ring="$(server_link_tx_ring)"
    original_server_rmem_max="$(ssh_control "$server_ssh" "sysctl -n net.core.rmem_max")"
    if [[ -n "$server_rmem_max" ]]; then
        ssh_control "$server_ssh" "sudo sysctl -w net.core.rmem_max='$server_rmem_max'" >/dev/null
    fi
    effective_rmem_max="$(ssh_control "$server_ssh" "sysctl -n net.core.rmem_max")"
    original_server_wmem_max="$(ssh_control "$server_ssh" "sysctl -n net.core.wmem_max")"
    if [[ -n "$server_wmem_max" ]]; then
        ssh_control "$server_ssh" "sudo sysctl -w net.core.wmem_max='$server_wmem_max'" >/dev/null
    fi
    effective_wmem_max="$(ssh_control "$server_ssh" "sysctl -n net.core.wmem_max")"
    ssh_control "$server_ssh" bash -s -- "$out_abs" "$original_server_txqueuelen" "${server_txqueuelen:-__none__}" "$effective_txqueuelen" "$original_server_tx_ring" "${server_tx_ring:-__none__}" "$effective_tx_ring" "$server_tx_fq_limit" "${server_tx_fq_flow_limit:-__none__}" "${server_tx_fq_quantum:-__none__}" "${server_tx_fq_initial_quantum:-__none__}" "${server_tx_fq_pacing:-__none__}" "$original_server_rmem_max" "${server_rmem_max:-__none__}" "$effective_rmem_max" "$original_server_wmem_max" "${server_wmem_max:-__none__}" "$effective_wmem_max" <<'REMOTE'
set -euo pipefail
out_abs="$1"
original_txqueuelen="$2"
requested_txqueuelen="$3"
effective_txqueuelen="$4"
original_tx_ring="$5"
requested_tx_ring="$6"
effective_tx_ring="$7"
requested_fq_limit="$8"
requested_fq_flow_limit="$9"
requested_fq_quantum="${10}"
requested_fq_initial_quantum="${11}"
requested_fq_pacing="${12}"
original_rmem_max="${13}"
requested_rmem_max="${14}"
effective_rmem_max="${15}"
original_wmem_max="${16}"
requested_wmem_max="${17}"
effective_wmem_max="${18}"
if [[ "$requested_txqueuelen" == "__none__" ]]; then
    requested_txqueuelen=""
fi
if [[ "$requested_fq_flow_limit" == "__none__" ]]; then
    requested_fq_flow_limit=""
fi
if [[ "$requested_fq_quantum" == "__none__" ]]; then
    requested_fq_quantum=""
fi
if [[ "$requested_fq_initial_quantum" == "__none__" ]]; then
    requested_fq_initial_quantum=""
fi
if [[ "$requested_fq_pacing" == "__none__" ]]; then
    requested_fq_pacing=""
fi
if [[ "$requested_tx_ring" == "__none__" ]]; then
    requested_tx_ring=""
fi
if [[ "$requested_rmem_max" == "__none__" ]]; then
    requested_rmem_max=""
fi
if [[ "$requested_wmem_max" == "__none__" ]]; then
    requested_wmem_max=""
fi
cat >"$out_abs/host/server-link-tuning.txt" <<EOF
original_txqueuelen=$original_txqueuelen
requested_txqueuelen=$requested_txqueuelen
effective_txqueuelen=$effective_txqueuelen
original_tx_ring=$original_tx_ring
requested_tx_ring=$requested_tx_ring
effective_tx_ring=$effective_tx_ring
requested_fq_limit=$requested_fq_limit
requested_fq_flow_limit=$requested_fq_flow_limit
requested_fq_quantum=$requested_fq_quantum
requested_fq_initial_quantum=$requested_fq_initial_quantum
requested_fq_pacing=$requested_fq_pacing
original_rmem_max=$original_rmem_max
requested_rmem_max=$requested_rmem_max
effective_rmem_max=$effective_rmem_max
original_wmem_max=$original_wmem_max
requested_wmem_max=$requested_wmem_max
effective_wmem_max=$effective_wmem_max
EOF
REMOTE
}

capture_static_host_context() {
    local player_context

    ssh_control "$server_ssh" bash -s -- "$out_abs" "$interface" <<'REMOTE'
set -euo pipefail
out_abs="$1"
server_interface="$2"
mkdir -p "$out_abs/host"
{
    hostname
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    nproc
} >"$out_abs/host/server-system.txt"
lscpu -e=CPU,CORE,SOCKET,NODE,ONLINE >"$out_abs/host/server-lscpu.tsv" 2>&1 || true
ip -s link show dev "$server_interface" >"$out_abs/host/server-ip-link.txt" 2>&1 || true
tc -s qdisc show dev "$server_interface" >"$out_abs/host/server-tc-qdisc.txt" 2>&1 || true
cp /proc/interrupts "$out_abs/host/server-proc-interrupts.txt"
cp /proc/softirqs "$out_abs/host/server-proc-softirqs.txt"
ethtool -i "$server_interface" >"$out_abs/host/server-ethtool-driver.txt" 2>&1 || true
ethtool -g "$server_interface" >"$out_abs/host/server-ethtool-ring.txt" 2>&1 || true
ethtool -l "$server_interface" >"$out_abs/host/server-ethtool-channels.txt" 2>&1 || true
ethtool -x "$server_interface" >"$out_abs/host/server-ethtool-rss.txt" 2>&1 || true
ethtool -k "$server_interface" >"$out_abs/host/server-ethtool-features.txt" 2>&1 || true
REMOTE

    player_context="$(
        ssh_control "$player_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
player_interface="$1"
{
    printf 'system\n'
    hostname
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    nproc
    printf '\nlscpu\n'
    lscpu -e=CPU,CORE,SOCKET,NODE,ONLINE 2>&1 || true
    printf '\nethtool_channels\n'
    ethtool -l "$player_interface" 2>&1 || true
    printf '\nethtool_driver\n'
    ethtool -i "$player_interface" 2>&1 || true
    printf '\ninterrupts\n'
    grep -E "$player_interface|mlx|enp|eth" /proc/interrupts 2>/dev/null || true
}
REMOTE
    )"
    printf '%s\n' "$player_context" | ssh_control "$server_ssh" "cat > '$out_abs/host/player-context.txt'"
}

configure_server_link_tuning
capture_static_host_context

run_knot_reference_start() {
    local run_abs="$1"
    local server_interface="$2"

    ssh_control "$server_ssh" bash -s -- "$stage_abs" "$run_abs" "$target_ip" "$knot_port" "$server_interface" <<'REMOTE'
set -euo pipefail
stage_abs="$1"
run_abs="$2"
knot_target_ip="$3"
knot_target_port="$4"
server_interface="$5"

mkdir -p "$run_abs"
pkill -u codex -x oxidedns 2>/dev/null || true
pkill -u codex -x knotd 2>/dev/null || true
sleep 0.2

cd "$stage_abs"
knotd -c knot.conf -v >"$run_abs/knot.log" 2>&1 &
echo $! >"$run_abs/knot.pid"
for _ in $(seq 1 80); do
    if dig @"$knot_target_ip" -p "$knot_target_port" perf.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

cp /proc/net/dev "$run_abs/server-proc-net-dev-before.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-before.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-before.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-before.txt" 2>&1 || true
tc -s qdisc show dev "$server_interface" >"$run_abs/server-tc-qdisc-before.txt" 2>&1 || true
REMOTE
}

run_knot_reference_stop() {
    local run_abs="$1"

    ssh_control "$server_ssh" bash -s -- "$run_abs" <<'REMOTE'
set -euo pipefail
run_abs="$1"
if [[ -f "$run_abs/knot.pid" ]]; then
    kill "$(cat "$run_abs/knot.pid")" 2>/dev/null || true
    wait "$(cat "$run_abs/knot.pid")" 2>/dev/null || true
fi
REMOTE
}

run_server_start() {
    local run_abs="$1"
    local workers="$2"
    local hot_path="$3"
    local idle_strategy="$4"
    local knot_target_ip="$5"
    local knot_target_port="$6"
    local socket_receive_buffer="$7"
    local socket_send_buffer="$8"
    local socket_max_pacing_rate="$9"
    local cpus="${10}"
    local selected_server_bin="${11}"
    local selected_server_prefix="${12}"
    local server_interface="${13}"
    local udp_batch_size="${14}"
    local socket_receive_buffer_arg="${socket_receive_buffer:-__none__}"
    local socket_send_buffer_arg="${socket_send_buffer:-__none__}"
    local socket_max_pacing_rate_arg="${socket_max_pacing_rate:-__none__}"
    local cpus_arg="${cpus:-__none__}"
    local udp_batch_size_arg="${udp_batch_size:-staged}"

    ssh_control "$server_ssh" bash -s -- "$server_root_abs" "$stage_abs" "$run_abs" "$workers" "$hot_path" "$idle_strategy" "$knot_target_ip" "$knot_target_port" "$socket_receive_buffer_arg" "$socket_send_buffer_arg" "$socket_max_pacing_rate_arg" "$cpus_arg" "$selected_server_bin" "$selected_server_prefix" "$server_interface" "$udp_batch_size_arg" <<'REMOTE'
set -euo pipefail
server_root="$1"
stage_abs="$2"
run_abs="$3"
workers="$4"
hot_path="$5"
idle_strategy="$6"
knot_target_ip="$7"
knot_target_port="$8"
socket_receive_buffer="$9"
socket_send_buffer="${10}"
socket_max_pacing_rate="${11}"
cpus="${12}"
server_bin="${13}"
server_prefix_b64="${14}"
server_interface="${15}"
udp_batch_size="${16}"
if [[ "$socket_receive_buffer" == "__none__" ]]; then
    socket_receive_buffer=""
fi
if [[ "$socket_send_buffer" == "__none__" ]]; then
    socket_send_buffer=""
fi
if [[ "$socket_max_pacing_rate" == "__none__" ]]; then
    socket_max_pacing_rate=""
fi
if [[ "$cpus" == "__none__" ]]; then
    cpus=""
fi
if [[ "$server_bin" == "__default__" ]]; then
    server_bin="$server_root/target/release/oxidedns"
elif [[ "$server_bin" != /* ]]; then
    server_bin="$server_root/$server_bin"
fi
server_prefix=""
if [[ "$server_prefix_b64" != "__none__" ]]; then
    server_prefix="$(printf '%s' "$server_prefix_b64" | base64 -d)"
fi
server_cmd=()
if [[ -n "$server_prefix" ]]; then
    read -r -a server_cmd <<< "$server_prefix"
fi
server_cmd+=("$server_bin")

mkdir -p "$run_abs"
pkill -u codex -x oxidedns 2>/dev/null || true
pkill -u codex -x knotd 2>/dev/null || true
sleep 0.2

cp "$stage_abs/oxidedns.toml" "$run_abs/oxidedns.toml"
python3 - "$run_abs/oxidedns.toml" "$workers" "$hot_path" "$idle_strategy" <<'PY'
import re
import sys

path, workers, hot_path, idle_strategy = sys.argv[1:5]
text = open(path, encoding="utf-8").read()
text = re.sub(r"udp_reuseport_workers = \d+", f"udp_reuseport_workers = {workers}", text)
text = re.sub(r'hot_path_detail = "[^"]+"', f'hot_path_detail = "{hot_path}"', text)
if "udp_idle_strategy" in text:
    text = re.sub(r'udp_idle_strategy = "[^"]+"', f'udp_idle_strategy = "{idle_strategy}"', text)
else:
    text = text.replace(
        'udp_runtime = "dedicated"',
        f'udp_runtime = "dedicated"\nudp_idle_strategy = "{idle_strategy}"',
    )
open(path, "w", encoding="utf-8").write(text)
PY
if [[ -n "$socket_receive_buffer" || -n "$socket_send_buffer" || -n "$socket_max_pacing_rate" ]]; then
    python3 - "$run_abs/oxidedns.toml" "$socket_receive_buffer" "$socket_send_buffer" "$socket_max_pacing_rate" <<'PY'
import re
import sys

path, socket_receive_buffer, socket_send_buffer, socket_max_pacing_rate = sys.argv[1:5]
text = open(path, encoding="utf-8").read()
for key, value in (
    ("udp_socket_receive_buffer_bytes", socket_receive_buffer),
    ("udp_socket_send_buffer_bytes", socket_send_buffer),
    ("udp_socket_max_pacing_rate_bytes_per_second", socket_max_pacing_rate),
):
    if not value:
        continue
    if key in text:
        text = re.sub(rf"{key} = \d+", f"{key} = {value}", text)
    else:
        text = text.replace('udp_runtime = "dedicated"', f'udp_runtime = "dedicated"\n{key} = {value}')
open(path, "w", encoding="utf-8").write(text)
PY
fi
if [[ "$udp_batch_size" != "staged" ]]; then
    python3 - "$run_abs/oxidedns.toml" "$udp_batch_size" <<'PY'
import re
import sys

path, udp_batch_size = sys.argv[1:3]
text = open(path, encoding="utf-8").read()
if "udp_batch_size" in text:
    text = re.sub(r"udp_batch_size = \d+", f"udp_batch_size = {udp_batch_size}", text)
else:
    text = text.replace('udp_runtime = "dedicated"', f'udp_runtime = "dedicated"\nudp_batch_size = {udp_batch_size}')
open(path, "w", encoding="utf-8").write(text)
PY
fi
if [[ -n "$cpus" ]]; then
    python3 - "$run_abs/oxidedns.toml" "$cpus" <<'PY'
import re
import sys

path, cpus = sys.argv[1:3]
cpu_values = [int(cpu.strip()) for cpu in cpus.split(",") if cpu.strip()]
cpu_text = ", ".join(str(cpu) for cpu in cpu_values)
text = open(path, encoding="utf-8").read()
if "udp_worker_cpu_affinity" in text:
    text = re.sub(r"udp_worker_cpu_affinity = \[[^\]]*\]", f"udp_worker_cpu_affinity = [{cpu_text}]", text)
else:
    text = text.replace(
        'udp_reuseport_workers = ',
        f'udp_worker_cpu_affinity = [{cpu_text}]\nudp_reuseport_workers = ',
    )
open(path, "w", encoding="utf-8").write(text)
PY
fi

"${server_cmd[@]}" --validate-config "$run_abs/oxidedns.toml" >"$run_abs/validate.out" 2>&1

cd "$stage_abs"
knotd -c knot.conf -v >"$run_abs/knot.log" 2>&1 &
echo $! >"$run_abs/knot.pid"
for _ in $(seq 1 80); do
    if dig @"$knot_target_ip" -p "$knot_target_port" perf.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

ulimit -n 65536
"${server_cmd[@]}" serve --config "$run_abs/oxidedns.toml" >"$run_abs/oxidedns.log" 2>&1 &
echo $! >"$run_abs/oxidedns.pid"

ready=""
for _ in $(seq 1 180); do
    ready="$(curl -fsS http://127.0.0.1:8080/readyz 2>/dev/null || true)"
    if [[ "$ready" == ready ]] || printf '%s' "$ready" | grep -q ready; then
        break
    fi
    sleep 0.25
done
if ! ([[ "$ready" == ready ]] || printf '%s' "$ready" | grep -q ready); then
    tail -80 "$run_abs/oxidedns.log" >&2
    exit 1
fi

kill "$(cat "$run_abs/knot.pid")" 2>/dev/null || true
wait "$(cat "$run_abs/knot.pid")" 2>/dev/null || true
cp /proc/net/dev "$run_abs/server-proc-net-dev-before.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-before.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-before.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-before.txt" 2>&1 || true
REMOTE
}

run_server_finish() {
    local run_abs="$1"
    local target="$2"
    local workers="$3"
    local rate="$4"
    local selected_kxdpgun_batch="$5"
    local selected_kxdpgun_mode="$6"
    local udp_batch_size="$7"
    local hot_path="$8"
    local idle_strategy="$9"
    local socket_receive_buffer="${10}"
    local socket_send_buffer="${11}"
    local socket_max_pacing_rate="${12}"
    local cpus="${13}"
    local selected_server_prefix_b64="${14}"
    local server_interface="${15}"
    local socket_receive_buffer_arg="${socket_receive_buffer:-__none__}"
    local socket_send_buffer_arg="${socket_send_buffer:-__none__}"
    local socket_max_pacing_rate_arg="${socket_max_pacing_rate:-__none__}"
    local cpus_arg="${cpus:-__none__}"
    local server_prefix_arg="${selected_server_prefix_b64:-__none__}"
    local udp_batch_size_arg="${udp_batch_size:-staged}"

    ssh_control "$server_ssh" bash -s -- "$out_abs" "$run_abs" "$target" "$workers" "$rate" "$selected_kxdpgun_batch" "$selected_kxdpgun_mode" "$udp_batch_size_arg" "$hot_path" "$idle_strategy" "$socket_receive_buffer_arg" "$socket_send_buffer_arg" "$socket_max_pacing_rate_arg" "$cpus_arg" "$server_prefix_arg" "$server_interface" <<'REMOTE'
set -euo pipefail
out_abs="$1"
run_abs="$2"
target="$3"
workers="$4"
rate="$5"
kxdpgun_batch="$6"
kxdpgun_mode="$7"
udp_batch_size="$8"
hot_path="$9"
idle_strategy="${10}"
socket_receive_buffer="${11}"
socket_send_buffer="${12}"
socket_max_pacing_rate="${13}"
cpus="${14}"
server_prefix_b64="${15}"
server_interface="${16}"
if [[ "$socket_receive_buffer" == "__none__" ]]; then
    socket_receive_buffer=""
fi
if [[ "$socket_send_buffer" == "__none__" ]]; then
    socket_send_buffer=""
fi
if [[ "$socket_max_pacing_rate" == "__none__" ]]; then
    socket_max_pacing_rate=""
fi
if [[ "$cpus" == "__none__" ]]; then
    cpus=""
fi
server_prefix=""
if [[ "$server_prefix_b64" != "__none__" ]]; then
    server_prefix="$(printf '%s' "$server_prefix_b64" | base64 -d)"
fi
server_txqueuelen="$(ip -o link show dev "$server_interface" | sed -n 's/.*qlen \([0-9][0-9]*\).*/\1/p')"
server_tx_ring="$(ethtool -g "$server_interface" 2>/dev/null | awk '
    /^Current hardware settings:/ {current = 1; next}
    current && $1 == "TX:" {print $2; exit}
')"
server_tx_qdisc="$(tc qdisc show dev "$server_interface" | awk '
    $1 == "qdisc" && $4 == "parent" {count[$2] += 1}
    END {
        first = 1
        for (kind in count) {
            if (!first) {
                printf ","
            }
            printf "%s:%d", kind, count[kind]
            first = 0
        }
        if (first) {
            printf "unknown"
        }
    }
')"
server_tx_fq_limit="$(tc qdisc show dev "$server_interface" | awk '$1 == "qdisc" && $2 == "fq" && $4 == "parent" && !printed {
    for (field = 1; field <= NF; field++) {
        if ($field == "limit" && field < NF) {
            print $(field + 1)
            printed = 1
        }
    }
}')"
server_tx_fq_flow_limit="$(tc qdisc show dev "$server_interface" | awk '$1 == "qdisc" && $2 == "fq" && $4 == "parent" && !printed {
    for (field = 1; field <= NF; field++) {
        if ($field == "flow_limit" && field < NF) {
            print $(field + 1)
            printed = 1
        }
    }
}')"
server_rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || printf unknown)"
server_wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || printf unknown)"

cp /proc/net/dev "$run_abs/server-proc-net-dev-after.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-after.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-after.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-after.txt" 2>&1 || true
tc -s qdisc show dev "$server_interface" >"$run_abs/server-tc-qdisc-after.txt" 2>&1 || true
curl -fsS http://127.0.0.1:8080/metrics >"$run_abs/metrics-after.prom" 2>/dev/null || true
python3 - "$target" "$workers" "$rate" "$kxdpgun_batch" "$kxdpgun_mode" "$udp_batch_size" "$hot_path" "$idle_strategy" "$socket_receive_buffer" "$socket_send_buffer" "$socket_max_pacing_rate" "$server_txqueuelen" "$server_tx_ring" "$server_tx_qdisc" "$server_tx_fq_limit" "$server_tx_fq_flow_limit" "$server_rmem_max" "$server_wmem_max" "$cpus" "$server_prefix" "$server_interface" "$run_abs" "$run_abs/kxdpgun.log" >>"$out_abs/summary.tsv" <<'PY'
import re
import sys

target, workers, rate, kxdpgun_batch, kxdpgun_mode, udp_batch_size, hot_path, idle_strategy, socket_receive_buffer, socket_send_buffer, socket_max_pacing_rate, server_txqueuelen, server_tx_ring, server_tx_qdisc, server_tx_fq_limit, server_tx_fq_flow_limit, server_rmem_max, server_wmem_max, cpus, server_prefix, interface, run_abs, log = sys.argv[1:24]
text = open(log, encoding="utf-8", errors="ignore").read()
replies = re.search(r"total replies:\s+\d+ \(([0-9,]+) pps\) \(([0-9.]+) %\)", text)
size = re.search(r"average DNS reply size:\s+([0-9.]+) B", text)
bps = re.search(r"average Ethernet reply rate:\s+([0-9]+) bps", text)
duration = re.search(r"duration:\s+([0-9.]+) s", text)

def read(path):
    try:
        return open(path, encoding="utf-8", errors="ignore").read()
    except FileNotFoundError:
        return ""

def parse_dev_packets(path, device):
    for raw in read(path).splitlines():
        if ":" not in raw:
            continue
        name, values = raw.split(":", 1)
        if name.strip() != device:
            continue
        fields = values.split()
        return {
            "rx": int(fields[1]) if len(fields) > 1 else 0,
            "tx": int(fields[9]) if len(fields) > 9 else 0,
        }
    return {"rx": 0, "tx": 0}

def parse_udp_snmp(path):
    lines = read(path).splitlines()
    for index, raw in enumerate(lines[:-1]):
        if not raw.startswith("Udp:"):
            continue
        next_line = lines[index + 1]
        if not next_line.startswith("Udp:"):
            continue
        keys = raw.split()[1:]
        values = next_line.split()[1:]
        if len(keys) == len(values):
            return {key: int(value) for key, value in zip(keys, values)}
    return {}

def parse_softnet(path):
    processed = dropped = time_squeeze = 0
    for raw in read(path).splitlines():
        fields = raw.split()
        if len(fields) >= 3:
            processed += int(fields[0], 16)
            dropped += int(fields[1], 16)
            time_squeeze += int(fields[2], 16)
    return {"processed": processed, "dropped": dropped, "time_squeeze": time_squeeze}

def parse_qdisc(path):
    text = read(path)
    root = {"dropped": 0, "requeues": 0, "flows_plimit": 0}
    child_dropped = 0
    child_flows_plimit = 0
    current_kind = None
    for raw in text.splitlines():
        if raw.startswith("qdisc "):
            fields = raw.split()
            current_kind = fields[1] if len(fields) > 1 else None
            continue
        dropped = re.search(r"\(dropped ([0-9]+),", raw)
        requeues = re.search(r" requeues ([0-9]+)\)", raw)
        if dropped or requeues:
            values = {
                "dropped": int(dropped.group(1)) if dropped else 0,
                "requeues": int(requeues.group(1)) if requeues else 0,
            }
            if current_kind == "mq":
                root = values
            elif current_kind is not None:
                child_dropped += values["dropped"]
        flows_plimit = re.search(r"(?:^| )flows_plimit ([0-9]+)(?: |$)", raw)
        if flows_plimit and current_kind is not None:
            child_flows_plimit += int(flows_plimit.group(1))
    if child_dropped:
        root["dropped"] = child_dropped
    if child_flows_plimit:
        root["flows_plimit"] = child_flows_plimit
    return root

def parse_prom_metrics(path):
    values = {}
    for raw in read(path).splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split()
        if len(fields) < 2:
            continue
        try:
            values[fields[0]] = str(int(float(fields[1])))
        except ValueError:
            continue
    return values

def delta(before, after, key):
    return str(after.get(key, 0) - before.get(key, 0))

dev_before = parse_dev_packets(f"{run_abs}/server-proc-net-dev-before.txt", interface)
dev_after = parse_dev_packets(f"{run_abs}/server-proc-net-dev-after.txt", interface)
udp_before = parse_udp_snmp(f"{run_abs}/server-proc-net-snmp-before.txt")
udp_after = parse_udp_snmp(f"{run_abs}/server-proc-net-snmp-after.txt")
soft_before = parse_softnet(f"{run_abs}/server-proc-net-softnet-before.txt")
soft_after = parse_softnet(f"{run_abs}/server-proc-net-softnet-after.txt")
qdisc_before = parse_qdisc(f"{run_abs}/server-tc-qdisc-before.txt")
qdisc_after = parse_qdisc(f"{run_abs}/server-tc-qdisc-after.txt")
prom = parse_prom_metrics(f"{run_abs}/metrics-after.prom")

print("\t".join([
    target,
    workers,
    rate,
    kxdpgun_batch,
    kxdpgun_mode,
    udp_batch_size,
    hot_path,
    idle_strategy,
    socket_receive_buffer or "default",
    socket_send_buffer or "default",
    socket_max_pacing_rate or "default",
    server_txqueuelen or "unknown",
    server_tx_ring or "unknown",
    server_tx_qdisc or "unknown",
    server_tx_fq_limit or "default",
    server_tx_fq_flow_limit or "default",
    server_rmem_max or "unknown",
    server_wmem_max or "unknown",
    cpus or "unbound",
    server_prefix or "none",
    replies.group(1).replace(",", "") if replies else "",
    replies.group(2) if replies else "",
    size.group(1) if size else "",
    bps.group(1) if bps else "",
    duration.group(1) if duration else "",
    str(dev_after["rx"] - dev_before["rx"]),
    str(dev_after["tx"] - dev_before["tx"]),
    delta(qdisc_before, qdisc_after, "dropped"),
    delta(qdisc_before, qdisc_after, "requeues"),
    delta(udp_before, udp_after, "InDatagrams"),
    delta(udp_before, udp_after, "OutDatagrams"),
    delta(udp_before, udp_after, "InErrors"),
    delta(udp_before, udp_after, "RcvbufErrors"),
    delta(udp_before, udp_after, "SndbufErrors"),
    prom.get("oxidedns_udp_mmsg_send_syscalls_total", "0"),
    prom.get("oxidedns_udp_mmsg_sent_datagrams_total", "0"),
    prom.get("oxidedns_udp_mmsg_send_partial_syscalls_total", "0"),
    prom.get("oxidedns_udp_mmsg_send_wouldblock_retries_total", "0"),
    prom.get("oxidedns_udp_mmsg_receive_syscalls_total", "0"),
    prom.get("oxidedns_udp_mmsg_received_datagrams_total", "0"),
    delta(soft_before, soft_after, "dropped"),
    delta(soft_before, soft_after, "time_squeeze"),
    delta(qdisc_before, qdisc_after, "flows_plimit"),
]))
PY

if [[ -f "$run_abs/oxidedns.pid" ]]; then
    kill "$(cat "$run_abs/oxidedns.pid")" 2>/dev/null || true
    wait "$(cat "$run_abs/oxidedns.pid")" 2>/dev/null || true
fi
REMOTE
}

run_server_perf_start() {
    local run_abs="$1"
    local record="$2"
    local frequency="$3"
    local seconds="$4"

    if [[ "$record" != true ]]; then
        return 0
    fi

    ssh_control "$server_ssh" bash -s -- "$run_abs" "$frequency" "$seconds" <<'REMOTE'
set -euo pipefail
run_abs="$1"
frequency="$2"
seconds="$3"
pid="$(cat "$run_abs/oxidedns.pid")"
sudo perf record -F "$frequency" -g -p "$pid" -o "$run_abs/perf.data" -- sleep "$seconds" >"$run_abs/perf-record.log" 2>&1 &
echo $! >"$run_abs/perf.pid"
REMOTE
}

run_server_perf_finish() {
    local run_abs="$1"
    local record="$2"
    local report_timeout="$3"
    local report_children="$4"

    if [[ "$record" != true ]]; then
        return 0
    fi

    ssh_control "$server_ssh" bash -s -- "$run_abs" "$report_timeout" "$report_children" <<'REMOTE'
set -euo pipefail
run_abs="$1"
report_timeout="$2"
report_children="$3"
if [[ -f "$run_abs/perf.pid" ]]; then
    perf_pid="$(cat "$run_abs/perf.pid")"
    for _ in $(seq 1 120); do
        if ! ps -p "$perf_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.25
    done
    if ps -p "$perf_pid" >/dev/null 2>&1; then
        echo "perf record did not finish before timeout; terminating pid $perf_pid" >>"$run_abs/perf-record.log"
        sudo kill "$perf_pid" >/dev/null 2>&1 || kill "$perf_pid" >/dev/null 2>&1 || true
        sleep 1
    fi
fi
if [[ -f "$run_abs/perf.data" ]]; then
    timeout --kill-after=5s "$report_timeout" sudo perf report -i "$run_abs/perf.data" --stdio --no-children --sort comm,symbol,dso >"$run_abs/perf-report-symbols.txt" 2>"$run_abs/perf-report-symbols.err" || echo "perf symbols report failed or timed out after $report_timeout" >>"$run_abs/perf-report-symbols.err"
    if [[ "$report_children" == true ]]; then
        timeout --kill-after=5s "$report_timeout" sudo perf report -i "$run_abs/perf.data" --stdio --children --sort comm,symbol,dso >"$run_abs/perf-report-children.txt" 2>"$run_abs/perf-report-children.err" || echo "perf children report failed or timed out after $report_timeout" >>"$run_abs/perf-report-children.err"
    fi
fi
REMOTE
}

run_server_socket_sample_start() {
    local run_abs="$1"
    local enabled="$2"
    local port="$3"
    local seconds="$4"
    local interval="$5"

    if [[ "$enabled" != true ]]; then
        return 0
    fi

    ssh_control "$server_ssh" bash -s -- "$run_abs" "$port" "$seconds" "$interval" <<'REMOTE'
set -euo pipefail
run_abs="$1"
port="$2"
seconds="$3"
interval="$4"
(
    end="$(python3 - "$seconds" <<'PY'
import sys
import time

print(time.monotonic() + float(sys.argv[1]) + 1.0)
PY
)"
    while python3 - "$end" <<'PY'
import sys
import time

raise SystemExit(0 if time.monotonic() < float(sys.argv[1]) else 1)
PY
    do
        {
            date -u +%Y-%m-%dT%H:%M:%S.%NZ
            printf 'oxidedns_udp_port=%s\n' "$port"
            ss -H -u -a -n -m 2>&1 || true
        } >>"$run_abs/udp-socket-samples.txt"
        sleep "$interval"
    done
) &
echo $! >"$run_abs/udp-socket-sample.pid"
REMOTE
}

run_server_socket_sample_finish() {
    local run_abs="$1"
    local enabled="$2"

    if [[ "$enabled" != true ]]; then
        return 0
    fi

    ssh_control "$server_ssh" bash -s -- "$run_abs" <<'REMOTE'
set -euo pipefail
run_abs="$1"
if [[ -f "$run_abs/udp-socket-sample.pid" ]]; then
    sample_pid="$(cat "$run_abs/udp-socket-sample.pid")"
    for _ in $(seq 1 80); do
        if ! ps -p "$sample_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
fi
REMOTE
}

run_player_kxdpgun() {
    local run_abs="$1"
    local id="$2"
    local port="$3"
    local rate="$4"
    local local_log="$id.kxdpgun.tmp"
    local player_run_dir
    local remote_run_dir
    local status="255"
    local done="false"

    player_run_dir=".oxidedns-physical-${id}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    remote_run_dir="$player_workdir_abs/$player_run_dir"

    ssh_control "$player_ssh" bash -s -- "$player_workdir_abs" "$player_run_dir" "$duration" "$port" "$batch" "$rate" "$interface" "$kxdpgun_mode" "$source_ip" "$target_ip" <<'REMOTE'
set -euo pipefail
workdir="$1"
run_dir="$2"
duration="$3"
port="$4"
batch="$5"
rate="$6"
interface="$7"
mode="$8"
source_ip="$9"
target_ip="${10}"
mkdir -p "$workdir/$run_dir"
(
    cd "$workdir"
    set +e
    sudo kxdpgun -t "$duration" -p "$port" -b "$batch" -Q "$rate" -I "$interface" -m "$mode" -l "$source_ip" -i querydb "$target_ip"
    status="$?"
    printf '%s\n' "$status" >"$workdir/$run_dir/status"
    touch "$workdir/$run_dir/done"
) >"$workdir/$run_dir/kxdpgun.log" 2>&1 </dev/null &
echo "$!" >"$workdir/$run_dir/pid"
REMOTE

    for _ in $(seq 1 240); do
        if ssh_control "$player_ssh" "test -f '$remote_run_dir/done'" >/dev/null 2>&1; then
            done="true"
            break
        fi
        sleep 0.5
    done

    if [[ "$done" != true ]]; then
        {
            printf 'timed out waiting for detached kxdpgun run %s\n' "$id"
            ssh_control "$player_ssh" "cat '$remote_run_dir/kxdpgun.log' 2>/dev/null || true" || true
        } >"$local_log"
        status="124"
    else
        ssh_control "$player_ssh" "cat '$remote_run_dir/kxdpgun.log'" >"$local_log" 2>&1 || status="$?"
        if [[ "$status" == "255" ]]; then
            status="$(ssh_control "$player_ssh" "cat '$remote_run_dir/status'" 2>/dev/null || printf '255')"
        fi
    fi
    ssh_control "$server_ssh" "cat > '$run_abs/kxdpgun.log'" <"$local_log" || true
    ssh_control "$player_ssh" "rm -rf '$remote_run_dir'" >/dev/null 2>&1 || true
    rm -f "$local_log"
    [[ "$status" == "0" ]]
}

if [[ "$include_knot" == true ]]; then
    for rate in $rates_list; do
        select_run_id "knot-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        run_knot_reference_start "$run_abs" "$interface"
        run_player_kxdpgun "$run_abs" "$run_id" "$knot_port" "$rate"
        run_server_finish "$run_abs" "knot" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_knot_reference_stop "$run_abs"
    done
fi

for workers in $workers_list; do
    for rate in $rates_list; do
        for udp_batch_size in $udp_batch_sizes; do
            for hot_path in $hot_path_list; do
                for idle_strategy in $idle_strategy_list; do
                    for socket_max_pacing_rate in $socket_max_pacing_rates_bytes_per_second; do
                        pacing_run_suffix=""
                        socket_max_pacing_rate_arg="$socket_max_pacing_rate"
                        if [[ "$socket_max_pacing_rate" == "__none__" ]]; then
                            socket_max_pacing_rate_arg=""
                        else
                            pacing_run_suffix="-pace-${socket_max_pacing_rate}"
                        fi
                        select_run_id "oxidedns-w${workers}-q${rate}-batch-${udp_batch_size}-metrics-${hot_path}-idle-${idle_strategy}${pacing_run_suffix}"
                        run_abs="$out_abs/$run_id"
                        printf 'running %s\n' "$run_id"
                        run_server_start "$run_abs" "$workers" "$hot_path" "$idle_strategy" "$target_ip" "$knot_port" "$socket_receive_buffer_bytes" "$socket_send_buffer_bytes" "$socket_max_pacing_rate_arg" "$worker_cpus" "$server_bin_arg" "$server_prefix_arg" "$interface" "$udp_batch_size"
                        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration"
                        run_server_socket_sample_start "$run_abs" "$socket_sample" "$oxidedns_port" "$duration" "$socket_sample_interval"
                        run_player_kxdpgun "$run_abs" "$run_id" "$oxidedns_port" "$rate"
                        run_server_socket_sample_finish "$run_abs" "$socket_sample"
                        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
                        run_server_finish "$run_abs" "oxidedns" "$workers" "$rate" "$batch" "$kxdpgun_mode" "$udp_batch_size" "$hot_path" "$idle_strategy" "$socket_receive_buffer_bytes" "$socket_send_buffer_bytes" "$socket_max_pacing_rate_arg" "$worker_cpus" "$server_prefix_arg" "$interface"
                    done
                done
            done
        done
    done
done

printf 'artifact_dir=%s\n' "$out_abs"
ssh_control "$server_ssh" "cat '$out_abs/summary.tsv'"
