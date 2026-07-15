#!/usr/bin/env bash
# shellcheck disable=SC2029
set -euo pipefail

server_ssh="${BORONDNS_PHYSICAL_SERVER_SSH:-borondns-1}"
player_ssh="${BORONDNS_PHYSICAL_PLAYER_SSH:-oxidegun-1}"
server_root="${BORONDNS_PHYSICAL_SERVER_ROOT:-~/borondns}"
server_bin="${BORONDNS_PHYSICAL_SERVER_BIN:-}"
server_prefix="${BORONDNS_PHYSICAL_SERVER_PREFIX:-}"
player_workdir="${BORONDNS_PHYSICAL_PLAYER_WORKDIR:-~/borondns-tools/bench}"
target_ip="${BORONDNS_PHYSICAL_TARGET_IP:-198.18.0.1}"
source_ip="${BORONDNS_PHYSICAL_SOURCE_IP:-198.18.0.2}"
interface="${BORONDNS_PHYSICAL_INTERFACE:-eno1np0}"
borondns_port="${BORONDNS_PHYSICAL_BORONDNS_PORT:-5300}"
knot_port="${BORONDNS_PHYSICAL_KNOT_PORT:-5301}"
duration="${BORONDNS_PHYSICAL_DURATION:-5}"
batch="${BORONDNS_PHYSICAL_KXDPGUN_BATCH:-10}"
kxdpgun_mode="${BORONDNS_PHYSICAL_KXDPGUN_MODE:-auto}"
player_mtu="${BORONDNS_PHYSICAL_PLAYER_MTU:-${BORONDNS_PHYSICAL_KXDPGUN_MTU:-}}"
player_tool="${BORONDNS_PHYSICAL_PLAYER_TOOL:-kxdpgun}"
oxide_gun_bin="${BORONDNS_PHYSICAL_OXIDE_GUN_BIN:-__default__}"
oxide_gun_xdp_redirect_object="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_REDIRECT_OBJECT:-__default__}"
oxide_gun_xdp_mode="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_MODE:-drv}"
oxide_gun_xdp_zerocopy="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_ZERO_COPY:-auto}"
oxide_gun_xdp_batch_size="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_BATCH_SIZE:-64}"
oxide_gun_xdp_rx_drain_passes="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_RX_DRAIN_PASSES:-4}"
oxide_gun_xdp_tx_wakeup_interval="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_TX_WAKEUP_INTERVAL:-1}"
oxide_gun_xdp_pace_wait_fraction="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_PACE_WAIT_FRACTION:-__omit__}"
oxide_gun_xdp_umem_frame_count="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_UMEM_FRAME_COUNT:-16384}"
oxide_gun_xdp_ring_size="${BORONDNS_PHYSICAL_OXIDE_GUN_XDP_RING_SIZE:-4096}"
oxide_gun_queue_count="${BORONDNS_PHYSICAL_OXIDE_GUN_QUEUE_COUNT:-__auto__}"
oxide_gun_queue_list="${BORONDNS_PHYSICAL_OXIDE_GUN_QUEUE_LIST:-__none__}"
oxide_gun_knot_queue_list="${BORONDNS_PHYSICAL_OXIDE_GUN_KNOT_QUEUE_LIST:-$oxide_gun_queue_list}"
oxide_gun_borondns_queue_list="${BORONDNS_PHYSICAL_OXIDE_GUN_BORONDNS_QUEUE_LIST:-$oxide_gun_queue_list}"
oxide_gun_nsd_queue_list="${BORONDNS_PHYSICAL_OXIDE_GUN_NSD_QUEUE_LIST:-$oxide_gun_knot_queue_list}"
oxide_gun_source_port="${BORONDNS_PHYSICAL_OXIDE_GUN_SOURCE_PORT:-53000}"
oxide_gun_source_port_range="${BORONDNS_PHYSICAL_OXIDE_GUN_SOURCE_PORT_RANGE:-__auto__}"
oxide_gun_source_port_list="${BORONDNS_PHYSICAL_OXIDE_GUN_SOURCE_PORT_LIST:-__none__}"
oxide_gun_knot_source_port_list="${BORONDNS_PHYSICAL_OXIDE_GUN_KNOT_SOURCE_PORT_LIST:-$oxide_gun_source_port_list}"
oxide_gun_borondns_source_port_list="${BORONDNS_PHYSICAL_OXIDE_GUN_BORONDNS_SOURCE_PORT_LIST:-$oxide_gun_source_port_list}"
oxide_gun_nsd_source_port_list="${BORONDNS_PHYSICAL_OXIDE_GUN_NSD_SOURCE_PORT_LIST:-$oxide_gun_knot_source_port_list}"
oxide_gun_source_port_select="${BORONDNS_PHYSICAL_OXIDE_GUN_SOURCE_PORT_SELECT:-sequential}"
oxide_gun_response_timeout_ms="${BORONDNS_PHYSICAL_OXIDE_GUN_RESPONSE_TIMEOUT_MS:-1000}"
oxide_gun_source_mac="${BORONDNS_PHYSICAL_SOURCE_MAC:-b8:59:9f:4b:73:2c}"
oxide_gun_target_mac="${BORONDNS_PHYSICAL_TARGET_MAC:-1c:34:da:60:67:00}"
perf_record="${BORONDNS_PHYSICAL_PERF_RECORD:-false}"
perf_scope="${BORONDNS_PHYSICAL_PERF_SCOPE:-process}"
perf_event="${BORONDNS_PHYSICAL_PERF_EVENT:-__default__}"
perf_frequency="${BORONDNS_PHYSICAL_PERF_FREQUENCY:-999}"
perf_report_timeout="${BORONDNS_PHYSICAL_PERF_REPORT_TIMEOUT:-30s}"
perf_report_children="${BORONDNS_PHYSICAL_PERF_REPORT_CHILDREN:-true}"
socket_sample="${BORONDNS_PHYSICAL_SOCKET_SAMPLE:-false}"
socket_sample_interval="${BORONDNS_PHYSICAL_SOCKET_SAMPLE_INTERVAL:-0.25}"
include_borondns="${BORONDNS_PHYSICAL_INCLUDE_BORONDNS:-true}"
include_knot="${BORONDNS_PHYSICAL_INCLUDE_KNOT:-false}"
include_knot_xdp="${BORONDNS_PHYSICAL_INCLUDE_KNOT_XDP:-false}"
include_nsd="${BORONDNS_PHYSICAL_INCLUDE_NSD:-false}"
include_nsd_xdp="${BORONDNS_PHYSICAL_INCLUDE_NSD_XDP:-false}"
comparison_run_order="${BORONDNS_PHYSICAL_COMPARISON_RUN_ORDER:-knot-first}"
borondns_udp_backends="${BORONDNS_PHYSICAL_BORONDNS_UDP_BACKENDS:-std}"
knot_bin="${BORONDNS_PHYSICAL_KNOT_BIN:-knotd}"
nsd_bin="${BORONDNS_PHYSICAL_NSD_BIN:-/home/codex/nsd-xdp-master/sbin/nsd}"
nsd_checkconf="${BORONDNS_PHYSICAL_NSD_CHECKCONF:-}"
nsd_checkzone="${BORONDNS_PHYSICAL_NSD_CHECKZONE:-}"
nsd_port="${BORONDNS_PHYSICAL_NSD_PORT:-5302}"
nsd_xdp_port="${BORONDNS_PHYSICAL_NSD_XDP_PORT:-53}"
nsd_xdp_program="${BORONDNS_PHYSICAL_NSD_XDP_PROGRAM:-__default__}"
nsd_server_count="${BORONDNS_PHYSICAL_NSD_SERVER_COUNT:-48}"
nsd_run_as_user="${BORONDNS_PHYSICAL_NSD_RUN_AS_USER:-codex}"
workers_list="${BORONDNS_PHYSICAL_WORKERS:-24}"
rates_list="${BORONDNS_PHYSICAL_RATES:-2000000}"
hot_path_list="${BORONDNS_PHYSICAL_HOT_PATH_DETAILS:-reduced off}"
idle_strategy_list="${BORONDNS_PHYSICAL_IDLE_STRATEGIES:-park spin}"
socket_buffer_bytes="${BORONDNS_PHYSICAL_SOCKET_BUFFER_BYTES:-}"
socket_receive_buffer_bytes="${BORONDNS_PHYSICAL_SOCKET_RECEIVE_BUFFER_BYTES:-$socket_buffer_bytes}"
socket_send_buffer_bytes="${BORONDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES:-$socket_buffer_bytes}"
socket_max_pacing_rates_bytes_per_second="${BORONDNS_PHYSICAL_SOCKET_MAX_PACING_RATES_BYTES_PER_SECOND:-${BORONDNS_PHYSICAL_SOCKET_MAX_PACING_RATE_BYTES_PER_SECOND:-__none__}}"
worker_cpus="${BORONDNS_PHYSICAL_WORKER_CPUS:-}"
udp_batch_sizes="${BORONDNS_PHYSICAL_UDP_BATCH_SIZES:-staged}"
server_txqueuelen="${BORONDNS_PHYSICAL_SERVER_TXQUEUELEN:-}"
server_tx_qdisc="${BORONDNS_PHYSICAL_SERVER_TX_QDISC:-}"
server_tx_fq_limit="${BORONDNS_PHYSICAL_SERVER_TX_FQ_LIMIT:-10000}"
server_tx_fq_flow_limit="${BORONDNS_PHYSICAL_SERVER_TX_FQ_FLOW_LIMIT:-}"
server_tx_fq_quantum="${BORONDNS_PHYSICAL_SERVER_TX_FQ_QUANTUM:-}"
server_tx_fq_initial_quantum="${BORONDNS_PHYSICAL_SERVER_TX_FQ_INITIAL_QUANTUM:-}"
server_tx_fq_pacing="${BORONDNS_PHYSICAL_SERVER_TX_FQ_PACING:-}"
server_tx_ring="${BORONDNS_PHYSICAL_SERVER_TX_RING:-}"
server_rmem_max="${BORONDNS_PHYSICAL_SERVER_RMEM_MAX:-}"
server_wmem_max="${BORONDNS_PHYSICAL_SERVER_WMEM_MAX:-}"
stage_override="${BORONDNS_PHYSICAL_STAGE:-}"
xdp_redirect_object="${BORONDNS_PHYSICAL_XDP_REDIRECT_OBJECT:-}"
xdp_mode="${BORONDNS_PHYSICAL_XDP_MODE:-drv}"
xdp_zero_copy="${BORONDNS_PHYSICAL_XDP_ZERO_COPY:-require}"
xdp_rx_drain_passes="${BORONDNS_PHYSICAL_XDP_RX_DRAIN_PASSES:-1}"
xdp_tx_wakeup_interval="${BORONDNS_PHYSICAL_XDP_TX_WAKEUP_INTERVAL:-1}"
xdp_queue_id="${BORONDNS_PHYSICAL_XDP_QUEUE_ID:-0}"
xdp_queue_ids="${BORONDNS_PHYSICAL_XDP_QUEUE_IDS:-}"
xdp_ring_size="${BORONDNS_PHYSICAL_XDP_RING_SIZE:-8192}"
xdp_umem_frame_count="${BORONDNS_PHYSICAL_XDP_UMEM_FRAME_COUNT:-32768}"
xdp_batch_size="${BORONDNS_PHYSICAL_XDP_BATCH_SIZE:-1024}"
xdp_run_as_user="${BORONDNS_PHYSICAL_XDP_RUN_AS_USER:-codex}"
xdp_mtu="${BORONDNS_PHYSICAL_XDP_MTU:-}"
knot_xdp_run_as_user="${BORONDNS_PHYSICAL_KNOT_XDP_RUN_AS_USER:-codex:codex}"
knot_xdp_zero_copy="${BORONDNS_PHYSICAL_KNOT_XDP_ZERO_COPY:-__omit__}"
knot_xdp_ring_size="${BORONDNS_PHYSICAL_KNOT_XDP_RING_SIZE:-2048}"
knot_xdp_busypoll_budget="${BORONDNS_PHYSICAL_KNOT_XDP_BUSYPOLL_BUDGET:-__omit__}"
knot_xdp_busypoll_timeout="${BORONDNS_PHYSICAL_KNOT_XDP_BUSYPOLL_TIMEOUT:-__omit__}"
server_napi_defer_hard_irqs="${BORONDNS_PHYSICAL_SERVER_NAPI_DEFER_HARD_IRQS:-__omit__}"
server_gro_flush_timeout="${BORONDNS_PHYSICAL_SERVER_GRO_FLUSH_TIMEOUT:-__omit__}"
original_server_txqueuelen=""
original_server_tx_ring=""
original_server_rmem_max=""
original_server_wmem_max=""
original_server_mtu=""
original_server_napi_defer_hard_irqs=""
original_server_gro_flush_timeout=""
original_player_mtu=""

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$1" >&2
        exit 69
    fi
}

require_tool ssh
require_tool base64

ssh_control_dir="$(mktemp -d "${TMPDIR:-/tmp}/borondns-physical-ssh.XXXXXX")"
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
        ssh_control "$server_ssh" "cd $server_root && stage=\$(cat ~/borondns-last-benchmark-stage.txt 2>/dev/null || ls -td target/physical-knot-comparison-*/staged | head -1) && realpath \"\$stage\""
    fi
}

remote_player_workdir() {
    ssh_control "$player_ssh" "cd $player_workdir && pwd"
}

cleanup_remote() {
    if [[ -n "${out_abs:-}" ]]; then
        ssh_control "$server_ssh" bash -s -- "$out_abs" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
out_abs="$1"
if [[ -d "$out_abs" ]]; then
    while IFS= read -r -d '' pid_file; do
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        sudo kill "$pid" 2>/dev/null || true
    done < <(find "$out_abs" -mindepth 2 -maxdepth 2 -name '*.pid' -print0)
    sleep 0.2
    while IFS= read -r -d '' pid_file; do
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        if ps -p "$pid" >/dev/null 2>&1; then
            sudo kill -9 "$pid" 2>/dev/null || true
        fi
    done < <(find "$out_abs" -mindepth 2 -maxdepth 2 -name '*.pid' -print0)
fi
REMOTE
    fi
    ssh_control "$server_ssh" "pkill -u codex -x borondns 2>/dev/null || true; pkill -u codex -x knotd 2>/dev/null || true; pkill -u codex -x nsd 2>/dev/null || true" >/dev/null 2>&1 || true
    ssh_control "$server_ssh" "sudo pkill -x borondns 2>/dev/null || true" >/dev/null 2>&1 || true
    ssh_control "$server_ssh" "sudo pkill -x knotd 2>/dev/null || true" >/dev/null 2>&1 || true
    ssh_control "$server_ssh" "sudo pkill -x nsd 2>/dev/null || true" >/dev/null 2>&1 || true
    ssh_control "$server_ssh" "for pid in \$(pgrep -x borondns 2>/dev/null) \$(pgrep -x knotd 2>/dev/null) \$(pgrep -x nsd 2>/dev/null); do sudo kill \"\$pid\" 2>/dev/null || true; done; sleep 0.2; for pid in \$(pgrep -x borondns 2>/dev/null) \$(pgrep -x knotd 2>/dev/null) \$(pgrep -x nsd 2>/dev/null); do sudo kill -9 \"\$pid\" 2>/dev/null || true; done" >/dev/null 2>&1 || true
    ssh_control "$server_ssh" "sudo ip link set dev '$interface' xdp off 2>/dev/null || true; sudo ip link set dev '$interface' xdpgeneric off 2>/dev/null || true" >/dev/null 2>&1 || true
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
    if [[ -n "$xdp_mtu" && -n "$original_server_mtu" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$original_server_mtu" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
mtu="$2"
sudo ip link set dev "$iface" mtu "$mtu"
REMOTE
    fi
    if [[ "$server_napi_defer_hard_irqs" != "__omit__" && -n "$original_server_napi_defer_hard_irqs" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$original_server_napi_defer_hard_irqs" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
value="$2"
path="/sys/class/net/$iface/napi_defer_hard_irqs"
if [[ -e "$path" ]]; then
    printf '%s\n' "$value" | sudo tee "$path" >/dev/null
fi
REMOTE
    fi
    if [[ "$server_gro_flush_timeout" != "__omit__" && -n "$original_server_gro_flush_timeout" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$original_server_gro_flush_timeout" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
value="$2"
path="/sys/class/net/$iface/gro_flush_timeout"
if [[ -e "$path" ]]; then
    printf '%s\n' "$value" | sudo tee "$path" >/dev/null
fi
REMOTE
    fi
    ssh_control "$player_ssh" "sudo ip link set dev '$interface' xdp off 2>/dev/null || true; sudo ip link set dev '$interface' xdpgeneric off 2>/dev/null || true" >/dev/null 2>&1 || true
    if [[ -n "$player_mtu" && -n "$original_player_mtu" ]]; then
        ssh_control "$player_ssh" bash -s -- "$interface" "$original_player_mtu" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
mtu="$2"
sudo ip link set dev "$iface" mtu "$mtu"
REMOTE
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

ssh_control "$server_ssh" "mkdir -p '$out_abs' && printf 'target\\tserver_udp_backend\\txdp_mode\\txdp_zero_copy\\txdp_rx_drain_passes\\txdp_tx_wakeup_interval\\tworkers\\trate\\tplayer_tool\\toxide_gun_response_timeout_ms\\tkxdpgun_batch\\tkxdpgun_mode\\tudp_batch_size\\thot_path_detail\\tidle_strategy\\tsocket_receive_buffer_bytes\\tsocket_send_buffer_bytes\\tsocket_max_pacing_rate_bytes_per_second\\tserver_txqueuelen\\tserver_tx_ring\\tserver_tx_qdisc\\tserver_tx_fq_limit\\tserver_tx_fq_flow_limit\\tserver_rmem_max\\tserver_wmem_max\\tworker_cpus\\tserver_prefix\\treplies_per_second\\treply_percent\\tdns_reply_size\\tethernet_reply_bps\\tduration_seconds\\tplayer_rx_packets_delta\\tplayer_tx_packets_delta\\tplayer_softnet_dropped_delta\\tplayer_softnet_time_squeeze_delta\\tplayer_rx_packets_phy_delta\\tplayer_tx_packets_phy_delta\\tplayer_rx_discards_phy_delta\\tplayer_tx_discards_phy_delta\\tplayer_rx_xsk_xdp_redirect_delta\\tplayer_tx_xsk_xmit_delta\\tplayer_tx_xsk_wakeup_delta\\tserver_rx_packets_delta\\tserver_tx_packets_delta\\tserver_qdisc_dropped_delta\\tserver_qdisc_requeues_delta\\tserver_udp_in_datagrams_delta\\tserver_udp_out_datagrams_delta\\tserver_udp_in_errors_delta\\tserver_udp_rcvbuf_errors_delta\\tserver_udp_sndbuf_errors_delta\\tserver_udp_mmsg_send_syscalls\\tserver_udp_mmsg_sent_datagrams\\tserver_udp_mmsg_send_partial_syscalls\\tserver_udp_mmsg_send_wouldblock_retries\\tserver_udp_mmsg_receive_syscalls\\tserver_udp_mmsg_receive_wouldblock_syscalls\\tserver_udp_mmsg_received_datagrams\\tserver_af_xdp_rx_recv_calls\\tserver_af_xdp_rx_empty_recv_calls\\tserver_af_xdp_rx_received_packets\\tserver_af_xdp_rx_parse_errors\\tserver_af_xdp_tx_send_calls\\tserver_af_xdp_tx_queued_packets\\tserver_af_xdp_tx_empty_send_calls\\tserver_af_xdp_tx_wakeups\\tserver_af_xdp_tx_poll_write_calls\\tserver_af_xdp_tx_poll_write_ready\\tserver_af_xdp_completion_dequeues\\tserver_af_xdp_completed_packets\\tserver_af_xdp_worker_active\\tserver_af_xdp_worker_received_min\\tserver_af_xdp_worker_received_max\\tserver_af_xdp_worker_sent_min\\tserver_af_xdp_worker_sent_max\\tsoftnet_dropped_delta\\tsoftnet_time_squeeze_delta\\tserver_qdisc_flows_plimit_delta\\n' > '$out_abs/summary.tsv'"

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

cleanup_server_row_state() {
    ssh_control "$server_ssh" bash -s -- "$interface" "$borondns_port" "$knot_port" "$nsd_port" "$nsd_xdp_port" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
server_interface="$1"
borondns_port="$2"
knot_port="$3"
nsd_port="$4"
nsd_xdp_port="$5"

pkill -u codex -x borondns 2>/dev/null || true
pkill -u codex -x knotd 2>/dev/null || true
pkill -u codex -x nsd 2>/dev/null || true
sudo pkill -x borondns 2>/dev/null || true
sudo pkill -x knotd 2>/dev/null || true
sudo pkill -x nsd 2>/dev/null || true

for _ in $(seq 1 80); do
    if pgrep -x borondns >/dev/null 2>&1 || pgrep -x knotd >/dev/null 2>&1 || pgrep -x nsd >/dev/null 2>&1; then
        sleep 0.1
        continue
    fi
    if ss -Hlnptu 2>/dev/null | awk -v oxi=":$borondns_port" -v knot=":$knot_port" -v nsd=":$nsd_port" -v nsdxdp=":$nsd_xdp_port" '
        $5 ~ oxi "$" || $5 ~ knot "$" || $5 ~ nsd "$" || $5 ~ nsdxdp "$" { found = 1 }
        END { exit found ? 0 : 1 }
    '; then
        sleep 0.1
        continue
    fi
    break
done

for pid in $(pgrep -x borondns 2>/dev/null) $(pgrep -x knotd 2>/dev/null) $(pgrep -x nsd 2>/dev/null); do
    sudo kill -9 "$pid" 2>/dev/null || true
done
sudo ip link set dev "$server_interface" xdp off 2>/dev/null || true
sudo ip link set dev "$server_interface" xdpgeneric off 2>/dev/null || true
REMOTE
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

server_link_mtu() {
    ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
cat "/sys/class/net/$iface/mtu"
REMOTE
}

player_link_mtu() {
    ssh_control "$player_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
cat "/sys/class/net/$iface/mtu"
REMOTE
}

player_rx_queue_count() {
    ssh_control "$player_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
count="$(find "/sys/class/net/$iface/queues" -maxdepth 1 -type d -name 'rx-*' 2>/dev/null | wc -l | tr -d ' ')"
if [[ -z "$count" || "$count" == "0" ]]; then
    count="$(ethtool -l "$iface" 2>/dev/null | awk '
        /^Current hardware settings:/ {current = 1; next}
        current && $1 == "Combined:" {print $2; exit}
    ')"
fi
if [[ -z "$count" || "$count" == "0" ]]; then
    count="1"
fi
printf '%s\n' "$count"
REMOTE
}

configure_player_xdp_tuning() {
    local effective_player_mtu
    local requested_oxide_gun_queue_count="$oxide_gun_queue_count"

    ssh_control "$player_ssh" "sudo ip link set dev '$interface' xdp off 2>/dev/null || true; sudo ip link set dev '$interface' xdpgeneric off 2>/dev/null || true" >/dev/null 2>&1 || true
    original_player_mtu="$(player_link_mtu)"
    if [[ -n "$player_mtu" ]]; then
        ssh_control "$player_ssh" bash -s -- "$interface" "$player_mtu" <<'REMOTE'
set -euo pipefail
iface="$1"
mtu="$2"
sudo ip link set dev "$iface" mtu "$mtu"
REMOTE
    fi
    effective_player_mtu="$(player_link_mtu)"
    if [[ "$player_tool" == "oxide-gun" && "$oxide_gun_queue_count" == "__auto__" ]]; then
        oxide_gun_queue_count="$(player_rx_queue_count)"
    fi
    ssh_control "$server_ssh" bash -s -- "$out_abs" "$original_player_mtu" "${player_mtu:-__none__}" "$effective_player_mtu" "$requested_oxide_gun_queue_count" "$oxide_gun_queue_count" "$oxide_gun_queue_list" <<'REMOTE'
set -euo pipefail
out_abs="$1"
original_player_mtu="$2"
requested_player_mtu="$3"
effective_player_mtu="$4"
requested_oxide_gun_queue_count="$5"
effective_oxide_gun_queue_count="$6"
oxide_gun_queue_list="$7"
if [[ "$requested_player_mtu" == "__none__" ]]; then
    requested_player_mtu=""
fi
if [[ "$oxide_gun_queue_list" == "__none__" ]]; then
    oxide_gun_queue_list=""
fi
cat >"$out_abs/host/player-link-tuning.txt" <<EOF
original_mtu=$original_player_mtu
requested_mtu=$requested_player_mtu
effective_mtu=$effective_player_mtu
oxide_gun_requested_queue_count=$requested_oxide_gun_queue_count
oxide_gun_effective_queue_count=$effective_oxide_gun_queue_count
oxide_gun_queue_list=$oxide_gun_queue_list
EOF
REMOTE
}

configure_server_link_tuning() {
    local effective_txqueuelen
    local effective_mtu
    local effective_wmem_max

    ssh_control "$server_ssh" "mkdir -p '$out_abs/host'"
    if [[ -n "$server_tx_qdisc" ]]; then
        case "$server_tx_qdisc" in
        fq | fq_codel | pfifo_fast) ;;
        *)
            printf 'unsupported BORONDNS_PHYSICAL_SERVER_TX_QDISC: %s\n' "$server_tx_qdisc" >&2
            exit 64
            ;;
        esac
        case "$server_tx_fq_pacing" in
        "" | pacing | nopacing) ;;
        *)
            printf 'unsupported BORONDNS_PHYSICAL_SERVER_TX_FQ_PACING: %s\n' "$server_tx_fq_pacing" >&2
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
    original_server_mtu="$(server_link_mtu)"
    if [[ -n "$xdp_mtu" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$xdp_mtu" <<'REMOTE'
set -euo pipefail
iface="$1"
mtu="$2"
sudo ip link set dev "$iface" mtu "$mtu"
REMOTE
    fi
    effective_mtu="$(server_link_mtu)"
    original_server_napi_defer_hard_irqs="$(
        ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
iface="$1"
path="/sys/class/net/$iface/napi_defer_hard_irqs"
if [[ -e "$path" ]]; then
    cat "$path"
fi
REMOTE
    )"
    if [[ "$server_napi_defer_hard_irqs" != "__omit__" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$server_napi_defer_hard_irqs" <<'REMOTE'
set -euo pipefail
iface="$1"
value="$2"
path="/sys/class/net/$iface/napi_defer_hard_irqs"
if [[ ! -e "$path" ]]; then
    printf 'interface %s does not expose %s\n' "$iface" "$path" >&2
    exit 65
fi
printf '%s\n' "$value" | sudo tee "$path" >/dev/null
REMOTE
    fi
    effective_server_napi_defer_hard_irqs="$(
        ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
iface="$1"
path="/sys/class/net/$iface/napi_defer_hard_irqs"
if [[ -e "$path" ]]; then
    cat "$path"
fi
REMOTE
    )"
    original_server_gro_flush_timeout="$(
        ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
iface="$1"
path="/sys/class/net/$iface/gro_flush_timeout"
if [[ -e "$path" ]]; then
    cat "$path"
fi
REMOTE
    )"
    if [[ "$server_gro_flush_timeout" != "__omit__" ]]; then
        ssh_control "$server_ssh" bash -s -- "$interface" "$server_gro_flush_timeout" <<'REMOTE'
set -euo pipefail
iface="$1"
value="$2"
path="/sys/class/net/$iface/gro_flush_timeout"
if [[ ! -e "$path" ]]; then
    printf 'interface %s does not expose %s\n' "$iface" "$path" >&2
    exit 65
fi
printf '%s\n' "$value" | sudo tee "$path" >/dev/null
REMOTE
    fi
    effective_server_gro_flush_timeout="$(
        ssh_control "$server_ssh" bash -s -- "$interface" <<'REMOTE'
iface="$1"
path="/sys/class/net/$iface/gro_flush_timeout"
if [[ -e "$path" ]]; then
    cat "$path"
fi
REMOTE
    )"
    ssh_control "$server_ssh" bash -s -- "$out_abs" "$original_server_txqueuelen" "${server_txqueuelen:-__none__}" "$effective_txqueuelen" "$original_server_tx_ring" "${server_tx_ring:-__none__}" "$effective_tx_ring" "$server_tx_fq_limit" "${server_tx_fq_flow_limit:-__none__}" "${server_tx_fq_quantum:-__none__}" "${server_tx_fq_initial_quantum:-__none__}" "${server_tx_fq_pacing:-__none__}" "$original_server_rmem_max" "${server_rmem_max:-__none__}" "$effective_rmem_max" "$original_server_wmem_max" "${server_wmem_max:-__none__}" "$effective_wmem_max" "$original_server_mtu" "${xdp_mtu:-__none__}" "$effective_mtu" "$original_server_napi_defer_hard_irqs" "$server_napi_defer_hard_irqs" "$effective_server_napi_defer_hard_irqs" "$original_server_gro_flush_timeout" "$server_gro_flush_timeout" "$effective_server_gro_flush_timeout" <<'REMOTE'
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
original_mtu="${19}"
requested_mtu="${20}"
effective_mtu="${21}"
original_napi_defer_hard_irqs="${22}"
requested_napi_defer_hard_irqs="${23}"
effective_napi_defer_hard_irqs="${24}"
original_gro_flush_timeout="${25}"
requested_gro_flush_timeout="${26}"
effective_gro_flush_timeout="${27}"
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
if [[ "$requested_mtu" == "__none__" ]]; then
    requested_mtu=""
fi
if [[ "$requested_napi_defer_hard_irqs" == "__omit__" ]]; then
    requested_napi_defer_hard_irqs=""
fi
if [[ "$requested_gro_flush_timeout" == "__omit__" ]]; then
    requested_gro_flush_timeout=""
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
original_mtu=$original_mtu
requested_mtu=$requested_mtu
effective_mtu=$effective_mtu
original_napi_defer_hard_irqs=$original_napi_defer_hard_irqs
requested_napi_defer_hard_irqs=$requested_napi_defer_hard_irqs
effective_napi_defer_hard_irqs=$effective_napi_defer_hard_irqs
original_gro_flush_timeout=$original_gro_flush_timeout
requested_gro_flush_timeout=$requested_gro_flush_timeout
effective_gro_flush_timeout=$effective_gro_flush_timeout
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
ethtool -c "$server_interface" >"$out_abs/host/server-ethtool-coalesce.txt" 2>&1 || true
ethtool -a "$server_interface" >"$out_abs/host/server-ethtool-pause.txt" 2>&1 || true
{
    printf 'path\tvalue\n'
    for path in \
        /sys/class/net/"$server_interface"/queues/rx-*/rps_cpus \
        /sys/class/net/"$server_interface"/queues/rx-*/rps_flow_cnt \
        /sys/class/net/"$server_interface"/queues/tx-*/xps_cpus; do
        [[ -e "$path" ]] || continue
        printf '%s\t%s\n' "$path" "$(cat "$path")"
    done
} >"$out_abs/host/server-queue-steering.tsv" 2>&1 || true
python3 - "$server_interface" "$out_abs/host/server-irq-affinity.tsv" <<'PY' 2>/dev/null || true
import pathlib
import sys

interface, output = sys.argv[1:3]
device_link = pathlib.Path("/sys/class/net") / interface / "device"
try:
    bus_id = device_link.resolve().name
except FileNotFoundError:
    bus_id = ""

rows = ["irq\tname\tsmp_affinity_list"]
for raw in pathlib.Path("/proc/interrupts").read_text(encoding="utf-8", errors="ignore").splitlines():
    fields = raw.split()
    if not fields or not fields[0].endswith(":"):
        continue
    irq = fields[0].rstrip(":")
    name = fields[-1]
    if bus_id and bus_id not in name:
        continue
    try:
        affinity = pathlib.Path(f"/proc/irq/{irq}/smp_affinity_list").read_text().strip()
    except OSError:
        affinity = ""
    rows.append(f"{irq}\t{name}\t{affinity}")

pathlib.Path(output).write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
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
    printf '\nethtool_coalesce\n'
    ethtool -c "$player_interface" 2>&1 || true
    printf '\ninterrupts\n'
    grep -E "$player_interface|mlx|enp|eth" /proc/interrupts 2>/dev/null || true
}
REMOTE
    )"
    printf '%s\n' "$player_context" | ssh_control "$server_ssh" "cat > '$out_abs/host/player-context.txt'"
}

configure_server_link_tuning
configure_player_xdp_tuning
capture_static_host_context

run_knot_reference_start() {
    local run_abs="$1"
    local server_interface="$2"
    local knot_backend="${3:-std}"

    ssh_control "$server_ssh" bash -s -- "$stage_abs" "$run_abs" "$target_ip" "$knot_port" "$server_interface" "$knot_backend" "$knot_xdp_zero_copy" "$knot_xdp_ring_size" "$knot_bin" "$knot_xdp_run_as_user" "$knot_xdp_busypoll_budget" "$knot_xdp_busypoll_timeout" <<'REMOTE'
set -euo pipefail
stage_abs="$1"
run_abs="$2"
knot_target_ip="$3"
knot_target_port="$4"
server_interface="$5"
knot_backend="$6"
knot_xdp_zero_copy="$7"
knot_xdp_ring_size="$8"
knot_bin="$9"
knot_xdp_run_as_user="${10}"
knot_xdp_busypoll_budget="${11}"
knot_xdp_busypoll_timeout="${12}"

mkdir -p "$run_abs"
pkill -u codex -x borondns 2>/dev/null || true
pkill -u codex -x knotd 2>/dev/null || true
sudo pkill -x knotd 2>/dev/null || true
sleep 0.2

cd "$stage_abs"
ulimit -n 65536
ulimit -l unlimited 2>/dev/null || true
knot_conf="$stage_abs/knot.conf"
knot_cmd=("$knot_bin" -c "$knot_conf" -v)
if [[ "$knot_backend" == "xdp" ]]; then
    cp "$stage_abs/knot.conf" "$run_abs/knot-xdp.conf"
    if [[ -n "$knot_xdp_run_as_user" ]]; then
        python3 - "$run_abs/knot-xdp.conf" "$knot_xdp_run_as_user" <<'PY'
import re
import sys

path, run_as_user = sys.argv[1:3]
text = open(path, encoding="utf-8").read()
replacement = f"server:\n    user: {run_as_user}"
if re.search(r"(?m)^server:\n(?:    .*\n)*?    user:", text):
    text = re.sub(r"(?m)^(server:\n(?:    .*\n)*?    user:).*$", rf"\1 {run_as_user}", text, count=1)
else:
    text = text.replace("server:", replacement, 1)
open(path, "w", encoding="utf-8").write(text)
PY
    fi
    cat >>"$run_abs/knot-xdp.conf" <<EOF

xdp:
    listen: $server_interface@$knot_target_port
    udp: on
    tcp: off
    ring-size: $knot_xdp_ring_size
EOF
    if [[ "$knot_xdp_zero_copy" != "__omit__" ]]; then
        printf '    zero-copy: %s\n' "$knot_xdp_zero_copy" >>"$run_abs/knot-xdp.conf"
    fi
    if [[ "$knot_xdp_busypoll_budget" != "__omit__" ]]; then
        printf '    busypoll-budget: %s\n' "$knot_xdp_busypoll_budget" >>"$run_abs/knot-xdp.conf"
    fi
    if [[ "$knot_xdp_busypoll_timeout" != "__omit__" ]]; then
        printf '    busypoll-timeout: %s\n' "$knot_xdp_busypoll_timeout" >>"$run_abs/knot-xdp.conf"
    fi
    knot_conf="$run_abs/knot-xdp.conf"
    knot_cmd=(sudo "$knot_bin" -c "$knot_conf" -v)
fi
"$knot_bin" -VV >"$run_abs/knot-version.txt" 2>&1 || true
"${knot_cmd[@]}" >"$run_abs/knot.log" 2>&1 &
echo $! >"$run_abs/knot.pid"
knot_ready=false
for _ in $(seq 1 80); do
    if dig @"$knot_target_ip" -p "$knot_target_port" perf.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        knot_ready=true
        break
    fi
    if ! kill -0 "$(cat "$run_abs/knot.pid")" 2>/dev/null; then
        break
    fi
    sleep 0.25
done
if [[ "$knot_ready" != true ]]; then
    printf 'Knot reference did not become queryable on %s:%s\n' "$knot_target_ip" "$knot_target_port" >&2
    tail -200 "$run_abs/knot.log" >&2 || true
    exit 1
fi

cp /proc/net/dev "$run_abs/server-proc-net-dev-before.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-before.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-before.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-before.txt" 2>&1 || true
tc -s qdisc show dev "$server_interface" >"$run_abs/server-tc-qdisc-before.txt" 2>&1 || true
ip -details link show dev "$server_interface" >"$run_abs/server-ip-link-before-benchmark.txt" 2>&1 || true
sudo bpftool net show dev "$server_interface" >"$run_abs/server-bpftool-net-before-benchmark.txt" 2>&1 || true
REMOTE
}

run_knot_reference_stop() {
    local run_abs="$1"

    ssh_control "$server_ssh" bash -s -- "$run_abs" "$interface" <<'REMOTE'
set -euo pipefail
run_abs="$1"
server_interface="$2"
if [[ -f "$run_abs/knot.pid" ]]; then
    knot_pid="$(cat "$run_abs/knot.pid")"
    kill "$knot_pid" 2>/dev/null || true
    sudo kill "$knot_pid" 2>/dev/null || true
    for _ in $(seq 1 80); do
        if ! ps -p "$knot_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if ps -p "$knot_pid" >/dev/null 2>&1; then
        sudo kill -9 "$knot_pid" 2>/dev/null || true
    fi
fi
for pid in $(pgrep -x knotd 2>/dev/null); do
    sudo kill "$pid" 2>/dev/null || true
done
sleep 0.2
for pid in $(pgrep -x knotd 2>/dev/null); do
    sudo kill -9 "$pid" 2>/dev/null || true
done
sudo ip link set dev "$server_interface" xdp off 2>/dev/null || true
sudo ip link set dev "$server_interface" xdpgeneric off 2>/dev/null || true
REMOTE
}

run_nsd_reference_start() {
    local run_abs="$1"
    local server_interface="$2"
    local nsd_backend="${3:-std}"

    ssh_control "$server_ssh" bash -s -- "$stage_abs" "$run_abs" "$target_ip" "$nsd_port" "$nsd_xdp_port" "$server_interface" "$nsd_backend" "$nsd_bin" "${nsd_checkconf:-__default__}" "${nsd_checkzone:-__default__}" "$nsd_xdp_program" "$nsd_server_count" "$nsd_run_as_user" <<'REMOTE'
set -euo pipefail
stage_abs="$1"
run_abs="$2"
nsd_target_ip="$3"
nsd_port="$4"
nsd_xdp_port="$5"
server_interface="$6"
nsd_backend="$7"
nsd_bin="$8"
nsd_checkconf="$9"
shift 9
nsd_checkzone="$1"
nsd_xdp_program="$2"
nsd_server_count="$3"
nsd_run_as_user="$4"

mkdir -p "$run_abs"
pkill -u codex -x borondns 2>/dev/null || true
pkill -u codex -x knotd 2>/dev/null || true
pkill -u codex -x nsd 2>/dev/null || true
sudo pkill -x nsd 2>/dev/null || true
sleep 0.2

if [[ "$nsd_checkconf" == "__default__" ]]; then
    nsd_checkconf="$(dirname "$nsd_bin")/nsd-checkconf"
fi
if [[ "$nsd_checkzone" == "__default__" ]]; then
    nsd_checkzone="$(dirname "$nsd_bin")/nsd-checkzone"
fi
if [[ "$nsd_xdp_program" == "__default__" ]]; then
    nsd_xdp_program="$(cd "$(dirname "$nsd_bin")/.." && pwd)/share/nsd/xdp-dns-redirect_kern.o"
fi

selected_port="$nsd_port"
if [[ "$nsd_backend" == "xdp" ]]; then
    selected_port="$nsd_xdp_port"
fi

cat >"$run_abs/nsd.conf" <<EOF
server:
    server-count: $nsd_server_count
    ip-address: $nsd_target_ip@$selected_port
    do-ip4: yes
    do-ip6: no
    database: "$run_abs/nsd.db"
    pidfile: "$run_abs/nsd.pid"
    logfile: "$run_abs/nsd.log"
    zonesdir: "$run_abs"
    username: "$nsd_run_as_user"
    hide-version: yes
    verbosity: 0
    reuseport: yes
EOF

if [[ "$nsd_backend" == "xdp" ]]; then
    cat >>"$run_abs/nsd.conf" <<EOF
    xdp-interface: $server_interface
    xdp-program-path: "$nsd_xdp_program"
    xdp-program-load: yes
    xdp-force-copy: no
EOF
fi

cat >>"$run_abs/nsd.conf" <<EOF

zone:
    name: "perf.test."
    zonefile: "$stage_abs/primary.zone"
EOF

"$nsd_bin" -v >"$run_abs/nsd-version.txt" 2>&1 || true
"$nsd_checkzone" perf.test. "$stage_abs/primary.zone" >"$run_abs/nsd-checkzone.out" 2>&1
"$nsd_checkconf" "$run_abs/nsd.conf" >"$run_abs/nsd-checkconf.out" 2>&1
"$nsd_checkconf" -o reuseport "$run_abs/nsd.conf" >"$run_abs/nsd-reuseport.txt" 2>&1 || true

ulimit -n 65536
ulimit -l unlimited 2>/dev/null || true
if [[ "$nsd_backend" == "xdp" || "$selected_port" == "53" ]]; then
    sudo "$nsd_bin" -d -c "$run_abs/nsd.conf" >"$run_abs/nsd-stdout.log" 2>"$run_abs/nsd-stderr.log" &
else
    "$nsd_bin" -d -c "$run_abs/nsd.conf" >"$run_abs/nsd-stdout.log" 2>"$run_abs/nsd-stderr.log" &
fi
echo $! >"$run_abs/nsd.pid.actual"

nsd_ready=false
for _ in $(seq 1 160); do
    if dig @"$nsd_target_ip" -p "$selected_port" perf.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        nsd_ready=true
        break
    fi
    if ! kill -0 "$(cat "$run_abs/nsd.pid.actual")" 2>/dev/null; then
        break
    fi
    sleep 0.25
done
if [[ "$nsd_ready" != true ]]; then
    printf 'NSD reference did not become queryable on %s:%s\n' "$nsd_target_ip" "$selected_port" >&2
    tail -200 "$run_abs/nsd-stderr.log" >&2 || true
    tail -200 "$run_abs/nsd.log" >&2 || true
    exit 1
fi

cp /proc/net/dev "$run_abs/server-proc-net-dev-before.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-before.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-before.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-before.txt" 2>&1 || true
tc -s qdisc show dev "$server_interface" >"$run_abs/server-tc-qdisc-before.txt" 2>&1 || true
ip -details link show dev "$server_interface" >"$run_abs/server-ip-link-before-benchmark.txt" 2>&1 || true
sudo bpftool net show dev "$server_interface" >"$run_abs/server-bpftool-net-before-benchmark.txt" 2>&1 || true
REMOTE
}

run_nsd_reference_stop() {
    local run_abs="$1"

    ssh_control "$server_ssh" bash -s -- "$run_abs" "$interface" <<'REMOTE'
set -euo pipefail
run_abs="$1"
server_interface="$2"
if [[ -f "$run_abs/nsd.pid.actual" ]]; then
    nsd_pid="$(cat "$run_abs/nsd.pid.actual")"
    kill "$nsd_pid" 2>/dev/null || true
    sudo kill "$nsd_pid" 2>/dev/null || true
    for _ in $(seq 1 80); do
        if ! ps -p "$nsd_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if ps -p "$nsd_pid" >/dev/null 2>&1; then
        sudo kill -9 "$nsd_pid" 2>/dev/null || true
    fi
fi
for pid in $(pgrep -x nsd 2>/dev/null); do
    sudo kill "$pid" 2>/dev/null || true
done
sleep 0.2
for pid in $(pgrep -x nsd 2>/dev/null); do
    sudo kill -9 "$pid" 2>/dev/null || true
done
sudo ip link set dev "$server_interface" xdp off 2>/dev/null || true
sudo ip link set dev "$server_interface" xdpgeneric off 2>/dev/null || true
REMOTE
}

run_server_start() {
    local run_abs="$1"
    local udp_backend="$2"
    local workers="$3"
    local hot_path="$4"
    local idle_strategy="$5"
    local knot_target_ip="$6"
    local knot_target_port="$7"
    local socket_receive_buffer="$8"
    local socket_send_buffer="$9"
    local socket_max_pacing_rate="${10}"
    local cpus="${11}"
    local selected_server_bin="${12}"
    local selected_server_prefix="${13}"
    local server_interface="${14}"
    local udp_batch_size="${15}"
    local socket_receive_buffer_arg="${socket_receive_buffer:-__none__}"
    local socket_send_buffer_arg="${socket_send_buffer:-__none__}"
    local socket_max_pacing_rate_arg="${socket_max_pacing_rate:-__none__}"
    local cpus_arg="${cpus:-__none__}"
    local udp_batch_size_arg="${udp_batch_size:-staged}"
    local xdp_redirect_object_arg="${xdp_redirect_object:-__default__}"
    local xdp_queue_ids_arg="${xdp_queue_ids:-__none__}"

    ssh_control "$server_ssh" bash -s -- "$server_root_abs" "$stage_abs" "$run_abs" "$udp_backend" "$workers" "$hot_path" "$idle_strategy" "$knot_target_ip" "$knot_target_port" "$socket_receive_buffer_arg" "$socket_send_buffer_arg" "$socket_max_pacing_rate_arg" "$cpus_arg" "$selected_server_bin" "$selected_server_prefix" "$server_interface" "$udp_batch_size_arg" "$xdp_redirect_object_arg" "$xdp_mode" "$xdp_zero_copy" "$xdp_rx_drain_passes" "$xdp_tx_wakeup_interval" "$xdp_queue_id" "$xdp_queue_ids_arg" "$xdp_ring_size" "$xdp_umem_frame_count" "$xdp_run_as_user" <<'REMOTE'
set -euo pipefail
server_root="$1"
stage_abs="$2"
run_abs="$3"
udp_backend="$4"
workers="$5"
hot_path="$6"
idle_strategy="$7"
knot_target_ip="$8"
knot_target_port="$9"
socket_receive_buffer="${10}"
socket_send_buffer="${11}"
socket_max_pacing_rate="${12}"
cpus="${13}"
server_bin="${14}"
server_prefix_b64="${15}"
server_interface="${16}"
udp_batch_size="${17}"
xdp_redirect_object="${18}"
xdp_mode="${19}"
xdp_zero_copy="${20}"
xdp_rx_drain_passes="${21}"
xdp_tx_wakeup_interval="${22}"
xdp_queue_id="${23}"
xdp_queue_ids="${24}"
xdp_ring_size="${25}"
xdp_umem_frame_count="${26}"
xdp_run_as_user="${27}"
xdp_batch_size="$udp_batch_size"
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
    server_bin="$server_root/target/release/borondns"
elif [[ "$server_bin" != /* ]]; then
    server_bin="$server_root/$server_bin"
fi
if [[ "$xdp_redirect_object" == "__default__" ]]; then
    xdp_redirect_object="$server_root/crates/borondns-server-ebpf/target/bpfel-unknown-none/release/borondns-xdp-redirect.bpf.o"
elif [[ "$xdp_redirect_object" != /* ]]; then
    xdp_redirect_object="$server_root/$xdp_redirect_object"
fi
if [[ "$xdp_queue_ids" == "__none__" ]]; then
    xdp_queue_ids=""
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
serve_cmd=("${server_cmd[@]}")
if [[ "$udp_backend" == "af_xdp" ]]; then
    serve_cmd=(sudo "${server_cmd[@]}")
fi

mkdir -p "$run_abs"
pkill -u codex -x borondns 2>/dev/null || true
pkill -u codex -x knotd 2>/dev/null || true
sudo pkill -x borondns 2>/dev/null || true
sudo pkill -x knotd 2>/dev/null || true
sleep 0.2

cp "$stage_abs/borondns.toml" "$run_abs/borondns.toml"
python3 - "$run_abs/borondns.toml" "$workers" "$hot_path" "$idle_strategy" <<'PY'
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
if [[ "$udp_backend" == "af_xdp" ]]; then
    python3 - "$run_abs/borondns.toml" "$server_interface" "$xdp_redirect_object" "$xdp_mode" "$xdp_zero_copy" "$xdp_rx_drain_passes" "$xdp_tx_wakeup_interval" "$xdp_queue_id" "$xdp_queue_ids" "$xdp_ring_size" "$xdp_umem_frame_count" "$xdp_batch_size" "$xdp_run_as_user" "$workers" <<'PY'
import re
import sys

path, interface, redirect_object, xdp_mode, zero_copy, rx_drain_passes, tx_wakeup_interval, queue_id, queue_ids, ring_size, umem_frame_count, xdp_batch_size, run_as_user, workers = sys.argv[1:15]
text = open(path, encoding="utf-8").read()

def set_key(section, key, value):
    global text
    header = f"[{section}]"
    pattern = rf"(?ms)^(\[{re.escape(section)}\]\n)(.*?)(?=^\[|\Z)"
    match = re.search(pattern, text)
    line = f"{key} = {value}"
    if match:
        body = match.group(2)
        if re.search(rf"^{re.escape(key)}\s*=", body, flags=re.M):
            body = re.sub(rf"^{re.escape(key)}\s*=.*$", line, body, flags=re.M)
        else:
            body = body.rstrip() + "\n" + line + "\n"
        text = text[:match.start(2)] + body + text[match.end(2):]
    else:
        text = text.rstrip() + f"\n\n{header}\n{line}\n"

def remove_key(section, key):
    global text
    pattern = rf"(?ms)^(\[{re.escape(section)}\]\n)(.*?)(?=^\[|\Z)"
    match = re.search(pattern, text)
    if not match:
        return
    body = re.sub(rf"^{re.escape(key)}\s*=.*\n?", "", match.group(2), flags=re.M)
    text = text[:match.start(2)] + body + text[match.end(2):]

set_key("limits", "udp_backend", '"af_xdp"')
set_key("limits", "udp_runtime", '"tokio"')
set_key("limits", "udp_reuseport_workers", workers)
set_key("limits", "udp_idle_strategy", '"park"')
set_key("limits", "udp_batch_size", xdp_batch_size)
set_key("process", "run_as_user", f'"{run_as_user}"')
set_key("xdp", "interface", f'"{interface}"')
set_key("xdp", "redirect_object", f'"{redirect_object}"')
set_key("xdp", "mode", f'"{xdp_mode}"')
set_key("xdp", "zero_copy", f'"{zero_copy}"')
set_key("xdp", "rx_drain_passes", rx_drain_passes)
set_key("xdp", "tx_wakeup_interval", tx_wakeup_interval)
if queue_ids:
    parsed_queue_ids = [int(part) for part in queue_ids.split(",") if part]
    remove_key("xdp", "queue_id")
    set_key("xdp", "queue_ids", "[" + ", ".join(str(queue_id) for queue_id in parsed_queue_ids) + "]")
else:
    remove_key("xdp", "queue_ids")
    set_key("xdp", "queue_id", queue_id)
set_key("xdp", "umem_frame_count", umem_frame_count)
for key in ("rx_ring_size", "tx_ring_size", "fill_ring_size", "completion_ring_size"):
    set_key("xdp", key, ring_size)
set_key("xdp", "batch_size", xdp_batch_size)
open(path, "w", encoding="utf-8").write(text)
PY
fi
if [[ -n "$socket_receive_buffer" || -n "$socket_send_buffer" || -n "$socket_max_pacing_rate" ]]; then
    python3 - "$run_abs/borondns.toml" "$socket_receive_buffer" "$socket_send_buffer" "$socket_max_pacing_rate" <<'PY'
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
    python3 - "$run_abs/borondns.toml" "$udp_batch_size" <<'PY'
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
if [[ -n "$cpus" && "$udp_backend" != "af_xdp" ]]; then
    python3 - "$run_abs/borondns.toml" "$cpus" <<'PY'
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

"${server_cmd[@]}" --validate-config "$run_abs/borondns.toml" >"$run_abs/validate.out" 2>&1

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
ulimit -l unlimited 2>/dev/null || true
"${serve_cmd[@]}" serve --config "$run_abs/borondns.toml" >"$run_abs/borondns.log" 2>&1 &
echo $! >"$run_abs/borondns.pid"

ready=""
for _ in $(seq 1 180); do
    ready="$(curl -fsS http://127.0.0.1:8080/readyz 2>/dev/null || true)"
    if [[ "$ready" == ready ]] || printf '%s' "$ready" | grep -q ready; then
        break
    fi
    sleep 0.25
done
if ! ([[ "$ready" == ready ]] || printf '%s' "$ready" | grep -q ready); then
    tail -80 "$run_abs/borondns.log" >&2
    exit 1
fi

kill "$(cat "$run_abs/knot.pid")" 2>/dev/null || true
wait "$(cat "$run_abs/knot.pid")" 2>/dev/null || true
cp /proc/net/dev "$run_abs/server-proc-net-dev-before.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-before.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-before.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-before.txt" 2>&1 || true
ip -details link show dev "$server_interface" >"$run_abs/server-ip-link-before-benchmark.txt" 2>&1 || true
if [[ "$udp_backend" == "af_xdp" ]]; then
    sudo bpftool net show dev "$server_interface" >"$run_abs/server-bpftool-net-before-benchmark.txt" 2>&1 || true
fi
REMOTE
}

run_server_finish() {
    local run_abs="$1"
    local target="$2"
    local server_udp_backend="$3"
    local row_xdp_mode="$4"
    local row_xdp_zero_copy="$5"
    local row_xdp_rx_drain_passes="$6"
    local row_xdp_tx_wakeup_interval="$7"
    local workers="$8"
    local rate="$9"
    local selected_kxdpgun_batch="${10}"
    local selected_kxdpgun_mode="${11}"
    local udp_batch_size="${12}"
    local hot_path="${13}"
    local idle_strategy="${14}"
    local socket_receive_buffer="${15}"
    local socket_send_buffer="${16}"
    local socket_max_pacing_rate="${17}"
    local cpus="${18}"
    local selected_server_prefix_b64="${19}"
    local server_interface="${20}"
    local socket_receive_buffer_arg="${socket_receive_buffer:-__none__}"
    local socket_send_buffer_arg="${socket_send_buffer:-__none__}"
    local socket_max_pacing_rate_arg="${socket_max_pacing_rate:-__none__}"
    local cpus_arg="${cpus:-__none__}"
    local server_prefix_arg="${selected_server_prefix_b64:-__none__}"
    local udp_batch_size_arg="${udp_batch_size:-staged}"

    ssh_control "$server_ssh" bash -s -- "$out_abs" "$run_abs" "$target" "$server_udp_backend" "$row_xdp_mode" "$row_xdp_zero_copy" "$row_xdp_rx_drain_passes" "$row_xdp_tx_wakeup_interval" "$workers" "$rate" "$player_tool" "$oxide_gun_response_timeout_ms" "$selected_kxdpgun_batch" "$selected_kxdpgun_mode" "$udp_batch_size_arg" "$hot_path" "$idle_strategy" "$socket_receive_buffer_arg" "$socket_send_buffer_arg" "$socket_max_pacing_rate_arg" "$cpus_arg" "$server_prefix_arg" "$server_interface" <<'REMOTE'
set -euo pipefail
out_abs="$1"
run_abs="$2"
target="$3"
server_udp_backend="$4"
xdp_mode="$5"
xdp_zero_copy="$6"
xdp_rx_drain_passes="$7"
xdp_tx_wakeup_interval="$8"
workers="$9"
rate="${10}"
player_tool="${11}"
oxide_gun_response_timeout_ms="${12}"
kxdpgun_batch="${13}"
kxdpgun_mode="${14}"
udp_batch_size="${15}"
hot_path="${16}"
idle_strategy="${17}"
socket_receive_buffer="${18}"
socket_send_buffer="${19}"
socket_max_pacing_rate="${20}"
cpus="${21}"
server_prefix_b64="${22}"
server_interface="${23}"
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
ip -details link show dev "$server_interface" >"$run_abs/server-ip-link-after-benchmark.txt" 2>&1 || true
sudo bpftool net show dev "$server_interface" >"$run_abs/server-bpftool-net-after-benchmark.txt" 2>&1 || true
curl -fsS http://127.0.0.1:8080/metrics >"$run_abs/metrics-after.prom" 2>/dev/null || true
python3 - "$target" "$server_udp_backend" "$xdp_mode" "$xdp_zero_copy" "$xdp_rx_drain_passes" "$xdp_tx_wakeup_interval" "$workers" "$rate" "$player_tool" "$oxide_gun_response_timeout_ms" "$kxdpgun_batch" "$kxdpgun_mode" "$udp_batch_size" "$hot_path" "$idle_strategy" "$socket_receive_buffer" "$socket_send_buffer" "$socket_max_pacing_rate" "$server_txqueuelen" "$server_tx_ring" "$server_tx_qdisc" "$server_tx_fq_limit" "$server_tx_fq_flow_limit" "$server_rmem_max" "$server_wmem_max" "$cpus" "$server_prefix" "$server_interface" "$run_abs" "$run_abs/kxdpgun.log" >>"$out_abs/summary.tsv" <<'PY'
import json
import re
import sys

target, server_udp_backend, xdp_mode, xdp_zero_copy, xdp_rx_drain_passes, xdp_tx_wakeup_interval, workers, rate, player_tool, oxide_gun_response_timeout_ms, kxdpgun_batch, kxdpgun_mode, udp_batch_size, hot_path, idle_strategy, socket_receive_buffer, socket_send_buffer, socket_max_pacing_rate, server_txqueuelen, server_tx_ring, server_tx_qdisc, server_tx_fq_limit, server_tx_fq_flow_limit, server_rmem_max, server_wmem_max, cpus, server_prefix, interface, run_abs, log = sys.argv[1:31]
text = open(log, encoding="utf-8", errors="ignore").read()
replies_per_second = ""
reply_percent = ""
dns_reply_size = ""
ethernet_reply_bps = ""
duration_seconds = ""
if player_tool == "oxide-gun":
    summary = None
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if record.get("summary") or record.get("record_type") == "summary":
            summary = record
    if summary is not None:
        duration_value = float(
            summary.get("send_duration_seconds")
            or summary.get("duration_seconds")
            or 0.0
        )
        tx_packets = int(summary.get("tx_packets_total") or 0)
        rx_packets = int(summary.get("rx_packets_total") or 0)
        rx_bytes = int(summary.get("rx_bytes_total") or 0)
        positive = int(summary.get("positive_total") or 0)
        if duration_value > 0.0:
            replies_per_second = str(int(round(positive / duration_value)))
            ethernet_reply_bps = str(int(round(rx_bytes * 8 / duration_value)))
            duration_seconds = f"{duration_value:.4f}"
        if tx_packets > 0:
            reply_percent = f"{positive * 100.0 / tx_packets:.6f}"
        if rx_packets > 0:
            avg_frame = rx_bytes / rx_packets
            dns_reply_size = f"{max(0.0, avg_frame - 42.0):.0f}"
else:
    replies = re.search(r"total replies:\s+\d+ \(([0-9,]+) pps\) \(([0-9.]+) %\)", text)
    size = re.search(r"average DNS reply size:\s+([0-9.]+) B", text)
    bps = re.search(r"average Ethernet reply rate:\s+([0-9]+) bps", text)
    duration = re.search(r"duration:\s+([0-9.]+) s", text)
    replies_per_second = replies.group(1).replace(",", "") if replies else ""
    reply_percent = replies.group(2) if replies else ""
    dns_reply_size = size.group(1) if size else ""
    ethernet_reply_bps = bps.group(1) if bps else ""
    duration_seconds = duration.group(1) if duration else ""

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

def parse_ethtool(path):
    values = {}
    for raw in read(path).splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        fields = value.strip().split()
        if not key or not fields:
            continue
        try:
            values[key] = int(fields[0])
        except ValueError:
            continue
    return values

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

def prom_label_values(values, metric):
    prefix = f"{metric}{{"
    parsed = []
    for key, value in values.items():
        if not key.startswith(prefix):
            continue
        try:
            parsed.append(int(value))
        except ValueError:
            continue
    return parsed

def prom_series_summary(values, metric):
    series = prom_label_values(values, metric)
    if not series:
        return ("0", "0", "0")
    return (str(len(series)), str(min(series)), str(max(series)))

def delta(before, after, key):
    return str(after.get(key, 0) - before.get(key, 0))

dev_before = parse_dev_packets(f"{run_abs}/server-proc-net-dev-before.txt", interface)
dev_after = parse_dev_packets(f"{run_abs}/server-proc-net-dev-after.txt", interface)
player_dev_before = parse_dev_packets(f"{run_abs}/player-proc-net-dev-before.txt", interface)
player_dev_after = parse_dev_packets(f"{run_abs}/player-proc-net-dev-after.txt", interface)
udp_before = parse_udp_snmp(f"{run_abs}/server-proc-net-snmp-before.txt")
udp_after = parse_udp_snmp(f"{run_abs}/server-proc-net-snmp-after.txt")
soft_before = parse_softnet(f"{run_abs}/server-proc-net-softnet-before.txt")
soft_after = parse_softnet(f"{run_abs}/server-proc-net-softnet-after.txt")
player_soft_before = parse_softnet(f"{run_abs}/player-proc-net-softnet-before.txt")
player_soft_after = parse_softnet(f"{run_abs}/player-proc-net-softnet-after.txt")
qdisc_before = parse_qdisc(f"{run_abs}/server-tc-qdisc-before.txt")
qdisc_after = parse_qdisc(f"{run_abs}/server-tc-qdisc-after.txt")
player_ethtool_before = parse_ethtool(f"{run_abs}/player-ethtool-stats-before.txt")
player_ethtool_after = parse_ethtool(f"{run_abs}/player-ethtool-stats-after.txt")
prom = parse_prom_metrics(f"{run_abs}/metrics-after.prom")
af_xdp_worker_active, af_xdp_worker_received_min, af_xdp_worker_received_max = (
    prom_series_summary(prom, "borondns_af_xdp_worker_received_packets_total")
)
_, af_xdp_worker_sent_min, af_xdp_worker_sent_max = prom_series_summary(
    prom, "borondns_af_xdp_worker_sent_packets_total"
)

print("\t".join([
    target,
    server_udp_backend,
    xdp_mode,
    xdp_zero_copy,
    xdp_rx_drain_passes,
    xdp_tx_wakeup_interval,
    workers,
    rate,
    player_tool,
    oxide_gun_response_timeout_ms,
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
    replies_per_second,
    reply_percent,
    dns_reply_size,
    ethernet_reply_bps,
    duration_seconds,
    str(player_dev_after["rx"] - player_dev_before["rx"]),
    str(player_dev_after["tx"] - player_dev_before["tx"]),
    delta(player_soft_before, player_soft_after, "dropped"),
    delta(player_soft_before, player_soft_after, "time_squeeze"),
    delta(player_ethtool_before, player_ethtool_after, "rx_packets_phy"),
    delta(player_ethtool_before, player_ethtool_after, "tx_packets_phy"),
    delta(player_ethtool_before, player_ethtool_after, "rx_discards_phy"),
    delta(player_ethtool_before, player_ethtool_after, "tx_discards_phy"),
    delta(player_ethtool_before, player_ethtool_after, "rx_xsk_xdp_redirect"),
    delta(player_ethtool_before, player_ethtool_after, "tx_xsk_xmit"),
    delta(player_ethtool_before, player_ethtool_after, "tx_xsk_wakeup"),
    str(dev_after["rx"] - dev_before["rx"]),
    str(dev_after["tx"] - dev_before["tx"]),
    delta(qdisc_before, qdisc_after, "dropped"),
    delta(qdisc_before, qdisc_after, "requeues"),
    delta(udp_before, udp_after, "InDatagrams"),
    delta(udp_before, udp_after, "OutDatagrams"),
    delta(udp_before, udp_after, "InErrors"),
    delta(udp_before, udp_after, "RcvbufErrors"),
    delta(udp_before, udp_after, "SndbufErrors"),
    prom.get("borondns_udp_mmsg_send_syscalls_total", "0"),
    prom.get("borondns_udp_mmsg_sent_datagrams_total", "0"),
    prom.get("borondns_udp_mmsg_send_partial_syscalls_total", "0"),
    prom.get("borondns_udp_mmsg_send_wouldblock_retries_total", "0"),
    prom.get("borondns_udp_mmsg_receive_syscalls_total", "0"),
    prom.get("borondns_udp_mmsg_receive_wouldblock_syscalls_total", "0"),
    prom.get("borondns_udp_mmsg_received_datagrams_total", "0"),
    prom.get("borondns_af_xdp_rx_recv_calls_total", "0"),
    prom.get("borondns_af_xdp_rx_empty_recv_calls_total", "0"),
    prom.get("borondns_af_xdp_rx_received_packets_total", "0"),
    prom.get("borondns_af_xdp_rx_parse_errors_total", "0"),
    prom.get("borondns_af_xdp_tx_send_calls_total", "0"),
    prom.get("borondns_af_xdp_tx_queued_packets_total", "0"),
    prom.get("borondns_af_xdp_tx_empty_send_calls_total", "0"),
    prom.get("borondns_af_xdp_tx_wakeups_total", "0"),
    prom.get("borondns_af_xdp_tx_poll_write_calls_total", "0"),
    prom.get("borondns_af_xdp_tx_poll_write_ready_total", "0"),
    prom.get("borondns_af_xdp_completion_dequeues_total", "0"),
    prom.get("borondns_af_xdp_completed_packets_total", "0"),
    af_xdp_worker_active,
    af_xdp_worker_received_min,
    af_xdp_worker_received_max,
    af_xdp_worker_sent_min,
    af_xdp_worker_sent_max,
    delta(soft_before, soft_after, "dropped"),
    delta(soft_before, soft_after, "time_squeeze"),
    delta(qdisc_before, qdisc_after, "flows_plimit"),
]))
PY

if [[ -f "$run_abs/borondns.pid" ]]; then
    borondns_pid="$(cat "$run_abs/borondns.pid")"
    kill "$borondns_pid" 2>/dev/null || true
    sudo kill "$borondns_pid" 2>/dev/null || true
    for _ in $(seq 1 80); do
        if ! ps -p "$borondns_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if ps -p "$borondns_pid" >/dev/null 2>&1; then
        sudo kill -9 "$borondns_pid" 2>/dev/null || true
    fi
fi
for pid in $(pgrep -x borondns 2>/dev/null); do
    sudo kill "$pid" 2>/dev/null || true
done
sleep 0.2
for pid in $(pgrep -x borondns 2>/dev/null); do
    sudo kill -9 "$pid" 2>/dev/null || true
done
sudo ip link set dev "$server_interface" xdp off 2>/dev/null || true
sudo ip link set dev "$server_interface" xdpgeneric off 2>/dev/null || true
REMOTE
}

run_server_perf_start() {
    local run_abs="$1"
    local record="$2"
    local frequency="$3"
    local seconds="$4"
    local scope="$5"
    local event="$6"
    local pid_file="${7:-borondns.pid}"

    if [[ "$record" != true ]]; then
        return 0
    fi

    ssh_control "$server_ssh" bash -s -- "$run_abs" "$frequency" "$seconds" "$scope" "$event" "$pid_file" <<'REMOTE'
set -euo pipefail
run_abs="$1"
frequency="$2"
seconds="$3"
scope="$4"
event="$5"
pid_file="$6"
perf_args=(record -F "$frequency" -g -o "$run_abs/perf.data")
if [[ "$event" != "__default__" ]]; then
    perf_args+=(-e "$event")
fi
case "$scope" in
process)
    pid="$(cat "$run_abs/$pid_file")"
    perf_args+=(-p "$pid")
    ;;
system)
    perf_args+=(-a)
    ;;
*)
    printf 'unsupported BORONDNS_PHYSICAL_PERF_SCOPE %q; expected process or system\n' "$scope" >&2
    exit 64
    ;;
esac
sudo perf "${perf_args[@]}" -- sleep "$seconds" >"$run_abs/perf-record.log" 2>&1 &
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

capture_player_row_state() {
    local run_abs="$1"
    local suffix="$2"

    ssh_control "$player_ssh" "cat /proc/net/dev" |
        ssh_control "$server_ssh" "cat > '$run_abs/player-proc-net-dev-$suffix.txt'" || true
    ssh_control "$player_ssh" "cat /proc/net/softnet_stat" |
        ssh_control "$server_ssh" "cat > '$run_abs/player-proc-net-softnet-$suffix.txt'" || true
    ssh_control "$player_ssh" "ethtool -S '$interface' 2>&1 || true" |
        ssh_control "$server_ssh" "cat > '$run_abs/player-ethtool-stats-$suffix.txt'" || true
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
            printf 'borondns_udp_port=%s\n' "$port"
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
    local row_source_port_list="${5:-$oxide_gun_source_port_list}"
    local row_queue_list="${6:-$oxide_gun_queue_list}"
    local local_log="$id.kxdpgun.tmp"
    local player_run_dir
    local remote_run_dir
    local status="255"
    local done="false"

    player_run_dir=".borondns-physical-${id}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    remote_run_dir="$player_workdir_abs/$player_run_dir"

    capture_player_row_state "$run_abs" before

    ssh_control "$player_ssh" bash -s -- "$player_workdir_abs" "$player_run_dir" "$duration" "$port" "$batch" "$rate" "$interface" "$kxdpgun_mode" "$source_ip" "$target_ip" "$player_tool" "$oxide_gun_bin" "$oxide_gun_xdp_redirect_object" "$oxide_gun_xdp_mode" "$oxide_gun_xdp_zerocopy" "$oxide_gun_xdp_batch_size" "$oxide_gun_xdp_rx_drain_passes" "$oxide_gun_xdp_tx_wakeup_interval" "$oxide_gun_xdp_pace_wait_fraction" "$oxide_gun_xdp_umem_frame_count" "$oxide_gun_xdp_ring_size" "$oxide_gun_queue_count" "$row_queue_list" "$oxide_gun_source_port" "$oxide_gun_source_port_range" "$row_source_port_list" "$oxide_gun_source_port_select" "$oxide_gun_source_mac" "$oxide_gun_target_mac" "$oxide_gun_response_timeout_ms" <<'REMOTE'
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
player_tool="${11}"
oxide_gun_bin="${12}"
oxide_gun_xdp_redirect_object="${13}"
oxide_gun_xdp_mode="${14}"
oxide_gun_xdp_zerocopy="${15}"
oxide_gun_xdp_batch_size="${16}"
oxide_gun_xdp_rx_drain_passes="${17}"
oxide_gun_xdp_tx_wakeup_interval="${18}"
oxide_gun_xdp_pace_wait_fraction="${19}"
oxide_gun_xdp_umem_frame_count="${20}"
oxide_gun_xdp_ring_size="${21}"
oxide_gun_queue_count="${22}"
oxide_gun_queue_list="${23}"
oxide_gun_source_port="${24}"
oxide_gun_source_port_range="${25}"
oxide_gun_source_port_list="${26}"
oxide_gun_source_port_select="${27}"
oxide_gun_source_mac="${28}"
oxide_gun_target_mac="${29}"
oxide_gun_response_timeout_ms="${30}"
mkdir -p "$workdir/$run_dir"
(
    cd "$workdir"
    set +e
    case "$player_tool" in
        kxdpgun)
            sudo kxdpgun -t "$duration" -p "$port" -b "$batch" -Q "$rate" -I "$interface" -m "$mode" -l "$source_ip" -i querydb "$target_ip"
            ;;
        oxide-gun)
            if [[ "$oxide_gun_bin" == "__default__" ]]; then
                oxide_gun_bin="$workdir/xdp-template-slice/oxide-gun"
            fi
            if [[ "$oxide_gun_xdp_redirect_object" == "__default__" ]]; then
                oxide_gun_xdp_redirect_object="$workdir/xdp-template-slice/oxide-gun-xdp.bpf.o"
            fi
            source_port_args=(--source-port "$oxide_gun_source_port")
            if [[ "$oxide_gun_source_port_range" != "__auto__" ]]; then
                source_port_args+=(
                    --source-port-range "$oxide_gun_source_port_range"
                    --source-port-select "$oxide_gun_source_port_select"
                )
            fi
            if [[ "$oxide_gun_source_port_list" != "__none__" ]]; then
                source_port_args+=(--source-port-list "$oxide_gun_source_port_list")
            fi
            queue_args=(--queue-count "$oxide_gun_queue_count")
            if [[ "$oxide_gun_queue_list" != "__none__" ]]; then
                queue_args+=(--queue-list "$oxide_gun_queue_list")
            fi
            pace_args=()
            if [[ "$oxide_gun_xdp_pace_wait_fraction" != "__omit__" ]]; then
                pace_args+=(--xdp-pace-wait-fraction "$oxide_gun_xdp_pace_wait_fraction")
            fi
            sudo "$oxide_gun_bin" \
                --backend xdp \
                --interface "$interface" \
                --tx-queue 0 \
                --rx-queue 0 \
                "${queue_args[@]}" \
                --xdp-mode "$oxide_gun_xdp_mode" \
                --xdp-zerocopy "$oxide_gun_xdp_zerocopy" \
                --xdp-redirect-object "$oxide_gun_xdp_redirect_object" \
                --xdp-reply-tracking count \
                --xdp-batch-size "$oxide_gun_xdp_batch_size" \
                --xdp-rx-drain-passes "$oxide_gun_xdp_rx_drain_passes" \
                --xdp-tx-wakeup-interval "$oxide_gun_xdp_tx_wakeup_interval" \
                "${pace_args[@]}" \
                --xdp-umem-frame-count "$oxide_gun_xdp_umem_frame_count" \
                --xdp-tx-ring-size "$oxide_gun_xdp_ring_size" \
                --xdp-rx-ring-size "$oxide_gun_xdp_ring_size" \
                --xdp-fill-ring-size "$oxide_gun_xdp_ring_size" \
                --xdp-completion-ring-size "$oxide_gun_xdp_ring_size" \
                --target "$target_ip:$port" \
                --source-ip "$source_ip" \
                "${source_port_args[@]}" \
                --source-mac "$oxide_gun_source_mac" \
                --target-mac "$oxide_gun_target_mac" \
                --query-list querydb \
                --query-select sequential \
                --max-packets 0 \
                --duration-seconds "$duration" \
                --target-qps "$rate" \
                --recv-mode process \
                --log-format json \
                --flush-interval-ms 0 \
                --response-timeout-ms "$oxide_gun_response_timeout_ms"
            ;;
        *)
            printf 'unsupported BORONDNS_PHYSICAL_PLAYER_TOOL: %s\n' "$player_tool" >&2
            false
            ;;
    esac
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
    capture_player_row_state "$run_abs" after
    ssh_control "$player_ssh" "sudo ip link set dev '$interface' xdp off 2>/dev/null || true; sudo ip link set dev '$interface' xdpgeneric off 2>/dev/null || true" >/dev/null 2>&1 || true
    ssh_control "$player_ssh" "rm -rf '$remote_run_dir'" >/dev/null 2>&1 || true
    rm -f "$local_log"
    [[ "$status" == "0" ]]
}

if [[ "$comparison_run_order" != "knot-first" && "$comparison_run_order" != "borondns-first" ]]; then
    printf 'BORONDNS_PHYSICAL_COMPARISON_RUN_ORDER must be knot-first or borondns-first, got %q\n' "$comparison_run_order" >&2
    exit 69
fi

if [[ "$comparison_run_order" == "knot-first" && "$include_knot" == true ]]; then
    for rate in $rates_list; do
        select_run_id "knot-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_knot_reference_start "$run_abs" "$interface" "std"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "knot.pid"
        run_player_kxdpgun "$run_abs" "$run_id" "$knot_port" "$rate" "$oxide_gun_knot_source_port_list" "$oxide_gun_knot_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "knot" "std" "n/a" "n/a" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_knot_reference_stop "$run_abs"
    done
fi

if [[ "$comparison_run_order" == "knot-first" && "$include_knot_xdp" == true ]]; then
    for rate in $rates_list; do
        select_run_id "knot-xdp-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_knot_reference_start "$run_abs" "$interface" "xdp"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "knot.pid"
        run_player_kxdpgun "$run_abs" "$run_id" "$knot_port" "$rate" "$oxide_gun_knot_source_port_list" "$oxide_gun_knot_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "knot-xdp" "xdp" "native" "$knot_xdp_zero_copy" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_knot_reference_stop "$run_abs"
    done
fi

if [[ "$comparison_run_order" == "knot-first" && "$include_nsd" == true ]]; then
    for rate in $rates_list; do
        select_run_id "nsd-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_nsd_reference_start "$run_abs" "$interface" "std"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "nsd.pid.actual"
        run_player_kxdpgun "$run_abs" "$run_id" "$nsd_port" "$rate" "$oxide_gun_nsd_source_port_list" "$oxide_gun_nsd_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "nsd" "std" "n/a" "n/a" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_nsd_reference_stop "$run_abs"
    done
fi

if [[ "$comparison_run_order" == "knot-first" && "$include_nsd_xdp" == true ]]; then
    for rate in $rates_list; do
        select_run_id "nsd-xdp-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_nsd_reference_start "$run_abs" "$interface" "xdp"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "nsd.pid.actual"
        run_player_kxdpgun "$run_abs" "$run_id" "$nsd_xdp_port" "$rate" "$oxide_gun_nsd_source_port_list" "$oxide_gun_nsd_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "nsd-xdp" "xdp" "native" "on" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_nsd_reference_stop "$run_abs"
    done
fi

if [[ "$include_borondns" == true ]]; then
    for udp_backend in $borondns_udp_backends; do
        for workers in $workers_list; do
            for rate in $rates_list; do
                for udp_batch_size in $udp_batch_sizes; do
                    for hot_path in $hot_path_list; do
                        for idle_strategy in $idle_strategy_list; do
                            for socket_max_pacing_rate in $socket_max_pacing_rates_bytes_per_second; do
                                pacing_run_suffix=""
                                socket_max_pacing_rate_arg="$socket_max_pacing_rate"
                                effective_workers="$workers"
                                effective_idle_strategy="$idle_strategy"
                                effective_udp_batch_size="$udp_batch_size"
                                effective_worker_cpus="$worker_cpus"
                                row_xdp_mode="n/a"
                                row_xdp_zero_copy="n/a"
                                row_xdp_rx_drain_passes="n/a"
                                row_xdp_tx_wakeup_interval="n/a"
                                if [[ "$socket_max_pacing_rate" == "__none__" ]]; then
                                    socket_max_pacing_rate_arg=""
                                else
                                    pacing_run_suffix="-pace-${socket_max_pacing_rate}"
                                fi
                                if [[ "$udp_backend" == "af_xdp" ]]; then
                                    effective_idle_strategy="park"
                                    effective_udp_batch_size="$xdp_batch_size"
                                    effective_worker_cpus=""
                                    row_xdp_mode="$xdp_mode"
                                    row_xdp_zero_copy="$xdp_zero_copy"
                                    row_xdp_rx_drain_passes="$xdp_rx_drain_passes"
                                    row_xdp_tx_wakeup_interval="$xdp_tx_wakeup_interval"
                                fi
                                select_run_id "borondns-${udp_backend}-w${effective_workers}-q${rate}-batch-${effective_udp_batch_size}-metrics-${hot_path}-idle-${effective_idle_strategy}${pacing_run_suffix}"
                                run_abs="$out_abs/$run_id"
                                printf 'running %s\n' "$run_id"
                                cleanup_server_row_state
                                run_server_start "$run_abs" "$udp_backend" "$effective_workers" "$hot_path" "$effective_idle_strategy" "$target_ip" "$knot_port" "$socket_receive_buffer_bytes" "$socket_send_buffer_bytes" "$socket_max_pacing_rate_arg" "$effective_worker_cpus" "$server_bin_arg" "$server_prefix_arg" "$interface" "$effective_udp_batch_size"
                                run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event"
                                run_server_socket_sample_start "$run_abs" "$socket_sample" "$borondns_port" "$duration" "$socket_sample_interval"
                                run_player_kxdpgun "$run_abs" "$run_id" "$borondns_port" "$rate" "$oxide_gun_borondns_source_port_list" "$oxide_gun_borondns_queue_list"
                                run_server_socket_sample_finish "$run_abs" "$socket_sample"
                                run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
                                run_server_finish "$run_abs" "borondns" "$udp_backend" "$row_xdp_mode" "$row_xdp_zero_copy" "$row_xdp_rx_drain_passes" "$row_xdp_tx_wakeup_interval" "$effective_workers" "$rate" "$batch" "$kxdpgun_mode" "$effective_udp_batch_size" "$hot_path" "$effective_idle_strategy" "$socket_receive_buffer_bytes" "$socket_send_buffer_bytes" "$socket_max_pacing_rate_arg" "$effective_worker_cpus" "$server_prefix_arg" "$interface"
                            done
                        done
                    done
                done
            done
        done
    done
fi

if [[ "$comparison_run_order" == "borondns-first" && "$include_knot" == true ]]; then
    for rate in $rates_list; do
        select_run_id "knot-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_knot_reference_start "$run_abs" "$interface" "std"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "knot.pid"
        run_player_kxdpgun "$run_abs" "$run_id" "$knot_port" "$rate" "$oxide_gun_knot_source_port_list" "$oxide_gun_knot_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "knot" "std" "n/a" "n/a" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_knot_reference_stop "$run_abs"
    done
fi

if [[ "$comparison_run_order" == "borondns-first" && "$include_knot_xdp" == true ]]; then
    for rate in $rates_list; do
        select_run_id "knot-xdp-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_knot_reference_start "$run_abs" "$interface" "xdp"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "knot.pid"
        run_player_kxdpgun "$run_abs" "$run_id" "$knot_port" "$rate" "$oxide_gun_knot_source_port_list" "$oxide_gun_knot_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "knot-xdp" "xdp" "native" "$knot_xdp_zero_copy" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_knot_reference_stop "$run_abs"
    done
fi

if [[ "$comparison_run_order" == "borondns-first" && "$include_nsd" == true ]]; then
    for rate in $rates_list; do
        select_run_id "nsd-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_nsd_reference_start "$run_abs" "$interface" "std"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "nsd.pid.actual"
        run_player_kxdpgun "$run_abs" "$run_id" "$nsd_port" "$rate" "$oxide_gun_nsd_source_port_list" "$oxide_gun_nsd_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "nsd" "std" "n/a" "n/a" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_nsd_reference_stop "$run_abs"
    done
fi

if [[ "$comparison_run_order" == "borondns-first" && "$include_nsd_xdp" == true ]]; then
    for rate in $rates_list; do
        select_run_id "nsd-xdp-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        cleanup_server_row_state
        run_nsd_reference_start "$run_abs" "$interface" "xdp"
        run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration" "$perf_scope" "$perf_event" "nsd.pid.actual"
        run_player_kxdpgun "$run_abs" "$run_id" "$nsd_xdp_port" "$rate" "$oxide_gun_nsd_source_port_list" "$oxide_gun_nsd_queue_list"
        run_server_perf_finish "$run_abs" "$perf_record" "$perf_report_timeout" "$perf_report_children"
        run_server_finish "$run_abs" "nsd-xdp" "xdp" "native" "on" "n/a" "n/a" "n/a" "$rate" "$batch" "$kxdpgun_mode" "n/a" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_nsd_reference_stop "$run_abs"
    done
fi

printf 'artifact_dir=%s\n' "$out_abs"
ssh_control "$server_ssh" "cat '$out_abs/summary.tsv'"
