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
worker_cpus="${OXIDEDNS_PHYSICAL_WORKER_CPUS:-}"
udp_batch_sizes="${OXIDEDNS_PHYSICAL_UDP_BATCH_SIZES:-staged}"
server_txqueuelen="${OXIDEDNS_PHYSICAL_SERVER_TXQUEUELEN:-}"
stage_override="${OXIDEDNS_PHYSICAL_STAGE:-}"
original_server_txqueuelen=""

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$1" >&2
        exit 69
    fi
}

require_tool ssh
require_tool base64

remote_server_root() {
    ssh "$server_ssh" "cd $server_root && pwd"
}

resolve_stage() {
    if [[ -n "$stage_override" ]]; then
        ssh "$server_ssh" "cd $server_root && realpath '$stage_override'"
    else
        ssh "$server_ssh" "cd $server_root && stage=\$(cat ~/oxidedns-last-benchmark-stage.txt 2>/dev/null || ls -td target/physical-knot-comparison-*/staged | head -1) && realpath \"\$stage\""
    fi
}

cleanup_remote() {
    ssh "$server_ssh" "pkill -u codex -x oxidedns 2>/dev/null || true; pkill -u codex -x knotd 2>/dev/null || true" >/dev/null 2>&1 || true
    if [[ -n "$server_txqueuelen" && -n "$original_server_txqueuelen" ]]; then
        ssh "$server_ssh" bash -s -- "$interface" "$original_server_txqueuelen" <<'REMOTE' >/dev/null 2>&1 || true
iface="$1"
txqueuelen="$2"
sudo ip link set dev "$iface" txqueuelen "$txqueuelen"
REMOTE
    fi
}

trap cleanup_remote EXIT

server_root_abs="$(remote_server_root)"
stage_abs="$(resolve_stage)"
out_abs="$stage_abs/evidence/physical-udp-knot-comparison-$(date -u +%Y%m%dT%H%M%SZ)"
server_bin_arg="${server_bin:-__default__}"
if [[ -n "$server_prefix" ]]; then
    server_prefix_arg="$(printf '%s' "$server_prefix" | base64 | tr -d '\n')"
else
    server_prefix_arg="__none__"
fi

ssh "$server_ssh" "mkdir -p '$out_abs' && printf 'target\\tworkers\\trate\\tudp_batch_size\\thot_path_detail\\tidle_strategy\\tsocket_receive_buffer_bytes\\tsocket_send_buffer_bytes\\tserver_txqueuelen\\tworker_cpus\\tserver_prefix\\treplies_per_second\\treply_percent\\tdns_reply_size\\tethernet_reply_bps\\tduration_seconds\\tserver_rx_packets_delta\\tserver_tx_packets_delta\\tserver_udp_in_datagrams_delta\\tserver_udp_out_datagrams_delta\\tserver_udp_in_errors_delta\\tserver_udp_rcvbuf_errors_delta\\tserver_udp_sndbuf_errors_delta\\tsoftnet_dropped_delta\\tsoftnet_time_squeeze_delta\\n' > '$out_abs/summary.tsv'"

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
    ssh "$server_ssh" bash -s -- "$interface" <<'REMOTE'
set -euo pipefail
iface="$1"
ip -o link show dev "$iface" | sed -n 's/.*qlen \([0-9][0-9]*\).*/\1/p'
REMOTE
}

configure_server_link_tuning() {
    local effective_txqueuelen

    ssh "$server_ssh" "mkdir -p '$out_abs/host'"
    original_server_txqueuelen="$(server_link_txqueuelen)"
    if [[ -n "$server_txqueuelen" ]]; then
        ssh "$server_ssh" bash -s -- "$interface" "$server_txqueuelen" <<'REMOTE'
set -euo pipefail
iface="$1"
txqueuelen="$2"
sudo ip link set dev "$iface" txqueuelen "$txqueuelen"
REMOTE
    fi
    effective_txqueuelen="$(server_link_txqueuelen)"
    ssh "$server_ssh" bash -s -- "$out_abs" "$original_server_txqueuelen" "${server_txqueuelen:-}" "$effective_txqueuelen" <<'REMOTE'
set -euo pipefail
out_abs="$1"
original_txqueuelen="$2"
requested_txqueuelen="$3"
effective_txqueuelen="$4"
cat >"$out_abs/host/server-link-tuning.txt" <<EOF
original_txqueuelen=$original_txqueuelen
requested_txqueuelen=$requested_txqueuelen
effective_txqueuelen=$effective_txqueuelen
EOF
REMOTE
}

capture_static_host_context() {
    local player_context

    ssh "$server_ssh" bash -s -- "$out_abs" "$interface" <<'REMOTE'
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
ethtool -l "$server_interface" >"$out_abs/host/server-ethtool-channels.txt" 2>&1 || true
ethtool -x "$server_interface" >"$out_abs/host/server-ethtool-rss.txt" 2>&1 || true
ethtool -k "$server_interface" >"$out_abs/host/server-ethtool-features.txt" 2>&1 || true
REMOTE

    player_context="$(
        ssh "$player_ssh" bash -s -- "$interface" <<'REMOTE'
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
    printf '%s\n' "$player_context" | ssh "$server_ssh" "cat > '$out_abs/host/player-context.txt'"
}

configure_server_link_tuning
capture_static_host_context

run_knot_reference_start() {
    local run_abs="$1"
    local server_interface="$2"

    ssh "$server_ssh" bash -s -- "$stage_abs" "$run_abs" "$target_ip" "$knot_port" "$server_interface" <<'REMOTE'
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

    ssh "$server_ssh" bash -s -- "$run_abs" <<'REMOTE'
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
    local cpus="$9"
    local selected_server_bin="${10}"
    local selected_server_prefix="${11}"
    local server_interface="${12}"
    local udp_batch_size="${13}"
    local socket_receive_buffer_arg="${socket_receive_buffer:-__none__}"
    local socket_send_buffer_arg="${socket_send_buffer:-__none__}"
    local cpus_arg="${cpus:-__none__}"
    local udp_batch_size_arg="${udp_batch_size:-staged}"

    ssh "$server_ssh" bash -s -- "$server_root_abs" "$stage_abs" "$run_abs" "$workers" "$hot_path" "$idle_strategy" "$knot_target_ip" "$knot_target_port" "$socket_receive_buffer_arg" "$socket_send_buffer_arg" "$cpus_arg" "$selected_server_bin" "$selected_server_prefix" "$server_interface" "$udp_batch_size_arg" <<'REMOTE'
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
cpus="${11}"
server_bin="${12}"
server_prefix_b64="${13}"
server_interface="${14}"
udp_batch_size="${15}"
if [[ "$socket_receive_buffer" == "__none__" ]]; then
    socket_receive_buffer=""
fi
if [[ "$socket_send_buffer" == "__none__" ]]; then
    socket_send_buffer=""
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
if [[ -n "$socket_receive_buffer" || -n "$socket_send_buffer" ]]; then
    python3 - "$run_abs/oxidedns.toml" "$socket_receive_buffer" "$socket_send_buffer" <<'PY'
import re
import sys

path, socket_receive_buffer, socket_send_buffer = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
for key, value in (
    ("udp_socket_receive_buffer_bytes", socket_receive_buffer),
    ("udp_socket_send_buffer_bytes", socket_send_buffer),
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
    local udp_batch_size="$5"
    local hot_path="$6"
    local idle_strategy="$7"
    local socket_receive_buffer="$8"
    local socket_send_buffer="$9"
    local cpus="${10}"
    local selected_server_prefix_b64="${11}"
    local server_interface="${12}"
    local socket_receive_buffer_arg="${socket_receive_buffer:-__none__}"
    local socket_send_buffer_arg="${socket_send_buffer:-__none__}"
    local cpus_arg="${cpus:-__none__}"
    local server_prefix_arg="${selected_server_prefix_b64:-__none__}"
    local udp_batch_size_arg="${udp_batch_size:-staged}"

    ssh "$server_ssh" bash -s -- "$out_abs" "$run_abs" "$target" "$workers" "$rate" "$udp_batch_size_arg" "$hot_path" "$idle_strategy" "$socket_receive_buffer_arg" "$socket_send_buffer_arg" "$cpus_arg" "$server_prefix_arg" "$server_interface" <<'REMOTE'
set -euo pipefail
out_abs="$1"
run_abs="$2"
target="$3"
workers="$4"
rate="$5"
udp_batch_size="$6"
hot_path="$7"
idle_strategy="$8"
socket_receive_buffer="$9"
socket_send_buffer="${10}"
cpus="${11}"
server_prefix_b64="${12}"
server_interface="${13}"
if [[ "$socket_receive_buffer" == "__none__" ]]; then
    socket_receive_buffer=""
fi
if [[ "$socket_send_buffer" == "__none__" ]]; then
    socket_send_buffer=""
fi
if [[ "$cpus" == "__none__" ]]; then
    cpus=""
fi
server_prefix=""
if [[ "$server_prefix_b64" != "__none__" ]]; then
    server_prefix="$(printf '%s' "$server_prefix_b64" | base64 -d)"
fi
server_txqueuelen="$(ip -o link show dev "$server_interface" | sed -n 's/.*qlen \([0-9][0-9]*\).*/\1/p')"

cp /proc/net/dev "$run_abs/server-proc-net-dev-after.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-after.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-after.txt"
ethtool -S "$server_interface" >"$run_abs/server-ethtool-stats-after.txt" 2>&1 || true
tc -s qdisc show dev "$server_interface" >"$run_abs/server-tc-qdisc-after.txt" 2>&1 || true
curl -fsS http://127.0.0.1:8080/metrics >"$run_abs/metrics-after.prom" 2>/dev/null || true
python3 - "$target" "$workers" "$rate" "$udp_batch_size" "$hot_path" "$idle_strategy" "$socket_receive_buffer" "$socket_send_buffer" "$server_txqueuelen" "$cpus" "$server_prefix" "$server_interface" "$run_abs" "$run_abs/kxdpgun.log" >>"$out_abs/summary.tsv" <<'PY'
import re
import sys

target, workers, rate, udp_batch_size, hot_path, idle_strategy, socket_receive_buffer, socket_send_buffer, server_txqueuelen, cpus, server_prefix, interface, run_abs, log = sys.argv[1:15]
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

def delta(before, after, key):
    return str(after.get(key, 0) - before.get(key, 0))

dev_before = parse_dev_packets(f"{run_abs}/server-proc-net-dev-before.txt", interface)
dev_after = parse_dev_packets(f"{run_abs}/server-proc-net-dev-after.txt", interface)
udp_before = parse_udp_snmp(f"{run_abs}/server-proc-net-snmp-before.txt")
udp_after = parse_udp_snmp(f"{run_abs}/server-proc-net-snmp-after.txt")
soft_before = parse_softnet(f"{run_abs}/server-proc-net-softnet-before.txt")
soft_after = parse_softnet(f"{run_abs}/server-proc-net-softnet-after.txt")

print("\t".join([
    target,
    workers,
    rate,
    udp_batch_size,
    hot_path,
    idle_strategy,
    socket_receive_buffer or "default",
    socket_send_buffer or "default",
    server_txqueuelen or "unknown",
    cpus or "unbound",
    server_prefix or "none",
    replies.group(1).replace(",", "") if replies else "",
    replies.group(2) if replies else "",
    size.group(1) if size else "",
    bps.group(1) if bps else "",
    duration.group(1) if duration else "",
    str(dev_after["rx"] - dev_before["rx"]),
    str(dev_after["tx"] - dev_before["tx"]),
    delta(udp_before, udp_after, "InDatagrams"),
    delta(udp_before, udp_after, "OutDatagrams"),
    delta(udp_before, udp_after, "InErrors"),
    delta(udp_before, udp_after, "RcvbufErrors"),
    delta(udp_before, udp_after, "SndbufErrors"),
    delta(soft_before, soft_after, "dropped"),
    delta(soft_before, soft_after, "time_squeeze"),
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

    ssh "$server_ssh" bash -s -- "$run_abs" "$frequency" "$seconds" <<'REMOTE'
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

    if [[ "$record" != true ]]; then
        return 0
    fi

    ssh "$server_ssh" bash -s -- "$run_abs" <<'REMOTE'
set -euo pipefail
run_abs="$1"
if [[ -f "$run_abs/perf.pid" ]]; then
    perf_pid="$(cat "$run_abs/perf.pid")"
    for _ in $(seq 1 120); do
        if ! ps -p "$perf_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.25
    done
fi
if [[ -f "$run_abs/perf.data" ]]; then
    sudo perf report -i "$run_abs/perf.data" --stdio --no-children --sort comm,symbol,dso >"$run_abs/perf-report-symbols.txt" 2>"$run_abs/perf-report-symbols.err" || true
    sudo perf report -i "$run_abs/perf.data" --stdio --children --sort comm,symbol,dso >"$run_abs/perf-report-children.txt" 2>"$run_abs/perf-report-children.err" || true
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

    ssh "$server_ssh" bash -s -- "$run_abs" "$port" "$seconds" "$interval" <<'REMOTE'
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

    ssh "$server_ssh" bash -s -- "$run_abs" <<'REMOTE'
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

if [[ "$include_knot" == true ]]; then
    for rate in $rates_list; do
        select_run_id "knot-q${rate}"
        run_abs="$out_abs/$run_id"
        printf 'running %s\n' "$run_id"
        run_knot_reference_start "$run_abs" "$interface"
        ssh "$player_ssh" "cd $player_workdir && sudo kxdpgun -t '$duration' -p '$knot_port' -b '$batch' -Q '$rate' -I '$interface' -m '$kxdpgun_mode' -l '$source_ip' -i querydb '$target_ip'" >"$run_id.kxdpgun.tmp" 2>&1
        ssh "$server_ssh" "cat > '$run_abs/kxdpgun.log'" <"$run_id.kxdpgun.tmp"
        rm -f "$run_id.kxdpgun.tmp"
        run_server_finish "$run_abs" "knot" "n/a" "$rate" "n/a" "n/a" "n/a" "n/a" "n/a" "unbound" "__none__" "$interface"
        run_knot_reference_stop "$run_abs"
    done
fi

for workers in $workers_list; do
    for rate in $rates_list; do
        for udp_batch_size in $udp_batch_sizes; do
            for hot_path in $hot_path_list; do
                for idle_strategy in $idle_strategy_list; do
                    select_run_id "oxidedns-w${workers}-q${rate}-batch-${udp_batch_size}-metrics-${hot_path}-idle-${idle_strategy}"
                    run_abs="$out_abs/$run_id"
                    printf 'running %s\n' "$run_id"
                    run_server_start "$run_abs" "$workers" "$hot_path" "$idle_strategy" "$target_ip" "$knot_port" "$socket_receive_buffer_bytes" "$socket_send_buffer_bytes" "$worker_cpus" "$server_bin_arg" "$server_prefix_arg" "$interface" "$udp_batch_size"
                    run_server_perf_start "$run_abs" "$perf_record" "$perf_frequency" "$duration"
                    run_server_socket_sample_start "$run_abs" "$socket_sample" "$oxidedns_port" "$duration" "$socket_sample_interval"
                    ssh "$player_ssh" "cd $player_workdir && sudo kxdpgun -t '$duration' -p '$oxidedns_port' -b '$batch' -Q '$rate' -I '$interface' -m '$kxdpgun_mode' -l '$source_ip' -i querydb '$target_ip'" >"$run_id.kxdpgun.tmp" 2>&1
                    ssh "$server_ssh" "cat > '$run_abs/kxdpgun.log'" <"$run_id.kxdpgun.tmp"
                    rm -f "$run_id.kxdpgun.tmp"
                    run_server_socket_sample_finish "$run_abs" "$socket_sample"
                    run_server_perf_finish "$run_abs" "$perf_record"
                    run_server_finish "$run_abs" "oxidedns" "$workers" "$rate" "$udp_batch_size" "$hot_path" "$idle_strategy" "$socket_receive_buffer_bytes" "$socket_send_buffer_bytes" "$worker_cpus" "$server_prefix_arg" "$interface"
                done
            done
        done
    done
done

printf 'artifact_dir=%s\n' "$out_abs"
ssh "$server_ssh" "cat '$out_abs/summary.tsv'"
