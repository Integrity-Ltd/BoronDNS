#!/usr/bin/env bash
# shellcheck disable=SC2029
set -euo pipefail

server_ssh="${OXIDEDNS_PHYSICAL_SERVER_SSH:-oxidedns-1}"
player_ssh="${OXIDEDNS_PHYSICAL_PLAYER_SSH:-oxidegun-1}"
server_root="${OXIDEDNS_PHYSICAL_SERVER_ROOT:-~/oxidedns}"
player_workdir="${OXIDEDNS_PHYSICAL_PLAYER_WORKDIR:-~/oxidedns-tools/bench}"
target_ip="${OXIDEDNS_PHYSICAL_TARGET_IP:-198.18.0.1}"
source_ip="${OXIDEDNS_PHYSICAL_SOURCE_IP:-198.18.0.2}"
interface="${OXIDEDNS_PHYSICAL_INTERFACE:-eno1np0}"
oxidedns_port="${OXIDEDNS_PHYSICAL_OXIDEDNS_PORT:-5300}"
knot_port="${OXIDEDNS_PHYSICAL_KNOT_PORT:-5301}"
duration="${OXIDEDNS_PHYSICAL_DURATION:-5}"
batch="${OXIDEDNS_PHYSICAL_KXDPGUN_BATCH:-10}"
kxdpgun_mode="${OXIDEDNS_PHYSICAL_KXDPGUN_MODE:-generic}"
workers_list="${OXIDEDNS_PHYSICAL_WORKERS:-24}"
rates_list="${OXIDEDNS_PHYSICAL_RATES:-2000000}"
hot_path_list="${OXIDEDNS_PHYSICAL_HOT_PATH_DETAILS:-reduced off}"
idle_strategy_list="${OXIDEDNS_PHYSICAL_IDLE_STRATEGIES:-park spin}"
socket_buffer_bytes="${OXIDEDNS_PHYSICAL_SOCKET_BUFFER_BYTES:-}"
worker_cpus="${OXIDEDNS_PHYSICAL_WORKER_CPUS:-}"
stage_override="${OXIDEDNS_PHYSICAL_STAGE:-}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$1" >&2
        exit 69
    fi
}

require_tool ssh

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
}

trap cleanup_remote EXIT

server_root_abs="$(remote_server_root)"
stage_abs="$(resolve_stage)"
out_abs="$stage_abs/evidence/physical-udp-knot-comparison-$(date -u +%Y%m%dT%H%M%SZ)"

ssh "$server_ssh" "mkdir -p '$out_abs' && printf 'target\\tworkers\\trate\\thot_path_detail\\tidle_strategy\\tsocket_buffer_bytes\\tworker_cpus\\treplies_per_second\\treply_percent\\tdns_reply_size\\tethernet_reply_bps\\tduration_seconds\\n' > '$out_abs/summary.tsv'"

run_server_start() {
    local run_abs="$1"
    local workers="$2"
    local hot_path="$3"
    local idle_strategy="$4"
    local knot_target_ip="$5"
    local knot_target_port="$6"
    local socket_buffer="$7"
    local cpus="$8"
    local socket_buffer_arg="${socket_buffer:-__none__}"
    local cpus_arg="${cpus:-__none__}"

    ssh "$server_ssh" bash -s -- "$server_root_abs" "$stage_abs" "$run_abs" "$workers" "$hot_path" "$idle_strategy" "$knot_target_ip" "$knot_target_port" "$socket_buffer_arg" "$cpus_arg" <<'REMOTE'
set -euo pipefail
server_root="$1"
stage_abs="$2"
run_abs="$3"
workers="$4"
hot_path="$5"
idle_strategy="$6"
knot_target_ip="$7"
knot_target_port="$8"
socket_buffer="$9"
cpus="${10}"
if [[ "$socket_buffer" == "__none__" ]]; then
    socket_buffer=""
fi
if [[ "$cpus" == "__none__" ]]; then
    cpus=""
fi

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
if [[ -n "$socket_buffer" ]]; then
    python3 - "$run_abs/oxidedns.toml" "$socket_buffer" <<'PY'
import re
import sys

path, socket_buffer = sys.argv[1:3]
text = open(path, encoding="utf-8").read()
for key in ("udp_socket_receive_buffer_bytes", "udp_socket_send_buffer_bytes"):
    if key in text:
        text = re.sub(rf"{key} = \d+", f"{key} = {socket_buffer}", text)
    else:
        text = text.replace(
            'udp_runtime = "dedicated"',
            f'udp_runtime = "dedicated"\n{key} = {socket_buffer}',
        )
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

"$server_root/target/release/oxidedns" --validate-config "$run_abs/oxidedns.toml" >"$run_abs/validate.out" 2>&1

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
"$server_root/target/release/oxidedns" serve --config "$run_abs/oxidedns.toml" >"$run_abs/oxidedns.log" 2>&1 &
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
REMOTE
}

run_server_finish() {
    local run_abs="$1"
    local target="$2"
    local workers="$3"
    local rate="$4"
    local hot_path="$5"
    local idle_strategy="$6"
    local socket_buffer="$7"
    local cpus="$8"
    local socket_buffer_arg="${socket_buffer:-__none__}"
    local cpus_arg="${cpus:-__none__}"

    ssh "$server_ssh" bash -s -- "$out_abs" "$run_abs" "$target" "$workers" "$rate" "$hot_path" "$idle_strategy" "$socket_buffer_arg" "$cpus_arg" <<'REMOTE'
set -euo pipefail
out_abs="$1"
run_abs="$2"
target="$3"
workers="$4"
rate="$5"
hot_path="$6"
idle_strategy="$7"
socket_buffer="$8"
cpus="${9}"
if [[ "$socket_buffer" == "__none__" ]]; then
    socket_buffer=""
fi
if [[ "$cpus" == "__none__" ]]; then
    cpus=""
fi

cp /proc/net/dev "$run_abs/server-proc-net-dev-after.txt"
curl -fsS http://127.0.0.1:8080/metrics >"$run_abs/metrics-after.prom" || true
python3 - "$target" "$workers" "$rate" "$hot_path" "$idle_strategy" "$socket_buffer" "$cpus" "$run_abs/kxdpgun.log" >>"$out_abs/summary.tsv" <<'PY'
import re
import sys

target, workers, rate, hot_path, idle_strategy, socket_buffer, cpus, log = sys.argv[1:9]
text = open(log, encoding="utf-8", errors="ignore").read()
replies = re.search(r"total replies:\s+\d+ \(([0-9,]+) pps\) \(([0-9.]+) %\)", text)
size = re.search(r"average DNS reply size:\s+([0-9.]+) B", text)
bps = re.search(r"average Ethernet reply rate:\s+([0-9]+) bps", text)
duration = re.search(r"duration:\s+([0-9.]+) s", text)
print("\t".join([
    target,
    workers,
    rate,
    hot_path,
    idle_strategy,
    socket_buffer or "default",
    cpus or "unbound",
    replies.group(1).replace(",", "") if replies else "",
    replies.group(2) if replies else "",
    size.group(1) if size else "",
    bps.group(1) if bps else "",
    duration.group(1) if duration else "",
]))
PY

if [[ -f "$run_abs/oxidedns.pid" ]]; then
    kill "$(cat "$run_abs/oxidedns.pid")" 2>/dev/null || true
    wait "$(cat "$run_abs/oxidedns.pid")" 2>/dev/null || true
fi
REMOTE
}

for workers in $workers_list; do
    for rate in $rates_list; do
        for hot_path in $hot_path_list; do
            for idle_strategy in $idle_strategy_list; do
                run_id="oxidedns-w${workers}-q${rate}-metrics-${hot_path}-idle-${idle_strategy}"
                run_abs="$out_abs/$run_id"
                printf 'running %s\n' "$run_id"
                run_server_start "$run_abs" "$workers" "$hot_path" "$idle_strategy" "$target_ip" "$knot_port" "$socket_buffer_bytes" "$worker_cpus"
                ssh "$player_ssh" "cd $player_workdir && sudo kxdpgun -t '$duration' -p '$oxidedns_port' -b '$batch' -Q '$rate' -I '$interface' -m '$kxdpgun_mode' -l '$source_ip' -i querydb '$target_ip'" >"$run_id.kxdpgun.tmp" 2>&1
                ssh "$server_ssh" "cat > '$run_abs/kxdpgun.log'" <"$run_id.kxdpgun.tmp"
                rm -f "$run_id.kxdpgun.tmp"
                run_server_finish "$run_abs" "oxidedns" "$workers" "$rate" "$hot_path" "$idle_strategy" "$socket_buffer_bytes" "$worker_cpus"
            done
        done
    done
done

printf 'artifact_dir=%s\n' "$out_abs"
ssh "$server_ssh" "cat '$out_abs/summary.tsv'"
