#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${BORON_GUN_BIN:-$repo_root/target/release/boron-gun}"
out_dir="${BORON_GUN_EVIDENCE_DIR:-$repo_root/target/boron-gun-xdp-lab-throughput/$(date -u +%Y%m%dT%H%M%SZ)}"

usage() {
    cat >&2 <<'EOF'
Usage:
  BORON_GUN_INTERFACE=ens6f0 \
  BORON_GUN_SOURCE_MAC=02:00:00:00:00:01 \
  BORON_GUN_TARGET=198.18.0.53:53 \
  BORON_GUN_TARGET_MAC=aa:bb:cc:dd:ee:ff \
  scripts/boron-gun-xdp-lab-throughput.sh

Optional environment:
  BORON_GUN_BIN                    default target/release/boron-gun
  BORON_GUN_EVIDENCE_DIR           default target/boron-gun-xdp-lab-throughput/<utc>
  BORON_GUN_DRY_RUN                write config/command only, default 0
  BORON_GUN_SKIP_PREFLIGHT         skip interface preflight, default 0
  BORON_GUN_ALLOW_DEFAULT_ROUTE    pass through to preflight, default 0
  BORON_GUN_REQUIRE_PHYSICAL       require physical-interface preflight, default 0
  BORON_GUN_TX_QUEUE               default 0
  BORON_GUN_RX_QUEUE               default 0
  BORON_GUN_SOURCE_IP              default 198.18.0.1
  BORON_GUN_SOURCE_CIDR            default 198.18.10.0/24
  BORON_GUN_SOURCE_PORT_RANGE      default 53000-53999
  BORON_GUN_SOURCE_PORT_SELECT     default random
  BORON_GUN_QNAME_TEMPLATE         default host{}.rrl.example.
  BORON_GUN_QNAME_COUNT            default 10000
  BORON_GUN_QUERY_SELECT           default random
  BORON_GUN_DURATION_SECONDS       default 10
  BORON_GUN_MAX_PACKETS            default 1000000000
  BORON_GUN_TARGET_QPS             default 0, meaning unlimited
  BORON_GUN_FLUSH_INTERVAL_MS      default 1000
  BORON_GUN_COUNTER_SETTLE_SECONDS default 0.1 before post-run counters
  BORON_GUN_XDP_MODE               default drv
  BORON_GUN_XDP_ZEROCOPY           default auto
  BORON_GUN_XDP_BATCH_SIZE         default 128
  BORON_GUN_XDP_UMEM_FRAME_COUNT   default 16384
  BORON_GUN_XDP_RING_SIZE          default 4096 for all rings
  BORON_GUN_XDP_DROP_OBJECT        optional compiled eBPF drop object
  BORON_GUN_CPUSET                 optional taskset -c CPU list for boron-gun
  BORON_GUN_MIN_TX_QPS             optional evidence threshold
  BORON_GUN_MIN_TX_PACKETS         optional evidence threshold
  BORON_GUN_MIN_IF_TX_PACKETS      optional evidence threshold
  BORON_GUN_MIN_IF_TX_RATIO        optional if_tx_packets / tx_packets threshold
  BORON_GUN_MAX_ERRORS             optional evidence threshold, default unset
  BORON_GUN_MAX_IF_TX_ERRORS       optional evidence threshold, default unset
  BORON_GUN_MAX_IF_TX_DROPPED      optional evidence threshold, default unset
EOF
}

require_env() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "$name is required" >&2
        usage
        exit 2
    fi
}

dry_run="${BORON_GUN_DRY_RUN:-0}"
if [[ "$(id -u)" -ne 0 && "$dry_run" != "1" ]]; then
    echo "boron-gun XDP lab throughput run requires root or equivalent capabilities" >&2
    exit 77
fi
if [[ ! -x "$binary" ]]; then
    echo "boron-gun binary is not executable: $binary" >&2
    exit 1
fi

require_env BORON_GUN_INTERFACE
require_env BORON_GUN_SOURCE_MAC
require_env BORON_GUN_TARGET
require_env BORON_GUN_TARGET_MAC

source_ip="${BORON_GUN_SOURCE_IP:-198.18.0.1}"
source_cidr="${BORON_GUN_SOURCE_CIDR:-198.18.10.0/24}"
source_port_range="${BORON_GUN_SOURCE_PORT_RANGE:-53000-53999}"
source_port_select="${BORON_GUN_SOURCE_PORT_SELECT:-random}"
qname_template="${BORON_GUN_QNAME_TEMPLATE-}"
if [[ -z "$qname_template" ]]; then
    qname_template='host{}.rrl.example.'
fi
qname_count="${BORON_GUN_QNAME_COUNT:-10000}"
query_select="${BORON_GUN_QUERY_SELECT:-random}"
duration_seconds="${BORON_GUN_DURATION_SECONDS:-10}"
max_packets="${BORON_GUN_MAX_PACKETS:-1000000000}"
target_qps="${BORON_GUN_TARGET_QPS:-0}"
flush_interval_ms="${BORON_GUN_FLUSH_INTERVAL_MS:-1000}"
counter_settle_seconds="${BORON_GUN_COUNTER_SETTLE_SECONDS:-0.1}"
xdp_mode="${BORON_GUN_XDP_MODE:-drv}"
xdp_zerocopy="${BORON_GUN_XDP_ZEROCOPY:-auto}"
xdp_batch_size="${BORON_GUN_XDP_BATCH_SIZE:-128}"
xdp_umem_frame_count="${BORON_GUN_XDP_UMEM_FRAME_COUNT:-16384}"
xdp_tx_ring_size="${BORON_GUN_XDP_TX_RING_SIZE:-${BORON_GUN_XDP_RING_SIZE:-4096}}"
xdp_rx_ring_size="${BORON_GUN_XDP_RX_RING_SIZE:-${BORON_GUN_XDP_RING_SIZE:-4096}}"
xdp_fill_ring_size="${BORON_GUN_XDP_FILL_RING_SIZE:-${BORON_GUN_XDP_RING_SIZE:-4096}}"
xdp_completion_ring_size="${BORON_GUN_XDP_COMPLETION_RING_SIZE:-${BORON_GUN_XDP_RING_SIZE:-4096}}"
tx_queue="${BORON_GUN_TX_QUEUE:-0}"
rx_queue="${BORON_GUN_RX_QUEUE:-0}"
drop_object="${BORON_GUN_XDP_DROP_OBJECT:-}"
skip_preflight="${BORON_GUN_SKIP_PREFLIGHT:-0}"
cpuset="${BORON_GUN_CPUSET:-}"

command -v ip >/dev/null
command -v ethtool >/dev/null || true
if [[ -n "$cpuset" ]]; then
    command -v taskset >/dev/null
fi

mkdir -p "$out_dir"
config="$out_dir/config.toml"
output="$out_dir/boron-gun.jsonl"
summary="$out_dir/summary.json"
evidence="$out_dir/evidence-summary.json"
metadata="$out_dir/metadata.txt"
command_file="$out_dir/command.txt"

cat >"$config" <<TOML
[xdp]
mode = "$xdp_mode"
zerocopy = "$xdp_zerocopy"
batch_size = $xdp_batch_size
umem_frame_count = $xdp_umem_frame_count
tx_ring_size = $xdp_tx_ring_size
rx_ring_size = $xdp_rx_ring_size
fill_ring_size = $xdp_fill_ring_size
completion_ring_size = $xdp_completion_ring_size
TOML

{
    printf 'utc_start=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'binary=%s\n' "$binary"
    printf 'binary_sha256=%s\n' "$(sha256sum "$binary" | awk '{print $1}')"
    printf 'git_commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)"
    if git -C "$repo_root" diff --quiet -- . 2>/dev/null; then
        printf 'git_worktree_dirty=false\n'
    else
        printf 'git_worktree_dirty=true\n'
    fi
    printf 'rustc=%s\n' "$(rustc --version 2>/dev/null || printf unknown)"
    printf 'cargo=%s\n' "$(cargo --version 2>/dev/null || printf unknown)"
    printf 'interface=%s\n' "$BORON_GUN_INTERFACE"
    printf 'target=%s\n' "$BORON_GUN_TARGET"
    printf 'target_qps=%s\n' "$target_qps"
    printf 'duration_seconds=%s\n' "$duration_seconds"
    printf 'cpuset=%s\n' "$cpuset"
    printf 'nproc=%s\n' "$(nproc 2>/dev/null || printf unknown)"
    printf 'allow_default_route=%s\n' "${BORON_GUN_ALLOW_DEFAULT_ROUTE:-0}"
    printf 'require_physical=%s\n' "${BORON_GUN_REQUIRE_PHYSICAL:-0}"
    printf 'xdp_mode=%s\n' "$xdp_mode"
    printf 'xdp_zerocopy=%s\n' "$xdp_zerocopy"
    printf 'tx_queue=%s\n' "$tx_queue"
    printf 'rx_queue=%s\n' "$rx_queue"
    uname -a
} >"$metadata"

cmd=(
    "$binary"
    --config "$config"
    --backend xdp
    --interface "$BORON_GUN_INTERFACE"
    --tx-queue "$tx_queue"
    --rx-queue "$rx_queue"
    --xdp-mode "$xdp_mode"
    --xdp-zerocopy "$xdp_zerocopy"
    --source-ip "$source_ip"
    --source-cidr "$source_cidr"
    --source-port-range "$source_port_range"
    --source-port-select "$source_port_select"
    --source-mac "$BORON_GUN_SOURCE_MAC"
    --target "$BORON_GUN_TARGET"
    --target-mac "$BORON_GUN_TARGET_MAC"
    --qname-template "$qname_template"
    --qname-count "$qname_count"
    --query-select "$query_select"
    --recv-mode drop
    --duration-seconds "$duration_seconds"
    --max-packets "$max_packets"
    --target-qps "$target_qps"
    --seed 42
    --flush-interval-ms "$flush_interval_ms"
)
if [[ -n "$drop_object" ]]; then
    cmd+=(--xdp-drop-object "$drop_object")
fi

run_cmd=("${cmd[@]}")
if [[ -n "$cpuset" ]]; then
    run_cmd=(taskset -c "$cpuset" "${cmd[@]}")
fi

printf '%q ' "${run_cmd[@]}" >"$command_file"
printf '\n' >>"$command_file"

if [[ "$dry_run" == "1" ]]; then
    printf 'boron-gun XDP lab dry-run written: %s\n' "$out_dir"
    exit 0
fi

if [[ "$skip_preflight" != "1" ]]; then
    BORON_GUN_PREFLIGHT_DIR="$out_dir/preflight" \
        BORON_GUN_INTERFACE="$BORON_GUN_INTERFACE" \
        BORON_GUN_TARGET="$BORON_GUN_TARGET" \
        BORON_GUN_TARGET_MAC="$BORON_GUN_TARGET_MAC" \
        BORON_GUN_SOURCE_MAC="$BORON_GUN_SOURCE_MAC" \
        BORON_GUN_TX_QUEUE="$tx_queue" \
        BORON_GUN_RX_QUEUE="$rx_queue" \
        BORON_GUN_XDP_MODE="$xdp_mode" \
        BORON_GUN_XDP_ZEROCOPY="$xdp_zerocopy" \
        BORON_GUN_XDP_DROP_OBJECT="$drop_object" \
        BORON_GUN_ALLOW_DEFAULT_ROUTE="${BORON_GUN_ALLOW_DEFAULT_ROUTE:-0}" \
        BORON_GUN_REQUIRE_PHYSICAL="${BORON_GUN_REQUIRE_PHYSICAL:-0}" \
        "$repo_root/scripts/boron-gun-xdp-lab-preflight.sh" >"$out_dir/preflight.out"
fi

ip -s link show dev "$BORON_GUN_INTERFACE" >"$out_dir/ip-link-before.txt"
ip -j -s link show dev "$BORON_GUN_INTERFACE" >"$out_dir/ip-link-before.json"
if command -v ethtool >/dev/null; then
    ethtool -S "$BORON_GUN_INTERFACE" >"$out_dir/ethtool-before.txt" 2>"$out_dir/ethtool-before.err" || true
fi

"${run_cmd[@]}" >"$output"

sleep "$counter_settle_seconds"
ip -s link show dev "$BORON_GUN_INTERFACE" >"$out_dir/ip-link-after.txt"
ip -j -s link show dev "$BORON_GUN_INTERFACE" >"$out_dir/ip-link-after.json"
if command -v ethtool >/dev/null; then
    ethtool -S "$BORON_GUN_INTERFACE" >"$out_dir/ethtool-after.txt" 2>"$out_dir/ethtool-after.err" || true
fi
printf 'utc_end=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$metadata"

python3 - "$output" "$summary" "$out_dir/ip-link-before.json" "$out_dir/ip-link-after.json" "$evidence" "$out_dir/preflight/summary.json" "$metadata" <<'PY'
import json
import os
import sys

(
    output_path,
    summary_path,
    before_path,
    after_path,
    evidence_path,
    preflight_path,
    metadata_path,
) = sys.argv[1:8]

records = []
with open(output_path, encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if line:
            records.append(json.loads(line))
if not records:
    raise SystemExit("boron-gun produced no JSON records")

summary = next((record for record in reversed(records) if record.get("summary")), records[-1])
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, sort_keys=True)
    handle.write("\n")

def load_link_stats(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not data:
        return {}
    return data[0].get("stats64", {})

def delta(before, after, direction, field):
    return (
        after.get(direction, {}).get(field, 0)
        - before.get(direction, {}).get(field, 0)
    )

before = load_link_stats(before_path)
after = load_link_stats(after_path)
counter_delta = {
    "tx_packets": delta(before, after, "tx", "packets"),
    "tx_bytes": delta(before, after, "tx", "bytes"),
    "tx_errors": delta(before, after, "tx", "errors"),
    "tx_dropped": delta(before, after, "tx", "dropped"),
    "rx_packets": delta(before, after, "rx", "packets"),
    "rx_bytes": delta(before, after, "rx", "bytes"),
    "rx_errors": delta(before, after, "rx", "errors"),
    "rx_dropped": delta(before, after, "rx", "dropped"),
}

def parse_metadata(path):
    metadata = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if "=" in line:
                key, value = line.split("=", 1)
                metadata[key] = value
            elif line:
                metadata.setdefault("uname", line)
    return metadata

def optional_float(name):
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return float(value)

def optional_int(name):
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return int(value)

thresholds = {
    "min_tx_qps": optional_float("BORON_GUN_MIN_TX_QPS"),
    "min_tx_packets": optional_int("BORON_GUN_MIN_TX_PACKETS"),
    "min_if_tx_packets": optional_int("BORON_GUN_MIN_IF_TX_PACKETS"),
    "min_if_tx_ratio": optional_float("BORON_GUN_MIN_IF_TX_RATIO"),
    "max_errors": optional_int("BORON_GUN_MAX_ERRORS"),
    "max_if_tx_errors": optional_int("BORON_GUN_MAX_IF_TX_ERRORS"),
    "max_if_tx_dropped": optional_int("BORON_GUN_MAX_IF_TX_DROPPED"),
}

threshold_failures = []
tx_packets_total = summary.get("tx_packets_total", 0) or 0
if thresholds["min_tx_qps"] is not None and summary.get("tx_qps", 0) < thresholds["min_tx_qps"]:
    threshold_failures.append(
        f"tx_qps {summary.get('tx_qps')} < {thresholds['min_tx_qps']}"
    )
if thresholds["min_tx_packets"] is not None and tx_packets_total < thresholds["min_tx_packets"]:
    threshold_failures.append(
        f"tx_packets_total {summary.get('tx_packets_total')} < {thresholds['min_tx_packets']}"
    )
if thresholds["min_if_tx_packets"] is not None and counter_delta["tx_packets"] < thresholds["min_if_tx_packets"]:
    threshold_failures.append(
        f"interface tx_packets delta {counter_delta['tx_packets']} < {thresholds['min_if_tx_packets']}"
    )
if thresholds["min_if_tx_ratio"] is not None:
    if_tx_ratio = counter_delta["tx_packets"] / max(tx_packets_total, 1)
    if if_tx_ratio < thresholds["min_if_tx_ratio"]:
        threshold_failures.append(
            f"interface tx ratio {if_tx_ratio:.6f} < {thresholds['min_if_tx_ratio']}"
        )
if thresholds["max_errors"] is not None and summary.get("errors_total", 0) > thresholds["max_errors"]:
    threshold_failures.append(
        f"errors_total {summary.get('errors_total')} > {thresholds['max_errors']}"
    )
if thresholds["max_if_tx_errors"] is not None and counter_delta["tx_errors"] > thresholds["max_if_tx_errors"]:
    threshold_failures.append(
        f"interface tx_errors delta {counter_delta['tx_errors']} > {thresholds['max_if_tx_errors']}"
    )
if thresholds["max_if_tx_dropped"] is not None and counter_delta["tx_dropped"] > thresholds["max_if_tx_dropped"]:
    threshold_failures.append(
        f"interface tx_dropped delta {counter_delta['tx_dropped']} > {thresholds['max_if_tx_dropped']}"
    )

evidence = {
    "run": parse_metadata(metadata_path),
    "boron_gun": {
        "tx_packets_total": summary.get("tx_packets_total"),
        "tx_bytes_total": summary.get("tx_bytes_total"),
        "tx_qps": summary.get("tx_qps"),
        "rx_kernel_dropped_total": summary.get("rx_kernel_dropped_total"),
        "errors_total": summary.get("errors_total"),
        "zerocopy": summary.get("zerocopy"),
        "xdp_mode": summary.get("xdp_mode"),
        "recv_mode": summary.get("recv_mode"),
        "drop_implementation": summary.get("drop_implementation"),
    },
    "interface_counter_delta": counter_delta,
    "interface_tx_packet_ratio": counter_delta["tx_packets"] / max(tx_packets_total, 1),
    "thresholds": {key: value for key, value in thresholds.items() if value is not None},
    "threshold_failures": threshold_failures,
}
if os.path.exists(preflight_path):
    with open(preflight_path, encoding="utf-8") as handle:
        evidence["preflight"] = json.load(handle)
with open(evidence_path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, indent=2, sort_keys=True)
    handle.write("\n")

for key in ("tx_packets_total", "tx_bytes_total", "tx_qps", "errors_total"):
    print(f"{key}={summary.get(key)}")
for key, value in counter_delta.items():
    print(f"if_{key}_delta={value}")
if threshold_failures:
    for failure in threshold_failures:
        print(f"threshold_failure={failure}", file=sys.stderr)
    raise SystemExit(1)
PY
printf 'boron-gun XDP lab evidence written: %s\n' "$out_dir"
