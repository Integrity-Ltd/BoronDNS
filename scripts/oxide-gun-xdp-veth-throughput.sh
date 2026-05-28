#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/target/debug/oxide-gun}"

if [[ "${OXIDE_GUN_XDP_VETH_THROUGHPUT_INSIDE:-0}" != "1" ]]; then
    command -v unshare >/dev/null
    if [[ "$(id -u)" -eq 0 ]]; then
        exec unshare -n env OXIDE_GUN_XDP_VETH_THROUGHPUT_INSIDE=1 bash "$0" "$binary"
    fi
    exec unshare -Urn env OXIDE_GUN_XDP_VETH_THROUGHPUT_INSIDE=1 bash "$0" "$binary"
fi

out_dir="$repo_root/target/oxide-gun-xdp-veth-throughput"
src_if="veth-oxg-src"
dst_if="veth-oxg-dst"
src_ip="198.18.0.1"
dst_ip="198.18.0.53"
src_mac="02:00:00:00:40:01"
dst_mac="02:00:00:00:40:53"

if [[ ! -x "$binary" ]]; then
    echo "oxide-gun binary is not executable: $binary" >&2
    exit 1
fi

command -v ip >/dev/null

cleanup() {
    ip link del "$src_if" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$out_dir"
mkdir -p "$out_dir"

ip link add "$src_if" address "$src_mac" type veth peer name "$dst_if" address "$dst_mac"
ip addr add "$src_ip/24" dev "$src_if"
ip addr add "$dst_ip/24" dev "$dst_if"
ip link set lo up
ip link set "$src_if" up
ip link set "$dst_if" up

env \
    OXIDE_GUN_BIN="$binary" \
    OXIDE_GUN_EVIDENCE_DIR="$out_dir" \
    OXIDE_GUN_INTERFACE="$src_if" \
    OXIDE_GUN_SOURCE_MAC="$src_mac" \
    OXIDE_GUN_TARGET="$dst_ip:53" \
    OXIDE_GUN_TARGET_MAC="$dst_mac" \
    OXIDE_GUN_SOURCE_IP="$src_ip" \
    OXIDE_GUN_SOURCE_CIDR="198.18.10.0/24" \
    OXIDE_GUN_SOURCE_PORT_RANGE="53000-53999" \
    OXIDE_GUN_DURATION_SECONDS="${OXIDE_GUN_VETH_DURATION_SECONDS:-1}" \
    OXIDE_GUN_MAX_PACKETS="${OXIDE_GUN_VETH_MAX_PACKETS:-20000}" \
    OXIDE_GUN_TARGET_QPS="${OXIDE_GUN_VETH_TARGET_QPS:-0}" \
    OXIDE_GUN_FLUSH_INTERVAL_MS=0 \
    OXIDE_GUN_QNAME_TEMPLATE="veth{}.rrl.example." \
    OXIDE_GUN_QNAME_COUNT=1024 \
    OXIDE_GUN_XDP_MODE=skb \
    OXIDE_GUN_XDP_ZEROCOPY=copy \
    OXIDE_GUN_XDP_BATCH_SIZE=64 \
    OXIDE_GUN_XDP_UMEM_FRAME_COUNT=256 \
    OXIDE_GUN_XDP_RING_SIZE=256 \
    OXIDE_GUN_MIN_TX_QPS="${OXIDE_GUN_VETH_MIN_TX_QPS:-100000}" \
    OXIDE_GUN_MIN_TX_PACKETS="${OXIDE_GUN_VETH_MIN_TX_PACKETS:-1}" \
    OXIDE_GUN_MIN_IF_TX_PACKETS="${OXIDE_GUN_VETH_MIN_IF_TX_PACKETS:-1}" \
    OXIDE_GUN_MIN_IF_TX_RATIO="${OXIDE_GUN_VETH_MIN_IF_TX_RATIO:-0.90}" \
    OXIDE_GUN_MAX_ERRORS=0 \
    OXIDE_GUN_MAX_IF_TX_ERRORS=0 \
    OXIDE_GUN_MAX_IF_TX_DROPPED=0 \
    "$repo_root/scripts/oxide-gun-xdp-lab-throughput.sh"

python3 - "$out_dir/evidence-summary.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    evidence = json.load(handle)
oxide = evidence["oxide_gun"]
counters = evidence["interface_counter_delta"]
threshold_failures = evidence.get("threshold_failures", [])

if oxide.get("errors_total") != 0:
    raise SystemExit(f"errors_total: expected 0, got {oxide.get('errors_total')!r}")
if threshold_failures:
    raise SystemExit(f"threshold_failures is not empty: {threshold_failures!r}")
if oxide.get("drop_implementation") != "userspace_suppression":
    raise SystemExit(
        f"drop_implementation: expected userspace_suppression, got {oxide.get('drop_implementation')!r}"
    )
if oxide.get("tx_packets_total", 0) <= 0:
    raise SystemExit("tx_packets_total did not increase")
if counters.get("tx_packets", 0) <= 0:
    raise SystemExit("interface TX packet counter did not increase")
PY

printf 'oxide-gun XDP veth throughput evidence passed: %s\n' "$out_dir"
