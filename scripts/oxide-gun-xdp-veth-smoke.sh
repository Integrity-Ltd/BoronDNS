#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/target/debug/oxide-gun}"
out_dir="$repo_root/target/oxide-gun-xdp-veth-smoke"
config="$out_dir/smoke.toml"
src_ns="oxg-src-$$"
dst_ns="oxg-dst-$$"
src_if="veth-oxg-src"
dst_if="veth-oxg-dst"
src_ip="198.18.0.1"
dst_ip="198.18.0.53"
src_range_start="198.18.0.10"
src_mac="02:00:00:00:10:01"
dst_mac="02:00:00:00:10:53"
packet_count=4
drop_object="${OXIDE_GUN_XDP_DROP_OBJECT:-}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "oxide-gun XDP veth smoke requires root; run with pkexec or sudo" >&2
    exit 77
fi

if [[ ! -x "$binary" ]]; then
    echo "oxide-gun binary is not executable: $binary" >&2
    exit 1
fi

command -v ip >/dev/null
command -v timeout >/dev/null
command -v tcpdump >/dev/null

mkdir -p "$out_dir"
summary="$out_dir/summary.json"
pcap="$out_dir/peer.pcap"
tcpdump_log="$out_dir/tcpdump.log"
rm -f "$summary" "$pcap" "$tcpdump_log"
cat >"$config" <<'TOML'
[xdp]
mode = "skb"
zerocopy = "copy"
batch_size = 4
umem_frame_count = 64
tx_ring_size = 64
rx_ring_size = 64
fill_ring_size = 64
completion_ring_size = 64
TOML

cleanup() {
    ip netns pids "$dst_ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$src_ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$src_ns" 2>/dev/null || true
    ip netns del "$dst_ns" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$src_ns"
ip netns add "$dst_ns"
ip link add "$src_if" address "$src_mac" type veth peer name "$dst_if" address "$dst_mac"
ip link set "$src_if" netns "$src_ns"
ip link set "$dst_if" netns "$dst_ns"
ip -n "$src_ns" addr add "$src_ip/24" dev "$src_if"
ip -n "$dst_ns" addr add "$dst_ip/24" dev "$dst_if"
ip -n "$src_ns" link set lo up
ip -n "$dst_ns" link set lo up
ip -n "$src_ns" link set "$src_if" up
ip -n "$dst_ns" link set "$dst_if" up

ip netns exec "$dst_ns" timeout 8 tcpdump -i "$dst_if" -U -c "$packet_count" -w "$pcap" \
    "udp and dst port 53" >"$tcpdump_log" 2>&1 &
tcpdump_pid=$!
sleep 0.5

cmd=(
    ip netns exec "$src_ns" timeout 8 "$binary"
    --config "$config"
    --backend xdp
    --interface "$src_if"
    --tx-queue 0
    --rx-queue 0
    --xdp-zerocopy copy
    --source-ip "$src_ip"
    --source-port 53000
    --source-range-start "$src_range_start"
    --source-range-count "$packet_count"
    --source-port-range 53000-53003
    --source-port-select sequential
    --source-mac "$src_mac"
    --target "$dst_ip:53"
    --target-mac "$dst_mac"
    --qname smoke.oxide.test.
    --qtype A
    --recv-mode drop
    --max-packets "$packet_count"
    --target-qps 0
    --flush-interval-ms 0
)
if [[ -n "$drop_object" ]]; then
    cmd+=(--xdp-drop-object "$drop_object")
fi
"${cmd[@]}" >"$summary"

wait "$tcpdump_pid"

python3 - "$summary" "$packet_count" <<'PY'
import json
import sys

path = sys.argv[1]
expected = int(sys.argv[2])
with open(path, encoding="utf-8") as handle:
    record = json.load(handle)

checks = {
    "record_type": "summary",
    "backend": "xdp_af_xdp",
    "recv_mode": "drop",
    "drop_implementation": "userspace_suppression",
    "tx_packets_total": expected,
    "errors_total": 0,
    "source_strategy": "sequential:198.18.0.10/count=4/stride=1",
    "source_port_strategy": "sequential:53000-53003",
}
for key, expected_value in checks.items():
    actual = record.get(key)
    if actual != expected_value:
        raise SystemExit(f"{key}: expected {expected_value!r}, got {actual!r}")
if record.get("tx_bytes_total", 0) <= 0:
    raise SystemExit("tx_bytes_total did not increase")
PY

tcpdump -nn -r "$pcap" >"$out_dir/peer.txt" 2>/dev/null
for offset in $(seq 0 $((packet_count - 1))); do
    source_host=$((10 + offset))
    source_port=$((53000 + offset))
    grep -q "198\\.18\\.0\\.$source_host\\.$source_port > $dst_ip\\.53" "$out_dir/peer.txt"
done
printf 'oxide-gun XDP veth smoke passed: %s\n' "$out_dir"
