#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/target/debug/boron-gun}"
drop_object="${2:-${BORON_GUN_XDP_DROP_OBJECT:-}}"
out_dir="$repo_root/target/boron-gun-xdp-drop-veth-smoke"
config="$out_dir/smoke.toml"
src_ns="oxg-drop-src-$$"
dst_ns="oxg-drop-dst-$$"
src_if="veth-oxg-src"
dst_if="veth-oxg-dst"
src_ip="198.18.0.1"
dst_ip="198.18.0.53"
src_mac="02:00:00:00:20:01"
dst_mac="02:00:00:00:20:53"
drop_count=4
pass_port=54000

if [[ "$(id -u)" -ne 0 ]]; then
    echo "boron-gun XDP drop smoke requires root; run with pkexec or sudo" >&2
    exit 77
fi
if [[ ! -x "$binary" ]]; then
    echo "boron-gun binary is not executable: $binary" >&2
    exit 1
fi
if [[ -z "$drop_object" || ! -f "$drop_object" ]]; then
    echo "compiled eBPF drop object is required" >&2
    echo "build it with: ./scripts/boron-gun-build-ebpf.sh" >&2
    exit 1
fi

command -v ip >/dev/null
command -v timeout >/dev/null
command -v tcpdump >/dev/null

mkdir -p "$out_dir"
summary="$out_dir/summary.json"
stderr_log="$out_dir/boron-gun.stderr"
pass_pcap="$out_dir/pass-traffic.pcap"
pass_text="$out_dir/pass-traffic.txt"
pass_tcpdump_log="$out_dir/pass-tcpdump.log"
rm -f "$summary" "$stderr_log" "$pass_pcap" "$pass_text" "$pass_tcpdump_log"
cat >"$config" <<'TOML'
[xdp]
mode = "skb"
zerocopy = "copy"
batch_size = 32
umem_frame_count = 256
tx_ring_size = 256
rx_ring_size = 256
fill_ring_size = 256
completion_ring_size = 256
TOML

cleanup() {
    if [[ -n "${boron_pid:-}" ]]; then
        kill "$boron_pid" 2>/dev/null || true
    fi
    if [[ -n "${pass_tcpdump_pid:-}" ]]; then
        kill "$pass_tcpdump_pid" 2>/dev/null || true
    fi
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

ip netns exec "$src_ns" timeout 8 "$binary" \
    --config "$config" \
    --backend xdp \
    --interface "$src_if" \
    --tx-queue 0 \
    --rx-queue 0 \
    --xdp-mode skb \
    --xdp-zerocopy copy \
    --xdp-drop-object "$drop_object" \
    --source-ip "$src_ip" \
    --source-port 53000 \
    --source-port-range 53000-53003 \
    --source-port-select sequential \
    --source-mac "$src_mac" \
    --target "$dst_ip:53" \
    --target-mac "$dst_mac" \
    --qname drop.boron.test. \
    --qtype A \
    --recv-mode drop \
    --duration-seconds 2 \
    --max-packets 1000000 \
    --target-qps 1000 \
    --flush-interval-ms 0 >"$summary" 2>"$stderr_log" &
boron_pid=$!

sleep 0.5
ip netns exec "$src_ns" timeout 8 tcpdump -i "$src_if" -U -c 1 -w "$pass_pcap" \
    "udp and dst port $pass_port" >"$pass_tcpdump_log" 2>&1 &
pass_tcpdump_pid=$!
sleep 0.2
# shellcheck disable=SC2016
ip netns exec "$dst_ns" bash -lc '
set -euo pipefail
for port in 53000 53001 53002 53003; do
    printf "reply" >"/dev/udp/198.18.0.1/$port"
done
printf "pass" >"/dev/udp/198.18.0.1/'"$pass_port"'"
'

wait "$pass_tcpdump_pid"
wait "$boron_pid"

python3 - "$summary" "$drop_count" <<'PY'
import json
import sys

path = sys.argv[1]
expected = int(sys.argv[2])
with open(path, encoding="utf-8") as handle:
    record = json.load(handle)

checks = {
    "record_type": "summary",
    "backend": "xdp_af_xdp",
    "xdp_mode": "skb",
    "zerocopy": "copy",
    "recv_mode": "drop",
    "drop_implementation": "kernel_xdp_drop",
    "errors_total": 0,
}
for key, expected_value in checks.items():
    actual = record.get(key)
    if actual != expected_value:
        raise SystemExit(f"{key}: expected {expected_value!r}, got {actual!r}")
actual_drops = record.get("rx_kernel_dropped_total", 0)
if actual_drops < expected:
    raise SystemExit(
        f"rx_kernel_dropped_total: expected at least {expected}, got {actual_drops}"
    )
PY

tcpdump -nn -r "$pass_pcap" >"$pass_text" 2>/dev/null
grep -q "$dst_ip\\.[0-9][0-9]* > $src_ip\\.$pass_port" "$pass_text"

printf 'boron-gun XDP drop veth smoke passed: %s\n' "$out_dir"
