#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${1:-$repo_root/target/debug/borondns}"
if [[ "$binary" != /* ]]; then
    binary="$repo_root/$binary"
fi
out_dir="$repo_root/target/borondns-af-xdp-veth-smoke"
config="$out_dir/server.toml"
log="$out_dir/server.log"
srv_ns="odns-xdp-srv-$$"
peer_ns="odns-xdp-peer-$$"
srv_if="veth-odns-srv"
peer_if="veth-odns-peer"
srv_ip="198.18.10.53"
peer_ip="198.18.10.1"
run_as_user="${BORONDNS_SMOKE_RUN_AS_USER:-nobody}"

redirect_object="${BORONDNS_XDP_REDIRECT_OBJECT:-}"
if [[ -z "$redirect_object" ]]; then
    built_object="$repo_root/crates/borondns-server-ebpf/target/bpfel-unknown-none/release/borondns-xdp-redirect.bpf.o"
    if [[ ! -f "$built_object" ]]; then
        echo "BoronDNS XDP redirect object is missing." >&2
        echo "Build it before running this root smoke: ./scripts/borondns-server-build-ebpf.sh" >&2
        exit 1
    fi
    redirect_object="$built_object"
fi
if [[ "$redirect_object" != /* ]]; then
    redirect_object="$repo_root/$redirect_object"
fi
if [[ ! -f "$redirect_object" ]]; then
    echo "BoronDNS XDP redirect object does not exist: $redirect_object" >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "BoronDNS AF_XDP veth smoke requires root; run with pkexec or sudo" >&2
    exit 77
fi

if [[ ! -x "$binary" ]]; then
    echo "borondns binary is not executable: $binary" >&2
    echo "build it with: cargo build -p borondns-cli --features af-xdp" >&2
    exit 1
fi

command -v ip >/dev/null
command -v timeout >/dev/null

mkdir -p "$out_dir"
rm -f "$config" "$log"

cleanup() {
    ip netns pids "$srv_ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$peer_ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$srv_ns" 2>/dev/null || true
    ip netns del "$peer_ns" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$srv_ns"
ip netns add "$peer_ns"
ip link add "$srv_if" type veth peer name "$peer_if"
ip link set "$srv_if" netns "$srv_ns"
ip link set "$peer_if" netns "$peer_ns"
ip -n "$srv_ns" addr add "$srv_ip/24" dev "$srv_if"
ip -n "$peer_ns" addr add "$peer_ip/24" dev "$peer_if"
ip -n "$srv_ns" link set lo up
ip -n "$peer_ns" link set lo up
ip -n "$srv_ns" link set "$srv_if" up
ip -n "$peer_ns" link set "$peer_if" up

cat >"$config" <<TOML
[server]
listen_udp = ["$srv_ip:53"]
listen_tcp = []

[process]
run_as_user = "$run_as_user"

[limits]
udp_backend = "af_xdp"
udp_batch_size = 4

[xdp]
interface = "$srv_if"
redirect_object = "$redirect_object"
mode = "skb"
queue_id = 0
umem_frame_count = 64
rx_ring_size = 64
tx_ring_size = 64
fill_ring_size = 64
completion_ring_size = 64
batch_size = 4
zero_copy = "disable"

[[zones]]
name = "smoke.oxide.test."
primaries = ["$peer_ip:53"]
TOML

set +e
ip netns exec "$srv_ns" timeout 6 "$binary" serve --config "$config" >"$log" 2>&1
status=$?
set -e

if [[ "$status" -ne 124 ]]; then
    echo "BoronDNS AF_XDP veth smoke failed: server exited with status $status" >&2
    cat "$log" >&2
    exit 1
fi

if ! grep -q "UDP listener bound" "$log"; then
    echo "BoronDNS AF_XDP veth smoke failed: UDP listener did not bind" >&2
    cat "$log" >&2
    exit 1
fi

printf 'BoronDNS AF_XDP veth smoke passed: %s\n' "$out_dir"
