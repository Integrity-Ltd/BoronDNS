#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${OXIDE_GUN_PREFLIGHT_DIR:-$repo_root/target/oxide-gun-xdp-lab-preflight/$(date -u +%Y%m%dT%H%M%SZ)}"

usage() {
    cat >&2 <<'EOF'
Usage:
  OXIDE_GUN_INTERFACE=ens6f0 scripts/oxide-gun-xdp-lab-preflight.sh

Optional environment:
  OXIDE_GUN_TARGET                 target socket, recorded when set
  OXIDE_GUN_TARGET_MAC             target MAC, warning when unset
  OXIDE_GUN_SOURCE_MAC             source MAC, warning when it does not match interface MAC
  OXIDE_GUN_TX_QUEUE               default 0
  OXIDE_GUN_RX_QUEUE               default 0
  OXIDE_GUN_XDP_MODE               default drv
  OXIDE_GUN_XDP_ZEROCOPY           default auto
  OXIDE_GUN_XDP_DROP_OBJECT        optional compiled eBPF drop object path
  OXIDE_GUN_ALLOW_DEFAULT_ROUTE    allow default-route interface, default 0
  OXIDE_GUN_REQUIRE_PHYSICAL       require physical-interface evidence, default 0
  OXIDE_GUN_PREFLIGHT_DIR          evidence output directory
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

require_env OXIDE_GUN_INTERFACE

interface="$OXIDE_GUN_INTERFACE"
tx_queue="${OXIDE_GUN_TX_QUEUE:-0}"
rx_queue="${OXIDE_GUN_RX_QUEUE:-0}"
xdp_mode="${OXIDE_GUN_XDP_MODE:-drv}"
xdp_zerocopy="${OXIDE_GUN_XDP_ZEROCOPY:-auto}"

command -v ip >/dev/null
command -v python3 >/dev/null

mkdir -p "$out_dir"

capture() {
    local name="$1"
    shift
    if "$@" >"$out_dir/$name.out" 2>"$out_dir/$name.err"; then
        printf 'ok\n' >"$out_dir/$name.status"
    else
        printf 'failed\n' >"$out_dir/$name.status"
    fi
}

ip -j -d link show dev "$interface" >"$out_dir/ip-link-detail.json"
ip -j -s link show dev "$interface" >"$out_dir/ip-link-stats.json"
ip route show dev "$interface" >"$out_dir/ip-route.out" 2>"$out_dir/ip-route.err" || true
ip neigh show dev "$interface" >"$out_dir/ip-neigh.out" 2>"$out_dir/ip-neigh.err" || true

if command -v ethtool >/dev/null; then
    capture ethtool-driver ethtool -i "$interface"
    capture ethtool-channels ethtool -l "$interface"
    capture ethtool-ring ethtool -g "$interface"
    capture ethtool-features ethtool -k "$interface"
    capture ethtool-stats ethtool -S "$interface"
fi

{
    printf 'utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'repo=%s\n' "$repo_root"
    printf 'interface=%s\n' "$interface"
    printf 'target=%s\n' "${OXIDE_GUN_TARGET:-}"
    printf 'target_mac=%s\n' "${OXIDE_GUN_TARGET_MAC:-}"
    printf 'source_mac=%s\n' "${OXIDE_GUN_SOURCE_MAC:-}"
    printf 'tx_queue=%s\n' "$tx_queue"
    printf 'rx_queue=%s\n' "$rx_queue"
    printf 'xdp_mode=%s\n' "$xdp_mode"
    printf 'xdp_zerocopy=%s\n' "$xdp_zerocopy"
    printf 'xdp_drop_object=%s\n' "${OXIDE_GUN_XDP_DROP_OBJECT:-}"
    printf 'allow_default_route=%s\n' "${OXIDE_GUN_ALLOW_DEFAULT_ROUTE:-0}"
    printf 'require_physical=%s\n' "${OXIDE_GUN_REQUIRE_PHYSICAL:-0}"
    printf 'uid=%s\n' "$(id -u)"
    printf 'nproc=%s\n' "$(nproc 2>/dev/null || printf unknown)"
    uname -a
} >"$out_dir/metadata.txt"

{
    printf 'unprivileged_bpf_disabled='
    cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || printf 'unknown\n'
    printf 'memlock_soft_hard='
    ulimit -l 2>/dev/null || printf 'unknown\n'
} >"$out_dir/kernel-limits.txt"

python3 - "$out_dir" "$interface" "$tx_queue" "$rx_queue" <<'PY'
import json
import os
import re
import sys

out_dir, interface, tx_queue_raw, rx_queue_raw = sys.argv[1:5]
tx_queue = int(tx_queue_raw)
rx_queue = int(rx_queue_raw)
errors = []
warnings = []

def read(path):
    try:
        with open(os.path.join(out_dir, path), encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""

with open(os.path.join(out_dir, "ip-link-detail.json"), encoding="utf-8") as handle:
    links = json.load(handle)
if not links:
    errors.append(f"interface {interface!r} was not found")
    link = {}
else:
    link = links[0]

flags = set(link.get("flags", []))
link_type = link.get("link_type")
link_kind = link.get("linkinfo", {}).get("info_kind")
if "UP" not in flags:
    errors.append(f"interface {interface} is not UP")
if "LOWER_UP" not in flags:
    warnings.append(f"interface {interface} does not report LOWER_UP")
if link_type == "loopback":
    errors.append("loopback is not valid dedicated-interface XDP lab evidence")

routes = read("ip-route.out")
if os.environ.get("OXIDE_GUN_ALLOW_DEFAULT_ROUTE", "0") != "1":
    default_routes = [
        line for line in routes.splitlines()
        if line.split(maxsplit=1)[0:1] == ["default"]
    ]
    if default_routes:
        errors.append(
            "interface has a default route; set OXIDE_GUN_ALLOW_DEFAULT_ROUTE=1 "
            "only for an intentionally isolated lab host"
        )

source_mac = os.environ.get("OXIDE_GUN_SOURCE_MAC", "").lower()
iface_mac = str(link.get("address", "")).lower()
if source_mac and iface_mac and source_mac != iface_mac:
    warnings.append(
        f"source MAC {source_mac} does not match interface MAC {iface_mac}; "
        "this is valid only when intentionally spoofing"
    )
if not os.environ.get("OXIDE_GUN_TARGET_MAC"):
    warnings.append("OXIDE_GUN_TARGET_MAC is unset; lab runner requires an explicit target MAC")

drop_object = os.environ.get("OXIDE_GUN_XDP_DROP_OBJECT", "")
if drop_object and not os.path.isfile(drop_object):
    errors.append(f"XDP drop object does not exist: {drop_object}")

channels = read("ethtool-channels.out")
current_combined = None
current_rx = None
current_tx = None
if channels:
    current = channels.split("Current hardware settings:", 1)[-1]
    for key, attr in (("Combined", "combined"), ("RX", "rx"), ("TX", "tx")):
        match = re.search(rf"^\s*{key}:\s+(\d+)", current, re.MULTILINE)
        if match:
            value = int(match.group(1))
            if attr == "combined":
                current_combined = value
            elif attr == "rx":
                current_rx = value
            else:
                current_tx = value
queue_limit = current_combined or max(current_rx or 0, current_tx or 0) or None
if queue_limit is not None:
    if tx_queue >= queue_limit:
        errors.append(f"tx queue {tx_queue} is outside reported queue count {queue_limit}")
    if rx_queue >= queue_limit:
        errors.append(f"rx queue {rx_queue} is outside reported queue count {queue_limit}")
else:
    warnings.append("could not determine queue count from ethtool -l")

features = read("ethtool-features.out")
if "tx-checksumming: off" in features:
    warnings.append("TX checksum offload is disabled; OxideGun computes UDP checksums in software")

driver = read("ethtool-driver.out")
driver_name = None
for line in driver.splitlines():
    if line.startswith("driver:"):
        driver_name = line.split(":", 1)[1].strip()
        break

virtual_kinds = {
    "bareudp",
    "bond",
    "bridge",
    "dummy",
    "geneve",
    "gre",
    "gretap",
    "ifb",
    "ip6gre",
    "ip6tnl",
    "ipip",
    "ipoib",
    "macsec",
    "macvlan",
    "macvtap",
    "nlmon",
    "sit",
    "team",
    "tun",
    "vcan",
    "veth",
    "vlan",
    "vrf",
    "vxcan",
    "vxlan",
    "wireguard",
}
is_virtual_lab = (
    link_type == "loopback"
    or link_kind in virtual_kinds
    or driver_name in {"veth", "tun", "dummy", "bridge"}
)
if os.environ.get("OXIDE_GUN_REQUIRE_PHYSICAL", "0") == "1" and is_virtual_lab:
    errors.append(
        "physical-interface evidence was required, but this interface appears "
        f"virtual: link_type={link_type!r} link_kind={link_kind!r} driver={driver_name!r}"
    )
evidence_scope = "virtual_lab" if is_virtual_lab else "physical_interface"

status = "failed" if errors else ("warning" if warnings else "ok")
summary = {
    "status": status,
    "interface": interface,
    "ifindex": link.get("ifindex"),
    "link_type": link_type,
    "link_kind": link_kind,
    "evidence_scope": evidence_scope,
    "saturation_claim_allowed": evidence_scope == "physical_interface",
    "operstate": link.get("operstate"),
    "flags": link.get("flags", []),
    "mac": link.get("address"),
    "mtu": link.get("mtu"),
    "driver": driver_name,
    "queue_limit": queue_limit,
    "tx_queue": tx_queue,
    "rx_queue": rx_queue,
    "xdp_mode": os.environ.get("OXIDE_GUN_XDP_MODE", "drv"),
    "xdp_zerocopy": os.environ.get("OXIDE_GUN_XDP_ZEROCOPY", "auto"),
    "errors": errors,
    "warnings": warnings,
}
with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")

print(json.dumps(summary, sort_keys=True))
if errors:
    raise SystemExit(1)
PY

printf 'oxide-gun XDP lab preflight written: %s\n' "$out_dir"
