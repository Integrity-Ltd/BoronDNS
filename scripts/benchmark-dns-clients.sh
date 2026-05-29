#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_dir="${OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR:-$repo_root/target/evidence/dns-client-benchmark-$timestamp}"
workdir="$repo_root/target/dns-client-benchmark/$timestamp"

records="${OXIDEDNS_BENCH_RECORDS:-10000}"
stress_candidates="${OXIDEDNS_BENCH_STRESS_CANDIDATES:-0}"
duration="${OXIDEDNS_BENCH_DURATION_SECONDS:-10}"
transport="${OXIDEDNS_BENCH_TRANSPORT:-udp}"
server_threads="${OXIDEDNS_BENCH_SERVER_THREADS:-4}"
client_threads="${OXIDEDNS_BENCH_CLIENT_THREADS:-8}"
client_window="${OXIDEDNS_BENCH_CLIENT_WINDOW:-64}"
udp_batch_size="${OXIDEDNS_BENCH_UDP_BATCH_SIZE:-1}"
response_timeout_ms="${OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:-250}"
pipeline_timing_enabled="${OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED:-false}"
zone_image_serve_enabled="${OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED:-false}"
preflight_only="${OXIDEDNS_BENCH_PREFLIGHT_ONLY:-false}"
trace_enabled="${OXIDEDNS_BENCH_TRACE_ENABLED:-false}"
trace_file_override="${OXIDEDNS_BENCH_TRACE_FILE:-}"
listen_address="${OXIDEDNS_BENCH_LISTEN_ADDRESS:-127.0.0.1}"
client_server="${OXIDEDNS_BENCH_CLIENT_SERVER:-$listen_address}"
client_mode="${OXIDEDNS_BENCH_CLIENT_MODE:-local}"
client_bind_default="127.0.0.1:0"
if [[ "$client_mode" == ssh ]]; then
    client_bind_default="0.0.0.0:0"
fi
client_bind="${OXIDEDNS_BENCH_CLIENT_BIND:-$client_bind_default}"
network_device="${OXIDEDNS_BENCH_NETWORK_DEVICE:-auto}"
require_non_loopback_device="${OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE:-false}"
remote_client_ssh="${OXIDEDNS_BENCH_REMOTE_CLIENT_SSH:-}"
remote_client_workdir="${OXIDEDNS_BENCH_REMOTE_CLIENT_WORKDIR:-/tmp/oxidedns-bench-$timestamp}"
remote_client_ssh_connect_timeout="${OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS:-5}"
remote_client_allow_arch_mismatch="${OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH:-false}"
remote_client_local_arch="none"
remote_client_remote_arch="none"
remote_client_local_host_id="none"
remote_client_remote_host_id="none"
remote_client_same_host="none"
remote_client_bin_sha256="none"
git_revision="$(git -C "$repo_root" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"
if git -C "$repo_root" status --porcelain=v1 --untracked-files=normal >/dev/null 2>&1; then
    if [[ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)" ]]; then
        git_dirty="true"
    else
        git_dirty="false"
    fi
else
    git_dirty="unknown"
fi
kernel_version="$(uname -srmo 2>/dev/null || uname -a)"
rustc_version="$(rustc --version 2>/dev/null || printf 'unknown')"
cargo_version="$(cargo --version 2>/dev/null || printf 'unknown')"
build_profile="release"
server_bin_sha256="unknown"
client_bin_sha256="unknown"

digest_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{ print $1 }'
    else
        printf 'unknown'
    fi
}

hash_identity() {
    local identity="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$identity" | sha256sum | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$identity" | shasum -a 256 | awk '{ print $1 }'
    else
        printf 'unknown'
    fi
}

local_host_identity() {
    if [[ -r /proc/sys/kernel/random/boot_id ]]; then
        cat /proc/sys/kernel/random/boot_id
    else
        hostname
    fi
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

require_nonnegative_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s must be a non-negative integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

for pair in \
    "OXIDEDNS_BENCH_RECORDS:$records" \
    "OXIDEDNS_BENCH_DURATION_SECONDS:$duration" \
    "OXIDEDNS_BENCH_SERVER_THREADS:$server_threads" \
    "OXIDEDNS_BENCH_CLIENT_THREADS:$client_threads" \
    "OXIDEDNS_BENCH_CLIENT_WINDOW:$client_window" \
    "OXIDEDNS_BENCH_UDP_BATCH_SIZE:$udp_batch_size" \
    "OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:$response_timeout_ms"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
require_nonnegative_integer "OXIDEDNS_BENCH_STRESS_CANDIDATES" "$stress_candidates"
case "$transport" in
udp | tcp) ;;
*)
    printf 'OXIDEDNS_BENCH_TRANSPORT must be udp or tcp, got %q\n' "$transport" >&2
    exit 64
    ;;
esac
case "$pipeline_timing_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED must be true or false, got %q\n' "$pipeline_timing_enabled" >&2
    exit 64
    ;;
esac
case "$zone_image_serve_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED must be true or false, got %q\n' "$zone_image_serve_enabled" >&2
    exit 64
    ;;
esac
case "$preflight_only" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_PREFLIGHT_ONLY must be true or false, got %q\n' "$preflight_only" >&2
    exit 64
    ;;
esac
case "$trace_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_TRACE_ENABLED must be true or false, got %q\n' "$trace_enabled" >&2
    exit 64
    ;;
esac
case "$client_mode" in
local | ssh) ;;
*)
    printf 'OXIDEDNS_BENCH_CLIENT_MODE must be local or ssh, got %q\n' "$client_mode" >&2
    exit 64
    ;;
esac
case "$require_non_loopback_device" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE must be true or false, got %q\n' "$require_non_loopback_device" >&2
    exit 64
    ;;
esac
if [[ -n "$trace_file_override" && ! -f "$trace_file_override" ]]; then
    printf 'OXIDEDNS_BENCH_TRACE_FILE does not exist: %s\n' "$trace_file_override" >&2
    exit 64
fi
for pair in \
    "OXIDEDNS_BENCH_LISTEN_ADDRESS:$listen_address" \
    "OXIDEDNS_BENCH_CLIENT_SERVER:$client_server" \
    "OXIDEDNS_BENCH_CLIENT_BIND:$client_bind"; do
    if [[ "${pair#*:}" =~ [[:space:]] || -z "${pair#*:}" ]]; then
        printf '%s must be non-empty and contain no whitespace, got %q\n' "${pair%%:*}" "${pair#*:}" >&2
        exit 64
    fi
done
if [[ "$client_mode" == ssh ]]; then
    case "$remote_client_allow_arch_mismatch" in
    true | false) ;;
    *)
        printf 'OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH must be true or false, got %q\n' "$remote_client_allow_arch_mismatch" >&2
        exit 64
        ;;
    esac
    if [[ -z "$remote_client_ssh" || "$remote_client_ssh" =~ [[:space:]] ]]; then
        printf 'OXIDEDNS_BENCH_REMOTE_CLIENT_SSH must be non-empty and contain no whitespace when OXIDEDNS_BENCH_CLIENT_MODE=ssh\n' >&2
        exit 64
    fi
    if [[ -z "$remote_client_workdir" || "$remote_client_workdir" =~ [[:space:]] ]]; then
        printf 'OXIDEDNS_BENCH_REMOTE_CLIENT_WORKDIR must be non-empty and contain no whitespace when OXIDEDNS_BENCH_CLIENT_MODE=ssh\n' >&2
        exit 64
    fi
    for tool in ssh scp; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'OXIDEDNS_BENCH_CLIENT_MODE=ssh requires %s on PATH\n' "$tool" >&2
            exit 69
        fi
    done
    if ! [[ "$remote_client_ssh_connect_timeout" =~ ^[1-9][0-9]*$ ]]; then
        printf 'OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS must be a positive integer, got %q\n' "$remote_client_ssh_connect_timeout" >&2
        exit 64
    fi
    if ! ssh -o BatchMode=yes -o "ConnectTimeout=$remote_client_ssh_connect_timeout" "$remote_client_ssh" true; then
        printf 'remote benchmark client SSH preflight failed for %s\n' "$remote_client_ssh" >&2
        exit 69
    fi
    remote_client_local_arch="$(uname -m | tr -d '\r')"
    if ! remote_client_remote_arch="$(ssh -o BatchMode=yes -o "ConnectTimeout=$remote_client_ssh_connect_timeout" "$remote_client_ssh" 'uname -m' | tr -d '\r')"; then
        printf 'remote benchmark client architecture preflight failed for %s\n' "$remote_client_ssh" >&2
        exit 69
    fi
    if [[ -z "$remote_client_remote_arch" ]]; then
        printf 'remote benchmark client architecture preflight returned an empty architecture for %s\n' "$remote_client_ssh" >&2
        exit 69
    fi
    if [[ "$remote_client_local_arch" != "$remote_client_remote_arch" && "$remote_client_allow_arch_mismatch" != true ]]; then
        printf 'remote benchmark client architecture mismatch: local=%q remote=%q. The benchmark copies the local dns-load-client binary to the remote host; set OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH=true only if you will replace or run a compatible remote binary manually.\n' "$remote_client_local_arch" "$remote_client_remote_arch" >&2
        exit 69
    fi
    remote_client_local_host_raw="$(local_host_identity | tr -d '\r')"
    if ! remote_client_remote_host_raw="$(ssh -o BatchMode=yes -o "ConnectTimeout=$remote_client_ssh_connect_timeout" "$remote_client_ssh" 'if [ -r /proc/sys/kernel/random/boot_id ]; then cat /proc/sys/kernel/random/boot_id; else hostname; fi' | tr -d '\r')"; then
        printf 'remote benchmark client host-identity preflight failed for %s\n' "$remote_client_ssh" >&2
        exit 69
    fi
    if [[ -z "$remote_client_local_host_raw" || -z "$remote_client_remote_host_raw" ]]; then
        printf 'remote benchmark client host-identity preflight returned an empty identity for %s\n' "$remote_client_ssh" >&2
        exit 69
    fi
    remote_client_local_host_id="$(hash_identity "$remote_client_local_host_raw")"
    remote_client_remote_host_id="$(hash_identity "$remote_client_remote_host_raw")"
    if [[ "$remote_client_local_host_id" == "$remote_client_remote_host_id" ]]; then
        remote_client_same_host="true"
    else
        remote_client_same_host="false"
    fi
    if [[ "$require_non_loopback_device" == true && "$remote_client_same_host" == true ]]; then
        printf 'physical NIC evidence requested, but OXIDEDNS_BENCH_REMOTE_CLIENT_SSH appears to resolve to the local server host\n' >&2
        exit 64
    fi
fi

if [[ "$network_device" == auto ]]; then
    if [[ "$client_server" == "0.0.0.0" || "$client_server" == "::" ]]; then
        printf 'OXIDEDNS_BENCH_CLIENT_SERVER must be a concrete address when OXIDEDNS_BENCH_LISTEN_ADDRESS is wildcard\n' >&2
        exit 64
    fi
    if [[ "$client_mode" == ssh && "$listen_address" != "0.0.0.0" && "$listen_address" != "::" ]] && command -v ip >/dev/null 2>&1; then
        network_device="$(ip -o addr show | awk -v addr="$listen_address" '$4 ~ "^" addr "/" { print $2; exit }')"
        network_device="${network_device:-unknown}"
    elif [[ "$client_server" == "127.0.0.1" || "$client_server" == "localhost" ]]; then
        network_device="lo"
    elif command -v ip >/dev/null 2>&1; then
        network_device="$(ip route get "$client_server" 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
        network_device="${network_device:-unknown}"
    else
        network_device="unknown"
    fi
fi
if [[ "$require_non_loopback_device" == true ]]; then
    if [[ "$network_device" == lo || "$network_device" == unknown || -z "$network_device" ]]; then
        printf 'physical NIC evidence requested, but resolved network_device=%q\n' "$network_device" >&2
        exit 64
    fi
    if [[ ! -e "/sys/class/net/$network_device" ]]; then
        if ! command -v ip >/dev/null 2>&1 || ! ip link show dev "$network_device" >/dev/null 2>&1; then
            printf 'physical NIC evidence requested, but network_device=%q does not exist on this host\n' "$network_device" >&2
            exit 64
        fi
    fi
    if [[ "$client_server" == "127.0.0.1" || "$client_server" == "localhost" || "$client_server" == "::1" ]]; then
        printf 'physical NIC evidence requested, but OXIDEDNS_BENCH_CLIENT_SERVER=%q is loopback\n' "$client_server" >&2
        exit 64
    fi
fi

if [[ "$preflight_only" == true ]]; then
    printf 'dns_client_benchmark_preflight=passed\n'
    printf 'client_mode=%s\n' "$client_mode"
    printf 'listen_address=%s\n' "$listen_address"
    printf 'client_server=%s\n' "$client_server"
    printf 'client_bind=%s\n' "$client_bind"
    printf 'network_device=%s\n' "$network_device"
    printf 'require_non_loopback_device=%s\n' "$require_non_loopback_device"
    printf 'remote_client_ssh=%s\n' "${remote_client_ssh:-none}"
    printf 'remote_client_local_arch=%s\n' "$remote_client_local_arch"
    printf 'remote_client_remote_arch=%s\n' "$remote_client_remote_arch"
    printf 'remote_client_local_host_id=%s\n' "$remote_client_local_host_id"
    printf 'remote_client_remote_host_id=%s\n' "$remote_client_remote_host_id"
    printf 'remote_client_same_host=%s\n' "$remote_client_same_host"
    printf 'remote_client_allow_arch_mismatch=%s\n' "$([[ "$client_mode" == ssh ]] && echo "$remote_client_allow_arch_mismatch" || echo none)"
    printf 'git_revision=%s\n' "$git_revision"
    printf 'git_dirty=%s\n' "$git_dirty"
    printf 'kernel_version=%s\n' "$kernel_version"
    printf 'rustc_version=%s\n' "$rustc_version"
    printf 'cargo_version=%s\n' "$cargo_version"
    printf 'build_profile=%s\n' "$build_profile"
    exit 0
fi

mkdir -p "$artifact_dir" "$workdir" "$repo_root/target/benchmark-tools"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if [[ -n "${primary_pid:-}" ]] && kill -0 "$primary_pid" 2>/dev/null; then
        kill "$primary_pid" 2>/dev/null || true
        wait "$primary_pid" 2>/dev/null || true
    fi
    if ((status != 0)); then
        [[ -f "$artifact_dir/fake-primary.log" ]] && {
            echo "---- fake-primary.log ----" >&2
            tail -120 "$artifact_dir/fake-primary.log" >&2
        }
        [[ -f "$artifact_dir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -120 "$artifact_dir/oxidedns.log" >&2
        }
        [[ -f "$artifact_dir/client.log" ]] && {
            echo "---- client.log ----" >&2
            tail -120 "$artifact_dir/client.log" >&2
        }
    fi
}
trap cleanup EXIT

read -r primary_port dns_port health_port < <(
    python3 - <<'PY'
import socket

sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

fake_primary="$workdir/fake-primary.py"
config="$workdir/oxidedns.toml"
client_bin="$repo_root/target/benchmark-tools/dns-load-client"
primary_log="$artifact_dir/fake-primary.log"
server_log="$artifact_dir/oxidedns.log"
client_log="$artifact_dir/client.log"
network_dir="$artifact_dir/network"
trace_file=""
trace_source="generated-name-mode"

: >"$primary_log"
: >"$server_log"
: >"$client_log"

capture_network_snapshot() {
    local label="$1"
    mkdir -p "$network_dir"
    {
        printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'listen_address=%s\n' "$listen_address"
        printf 'client_server=%s\n' "$client_server"
        printf 'client_bind=%s\n' "$client_bind"
        printf 'network_device=%s\n' "$network_device"
        printf '\n## uname -a\n'
        uname -a
        if command -v ip >/dev/null 2>&1; then
            printf '\n## ip -br addr show\n'
            ip -br addr show
            printf '\n## ip route show table main\n'
            ip route show table main
            printf '\n## ip route get %s\n' "$client_server"
            ip route get "$client_server" || true
            if [[ "$network_device" != unknown && -n "$network_device" ]]; then
                printf '\n## ip -s link show dev %s\n' "$network_device"
                ip -s link show dev "$network_device" || true
            fi
        else
            printf '\n## ip command unavailable\n'
        fi
    } >"$network_dir/network-$label.txt" 2>&1

    [[ -r /proc/net/dev ]] && cp /proc/net/dev "$network_dir/proc-net-dev-$label.txt"
    [[ -r /proc/softirqs ]] && cp /proc/softirqs "$network_dir/proc-softirqs-$label.txt"
    [[ -r /proc/interrupts ]] && cp /proc/interrupts "$network_dir/proc-interrupts-$label.txt"

    if [[ "$network_device" != unknown && -n "$network_device" ]]; then
        {
            if command -v ethtool >/dev/null 2>&1; then
                printf '## ethtool -i %s\n' "$network_device"
                ethtool -i "$network_device" || true
                printf '\n## ethtool -k %s\n' "$network_device"
                ethtool -k "$network_device" || true
                printf '\n## ethtool -l %s\n' "$network_device"
                ethtool -l "$network_device" || true
                printf '\n## ethtool -S %s\n' "$network_device"
                ethtool -S "$network_device" || true
            else
                printf 'ethtool command unavailable\n'
            fi
        } >"$network_dir/ethtool-$network_device-$label.txt" 2>&1
    fi
}

write_network_counter_deltas() {
    mkdir -p "$network_dir"
    python3 - "$network_device" \
        "$network_dir/proc-net-dev-before.txt" \
        "$network_dir/proc-net-dev-after.txt" \
        >"$network_dir/proc-net-dev-delta.tsv" <<'PY'
import sys

device, before_path, after_path = sys.argv[1:4]
fields = [
    "rx_bytes", "rx_packets", "rx_errs", "rx_drop", "rx_fifo", "rx_frame",
    "rx_compressed", "rx_multicast", "tx_bytes", "tx_packets", "tx_errs",
    "tx_drop", "tx_fifo", "tx_colls", "tx_carrier", "tx_compressed",
]

def read_dev(path):
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                name = name.strip()
                nums = data.split()
                if len(nums) >= len(fields):
                    values[name] = {field: int(value) for field, value in zip(fields, nums)}
    except FileNotFoundError:
        pass
    return values

before = read_dev(before_path)
after = read_dev(after_path)
print("metric\tbefore\tafter\tdelta\tunit")
if device not in before or device not in after:
    print(f"status\tmissing-device-{device}\tmissing-device-{device}\t0\tstatus")
    raise SystemExit(0)
for field in fields:
    old = before[device][field]
    new = after[device][field]
    print(f"{field}\t{old}\t{new}\t{new - old}\tcount")
PY

    if [[ "$network_device" != unknown && -n "$network_device" ]]; then
        python3 - "$network_dir/ethtool-$network_device-before.txt" \
            "$network_dir/ethtool-$network_device-after.txt" \
            >"$network_dir/ethtool-delta.tsv" <<'PY'
import re
import sys

before_path, after_path = sys.argv[1:3]
number = re.compile(r"^\s*([^:#][^:]*):\s*(-?\d+)\s*$")

def sanitize(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("_") or "unknown"

def read_stats(path):
    section = "unknown"
    stats = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("## "):
                    section = sanitize(line[3:])
                    continue
                match = number.match(line)
                if match:
                    key = f"{section}.{sanitize(match.group(1))}"
                    stats[key] = int(match.group(2))
    except FileNotFoundError:
        pass
    return stats

before = read_stats(before_path)
after = read_stats(after_path)
print("metric\tbefore\tafter\tdelta\tunit")
for key in sorted(set(before) | set(after)):
    if key in before and key in after:
        print(f"{key}\t{before[key]}\t{after[key]}\t{after[key] - before[key]}\tcount")
PY
    fi
}

if [[ -n "$trace_file_override" ]]; then
    trace_file="$artifact_dir/query-trace.tsv"
    cp "$trace_file_override" "$trace_file"
    trace_source="$trace_file_override"
elif [[ "$trace_enabled" == true ]]; then
    trace_file="$artifact_dir/query-trace.tsv"
    python3 - "$records" "$stress_candidates" >"$trace_file" <<'PY'
import sys

records = int(sys.argv[1])
stress_candidates = int(sys.argv[2])
last = max(0, records - 1)
edns_index = min(1, last)
print("# qname qtype qclass edns label")
for _ in range(128):
    print("host000000.perf.test. A IN none hot_positive")
for index in range(min(records, 128)):
    print(f"host{index:06d}.perf.test. A IN none spread_positive")
print(f"host{last:06d}.perf.test. A IN none edge_positive")
print(f"host{edns_index:06d}.perf.test. A IN edns edns_positive")
print("perf.test. NS IN none apex_ns_positive")
print("perf.test. SOA IN none apex_soa_positive")
print("ns1.perf.test. A IN none glue_positive")
print("opaque.perf.test. 65280 IN none opaque_unknown")
print("host000000.perf.test. AAAA IN none rcode=NOERROR answers=0 nodata")
print("missing000000.perf.test. A IN none rcode=NXDOMAIN answers=0 nxdomain")
if stress_candidates > 0:
    case_count = min(stress_candidates, 64)
    for offset in range(case_count):
        candidate = offset * stress_candidates // case_count
        print(
            f"www.del{candidate:06d}.perf.test. A IN none "
            "rcode=NOERROR answers=0 delegation_stress"
        )
        print(
            f"leaf.dname{candidate:06d}.perf.test. A IN none "
            "rcode=NOERROR answers=3 dname_stress"
        )
PY
    if ((stress_candidates > 0)); then
        trace_source="script-generated-mixed-stress-trace"
    else
        trace_source="script-generated-mixed-trace"
    fi
fi

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
RECORDS = int(sys.argv[3])
STRESS_CANDIDATES = int(sys.argv[4])
ZONE = "perf.test."
IN = 1
A = 1
NS = 2
SOA = 6
DNAME = 39
AXFR = 252
UNKNOWN = 65280


def log(message):
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_name(packet, offset):
    labels = []
    consumed = 0
    while True:
        length = packet[offset]
        offset += 1
        consumed += 1
        if length == 0:
            return ".".join(labels) + ".", consumed
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
        consumed += length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass


def rr(owner, rrtype, rdata, ttl=60):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052501):
    return b"".join([
        name_wire("ns1.perf.test."),
        name_wire("hostmaster.perf.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    records = [
        soa,
        rr(ZONE, NS, name_wire("ns1.perf.test.")),
        rr("ns1.perf.test.", A, bytes([127, 0, 0, 1])),
        rr("opaque.perf.test.", UNKNOWN, bytes([0xC0, 0x0C, 0, 255])),
    ]
    for index in range(RECORDS):
        records.append(
            rr(
                f"host{index:06d}.perf.test.",
                A,
                bytes([192, 0, (index // 256) % 256, index % 256]),
            )
        )
    for index in range(STRESS_CANDIDATES):
        records.append(
            rr(
                f"del{index:06d}.perf.test.",
                NS,
                name_wire(f"ns.del{index:06d}.perf.test."),
            )
        )
        records.append(
            rr(
                f"ns.del{index:06d}.perf.test.",
                A,
                bytes([192, 0, (index // 256) % 256, index % 256]),
            )
        )
        records.append(
            rr(
                f"dname{index:06d}.perf.test.",
                DNAME,
                name_wire(f"target{index:06d}.perf.test."),
            )
        )
        records.append(
            rr(
                f"leaf.target{index:06d}.perf.test.",
                A,
                bytes([198, 51, (index // 256) % 256, index % 256]),
            )
        )
    records.append(soa)
    return records


def axfr_response_frames(qid):
    base_question = name_wire(ZONE) + struct.pack("!HH", AXFR, IN)
    base_size = 12 + len(base_question)
    frames = []
    chunk = []
    chunk_size = base_size
    for record in zone_records():
        if chunk and chunk_size + len(record) > 60000:
            frames.append(response_message(qid, base_question, chunk))
            chunk = []
            chunk_size = base_size
        chunk.append(record)
        chunk_size += len(record)
    if chunk:
        frames.append(response_message(qid, base_question, chunk))
    return frames


def response_message(qid, question, answers):
    return struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def handle_tcp(conn):
    with conn:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
        query = read_exact(conn, length)
        qid = struct.unpack("!H", query[:2])[0]
        qname, qtype, qclass = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 0, 0, 0, 0)
            conn.sendall(struct.pack("!H", len(response)) + response)
        else:
            log(f"TCP AXFR served records={len(zone_records())}")
            for response in axfr_response_frames(qid):
                conn.sendall(struct.pack("!H", len(response)) + response)


def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()
    log(f"READY port={PORT} records={RECORDS}")
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY

cat >"$config" <<EOF
[server]
listen_udp = ["$listen_address:$dns_port"]
listen_tcp = ["$listen_address:$dns_port"]
health = "127.0.0.1:$health_port"
log_level = "error"
log_format = "plain"

[query]
any_response = "minimal"
zone_image_serve_enabled = $zone_image_serve_enabled

[cookie]
policy = "disabled"

[rrl]
enabled = false

[metrics]
pipeline_timing_enabled = $pipeline_timing_enabled

[limits]
max_udp_payload = 1232
udp_batch_size = $udp_batch_size
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "perf.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

cat >"$artifact_dir/run.env" <<EOF
date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
records=$records
stress_candidates=$stress_candidates
transport=$transport
server_threads=$server_threads
client_threads=$client_threads
client_window=$client_window
udp_batch_size=$udp_batch_size
duration_seconds=$duration
response_timeout_ms=$response_timeout_ms
pipeline_timing_enabled=$pipeline_timing_enabled
zone_image_serve_enabled=$zone_image_serve_enabled
listen_address=$listen_address
client_server=$client_server
client_bind=$client_bind
network_device=$network_device
require_non_loopback_device=$require_non_loopback_device
network_snapshot_dir=network
trace_enabled=$([[ -n "$trace_file" ]] && echo true || echo false)
trace_source=$trace_source
trace_file=$([[ -n "$trace_file" ]] && echo query-trace.tsv || echo none)
primary_port=$primary_port
dns_port=$dns_port
health_port=$health_port
client_mode=$client_mode
remote_client_ssh=${remote_client_ssh:-none}
remote_client_workdir=$([[ "$client_mode" == ssh ]] && echo "$remote_client_workdir" || echo none)
remote_client_ssh_connect_timeout=$([[ "$client_mode" == ssh ]] && echo "$remote_client_ssh_connect_timeout" || echo none)
remote_client_local_arch=$remote_client_local_arch
remote_client_remote_arch=$remote_client_remote_arch
remote_client_local_host_id=$remote_client_local_host_id
remote_client_remote_host_id=$remote_client_remote_host_id
remote_client_same_host=$remote_client_same_host
remote_client_allow_arch_mismatch=$([[ "$client_mode" == ssh ]] && echo "$remote_client_allow_arch_mismatch" || echo none)
git_revision=$git_revision
git_dirty=$git_dirty
kernel_version=$kernel_version
rustc_version=$rustc_version
cargo_version=$cargo_version
build_profile=$build_profile
EOF

rustc --edition=2024 -O "$repo_root/tools/dns-load-client.rs" -o "$client_bin"
cargo build --locked --release -p oxidedns-cli >/dev/null
client_bin_sha256="$(digest_file "$client_bin")"
server_bin_sha256="$(digest_file "$repo_root/target/release/oxidedns")"
{
    printf 'client_bin_sha256=%s\n' "$client_bin_sha256"
    printf 'server_bin_sha256=%s\n' "$server_bin_sha256"
} >>"$artifact_dir/run.env"

python3 "$fake_primary" "$primary_port" "$primary_log" "$records" "$stress_candidates" &
primary_pid=$!
for _ in {1..100}; do
    if grep -q "READY" "$primary_log" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
if ! grep -q "READY" "$primary_log" 2>/dev/null; then
    echo "benchmark fake primary did not become ready" >&2
    exit 1
fi

server_cmd=("$repo_root/target/release/oxidedns" serve --config "$config")
server_affinity="not-applied"
if command -v taskset >/dev/null 2>&1 && ((server_threads > 0)); then
    last_cpu=$((server_threads - 1))
    server_cmd=(taskset -c "0-$last_cpu" "${server_cmd[@]}")
    server_affinity="0-$last_cpu"
fi
printf 'server_command=' >"$artifact_dir/server-command.txt"
printf ' %q' "${server_cmd[@]}" >>"$artifact_dir/server-command.txt"
printf '\n' >>"$artifact_dir/server-command.txt"
printf 'server_affinity=%s\n' "$server_affinity" >>"$artifact_dir/run.env"

"${server_cmd[@]}" >"$server_log" 2>&1 &
oxidedns_pid=$!
ready=0
for _ in {1..400}; do
    if curl -fsS "http://127.0.0.1:$health_port/readyz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.05
done
if ((ready != 1)); then
    echo "OxideDNS did not become ready for DNS client benchmark" >&2
    exit 1
fi

curl -fsS "http://127.0.0.1:$health_port/readyz" >"$artifact_dir/readyz-before.json"
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-before.prom"
capture_network_snapshot before

client_args=(
    --transport "$transport"
    --server "$client_server"
    --port "$dns_port"
    --bind "$client_bind"
    --threads "$client_threads"
    --duration "$duration"
    --window "$client_window"
    --names "$records"
    --timeout-ms "$response_timeout_ms"
)
if [[ -n "$trace_file" ]]; then
    client_args+=(--trace "$trace_file")
fi

quote_command() {
    local quoted
    printf -v quoted '%q ' "$@"
    printf '%s' "$quoted"
}

if [[ "$client_mode" == local ]]; then
    "$client_bin" "${client_args[@]}" | tee "$client_log"
else
    remote_client_bin="$remote_client_workdir/dns-load-client"
    remote_trace_file=""
    # shellcheck disable=SC2029
    ssh "$remote_client_ssh" "mkdir -p $(printf '%q' "$remote_client_workdir")"
    scp -q "$client_bin" "$remote_client_ssh:$remote_client_bin"
    # shellcheck disable=SC2029
    ssh "$remote_client_ssh" "chmod +x $(printf '%q' "$remote_client_bin")"
    # shellcheck disable=SC2029
    if remote_client_bin_sha256="$(ssh "$remote_client_ssh" "sha256sum $(printf '%q' "$remote_client_bin") 2>/dev/null | awk '{ print \$1 }'")"; then
        remote_client_bin_sha256="${remote_client_bin_sha256:-unknown}"
    else
        remote_client_bin_sha256="unknown"
    fi

    remote_client_args=(
        --transport "$transport"
        --server "$client_server"
        --port "$dns_port"
        --bind "$client_bind"
        --threads "$client_threads"
        --duration "$duration"
        --window "$client_window"
        --names "$records"
        --timeout-ms "$response_timeout_ms"
    )
    if [[ -n "$trace_file" ]]; then
        remote_trace_file="$remote_client_workdir/query-trace.tsv"
        scp -q "$trace_file" "$remote_client_ssh:$remote_trace_file"
        remote_client_args+=(--trace "$remote_trace_file")
    fi
    remote_command="$(quote_command "$remote_client_bin" "${remote_client_args[@]}")"
    {
        printf 'remote_client_ssh=%s\n' "$remote_client_ssh"
        printf 'remote_client_workdir=%s\n' "$remote_client_workdir"
        printf 'remote_client_local_arch=%s\n' "$remote_client_local_arch"
        printf 'remote_client_remote_arch=%s\n' "$remote_client_remote_arch"
        printf 'remote_client_local_host_id=%s\n' "$remote_client_local_host_id"
        printf 'remote_client_remote_host_id=%s\n' "$remote_client_remote_host_id"
        printf 'remote_client_same_host=%s\n' "$remote_client_same_host"
        printf 'remote_client_allow_arch_mismatch=%s\n' "$remote_client_allow_arch_mismatch"
        printf 'local_client_bin_sha256=%s\n' "$client_bin_sha256"
        printf 'remote_client_bin_sha256=%s\n' "$remote_client_bin_sha256"
        printf 'remote_client_command=%s\n' "$remote_command"
        printf 'remote_trace_file=%s\n' "${remote_trace_file:-none}"
    } >"$artifact_dir/remote-client-command.txt"
    # shellcheck disable=SC2029
    ssh "$remote_client_ssh" "$remote_command" | tee "$client_log"
fi
printf 'remote_client_bin_sha256=%s\n' "$remote_client_bin_sha256" >>"$artifact_dir/run.env"

capture_network_snapshot after
write_network_counter_deltas
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-after.prom"
cp "$config" "$artifact_dir/oxidedns.toml"

summary="$(tail -1 "$client_log")"
summary_value() {
    local key="$1"
    tr ' ' '\n' <<<"$summary" | awk -F= -v key="$key" '$1 == key { print $2; exit }'
}

responses_per_second="$(summary_value responses_per_second)"
latency_us_p50="$(summary_value latency_us_p50)"
latency_us_p99="$(summary_value latency_us_p99)"
latency_us_p999="$(summary_value latency_us_p999)"
dropped="$(summary_value dropped)"
errors="$(summary_value errors)"
query_mode="$(summary_value query_mode)"
trace_queries="$(summary_value trace_queries)"
client_bind_summary="$(summary_value bind)"
records_served="$(awk -F= '/TCP AXFR served records=/ { print $2; exit }' "$primary_log")"
network_rx_packets_delta="$(awk -F'\t' '$1 == "rx_packets" { print $4; exit }' "$network_dir/proc-net-dev-delta.tsv")"
network_tx_packets_delta="$(awk -F'\t' '$1 == "tx_packets" { print $4; exit }' "$network_dir/proc-net-dev-delta.tsv")"
network_rx_packets_delta="${network_rx_packets_delta:-unknown}"
network_tx_packets_delta="${network_tx_packets_delta:-unknown}"
prom_metric_value() {
    local metric="$1"
    awk -v metric="$metric" '$1 == metric { print $2; exit }' "$artifact_dir/metrics-after.prom"
}
zone_image_serve_hits="$(prom_metric_value oxidedns_zone_image_serve_hits_total)"
zone_image_serve_direct_hits="$(prom_metric_value oxidedns_zone_image_serve_direct_hits_total)"
zone_image_serve_semantic_hits="$(prom_metric_value oxidedns_zone_image_serve_semantic_hits_total)"
zone_image_serve_fallbacks="$(prom_metric_value oxidedns_zone_image_serve_fallbacks_total)"
udp_receive_batches="$(prom_metric_value oxidedns_udp_receive_batches_total)"
udp_received_datagrams="$(prom_metric_value oxidedns_udp_received_datagrams_total)"
udp_send_batches="$(prom_metric_value oxidedns_udp_send_batches_total)"
udp_sent_datagrams="$(prom_metric_value oxidedns_udp_sent_datagrams_total)"
zone_image_serve_hits="${zone_image_serve_hits:-unknown}"
zone_image_serve_direct_hits="${zone_image_serve_direct_hits:-unknown}"
zone_image_serve_semantic_hits="${zone_image_serve_semantic_hits:-unknown}"
zone_image_serve_fallbacks="${zone_image_serve_fallbacks:-unknown}"
udp_receive_batches="${udp_receive_batches:-unknown}"
udp_received_datagrams="${udp_received_datagrams:-unknown}"
udp_send_batches="${udp_send_batches:-unknown}"
udp_sent_datagrams="${udp_sent_datagrams:-unknown}"

cat >"$artifact_dir/benchmark-results.tsv" <<EOF
metric	value	unit
git_revision	$git_revision	revision
git_dirty	$git_dirty	boolean
kernel_version	$kernel_version	text
rustc_version	$rustc_version	text
cargo_version	$cargo_version	text
build_profile	$build_profile	profile
server_bin_sha256	$server_bin_sha256	sha256
client_bin_sha256	$client_bin_sha256	sha256
remote_client_bin_sha256	$remote_client_bin_sha256	sha256
transport	$transport	protocol
records_configured	$records	records
stress_candidates_configured	$stress_candidates	candidates
axfr_records_served	${records_served:-unknown}	records
server_threads	$server_threads	cpus
client_threads	$client_threads	threads
client_window	$client_window	queries_per_thread
udp_batch_size	$udp_batch_size	datagrams
udp_receive_batches	$udp_receive_batches	batches
udp_received_datagrams	$udp_received_datagrams	datagrams
udp_send_batches	$udp_send_batches	batches
udp_sent_datagrams	$udp_sent_datagrams	datagrams
listen_address	$listen_address	address
client_server	$client_server	address
client_bind	$client_bind_summary	address
network_device	$network_device	device
require_non_loopback_device	$require_non_loopback_device	boolean
network_snapshot_dir	network	directory
client_mode	$client_mode	mode
remote_client_ssh	${remote_client_ssh:-none}	ssh_target
remote_client_local_arch	$remote_client_local_arch	architecture
remote_client_remote_arch	$remote_client_remote_arch	architecture
remote_client_local_host_id	$remote_client_local_host_id	sha256
remote_client_remote_host_id	$remote_client_remote_host_id	sha256
remote_client_same_host	$remote_client_same_host	boolean
remote_client_allow_arch_mismatch	$([[ "$client_mode" == ssh ]] && echo "$remote_client_allow_arch_mismatch" || echo none)	boolean
network_rx_packets_delta	$network_rx_packets_delta	packets
network_tx_packets_delta	$network_tx_packets_delta	packets
duration_seconds	$duration	seconds
responses_per_second	$responses_per_second	qps
latency_us_p50	$latency_us_p50	microseconds
latency_us_p99	$latency_us_p99	microseconds
latency_us_p999	$latency_us_p999	microseconds
dropped	$dropped	responses
errors	$errors	responses
query_mode	$query_mode	mode
trace_queries	$trace_queries	queries
pipeline_timing_enabled	$pipeline_timing_enabled	boolean
zone_image_serve_enabled	$zone_image_serve_enabled	boolean
zone_image_serve_hits	$zone_image_serve_hits	queries
zone_image_serve_direct_hits	$zone_image_serve_direct_hits	queries
zone_image_serve_semantic_hits	$zone_image_serve_semantic_hits	queries
zone_image_serve_fallbacks	$zone_image_serve_fallbacks	queries
EOF

cat >"$artifact_dir/README.md" <<EOF
# OxideDNS DNS Client Benchmark

This artifact was generated by \`scripts/benchmark-dns-clients.sh\`.

The run starts a synthetic TCP AXFR primary, loads \`$records\` A records into
OxideDNS, pins OxideDNS to CPU affinity \`$server_affinity\` when \`taskset\` is
available, then drives \`$transport\` direct-hit A queries against
\`$client_server:$dns_port\` with UDP client bind setting
\`$client_bind_summary\` and the checked-in \`tools/dns-load-client.rs\` client
in \`client_mode=$client_mode\`.
TCP source address selection is left to the OS. Network device was recorded as
\`$network_device\`; route, link, /proc, optional ethtool snapshots, and quick
counter deltas are retained under \`network/\`. Query pipeline timing metrics
were configured as \`pipeline_timing_enabled=$pipeline_timing_enabled\`.
\`zone_image_serve_enabled=$zone_image_serve_enabled\`.
Query mode was \`$query_mode\`; when this is \`trace\`, the retained
\`query-trace.tsv\` file is the exact replay input.
The configured UDP batch size was \`$udp_batch_size\`; packet I/O counters
recorded \`$udp_receive_batches\` receive batches, \`$udp_received_datagrams\`
received datagrams, \`$udp_send_batches\` send batches, and
\`$udp_sent_datagrams\` sent datagrams.

This is a local engineering benchmark, not the full SRS Reference
Hardware/Profile acceptance campaign.
EOF

printf 'dns_client_benchmark_dir=%s\n' "$artifact_dir"
printf 'capability_summary transport=%s query_mode=%s trace_queries=%s zone_image_serve_enabled=%s udp_batch_size=%s listen_address=%s client_server=%s client_bind=%s network_device=%s require_non_loopback_device=%s network_rx_packets_delta=%s network_tx_packets_delta=%s server_threads=%s client_threads=%s records=%s responses_per_second=%s latency_us_p50=%s latency_us_p99=%s latency_us_p999=%s dropped=%s errors=%s\n' \
    "$transport" "$query_mode" "$trace_queries" "$zone_image_serve_enabled" "$udp_batch_size" "$listen_address" "$client_server" "$client_bind_summary" "$network_device" "$require_non_loopback_device" "$network_rx_packets_delta" "$network_tx_packets_delta" "$server_threads" "$client_threads" "$records" "$responses_per_second" "$latency_us_p50" "$latency_us_p99" "$latency_us_p999" "$dropped" "$errors"
