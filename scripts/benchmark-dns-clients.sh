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
udp_client_sockets_per_thread="${OXIDEDNS_BENCH_UDP_CLIENT_SOCKETS_PER_THREAD:-1}"
udp_batch_size="${OXIDEDNS_BENCH_UDP_BATCH_SIZE:-1}"
udp_reuseport_workers="${OXIDEDNS_BENCH_UDP_REUSEPORT_WORKERS:-1}"
udp_worker_cpu_affinity="${OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY:-}"
udp_runtime="${OXIDEDNS_BENCH_UDP_RUNTIME:-tokio}"
response_timeout_ms="${OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:-250}"
pipeline_timing_enabled="${OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED:-false}"
zone_shape_metrics_enabled="${OXIDEDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED:-false}"
hot_path_detail="${OXIDEDNS_BENCH_HOT_PATH_DETAIL:-full}"
requested_zone_image_serve_enabled="${OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED:-true}"
zone_image_serve_enabled="true"
packet_capture_enabled="${OXIDEDNS_BENCH_PACKET_CAPTURE_ENABLED:-false}"
packet_capture_count="${OXIDEDNS_BENCH_PACKET_CAPTURE_COUNT:-256}"
perf_stat_enabled="${OXIDEDNS_BENCH_PERF_STAT:-false}"
perf_record_enabled="${OXIDEDNS_BENCH_PERF_RECORD:-false}"
perf_frequency="${OXIDEDNS_BENCH_PERF_FREQUENCY:-99}"
perf_events="${OXIDEDNS_BENCH_PERF_EVENTS:-cycles,instructions,branches,branch-misses}"
perf_privileged_helper_enabled="${OXIDEDNS_BENCH_PERF_PRIVILEGED_HELPER:-false}"
perf_helper_path="${OXIDEDNS_BENCH_PERF_HELPER_PATH:-/usr/local/libexec/oxidedns-perf-capture}"
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
    "OXIDEDNS_BENCH_UDP_CLIENT_SOCKETS_PER_THREAD:$udp_client_sockets_per_thread" \
    "OXIDEDNS_BENCH_UDP_BATCH_SIZE:$udp_batch_size" \
    "OXIDEDNS_BENCH_UDP_REUSEPORT_WORKERS:$udp_reuseport_workers" \
    "OXIDEDNS_BENCH_RESPONSE_TIMEOUT_MS:$response_timeout_ms"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
if [[ -n "$udp_worker_cpu_affinity" ]]; then
    if [[ "$udp_runtime" != dedicated ]]; then
        printf 'OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY requires OXIDEDNS_BENCH_UDP_RUNTIME=dedicated\n' >&2
        exit 64
    fi
    IFS=',' read -r -a udp_worker_cpus <<<"$udp_worker_cpu_affinity"
    if [[ "${#udp_worker_cpus[@]}" -ne "$udp_reuseport_workers" ]]; then
        printf 'OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY must contain one comma-separated CPU per UDP reuseport worker\n' >&2
        exit 64
    fi
    for cpu in "${udp_worker_cpus[@]}"; do
        require_nonnegative_integer "OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY" "$cpu"
    done
fi
require_nonnegative_integer "OXIDEDNS_BENCH_STRESS_CANDIDATES" "$stress_candidates"
case "$udp_runtime" in
tokio | dedicated) ;;
*)
    printf 'OXIDEDNS_BENCH_UDP_RUNTIME must be tokio or dedicated, got %q\n' "$udp_runtime" >&2
    exit 64
    ;;
esac
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
case "$zone_shape_metrics_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED must be true or false, got %q\n' "$zone_shape_metrics_enabled" >&2
    exit 64
    ;;
esac
case "$hot_path_detail" in
full | reduced) ;;
*)
    printf 'OXIDEDNS_BENCH_HOT_PATH_DETAIL must be full or reduced, got %q\n' "$hot_path_detail" >&2
    exit 64
    ;;
esac
case "$packet_capture_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_PACKET_CAPTURE_ENABLED must be true or false, got %q\n' "$packet_capture_enabled" >&2
    exit 64
    ;;
esac
require_positive_integer "OXIDEDNS_BENCH_PACKET_CAPTURE_COUNT" "$packet_capture_count"
case "$perf_stat_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_PERF_STAT must be true or false, got %q\n' "$perf_stat_enabled" >&2
    exit 64
    ;;
esac
case "$perf_record_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_PERF_RECORD must be true or false, got %q\n' "$perf_record_enabled" >&2
    exit 64
    ;;
esac
case "$perf_privileged_helper_enabled" in
true | false) ;;
*)
    printf 'OXIDEDNS_BENCH_PERF_PRIVILEGED_HELPER must be true or false, got %q\n' "$perf_privileged_helper_enabled" >&2
    exit 64
    ;;
esac
require_positive_integer "OXIDEDNS_BENCH_PERF_FREQUENCY" "$perf_frequency"
if [[ "$perf_stat_enabled" == true || "$perf_record_enabled" == true ]]; then
    if [[ "$perf_privileged_helper_enabled" == true ]]; then
        if ! command -v sudo >/dev/null 2>&1; then
            printf 'privileged perf helper requested but sudo is not available in PATH\n' >&2
            exit 64
        fi
        if [[ ! -x "$perf_helper_path" ]]; then
            printf 'privileged perf helper requested but helper is not executable: %s\n' "$perf_helper_path" >&2
            printf 'Install it with scripts/install-oxidedns-perf-helper.sh\n' >&2
            exit 64
        fi
    elif ! command -v perf >/dev/null 2>&1; then
        printf 'perf capture requested but perf is not available in PATH\n' >&2
        exit 64
    fi
fi
if [[ "$requested_zone_image_serve_enabled" != true ]]; then
    printf 'OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false was retired with the live snapshot-serving rollback path; ZoneImage serving is always enabled.\n' >&2
    exit 64
fi
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
    printf 'udp_client_sockets_per_thread=%s\n' "$udp_client_sockets_per_thread"
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
    printf 'zone_shape_metrics_enabled=%s\n' "$zone_shape_metrics_enabled"
    printf 'packet_capture_enabled=%s\n' "$packet_capture_enabled"
    printf 'packet_capture_count=%s\n' "$packet_capture_count"
    printf 'perf_stat_enabled=%s\n' "$perf_stat_enabled"
    printf 'perf_record_enabled=%s\n' "$perf_record_enabled"
    printf 'perf_privileged_helper_enabled=%s\n' "$perf_privileged_helper_enabled"
    printf 'perf_helper_path=%s\n' "$perf_helper_path"
    printf 'perf_frequency=%s\n' "$perf_frequency"
    printf 'perf_events=%s\n' "$perf_events"
    printf 'kernel_version=%s\n' "$kernel_version"
    printf 'rustc_version=%s\n' "$rustc_version"
    printf 'cargo_version=%s\n' "$cargo_version"
    printf 'build_profile=%s\n' "$build_profile"
    exit 0
fi

mkdir -p "$artifact_dir" "$workdir" "$repo_root/target/benchmark-tools"

cleanup() {
    local status=$?
    if [[ -n "${perf_stat_pid:-}" ]] && kill -0 "$perf_stat_pid" 2>/dev/null; then
        kill "$perf_stat_pid" 2>/dev/null || true
        wait "$perf_stat_pid" 2>/dev/null || true
    fi
    if [[ -n "${perf_record_pid:-}" ]] && kill -0 "$perf_record_pid" 2>/dev/null; then
        kill "$perf_record_pid" 2>/dev/null || true
        wait "$perf_record_pid" 2>/dev/null || true
    fi
    if [[ -n "${packet_capture_pid:-}" ]] && kill -0 "$packet_capture_pid" 2>/dev/null; then
        kill "$packet_capture_pid" 2>/dev/null || true
        wait "$packet_capture_pid" 2>/dev/null || true
    fi
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
packet_capture_dir="$artifact_dir/packet-capture"
trace_file=""
trace_source="generated-name-mode"
packet_capture_file="none"
packet_capture_status="disabled"
packet_capture_packets="0"
packet_capture_dns_packets="0"
packet_capture_dns_query_packets="0"
packet_capture_dns_response_packets="0"

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

start_packet_capture() {
    if [[ "$packet_capture_enabled" != true ]]; then
        return
    fi
    if [[ "$transport" != udp ]]; then
        mkdir -p "$packet_capture_dir"
        {
            printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
            printf 'packet_capture_status=skipped-non-udp\n'
            printf 'transport=%s\n' "$transport"
        } >"$packet_capture_dir/packet-capture.env"
        packet_capture_status="skipped-non-udp"
        return
    fi
    if [[ "$network_device" == unknown || -z "$network_device" ]]; then
        printf 'packet capture requested, but network_device=%q\n' "$network_device" >&2
        exit 64
    fi
    local capture_tool
    if command -v dumpcap >/dev/null 2>&1; then
        capture_tool="dumpcap"
    elif command -v tcpdump >/dev/null 2>&1; then
        capture_tool="tcpdump"
    else
        printf 'packet capture requested, but neither dumpcap nor tcpdump is on PATH\n' >&2
        exit 69
    fi

    mkdir -p "$packet_capture_dir"
    packet_capture_file="$packet_capture_dir/dns-udp.pcapng"
    packet_capture_status="started"
    {
        printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'tool=%s\n' "$capture_tool"
        printf 'network_device=%s\n' "$network_device"
        printf 'dns_port=%s\n' "$dns_port"
        printf 'packet_capture_count=%s\n' "$packet_capture_count"
        printf 'filter=udp and port %s\n' "$dns_port"
        "$capture_tool" --version 2>&1 | head -1 || true
    } >"$packet_capture_dir/packet-capture.env"

    if [[ "$capture_tool" == dumpcap ]]; then
        dumpcap -i "$network_device" -s 0 -p -c "$packet_capture_count" \
            -f "udp and port $dns_port" -w "$packet_capture_file" \
            >"$packet_capture_dir/dumpcap.stdout" 2>"$packet_capture_dir/dumpcap.stderr" &
    else
        tcpdump -i "$network_device" -s 0 -U -n -c "$packet_capture_count" \
            -w "$packet_capture_file" "udp and port $dns_port" \
            >"$packet_capture_dir/tcpdump.stdout" 2>"$packet_capture_dir/tcpdump.stderr" &
    fi
    packet_capture_pid=$!
    sleep 0.25
    if ! kill -0 "$packet_capture_pid" 2>/dev/null; then
        packet_capture_status="start-failed"
        printf 'packet capture failed to start; see %s\n' "$packet_capture_dir" >&2
        exit 69
    fi
}

finish_packet_capture() {
    if [[ "$packet_capture_enabled" != true || "$packet_capture_status" == disabled ]]; then
        return
    fi
    if [[ -n "${packet_capture_pid:-}" ]] && kill -0 "$packet_capture_pid" 2>/dev/null; then
        for _ in {1..20}; do
            if ! kill -0 "$packet_capture_pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
        done
    fi
    if [[ -n "${packet_capture_pid:-}" ]] && kill -0 "$packet_capture_pid" 2>/dev/null; then
        kill "$packet_capture_pid" 2>/dev/null || true
    fi
    if [[ -n "${packet_capture_pid:-}" ]]; then
        wait "$packet_capture_pid" 2>/dev/null || true
        packet_capture_pid=""
    fi
    if [[ -s "$packet_capture_file" ]]; then
        packet_capture_status="captured"
        if command -v capinfos >/dev/null 2>&1; then
            packet_capture_packets="$(
                capinfos -c -M "$packet_capture_file" 2>/dev/null |
                    awk -F: '/Number of packets/ { gsub(/ /, "", $2); print $2; exit }'
            )"
        elif command -v tshark >/dev/null 2>&1; then
            packet_capture_packets="$(tshark -r "$packet_capture_file" 2>/dev/null | wc -l | awk '{ print $1 }')"
        else
            packet_capture_packets="unknown"
        fi
        packet_capture_packets="${packet_capture_packets:-unknown}"
        if command -v tshark >/dev/null 2>&1; then
            {
                printf 'metric\tvalue\tunit\n'
                printf 'dns_packets\t%s\tpackets\n' "$(
                    tshark -r "$packet_capture_file" -Y dns 2>/dev/null | wc -l | awk '{ print $1 }'
                )"
                printf 'dns_query_packets\t%s\tpackets\n' "$(
                    tshark -r "$packet_capture_file" -Y 'dns && dns.flags.response == 0' 2>/dev/null | wc -l | awk '{ print $1 }'
                )"
                printf 'dns_response_packets\t%s\tpackets\n' "$(
                    tshark -r "$packet_capture_file" -Y 'dns && dns.flags.response == 1' 2>/dev/null | wc -l | awk '{ print $1 }'
                )"
                printf 'dns_sample\t%s\tfile\n' "dns-sample.tsv"
            } >"$packet_capture_dir/dns-summary.tsv"
            tshark -r "$packet_capture_file" -Y dns -T fields \
                -e frame.number -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
                -e dns.flags.response -e dns.flags.rcode -e dns.count.answers -e dns.qry.name \
                >"$packet_capture_dir/dns-sample.tsv" 2>/dev/null || true
        fi
    elif [[ "$packet_capture_status" == skipped-non-udp ]]; then
        packet_capture_packets="0"
    else
        packet_capture_status="empty"
        packet_capture_packets="0"
    fi
    {
        printf 'packet_capture_status=%s\n' "$packet_capture_status"
        printf 'packet_capture_packets=%s\n' "$packet_capture_packets"
        printf 'packet_capture_file=%s\n' "$packet_capture_file"
    } >>"$packet_capture_dir/packet-capture.env"
}

start_perf_capture() {
    perf_stat_status="disabled"
    perf_record_status="disabled"
    if [[ "$perf_stat_enabled" == true ]]; then
        perf_stat_status="started"
        if [[ "$perf_privileged_helper_enabled" == true ]]; then
            sudo -n "$perf_helper_path" stat \
                --pid "$oxidedns_pid" \
                --duration "$duration" \
                --events "$perf_events" \
                --output "$artifact_dir/perf-stat.txt" \
                >"$artifact_dir/perf-stat.stdout" 2>"$artifact_dir/perf-stat.stderr" &
        else
            perf stat -e "$perf_events" -p "$oxidedns_pid" -o "$artifact_dir/perf-stat.txt" -- sleep "$duration" \
                >"$artifact_dir/perf-stat.stdout" 2>"$artifact_dir/perf-stat.stderr" &
        fi
        perf_stat_pid=$!
    fi
    if [[ "$perf_record_enabled" == true ]]; then
        perf_record_status="started"
        if [[ "$perf_privileged_helper_enabled" == true ]]; then
            sudo -n "$perf_helper_path" record \
                --pid "$oxidedns_pid" \
                --duration "$duration" \
                --frequency "$perf_frequency" \
                --output "$artifact_dir/perf.data" \
                >"$artifact_dir/perf-record.stdout" 2>"$artifact_dir/perf-record.stderr" &
        else
            perf record -F "$perf_frequency" -g -p "$oxidedns_pid" -o "$artifact_dir/perf.data" -- sleep "$duration" \
                >"$artifact_dir/perf-record.stdout" 2>"$artifact_dir/perf-record.stderr" &
        fi
        perf_record_pid=$!
    fi
}

finish_perf_capture() {
    if [[ -n "${perf_stat_pid:-}" ]]; then
        wait "$perf_stat_pid" 2>/dev/null && perf_stat_status="captured" || perf_stat_status="failed"
        perf_stat_pid=""
    fi
    if [[ -n "${perf_record_pid:-}" ]]; then
        wait "$perf_record_pid" 2>/dev/null && perf_record_status="captured" || perf_record_status="failed"
        perf_record_pid=""
        if [[ "$perf_record_status" == captured && -s "$artifact_dir/perf.data" ]]; then
            perf script -i "$artifact_dir/perf.data" >"$artifact_dir/perf.script" 2>"$artifact_dir/perf-script.stderr" || true
            if command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
                inferno-collapse-perf "$artifact_dir/perf.script" >"$artifact_dir/perf.folded" 2>"$artifact_dir/inferno-collapse.stderr" || true
                inferno-flamegraph "$artifact_dir/perf.folded" >"$artifact_dir/flamegraph.svg" 2>"$artifact_dir/inferno-flamegraph.stderr" || true
            fi
        fi
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

[cookie]
policy = "disabled"

[rrl]
enabled = false

[metrics]
hot_path_detail = "$hot_path_detail"
pipeline_timing_enabled = $pipeline_timing_enabled
zone_shape_enabled = $zone_shape_metrics_enabled

[limits]
max_udp_payload = 1232
udp_batch_size = $udp_batch_size
udp_reuseport_workers = $udp_reuseport_workers
udp_runtime = "$udp_runtime"
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

EOF

if [[ -n "$udp_worker_cpu_affinity" ]]; then
    printf 'udp_worker_cpu_affinity = [%s]\n' "$udp_worker_cpu_affinity" >>"$config"
fi

cat >>"$config" <<EOF

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
udp_client_sockets_per_thread=$udp_client_sockets_per_thread
udp_batch_size=$udp_batch_size
udp_reuseport_workers=$udp_reuseport_workers
udp_runtime=$udp_runtime
udp_worker_cpu_affinity=${udp_worker_cpu_affinity:-none}
duration_seconds=$duration
response_timeout_ms=$response_timeout_ms
pipeline_timing_enabled=$pipeline_timing_enabled
zone_shape_metrics_enabled=$zone_shape_metrics_enabled
hot_path_detail=$hot_path_detail
zone_image_serve_enabled=$zone_image_serve_enabled
packet_capture_enabled=$packet_capture_enabled
packet_capture_count=$packet_capture_count
perf_stat_enabled=$perf_stat_enabled
perf_record_enabled=$perf_record_enabled
perf_privileged_helper_enabled=$perf_privileged_helper_enabled
perf_helper_path=$perf_helper_path
perf_frequency=$perf_frequency
perf_events=$perf_events
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
start_packet_capture
start_perf_capture

client_args=(
    --transport "$transport"
    --server "$client_server"
    --port "$dns_port"
    --bind "$client_bind"
    --threads "$client_threads"
    --udp-sockets-per-thread "$udp_client_sockets_per_thread"
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
        --udp-sockets-per-thread "$udp_client_sockets_per_thread"
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
finish_perf_capture
finish_packet_capture
if [[ -f "$packet_capture_dir/dns-summary.tsv" ]]; then
    packet_capture_dns_packets="$(awk -F'\t' '$1 == "dns_packets" { print $2; exit }' "$packet_capture_dir/dns-summary.tsv")"
    packet_capture_dns_query_packets="$(awk -F'\t' '$1 == "dns_query_packets" { print $2; exit }' "$packet_capture_dir/dns-summary.tsv")"
    packet_capture_dns_response_packets="$(awk -F'\t' '$1 == "dns_response_packets" { print $2; exit }' "$packet_capture_dir/dns-summary.tsv")"
fi
packet_capture_dns_packets="${packet_capture_dns_packets:-0}"
packet_capture_dns_query_packets="${packet_capture_dns_query_packets:-0}"
packet_capture_dns_response_packets="${packet_capture_dns_response_packets:-0}"

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
network_rx_bytes_delta="$(awk -F'\t' '$1 == "rx_bytes" { print $4; exit }' "$network_dir/proc-net-dev-delta.tsv")"
network_tx_bytes_delta="$(awk -F'\t' '$1 == "tx_bytes" { print $4; exit }' "$network_dir/proc-net-dev-delta.tsv")"
network_rx_packets_delta="$(awk -F'\t' '$1 == "rx_packets" { print $4; exit }' "$network_dir/proc-net-dev-delta.tsv")"
network_tx_packets_delta="$(awk -F'\t' '$1 == "tx_packets" { print $4; exit }' "$network_dir/proc-net-dev-delta.tsv")"
network_rx_bytes_delta="${network_rx_bytes_delta:-unknown}"
network_tx_bytes_delta="${network_tx_bytes_delta:-unknown}"
network_rx_packets_delta="${network_rx_packets_delta:-unknown}"
network_tx_packets_delta="${network_tx_packets_delta:-unknown}"
throughput_summary() {
    python3 - "$duration" "$responses_per_second" "$network_rx_bytes_delta" "$network_tx_bytes_delta" "$network_device" <<'PY'
import math
import sys

duration, qps, rx_bytes, tx_bytes, device = sys.argv[1:]

def number(value):
    try:
        return float(value)
    except ValueError:
        return math.nan

duration = number(duration)
qps = number(qps)
rx = number(rx_bytes)
tx = number(tx_bytes)

def fmt(value):
    return "unknown" if math.isnan(value) else f"{value:.6f}"

def bytes_per_second(value):
    return math.nan if math.isnan(value) or duration <= 0 else value / duration

rx_bps = bytes_per_second(rx)
tx_bps = bytes_per_second(tx)
sum_bps = rx_bps + tx_bps if not math.isnan(rx_bps) and not math.isnan(tx_bps) else math.nan
rx_gbps = rx_bps * 8 / 1_000_000_000 if not math.isnan(rx_bps) else math.nan
tx_gbps = tx_bps * 8 / 1_000_000_000 if not math.isnan(tx_bps) else math.nan
sum_gbps = sum_bps * 8 / 1_000_000_000 if not math.isnan(sum_bps) else math.nan
rx_gBps = rx_bps / 1_000_000_000 if not math.isnan(rx_bps) else math.nan
tx_gBps = tx_bps / 1_000_000_000 if not math.isnan(tx_bps) else math.nan
sum_gBps = sum_bps / 1_000_000_000 if not math.isnan(sum_bps) else math.nan
rx_bytes_per_response = rx_bps / qps if qps > 0 and not math.isnan(rx_bps) else math.nan
tx_bytes_per_response = tx_bps / qps if qps > 0 and not math.isnan(tx_bps) else math.nan
sum_bytes_per_response = sum_bps / qps if qps > 0 and not math.isnan(sum_bps) else math.nan
scope = "loopback-summed-not-wire-rate" if device == "lo" else "interface-counter"

values = [
    rx_bps,
    tx_bps,
    sum_bps,
    rx_gbps,
    tx_gbps,
    sum_gbps,
    rx_gBps,
    tx_gBps,
    sum_gBps,
    rx_bytes_per_response,
    tx_bytes_per_response,
    sum_bytes_per_response,
]
print("\t".join([*(fmt(value) for value in values), scope]))
PY
}
IFS=$'\t' read -r network_rx_bytes_per_second network_tx_bytes_per_second network_sum_bytes_per_second \
    network_rx_gbps network_tx_gbps network_sum_gbps \
    network_rx_gigabytes_per_second network_tx_gigabytes_per_second network_sum_gigabytes_per_second \
    network_rx_bytes_per_response network_tx_bytes_per_response network_sum_bytes_per_response \
    network_throughput_scope \
    <<<"$(throughput_summary)"
prom_metric_value() {
    local metric="$1"
    awk -v metric="$metric" '$1 == metric { print $2; exit }' "$artifact_dir/metrics-after.prom"
}
zone_image_serve_hits="$(prom_metric_value oxidedns_zone_image_serve_hits_total)"
zone_image_serve_direct_hits="$(prom_metric_value oxidedns_zone_image_serve_direct_hits_total)"
zone_image_serve_semantic_hits="$(prom_metric_value oxidedns_zone_image_serve_semantic_hits_total)"
zone_image_serve_failures="$(prom_metric_value oxidedns_zone_image_serve_failures_total)"
udp_receive_batches="$(prom_metric_value oxidedns_udp_receive_batches_total)"
udp_received_datagrams="$(prom_metric_value oxidedns_udp_received_datagrams_total)"
udp_send_batches="$(prom_metric_value oxidedns_udp_send_batches_total)"
udp_sent_datagrams="$(prom_metric_value oxidedns_udp_sent_datagrams_total)"
udp_mmsg_receive_syscalls="$(prom_metric_value oxidedns_udp_mmsg_receive_syscalls_total)"
udp_mmsg_received_datagrams="$(prom_metric_value oxidedns_udp_mmsg_received_datagrams_total)"
udp_mmsg_send_syscalls="$(prom_metric_value oxidedns_udp_mmsg_send_syscalls_total)"
udp_mmsg_sent_datagrams="$(prom_metric_value oxidedns_udp_mmsg_sent_datagrams_total)"
udp_mmsg_send_partial_syscalls="$(prom_metric_value oxidedns_udp_mmsg_send_partial_syscalls_total)"
udp_mmsg_send_wouldblock_retries="$(prom_metric_value oxidedns_udp_mmsg_send_wouldblock_retries_total)"
worker_metric_summary() {
    local metric="$1"
    python3 - "$artifact_dir/metrics-after.prom" "$metric" <<'PY'
import re
import sys

path, metric = sys.argv[1], sys.argv[2]
pattern = re.compile(rf"^{re.escape(metric)}\{{worker=\"(\d+)\"\}}\s+([0-9.]+)")
values = []
with open(path, encoding="utf-8") as handle:
    for line in handle:
        match = pattern.match(line)
        if match:
            values.append(float(match.group(2)))
if not values:
    print("0\t0\t0\tnan")
else:
    low = min(values)
    high = max(values)
    ratio = "nan" if low == 0 else f"{high / low:.3f}"
    print(f"{len(values)}\t{int(low)}\t{int(high)}\t{ratio}")
PY
}
IFS=$'\t' read -r udp_worker_receive_slots udp_worker_received_datagrams_min udp_worker_received_datagrams_max udp_worker_received_datagrams_imbalance_ratio \
    <<<"$(worker_metric_summary oxidedns_udp_worker_received_datagrams_total)"
IFS=$'\t' read -r udp_worker_send_slots udp_worker_sent_datagrams_min udp_worker_sent_datagrams_max udp_worker_sent_datagrams_imbalance_ratio \
    <<<"$(worker_metric_summary oxidedns_udp_worker_sent_datagrams_total)"
zone_image_serve_hits="${zone_image_serve_hits:-unknown}"
zone_image_serve_direct_hits="${zone_image_serve_direct_hits:-unknown}"
zone_image_serve_semantic_hits="${zone_image_serve_semantic_hits:-unknown}"
zone_image_serve_failures="${zone_image_serve_failures:-unknown}"
zone_image_serve_rollbacks="0"
udp_receive_batches="${udp_receive_batches:-unknown}"
udp_received_datagrams="${udp_received_datagrams:-unknown}"
udp_send_batches="${udp_send_batches:-unknown}"
udp_sent_datagrams="${udp_sent_datagrams:-unknown}"
udp_mmsg_receive_syscalls="${udp_mmsg_receive_syscalls:-0}"
udp_mmsg_received_datagrams="${udp_mmsg_received_datagrams:-0}"
udp_mmsg_send_syscalls="${udp_mmsg_send_syscalls:-0}"
udp_mmsg_sent_datagrams="${udp_mmsg_sent_datagrams:-0}"
udp_mmsg_send_partial_syscalls="${udp_mmsg_send_partial_syscalls:-0}"
udp_mmsg_send_wouldblock_retries="${udp_mmsg_send_wouldblock_retries:-0}"

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
udp_client_sockets_per_thread	$udp_client_sockets_per_thread	sockets
udp_batch_size	$udp_batch_size	datagrams
udp_reuseport_workers	$udp_reuseport_workers	workers
udp_runtime	$udp_runtime	mode
udp_worker_cpu_affinity	${udp_worker_cpu_affinity:-none}	cpus
udp_receive_batches	$udp_receive_batches	batches
udp_received_datagrams	$udp_received_datagrams	datagrams
udp_send_batches	$udp_send_batches	batches
udp_sent_datagrams	$udp_sent_datagrams	datagrams
udp_mmsg_receive_syscalls	$udp_mmsg_receive_syscalls	syscalls
udp_mmsg_received_datagrams	$udp_mmsg_received_datagrams	datagrams
udp_mmsg_send_syscalls	$udp_mmsg_send_syscalls	syscalls
udp_mmsg_sent_datagrams	$udp_mmsg_sent_datagrams	datagrams
udp_mmsg_send_partial_syscalls	$udp_mmsg_send_partial_syscalls	syscalls
udp_mmsg_send_wouldblock_retries	$udp_mmsg_send_wouldblock_retries	retries
udp_worker_receive_slots	$udp_worker_receive_slots	workers
udp_worker_received_datagrams_min	$udp_worker_received_datagrams_min	datagrams
udp_worker_received_datagrams_max	$udp_worker_received_datagrams_max	datagrams
udp_worker_received_datagrams_imbalance_ratio	$udp_worker_received_datagrams_imbalance_ratio	ratio
udp_worker_send_slots	$udp_worker_send_slots	workers
udp_worker_sent_datagrams_min	$udp_worker_sent_datagrams_min	datagrams
udp_worker_sent_datagrams_max	$udp_worker_sent_datagrams_max	datagrams
udp_worker_sent_datagrams_imbalance_ratio	$udp_worker_sent_datagrams_imbalance_ratio	ratio
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
network_rx_bytes_delta	$network_rx_bytes_delta	bytes
network_tx_bytes_delta	$network_tx_bytes_delta	bytes
network_rx_packets_delta	$network_rx_packets_delta	packets
network_tx_packets_delta	$network_tx_packets_delta	packets
network_rx_bytes_per_second	$network_rx_bytes_per_second	bytes_per_second
network_tx_bytes_per_second	$network_tx_bytes_per_second	bytes_per_second
network_sum_bytes_per_second	$network_sum_bytes_per_second	bytes_per_second
network_rx_gbps	$network_rx_gbps	gigabits_per_second
network_tx_gbps	$network_tx_gbps	gigabits_per_second
network_sum_gbps	$network_sum_gbps	gigabits_per_second
network_rx_gigabytes_per_second	$network_rx_gigabytes_per_second	gigabytes_per_second
network_tx_gigabytes_per_second	$network_tx_gigabytes_per_second	gigabytes_per_second
network_sum_gigabytes_per_second	$network_sum_gigabytes_per_second	gigabytes_per_second
network_rx_bytes_per_response	$network_rx_bytes_per_response	bytes_per_response
network_tx_bytes_per_response	$network_tx_bytes_per_response	bytes_per_response
network_sum_bytes_per_response	$network_sum_bytes_per_response	bytes_per_response
network_throughput_scope	$network_throughput_scope	scope
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
zone_shape_metrics_enabled	$zone_shape_metrics_enabled	boolean
hot_path_detail	$hot_path_detail	mode
zone_image_serve_enabled	$zone_image_serve_enabled	boolean
packet_capture_enabled	$packet_capture_enabled	boolean
packet_capture_status	$packet_capture_status	status
packet_capture_file	$packet_capture_file	file
packet_capture_packets	$packet_capture_packets	packets
packet_capture_dns_packets	$packet_capture_dns_packets	packets
packet_capture_dns_query_packets	$packet_capture_dns_query_packets	packets
packet_capture_dns_response_packets	$packet_capture_dns_response_packets	packets
perf_stat_enabled	$perf_stat_enabled	boolean
perf_stat_status	$perf_stat_status	status
perf_stat_file	$([[ "$perf_stat_enabled" == true ]] && echo perf-stat.txt || echo none)	file
perf_privileged_helper_enabled	$perf_privileged_helper_enabled	boolean
perf_helper_path	$perf_helper_path	path
perf_events	$perf_events	events
perf_record_enabled	$perf_record_enabled	boolean
perf_record_status	$perf_record_status	status
perf_record_file	$([[ "$perf_record_enabled" == true ]] && echo perf.data || echo none)	file
perf_script_file	$([[ "$perf_record_status" == captured && -s "$artifact_dir/perf.script" ]] && echo perf.script || echo none)	file
flamegraph_file	$([[ -s "$artifact_dir/flamegraph.svg" ]] && echo flamegraph.svg || echo none)	file
zone_image_serve_hits	$zone_image_serve_hits	queries
zone_image_serve_direct_hits	$zone_image_serve_direct_hits	queries
zone_image_serve_semantic_hits	$zone_image_serve_semantic_hits	queries
zone_image_serve_failures	$zone_image_serve_failures	queries
zone_image_serve_rollbacks	$zone_image_serve_rollbacks	queries
EOF

cat >"$artifact_dir/README.md" <<EOF
# OxideDNS DNS Client Benchmark

This artifact was generated by \`scripts/benchmark-dns-clients.sh\`.

The run starts a synthetic TCP AXFR primary, loads \`$records\` A records into
OxideDNS, pins OxideDNS to CPU affinity \`$server_affinity\` when \`taskset\` is
available, then drives \`$transport\` direct-hit A queries against
\`$client_server:$dns_port\` with UDP client bind setting
\`$client_bind_summary\`, UDP client sockets per thread
\`$udp_client_sockets_per_thread\`, and the checked-in
\`tools/dns-load-client.rs\` client in \`client_mode=$client_mode\`.
TCP source address selection is left to the OS. Network device was recorded as
\`$network_device\`; route, link, /proc, optional ethtool snapshots, and quick
counter deltas are retained under \`network/\`. Query pipeline timing metrics
were configured as \`pipeline_timing_enabled=$pipeline_timing_enabled\`.
\`zone_shape_metrics_enabled=$zone_shape_metrics_enabled\` controls whether
scrape-time zone-shape gauges and histograms were collected.
\`zone_image_serve_enabled=$zone_image_serve_enabled\`.
Query mode was \`$query_mode\`; when this is \`trace\`, the retained
\`query-trace.tsv\` file is the exact replay input.
The configured UDP runtime was \`$udp_runtime\`, and the configured UDP batch
size was \`$udp_batch_size\`; packet I/O counters
recorded \`$udp_receive_batches\` receive batches, \`$udp_received_datagrams\`
received datagrams, \`$udp_send_batches\` send batches, and
\`$udp_sent_datagrams\` sent datagrams.
Packet capture was configured as \`packet_capture_enabled=$packet_capture_enabled\`;
status \`$packet_capture_status\`, packet count \`$packet_capture_packets\`,
DNS packets \`$packet_capture_dns_packets\`, DNS query packets
\`$packet_capture_dns_query_packets\`, DNS response packets
\`$packet_capture_dns_response_packets\`, file \`$packet_capture_file\`.
Perf stat was configured as \`perf_stat_enabled=$perf_stat_enabled\` with status
\`$perf_stat_status\`; perf record was configured as
\`perf_record_enabled=$perf_record_enabled\` with status \`$perf_record_status\`.

This is a local engineering benchmark, not the full SRS Reference
Hardware/Profile acceptance campaign.
EOF

printf 'dns_client_benchmark_dir=%s\n' "$artifact_dir"
printf 'capability_summary transport=%s query_mode=%s trace_queries=%s zone_image_serve_enabled=%s udp_runtime=%s udp_batch_size=%s udp_reuseport_workers=%s udp_worker_cpu_affinity=%s udp_client_sockets_per_thread=%s listen_address=%s client_server=%s client_bind=%s network_device=%s require_non_loopback_device=%s network_rx_packets_delta=%s network_tx_packets_delta=%s server_threads=%s client_threads=%s records=%s responses_per_second=%s latency_us_p50=%s latency_us_p99=%s latency_us_p999=%s dropped=%s errors=%s\n' \
    "$transport" "$query_mode" "$trace_queries" "$zone_image_serve_enabled" "$udp_runtime" "$udp_batch_size" "$udp_reuseport_workers" "${udp_worker_cpu_affinity:-none}" "$udp_client_sockets_per_thread" "$listen_address" "$client_server" "$client_bind_summary" "$network_device" "$require_non_loopback_device" "$network_rx_packets_delta" "$network_tx_packets_delta" "$server_threads" "$client_threads" "$records" "$responses_per_second" "$latency_us_p50" "$latency_us_p99" "$latency_us_p999" "$dropped" "$errors"
