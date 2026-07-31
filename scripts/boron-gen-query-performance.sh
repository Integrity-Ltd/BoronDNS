#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_dir="${BORON_GEN_PERF_ARTIFACT_DIR:-$repo_root/target/evidence/boron-gen-query-performance-$timestamp}"
profile="${BORON_GEN_PERF_PROFILE:-registry-nsec3}"
origin="${BORON_GEN_PERF_ORIGIN:-load.borongen.}"
zones="${BORON_GEN_PERF_ZONES:-1}"
names_per_zone="${BORON_GEN_PERF_NAMES_PER_ZONE:-10000}"
server_address="${BORON_GEN_PERF_SERVER_ADDRESS:-127.0.0.1}"
server_port="${BORON_GEN_PERF_SERVER_PORT:-15300}"
server_device="${BORON_GEN_PERF_SERVER_DEVICE:-auto}"
server_ssh="${BORON_GEN_PERF_SERVER_SSH:-}"
mode="${BORON_GEN_PERF_MODE:-local}"
client_bind_default="127.0.0.1:0"
if [[ "$mode" == "ssh" ]]; then
    client_bind_default="0.0.0.0:0"
fi
client_bind="${BORON_GEN_PERF_CLIENT_BIND:-$client_bind_default}"
client_device="${BORON_GEN_PERF_CLIENT_DEVICE:-auto}"
remote_ssh="${BORON_GEN_PERF_REMOTE_SSH:-}"
remote_workdir="${BORON_GEN_PERF_REMOTE_WORKDIR:-/tmp/borondns-boron-gen-perf-${timestamp,,}-$$}"
ssh_connect_timeout="${BORON_GEN_PERF_SSH_CONNECT_TIMEOUT_SECONDS:-5}"
warmup_seconds="${BORON_GEN_PERF_WARMUP_SECONDS:-15}"
duration_seconds="${BORON_GEN_PERF_DURATION_SECONDS:-60}"
repetitions="${BORON_GEN_PERF_REPETITIONS:-3}"
target_qps_steps="${BORON_GEN_PERF_TARGET_QPS_STEPS:-0}"
client_threads="${BORON_GEN_PERF_CLIENT_THREADS:-32}"
client_window="${BORON_GEN_PERF_CLIENT_WINDOW:-256}"
client_sockets_per_thread="${BORON_GEN_PERF_CLIENT_SOCKETS_PER_THREAD:-4}"
client_timeout_ms="${BORON_GEN_PERF_CLIENT_TIMEOUT_MS:-1000}"
client_cpu_list="${BORON_GEN_PERF_CLIENT_CPU_LIST:-}"
max_drop_permille="${BORON_GEN_PERF_MAX_DROP_PERMILLE:-100}"
sample_count="${BORON_GEN_PERF_TRACE_SAMPLE_COUNT:-256}"
hot_count="${BORON_GEN_PERF_TRACE_HOT_COUNT:-128}"
negative_count="${BORON_GEN_PERF_TRACE_NEGATIVE_COUNT:-128}"
metrics_url="${BORON_GEN_PERF_METRICS_URL:-}"
http_connect_timeout="${BORON_GEN_PERF_HTTP_CONNECT_TIMEOUT_SECONDS:-2}"
http_max_time="${BORON_GEN_PERF_HTTP_MAX_TIME_SECONDS:-10}"
preflight_only="${BORON_GEN_PERF_PREFLIGHT_ONLY:-false}"
client_bin="${BORON_GEN_PERF_CLIENT_BINARY:-$repo_root/target/benchmark-tools/dns-load-client}"
trace_generator="$repo_root/scripts/generate-boron-gen-query-trace.py"
performance_analyzer="$repo_root/scripts/analyze-boron-gen-query-performance.py"

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
    "BORON_GEN_PERF_ZONES:$zones" \
    "BORON_GEN_PERF_NAMES_PER_ZONE:$names_per_zone" \
    "BORON_GEN_PERF_SERVER_PORT:$server_port" \
    "BORON_GEN_PERF_SSH_CONNECT_TIMEOUT_SECONDS:$ssh_connect_timeout" \
    "BORON_GEN_PERF_WARMUP_SECONDS:$warmup_seconds" \
    "BORON_GEN_PERF_DURATION_SECONDS:$duration_seconds" \
    "BORON_GEN_PERF_REPETITIONS:$repetitions" \
    "BORON_GEN_PERF_CLIENT_THREADS:$client_threads" \
    "BORON_GEN_PERF_CLIENT_WINDOW:$client_window" \
    "BORON_GEN_PERF_CLIENT_SOCKETS_PER_THREAD:$client_sockets_per_thread" \
    "BORON_GEN_PERF_CLIENT_TIMEOUT_MS:$client_timeout_ms" \
    "BORON_GEN_PERF_TRACE_SAMPLE_COUNT:$sample_count" \
    "BORON_GEN_PERF_TRACE_HOT_COUNT:$hot_count" \
    "BORON_GEN_PERF_TRACE_NEGATIVE_COUNT:$negative_count" \
    "BORON_GEN_PERF_HTTP_CONNECT_TIMEOUT_SECONDS:$http_connect_timeout" \
    "BORON_GEN_PERF_HTTP_MAX_TIME_SECONDS:$http_max_time"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
require_nonnegative_integer "BORON_GEN_PERF_MAX_DROP_PERMILLE" "$max_drop_permille"
if ((max_drop_permille > 1000)); then
    printf 'BORON_GEN_PERF_MAX_DROP_PERMILLE must be at most 1000, got %q\n' \
        "$max_drop_permille" >&2
    exit 64
fi
if [[ ! "$target_qps_steps" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    printf 'BORON_GEN_PERF_TARGET_QPS_STEPS must be 0 or a comma-separated list of positive integers, got %q\n' \
        "$target_qps_steps" >&2
    exit 64
fi
IFS=, read -r -a target_qps_values <<<"$target_qps_steps"
previous_target=0
for target_qps in "${target_qps_values[@]}"; do
    if ((target_qps == 0)); then
        if ((${#target_qps_values[@]} != 1)); then
            echo "BORON_GEN_PERF_TARGET_QPS_STEPS=0 cannot be combined with paced steps" >&2
            exit 64
        fi
    elif ((target_qps <= previous_target)); then
        echo "BORON_GEN_PERF_TARGET_QPS_STEPS must be strictly increasing" >&2
        exit 64
    fi
    previous_target="$target_qps"
done

case "$profile" in
registry-nsec3 | mixed | large-rrset) ;;
*)
    printf 'BORON_GEN_PERF_PROFILE must be registry-nsec3, mixed, or large-rrset\n' >&2
    exit 64
    ;;
esac
case "$mode" in
local | ssh) ;;
*)
    printf 'BORON_GEN_PERF_MODE must be local or ssh\n' >&2
    exit 64
    ;;
esac
case "$preflight_only" in
true | false) ;;
*)
    printf 'BORON_GEN_PERF_PREFLIGHT_ONLY must be true or false\n' >&2
    exit 64
    ;;
esac
if [[ -n "$client_cpu_list" && ! "$client_cpu_list" =~ ^[0-9,-]+$ ]]; then
    printf 'BORON_GEN_PERF_CLIENT_CPU_LIST must contain only CPU numbers, commas, and ranges\n' >&2
    exit 64
fi
for pair in \
    "BORON_GEN_PERF_SERVER_ADDRESS:$server_address" \
    "BORON_GEN_PERF_CLIENT_BIND:$client_bind"; do
    if [[ -z "${pair#*:}" || "${pair#*:}" =~ [[:space:]] ]]; then
        printf '%s must be non-empty and contain no whitespace\n' "${pair%%:*}" >&2
        exit 64
    fi
done
if [[ ! -x "$trace_generator" ]]; then
    printf 'missing executable trace generator: %s\n' "$trace_generator" >&2
    exit 69
fi
if [[ ! -x "$performance_analyzer" ]]; then
    printf 'missing executable performance analyzer: %s\n' \
        "$performance_analyzer" >&2
    exit 69
fi
for tool in curl ip python3 rustc sha256sum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing required performance tool: %s\n' "$tool" >&2
        exit 69
    fi
done

ssh_options=(-o BatchMode=yes -o "ConnectTimeout=$ssh_connect_timeout")
if [[ "$mode" == "ssh" ]]; then
    for tool in scp ssh; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'SSH performance mode requires %s\n' "$tool" >&2
            exit 69
        fi
    done
    if [[ -z "$remote_ssh" || "$remote_ssh" =~ [[:space:]] ]]; then
        printf 'BORON_GEN_PERF_REMOTE_SSH is required in SSH mode\n' >&2
        exit 64
    fi
    if [[ "$remote_workdir" != /* || "$remote_workdir" == "/" ||
        "$remote_workdir" =~ [[:space:]] ]]; then
        printf 'BORON_GEN_PERF_REMOTE_WORKDIR must be an absolute non-root path without whitespace\n' >&2
        exit 64
    fi
    ssh "${ssh_options[@]}" "$remote_ssh" true
    local_arch="$(uname -m)"
    remote_arch="$(ssh "${ssh_options[@]}" "$remote_ssh" uname -m | tr -d '\r')"
    if [[ "$local_arch" != "$remote_arch" ]]; then
        printf 'local and remote client architectures differ: local=%s remote=%s\n' \
            "$local_arch" "$remote_arch" >&2
        exit 69
    fi
    local_host_id="$(
        if [[ -r /proc/sys/kernel/random/boot_id ]]; then
            cat /proc/sys/kernel/random/boot_id
        else
            hostname
        fi
    )"
    remote_host_id="$(
        ssh "${ssh_options[@]}" "$remote_ssh" \
            'if [ -r /proc/sys/kernel/random/boot_id ]; then cat /proc/sys/kernel/random/boot_id; else hostname; fi' |
            tr -d '\r'
    )"
    if [[ -z "$server_ssh" && "$local_host_id" == "$remote_host_id" ]]; then
        echo "SSH performance mode requires a distinct remote client host" >&2
        exit 64
    fi
    if [[ -n "$server_ssh" ]]; then
        if [[ "$server_ssh" =~ [[:space:]] ]]; then
            echo "BORON_GEN_PERF_SERVER_SSH must not contain whitespace" >&2
            exit 64
        fi
        ssh "${ssh_options[@]}" "$server_ssh" true
        server_host_id="$(
            ssh "${ssh_options[@]}" "$server_ssh" \
                'if [ -r /proc/sys/kernel/random/boot_id ]; then cat /proc/sys/kernel/random/boot_id; else hostname; fi' |
                tr -d '\r'
        )"
        if [[ "$server_host_id" == "$remote_host_id" ]]; then
            echo "server and client SSH targets resolve to the same host" >&2
            exit 64
        fi
    fi
    client_bind_address="${client_bind%:*}"
    if [[ "$client_bind_address" == "0.0.0.0" ||
        "$client_bind_address" == "127.0.0.1" ]]; then
        echo "SSH performance mode requires a concrete non-loopback client bind address" >&2
        exit 64
    fi
    if ! python3 - "$server_address" "$client_bind_address" <<'PY'; then
import ipaddress
import sys

for label, value in (("server", sys.argv[1]), ("client bind", sys.argv[2])):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise SystemExit(f"invalid {label} address: {error}")
    if address.is_loopback or address.is_unspecified:
        raise SystemExit(f"{label} address must be concrete and non-loopback")
PY
        exit 64
    fi
fi

resolve_local_server_device() {
    if [[ "$server_device" != "auto" ]]; then
        return 0
    fi
    if [[ -n "$server_ssh" ]]; then
        # shellcheck disable=SC2029
        server_device="$(
            ssh "${ssh_options[@]}" "$server_ssh" \
                "ip -o addr show; ip route get $(printf '%q' "$server_address")" |
                awk -v address="$server_address" '
                    $4 ~ "^" address "/" { found = 1; print $2; exit }
                    {
                        for (i = 1; i <= NF; i++) {
                            if ($i == "dev") {
                                candidate = $(i + 1)
                            }
                        }
                    }
                    END {
                        if (!found && candidate != "") {
                            print candidate
                        }
                    }
                '
        )"
    else
        server_device="$(
            ip -o addr show |
                awk -v address="$server_address" '$4 ~ "^" address "/" { print $2; exit }'
        )"
        if [[ -z "$server_device" ]]; then
            server_device="$(
                ip route get "$server_address" 2>/dev/null |
                    awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
            )"
        fi
    fi
    server_device="${server_device:-unknown}"
}

resolve_local_server_device
if [[ "$server_device" == "unknown" ]]; then
    printf 'cannot resolve server network device for %s\n' "$server_address" >&2
    exit 69
fi
if [[ -n "$server_ssh" ]]; then
    # shellcheck disable=SC2029
    if ! ssh "${ssh_options[@]}" "$server_ssh" \
        "ip link show dev $(printf '%q' "$server_device")" >/dev/null 2>&1; then
        printf 'server network device does not exist: %s\n' "$server_device" >&2
        exit 69
    fi
else
    if ! ip link show dev "$server_device" >/dev/null 2>&1; then
        printf 'server network device does not exist: %s\n' "$server_device" >&2
        exit 69
    fi
fi

if [[ "$mode" == "local" ]]; then
    if [[ "$client_device" == "auto" ]]; then
        client_device="$(
            ip route get "$server_address" 2>/dev/null |
                awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
        )"
        client_device="${client_device:-$server_device}"
    fi
    if ! ip link show dev "$client_device" >/dev/null 2>&1; then
        printf 'local client network device does not exist: %s\n' "$client_device" >&2
        exit 69
    fi
else
    if [[ "$client_device" == "auto" ]]; then
        # shellcheck disable=SC2029
        client_device="$(
            ssh "${ssh_options[@]}" "$remote_ssh" \
                "ip route get $(printf '%q' "$server_address")" |
                awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
        )"
        client_device="${client_device:-unknown}"
    fi
    if [[ ! "$client_device" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
        printf 'invalid remote client network device: %q\n' "$client_device" >&2
        exit 64
    fi
    # shellcheck disable=SC2029
    if ! ssh "${ssh_options[@]}" "$remote_ssh" \
        "ip link show dev $(printf '%q' "$client_device")" >/dev/null 2>&1; then
        printf 'remote client network device does not exist: %s\n' "$client_device" >&2
        exit 69
    fi
    # shellcheck disable=SC2029
    if ! ssh "${ssh_options[@]}" "$remote_ssh" \
        "ip -o addr show dev $(printf '%q' "$client_device")" |
        awk -v address="$client_bind_address" \
            '$4 ~ "^" address "/" { found = 1 } END { exit !found }'; then
        printf 'remote client bind address %s is not assigned to %s\n' \
            "$client_bind_address" "$client_device" >&2
        exit 69
    fi
    if [[ "$server_device" == "lo" || "$client_device" == "lo" ]]; then
        echo "SSH performance mode refuses loopback network devices" >&2
        exit 64
    fi
fi

if [[ "$preflight_only" == "true" ]]; then
    printf 'boron_gen_performance_preflight=passed\n'
    printf 'mode=%s\n' "$mode"
    printf 'server_address=%s\n' "$server_address"
    printf 'server_port=%s\n' "$server_port"
    printf 'server_device=%s\n' "$server_device"
    printf 'server_ssh=%s\n' "${server_ssh:-none}"
    printf 'client_device=%s\n' "$client_device"
    printf 'client_bind=%s\n' "$client_bind"
    printf 'remote_ssh=%s\n' "${remote_ssh:-none}"
    exit 0
fi

mkdir -p "$artifact_dir/network/server" "$artifact_dir/network/client" \
    "$(dirname "$client_bin")"
chmod 700 "$artifact_dir"
trace_file="$artifact_dir/query-trace.tsv"
"$trace_generator" \
    --profile "$profile" \
    --origin "$origin" \
    --zones "$zones" \
    --names-per-zone "$names_per_zone" \
    --sample-count "$sample_count" \
    --hot-count "$hot_count" \
    --negative-count "$negative_count" \
    >"$trace_file"
rustc --edition=2024 -O "$repo_root/tools/dns-load-client.rs" -o "$client_bin"
client_sha256="$(sha256sum "$client_bin" | awk '{ print $1 }')"
trace_sha256="$(sha256sum "$trace_file" | awk '{ print $1 }')"
analyzer_sha256="$(sha256sum "$performance_analyzer" | awk '{ print $1 }')"

remote_initialized=false
remote_client_bin=""
remote_trace_file=""
remote_marker=""
cleanup_remote() {
    local status=0
    if [[ "$mode" != "ssh" || "$remote_initialized" != "true" ]]; then
        return 0
    fi
    # Remove only the exact files created by this run, then remove the directory
    # only if it is empty. This cannot recursively erase a caller-supplied path.
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$remote_ssh" \
        "rm -f -- $(printf '%q' "$remote_client_bin") $(printf '%q' "$remote_trace_file") $(printf '%q' "$remote_marker") && rmdir -- $(printf '%q' "$remote_workdir")" ||
        status=$?
    if ((status == 0)); then
        printf 'remote_cleanup=completed\n' >"$artifact_dir/remote-cleanup.txt"
        remote_initialized=false
    else
        printf 'remote_cleanup=failed\n' >"$artifact_dir/remote-cleanup.txt"
    fi
    return "$status"
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if ! cleanup_remote; then
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

if [[ "$mode" == "ssh" ]]; then
    remote_client_bin="$remote_workdir/dns-load-client"
    remote_trace_file="$remote_workdir/query-trace.tsv"
    remote_marker="$remote_workdir/.borondns-boron-gen-performance"
    # Refuse to reuse an existing path so uploaded tools cannot overwrite
    # unrelated remote files and cleanup ownership is unambiguous.
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$remote_ssh" \
        "test ! -e $(printf '%q' "$remote_workdir") && mkdir -m 700 -- $(printf '%q' "$remote_workdir") && : > $(printf '%q' "$remote_marker")"
    remote_initialized=true
    scp -q "${ssh_options[@]}" "$client_bin" "$remote_ssh:$remote_client_bin"
    scp -q "${ssh_options[@]}" "$trace_file" "$remote_ssh:$remote_trace_file"
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$remote_ssh" \
        "chmod 700 -- $(printf '%q' "$remote_client_bin"); chmod 600 -- $(printf '%q' "$remote_trace_file")"
    remote_client_sha256="$(
        # shellcheck disable=SC2029
        ssh "${ssh_options[@]}" "$remote_ssh" \
            "sha256sum -- $(printf '%q' "$remote_client_bin")" |
            awk '{ print $1 }'
    )"
    if [[ "$remote_client_sha256" != "$client_sha256" ]]; then
        echo "remote dns-load-client digest does not match the local binary" >&2
        exit 1
    fi
fi

capture_local_snapshot() {
    local role="$1"
    local device="$2"
    local label="$3"
    local directory="$artifact_dir/network/$role"
    cp /proc/net/dev "$directory/proc-net-dev-$label.txt"
    cp /proc/stat "$directory/proc-stat-$label.txt"
    cp /proc/softirqs "$directory/proc-softirqs-$label.txt"
    cp /proc/interrupts "$directory/proc-interrupts-$label.txt"
    cp /proc/net/snmp "$directory/proc-net-snmp-$label.txt"
    cp /proc/net/netstat "$directory/proc-net-netstat-$label.txt"
    cp /proc/net/softnet_stat "$directory/proc-net-softnet-stat-$label.txt"
    cp /proc/net/udp "$directory/proc-net-udp-$label.txt"
    cp /proc/net/udp6 "$directory/proc-net-udp6-$label.txt"
    if command -v ss >/dev/null 2>&1; then
        ss -u -a -n -m >"$directory/ss-udp-$label.txt" 2>&1 || true
    fi
    {
        date -u '+date_utc=%Y-%m-%dT%H:%M:%SZ'
        uname -a
        ip route get "$server_address" || true
        ip -s link show dev "$device" || true
    } >"$directory/network-$label.txt" 2>&1
    if command -v ethtool >/dev/null 2>&1; then
        ethtool -S "$device" >"$directory/ethtool-$label.txt" 2>&1 || true
    fi
}

capture_remote_snapshot() {
    local role="$1"
    local target="$2"
    local device="$3"
    local label="$4"
    local directory="$artifact_dir/network/$role"
    ssh "${ssh_options[@]}" "$target" cat /proc/net/dev \
        >"$directory/proc-net-dev-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/stat \
        >"$directory/proc-stat-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/softirqs \
        >"$directory/proc-softirqs-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/interrupts \
        >"$directory/proc-interrupts-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/net/snmp \
        >"$directory/proc-net-snmp-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/net/netstat \
        >"$directory/proc-net-netstat-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/net/softnet_stat \
        >"$directory/proc-net-softnet-stat-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/net/udp \
        >"$directory/proc-net-udp-$label.txt"
    ssh "${ssh_options[@]}" "$target" cat /proc/net/udp6 \
        >"$directory/proc-net-udp6-$label.txt"
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$target" \
        "if command -v ss >/dev/null 2>&1; then ss -u -a -n -m; fi" \
        >"$directory/ss-udp-$label.txt" 2>&1 || true
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$target" \
        "date -u '+date_utc=%Y-%m-%dT%H:%M:%SZ'; uname -a; ip route get $(printf '%q' "$server_address"); ip -s link show dev $(printf '%q' "$device")" \
        >"$directory/network-$label.txt" 2>&1
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$target" \
        "if command -v ethtool >/dev/null 2>&1; then ethtool -S $(printf '%q' "$device"); fi" \
        >"$directory/ethtool-$label.txt" 2>&1 || true
}

capture_remote_client_snapshot() {
    local label="$1"
    capture_remote_snapshot client "$remote_ssh" "$client_device" "$label"
}

capture_snapshot() {
    local label="$1"
    if [[ -n "$server_ssh" ]]; then
        capture_remote_snapshot server "$server_ssh" "$server_device" "$label"
    else
        capture_local_snapshot server "$server_device" "$label"
    fi
    if [[ "$mode" == "ssh" ]]; then
        capture_remote_client_snapshot "$label"
    else
        capture_local_snapshot client "$client_device" "$label"
    fi
}

capture_metrics() {
    local label="$1"
    [[ -n "$metrics_url" ]] || return 0
    if [[ -n "$server_ssh" ]]; then
        # shellcheck disable=SC2029
        ssh "${ssh_options[@]}" "$server_ssh" \
            "curl --fail --silent --show-error --connect-timeout $(printf '%q' "$http_connect_timeout") --max-time $(printf '%q' "$http_max_time") $(printf '%q' "$metrics_url")" \
            >"$artifact_dir/metrics-$label.prom"
    else
        curl --fail --silent --show-error \
            --connect-timeout "$http_connect_timeout" \
            --max-time "$http_max_time" \
            "$metrics_url" >"$artifact_dir/metrics-$label.prom"
    fi
}

base_client_args=(
    --transport udp
    --server "$server_address"
    --port "$server_port"
    --bind "$client_bind"
    --threads "$client_threads"
    --udp-sockets-per-thread "$client_sockets_per_thread"
    --window "$client_window"
    --names "$names_per_zone"
    --timeout-ms "$client_timeout_ms"
    --random
)

quote_command() {
    local quoted
    printf -v quoted '%q ' "$@"
    printf '%s' "$quoted"
}

run_client_phase() {
    local label="$1"
    local seconds="$2"
    local target_qps="$3"
    local log="$artifact_dir/$label.log"
    local args=("${base_client_args[@]}" --duration "$seconds")
    if ((target_qps > 0)); then
        args+=(--target-qps "$target_qps")
    fi
    capture_snapshot "$label-before"
    capture_metrics "$label-before"
    if [[ "$mode" == "local" ]]; then
        args+=(--trace "$trace_file")
        if [[ -n "$client_cpu_list" ]]; then
            taskset -c "$client_cpu_list" "$client_bin" "${args[@]}" | tee "$log"
        else
            "$client_bin" "${args[@]}" | tee "$log"
        fi
    else
        args+=(--trace "$remote_trace_file")
        remote_command=("$remote_client_bin" "${args[@]}")
        if [[ -n "$client_cpu_list" ]]; then
            remote_command=(taskset -c "$client_cpu_list" "${remote_command[@]}")
        fi
        # shellcheck disable=SC2029
        ssh "${ssh_options[@]}" "$remote_ssh" \
            "$(quote_command "${remote_command[@]}")" | tee "$log"
    fi
    capture_metrics "$label-after"
    capture_snapshot "$label-after"
}

cat >"$artifact_dir/run.env" <<EOF
profile=$profile
origin=$origin
zones=$zones
names_per_zone=$names_per_zone
server_address=$server_address
server_port=$server_port
server_device=$server_device
server_ssh=${server_ssh:-none}
mode=$mode
client_bind=$client_bind
client_device=$client_device
remote_ssh=${remote_ssh:-none}
warmup_seconds=$warmup_seconds
duration_seconds=$duration_seconds
repetitions=$repetitions
target_qps_steps=$target_qps_steps
client_threads=$client_threads
client_window=$client_window
client_sockets_per_thread=$client_sockets_per_thread
client_timeout_ms=$client_timeout_ms
client_cpu_list=${client_cpu_list:-none}
max_drop_permille=$max_drop_permille
client_sha256=$client_sha256
trace_sha256=$trace_sha256
analyzer_sha256=$analyzer_sha256
EOF

warmup_target="${target_qps_values[-1]}"
if ((warmup_target == 0)); then
    warmup_label="warmup-unlimited"
else
    printf -v warmup_label 'warmup-qps-%012d' "$warmup_target"
fi
run_client_phase "$warmup_label" "$warmup_seconds" "$warmup_target"
for target_qps in "${target_qps_values[@]}"; do
    if ((target_qps == 0)); then
        step_label="unlimited"
    else
        printf -v step_label 'qps-%012d' "$target_qps"
    fi
    for ((repetition = 1; repetition <= repetitions; repetition++)); do
        printf -v label '%s-repetition-%03d' "$step_label" "$repetition"
        run_client_phase "$label" "$duration_seconds" "$target_qps"
    done
done

analysis_status=0
"$performance_analyzer" \
    "$artifact_dir" \
    "$repetitions" \
    "$target_qps_steps" \
    "$server_device" \
    "$client_device" \
    "$mode" \
    "$max_drop_permille" || analysis_status=$?

cleanup_remote
(
    cd "$artifact_dir"
    sha256sum \
        query-trace.tsv \
        run.env \
        performance-results.tsv \
        performance-summary.json \
        performance-acceptance.json \
        >evidence.sha256
)
if ((analysis_status != 0)); then
    printf 'BoronGen query performance acceptance failed; evidence retained: %s\n' \
        "$artifact_dir" >&2
    exit "$analysis_status"
fi
printf 'BoronGen query performance completed; evidence: %s\n' "$artifact_dir"
