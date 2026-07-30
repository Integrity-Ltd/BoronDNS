#!/usr/bin/env bash
set -euo pipefail

for tool in cargo curl dig git jq journalctl python3 sha256sum systemctl systemd-run; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 69
    fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_dir="${BORON_LOAD_ARTIFACT_DIR:-$repo_root/target/evidence/boron-gen-bounded-load-$timestamp}"
workdir=""
unit_suffix="${timestamp,,}-$$"
generator_unit="boron-gen-load-$unit_suffix.service"
server_unit="borondns-load-$unit_suffix.service"
slice_suffix="${timestamp,,}p$$"

profile="${BORON_LOAD_PROFILE:-registry-nsec3}"
zones="${BORON_LOAD_ZONES:-1}"
names_per_zone="${BORON_LOAD_NAMES_PER_ZONE:-10000}"
nsec3_records_per_zone="${BORON_LOAD_NSEC3_RECORDS_PER_ZONE:-$names_per_zone}"
records_per_name="${BORON_LOAD_RECORDS_PER_NAME:-4}"
origin="${BORON_LOAD_ORIGIN:-load.borongen.}"
catalog_origin="${BORON_LOAD_CATALOG_ORIGIN:-catalog.borongen.}"
generator_listen="${BORON_LOAD_GENERATOR_LISTEN:-127.0.0.1:15353}"
dns_listen="${BORON_LOAD_DNS_LISTEN:-127.0.0.1:15300}"
health_listen="${BORON_LOAD_HEALTH_LISTEN:-127.0.0.1:18081}"
message_bytes="${BORON_LOAD_MESSAGE_BYTES:-60000}"
transfer_bytes="${BORON_LOAD_MAX_TRANSFER_BYTES:-25769803776}"
transfer_messages="${BORON_LOAD_MAX_TRANSFER_MESSAGES:-1000000}"
ready_timeout="${BORON_LOAD_READY_TIMEOUT_SECONDS:-7200}"
hold_seconds="${BORON_LOAD_HOLD_SECONDS:-60}"
query_packets="${BORON_LOAD_QUERY_PACKETS:-10000}"
query_target_qps="${BORON_LOAD_QUERY_TARGET_QPS:-20000}"
http_connect_timeout="${BORON_LOAD_HTTP_CONNECT_TIMEOUT_SECONDS:-2}"
http_max_time="${BORON_LOAD_HTTP_MAX_TIME_SECONDS:-10}"
quiescence_enabled="${BORON_LOAD_QUIESCENCE_ENABLED:-true}"
quiescence_window="${BORON_LOAD_QUIESCENCE_WINDOW_SECONDS:-30}"
quiescence_timeout="${BORON_LOAD_QUIESCENCE_TIMEOUT_SECONDS:-600}"
stable_memory_delta_bytes="${BORON_LOAD_STABLE_MEMORY_DELTA_BYTES:-268435456}"
minimum_available_bytes="${BORON_LOAD_MIN_AVAILABLE_BYTES:-4294967296}"
minimum_cgroup_headroom_bytes="${BORON_LOAD_MIN_CGROUP_HEADROOM_BYTES:-8589934592}"
maximum_idle_cpu_percent="${BORON_LOAD_MAX_IDLE_CPU_PERCENT:-10}"
maximum_memory_pressure_avg10="${BORON_LOAD_MAX_MEMORY_PRESSURE_AVG10:-10}"
performance_mode="${BORON_LOAD_PERFORMANCE_MODE:-off}"
performance_server_address="${BORON_LOAD_PERFORMANCE_SERVER_ADDRESS:-}"
performance_server_device="${BORON_LOAD_PERFORMANCE_SERVER_DEVICE:-auto}"
performance_client_bind="${BORON_LOAD_PERFORMANCE_CLIENT_BIND:-}"
performance_client_source_cidr="${BORON_LOAD_PERFORMANCE_CLIENT_SOURCE_CIDR:-}"
performance_client_device="${BORON_LOAD_PERFORMANCE_CLIENT_DEVICE:-auto}"
performance_remote_ssh="${BORON_LOAD_PERFORMANCE_REMOTE_SSH:-}"
performance_remote_workdir="${BORON_LOAD_PERFORMANCE_REMOTE_WORKDIR:-}"
performance_warmup="${BORON_LOAD_PERFORMANCE_WARMUP_SECONDS:-15}"
performance_duration="${BORON_LOAD_PERFORMANCE_DURATION_SECONDS:-60}"
performance_repetitions="${BORON_LOAD_PERFORMANCE_REPETITIONS:-3}"
performance_client_threads="${BORON_LOAD_PERFORMANCE_CLIENT_THREADS:-32}"
performance_client_window="${BORON_LOAD_PERFORMANCE_CLIENT_WINDOW:-256}"
performance_client_sockets="${BORON_LOAD_PERFORMANCE_CLIENT_SOCKETS_PER_THREAD:-4}"
performance_client_timeout_ms="${BORON_LOAD_PERFORMANCE_CLIENT_TIMEOUT_MS:-1000}"
performance_client_cpu_list="${BORON_LOAD_PERFORMANCE_CLIENT_CPU_LIST:-}"
performance_max_drop_permille="${BORON_LOAD_PERFORMANCE_MAX_DROP_PERMILLE:-100}"
performance_external_timeout="${BORON_LOAD_PERFORMANCE_EXTERNAL_TIMEOUT_SECONDS:-7200}"
expected_outcome="${BORON_LOAD_EXPECT_OUTCOME:-ready}"
server_memory_high="${BORON_LOAD_MEMORY_HIGH:-30G}"
server_memory_max="${BORON_LOAD_MEMORY_MAX:-32G}"
generator_memory_high="${BORON_GEN_MEMORY_HIGH:-768M}"
generator_memory_max="${BORON_GEN_MEMORY_MAX:-1G}"
systemd_manager="${BORON_LOAD_SYSTEMD_MANAGER:-user}"
oomd_pressure_limit_percent="${BORON_LOAD_OOMD_PRESSURE_LIMIT_PERCENT:-80}"
load_slice="${BORON_LOAD_SYSTEMD_SLICE:-borondnsload${slice_suffix}.slice}"
tsig_name="boron-gen-load-key."
tsig_secret="Ym9yb24tZ2VuLWJvdW5kZWQtbG9hZC10ZXN0LWtleQ=="

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

for pair in \
    "BORON_LOAD_ZONES:$zones" \
    "BORON_LOAD_NAMES_PER_ZONE:$names_per_zone" \
    "BORON_LOAD_NSEC3_RECORDS_PER_ZONE:$nsec3_records_per_zone" \
    "BORON_LOAD_RECORDS_PER_NAME:$records_per_name" \
    "BORON_LOAD_MESSAGE_BYTES:$message_bytes" \
    "BORON_LOAD_MAX_TRANSFER_BYTES:$transfer_bytes" \
    "BORON_LOAD_MAX_TRANSFER_MESSAGES:$transfer_messages" \
    "BORON_LOAD_READY_TIMEOUT_SECONDS:$ready_timeout" \
    "BORON_LOAD_HOLD_SECONDS:$hold_seconds" \
    "BORON_LOAD_QUERY_PACKETS:$query_packets" \
    "BORON_LOAD_HTTP_CONNECT_TIMEOUT_SECONDS:$http_connect_timeout" \
    "BORON_LOAD_HTTP_MAX_TIME_SECONDS:$http_max_time" \
    "BORON_LOAD_QUIESCENCE_WINDOW_SECONDS:$quiescence_window" \
    "BORON_LOAD_QUIESCENCE_TIMEOUT_SECONDS:$quiescence_timeout" \
    "BORON_LOAD_PERFORMANCE_WARMUP_SECONDS:$performance_warmup" \
    "BORON_LOAD_PERFORMANCE_DURATION_SECONDS:$performance_duration" \
    "BORON_LOAD_PERFORMANCE_REPETITIONS:$performance_repetitions" \
    "BORON_LOAD_PERFORMANCE_CLIENT_THREADS:$performance_client_threads" \
    "BORON_LOAD_PERFORMANCE_CLIENT_WINDOW:$performance_client_window" \
    "BORON_LOAD_PERFORMANCE_CLIENT_SOCKETS_PER_THREAD:$performance_client_sockets" \
    "BORON_LOAD_PERFORMANCE_CLIENT_TIMEOUT_MS:$performance_client_timeout_ms" \
    "BORON_LOAD_PERFORMANCE_EXTERNAL_TIMEOUT_SECONDS:$performance_external_timeout"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
if ! [[ "$query_target_qps" =~ ^[0-9]+$ ]]; then
    printf 'BORON_LOAD_QUERY_TARGET_QPS must be a non-negative integer, got %q\n' \
        "$query_target_qps" >&2
    exit 64
fi
for pair in \
    "BORON_LOAD_STABLE_MEMORY_DELTA_BYTES:$stable_memory_delta_bytes" \
    "BORON_LOAD_MIN_AVAILABLE_BYTES:$minimum_available_bytes" \
    "BORON_LOAD_MIN_CGROUP_HEADROOM_BYTES:$minimum_cgroup_headroom_bytes" \
    "BORON_LOAD_MAX_IDLE_CPU_PERCENT:$maximum_idle_cpu_percent" \
    "BORON_LOAD_MAX_MEMORY_PRESSURE_AVG10:$maximum_memory_pressure_avg10" \
    "BORON_LOAD_PERFORMANCE_MAX_DROP_PERMILLE:$performance_max_drop_permille"; do
    if ! [[ "${pair#*:}" =~ ^[0-9]+$ ]]; then
        printf '%s must be a non-negative integer, got %q\n' \
            "${pair%%:*}" "${pair#*:}" >&2
        exit 64
    fi
done
if ((performance_max_drop_permille > 1000)); then
    printf 'BORON_LOAD_PERFORMANCE_MAX_DROP_PERMILLE must be at most 1000\n' >&2
    exit 64
fi
case "$quiescence_enabled" in
true | false) ;;
*)
    printf 'BORON_LOAD_QUIESCENCE_ENABLED must be true or false\n' >&2
    exit 64
    ;;
esac
case "$performance_mode" in
off | local | ssh | external) ;;
*)
    printf 'BORON_LOAD_PERFORMANCE_MODE must be off, local, ssh, or external\n' >&2
    exit 64
    ;;
esac
if [[ -n "$performance_client_cpu_list" &&
    ! "$performance_client_cpu_list" =~ ^[0-9,-]+$ ]]; then
    printf 'BORON_LOAD_PERFORMANCE_CLIENT_CPU_LIST must contain only CPU numbers, commas, and ranges\n' >&2
    exit 64
fi

case "$profile" in
registry-nsec3 | mixed | large-rrset) ;;
*)
    printf 'BORON_LOAD_PROFILE must be registry-nsec3, mixed, or large-rrset\n' >&2
    exit 64
    ;;
esac

case "$expected_outcome" in
ready | contained-oom) ;;
*)
    printf 'BORON_LOAD_EXPECT_OUTCOME must be ready or contained-oom\n' >&2
    exit 64
    ;;
esac

case "$systemd_manager" in
user | system) ;;
*)
    printf 'BORON_LOAD_SYSTEMD_MANAGER must be user or system\n' >&2
    exit 64
    ;;
esac
if ! [[ "$oomd_pressure_limit_percent" =~ ^[1-9][0-9]?$|^100$ ]]; then
    printf 'BORON_LOAD_OOMD_PRESSURE_LIMIT_PERCENT must be between 1 and 100, got %q\n' \
        "$oomd_pressure_limit_percent" >&2
    exit 64
fi
if [[ "$systemd_manager" == "system" ]]; then
    if ! [[ "$load_slice" =~ ^borondnsload[A-Za-z0-9_.@]+[.]slice$ ]]; then
        printf 'BORON_LOAD_SYSTEMD_SLICE must be a dedicated borondnsload*.slice unit, got %q\n' \
            "$load_slice" >&2
        exit 64
    fi
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
        echo "system-manager load units require non-interactive sudo" >&2
        exit 69
    fi
fi

generator_host="${generator_listen%:*}"
generator_port="${generator_listen##*:}"
dns_host="${dns_listen%:*}"
dns_port="${dns_listen##*:}"
health_host="${health_listen%:*}"
health_port="${health_listen##*:}"
performance_server_address="${performance_server_address:-$dns_host}"
if [[ -z "$performance_client_bind" ]]; then
    if [[ "$performance_mode" == "ssh" || "$performance_mode" == "external" ]]; then
        performance_client_bind="0.0.0.0:0"
    else
        performance_client_bind="127.0.0.1:0"
    fi
fi
if [[ -z "$performance_remote_workdir" ]]; then
    performance_remote_workdir="/tmp/borondns-boron-gen-perf-${timestamp,,}-$$"
fi
rrl_allowlist_entries='"127.0.0.0/8"'
if [[ "$dns_host" != "127.0.0.1" && "$dns_host" != "0.0.0.0" ]]; then
    if ! python3 - "$dns_host" <<'PY'; then
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError as error:
    raise SystemExit(f"invalid DNS listen address: {error}")
if address.version != 4:
    raise SystemExit("the bounded load harness currently requires IPv4 listeners")
PY
        exit 64
    fi
    rrl_allowlist_entries+=", \"$dns_host/32\""
fi
if [[ "$performance_mode" == "ssh" || "$performance_mode" == "external" ]]; then
    if [[ -z "$performance_client_source_cidr" ]]; then
        performance_client_address="${performance_client_bind%:*}"
        if [[ "$performance_client_address" == "0.0.0.0" ]]; then
            printf 'SSH performance mode requires BORON_LOAD_PERFORMANCE_CLIENT_SOURCE_CIDR when the client bind is wildcard\n' >&2
            exit 64
        fi
        performance_client_source_cidr="$performance_client_address/32"
    fi
    if ! python3 - "$performance_client_source_cidr" <<'PY'; then
import ipaddress
import sys

try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError as error:
    raise SystemExit(f"invalid performance client source CIDR: {error}")
PY
        exit 64
    fi
    rrl_allowlist_entries+=", \"$performance_client_source_cidr\""
fi
rrl_allowlist="[$rrl_allowlist_entries]"
for pair in \
    "generator port:$generator_port" \
    "DNS port:$dns_port" \
    "health port:$health_port"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
if [[ "$performance_mode" == "ssh" &&
    (-z "$performance_remote_ssh" || "$performance_remote_ssh" =~ [[:space:]]) ]]; then
    printf 'BORON_LOAD_PERFORMANCE_REMOTE_SSH is required in SSH performance mode\n' >&2
    exit 64
fi

http_get() {
    curl --fail --silent --show-error \
        --connect-timeout "$http_connect_timeout" \
        --max-time "$http_max_time" \
        "$@"
}

systemctl_load() {
    if [[ "$systemd_manager" == "system" ]]; then
        sudo -n systemctl "$@"
    else
        systemctl --user "$@"
    fi
}

journal_load_unit() {
    local unit="$1"
    if [[ "$systemd_manager" == "system" ]]; then
        sudo -n journalctl -u "$unit" --no-pager
    else
        journalctl --user-unit "$unit" --no-pager
    fi
}

unit_property() {
    local unit="$1"
    local property="$2"
    systemctl_load show "$unit" -p "$property" --value 2>/dev/null || true
}

wait_for_quiescence() {
    local deadline cgroup_path pressure_path attempt
    local start_memory end_memory start_cpu end_cpu start_time end_time
    local available memory_max pressure_avg10 evaluation evaluation_status
    local summary_path="$artifact_dir/quiescence-summary.json"
    local samples_path="$artifact_dir/quiescence-samples.tsv"

    if [[ "$quiescence_enabled" != "true" ]]; then
        printf '{"status":"disabled"}\n' >"$summary_path"
        return 0
    fi
    cgroup_path="$(unit_property "$server_unit" ControlGroup)"
    pressure_path="/sys/fs/cgroup$cgroup_path/memory.pressure"
    if [[ -z "$cgroup_path" || ! -r "$pressure_path" ]]; then
        failure_reason="cannot inspect the BoronDNS cgroup for quiescence"
        return 1
    fi
    printf 'attempt\tstart_unix\tend_unix\tmemory_start\tmemory_end\tmemory_delta_abs\tmemory_headroom\tmem_available\tcpu_percent\tmemory_pressure_full_avg10\tstable\n' \
        >"$samples_path"
    deadline=$((SECONDS + quiescence_timeout))
    attempt=0
    while ((SECONDS < deadline)); do
        if ! systemctl_load is-active --quiet "$server_unit"; then
            failure_reason="BoronDNS stopped while waiting for a quiescent measurement window"
            return 1
        fi
        attempt=$((attempt + 1))
        start_memory="$(unit_property "$server_unit" MemoryCurrent)"
        start_cpu="$(unit_property "$server_unit" CPUUsageNSec)"
        start_time="$(date +%s)"
        sleep "$quiescence_window"
        end_time="$(date +%s)"
        end_memory="$(unit_property "$server_unit" MemoryCurrent)"
        end_cpu="$(unit_property "$server_unit" CPUUsageNSec)"
        memory_max="$(unit_property "$server_unit" MemoryMax)"
        available="$(
            awk '$1 == "MemAvailable:" { printf "%.0f\n", $2 * 1024; exit }' \
                /proc/meminfo
        )"
        pressure_avg10="$(
            awk '
                $1 == "full" {
                    for (i = 2; i <= NF; i++) {
                        if ($i ~ /^avg10=/) {
                            sub(/^avg10=/, "", $i)
                            print $i
                            exit
                        }
                    }
                }
            ' "$pressure_path"
        )"
        set +e
        evaluation="$(
            python3 - \
                "$attempt" \
                "$start_time" "$end_time" \
                "$start_memory" "$end_memory" \
                "$start_cpu" "$end_cpu" \
                "$memory_max" "$available" "${pressure_avg10:-0}" \
                "$stable_memory_delta_bytes" \
                "$minimum_cgroup_headroom_bytes" \
                "$minimum_available_bytes" \
                "$maximum_idle_cpu_percent" \
                "$maximum_memory_pressure_avg10" <<'PY'
import json
import math
import sys

(
    attempt,
    start_time,
    end_time,
    start_memory,
    end_memory,
    start_cpu,
    end_cpu,
    memory_max,
    available,
    pressure,
    maximum_delta,
    minimum_headroom,
    minimum_available,
    maximum_cpu,
    maximum_pressure,
) = sys.argv[1:]
values = [
    start_time,
    end_time,
    start_memory,
    end_memory,
    start_cpu,
    end_cpu,
    memory_max,
    available,
    maximum_delta,
    minimum_headroom,
    minimum_available,
    maximum_cpu,
    maximum_pressure,
]
if not all(value.isdigit() for value in values):
    raise SystemExit("systemd returned a non-numeric quiescence property")
start_time_i, end_time_i = int(start_time), int(end_time)
start_memory_i, end_memory_i = int(start_memory), int(end_memory)
start_cpu_i, end_cpu_i = int(start_cpu), int(end_cpu)
memory_max_i, available_i = int(memory_max), int(available)
elapsed = max(1, end_time_i - start_time_i)
memory_delta = abs(end_memory_i - start_memory_i)
headroom = max(0, memory_max_i - end_memory_i)
cpu_percent = max(0.0, (end_cpu_i - start_cpu_i) / (elapsed * 10_000_000.0))
pressure_f = float(pressure)
checks = {
    "memory_delta": memory_delta <= int(maximum_delta),
    "memory_headroom": headroom >= int(minimum_headroom),
    "host_available": available_i >= int(minimum_available),
    "cpu_idle": cpu_percent <= int(maximum_cpu),
    "memory_pressure": pressure_f <= int(maximum_pressure),
}
stable = all(checks.values())
row = [
    attempt,
    start_time,
    end_time,
    start_memory,
    end_memory,
    str(memory_delta),
    str(headroom),
    available,
    f"{cpu_percent:.3f}",
    f"{pressure_f:.2f}",
    "true" if stable else "false",
]
print("\t".join(row))
report = {
    "status": "stable" if stable else "not_stable",
    "attempt": int(attempt),
    "window_seconds": elapsed,
    "memory_start_bytes": start_memory_i,
    "memory_end_bytes": end_memory_i,
    "memory_delta_abs_bytes": memory_delta,
    "memory_headroom_bytes": headroom,
    "host_mem_available_bytes": available_i,
    "cpu_percent_of_one_core": cpu_percent,
    "memory_pressure_full_avg10": pressure_f,
    "checks": checks,
}
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if stable else 1)
PY
        )"
        evaluation_status=$?
        set -e
        printf '%s\n' "$(sed -n '1p' <<<"$evaluation")" >>"$samples_path"
        printf '%s\n' "$(sed -n '2p' <<<"$evaluation")" >"$summary_path"
        if ((evaluation_status == 0)); then
            return 0
        fi
    done
    failure_reason="BoronDNS did not reach the configured stable-memory, headroom, CPU, and pressure thresholds within ${quiescence_timeout}s"
    return 1
}

check_oomd_limit_not_lower() {
    local unit="$1"
    local pressure raw requested_raw
    pressure="$(systemctl show -p ManagedOOMMemoryPressure --value -- "$unit" 2>/dev/null || true)"
    [[ "$pressure" == "kill" ]] || return 0
    raw="$(systemctl show -p ManagedOOMMemoryPressureLimit --value -- "$unit" 2>/dev/null || true)"
    [[ "$raw" =~ ^[0-9]+$ ]] || return 0
    requested_raw=$((oomd_pressure_limit_percent * 4294967296 / 100))
    if ((raw < requested_raw)); then
        printf 'ancestor %s has a lower systemd-oomd pressure limit than the requested leaf: raw=%s requested=%s%%\n' \
            "$unit" "$raw" "$oomd_pressure_limit_percent" >&2
        return 1
    fi
}

start_load_unit() {
    local unit="$1"
    shift
    if [[ "$systemd_manager" == "system" ]]; then
        sudo -n systemd-run \
            --unit "$unit" \
            --slice "$load_slice" \
            --uid "$(id -un)" \
            --gid "$(id -gn)" \
            "$@"
    else
        systemd-run --user --unit "$unit" "$@"
    fi
}

write_failure_summary() {
    local status="$1"
    local server_result server_status server_peak generator_peak summary_status
    [[ -s "$artifact_dir/run-summary.json" ]] && return 0
    server_result="$(unit_property "$server_unit" Result)"
    server_status="$(unit_property "$server_unit" ExecMainStatus)"
    server_peak="$(unit_property "$server_unit" MemoryPeak)"
    generator_peak="$(unit_property "$generator_unit" MemoryPeak)"
    summary_status="harness_failed"
    if [[ "$server_result" == "oom-kill" && "$expected_outcome" == "ready" ]]; then
        summary_status="contained_oom_unexpected"
    elif [[ "$failure_reason" == deterministic\ publication\ failure:* ]]; then
        summary_status="deterministic_publication_failure"
    elif [[ "$failure_stage" == "readiness-timeout" ]]; then
        summary_status="readiness_timeout"
    fi
    python3 - \
        "$artifact_dir/scenario-manifest.json" \
        "$artifact_dir/run-summary.json" \
        "$summary_status" \
        "$status" \
        "$failure_stage" \
        "${failure_reason:-$failure_stage failed}" \
        "$server_result" \
        "$server_status" \
        "$server_peak" \
        "$generator_peak" \
        "$SECONDS" \
        "$server_memory_high" \
        "$server_memory_max" \
        "$systemd_manager" \
        "$load_slice" \
        "$oomd_pressure_limit_percent" <<'PY'
import json
import pathlib
import sys

(
    manifest_path,
    output_path,
    status,
    exit_status,
    stage,
    reason,
    server_result,
    server_exit_status,
    server_memory_peak,
    generator_memory_peak,
    elapsed_seconds,
    memory_high,
    memory_max,
    systemd_manager,
    load_slice,
    oomd_pressure_limit_percent,
) = sys.argv[1:]

def optional_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

manifest_file = pathlib.Path(manifest_path)
scenario = None
if manifest_file.is_file():
    with manifest_file.open(encoding="utf-8") as source:
        scenario = json.load(source)
summary = {
    "status": status,
    "scenario": scenario,
    "failure": {
        "stage": stage,
        "reason": reason,
        "harness_exit_status": int(exit_status),
    },
    "server_result": server_result or None,
    "server_exit_status": optional_int(server_exit_status),
    "observed": {
        "server_memory_peak_bytes": optional_int(server_memory_peak),
        "generator_memory_peak_bytes": optional_int(generator_memory_peak),
        "elapsed_seconds": int(elapsed_seconds),
    },
    "containment": {
        "cgroup_version": 2,
        "memory_high": memory_high,
        "memory_max": memory_max,
        "memory_swap_max": 0,
        "systemd_oomd_required": True,
        "systemd_manager": systemd_manager,
        "slice": load_slice if systemd_manager == "system" else None,
        "pressure_limit_percent": int(oomd_pressure_limit_percent),
    },
}
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}

resource_sampler_pid=""
slice_started=false
failure_stage="preflight"
failure_reason=""
mkdir -p "$artifact_dir"
workdir="$(mktemp -d -t "boron-gen-bounded-load-$timestamp-XXXXXX")"
chmod 700 "$workdir" "$artifact_dir"
cleanup() {
    local status=$?
    local cgroup_path slice_cgroup_path
    trap - EXIT INT TERM
    if [[ -n "$resource_sampler_pid" ]] && kill -0 "$resource_sampler_pid" 2>/dev/null; then
        kill "$resource_sampler_pid" 2>/dev/null || true
        wait "$resource_sampler_pid" 2>/dev/null || true
    fi
    for unit in "$server_unit" "$generator_unit"; do
        systemctl_load show "$unit" >"$artifact_dir/${unit%.service}-unit-final.txt" 2>&1 || true
        journal_load_unit "$unit" >"$artifact_dir/${unit%.service}.log" 2>&1 || true
        cgroup_path="$(unit_property "$unit" ControlGroup)"
        if [[ -n "$cgroup_path" && -r "/sys/fs/cgroup$cgroup_path/memory.events" ]]; then
            cp "/sys/fs/cgroup$cgroup_path/memory.events" \
                "$artifact_dir/${unit%.service}-memory.events" || true
            cp "/sys/fs/cgroup$cgroup_path/memory.pressure" \
                "$artifact_dir/${unit%.service}-memory.pressure" || true
        fi
    done
    if [[ -s "$artifact_dir/${server_unit%.service}.log" &&
        -s "$artifact_dir/resource-samples.tsv" ]]; then
        python3 "$repo_root/scripts/summarize-boron-gen-publication-memory.py" \
            --journal "$artifact_dir/${server_unit%.service}.log" \
            --samples "$artifact_dir/resource-samples.tsv" \
            --output "$artifact_dir/publication-memory-phases.tsv" || true
    fi
    if [[ "$slice_started" == "true" ]]; then
        systemctl_load show "$load_slice" \
            >"$artifact_dir/${load_slice%.slice}-slice-final.txt" 2>&1 || true
        slice_cgroup_path="$(
            sudo -n systemctl show "$load_slice" -p ControlGroup --value 2>/dev/null || true
        )"
        if [[ -n "$slice_cgroup_path" &&
            -r "/sys/fs/cgroup$slice_cgroup_path/memory.pressure" ]]; then
            cp "/sys/fs/cgroup$slice_cgroup_path/memory.pressure" \
                "$artifact_dir/${load_slice%.slice}-memory.pressure" || true
        fi
    fi
    if ((status != 0)); then
        write_failure_summary "$status" || true
    fi
    for unit in "$server_unit" "$generator_unit"; do
        systemctl_load stop "$unit" >/dev/null 2>&1 || true
        systemctl_load reset-failed "$unit" >/dev/null 2>&1 || true
    done
    if [[ "$slice_started" == "true" ]]; then
        sudo -n systemctl stop "$load_slice" >/dev/null 2>&1 || true
        sudo -n systemctl reset-failed "$load_slice" >/dev/null 2>&1 || true
    fi
    printf '%s\n' "$status" >"$artifact_dir/exit-status"
    if ((status == 0)); then
        rm -rf -- "$workdir"
    else
        printf 'bounded load failed; retained workdir: %s\n' "$workdir" >&2
        printf '%s\n' "$workdir" >"$artifact_dir/retained-workdir"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

python3 - \
    "$generator_host" "$generator_port" \
    "$dns_host" "$dns_port" \
    "$health_host" "$health_port" <<'PY'
import socket
import sys

gen_host, gen_port, dns_host, dns_port, health_host, health_port = sys.argv[1:]
checks = [
    ("generator TCP", socket.SOCK_STREAM, gen_host, int(gen_port)),
    ("generator UDP", socket.SOCK_DGRAM, gen_host, int(gen_port)),
    ("BoronDNS TCP", socket.SOCK_STREAM, dns_host, int(dns_port)),
    ("BoronDNS UDP", socket.SOCK_DGRAM, dns_host, int(dns_port)),
    ("health TCP", socket.SOCK_STREAM, health_host, int(health_port)),
]
for label, kind, host, port in checks:
    sock = socket.socket(socket.AF_INET, kind)
    try:
        if kind == socket.SOCK_STREAM:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError as error:
        raise SystemExit(f"{label} address {host}:{port} is unavailable: {error}")
    finally:
        sock.close()
PY

if [[ "$performance_mode" == "local" || "$performance_mode" == "ssh" ]]; then
    if [[ ! -x "$repo_root/scripts/boron-gen-query-performance.sh" ]]; then
        echo "BoronGen performance harness is missing or not executable" >&2
        exit 69
    fi
    failure_stage="performance-preflight"
    BORON_GEN_PERF_PREFLIGHT_ONLY=true \
        BORON_GEN_PERF_PROFILE="$profile" \
        BORON_GEN_PERF_ORIGIN="$origin" \
        BORON_GEN_PERF_ZONES="$zones" \
        BORON_GEN_PERF_NAMES_PER_ZONE="$names_per_zone" \
        BORON_GEN_PERF_SERVER_ADDRESS="$performance_server_address" \
        BORON_GEN_PERF_SERVER_PORT="$dns_port" \
        BORON_GEN_PERF_SERVER_DEVICE="$performance_server_device" \
        BORON_GEN_PERF_MODE="$performance_mode" \
        BORON_GEN_PERF_CLIENT_BIND="$performance_client_bind" \
        BORON_GEN_PERF_CLIENT_DEVICE="$performance_client_device" \
        BORON_GEN_PERF_REMOTE_SSH="$performance_remote_ssh" \
        BORON_GEN_PERF_REMOTE_WORKDIR="$performance_remote_workdir" \
        BORON_GEN_PERF_WARMUP_SECONDS="$performance_warmup" \
        BORON_GEN_PERF_DURATION_SECONDS="$performance_duration" \
        BORON_GEN_PERF_REPETITIONS="$performance_repetitions" \
        BORON_GEN_PERF_CLIENT_THREADS="$performance_client_threads" \
        BORON_GEN_PERF_CLIENT_WINDOW="$performance_client_window" \
        BORON_GEN_PERF_CLIENT_SOCKETS_PER_THREAD="$performance_client_sockets" \
        BORON_GEN_PERF_CLIENT_TIMEOUT_MS="$performance_client_timeout_ms" \
        BORON_GEN_PERF_CLIENT_CPU_LIST="$performance_client_cpu_list" \
        BORON_GEN_PERF_MAX_DROP_PERMILLE="$performance_max_drop_permille" \
        "$repo_root/scripts/boron-gen-query-performance.sh" \
        >"$artifact_dir/performance-preflight.env"
fi

if [[ "$(stat -fc %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
    echo "cgroup v2 is required" >&2
    exit 69
fi
if ! systemctl is-active --quiet systemd-oomd.service; then
    echo "system systemd-oomd.service must be active" >&2
    exit 69
fi
failure_stage="containment-preflight"
if [[ "$systemd_manager" == "system" ]]; then
    if sudo -n systemctl is-active --quiet "$load_slice"; then
        printf 'dedicated load slice is already active: %s\n' "$load_slice" >&2
        exit 69
    fi
    sudo -n systemctl start "$load_slice"
    slice_started=true
    sudo -n systemctl set-property --runtime "$load_slice" \
        ManagedOOMMemoryPressure=kill \
        "ManagedOOMMemoryPressureLimit=$oomd_pressure_limit_percent%"
    check_oomd_limit_not_lower "$load_slice"
    check_oomd_limit_not_lower '-.slice'
else
    check_oomd_limit_not_lower "user@$(id -u).service"
    check_oomd_limit_not_lower "user-$(id -u).slice"
    check_oomd_limit_not_lower user.slice
    check_oomd_limit_not_lower '-.slice'
fi
if [[ "$systemd_manager" == "system" ]]; then
    containment_test=(
        sudo -n systemd-run
        --scope
        --quiet
        --slice "$load_slice"
        --uid "$(id -un)"
        --gid "$(id -gn)"
    )
else
    containment_test=(systemd-run --user --scope --quiet)
fi
if ! "${containment_test[@]}" \
    -p MemoryHigh=24M \
    -p MemoryMax=32M \
    -p MemorySwapMax=0 \
    -p ManagedOOMMemoryPressure=kill \
    -p "ManagedOOMMemoryPressureLimit=$oomd_pressure_limit_percent%" \
    true; then
    printf 'the %s manager cannot create a memory-bounded cgroup\n' \
        "$systemd_manager" >&2
    exit 69
fi

failure_stage="build"
cargo build --locked --release -p boron-gen -p boron-gun -p borondns-cli
generator_binary="$repo_root/target/release/boron-gen"
load_binary="$repo_root/target/release/boron-gun"
server_binary="$repo_root/target/release/borondns"
git -C "$repo_root" rev-parse HEAD >"$artifact_dir/source-commit.txt"
git -C "$repo_root" status --short >"$artifact_dir/source-status.txt"
git -C "$repo_root" diff --binary HEAD >"$artifact_dir/source-diff.patch"
while IFS= read -r -d '' source_path; do
    sha256sum "$repo_root/$source_path"
done < <(
    git -C "$repo_root" ls-files -z --modified --others --exclude-standard
) >"$artifact_dir/source-files.sha256"
sha256sum "$generator_binary" "$load_binary" "$server_binary" >"$artifact_dir/binaries.sha256"

"$generator_binary" manifest \
    --profile "$profile" \
    --origin "$origin" \
    --catalog-origin "$catalog_origin" \
    --zones "$zones" \
    --names-per-zone "$names_per_zone" \
    --records-per-name "$records_per_name" \
    --nsec3-records-per-zone "$nsec3_records_per_zone" \
    >"$artifact_dir/scenario-manifest.json"

cat >"$workdir/borondns.toml" <<EOF
[server]
log_level = "info"
log_format = "json"

[interfaces]
dns = [{ address = "$dns_host:$dns_port", name = "bounded-load" }]
mgmt = ["$health_host:$health_port"]
transfer = ["127.0.0.1:0"]

[health]
bind_address = "$health_host"
bind_port = $health_port
metrics_rate_limit_per_minute = 10000

[transfer]
require_tsig = true

[limits]
axfr_timeout_secs = 31536000
ixfr_timeout_secs = 31536000
tcp_connect_timeout_secs = 30
max_concurrent_transfers = 1
max_transfer_ingest_bytes = $transfer_bytes
max_transfer_ingest_messages = $transfer_messages
zsm_loading_warning_threshold_secs = 31536000

[rrl]
# The bounded query probe runs from loopback and measures the loaded-zone
# lookup path, not response-rate limiting. Keep RRL enabled for every other
# source while exempting only explicitly configured harness clients.
allowlist = $rrl_allowlist

[tsig]
fudge_seconds = 300

[[tsig_keys]]
name = "$tsig_name"
algorithm = "hmac-sha256"
secret = "$tsig_secret"

[[catalog_zones]]
name = "$catalog_origin"
primaries = ["$generator_host:$generator_port"]
notify_sources = ["$generator_host"]
tsig_key = "$tsig_name"
max_member_zones = $zones
EOF
chmod 600 "$workdir/borondns.toml"
"$server_binary" --validate-config "$workdir/borondns.toml" \
    >"$artifact_dir/config-validation.txt"

failure_stage="generator-start"
start_load_unit "$generator_unit" \
    --service-type exec \
    -p "MemoryHigh=$generator_memory_high" \
    -p "MemoryMax=$generator_memory_max" \
    -p MemorySwapMax=0 \
    -p OOMPolicy=stop \
    -p ManagedOOMMemoryPressure=kill \
    -p "ManagedOOMMemoryPressureLimit=$oomd_pressure_limit_percent%" \
    -p Restart=no \
    --setenv "BORON_GEN_TSIG_SECRET=$tsig_secret" \
    "$generator_binary" serve \
    --listen "$generator_listen" \
    --message-bytes "$message_bytes" \
    --max-connections 2 \
    --profile "$profile" \
    --origin "$origin" \
    --catalog-origin "$catalog_origin" \
    --zones "$zones" \
    --names-per-zone "$names_per_zone" \
    --records-per-name "$records_per_name" \
    --nsec3-records-per-zone "$nsec3_records_per_zone" \
    --tsig-name "$tsig_name" \
    --json-logs

for _ in {1..100}; do
    if systemctl_load is-active --quiet "$generator_unit"; then
        break
    fi
    sleep 0.1
done
systemctl_load is-active --quiet "$generator_unit"

failure_stage="server-start"
start_load_unit "$server_unit" \
    --service-type exec \
    -p "MemoryHigh=$server_memory_high" \
    -p "MemoryMax=$server_memory_max" \
    -p MemorySwapMax=0 \
    -p OOMPolicy=stop \
    -p ManagedOOMMemoryPressure=kill \
    -p "ManagedOOMMemoryPressureLimit=$oomd_pressure_limit_percent%" \
    -p Restart=no \
    -p LimitNOFILE=1048576 \
    "$server_binary" --config "$workdir/borondns.toml" serve

printf 'unix_seconds\tmemory_current\tmemory_peak\tmemory_high\tmemory_max\tn_restarts\tactive_state\tsub_state\n' \
    >"$artifact_dir/resource-samples.tsv"
(
    while true; do
        values="$(systemctl_load show "$server_unit" \
            -p MemoryCurrent \
            -p MemoryPeak \
            -p MemoryHigh \
            -p MemoryMax \
            -p NRestarts \
            -p ActiveState \
            -p SubState 2>/dev/null || true)"
        value_of() {
            local field="$1"
            awk -F= -v field="$field" '$1 == field { print $2 }' <<<"$values"
        }
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(date +%s)" \
            "$(value_of MemoryCurrent)" \
            "$(value_of MemoryPeak)" \
            "$(value_of MemoryHigh)" \
            "$(value_of MemoryMax)" \
            "$(value_of NRestarts)" \
            "$(value_of ActiveState)" \
            "$(value_of SubState)" \
            >>"$artifact_dir/resource-samples.tsv"
        sleep 5
    done
) &
resource_sampler_pid=$!

failure_stage="readiness"
deadline=$((SECONDS + ready_timeout))
while ((SECONDS < deadline)); do
    if ! systemctl_load is-active --quiet "$server_unit"; then
        if [[ "$expected_outcome" == "contained-oom" ]]; then
            server_result="$(unit_property "$server_unit" Result)"
            server_status="$(unit_property "$server_unit" ExecMainStatus)"
            if [[ "$server_result" != "oom-kill" || "$server_status" != "9" ]]; then
                failure_reason="BoronDNS stopped without the expected contained OOM: result=$server_result status=$server_status"
                printf 'BoronDNS stopped, but not through the expected contained OOM: result=%s status=%s\n' \
                    "$server_result" "$server_status" >&2
                exit 1
            fi
            if ! systemctl_load is-active --quiet "$generator_unit"; then
                failure_reason="BoronGen did not survive the contained BoronDNS OOM"
                echo "BoronGen did not survive the contained BoronDNS OOM" >&2
                exit 1
            fi
            python3 - \
                "$artifact_dir/scenario-manifest.json" \
                "$artifact_dir/run-summary.json" \
                "$server_memory_high" \
                "$server_memory_max" \
                "$server_result" \
                "$server_status" \
                "$(unit_property "$server_unit" MemoryPeak)" \
                "$(unit_property "$generator_unit" MemoryPeak)" \
                "$SECONDS" \
                "$systemd_manager" \
                "$load_slice" \
                "$oomd_pressure_limit_percent" <<'PY'
import json
import pathlib
import sys

(
    manifest_path,
    output_path,
    memory_high,
    memory_max,
    server_result,
    server_status,
    server_memory_peak,
    generator_memory_peak,
    elapsed_seconds,
    systemd_manager,
    load_slice,
    oomd_pressure_limit_percent,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)
summary = {
    "status": "contained_oom_as_expected",
    "scenario": manifest,
    "server_result": server_result,
    "server_exit_status": int(server_status),
    "generator_survived": True,
    "observed": {
        "server_memory_peak_bytes": int(server_memory_peak),
        "generator_memory_peak_bytes": int(generator_memory_peak),
        "elapsed_seconds": int(elapsed_seconds),
    },
    "containment": {
        "cgroup_version": 2,
        "memory_high": memory_high,
        "memory_max": memory_max,
        "memory_swap_max": 0,
        "systemd_oomd_required": True,
        "systemd_manager": systemd_manager,
        "slice": load_slice if systemd_manager == "system" else None,
        "pressure_limit_percent": int(oomd_pressure_limit_percent),
    },
}
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
PY
            printf 'contained BoronDNS OOM completed as expected; evidence: %s\n' "$artifact_dir"
            exit 0
        fi
        server_result="$(unit_property "$server_unit" Result)"
        server_status="$(unit_property "$server_unit" ExecMainStatus)"
        failure_reason="BoronDNS stopped before readiness: result=$server_result status=$server_status"
        echo "BoronDNS bounded unit stopped before readiness" >&2
        exit 1
    fi
    if publication_failure="$(
        journal_load_unit "$server_unit" |
            grep -E 'AXFR publication failed.*compact field capacity exceeded' |
            tail -n 1
    )"; then
        printf '%s\n' "$publication_failure" \
            >"$artifact_dir/deterministic-publication-failure.log"
        failure_reason="deterministic publication failure: $publication_failure"
        printf '%s\n' "$failure_reason" >&2
        exit 1
    fi
    if http_get \
        "http://$health_host:$health_port/readyz" \
        >"$artifact_dir/readyz.txt" 2>"$artifact_dir/readyz-errors.log"; then
        if jq -e \
            --argjson expected_zones "$zones" \
            '.status == "ready"
             and .zones_active == $expected_zones
             and .zones_loading == 0
             and .zones_expired == 0' \
            "$artifact_dir/readyz.txt" >/dev/null; then
            if [[ "$expected_outcome" != "ready" ]]; then
                failure_reason="BoronDNS became fully ready instead of producing expected outcome $expected_outcome"
                printf 'BoronDNS became ready instead of producing expected outcome %s\n' \
                    "$expected_outcome" >&2
                exit 1
            fi
            break
        fi
    fi
    sleep 2
done
if ((SECONDS >= deadline)); then
    failure_stage="readiness-timeout"
    failure_reason="timed out waiting for all $zones member zones to become active"
    echo "timed out waiting for BoronDNS readiness" >&2
    exit 1
fi

failure_stage="readiness-metrics-validation"
http_get \
    "http://$health_host:$health_port/metrics" \
    >"$artifact_dir/metrics-at-ready.prom"
python3 - "$artifact_dir/metrics-at-ready.prom" "$zones" <<'PY'
import re
import sys

metrics_path, expected_text = sys.argv[1:]
expected = int(expected_text)
active = None
completed_axfr = None
managed_members = 0
with open(metrics_path, encoding="utf-8") as source:
    for raw_line in source:
        line = raw_line.strip()
        if line.startswith("borondns_zones_active "):
            active = int(float(line.rsplit(None, 1)[1]))
        elif line.startswith(
            'borondns_transfer_sessions_completed_total{protocol="axfr"} '
        ):
            completed_axfr = int(float(line.rsplit(None, 1)[1]))
        elif (
            line.startswith("borondns_catalog_member_info{")
            and 'managed="true"' in line
            and re.search(r"\s1(?:\.0)?$", line)
        ):
            managed_members += 1
if active != expected:
    raise SystemExit(f"active-zone metric is {active}, expected {expected}")
if managed_members != expected:
    raise SystemExit(
        f"managed catalog-member metric count is {managed_members}, expected {expected}"
    )
if completed_axfr is None or completed_axfr < expected + 1:
    raise SystemExit(
        f"completed AXFR count is {completed_axfr}, expected at least {expected + 1}"
    )
PY

failure_stage="quiescence"
failure_reason="BoronDNS did not become quiescent enough for reproducible query measurement"
if ! wait_for_quiescence; then
    printf '%s\n' "$failure_reason" >&2
    exit 1
fi

failure_stage="dnssec-negative-probe"
if [[ "$zones" == "1" ]]; then
    first_member_origin="$origin"
else
    first_member_origin="z0000000000000000.$origin"
fi
negative_name="boron-gen-negative.$first_member_origin"
dig "@$dns_host" \
    -p "$dns_port" \
    "$negative_name" \
    A \
    +tcp \
    +dnssec \
    +noall \
    +comments \
    +authority \
    >"$artifact_dir/dnssec-negative-query.txt"
if ! grep -q 'status: NXDOMAIN' "$artifact_dir/dnssec-negative-query.txt"; then
    failure_reason="published member zone did not return NXDOMAIN for the negative lookup probe"
    echo "published member zone did not return NXDOMAIN for the negative lookup probe" >&2
    exit 1
fi
if [[ "$profile" == "registry-nsec3" ]] &&
    ! grep -q '[[:space:]]NSEC3[[:space:]]' "$artifact_dir/dnssec-negative-query.txt"; then
    failure_reason="registry-nsec3 member did not exercise the NSEC3 denial lookup path"
    echo "registry-nsec3 member did not exercise the NSEC3 denial lookup path" >&2
    exit 1
fi

query_payload_hex="$(
    python3 - "$negative_name" <<'PY'
import struct
import sys

name = sys.argv[1]
labels = name.rstrip(".").split(".")
qname = b"".join(bytes([len(label.encode("ascii"))]) + label.encode("ascii") for label in labels)
qname += b"\x00"
header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 1)
question = qname + struct.pack("!HH", 1, 1)
opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
print((header + question + opt).hex())
PY
)"
failure_stage="query-load"
failure_reason="BoronGun query load or response validation failed"
"$load_binary" \
    --target "$dns_host:$dns_port" \
    --query-payload-hex "$query_payload_hex" \
    --max-packets "$query_packets" \
    --target-qps "$query_target_qps" \
    --recv-mode process \
    --log-format json \
    --flush-interval-ms 0 \
    --response-timeout-ms 2000 \
    >"$artifact_dir/query-load-summary.json"
python3 - "$artifact_dir/query-load-summary.json" "$query_packets" <<'PY'
import json
import sys

path, expected_text = sys.argv[1:]
expected = int(expected_text)
with open(path, encoding="utf-8") as source:
    summary = json.load(source)
if summary.get("record_type") != "summary":
    raise SystemExit("BoronGun did not emit a summary record")
if summary.get("tx_packets_total") != expected:
    raise SystemExit(
        f"BoronGun sent {summary.get('tx_packets_total')} packets, expected {expected}"
    )
minimum_responses = (expected * 99 + 99) // 100
if summary.get("rx_dns_responses_total", 0) < minimum_responses:
    raise SystemExit(
        "BoronGun DNS response count fell below the 99% local-load threshold"
    )
negative_responses = (
    summary.get("nxdomain_total", 0) + summary.get("rx_truncated_total", 0)
)
if negative_responses < minimum_responses:
    raise SystemExit(
        "BoronGun NXDOMAIN plus valid truncated response count fell below "
        "the 99% local-load threshold"
    )
if summary.get("errors_total") != 0:
    raise SystemExit(f"BoronGun reported {summary.get('errors_total')} errors")
PY

if [[ "$performance_mode" == "local" || "$performance_mode" == "ssh" ]]; then
    failure_stage="query-performance"
    failure_reason="BoronGen two-host query performance phase failed"
    BORON_GEN_PERF_ARTIFACT_DIR="$artifact_dir/performance" \
        BORON_GEN_PERF_PROFILE="$profile" \
        BORON_GEN_PERF_ORIGIN="$origin" \
        BORON_GEN_PERF_ZONES="$zones" \
        BORON_GEN_PERF_NAMES_PER_ZONE="$names_per_zone" \
        BORON_GEN_PERF_SERVER_ADDRESS="$performance_server_address" \
        BORON_GEN_PERF_SERVER_PORT="$dns_port" \
        BORON_GEN_PERF_SERVER_DEVICE="$performance_server_device" \
        BORON_GEN_PERF_MODE="$performance_mode" \
        BORON_GEN_PERF_CLIENT_BIND="$performance_client_bind" \
        BORON_GEN_PERF_CLIENT_DEVICE="$performance_client_device" \
        BORON_GEN_PERF_REMOTE_SSH="$performance_remote_ssh" \
        BORON_GEN_PERF_REMOTE_WORKDIR="$performance_remote_workdir" \
        BORON_GEN_PERF_WARMUP_SECONDS="$performance_warmup" \
        BORON_GEN_PERF_DURATION_SECONDS="$performance_duration" \
        BORON_GEN_PERF_REPETITIONS="$performance_repetitions" \
        BORON_GEN_PERF_CLIENT_THREADS="$performance_client_threads" \
        BORON_GEN_PERF_CLIENT_WINDOW="$performance_client_window" \
        BORON_GEN_PERF_CLIENT_SOCKETS_PER_THREAD="$performance_client_sockets" \
        BORON_GEN_PERF_CLIENT_TIMEOUT_MS="$performance_client_timeout_ms" \
        BORON_GEN_PERF_CLIENT_CPU_LIST="$performance_client_cpu_list" \
        BORON_GEN_PERF_MAX_DROP_PERMILLE="$performance_max_drop_permille" \
        BORON_GEN_PERF_METRICS_URL="http://$health_host:$health_port/metrics" \
        BORON_GEN_PERF_HTTP_CONNECT_TIMEOUT_SECONDS="$http_connect_timeout" \
        BORON_GEN_PERF_HTTP_MAX_TIME_SECONDS="$http_max_time" \
        "$repo_root/scripts/boron-gen-query-performance.sh"
elif [[ "$performance_mode" == "external" ]]; then
    failure_stage="external-performance-request"
    failure_reason="external two-host performance coordinator did not complete"
    python3 - \
        "$artifact_dir/performance-request.json" \
        "$profile" "$origin" "$zones" "$names_per_zone" \
        "$performance_server_address" "$dns_port" "$performance_server_device" \
        "$performance_client_bind" "$performance_client_source_cidr" \
        "$performance_client_device" \
        "$performance_warmup" "$performance_duration" "$performance_repetitions" \
        "$performance_client_threads" "$performance_client_window" \
        "$performance_client_sockets" "$performance_client_timeout_ms" \
        "$performance_client_cpu_list" "$performance_max_drop_permille" \
        "$health_host" "$health_port" <<'PY'
import json
import sys

(
    output_path,
    profile,
    origin,
    zones,
    names_per_zone,
    server_address,
    server_port,
    server_device,
    client_bind,
    client_source_cidr,
    client_device,
    warmup_seconds,
    duration_seconds,
    repetitions,
    client_threads,
    client_window,
    client_sockets,
    client_timeout_ms,
    client_cpu_list,
    max_drop_permille,
    health_host,
    health_port,
) = sys.argv[1:]
request = {
    "format": "boron-gen-external-performance-request-v1",
    "profile": profile,
    "origin": origin,
    "zones": int(zones),
    "names_per_zone": int(names_per_zone),
    "server_address": server_address,
    "server_port": int(server_port),
    "server_device": server_device,
    "client_bind": client_bind,
    "client_source_cidr": client_source_cidr,
    "client_device": client_device,
    "warmup_seconds": int(warmup_seconds),
    "duration_seconds": int(duration_seconds),
    "repetitions": int(repetitions),
    "client_threads": int(client_threads),
    "client_window": int(client_window),
    "client_sockets_per_thread": int(client_sockets),
    "client_timeout_ms": int(client_timeout_ms),
    "client_cpu_list": client_cpu_list or None,
    "max_drop_permille": int(max_drop_permille),
    "metrics_url": f"http://{health_host}:{health_port}/metrics",
}
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(request, output, indent=2, sort_keys=True)
    output.write("\n")
PY
    external_deadline=$((SECONDS + performance_external_timeout))
    while [[ ! -f "$artifact_dir/performance-complete" ]]; do
        if ! systemctl_load is-active --quiet "$server_unit"; then
            failure_reason="BoronDNS stopped while waiting for external performance evidence"
            exit 1
        fi
        if ((SECONDS >= external_deadline)); then
            failure_reason="external performance coordinator timed out after ${performance_external_timeout}s"
            exit 1
        fi
        sleep 5
    done
    if [[ -L "$artifact_dir/performance" ||
        ! -s "$artifact_dir/performance/performance-summary.json" ||
        ! -s "$artifact_dir/performance/performance-results.tsv" ]]; then
        failure_reason="external performance completion marker lacks complete evidence"
        exit 1
    fi
    jq -e \
        --argjson expected_repetitions "$performance_repetitions" \
        '.format == "boron-gen-query-performance-v1"
         and (.repetitions | length) == $expected_repetitions' \
        "$artifact_dir/performance/performance-summary.json" >/dev/null
fi

failure_stage="hold"
failure_reason=""
sleep "$hold_seconds"

failure_stage="post-hold-metrics"
http_get \
    "http://$health_host:$health_port/metrics" \
    >"$artifact_dir/metrics-after-hold.prom"

python3 - \
    "$artifact_dir/metrics-after-hold.prom" \
    "$profile" \
    "$query_packets" <<'PY'
import sys

metrics_path, profile, expected_text = sys.argv[1:]
expected = int(expected_text)
metrics = {}
with open(metrics_path, encoding="utf-8") as source:
    for raw_line in source:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, value = line.rsplit(None, 1)
        metrics[name] = float(value)

if metrics.get("borondns_rrl_responses_dropped_total", 0) != 0:
    raise SystemExit("loopback lookup probe unexpectedly exercised RRL drops")
if profile == "registry-nsec3":
    metric = (
        'borondns_secondary_query_duration_seconds_count'
        '{query_category="dnssec_augmented"}'
    )
    if metrics.get(metric, 0) < expected:
        raise SystemExit(
            "DNSSEC-augmented query metric did not account for the bounded load probe"
        )
PY

if [[ "$profile" == "registry-nsec3" ]]; then
    failure_stage="nsec3-index-validation"
    journal_load_unit "$server_unit" \
        >"$artifact_dir/publication-journal-at-ready.log"
    if ! grep -E \
        '"nsec3_indexed_groups":1.*"nsec3_fallback_groups":0' \
        "$artifact_dir/publication-journal-at-ready.log" \
        >"$artifact_dir/nsec3-index-validation.txt"; then
        echo "published member did not compile the indexed NSEC3 lookup path" >&2
        exit 1
    fi
fi

failure_stage="final-unit-validation"
systemctl_load is-active --quiet "$server_unit"
systemctl_load is-active --quiet "$generator_unit"

failure_stage="summary"
python3 - \
    "$artifact_dir/scenario-manifest.json" \
    "$artifact_dir/run-summary.json" \
    "$server_memory_high" \
    "$server_memory_max" \
    "$(unit_property "$server_unit" MemoryPeak)" \
    "$(unit_property "$generator_unit" MemoryPeak)" \
    "$SECONDS" \
    "$systemd_manager" \
    "$load_slice" \
    "$oomd_pressure_limit_percent" <<'PY'
import json
import pathlib
import sys

(
    manifest_path,
    output_path,
    memory_high,
    memory_max,
    server_memory_peak,
    generator_memory_peak,
    elapsed_seconds,
    systemd_manager,
    load_slice,
    oomd_pressure_limit_percent,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)
with open(
    output_path.rsplit("/", 1)[0] + "/query-load-summary.json",
    encoding="utf-8",
) as source:
    query_probe = json.load(source)
artifact_root = pathlib.Path(output_path).parent
with (artifact_root / "quiescence-summary.json").open(encoding="utf-8") as source:
    quiescence = json.load(source)
performance_path = artifact_root / "performance" / "performance-summary.json"
performance = None
if performance_path.is_file():
    with performance_path.open(encoding="utf-8") as source:
        performance = json.load(source)
summary = {
    "status": "ready_and_held",
    "scenario": manifest,
    "observed": {
        "server_memory_peak_bytes": int(server_memory_peak),
        "generator_memory_peak_bytes": int(generator_memory_peak),
        "elapsed_seconds": int(elapsed_seconds),
        "query_probe": query_probe,
        "quiescence": quiescence,
        "performance": performance,
    },
    "containment": {
        "cgroup_version": 2,
        "memory_high": memory_high,
        "memory_max": memory_max,
        "memory_swap_max": 0,
        "systemd_oomd_required": True,
        "systemd_manager": systemd_manager,
        "slice": load_slice if systemd_manager == "system" else None,
        "pressure_limit_percent": int(oomd_pressure_limit_percent),
    },
}
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
PY

printf 'bounded BoronGen load completed; evidence: %s\n' "$artifact_dir"
