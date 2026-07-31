#!/usr/bin/env bash
set -euo pipefail

umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="$repo_root/scripts/boron-gen-bounded-load.sh"
command="${1:-run}"
campaign_id="${BORON_CAMPAIGN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')}"
artifact_root="${BORON_CAMPAIGN_ARTIFACT_DIR:-$repo_root/target/evidence/boron-gen-large-memory-$campaign_id}"
minimum_total_bytes="${BORON_CAMPAIGN_MIN_TOTAL_BYTES:-773094113280}"
minimum_available_bytes="${BORON_CAMPAIGN_MIN_AVAILABLE_BYTES:-751619276800}"
minimum_disk_bytes="${BORON_CAMPAIGN_MIN_DISK_BYTES:-53687091200}"
recovery_timeout_seconds="${BORON_CAMPAIGN_RECOVERY_TIMEOUT_SECONDS:-1800}"
transfer_bytes="${BORON_CAMPAIGN_MAX_TRANSFER_BYTES:-274877906944}"
transfer_messages="${BORON_CAMPAIGN_MAX_TRANSFER_MESSAGES:-2000000}"
dns_listen="${BORON_CAMPAIGN_DNS_LISTEN:-127.0.0.1:15300}"
performance_mode="${BORON_CAMPAIGN_PERFORMANCE_MODE:-off}"
performance_server_device="${BORON_CAMPAIGN_PERFORMANCE_SERVER_DEVICE:-auto}"
performance_client_bind="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_BIND:-}"
performance_client_source_cidr="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_SOURCE_CIDR:-}"
performance_client_device="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_DEVICE:-auto}"
performance_remote_ssh="${BORON_CAMPAIGN_PERFORMANCE_REMOTE_SSH:-}"
performance_warmup="${BORON_CAMPAIGN_PERFORMANCE_WARMUP_SECONDS:-15}"
performance_duration="${BORON_CAMPAIGN_PERFORMANCE_DURATION_SECONDS:-60}"
performance_repetitions="${BORON_CAMPAIGN_PERFORMANCE_REPETITIONS:-3}"
performance_client_threads="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_THREADS:-32}"
performance_client_window="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_WINDOW:-256}"
performance_client_sockets="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_SOCKETS_PER_THREAD:-4}"
performance_client_cpu_list="${BORON_CAMPAIGN_PERFORMANCE_CLIENT_CPU_LIST:-}"
udp_batch_size="${BORON_CAMPAIGN_UDP_BATCH_SIZE:-1}"
udp_reuseport_workers="${BORON_CAMPAIGN_UDP_REUSEPORT_WORKERS:-1}"
udp_runtime="${BORON_CAMPAIGN_UDP_RUNTIME:-tokio}"
udp_idle_strategy="${BORON_CAMPAIGN_UDP_IDLE_STRATEGY:-park}"
udp_socket_receive_buffer_bytes="${BORON_CAMPAIGN_UDP_SOCKET_RECEIVE_BUFFER_BYTES:-0}"
udp_socket_send_buffer_bytes="${BORON_CAMPAIGN_UDP_SOCKET_SEND_BUFFER_BYTES:-0}"
scenario_selector="${BORON_CAMPAIGN_SCENARIOS:-all}"

usage() {
    cat <<'EOF'
Usage: scripts/boron-gen-large-memory-campaign.sh [plan|run]

Commands:
  plan  Validate and print the serialized scenario matrix without running it.
  run   Run or resume the matrix, preserving every scenario attempt.

The run command is intended for the 750 GiB oxidedns host. It requires cgroup
v2, an active systemd-oomd service, at least 720 GiB total RAM, at least
700 GiB available before every scenario, at least 50 GiB available disk, and
non-interactive sudo for dedicated system-level load slices.
EOF
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

for pair in \
    "BORON_CAMPAIGN_MIN_TOTAL_BYTES:$minimum_total_bytes" \
    "BORON_CAMPAIGN_MIN_AVAILABLE_BYTES:$minimum_available_bytes" \
    "BORON_CAMPAIGN_MIN_DISK_BYTES:$minimum_disk_bytes" \
    "BORON_CAMPAIGN_RECOVERY_TIMEOUT_SECONDS:$recovery_timeout_seconds" \
    "BORON_CAMPAIGN_MAX_TRANSFER_BYTES:$transfer_bytes" \
    "BORON_CAMPAIGN_MAX_TRANSFER_MESSAGES:$transfer_messages" \
    "BORON_CAMPAIGN_PERFORMANCE_WARMUP_SECONDS:$performance_warmup" \
    "BORON_CAMPAIGN_PERFORMANCE_DURATION_SECONDS:$performance_duration" \
    "BORON_CAMPAIGN_PERFORMANCE_REPETITIONS:$performance_repetitions" \
    "BORON_CAMPAIGN_PERFORMANCE_CLIENT_THREADS:$performance_client_threads" \
    "BORON_CAMPAIGN_PERFORMANCE_CLIENT_WINDOW:$performance_client_window" \
    "BORON_CAMPAIGN_PERFORMANCE_CLIENT_SOCKETS_PER_THREAD:$performance_client_sockets" \
    "BORON_CAMPAIGN_UDP_BATCH_SIZE:$udp_batch_size" \
    "BORON_CAMPAIGN_UDP_REUSEPORT_WORKERS:$udp_reuseport_workers"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
for pair in \
    "BORON_CAMPAIGN_UDP_SOCKET_RECEIVE_BUFFER_BYTES:$udp_socket_receive_buffer_bytes" \
    "BORON_CAMPAIGN_UDP_SOCKET_SEND_BUFFER_BYTES:$udp_socket_send_buffer_bytes"; do
    if ! [[ "${pair#*:}" =~ ^[0-9]+$ ]]; then
        printf '%s must be a non-negative integer, got %q\n' \
            "${pair%%:*}" "${pair#*:}" >&2
        exit 64
    fi
done
if ((udp_batch_size > 1024 || udp_reuseport_workers > 64)); then
    echo "campaign UDP batch size or reuseport worker count exceeds the supported ceiling" >&2
    exit 64
fi
case "$udp_runtime:$udp_idle_strategy" in
tokio:park | dedicated:park | dedicated:spin) ;;
*)
    printf 'invalid campaign UDP runtime/idle strategy: %s/%s\n' \
        "$udp_runtime" "$udp_idle_strategy" >&2
    exit 64
    ;;
esac
case "$performance_mode" in
off | local | ssh | external) ;;
*)
    printf 'BORON_CAMPAIGN_PERFORMANCE_MODE must be off, local, ssh, or external\n' >&2
    exit 64
    ;;
esac
if [[ "$performance_mode" == "ssh" || "$performance_mode" == "external" ]]; then
    if [[ -z "$performance_client_source_cidr" ]]; then
        printf '%s performance mode requires BORON_CAMPAIGN_PERFORMANCE_CLIENT_SOURCE_CIDR\n' \
            "$performance_mode" >&2
        exit 64
    fi
    if [[ "$dns_listen" == 127.0.0.1:* || "$dns_listen" == localhost:* ]]; then
        echo "SSH performance mode requires a non-loopback BORON_CAMPAIGN_DNS_LISTEN" >&2
        exit 64
    fi
fi

if (($# > 1)); then
    usage >&2
    exit 64
fi
case "$command" in
plan | run) ;;
-h | --help | help)
    usage
    exit 0
    ;;
*)
    usage >&2
    exit 64
    ;;
esac

for tool in cargo curl dig git jq journalctl python3 sha256sum sudo systemctl systemd-run; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 69
    fi
done
if [[ ! -x "$harness" ]]; then
    printf 'bounded load harness is not executable: %s\n' "$harness" >&2
    exit 69
fi

# Columns:
# id, profile, zones, names/zone, records/name, NSEC3/zone, projected peak GiB,
# MemoryHigh, MemoryMax, readiness timeout, hold seconds, query packets,
# expected retained member records, expected outcome.
scenario_rows() {
    cat <<'EOF'
01-wide-rrset-10m	large-rrset	1	1	10000000	2	4	8G	12G	21600	120	50000	10000007	ready
02-wide-rrset-100m	large-rrset	1	1	100000000	2	36	48G	64G	43200	180	100000	100000007	ready
03-mixed-5m-x32	mixed	1	5000000	32	2	101	120G	144G	86400	180	100000	185000006	ready
04-catalog-128x100k	registry-nsec3	128	100000	4	100000	91	120G	144G	86400	180	100000	116481024	ready
05-catalog-512x100k	registry-nsec3	512	100000	4	100000	465	480G	520G	172800	300	100000	465924096	ready
06-nsec3-heavy-10m-100m	registry-nsec3	1	10000000	4	100000000	320	400G	460G	172800	300	100000	271000008	ready
07-registry-balanced-1m	registry-nsec3	1	1000000	4	1000000	12	20G	28G	43200	180	100000	9100008	ready
08-registry-balanced-10m	registry-nsec3	1	10000000	4	10000000	120	144G	168G	86400	180	100000	91000008	ready
09-registry-balanced-20m	registry-nsec3	1	20000000	4	20000000	240	280G	320G	129600	180	100000	182000008	ready
10-registry-balanced-40m	registry-nsec3	1	40000000	4	40000000	480	520G	560G	172800	300	100000	364000008	ready
11-registry-balanced-50m	registry-nsec3	1	50000000	4	50000000	590	620G	650G	216000	300	100000	455000008	ready
12-registry-balanced-55m	registry-nsec3	1	55000000	4	55000000	640	650G	680G	237600	300	100000	500500008	ready
13-registry-balanced-60m	registry-nsec3	1	60000000	4	60000000	650	640G	680G	259200	300	100000	546000008	ready
14-contained-oom-100k-512m	registry-nsec3	1	100000	4	100000	1	512M	512M	3600	1	1000	910008	contained-oom
EOF
}

declare -A selected_scenarios=()
if [[ "$scenario_selector" != "all" ]]; then
    if [[ ! "$scenario_selector" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]]; then
        printf 'BORON_CAMPAIGN_SCENARIOS must be all or a comma-separated list of scenario IDs, got %q\n' \
            "$scenario_selector" >&2
        exit 64
    fi
    declare -A known_scenarios=()
    while IFS=$'\t' read -r known_id _; do
        known_scenarios["$known_id"]=1
    done < <(scenario_rows)
    IFS=, read -r -a requested_scenarios <<<"$scenario_selector"
    for requested_id in "${requested_scenarios[@]}"; do
        if [[ -z "${known_scenarios[$requested_id]+present}" ]]; then
            printf 'BORON_CAMPAIGN_SCENARIOS contains unknown scenario ID %q\n' \
                "$requested_id" >&2
            exit 64
        fi
        if [[ -n "${selected_scenarios[$requested_id]+present}" ]]; then
            printf 'BORON_CAMPAIGN_SCENARIOS contains duplicate scenario ID %q\n' \
                "$requested_id" >&2
            exit 64
        fi
        selected_scenarios["$requested_id"]=1
    done
fi

selected_scenario_rows() {
    local row id
    while IFS= read -r row; do
        id="${row%%$'\t'*}"
        if [[ "$scenario_selector" == "all" ||
            -n "${selected_scenarios[$id]+present}" ]]; then
            printf '%s\n' "$row"
        fi
    done < <(scenario_rows)
}

ensure_release_binaries() {
    cargo build --locked --release -p boron-gen -p boron-gun -p borondns-cli
}

validate_plan() {
    local id profile zones names records nsec3 projected high max timeout hold queries expected outcome
    local actual

    printf 'id\tprofile\tzones\tnames_per_zone\trecords_per_name\tnsec3_per_zone\tprojected_peak_gib\tmemory_high\tmemory_max\tretained_records\texpected_outcome\n'
    while IFS=$'\t' read -r id profile zones names records nsec3 projected high max timeout hold queries expected outcome; do
        actual="$(
            "$repo_root/target/release/boron-gen" manifest \
                --profile "$profile" \
                --origin "${id}.load.borongen." \
                --catalog-origin "${id}.catalog.borongen." \
                --zones "$zones" \
                --names-per-zone "$names" \
                --records-per-name "$records" \
                --nsec3-records-per-zone "$nsec3" |
                jq -er '.all_member_snapshot_records'
        )"
        if [[ "$actual" != "$expected" ]]; then
            printf '%s manifest drift: expected %s retained records, got %s\n' \
                "$id" "$expected" "$actual" >&2
            exit 1
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$id" "$profile" "$zones" "$names" "$records" "$nsec3" \
            "$projected" "$high" "$max" "$actual" "$outcome"
    done < <(selected_scenario_rows)
}

memory_value_bytes() {
    local key="$1"
    awk -v key="$key" '$1 == key ":" { printf "%.0f\n", $2 * 1024; exit }' /proc/meminfo
}

active_load_units() {
    {
        systemctl --user list-units \
            'boron-gen-load-*.service' \
            'borondns-load-*.service' \
            --state=running \
            --no-legend \
            --no-pager 2>/dev/null || true
        sudo -n systemctl list-units \
            'boron-gen-load-*.service' \
            'borondns-load-*.service' \
            --state=running \
            --no-legend \
            --no-pager 2>/dev/null || true
    } |
        awk 'NF { print $1 }'
}

sampled_server_peak() {
    local samples="$1"
    if [[ ! -r "$samples" ]]; then
        printf 'null\n'
        return 0
    fi
    awk -F '\t' '
        NR > 1 && $3 ~ /^[0-9]+$/ {
            if ($3 > peak) {
                peak = $3
            }
        }
        END {
            if (peak == "") {
                print "null"
            } else {
                printf "%.0f\n", peak
            }
        }
    ' "$samples"
}

unit_file_peak() {
    local evidence_dir="$1"
    local prefix="$2"
    local files=()
    shopt -s nullglob
    files=("$evidence_dir"/"$prefix"*-unit-final.txt)
    shopt -u nullglob
    if ((${#files[@]} == 0)); then
        printf 'null\n'
        return 0
    fi
    awk -F= '
        $1 == "MemoryPeak" && $2 ~ /^[0-9]+$/ {
            if ($2 > peak) {
                peak = $2
            }
        }
        END {
            if (peak == "") {
                print "null"
            } else {
                printf "%.0f\n", peak
            }
        }
    ' "${files[@]}"
}

attempt_elapsed_seconds() {
    local attempt_dir="$1"
    python3 - "$attempt_dir/started-utc.txt" "$attempt_dir/finished-utc.txt" <<'PY'
import datetime
import pathlib
import sys

try:
    started = datetime.datetime.fromisoformat(
        pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip().replace("Z", "+00:00")
    )
    finished = datetime.datetime.fromisoformat(
        pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip().replace("Z", "+00:00")
    )
except (OSError, ValueError):
    print("null")
else:
    print(max(0, int((finished - started).total_seconds())))
PY
}

wait_for_safe_baseline() {
    local deadline=$((SECONDS + recovery_timeout_seconds))
    local available disk_available units

    while true; do
        if ! systemctl is-active --quiet systemd-oomd.service; then
            echo "systemd-oomd.service is not active" >&2
            return 1
        fi
        units="$(active_load_units)"
        available="$(memory_value_bytes MemAvailable)"
        disk_available="$(df -B1 --output=avail "$artifact_root" | awk 'NR == 2 { print $1 }')"
        if [[ -z "$units" ]] &&
            ((available >= minimum_available_bytes)) &&
            ((disk_available >= minimum_disk_bytes)); then
            return 0
        fi
        if ((SECONDS >= deadline)); then
            printf 'safe baseline did not return: available=%s required=%s disk=%s required_disk=%s active_units=%q\n' \
                "$available" "$minimum_available_bytes" \
                "$disk_available" "$minimum_disk_bytes" "$units" >&2
            return 1
        fi
        printf 'waiting for safe baseline: available=%s disk=%s active_units=%q\n' \
            "$available" "$disk_available" "$units"
        sleep 15
    done
}

next_attempt_dir() {
    local scenario_root="$1"
    local number=1
    local candidate

    while true; do
        printf -v candidate '%s/attempt-%03d' "$scenario_root" "$number"
        if [[ ! -e "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
        ((number += 1))
    done
}

write_host_facts() {
    {
        printf 'campaign_id=%s\n' "$campaign_id"
        printf 'started_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'hostname=%s\n' "$(hostname -f 2>/dev/null || hostname)"
        printf 'kernel=%s\n' "$(uname -srmo)"
        printf 'cpus=%s\n' "$(nproc)"
        printf 'cgroup_filesystem=%s\n' "$(stat -fc %T /sys/fs/cgroup)"
        printf 'systemd_oomd=%s\n' "$(systemctl is-active systemd-oomd.service)"
        printf 'dns_listen=%s\n' "$dns_listen"
        printf 'performance_mode=%s\n' "$performance_mode"
        printf 'scenario_selector=%s\n' "$scenario_selector"
        printf 'performance_remote_ssh=%s\n' "${performance_remote_ssh:-none}"
        printf 'performance_server_device=%s\n' "$performance_server_device"
        printf 'performance_client_device=%s\n' "$performance_client_device"
        awk '/MemTotal|MemAvailable|SwapTotal/ { print }' /proc/meminfo
        df -B1 --output=target,size,avail "$artifact_root"
    } >"$artifact_root/host-facts.txt"
}

write_campaign_summary() {
    python3 - "$artifact_root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
results = []
for result_path in sorted(root.glob("runs/*/attempt-*/result.json")):
    with result_path.open(encoding="utf-8") as source:
        results.append(json.load(source))
summary = {
    "format": "boron-gen-large-memory-campaign-v2",
    "campaign_id": root.name.removeprefix("boron-gen-large-memory-"),
    "attempts": results,
    "scenario_attempts": len(results),
    "successful_attempts": sum(result["exit_status"] == 0 for result in results),
    "failed_attempts": sum(result["exit_status"] != 0 for result in results),
}
with (root / "campaign-summary.json").open("w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}

write_performance_curve() {
    "$repo_root/scripts/summarize-boron-gen-performance.py" \
        --plan "$artifact_root/plan.tsv" \
        --results "$artifact_root/results.tsv" \
        --output "$artifact_root/performance-size-curve.tsv"
}

ensure_release_binaries
if [[ "$command" == "plan" ]]; then
    validate_plan
    exit 0
fi

if [[ "$(stat -fc %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
    echo "cgroup v2 is required" >&2
    exit 69
fi
if ! systemctl is-active --quiet systemd-oomd.service; then
    echo "system systemd-oomd.service must be active" >&2
    exit 69
fi
if ! sudo -n true; then
    echo "large-memory campaign requires non-interactive sudo for system-level load slices" >&2
    exit 69
fi
total_bytes="$(memory_value_bytes MemTotal)"
if ((total_bytes < minimum_total_bytes)); then
    printf 'host has %s bytes RAM; campaign requires at least %s\n' \
        "$total_bytes" "$minimum_total_bytes" >&2
    exit 69
fi
if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
    echo "large-memory campaign requires a clean source tree" >&2
    exit 65
fi

mkdir -p "$artifact_root/runs"
chmod 700 "$artifact_root" "$artifact_root/runs"
if [[ -L "$artifact_root" || -L "$artifact_root/runs" ]]; then
    echo "campaign artifact paths must not be symlinks" >&2
    exit 73
fi

git -C "$repo_root" rev-parse HEAD >"$artifact_root/source-commit.txt"
git -C "$repo_root" status --short --branch >"$artifact_root/source-status.txt"
sha256sum \
    "$harness" \
    "$repo_root/scripts/boron-gen-external-performance-coordinator.sh" \
    "$repo_root/scripts/boron-gen-large-memory-campaign.sh" \
    "$repo_root/scripts/boron-gen-query-performance.sh" \
    "$repo_root/scripts/analyze-boron-gen-query-performance.py" \
    "$repo_root/scripts/generate-boron-gen-query-trace.py" \
    "$repo_root/scripts/summarize-boron-gen-performance.py" \
    >"$artifact_root/harnesses.sha256"
write_host_facts
validate_plan >"$artifact_root/plan.tsv"
results_header='finished_utc	scenario	attempt	exit_status	result	server_peak_bytes	generator_peak_bytes	elapsed_seconds	median_qps	median_p99_us	median_server_cpu_percent	median_client_cpu_percent	median_server_udp_rcvbuf_errors	median_server_udp_mem_errors	median_server_softnet_dropped'
if [[ ! -e "$artifact_root/results.tsv" ]]; then
    printf '%s\n' "$results_header" >"$artifact_root/results.tsv"
elif [[ "$(head -n 1 "$artifact_root/results.tsv")" != "$results_header" ]]; then
    echo "existing campaign results use an incompatible schema; choose a new artifact directory" >&2
    exit 65
fi

id=""
campaign_interrupted() {
    printf 'campaign interrupted while processing %s\n' "${id:-preflight}" >&2
    exit 143
}
trap campaign_interrupted TERM INT

while IFS=$'\t' read -r id profile zones names records nsec3 projected high max timeout hold queries expected outcome; do
    scenario_root="$artifact_root/runs/$id"
    mkdir -p "$scenario_root"
    chmod 700 "$scenario_root"
    if [[ -e "$scenario_root/completed" ]]; then
        printf 'skipping completed scenario %s\n' "$id"
        continue
    fi

    wait_for_safe_baseline
    attempt_dir="$(next_attempt_dir "$scenario_root")"
    mkdir -p "$attempt_dir/evidence"
    chmod 700 "$attempt_dir" "$attempt_dir/evidence"
    attempt="${attempt_dir##*/}"
    printf '%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$attempt_dir/started-utc.txt"
    printf 'starting %s %s: projected=%s GiB high=%s max=%s retained_records=%s\n' \
        "$id" "$attempt" "$projected" "$high" "$max" "$expected"

    set +e
    env \
        BORON_LOAD_ARTIFACT_DIR="$attempt_dir/evidence" \
        BORON_LOAD_PROFILE="$profile" \
        BORON_LOAD_ZONES="$zones" \
        BORON_LOAD_NAMES_PER_ZONE="$names" \
        BORON_LOAD_RECORDS_PER_NAME="$records" \
        BORON_LOAD_NSEC3_RECORDS_PER_ZONE="$nsec3" \
        BORON_LOAD_ORIGIN="${id}.load.borongen." \
        BORON_LOAD_CATALOG_ORIGIN="${id}.catalog.borongen." \
        BORON_LOAD_DNS_LISTEN="$dns_listen" \
        BORON_LOAD_MAX_TRANSFER_BYTES="$transfer_bytes" \
        BORON_LOAD_MAX_TRANSFER_MESSAGES="$transfer_messages" \
        BORON_LOAD_READY_TIMEOUT_SECONDS="$timeout" \
        BORON_LOAD_HOLD_SECONDS="$hold" \
        BORON_LOAD_QUERY_PACKETS="$queries" \
        BORON_LOAD_QUERY_TARGET_QPS=20000 \
        BORON_LOAD_HTTP_CONNECT_TIMEOUT_SECONDS=2 \
        BORON_LOAD_HTTP_MAX_TIME_SECONDS=10 \
        BORON_LOAD_QUIESCENCE_ENABLED=true \
        BORON_LOAD_QUIESCENCE_WINDOW_SECONDS=30 \
        BORON_LOAD_QUIESCENCE_TIMEOUT_SECONDS=900 \
        BORON_LOAD_STABLE_MEMORY_DELTA_BYTES=268435456 \
        BORON_LOAD_MIN_AVAILABLE_BYTES=68719476736 \
        BORON_LOAD_MIN_CGROUP_HEADROOM_BYTES=4294967296 \
        BORON_LOAD_MAX_IDLE_CPU_PERCENT=10 \
        BORON_LOAD_MAX_MEMORY_PRESSURE_AVG10=10 \
        BORON_LOAD_UDP_BATCH_SIZE="$udp_batch_size" \
        BORON_LOAD_UDP_REUSEPORT_WORKERS="$udp_reuseport_workers" \
        BORON_LOAD_UDP_RUNTIME="$udp_runtime" \
        BORON_LOAD_UDP_IDLE_STRATEGY="$udp_idle_strategy" \
        BORON_LOAD_UDP_SOCKET_RECEIVE_BUFFER_BYTES="$udp_socket_receive_buffer_bytes" \
        BORON_LOAD_UDP_SOCKET_SEND_BUFFER_BYTES="$udp_socket_send_buffer_bytes" \
        BORON_LOAD_PERFORMANCE_MODE="$performance_mode" \
        BORON_LOAD_PERFORMANCE_SERVER_DEVICE="$performance_server_device" \
        BORON_LOAD_PERFORMANCE_CLIENT_BIND="$performance_client_bind" \
        BORON_LOAD_PERFORMANCE_CLIENT_SOURCE_CIDR="$performance_client_source_cidr" \
        BORON_LOAD_PERFORMANCE_CLIENT_DEVICE="$performance_client_device" \
        BORON_LOAD_PERFORMANCE_REMOTE_SSH="$performance_remote_ssh" \
        BORON_LOAD_PERFORMANCE_WARMUP_SECONDS="$performance_warmup" \
        BORON_LOAD_PERFORMANCE_DURATION_SECONDS="$performance_duration" \
        BORON_LOAD_PERFORMANCE_REPETITIONS="$performance_repetitions" \
        BORON_LOAD_PERFORMANCE_CLIENT_THREADS="$performance_client_threads" \
        BORON_LOAD_PERFORMANCE_CLIENT_WINDOW="$performance_client_window" \
        BORON_LOAD_PERFORMANCE_CLIENT_SOCKETS_PER_THREAD="$performance_client_sockets" \
        BORON_LOAD_PERFORMANCE_CLIENT_CPU_LIST="$performance_client_cpu_list" \
        BORON_LOAD_PERFORMANCE_EXTERNAL_TIMEOUT_SECONDS=7200 \
        BORON_LOAD_EXPECT_OUTCOME="$outcome" \
        BORON_LOAD_MEMORY_HIGH="$high" \
        BORON_LOAD_MEMORY_MAX="$max" \
        BORON_LOAD_SYSTEMD_MANAGER=system \
        BORON_LOAD_OOMD_PRESSURE_LIMIT_PERCENT=80 \
        BORON_GEN_MEMORY_HIGH=768M \
        BORON_GEN_MEMORY_MAX=1G \
        "$harness" \
        >"$attempt_dir/harness.stdout.log" \
        2>"$attempt_dir/harness.stderr.log"
    status=$?
    set -e

    printf '%s\n' "$status" >"$attempt_dir/exit-status"
    printf '%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$attempt_dir/finished-utc.txt"
    if [[ -s "$attempt_dir/evidence/run-summary.json" ]]; then
        server_peak="$(jq -r '.observed.server_memory_peak_bytes // "null"' "$attempt_dir/evidence/run-summary.json")"
        generator_peak="$(jq -r '.observed.generator_memory_peak_bytes // "null"' "$attempt_dir/evidence/run-summary.json")"
        elapsed="$(jq -r '.observed.elapsed_seconds // "null"' "$attempt_dir/evidence/run-summary.json")"
        result="$(jq -er '.status' "$attempt_dir/evidence/run-summary.json")"
        failure_reason="$(jq -r '.failure.reason // ""' "$attempt_dir/evidence/run-summary.json")"
        median_qps="$(jq -r '.observed.performance.aggregate.median_responses_per_second // "null"' "$attempt_dir/evidence/run-summary.json")"
        median_p99="$(jq -r '.observed.performance.aggregate.median_latency_us_p99 // "null"' "$attempt_dir/evidence/run-summary.json")"
        median_server_cpu="$(jq -r '.observed.performance.aggregate.median_server_cpu_percent // "null"' "$attempt_dir/evidence/run-summary.json")"
        median_client_cpu="$(jq -r '.observed.performance.aggregate.median_client_cpu_percent // "null"' "$attempt_dir/evidence/run-summary.json")"
        median_server_udp_rcvbuf_errors="$(jq -r '.observed.performance.aggregate.median_server_udp_rcvbuf_errors // "null"' "$attempt_dir/evidence/run-summary.json")"
        median_server_udp_mem_errors="$(jq -r '.observed.performance.aggregate.median_server_udp_mem_errors // "null"' "$attempt_dir/evidence/run-summary.json")"
        median_server_softnet_dropped="$(jq -r '.observed.performance.aggregate.median_server_softnet_dropped // "null"' "$attempt_dir/evidence/run-summary.json")"
    else
        server_peak="$(sampled_server_peak "$attempt_dir/evidence/resource-samples.tsv")"
        if [[ "$server_peak" == "null" ]]; then
            server_peak="$(unit_file_peak "$attempt_dir/evidence" "borondns-load-")"
        fi
        generator_peak="$(unit_file_peak "$attempt_dir/evidence" "boron-gen-load-")"
        elapsed="$(attempt_elapsed_seconds "$attempt_dir")"
        result="failed_without_summary"
        failure_reason="$(tail -n 1 "$attempt_dir/harness.stderr.log" 2>/dev/null || true)"
        median_qps="null"
        median_p99="null"
        median_server_cpu="null"
        median_client_cpu="null"
        median_server_udp_rcvbuf_errors="null"
        median_server_udp_mem_errors="null"
        median_server_softnet_dropped="null"
    fi
    jq -n \
        --arg scenario "$id" \
        --arg attempt "$attempt" \
        --arg result "$result" \
        --arg failure_reason "$failure_reason" \
        --argjson exit_status "$status" \
        --argjson server_peak_bytes "$server_peak" \
        --argjson generator_peak_bytes "$generator_peak" \
        --argjson elapsed_seconds "$elapsed" \
        --argjson median_qps "$median_qps" \
        --argjson median_p99_us "$median_p99" \
        --argjson median_server_cpu_percent "$median_server_cpu" \
        --argjson median_client_cpu_percent "$median_client_cpu" \
        --argjson median_server_udp_rcvbuf_errors "$median_server_udp_rcvbuf_errors" \
        --argjson median_server_udp_mem_errors "$median_server_udp_mem_errors" \
        --argjson median_server_softnet_dropped "$median_server_softnet_dropped" \
        '{
            scenario: $scenario,
            attempt: $attempt,
            exit_status: $exit_status,
            result: $result,
            failure_reason: (if $failure_reason == "" then null else $failure_reason end),
            server_peak_bytes: $server_peak_bytes,
            generator_peak_bytes: $generator_peak_bytes,
            elapsed_seconds: $elapsed_seconds,
            median_qps: $median_qps,
            median_p99_us: $median_p99_us,
            median_server_cpu_percent: $median_server_cpu_percent,
            median_client_cpu_percent: $median_client_cpu_percent,
            median_server_udp_rcvbuf_errors: $median_server_udp_rcvbuf_errors,
            median_server_udp_mem_errors: $median_server_udp_mem_errors,
            median_server_softnet_dropped: $median_server_softnet_dropped
        }' >"$attempt_dir/result.json"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$id" "$attempt" "$status" "$result" "$server_peak" "$generator_peak" "$elapsed" \
        "$median_qps" "$median_p99" "$median_server_cpu" "$median_client_cpu" \
        "$median_server_udp_rcvbuf_errors" "$median_server_udp_mem_errors" \
        "$median_server_softnet_dropped" \
        >>"$artifact_root/results.tsv"
    if ((status == 0)); then
        printf '%s\n' "$attempt" >"$scenario_root/completed"
        printf 'completed %s: server_peak=%s generator_peak=%s elapsed=%s\n' \
            "$id" "$server_peak" "$generator_peak" "$elapsed"
    else
        printf 'scenario %s failed with status %s; evidence retained; continuing after recovery\n' \
            "$id" "$status" >&2
    fi
    write_campaign_summary
    write_performance_curve
    wait_for_safe_baseline
done < <(selected_scenario_rows)

write_campaign_summary
write_performance_curve
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$artifact_root/completed-utc.txt"
sha256sum "$artifact_root/plan.tsv" "$artifact_root/results.tsv" \
    "$artifact_root/performance-size-curve.tsv" \
    "$artifact_root/campaign-summary.json" >"$artifact_root/campaign-summary.sha256"
printf 'large-memory campaign completed; evidence: %s\n' "$artifact_root"
