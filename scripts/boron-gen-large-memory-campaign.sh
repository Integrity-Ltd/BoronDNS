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

usage() {
    cat <<'EOF'
Usage: scripts/boron-gen-large-memory-campaign.sh [plan|run]

Commands:
  plan  Validate and print the serialized scenario matrix without running it.
  run   Run or resume the matrix, preserving every scenario attempt.

The run command is intended for the 750 GiB oxidedns host. It requires cgroup
v2, an active systemd-oomd service, at least 720 GiB total RAM, at least
700 GiB available before every scenario, and at least 50 GiB available disk.
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
    "BORON_CAMPAIGN_MAX_TRANSFER_MESSAGES:$transfer_messages"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done

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

for tool in cargo curl dig git jq journalctl python3 sha256sum systemctl systemd-run; do
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
# expected retained member records.
scenario_rows() {
    cat <<'EOF'
01-wide-rrset-10m	large-rrset	1	1	10000000	2	4	8G	12G	21600	120	50000	10000007
02-wide-rrset-100m	large-rrset	1	1	100000000	2	36	48G	64G	43200	180	100000	100000007
03-mixed-5m-x32	mixed	1	5000000	32	2	101	120G	144G	86400	180	100000	185000006
04-catalog-128x100k	registry-nsec3	128	100000	4	100000	91	120G	144G	86400	180	100000	116481024
05-catalog-512x100k	registry-nsec3	512	100000	4	100000	362	420G	480G	172800	300	100000	465924096
06-nsec3-heavy-10m-100m	registry-nsec3	1	10000000	4	100000000	320	400G	460G	172800	300	100000	271000008
07-registry-balanced-40m	registry-nsec3	1	40000000	4	40000000	390	460G	520G	172800	300	100000	364000008
08-registry-balanced-65m	registry-nsec3	1	65000000	4	65000000	633	640G	680G	259200	600	200000	591500008
EOF
}

ensure_release_binaries() {
    cargo build --locked --release -p boron-gen -p boron-gun -p borondns-cli
}

validate_plan() {
    local id profile zones names records nsec3 projected high max timeout hold queries expected
    local actual

    printf 'id\tprofile\tzones\tnames_per_zone\trecords_per_name\tnsec3_per_zone\tprojected_peak_gib\tmemory_high\tmemory_max\tretained_records\n'
    while IFS=$'\t' read -r id profile zones names records nsec3 projected high max timeout hold queries expected; do
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
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$id" "$profile" "$zones" "$names" "$records" "$nsec3" \
            "$projected" "$high" "$max" "$actual"
    done < <(scenario_rows)
}

memory_value_bytes() {
    local key="$1"
    awk -v key="$key" '$1 == key ":" { printf "%.0f\n", $2 * 1024; exit }' /proc/meminfo
}

active_load_units() {
    systemctl --user list-units \
        'boron-gen-load-*.service' \
        'borondns-load-*.service' \
        --state=running \
        --no-legend \
        --no-pager 2>/dev/null |
        awk 'NF { print $1 }'
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
    "format": "boron-gen-large-memory-campaign-v1",
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
sha256sum "$harness" "$repo_root/scripts/boron-gen-large-memory-campaign.sh" \
    >"$artifact_root/harnesses.sha256"
write_host_facts
validate_plan >"$artifact_root/plan.tsv"
if [[ ! -e "$artifact_root/results.tsv" ]]; then
    printf 'finished_utc\tscenario\tattempt\texit_status\tresult\tserver_peak_bytes\tgenerator_peak_bytes\telapsed_seconds\n' \
        >"$artifact_root/results.tsv"
fi

id=""
campaign_interrupted() {
    printf 'campaign interrupted while processing %s\n' "${id:-preflight}" >&2
    exit 143
}
trap campaign_interrupted TERM INT

while IFS=$'\t' read -r id profile zones names records nsec3 projected high max timeout hold queries expected; do
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
        BORON_LOAD_MAX_TRANSFER_BYTES="$transfer_bytes" \
        BORON_LOAD_MAX_TRANSFER_MESSAGES="$transfer_messages" \
        BORON_LOAD_READY_TIMEOUT_SECONDS="$timeout" \
        BORON_LOAD_HOLD_SECONDS="$hold" \
        BORON_LOAD_QUERY_PACKETS="$queries" \
        BORON_LOAD_QUERY_TARGET_QPS=20000 \
        BORON_LOAD_EXPECT_OUTCOME=ready \
        BORON_LOAD_MEMORY_HIGH="$high" \
        BORON_LOAD_MEMORY_MAX="$max" \
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
        server_peak="$(jq -er '.observed.server_memory_peak_bytes' "$attempt_dir/evidence/run-summary.json")"
        generator_peak="$(jq -er '.observed.generator_memory_peak_bytes' "$attempt_dir/evidence/run-summary.json")"
        elapsed="$(jq -er '.observed.elapsed_seconds' "$attempt_dir/evidence/run-summary.json")"
        result="$(jq -er '.status' "$attempt_dir/evidence/run-summary.json")"
    else
        server_peak="null"
        generator_peak="null"
        elapsed="null"
        result="failed_before_summary"
    fi
    jq -n \
        --arg scenario "$id" \
        --arg attempt "$attempt" \
        --arg result "$result" \
        --argjson exit_status "$status" \
        --argjson server_peak_bytes "$server_peak" \
        --argjson generator_peak_bytes "$generator_peak" \
        --argjson elapsed_seconds "$elapsed" \
        '{
            scenario: $scenario,
            attempt: $attempt,
            exit_status: $exit_status,
            result: $result,
            server_peak_bytes: $server_peak_bytes,
            generator_peak_bytes: $generator_peak_bytes,
            elapsed_seconds: $elapsed_seconds
        }' >"$attempt_dir/result.json"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$id" "$attempt" "$status" "$result" "$server_peak" "$generator_peak" "$elapsed" \
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
    wait_for_safe_baseline
done < <(scenario_rows)

write_campaign_summary
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$artifact_root/completed-utc.txt"
sha256sum "$artifact_root/plan.tsv" "$artifact_root/results.tsv" \
    "$artifact_root/campaign-summary.json" >"$artifact_root/campaign-summary.sha256"
printf 'large-memory campaign completed; evidence: %s\n' "$artifact_root"
