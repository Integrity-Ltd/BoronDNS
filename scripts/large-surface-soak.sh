#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/large-surface-soak.sh [OPTIONS]

Run a long large-surface OxideDNS soak by repeatedly executing retained
real-primary and protocol scenarios, while sampling host resources and retaining
per-scenario artifacts.

Options:
  --evidence-dir DIR       Evidence output directory.
  --duration SECONDS       Wall-clock duration. Default: 86400.
  --scenario NAME          Scenario to include; repeatable. Defaults to broad set.
  --scenario-timeout SECS  Per-scenario timeout. Default: 1800.
  --cycle-sleep SECS       Sleep between full cycles. Default: 5.
  --sample-interval SECS   Resource sample interval. Default: 60.
  --allow-skip             Treat scenario self-skip as skipped instead of failed. Default.
  --fail-on-skip           Treat scenario self-skip as failed.
  --dry-run                Print selected scenarios and exit.
  -h, --help               Show this help.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="${OXIDEDNS_LARGE_SOAK_DIR:-$repo_root/target/evidence/large-surface-soak-$timestamp}"
duration="${OXIDEDNS_LARGE_SOAK_DURATION_SECONDS:-86400}"
scenario_timeout="${OXIDEDNS_LARGE_SOAK_SCENARIO_TIMEOUT_SECONDS:-1800}"
cycle_sleep="${OXIDEDNS_LARGE_SOAK_CYCLE_SLEEP_SECONDS:-5}"
sample_interval="${OXIDEDNS_LARGE_SOAK_SAMPLE_INTERVAL_SECONDS:-60}"
allow_skip="${OXIDEDNS_LARGE_SOAK_ALLOW_SKIP:-1}"
dry_run=0
selected_scenarios=()
scenario_names=()
scenario_scripts=()
scenario_env_vars=()
sampler_pid=""

add_scenario() {
    scenario_names+=("$1")
    scenario_scripts+=("$2")
    scenario_env_vars+=("$3")
}

init_scenarios() {
    add_scenario bind_catalog scripts/interop-bind-catalog-zone-docker.sh OXIDEDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR
    add_scenario bind_xot_catalog scripts/interop-bind-xot-catalog-zone-docker.sh OXIDEDNS_BIND_XOT_CATALOG_DOCKER_ARTIFACT_DIR
    add_scenario powerdns_catalog_tsig scripts/interop-powerdns-postgres-catalog-tsig-docker.sh OXIDEDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR
    add_scenario powerdns_catalog_extension scripts/interop-powerdns-catalog-member-extension-docker.sh OXIDEDNS_POWERDNS_CATALOG_MEMBER_EXTENSION_ARTIFACT_DIR
    add_scenario powerdns_split_primaries scripts/interop-powerdns-catalog-split-primaries-docker.sh OXIDEDNS_POWERDNS_CATALOG_SPLIT_PRIMARIES_ARTIFACT_DIR
    add_scenario bind_axfr scripts/interop-bind-axfr.sh OXIDEDNS_BIND_AXFR_ARTIFACT_DIR
    add_scenario bind_tsig_axfr scripts/interop-bind-tsig-axfr.sh OXIDEDNS_BIND_TSIG_AXFR_ARTIFACT_DIR
    add_scenario bind_notify scripts/interop-bind-notify-refresh.sh OXIDEDNS_BIND_NOTIFY_ARTIFACT_DIR
    add_scenario bind_ixfr scripts/interop-bind-ixfr-refresh.sh OXIDEDNS_BIND_IXFR_ARTIFACT_DIR
    add_scenario nsd_axfr scripts/interop-nsd-axfr-docker.sh OXIDEDNS_NSD_AXFR_ARTIFACT_DIR
    add_scenario nsd_tsig_axfr scripts/interop-nsd-tsig-axfr-docker.sh OXIDEDNS_NSD_TSIG_AXFR_ARTIFACT_DIR
    add_scenario nsd_notify scripts/interop-nsd-notify-refresh-docker.sh OXIDEDNS_NSD_NOTIFY_ARTIFACT_DIR
    add_scenario knot_axfr scripts/interop-knot-axfr-docker.sh OXIDEDNS_KNOT_AXFR_ARTIFACT_DIR
    add_scenario knot_tsig_axfr scripts/interop-knot-tsig-axfr-docker.sh OXIDEDNS_KNOT_TSIG_AXFR_ARTIFACT_DIR
    add_scenario knot_notify scripts/interop-knot-notify-refresh-docker.sh OXIDEDNS_KNOT_NOTIFY_ARTIFACT_DIR
    add_scenario knot_ixfr scripts/interop-knot-ixfr-refresh-docker.sh OXIDEDNS_KNOT_IXFR_ARTIFACT_DIR
    add_scenario knot_xot scripts/interop-knot-xot-docker.sh OXIDEDNS_KNOT_XOT_ARTIFACT_DIR
    add_scenario knot_xot_tsig scripts/interop-knot-xot-tsig-docker.sh OXIDEDNS_KNOT_XOT_TSIG_ARTIFACT_DIR
    add_scenario dnssec_serve scripts/interop-dnssec-serve.sh OXIDEDNS_DNSSEC_SERVE_ARTIFACT_DIR
    add_scenario dnssec_nsec3 scripts/interop-dnssec-nsec3-serve.sh OXIDEDNS_DNSSEC_NSEC3_ARTIFACT_DIR
    add_scenario unknown_rr scripts/interop-unknown-rr.sh OXIDEDNS_UNKNOWN_RR_ARTIFACT_DIR
    add_scenario unknown_rr_bad_transfer scripts/interop-unknown-rr-bad-transfer.sh OXIDEDNS_UNKNOWN_RR_BAD_ARTIFACT_DIR
    add_scenario negative_responses scripts/interop-negative-responses.sh OXIDEDNS_NEGATIVE_RESPONSE_ARTIFACT_DIR
    add_scenario notify_negative scripts/interop-notify-negative.sh OXIDEDNS_NOTIFY_NEGATIVE_ARTIFACT_DIR
    add_scenario tcp_truncation scripts/interop-tcp-truncation-retry.sh OXIDEDNS_TCP_TRUNCATION_ARTIFACT_DIR
    add_scenario edns_behavior scripts/interop-edns-behavior.sh OXIDEDNS_EDNS_BEHAVIOR_ARTIFACT_DIR
    add_scenario dns_cookie scripts/interop-dns-cookie-dig.sh OXIDEDNS_DNS_COOKIE_ARTIFACT_DIR
    add_scenario ixfr_notimp scripts/interop-ixfr-notimp-fallback.sh OXIDEDNS_IXFR_FALLBACK_ARTIFACT_DIR
    add_scenario rrl_udp scripts/interop-rrl-udp.sh OXIDEDNS_RRL_UDP_ARTIFACT_DIR
    add_scenario chaos_queries scripts/interop-chaos-queries.sh OXIDEDNS_CHAOS_QUERIES_ARTIFACT_DIR
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
        --evidence-dir)
            (($# >= 2)) || die "--evidence-dir requires a value"
            evidence_dir="$2"
            shift 2
            ;;
        --duration)
            (($# >= 2)) || die "--duration requires a value"
            duration="$2"
            shift 2
            ;;
        --scenario)
            (($# >= 2)) || die "--scenario requires a value"
            selected_scenarios+=("$2")
            shift 2
            ;;
        --scenario-timeout)
            (($# >= 2)) || die "--scenario-timeout requires a value"
            scenario_timeout="$2"
            shift 2
            ;;
        --cycle-sleep)
            (($# >= 2)) || die "--cycle-sleep requires a value"
            cycle_sleep="$2"
            shift 2
            ;;
        --sample-interval)
            (($# >= 2)) || die "--sample-interval requires a value"
            sample_interval="$2"
            shift 2
            ;;
        --allow-skip)
            allow_skip=1
            shift
            ;;
        --fail-on-skip)
            allow_skip=0
            shift
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
        esac
    done
}

scenario_index() {
    local wanted="$1"
    local index
    for index in "${!scenario_names[@]}"; do
        if [[ "${scenario_names[$index]}" == "$wanted" ]]; then
            printf '%s' "$index"
            return 0
        fi
    done
    return 1
}

selected_indices() {
    local scenario index
    if ((${#selected_scenarios[@]} == 0)); then
        for index in "${!scenario_names[@]}"; do
            printf '%s\n' "$index"
        done
        return 0
    fi
    for scenario in "${selected_scenarios[@]}"; do
        index="$(scenario_index "$scenario")" || die "unknown scenario: $scenario"
        printf '%s\n' "$index"
    done
}

record_tool_versions() {
    local output="$evidence_dir/tool-versions.txt"
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '$ git rev-parse HEAD\n'
        git -C "$repo_root" rev-parse HEAD 2>&1 || true
        printf '$ git status --short\n'
        git -C "$repo_root" status --short 2>&1 || true
        for cmd in \
            "rustc --version" \
            "cargo --version" \
            "cargo fuzz --version" \
            "docker --version" \
            "docker compose version" \
            "dig -v" \
            "curl --version" \
            "openssl version" \
            "python3 --version"; do
            printf '$ %s\n' "$cmd"
            bash -lc "$cmd" 2>&1 || true
        done
    } >"$output"
}

record_host_info() {
    local output="$evidence_dir/host-info.txt"
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        if command -v hostname >/dev/null 2>&1; then
            hostname || true
        else
            printf 'hostname command unavailable\n'
        fi
        uname -a || true
        lscpu || true
        free -h || true
        df -h "$repo_root" "$evidence_dir" || true
        printf '\n/proc/cmdline:\n'
        cat /proc/cmdline 2>/dev/null || true
        printf '\nDocker info:\n'
        if command -v docker >/dev/null 2>&1; then
            docker info 2>&1 || true
        else
            printf 'docker command unavailable\n'
        fi
    } >"$output"
}

sample_resources() {
    local samples="$evidence_dir/resource-samples.tsv"
    local process_samples="$evidence_dir/process-samples.tsv"
    local end_epoch="$1"
    printf 'timestamp_utc\tload1\tload5\tload15\tmem_available_kib\tdocker_containers\toxidedns_processes\ttotal_oxidedns_rss_kib\n' >"$samples"
    printf 'timestamp_utc\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm\targs\n' >"$process_samples"
    while :; do
        local now timestamp load_values mem_available docker_containers ps_summary
        now="$(date +%s)"
        timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        load_values="$(awk '{ printf "%s\t%s\t%s", $1, $2, $3 }' /proc/loadavg)"
        mem_available="$(awk '/MemAvailable:/ { print $2 }' /proc/meminfo)"
        if command -v docker >/dev/null 2>&1; then
            docker_containers="$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"
        else
            docker_containers=0
        fi
        ps_summary="$(
            ps -u "$(id -un)" -o pid=,pcpu=,pmem=,rss=,etime=,comm=,args= |
                awk '
					$0 ~ /(oxidedns|cargo|rustc|docker|named|knot|pdns|nsd)/ {
						count += 1;
						rss += $4;
					}
					END { printf "%d\t%d", count, rss }
				'
        )"
        printf '%s\t%s\t%s\t%s\t%s\n' "$timestamp" "$load_values" "$mem_available" "$docker_containers" "$ps_summary" >>"$samples"
        ps -u "$(id -un)" -o pid=,pcpu=,pmem=,rss=,etime=,comm=,args= |
            awk -v ts="$timestamp" '
				$0 ~ /(oxidedns|cargo|rustc|docker|named|knot|pdns|nsd)/ {
					pid=$1; pcpu=$2; pmem=$3; rss=$4; etime=$5; comm=$6;
					sub(/^ *[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", $0);
					printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, pid, pcpu, pmem, rss, etime, comm, $0;
				}
			' >>"$process_samples"
        if ((now >= end_epoch)); then
            break
        fi
        sleep "$sample_interval"
    done
}

write_summary() {
    local summary="$evidence_dir/soak-summary.env"
    python3 - "$evidence_dir/scenario-results.tsv" >"$summary" <<'PY'
import csv
import sys
from collections import Counter

path = sys.argv[1]
rows = []
try:
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
except FileNotFoundError:
    rows = []

status = Counter(row["status"] for row in rows)
scenario = Counter(row["scenario"] for row in rows if row["status"] == "passed")
print(f"scenario_runs_total={len(rows)}")
for key in sorted(status):
    print(f"status_{key}={status[key]}")
for key in sorted(scenario):
    print(f"passed_{key}={scenario[key]}")
failed = [row for row in rows if row["status"] == "failed"]
print(f"failed_count={len(failed)}")
if failed:
    print("failed_first=" + failed[0]["scenario_artifact_dir"])
PY
}

run_scenario() {
    local cycle="$1"
    local index="$2"
    local scenario="${scenario_names[$index]}"
    local script="${scenario_scripts[$index]}"
    local env_var="${scenario_env_vars[$index]}"
    local scenario_dir log
    local started ended status exit_status
    scenario_dir="$evidence_dir/scenarios/cycle-$(printf '%04d' "$cycle")/$scenario"
    log="$scenario_dir/scenario.log"
    mkdir -p "$scenario_dir"
    started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    set +e
    (
        cd "$repo_root"
        printf '$ %s=%q timeout --preserve-status %q %q\n' "$env_var" "$scenario_dir/artifacts" "$scenario_timeout" "$script"
        env "$env_var=$scenario_dir/artifacts" timeout --preserve-status "$scenario_timeout" "$repo_root/$script"
    ) >"$log" 2>&1
    exit_status=$?
    set -e
    ended="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if ((exit_status == 0)); then
        if grep -Eiq '(^|[[:space:]])skipping ' "$log"; then
            if [[ "$allow_skip" == "1" ]]; then
                status="skipped"
            else
                status="failed"
            fi
        else
            status="passed"
        fi
    else
        status="failed"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$cycle" "$scenario" "$status" "$exit_status" "$started" "$ended" "$scenario_dir" "$log" \
        >>"$evidence_dir/scenario-results.tsv"
    if [[ "$status" == "failed" ]]; then
        printf 'scenario failed: cycle=%s scenario=%s exit=%s log=%s\n' "$cycle" "$scenario" "$exit_status" "$log" >&2
        return 1
    fi
    return 0
}

main() {
    init_scenarios
    parse_args "$@"
    require_positive_integer "--duration" "$duration"
    require_positive_integer "--scenario-timeout" "$scenario_timeout"
    require_positive_integer "--cycle-sleep" "$cycle_sleep"
    require_positive_integer "--sample-interval" "$sample_interval"

    mapfile -t indices < <(selected_indices)
    if ((dry_run)); then
        printf 'large-surface soak dry-run\n'
        printf 'duration_seconds=%s\n' "$duration"
        printf 'scenario_timeout_seconds=%s\n' "$scenario_timeout"
        for index in "${indices[@]}"; do
            printf '%s\t%s\t%s\n' "${scenario_names[$index]}" "${scenario_scripts[$index]}" "${scenario_env_vars[$index]}"
        done
        exit 0
    fi

    mkdir -p "$evidence_dir/scenarios"
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'repo_root=%s\n' "$repo_root"
        printf 'duration_seconds=%s\n' "$duration"
        printf 'scenario_timeout_seconds=%s\n' "$scenario_timeout"
        printf 'cycle_sleep_seconds=%s\n' "$cycle_sleep"
        printf 'sample_interval_seconds=%s\n' "$sample_interval"
        printf 'allow_skip=%s\n' "$allow_skip"
        printf 'scenarios='
        local first=1 index
        for index in "${indices[@]}"; do
            ((first)) || printf ' '
            first=0
            printf '%s' "${scenario_names[$index]}"
        done
        printf '\n'
    } >"$evidence_dir/soak.env"
    printf 'cycle\tscenario\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path\n' >"$evidence_dir/scenario-results.tsv"
    record_host_info
    record_tool_versions

    local end_epoch cycle index
    end_epoch=$(($(date +%s) + duration))
    sample_resources "$end_epoch" &
    sampler_pid=$!
    trap 'if [[ -n "${sampler_pid:-}" ]]; then kill "$sampler_pid" 2>/dev/null || true; wait "$sampler_pid" 2>/dev/null || true; fi; write_summary' EXIT

    cycle=0
    while (($(date +%s) < end_epoch)); do
        cycle=$((cycle + 1))
        for index in "${indices[@]}"; do
            if ! run_scenario "$cycle" "$index"; then
                exit 1
            fi
            if (($(date +%s) >= end_epoch)); then
                break
            fi
        done
        write_summary
        if (($(date +%s) < end_epoch)); then
            sleep "$cycle_sleep"
        fi
    done
}

main "$@"
