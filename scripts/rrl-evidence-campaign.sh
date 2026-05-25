#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/rrl-evidence-campaign.sh [OPTIONS]

Run repeated RRL UDP interop evidence and retain command logs.

Options:
  --iterations COUNT    Number of interop runs to execute (default: 3)
  --duration SECONDS    Run completed iterations until this wall-clock duration is reached
  --evidence-dir DIR    Output directory (default: target/rrl-evidence/<timestamp>)
  --dry-run             Write config and print commands without running the interop script
  --list-config         Print resolved configuration and exit without writing files
  -h, --help            Show this help

Environment:
  BASH_BIN              Bash executable to use for the interop script (default: current bash)
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
interop_script="$repo_root/scripts/interop-rrl-udp.sh"
threshold_doc="$repo_root/docs/rrl-release-thresholds.md"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="$repo_root/target/rrl-evidence/$timestamp"
bash_bin="${BASH_BIN:-${BASH:-bash}}"
iterations=3
duration=""
iterations_set=0
duration_set=0
dry_run=0
list_config=0

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
        --iterations)
            (($# >= 2)) || die "--iterations requires a value"
            iterations="$2"
            iterations_set=1
            shift 2
            ;;
        --duration)
            (($# >= 2)) || die "--duration requires a value"
            duration="$2"
            duration_set=1
            shift 2
            ;;
        --evidence-dir)
            (($# >= 2)) || die "--evidence-dir requires a value"
            evidence_dir="$2"
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        --list-config)
            list_config=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            (($# == 0)) || die "unexpected positional argument: $1"
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            die "unexpected positional argument: $1"
            ;;
        esac
    done
}

resolve_config() {
    [[ "$evidence_dir" == /* ]] || evidence_dir="$repo_root/$evidence_dir"
    [[ -f "$interop_script" ]] || die "missing interop script: $interop_script"
    [[ -f "$threshold_doc" ]] || die "missing RRL threshold baseline document: $threshold_doc"
    require_positive_integer "--iterations" "$iterations"
    if ((duration_set)); then
        require_positive_integer "--duration" "$duration"
    fi
    if ((duration_set && iterations_set)); then
        die "use --iterations or --duration, not both"
    fi
}

print_config() {
    local mode="iterations"
    if ((duration_set)); then
        mode="duration"
    fi
    printf 'repo_root=%s\n' "$repo_root"
    printf 'interop_script=%s\n' "$interop_script"
    printf 'threshold_doc=%s\n' "$threshold_doc"
    printf 'evidence_dir=%s\n' "$evidence_dir"
    printf 'mode=%s\n' "$mode"
    printf 'iterations=%s\n' "$iterations"
    printf 'duration_seconds=%s\n' "${duration:-}"
    printf 'dry_run=%s\n' "$dry_run"
    printf 'bash=%s\n' "$bash_bin"
    printf 'command='
    printf '%q ' "$bash_bin" "$interop_script"
    printf '\n'
}

record_versions() {
    local versions_file="$1"
    {
        printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'repo_root=%s\n' "$repo_root"
        printf 'commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
        printf 'branch=%s\n' "$(git -C "$repo_root" branch --show-current 2>/dev/null || printf 'unknown')"
        printf 'uname=%s\n' "$(uname -a)"
        printf 'bash=%s\n' "$bash_bin"
        if command -v "$bash_bin" >/dev/null 2>&1; then
            "$bash_bin" --version | head -1
        else
            printf '%s not found on PATH\n' "$bash_bin"
        fi
        for tool in cargo rustc python3 curl shellcheck; do
            if command -v "$tool" >/dev/null 2>&1; then
                "$tool" --version 2>&1 | head -1
            else
                printf '%s not found on PATH\n' "$tool"
            fi
        done
    } >"$versions_file"
}

write_config() {
    local config_file="$1"
    print_config >"$config_file"
    {
        printf 'interop_script_sha256='
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$interop_script" | awk '{ print $1 }'
        else
            printf 'sha256sum not found\n'
        fi
    } >>"$config_file"
}

write_git_state() {
    git -C "$repo_root" status --short >"$evidence_dir/git-status.txt"
    git -C "$repo_root" diff --stat >"$evidence_dir/git-diff-stat.txt"
    git -C "$repo_root" diff --check >"$evidence_dir/git-diff-check.txt" 2>&1 || true
}

write_readme() {
    cat >"$evidence_dir/README.md" <<EOF
# OxideDNS RRL Evidence Campaign

- Created UTC: $timestamp
- Repository: $repo_root
- Interop script: $interop_script
- Threshold baseline: $threshold_doc

This retained artifact wraps scripts/interop-rrl-udp.sh and records repeated
runtime UDP RRL drop/slip evidence. Any failed interop run fails the campaign.
The campaign also writes aggregate.tsv and aggregate-summary.env so release
review can inspect per-run and campaign-total RRL evidence without opening each
raw artifact directory.

threshold-decision.tsv records the current SRS v0.7 RRL baseline used for
release review. The slip value follows the SRS body default, but Appendix C.5
confirmation remains pending and must be handled in release notes.
EOF
}

write_threshold_decision() {
    local decision_file="$evidence_dir/threshold-decision.tsv"

    {
        printf 'setting\tvalue\trequirement\tstatus\tnote\n'
        printf 'enabled\ttrue\tODS-FR-RRL-001\timplemented-srs-body-default\tRRL is enabled by default\n'
        printf 'ipv4_prefix_len\t24\tODS-FR-RRL-002\timplemented-srs-body-default\tIPv4 accounting prefix length\n'
        printf 'ipv6_prefix_len\t56\tODS-FR-RRL-002\timplemented-srs-body-default\tIPv6 accounting prefix length\n'
        printf 'positive_per_second\t20\tODS-FR-RRL-003\timplemented-srs-body-default\tPositive response rate limit\n'
        printf 'nxdomain_per_second\t5\tODS-FR-RRL-003\timplemented-srs-body-default\tNXDOMAIN response rate limit\n'
        printf 'nodata_per_second\t10\tODS-FR-RRL-003\timplemented-srs-body-default\tNODATA response rate limit\n'
        printf 'referral_per_second\t10\tODS-FR-RRL-003\timplemented-srs-body-default\tReferral response rate limit\n'
        printf 'error_per_second\t5\tODS-FR-RRL-003\timplemented-srs-body-default\tError response rate limit\n'
        printf 'slip\t2\tODS-FR-RRL-005\timplemented-srs-body-default-c5-pending\tAppendix C.5 confirmation remains pending\n'
        printf 'max_keys\t100000\tODS-FR-RRL-010\timplemented-srs-body-default\tMaximum tracked accounting keys\n'
        printf 'summary_log_interval_secs\t60\tODS-FR-RRL-011\timplemented-srs-body-default\tAggregate RRL summary interval\n'
    } >"$decision_file"
}

run_one() {
    local run_number="$1"
    local run_id
    local run_log
    local command_file
    local run_summary_file
    local artifact_dir
    local status
    local started
    local finished
    local started_epoch
    local finished_epoch
    local elapsed_seconds
    local -a cmd

    printf -v run_id 'run-%03d' "$run_number"
    run_log="$evidence_dir/logs/$run_id.log"
    command_file="$evidence_dir/logs/$run_id.command"
    artifact_dir="$evidence_dir/artifacts/$run_id"
    run_summary_file="$artifact_dir/run-summary.env"
    cmd=("$bash_bin" "$interop_script")
    mkdir -p "$artifact_dir"

    {
        printf 'run=%s\n' "$run_id"
        printf 'command='
        printf '%q ' "${cmd[@]}"
        printf '\n'
    } >"$command_file"

    printf 'Running %s; log: %s\n' "$run_id" "$run_log"
    started_epoch="$(date +%s)"
    started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    set +e
    (
        cd "$repo_root"
        OXIDEDNS_RRL_UDP_ARTIFACT_DIR="$artifact_dir" "${cmd[@]}"
    ) >"$run_log" 2>&1
    status=$?
    set -e
    finished_epoch="$(date +%s)"
    finished="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    elapsed_seconds=$((finished_epoch - started_epoch))

    {
        printf 'run=%s status=%s started=%s finished=%s log=%s\n' \
            "$run_id" "$status" "$started" "$finished" "$run_log"
    } >>"$evidence_dir/summary.txt"

    {
        printf 'run=%s\n' "$run_id"
        printf 'status=%s\n' "$status"
        printf 'started=%s\n' "$started"
        printf 'finished=%s\n' "$finished"
        printf 'elapsed_seconds=%s\n' "$elapsed_seconds"
        printf 'log=%s\n' "$run_log"
    } >"$run_summary_file"

    if ((status != 0)); then
        printf 'RRL evidence %s failed with exit %s\n' "$run_id" "$status" >&2
        printf -- '---- %s tail ----\n' "$run_log" >&2
        tail -160 "$run_log" >&2 || true
        return "$status"
    fi
}

env_value() {
    local key="$1"
    local path="$2"
    awk -F= -v key="$key" '$1 == key { print $2; found = 1; exit } END { if (!found) print "" }' "$path"
}

write_aggregate() {
    local aggregate_tsv="$evidence_dir/aggregate.tsv"
    local aggregate_summary="$evidence_dir/aggregate-summary.env"
    local commit
    local artifact_dir
    local run_summary
    local client_summary
    local metrics_summary
    local run_id
    local run_count=0
    local status
    local started
    local finished
    local elapsed_seconds
    local attempts
    local responses
    local dropped
    local truncated
    local rrl_subject_total
    local rrl_dropped_total
    local rrl_truncated_total
    local queries_truncated_total
    local rrl_keys_tracked
    local rrl_categories_checked

    commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    printf 'run\tstatus\tstarted\tfinished\telapsed_seconds\tcommit\trequirements\tattempts\tresponses\tdropped\ttruncated\trrl_subject_total\trrl_dropped_total\trrl_truncated_total\tqueries_truncated_total\trrl_keys_tracked\trrl_categories_checked\n' >"$aggregate_tsv"

    for artifact_dir in "$evidence_dir"/artifacts/run-*; do
        [[ -d "$artifact_dir" ]] || continue
        run_count=$((run_count + 1))
        run_summary="$artifact_dir/run-summary.env"
        client_summary="$artifact_dir/client-summary.env"
        metrics_summary="$artifact_dir/metrics-summary.env"
        run_id="$(basename "$artifact_dir")"

        status="$(env_value status "$run_summary")"
        started="$(env_value started "$run_summary")"
        finished="$(env_value finished "$run_summary")"
        elapsed_seconds="$(env_value elapsed_seconds "$run_summary")"
        attempts="$(env_value attempts "$client_summary")"
        responses="$(env_value responses "$client_summary")"
        dropped="$(env_value dropped "$client_summary")"
        truncated="$(env_value truncated "$client_summary")"
        rrl_subject_total="$(env_value rrl_subject_total "$metrics_summary")"
        rrl_dropped_total="$(env_value rrl_dropped_total "$metrics_summary")"
        rrl_truncated_total="$(env_value rrl_truncated_total "$metrics_summary")"
        queries_truncated_total="$(env_value queries_truncated_total "$metrics_summary")"
        rrl_keys_tracked="$(env_value rrl_keys_tracked "$metrics_summary")"
        rrl_categories_checked="$(env_value rrl_categories_checked "$metrics_summary")"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$run_id" "$status" "$started" "$finished" "$elapsed_seconds" "$commit" \
            "ODS-FR-RRL-001..ODS-FR-RRL-012" "$attempts" "$responses" "$dropped" \
            "$truncated" "$rrl_subject_total" "$rrl_dropped_total" "$rrl_truncated_total" \
            "$queries_truncated_total" "$rrl_keys_tracked" "$rrl_categories_checked" \
            >>"$aggregate_tsv"
    done

    if ((run_count == 0)); then
        die "no RRL run artifacts found to aggregate"
    fi

    awk -F'\t' '
    NR > 1 {
      runs++
      attempts += $8
      responses += $9
      dropped += $10
      truncated += $11
      subject += $12
      metric_dropped += $13
      metric_truncated += $14
      queries_truncated += $15
    }
    END {
      printf "aggregate_runs=%d\n", runs
      printf "aggregate_attempts=%d\n", attempts
      printf "aggregate_responses=%d\n", responses
      printf "aggregate_client_dropped=%d\n", dropped
      printf "aggregate_client_truncated=%d\n", truncated
      printf "aggregate_metric_subject=%d\n", subject
      printf "aggregate_metric_dropped=%d\n", metric_dropped
      printf "aggregate_metric_truncated=%d\n", metric_truncated
      printf "aggregate_queries_truncated=%d\n", queries_truncated
      printf "requirements=ODS-FR-RRL-001..ODS-FR-RRL-012\n"
    }
  ' "$aggregate_tsv" >"$aggregate_summary"
}

run_campaign() {
    local run_count=0
    local start_epoch
    local elapsed

    start_epoch="$(date +%s)"
    : >"$evidence_dir/summary.txt"

    if ((duration_set)); then
        while true; do
            run_count=$((run_count + 1))
            run_one "$run_count"
            elapsed=$(($(date +%s) - start_epoch))
            ((elapsed >= duration)) && break
        done
    else
        for ((run_count = 1; run_count <= iterations; run_count++)); do
            run_one "$run_count"
        done
    fi

    printf 'rrl_runs_completed=%s\n' "$run_count" >>"$evidence_dir/summary.txt"
    write_aggregate
}

main() {
    parse_args "$@"
    resolve_config

    if ((list_config)); then
        print_config
        exit 0
    fi

    mkdir -p "$evidence_dir/logs"
    write_config "$evidence_dir/config.txt"
    record_versions "$evidence_dir/tool-versions.txt"
    write_git_state
    write_readme
    write_threshold_decision

    if ((dry_run)); then
        printf 'DRY RUN: would run RRL evidence campaign with this configuration:\n'
        print_config
        printf 'rrl evidence dry-run files written to %s\n' "$evidence_dir"
        exit 0
    fi

    command -v "$bash_bin" >/dev/null 2>&1 || die "$bash_bin not found on PATH"
    run_campaign
    printf 'rrl evidence retained at %s\n' "$evidence_dir"
}

main "$@"
