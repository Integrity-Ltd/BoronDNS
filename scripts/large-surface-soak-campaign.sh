#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/campaign-env.sh
source "$repo_root/scripts/campaign-env.sh"

usage() {
    cat <<'EOF'
Usage: scripts/large-surface-soak-campaign.sh COMMAND [OPTIONS]

Prepare and manage a two-host large-surface soak campaign.

Commands:
  plan      Write a local campaign manifest and remote launch commands.
  launch    Create a plan, optionally install prerequisites, then start systemd units.
  resume    Resume failed or inactive units from an existing evidence plan.
  status    Inspect remote soak unit status and current summaries.
  collect   Copy remote evidence directories back to the local manifest.
  cleanup   Remove only verified inactive campaign units and owned build trees.

Options:
  --evidence-dir DIR       Local plan/evidence dir.
  --campaign-id ID         Campaign id used in local and remote paths.
  --host HOST              SSH target; repeatable. Defaults to borondns-1 oxidegun-1.
  --remote-repo DIR        Remote repo root. Default: /home/codex/borondns-fuzz.
  --remote-evidence DIR    Remote evidence root. Default: REMOTE_REPO/target/evidence/large-surface-soak-ID.
  --duration SECONDS       Soak duration. Default: 2592000 (30 days).
  --scenario NAME          Scenario to include; repeatable. Defaults to runner default set.
  --scenario-timeout SECS  Per-scenario timeout. Default: 1800.
  --scenario-kill-after SECS
                           Hard-kill grace after timeout. Default: 30.
  --docker-cleanup-timeout SECS
                           Timeout for each owned Docker cleanup operation. Default: 30.
  --cycle-sleep SECS       Sleep between full cycles. Default: 5.
  --sample-interval SECS   Resource sample interval. Default: 60.
  --install-prereqs        Install Docker, BIND, dnsutils, curl, and OpenSSL before launch.
  --fail-on-skip           Make scenario self-skips fail the soak service.
  -h, --help               Show this help.

Environment:
  BORONDNS_LARGE_SOAK_HOSTS
  BORONDNS_LARGE_SOAK_REMOTE_REPO
  BORONDNS_LARGE_SOAK_REMOTE_EVIDENCE
  BORONDNS_LARGE_SOAK_DURATION_SECONDS
  BORONDNS_LARGE_SOAK_DOCKER_CLEANUP_TIMEOUT_SECONDS
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

large_soak_bounded_probe() {
    local probe_timeout="${BORONDNS_LARGE_SOAK_PREFLIGHT_TIMEOUT_SECONDS:-30}"
    local probe_kill_after="${BORONDNS_LARGE_SOAK_PREFLIGHT_KILL_AFTER_SECONDS:-5}"
    [[ "$probe_timeout" =~ ^[1-9][0-9]*$ && "$probe_kill_after" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid large-soak preflight timeout configuration\n' >&2
        return 1
    }
    ((probe_timeout <= 300 && probe_kill_after <= 60)) || {
        printf 'large-soak preflight timeout configuration exceeds supported bounds\n' >&2
        return 1
    }
    timeout --preserve-status --kill-after="$probe_kill_after" "$probe_timeout" "$@"
}

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
command=""
campaign_id="$timestamp"
evidence_dir=""
remote_repo="${BORONDNS_LARGE_SOAK_REMOTE_REPO:-/home/codex/borondns-fuzz}"
remote_evidence="${BORONDNS_LARGE_SOAK_REMOTE_EVIDENCE:-}"
duration="${BORONDNS_LARGE_SOAK_DURATION_SECONDS:-2592000}"
duration_seconds=""
scenario_timeout="${BORONDNS_LARGE_SOAK_SCENARIO_TIMEOUT_SECONDS:-1800}"
scenario_timeout_seconds=""
scenario_kill_after="${BORONDNS_LARGE_SOAK_SCENARIO_KILL_AFTER_SECONDS:-30}"
scenario_kill_after_seconds=""
docker_cleanup_timeout="${BORONDNS_LARGE_SOAK_DOCKER_CLEANUP_TIMEOUT_SECONDS:-30}"
docker_cleanup_timeout_seconds=""
docker_cleanup_operation_count=6
docker_cleanup_kill_after_seconds=5
resource_sampler_terminal_budget_seconds=45
service_stop_overhead_seconds=30
docker_cleanup_total_budget_seconds=""
service_runtime_max_seconds=""
service_stop_timeout_seconds=""
cycle_sleep="${BORONDNS_LARGE_SOAK_CYCLE_SLEEP_SECONDS:-5}"
cycle_sleep_seconds=""
sample_interval="${BORONDNS_LARGE_SOAK_SAMPLE_INTERVAL_SECONDS:-60}"
sample_interval_seconds=""
install_prereqs=0
allow_skip=1
cargo_sha256=""
rustc_sha256=""
preflight_source_commit=""
preflight_source_status=""
preflight_source_clean=""
hosts=()
scenarios=()
resume_override_used=0
plan_staging_dir=""
semantic_reference_dir=""
plan_staging_cleanup_root=""
semantic_reference_cleanup_root=""
validated_command_dir=""
known_scenarios=(
    bind_catalog bind_xot_catalog powerdns_catalog_tsig powerdns_catalog_extension
    powerdns_split_primaries bind_axfr bind_tsig_axfr bind_notify bind_ixfr
    nsd_axfr nsd_tsig_axfr nsd_notify knot_axfr knot_tsig_axfr knot_notify
    knot_ixfr knot_xot knot_xot_tsig dnssec_serve dnssec_nsec3 unknown_rr
    unknown_rr_bad_transfer negative_responses notify_negative tcp_truncation
    edns_behavior dns_cookie ixfr_notimp rrl_udp chaos_queries
)

cleanup_plan_staging() {
    local final_status="$?" cleanup_failed=0 path prefix label lock_root acquired
    trap - EXIT
    for prefix in large_plan_staging large_semantic_reference; do
        case "$prefix" in
        large_plan_staging)
            path="$plan_staging_dir"
            label="large-surface plan staging"
            lock_root="$plan_staging_cleanup_root"
            ;;
        large_semantic_reference)
            path="$semantic_reference_dir"
            label="large-surface semantic reference"
            lock_root="$semantic_reference_cleanup_root"
            ;;
        esac
        [[ -n "$path" ]] || continue
        if [[ ! -e "$path" && ! -L "$path" ]]; then
            printf '%s exit cleanup lost its tracked pathname: %s\n' "$label" "$path" >&2
            cleanup_failed=1
            continue
        fi
        acquired=0
        if [[ -z "${campaign_lock_pid:-}" ]]; then
            if [[ -z "$lock_root" ]] ||
                ! campaign_acquire_private_lock "$lock_root" "$(realpath -ms "$path"):exit-cleanup" \
                    "$label exit cleanup lock"; then
                printf 'cannot acquire %s authority for exit cleanup: %s\n' "$label" "$path" >&2
                cleanup_failed=1
                continue
            fi
            acquired=1
        fi
        if ! campaign_remove_private_temporary_tree "$path" "$prefix" "$label"; then
            printf 'identity-bound %s exit cleanup failed: %s\n' "$label" "$path" >&2
            cleanup_failed=1
        fi
        if ((acquired != 0)) && ! campaign_release_private_lock; then
            printf '%s exit cleanup lock release failed\n' "$label" >&2
            cleanup_failed=1
        fi
    done
    if ((cleanup_failed != 0 && final_status == 0)); then
        final_status=74
    fi
    exit "$final_status"
}
trap cleanup_plan_staging EXIT

shell_quote() {
    printf '%q' "$1"
}

systemd_escape_fragment() {
    local value="$1"
    value="${value//[^A-Za-z0-9_.-]/_}"
    printf '%s' "$value"
}

require_canonical_campaign_id() {
    local value="$1"
    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ && "$value" != *..* && ${#value} -le 96 ]] ||
        die "--campaign-id must be a canonical systemd-safe identifier of at most 96 characters: $value"
    [[ "$(systemd_escape_fragment "$value")" == "$value" ]] ||
        die "--campaign-id is not systemd-safe: $value"
}

require_canonical_absolute_path() {
    local name="$1" value="$2" canonical
    [[ "$value" == /* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] ||
        die "$name must be an absolute canonical path: $value"
    canonical="$(realpath -ms -- "$value")" || die "cannot canonicalize $name: $value"
    [[ "$canonical" == "$value" && "$value" != / ]] ||
        die "$name must be an absolute canonical non-root path: $value"
}

validate_plan_fields() {
    require_canonical_campaign_id "$campaign_id"
    require_canonical_absolute_path "--evidence-dir" "$evidence_dir"
    require_canonical_absolute_path "--remote-repo" "$remote_repo"
    require_canonical_absolute_path "--remote-evidence" "$remote_evidence"
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

require_bounded_positive_integer() {
    local name="$1" value="$2" maximum="$3"
    require_positive_integer "$name" "$value"
    if ((${#value} > ${#maximum})) ||
        { ((${#value} == ${#maximum})) && [[ "$value" > "$maximum" ]]; }; then
        die "$name exceeds the supported maximum $maximum: $value"
    fi
}

prevalidate_plan_source() {
    preflight_source_commit="$(large_soak_bounded_probe git -C "$repo_root" rev-parse HEAD 2>/dev/null)" ||
        die "cannot resolve repository HEAD"
    [[ "$preflight_source_commit" =~ ^[0-9a-f]{40}$ ]] ||
        die "repository HEAD is not a canonical SHA-1 commit"
    campaign_git_status_capture preflight_source_status "$repo_root" ||
        die "cannot verify repository cleanliness"
    preflight_source_clean=1
    if [[ -n "$preflight_source_status" ]]; then
        preflight_source_clean=0
        [[ "${BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY:-0}" == 1 ]] || {
            printf 'local repository is dirty; refusing campaign plan from %s\n%s\n' \
                "$repo_root" "$preflight_source_status" >&2
            exit 1
        }
    fi
}

list_contains_word() {
    local needle="$1"
    shift
    local value
    for value in "$@"; do
        [[ "$value" != "$needle" ]] || return 0
    done
    return 1
}

campaign_command_matches_saved_tools() {
    local actual="$1"
    local reference="$2"
    local expected_line
    for expected_line in "expected_cargo_sha256=$cargo_sha256" "expected_rustc_sha256=$rustc_sha256"; do
        [[ "$(grep -Fxc "$expected_line" "$actual")" == 1 ]] || return 1
    done
    cmp -s \
        <(sed -E 's/^(expected_(cargo|rustc)_sha256)=.*/\1=<authenticated-saved-digest>/' "$actual") \
        <(sed -E 's/^(expected_(cargo|rustc)_sha256)=.*/\1=<authenticated-saved-digest>/' "$reference")
}

parse_args() {
    (($# > 0)) || {
        usage
        exit 64
    }
    command="$1"
    shift
    case "$command" in
    plan | launch | resume | status | collect | cleanup) ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        die "unknown command: $command"
        ;;
    esac

    while (($# > 0)); do
        case "$1" in
        --evidence-dir)
            (($# >= 2)) || die "--evidence-dir requires a value"
            evidence_dir="$2"
            shift 2
            ;;
        --campaign-id)
            (($# >= 2)) || die "--campaign-id requires a value"
            campaign_id="$2"
            resume_override_used=1
            shift 2
            ;;
        --host)
            (($# >= 2)) || die "--host requires a value"
            hosts+=("$2")
            resume_override_used=1
            shift 2
            ;;
        --remote-repo)
            (($# >= 2)) || die "--remote-repo requires a value"
            remote_repo="$2"
            resume_override_used=1
            shift 2
            ;;
        --remote-evidence)
            (($# >= 2)) || die "--remote-evidence requires a value"
            remote_evidence="$2"
            resume_override_used=1
            shift 2
            ;;
        --duration)
            (($# >= 2)) || die "--duration requires a value"
            duration="$2"
            resume_override_used=1
            shift 2
            ;;
        --scenario)
            (($# >= 2)) || die "--scenario requires a value"
            scenarios+=("$2")
            resume_override_used=1
            shift 2
            ;;
        --scenario-timeout)
            (($# >= 2)) || die "--scenario-timeout requires a value"
            scenario_timeout="$2"
            resume_override_used=1
            shift 2
            ;;
        --scenario-kill-after)
            (($# >= 2)) || die "--scenario-kill-after requires a value"
            scenario_kill_after="$2"
            resume_override_used=1
            shift 2
            ;;
        --docker-cleanup-timeout)
            (($# >= 2)) || die "--docker-cleanup-timeout requires a value"
            docker_cleanup_timeout="$2"
            resume_override_used=1
            shift 2
            ;;
        --cycle-sleep)
            (($# >= 2)) || die "--cycle-sleep requires a value"
            cycle_sleep="$2"
            resume_override_used=1
            shift 2
            ;;
        --sample-interval)
            (($# >= 2)) || die "--sample-interval requires a value"
            sample_interval="$2"
            resume_override_used=1
            shift 2
            ;;
        --install-prereqs)
            install_prereqs=1
            resume_override_used=1
            shift
            ;;
        --fail-on-skip)
            allow_skip=0
            resume_override_used=1
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

set_defaults() {
    if [[ -z "$evidence_dir" ]]; then
        evidence_dir="$repo_root/target/evidence/large-surface-soak-$campaign_id"
    fi
    if [[ -z "$remote_evidence" ]]; then
        remote_evidence="$remote_repo/target/evidence/large-surface-soak-$campaign_id"
    fi
    validate_plan_fields

    if ((${#hosts[@]} == 0)); then
        if [[ -n "${BORONDNS_LARGE_SOAK_HOSTS:-}" ]]; then
            # shellcheck disable=SC2206
            hosts=(${BORONDNS_LARGE_SOAK_HOSTS})
        else
            hosts=(borondns-1 oxidegun-1)
        fi
    fi
    ((${#hosts[@]} > 0)) || die "at least one host is required"
    local -A seen_hosts=() canonical_host_owners=()
    local host safe_host
    for host in "${hosts[@]}"; do
        [[ "$host" =~ ^[A-Za-z0-9_.@:+-]+$ && "$host" != -* ]] ||
            die "invalid or option-like large-surface campaign host: $host"
        campaign_remote_copy_host "$host" >/dev/null ||
            die "invalid large-surface campaign SSH host syntax: $host"
        [[ -z "${seen_hosts[$host]:-}" ]] || die "duplicate large-surface campaign host: $host"
        seen_hosts[$host]=1
        safe_host="$(systemd_escape_fragment "$host")"
        if [[ -n "${canonical_host_owners[$safe_host]:-}" && "${canonical_host_owners[$safe_host]}" != "$host" ]]; then
            die "large-surface campaign hosts collide after canonicalization: ${canonical_host_owners[$safe_host]} and $host"
        fi
        canonical_host_owners[$safe_host]="$host"
        ((${#campaign_id} + ${#safe_host} + 24 <= 255)) ||
            die "large-surface campaign id and host exceed the systemd unit-name limit: $campaign_id $host"
    done
    local -A seen_scenarios=()
    local scenario known matched
    if ((${#scenarios[@]} == 0)); then
        scenarios=("${known_scenarios[@]}")
    fi
    for scenario in "${scenarios[@]}"; do
        matched=0
        for known in "${known_scenarios[@]}"; do
            [[ "$scenario" != "$known" ]] || matched=1
        done
        ((matched)) || die "unknown large-surface scenario: $scenario"
        [[ -z "${seen_scenarios[$scenario]:-}" ]] || die "duplicate large-surface scenario: $scenario"
        seen_scenarios[$scenario]=1
    done
    local maximum_runtime=2147483647 runtime_reserve=3600 runtime_component
    require_bounded_positive_integer "--duration" "$duration" "$maximum_runtime"
    runtime_reserve=$((runtime_reserve + duration))
    for runtime_component in "$scenario_timeout" "$scenario_kill_after"; do
        require_bounded_positive_integer "large-soak runtime component" "$runtime_component" "$maximum_runtime"
        ((runtime_component <= maximum_runtime - runtime_reserve)) ||
            die "large-soak service runtime exceeds supported maximum $maximum_runtime"
        runtime_reserve=$((runtime_reserve + runtime_component))
    done
    require_bounded_positive_integer "--docker-cleanup-timeout" "$docker_cleanup_timeout" "$maximum_runtime"
    ((docker_cleanup_timeout <= maximum_runtime - docker_cleanup_kill_after_seconds)) ||
        die "large-soak Docker cleanup timeout exceeds supported arithmetic"
    ((docker_cleanup_timeout + docker_cleanup_kill_after_seconds <= maximum_runtime / docker_cleanup_operation_count)) ||
        die "large-soak Docker cleanup budget exceeds supported arithmetic"
    docker_cleanup_total_budget_seconds=$((\
        docker_cleanup_operation_count * (docker_cleanup_timeout + docker_cleanup_kill_after_seconds)))
    for runtime_component in "$docker_cleanup_total_budget_seconds" "$resource_sampler_terminal_budget_seconds"; do
        ((runtime_component <= maximum_runtime - runtime_reserve)) ||
            die "large-soak service runtime exceeds supported maximum $maximum_runtime"
        runtime_reserve=$((runtime_reserve + runtime_component))
    done
    service_runtime_max_seconds="$runtime_reserve"
    ((docker_cleanup_total_budget_seconds <= maximum_runtime - resource_sampler_terminal_budget_seconds - service_stop_overhead_seconds)) ||
        die "large-soak stop timeout exceeds supported maximum $maximum_runtime"
    service_stop_timeout_seconds=$((\
        docker_cleanup_total_budget_seconds + resource_sampler_terminal_budget_seconds + service_stop_overhead_seconds))
    require_bounded_positive_integer "--cycle-sleep" "$cycle_sleep" "$maximum_runtime"
    require_bounded_positive_integer "--sample-interval" "$sample_interval" "$maximum_runtime"
    command -v rustup >/dev/null 2>&1 || die "rustup is required to authenticate large-soak tools"
    local planned_cargo planned_rustc
    planned_cargo="$(large_soak_bounded_probe rustup which cargo 2>/dev/null)" || die "cannot resolve planned cargo"
    planned_rustc="$(large_soak_bounded_probe rustup which rustc 2>/dev/null)" || die "cannot resolve planned rustc"
    cargo_sha256="$(campaign_sha256 "$(realpath -e "$planned_cargo")")" || die "cannot hash planned cargo"
    rustc_sha256="$(campaign_sha256 "$(realpath -e "$planned_rustc")")" || die "cannot hash planned rustc"
    # Authenticate the source before write_plan can create the plan parent or
    # its private lock namespace. write_plan repeats this check under the lock.
    prevalidate_plan_source
}

scenario_args_string() {
    local scenario args=()
    for scenario in "${scenarios[@]}"; do
        args+=(--scenario "$scenario")
    done
    ((${#args[@]} > 0)) || return 0
    printf '%q ' "${args[@]}"
}

write_plan() {
    local plan_parent
    plan_parent="$(dirname "$evidence_dir")"
    mkdir -p "$plan_parent"
    campaign_require_owned_real_directory "$plan_parent" "large-surface plan parent" || die "unsafe large-surface plan parent"
    campaign_acquire_private_lock "$plan_parent" "$(realpath -ms "$evidence_dir"):plan" "large-surface campaign plan lock" ||
        die "could not acquire the private large-surface campaign plan lock"
    campaign_assert_private_lock || die "large-surface campaign plan lock broker exited"
    if [[ -e "$evidence_dir" ]]; then
        campaign_require_owned_real_directory "$evidence_dir" "large-surface campaign plan directory" || die "unsafe campaign plan directory"
        [[ -z "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
            die "campaign plan directory is non-empty; use resume or choose a new path: $evidence_dir"
    fi
    # Recheck provenance after acquiring the publication lock so the manifest
    # records the source state governing the actual plan write.
    prevalidate_plan_source
    local source_commit="$preflight_source_commit"
    local source_clean="$preflight_source_clean"
    local final_evidence="$evidence_dir"
    plan_staging_cleanup_root="$plan_parent"
    campaign_prepare_private_temporary_tree "$plan_parent" borondns-large-plan-staging \
        large_plan_staging plan_staging_dir || die "could not create private large-surface plan staging"
    local staging="$plan_staging_dir"
    mkdir -p "$staging/commands"
    install -m 0555 -- "$repo_root/scripts/validate-collected-campaign.py" \
        "$staging/validate-collected-campaign.py"
    {
        campaign_env_write campaign_id "$campaign_id"
        campaign_env_write created_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        campaign_env_write repo_root "$repo_root"
        campaign_env_write source_commit "$source_commit"
        campaign_env_write source_clean "$source_clean"
        campaign_env_write remote_repo "$remote_repo"
        campaign_env_write remote_evidence "$remote_evidence"
        campaign_env_write duration_seconds "$duration"
        campaign_env_write scenario_timeout_seconds "$scenario_timeout"
        campaign_env_write scenario_kill_after_seconds "$scenario_kill_after"
        campaign_env_write docker_cleanup_timeout_seconds "$docker_cleanup_timeout"
        campaign_env_write cycle_sleep_seconds "$cycle_sleep"
        campaign_env_write sample_interval_seconds "$sample_interval"
        campaign_env_write install_prereqs "$install_prereqs"
        campaign_env_write allow_skip "$allow_skip"
        campaign_env_write cargo_sha256 "$cargo_sha256"
        campaign_env_write rustc_sha256 "$rustc_sha256"
        campaign_env_write hosts "${hosts[*]}"
        campaign_env_write scenarios "${scenarios[*]}"
    } >"$staging/campaign.env"

    printf 'host\tremote_evidence_dir\tsystemd_unit\tremote_command_file\n' >"$staging/assignments.tsv"

    local safe_campaign host safe_host host_evidence systemd_unit command_file remote_runner remote_build_root
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    for host in "${hosts[@]}"; do
        safe_host="$(systemd_escape_fragment "$host")"
        host_evidence="$remote_evidence/host/$safe_host"
        systemd_unit="borondns-soak-$safe_campaign-$safe_host.service"
        remote_runner="$remote_evidence/launch/${systemd_unit%.service}-run.sh"
        remote_build_root="/var/tmp/borondns-large-$safe_campaign/$safe_host"
        command_file="$final_evidence/commands/$host-launch.sh"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'set -euo pipefail\n'
            printf 'remote_repo=%q\n' "$remote_repo"
            printf 'remote_evidence=%q\n' "$remote_evidence"
            printf 'host_evidence=%q\n' "$host_evidence"
            printf 'systemd_unit=%q\n' "$systemd_unit"
            printf 'remote_runner=%q\n' "$remote_runner"
            printf 'remote_build_root=%q\n' "$remote_build_root"
            printf 'duration=%q\n' "$duration"
            printf 'scenario_timeout=%q\n' "$scenario_timeout"
            printf 'scenario_kill_after=%q\n' "$scenario_kill_after"
            printf 'docker_cleanup_timeout=%q\n' "$docker_cleanup_timeout"
            printf 'docker_cleanup_total_budget_seconds=%q\n' "$docker_cleanup_total_budget_seconds"
            printf 'service_runtime_max_seconds=%q\n' "$service_runtime_max_seconds"
            printf 'service_stop_timeout_seconds=%q\n' "$service_stop_timeout_seconds"
            printf 'cycle_sleep=%q\n' "$cycle_sleep"
            printf 'sample_interval=%q\n' "$sample_interval"
            printf 'install_prereqs=%q\n' "$install_prereqs"
            printf 'allow_skip=%q\n' "$allow_skip"
            printf 'expected_commit=%q\n' "$source_commit"
            printf 'campaign_helper_sha256=%q\n' "$(campaign_sha256 "$repo_root/scripts/campaign-env.sh")"
            printf 'campaign_lock_helper_sha256=%q\n' "$(campaign_sha256 "$repo_root/scripts/campaign-lock-helper.py")"
            printf 'expected_cargo_sha256=%q\n' "$cargo_sha256"
            printf 'expected_rustc_sha256=%q\n' "$rustc_sha256"
            printf 'scenario_args=%q\n' "$(scenario_args_string)"
            printf 'expected_scenarios=('
            printf '%q ' "${scenarios[@]}"
            printf ')\n'
            cat <<'REMOTE'

require_resume="${BORONDNS_CAMPAIGN_REQUIRE_RESUME:-0}"
unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
require_owned_real_dir() {
	local path="$1" label="$2" lexical real
	[[ -d "$path" && ! -L "$path" ]] || { printf 'unsafe %s (not a real directory): %s\n' "$label" "$path" >&2; return 1; }
	lexical="$(realpath -ms "$path")" || return 1
	real="$(realpath -e "$path")" || return 1
	[[ "$lexical" == "$real" ]] || { printf 'unsafe %s (symlink traversal): %s\n' "$label" "$path" >&2; return 1; }
	[[ "$(stat -c %u "$real")" == "$(id -u)" ]] || { printf 'unsafe %s (owner mismatch): %s\n' "$label" "$path" >&2; return 1; }
}
ensure_owned_dir() {
	local root="$1" path="$2" label="$3" root_real path_real
	require_owned_real_dir "$root" "$label root" || return 1
	if [[ -e "$path" || -L "$path" ]]; then
		require_owned_real_dir "$path" "$label" || return 1
	else
		mkdir -m 0700 "$path" 2>/dev/null || require_owned_real_dir "$path" "$label" || return 1
		require_owned_real_dir "$path" "$label" || return 1
	fi
	root_real="$(realpath -e "$root")" || return 1
	path_real="$(realpath -e "$path")" || return 1
	[[ "$path_real" == "$root_real"/* ]] || { printf '%s escapes root: %s\n' "$label" "$path" >&2; return 1; }
}
unit_is_exactly_active() {
	local unit="$1" fragment_expected="$2" runner_prefix="$3" properties load active fragment exec_start runner
	if ! properties="$(timeout --preserve-status --kill-after=5 30 systemctl show "$unit" -p LoadState -p ActiveState -p FragmentPath -p ExecStart --no-pager)"; then
		printf 'systemctl state probe failed for %s\n' "$unit" >&2
		return 2
	fi
	load="$(awk -F= '$1 == "LoadState" { print substr($0, index($0, "=") + 1) }' <<<"$properties")"
	active="$(awk -F= '$1 == "ActiveState" { print substr($0, index($0, "=") + 1) }' <<<"$properties")"
	fragment="$(awk -F= '$1 == "FragmentPath" { print substr($0, index($0, "=") + 1) }' <<<"$properties")"
	exec_start="$(awk -F= '$1 == "ExecStart" { print substr($0, index($0, "=") + 1) }' <<<"$properties")"
	if [[ "$load" == not-found ]]; then
		if [[ -e "$fragment_expected" || -L "$fragment_expected" ]]; then
			[[ -f "$fragment_expected" && ! -L "$fragment_expected" ]] || return 2
			runner="$(campaign_validate_systemd_fragment_runner "$fragment_expected" "$runner_prefix")" || return 2
		fi
		return 1
	fi
	[[ "$load" == loaded ]] || return 2
	case "$active" in active | activating | reloading | inactive | failed) ;; *) return 2 ;; esac
	[[ "$fragment" == "$fragment_expected" && -f "$fragment" && ! -L "$fragment" ]] || return 2
	runner="$(campaign_validate_systemd_fragment_runner "$fragment" "$runner_prefix")" || return 2
	[[ "$exec_start" == "{ path=$runner ;"* ]] || return 2
	[[ "$active" != inactive && "$active" != failed ]] || return 1
}
soak_evidence_is_complete() {
	local -a validator=(
		python3 "$remote_repo/scripts/validate-collected-campaign.py" soak-host "$host_evidence" "$expected_commit"
		--expected-duration "$duration"
		--expected-scenario-timeout "$scenario_timeout"
		--expected-scenario-kill-after "$scenario_kill_after"
		--expected-docker-cleanup-timeout "$docker_cleanup_timeout"
		--expected-cycle-sleep "$cycle_sleep"
		--expected-sample-interval "$sample_interval"
		--expected-allow-skip "$allow_skip"
		--expected-cargo-sha256 "$expected_cargo_sha256"
		--expected-rustc-sha256 "$expected_rustc_sha256"
	)
	local expected_scenario
	for expected_scenario in "${expected_scenarios[@]}"; do
		validator+=(--expected-scenario "$expected_scenario")
	done
	"${validator[@]}" >/dev/null 2>&1
}
remote_lock_root="/tmp/borondns-campaign-locks-$(id -u)"
if [[ -e "$remote_lock_root" || -L "$remote_lock_root" ]]; then
	require_owned_real_dir "$remote_lock_root" "remote campaign lock directory" || exit 1
else
	mkdir -m 0700 "$remote_lock_root" 2>/dev/null || require_owned_real_dir "$remote_lock_root" "remote campaign lock directory" || exit 1
	require_owned_real_dir "$remote_lock_root" "remote campaign lock directory" || exit 1
fi
remote_lock_mode="$(stat -c %a "$remote_lock_root")" || exit 1
(( (8#$remote_lock_mode & 077) == 0 )) || { printf 'remote campaign lock directory is not private: %s\n' "$remote_lock_root" >&2; exit 1; }
cd "$remote_repo"
git_path=/usr/bin/git
probe_timeout=30
probe_kill_after=5
bounded_probe() {
	timeout --preserve-status --kill-after="$probe_kill_after" "$probe_timeout" "$@"
}
[[ -x "$git_path" && -f "$git_path" && ! -L "$git_path" && "$(stat -c %u "$git_path")" == 0 ]] || {
	printf 'trusted system git is unavailable: %s\n' "$git_path" >&2
	exit 1
}
actual_commit="$(bounded_probe "$git_path" rev-parse HEAD 2>/dev/null)" || {
	printf 'cannot resolve remote repository HEAD: %s\n' "$remote_repo" >&2
	exit 1
}
if [[ "$actual_commit" != "$expected_commit" ]]; then
	printf 'remote repository commit mismatch: expected=%s actual=%s repo=%s\n' "$expected_commit" "$actual_commit" "$remote_repo" >&2
	exit 1
fi
remote_status=""
if ! remote_status="$(bounded_probe "$git_path" status --short --untracked-files=all)"; then
	printf 'git status failed while checking remote repository: %s\n' "$remote_repo" >&2
	exit 1
fi
if [[ -n "$remote_status" ]]; then
	printf 'remote repo has uncommitted changes; refusing soak launch from %s\n' "$remote_repo" >&2
	printf '%s\n' "$remote_status" >&2
	exit 1
fi
actual_cargo="$(bounded_probe rustup which cargo 2>/dev/null)" || exit 1
actual_rustc="$(bounded_probe rustup which rustc 2>/dev/null)" || exit 1
actual_cargo="$(realpath -e "$actual_cargo")" || exit 1
actual_rustc="$(realpath -e "$actual_rustc")" || exit 1
[[ "$(sha256sum "$actual_cargo" | awk '{ print $1 }')" == "$expected_cargo_sha256" ]] || { printf 'remote cargo identity drift\n' >&2; exit 1; }
[[ "$(sha256sum "$actual_rustc" | awk '{ print $1 }')" == "$expected_rustc_sha256" ]] || { printf 'remote rustc identity drift\n' >&2; exit 1; }
[[ -f "$remote_repo/scripts/campaign-env.sh" && ! -L "$remote_repo/scripts/campaign-env.sh" &&
    -f "$remote_repo/scripts/campaign-lock-helper.py" && ! -L "$remote_repo/scripts/campaign-lock-helper.py" ]] || exit 1
exec {campaign_env_fd}<"$remote_repo/scripts/campaign-env.sh" || exit 1
exec {campaign_lock_helper_fd}<"$remote_repo/scripts/campaign-lock-helper.py" || exit 1
campaign_env_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_env_fd")" || exit 1
campaign_lock_helper_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_lock_helper_fd")" || exit 1
[[ "$(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" == "$campaign_helper_sha256" &&
    "$(printf '%s' "$campaign_lock_helper_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" == "$campaign_lock_helper_sha256" ]] || {
	printf 'remote campaign helper digest drift\n' >&2
	exit 1
}
exec {campaign_env_fd}<&-
exec {campaign_lock_helper_fd}<&-
# shellcheck source=/dev/null
source <(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode)
BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"
export BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64
campaign_acquire_private_lock "$remote_lock_root" "$systemd_unit:campaign" "remote large-soak campaign lock" || exit 1
runner_prefix="/var/tmp/borondns-campaign-runners/${systemd_unit%.service}/attempt."
unit_probe_status=0
unit_is_exactly_active "$systemd_unit" "$unit_root/$systemd_unit" "$runner_prefix" || unit_probe_status=$?
if ((unit_probe_status == 0)); then
	if [[ "$require_resume" == "1" ]]; then
		printf 'soak unit is already active with verified clean source; leaving it undisturbed: %s\n' "$systemd_unit"
		exit 0
	fi
	printf 'soak unit name is already active; refusing ambiguous initial launch: %s\n' "$systemd_unit" >&2
	exit 1
fi
((unit_probe_status == 1)) || { printf 'soak unit state or identity probe failed: %s\n' "$systemd_unit" >&2; exit "$unit_probe_status"; }

remote_parent="$(dirname "$remote_evidence")"
require_owned_real_dir "$remote_parent" "remote evidence parent" || exit 1
ensure_owned_dir "$remote_parent" "$remote_evidence" "remote evidence directory" || exit 1
ensure_owned_dir "$remote_evidence" "$remote_evidence/host" "host evidence root" || exit 1
if [[ -e "$host_evidence" || -L "$host_evidence" ]]; then
	require_owned_real_dir "$host_evidence" "host soak evidence" || exit 1
else
	ensure_owned_dir "$remote_evidence/host" "$host_evidence" "host soak evidence" || exit 1
fi

results="$host_evidence/scenario-results.tsv"
expected_header=$'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path'
resume_arg=""
if [[ -f "$results" && ! -L "$results" ]]; then
	if [[ "$require_resume" != "1" ]]; then
		printf 'remote soak evidence already exists; use the resume command: %s\n' "$host_evidence" >&2
		exit 1
	fi
	IFS= read -r actual_header <"$results" || true
	if [[ "$actual_header" != "$expected_header" ]]; then
		printf 'remote scenario results have an invalid header: %s\n' "$results" >&2
		exit 1
	fi
	if [[ "$require_resume" == "1" && -f "$host_evidence/campaign-completed.env" ]]; then
		soak_evidence_is_complete || { printf 'existing terminal soak evidence failed strict validation: %s\n' "$host_evidence" >&2; exit 1; }
		printf 'soak host has exact completed evidence; leaving it undisturbed: %s\n' "$host_evidence"
		exit 0
	fi
	resume_arg=--resume
elif [[ -n "$(find "$host_evidence" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	printf 'remote evidence directory is non-empty but has no scenario results: %s\n' "$host_evidence" >&2
	exit 1
fi
launch_root="$(dirname "$remote_runner")"
ensure_owned_dir "$remote_evidence" "$launch_root" "remote launch directory" || exit 1
launch_attempt_root="$launch_root/${systemd_unit%.service}-attempts"
ensure_owned_dir "$launch_root" "$launch_attempt_root" "soak launch attempt root" || exit 1
campaign_assert_private_lock || { printf 'remote large-soak campaign lock broker exited before attempt publication\n' >&2; exit 1; }
launch_attempt="$(mktemp -d "$launch_attempt_root/attempt.XXXXXX")"
require_owned_real_dir "$launch_attempt" "fresh soak launch attempt" || exit 1
remote_runner="$launch_attempt/run.sh"
build_parent="$(dirname "$remote_build_root")"
if [[ -e "$build_parent" || -L "$build_parent" ]]; then
	[[ -d "$build_parent" && ! -L "$build_parent" && "$(stat -c %u "$build_parent")" == "$(id -u)" ]] || {
		printf 'unsafe large-soak build parent: %s\n' "$build_parent" >&2
		exit 1
	}
else
	mkdir -m 0700 "$build_parent"
fi
require_owned_real_dir "$build_parent" "large-soak build parent" || exit 1
target_root="$remote_build_root/targets"
if [[ -e "$remote_build_root" || -L "$remote_build_root" ]]; then
	[[ -d "$remote_build_root" && ! -L "$remote_build_root" && "$(stat -c %u "$remote_build_root")" == 0 ]] || {
		printf 'unsafe large-soak build root: %s\n' "$remote_build_root" >&2
		exit 1
	}
	build_root_mode="$(stat -c %a "$remote_build_root")" || exit 1
	(( (8#$build_root_mode & 022) == 0 )) || { printf 'large-soak build root is writable by non-root: %s\n' "$remote_build_root" >&2; exit 1; }
else
	sudo install -d -m 0755 -o root -g root "$remote_build_root"
fi

if [[ -e "$target_root" || -L "$target_root" ]]; then
	require_owned_real_dir "$target_root" "large-soak target root" || exit 1
else
	sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$target_root"
	require_owned_real_dir "$target_root" "large-soak target root" || exit 1
fi

# Pre-create the only writable runtime tree before sealing the detached source.
# The ignored target link lets existing interop scripts use their conventional
# repo_root/target paths while every byte lands in this campaign-owned tree.
build_dir="$(mktemp -d "$target_root/target.XXXXXX")"
require_owned_real_dir "$build_dir" "fresh large-soak runtime directory" || exit 1
[[ -z "$(find "$build_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || exit 1

# The root-owned parent prevents the campaign UID from replacing a reviewed
# snapshot entry after it becomes immutable.  A fresh, pre-created child is
# writable only during clone and is root-owned before the runner is published.
source_snapshot="$remote_build_root/source-${launch_attempt##*/}"
[[ ! -e "$source_snapshot" && ! -L "$source_snapshot" ]] || { printf 'large-soak source snapshot already exists: %s\n' "$source_snapshot" >&2; exit 1; }
sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$source_snapshot"
"$git_path" clone --quiet --shared --no-checkout "$remote_repo" "$source_snapshot"
"$git_path" -C "$source_snapshot" checkout --quiet --detach "$expected_commit"
[[ "$("$git_path" -C "$source_snapshot" rev-parse HEAD)" == "$expected_commit" ]] || exit 1
[[ -z "$("$git_path" -C "$source_snapshot" status --short --untracked-files=all)" ]] || exit 1
printf '/target\n' >>"$source_snapshot/.git/info/exclude"
ln -s -- "$build_dir" "$source_snapshot/target"
[[ "$(realpath -e "$source_snapshot/target")" == "$(realpath -e "$build_dir")" ]] || exit 1
[[ -z "$("$git_path" -C "$source_snapshot" status --short --untracked-files=all)" ]] || {
    printf 'large-soak target link is not ignored by the immutable snapshot: %s\n' "$source_snapshot/target" >&2
    exit 1
}
sudo chown -R root:root "$source_snapshot"
sudo chmod -R a-w "$source_snapshot"
sudo chmod 0555 "$source_snapshot"
[[ "$(stat -c %u "$source_snapshot")" == 0 ]] || { printf 'large-soak source snapshot is not root-owned: %s\n' "$source_snapshot" >&2; exit 1; }
[[ "$(stat -c %u "$(dirname "$source_snapshot")")" == 0 ]] || { printf 'large-soak source parent is not root-owned: %s\n' "$source_snapshot" >&2; exit 1; }
[[ -L "$source_snapshot/target" && "$(stat -c %u "$source_snapshot/target")" == 0 ]] || exit 1

# Root owns the executable search directory.  Its cargo entry resolves through
# the service's inherited descriptor, so literal `cargo` calls in interop
# scripts execute the same inode authenticated by the plan.
authenticated_tool_dir="$remote_build_root/tools-${launch_attempt##*/}"
[[ ! -e "$authenticated_tool_dir" && ! -L "$authenticated_tool_dir" ]] || exit 1
sudo install -d -m 0755 -o root -g root -- "$authenticated_tool_dir"
sudo ln -s -- /proc/self/fd/7 "$authenticated_tool_dir/cargo"
docker_wrapper_candidate="$launch_attempt/docker"
cat >"$docker_wrapper_candidate" <<'DOCKER_WRAPPER'
#!/usr/bin/bash
set -euo pipefail
docker_command=(/usr/bin/docker)
if [[ "${BORONDNS_SOAK_DOCKER_USE_SUDO:-0}" == 1 ]]; then
    docker_command=(sudo /usr/bin/docker)
fi
resource_label="${BORONDNS_SOAK_DOCKER_LABEL:-}"
case "${1:-}" in
run | create)
    [[ -z "$resource_label" ]] || {
        subcommand="$1"
        shift
        exec "${docker_command[@]}" "$subcommand" --label "$resource_label" "$@"
    }
    ;;
network | volume)
    if [[ -n "$resource_label" && "${2:-}" == create ]]; then
        resource="$1"
        shift 2
        exec "${docker_command[@]}" "$resource" create --label "$resource_label" "$@"
    fi
    ;;
esac
exec "${docker_command[@]}" "$@"
DOCKER_WRAPPER
docker_wrapper_sha256="$(sha256sum "$docker_wrapper_candidate" | awk '{ print $1 }')"
[[ "$docker_wrapper_sha256" =~ ^[0-9a-f]{64}$ ]] || exit 1
sudo install -m 0555 -o root -g root -- "$docker_wrapper_candidate" "$authenticated_tool_dir/docker"
sudo chmod 0555 -- "$authenticated_tool_dir"
[[ -d "$authenticated_tool_dir" && ! -L "$authenticated_tool_dir" &&
    "$(stat -c %u "$authenticated_tool_dir")" == 0 && "$(stat -c %a "$authenticated_tool_dir")" == 555 &&
    -L "$authenticated_tool_dir/cargo" && "$(readlink "$authenticated_tool_dir/cargo")" == /proc/self/fd/7 &&
    -f "$authenticated_tool_dir/docker" && ! -L "$authenticated_tool_dir/docker" &&
    "$(stat -c '%u:%a:%h' "$authenticated_tool_dir/docker")" == 0:555:1 &&
    "$(sha256sum "$authenticated_tool_dir/docker" | awk '{ print $1 }')" == "$docker_wrapper_sha256" ]] || exit 1

prerequisite_state_file="$remote_build_root/prerequisite-service-state.env"
prerequisite_restored_marker="$remote_build_root/prerequisite-service-state-restored.env"
if [[ "$install_prereqs" == "1" ]]; then
	[[ ! -e "$prerequisite_restored_marker" && ! -L "$prerequisite_restored_marker" ]] || {
		printf 'large-soak prerequisite state was already restored; use a new campaign id\n' >&2
		exit 1
	}
	if [[ -e "$prerequisite_state_file" || -L "$prerequisite_state_file" ]]; then
		campaign_load_prerequisite_service_state "$prerequisite_state_file" || {
			printf 'large-soak prerequisite state is unsafe: %s\n' "$prerequisite_state_file" >&2
			exit 1
		}
	else
		prerequisite_state="$(campaign_capture_prerequisite_service_state)" || exit 1
		campaign_publish_root_atomic_text "$remote_build_root" "$prerequisite_state_file" \
			"$prerequisite_state" "large-soak prerequisite state" prerequisite-service-state || exit 1
	fi
	timeout --preserve-status --kill-after=30 900 sudo apt-get update
	timeout --preserve-status --kill-after=30 900 sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io bind9 bind9-utils dnsutils curl openssl ca-certificates rsync
	timeout --preserve-status --kill-after=10 120 sudo systemctl enable --now docker
	timeout --preserve-status --kill-after=10 120 sudo systemctl disable --now named >/dev/null 2>&1 || true
	timeout --preserve-status --kill-after=10 120 sudo systemctl disable --now bind9 >/dev/null 2>&1 || true
	timeout --preserve-status --kill-after=5 30 sudo install -d -m 1777 -o codex -g codex /var/cache/bind/borondns-interop
fi

# Build reusable Alpine primary images once before the long-running service
# starts. Individual scenarios then avoid live apk network fetches in every
# cycle; transient mirror/DNS failures stay isolated to launch-time retries.
# shellcheck source=/dev/null
source "$source_snapshot/scripts/interop-docker-images.sh"
if [[ "$install_prereqs" == "1" ]]; then
	export BORONDNS_SOAK_DOCKER_USE_SUDO=1
fi
export PATH="$authenticated_tool_dir:$PATH"
ensure_alpine_bind_image >/dev/null
ensure_alpine_knot_image >/dev/null
ensure_alpine_nsd_image >/dev/null
ensure_alpine_nsd_notify_image >/dev/null
unset BORONDNS_SOAK_DOCKER_USE_SUDO

runner="$source_snapshot/scripts/large-surface-soak.sh"
[[ -x "$runner" ]] || {
	printf 'missing executable runner: %s\n' "$runner" >&2
	exit 1
}

allow_arg=--allow-skip
if [[ "$allow_skip" == "0" ]]; then
	allow_arg=--fail-on-skip
fi

cat >"$remote_runner" <<RUNNER
#!/usr/bin/env bash
set -euo pipefail
cd $(printf '%q' "$source_snapshot")
expected_commit=$(printf '%q' "$expected_commit")
git_path=$(printf '%q' "$git_path")
expected_cargo_path=$(printf '%q' "$actual_cargo")
expected_rustc_path=$(printf '%q' "$actual_rustc")
expected_cargo_sha256=$(printf '%q' "$expected_cargo_sha256")
expected_rustc_sha256=$(printf '%q' "$expected_rustc_sha256")
build_dir=$(printf '%q' "$build_dir")
authenticated_tool_dir=$(printf '%q' "$authenticated_tool_dir")
docker_wrapper_sha256=$(printf '%q' "$docker_wrapper_sha256")
exec 7<"\$expected_cargo_path"
exec 8<"\$expected_rustc_path"
authenticated_cargo=/proc/self/fd/7
authenticated_rustc=/proc/self/fd/8
[[ "\$(sha256sum "\$authenticated_cargo" | awk '{ print \$1 }')" == "\$expected_cargo_sha256" ]] || exit 1
[[ "\$(sha256sum "\$authenticated_rustc" | awk '{ print \$1 }')" == "\$expected_rustc_sha256" ]] || exit 1
[[ -d "\$authenticated_tool_dir" && ! -L "\$authenticated_tool_dir" &&
    "\$(stat -c %u "\$authenticated_tool_dir")" == 0 && "\$(stat -c %a "\$authenticated_tool_dir")" == 555 &&
    -L "\$authenticated_tool_dir/cargo" && "\$(readlink "\$authenticated_tool_dir/cargo")" == /proc/self/fd/7 &&
    -f "\$authenticated_tool_dir/docker" && ! -L "\$authenticated_tool_dir/docker" &&
    "\$(stat -c '%u:%a:%h' "\$authenticated_tool_dir/docker")" == 0:555:1 &&
    "\$(sha256sum "\$authenticated_tool_dir/docker" | awk '{ print \$1 }')" == "\$docker_wrapper_sha256" ]] || exit 1
export PATH="\$authenticated_tool_dir:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
[[ "\$(command -v cargo)" == "\$authenticated_tool_dir/cargo" ]] || exit 1
[[ "\$(command -v docker)" == "\$authenticated_tool_dir/docker" ]] || exit 1
[[ "\$(sha256sum "\$(command -v cargo)" | awk '{ print \$1 }')" == "\$expected_cargo_sha256" ]] || exit 1
export BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO="\$authenticated_cargo"
export BORONDNS_LARGE_SOAK_AUTHENTICATED_RUSTC="\$authenticated_rustc"
export BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO_SHIM="\$authenticated_tool_dir/cargo"
export BORONDNS_LARGE_SOAK_AUTHENTICATED_DOCKER_SHIM="\$authenticated_tool_dir/docker"
export BORONDNS_LARGE_SOAK_DOCKER_CLEANUP_TIMEOUT_SECONDS=$(printf '%q' "$docker_cleanup_timeout")
actual_commit="\$("\$git_path" rev-parse HEAD 2>/dev/null)"
[[ "\$actual_commit" == "\$expected_commit" ]] || { printf 'soak runner commit mismatch: expected=%s actual=%s\n' "\$expected_commit" "\$actual_commit" >&2; exit 1; }
runner_status=""
if ! runner_status="\$("\$git_path" status --short --untracked-files=all)"; then
  printf 'git status failed while checking soak runner repository: %s\n' "\$PWD" >&2
  exit 1
fi
[[ -z "\$runner_status" ]] || { printf 'soak runner repository is dirty: %s\n%s\n' "\$PWD" "\$runner_status" >&2; exit 1; }
build_root=$(printf '%q' "$remote_build_root")
target_root="\$build_root/targets"
[[ -d "\$build_root" && ! -L "\$build_root" && "\$(stat -c %u "\$build_root")" == 0 ]] || { printf 'unsafe soak build root: %s\n' "\$build_root" >&2; exit 1; }
[[ -d "\$target_root" && ! -L "\$target_root" && "\$(stat -c %u "\$target_root")" == "\$(id -u)" ]] || { printf 'unsafe soak target root: %s\n' "\$target_root" >&2; exit 1; }
[[ -d "\$PWD" && ! -L "\$PWD" && "\$(stat -c %u "\$PWD")" == 0 && "\$(stat -c %u "\$(dirname "\$PWD")")" == 0 ]] || { printf 'mutable soak source snapshot: %s\n' "\$PWD" >&2; exit 1; }
[[ -d "\$build_dir" && ! -L "\$build_dir" && "\$(stat -c %u "\$build_dir")" == "\$(id -u)" ]] || { printf 'unsafe fresh soak build directory: %s\n' "\$build_dir" >&2; exit 1; }
[[ -z "\$(find "\$build_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { printf 'fresh soak build directory is not empty: %s\n' "\$build_dir" >&2; exit 1; }
[[ -L "\$PWD/target" && "\$(stat -c %u "\$PWD/target")" == 0 &&
    "\$(realpath -e "\$PWD/target")" == "\$(realpath -e "\$build_dir")" ]] || { printf 'soak runtime target link mismatch: %s\n' "\$PWD/target" >&2; exit 1; }
export CARGO_TARGET_DIR="\$build_dir"
exec scripts/large-surface-soak.sh \\
  --evidence-dir $(printf '%q' "$host_evidence") \\
  --duration $(printf '%q' "$duration") \\
  --scenario-timeout $(printf '%q' "$scenario_timeout") \\
  --scenario-kill-after $(printf '%q' "$scenario_kill_after") \\
  --cycle-sleep $(printf '%q' "$cycle_sleep") \\
  --sample-interval $(printf '%q' "$sample_interval") \\
  --expected-commit $(printf '%q' "$expected_commit") \\
  --expected-cargo-sha256 $(printf '%q' "$expected_cargo_sha256") \\
  --expected-rustc-sha256 $(printf '%q' "$expected_rustc_sha256") \\
  $allow_arg $resume_arg $scenario_args
RUNNER
chmod +x "$remote_runner"

campaign_capture_candidate_identity "$remote_runner" runner_candidate || exit 1
campaign_publish_root_runner "$systemd_unit" "$remote_runner" \
	"$runner_candidate_sha256" "$runner_candidate_device" "$runner_candidate_inode" "large-soak runner" || exit 1
remote_runner="$campaign_published_runner"
fragment_candidate="$(mktemp)"
cat >"$fragment_candidate" <<UNIT
[Unit]
Description=BoronDNS large-surface soak campaign
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=codex
WorkingDirectory=$remote_repo
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=CARGO_HOME=/home/codex/.cargo
Environment=RUSTUP_HOME=/home/codex/.rustup
SupplementaryGroups=docker
LimitNOFILE=1048576
RuntimeMaxSec=$service_runtime_max_seconds
TimeoutStopSec=$service_stop_timeout_seconds
ExecStart=$remote_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${systemd_unit%.service}
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
campaign_capture_candidate_identity "$fragment_candidate" fragment_candidate_identity || { rm -f "$fragment_candidate"; exit 1; }
campaign_publish_systemd_fragment "$unit_root" "$unit_root/$systemd_unit" "$fragment_candidate" "$remote_runner" \
	"$fragment_candidate_identity_sha256" "$fragment_candidate_identity_device" "$fragment_candidate_identity_inode" \
	"large-soak unit" || { rm -f "$fragment_candidate"; exit 1; }
rm -f "$fragment_candidate"

timeout --preserve-status --kill-after=10 120 sudo systemctl daemon-reload
timeout --preserve-status --kill-after=10 120 sudo systemctl reset-failed "$systemd_unit" >/dev/null 2>&1 || true
timeout --preserve-status --kill-after=10 120 sudo systemctl start "$systemd_unit"
post_start_status=0
unit_is_exactly_active "$systemd_unit" "$unit_root/$systemd_unit" "$runner_prefix" || post_start_status=$?
if ((post_start_status != 0)); then
	if ((post_start_status == 1)) && soak_evidence_is_complete; then
		printf 'large-surface soak completed before post-start probe: %s\n' "$host_evidence"
	else
		printf 'large-surface soak failed exact post-start identity confirmation: %s\n' "$systemd_unit" >&2
		exit "$post_start_status"
	fi
fi
timeout --preserve-status --kill-after=5 30 systemctl --no-pager --full status "$systemd_unit" || true
REMOTE
        } >"$staging/commands/$host-launch.sh"
        chmod +x "$staging/commands/$host-launch.sh"
        printf '%s\t%s\t%s\t%s\n' "$host" "$host_evidence" "$systemd_unit" "$command_file" >>"$staging/assignments.tsv"
    done

    cat >"$staging/status-command.txt" <<EOF
scripts/large-surface-soak-campaign.sh status --evidence-dir $(shell_quote "$final_evidence")
EOF
    cat >"$staging/collect-command.txt" <<EOF
scripts/large-surface-soak-campaign.sh collect --evidence-dir $(shell_quote "$final_evidence")
EOF
    cat >"$staging/README.md" <<EOF
# BoronDNS Large-Surface Soak Campaign

Created UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

- Campaign id: \`$campaign_id\`
- Remote repo: \`$remote_repo\`
- Remote evidence root: \`$remote_evidence\`
- Duration: \`$duration\` seconds
- Scenario timeout: \`$scenario_timeout\` seconds
- Docker cleanup timeout: \`$docker_cleanup_timeout\` seconds per operation
- Hosts: \`${hosts[*]}\`
- Scenarios: \`${scenarios[*]:-runner-default}\`

Status:

\`\`\`sh
$(cat "$staging/status-command.txt")
\`\`\`

Collect:

\`\`\`sh
$(cat "$staging/collect-command.txt")
\`\`\`
EOF
    printf 'complete\n' >"$staging/plan-complete"
    campaign_manifest_write "$staging" || die "failed to write canonical campaign manifest"
    chmod -R go-w "$staging"
    if [[ -d "$final_evidence" ]]; then
        rmdir "$final_evidence" || die "campaign evidence directory became non-empty during planning: $final_evidence"
    fi
    campaign_assert_private_lock || die "large-surface campaign plan lock broker exited before publication"
    campaign_rename_noreplace "$staging" "$final_evidence" ||
        die "large-surface campaign plan destination reappeared before publication: $final_evidence"
    campaign_disarm_published_private_temporary_tree "$final_evidence" large_plan_staging \
        "published large-surface campaign plan" || die "could not disarm published large-surface plan cleanup journal"
    plan_staging_dir=""
    campaign_release_private_lock || die "could not release large-surface campaign plan lock"
}

load_plan() {
    local executing_repo_root="$repo_root"
    [[ -n "$evidence_dir" ]] || die "--evidence-dir is required for $command"
    campaign_require_real_directory "$evidence_dir" "campaign plan directory" || die "unsafe campaign plan directory: $evidence_dir"
    campaign_require_real_directory "$evidence_dir/commands" "campaign commands directory" || die "unsafe campaign commands directory"
    campaign_require_owned_nonwritable_plan_tree "$evidence_dir" "large-surface campaign plan tree" ||
        die "campaign plan tree is not exclusively writable by its owner: $evidence_dir"
    [[ -f "$evidence_dir/plan-complete" && ! -L "$evidence_dir/plan-complete" ]] || die "campaign plan is incomplete: $evidence_dir"
    [[ "$(cat "$evidence_dir/plan-complete")" == complete ]] || die "campaign completion marker is invalid: $evidence_dir"
    campaign_require_contained_file "$evidence_dir" "$evidence_dir/campaign.env" "campaign env" || die "missing or unsafe campaign env: $evidence_dir/campaign.env"
    campaign_manifest_verify "$evidence_dir" || die "campaign manifest verification failed: $evidence_dir"
    campaign_require_contained_file "$evidence_dir" "$evidence_dir/validate-collected-campaign.py" "saved campaign validator" ||
        die "missing or unsafe saved campaign validator"
    unset hosts scenarios remote_repo remote_evidence campaign_id
    unset duration_seconds scenario_timeout_seconds scenario_kill_after_seconds docker_cleanup_timeout_seconds
    unset cycle_sleep_seconds sample_interval_seconds install_prereqs allow_skip cargo_sha256 rustc_sha256
    campaign_env_load "$evidence_dir/campaign.env" \
        campaign_id created_utc repo_root source_commit source_clean remote_repo remote_evidence \
        duration_seconds scenario_timeout_seconds scenario_kill_after_seconds docker_cleanup_timeout_seconds cycle_sleep_seconds \
        sample_interval_seconds install_prereqs allow_skip cargo_sha256 rustc_sha256 hosts scenarios ||
        die "invalid campaign env: $evidence_dir/campaign.env"
    [[ "$repo_root" == "$executing_repo_root" ]] || die "campaign repo_root does not match the executing checkout"
    repo_root="$executing_repo_root"
    local host_list="${hosts[*]}"
    IFS=' ' read -r -a hosts <<<"$host_list"
    [[ "$source_clean" == 1 || "${BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY:-0}" == 1 ]] ||
        die "saved campaign was planned from a dirty source tree"
    local assignments="$evidence_dir/assignments.tsv"
    campaign_validate_tsv "$assignments" \
        $'host\tremote_evidence_dir\tsystemd_unit\tremote_command_file' 4 ||
        die "invalid campaign assignments: $assignments"
    semantic_reference_cleanup_root="${TMPDIR:-/tmp}"
    campaign_prepare_private_temporary_tree "$semantic_reference_cleanup_root" \
        borondns-large-plan-reference large_semantic_reference semantic_reference_dir ||
        die "could not create private large-surface semantic reference"
    semantic_reference_cleanup_root="$(dirname "$semantic_reference_dir")"
    local reference_plan="$semantic_reference_dir/plan"
    local -a reference_args=(
        plan --evidence-dir "$reference_plan" --campaign-id "$campaign_id"
        --remote-repo "$remote_repo" --remote-evidence "$remote_evidence"
        --duration "$duration_seconds" --scenario-timeout "$scenario_timeout_seconds"
        --scenario-kill-after "$scenario_kill_after_seconds"
        --docker-cleanup-timeout "$docker_cleanup_timeout_seconds" --cycle-sleep "$cycle_sleep_seconds"
        --sample-interval "$sample_interval_seconds"
    )
    local expected_host
    for expected_host in "${hosts[@]}"; do
        reference_args+=(--host "$expected_host")
    done
    local scenario_list="${scenarios[*]}" reference_scenario
    local -a reference_scenarios=()
    read -r -a reference_scenarios <<<"$scenario_list"
    for reference_scenario in "${reference_scenarios[@]}"; do
        reference_args+=(--scenario "$reference_scenario")
    done
    [[ "$install_prereqs" == 0 ]] || reference_args+=(--install-prereqs)
    [[ "$allow_skip" == 1 ]] || reference_args+=(--fail-on-skip)
    BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 "$repo_root/scripts/large-surface-soak-campaign.sh" \
        "${reference_args[@]}" >/dev/null || die "could not regenerate large-surface semantic reference"
    cmp -s "$evidence_dir/validate-collected-campaign.py" "$reference_plan/validate-collected-campaign.py" ||
        die "saved large-surface collection validator content drift"

    local row_host row_evidence row_unit row_command safe_host expected_command expected_unit row_count=0
    local safe_campaign
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    local -A seen_assignment_hosts=() expected_command_files=()
    while IFS=$'\t' read -r row_host row_evidence row_unit row_command; do
        list_contains_word "$row_host" "${hosts[@]}" || die "assignment names host outside campaign metadata: $row_host"
        [[ -z "${seen_assignment_hosts[$row_host]:-}" ]] || die "duplicate large-surface assignment host: $row_host"
        seen_assignment_hosts[$row_host]=1
        safe_host="$(systemd_escape_fragment "$row_host")"
        [[ "$row_evidence" == "$remote_evidence/host/$safe_host" ]] || die "assignment evidence path drift for host: $row_host"
        expected_unit="borondns-soak-$safe_campaign-$safe_host.service"
        [[ "$row_unit" == "$expected_unit" ]] || die "assignment systemd unit identity drift for host: $row_host"
        expected_command="$evidence_dir/commands/$row_host-launch.sh"
        [[ "$row_command" == "$expected_command" && -x "$row_command" ]] ||
            die "invalid assignment command path for host: $row_host"
        campaign_require_contained_file "$evidence_dir/commands" "$row_command" "assignment command" ||
            die "unsafe assignment command path for host: $row_host"
        expected_command_files["$(basename "$row_command")"]=1
        campaign_command_matches_saved_tools "$row_command" "$reference_plan/commands/$row_host-launch.sh" ||
            die "assignment command content drift for host: $row_host"
        row_count=$((row_count + 1))
    done < <(tail -n +2 "$assignments")
    ((row_count == ${#hosts[@]})) || die "campaign assignment row count does not match host list"
    for expected_host in "${hosts[@]}"; do
        [[ -n "${seen_assignment_hosts[$expected_host]:-}" ]] || die "missing large-surface assignment host: $expected_host"
    done
    local actual_command
    while IFS= read -r -d '' actual_command; do
        [[ -f "$actual_command" && ! -L "$actual_command" && -n "${expected_command_files[$(basename "$actual_command")]:-}" ]] ||
            die "unreferenced or unsafe large-surface command in canonical plan: $actual_command"
    done < <(find "$evidence_dir/commands" -mindepth 1 -maxdepth 1 -print0 | sort -z)
    [[ "$(find "$evidence_dir/commands" -mindepth 1 -maxdepth 1 -type f | wc -l)" == "${#expected_command_files[@]}" ]] ||
        die "large-surface command count does not match canonical assignments"
    validated_command_dir="$reference_plan/commands"
}

launch_plan() {
    write_plan
    load_plan
    local host host_evidence systemd_unit command_file validated_command
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        printf 'launching host=%s unit=%s evidence=%s\n' "$host" "$systemd_unit" "$host_evidence"
        validated_command="$validated_command_dir/$(basename "$command_file")"
        campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_LAUNCH_TIMEOUT_SECONDS:-3600}" \
            -- "$host" "bash -s" <"$validated_command"
    done
}

resume_plan() {
    ((resume_override_used == 0)) || die "resume accepts only --evidence-dir; campaign parameters come from the saved plan"
    load_plan
    [[ -s "$evidence_dir/assignments.tsv" ]] || die "missing campaign assignments: $evidence_dir/assignments.tsv"
    local host host_evidence systemd_unit command_file validated_command
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        printf 'classifying and resuming host=%s unit=%s evidence=%s under remote lock\n' "$host" "$systemd_unit" "$host_evidence"
        validated_command="$validated_command_dir/$(basename "$command_file")"
        campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_LAUNCH_TIMEOUT_SECONDS:-3600}" \
            -- "$host" "BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 bash -s" <"$validated_command"
    done
}

status_plan() {
    load_plan
    local host host_evidence systemd_unit command_file runner_prefix helper_sha256
    local status_result=0
    while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        printf '== %s ==\n' "$host"
        runner_prefix="/var/tmp/borondns-campaign-runners/${systemd_unit%.service}/attempt."
        helper_sha256="$(sed -n 's/^campaign_helper_sha256=//p' "$command_file")"
        [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid authenticated campaign helper digest: $command_file"
        if ! campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_STATUS_TIMEOUT_SECONDS:-120}" \
            -- "$host" bash -s -- "$systemd_unit" "$host_evidence" "$remote_repo" "$source_commit" "$runner_prefix" "$helper_sha256" <<'REMOTE'; then
set -euo pipefail
unit="$1"
host_evidence="$2"
repo="$3"
expected_commit="$4"
runner_prefix="$5"
expected_helper_sha256="$6"
unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
fragment_expected="$unit_root/$unit"
remote_probe_status=0
source_exact=1
if ! actual_commit="$(timeout --preserve-status --kill-after=5 30 git -C "$repo" rev-parse HEAD 2>/dev/null)"; then
	actual_commit=unknown
	remote_probe_status=1
	source_exact=0
fi
dirty=""
git_status_ok=1
if ! dirty="$(timeout --preserve-status --kill-after=5 30 git -C "$repo" status --short --untracked-files=all 2>/dev/null)"; then git_status_ok=0; remote_probe_status=1; source_exact=0; fi
printf 'source_commit_expected=%s\nsource_commit_actual=%s\n' "$expected_commit" "$actual_commit"
if [[ "$actual_commit" != "$expected_commit" || "$git_status_ok" != 1 || -n "$dirty" ]]; then
	printf 'source_drift=1\n'
	remote_probe_status=1
	source_exact=0
else
	printf 'source_drift=0\n'
fi
timeout --preserve-status --kill-after=5 30 systemctl is-active "$unit" 2>/dev/null || true
unit_properties=""
if ! unit_properties="$(timeout --preserve-status --kill-after=5 30 systemctl show "$unit" \
    -p LoadState \
    -p ActiveState \
    -p SubState \
    -p Result \
    -p FragmentPath \
    -p ExecStart \
    -p ExecMainStatus \
    -p ExecMainStartTimestamp \
    -p ExecMainExitTimestamp \
    --no-pager 2>/dev/null)"; then
	printf 'systemctl_status_probe_failed=%s\n' "$unit" >&2
	remote_probe_status=1
else
	printf '%s\n' "$unit_properties"
	load="$(awk -F= '$1 == "LoadState" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	fragment="$(awk -F= '$1 == "FragmentPath" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	exec_start="$(awk -F= '$1 == "ExecStart" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	if [[ "$load" == not-found && ! -e "$fragment_expected" && ! -L "$fragment_expected" ]]; then
		printf 'unit_identity=absent\n'
	elif [[ "$load" == loaded && "$fragment" == "$fragment_expected" && "$source_exact" == 1 &&
		-f "$repo/scripts/campaign-env.sh" && ! -L "$repo/scripts/campaign-env.sh" ]]; then
		exec {campaign_env_fd}<"$repo/scripts/campaign-env.sh" || exit 1
		campaign_env_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_env_fd")" || exit 1
		if [[ ! "$expected_helper_sha256" =~ ^[0-9a-f]{64}$ ||
			"$(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" != "$expected_helper_sha256" ]]; then
			printf 'status campaign helper digest drift\n' >&2
			remote_probe_status=1
		else
			# shellcheck source=/dev/null
			exec {campaign_env_fd}<&-
			source <(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode)
		runner="$(campaign_validate_systemd_fragment_runner "$fragment_expected" "$runner_prefix")" || runner=""
		if [[ -n "$runner" && "$exec_start" == "{ path=$runner ;"* ]]; then
			printf 'unit_identity=exact\n'
		else
			printf 'unit_identity=mismatch\n' >&2
			remote_probe_status=1
		fi
		fi
	else
		printf 'unit_identity=mismatch\n' >&2
		remote_probe_status=1
	fi
fi
if [[ -r "$host_evidence/soak-summary.env" ]]; then
	cat "$host_evidence/soak-summary.env"
else
	printf 'summary_missing=%s\n' "$host_evidence/soak-summary.env"
fi
if [[ -r "$host_evidence/scenario-results.tsv" ]]; then
	printf '%s\n' '-- recent scenario results --'
	tail -20 "$host_evidence/scenario-results.tsv"
fi
latest_resource_samples=""
if [[ -d "$host_evidence/resource-sampler-attempts" ]]; then
	while IFS= read -r -d '' candidate; do
		latest_resource_samples="$candidate"
	done < <(find "$host_evidence/resource-sampler-attempts" -mindepth 2 -maxdepth 2 \
		-type f -name resource-samples.tsv -print0 | sort -z)
fi
if [[ -n "$latest_resource_samples" && -r "$latest_resource_samples" ]]; then
	printf '%s\n' '-- recent resource samples --'
	tail -5 "$latest_resource_samples"
fi
timeout --preserve-status --kill-after=5 30 journalctl -u "$unit" --no-pager -n 80 2>/dev/null || true
exit "$remote_probe_status"
REMOTE
            printf 'status probe failed: host=%s unit=%s\n' "$host" "$systemd_unit" >&2
            status_result=1
        fi
    done < <(tail -n +2 "$evidence_dir/assignments.tsv")
    return "$status_result"
}

collect_plan() {
    load_plan
    campaign_prepare_contained_directory "$evidence_dir" "$evidence_dir/remotes" "campaign remotes directory" ||
        die "unsafe campaign collection directory"
    local host safe_host transport_host host_evidence systemd_unit command_file
    local destination staging before_snapshot after_snapshot local_snapshot validated_snapshot validation_output classification status_file status_commit_file journal_dir journal_staging status_staging status_commit_staging
    local collection_deadline collection_copy_timeout collection_journal_timeout
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        safe_host="${host//[^A-Za-z0-9_.-]/_}"
        transport_host="$(campaign_remote_copy_host "$host")" || die "invalid collection host: $host"
        destination="$evidence_dir/remotes/$safe_host"
        journal_dir="$evidence_dir/remotes/$safe_host.journal"
        status_file="$evidence_dir/remotes/$safe_host.collection-status.tsv"
        status_commit_file="$status_file.commit"
        campaign_prepare_collection_budget collection_deadline || die "invalid large-soak collection resource budget"
        campaign_acquire_private_lock "$evidence_dir/remotes" "$(realpath -ms "$evidence_dir"):collect:$safe_host" \
            "soak host collection lock" "$collection_deadline" "$collection_deadline" ||
            die "another collector is active or the collection budget is unavailable for host: $safe_host"
        campaign_assert_private_lock || die "soak host collection lock broker exited: $safe_host"
        campaign_recover_collection_bundle "$evidence_dir/remotes" "$destination" "$journal_dir" "$status_file" \
            "$status_commit_file" "soak host collection" "$collection_deadline" ||
            die "could not recover interrupted collection bundle: $safe_host"
        if [[ -e "$destination" || -L "$destination" ]]; then
            campaign_require_owned_real_directory "$destination" "host collection directory" || die "unsafe host collection directory: $safe_host"
        fi
        staging="$(mktemp -d "$evidence_dir/remotes/.${safe_host}.collection.XXXXXX")"
        campaign_require_owned_real_directory "$staging" "host collection staging directory" || die "unsafe host collection staging directory: $safe_host"
        campaign_capture_cleanup_identity "$staging" tree soak_collection_evidence_staging \
            "soak collection evidence staging" || die "could not bind host collection staging identity: $safe_host"
        before_snapshot="$(campaign_remote_tree_snapshot "$host" "$host_evidence" "$collection_deadline")" || {
            campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                "soak collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-preflight-failed\n' "soak collection status" || true
            die "remote evidence preflight failed: $host"
        }
        printf 'collecting host=%s remote=%s\n' "$host" "$host_evidence"
        campaign_collection_phase_timeout_seconds collection_copy_timeout "$collection_deadline" \
            "${BORONDNS_CAMPAIGN_REMOTE_COPY_TIMEOUT_SECONDS:-7200}" || die "large-soak collection copy budget expired: $host"
        if command -v rsync >/dev/null 2>&1; then
            if ! BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$collection_deadline" \
                campaign_rsync_bounded "$collection_copy_timeout" \
                -a --delete --no-links --no-devices --no-specials -- \
                "$transport_host:$(shell_quote "$host_evidence")/" "$staging/"; then
                campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                    "soak collection evidence staging" || true
                campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-copy-failed\n' "soak collection status" || true
                die "remote evidence copy failed: $host"
            fi
        else
            campaign_scp_remote_path_is_safe "$host_evidence" || {
                campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                    "soak collection evidence staging" || true
                campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\trsync-required-for-unsafe-remote-path\n' "soak collection status" || true
                die "rsync is required to collect a remote evidence path containing whitespace or shell metacharacters: $host_evidence"
            }
            if ! BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$collection_deadline" \
                campaign_scp_bounded "$collection_copy_timeout" \
                -r -- "$transport_host:$host_evidence/." "$staging/"; then
                campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                    "soak collection evidence staging" || true
                campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-copy-failed\n' "soak collection status" || true
                die "remote evidence copy failed: $host"
            fi
        fi
        after_snapshot="$(campaign_remote_tree_snapshot "$host" "$host_evidence" "$collection_deadline")" || {
            campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                "soak collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-postflight-failed\n' "soak collection status" || true
            die "remote evidence postflight failed: $host"
        }
        local_snapshot="$(campaign_local_tree_snapshot "$staging" "$collection_deadline" \
            "$evidence_dir/validate-collected-campaign.py")" || {
            campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                "soak collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tunsafe-local-tree\n' "soak collection status" || true
            die "unsafe copied evidence tree: $host"
        }
        [[ "$before_snapshot" == "$after_snapshot" && "$after_snapshot" == "$local_snapshot" ]] || {
            campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                "soak collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tconcurrent-mutation-or-copy-mismatch\n' "soak collection status" || true
            die "remote evidence changed during collection or copied bytes differ: $host"
        }
        validation_output="$(mktemp "$evidence_dir/remotes/.${safe_host}.validation.XXXXXX")"
        campaign_capture_cleanup_identity "$validation_output" file soak_collection_validation_staging \
            "soak collection validation staging" || die "could not bind validation staging identity: $safe_host"
        local -a validator_args=(
            soak-host "$staging" "$source_commit"
            --expected-duration "$duration_seconds"
            --expected-scenario-timeout "$scenario_timeout_seconds"
            --expected-scenario-kill-after "$scenario_kill_after_seconds"
            --expected-docker-cleanup-timeout "$docker_cleanup_timeout_seconds"
            --expected-cycle-sleep "$cycle_sleep_seconds"
            --expected-sample-interval "$sample_interval_seconds"
            --expected-allow-skip "$allow_skip"
            --expected-cargo-sha256 "$cargo_sha256"
            --expected-rustc-sha256 "$rustc_sha256"
            --absolute-deadline-nanoseconds "$collection_deadline"
            --max-entries "$campaign_collection_max_entries"
            --max-depth "$campaign_collection_max_depth"
            --max-file-bytes "$campaign_collection_max_file_bytes"
            --max-total-bytes "$campaign_collection_max_total_bytes"
        )
        local expected_scenario
        for expected_scenario in "${scenarios[@]}"; do
            validator_args+=(--expected-scenario "$expected_scenario")
        done
        if ! campaign_run_before_deadline "$collection_deadline" \
            python3 "$evidence_dir/validate-collected-campaign.py" "${validator_args[@]}" >"$validation_output"; then
            campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                "soak collection evidence staging" || true
            campaign_remove_captured_cleanup_object "$validation_output" soak_collection_validation_staging \
                "soak collection validation staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tstrict-local-validation-failed\n' "soak collection status" || true
            die "strict local soak evidence validation failed: $host"
        fi
        validated_snapshot="$(campaign_local_tree_snapshot "$staging" "$collection_deadline" \
            "$evidence_dir/validate-collected-campaign.py")" || die "post-validation soak snapshot failed: $host"
        [[ "$validated_snapshot" == "$local_snapshot" ]] ||
            die "copied soak evidence changed during strict local validation: $host"
        classification="$(awk -F '\t' 'NR == 2 { print $4 }' "$validation_output")"
        [[ "$classification" == complete || "$classification" == incomplete ]] || die "invalid local soak classification: $host"
        status_staging="$(mktemp "$evidence_dir/remotes/.${safe_host}.status.XXXXXX")"
        {
            printf 'collection\t%s\tremote-snapshot\t%s\t%s\n' \
                "$safe_host" "$classification" "$validated_snapshot"
            cat "$validation_output"
        } >"$status_staging"
        campaign_remove_captured_cleanup_object "$validation_output" soak_collection_validation_staging \
            "soak collection validation staging" || die "could not remove validation staging: $safe_host"
        campaign_capture_cleanup_identity "$status_staging" file soak_collection_status_staging \
            "soak collection status staging" || die "could not bind status staging identity: $safe_host"
        status_commit_staging="$(mktemp "$evidence_dir/remotes/.${safe_host}.status-commit.XXXXXX")"
        campaign_collection_status_commit_text "$status_staging" "$validated_snapshot" \
            "$collection_deadline" >"$status_commit_staging" ||
            die "could not construct status commit: $safe_host"
        campaign_capture_cleanup_identity "$status_commit_staging" file \
            soak_collection_status_commit_staging "soak collection status commit staging" ||
            die "could not bind status commit staging identity: $safe_host"
        journal_staging="$(mktemp -d "$evidence_dir/remotes/.${safe_host}.journal.XXXXXX")"
        campaign_capture_cleanup_identity "$journal_staging" tree soak_collection_journal_staging \
            "soak collection journal staging" || die "could not bind journal staging identity: $safe_host"
        campaign_collection_phase_timeout_seconds collection_journal_timeout "$collection_deadline" \
            "${BORONDNS_CAMPAIGN_REMOTE_JOURNAL_TIMEOUT_SECONDS:-300}" ||
            die "large-soak collection journal budget expired: $host"
        BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$collection_deadline" \
            campaign_ssh_bounded "$collection_journal_timeout" \
            -n -- "$host" "journalctl -u $(shell_quote "$systemd_unit") --no-pager" \
            >"$journal_staging/$systemd_unit.log" 2>&1 || true
        campaign_publish_collection_bundle "$evidence_dir/remotes" "$staging" "$destination" \
            "$journal_staging" "$journal_dir" "$status_staging" "$status_file" "soak host collection" \
            "$validated_snapshot" "$collection_deadline" "$evidence_dir/validate-collected-campaign.py" \
            "$status_commit_staging" "$status_commit_file" || {
            campaign_remove_captured_cleanup_object "$staging" soak_collection_evidence_staging \
                "soak collection evidence staging" || true
            campaign_remove_captured_cleanup_object "$journal_staging" soak_collection_journal_staging \
                "soak collection journal staging" || true
            campaign_remove_captured_cleanup_object "$status_staging" soak_collection_status_staging \
                "soak collection status staging" || true
            campaign_remove_captured_cleanup_object "$status_commit_staging" \
                soak_collection_status_commit_staging \
                "soak collection status commit staging" || true
            die "could not publish validated collection bundle: $safe_host"
        }
        campaign_collection_status_accepts_generation "$destination" "$status_file" \
            "$collection_deadline" "$evidence_dir/validate-collected-campaign.py" ||
            die "published large-soak collection does not match its committed digest: $safe_host"
        campaign_release_private_lock
    done
}

cleanup_remote_soak() {
    local host="$1" unit="$2" runner_prefix="$3" build_root="$4" repo="$5" expected_commit="$6" expected_helper_sha256="$7" expected_lock_helper_sha256="$8"
    campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_CLEANUP_TIMEOUT_SECONDS:-300}" \
        -- "$host" bash -s -- "$unit" "$runner_prefix" "$build_root" "$repo" "$expected_commit" "$expected_helper_sha256" "$expected_lock_helper_sha256" <<'REMOTE'
set -euo pipefail
unit="$1"
runner_prefix="$2"
build_root="$3"
repo="$4"
expected_commit="$5"
expected_helper_sha256="$6"
expected_lock_helper_sha256="$7"
unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
fragment="$unit_root/$unit"
lock_root="/tmp/borondns-campaign-locks-$(id -u)"
[[ -d "$lock_root" && ! -L "$lock_root" ]] || exit 1
[[ "$(realpath -ms "$lock_root")" == "$(realpath -e "$lock_root")" && "$(stat -c %u "$lock_root")" == "$(id -u)" ]] || exit 1
lock_mode="$(stat -c %a "$lock_root")"
(( (8#$lock_mode & 077) == 0 )) || exit 1
git_path=/usr/bin/git
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ -x "$git_path" && -f "$git_path" && ! -L "$git_path" && "$(stat -c %u "$git_path")" == 0 ]] || exit 1
[[ -f "$repo/scripts/campaign-env.sh" && ! -L "$repo/scripts/campaign-env.sh" ]] || exit 1
[[ -f "$repo/scripts/campaign-lock-helper.py" && ! -L "$repo/scripts/campaign-lock-helper.py" ]] || exit 1
exec {campaign_env_fd}<"$repo/scripts/campaign-env.sh" || exit 1
exec {campaign_lock_helper_fd}<"$repo/scripts/campaign-lock-helper.py" || exit 1
campaign_env_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_env_fd")" || exit 1
campaign_lock_helper_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_lock_helper_fd")" || exit 1
[[ "$expected_helper_sha256" =~ ^[0-9a-f]{64}$ &&
    "$expected_lock_helper_sha256" =~ ^[0-9a-f]{64}$ &&
    "$(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" == "$expected_helper_sha256" &&
    "$(printf '%s' "$campaign_lock_helper_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" == "$expected_lock_helper_sha256" ]] || {
    printf 'cleanup helper digest does not match the authenticated plan\n' >&2
    exit 1
}
actual_commit="$(timeout --preserve-status --kill-after=5 30 "$git_path" -C "$repo" rev-parse HEAD 2>/dev/null)" || exit 1
[[ "$actual_commit" == "$expected_commit" ]] || {
    printf 'cleanup repository commit mismatch: expected=%s actual=%s\n' "$expected_commit" "$actual_commit" >&2
    exit 1
}
cleanup_status="$(timeout --preserve-status --kill-after=5 30 "$git_path" -C "$repo" status --short --untracked-files=all)" || exit 1
[[ -z "$cleanup_status" ]] || {
    printf 'cleanup repository is dirty; refusing executable helper\n%s\n' "$cleanup_status" >&2
    exit 1
}
# shellcheck source=/dev/null
exec {campaign_env_fd}<&-
exec {campaign_lock_helper_fd}<&-
source <(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode)
BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"
export BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64
campaign_acquire_private_lock "$lock_root" "${unit%.service}:campaign" "remote large-soak cleanup lock" || exit 1
unit_property() {
    local key="$1" data="$2" count value
    count="$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' <<<"$data")" || return 1
    [[ "$count" == 1 ]] || return 1
    value="$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1) }' <<<"$data")" || return 1
    printf '%s\n' "$value"
}
verify_old_cgroup_empty() {
    local relative="$1"
    [[ -z "$relative" ]] && return 0
    [[ "$relative" == /* && "$relative" != *..* && "$relative" != *$'\n'* ]] || return 1
    python3 - "/sys/fs/cgroup$relative" <<'PY'
import os
import sys

root = sys.argv[1]
if not os.path.exists(root):
    raise SystemExit(0)
if not os.path.isdir(root) or os.path.islink(root):
    raise SystemExit("old systemd cgroup is not a real directory")
for directory, children, files in os.walk(root, topdown=False, followlinks=False):
    if any(os.path.islink(os.path.join(directory, child)) for child in children):
        raise SystemExit("old systemd cgroup contains a symlink")
    procs = os.path.join(directory, "cgroup.procs")
    events = os.path.join(directory, "cgroup.events")
    if not os.path.isfile(procs) or open(procs, encoding="ascii").read().strip():
        raise SystemExit("old systemd cgroup still has processes")
    values = {}
    for line in open(events, encoding="ascii"):
        key, value = line.split()
        if key in values:
            raise SystemExit("duplicate old systemd cgroup event")
        values[key] = value
    if values.get("populated") != "0":
        raise SystemExit("old systemd cgroup remains populated")
PY
}
properties="$(timeout --preserve-status --kill-after=5 30 systemctl show "$unit" \
    -p LoadState -p ActiveState -p SubState -p MainPID -p ControlPID -p Job \
    -p ControlGroup -p FragmentPath -p ExecStart --no-pager)" || exit 1
load="$(unit_property LoadState "$properties")" || exit 1
active="$(unit_property ActiveState "$properties")" || exit 1
sub="$(unit_property SubState "$properties")" || exit 1
main_pid="$(unit_property MainPID "$properties")" || exit 1
control_pid="$(unit_property ControlPID "$properties")" || exit 1
job="$(unit_property Job "$properties")" || exit 1
old_control_group="$(unit_property ControlGroup "$properties")" || exit 1
loaded_fragment="$(unit_property FragmentPath "$properties")" || exit 1
exec_start="$(unit_property ExecStart "$properties")" || exit 1
case "$load" in loaded | not-found) ;; *) printf 'cleanup refused for unknown load state: %s state=%s\n' "$unit" "$load" >&2; exit 1 ;; esac
case "$active" in active | activating | reloading | refreshing | deactivating) printf 'cleanup refused for non-inactive unit: %s state=%s\n' "$unit" "$active" >&2; exit 1 ;; inactive | failed | "") ;; *) exit 1 ;; esac
[[ "$main_pid" == 0 && "$control_pid" == 0 && -z "$job" ]] || exit 1
runner=""
fragment_present=0
if [[ -e "$fragment" || -L "$fragment" ]]; then
	[[ -f "$fragment" && ! -L "$fragment" ]] || exit 1
		runner="$(campaign_validate_systemd_fragment_runner "$fragment" "$runner_prefix")" || exit 1
		if [[ "$load" != not-found ]]; then
			[[ "$loaded_fragment" == "$fragment" && "$exec_start" == "{ path=$runner ;"* ]] || exit 1
		fi
	fragment_parent_identity="$(stat -c '%d:%i:%u' "$unit_root")" || exit 1
	fragment_parent_device="${fragment_parent_identity%%:*}"
	fragment_parent_identity="${fragment_parent_identity#*:}"
	fragment_parent_inode="${fragment_parent_identity%%:*}"
	fragment_parent_owner="${fragment_parent_identity##*:}"
	fragment_identity="$(stat -c '%d:%i:%u' "$fragment")" || exit 1
	fragment_device="${fragment_identity%%:*}"
	fragment_identity="${fragment_identity#*:}"
	fragment_inode="${fragment_identity%%:*}"
	fragment_owner="${fragment_identity##*:}"
	fragment_present=1
elif [[ "$load" != not-found ]]; then
	[[ "$loaded_fragment" == "$fragment" ]] || exit 1
	loaded_runner="${exec_start#\{ path=}"
	loaded_runner="${loaded_runner%% ;*}"
		campaign_validate_root_runner "$loaded_runner" "$runner_prefix" || exit 1
fi
	if [[ ! -e "$build_root" && ! -L "$build_root" ]]; then
		printf 'cleanup expected large-soak build root is missing; refusing ambiguous cleanup: %s\n' "$build_root" >&2
		exit 1
	fi
	if [[ -e "$build_root" || -L "$build_root" ]]; then
	[[ "$build_root" == /var/tmp/borondns-large-* && -d "$build_root" && ! -L "$build_root" ]] || exit 1
	[[ "$(realpath -ms "$build_root")" == "$(realpath -e "$build_root")" && "$(stat -c %u "$build_root")" == 0 ]] || exit 1
	build_root_mode="$(stat -c %a "$build_root")" || exit 1
	(( (8#$build_root_mode & 022) == 0 )) || exit 1
	while IFS= read -r -d '' build_link; do
		case "$build_link" in
		"$build_root"/source-attempt.*/target)
			[[ "$(stat -c %u "$build_link")" == 0 ]] || exit 1
			link_target="$(realpath -e "$build_link")" || exit 1
			[[ "$link_target" == "$build_root"/targets/target.* && -d "$link_target" && ! -L "$link_target" &&
				"$(stat -c %u "$link_target")" == "$(id -u)" ]] || exit 1
			;;
		"$build_root"/tools-attempt.*/cargo)
			[[ "$(readlink "$build_link")" == /proc/self/fd/7 ]] || exit 1
			tool_parent="$(dirname "$build_link")"
			[[ -d "$tool_parent" && ! -L "$tool_parent" && "$(stat -c %u "$tool_parent")" == 0 &&
				"$(stat -c %a "$tool_parent")" == 555 ]] || exit 1
			;;
		*)
			printf 'cleanup build root contains an unknown symlink: %s\n' "$build_link" >&2
			exit 1
			;;
		esac
	done < <(find "$build_root" -type l -print0)
	prerequisite_state_file="$build_root/prerequisite-service-state.env"
	prerequisite_restored_marker="$build_root/prerequisite-service-state-restored.env"
	if [[ -e "$prerequisite_state_file" || -L "$prerequisite_state_file" ]]; then
		campaign_load_prerequisite_service_state "$prerequisite_state_file" || exit 1
		if [[ -e "$prerequisite_restored_marker" || -L "$prerequisite_restored_marker" ]]; then
			[[ -f "$prerequisite_restored_marker" && ! -L "$prerequisite_restored_marker" &&
				"$(stat -c %u "$prerequisite_restored_marker")" == 0 &&
				"$(stat -c %a "$prerequisite_restored_marker")" == 444 &&
				"$(stat -c %h "$prerequisite_restored_marker")" == 1 &&
				"$(cat "$prerequisite_restored_marker")" == restored ]] || exit 1
		fi
		elif [[ -e "$build_root/prerequisite-service-state-restored.env" || -L "$build_root/prerequisite-service-state-restored.env" ]]; then
			exit 1
		fi
	build_parent="$(dirname "$build_root")"
	build_parent_identity="$(stat -c '%d:%i:%u' "$build_parent")" || exit 1
	build_parent_device="${build_parent_identity%%:*}"
	build_parent_identity="${build_parent_identity#*:}"
	build_parent_inode="${build_parent_identity%%:*}"
	build_parent_owner="${build_parent_identity##*:}"
	build_identity="$(stat -c '%d:%i:%u' "$build_root")" || exit 1
	build_device="${build_identity%%:*}"
	build_identity="${build_identity#*:}"
	build_inode="${build_identity%%:*}"
	build_owner="${build_identity##*:}"
		preflight_build=1
	fi
campaign_remove_systemd_fragment_staging "$unit_root" "$fragment" "remote large-soak cleanup" || exit 1
campaign_assert_private_lock || exit 1
if ((fragment_present)); then
	campaign_privileged_identity_bound_remove file "$unit_root" "$fragment" \
		"$fragment_parent_device" "$fragment_parent_inode" "$fragment_parent_owner" \
		"$fragment_device" "$fragment_inode" "$fragment_owner" || exit 1
fi
timeout --preserve-status --kill-after=10 120 sudo systemctl daemon-reload
post_properties="$(timeout --preserve-status --kill-after=5 30 systemctl show "$unit" \
    -p LoadState -p ActiveState -p SubState -p MainPID -p ControlPID -p Job \
    -p ControlGroup --no-pager)" || exit 1
post_load="$(unit_property LoadState "$post_properties")" || exit 1
post_active="$(unit_property ActiveState "$post_properties")" || exit 1
post_sub="$(unit_property SubState "$post_properties")" || exit 1
post_main="$(unit_property MainPID "$post_properties")" || exit 1
post_control="$(unit_property ControlPID "$post_properties")" || exit 1
post_job="$(unit_property Job "$post_properties")" || exit 1
post_control_group="$(unit_property ControlGroup "$post_properties")" || exit 1
[[ "$post_load" == not-found && "$post_active" == inactive && "$post_sub" == dead &&
    "$post_main" == 0 && "$post_control" == 0 && -z "$post_job" && -z "$post_control_group" ]] || exit 1
verify_old_cgroup_empty "$old_control_group" || exit 1
campaign_remove_root_runner_tree "$unit" "remote large-soak cleanup" || exit 1
if ((preflight_build)); then
	if [[ -f "$prerequisite_state_file" && ! -e "$prerequisite_restored_marker" && ! -L "$prerequisite_restored_marker" ]]; then
		campaign_restore_prerequisite_service_state "$prerequisite_state_file" || {
			printf 'large-soak prerequisite service restoration failed; cleanup is resumable: %s\n' "$prerequisite_state_file" >&2
			exit 1
		}
		campaign_publish_root_atomic_text "$build_root" "$prerequisite_restored_marker" restored \
			"large-soak prerequisite restoration marker" restored-marker || exit 1
	fi
	# The parent remains campaign-UID-owned, so sudo cannot make recursive
	# pathname deletion authoritative. Publish an exact identity journal before
	# retaining the logically removed root under its preallocated quarantine.
	campaign_assert_private_lock || exit 1
	campaign_retained_identity_bound_remove privileged tree "$build_parent" "$build_root" \
		"$build_parent_device" "$build_parent_inode" "$build_parent_owner" \
		"$build_device" "$build_inode" "$build_owner" "" \
		"remote large-soak build-root cleanup" || exit 1
fi
REMOTE
}

cleanup_plan() {
    load_plan
    local host host_evidence systemd_unit command_file safe_campaign safe_host build_root runner_prefix helper_sha256 lock_helper_sha256
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    while IFS=$'\t' read -r host host_evidence systemd_unit command_file; do
        safe_host="$(systemd_escape_fragment "$host")"
        build_root="/var/tmp/borondns-large-$safe_campaign/$safe_host"
        runner_prefix="/var/tmp/borondns-campaign-runners/${systemd_unit%.service}/attempt."
        helper_sha256="$(sed -n 's/^campaign_helper_sha256=//p' "$command_file")"
        lock_helper_sha256="$(sed -n 's/^campaign_lock_helper_sha256=//p' "$command_file")"
        [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ && "$lock_helper_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid authenticated campaign helper digest: $command_file"
        cleanup_remote_soak "$host" "$systemd_unit" "$runner_prefix" "$build_root" "$remote_repo" "$source_commit" "$helper_sha256" "$lock_helper_sha256"
    done < <(tail -n +2 "$evidence_dir/assignments.tsv")
}

main() {
    parse_args "$@"
    case "$command" in
    plan)
        set_defaults
        write_plan
        printf 'large-surface soak plan written to %s\n' "$evidence_dir"
        ;;
    launch)
        set_defaults
        launch_plan
        printf 'large-surface soak launched from %s\n' "$evidence_dir"
        ;;
    resume)
        [[ -n "$evidence_dir" ]] || die "--evidence-dir is required for resume"
        resume_plan
        printf 'large-surface soak resumed from %s\n' "$evidence_dir"
        ;;
    status)
        status_plan
        ;;
    collect)
        collect_plan
        printf 'large-surface soak evidence collected under %s/remotes\n' "$evidence_dir"
        ;;
    cleanup)
        cleanup_plan
        printf 'large-surface soak units cleaned; build roots identity-quarantined with retained-cleanup journals from %s\n' "$evidence_dir"
        ;;
    esac
}

main "$@"
