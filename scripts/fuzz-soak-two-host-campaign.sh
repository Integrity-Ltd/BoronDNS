#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/campaign-env.sh
source "$repo_root/scripts/campaign-env.sh"

usage() {
    cat <<'EOF'
Usage: scripts/fuzz-soak-two-host-campaign.sh COMMAND [OPTIONS]

Prepare and optionally run a two-host fuzz/soak evidence campaign.

Commands:
  plan      Write a local campaign manifest and per-target remote commands.
  launch    Create a plan, then install and start remote systemd fuzz units.
  resume    Launch only never-started jobs from an existing complete plan.
  status    Inspect remote campaign status from a local manifest.
  collect   Copy remote evidence directories back to the local manifest.
  cleanup   Remove only verified inactive campaign units and owned build trees.

Options:
  --evidence-dir DIR       Local plan/evidence dir.
  --campaign-id ID         Campaign id used in local and remote paths.
  --host HOST              SSH target; repeatable. Defaults to BORONDNS_FUZZ_SOAK_HOSTS or borondns-1 oxidegun-1.
  --remote-repo DIR        Remote repo root. Default: /home/codex/borondns.
  --remote-evidence DIR    Remote evidence root. Default: REMOTE_REPO/target/evidence/fuzz-soak-two-host-ID.
  --duration SECONDS       Per-target fuzz duration. Default: 86400.
  --target TARGET          Fuzz target; repeatable. Default: all current fuzz targets.
  --target-repeat COUNT    Repeat the selected target set COUNT times. Default: 1.
  --toolchain TOOLCHAIN    cargo-fuzz toolchain. Default: nightly.
  --sanitizer NAME         Optional cargo-fuzz sanitizer mode, for example address or thread.
  --sampler-interval SECS  Host sampler interval. Default: 60.
  --no-sampler             Do not install per-host sampler services.
  -h, --help               Show this help.

Environment:
  BORONDNS_FUZZ_SOAK_HOSTS               Space-separated default host list.
  BORONDNS_FUZZ_SOAK_REMOTE_REPO         Default remote repo root.
  BORONDNS_FUZZ_SOAK_REMOTE_EVIDENCE     Default remote evidence root.
  BORONDNS_FUZZ_SOAK_DURATION_SECONDS    Default per-target fuzz duration.
  BORONDNS_FUZZ_SOAK_TOOLCHAIN           Default cargo-fuzz toolchain.
  BORONDNS_FUZZ_SOAK_SANITIZER           Optional cargo-fuzz sanitizer mode.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
campaign_id="$timestamp"
evidence_dir=""
remote_repo="${BORONDNS_FUZZ_SOAK_REMOTE_REPO:-/home/codex/borondns}"
remote_evidence="${BORONDNS_FUZZ_SOAK_REMOTE_EVIDENCE:-}"
duration="${BORONDNS_FUZZ_SOAK_DURATION_SECONDS:-86400}"
duration_seconds=""
toolchain="${BORONDNS_FUZZ_SOAK_TOOLCHAIN:-nightly}"
sanitizer="${BORONDNS_FUZZ_SOAK_SANITIZER:-}"
target_repeat=1
sampler_interval="${BORONDNS_FUZZ_SOAK_SAMPLER_INTERVAL_SECONDS:-60}"
sampler_interval_seconds=""
sampler_enabled=1
hosts=()
targets=()
command=""
plan_staging_dir=""
semantic_reference_dir=""
plan_staging_cleanup_root=""
semantic_reference_cleanup_root=""
validated_command_dir=""
cargo_sha256=""
rustc_sha256=""
cargo_fuzz_sha256=""
preflight_source_commit=""
preflight_source_status=""
preflight_source_clean=""
created_utc=""
plan_created_utc=""
sampler_deadline_epoch_seconds=""
target_setup_reserve_seconds=600
target_activation_reserve_seconds=300
sampler_probe_budget_seconds=10
sampler_terminal_overhead_seconds=5
fuzz_probe_timeout_seconds=30
fuzz_probe_kill_after_seconds=5
max_nanosecond_seconds=9223372036
max_target_repeat=1000
max_expanded_targets=10000
max_sampler_interval_seconds=86400

cleanup_plan_staging() {
    local final_status="$?" cleanup_failed=0 path prefix label lock_root acquired
    trap - EXIT
    for prefix in fuzz_plan_staging fuzz_semantic_reference; do
        case "$prefix" in
        fuzz_plan_staging)
            path="$plan_staging_dir"
            label="fuzz plan staging"
            lock_root="$plan_staging_cleanup_root"
            ;;
        fuzz_semantic_reference)
            path="$semantic_reference_dir"
            label="fuzz semantic reference"
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

default_targets=(
    dns_datagram
    notify_edns_datagram
    transfer_stream
    tsig_message
    zone_image_datagram
    catalog_zone
    zone_store_state
    zone_store_concurrent
    server_lifecycle
)

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
    [[ "$toolchain" =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ && ${#toolchain} -le 96 ]] ||
        die "--toolchain must be a canonical toolchain identifier: $toolchain"
    [[ -z "$sanitizer" || "$sanitizer" =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ ]] ||
        die "--sanitizer must be a canonical cargo-fuzz sanitizer name: $sanitizer"
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer: $value"
}

require_bounded_positive_integer() {
    local name="$1"
    local value="$2"
    local maximum="$3"
    require_positive_integer "$name" "$value"
    if ((${#value} > ${#maximum})) ||
        { ((${#value} == ${#maximum})) && [[ "$value" > "$maximum" ]]; }; then
        die "$name exceeds the supported maximum $maximum: $value"
    fi
}

prevalidate_plan_source() {
    preflight_source_commit="$(fuzz_bounded_probe git -C "$repo_root" rev-parse HEAD 2>/dev/null)" ||
        die "cannot resolve repository HEAD"
    [[ "$preflight_source_commit" =~ ^[0-9a-f]{40}$ ]] ||
        die "repository HEAD is not a canonical SHA-1 commit"
    preflight_source_status="$(fuzz_bounded_probe git -C "$repo_root" status --short --untracked-files=all)" ||
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

prepare_plan_timing_schedule() {
    plan_created_utc="${BORONDNS_FUZZ_SOAK_INTERNAL_CREATED_UTC:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
    local plan_created_epoch
    plan_created_epoch="$(utc_timestamp_epoch "$plan_created_utc")" || die "invalid internal campaign creation timestamp"
    require_bounded_positive_integer "--duration" "$duration" "$max_nanosecond_seconds"
    ((plan_created_epoch <= 9223372036854775807 - duration - 3600 - target_setup_reserve_seconds)) ||
        die "fuzz sampler deadline exceeds signed 64-bit epoch time"
    sampler_deadline_epoch_seconds=$((plan_created_epoch + duration + 3600 + target_setup_reserve_seconds))
}

fuzz_bounded_probe() {
    timeout --preserve-status --kill-after="$fuzz_probe_kill_after_seconds" "$fuzz_probe_timeout_seconds" "$@"
}

utc_timestamp_epoch() {
    local timestamp_value="$1" epoch canonical
    [[ "$timestamp_value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
    epoch="$(date -u -d "$timestamp_value" +%s 2>/dev/null)" || return 1
    canonical="$(date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" || return 1
    [[ "$canonical" == "$timestamp_value" ]] || return 1
    printf '%s\n' "$epoch"
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
    for expected_line in \
        "expected_cargo_sha256=$cargo_sha256" \
        "expected_rustc_sha256=$rustc_sha256" \
        "expected_cargo_fuzz_sha256=$cargo_fuzz_sha256"; do
        [[ "$(grep -Fxc "$expected_line" "$actual")" == 1 ]] || return 1
    done
    cmp -s \
        <(sed -E 's/^(expected_(cargo|rustc|cargo_fuzz)_sha256)=.*/\1=<authenticated-saved-digest>/' "$actual") \
        <(sed -E 's/^(expected_(cargo|rustc|cargo_fuzz)_sha256)=.*/\1=<authenticated-saved-digest>/' "$reference")
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
            shift 2
            ;;
        --host)
            (($# >= 2)) || die "--host requires a value"
            hosts+=("$2")
            shift 2
            ;;
        --remote-repo)
            (($# >= 2)) || die "--remote-repo requires a value"
            remote_repo="$2"
            shift 2
            ;;
        --remote-evidence)
            (($# >= 2)) || die "--remote-evidence requires a value"
            remote_evidence="$2"
            shift 2
            ;;
        --duration)
            (($# >= 2)) || die "--duration requires a value"
            duration="$2"
            shift 2
            ;;
        --target)
            (($# >= 2)) || die "--target requires a value"
            targets+=("$2")
            shift 2
            ;;
        --target-repeat)
            (($# >= 2)) || die "--target-repeat requires a value"
            target_repeat="$2"
            shift 2
            ;;
        --toolchain)
            (($# >= 2)) || die "--toolchain requires a value"
            toolchain="$2"
            shift 2
            ;;
        --sanitizer)
            (($# >= 2)) || die "--sanitizer requires a value"
            sanitizer="$2"
            shift 2
            ;;
        --sampler-interval)
            (($# >= 2)) || die "--sampler-interval requires a value"
            sampler_interval="$2"
            shift 2
            ;;
        --no-sampler)
            sampler_enabled=0
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
        evidence_dir="$repo_root/target/evidence/fuzz-soak-two-host-$campaign_id"
    fi
    if [[ -z "$remote_evidence" ]]; then
        remote_evidence="$remote_repo/target/evidence/fuzz-soak-two-host-$campaign_id"
    fi
    validate_plan_fields

    if ((${#hosts[@]} == 0)); then
        if [[ -n "${BORONDNS_FUZZ_SOAK_HOSTS:-}" ]]; then
            # shellcheck disable=SC2206
            hosts=(${BORONDNS_FUZZ_SOAK_HOSTS})
        else
            hosts=(borondns-1 oxidegun-1)
        fi
    fi
    ((${#hosts[@]} > 0)) || die "at least one host is required"
    local host safe_host
    local -A canonical_host_owners=()
    for host in "${hosts[@]}"; do
        [[ "$host" =~ ^[A-Za-z0-9_.@:+-]+$ && "$host" != -* ]] ||
            die "invalid or option-like fuzz campaign host: $host"
        campaign_remote_copy_host "$host" >/dev/null ||
            die "invalid fuzz campaign SSH host syntax: $host"
        safe_host="$(systemd_escape_fragment "$host")"
        if [[ -n "${canonical_host_owners[$safe_host]:-}" && "${canonical_host_owners[$safe_host]}" != "$host" ]]; then
            die "fuzz campaign hosts collide after canonicalization: ${canonical_host_owners[$safe_host]} and $host"
        fi
        canonical_host_owners[$safe_host]="$host"
    done

    if ((${#targets[@]} == 0)); then
        targets=("${default_targets[@]}")
    fi

    local target known matched
    local -A seen_targets=() canonical_target_owners=()
    for target in "${targets[@]}"; do
        matched=0
        for known in "${default_targets[@]}"; do
            [[ "$target" != "$known" ]] || matched=1
        done
        ((matched)) || die "unknown fuzz campaign target: $target"
        [[ -f "$repo_root/fuzz/fuzz_targets/$target.rs" && ! -L "$repo_root/fuzz/fuzz_targets/$target.rs" ]] ||
            die "fuzz campaign target has no real repository harness: $target"
        [[ "$target" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ && "$target" != *..* ]] ||
            die "fuzz campaign target is not a canonical systemd-safe identifier: $target"
        [[ -z "${seen_targets[$target]:-}" ]] || die "duplicate fuzz campaign target: $target"
        seen_targets[$target]=1
        safe_host="$(systemd_escape_fragment "$target")"
        if [[ -n "${canonical_target_owners[$safe_host]:-}" && "${canonical_target_owners[$safe_host]}" != "$target" ]]; then
            die "fuzz campaign targets collide after canonicalization: ${canonical_target_owners[$safe_host]} and $target"
        fi
        canonical_target_owners[$safe_host]="$target"
        ((${#campaign_id} + ${#target} + 32 <= 255)) ||
            die "fuzz campaign id and target exceed the systemd unit-name limit: $campaign_id $target"
    done

    require_bounded_positive_integer "--duration" "$duration" "$max_nanosecond_seconds"
    require_bounded_positive_integer "--target-repeat" "$target_repeat" "$max_target_repeat"
    require_bounded_positive_integer "--sampler-interval" "$sampler_interval" "$max_sampler_interval_seconds"
    ((${#targets[@]} <= max_expanded_targets / target_repeat)) ||
        die "expanded fuzz target count exceeds the supported maximum $max_expanded_targets"
    prepare_plan_timing_schedule

    command -v rustup >/dev/null 2>&1 || die "rustup is required to authenticate the fuzz toolchain"
    local planned_cargo planned_rustc planned_cargo_fuzz
    planned_cargo="$(fuzz_bounded_probe rustup which --toolchain "$toolchain" cargo 2>/dev/null)" || die "cannot resolve cargo for $toolchain"
    planned_rustc="$(fuzz_bounded_probe rustup which --toolchain "$toolchain" rustc 2>/dev/null)" || die "cannot resolve rustc for $toolchain"
    planned_cargo_fuzz="$(command -v cargo-fuzz 2>/dev/null || true)"
    [[ -n "$planned_cargo_fuzz" ]] || planned_cargo_fuzz="${CARGO_HOME:-$HOME/.cargo}/bin/cargo-fuzz"
    [[ -x "$planned_cargo_fuzz" ]] || die "cannot resolve cargo-fuzz"
    cargo_sha256="$(campaign_sha256 "$(realpath -e "$planned_cargo")")" || die "cannot hash planned cargo"
    rustc_sha256="$(campaign_sha256 "$(realpath -e "$planned_rustc")")" || die "cannot hash planned rustc"
    cargo_fuzz_sha256="$(campaign_sha256 "$(realpath -e "$planned_cargo_fuzz")")" || die "cannot hash planned cargo-fuzz"

    # Authenticate source provenance before write_plan can create the parent
    # or lock namespace. write_plan repeats the check while holding the lock.
    prevalidate_plan_source

    if ((target_repeat > 1)); then
        local -a repeated_targets=()
        local repeat target
        for ((repeat = 0; repeat < target_repeat; repeat++)); do
            for target in "${targets[@]}"; do
                repeated_targets+=("$target")
            done
        done
        targets=("${repeated_targets[@]}")
    fi

}

write_plan() {
    local plan_parent
    plan_parent="$(dirname "$evidence_dir")"
    mkdir -p "$plan_parent"
    campaign_require_owned_real_directory "$plan_parent" "fuzz plan parent" || die "unsafe fuzz plan parent"
    campaign_acquire_private_lock "$plan_parent" "$(realpath -ms "$evidence_dir"):plan" "fuzz campaign plan lock" ||
        die "could not acquire the private fuzz campaign plan lock"
    campaign_assert_private_lock || die "fuzz campaign plan lock broker exited"
    if [[ -e "$evidence_dir" ]]; then
        campaign_require_owned_real_directory "$evidence_dir" "fuzz campaign plan directory" || die "unsafe fuzz campaign plan directory"
        if [[ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
            die "campaign plan directory is non-empty; choose a new path: $evidence_dir"
        fi
    fi
    # Recheck after acquiring the publication lock so the plan records the
    # exact source state governing its write.
    prevalidate_plan_source
    local source_commit="$preflight_source_commit"
    local source_clean="$preflight_source_clean"
    local final_evidence="$evidence_dir"
    plan_staging_cleanup_root="$plan_parent"
    campaign_prepare_private_temporary_tree "$plan_parent" borondns-fuzz-plan-staging \
        fuzz_plan_staging plan_staging_dir || die "could not create identity-bound fuzz plan staging"
    local staging="$plan_staging_dir"
    mkdir -p "$staging/commands"
    install -m 0555 -- "$repo_root/scripts/validate-collected-campaign.py" \
        "$staging/validate-collected-campaign.py"

    {
        campaign_env_write campaign_id "$campaign_id"
        campaign_env_write created_utc "$plan_created_utc"
        campaign_env_write repo_root "$repo_root"
        campaign_env_write source_commit "$source_commit"
        campaign_env_write source_clean "$source_clean"
        campaign_env_write remote_repo "$remote_repo"
        campaign_env_write remote_evidence "$remote_evidence"
        campaign_env_write duration_seconds "$duration"
        campaign_env_write toolchain "$toolchain"
        campaign_env_write sanitizer "${sanitizer:-cargo-fuzz-default}"
        campaign_env_write cargo_sha256 "$cargo_sha256"
        campaign_env_write rustc_sha256 "$rustc_sha256"
        campaign_env_write cargo_fuzz_sha256 "$cargo_fuzz_sha256"
        campaign_env_write target_repeat "$target_repeat"
        campaign_env_write sampler_interval_seconds "$sampler_interval"
        campaign_env_write sampler_deadline_epoch_seconds "$sampler_deadline_epoch_seconds"
        campaign_env_write sampler_enabled "$sampler_enabled"
        campaign_env_write hosts "${hosts[*]}"
        campaign_env_write targets "${targets[*]}"
    } >"$staging/campaign.env"

    printf 'host\ttarget\tduration_seconds\tremote_evidence_dir\tsystemd_unit\tremote_command_file\n' \
        >"$staging/assignments.tsv"

    local index=0
    local target host safe_target safe_campaign safe_instance command_file remote_target_dir remote_log_dir remote_build_root systemd_unit
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    for target in "${targets[@]}"; do
        host="${hosts[$((index % ${#hosts[@]}))]}"
        safe_target="$(systemd_escape_fragment "$target")"
        safe_instance="$(printf '%03d-%s' "$index" "$safe_target")"
        remote_target_dir="$remote_evidence/fuzz/$safe_instance"
        remote_log_dir="$remote_evidence/launch"
        remote_build_root="/var/tmp/borondns-fuzz-$safe_campaign/$safe_instance"
        systemd_unit="borondns-fuzz-$safe_campaign-$index-$safe_target"
        command_file="$final_evidence/commands/$host-$safe_instance.sh"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'set -euo pipefail\n'
            printf 'remote_repo=%q\n' "$remote_repo"
            printf 'remote_target_dir=%q\n' "$remote_target_dir"
            printf 'remote_evidence=%q\n' "$remote_evidence"
            printf 'remote_log_dir=%q\n' "$remote_log_dir"
            printf 'remote_build_root=%q\n' "$remote_build_root"
            printf 'systemd_unit=%q\n' "$systemd_unit"
            printf 'target=%q\n' "$target"
            printf 'duration=%q\n' "$duration"
            printf 'sampler_enabled=%q\n' "$sampler_enabled"
            printf 'sampler_deadline_epoch=%q\n' "$sampler_deadline_epoch_seconds"
            printf 'target_setup_reserve_seconds=%q\n' "$target_setup_reserve_seconds"
            printf 'target_activation_reserve_seconds=%q\n' "$target_activation_reserve_seconds"
            printf 'toolchain=%q\n' "$toolchain"
            printf 'sanitizer=%q\n' "$sanitizer"
            printf 'expected_commit=%q\n' "$source_commit"
            printf 'campaign_helper_sha256=%q\n' "$(campaign_sha256 "$repo_root/scripts/campaign-env.sh")"
            printf 'campaign_lock_helper_sha256=%q\n' "$(campaign_sha256 "$repo_root/scripts/campaign-lock-helper.py")"
            printf 'expected_cargo_sha256=%q\n' "$cargo_sha256"
            printf 'expected_rustc_sha256=%q\n' "$rustc_sha256"
            printf 'expected_cargo_fuzz_sha256=%q\n' "$cargo_fuzz_sha256"
            cat <<'REMOTE'

require_resume="${BORONDNS_CAMPAIGN_REQUIRE_RESUME:-0}"
classify_only="${BORONDNS_CAMPAIGN_CLASSIFY_ONLY:-0}"
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
summary_is_complete() {
	local summary="$1"
	local evidence evidence_real marker manifest expected actual manifest_line referenced referenced_real marker_lines manifest_count=0
	local -A authenticated=()
	evidence="$(dirname "$summary")"
	marker="$evidence/campaign-completed.env"
	manifest="$evidence/artifact-manifest.sha256"
	[[ -f "$summary" && ! -L "$summary" && -f "$marker" && ! -L "$marker" && -f "$manifest" && ! -L "$manifest" ]] || return 1
	evidence_real="$(realpath -e "$evidence")" || return 1
	mapfile -t marker_lines <"$marker" || return 1
	((${#marker_lines[@]} == 5)) || return 1
	[[ "${marker_lines[0]}" == status=passed ]] || return 1
	[[ "${marker_lines[1]}" =~ ^completed_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
	[[ "${marker_lines[2]}" == target_count=1 ]] || return 1
	[[ "${marker_lines[3]}" =~ ^summary_sha256=([0-9a-f]{64})$ ]] || return 1
	expected="${BASH_REMATCH[1]}"
	actual="$(sha256sum "$summary" | awk '{ print $1 }')" || return 1
	[[ "$actual" == "$expected" ]] || return 1
	[[ "${marker_lines[4]}" =~ ^artifact_manifest_sha256=([0-9a-f]{64})$ ]] || return 1
	expected="${BASH_REMATCH[1]}"
	actual="$(sha256sum "$manifest" | awk '{ print $1 }')" || return 1
	[[ "$actual" == "$expected" ]] || return 1
	while IFS= read -r manifest_line || [[ -n "$manifest_line" ]]; do
		[[ "$manifest_line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9_.@/+:-]+)$ ]] || return 1
		expected="${BASH_REMATCH[1]}"
		referenced="${BASH_REMATCH[2]}"
		[[ "$referenced" != /* && "$referenced" != .. && "$referenced" != ../* && "$referenced" != */../* && "$referenced" != */.. ]] || return 1
		referenced_real="$(realpath -e "$evidence/$referenced")" || return 1
		[[ "$referenced_real" == "$evidence_real"/* && -f "$referenced_real" && ! -L "$evidence/$referenced" ]] || return 1
		[[ "$(sha256sum "$referenced_real" | awk '{ print $1 }')" == "$expected" ]] || return 1
		[[ -z "${authenticated[$referenced]:-}" ]] || return 1
		authenticated[$referenced]=1
		manifest_count=$((manifest_count + 1))
	done <"$manifest"
	((manifest_count > 0)) || return 1
	while IFS= read -r -d '' referenced; do
		[[ ! -L "$referenced" && -f "$referenced" ]] || return 1
		referenced="${referenced#"$evidence"/}"
		[[ "$referenced" == artifact-manifest.sha256 || "$referenced" == campaign-completed.env || -n "${authenticated[$referenced]:-}" ]] || return 1
	done < <(find "$evidence" \( -type f -o -type l \) -print0)
	awk -F '\t' -v target="$target" -v duration="$duration" -v evidence="$evidence" '
		NR == 1 { ok = ($0 == "target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file"); next }
		NR == 2 {
			minimum_elapsed = duration * 1000000000 - 250000000;
			minimum_wall = duration - 1;
			if (minimum_wall < 1) minimum_wall = 1;
			wall_seconds = $6 - $5;
			wall_nanoseconds = wall_seconds * 1000000000;
			ok = ok && NF == 10 && $1 == target && $2 == "passed" && $3 == "0" && $4 == duration &&
				$5 ~ /^[0-9]+$/ && $6 ~ /^[0-9]+$/ && wall_seconds >= minimum_wall &&
				$7 ~ /^[0-9]+$/ && $7 >= minimum_elapsed &&
				$7 + 2000000000 >= wall_nanoseconds && $7 <= wall_nanoseconds + 2000000000 &&
				$8 == "logs/" target ".log" && $9 == "artifacts/" target &&
				$10 == "logs/" target ".command";
			next
		}
		{ ok = 0 }
		END { exit !(NR == 2 && ok) }
	' "$summary" || return 1
	local log_path="$evidence/logs/$target.log"
	local artifact_dir="$evidence/artifacts/$target"
	local command_path="$evidence/logs/$target.command"
	[[ -f "$log_path" && ! -L "$log_path" && -d "$artifact_dir" && ! -L "$artifact_dir" && -f "$command_path" && ! -L "$command_path" ]] || return 1
	[[ "$(realpath -ms "$log_path")" == "$(realpath -e "$log_path")" ]] || return 1
	[[ "$(realpath -ms "$artifact_dir")" == "$(realpath -e "$artifact_dir")" ]] || return 1
	[[ "$(realpath -ms "$command_path")" == "$(realpath -e "$command_path")" ]] || return 1
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
			[[ -f "$fragment_expected" && ! -L "$fragment_expected" ]] || { printf 'unloaded unit fragment is unsafe: %s\n' "$unit" >&2; return 2; }
			runner="$(campaign_validate_systemd_fragment_runner "$fragment_expected" "$runner_prefix")" || { printf 'unloaded unit runner mismatch: %s\n' "$unit" >&2; return 2; }
		fi
		return 1
	fi
	[[ "$load" == loaded ]] || { printf 'ambiguous systemd load state for %s: %s\n' "$unit" "$load" >&2; return 2; }
	case "$active" in active | activating | reloading | inactive | failed) ;; *) printf 'ambiguous systemd state for %s: load=%s active=%s\n' "$unit" "$load" "$active" >&2; return 2 ;; esac
	[[ "$fragment" == "$fragment_expected" && -f "$fragment" && ! -L "$fragment" ]] || { printf 'active unit fragment mismatch: %s\n' "$unit" >&2; return 2; }
	runner="$(campaign_validate_systemd_fragment_runner "$fragment" "$runner_prefix")" || { printf 'active unit runner mismatch: %s\n' "$unit" >&2; return 2; }
	[[ "$exec_start" == "{ path=$runner ;"* ]] || { printf 'loaded ExecStart differs from unit file: %s\n' "$unit" >&2; return 2; }
	[[ "$active" != inactive && "$active" != failed ]] || return 1
}
cd "$remote_repo"
probe_timeout=30
probe_kill_after=5
bounded_probe() {
	timeout --preserve-status --kill-after="$probe_kill_after" "$probe_timeout" "$@"
}
git_path=/usr/bin/git
[[ -x "$git_path" && -f "$git_path" && ! -L "$git_path" && "$(stat -c %u "$git_path")" == 0 ]] || {
	printf 'trusted system git is unavailable: %s\n' "$git_path" >&2
	exit 1
}
actual_commit="$(bounded_probe "$git_path" rev-parse HEAD 2>/dev/null)" || {
	printf 'cannot resolve remote repository HEAD: %s\n' "$remote_repo" >&2
	exit 1
}
if [[ "$actual_commit" != "$expected_commit" ]]; then
	printf 'remote repository commit mismatch: expected=%s actual=%s repo=%s\n' \
		"$expected_commit" "$actual_commit" "$remote_repo" >&2
	exit 1
fi
remote_status=""
if ! remote_status="$(bounded_probe "$git_path" status --short --untracked-files=all)"; then
	printf 'git status failed while checking remote repository: %s\n' "$remote_repo" >&2
	exit 1
fi
if [[ -n "$remote_status" ]]; then
	printf 'remote repository is dirty; refusing fuzz launch: %s\n' "$remote_repo" >&2
	printf '%s\n' "$remote_status" >&2
	exit 1
fi
actual_cargo="$(bounded_probe rustup which --toolchain "$toolchain" cargo 2>/dev/null)" || exit 1
actual_rustc="$(bounded_probe rustup which --toolchain "$toolchain" rustc 2>/dev/null)" || exit 1
actual_cargo_fuzz="$(command -v cargo-fuzz 2>/dev/null || true)"
[[ -n "$actual_cargo_fuzz" ]] || actual_cargo_fuzz="${CARGO_HOME:-$HOME/.cargo}/bin/cargo-fuzz"
[[ -x "$actual_cargo_fuzz" ]] || { printf 'remote cargo-fuzz is missing or not executable\n' >&2; exit 1; }
actual_cargo="$(realpath -e "$actual_cargo")" || exit 1
actual_rustc="$(realpath -e "$actual_rustc")" || exit 1
actual_cargo_fuzz="$(realpath -e "$actual_cargo_fuzz")" || exit 1
[[ "$(sha256sum "$actual_cargo" | awk '{print $1}')" == "$expected_cargo_sha256" ]] || { printf 'remote cargo identity drift\n' >&2; exit 1; }
[[ "$(sha256sum "$actual_rustc" | awk '{print $1}')" == "$expected_rustc_sha256" ]] || { printf 'remote rustc identity drift\n' >&2; exit 1; }
[[ "$(sha256sum "$actual_cargo_fuzz" | awk '{print $1}')" == "$expected_cargo_fuzz_sha256" ]] || { printf 'remote cargo-fuzz identity drift\n' >&2; exit 1; }
if [[ "$classify_only" == 1 ]]; then
	runner_prefix="/var/tmp/borondns-campaign-runners/$systemd_unit/attempt."
	unit_probe_status=0
	unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || unit_probe_status=$?
	if ((unit_probe_status == 0)); then
		printf 'target_resume_classification=active\n'
		exit 0
	fi
	((unit_probe_status == 1)) || exit "$unit_probe_status"
	if [[ ! -e "$remote_target_dir" && ! -L "$remote_target_dir" ]]; then
		printf 'target_resume_classification=launch-required\n'
		exit 0
	fi
	require_owned_real_dir "$remote_target_dir" "target evidence directory" || exit 1
	[[ -d "$remote_target_dir/attempts" && ! -L "$remote_target_dir/attempts" ]] || {
		printf 'target evidence lacks a real attempt root: %s\n' "$remote_target_dir" >&2
		exit 1
	}
	while IFS= read -r -d '' target_node; do
		[[ ! -L "$target_node" && -d "$target_node" && "$(basename "$target_node")" == attempts ]] || {
			printf 'target evidence root contains an unsafe or unknown node: %s\n' "$target_node" >&2
			exit 1
		}
	done < <(find "$remote_target_dir" -mindepth 1 -maxdepth 1 -print0)
	complete_attempt=""
	while IFS= read -r -d '' attempt_node; do
		[[ -d "$attempt_node" && ! -L "$attempt_node" && "$(basename "$attempt_node")" == attempt.* ]] || {
			printf 'target attempt root contains an unsafe or unknown node: %s\n' "$attempt_node" >&2
			exit 1
		}
		require_owned_real_dir "$attempt_node" "target attempt directory" || exit 1
		[[ -z "$(find "$attempt_node" -type l -print -quit)" ]] || {
			printf 'target attempt contains a symlink: %s\n' "$attempt_node" >&2
			exit 1
		}
		if summary_is_complete "$attempt_node/evidence/campaign-summary.tsv"; then
			[[ -z "$complete_attempt" ]] || {
				printf 'multiple completed target attempts: %s\n' "$remote_target_dir" >&2
				exit 1
			}
			complete_attempt="$attempt_node"
		fi
	done < <(find "$remote_target_dir/attempts" -mindepth 1 -maxdepth 1 -print0 | sort -z)
	if [[ -n "$complete_attempt" ]]; then
		printf 'target_resume_classification=complete\n'
	else
		printf 'target_resume_classification=launch-required\n'
	fi
	exit 0
fi
lock_root="/tmp/borondns-campaign-locks-$(id -u)"
if [[ ! -e "$lock_root" ]]; then mkdir -m 0700 "$lock_root"; fi
require_owned_real_dir "$lock_root" "remote campaign lock root" || exit 1
(( (8#$(stat -c %a "$lock_root") & 077) == 0 )) || exit 1
# shellcheck source=/dev/null
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
source <(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode)
BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"
export BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64
campaign_acquire_private_lock "$lock_root" "$systemd_unit:campaign" "remote fuzz campaign lock" || exit 1
runner_prefix="/var/tmp/borondns-campaign-runners/$systemd_unit/attempt."
unit_probe_status=0
unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || unit_probe_status=$?
if ((unit_probe_status == 0)); then
	if [[ "$require_resume" == "1" ]]; then
		printf 'fuzz unit is active with verified clean source; leaving it undisturbed: %s.service\n' "$systemd_unit"
		exit 0
	fi
	printf 'fuzz unit name is already active; refusing ambiguous initial launch: %s.service\n' "$systemd_unit" >&2
	exit 1
fi
((unit_probe_status == 1)) || exit "$unit_probe_status"
remote_parent="$(dirname "$remote_evidence")"
require_owned_real_dir "$remote_parent" "remote evidence parent" || exit 1
ensure_owned_dir "$remote_parent" "$remote_evidence" "remote evidence directory" || exit 1
ensure_owned_dir "$remote_evidence" "$remote_evidence/fuzz" "fuzz evidence root" || exit 1
if [[ "$require_resume" != "1" && -e "$remote_target_dir" ]]; then
	printf 'fuzz target evidence already exists; use resume: %s\n' "$remote_target_dir" >&2
	exit 1
fi
ensure_owned_dir "$remote_evidence/fuzz" "$remote_target_dir" "target evidence directory" || exit 1
ensure_owned_dir "$remote_target_dir" "$remote_target_dir/attempts" "target attempt root" || exit 1
while IFS= read -r -d '' target_node; do
	[[ ! -L "$target_node" && -d "$target_node" && "$(basename "$target_node")" == attempts ]] || {
		printf 'target evidence root contains an unsafe or unknown node: %s\n' "$target_node" >&2
		exit 1
	}
done < <(find "$remote_target_dir" -mindepth 1 -maxdepth 1 -print0)
complete_attempt=""
while IFS= read -r -d '' attempt_node; do
	[[ -d "$attempt_node" && ! -L "$attempt_node" && "$(basename "$attempt_node")" == attempt.* ]] || {
		printf 'target attempt root contains an unsafe or unknown node: %s\n' "$attempt_node" >&2
		exit 1
	}
done < <(find "$remote_target_dir/attempts" -mindepth 1 -maxdepth 1 -print0)
while IFS= read -r -d '' prior_attempt; do
	require_owned_real_dir "$prior_attempt" "target attempt directory" || exit 1
	[[ -z "$(find "$prior_attempt" -type l -print -quit)" ]] || { printf 'target attempt contains a symlink: %s\n' "$prior_attempt" >&2; exit 1; }
	if summary_is_complete "$prior_attempt/evidence/campaign-summary.tsv"; then
		[[ -z "$complete_attempt" ]] || { printf 'multiple completed target attempts: %s\n' "$remote_target_dir" >&2; exit 1; }
		complete_attempt="$prior_attempt"
	fi
done < <(find "$remote_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' -print0 | sort -z)
if [[ "$require_resume" == "1" && -n "$complete_attempt" ]]; then
	printf 'fuzz target has exact completed evidence; leaving it undisturbed: %s\n' "$complete_attempt"
	exit 0
fi
if ((sampler_enabled)) && (($(date +%s) > sampler_deadline_epoch - duration - target_setup_reserve_seconds)); then
	printf 'authenticated sampler window cannot reserve target setup: deadline=%s duration=%s setup_reserve=%s\n' \
		"$sampler_deadline_epoch" "$duration" "$target_setup_reserve_seconds" >&2
	exit 1
fi
campaign_assert_private_lock || { printf 'remote fuzz campaign lock broker exited before attempt publication\n' >&2; exit 1; }
attempt_dir="$(mktemp -d "$remote_target_dir/attempts/attempt.XXXXXX")"
require_owned_real_dir "$attempt_dir" "fresh target attempt" || exit 1
[[ -z "$(find "$attempt_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { printf 'fresh target attempt is not empty: %s\n' "$attempt_dir" >&2; exit 1; }
ensure_owned_dir "$remote_evidence" "$remote_log_dir" "remote launch directory" || exit 1
remote_runner="$attempt_dir/run.sh"
build_parent="$(dirname "$remote_build_root")"
if [[ -e "$build_parent" || -L "$build_parent" ]]; then
	require_owned_real_dir "$build_parent" "fuzz build parent" || exit 1
else
	mkdir -m 0700 "$build_parent"
	require_owned_real_dir "$build_parent" "fuzz build parent" || exit 1
fi
if [[ -e "$remote_build_root" || -L "$remote_build_root" ]]; then
	require_owned_real_dir "$remote_build_root" "fuzz build root" || exit 1
else
	mkdir -m 0700 "$remote_build_root"
	require_owned_real_dir "$remote_build_root" "fuzz build root" || exit 1
fi
remote_build_dir="$(mktemp -d "$remote_build_root/attempt.XXXXXX")"
require_owned_real_dir "$remote_build_dir" "fresh fuzz build directory" || exit 1
[[ -z "$(find "$remote_build_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { printf 'fresh fuzz build directory is not empty: %s\n' "$remote_build_dir" >&2; exit 1; }
{
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
	printf 'remote_repo=%q\n' "$remote_repo"
	printf 'expected_commit=%q\n' "$expected_commit"
	printf 'remote_build_dir=%q\n' "$remote_build_dir"
	printf 'git_path=%q\n' "$git_path"
	printf 'expected_cargo_path=%q\n' "$actual_cargo"
	printf 'expected_rustc_path=%q\n' "$actual_rustc"
	printf 'expected_cargo_fuzz_path=%q\n' "$actual_cargo_fuzz"
	printf 'expected_cargo_sha256=%q\n' "$expected_cargo_sha256"
	printf 'expected_rustc_sha256=%q\n' "$expected_rustc_sha256"
	printf 'expected_cargo_fuzz_sha256=%q\n' "$expected_cargo_fuzz_sha256"
	cat <<'RUNNER_CHECK'
source_dir="$remote_build_dir/source"
target_dir="$remote_build_dir/target"
exec 7<"$expected_cargo_path"
exec 8<"$expected_rustc_path"
exec 9<"$expected_cargo_fuzz_path"
authenticated_cargo=/proc/self/fd/7
authenticated_rustc=/proc/self/fd/8
authenticated_cargo_fuzz=/proc/self/fd/9
[[ "$(sha256sum "$authenticated_cargo" | awk '{ print $1 }')" == "$expected_cargo_sha256" ]] || exit 1
[[ "$(sha256sum "$authenticated_rustc" | awk '{ print $1 }')" == "$expected_rustc_sha256" ]] || exit 1
[[ "$(sha256sum "$authenticated_cargo_fuzz" | awk '{ print $1 }')" == "$expected_cargo_fuzz_sha256" ]] || exit 1
"$git_path" clone --quiet --shared --no-checkout "$remote_repo" "$source_dir"
"$git_path" -C "$source_dir" checkout --quiet --detach "$expected_commit"
mkdir -m 0700 "$target_dir"
sudo chown -R root:root "$source_dir"
sudo chmod -R a-w "$source_dir"
sudo chown root:root "$remote_build_dir"
sudo chmod 0755 "$remote_build_dir"
cd "$source_dir"
actual_commit="$(timeout --preserve-status --kill-after=5 30 "$git_path" rev-parse HEAD 2>/dev/null)" || {
    printf 'cannot resolve immutable fuzz snapshot HEAD: %s\n' "$PWD" >&2
	exit 1
}
if [[ "$actual_commit" != "$expected_commit" ]]; then
    printf 'fuzz snapshot commit mismatch: expected=%s actual=%s repo=%s\n' \
		"$expected_commit" "$actual_commit" "$PWD" >&2
	exit 1
fi
runner_status=""
if ! runner_status="$(timeout --preserve-status --kill-after=5 30 "$git_path" status --short --untracked-files=all)"; then
    printf 'git status failed while checking immutable fuzz snapshot: %s\n' "$PWD" >&2
	exit 1
fi
if [[ -n "$runner_status" ]]; then
    printf 'immutable fuzz snapshot is dirty; refusing evidence writes: %s\n' "$PWD" >&2
	printf '%s\n' "$runner_status" >&2
	exit 1
fi
RUNNER_CHECK
    cat <<'RUNNER_BUILD'
[[ -d "$remote_build_dir" && ! -L "$remote_build_dir" ]] || { printf 'unsafe fuzz build directory: %s\n' "$remote_build_dir" >&2; exit 1; }
[[ "$(stat -c %u "$remote_build_dir")" == 0 && "$(stat -c %u "$source_dir")" == 0 ]] || { printf 'fuzz source snapshot is not root-owned: %s\n' "$source_dir" >&2; exit 1; }
[[ "$(stat -c %u "$target_dir")" == "$(id -u)" ]] || { printf 'fuzz target directory owner mismatch: %s\n' "$target_dir" >&2; exit 1; }
export CARGO_TARGET_DIR="$target_dir"
export BORONDNS_FUZZ_AUTHENTICATED_CARGO="$authenticated_cargo"
export BORONDNS_FUZZ_AUTHENTICATED_RUSTC="$authenticated_rustc"
export BORONDNS_FUZZ_AUTHENTICATED_CARGO_FUZZ="$authenticated_cargo_fuzz"
RUNNER_BUILD
    printf 'mkdir -m 0700 %q\n' "$attempt_dir/evidence"
    printf 'exec scripts/fuzz-campaign.sh --toolchain %q ' "$toolchain"
    if [[ -n "$sanitizer" ]]; then
        printf '%q %q ' --sanitizer "$sanitizer"
    fi
    printf '%s %q %s %q %s %q\n' \
        "--duration" "$duration" "--evidence-dir" "$attempt_dir/evidence" "--target" "$target"
} >"$remote_runner"
chmod +x "$remote_runner"

if ((sampler_enabled)) && (($(date +%s) > sampler_deadline_epoch - duration - target_activation_reserve_seconds)); then
	printf 'authenticated sampler window cannot reserve target activation after setup: deadline=%s duration=%s activation_reserve=%s\n' \
		"$sampler_deadline_epoch" "$duration" "$target_activation_reserve_seconds" >&2
	exit 1
fi
campaign_capture_candidate_identity "$remote_runner" runner_candidate || exit 1
campaign_publish_root_runner "$systemd_unit.service" "$remote_runner" \
	"$runner_candidate_sha256" "$runner_candidate_device" "$runner_candidate_inode" "fuzz target runner" || exit 1
remote_runner="$campaign_published_runner"
fragment_candidate="$(mktemp)"
cat >"$fragment_candidate" <<UNIT
[Unit]
Description=BoronDNS fuzz target $target
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex
WorkingDirectory=$remote_repo
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=CARGO_HOME=/home/codex/.cargo
Environment=RUSTUP_HOME=/home/codex/.rustup
LimitNOFILE=65536
RuntimeMaxSec=$((duration + 3600))
TimeoutStopSec=30
ExecStart=$remote_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$systemd_unit
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
campaign_capture_candidate_identity "$fragment_candidate" fragment_candidate_identity || { rm -f "$fragment_candidate"; exit 1; }
campaign_publish_systemd_fragment "$unit_root" "$unit_root/$systemd_unit.service" "$fragment_candidate" "$remote_runner" \
	"$fragment_candidate_identity_sha256" "$fragment_candidate_identity_device" "$fragment_candidate_identity_inode" \
	"fuzz target unit" || { rm -f "$fragment_candidate"; exit 1; }
rm -f "$fragment_candidate"

timeout --preserve-status --kill-after=10 120 sudo systemctl daemon-reload
timeout --preserve-status --kill-after=10 120 sudo systemctl reset-failed "$systemd_unit.service" >/dev/null 2>&1 || true
timeout --preserve-status --kill-after=10 120 sudo systemctl start "$systemd_unit.service"
post_start_status=0
unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || post_start_status=$?
if ((post_start_status != 0)); then
	if ((post_start_status == 1)) && summary_is_complete "$attempt_dir/evidence/campaign-summary.tsv"; then
		printf 'fuzz target completed before post-start probe: %s\n' "$attempt_dir"
	else
		printf 'fuzz target failed exact post-start identity confirmation: %s.service\n' "$systemd_unit" >&2
		exit "$post_start_status"
	fi
fi
timeout --preserve-status --kill-after=5 30 systemctl --no-pager --full status "$systemd_unit.service" || true
REMOTE
        } >"$staging/commands/$host-$safe_instance.sh"
        chmod +x "$staging/commands/$host-$safe_instance.sh"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$host" "$target" "$duration" "$remote_target_dir" "$systemd_unit.service" "$command_file" \
            >>"$staging/assignments.tsv"
        index=$((index + 1))
    done

    if ((sampler_enabled)); then
        write_sampler_plan "$safe_campaign" "$source_commit" "$staging" "$final_evidence"
    fi

    cat >"$staging/status-command.txt" <<EOF
scripts/fuzz-soak-two-host-campaign.sh status --evidence-dir $(shell_quote "$final_evidence")
EOF

    cat >"$staging/collect-command.txt" <<EOF
scripts/fuzz-soak-two-host-campaign.sh collect --evidence-dir $(shell_quote "$final_evidence")
EOF

    cat >"$staging/README.md" <<EOF
# BoronDNS Two-Host Fuzz/Soak Campaign Plan

Created UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Source commit: $source_commit

This directory is a prepared execution manifest. It does not claim fuzz or soak
evidence until the remote jobs complete and their artifacts are collected.

- Campaign id: \`$campaign_id\`
- Remote repo: \`$remote_repo\`
- Remote evidence root: \`$remote_evidence\`
- Per-target fuzz duration: \`$duration\` seconds
- Toolchain: \`$toolchain\`
- Sanitizer: \`${sanitizer:-cargo-fuzz-default}\`
- Target services: \`${#targets[@]}\`
- Host sampler: \`$([[ "$sampler_enabled" == 1 ]] && printf 'enabled every %ss' "$sampler_interval" || printf disabled)\`

Remote jobs are installed as named systemd units. Unit names are recorded in
\`assignments.tsv\`; inspect a target with:

\`\`\`sh
ssh <host> 'systemctl status <unit>; journalctl -u <unit> --no-pager -n 200'
\`\`\`

Run status:

\`\`\`sh
$(cat "$staging/status-command.txt")
\`\`\`

Collect completed remote artifacts:

\`\`\`sh
$(cat "$staging/collect-command.txt")
\`\`\`

Soak execution remains a separate lane. Use this plan alongside
\`docs/two-host-fuzz-soak-campaign.md\` and the schemas generated by
\`scripts/capture-soak-handoff.sh\`.
EOF
    printf 'complete\n' >"$staging/plan-complete"
    campaign_manifest_write "$staging" || die "failed to write canonical campaign manifest"
    chmod -R go-w "$staging"
    if [[ -d "$final_evidence" ]]; then
        rmdir "$final_evidence" || die "campaign evidence directory became non-empty during planning: $final_evidence"
    fi
    campaign_assert_private_lock || die "fuzz campaign plan lock broker exited before publication"
    campaign_rename_noreplace "$staging" "$final_evidence" ||
        die "fuzz campaign plan destination reappeared before publication: $final_evidence"
    campaign_disarm_published_private_temporary_tree "$final_evidence" fuzz_plan_staging \
        "published fuzz campaign plan" || die "could not disarm published fuzz plan cleanup journal"
    plan_staging_dir=""
    campaign_release_private_lock || die "could not release fuzz campaign plan lock"
}

unique_hosts() {
    local -A physical_hosts_seen=()
    local host
    for host in "${hosts[@]}"; do
        [[ -z "${physical_hosts_seen[$host]:-}" ]] || continue
        physical_hosts_seen[$host]=1
        printf '%s\n' "$host"
    done
}

write_sampler_plan() {
    local safe_campaign="$1"
    local source_commit="$2"
    local staging="$3"
    local final_evidence="$4"
    local sampler_tsv="$staging/host-samplers.tsv"
    printf 'host\tremote_sample_dir\tsystemd_unit\tremote_command_file\tdeadline_epoch_seconds\n' >"$sampler_tsv"

    local host safe_host remote_sample_dir remote_log_dir command_file systemd_unit sampler_units_planned_count
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        safe_host="$(systemd_escape_fragment "$host")"
        remote_sample_dir="$remote_evidence/host/$safe_host"
        remote_log_dir="$remote_evidence/launch"
        systemd_unit="borondns-fuzz-$safe_campaign-host-sampler-$safe_host"
        command_file="$final_evidence/commands/$host-host-sampler.sh"
        sampler_units_planned_count="$(awk -F '\t' -v host="$host" 'NR > 1 && $1 == host { count += 1 } END { print count + 0 }' "$staging/assignments.tsv")"
        [[ "$sampler_units_planned_count" =~ ^[1-9][0-9]*$ ]] || die "sampler host has no planned fuzz units: $host"
        {
            printf '#!/usr/bin/env bash\n'
            printf 'set -euo pipefail\n'
            printf 'remote_sample_dir=%q\n' "$remote_sample_dir"
            printf 'remote_evidence=%q\n' "$remote_evidence"
            printf 'remote_log_dir=%q\n' "$remote_log_dir"
            printf 'systemd_unit=%q\n' "$systemd_unit"
            printf 'duration=%q\n' "$duration"
            printf 'deadline_epoch=%q\n' "$sampler_deadline_epoch_seconds"
            printf 'target_setup_reserve_seconds=%q\n' "$target_setup_reserve_seconds"
            printf 'sampler_probe_budget_seconds=%q\n' "$sampler_probe_budget_seconds"
            printf 'sampler_terminal_overhead_seconds=%q\n' "$sampler_terminal_overhead_seconds"
            printf 'sampler_units_planned_count=%q\n' "$sampler_units_planned_count"
            printf 'sampler_command_probe_timeout_seconds=%q\n' "$fuzz_probe_timeout_seconds"
            printf 'sampler_command_probe_kill_after_seconds=%q\n' "$fuzz_probe_kill_after_seconds"
            printf 'sampler_interval=%q\n' "$sampler_interval"
            printf 'campaign_id=%q\n' "$campaign_id"
            printf 'repo=%q\n' "$remote_repo"
            printf 'expected_commit=%q\n' "$source_commit"
            printf 'campaign_helper_sha256=%q\n' "$(campaign_sha256 "$repo_root/scripts/campaign-env.sh")"
            printf 'campaign_lock_helper_sha256=%q\n' "$(campaign_sha256 "$repo_root/scripts/campaign-lock-helper.py")"
            cat <<'REMOTE'

cd "$repo"
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
sampler_process_evidence_consistent() {
	local attempt="$1" units_file="$1/fuzz-units.txt"
	local samples="$1/host-samples.tsv" processes="$1/process-samples.tsv" unit_count
	[[ -f "$samples" && ! -L "$samples" && -f "$processes" && ! -L "$processes" &&
		-f "$units_file" && ! -L "$units_file" ]] || return 1
	unit_count="$(awk 'NF { count += 1 } END { print count + 0 }' "$units_file")"
	[[ "$unit_count" =~ ^[1-9][0-9]*$ ]] || return 1
	python3 - "$samples" "$processes" "$unit_count" <<'PY'
import csv
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
import re
import sys

samples, processes, unit_count = sys.argv[1], sys.argv[2], int(sys.argv[3])
timestamp = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
uint = re.compile(r"^[0-9]+$")
number = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
with open(samples, newline="", encoding="utf-8") as handle:
    hosts = list(csv.reader(handle, delimiter="\t"))
with open(processes, newline="", encoding="utf-8") as handle:
    process_rows = list(csv.reader(handle, delimiter="\t"))
if not hosts or hosts[0] != ["timestamp_utc", "epoch_seconds", "active_units", "fuzz_processes", "total_fuzz_pcpu", "total_fuzz_rss_kib", "load1", "load5", "load15", "mem_available_kib"]:
    raise SystemExit(1)
if not process_rows or process_rows[0] != ["timestamp_utc", "epoch_seconds", "pid", "pcpu", "pmem", "rss_kib", "etime", "comm"]:
    raise SystemExit(1)
hosts = hosts[1:]
positions = {}
details = {}
epochs = []
for index, row in enumerate(hosts):
    if len(row) != 10 or not timestamp.fullmatch(row[0]) or not all(uint.fullmatch(row[i]) for i in (1, 2, 3, 5, 9)) or not all(number.fullmatch(row[i]) for i in (4, 6, 7, 8)) or int(row[2]) > unit_count:
        raise SystemExit(1)
    epoch = int(row[1])
    parsed = int(datetime.strptime(row[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    if abs(parsed - epoch) > 1:
        raise SystemExit(1)
    key = (row[0], row[1])
    if key in positions:
        raise SystemExit(1)
    positions[key] = index
    details[key] = []
    epochs.append(epoch)
if epochs != sorted(set(epochs)):
    raise SystemExit(1)
order = []
seen = set()
for row in process_rows[1:]:
    if len(row) != 8 or not timestamp.fullmatch(row[0]) or not uint.fullmatch(row[1]) or not re.fullmatch(r"[1-9][0-9]*", row[2]) or not number.fullmatch(row[3]) or not number.fullmatch(row[4]) or not uint.fullmatch(row[5]) or not re.fullmatch(r"[0-9:-]+", row[6]) or not re.fullmatch(r"[!-~]{1,15}", row[7]):
        raise SystemExit(1)
    key = (row[0], row[1])
    if key not in positions:
        raise SystemExit(1)
    pid_key = (key, row[2])
    if pid_key in seen:
        raise SystemExit(1)
    seen.add(pid_key)
    details[key].append(row)
    order.append(positions[key])
if order != sorted(order):
    raise SystemExit(1)
for row in hosts:
    group = details[(row[0], row[1])]
    cpu = sum((Decimal(detail[3]) for detail in group), Decimal(0))
    rss = sum(int(detail[5]) for detail in group)
    rendered_cpu = format(cpu.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), ".2f")
    if row[3] != str(len(group)) or row[4] != rendered_cpu or row[5] != str(rss):
        raise SystemExit(1)
PY
}
sampler_attempt_complete() {
	local attempt="$1" marker="$1/sampler-completed.env" samples="$1/host-samples.tsv" processes="$1/process-samples.tsv" metadata="$1/sampler.env" last
	local units_file="$1/fuzz-units.txt" unit_count terminal_deadline completed_epoch last_sample_epoch
	[[ ! -e "$attempt/sampler-hard-stop.env" ]] || return 1
	[[ -f "$marker" && ! -L "$marker" && -f "$samples" && ! -L "$samples" && -f "$processes" && ! -L "$processes" && -f "$metadata" && ! -L "$metadata" && -f "$units_file" && ! -L "$units_file" ]] || return 1
	unit_count="$(awk 'NF { count += 1 } END { print count + 0 }' "$units_file")"
	[[ "$unit_count" =~ ^[1-9][0-9]*$ ]] || return 1
	((unit_count <= (9223372036854775807 - sampler_terminal_overhead_seconds) / sampler_probe_budget_seconds)) || return 1
	((deadline_epoch <= 9223372036854775807 - unit_count * sampler_probe_budget_seconds - sampler_terminal_overhead_seconds)) || return 1
	terminal_deadline=$((deadline_epoch + unit_count * sampler_probe_budget_seconds + sampler_terminal_overhead_seconds))
	[[ "$(sed -n '1p' "$metadata")" == "source_commit=$expected_commit" && "$(sed -n '2p' "$metadata")" == source_clean=1 ]] || return 1
	[[ "$(sed -n '3p' "$metadata")" == "sample_interval_seconds=$sampler_interval" && "$(sed -n '4p' "$metadata")" == "deadline_epoch_seconds=$deadline_epoch" ]] || return 1
	[[ "$(sed -n '5p' "$metadata")" =~ ^started_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
	[[ "$(sed -n '6p' "$metadata")" =~ ^started_epoch_seconds=[0-9]+$ && "$(wc -l <"$metadata")" == 6 ]] || return 1
	[[ "$(sed -n '1p' "$marker")" == status=passed ]] || return 1
	[[ "$(sed -n '2p' "$marker")" =~ ^completed_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
	[[ "$(sed -n '3p' "$marker")" =~ ^completed_epoch_seconds=([0-9]+)$ ]] || return 1
	completed_epoch="${BASH_REMATCH[1]}"
	((completed_epoch >= deadline_epoch && completed_epoch <= terminal_deadline)) || return 1
	[[ "$(sed -n '4p' "$marker")" == active_units=0 && "$(sed -n '5p' "$marker")" == "deadline_epoch_seconds=$deadline_epoch" ]] || return 1
	[[ "$(sed -n '6p' "$marker")" =~ ^last_sample_epoch_seconds=([0-9]+)$ ]] || return 1
	last_sample_epoch="${BASH_REMATCH[1]}"
	((last_sample_epoch >= deadline_epoch && last_sample_epoch <= terminal_deadline && completed_epoch >= last_sample_epoch)) || return 1
	[[ "$(wc -l <"$marker")" == 6 ]] || return 1
	awk -F '\t' '
		NR == 1 { ok = ($0 == "timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib"); next }
		{
			ok = ok && NF == 10 && $1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/ &&
				$2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+([.][0-9]+)?$/ &&
				$6 ~ /^[0-9]+$/ && $7 ~ /^[0-9]+([.][0-9]+)?$/ && $8 ~ /^[0-9]+([.][0-9]+)?$/ &&
				$9 ~ /^[0-9]+([.][0-9]+)?$/ && $10 ~ /^[0-9]+$/;
			rows += 1
		}
		END { exit !(ok && rows > 0) }
	' "$samples" || return 1
	awk -F '\t' '
			NR == 1 { ok = ($0 == "timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm"); next }
			{
				ok = ok && NF == 8 && $1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/ &&
					$2 ~ /^[0-9]+$/ && $3 ~ /^[1-9][0-9]*$/ && $4 ~ /^[0-9]+([.][0-9]+)?$/ &&
					$5 ~ /^[0-9]+([.][0-9]+)?$/ && $6 ~ /^[0-9]+$/ && $7 ~ /^[0-9:-]+$/ &&
					$8 ~ /^[!-~]{1,15}$/;
			}
		END { exit !ok }
	' "$processes" || return 1
	sampler_process_evidence_consistent "$attempt" || return 1
	last="$(tail -n 1 "$samples")"
	[[ "$(awk -F '\t' '{ print NF }' <<<"$last")" == 10 && "$(cut -f3 <<<"$last")" == 0 && "$(cut -f2 <<<"$last")" == "$last_sample_epoch" ]] || return 1
}
sampler_attempt_hard_stopped() {
	local marker="$1/sampler-hard-stop.env" units_file="$1/fuzz-units.txt"
	local active_units line_count terminal_reason unit_count
	[[ ! -e "$1/sampler-completed.env" ]] || return 1
	[[ -f "$marker" && ! -L "$marker" && -f "$units_file" && ! -L "$units_file" ]] || return 1
	unit_count="$(awk '
		!/^borondns-fuzz-[A-Za-z0-9_.-]+-[0-9]+-[A-Za-z0-9_.-]+[.]service$/ || seen[$0]++ { invalid = 1 }
		{ count += 1 }
		END { if (invalid || count == 0) exit 1; print count }
	' "$units_file")" || return 1
	[[ "$unit_count" =~ ^[1-9][0-9]*$ ]] || return 1
	[[ "$(sed -n '1p' "$marker")" =~ ^sampler_hard_stop_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
	[[ "$(sed -n '2p' "$marker")" =~ ^active_units=([0-9]+)$ ]] || return 1
	active_units="${BASH_REMATCH[1]}"
	awk -v active="$active_units" -v allowed="$unit_count" \
		'BEGIN { exit !(active ~ /^[0-9]+$/ && active + 0 <= allowed) }' || return 1
	line_count="$(wc -l <"$marker")"
	if [[ "$line_count" == 2 ]]; then
		((active_units > 0))
	elif [[ "$line_count" == 3 ]]; then
		terminal_reason="$(sed -n '3p' "$marker")"
		[[ "$terminal_reason" == probe_deadline_exhausted=1 || "$terminal_reason" == probe_failed=1 ]]
	else
		return 1
	fi || return 1
	if [[ -e "$1/host-samples.tsv" || -e "$1/process-samples.tsv" ]]; then
		sampler_process_evidence_consistent "$1" || return 1
	fi
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
git_path=/usr/bin/git
[[ -x "$git_path" && -f "$git_path" && ! -L "$git_path" && "$(stat -c %u "$git_path")" == 0 ]] || exit 1
actual_commit="$(timeout --preserve-status --kill-after=5 30 "$git_path" rev-parse HEAD 2>/dev/null)" || {
	printf 'cannot resolve sampler repository HEAD: %s\n' "$repo" >&2
	exit 1
}
if [[ "$actual_commit" != "$expected_commit" ]]; then
	printf 'sampler repository commit mismatch: expected=%s actual=%s repo=%s\n' \
		"$expected_commit" "$actual_commit" "$repo" >&2
	exit 1
fi
sampler_setup_status=""
if ! sampler_setup_status="$(timeout --preserve-status --kill-after=5 30 "$git_path" status --short --untracked-files=all)"; then
	printf 'git status failed while checking sampler repository: %s\n' "$repo" >&2
	exit 1
fi
if [[ -n "$sampler_setup_status" ]]; then
	printf 'sampler repository is dirty; refusing evidence writes: %s\n' "$repo" >&2
	printf '%s\n' "$sampler_setup_status" >&2
	exit 1
fi
require_resume="${BORONDNS_CAMPAIGN_REQUIRE_RESUME:-0}"
classify_only="${BORONDNS_CAMPAIGN_CLASSIFY_ONLY:-0}"
[[ "$require_resume" == 0 || "$require_resume" == 1 ]] || { printf 'invalid sampler resume mode\n' >&2; exit 1; }
[[ "$classify_only" == 0 || "$classify_only" == 1 ]] || { printf 'invalid sampler classification mode\n' >&2; exit 1; }
unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
# The authenticated checkout was verified clean above. Load the shared identity
# validators before the read-only branch; classification must not create locks,
# directories, attempts, runners, or unit fragments.
# shellcheck source=/dev/null
[[ -f "$repo/scripts/campaign-env.sh" && ! -L "$repo/scripts/campaign-env.sh" &&
    -f "$repo/scripts/campaign-lock-helper.py" && ! -L "$repo/scripts/campaign-lock-helper.py" ]] || exit 1
exec {campaign_env_fd}<"$repo/scripts/campaign-env.sh" || exit 1
exec {campaign_lock_helper_fd}<"$repo/scripts/campaign-lock-helper.py" || exit 1
campaign_env_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_env_fd")" || exit 1
campaign_lock_helper_snapshot_b64="$(base64 -w0 "/proc/self/fd/$campaign_lock_helper_fd")" || exit 1
[[ "$(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" == "$campaign_helper_sha256" &&
    "$(printf '%s' "$campaign_lock_helper_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')" == "$campaign_lock_helper_sha256" ]] || {
	printf 'remote sampler helper digest drift\n' >&2
	exit 1
}
exec {campaign_env_fd}<&-
exec {campaign_lock_helper_fd}<&-
source <(printf '%s' "$campaign_env_snapshot_b64" | base64 --decode)
BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"
export BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64
runner_prefix="/var/tmp/borondns-campaign-runners/$systemd_unit/attempt."
if [[ "$classify_only" == 1 ]]; then
	unit_probe_status=0
	unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || unit_probe_status=$?
	if ((unit_probe_status == 0)); then
		printf 'sampler_resume_classification=active\n'
		exit 0
	fi
	((unit_probe_status == 1)) || { printf 'sampler unit state or identity probe failed: %s.service\n' "$systemd_unit" >&2; exit "$unit_probe_status"; }
	if [[ ! -e "$remote_sample_dir" && ! -L "$remote_sample_dir" ]]; then
		printf 'sampler_resume_classification=absent\n'
		exit 0
	fi
	require_owned_real_dir "$remote_sample_dir" "sampler host directory" || exit 1
	while IFS= read -r -d '' sampler_node; do
		[[ ! -L "$sampler_node" && -d "$sampler_node" && "$(basename "$sampler_node")" == attempts ]] || {
			printf 'sampler host root contains an unsafe or unknown node: %s\n' "$sampler_node" >&2
			exit 1
		}
	done < <(find "$remote_sample_dir" -mindepth 1 -maxdepth 1 -print0)
	if [[ ! -e "$remote_sample_dir/attempts" && ! -L "$remote_sample_dir/attempts" ]]; then
		printf 'sampler_resume_classification=absent\n'
		exit 0
	fi
	require_owned_real_dir "$remote_sample_dir/attempts" "sampler attempt root" || exit 1
	while IFS= read -r -d '' attempt_node; do
		[[ -d "$attempt_node" && ! -L "$attempt_node" && "$(basename "$attempt_node")" == attempt.* ]] || {
			printf 'sampler attempt root contains an unsafe or unknown node: %s\n' "$attempt_node" >&2
			exit 1
		}
	done < <(find "$remote_sample_dir/attempts" -mindepth 1 -maxdepth 1 -print0)
	complete_attempt=""
	hard_stop_attempt=""
	attempt_count=0
	while IFS= read -r -d '' attempt_node; do
		[[ -d "$attempt_node" && ! -L "$attempt_node" && "$(basename "$attempt_node")" == attempt.* ]] || {
			printf 'sampler attempt root contains an unsafe or unknown node: %s\n' "$attempt_node" >&2
			exit 1
		}
		require_owned_real_dir "$attempt_node" "sampler attempt directory" || exit 1
		[[ -z "$(find "$attempt_node" -type l -print -quit)" ]] || { printf 'sampler attempt contains a symlink: %s\n' "$attempt_node" >&2; exit 1; }
		attempt_count=$((attempt_count + 1))
		if sampler_attempt_complete "$attempt_node"; then
			[[ -z "$complete_attempt" ]] || { printf 'multiple completed sampler attempts: %s\n' "$remote_sample_dir" >&2; exit 1; }
			complete_attempt="$attempt_node"
		elif sampler_attempt_hard_stopped "$attempt_node"; then
			hard_stop_attempt="$attempt_node"
		fi
	done < <(find "$remote_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' -print0 | sort -z)
	if [[ -n "$complete_attempt" ]]; then
		printf 'sampler_resume_classification=complete\n'
	elif [[ -n "$hard_stop_attempt" ]]; then
		printf 'sampler_resume_classification=hard-stopped\n'
	elif ((attempt_count == 0)); then
		printf 'sampler_resume_classification=absent\n'
	else
		printf 'sampler_resume_classification=failed\n'
	fi
	exit 0
fi
wait_for_sampler_first_sample() {
	local fixed_probe_count=11
	((sampler_units_planned_count <=
		(9223372036854775807 - sampler_terminal_overhead_seconds -
		fixed_probe_count * (sampler_command_probe_timeout_seconds + sampler_command_probe_kill_after_seconds)) /
		sampler_probe_budget_seconds)) || return 1
	local wait_seconds=$((
		fixed_probe_count * (sampler_command_probe_timeout_seconds + sampler_command_probe_kill_after_seconds) +
		sampler_units_planned_count * sampler_probe_budget_seconds + sampler_terminal_overhead_seconds
	))
	local deadline=$((SECONDS + wait_seconds)) latest samples
	while ((SECONDS < deadline)); do
		latest="$(find "$remote_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
		if [[ -n "$latest" ]]; then
			samples="$latest/host-samples.tsv"
			if [[ -f "$samples" && ! -L "$samples" && "$(wc -l <"$samples")" -ge 2 ]]; then
				return 0
			fi
		fi
		unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || return 1
		sleep 1
	done
	printf 'sampler did not publish its first resource sample within the authenticated setup bound: %s.service\n' "$systemd_unit" >&2
	return 1
}

sampler_lock_root="/tmp/borondns-campaign-locks-$(id -u)"
if [[ -e "$sampler_lock_root" || -L "$sampler_lock_root" ]]; then
	require_owned_real_dir "$sampler_lock_root" "sampler lock directory" || exit 1
else
	mkdir -m 0700 "$sampler_lock_root" 2>/dev/null || require_owned_real_dir "$sampler_lock_root" "sampler lock directory" || exit 1
	require_owned_real_dir "$sampler_lock_root" "sampler lock directory" || exit 1
fi
sampler_lock_mode="$(stat -c %a "$sampler_lock_root")" || exit 1
(( (8#$sampler_lock_mode & 077) == 0 )) || { printf 'sampler lock directory is not private: %s\n' "$sampler_lock_root" >&2; exit 1; }
campaign_acquire_private_lock "$sampler_lock_root" "$systemd_unit:setup" "remote sampler setup lock" || exit 1
remote_parent="$(dirname "$remote_evidence")"
require_owned_real_dir "$remote_parent" "remote evidence parent" || exit 1
ensure_owned_dir "$remote_parent" "$remote_evidence" "remote evidence directory" || exit 1
ensure_owned_dir "$remote_evidence" "$remote_evidence/host" "host evidence root" || exit 1
ensure_owned_dir "$remote_evidence/host" "$remote_sample_dir" "sampler host directory" || exit 1
ensure_owned_dir "$remote_sample_dir" "$remote_sample_dir/attempts" "sampler attempt root" || exit 1
ensure_owned_dir "$remote_evidence" "$remote_log_dir" "remote launch directory" || exit 1
while IFS= read -r -d '' sampler_node; do
	[[ ! -L "$sampler_node" && -d "$sampler_node" && "$(basename "$sampler_node")" == attempts ]] || {
		printf 'sampler host root contains an unsafe or unknown node: %s\n' "$sampler_node" >&2
		exit 1
	}
done < <(find "$remote_sample_dir" -mindepth 1 -maxdepth 1 -print0)
unit_probe_status=0
unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || unit_probe_status=$?
if ((unit_probe_status == 0)); then
	if [[ "$require_resume" == "1" ]]; then
		wait_for_sampler_first_sample || exit 1
		printf 'sampler unit is active; leaving it undisturbed: %s.service\n' "$systemd_unit"
		exit 0
	fi
	printf 'sampler unit name is already active; refusing ambiguous initial launch: %s.service\n' "$systemd_unit" >&2
	exit 1
fi
((unit_probe_status == 1)) || { printf 'sampler unit state or identity probe failed: %s.service\n' "$systemd_unit" >&2; exit "$unit_probe_status"; }
complete_attempt=""
hard_stop_attempt=""
while IFS= read -r -d '' attempt_node; do
	[[ -d "$attempt_node" && ! -L "$attempt_node" && "$(basename "$attempt_node")" == attempt.* ]] || {
		printf 'sampler attempt root contains an unsafe or unknown node: %s\n' "$attempt_node" >&2
		exit 1
	}
done < <(find "$remote_sample_dir/attempts" -mindepth 1 -maxdepth 1 -print0)
while IFS= read -r -d '' prior_attempt; do
	require_owned_real_dir "$prior_attempt" "sampler attempt directory" || exit 1
	[[ -z "$(find "$prior_attempt" -type l -print -quit)" ]] || { printf 'sampler attempt contains a symlink: %s\n' "$prior_attempt" >&2; exit 1; }
	if sampler_attempt_complete "$prior_attempt"; then
		[[ -z "$complete_attempt" ]] || { printf 'multiple completed sampler attempts: %s\n' "$remote_sample_dir" >&2; exit 1; }
		complete_attempt="$prior_attempt"
	elif sampler_attempt_hard_stopped "$prior_attempt"; then
		hard_stop_attempt="$prior_attempt"
	fi
done < <(find "$remote_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' -print0 | sort -z)
if [[ "$require_resume" == "1" && -n "$complete_attempt" ]]; then
	printf 'sampler has exact terminal success evidence; leaving it undisturbed: %s\n' "$complete_attempt"
	exit 0
fi
if [[ "$require_resume" == "1" && -n "$hard_stop_attempt" ]]; then
	printf 'sampler has terminal hard-stop evidence; leaving it undisturbed: %s\n' "$hard_stop_attempt"
	exit 0
fi
campaign_assert_private_lock || { printf 'remote sampler setup lock broker exited before attempt publication\n' >&2; exit 1; }
attempt_dir="$(mktemp -d "$remote_sample_dir/attempts/attempt.XXXXXX")"
require_owned_real_dir "$attempt_dir" "fresh sampler attempt" || exit 1
[[ -z "$(find "$attempt_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { printf 'fresh sampler attempt is not empty: %s\n' "$attempt_dir" >&2; exit 1; }
units_file="$attempt_dir/fuzz-units.txt"
remote_runner="$attempt_dir/run.sh"
cat >"$units_file" <<UNITS
REMOTE
            tail -n +2 "$staging/assignments.tsv" | awk -F '\t' -v host="$host" '$1 == host { print $5 }'
            cat <<'REMOTE'
UNITS

campaign_capture_candidate_identity "$units_file" units_candidate || exit 1
units_expected_count="$(awk 'NF { count += 1 } END { print count + 0 }' "$units_file")"
[[ "$units_expected_count" =~ ^[1-9][0-9]*$ ]] || { printf 'sampler unit allowlist is empty\n' >&2; exit 1; }
[[ "$units_expected_count" == "$sampler_units_planned_count" ]] || { printf 'sampler unit allowlist count differs from the authenticated plan\n' >&2; exit 1; }
((units_expected_count <= (9223372036854775807 - sampler_terminal_overhead_seconds) / sampler_probe_budget_seconds)) || {
	printf 'sampler unit allowlist exceeds terminal probe budget arithmetic\n' >&2
	exit 1
}
sampler_terminal_reserve_seconds=$((units_expected_count * sampler_probe_budget_seconds + sampler_terminal_overhead_seconds))
((deadline_epoch <= 9223372036854775807 - sampler_terminal_reserve_seconds)) || {
	printf 'sampler terminal deadline exceeds signed 64-bit epoch time\n' >&2
	exit 1
}

{
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf 'export LC_ALL=C\n'
    printf 'sample_dir=%q\n' "$attempt_dir"
    printf 'interval=%q\n' "$sampler_interval"
    printf 'duration=%q\n' "$duration"
    printf 'deadline_epoch=%q\n' "$deadline_epoch"
    printf 'terminal_reserve_seconds=%q\n' "$sampler_terminal_reserve_seconds"
    printf 'campaign_id=%q\n' "$campaign_id"
	printf 'repo=%q\n' "$repo"
	printf 'expected_commit=%q\n' "$expected_commit"
	printf 'git_path=%q\n' "$git_path"
    printf 'units_expected_sha256=%q\n' "$units_candidate_sha256"
    printf 'units_expected_count=%q\n' "$units_expected_count"
    printf 'units_expected_prefix=%q\n' "borondns-fuzz-$campaign_id-"
    cat <<'SAMPLER'
runner_path="$(realpath -e "${BASH_SOURCE[0]}")" || exit 1
units_file="$(dirname "$runner_path")/fuzz-units.txt"
cd "$repo"
actual_commit="$(timeout --preserve-status --kill-after=5 30 "$git_path" rev-parse HEAD 2>/dev/null)" || {
	printf 'cannot resolve sampler runner repository HEAD: %s\n' "$repo" >&2
	exit 1
}
if [[ "$actual_commit" != "$expected_commit" ]]; then
	printf 'sampler runner repository commit mismatch: expected=%s actual=%s repo=%s\n' \
		"$expected_commit" "$actual_commit" "$repo" >&2
	exit 1
fi
sampler_status=""
if ! sampler_status="$(timeout --preserve-status --kill-after=5 30 "$git_path" status --short --untracked-files=all)"; then
	printf 'git status failed while checking sampler runner repository: %s\n' "$repo" >&2
	exit 1
fi
if [[ -n "$sampler_status" ]]; then
	printf 'sampler runner repository is dirty; refusing evidence writes: %s\n' "$repo" >&2
	printf '%s\n' "$sampler_status" >&2
	exit 1
fi
# The unit allowlist is an immutable root-owned sibling of this root-owned
# runner. Its digest commits to the exact plan-derived unit sequence. Validate
# it without sourcing user-writable code after the repository cleanliness probe.
units_identity="$units_file.identity"
[[ -f "$units_file" && ! -L "$units_file" && "$(stat -c %u "$units_file")" == 0 &&
	"$(stat -c %a "$units_file")" == 444 && "$(stat -c %h "$units_file")" == 1 &&
	-f "$units_identity" && ! -L "$units_identity" && "$(stat -c %u "$units_identity")" == 0 &&
	"$(stat -c %a "$units_identity")" == 444 && "$(stat -c %h "$units_identity")" == 1 ]] || {
	printf 'sampler unit allowlist identity validation failed: %s\n' "$units_file" >&2
	exit 1
}
units_digest="$(sha256sum "$units_file" | awk '{ print $1 }')"
mapfile -t units_identity_lines <"$units_identity"
[[ "$units_digest" == "$units_expected_sha256" && ${#units_identity_lines[@]} == 4 &&
	"${units_identity_lines[0]}" == "path=$units_file" &&
	"${units_identity_lines[1]}" == "sha256=$units_digest" &&
	"${units_identity_lines[2]}" == "device=$(stat -c %d "$units_file")" &&
	"${units_identity_lines[3]}" == "inode=$(stat -c %i "$units_file")" ]] || {
	printf 'sampler unit allowlist digest or binding mismatch: %s\n' "$units_file" >&2
	exit 1
}
mapfile -t planned_units <"$units_file"
((${#planned_units[@]} == units_expected_count)) || {
	printf 'sampler unit allowlist count mismatch: expected=%s actual=%s\n' \
		"$units_expected_count" "${#planned_units[@]}" >&2
	exit 1
}
declare -A canonical_units=()
for planned_unit in "${planned_units[@]}"; do
	[[ "$planned_unit" =~ ^${units_expected_prefix}[0-9]+-[A-Za-z0-9_.@-]+\.service$ &&
		-z "${canonical_units[$planned_unit]:-}" ]] || {
		printf 'sampler unit allowlist contains a non-canonical or duplicate unit: %s\n' "$planned_unit" >&2
		exit 1
	}
	canonical_units[$planned_unit]=1
done
command -v flock >/dev/null 2>&1 || {
	printf 'missing required sampler lock tool: flock\n' >&2
	exit 1
}
sampler_lock="$sample_dir"
exec {sampler_lock_fd}<"$sampler_lock"
flock -n "$sampler_lock_fd" || {
	printf 'another sampler writer holds the evidence lock: %s\n' "$sampler_lock" >&2
	exit 1
}
samples="$sample_dir/host-samples.tsv"
process_samples="$sample_dir/process-samples.tsv"
host_info="$sample_dir/host-info.txt"
sampler_metadata="$sample_dir/sampler.env"
if [[ -e "$samples" || -e "$process_samples" || -e "$host_info" || -e "$sampler_metadata" ]]; then
	printf 'sampler evidence already exists; refusing overwrite: %s\n' "$sample_dir" >&2
	exit 1
fi
sampler_atomic_marker() {
	local destination="$1" content="$2" staged
	staged="$(mktemp "$sample_dir/.${destination##*/}.XXXXXX")" || return 1
	if ! printf '%s' "$content" >"$staged"; then
		rm -f -- "$staged"
		return 1
	fi
	printf '\n' >>"$staged" || return 1
	sync -f "$staged" 2>/dev/null || true
	mv -f -- "$staged" "$destination"
}
active_units=0
sampler_finalize() {
	local status=$?
	trap - EXIT
	trap '' INT TERM HUP
	if declare -F sampler_finalize_started_hook >/dev/null 2>&1; then
		sampler_finalize_started_hook
	fi
	if ((status != 0)) && [[ ! -e "$sample_dir/sampler-completed.env" && ! -e "$sample_dir/sampler-hard-stop.env" ]]; then
		sampler_atomic_marker "$sample_dir/sampler-hard-stop.env" \
			"$(printf 'sampler_hard_stop_utc=%s\nactive_units=%s\nprobe_failed=1\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$active_units")" || true
	fi
	exit "$status"
}
trap sampler_finalize EXIT
[[ "$deadline_epoch" =~ ^[1-9][0-9]*$ ]] || {
	printf 'invalid sampler deadline: %s\n' "$deadline_epoch" >&2
	exit 1
}
end_epoch="$deadline_epoch"
hard_stop_epoch=$((end_epoch + terminal_reserve_seconds))

sampler_started_epoch="$(date +%s)"
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=%s\ndeadline_epoch_seconds=%s\nstarted_utc=%s\nstarted_epoch_seconds=%s\n' \
	"$expected_commit" "$interval" "$end_epoch" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$sampler_started_epoch" >"$sampler_metadata"

{
    printf 'campaign_id=%s\n' "$campaign_id"
    printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'hostname=%s\n' "$(timeout --preserve-status --kill-after=5 30 uname -n 2>/dev/null || printf unknown)"
    printf 'repo=%s\n' "$repo"
    timeout --preserve-status --kill-after=5 30 "$git_path" -C "$repo" rev-parse HEAD 2>&1 || true
    timeout --preserve-status --kill-after=5 30 "$git_path" -C "$repo" status --short 2>&1 || true
    timeout --preserve-status --kill-after=5 30 uname -a || true
    timeout --preserve-status --kill-after=5 30 lscpu || true
    timeout --preserve-status --kill-after=5 30 free -h || true
    timeout --preserve-status --kill-after=5 30 df -h "$repo" || true
    timeout --preserve-status --kill-after=5 30 rustup show active-toolchain 2>&1 || true
    timeout --preserve-status --kill-after=5 30 cargo fuzz --version 2>&1 || true
} >"$host_info"

printf 'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib\n' >"$samples"
printf 'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm\n' >"$process_samples"

while :; do
    now_epoch=$(date +%s)
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	active_units=0
	declare -A sampled_pids=()
	process_rows=""
		while IFS= read -r unit; do
        [ -n "$unit" ] || continue
		probe_remaining=$((hard_stop_epoch - $(date +%s)))
        if [ "$probe_remaining" -le 0 ]; then
			sampler_atomic_marker "$sample_dir/sampler-hard-stop.env" \
				"$(printf 'sampler_hard_stop_utc=%s\nactive_units=%s\nprobe_deadline_exhausted=1\n' "$timestamp" "$active_units")"
            printf 'sampler hard deadline reached during systemd probes\n' >&2
            exit 75
        fi
        probe_timeout=5
        [ "$probe_timeout" -le "$probe_remaining" ] || probe_timeout="$probe_remaining"
		probe_output=""
		probe_status=0
		if probe_output="$(timeout --preserve-status --signal=KILL "$probe_timeout" systemctl is-active "$unit" 2>/dev/null)"; then
			probe_status=0
		else
			probe_status=$?
		fi
		case "$probe_output" in
		active | activating | reloading | refreshing | deactivating)
			active_units=$((active_units + 1))
			unit_identity="$(timeout --preserve-status --signal=KILL "$probe_timeout" \
				systemctl show "$unit" -p MainPID -p ControlGroup --no-pager 2>/dev/null)" || unit_identity=""
			main_pid="$(awk -F= '$1 == "MainPID" { print $2 }' <<<"$unit_identity")"
			control_group="$(awk -F= '$1 == "ControlGroup" { print substr($0, index($0, "=") + 1) }' <<<"$unit_identity")"
			if [[ ! "$main_pid" =~ ^[0-9]+$ || "$control_group" != /* || "$control_group" == *'/../'* || "$control_group" == */.. ]]; then
				sampler_atomic_marker "$sample_dir/sampler-hard-stop.env" \
					"$(printf 'sampler_hard_stop_utc=%s\nactive_units=%s\nprobe_failed=1' "$timestamp" "$active_units")"
				printf 'sampler unit identity probe was malformed: unit=%s\n' "$unit" >&2
				exit 75
			fi
			cgroup_procs="/sys/fs/cgroup${control_group}/cgroup.procs"
			if [[ -r "$cgroup_procs" ]]; then
				while IFS= read -r pid; do
					[[ "$pid" =~ ^[1-9][0-9]*$ && -z "${sampled_pids[$pid]:-}" ]] || continue
					stat_before="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
					stat_tail="${stat_before##*) }"
					start_before="$(awk '{ print $20 }' <<<"$stat_tail")"
					[[ "$start_before" =~ ^[0-9]+$ ]] || continue
					row="$(ps -p "$pid" -o pid=,pcpu=,pmem=,rss=,etime=,comm= 2>/dev/null || true)"
					[[ -n "$row" ]] || continue
					stat_after="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
					stat_tail="${stat_after##*) }"
					start_after="$(awk '{ print $20 }' <<<"$stat_tail")"
					[[ "$start_after" == "$start_before" ]] || continue
					sampled_pids[$pid]=1
					process_rows+="$row"$'\n'
				done <"$cgroup_procs"
			elif [[ "$main_pid" != 0 ]]; then
				# A unit may leave the active state between the state and identity probes.
				# Treat the vanished cgroup as an empty sample; the next loop reclassifies it.
				:
			fi
			;;
		inactive | failed)
			;;
		*)
			sampler_atomic_marker "$sample_dir/sampler-hard-stop.env" \
				"$(printf 'sampler_hard_stop_utc=%s\nactive_units=%s\nprobe_failed=1\n' "$timestamp" "$active_units")"
			printf 'sampler systemd probe failed: unit=%s exit_status=%s output=%q\n' "$unit" "$probe_status" "$probe_output" >&2
			exit 75
			;;
		esac
	done <"$units_file"

		awk_result="$(awk 'NF >= 6 { count += 1; cpu += $2; rss += $4 } END { printf "%d\t%.2f\t%d", count, cpu, rss }' <<<"$process_rows")"
    load_values=$(awk '{ printf "%s\t%s\t%s", $1, $2, $3 }' /proc/loadavg)
    mem_available=$(awk '/MemAvailable:/ { print $2 }' /proc/meminfo)
		now_epoch=$(date +%s)
		timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$timestamp" "$now_epoch" "$active_units" "$awk_result" "$load_values" "$mem_available" >>"$samples"

		[[ -z "$process_rows" ]] || awk -v ts="$timestamp" -v epoch="$now_epoch" \
			'{ printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, epoch, $1, $2, $3, $4, $5, $6 }' \
			<<<"$process_rows" >>"$process_samples"

	if [ "$now_epoch" -ge "$end_epoch" ]; then
		if [ "$active_units" -ne 0 ]; then
			sampler_atomic_marker "$sample_dir/sampler-hard-stop.env" \
				"$(printf 'sampler_hard_stop_utc=%s\nactive_units=%s\n' "$timestamp" "$active_units")"
			printf 'sampler hard deadline reached with %s active fuzz units\n' "$active_units" >&2
			exit 75
		fi
		break
	fi
		remaining_sleep=$((end_epoch - $(date +%s)))
		((remaining_sleep > 0)) || continue
		((remaining_sleep < interval)) || remaining_sleep="$interval"
	    sleep "$remaining_sleep"
	done
sampler_completed_epoch="$(date +%s)"
sampler_atomic_marker "$sample_dir/sampler-completed.env" \
	"$(printf 'status=passed\ncompleted_utc=%s\ncompleted_epoch_seconds=%s\nactive_units=0\ndeadline_epoch_seconds=%s\nlast_sample_epoch_seconds=%s\n' \
		"$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$sampler_completed_epoch" "$end_epoch" "$now_epoch")"
SAMPLER
} >"$remote_runner"
chmod +x "$remote_runner"

campaign_capture_candidate_identity "$remote_runner" runner_candidate || exit 1
campaign_publish_root_runner "$systemd_unit.service" "$remote_runner" \
	"$runner_candidate_sha256" "$runner_candidate_device" "$runner_candidate_inode" "fuzz sampler runner" || exit 1
remote_runner="$campaign_published_runner"
campaign_publish_root_bound_file "$remote_runner" "$units_file" fuzz-units.txt \
	"$units_candidate_sha256" "$units_candidate_device" "$units_candidate_inode" "fuzz sampler unit allowlist" || exit 1
fragment_candidate="$(mktemp)"
cat >"$fragment_candidate" <<UNIT
[Unit]
Description=BoronDNS fuzz campaign host sampler $campaign_id
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex
WorkingDirectory=$repo
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LimitNOFILE=65536
RuntimeMaxSec=$((duration + 3600 + target_setup_reserve_seconds + sampler_terminal_reserve_seconds))
TimeoutStopSec=30
ExecStart=$remote_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$systemd_unit
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
campaign_capture_candidate_identity "$fragment_candidate" fragment_candidate_identity || { rm -f "$fragment_candidate"; exit 1; }
campaign_publish_systemd_fragment "$unit_root" "$unit_root/$systemd_unit.service" "$fragment_candidate" "$remote_runner" \
	"$fragment_candidate_identity_sha256" "$fragment_candidate_identity_device" "$fragment_candidate_identity_inode" \
	"fuzz sampler unit" || { rm -f "$fragment_candidate"; exit 1; }
rm -f "$fragment_candidate"

timeout --preserve-status --kill-after=10 120 sudo systemctl daemon-reload
timeout --preserve-status --kill-after=10 120 sudo systemctl reset-failed "$systemd_unit.service" >/dev/null 2>&1 || true
timeout --preserve-status --kill-after=10 120 sudo systemctl start "$systemd_unit.service"
unit_is_exactly_active "$systemd_unit.service" "$unit_root/$systemd_unit.service" "$runner_prefix" || {
	printf 'sampler post-start unit identity confirmation failed: %s.service\n' "$systemd_unit" >&2
	exit 1
}
wait_for_sampler_first_sample || exit 1
timeout --preserve-status --kill-after=5 30 systemctl --no-pager --full status "$systemd_unit.service" || true
REMOTE
        } >"$staging/commands/$host-host-sampler.sh"
        chmod +x "$staging/commands/$host-host-sampler.sh"
        printf '%s\t%s\t%s\t%s\t%s\n' "$host" "$remote_sample_dir" "$systemd_unit.service" "$command_file" \
            "$sampler_deadline_epoch_seconds" >>"$sampler_tsv"
    done < <(unique_hosts)
}

load_plan() {
    local executing_repo_root="$repo_root"
    [[ -n "$evidence_dir" ]] || die "--evidence-dir is required for $command"
    campaign_require_real_directory "$evidence_dir" "campaign plan directory" || die "unsafe campaign plan directory: $evidence_dir"
    campaign_require_real_directory "$evidence_dir/commands" "campaign commands directory" || die "unsafe campaign commands directory"
    campaign_require_owned_nonwritable_plan_tree "$evidence_dir" "fuzz campaign plan tree" ||
        die "campaign plan tree is not exclusively writable by its owner: $evidence_dir"
    [[ -f "$evidence_dir/plan-complete" && ! -L "$evidence_dir/plan-complete" ]] || die "campaign plan is incomplete: $evidence_dir"
    [[ "$(cat "$evidence_dir/plan-complete")" == complete ]] || die "campaign completion marker is invalid: $evidence_dir"
    campaign_require_contained_file "$evidence_dir" "$evidence_dir/campaign.env" "campaign env" || die "missing or unsafe campaign env: $evidence_dir/campaign.env"
    campaign_manifest_verify "$evidence_dir" || die "campaign manifest verification failed: $evidence_dir"
    campaign_require_contained_file "$evidence_dir" "$evidence_dir/validate-collected-campaign.py" "saved campaign validator" ||
        die "missing or unsafe saved campaign validator"
    unset hosts targets
    campaign_env_load "$evidence_dir/campaign.env" \
        campaign_id created_utc repo_root source_commit source_clean remote_repo remote_evidence \
        duration_seconds toolchain sanitizer cargo_sha256 rustc_sha256 cargo_fuzz_sha256 \
        target_repeat sampler_interval_seconds sampler_deadline_epoch_seconds sampler_enabled \
        hosts targets || die "invalid campaign env: $evidence_dir/campaign.env"
    [[ "$repo_root" == "$executing_repo_root" ]] || die "campaign repo_root does not match the executing checkout"
    repo_root="$executing_repo_root"
    local host_list="${hosts[*]}"
    local target_list="${targets[*]}"
    IFS=' ' read -r -a hosts <<<"$host_list"
    IFS=' ' read -r -a targets <<<"$target_list"
    local saved_target
    for saved_target in "${targets[@]}"; do
        [[ "$saved_target" =~ ^[A-Za-z0-9_-]+$ && -f "$repo_root/fuzz/fuzz_targets/$saved_target.rs" ]] ||
            die "campaign metadata names unknown fuzz target: $saved_target"
    done
    [[ "$source_clean" == 1 || "${BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY:-0}" == 1 ]] ||
        die "saved campaign was planned from a dirty source tree"
    local created_epoch expected_sampler_deadline
    created_epoch="$(utc_timestamp_epoch "$created_utc")" || die "invalid campaign creation timestamp"
    require_bounded_positive_integer "saved duration_seconds" "$duration_seconds" "$max_nanosecond_seconds"
    require_bounded_positive_integer "saved target_repeat" "$target_repeat" "$max_target_repeat"
    require_bounded_positive_integer "saved sampler_interval_seconds" "$sampler_interval_seconds" "$max_sampler_interval_seconds"
    ((${#targets[@]} <= max_expanded_targets)) ||
        die "saved expanded fuzz target count exceeds the supported maximum $max_expanded_targets"
    ((created_epoch <= 9223372036854775807 - duration_seconds - 3600 - target_setup_reserve_seconds)) ||
        die "saved fuzz sampler deadline exceeds signed 64-bit epoch time"
    expected_sampler_deadline=$((created_epoch + duration_seconds + 3600 + target_setup_reserve_seconds))
    [[ "$sampler_deadline_epoch_seconds" == "$expected_sampler_deadline" ]] ||
        die "fuzz sampler deadline differs from the immutable campaign schedule"
    local assignments="$evidence_dir/assignments.tsv"
    campaign_validate_tsv "$assignments" \
        $'host\ttarget\tduration_seconds\tremote_evidence_dir\tsystemd_unit\tremote_command_file' 6 ||
        die "invalid fuzz campaign assignments: $assignments"
    ((${#targets[@]} % target_repeat == 0)) || die "fuzz target list is not divisible by target_repeat"
    local base_target_count
    base_target_count=$((${#targets[@]} / target_repeat))
    ((base_target_count > 0)) || die "fuzz campaign has no base targets"
    local -a base_targets=("${targets[@]:0:base_target_count}")
    local repeat_index base_index
    for ((repeat_index = 0; repeat_index < target_repeat; repeat_index++)); do
        for ((base_index = 0; base_index < base_target_count; base_index++)); do
            [[ "${targets[$((repeat_index * base_target_count + base_index))]}" == "${base_targets[$base_index]}" ]] ||
                die "fuzz target repetition order drift at repeat $repeat_index index $base_index"
        done
    done
    campaign_prepare_private_temporary_tree "${TMPDIR:-/tmp}" borondns-fuzz-plan-reference \
        fuzz_semantic_reference semantic_reference_dir ||
        die "could not create identity-bound fuzz semantic reference"
    semantic_reference_cleanup_root="$(dirname "$semantic_reference_dir")"
    local reference_plan="$semantic_reference_dir/plan"
    local -a reference_args=(
        plan --evidence-dir "$reference_plan" --campaign-id "$campaign_id"
        --remote-repo "$remote_repo" --remote-evidence "$remote_evidence"
        --duration "$duration_seconds" --target-repeat "$target_repeat"
        --toolchain "$toolchain" --sampler-interval "$sampler_interval_seconds"
    )
    local reference_host reference_target
    for reference_host in "${hosts[@]}"; do
        reference_args+=(--host "$reference_host")
    done
    for reference_target in "${base_targets[@]}"; do
        reference_args+=(--target "$reference_target")
    done
    [[ "$sanitizer" == cargo-fuzz-default ]] || reference_args+=(--sanitizer "$sanitizer")
    [[ "$sampler_enabled" == 1 ]] || reference_args+=(--no-sampler)
    BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 BORONDNS_FUZZ_SOAK_INTERNAL_CREATED_UTC="$created_utc" \
        "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" \
        "${reference_args[@]}" >/dev/null || die "could not regenerate fuzz campaign semantic reference"
    cmp -s "$evidence_dir/validate-collected-campaign.py" "$reference_plan/validate-collected-campaign.py" ||
        die "saved fuzz collection validator content drift"

    local row_host row_target row_duration row_evidence row_unit row_command
    local index=0 safe_target safe_instance expected_host expected_evidence expected_command expected_unit
    local safe_campaign
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    local -A seen_assignment_instances=() expected_command_files=()
    while IFS=$'\t' read -r row_host row_target row_duration row_evidence row_unit row_command; do
        ((index < ${#targets[@]})) || die "fuzz campaign has excess assignment rows"
        expected_host="${hosts[$((index % ${#hosts[@]}))]}"
        [[ "$row_host" == "$expected_host" ]] || die "fuzz assignment host distribution drift at row $index"
        [[ "$row_target" == "${targets[$index]}" ]] || die "fuzz assignment target order drift at row $index"
        [[ "$row_duration" == "$duration_seconds" ]] || die "fuzz assignment duration drift at row $index"
        safe_target="$(systemd_escape_fragment "$row_target")"
        safe_instance="$(printf '%03d-%s' "$index" "$safe_target")"
        [[ -z "${seen_assignment_instances[$safe_instance]:-}" ]] || die "duplicate fuzz assignment instance: $safe_instance"
        seen_assignment_instances[$safe_instance]=1
        expected_evidence="$remote_evidence/fuzz/$safe_instance"
        expected_command="$evidence_dir/commands/$row_host-$safe_instance.sh"
        [[ "$row_evidence" == "$expected_evidence" ]] || die "fuzz assignment evidence path drift at row $index"
        expected_unit="borondns-fuzz-$safe_campaign-$index-$safe_target.service"
        [[ "$row_unit" == "$expected_unit" ]] || die "fuzz assignment unit identity drift at row $index"
        [[ "$row_command" == "$expected_command" && -x "$row_command" ]] ||
            die "invalid fuzz assignment command path at row $index"
        campaign_require_contained_file "$evidence_dir/commands" "$row_command" "fuzz assignment command" ||
            die "unsafe fuzz assignment command path at row $index"
        expected_command_files["$(basename "$row_command")"]=1
        campaign_command_matches_saved_tools "$row_command" "$reference_plan/commands/$row_host-$safe_instance.sh" ||
            die "fuzz assignment command content drift at row $index"
        index=$((index + 1))
    done < <(tail -n +2 "$assignments")
    ((index == ${#targets[@]})) || die "fuzz assignment row count does not match target list"
    if [[ "$sampler_enabled" == 1 ]]; then
        local sampler_tsv="$evidence_dir/host-samplers.tsv"
        campaign_validate_tsv "$sampler_tsv" \
            $'host\tremote_sample_dir\tsystemd_unit\tremote_command_file\tdeadline_epoch_seconds' 5 ||
            die "invalid fuzz sampler assignments: $sampler_tsv"
        local sampler_host sample_dir sampler_unit sampler_command sampler_deadline sampler_count=0 safe_host expected_sampler_unit
        local -A expected_sampler_hosts=() seen_sampler_hosts=()
        local expected_sampler_host
        local -a ordered_sampler_hosts=()
        for expected_sampler_host in "${hosts[@]}"; do
            if [[ -z "${expected_sampler_hosts[$expected_sampler_host]:-}" ]]; then
                expected_sampler_hosts[$expected_sampler_host]=1
                ordered_sampler_hosts+=("$expected_sampler_host")
            fi
        done
        while IFS=$'\t' read -r sampler_host sample_dir sampler_unit sampler_command sampler_deadline; do
            ((sampler_count < ${#ordered_sampler_hosts[@]})) || die "fuzz sampler has excess assignment rows"
            [[ -z "${seen_sampler_hosts[$sampler_host]:-}" ]] || die "duplicate sampler assignment host: $sampler_host"
            seen_sampler_hosts[$sampler_host]=1
            [[ "$sampler_host" == "${ordered_sampler_hosts[$sampler_count]}" ]] ||
                die "sampler host order drift at row $sampler_count"
            list_contains_word "$sampler_host" "${hosts[@]}" || die "sampler assignment names unknown host: $sampler_host"
            safe_host="$(systemd_escape_fragment "$sampler_host")"
            [[ "$sample_dir" == "$remote_evidence/host/$safe_host" ]] || die "sampler evidence path drift: $sampler_host"
            expected_sampler_unit="borondns-fuzz-$safe_campaign-host-sampler-$safe_host.service"
            [[ "$sampler_unit" == "$expected_sampler_unit" ]] || die "sampler unit identity drift: $sampler_host"
            [[ "$sampler_command" == "$evidence_dir/commands/$sampler_host-host-sampler.sh" && -x "$sampler_command" ]] ||
                die "invalid sampler command path: $sampler_host"
            [[ "$sampler_deadline" == "$sampler_deadline_epoch_seconds" ]] ||
                die "sampler assignment deadline drift: $sampler_host"
            campaign_require_contained_file "$evidence_dir/commands" "$sampler_command" "sampler command" ||
                die "unsafe sampler command path: $sampler_host"
            expected_command_files["$(basename "$sampler_command")"]=1
            cmp -s "$sampler_command" "$reference_plan/commands/$sampler_host-host-sampler.sh" ||
                die "sampler command content drift: $sampler_host"
            sampler_count=$((sampler_count + 1))
        done < <(tail -n +2 "$sampler_tsv")
        ((sampler_count == ${#expected_sampler_hosts[@]})) || die "sampler assignment row count does not match unique host list"
    elif [[ -e "$evidence_dir/host-samplers.tsv" ]]; then
        die "sampler TSV exists although sampler is disabled"
    fi
    local actual_command
    while IFS= read -r -d '' actual_command; do
        [[ -f "$actual_command" && ! -L "$actual_command" && -n "${expected_command_files[$(basename "$actual_command")]:-}" ]] ||
            die "unreferenced or unsafe fuzz command in canonical plan: $actual_command"
    done < <(find "$evidence_dir/commands" -mindepth 1 -maxdepth 1 -print0 | sort -z)
    [[ "$(find "$evidence_dir/commands" -mindepth 1 -maxdepth 1 -type f | wc -l)" == "${#expected_command_files[@]}" ]] ||
        die "fuzz command count does not match canonical assignments"
    validated_command_dir="$reference_plan/commands"
}

new_target_launch_fits_sampler_window() {
    ((sampler_enabled)) || return 0
    local now_epoch latest_start_epoch
    now_epoch="$(date +%s)" || die "cannot read current epoch for fuzz launch preflight"
    [[ "$now_epoch" =~ ^[0-9]+$ ]] || die "current epoch is invalid: $now_epoch"
    latest_start_epoch=$((sampler_deadline_epoch_seconds - duration_seconds - target_setup_reserve_seconds))
    ((now_epoch <= latest_start_epoch))
}

require_launch_sampler_window() {
    new_target_launch_fits_sampler_window ||
        die "authenticated sampler window cannot reserve a newly launched target setup (deadline=$sampler_deadline_epoch_seconds duration=$duration_seconds setup_reserve=$target_setup_reserve_seconds)"
}

resume_window_preflight() {
    resume_window_noop=0
    new_target_launch_fits_sampler_window && return 0

    local host target remote_target_dir systemd_unit command_file validated_command
    local classification_output classification
    local launch_required=0 sampler_incompatible=0 target_incompatible=0
    local -A sampler_state_by_host=()
    if ((sampler_enabled)); then
        local remote_sample_dir sampler_state
        while IFS=$'\t' read -r host remote_sample_dir systemd_unit command_file _; do
            validated_command="$validated_command_dir/$(basename "$command_file")"
            if ! classification_output="$(campaign_ssh_bounded \
                "${BORONDNS_CAMPAIGN_REMOTE_STATUS_TIMEOUT_SECONDS:-120}" \
                -- "$host" "BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 BORONDNS_CAMPAIGN_CLASSIFY_ONLY=1 bash -s" \
                <"$validated_command")"; then
                die "read-only sampler resume classification failed: host=$host unit=$systemd_unit"
            fi
            classification="$(tail -n 1 <<<"$classification_output")"
            case "$classification" in
            sampler_resume_classification=active | sampler_resume_classification=complete)
                sampler_state="${classification#*=}"
                sampler_state_by_host[$host]="$sampler_state"
                printf 'resume preflight host=%s sampler=%s\n' "$host" "$sampler_state"
                ;;
            sampler_resume_classification=absent | sampler_resume_classification=failed | sampler_resume_classification=hard-stopped)
                sampler_state="${classification#*=}"
                sampler_state_by_host[$host]="$sampler_state"
                sampler_incompatible=1
                printf 'resume preflight host=%s sampler=%s\n' "$host" "$sampler_state"
                ;;
            *)
                die "ambiguous read-only sampler resume classification: host=$host output=$classification"
                ;;
            esac
        done < <(tail -n +2 "$evidence_dir/host-samplers.tsv")
    fi
    while IFS=$'\t' read -r host target _ remote_target_dir systemd_unit command_file; do
        validated_command="$validated_command_dir/$(basename "$command_file")"
        if ! classification_output="$(campaign_ssh_bounded \
            "${BORONDNS_CAMPAIGN_REMOTE_STATUS_TIMEOUT_SECONDS:-120}" \
            -- "$host" "BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 BORONDNS_CAMPAIGN_CLASSIFY_ONLY=1 bash -s" \
            <"$validated_command")"; then
            die "read-only resume classification failed: host=$host target=$target unit=$systemd_unit"
        fi
        classification="$(tail -n 1 <<<"$classification_output")"
        case "$classification" in
        target_resume_classification=active)
            printf 'resume preflight host=%s target=%s active\n' "$host" "$target"
            if ((sampler_enabled)) && [[ "${sampler_state_by_host[$host]:-}" != active ]]; then
                target_incompatible=1
            fi
            ;;
        target_resume_classification=complete)
            printf 'resume preflight host=%s target=%s complete\n' "$host" "$target"
            if ((sampler_enabled)); then
                case "${sampler_state_by_host[$host]:-}" in active | complete) ;; *) target_incompatible=1 ;; esac
            fi
            ;;
        target_resume_classification=launch-required)
            printf 'resume preflight host=%s target=%s launch-required\n' "$host" "$target"
            launch_required=1
            ;;
        *)
            die "ambiguous read-only resume classification: host=$host target=$target output=$classification"
            ;;
        esac
    done < <(tail -n +2 "$evidence_dir/assignments.tsv")

    if ((sampler_incompatible)); then
        die "expired resume requires every sampler to remain active or have exact terminal success evidence"
    fi
    if ((target_incompatible)); then
        die "expired resume target state is incompatible with its authenticated sampler state"
    fi
    if ((launch_required)); then
        die "authenticated sampler window cannot cover a newly launched resume target (deadline=$sampler_deadline_epoch_seconds duration=$duration_seconds)"
    fi
    printf 'resume is already active or complete; no mutation is needed after the sampler launch window\n'
    resume_window_noop=1
}

launch_plan() {
    write_plan
    load_plan
    require_launch_sampler_window
    local host target remote_target_dir systemd_unit command_file validated_command
    if ((sampler_enabled)) && [[ -r "$evidence_dir/host-samplers.tsv" ]]; then
        local remote_sample_dir
        tail -n +2 "$evidence_dir/host-samplers.tsv" | while IFS=$'\t' read -r host remote_sample_dir systemd_unit command_file _; do
            printf 'launching host=%s sampler_unit=%s evidence=%s\n' "$host" "$systemd_unit" "$remote_sample_dir"
            validated_command="$validated_command_dir/$(basename "$command_file")"
            campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_LAUNCH_TIMEOUT_SECONDS:-3600}" \
                -- "$host" "bash -s" <"$validated_command"
        done
    fi
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host target _ remote_target_dir systemd_unit command_file; do
        printf 'launching host=%s target=%s unit=%s evidence=%s\n' "$host" "$target" "$systemd_unit" "$remote_target_dir"
        validated_command="$validated_command_dir/$(basename "$command_file")"
        campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_LAUNCH_TIMEOUT_SECONDS:-3600}" \
            -- "$host" "bash -s" <"$validated_command"
    done
}

resume_plan() {
    load_plan
    resume_window_preflight
    ((resume_window_noop == 0)) || return 0
    local host target remote_target_dir systemd_unit command_file validated_command
    if [[ -r "$evidence_dir/host-samplers.tsv" ]]; then
        local remote_sample_dir
        tail -n +2 "$evidence_dir/host-samplers.tsv" | while IFS=$'\t' read -r host remote_sample_dir systemd_unit command_file _; do
            printf 'classifying and launching sampler host=%s unit=%s under remote lock\n' "$host" "$systemd_unit"
            validated_command="$validated_command_dir/$(basename "$command_file")"
            campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_LAUNCH_TIMEOUT_SECONDS:-3600}" \
                -- "$host" "BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 bash -s" <"$validated_command"
        done
    fi
    tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r host target _ remote_target_dir systemd_unit command_file; do
        printf 'classifying and launching target=%s host=%s unit=%s under remote lock\n' "$target" "$host" "$systemd_unit"
        validated_command="$validated_command_dir/$(basename "$command_file")"
        campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_LAUNCH_TIMEOUT_SECONDS:-3600}" \
            -- "$host" "BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 bash -s" <"$validated_command"
    done
}

status_plan() {
    load_plan
    local host target remote_target_dir systemd_unit command_file helper_sha256
    local status_result=0
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        printf '== %s ==\n' "$host"
        while IFS=$'\t' read -r row_host target _ remote_target_dir systemd_unit command_file; do
            [[ "$row_host" == "$host" ]] || continue
            printf '%s\n' "-- target=$target unit=$systemd_unit --"
            helper_sha256="$(sed -n 's/^campaign_helper_sha256=//p' "$command_file")"
            [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid authenticated campaign helper digest: $command_file"
            if ! campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_STATUS_TIMEOUT_SECONDS:-120}" \
                -- "$host" bash -s -- "$systemd_unit" "$remote_target_dir" "$remote_repo" "$source_commit" "$helper_sha256" <<'REMOTE'; then
set -euo pipefail
unit="$1"
remote_target_dir="$2"
repo="$3"
expected_commit="$4"
expected_helper_sha256="$5"
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

unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
fragment_expected="$unit_root/$unit"
runner_prefix="/var/tmp/borondns-campaign-runners/${unit%.service}/attempt."
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
	loaded_fragment="$(awk -F= '$1 == "FragmentPath" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	exec_start="$(awk -F= '$1 == "ExecStart" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	if [[ "$load" == not-found && ! -e "$fragment_expected" && ! -L "$fragment_expected" ]]; then
		printf 'unit_identity=absent\n'
		elif [[ "$source_exact" == 1 && "$load" == loaded ]]; then
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
				if [[ -n "$runner" && "$loaded_fragment" == "$fragment_expected" && "$exec_start" == "{ path=$runner ;"* ]]; then
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
summary_count=0
while IFS= read -r -d '' summary; do
	summary_count=$((summary_count + 1))
	printf 'campaign_summary=%s\n' "$summary"
	cat "$summary"
done < <(find "$remote_target_dir/attempts" -mindepth 3 -maxdepth 3 -type f -path '*/evidence/campaign-summary.tsv' -print0 2>/dev/null | sort -z)
if [[ "$summary_count" == 0 ]]; then
	printf 'campaign_summary_missing_under=%s\n' "$remote_target_dir/attempts"
fi
timeout --preserve-status --kill-after=5 30 journalctl -u "$unit" --no-pager -n 60 2>/dev/null || true
exit "$remote_probe_status"
REMOTE
                printf 'status probe failed: host=%s unit=%s\n' "$host" "$systemd_unit" >&2
                status_result=1
            fi
        done < <(tail -n +2 "$evidence_dir/assignments.tsv")
        if [[ -r "$evidence_dir/host-samplers.tsv" ]]; then
            while IFS=$'\t' read -r row_host remote_sample_dir systemd_unit command_file _; do
                [[ "$row_host" == "$host" ]] || continue
                printf '%s\n' "-- host-sampler unit=$systemd_unit --"
                helper_sha256="$(sed -n 's/^campaign_helper_sha256=//p' "$command_file")"
                [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid authenticated campaign helper digest: $command_file"
                if ! campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_STATUS_TIMEOUT_SECONDS:-120}" \
                    -- "$host" bash -s -- "$systemd_unit" "$remote_sample_dir" "$remote_repo" "$source_commit" "$helper_sha256" <<'REMOTE'; then
set -euo pipefail
unit="$1"
remote_sample_dir="$2"
repo="$3"
expected_commit="$4"
expected_helper_sha256="$5"
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
unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
fragment_expected="$unit_root/$unit"
runner_prefix="/var/tmp/borondns-campaign-runners/${unit%.service}/attempt."
unit_properties=""
if ! unit_properties="$(timeout --preserve-status --kill-after=5 30 systemctl show "$unit" -p LoadState -p ActiveState -p SubState -p Result \
	-p FragmentPath -p ExecStart -p ExecMainStatus --no-pager 2>/dev/null)"; then
	printf 'systemctl_status_probe_failed=%s\n' "$unit" >&2
	remote_probe_status=1
else
	printf '%s\n' "$unit_properties"
	load="$(awk -F= '$1 == "LoadState" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	loaded_fragment="$(awk -F= '$1 == "FragmentPath" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	exec_start="$(awk -F= '$1 == "ExecStart" { print substr($0, index($0, "=") + 1) }' <<<"$unit_properties")"
	if [[ "$load" == not-found && ! -e "$fragment_expected" && ! -L "$fragment_expected" ]]; then
		printf 'unit_identity=absent\n'
		elif [[ "$source_exact" == 1 && "$load" == loaded ]]; then
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
				if [[ -n "$runner" && "$loaded_fragment" == "$fragment_expected" && "$exec_start" == "{ path=$runner ;"* ]]; then
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
sample_count=0
while IFS= read -r -d '' samples; do
	sample_count=$((sample_count + 1))
	printf 'host_samples=%s\n' "$samples"
	tail -5 "$samples"
done < <(find "$remote_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name host-samples.tsv -print0 2>/dev/null | sort -z)
if [[ "$sample_count" == 0 ]]; then
	printf 'host_samples_missing_under=%s\n' "$remote_sample_dir/attempts"
fi
exit "$remote_probe_status"
REMOTE
                    printf 'status probe failed: host=%s unit=%s\n' "$host" "$systemd_unit" >&2
                    status_result=1
                fi
            done < <(tail -n +2 "$evidence_dir/host-samplers.tsv")
        fi
    done < <(unique_hosts)
    return "$status_result"
}

collect_plan() {
    load_plan
    campaign_prepare_contained_directory "$evidence_dir" "$evidence_dir/remotes" "campaign remotes directory" ||
        die "unsafe campaign collection directory"
    local host safe_host transport_host target remote_target_dir systemd_unit command_file
    local destination staging before_snapshot after_snapshot local_snapshot validated_snapshot validation_output classification status_file status_commit_file journal_dir journal_staging status_staging status_commit_staging
    local collection_deadline collection_copy_timeout collection_journal_timeout
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        safe_host="${host//[^A-Za-z0-9_.-]/_}"
        transport_host="$(campaign_remote_copy_host "$host")" || die "invalid collection host: $host"
        destination="$evidence_dir/remotes/$safe_host"
        journal_dir="$evidence_dir/remotes/$safe_host.journal"
        status_file="$evidence_dir/remotes/$safe_host.collection-status.tsv"
        status_commit_file="$status_file.commit"
        campaign_prepare_collection_budget collection_deadline || die "invalid fuzz collection resource budget"
        campaign_acquire_private_lock "$evidence_dir/remotes" "$(realpath -ms "$evidence_dir"):collect:$safe_host" \
            "fuzz host collection lock" "$collection_deadline" "$collection_deadline" ||
            die "another collector is active or the collection budget is unavailable for host: $safe_host"
        campaign_assert_private_lock || die "fuzz host collection lock broker exited: $safe_host"
        campaign_recover_collection_bundle "$evidence_dir/remotes" "$destination" "$journal_dir" "$status_file" \
            "$status_commit_file" "fuzz host collection" "$collection_deadline" ||
            die "could not recover interrupted collection bundle: $safe_host"
        if [[ -e "$destination" || -L "$destination" ]]; then
            campaign_require_owned_real_directory "$destination" "host collection directory" || die "unsafe host collection directory: $safe_host"
        fi
        staging="$(mktemp -d "$evidence_dir/remotes/.${safe_host}.collection.XXXXXX")"
        campaign_require_owned_real_directory "$staging" "host collection staging directory" || die "unsafe host collection staging directory: $safe_host"
        campaign_capture_cleanup_identity "$staging" tree fuzz_collection_evidence_staging \
            "fuzz collection evidence staging" || die "could not bind host collection staging identity: $safe_host"
        before_snapshot="$(campaign_remote_tree_snapshot "$host" "$remote_evidence" "$collection_deadline")" || {
            campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                "fuzz collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-preflight-failed\n' "fuzz collection status" || true
            die "remote evidence preflight failed: $host"
        }
        printf 'collecting host=%s remote=%s\n' "$host" "$remote_evidence"
        campaign_collection_phase_timeout_seconds collection_copy_timeout "$collection_deadline" \
            "${BORONDNS_CAMPAIGN_REMOTE_COPY_TIMEOUT_SECONDS:-7200}" || die "fuzz collection copy budget expired: $host"
        if command -v rsync >/dev/null 2>&1; then
            if ! BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$collection_deadline" \
                campaign_rsync_bounded "$collection_copy_timeout" \
                -a --delete --no-links --no-devices --no-specials -- \
                "$transport_host:$(shell_quote "$remote_evidence")/" "$staging/"; then
                campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                    "fuzz collection evidence staging" || true
                campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-copy-failed\n' "fuzz collection status" || true
                die "remote evidence copy failed: $host"
            fi
        else
            campaign_scp_remote_path_is_safe "$remote_evidence" || {
                campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                    "fuzz collection evidence staging" || true
                campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\trsync-required-for-unsafe-remote-path\n' "fuzz collection status" || true
                die "rsync is required to collect a remote evidence path containing whitespace or shell metacharacters: $remote_evidence"
            }
            if ! BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$collection_deadline" \
                campaign_scp_bounded "$collection_copy_timeout" \
                -r -- "$transport_host:$remote_evidence/." "$staging/"; then
                campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                    "fuzz collection evidence staging" || true
                campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-copy-failed\n' "fuzz collection status" || true
                die "remote evidence copy failed: $host"
            fi
        fi
        after_snapshot="$(campaign_remote_tree_snapshot "$host" "$remote_evidence" "$collection_deadline")" || {
            campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                "fuzz collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tremote-postflight-failed\n' "fuzz collection status" || true
            die "remote evidence postflight failed: $host"
        }
        local_snapshot="$(campaign_local_tree_snapshot "$staging" "$collection_deadline" \
            "$evidence_dir/validate-collected-campaign.py")" || {
            campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                "fuzz collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tunsafe-local-tree\n' "fuzz collection status" || true
            die "unsafe copied evidence tree: $host"
        }
        [[ "$before_snapshot" == "$after_snapshot" && "$after_snapshot" == "$local_snapshot" ]] || {
            campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                "fuzz collection evidence staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tconcurrent-mutation-or-copy-mismatch\n' "fuzz collection status" || true
            die "remote evidence changed during collection or copied bytes differ: $host"
        }
        validation_output="$(mktemp "$evidence_dir/remotes/.${safe_host}.validation.XXXXXX")"
        campaign_capture_cleanup_identity "$validation_output" file fuzz_collection_validation_staging \
            "fuzz collection validation staging" || die "could not bind validation staging identity: $safe_host"
        local -a validator_args=(
            fuzz-host "$staging" "$source_commit"
            --expected-duration "$duration_seconds"
            --expected-toolchain "$toolchain"
            --expected-sanitizer "$sanitizer"
            --expected-cargo-sha256 "$cargo_sha256"
            --expected-rustc-sha256 "$rustc_sha256"
            --expected-cargo-fuzz-sha256 "$cargo_fuzz_sha256"
            --absolute-deadline-nanoseconds "$collection_deadline"
            --max-entries "$campaign_collection_max_entries"
            --max-depth "$campaign_collection_max_depth"
            --max-file-bytes "$campaign_collection_max_file_bytes"
            --max-total-bytes "$campaign_collection_max_total_bytes"
        )
        while IFS=$'\t' read -r row_host target _ remote_target_dir systemd_unit command_file; do
            [[ "$row_host" == "$host" ]] || continue
            validator_args+=(--expected-target "$(basename "$remote_target_dir")")
        done < <(tail -n +2 "$evidence_dir/assignments.tsv")
        if [[ -r "$evidence_dir/host-samplers.tsv" ]] && awk -F '\t' -v host="$host" 'NR > 1 && $1 == host { found=1 } END { exit !found }' "$evidence_dir/host-samplers.tsv"; then
            validator_args+=(
                --expected-sampler "$safe_host"
                --expected-sampler-interval "$sampler_interval_seconds"
                --expected-sampler-deadline "$sampler_deadline_epoch_seconds"
            )
            while IFS=$'\t' read -r row_host _ _ _ systemd_unit _; do
                [[ "$row_host" == "$host" ]] || continue
                validator_args+=(--expected-sampler-unit "$systemd_unit")
            done < <(tail -n +2 "$evidence_dir/assignments.tsv")
        else
            validator_args+=(--no-sampler)
        fi
        if ! campaign_run_before_deadline "$collection_deadline" \
            python3 "$evidence_dir/validate-collected-campaign.py" "${validator_args[@]}" >"$validation_output"; then
            campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                "fuzz collection evidence staging" || true
            campaign_remove_captured_cleanup_object "$validation_output" fuzz_collection_validation_staging \
                "fuzz collection validation staging" || true
            campaign_publish_status_text "$evidence_dir/remotes" "$status_file" $'classification\treason\ninvalid\tstrict-local-validation-failed\n' "fuzz collection status" || true
            die "strict local fuzz evidence validation failed: $host"
        fi
        validated_snapshot="$(campaign_local_tree_snapshot "$staging" "$collection_deadline" \
            "$evidence_dir/validate-collected-campaign.py")" || die "post-validation fuzz snapshot failed: $host"
        [[ "$validated_snapshot" == "$local_snapshot" ]] ||
            die "copied fuzz evidence changed during strict local validation: $host"
        classification=incomplete
        if [[ "$(wc -l <"$validation_output")" -gt 1 ]] && awk -F '\t' 'NR > 1 && $4 != "complete" { exit 1 }' "$validation_output"; then
            classification=complete
        fi
        status_staging="$(mktemp "$evidence_dir/remotes/.${safe_host}.status.XXXXXX")"
        {
            printf 'collection\t%s\tremote-snapshot\t%s\t%s\n' \
                "$safe_host" "$classification" "$validated_snapshot"
            cat "$validation_output"
        } >"$status_staging"
        campaign_remove_captured_cleanup_object "$validation_output" fuzz_collection_validation_staging \
            "fuzz collection validation staging" || die "could not remove validation staging: $safe_host"
        campaign_capture_cleanup_identity "$status_staging" file fuzz_collection_status_staging \
            "fuzz collection status staging" || die "could not bind status staging identity: $safe_host"
        status_commit_staging="$(mktemp "$evidence_dir/remotes/.${safe_host}.status-commit.XXXXXX")"
        campaign_collection_status_commit_text "$status_staging" "$validated_snapshot" \
            "$collection_deadline" >"$status_commit_staging" ||
            die "could not construct status commit: $safe_host"
        campaign_capture_cleanup_identity "$status_commit_staging" file \
            fuzz_collection_status_commit_staging "fuzz collection status commit staging" ||
            die "could not bind status commit staging identity: $safe_host"
        journal_staging="$(mktemp -d "$evidence_dir/remotes/.${safe_host}.journal.XXXXXX")"
        campaign_capture_cleanup_identity "$journal_staging" tree fuzz_collection_journal_staging \
            "fuzz collection journal staging" || die "could not bind journal staging identity: $safe_host"
        tail -n +2 "$evidence_dir/assignments.tsv" | while IFS=$'\t' read -r row_host target _ remote_target_dir systemd_unit command_file; do
            [[ "$row_host" == "$host" ]] || continue
            campaign_collection_phase_timeout_seconds collection_journal_timeout "$collection_deadline" \
                "${BORONDNS_CAMPAIGN_REMOTE_JOURNAL_TIMEOUT_SECONDS:-300}" ||
                die "fuzz collection journal budget expired: $host"
            BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$collection_deadline" \
                campaign_ssh_bounded "$collection_journal_timeout" \
                -n -- "$host" "journalctl -u $(shell_quote "$systemd_unit") --no-pager" \
                >"$journal_staging/$systemd_unit.log" 2>&1 || true
        done
        campaign_publish_collection_bundle "$evidence_dir/remotes" "$staging" "$destination" \
            "$journal_staging" "$journal_dir" "$status_staging" "$status_file" "fuzz host collection" \
            "$validated_snapshot" "$collection_deadline" "$evidence_dir/validate-collected-campaign.py" \
            "$status_commit_staging" "$status_commit_file" || {
            campaign_remove_captured_cleanup_object "$staging" fuzz_collection_evidence_staging \
                "fuzz collection evidence staging" || true
            campaign_remove_captured_cleanup_object "$journal_staging" fuzz_collection_journal_staging \
                "fuzz collection journal staging" || true
            campaign_remove_captured_cleanup_object "$status_staging" fuzz_collection_status_staging \
                "fuzz collection status staging" || true
            campaign_remove_captured_cleanup_object "$status_commit_staging" \
                fuzz_collection_status_commit_staging \
                "fuzz collection status commit staging" || true
            die "could not publish validated collection bundle: $safe_host"
        }
        campaign_collection_status_accepts_generation "$destination" "$status_file" \
            "$collection_deadline" "$evidence_dir/validate-collected-campaign.py" ||
            die "published fuzz collection does not match its committed digest: $safe_host"
        campaign_release_private_lock
    done < <(unique_hosts)
}

cleanup_remote_job() {
    local host="$1" unit="$2" runner_prefix="$3" build_root="$4" lock_kind="$5" repo="$6" expected_commit="$7" expected_helper_sha256="$8" expected_lock_helper_sha256="$9"
    campaign_ssh_bounded "${BORONDNS_CAMPAIGN_REMOTE_CLEANUP_TIMEOUT_SECONDS:-300}" \
        -- "$host" bash -s -- "$unit" "$runner_prefix" "$build_root" "$lock_kind" "$repo" "$expected_commit" "$expected_helper_sha256" "$expected_lock_helper_sha256" <<'REMOTE'
set -euo pipefail
unit="$1"
runner_prefix="$2"
build_root="$3"
lock_kind="$4"
repo="$5"
expected_commit="$6"
expected_helper_sha256="$7"
expected_lock_helper_sha256="$8"
unit_root="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}"
fragment="$unit_root/$unit"
lock_root="/tmp/borondns-campaign-locks-$(id -u)"
[[ -d "$lock_root" && ! -L "$lock_root" ]] || { printf 'cleanup lock root is unsafe: %s\n' "$lock_root" >&2; exit 1; }
[[ "$(realpath -ms "$lock_root")" == "$(realpath -e "$lock_root")" && "$(stat -c %u "$lock_root")" == "$(id -u)" ]] || exit 1
lock_mode="$(stat -c %a "$lock_root")"
(( (8#$lock_mode & 077) == 0 )) || { printf 'cleanup lock root is not private: %s\n' "$lock_root" >&2; exit 1; }
case "$lock_kind" in
campaign | setup) ;;
*) printf 'cleanup lock kind is invalid: %s\n' "$lock_kind" >&2; exit 1 ;;
esac
git_path=/usr/bin/git
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || { printf 'cleanup expected commit is invalid\n' >&2; exit 1; }
[[ -x "$git_path" && -f "$git_path" && ! -L "$git_path" && "$(stat -c %u "$git_path")" == 0 ]] || {
    printf 'cleanup trusted git executable is unsafe: %s\n' "$git_path" >&2
    exit 1
}
[[ -f "$repo/scripts/campaign-env.sh" && ! -L "$repo/scripts/campaign-env.sh" ]] || {
    printf 'cleanup helper is unsafe: %s\n' "$repo/scripts/campaign-env.sh" >&2
    exit 1
}
[[ -f "$repo/scripts/campaign-lock-helper.py" && ! -L "$repo/scripts/campaign-lock-helper.py" ]] || {
    printf 'cleanup lock helper is unsafe: %s\n' "$repo/scripts/campaign-lock-helper.py" >&2
    exit 1
}
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
campaign_acquire_private_lock "$lock_root" "${unit%.service}:$lock_kind" "remote cleanup lock" || exit 1
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
import stat
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
    -p ControlGroup -p FragmentPath -p ExecStart --no-pager)" || {
    printf 'cleanup refused because systemctl state probe failed: %s\n' "$unit" >&2
    exit 1
}
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
[[ "$main_pid" == 0 && "$control_pid" == 0 && -z "$job" ]] || {
    printf 'cleanup refused for live or queued unit: %s main=%s control=%s job=%s\n' "$unit" "$main_pid" "$control_pid" "$job" >&2
    exit 1
}
# Complete every identity and build-root check before the first removal.  A
# loaded unit whose already-verified fragment was removed by an earlier cleanup
# attempt remains recoverable through its exact loaded ExecStart identity.
runner=""
fragment_present=0
if [[ -e "$fragment" || -L "$fragment" ]]; then
		[[ -f "$fragment" && ! -L "$fragment" ]] || { printf 'cleanup unit fragment mismatch: %s\n' "$unit" >&2; exit 1; }
		runner="$(campaign_validate_systemd_fragment_runner "$fragment" "$runner_prefix")" || { printf 'cleanup unit runner mismatch: %s\n' "$unit" >&2; exit 1; }
	if [[ "$load" != not-found ]]; then
			[[ "$loaded_fragment" == "$fragment" && "$exec_start" == "{ path=$runner ;"* ]] || { printf 'cleanup loaded unit identity mismatch: %s\n' "$unit" >&2; exit 1; }
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
	[[ "$loaded_fragment" == "$fragment" ]] || { printf 'cleanup loaded fragment identity mismatch: %s\n' "$unit" >&2; exit 1; }
	loaded_runner="${exec_start#\{ path=}"
	loaded_runner="${loaded_runner%% ;*}"
		campaign_validate_root_runner "$loaded_runner" "$runner_prefix" || { printf 'cleanup loaded runner identity mismatch: %s\n' "$unit" >&2; exit 1; }
fi
	build_root_present=0
	if [[ -n "$build_root" && ! -e "$build_root" && ! -L "$build_root" ]]; then
		printf 'cleanup expected fuzz build root is missing; refusing ambiguous cleanup: %s\n' "$build_root" >&2
		exit 1
	fi
	if [[ -n "$build_root" ]]; then
		[[ "$build_root" == /var/tmp/borondns-fuzz-* && -d "$build_root" && ! -L "$build_root" ]] || exit 1
		[[ "$(realpath -ms "$build_root")" == "$(realpath -e "$build_root")" && "$(stat -c %u "$build_root")" == "$(id -u)" ]] || exit 1
		[[ -z "$(find "$build_root" -type l -print -quit)" ]] || { printf 'cleanup build root contains symlinks: %s\n' "$build_root" >&2; exit 1; }
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
	build_root_present=1
fi
campaign_remove_systemd_fragment_staging "$unit_root" "$fragment" "remote cleanup" || exit 1
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
    "$post_main" == 0 && "$post_control" == 0 && -z "$post_job" && -z "$post_control_group" ]] || {
    printf 'cleanup daemon-reload left non-terminal unit state: %s load=%s active=%s sub=%s main=%s control=%s job=%s cgroup=%s\n' \
        "$unit" "$post_load" "$post_active" "$post_sub" "$post_main" "$post_control" "$post_job" "$post_control_group" >&2
    exit 1
}
verify_old_cgroup_empty "$old_control_group" || {
    printf 'cleanup refused because old unit cgroup is populated: %s cgroup=%s\n' "$unit" "$old_control_group" >&2
    exit 1
}
campaign_remove_root_runner_tree "$unit" "remote cleanup" || exit 1
if ((build_root_present)); then
	# This campaign-UID-owned namespace is never safe for pathname-based
	# recursive deletion. Publish the exact identity mapping before logically
	# removing the canonical name, then retain the whole tree for reconciliation.
	campaign_assert_private_lock || exit 1
	campaign_retained_identity_bound_remove unprivileged tree "$build_parent" "$build_root" \
		"$build_parent_device" "$build_parent_inode" "$build_parent_owner" \
		"$build_device" "$build_inode" "$build_owner" "" \
		"remote fuzz-soak build-root cleanup" || exit 1
fi
REMOTE
}

cleanup_plan() {
    load_plan
    local host target remote_target_dir systemd_unit command_file safe_campaign safe_instance build_root helper_sha256 lock_helper_sha256
    safe_campaign="$(systemd_escape_fragment "$campaign_id")"
    while IFS=$'\t' read -r host target _ remote_target_dir systemd_unit command_file; do
        safe_instance="$(basename "$remote_target_dir")"
        build_root="/var/tmp/borondns-fuzz-$safe_campaign/$safe_instance"
        helper_sha256="$(sed -n 's/^campaign_helper_sha256=//p' "$command_file")"
        lock_helper_sha256="$(sed -n 's/^campaign_lock_helper_sha256=//p' "$command_file")"
        [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ && "$lock_helper_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid authenticated campaign helper digest: $command_file"
        cleanup_remote_job "$host" "$systemd_unit" "/var/tmp/borondns-campaign-runners/${systemd_unit%.service}/attempt." "$build_root" campaign "$remote_repo" "$source_commit" "$helper_sha256" "$lock_helper_sha256"
    done < <(tail -n +2 "$evidence_dir/assignments.tsv")
    if [[ -r "$evidence_dir/host-samplers.tsv" ]]; then
        local remote_sample_dir
        while IFS=$'\t' read -r host remote_sample_dir systemd_unit command_file _; do
            helper_sha256="$(sed -n 's/^campaign_helper_sha256=//p' "$command_file")"
            lock_helper_sha256="$(sed -n 's/^campaign_lock_helper_sha256=//p' "$command_file")"
            [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ && "$lock_helper_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid authenticated campaign helper digest: $command_file"
            cleanup_remote_job "$host" "$systemd_unit" "/var/tmp/borondns-campaign-runners/${systemd_unit%.service}/attempt." "" setup "$remote_repo" "$source_commit" "$helper_sha256" "$lock_helper_sha256"
        done < <(tail -n +2 "$evidence_dir/host-samplers.tsv")
    fi
}

main() {
    parse_args "$@"
    case "$command" in
    plan)
        set_defaults
        write_plan
        printf 'campaign_plan_dir=%s\n' "$evidence_dir"
        ;;
    launch)
        set_defaults
        launch_plan
        printf 'campaign_plan_dir=%s\n' "$evidence_dir"
        ;;
    resume)
        [[ -n "$evidence_dir" ]] || die "--evidence-dir is required for resume"
        resume_plan
        ;;
    status)
        status_plan
        ;;
    collect)
        collect_plan
        ;;
    cleanup)
        cleanup_plan
        ;;
    esac
}

main "$@"
