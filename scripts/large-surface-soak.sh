#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/large-surface-soak.sh [OPTIONS]

Run a long large-surface BoronDNS soak by repeatedly executing retained
real-primary and protocol scenarios, while sampling host resources and retaining
per-scenario artifacts.

Options:
  --evidence-dir DIR       Evidence output directory.
  --duration SECONDS       Wall-clock duration. Default: 86400.
  --scenario NAME          Scenario to include; repeatable. Defaults to broad set.
  --scenario-timeout SECS  Per-scenario timeout. Default: 1800.
  --scenario-kill-after SECS
                           Hard-kill grace after timeout. Default: 30.
  --cycle-sleep SECS       Sleep between full cycles. Default: 5.
  --sample-interval SECS   Resource sample interval. Default: 60.
  --expected-commit SHA    Require this exact clean repository HEAD before each cycle and scenario.
  --allow-skip             Treat scenario self-skip as skipped instead of failed. Default.
  --fail-on-skip           Treat scenario self-skip as failed.
  --resume                 Append to an existing evidence directory and continue
                           at the next cycle number.
  --resume-cross-boot-diagnostic
                           Permit a cross-boot resume only as non-release
                           diagnostic evidence. Prior active time is retained
                           but not credited; a fresh full duration is run.
  --dry-run                Print selected scenarios and exit.
  -h, --help               Show this help.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/campaign-env.sh
source "$repo_root/scripts/campaign-env.sh"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="${BORONDNS_LARGE_SOAK_DIR:-$repo_root/target/evidence/large-surface-soak-$timestamp}"
duration="${BORONDNS_LARGE_SOAK_DURATION_SECONDS:-86400}"
scenario_timeout="${BORONDNS_LARGE_SOAK_SCENARIO_TIMEOUT_SECONDS:-1800}"
scenario_kill_after="${BORONDNS_LARGE_SOAK_SCENARIO_KILL_AFTER_SECONDS:-30}"
cycle_sleep="${BORONDNS_LARGE_SOAK_CYCLE_SLEEP_SECONDS:-5}"
sample_interval="${BORONDNS_LARGE_SOAK_SAMPLE_INTERVAL_SECONDS:-60}"
allow_skip="${BORONDNS_LARGE_SOAK_ALLOW_SKIP:-1}"
resume=0
resume_cross_boot_diagnostic=0
cross_boot_diagnostic_active=0
dry_run=0
selected_scenarios=()
scenario_names=()
scenario_scripts=()
scenario_env_vars=()
sampler_pid=""
sampler_attempt_dir=""
campaign_start_epoch=""
campaign_deadline_epoch=""
campaign_control_deadline_nanoseconds=""
campaign_boot_id=""
docker_cleanup_timeout="${BORONDNS_LARGE_SOAK_DOCKER_CLEANUP_TIMEOUT_SECONDS:-30}"
host_probe_timeout="${BORONDNS_LARGE_SOAK_HOST_PROBE_TIMEOUT_SECONDS:-30}"
host_probe_kill_after="${BORONDNS_LARGE_SOAK_HOST_PROBE_KILL_AFTER_SECONDS:-5}"
docker_cleanup_operation_count=6
docker_cleanup_kill_after_seconds=5
scenario_timestamp_tolerance_seconds=2
cargo_target_dir="${CARGO_TARGET_DIR:-}"
cargo_target_dir_auto=0
expected_commit="${BORONDNS_LARGE_SOAK_EXPECTED_COMMIT:-}"
expected_cargo_sha256="${BORONDNS_LARGE_SOAK_EXPECTED_CARGO_SHA256:-}"
expected_rustc_sha256="${BORONDNS_LARGE_SOAK_EXPECTED_RUSTC_SHA256:-}"
selected_cargo_path=""
selected_rustc_path=""
authenticated_cargo_shim=""
scenario_list_for_validation=""

add_scenario() {
    scenario_names+=("$1")
    scenario_scripts+=("$2")
    scenario_env_vars+=("$3")
}

init_scenarios() {
    add_scenario bind_catalog scripts/interop-bind-catalog-zone-docker.sh BORONDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR
    add_scenario bind_xot_catalog scripts/interop-bind-xot-catalog-zone-docker.sh BORONDNS_BIND_XOT_CATALOG_DOCKER_ARTIFACT_DIR
    add_scenario powerdns_catalog_tsig scripts/interop-powerdns-postgres-catalog-tsig-docker.sh BORONDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR
    add_scenario powerdns_catalog_extension scripts/interop-powerdns-catalog-member-extension-docker.sh BORONDNS_POWERDNS_CATALOG_MEMBER_EXTENSION_ARTIFACT_DIR
    add_scenario powerdns_split_primaries scripts/interop-powerdns-catalog-split-primaries-docker.sh BORONDNS_POWERDNS_CATALOG_SPLIT_PRIMARIES_ARTIFACT_DIR
    add_scenario bind_axfr scripts/interop-bind-axfr.sh BORONDNS_BIND_AXFR_ARTIFACT_DIR
    add_scenario bind_tsig_axfr scripts/interop-bind-tsig-axfr.sh BORONDNS_BIND_TSIG_AXFR_ARTIFACT_DIR
    add_scenario bind_notify scripts/interop-bind-notify-refresh.sh BORONDNS_BIND_NOTIFY_ARTIFACT_DIR
    add_scenario bind_ixfr scripts/interop-bind-ixfr-refresh.sh BORONDNS_BIND_IXFR_ARTIFACT_DIR
    add_scenario nsd_axfr scripts/interop-nsd-axfr-docker.sh BORONDNS_NSD_AXFR_ARTIFACT_DIR
    add_scenario nsd_tsig_axfr scripts/interop-nsd-tsig-axfr-docker.sh BORONDNS_NSD_TSIG_AXFR_ARTIFACT_DIR
    add_scenario nsd_notify scripts/interop-nsd-notify-refresh-docker.sh BORONDNS_NSD_NOTIFY_ARTIFACT_DIR
    add_scenario knot_axfr scripts/interop-knot-axfr-docker.sh BORONDNS_KNOT_AXFR_ARTIFACT_DIR
    add_scenario knot_tsig_axfr scripts/interop-knot-tsig-axfr-docker.sh BORONDNS_KNOT_TSIG_AXFR_ARTIFACT_DIR
    add_scenario knot_notify scripts/interop-knot-notify-refresh-docker.sh BORONDNS_KNOT_NOTIFY_ARTIFACT_DIR
    add_scenario knot_ixfr scripts/interop-knot-ixfr-refresh-docker.sh BORONDNS_KNOT_IXFR_ARTIFACT_DIR
    add_scenario knot_xot scripts/interop-knot-xot-docker.sh BORONDNS_KNOT_XOT_ARTIFACT_DIR
    add_scenario knot_xot_tsig scripts/interop-knot-xot-tsig-docker.sh BORONDNS_KNOT_XOT_TSIG_ARTIFACT_DIR
    add_scenario dnssec_serve scripts/interop-dnssec-serve.sh BORONDNS_DNSSEC_SERVE_ARTIFACT_DIR
    add_scenario dnssec_nsec3 scripts/interop-dnssec-nsec3-serve.sh BORONDNS_DNSSEC_NSEC3_ARTIFACT_DIR
    add_scenario unknown_rr scripts/interop-unknown-rr.sh BORONDNS_UNKNOWN_RR_ARTIFACT_DIR
    add_scenario unknown_rr_bad_transfer scripts/interop-unknown-rr-bad-transfer.sh BORONDNS_UNKNOWN_RR_BAD_ARTIFACT_DIR
    add_scenario negative_responses scripts/interop-negative-responses.sh BORONDNS_NEGATIVE_RESPONSE_ARTIFACT_DIR
    add_scenario notify_negative scripts/interop-notify-negative.sh BORONDNS_NOTIFY_NEGATIVE_ARTIFACT_DIR
    add_scenario tcp_truncation scripts/interop-tcp-truncation-retry.sh BORONDNS_TCP_TRUNCATION_ARTIFACT_DIR
    add_scenario edns_behavior scripts/interop-edns-behavior.sh BORONDNS_EDNS_BEHAVIOR_ARTIFACT_DIR
    add_scenario dns_cookie scripts/interop-dns-cookie-dig.sh BORONDNS_DNS_COOKIE_ARTIFACT_DIR
    add_scenario ixfr_notimp scripts/interop-ixfr-notimp-fallback.sh BORONDNS_IXFR_FALLBACK_ARTIFACT_DIR
    add_scenario rrl_udp scripts/interop-rrl-udp.sh BORONDNS_RRL_UDP_ARTIFACT_DIR
    add_scenario chaos_queries scripts/interop-chaos-queries.sh BORONDNS_CHAOS_QUERIES_ARTIFACT_DIR
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

checked_campaign_deadline() {
    local start_epoch="$1"
    local campaign_duration="$2"
    local max_epoch=9223372036
    [[ "$start_epoch" =~ ^[0-9]+$ ]] || return 1
    ((start_epoch <= max_epoch && campaign_duration <= max_epoch - start_epoch)) || return 1
    printf '%s\n' "$((start_epoch + campaign_duration))"
}

monotonic_nanoseconds() {
    # CLOCK_BOOTTIME keeps one deadline meaningful across suspend and is paired
    # with the kernel boot ID before it is ever reused by --resume.
    python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))'
}

current_boot_id() {
    local value
    IFS= read -r value </proc/sys/kernel/random/boot_id || return 1
    [[ "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
    printf '%s\n' "$value"
}

initialize_campaign_control_deadline() {
    local wall_now monotonic_now remaining_seconds saved_boot_id saved_deadline original
    wall_now="$(date +%s)" || return 1
    monotonic_now="$(monotonic_nanoseconds)" || return 1
    campaign_boot_id="$(current_boot_id)" || return 1
    [[ "$wall_now" =~ ^[0-9]+$ && "$monotonic_now" =~ ^[0-9]+$ ]] || return 1
    if ! ((resume)); then
        remaining_seconds=$((campaign_deadline_epoch - wall_now))
        ((remaining_seconds > 0)) || return 1
        ((monotonic_now <= 9223372036854775807 - remaining_seconds * 1000000000)) || return 1
        campaign_control_deadline_nanoseconds=$((monotonic_now + remaining_seconds * 1000000000))
        return 0
    fi

    original="$evidence_dir/soak.env"
    saved_boot_id="$(resume_identity_value "$original" boot_id)" || {
        printf 'original campaign metadata has no unique boot_id: %s\n' "$original" >&2
        return 1
    }
    saved_deadline="$(resume_identity_value "$original" control_deadline_boottime_nanoseconds)" || {
        printf 'original campaign metadata has no unique control_deadline_boottime_nanoseconds: %s\n' "$original" >&2
        return 1
    }
    [[ "$saved_boot_id" =~ ^[0-9a-f-]{36}$ && "$saved_deadline" =~ ^[0-9]+$ ]] || return 1
    if [[ "$saved_boot_id" == "$campaign_boot_id" ]]; then
        ((monotonic_now < saved_deadline)) || return 1
        campaign_control_deadline_nanoseconds="$saved_deadline"
        return 0
    fi
    ((resume_cross_boot_diagnostic)) || {
        printf 'release-evidence resume refused across boot IDs: saved=%s current=%s\n' \
            "$saved_boot_id" "$campaign_boot_id" >&2
        return 1
    }

    # Cross-boot elapsed wall time is not trustworthy enough to reconstruct a
    # release deadline. Diagnostic mode therefore credits none of the earlier
    # active time and runs a new full-duration window, conservatively longer.
    ((monotonic_now <= 9223372036854775807 - duration * 1000000000)) || return 1
    campaign_control_deadline_nanoseconds=$((monotonic_now + duration * 1000000000))
    campaign_start_epoch="$wall_now"
    campaign_deadline_epoch="$(checked_campaign_deadline "$wall_now" "$duration")" || return 1
    cross_boot_diagnostic_active=1
}

validate_timing_bounds() {
    local now_epoch="$1"
    local max_epoch=9223372036
    [[ "$now_epoch" =~ ^[0-9]+$ ]] || die "current epoch is invalid: $now_epoch"
    ((now_epoch < max_epoch)) || die "current epoch exceeds nanosecond-safe campaign time"
    require_bounded_positive_integer "--duration" "$duration" "$((max_epoch - now_epoch))"
    require_bounded_positive_integer "--scenario-timeout" "$scenario_timeout" "$max_epoch"
    require_bounded_positive_integer "--scenario-kill-after" "$scenario_kill_after" "$max_epoch"
    require_bounded_positive_integer "--cycle-sleep" "$cycle_sleep" "$max_epoch"
    require_bounded_positive_integer "--sample-interval" "$sample_interval" "$max_epoch"
    require_bounded_positive_integer "BORONDNS_LARGE_SOAK_DOCKER_CLEANUP_TIMEOUT_SECONDS" "$docker_cleanup_timeout" "$max_epoch"
    require_bounded_positive_integer "BORONDNS_LARGE_SOAK_HOST_PROBE_TIMEOUT_SECONDS" "$host_probe_timeout" "$max_epoch"
    require_bounded_positive_integer "BORONDNS_LARGE_SOAK_HOST_PROBE_KILL_AFTER_SECONDS" "$host_probe_kill_after" "$max_epoch"
}

large_soak_bounded_probe() {
    timeout --preserve-status --kill-after="$host_probe_kill_after" "$host_probe_timeout" "$@"
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
        --scenario-kill-after)
            (($# >= 2)) || die "--scenario-kill-after requires a value"
            scenario_kill_after="$2"
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
        --expected-commit)
            (($# >= 2)) || die "--expected-commit requires a value"
            expected_commit="$2"
            shift 2
            ;;
        --expected-cargo-sha256)
            (($# >= 2)) || die "--expected-cargo-sha256 requires a value"
            expected_cargo_sha256="$2"
            shift 2
            ;;
        --expected-rustc-sha256)
            (($# >= 2)) || die "--expected-rustc-sha256 requires a value"
            expected_rustc_sha256="$2"
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
        --resume)
            resume=1
            shift
            ;;
        --resume-cross-boot-diagnostic)
            resume=1
            resume_cross_boot_diagnostic=1
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

verify_expected_clean_head() {
    [[ -n "$expected_commit" ]] || return 0
    [[ "$expected_commit" =~ ^[0-9a-f]{40,64}$ ]] || die "invalid --expected-commit SHA: $expected_commit"
    local actual_commit status
    actual_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || die "cannot resolve repository HEAD: $repo_root"
    [[ "$actual_commit" == "$expected_commit" ]] ||
        die "soak repository commit drift: expected=$expected_commit actual=$actual_commit"
    if ! status="$(git -C "$repo_root" status --short --untracked-files=all)"; then
        die "git status failed while checking soak repository: $repo_root"
    fi
    [[ -z "$status" ]] || {
        printf 'soak repository became dirty before evidence execution: %s\n%s\n' "$repo_root" "$status" >&2
        return 1
    }
}

bind_initial_provenance() {
    if [[ -z "$expected_commit" ]]; then
        expected_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" ||
            die "cannot resolve repository HEAD: $repo_root"
    fi
    if [[ -z "$expected_cargo_sha256" && -z "$expected_rustc_sha256" ]]; then
        expected_cargo_sha256="$(campaign_sha256 "$selected_cargo_path")" ||
            die "cannot hash selected cargo"
        expected_rustc_sha256="$(campaign_sha256 "$selected_rustc_path")" ||
            die "cannot hash selected rustc"
    fi
    verify_expected_clean_head
    verify_expected_tool_hashes
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
    local output="${1:-$evidence_dir/tool-versions.txt}"
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'cargo_target_dir=%s\n' "$cargo_target_dir"
        printf 'cargo_path=%s\n' "$selected_cargo_path"
        printf 'cargo_sha256=%s\n' "$(campaign_sha256 "$selected_cargo_path")"
        printf 'rustc_path=%s\n' "$selected_rustc_path"
        printf 'rustc_sha256=%s\n' "$(campaign_sha256 "$selected_rustc_path")"
        printf '$ git rev-parse HEAD\n'
        large_soak_bounded_probe git -C "$repo_root" rev-parse HEAD 2>&1 || true
        printf '$ git status --short\n'
        large_soak_bounded_probe git -C "$repo_root" status --short 2>&1 || true
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
            large_soak_bounded_probe bash -lc "$cmd" 2>&1 || true
        done
    } >"$output"
}

resolve_rust_tools() {
    if [[ -n "${BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO:-}" || -n "${BORONDNS_LARGE_SOAK_AUTHENTICATED_RUSTC:-}" ]]; then
        [[ -n "${BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO:-}" && -n "${BORONDNS_LARGE_SOAK_AUTHENTICATED_RUSTC:-}" ]] ||
            die "authenticated large-soak tool overrides must be supplied together"
        selected_cargo_path="$BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO"
        selected_rustc_path="$BORONDNS_LARGE_SOAK_AUTHENTICATED_RUSTC"
        authenticated_cargo_shim="${BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO_SHIM:-}"
        [[ -n "$authenticated_cargo_shim" && "$(command -v cargo 2>/dev/null)" == "$authenticated_cargo_shim" &&
        -L "$authenticated_cargo_shim" && "$(readlink "$authenticated_cargo_shim")" == /proc/self/fd/7 ]] ||
            die "authenticated large-soak Cargo shim is missing or not first on PATH"
    elif command -v rustup >/dev/null 2>&1; then
        selected_cargo_path="$(rustup which cargo 2>/dev/null)" || die "cannot resolve active rustup cargo"
        selected_rustc_path="$(rustup which rustc 2>/dev/null)" || die "cannot resolve active rustup rustc"
    else
        selected_cargo_path="$(command -v cargo 2>/dev/null)" || die "cargo not found on PATH"
        selected_rustc_path="$(command -v rustc 2>/dev/null)" || die "rustc not found on PATH"
    fi
    if [[ -z "${BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO:-}" ]]; then
        selected_cargo_path="$(realpath -e "$selected_cargo_path")" || die "cannot canonicalize selected cargo"
        selected_rustc_path="$(realpath -e "$selected_rustc_path")" || die "cannot canonicalize selected rustc"
    fi
    [[ -x "$selected_cargo_path" && -f "$selected_cargo_path" ]] || die "selected cargo is not executable"
    [[ -x "$selected_rustc_path" && -f "$selected_rustc_path" ]] || die "selected rustc is not executable"
    if [[ -z "${BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO:-}" ]]; then
        local selected_tool_dir
        selected_tool_dir="$(dirname "$selected_cargo_path")"
        export PATH="$selected_tool_dir:$PATH"
    fi
    export RUSTC="$selected_rustc_path"
}

verify_expected_tool_hashes() {
    if [[ -z "$expected_cargo_sha256" && -z "$expected_rustc_sha256" ]]; then
        return 0
    fi
    [[ -n "$expected_cargo_sha256" && -n "$expected_rustc_sha256" ]] ||
        die "expected cargo and rustc SHA-256 values must be supplied together"
    [[ "$expected_cargo_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid expected cargo SHA-256"
    [[ "$expected_rustc_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid expected rustc SHA-256"
    [[ "$(campaign_sha256 "$selected_cargo_path")" == "$expected_cargo_sha256" ]] ||
        die "large-soak cargo identity drift"
    [[ "$(campaign_sha256 "$selected_rustc_path")" == "$expected_rustc_sha256" ]] ||
        die "large-soak rustc identity drift"
    if [[ -n "$authenticated_cargo_shim" ]]; then
        [[ "$(command -v cargo 2>/dev/null)" == "$authenticated_cargo_shim" ]] ||
            die "large-soak Cargo command search identity drift"
        [[ "$(stat -Lc '%d:%i' "$authenticated_cargo_shim")" == "$(stat -Lc '%d:%i' "$selected_cargo_path")" ]] ||
            die "large-soak Cargo shim no longer resolves to the inherited executable"
        [[ "$(campaign_sha256 "$authenticated_cargo_shim")" == "$expected_cargo_sha256" ]] ||
            die "large-soak Cargo shim content drift"
    fi
}

prepare_build_directory() {
    if [[ -z "$cargo_target_dir" ]]; then
        campaign_prepare_private_temporary_tree "${TMPDIR:-/var/tmp}" borondns-large-builds \
            large_soak_auto_build cargo_target_dir || die "cannot create private automatic CARGO_TARGET_DIR"
        cargo_target_dir_auto=1
    elif [[ -e "$cargo_target_dir" || -L "$cargo_target_dir" ]]; then
        [[ -d "$cargo_target_dir" && ! -L "$cargo_target_dir" ]] ||
            die "CARGO_TARGET_DIR must be a real directory: $cargo_target_dir"
    else
        mkdir -m 0700 "$cargo_target_dir"
    fi
    local repo_real build_real
    repo_real="$(realpath -e "$repo_root")"
    build_real="$(realpath -e "$cargo_target_dir")" || die "cannot resolve CARGO_TARGET_DIR: $cargo_target_dir"
    campaign_require_owned_real_directory "$build_real" "CARGO_TARGET_DIR" || die "unsafe CARGO_TARGET_DIR"
    [[ "$build_real" != "$repo_real" && "$build_real" != "$repo_real"/* ]] ||
        die "CARGO_TARGET_DIR must be outside the repository: $cargo_target_dir"
    [[ "$(stat -c %u "$build_real")" == "$(id -u)" ]] ||
        die "CARGO_TARGET_DIR is not owned by the runner: $build_real"
    [[ -z "$(find "$build_real" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        die "CARGO_TARGET_DIR must be empty before the campaign build: $build_real"
    cargo_target_dir="$build_real"
    export CARGO_TARGET_DIR="$cargo_target_dir"
}

cleanup_automatic_build_directory() {
    ((cargo_target_dir_auto)) || return 0
    [[ -n "$cargo_target_dir" ]] || return 0
    campaign_remove_private_temporary_tree "$cargo_target_dir" large_soak_auto_build \
        "automatic large-soak CARGO_TARGET_DIR" || return 1
    cargo_target_dir=""
    cargo_target_dir_auto=0
}

cleanup_early_large_soak_exit() {
    local status=$? final_status
    final_status="$status"
    trap - EXIT
    trap '' INT TERM HUP
    if declare -F large_soak_early_cleanup_started_hook >/dev/null 2>&1; then
        large_soak_early_cleanup_started_hook
    fi
    cleanup_automatic_build_directory || {
        printf 'failed to remove automatic large-soak CARGO_TARGET_DIR: %s\n' "$cargo_target_dir" >&2
        ((final_status != 0)) || final_status=74
    }
    exit "$final_status"
}

write_artifact_manifests() {
    local staged list path relative digest manifest_failed=0
    list="$(mktemp "$evidence_dir/.build-artifact-list.XXXXXX")" || return 1
    staged="$(mktemp "$evidence_dir/.build-artifacts.XXXXXX")" || {
        rm -f "$list"
        return 1
    }
    if [[ -d "$cargo_target_dir" && ! -L "$cargo_target_dir" ]]; then
        if ! find "$cargo_target_dir" -type f -perm /111 -print0 | LC_ALL=C sort -z >"$list"; then
            rm -f "$list" "$staged"
            return 1
        fi
        while IFS= read -r -d '' path; do
            if ! digest="$(campaign_sha256 "$path")"; then
                manifest_failed=1
                break
            fi
            if ! printf '%s  %s\n' "$digest" "$path" >>"$staged"; then
                manifest_failed=1
                break
            fi
        done <"$list"
        if ((manifest_failed)); then
            rm -f "$list" "$staged"
            return 1
        fi
    fi
    mv "$staged" "$evidence_dir/build-artifacts.sha256" || {
        rm -f "$list"
        return 1
    }

    : >"$list"
    staged="$(mktemp "$evidence_dir/.artifact-manifest.XXXXXX")" || {
        rm -f "$list"
        return 1
    }
    if ! find "$evidence_dir" -type f \
        ! -path "$evidence_dir/artifact-manifest.sha256" \
        ! -path "$evidence_dir/campaign-completed.env" \
        ! -path "$evidence_dir/.artifact-manifest.*" \
        ! -path "$evidence_dir/.build-artifact-list.*" -print0 | LC_ALL=C sort -z >"$list"; then
        rm -f "$list" "$staged"
        return 1
    fi
    manifest_failed=0
    while IFS= read -r -d '' path; do
        if ! digest="$(campaign_sha256 "$path")"; then
            manifest_failed=1
            break
        fi
        relative="${path#"$evidence_dir"/}"
        if ! printf '%s  %s\n' "$digest" "$relative" >>"$staged"; then
            manifest_failed=1
            break
        fi
    done <"$list"
    if ((manifest_failed)); then
        rm -f "$list" "$staged"
        return 1
    fi
    rm -f "$list"
    [[ -s "$staged" ]] || {
        rm -f "$staged"
        return 1
    }
    mv "$staged" "$evidence_dir/artifact-manifest.sha256"
}

record_host_info() {
    local output="${1:-$evidence_dir/host-info.txt}"
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        if command -v hostname >/dev/null 2>&1; then
            large_soak_bounded_probe hostname || true
        else
            printf 'hostname command unavailable\n'
        fi
        large_soak_bounded_probe uname -a || true
        large_soak_bounded_probe lscpu || true
        large_soak_bounded_probe free -h || true
        large_soak_bounded_probe df -h "$repo_root" "$evidence_dir" || true
        printf '\n/proc/cmdline:\n'
        cat /proc/cmdline 2>/dev/null || true
        printf '\nDocker info:\n'
        if command -v docker >/dev/null 2>&1; then
            large_soak_bounded_probe docker info 2>&1 || true
        else
            printf 'docker command unavailable\n'
        fi
    } >"$output"
}

sample_resources() {
    local samples="$1/resource-samples.tsv"
    local process_samples="$1/process-samples.tsv"
    local sampler_dir="$1"
    local end_epoch="$2"
    local control_deadline_nanoseconds="${3:-$campaign_control_deadline_nanoseconds}"
    local LC_ALL=C
    export LC_ALL
    if [[ -z "$control_deadline_nanoseconds" ]]; then
        local fallback_wall_now fallback_monotonic_now fallback_remaining
        fallback_wall_now="$(date +%s)"
        fallback_monotonic_now="$(monotonic_nanoseconds)"
        fallback_remaining=$((end_epoch - fallback_wall_now))
        ((fallback_remaining > 0)) || fallback_remaining=0
        control_deadline_nanoseconds=$((fallback_monotonic_now + fallback_remaining * 1000000000))
    fi
    printf 'timestamp_utc\tepoch_seconds\tload1\tload5\tload15\tmem_available_kib\tdocker_containers\tborondns_processes\ttotal_borondns_rss_kib\n' >"$samples"
    printf 'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm\n' >"$process_samples"
    while :; do
        local now control_now timestamp load_values mem_available docker_containers ps_summary process_rows
        local pid row stat_before stat_after stat_tail start_before start_after
        local -a process_ids=()
        now="$(date +%s)"
        control_now="$(monotonic_nanoseconds)"
        timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        load_values="$(awk '{ printf "%s\t%s\t%s", $1, $2, $3 }' /proc/loadavg)"
        mem_available="$(awk '/MemAvailable:/ { print $2 }' /proc/meminfo)"
        if command -v docker >/dev/null 2>&1; then
            docker_containers="$(large_soak_bounded_probe docker ps -q 2>/dev/null | wc -l | tr -d ' ')"
        else
            docker_containers=0
        fi
        mapfile -t process_ids < <(ps -eo pid=,ppid= | awk -v root="$$" '
            { parent[$1]=$2; order[NR]=$1 }
            END {
                selected[root]=1
                do {
                    changed=0
                    for (index=1; index<=NR; index++) {
                        pid=order[index]
                        if (!selected[pid] && selected[parent[pid]]) { selected[pid]=1; changed=1 }
                    }
                } while (changed)
                for (index=1; index<=NR; index++) if (selected[order[index]]) print order[index]
            }
        ')
        ((${#process_ids[@]} > 0)) || process_ids=("$$")
        process_rows=""
        for pid in "${process_ids[@]}"; do
            [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
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
            process_rows+="$row"$'\n'
        done
        ps_summary="$(awk 'NF >= 4 { count += 1; rss += $4 } END { printf "%d\t%d", count, rss }' <<<"$process_rows")"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$timestamp" "$now" "$load_values" "$mem_available" "$docker_containers" "$ps_summary" >>"$samples"
        [[ -z "$process_rows" ]] || awk -v ts="$timestamp" -v epoch="$now" \
            '{ printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, epoch, $1, $2, $3, $4, $5, $6 }' \
            <<<"$process_rows" >>"$process_samples"
        if ((control_now >= control_deadline_nanoseconds)); then
            break
        fi
        local remaining_sleep
        if remaining_sleep="$(scenario_timeout_within_campaign \
            "$sample_interval" "$control_deadline_nanoseconds" "$control_now" 0 0)"; then
            sleep "$remaining_sleep"
        fi
    done
    local completed="$sampler_dir/resource-sampler-completed.env"
    local completed_content completed_epoch
    completed_epoch="$(date +%s)"
    printf -v completed_content 'status=passed\ncompleted_utc=%s\ncompleted_epoch_seconds=%s\ndeadline_epoch_seconds=%s\nlast_sample_epoch_seconds=%s' \
        "$(date -u -d "@$completed_epoch" '+%Y-%m-%dT%H:%M:%SZ')" "$completed_epoch" "$end_epoch" "$(tail -n 1 "$samples" | cut -f2)"
    campaign_atomic_replace_text "$completed" "$completed_content" "resource sampler completion marker"
}

start_resource_sampler() {
    local end_epoch="$1"
    local control_deadline_nanoseconds="${2:-$campaign_control_deadline_nanoseconds}"
    local attempt_root="$evidence_dir/resource-sampler-attempts"
    campaign_prepare_contained_directory "$evidence_dir" "$attempt_root" "resource sampler attempt root" ||
        die "unsafe resource sampler attempt root"
    local attempt_number=1 attempt_name
    while :; do
        printf -v attempt_name 'attempt-%04d' "$attempt_number"
        [[ -e "$attempt_root/$attempt_name" ]] || break
        attempt_number=$((attempt_number + 1))
    done
    sampler_attempt_dir="$attempt_root/$attempt_name"
    mkdir -m 0700 -- "$sampler_attempt_dir" || die "cannot create resource sampler attempt: $sampler_attempt_dir"
    campaign_require_owned_real_directory "$sampler_attempt_dir" "resource sampler attempt" ||
        die "unsafe resource sampler attempt directory"
    local sampler_metadata sampler_started_epoch
    sampler_started_epoch="$(date +%s)"
    printf -v sampler_metadata 'started_utc=%s\nstarted_epoch_seconds=%s\ndeadline_epoch_seconds=%s\nsample_interval_seconds=%s' \
        "$(date -u -d "@$sampler_started_epoch" '+%Y-%m-%dT%H:%M:%SZ')" "$sampler_started_epoch" "$end_epoch" "$sample_interval"
    campaign_atomic_replace_text "$sampler_attempt_dir/resource-sampler.env" "$sampler_metadata" \
        "resource sampler metadata"
    (
        # The sampler is a distinct Bash process. It owns only its dedicated
        # attempt directory and must not borrow the runner's inherited evidence
        # broker descriptors or terminate that broker from its EXIT path.
        campaign_detach_inherited_private_lock
        campaign_acquire_private_lock "$attempt_root" \
            "$sampler_attempt_dir:resource-sampler-writer" \
            "resource sampler writer lock" || exit 70
        set +e
        (
            set -e
            sample_resources "$sampler_attempt_dir" "$end_epoch" "$control_deadline_nanoseconds"
        )
        local sampler_status=$?
        if ((sampler_status != 0)); then
            local failure_content failed_epoch
            failed_epoch="$(date +%s)"
            printf -v failure_content 'status=failed\nfailed_utc=%s\nfailed_epoch_seconds=%s\nexit_status=%s' \
                "$(date -u -d "@$failed_epoch" '+%Y-%m-%dT%H:%M:%SZ')" "$failed_epoch" "$sampler_status"
            campaign_atomic_replace_text "$sampler_attempt_dir/resource-sampler-failed.env" "$failure_content" \
                "resource sampler failure marker"
        fi
        campaign_release_private_lock || sampler_status=70
        exit "$sampler_status"
    ) &
    sampler_pid=$!
}

wait_for_resource_sampler_bounded() {
    local end_epoch="$1"
    local control_deadline_nanoseconds="${2:-$campaign_control_deadline_nanoseconds}"
    [[ -n "$sampler_pid" ]] || return 0
    local now final_deadline terminate_deadline status remaining_sleep
    if [[ -z "$control_deadline_nanoseconds" ]]; then
        local fallback_wall_now fallback_remaining
        fallback_wall_now="$(date +%s)" || return 70
        if ! now="$(monotonic_nanoseconds)"; then
            kill -KILL "$sampler_pid" 2>/dev/null || true
            wait "$sampler_pid" 2>/dev/null || true
            return 70
        fi
        fallback_remaining=$((end_epoch - fallback_wall_now))
        ((fallback_remaining > 0)) || fallback_remaining=0
        control_deadline_nanoseconds=$((now + fallback_remaining * 1000000000))
    fi
    if ((control_deadline_nanoseconds > 9223372036854775807 - (\
        host_probe_timeout + host_probe_kill_after + 10) * 1000000000)); then
        kill -KILL "$sampler_pid" 2>/dev/null || true
        wait "$sampler_pid" 2>/dev/null || true
        return 70
    fi
    final_deadline=$((control_deadline_nanoseconds + (\
        host_probe_timeout + host_probe_kill_after + 10) * 1000000000))
    while kill -0 "$sampler_pid" 2>/dev/null; do
        if ! now="$(monotonic_nanoseconds)"; then
            kill -KILL "$sampler_pid" 2>/dev/null || true
            wait "$sampler_pid" 2>/dev/null || true
            return 70
        fi
        if ((now >= final_deadline)); then
            printf 'resource sampler exceeded its bounded final wait; terminating pid=%s\n' "$sampler_pid" >&2
            kill "$sampler_pid" 2>/dev/null || true
            terminate_deadline=$((now + host_probe_kill_after * 1000000000))
            while kill -0 "$sampler_pid" 2>/dev/null; do
                now="$(monotonic_nanoseconds)" || break
                ((now < terminate_deadline)) || break
                remaining_sleep="$(scenario_timeout_within_campaign 1 "$terminate_deadline" "$now" 0 0)" || break
                sleep "$remaining_sleep"
            done
            kill -KILL "$sampler_pid" 2>/dev/null || true
            wait "$sampler_pid" 2>/dev/null || true
            return 124
        fi
        remaining_sleep="$(scenario_timeout_within_campaign 1 "$final_deadline" "$now" 0 0)" || continue
        sleep "$remaining_sleep"
    done
    set +e
    wait "$sampler_pid"
    status=$?
    set -e
    return "$status"
}

terminate_resource_sampler_bounded() {
    [[ -n "$sampler_pid" ]] || return 0
    local terminate_deadline now remaining_sleep
    kill "$sampler_pid" 2>/dev/null || true
    if ! now="$(monotonic_nanoseconds)"; then
        kill -KILL "$sampler_pid" 2>/dev/null || true
        wait "$sampler_pid" 2>/dev/null || true
        return 70
    fi
    terminate_deadline=$((now + host_probe_kill_after * 1000000000))
    while kill -0 "$sampler_pid" 2>/dev/null; do
        now="$(monotonic_nanoseconds)" || break
        ((now < terminate_deadline)) || break
        remaining_sleep="$(scenario_timeout_within_campaign 1 "$terminate_deadline" "$now" 0 0)" || break
        sleep "$remaining_sleep"
    done
    kill -KILL "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
}

reconcile_interrupted_resource_samplers() {
    local root="$evidence_dir/resource-sampler-attempts"
    [[ -d "$root" && ! -L "$root" ]] || return 0
    python3 - "$root" <<'PY'
import csv
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import sys

root = Path(sys.argv[1])
timestamp_pattern = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

def atomic_write(path, content):
    fd, staged_name = tempfile.mkstemp(prefix=f".{path.name}.borondns-staged.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(staged_name):
            os.unlink(staged_name)

def parse_env(path, keys):
    values = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key in values:
            return None
        values[key] = value
    return values if list(values) == keys else None

def value_is_valid(key, value, partial=False):
    if key == "status":
        expected = "passed" if current_marker.name.endswith("completed.env") else "failed"
        return expected.startswith(value) if partial else value == expected
    if key in {"completed_utc", "failed_utc"}:
        return re.fullmatch(r"[0-9TZ:-]*", value) is not None if partial else timestamp_pattern.fullmatch(value) is not None
    if key in {"completed_epoch_seconds", "deadline_epoch_seconds", "last_sample_epoch_seconds", "failed_epoch_seconds", "exit_status"}:
        return re.fullmatch(r"[0-9]*", value) is not None if partial else value.isdigit()
    return False

def exactly_torn(path, keys):
    raw = path.read_bytes()
    if not raw or raw.endswith(b"\n"):
        return False
    try:
        lines = raw.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        return False
    if len(lines) > len(keys):
        return False
    for index, line in enumerate(lines):
        prefix = f"{keys[index]}="
        is_last = index == len(lines) - 1
        if is_last and prefix.startswith(line):
            continue
        if not line.startswith(prefix) or not value_is_valid(keys[index], line[len(prefix):], partial=is_last):
            return False
    return True

for attempt in sorted(root.iterdir()):
    if not attempt.is_dir() or attempt.is_symlink() or attempt.resolve() != attempt:
        raise SystemExit(f"unsafe retained resource sampler attempt: {attempt}")
    for stale in attempt.glob(".*.borondns-staged.*"):
        info = stale.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise SystemExit(f"unsafe stale resource sampler marker: {stale}")
        stale.unlink()
    completed = attempt / "resource-sampler-completed.env"
    failed = attempt / "resource-sampler-failed.env"
    completed_keys = ["status", "completed_utc", "completed_epoch_seconds", "deadline_epoch_seconds", "last_sample_epoch_seconds"]
    failed_keys = ["status", "failed_utc", "failed_epoch_seconds", "exit_status"]
    if completed.exists() and failed.exists():
        continue
    current_marker = completed if completed.exists() else failed
    current_keys = completed_keys if completed.exists() else failed_keys
    if current_marker.exists() and parse_env(current_marker, current_keys) is None:
        if not exactly_torn(current_marker, current_keys):
            raise SystemExit(f"invalid retained resource sampler marker: {current_marker}")
        if current_marker == completed:
            metadata = parse_env(
                attempt / "resource-sampler.env",
                ["started_utc", "started_epoch_seconds", "deadline_epoch_seconds", "sample_interval_seconds"],
            )
            samples = attempt / "resource-samples.tsv"
            if metadata is None or not samples.is_file() or samples.is_symlink():
                raise SystemExit(f"cannot reconstruct torn resource sampler completion: {attempt}")
            with samples.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle, delimiter="\t"))
            if len(rows) < 2 or len(rows[-1]) != 9 or not rows[-1][1].isdigit():
                raise SystemExit(f"cannot reconstruct torn resource sampler completion: {attempt}")
            deadline = metadata["deadline_epoch_seconds"]
            last_sample = rows[-1][1]
            if not deadline.isdigit() or int(last_sample) < int(deadline):
                raise SystemExit(f"torn resource sampler completion lacks deadline coverage: {attempt}")
            now_epoch = int(time.time())
            now = datetime.fromtimestamp(now_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            atomic_write(completed, f"status=passed\ncompleted_utc={now}\ncompleted_epoch_seconds={now_epoch}\ndeadline_epoch_seconds={deadline}\nlast_sample_epoch_seconds={last_sample}\n")
        else:
            now_epoch = int(time.time())
            now = datetime.fromtimestamp(now_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            atomic_write(failed, f"status=failed\nfailed_utc={now}\nfailed_epoch_seconds={now_epoch}\nexit_status=255\n")
    elif not current_marker.exists():
        now_epoch = int(time.time())
        now = datetime.fromtimestamp(now_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        atomic_write(failed, f"status=failed\nfailed_utc={now}\nfailed_epoch_seconds={now_epoch}\nexit_status=255\n")
PY
}

require_resource_sampler_alive() {
    [[ -n "$sampler_pid" ]] || return 1
    if ! kill -0 "$sampler_pid" 2>/dev/null; then
        wait "$sampler_pid" || true
        sampler_pid=""
        printf 'resource sampler terminated before campaign completion: %s\n' "$sampler_attempt_dir" >&2
        return 1
    fi
}

validate_resource_sampler_evidence() {
    python3 - "$evidence_dir" "$campaign_start_epoch" "$campaign_deadline_epoch" "$sample_interval" <<'PY'
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
campaign_start, deadline, interval = map(int, sys.argv[2:])
attempt_root = root / "resource-sampler-attempts"
attempts = sorted(attempt_root.iterdir()) if attempt_root.is_dir() else []
if not attempts:
    raise SystemExit("resource sampler has no attempts")
previous_last = None
previous_terminal = None
completed = 0
timestamp = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

def env(path, keys):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise SystemExit(f"invalid resource sampler metadata: {path}")
        values[key] = value
    if set(values) != set(keys):
        raise SystemExit(f"resource sampler metadata schema mismatch: {path}")
    return values

def timestamp_epoch(value, label):
    if not timestamp.fullmatch(value):
        raise SystemExit(f"invalid timestamp for {label}: {value}")
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())

def require_timestamp_epoch(value, epoch, label):
    if abs(timestamp_epoch(value, label) - epoch) > 1:
        raise SystemExit(f"{label} timestamp and epoch differ")

for number, attempt in enumerate(attempts, 1):
    if attempt.name != f"attempt-{number:04d}" or not attempt.is_dir() or attempt.is_symlink():
        raise SystemExit(f"unsafe resource sampler attempt: {attempt}")
    metadata = env(attempt / "resource-sampler.env", {
        "started_utc", "started_epoch_seconds", "deadline_epoch_seconds", "sample_interval_seconds",
    })
    if not timestamp.fullmatch(metadata["started_utc"]):
        raise SystemExit(f"invalid resource sampler start time: {attempt}")
    started = int(metadata["started_epoch_seconds"])
    require_timestamp_epoch(metadata["started_utc"], started, f"resource sampler start at {attempt}")
    if metadata["deadline_epoch_seconds"] != str(deadline) or metadata["sample_interval_seconds"] != str(interval):
        raise SystemExit(f"resource sampler policy differs from campaign: {attempt}")
    samples = attempt / "resource-samples.tsv"
    processes = attempt / "process-samples.tsv"
    if not samples.is_file() or samples.is_symlink() or not processes.is_file() or processes.is_symlink():
        raise SystemExit(f"resource sampler attempt lacks sample files: {attempt}")
    with samples.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle, delimiter="\t"))
    expected = ["timestamp_utc", "epoch_seconds", "load1", "load5", "load15", "mem_available_kib", "docker_containers", "borondns_processes", "total_borondns_rss_kib"]
    if not rows or rows[0] != expected or len(rows) < 2:
        raise SystemExit(f"resource sampler rows are absent or malformed: {samples}")
    sample_rows = rows[1:]
    epochs = []
    for row in sample_rows:
        if len(row) != 9 or not timestamp.fullmatch(row[0]):
            raise SystemExit(f"invalid resource sample row: {samples}")
        if not all(re.fullmatch(r"[0-9]+", row[i]) for i in (1, 5, 6, 7, 8)) or not all(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", row[i]) for i in (2, 3, 4)):
            raise SystemExit(f"invalid resource sample value: {samples}")
        epoch = int(row[1])
        require_timestamp_epoch(row[0], epoch, f"resource sample at {samples}")
        epochs.append(epoch)
    if epochs != sorted(set(epochs)) or epochs[0] < started or epochs[0] > started + 2:
        raise SystemExit(f"resource sampler start coverage is invalid: {samples}")
    if any(right - left > interval + 2 for left, right in zip(epochs, epochs[1:])):
        raise SystemExit(f"resource sampler cadence gap exceeds policy: {samples}")
    if previous_last is None:
        if started < campaign_start or started > campaign_start + 2:
            raise SystemExit("resource sampler did not start with the campaign")
    else:
        if previous_terminal is None or started < previous_terminal:
            raise SystemExit("resource sampler attempt chronology reverses")
        if started - previous_last > interval + 2:
            raise SystemExit("resource sampler attempts contain an unobserved cadence gap")
    with processes.open(newline="", encoding="utf-8") as handle:
        process_rows = list(csv.reader(handle, delimiter="\t"))
    expected_process = ["timestamp_utc", "epoch_seconds", "pid", "pcpu", "pmem", "rss_kib", "etime", "comm"]
    if not process_rows or process_rows[0] != expected_process:
        raise SystemExit(f"invalid resource process sample header: {processes}")
    host_positions = {(row[0], row[1]): index for index, row in enumerate(sample_rows)}
    if len(host_positions) != len(sample_rows):
        raise SystemExit(f"duplicate resource sampler host key: {samples}")
    details = {key: [] for key in host_positions}
    process_positions = []
    seen_pids = set()
    for row in process_rows[1:]:
        if len(row) != 8 or not timestamp.fullmatch(row[0]) or not re.fullmatch(r"[0-9]+", row[1]) or not re.fullmatch(r"[1-9][0-9]*", row[2]) or not all(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", row[i]) for i in (3, 4)) or not re.fullmatch(r"[0-9]+", row[5]) or not re.fullmatch(r"[0-9:-]+", row[6]) or not re.fullmatch(r"[!-~]{1,15}", row[7]):
            raise SystemExit(f"invalid resource process sample row: {processes}")
        process_epoch = int(row[1])
        require_timestamp_epoch(row[0], process_epoch, f"resource process sample at {processes}")
        key = (row[0], row[1])
        if key not in host_positions:
            raise SystemExit(f"orphan resource process sample row: {processes}")
        pid_key = (key, row[2])
        if pid_key in seen_pids:
            raise SystemExit(f"duplicate resource process PID: {processes}")
        seen_pids.add(pid_key)
        details[key].append(row)
        process_positions.append(host_positions[key])
    if process_positions != sorted(process_positions):
        raise SystemExit(f"resource process sample chronology is invalid: {processes}")
    for row in sample_rows:
        key = (row[0], row[1])
        process_count = len(details[key])
        total_rss = sum(int(detail[5]) for detail in details[key])
        if row[7] != str(process_count) or row[8] != str(total_rss):
            raise SystemExit(f"resource process aggregates differ from host sample: {samples}")
    success = attempt / "resource-sampler-completed.env"
    failure = attempt / "resource-sampler-failed.env"
    if success.exists() == failure.exists():
        raise SystemExit(f"resource sampler attempt has ambiguous terminal state: {attempt}")
    if success.exists():
        values = env(success, {"status", "completed_utc", "completed_epoch_seconds", "deadline_epoch_seconds", "last_sample_epoch_seconds"})
        if not values["completed_epoch_seconds"].isdigit():
            raise SystemExit(f"invalid resource sampler completion epoch: {attempt}")
        completed_epoch = int(values["completed_epoch_seconds"])
        require_timestamp_epoch(values["completed_utc"], completed_epoch, f"resource sampler completion at {attempt}")
        if number != len(attempts) or values["status"] != "passed" or values["deadline_epoch_seconds"] != str(deadline) or int(values["last_sample_epoch_seconds"]) != epochs[-1] or epochs[-1] < deadline or completed_epoch < epochs[-1]:
            raise SystemExit(f"resource sampler completion does not cover deadline: {attempt}")
        completed += 1
        terminal_epoch = completed_epoch
    else:
        values = env(failure, {"status", "failed_utc", "failed_epoch_seconds", "exit_status"})
        if values["status"] != "failed" or not values["exit_status"].isdigit() or int(values["exit_status"]) == 0:
            raise SystemExit(f"invalid resource sampler failure marker: {attempt}")
        if not values["failed_epoch_seconds"].isdigit():
            raise SystemExit(f"invalid resource sampler failure epoch: {attempt}")
        failed_epoch = int(values["failed_epoch_seconds"])
        require_timestamp_epoch(values["failed_utc"], failed_epoch, f"resource sampler failure at {attempt}")
        if failed_epoch < epochs[-1]:
            raise SystemExit(f"resource sampler failure predates its final sample: {attempt}")
        terminal_epoch = failed_epoch
    previous_last = epochs[-1]
    previous_terminal = terminal_epoch
if completed != 1:
    raise SystemExit("resource sampler lacks exactly one final successful attempt")
PY
}

write_summary() {
    local summary="$evidence_dir/soak-summary.env"
    local staged
    validate_scenario_results "$scenario_list_for_validation" || return 1
    staged="$(mktemp "$evidence_dir/.soak-summary.XXXXXX")" || return 1
    if ! python3 - "$evidence_dir/scenario-results.tsv" >"$staged" <<'PY'; then
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
        rm -f "$staged"
        return 1
    fi
    mv "$staged" "$summary"
}

next_scenario_work() {
    local scenario_list="$1"
    python3 - "$evidence_dir/scenario-results.tsv" "$scenario_list" <<'PY'
import csv
import sys

path, scenario_text = sys.argv[1:]
scenarios = scenario_text.split()
cycle = 1
index = 0
attempt = 1
with open(path, newline="", encoding="utf-8") as handle:
    for row in csv.DictReader(handle, delimiter="\t"):
        row_cycle = int(row["cycle"])
        row_attempt = int(row["attempt"])
        if row_cycle != cycle or row["scenario"] != scenarios[index] or row_attempt != attempt:
            raise SystemExit("scenario attempt ledger is not resumable in canonical order")
        attempt += 1
        if row["status"] in {"passed", "skipped"}:
            index += 1
            attempt = 1
            if index == len(scenarios):
                cycle += 1
                index = 0
print(cycle, index, attempt)
PY
}

validate_scenario_results() {
    local scenario_list="$1"
    local allow_one_unledgered="${2:-0}"
    local results="$evidence_dir/scenario-results.tsv"
    local maximum_attempt_elapsed_seconds=$((\
        scenario_timeout + scenario_kill_after + \
        docker_cleanup_operation_count * (docker_cleanup_timeout + docker_cleanup_kill_after_seconds) + \
        scenario_timestamp_tolerance_seconds))
    [[ -f "$results" && ! -L "$results" ]] || {
        printf 'scenario results must be a regular non-symlink file: %s\n' "$results" >&2
        return 1
    }
    campaign_require_contained_file "$evidence_dir" "$results" "scenario results" || return 1
    python3 - "$results" "$evidence_dir" "$scenario_list" "$allow_one_unledgered" \
        "$maximum_attempt_elapsed_seconds" <<'PY'
import csv
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import sys

path, evidence, scenario_text, allow_one_unledgered_text, maximum_attempt_elapsed_text = sys.argv[1:]
allow_one_unledgered = allow_one_unledgered_text == "1"
maximum_attempt_elapsed = int(maximum_attempt_elapsed_text)
expected_header = [
    "cycle", "scenario", "attempt", "status", "exit_status", "started_utc", "ended_utc",
    "scenario_artifact_dir", "log_path",
]
scenario_order = scenario_text.split()
allowed = set(scenario_order)
if not scenario_order or len(allowed) != len(scenario_order):
    raise SystemExit("selected scenario order is empty or contains duplicates")
timestamp = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
expected_cycle = 1
expected_index = 0
expected_attempt = 1
ledger_attempts = set()
previous_ended_epoch = None

def timestamp_epoch(value, label):
    if not timestamp.fullmatch(value):
        raise SystemExit(f"invalid timestamp for {label}: {value}")
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())

with open(path, newline="", encoding="utf-8") as handle:
    reader = csv.reader(handle, delimiter="\t")
    try:
        header = next(reader)
    except StopIteration:
        raise SystemExit("scenario results are empty")
    if header != expected_header:
        raise SystemExit("scenario results header does not match the canonical schema")
    for line_number, row in enumerate(reader, 2):
        if len(row) != 9:
            raise SystemExit(f"scenario results row {line_number} has {len(row)} columns, expected 9")
        cycle_text, scenario, attempt_text, status, exit_text, started, ended, artifact, log = row
        if not cycle_text.isdigit() or int(cycle_text) <= 0:
            raise SystemExit(f"scenario results row {line_number} has invalid cycle")
        cycle = int(cycle_text)
        if cycle != expected_cycle:
            raise SystemExit(f"scenario results row {line_number} has noncanonical cycle")
        if scenario != scenario_order[expected_index]:
            raise SystemExit(
                f"scenario results row {line_number} is out of canonical scenario order"
            )
        if not attempt_text.isdigit() or int(attempt_text) != expected_attempt:
            raise SystemExit(f"scenario results row {line_number} has noncanonical attempt number")
        if status not in {"passed", "skipped", "failed", "interrupted"}:
            raise SystemExit(f"scenario results row {line_number} has invalid status")
        if not exit_text.isdigit() or int(exit_text) > 255:
            raise SystemExit(f"scenario results row {line_number} has invalid exit status")
        if status in {"passed", "skipped"} and exit_text != "0":
            raise SystemExit(f"scenario results row {line_number} claims success with nonzero exit")
        if status in {"failed", "interrupted"} and exit_text == "0":
            raise SystemExit(f"scenario results row {line_number} claims failure with zero exit")
        started_epoch = timestamp_epoch(started, f"scenario results row {line_number} start")
        ended_epoch = timestamp_epoch(ended, f"scenario results row {line_number} end")
        if ended_epoch < started_epoch:
            raise SystemExit(f"scenario results row {line_number} ends before it starts")
        if ended_epoch - started_epoch > maximum_attempt_elapsed:
            raise SystemExit(
                f"scenario results row {line_number} exceeds the authenticated per-attempt runtime bound"
            )
        if previous_ended_epoch is not None and started_epoch < previous_ended_epoch:
            raise SystemExit(f"scenario results row {line_number} reverses attempt chronology")
        previous_ended_epoch = ended_epoch
        expected_dir = os.path.join(
            "scenarios", f"cycle-{cycle:04d}", scenario, "attempts", f"attempt-{int(attempt_text):04d}"
        )
        expected_log = os.path.join(expected_dir, "scenario.log")
        if artifact != expected_dir or log != expected_log:
            raise SystemExit(f"scenario results row {line_number} has noncanonical evidence paths")
        for relative, kind in ((artifact, "directory"), (log, "file")):
            candidate = os.path.join(evidence, relative)
            if os.path.isabs(relative) or os.path.normpath(relative) != relative:
                raise SystemExit(f"scenario results row {line_number} has a noncanonical relative path")
            if os.path.realpath(candidate) != candidate:
                raise SystemExit(f"scenario results row {line_number} traverses a symlink")
            if kind == "directory" and not os.path.isdir(candidate):
                raise SystemExit(f"scenario results row {line_number} artifact directory is missing")
            if kind == "file" and not os.path.isfile(candidate):
                raise SystemExit(f"scenario results row {line_number} log file is missing")
        ledger_attempts.add(expected_dir)
        expected_attempt += 1
        if status in {"passed", "skipped"}:
            expected_index += 1
            expected_attempt = 1
            if expected_index == len(scenario_order):
                expected_cycle += 1
                expected_index = 0
root = Path(evidence)
actual_attempts = set()
scenarios_root = root / "scenarios"
if scenarios_root.exists():
    for attempts_dir in scenarios_root.rglob("attempts"):
        if not attempts_dir.is_dir() or attempts_dir.is_symlink():
            raise SystemExit(f"unsafe scenario attempt root: {attempts_dir}")
        for attempt_dir in attempts_dir.iterdir():
            if (
                attempt_dir.is_dir()
                and not attempt_dir.is_symlink()
                and re.fullmatch(
                    r"\.attempt-[0-9]{4}\.borondns-remove\.[0-9]+\.[0-9a-f]{24}",
                    attempt_dir.name,
                )
            ):
                # Fail-closed deadline cleanup retains the exact attempt inode
                # under a quarantine name. It is manifest evidence, not a
                # resumable or ledgered scenario attempt.
                continue
            if not attempt_dir.is_dir() or attempt_dir.is_symlink() or not re.fullmatch(r"attempt-[0-9]{4}", attempt_dir.name):
                raise SystemExit(f"unexpected scenario attempt entity: {attempt_dir}")
            actual_attempts.add(attempt_dir.relative_to(root).as_posix())
missing = ledger_attempts - actual_attempts
unledgered = actual_attempts - ledger_attempts
if missing or (unledgered and not (allow_one_unledgered and len(unledgered) == 1)):
    raise SystemExit(
        f"scenario attempt directory and result ledger mismatch unledgered={sorted(unledgered)} missing={sorted(missing)}"
    )
PY
}

complete_scenario_cycle_count() {
    local scenario_list="$1"
    python3 - "$evidence_dir/scenario-results.tsv" "$scenario_list" <<'PY'
import csv
import sys

path, scenario_text = sys.argv[1:]
scenario_order = scenario_text.split()
if not scenario_order:
    raise SystemExit("selected scenario order is empty")
completed = 0
expected_index = 0
with open(path, newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    for row in reader:
        if row["scenario"] != scenario_order[expected_index]:
            raise SystemExit("scenario order changed while counting complete cycles")
        if row["status"] in {"passed", "skipped"}:
            expected_index = (expected_index + 1) % len(scenario_order)
            if expected_index == 0:
                completed += 1
print(completed)
PY
}

terminal_scenario_activity_max_gap_seconds() {
    # A scenario may consume its full timeout before the deadline-limited
    # attempt is discarded, and the preceding cycle may have slept once.  The
    # kill grace and timestamp resolution allowance keep this bound valid at
    # the exact second boundary without allowing an unbounded idle campaign.
    printf '%s\n' "$((scenario_timeout + scenario_kill_after + cycle_sleep + 2))"
}

validate_terminal_scenario_activity() {
    local maximum_gap
    maximum_gap="$(terminal_scenario_activity_max_gap_seconds)" || return 1
    python3 - "$evidence_dir/scenario-results.tsv" "$campaign_deadline_epoch" "$maximum_gap" <<'PY'
import csv
from datetime import datetime, timezone
import sys

path, deadline_text, maximum_gap_text = sys.argv[1:]
with open(path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
if not rows:
    raise SystemExit("terminal scenario activity requires at least one result row")
last_ended = int(
    datetime.strptime(rows[-1]["ended_utc"], "%Y-%m-%dT%H:%M:%SZ")
    .replace(tzinfo=timezone.utc)
    .timestamp()
)
deadline = int(deadline_text)
maximum_gap = int(maximum_gap_text)
if last_ended < deadline - maximum_gap:
    raise SystemExit(
        "terminal scenario activity gap exceeds authenticated policy: "
        f"last_ended={last_ended} deadline={deadline} maximum_gap={maximum_gap}"
    )
PY
}

reconcile_interrupted_attempts() {
    local scenario_list="$1"
    campaign_assert_private_lock || return 1
    python3 - "$evidence_dir" "$scenario_list" <<'PY'
import csv
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sys
import tempfile

root = Path(sys.argv[1])
scenarios = sys.argv[2].split()
results = root / "scenario-results.tsv"

def atomic_write(path, content):
    fd, staged_name = tempfile.mkstemp(prefix=f".{path.name}.staged.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(staged_name):
            os.unlink(staged_name)

def interrupted_marker_is_torn(raw):
    if not raw or raw.endswith(b"\n"):
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    prefix = "status=interrupted\nrecorded_utc="
    if prefix.startswith(text):
        return True
    if not text.startswith(prefix):
        return False
    timestamp_prefix = text[len(prefix):]
    return len(timestamp_prefix) <= 20 and re.fullmatch(r"[0-9TZ:-]*", timestamp_prefix) is not None
with results.open(newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
referenced = {row["scenario_artifact_dir"] for row in rows}
unrecorded = []
for started_file in sorted((root / "scenarios").glob("cycle-*/**/attempts/attempt-*/attempt-started.env")):
    attempt_dir = started_file.parent
    relative = attempt_dir.relative_to(root).as_posix()
    if relative in referenced:
        continue
    if attempt_dir.is_symlink() or attempt_dir.resolve() != attempt_dir:
        raise SystemExit(f"unsafe interrupted scenario attempt: {attempt_dir}")
    values = {}
    for line in started_file.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise SystemExit(f"invalid interrupted attempt metadata: {started_file}")
        values[key] = value
    if set(values) != {"cycle", "scenario", "attempt", "started_utc"}:
        raise SystemExit(f"interrupted attempt metadata schema mismatch: {started_file}")
    cycle = int(values["cycle"])
    attempt = int(values["attempt"])
    expected = root / "scenarios" / f"cycle-{cycle:04d}" / values["scenario"] / "attempts" / f"attempt-{attempt:04d}"
    if expected != attempt_dir or values["scenario"] not in scenarios:
        raise SystemExit(f"interrupted attempt path does not match metadata: {attempt_dir}")
    unrecorded.append((cycle, values["scenario"], attempt, values["started_utc"], attempt_dir, relative))
if len(unrecorded) > 1:
    raise SystemExit("multiple unrecorded scenario attempts require operator inspection")
if unrecorded:
    cycle, scenario, attempt, started, attempt_dir, relative = unrecorded[0]
    log = attempt_dir / "scenario.log"
    if log.exists() and (log.is_symlink() or not log.is_file()):
        raise SystemExit(f"unsafe interrupted scenario log: {log}")
    log.touch(exist_ok=True)
    marker = attempt_dir / "attempt-interrupted.env"
    if marker.is_symlink():
        raise SystemExit(f"unsafe interrupted marker: {marker}")
    if marker.exists():
        raw_marker = marker.read_bytes()
        try:
            marker_values = dict(
                line.split("=", 1) for line in raw_marker.decode("utf-8").splitlines()
            )
        except (UnicodeDecodeError, ValueError):
            marker_values = {}
        if set(marker_values) == {"status", "recorded_utc"} and marker_values["status"] == "interrupted" and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", marker_values["recorded_utc"]):
            ended = marker_values["recorded_utc"]
        elif interrupted_marker_is_torn(raw_marker):
            ended = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            atomic_write(marker, f"status=interrupted\nrecorded_utc={ended}\n")
        else:
            raise SystemExit(f"invalid interrupted marker: {marker}")
    else:
        ended = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        atomic_write(marker, f"status=interrupted\nrecorded_utc={ended}\n")
    with results.open(newline="", encoding="utf-8") as handle:
        retained = handle.read()
    fd, staged_name = tempfile.mkstemp(prefix=".scenario-results.", dir=root)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            handle.write(retained)
            csv.writer(handle, delimiter="\t", lineterminator="\n").writerow(
                [cycle, scenario, attempt, "interrupted", 255, started, ended, relative, f"{relative}/scenario.log"]
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged_name, results)
    finally:
        if os.path.exists(staged_name):
            os.unlink(staged_name)
PY
}

repair_torn_scenario_results_tail() {
    local scenario_list="$1"
    campaign_assert_private_lock || return 1
    python3 - "$evidence_dir" "$scenario_list" <<'PY'
import csv
import os
from pathlib import Path
import re
import sys
import tempfile

root = Path(sys.argv[1])
allowed = set(sys.argv[2].split())
results = root / "scenario-results.tsv"
raw = results.read_bytes()
if not raw or raw.endswith(b"\n"):
    raise SystemExit(0)
head, separator, tail = raw.rpartition(b"\n")
if not separator:
    raise SystemExit("scenario results header is torn")
try:
    partial = tail.decode("utf-8")
except UnicodeDecodeError:
    raise SystemExit("scenario results has a non-UTF-8 torn tail")
fields = partial.split("\t")
if len(fields) < 3 or len(fields) >= 9:
    raise SystemExit("scenario results has an unrecognized non-newline tail")
cycle_text, scenario, attempt_text = fields[:3]
if not cycle_text.isdigit() or not attempt_text.isdigit() or scenario not in allowed:
    raise SystemExit("scenario results torn tail lacks canonical attempt identity")
cycle = int(cycle_text)
attempt = int(attempt_text)
attempt_dir = root / "scenarios" / f"cycle-{cycle:04d}" / scenario / "attempts" / f"attempt-{attempt:04d}"
started_file = attempt_dir / "attempt-started.env"
if attempt_dir.is_symlink() or not started_file.is_file() or started_file.is_symlink():
    raise SystemExit("scenario results torn tail has no safe matching attempt metadata")
values = {}
for line in started_file.read_text(encoding="utf-8").splitlines():
    key, separator, value = line.partition("=")
    if not separator or key in values:
        raise SystemExit("invalid attempt metadata for scenario results torn tail")
    values[key] = value
if values != {"cycle": cycle_text, "scenario": scenario, "attempt": attempt_text, "started_utc": values.get("started_utc", "")}:
    raise SystemExit("scenario results torn tail does not match attempt metadata")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", values["started_utc"]):
    raise SystemExit("scenario results torn tail has invalid attempt timestamp")
try:
    retained_rows = list(csv.DictReader(head.decode("utf-8").splitlines(), delimiter="\t"))
except UnicodeDecodeError:
    raise SystemExit("scenario results retained prefix is not UTF-8")
referenced = {row.get("scenario_artifact_dir") for row in retained_rows}
unrecorded = []
for candidate in (root / "scenarios").glob("cycle-*/**/attempts/attempt-*/attempt-started.env"):
    relative = candidate.parent.relative_to(root).as_posix()
    if relative not in referenced:
        unrecorded.append(candidate.parent)
if unrecorded != [attempt_dir]:
    raise SystemExit("scenario results torn tail is not the sole unrecorded attempt")
if len(fields) >= 4 and not any(status.startswith(fields[3]) for status in ("passed", "skipped", "failed", "interrupted")):
    raise SystemExit("scenario results torn tail has invalid status prefix")
if len(fields) >= 5 and fields[4] and not fields[4].isdigit():
    raise SystemExit("scenario results torn tail has invalid exit-status prefix")
if len(fields) >= 6 and fields[5] and not values["started_utc"].startswith(fields[5]):
    raise SystemExit("scenario results torn tail has invalid start timestamp prefix")
fd, staged_name = tempfile.mkstemp(prefix=".scenario-results-repair.", dir=root)
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(head + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(staged_name, results)
finally:
    if os.path.exists(staged_name):
        os.unlink(staged_name)
PY
}

append_scenario_result() {
    campaign_assert_private_lock || return 1
    local results="$evidence_dir/scenario-results.tsv"
    local staged
    [[ -f "$results" && ! -L "$results" ]] || return 1
    staged="$(mktemp "$evidence_dir/.scenario-results.XXXXXX")" || return 1
    if ! cp -- "$results" "$staged" || ! printf '%s\n' "$1" >>"$staged"; then
        rm -f "$staged"
        return 1
    fi
    sync -f "$staged" 2>/dev/null || true
    campaign_assert_private_lock || {
        rm -f "$staged"
        return 1
    }
    mv -f -- "$staged" "$results"
}

prepare_scenario_results() {
    local scenario_list="$1"
    local results="$evidence_dir/scenario-results.tsv"
    local expected_header=$'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path'
    if ((resume)); then
        [[ -f "$results" ]] || die "--resume requires existing scenario results: $results"
        local actual_header
        IFS= read -r actual_header <"$results" || true
        [[ "$actual_header" == "$expected_header" ]] || die "--resume found an invalid scenario results header: $results"
        repair_torn_scenario_results_tail "$scenario_list" || die "--resume could not safely repair retained scenario results: $results"
        validate_scenario_results "$scenario_list" 1 || die "--resume found invalid retained scenario evidence: $results"
        reconcile_interrupted_attempts "$scenario_list"
        validate_scenario_results "$scenario_list" || die "--resume reconciliation did not produce an exact scenario attempt ledger: $results"
        validate_scenario_results "$scenario_list" || die "--resume interruption reconciliation produced invalid retained evidence: $results"
        return 0
    fi
    local staged
    staged="$(mktemp "$evidence_dir/.scenario-results.XXXXXX")" || return 1
    printf '%s\n' "$expected_header" >"$staged"
    sync -f "$staged" 2>/dev/null || true
    campaign_assert_private_lock || {
        rm -f "$staged"
        return 1
    }
    mv -- "$staged" "$results"
}

acquire_evidence_lock() {
    local evidence_parent
    evidence_parent="$(dirname "$evidence_dir")"
    mkdir -p "$evidence_parent"
    campaign_require_owned_real_directory "$evidence_parent" "soak evidence parent" || die "unsafe soak evidence parent"
    campaign_acquire_private_lock "$evidence_parent" "$(realpath -ms "$evidence_dir"):runner" "soak evidence lock" ||
        die "could not acquire the private soak evidence lock"
}

prepare_evidence_directory() {
    campaign_assert_private_lock || die "soak evidence lock broker exited"
    if ! ((resume)) && [[ -e "$evidence_dir" ]]; then
        campaign_require_owned_real_directory "$evidence_dir" "soak evidence directory" || die "unsafe soak evidence directory"
        if [[ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
            die "evidence directory is non-empty; use --resume or choose a new path: $evidence_dir"
        fi
    fi
    if [[ ! -e "$evidence_dir" ]]; then
        mkdir -m 0700 "$evidence_dir"
    fi
    campaign_require_owned_real_directory "$evidence_dir" "soak evidence directory" || die "unsafe soak evidence directory"
    [[ -z "$(find "$evidence_dir" -type l -print -quit)" ]] ||
        die "soak evidence tree contains a symlink: $evidence_dir"
    campaign_prepare_contained_directory "$evidence_dir" "$evidence_dir/scenarios" "soak scenarios directory" ||
        die "unsafe soak scenarios directory"
}

soak_metadata_value() {
    local path="$1"
    local key="$2"
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; found = 1; exit } END { if (!found) exit 1 }' "$path"
}

resume_identity_value() {
    local path="$1"
    local key="$2"
    awk -F= -v key="$key" '
        $1 == key { sub(/^[^=]*=/, ""); value = $0; count += 1 }
        END { if (count != 1) exit 1; print value }
    ' "$path"
}

bind_resume_provenance() {
    local original="$evidence_dir/soak.env"
    [[ -d "$evidence_dir" && ! -L "$evidence_dir" ]] ||
        die "--resume requires an existing real evidence directory: $evidence_dir"
    campaign_require_owned_real_directory "$evidence_dir" "soak evidence directory" ||
        die "unsafe soak evidence directory"
    [[ -z "$(find "$evidence_dir" -type l -print -quit)" ]] ||
        die "soak evidence tree contains a symlink: $evidence_dir"
    [[ -f "$original" && ! -L "$original" ]] ||
        die "--resume requires original campaign metadata: $original"

    local saved_commit saved_cargo_sha256 saved_rustc_sha256
    saved_commit="$(resume_identity_value "$original" expected_commit)" ||
        die "original campaign metadata has no unique expected_commit: $original"
    saved_cargo_sha256="$(resume_identity_value "$original" cargo_sha256)" ||
        die "original campaign metadata has no unique cargo_sha256: $original"
    saved_rustc_sha256="$(resume_identity_value "$original" rustc_sha256)" ||
        die "original campaign metadata has no unique rustc_sha256: $original"
    [[ "$saved_commit" =~ ^[0-9a-f]{40,64}$ ]] ||
        die "original campaign metadata has an invalid expected_commit: $original"
    [[ "$saved_cargo_sha256" =~ ^[0-9a-f]{64}$ ]] ||
        die "original campaign metadata has an invalid cargo_sha256: $original"
    [[ "$saved_rustc_sha256" =~ ^[0-9a-f]{64}$ ]] ||
        die "original campaign metadata has an invalid rustc_sha256: $original"

    if [[ -n "$expected_commit" && "$expected_commit" != "$saved_commit" ]]; then
        die "--resume expected commit differs from original campaign metadata"
    fi
    if [[ -n "$expected_cargo_sha256" && "$expected_cargo_sha256" != "$saved_cargo_sha256" ]]; then
        die "--resume expected cargo SHA-256 differs from original campaign metadata"
    fi
    if [[ -n "$expected_rustc_sha256" && "$expected_rustc_sha256" != "$saved_rustc_sha256" ]]; then
        die "--resume expected rustc SHA-256 differs from original campaign metadata"
    fi
    expected_commit="$saved_commit"
    expected_cargo_sha256="$saved_cargo_sha256"
    expected_rustc_sha256="$saved_rustc_sha256"
    verify_expected_clean_head
    verify_expected_tool_hashes
}

validate_resume_parameters() {
    local scenario_list="$1"
    local original="$evidence_dir/soak.env"
    [[ -r "$original" ]] || die "--resume requires original campaign metadata: $original"
    local key current saved
    for key in duration_seconds scenario_timeout_seconds cycle_sleep_seconds sample_interval_seconds allow_skip; do
        case "$key" in
        duration_seconds) current="$duration" ;;
        scenario_timeout_seconds) current="$scenario_timeout" ;;
        cycle_sleep_seconds) current="$cycle_sleep" ;;
        sample_interval_seconds) current="$sample_interval" ;;
        allow_skip) current="$allow_skip" ;;
        esac
        saved="$(soak_metadata_value "$original" "$key")" || die "original campaign metadata is missing $key: $original"
        [[ "$saved" == "$current" ]] || die "--resume cannot change $key (saved=$saved requested=$current)"
    done
    saved="$(soak_metadata_value "$original" scenarios)" || die "original campaign metadata is missing scenarios: $original"
    [[ "$saved" == "$scenario_list" ]] || die "--resume cannot change scenarios (saved=$saved requested=$scenario_list)"
    if saved="$(soak_metadata_value "$original" scenario_kill_after_seconds 2>/dev/null)"; then
        [[ "$saved" == "$scenario_kill_after" ]] || die "--resume cannot change scenario_kill_after_seconds (saved=$saved requested=$scenario_kill_after)"
    fi
    if saved="$(soak_metadata_value "$original" docker_cleanup_timeout_seconds 2>/dev/null)"; then
        [[ "$saved" == "$docker_cleanup_timeout" ]] || die "--resume cannot change docker_cleanup_timeout_seconds (saved=$saved requested=$docker_cleanup_timeout)"
    fi
}

prepare_campaign_deadline() {
    local original="$evidence_dir/soak.env"
    local completed="$evidence_dir/campaign-completed.env"
    local now created_utc
    now="$(date +%s)"
    if ! ((resume)); then
        campaign_start_epoch="$now"
        campaign_deadline_epoch="$(checked_campaign_deadline "$campaign_start_epoch" "$duration")" ||
            die "campaign duration exceeds nanosecond-safe deadline arithmetic"
        return 0
    fi

    [[ ! -e "$completed" ]] || die "--resume refused a completed campaign: $completed"
    if campaign_start_epoch="$(soak_metadata_value "$original" start_epoch_seconds 2>/dev/null)" &&
        campaign_deadline_epoch="$(soak_metadata_value "$original" deadline_epoch_seconds 2>/dev/null)"; then
        :
    else
        created_utc="$(soak_metadata_value "$original" created_utc)" || die "original campaign metadata is missing created_utc: $original"
        campaign_start_epoch="$(date -u -d "$created_utc" +%s 2>/dev/null)" ||
            die "cannot derive the legacy campaign start time from $created_utc"
        campaign_deadline_epoch="$(checked_campaign_deadline "$campaign_start_epoch" "$duration")" ||
            die "legacy campaign duration exceeds nanosecond-safe deadline arithmetic"
    fi
    [[ "$campaign_start_epoch" =~ ^[0-9]+$ ]] || die "invalid saved campaign start epoch: $campaign_start_epoch"
    [[ "$campaign_deadline_epoch" =~ ^[0-9]+$ ]] || die "invalid saved campaign deadline epoch: $campaign_deadline_epoch"
    local expected_deadline
    expected_deadline="$(checked_campaign_deadline "$campaign_start_epoch" "$duration")" ||
        die "saved campaign duration exceeds nanosecond-safe deadline arithmetic"
    [[ "$campaign_deadline_epoch" == "$expected_deadline" ]] ||
        die "saved campaign deadline does not match its start plus duration"
}

enforce_campaign_deadline() {
    local now
    now="$(date +%s)"
    ((now < campaign_deadline_epoch)) ||
        die "--resume refused an expired campaign deadline after retained cleanup reconciliation: $campaign_deadline_epoch"
}

mark_campaign_completed() {
    local completed="$evidence_dir/campaign-completed.env"
    local staged completed_utc completed_epoch summary_digest manifest_digest
    staged="$(mktemp "$evidence_dir/.campaign-completed.XXXXXX")" || return 1
    completed_epoch="$(date +%s)" || {
        rm -f "$staged"
        return 1
    }
    completed_utc="$(date -u -d "@$completed_epoch" '+%Y-%m-%dT%H:%M:%SZ')" || {
        rm -f "$staged"
        return 1
    }
    summary_digest="$(campaign_sha256 "$evidence_dir/soak-summary.env")" || {
        rm -f "$staged"
        return 1
    }
    manifest_digest="$(campaign_sha256 "$evidence_dir/artifact-manifest.sha256")" || {
        rm -f "$staged"
        return 1
    }
    if ! {
        if ((cross_boot_diagnostic_active)); then
            printf 'status=non-release-diagnostic\n'
        else
            printf 'status=passed\n'
        fi
        printf 'evidence_schema=2\n'
        printf 'completed_utc=%s\n' "$completed_utc"
        printf 'completed_epoch_seconds=%s\n' "$completed_epoch"
        printf 'deadline_epoch_seconds=%s\n' "$campaign_deadline_epoch"
        printf 'summary_sha256=%s\n' "$summary_digest"
        printf 'artifact_manifest_sha256=%s\n' "$manifest_digest"
    } >"$staged"; then
        rm -f "$staged"
        return 1
    fi
    mv "$staged" "$completed" || {
        rm -f "$staged"
        return 1
    }
}

finalize_soak_evidence() {
    local status=$?
    local final_status="$status"
    trap - EXIT
    trap '' INT TERM HUP
    if declare -F large_soak_finalize_started_hook >/dev/null 2>&1; then
        large_soak_finalize_started_hook
    fi
    if [[ -n "${sampler_pid:-}" ]]; then
        terminate_resource_sampler_bounded
        if [[ -n "$sampler_attempt_dir" && ! -e "$sampler_attempt_dir/resource-sampler-completed.env" && ! -e "$sampler_attempt_dir/resource-sampler-failed.env" ]]; then
            local failure_content failure_epoch failure_utc
            failure_epoch="$(date +%s)"
            failure_utc="$(date -u -d "@$failure_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
            printf -v failure_content 'status=failed\nfailed_utc=%s\nfailed_epoch_seconds=%s\nexit_status=255' \
                "$failure_utc" "$failure_epoch"
            campaign_atomic_replace_text "$sampler_attempt_dir/resource-sampler-failed.env" "$failure_content" \
                "final resource sampler failure marker" || true
        fi
        sampler_pid=""
    fi
    write_summary || {
        printf 'failed to finalize soak summary: %s\n' "$evidence_dir" >&2
        ((final_status != 0)) || final_status=74
    }
    write_artifact_manifests || {
        printf 'failed to finalize soak artifact manifests: %s\n' "$evidence_dir" >&2
        ((final_status != 0)) || final_status=74
    }
    if ((final_status == 0)); then
        validate_resource_sampler_evidence || {
            printf 'resource sampler evidence does not cover the authenticated campaign: %s\n' "$evidence_dir" >&2
            final_status=1
        }
    fi
    if ((final_status == 0)); then
        local next_work pending_attempt
        next_work="$(next_scenario_work "$scenario_list_for_validation")" || final_status=74
        pending_attempt="${next_work##* }"
        if ((final_status == 0 && pending_attempt != 1)); then
            printf 'unresolved failed or interrupted scenario attempt prevents terminal completion: %s\n' \
                "$evidence_dir/scenario-results.tsv" >&2
            final_status=1
        fi
    fi
    if ((final_status == 0)); then
        local complete_cycles
        complete_cycles="$(complete_scenario_cycle_count "$scenario_list_for_validation")" || {
            printf 'failed to count complete soak cycles: %s\n' "$evidence_dir/scenario-results.tsv" >&2
            final_status=74
        }
        if ((final_status == 0 && complete_cycles == 0)); then
            printf 'terminal soak completion requires at least one complete canonical scenario cycle: %s\n' \
                "$evidence_dir/scenario-results.tsv" >&2
            final_status=1
        fi
    fi
    if ((final_status == 0)); then
        validate_terminal_scenario_activity || {
            printf 'terminal soak scenario activity does not cover the authenticated campaign window: %s\n' \
                "$evidence_dir/scenario-results.tsv" >&2
            final_status=1
        }
    fi
    if ((final_status == 0)); then
        verify_expected_clean_head || {
            printf 'terminal soak source provenance no longer matches the authenticated commit\n' >&2
            final_status=1
        }
    fi
    if ((final_status == 0)); then
        verify_expected_tool_hashes || {
            printf 'terminal soak tool provenance no longer matches the authenticated plan\n' >&2
            final_status=1
        }
    fi
    if ((final_status == 0)); then
        cleanup_automatic_build_directory || {
            printf 'failed to remove automatic large-soak CARGO_TARGET_DIR: %s\n' "$cargo_target_dir" >&2
            final_status=74
        }
    else
        cleanup_automatic_build_directory || {
            printf 'failed to remove automatic large-soak CARGO_TARGET_DIR: %s\n' "$cargo_target_dir" >&2
            ((final_status != 0)) || final_status=74
        }
    fi
    if ((final_status == 0)); then
        mark_campaign_completed || {
            printf 'failed to publish soak completion marker: %s\n' "$evidence_dir" >&2
            final_status=74
        }
    fi
    if ((final_status == 0 && cross_boot_diagnostic_active)); then
        printf 'cross-boot resume evidence is non-release diagnostic only: %s\n' "$evidence_dir" >&2
        final_status=2
    fi
    exit "$final_status"
}

scenario_timeout_within_campaign() {
    local requested_timeout="$1"
    local deadline_nanoseconds="$2"
    local now_nanoseconds="${3:-$(monotonic_nanoseconds)}"
    local guard_nanoseconds="${4:-50000000}"
    local kill_after_seconds="${5:-0}"
    local requested_nanoseconds=$((requested_timeout * 1000000000))
    local kill_after_nanoseconds=$((kill_after_seconds * 1000000000))
    local remaining_nanoseconds=$((deadline_nanoseconds - now_nanoseconds - guard_nanoseconds - kill_after_nanoseconds))
    ((remaining_nanoseconds > 0)) || return 1
    if ((requested_nanoseconds < remaining_nanoseconds)); then
        remaining_nanoseconds="$requested_nanoseconds"
    fi
    printf '%s.%09d\n' \
        "$((remaining_nanoseconds / 1000000000))" \
        "$((remaining_nanoseconds % 1000000000))"
}

cleanup_soak_docker_resources() {
    local real_docker="$1"
    local resource_label="$2"
    local cleanup_status=0
    local command_status=0
    local listing id
    local -a ids=()

    if listing="$(timeout --preserve-status --kill-after=5 "$docker_cleanup_timeout" \
        "$real_docker" ps -aq --filter "label=$resource_label")"; then
        while IFS= read -r id; do
            [[ -z "$id" ]] || ids+=("$id")
        done <<<"$listing"
        if ((${#ids[@]} > 0)); then
            timeout --preserve-status --kill-after=5 "$docker_cleanup_timeout" \
                "$real_docker" rm -f "${ids[@]}" >/dev/null || {
                command_status=$?
                ((cleanup_status != 0)) || cleanup_status="$command_status"
            }
        fi
    else
        command_status=$?
        ((cleanup_status != 0)) || cleanup_status="$command_status"
    fi

    ids=()
    if listing="$(timeout --preserve-status --kill-after=5 "$docker_cleanup_timeout" \
        "$real_docker" network ls -q --filter "label=$resource_label")"; then
        while IFS= read -r id; do
            [[ -z "$id" ]] || ids+=("$id")
        done <<<"$listing"
        if ((${#ids[@]} > 0)); then
            timeout --preserve-status --kill-after=5 "$docker_cleanup_timeout" \
                "$real_docker" network rm "${ids[@]}" >/dev/null || {
                command_status=$?
                ((cleanup_status != 0)) || cleanup_status="$command_status"
            }
        fi
    else
        command_status=$?
        ((cleanup_status != 0)) || cleanup_status="$command_status"
    fi

    ids=()
    if listing="$(timeout --preserve-status --kill-after=5 "$docker_cleanup_timeout" \
        "$real_docker" volume ls -q --filter "label=$resource_label")"; then
        while IFS= read -r id; do
            [[ -z "$id" ]] || ids+=("$id")
        done <<<"$listing"
        if ((${#ids[@]} > 0)); then
            timeout --preserve-status --kill-after=5 "$docker_cleanup_timeout" \
                "$real_docker" volume rm -f "${ids[@]}" >/dev/null || {
                command_status=$?
                ((cleanup_status != 0)) || cleanup_status="$command_status"
            }
        fi
    else
        command_status=$?
        ((cleanup_status != 0)) || cleanup_status="$command_status"
    fi
    return "$cleanup_status"
}

record_docker_cleanup_failure() {
    local artifact_dir="$1"
    local resource_label="$2"
    local command_status="$3"
    local cleanup_status="$4"
    local evidence staged
    mkdir -p "$artifact_dir" || return 1
    evidence="$artifact_dir/docker-cleanup-failure.env"
    staged="$(mktemp "$artifact_dir/.docker-cleanup-failure.XXXXXX")" || return 1
    {
        printf 'evidence_schema=2\n'
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'ownership_label=%s\n' "$resource_label"
        printf 'primary_exit_status=%s\n' "$command_status"
        printf 'cleanup_exit_status=%s\n' "$cleanup_status"
    } >"$staged"
    mv "$staged" "$evidence"
}

record_docker_cleanup_active() {
    local artifact_dir="$1"
    local resource_label="$2"
    local evidence="$artifact_dir/docker-cleanup-active.env"
    local staged
    mkdir -p "$artifact_dir" || return 1
    staged="$(mktemp "$artifact_dir/.docker-cleanup-active.XXXXXX")" || return 1
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'ownership_label=%s\n' "$resource_label"
    } >"$staged" || {
        rm -f "$staged"
        return 1
    }
    mv "$staged" "$evidence"
}

record_docker_cleanup_reconciled() {
    local artifact_dir="$1"
    local resource_label="$2"
    local source_evidence="$3"
    local reconciled="$artifact_dir/docker-cleanup-reconciled.env"
    local staged
    staged="$(mktemp "$artifact_dir/.docker-cleanup-reconciled.XXXXXX")" || return 1
    {
        printf 'reconciled_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'ownership_label=%s\n' "$resource_label"
        printf 'source_evidence=%s\n' "$source_evidence"
    } >"$staged" || {
        rm -f "$staged"
        return 1
    }
    mv "$staged" "$reconciled" || {
        rm -f "$staged"
        return 1
    }
}

write_docker_cleanup_recovery_command() {
    local artifact_dir="$1"
    local real_docker="$2"
    local resource_label="$3"
    local recovery="$artifact_dir/docker-cleanup-recovery.sh"
    local staged
    staged="$(mktemp "$artifact_dir/.docker-cleanup-recovery.XXXXXX")" || return 1
    {
        printf '#!/usr/bin/env bash\n'
        printf 'set -euo pipefail\n'
        printf 'docker_bin=%q\n' "$real_docker"
        printf 'ownership_label=%q\n' "$resource_label"
        printf 'cleanup_timeout=%q\n' "$docker_cleanup_timeout"
        cat <<'RECOVERY'
containers="$(timeout --preserve-status --kill-after=5 "$cleanup_timeout" "$docker_bin" ps -aq --filter "label=$ownership_label")"
if [[ -n "$containers" ]]; then
    mapfile -t ids <<<"$containers"
    timeout --preserve-status --kill-after=5 "$cleanup_timeout" "$docker_bin" rm -f "${ids[@]}"
fi
networks="$(timeout --preserve-status --kill-after=5 "$cleanup_timeout" "$docker_bin" network ls -q --filter "label=$ownership_label")"
if [[ -n "$networks" ]]; then
    mapfile -t ids <<<"$networks"
    timeout --preserve-status --kill-after=5 "$cleanup_timeout" "$docker_bin" network rm "${ids[@]}"
fi
volumes="$(timeout --preserve-status --kill-after=5 "$cleanup_timeout" "$docker_bin" volume ls -q --filter "label=$ownership_label")"
if [[ -n "$volumes" ]]; then
    mapfile -t ids <<<"$volumes"
    timeout --preserve-status --kill-after=5 "$cleanup_timeout" "$docker_bin" volume rm -f "${ids[@]}"
fi
RECOVERY
    } >"$staged"
    chmod 0700 "$staged"
    mv "$staged" "$recovery"
}

reconcile_retained_docker_cleanup_failures() {
    ((resume)) || return 0
    local failures_root="$evidence_dir/scenarios"
    [[ -d "$failures_root" ]] || return 0
    local failure active artifact_dir reconciled resource_label cleanup_status source_evidence
    local aggregate_status=0
    local -a failures=() active_markers=() artifact_dirs=()
    local -A seen_artifact_dirs=()
    mapfile -d '' -t failures < <(find "$failures_root" -type f -name docker-cleanup-failure.env -print0 | sort -z)
    mapfile -d '' -t active_markers < <(find "$failures_root" -type f -name docker-cleanup-active.env -print0 | sort -z)
    for active in "${active_markers[@]}"; do
        artifact_dir="$(dirname "$active")"
        [[ -n "${seen_artifact_dirs[$artifact_dir]:-}" ]] || artifact_dirs+=("$artifact_dir")
        seen_artifact_dirs[$artifact_dir]=1
    done
    for failure in "${failures[@]}"; do
        artifact_dir="$(dirname "$failure")"
        [[ -n "${seen_artifact_dirs[$artifact_dir]:-}" ]] || artifact_dirs+=("$artifact_dir")
        seen_artifact_dirs[$artifact_dir]=1
    done
    ((${#artifact_dirs[@]} > 0)) || return 0
    local real_docker
    real_docker="$(command -v docker 2>/dev/null || true)"

    for artifact_dir in "${artifact_dirs[@]}"; do
        active="$artifact_dir/docker-cleanup-active.env"
        failure="$artifact_dir/docker-cleanup-failure.env"
        reconciled="$artifact_dir/docker-cleanup-reconciled.env"
        [[ ! -e "$reconciled" ]] || continue
        if [[ -f "$active" && ! -L "$active" ]]; then
            source_evidence="$active"
        elif [[ -f "$failure" && ! -L "$failure" ]]; then
            source_evidence="$failure"
        else
            die "retained Docker cleanup marker is unsafe: $artifact_dir"
        fi
        resource_label="$(awk -F= '$1 == "ownership_label" { sub(/^[^=]*=/, ""); print; found = 1; exit } END { if (!found) exit 1 }' "$source_evidence")" ||
            die "retained Docker cleanup evidence is missing ownership_label: $source_evidence"
        [[ "$resource_label" == io.borondns.soak.run=* ]] ||
            die "retained Docker cleanup evidence has an invalid ownership_label: $failure"
        cleanup_status=0
        if [[ -z "$real_docker" ]]; then
            cleanup_status=127
            # Keep the recovery command useful after Docker is restored to PATH.
            real_docker=docker
        else
            cleanup_soak_docker_resources "$real_docker" "$resource_label" || cleanup_status=$?
        fi
        if ((cleanup_status != 0)); then
            write_docker_cleanup_recovery_command "$artifact_dir" "$real_docker" "$resource_label" || true
            printf 'retained Docker cleanup still fails: evidence=%s ownership_label=%s exit_status=%s\n' \
                "$source_evidence" "$resource_label" "$cleanup_status" >&2
            printf 'run recovery command, then retry --resume: %s/docker-cleanup-recovery.sh\n' "$artifact_dir" >&2
            ((aggregate_status != 0)) || aggregate_status="$cleanup_status"
            [[ "$real_docker" != docker ]] || real_docker=""
            continue
        fi
        if ! record_docker_cleanup_reconciled "$artifact_dir" "$resource_label" "$source_evidence"; then
            printf 'failed to publish Docker reconciliation marker; continuing: %s\n' "$reconciled" >&2
            ((aggregate_status != 0)) || aggregate_status=70
            continue
        fi
    done
    return "$aggregate_status"
}

run_timeout_with_process_group_cleanup() {
    local timeout_pid timeout_pgid caller_pgid timeout_status=0

    timeout "$@" &
    timeout_pid=$!
    timeout_pgid="$(ps -o pgid= -p "$timeout_pid")" || {
        wait "$timeout_pid" || true
        printf 'failed to determine timeout process group: pid=%s\n' "$timeout_pid" >&2
        return 70
    }
    timeout_pgid="${timeout_pgid//[[:space:]]/}"
    caller_pgid="$(ps -o pgid= -p "$BASHPID")" || {
        wait "$timeout_pid" || true
        printf 'failed to determine scenario runner process group\n' >&2
        return 70
    }
    caller_pgid="${caller_pgid//[[:space:]]/}"
    if [[ ! "$timeout_pgid" =~ ^[1-9][0-9]*$ || "$timeout_pgid" == "$caller_pgid" ]]; then
        wait "$timeout_pid" || true
        printf 'timeout did not establish an isolated process group: timeout_pid=%s timeout_pgid=%s caller_pgid=%s\n' \
            "$timeout_pid" "$timeout_pgid" "$caller_pgid" >&2
        return 70
    fi

    wait "$timeout_pid" || timeout_status=$?
    # GNU timeout normally signals the complete command process group.  Some
    # compatible implementations signal only the immediate command, allowing
    # grandchildren to survive after the timeout process exits.  Reap anything
    # still in the authenticated, isolated group before returning to the soak.
    kill -KILL -- "-$timeout_pgid" 2>/dev/null || true
    return "$timeout_status"
}

run_bounded_scenario_command() {
    local timeout_seconds="$1"
    local kill_after_seconds="$2"
    local env_name="$3"
    local env_value="$4"
    local command="$5"
    local deadline_nanoseconds="${6:-}"
    local deadline_marker="${7:-}"
    local requested_timeout_seconds="$timeout_seconds"
    local command_status=0
    local cleanup_status=0
    local deadline_limited=0
    local effective_timeout_nanoseconds=0
    local command_started_nanoseconds=0
    local command_ended_nanoseconds=0
    local real_docker=""
    local docker_proxy_function=0
    local resource_label=""
    local -a command_env=(env "$env_name=$env_value")

    if real_docker="$(command -v docker 2>/dev/null)"; then
        resource_label="io.borondns.soak.run=run-$$-$(date +%s%N)"
        command_env+=("BORONDNS_SOAK_DOCKER_LABEL=$resource_label")
        if [[ "${BORONDNS_LARGE_SOAK_AUTHENTICATED_DOCKER_SHIM:-}" != "$real_docker" ]]; then
            BORONDNS_SOAK_REAL_DOCKER="$real_docker"
            export BORONDNS_SOAK_REAL_DOCKER
            # Exported into the bounded scenario's Bash process.
            # shellcheck disable=SC2317,SC2329
            docker() {
                local resource_label="${BORONDNS_SOAK_DOCKER_LABEL:?}"
                local real_docker="${BORONDNS_SOAK_REAL_DOCKER:?}"
                case "${1:-}" in
                run | create)
                    local subcommand="$1"
                    shift
                    "$real_docker" "$subcommand" --label "$resource_label" "$@"
                    ;;
                network | volume)
                    if [[ "${2:-}" == create ]]; then
                        local resource="$1"
                        shift 2
                        "$real_docker" "$resource" create --label "$resource_label" "$@"
                    else
                        "$real_docker" "$@"
                    fi
                    ;;
                *) "$real_docker" "$@" ;;
                esac
            }
            export -f docker
            docker_proxy_function=1
        fi
    fi

    if [[ -n "$deadline_nanoseconds" ]]; then
        if ! timeout_seconds="$(scenario_timeout_within_campaign "$timeout_seconds" "$deadline_nanoseconds" "$(monotonic_nanoseconds)" 50000000 "$kill_after_seconds")"; then
            printf 'campaign deadline reached before scenario command start\n' >&2
            [[ -z "$deadline_marker" ]] || : >"$deadline_marker"
            if ((docker_proxy_function)); then
                unset -f docker
                unset BORONDNS_SOAK_REAL_DOCKER
            fi
            return 75
        fi
        local timeout_whole="${timeout_seconds%%.*}"
        local timeout_fraction="${timeout_seconds#*.}"
        effective_timeout_nanoseconds=$((10#$timeout_whole * 1000000000 + 10#$timeout_fraction))
        if ((effective_timeout_nanoseconds < requested_timeout_seconds * 1000000000)); then
            deadline_limited=1
        fi
        printf 'effective_timeout_seconds=%s\n' "$timeout_seconds"
    fi

    if [[ -n "$real_docker" ]]; then
        if ! record_docker_cleanup_active "$env_value" "$resource_label"; then
            printf 'docker ownership marker setup failed: %s/docker-cleanup-active.env\n' "$env_value" >&2
            if ((docker_proxy_function)); then
                unset -f docker
                unset BORONDNS_SOAK_REAL_DOCKER
            fi
            return 70
        fi
    fi

    command_started_nanoseconds="$(monotonic_nanoseconds)"
    if ((deadline_limited)); then
        if run_timeout_with_process_group_cleanup \
            --kill-after="$kill_after_seconds" "$timeout_seconds" \
            "${command_env[@]}" "$command"; then
            command_status=0
        else
            command_status=$?
        fi
    else
        if run_timeout_with_process_group_cleanup \
            --preserve-status --kill-after="$kill_after_seconds" "$timeout_seconds" \
            "${command_env[@]}" "$command"; then
            command_status=0
        else
            command_status=$?
        fi
    fi
    command_ended_nanoseconds="$(monotonic_nanoseconds)"
    if ((deadline_limited && command_status == 124 && \
        command_ended_nanoseconds + 10000000 >= command_started_nanoseconds + effective_timeout_nanoseconds)); then
        [[ -z "$deadline_marker" ]] || : >"$deadline_marker"
    fi
    if [[ -n "$real_docker" ]]; then
        cleanup_soak_docker_resources "$real_docker" "$resource_label" || cleanup_status=$?
        if ((cleanup_status != 0)); then
            printf 'docker cleanup failed: ownership_label=%s cleanup_exit_status=%s primary_exit_status=%s\n' \
                "$resource_label" "$cleanup_status" "$command_status" >&2
            if ! record_docker_cleanup_failure "$env_value" "$resource_label" "$command_status" "$cleanup_status"; then
                printf 'docker cleanup failure evidence could not be written: %s/docker-cleanup-failure.env\n' \
                    "$env_value" >&2
            fi
        elif ! record_docker_cleanup_reconciled "$env_value" "$resource_label" "$env_value/docker-cleanup-active.env"; then
            printf 'docker cleanup succeeded but reconciliation marker could not be written\n' >&2
            cleanup_status=70
        fi
    fi
    if ((docker_proxy_function)); then
        unset -f docker
        unset BORONDNS_SOAK_REAL_DOCKER
    fi
    if [[ -n "$deadline_marker" && -e "$deadline_marker" && "$cleanup_status" == 0 ]]; then
        return 75
    fi
    ((command_status != 0)) && return "$command_status"
    return "$cleanup_status"
}

run_scenario() {
    local cycle="$1"
    local index="$2"
    local attempt="$3"
    local scenario="${scenario_names[$index]}"
    local script="${scenario_scripts[$index]}"
    local env_var="${scenario_env_vars[$index]}"
    local scenario_dir log
    local started ended status exit_status deadline_marker
    verify_expected_clean_head || return $?
    verify_expected_tool_hashes || return $?
    local cycle_dir
    cycle_dir="$evidence_dir/scenarios/cycle-$(printf '%04d' "$cycle")"
    local scenario_root attempt_root
    scenario_root="$cycle_dir/$scenario"
    attempt_root="$scenario_root/attempts"
    scenario_dir="$attempt_root/attempt-$(printf '%04d' "$attempt")"
    log="$scenario_dir/scenario.log"
    deadline_marker="$scenario_dir/.deadline-exhausted"
    scenario_timeout_within_campaign "$scenario_timeout" "$campaign_control_deadline_nanoseconds" \
        "$(monotonic_nanoseconds)" 50000000 "$scenario_kill_after" >/dev/null || {
        printf 'campaign deadline reached before scenario allocation: cycle=%s scenario=%s\n' "$cycle" "$scenario" >&2
        return 75
    }
    campaign_prepare_contained_directory "$evidence_dir/scenarios" "$cycle_dir" "soak cycle directory" ||
        die "unsafe soak cycle directory: $cycle"
    campaign_prepare_contained_directory "$cycle_dir" "$scenario_root" "soak scenario root" ||
        die "unsafe soak scenario root: $scenario_root"
    campaign_prepare_contained_directory "$scenario_root" "$attempt_root" "soak scenario attempt root" ||
        die "unsafe soak scenario attempt root: $attempt_root"
    campaign_prepare_owned_fresh_directory "$attempt_root" "$scenario_dir" "soak scenario attempt directory" ||
        die "unsafe or reused soak scenario directory: $scenario_dir"
    campaign_prepare_contained_directory "$scenario_dir" "$scenario_dir/artifacts" "scenario artifact directory" ||
        die "unsafe scenario artifact directory: $scenario_dir/artifacts"
    started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local started_content
    printf -v started_content 'cycle=%s\nscenario=%s\nattempt=%s\nstarted_utc=%s' \
        "$cycle" "$scenario" "$attempt" "$started"
    campaign_atomic_replace_text "$scenario_dir/attempt-started.env" "$started_content" \
        "scenario attempt start metadata"
    set +e
    (
        cd "$repo_root"
        printf '$ %s=%q bounded-to-deadline=%q timeout --preserve-status --kill-after=%q %q %q\n' \
            "$env_var" "$scenario_dir/artifacts" "$campaign_deadline_epoch" "$scenario_kill_after" "$scenario_timeout" "$script"
        run_bounded_scenario_command \
            "$scenario_timeout" "$scenario_kill_after" "$env_var" "$scenario_dir/artifacts" "$repo_root/$script" \
            "$campaign_control_deadline_nanoseconds" "$deadline_marker"
    ) >"$log" 2>&1
    exit_status=$?
    set -e
    if ((exit_status == 75)) && [[ -e "$deadline_marker" ]]; then
        campaign_require_owned_real_directory "$scenario_dir" "deadline-exhausted scenario attempt" || return 74
        [[ -f "$scenario_dir/attempt-started.env" && ! -L "$scenario_dir/attempt-started.env" &&
            -f "$log" && ! -L "$log" && -f "$deadline_marker" && ! -L "$deadline_marker" &&
            -d "$scenario_dir/artifacts" && ! -L "$scenario_dir/artifacts" &&
            -z "$(find "$scenario_dir" -type l -print -quit)" ]] || {
            printf 'deadline-exhausted scenario attempt contains unexpected evidence: %s\n' "$scenario_dir" >&2
            return 74
        }
        campaign_capture_cleanup_identity "$scenario_dir" tree deadline_scenario_cleanup \
            "deadline-exhausted scenario attempt" || return 74
        campaign_remove_captured_cleanup_object "$scenario_dir" deadline_scenario_cleanup \
            "deadline-exhausted scenario attempt" || return 74
        campaign_forget_cleanup_identity deadline_scenario_cleanup
        return 75
    fi
    ended="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if ((exit_status == 0)); then
        if grep -Eiq '(^|[[:space:]])skipping ' "$log"; then
            if [[ "$allow_skip" == "1" ]]; then
                status="skipped"
            else
                status="failed"
                # The scenario command itself succeeded, but fail-on-skip turns
                # that policy outcome into a canonical failed attempt.  Keep
                # the ledger status and exit status consistent so the retained
                # failure remains valid and resumable.
                exit_status=1
            fi
        else
            status="passed"
        fi
    else
        status="failed"
    fi
    local result_row
    printf -v result_row '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        "$cycle" "$scenario" "$attempt" "$status" "$exit_status" "$started" "$ended" \
        "${scenario_dir#"$evidence_dir"/}" "${log#"$evidence_dir"/}"
    append_scenario_result "$result_row" || return 74
    if [[ "$status" == "failed" ]]; then
        printf 'scenario failed: cycle=%s scenario=%s exit=%s log=%s\n' "$cycle" "$scenario" "$exit_status" "$log" >&2
        return 1
    fi
    return 0
}

main() {
    init_scenarios
    parse_args "$@"
    validate_timing_bounds "$(date +%s)"

    local selected_name
    local -A selected_seen=()
    for selected_name in "${selected_scenarios[@]}"; do
        scenario_index "$selected_name" >/dev/null || die "unknown scenario: $selected_name"
        [[ -z "${selected_seen[$selected_name]+x}" ]] || die "duplicate scenario: $selected_name"
        selected_seen[$selected_name]=1
    done
    mapfile -t indices < <(selected_indices)
    local scenario_list=""
    local scenario_index_value
    for scenario_index_value in "${indices[@]}"; do
        [[ -z "$scenario_list" ]] || scenario_list+=" "
        scenario_list+="${scenario_names[$scenario_index_value]}"
    done
    scenario_list_for_validation="$scenario_list"
    if ((dry_run)); then
        printf 'large-surface soak dry-run\n'
        printf 'duration_seconds=%s\n' "$duration"
        printf 'scenario_timeout_seconds=%s\n' "$scenario_timeout"
        for index in "${indices[@]}"; do
            printf '%s\t%s\t%s\n' "${scenario_names[$index]}" "${scenario_scripts[$index]}" "${scenario_env_vars[$index]}"
        done
        exit 0
    fi

    evidence_dir="$(realpath -ms -- "$evidence_dir")" || die "cannot normalize evidence directory: $evidence_dir"
    resolve_rust_tools
    acquire_evidence_lock
    if ((resume)); then
        bind_resume_provenance
        validate_resume_parameters "$scenario_list"
    else
        bind_initial_provenance
    fi
    trap cleanup_early_large_soak_exit EXIT
    prepare_build_directory
    prepare_evidence_directory
    prepare_scenario_results "$scenario_list"
    reconcile_retained_docker_cleanup_failures
    if ! ((resume)); then
        record_host_info
        record_tool_versions
    fi
    prepare_campaign_deadline
    initialize_campaign_control_deadline ||
        die "cannot bind the campaign deadline to this boot's CLOCK_BOOTTIME budget"
    local run_metadata="$evidence_dir/soak.env"
    if ((resume)); then
        run_metadata="$evidence_dir/soak-resume-$timestamp.env"
    fi
    {
        printf 'created_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'repo_root=%s\n' "$repo_root"
        printf 'cargo_target_dir=%s\n' "$cargo_target_dir"
        printf 'duration_seconds=%s\n' "$duration"
        printf 'start_epoch_seconds=%s\n' "$campaign_start_epoch"
        printf 'deadline_epoch_seconds=%s\n' "$campaign_deadline_epoch"
        printf 'boot_id=%s\n' "$campaign_boot_id"
        printf 'control_deadline_boottime_nanoseconds=%s\n' "$campaign_control_deadline_nanoseconds"
        printf 'cross_boot_diagnostic=%s\n' "$cross_boot_diagnostic_active"
        printf 'scenario_timeout_seconds=%s\n' "$scenario_timeout"
        printf 'scenario_kill_after_seconds=%s\n' "$scenario_kill_after"
        printf 'docker_cleanup_timeout_seconds=%s\n' "$docker_cleanup_timeout"
        printf 'cycle_sleep_seconds=%s\n' "$cycle_sleep"
        printf 'sample_interval_seconds=%s\n' "$sample_interval"
        printf 'allow_skip=%s\n' "$allow_skip"
        printf 'resume=%s\n' "$resume"
        printf 'expected_commit=%s\n' "$expected_commit"
        printf 'cargo_sha256=%s\n' "$(campaign_sha256 "$selected_cargo_path")"
        printf 'rustc_sha256=%s\n' "$(campaign_sha256 "$selected_rustc_path")"
        printf 'scenarios=%s\n' "$scenario_list"
    } >"$run_metadata"
    if ((resume)); then
        record_host_info "$evidence_dir/host-info-resume-$timestamp.txt"
        record_tool_versions "$evidence_dir/tool-versions-resume-$timestamp.txt"
    fi

    local end_epoch cycle index attempt scenario_status sampler_status bounded_cycle_sleep control_now
    end_epoch="$campaign_deadline_epoch"
    reconcile_interrupted_resource_samplers
    start_resource_sampler "$end_epoch" "$campaign_control_deadline_nanoseconds"
    trap finalize_soak_evidence EXIT

    read -r cycle index attempt <<<"$(next_scenario_work "$scenario_list")"
    control_now="$(monotonic_nanoseconds)"
    while ((control_now < campaign_control_deadline_nanoseconds)); do
        require_resource_sampler_alive
        verify_expected_clean_head
        verify_expected_tool_hashes
        while ((index < ${#indices[@]})); do
            if run_scenario "$cycle" "${indices[$index]}" "$attempt"; then
                :
            else
                scenario_status=$?
                if ((scenario_status == 75)); then
                    break 2
                fi
                exit "$scenario_status"
            fi
            attempt=1
            index=$((index + 1))
            control_now="$(monotonic_nanoseconds)"
            if ((control_now >= campaign_control_deadline_nanoseconds)); then
                break
            fi
            require_resource_sampler_alive
        done
        write_summary
        if ((index < ${#indices[@]})); then
            break
        fi
        control_now="$(monotonic_nanoseconds)"
        if ((control_now < campaign_control_deadline_nanoseconds)); then
            if bounded_cycle_sleep="$(scenario_timeout_within_campaign \
                "$cycle_sleep" "$campaign_control_deadline_nanoseconds")"; then
                sleep "$bounded_cycle_sleep"
            fi
        fi
        cycle=$((cycle + 1))
        index=0
        attempt=1
        control_now="$(monotonic_nanoseconds)"
    done
    sampler_status=0
    if [[ -n "$sampler_pid" ]]; then
        set +e
        wait_for_resource_sampler_bounded "$end_epoch" "$campaign_control_deadline_nanoseconds"
        sampler_status=$?
        set -e
    fi
    if ((sampler_status != 0)); then
        sampler_pid=""
        printf 'resource sampler failed before terminal evidence publication: exit=%s\n' "$sampler_status" >&2
        exit "$sampler_status"
    fi
    sampler_pid=""
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
