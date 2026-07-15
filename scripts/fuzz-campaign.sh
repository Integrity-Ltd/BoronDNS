#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/fuzz-campaign.sh [OPTIONS] [TARGET...]

Run a short cargo-fuzz evidence campaign and retain logs/artifacts.

Options:
  --all                  Run all known fuzz targets (default when no TARGET is given)
  --target TARGET        Add a fuzz target to run; may be repeated
  --duration SECONDS     Per-target fuzz duration (default: 10)
  --evidence-dir DIR     Output directory (default: target/fuzz-evidence/<timestamp>)
  --toolchain TOOLCHAIN  Run cargo through rustup with this toolchain (default: nightly)
  --sanitizer NAME       Pass a cargo-fuzz sanitizer mode, for example address or thread
  --dry-run              Validate wiring without running a target; evidence is non-release
  --list-targets         Print known targets and exit
  -h, --help             Show this help

Environment:
  CARGO                  Cargo executable to use (default: cargo)
  CARGO_TOOLCHAIN        Rustup toolchain override (default: nightly with rustup cargo)
  CARGO_FUZZ_SANITIZER   Optional cargo-fuzz sanitizer mode
  BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE
                         Allow a local dirty-source diagnostic; never accepted in CI
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/campaign-env.sh
source "$repo_root/scripts/campaign-env.sh"
fuzz_targets_dir="$repo_root/fuzz/fuzz_targets"
default_duration=10
duration="$default_duration"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="$repo_root/target/fuzz-evidence/$timestamp"
dry_run=0
list_targets=0
all_targets=0
cargo_bin="${CARGO:-cargo}"
cargo_overridden=0
[[ ! -v CARGO ]] || cargo_overridden=1
cargo_toolchain="${CARGO_TOOLCHAIN:-}"
if ((cargo_overridden == 0)) && [[ -z "$cargo_toolchain" ]] && command -v rustup >/dev/null 2>&1; then
    # cargo-fuzz's default sanitizer instrumentation requires nightly. The
    # repository pins stable for ordinary builds, so following the active
    # toolchain makes the documented no-argument campaign fail at rustc's -Z
    # option instead of running. Match the long-campaign runner's default.
    cargo_toolchain=nightly
fi
sanitizer="${CARGO_FUZZ_SANITIZER:-}"
allow_dirty_non_release="${BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE:-0}"
[[ "$allow_dirty_non_release" == 0 || "$allow_dirty_non_release" == 1 ]] ||
    die "BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE must be 0 or 1"
if [[ "$allow_dirty_non_release" == 1 ]] &&
    { [[ "${GITHUB_ACTIONS:-false}" == true ]] ||
        [[ -n "${CI:-}" && "${CI:-}" != false && "${CI:-}" != 0 ]] ||
        [[ "${GITHUB_REF_TYPE:-}" == tag ]] || [[ "${GITHUB_REF:-}" == refs/tags/* ]]; }; then
    die "dirty-source fuzz override is forbidden in CI and release contexts"
fi
fuzz_wall_clock_grace="${BORONDNS_FUZZ_WALL_CLOCK_GRACE_SECONDS:-1800}"
fuzz_wall_clock_kill_after="${BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS:-10}"
fuzz_probe_timeout="${BORONDNS_FUZZ_PREFLIGHT_TIMEOUT_SECONDS:-30}"
fuzz_probe_kill_after="${BORONDNS_FUZZ_PREFLIGHT_KILL_AFTER_SECONDS:-5}"
fuzz_elapsed_tolerance_nanoseconds=250000000
fuzz_wall_monotonic_tolerance_nanoseconds=2000000000
max_nanosecond_seconds=9223372036
cargo_target_dir="${CARGO_TARGET_DIR:-}"
cargo_target_dir_auto=0
selected_cargo_path=""
selected_rustc_path=""
selected_cargo_fuzz_path=""
authenticated_tool_dir=""
authenticated_tool_root=""
authenticated_cargo_path=""
authenticated_cargo_identity=""
authenticated_cargo_sha256=""
authenticated_rustc_path=""
authenticated_rustc_identity=""
authenticated_rustc_sha256=""
authenticated_rustc_library_dir=""
authenticated_rustc_library_tree_identity=""
authenticated_rustc_library_tree_sha256=""
authenticated_cargo_fuzz_path=""
authenticated_cargo_fuzz_identity=""
authenticated_cargo_fuzz_sha256=""
initial_source_commit=""
initial_source_status=""
source_clean=1
release_eligible=1
selected_targets=()
known_targets=()

run_fuzz_probe() {
    timeout --preserve-status --kill-after="$fuzz_probe_kill_after" "$fuzz_probe_timeout" "$@"
}

discover_targets() {
    local target_file
    [[ -d "$fuzz_targets_dir" ]] || die "missing fuzz target directory: $fuzz_targets_dir"
    while IFS= read -r target_file; do
        known_targets+=("$(basename "$target_file" .rs)")
    done < <(find "$fuzz_targets_dir" -maxdepth 1 -type f -name '*.rs' | sort)
    ((${#known_targets[@]} > 0)) || die "no fuzz targets found in $fuzz_targets_dir"
}

contains_target() {
    local needle="$1"
    local target
    for target in "${known_targets[@]}"; do
        [[ "$target" == "$needle" ]] && return 0
    done
    return 1
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

validate_timing_bounds() {
    require_bounded_positive_integer "--duration" "$duration" "$max_nanosecond_seconds"
    require_bounded_positive_integer "BORONDNS_FUZZ_WALL_CLOCK_GRACE_SECONDS" "$fuzz_wall_clock_grace" 9223372036854775807
    require_bounded_positive_integer "BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS" "$fuzz_wall_clock_kill_after" 9223372036854775807
    require_bounded_positive_integer "BORONDNS_FUZZ_PREFLIGHT_TIMEOUT_SECONDS" "$fuzz_probe_timeout" 9223372036854775807
    require_bounded_positive_integer "BORONDNS_FUZZ_PREFLIGHT_KILL_AFTER_SECONDS" "$fuzz_probe_kill_after" 9223372036854775807
    ((fuzz_wall_clock_grace <= 9223372036854775807 - duration)) ||
        die "fuzz duration plus wall-clock grace exceeds signed 64-bit time"
}

monotonic_nanoseconds() {
    python3 -c 'import time; print(time.monotonic_ns())'
}

capture_source_identity() {
    initial_source_commit="$(run_fuzz_probe git -C "$repo_root" rev-parse HEAD 2>/dev/null)" ||
        die "cannot resolve fuzz source commit"
    initial_source_status="$(run_fuzz_probe git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no)" ||
        die "cannot verify fuzz source cleanliness"
    source_clean=1
    release_eligible=1
    if [[ "$allow_dirty_non_release" == 1 ]] || ((dry_run)); then
        release_eligible=0
    fi
    if [[ -n "$initial_source_status" ]]; then
        source_clean=0
        if [[ "$allow_dirty_non_release" != 1 ]] && ((dry_run == 0)); then
            printf 'refusing fuzz campaign from dirty or untracked source:\n%s\n' "$initial_source_status" >&2
            printf 'use BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 only for local non-release diagnostics\n' >&2
            exit 1
        fi
        if ((dry_run)); then
            printf 'warning: dirty-source fuzz dry-run evidence is non-release validation only\n' >&2
        else
            printf 'warning: dirty-source fuzz override enabled; evidence is non-release diagnostic only\n' >&2
        fi
    fi
}

verify_source_identity() {
    local boundary="$1"
    local actual_commit actual_status
    actual_commit="$(run_fuzz_probe git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
        printf 'cannot resolve fuzz source commit at %s\n' "$boundary" >&2
        return 1
    }
    actual_status="$(run_fuzz_probe git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no)" || {
        printf 'cannot determine fuzz source status at %s\n' "$boundary" >&2
        return 1
    }
    if [[ "$actual_commit" != "$initial_source_commit" || "$actual_status" != "$initial_source_status" ]]; then
        printf 'fuzz source identity changed at %s\n' "$boundary" >&2
        return 1
    fi
}

resolve_rust_tools() {
    if [[ -n "${BORONDNS_FUZZ_AUTHENTICATED_CARGO:-}" || -n "${BORONDNS_FUZZ_AUTHENTICATED_RUSTC:-}" || -n "${BORONDNS_FUZZ_AUTHENTICATED_CARGO_FUZZ:-}" ]]; then
        [[ -n "${BORONDNS_FUZZ_AUTHENTICATED_CARGO:-}" && -n "${BORONDNS_FUZZ_AUTHENTICATED_RUSTC:-}" &&
            -n "${BORONDNS_FUZZ_AUTHENTICATED_CARGO_FUZZ:-}" ]] ||
            die "authenticated fuzz tool overrides must be supplied together"
        selected_cargo_path="$BORONDNS_FUZZ_AUTHENTICATED_CARGO"
        selected_rustc_path="$BORONDNS_FUZZ_AUTHENTICATED_RUSTC"
        selected_cargo_fuzz_path="$BORONDNS_FUZZ_AUTHENTICATED_CARGO_FUZZ"
    elif ((cargo_overridden == 0)) && [[ "$cargo_bin" == cargo ]] && command -v rustup >/dev/null 2>&1; then
        if [[ -n "$cargo_toolchain" ]]; then
            selected_cargo_path="$(run_fuzz_probe rustup which --toolchain "$cargo_toolchain" cargo 2>/dev/null)" ||
                die "cannot resolve cargo for rustup toolchain $cargo_toolchain"
            selected_rustc_path="$(run_fuzz_probe rustup which --toolchain "$cargo_toolchain" rustc 2>/dev/null)" ||
                die "cannot resolve rustc for rustup toolchain $cargo_toolchain"
        else
            selected_cargo_path="$(run_fuzz_probe rustup which cargo 2>/dev/null)" || die "cannot resolve active rustup cargo"
            selected_rustc_path="$(run_fuzz_probe rustup which rustc 2>/dev/null)" || die "cannot resolve active rustup rustc"
        fi
    else
        selected_cargo_path="$(command -v "$cargo_bin" 2>/dev/null)" || die "$cargo_bin not found on PATH"
        selected_rustc_path="$(command -v rustc 2>/dev/null || true)"
    fi
    if [[ -z "${BORONDNS_FUZZ_AUTHENTICATED_CARGO:-}" ]]; then
        selected_cargo_path="$(realpath -e "$selected_cargo_path")" || die "cannot canonicalize selected cargo"
    fi
    [[ -x "$selected_cargo_path" && -f "$selected_cargo_path" ]] || die "selected cargo is not an executable regular file"
    if [[ -n "$selected_rustc_path" ]]; then
        if [[ -z "${BORONDNS_FUZZ_AUTHENTICATED_RUSTC:-}" ]]; then
            selected_rustc_path="$(realpath -e "$selected_rustc_path")" || die "cannot canonicalize selected rustc"
            if [[ "$(basename "$selected_rustc_path")" == rustup ]] && command -v rustup >/dev/null 2>&1; then
                selected_rustc_path="$(run_fuzz_probe rustup which rustc 2>/dev/null)" ||
                    die "cannot resolve the concrete rustc behind the rustup proxy"
                selected_rustc_path="$(realpath -e "$selected_rustc_path")" ||
                    die "cannot canonicalize concrete rustc"
            fi
        fi
        [[ -x "$selected_rustc_path" && -f "$selected_rustc_path" ]] || die "selected rustc is not an executable regular file"
    fi
    [[ -n "$selected_rustc_path" ]] || die "rustc executable not found on PATH"
    local rustc_origin rustc_library_candidate
    rustc_origin="$(realpath -e "$selected_rustc_path")" || die "cannot resolve selected rustc origin"
    rustc_library_candidate="$(dirname "$rustc_origin")/../lib"
    if [[ -d "$rustc_library_candidate/rustlib" && ! -L "$rustc_library_candidate" ]] &&
        find "$rustc_library_candidate" -maxdepth 1 -type f -name 'librustc_driver*' -print -quit | grep -q .; then
        authenticated_rustc_library_dir="$(realpath -e "$rustc_library_candidate")" ||
            die "cannot resolve selected rustc runtime library directory"
    fi
    if [[ -z "$selected_cargo_fuzz_path" ]]; then
        selected_cargo_fuzz_path="$(command -v cargo-fuzz 2>/dev/null || true)"
        [[ -n "$selected_cargo_fuzz_path" ]] || selected_cargo_fuzz_path="${CARGO_HOME:-$HOME/.cargo}/bin/cargo-fuzz"
        [[ -n "$selected_cargo_fuzz_path" ]] || die "cargo-fuzz executable not found on PATH"
        selected_cargo_fuzz_path="$(realpath -e "$selected_cargo_fuzz_path")" || die "cannot canonicalize cargo-fuzz"
    fi
    [[ -x "$selected_cargo_fuzz_path" && -f "$selected_cargo_fuzz_path" ]] || die "selected cargo-fuzz is not an executable regular file"
    export RUSTC="$selected_rustc_path"
}

record_versions() {
    local versions_file="$1"
    verify_authenticated_rust_tools
    {
        printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'repo_root=%s\n' "$repo_root"
        printf 'cargo=%s\n' "$cargo_bin"
        printf 'cargo_target_dir=%s\n' "$cargo_target_dir"
        printf 'cargo_path=%s\n' "$selected_cargo_path"
        printf 'cargo_sha256=%s\n' "$authenticated_cargo_sha256"
        printf 'cargo_executed_path=%s\n' "$authenticated_cargo_path"
        printf 'cargo_executed_sha256=%s\n' "$authenticated_cargo_sha256"
        printf 'rustc_path=%s\n' "${selected_rustc_path:-unresolved}"
        if [[ -n "$selected_rustc_path" ]]; then
            printf 'rustc_sha256=%s\n' "$authenticated_rustc_sha256"
            printf 'rustc_executed_path=%s\n' "$authenticated_rustc_path"
            printf 'rustc_executed_sha256=%s\n' "$authenticated_rustc_sha256"
            printf 'rustc_runtime_library_dir=%s\n' "${authenticated_rustc_library_dir:-unresolved}"
            printf 'rustc_runtime_tree_sha256=%s\n' "${authenticated_rustc_library_tree_sha256:-unresolved}"
        fi
        printf 'cargo_toolchain=%s\n' "${cargo_toolchain:-default}"
        printf '$ git rev-parse HEAD\n'
        run_fuzz_probe git -C "$repo_root" rev-parse HEAD 2>&1 || true
        printf '$ git status --short\n'
        run_fuzz_probe git -C "$repo_root" status --short 2>&1 || true
        if [[ -n "$cargo_toolchain" ]]; then
            if command -v rustup >/dev/null 2>&1; then
                PATH="$(authenticated_tool_path)" run_fuzz_probe "$authenticated_cargo_path" --version
                PATH="$(authenticated_tool_path)" run_fuzz_probe "$authenticated_cargo_path" fuzz --version 2>&1 || true
                run_fuzz_probe "$authenticated_rustc_path" --version 2>&1 || true
            else
                printf 'rustup not found on PATH\n'
            fi
        elif command -v "$cargo_bin" >/dev/null 2>&1; then
            PATH="$(authenticated_tool_path)" run_fuzz_probe "$authenticated_cargo_path" --version
            PATH="$(authenticated_tool_path)" run_fuzz_probe "$authenticated_cargo_path" fuzz --version 2>&1 || true
        else
            printf '%s not found on PATH\n' "$cargo_bin"
        fi
        if [[ -n "$selected_rustc_path" ]]; then
            run_fuzz_probe "$authenticated_rustc_path" --version
        else
            printf 'rustc not found on PATH\n'
        fi
        if command -v rustup >/dev/null 2>&1; then
            run_fuzz_probe rustup show active-toolchain 2>&1 || true
        else
            printf 'rustup not found on PATH\n'
        fi
    } >"$versions_file"
    verify_authenticated_rust_tools
}

prepare_evidence_directory() {
    local evidence_parent
    evidence_parent="$(dirname "$evidence_dir")"
    mkdir -p "$evidence_parent"
    campaign_require_owned_real_directory "$evidence_parent" "fuzz evidence parent" || die "unsafe fuzz evidence parent"
    campaign_acquire_private_lock "$evidence_parent" "$(realpath -ms "$evidence_dir"):runner" "fuzz evidence lock" ||
        die "could not acquire the private fuzz evidence lock"
    campaign_assert_private_lock || die "fuzz evidence lock broker exited"
    if [[ -e "$evidence_dir" ]]; then
        campaign_require_owned_real_directory "$evidence_dir" "fuzz evidence directory" || die "unsafe fuzz evidence directory"
        if [[ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
            die "fuzz evidence directory is non-empty; choose a new path: $evidence_dir"
        fi
    else
        mkdir -m 0700 "$evidence_dir"
        campaign_require_owned_real_directory "$evidence_dir" "fuzz evidence directory" || die "unsafe fuzz evidence directory"
    fi
    campaign_prepare_owned_fresh_directory "$evidence_dir" "$evidence_dir/logs" "fuzz log directory" || die "unsafe fuzz log directory"
    campaign_prepare_owned_fresh_directory "$evidence_dir" "$evidence_dir/artifacts" "fuzz artifact directory" || die "unsafe fuzz artifact directory"
}

prepare_build_directory() {
    if [[ -z "$cargo_target_dir" ]]; then
        campaign_prepare_private_temporary_tree "${TMPDIR:-/var/tmp}" borondns-fuzz-builds \
            fuzz_auto_build cargo_target_dir || die "cannot create private automatic CARGO_TARGET_DIR"
        cargo_target_dir_auto=1
    elif [[ -e "$cargo_target_dir" || -L "$cargo_target_dir" ]]; then
        [[ -d "$cargo_target_dir" && ! -L "$cargo_target_dir" ]] ||
            die "CARGO_TARGET_DIR must be a real directory: $cargo_target_dir"
    else
        mkdir -m 0700 "$cargo_target_dir"
    fi
    local repo_real build_real owner
    repo_real="$(realpath -e "$repo_root")"
    build_real="$(realpath -e "$cargo_target_dir")" || die "cannot resolve CARGO_TARGET_DIR: $cargo_target_dir"
    campaign_require_owned_real_directory "$build_real" "CARGO_TARGET_DIR" || die "unsafe CARGO_TARGET_DIR"
    [[ "$build_real" != "$repo_real" && "$build_real" != "$repo_real"/* ]] ||
        die "CARGO_TARGET_DIR must be outside the repository: $cargo_target_dir"
    owner="$(stat -c %u "$build_real")"
    [[ "$owner" == "$(id -u)" ]] || die "CARGO_TARGET_DIR is not owned by the runner: $build_real"
    [[ -z "$(find "$build_real" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        die "CARGO_TARGET_DIR must be empty before the campaign build: $build_real"
    cargo_target_dir="$build_real"
    export CARGO_TARGET_DIR="$cargo_target_dir"
}

cleanup_automatic_build_directory() {
    ((cargo_target_dir_auto)) || return 0
    [[ -n "$cargo_target_dir" ]] || return 0
    campaign_remove_private_temporary_tree "$cargo_target_dir" fuzz_auto_build \
        "automatic fuzz CARGO_TARGET_DIR" || return 1
    cargo_target_dir=""
    cargo_target_dir_auto=0
}

cleanup_early_fuzz_exit() {
    local status=$? final_status
    final_status="$status"
    trap - EXIT
    cleanup_automatic_build_directory || {
        printf 'failed to remove automatic fuzz CARGO_TARGET_DIR: %s\n' "$cargo_target_dir" >&2
        ((final_status != 0)) || final_status=74
    }
    exit "$final_status"
}

stage_authenticated_executable() {
    local source_path="$1" destination="$2" label="$3"
    local source_fd source_digest staged_digest
    exec {source_fd}<"$source_path" || die "cannot open selected $label executable"
    source_digest="$(campaign_sha256 "/proc/self/fd/$source_fd")" ||
        die "cannot hash opened $label executable"
    install -m 0500 -- "/proc/self/fd/$source_fd" "$destination" ||
        die "cannot stage authenticated $label executable"
    staged_digest="$(campaign_sha256 "$destination")" || die "cannot hash staged $label executable"
    [[ "$staged_digest" == "$source_digest" ]] || die "staged $label bytes differ from opened executable"
    exec {source_fd}<&-
    printf '%s\n' "$staged_digest"
}

rustc_runtime_tree_digest() {
    local tree="$1"
    [[ -d "$tree" && ! -L "$tree" ]] || return 1
    [[ -z "$(find "$tree" -xdev \( -type l -o \! -type f \! -type d \) -print -quit)" ]] || return 1
    (
        cd "$tree"
        find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum -b -z
    ) | sha256sum | awk '{ print $1 }'
}

snapshot_rustc_runtime_tree() {
    [[ -n "$authenticated_rustc_library_dir" ]] || return 0
    local source_digest_before source_digest_after snapshot_digest
    source_digest_before="$(rustc_runtime_tree_digest "$authenticated_rustc_library_dir")" ||
        die "cannot authenticate selected rustc runtime tree"
    mkdir -m 0700 "$authenticated_tool_root/lib" || die "cannot create rustc runtime snapshot root"
    if ! cp -a --reflink=auto -- "$authenticated_rustc_library_dir/." "$authenticated_tool_root/lib/"; then
        rm -rf -- "${authenticated_tool_root:?}/lib"
        mkdir -m 0700 "$authenticated_tool_root/lib" || die "cannot recreate rustc runtime snapshot root"
        cp -a -- "$authenticated_rustc_library_dir/." "$authenticated_tool_root/lib/" ||
            die "cannot snapshot selected rustc runtime tree"
    fi
    snapshot_digest="$(rustc_runtime_tree_digest "$authenticated_tool_root/lib")" ||
        die "cannot authenticate snapshotted rustc runtime tree"
    source_digest_after="$(rustc_runtime_tree_digest "$authenticated_rustc_library_dir")" ||
        die "cannot re-authenticate selected rustc runtime tree"
    [[ "$source_digest_before" == "$source_digest_after" && "$snapshot_digest" == "$source_digest_before" ]] ||
        die "selected rustc runtime tree changed while it was snapshotted"
    authenticated_rustc_library_tree_identity="$(stat -Lc '%d:%i' -- "$authenticated_tool_root/lib")" ||
        die "cannot identify rustc runtime snapshot root"
    authenticated_rustc_library_tree_sha256="$snapshot_digest"
}

prepare_authenticated_rust_tools() {
    authenticated_tool_root="$(mktemp -d "$cargo_target_dir/.authenticated-rust-tools.XXXXXX")" ||
        die "cannot create private Rust tool execution directory"
    chmod 0700 "$authenticated_tool_root"
    authenticated_tool_dir="$authenticated_tool_root/bin"
    mkdir -m 0700 "$authenticated_tool_dir" || die "cannot create authenticated Rust tool bin directory"
    snapshot_rustc_runtime_tree
    authenticated_cargo_path="$authenticated_tool_dir/cargo"
    authenticated_rustc_path="$authenticated_tool_dir/rustc"
    authenticated_cargo_fuzz_path="$authenticated_tool_dir/cargo-fuzz"
    authenticated_cargo_sha256="$(stage_authenticated_executable \
        "$selected_cargo_path" "$authenticated_cargo_path" cargo)"
    authenticated_rustc_sha256="$(stage_authenticated_executable \
        "$selected_rustc_path" "$authenticated_rustc_path" rustc)"
    authenticated_cargo_fuzz_sha256="$(stage_authenticated_executable \
        "$selected_cargo_fuzz_path" "$authenticated_cargo_fuzz_path" cargo-fuzz)"
    authenticated_cargo_identity="$(stat -Lc '%d:%i' -- "$authenticated_cargo_path")" ||
        die "cannot identify staged cargo executable"
    authenticated_rustc_identity="$(stat -Lc '%d:%i' -- "$authenticated_rustc_path")" ||
        die "cannot identify staged rustc executable"
    authenticated_cargo_fuzz_identity="$(stat -Lc '%d:%i' -- "$authenticated_cargo_fuzz_path")" ||
        die "cannot identify staged cargo-fuzz executable"
    export RUSTC="$authenticated_rustc_path"
    verify_authenticated_rust_tools
}

verify_authenticated_executable() {
    local path="$1" identity="$2" digest="$3" label="$4"
    [[ -f "$path" && ! -L "$path" && -x "$path" ]] || die "authenticated $label path is unsafe"
    [[ "$(stat -Lc '%d:%i' -- "$path")" == "$identity" ]] || die "authenticated $label inode changed"
    [[ "$(campaign_sha256 "$path")" == "$digest" ]] || die "authenticated $label content changed"
}

verify_authenticated_rust_tools() {
    campaign_require_owned_real_directory "$authenticated_tool_dir" "authenticated Rust tool directory" ||
        die "authenticated Rust tool directory is unsafe"
    verify_authenticated_executable "$authenticated_cargo_path" "$authenticated_cargo_identity" \
        "$authenticated_cargo_sha256" cargo
    verify_authenticated_executable "$authenticated_rustc_path" "$authenticated_rustc_identity" \
        "$authenticated_rustc_sha256" rustc
    verify_authenticated_executable "$authenticated_cargo_fuzz_path" "$authenticated_cargo_fuzz_identity" \
        "$authenticated_cargo_fuzz_sha256" cargo-fuzz
    if [[ -n "$authenticated_rustc_library_dir" ]]; then
        [[ -d "$authenticated_tool_root/lib" && ! -L "$authenticated_tool_root/lib" &&
            "$(stat -Lc '%d:%i' -- "$authenticated_tool_root/lib")" == "$authenticated_rustc_library_tree_identity" ]] ||
            die "authenticated rustc runtime snapshot identity changed"
        [[ "$(rustc_runtime_tree_digest "$authenticated_tool_root/lib")" == "$authenticated_rustc_library_tree_sha256" ]] ||
            die "authenticated rustc runtime snapshot content changed"
    fi
    [[ "$(PATH="$authenticated_tool_dir" command -v cargo)" == "$authenticated_cargo_path" ]] ||
        die "authenticated cargo cannot be resolved exclusively"
    [[ "$(PATH="$authenticated_tool_dir" command -v rustc)" == "$authenticated_rustc_path" ]] ||
        die "authenticated rustc cannot be resolved exclusively"
    [[ "$(PATH="$authenticated_tool_dir" command -v cargo-fuzz)" == "$authenticated_cargo_fuzz_path" ]] ||
        die "authenticated cargo-fuzz cannot be resolved exclusively"
}

authenticated_tool_path() {
    printf '%s:%s' "$authenticated_tool_dir" "$PATH"
}

write_fuzz_artifact_manifests() {
    local staged list path relative digest manifest_failed=0
    list="$(mktemp "$evidence_dir/.build-artifact-list.XXXXXX")" || return 1
    staged="$(mktemp "$evidence_dir/.build-artifacts.XXXXXX")" || {
        rm -f "$list"
        return 1
    }
    if [[ -d "$cargo_target_dir" && ! -L "$cargo_target_dir" ]]; then
        if ! find "$cargo_target_dir" -type f -perm /111 -print0 | sort -z >"$list"; then
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
        ! -path "$evidence_dir/.build-artifact-list.*" -print0 | sort -z >"$list"; then
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

publish_fuzz_completion() {
    local marker="$evidence_dir/campaign-completed.env"
    local staged completion_status completed_utc summary_digest manifest_digest
    staged="$(mktemp "$evidence_dir/.campaign-completed.XXXXXX")" || return 1
    completed_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" || {
        rm -f "$staged"
        return 1
    }
    summary_digest="$(campaign_sha256 "$evidence_dir/campaign-summary.tsv")" || {
        rm -f "$staged"
        return 1
    }
    manifest_digest="$(campaign_sha256 "$evidence_dir/artifact-manifest.sha256")" || {
        rm -f "$staged"
        return 1
    }
    completion_status=passed
    if ((dry_run)); then
        completion_status=dry-run
    elif [[ "$release_eligible" != 1 ]]; then
        completion_status=non-release-diagnostic
    fi
    {
        printf 'status=%s\n' "$completion_status"
        printf 'completed_utc=%s\n' "$completed_utc"
        printf 'target_count=%s\n' "${#selected_targets[@]}"
        printf 'summary_sha256=%s\n' "$summary_digest"
        printf 'artifact_manifest_sha256=%s\n' "$manifest_digest"
    } >"$staged" || {
        rm -f "$staged"
        return 1
    }
    mv "$staged" "$marker"
}

finalize_campaign_evidence() {
    local status=$?
    local final_status="$status"
    trap - EXIT
    if [[ -d "$evidence_dir" ]]; then
        write_fuzz_artifact_manifests || {
            printf 'failed to finalize fuzz evidence manifests: %s\n' "$evidence_dir" >&2
            ((final_status != 0)) || final_status=74
        }
        cleanup_automatic_build_directory || {
            printf 'failed to remove automatic fuzz CARGO_TARGET_DIR: %s\n' "$cargo_target_dir" >&2
            ((final_status != 0)) || final_status=74
        }
        if ((final_status == 0)); then
            publish_fuzz_completion || {
                printf 'failed to publish fuzz completion marker: %s\n' "$evidence_dir" >&2
                final_status=74
            }
        fi
        if ((final_status == 0 && dry_run == 0)) && [[ "$release_eligible" != 1 ]]; then
            printf 'dirty-source diagnostic evidence is never authoritative fuzz evidence: %s\n' "$evidence_dir" >&2
            final_status=2
        fi
    else
        cleanup_automatic_build_directory || {
            printf 'failed to remove automatic fuzz CARGO_TARGET_DIR: %s\n' "$cargo_target_dir" >&2
            ((final_status != 0)) || final_status=74
        }
    fi
    exit "$final_status"
}

write_summary_header() {
    printf 'target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file\n' \
        >"$evidence_dir/campaign-summary.tsv"
}

append_summary_row() {
    local target="$1"
    local status="$2"
    local exit_status="$3"
    local started_epoch="$4"
    local ended_epoch="$5"
    local elapsed_nanoseconds="$6"
    local log_path="$7"
    local artifact_dir="$8"
    local command_file="$9"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$status" "$exit_status" "$duration" "$started_epoch" "$ended_epoch" "$elapsed_nanoseconds" \
        "${log_path#"$evidence_dir"/}" "${artifact_dir#"$evidence_dir"/}" \
        "${command_file#"$evidence_dir"/}" \
        >>"$evidence_dir/campaign-summary.tsv"
}

write_config() {
    local config_file="$1"
    {
        printf 'duration_seconds=%s\n' "$duration"
        printf 'wall_clock_grace_seconds=%s\n' "$fuzz_wall_clock_grace"
        printf 'wall_clock_kill_after_seconds=%s\n' "$fuzz_wall_clock_kill_after"
        printf 'minimum_elapsed_tolerance_nanoseconds=%s\n' "$fuzz_elapsed_tolerance_nanoseconds"
        printf 'wall_monotonic_tolerance_nanoseconds=%s\n' "$fuzz_wall_monotonic_tolerance_nanoseconds"
        printf 'preflight_timeout_seconds=%s\n' "$fuzz_probe_timeout"
        printf 'preflight_kill_after_seconds=%s\n' "$fuzz_probe_kill_after"
        printf 'evidence_dir=%s\n' "$evidence_dir"
        printf 'dry_run=%s\n' "$dry_run"
        printf 'cargo=%s\n' "$cargo_bin"
        printf 'cargo_target_dir=%s\n' "$cargo_target_dir"
        printf 'cargo_toolchain=%s\n' "${cargo_toolchain:-default}"
        printf 'cargo_sha256=%s\n' "$authenticated_cargo_sha256"
        printf 'cargo_executed_sha256=%s\n' "$authenticated_cargo_sha256"
        printf 'rustc_sha256=%s\n' "$authenticated_rustc_sha256"
        printf 'rustc_executed_sha256=%s\n' "$authenticated_rustc_sha256"
        printf 'rustc_runtime_library_dir=%s\n' "${authenticated_rustc_library_dir:-unresolved}"
        printf 'rustc_runtime_tree_sha256=%s\n' "${authenticated_rustc_library_tree_sha256:-unresolved}"
        printf 'cargo_fuzz_sha256=%s\n' "$authenticated_cargo_fuzz_sha256"
        printf 'cargo_fuzz_executed_sha256=%s\n' "$authenticated_cargo_fuzz_sha256"
        printf 'sanitizer=%s\n' "${sanitizer:-cargo-fuzz-default}"
        printf 'targets=%s\n' "${selected_targets[*]}"
        printf 'source_commit=%s\n' "$initial_source_commit"
        printf 'source_clean=%s\n' "$source_clean"
        printf 'release_eligible=%s\n' "$release_eligible"
        printf 'dirty_source_override=%s\n' "$allow_dirty_non_release"
    } >"$config_file"
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
        --all)
            all_targets=1
            shift
            ;;
        --target)
            (($# >= 2)) || die "--target requires a value"
            selected_targets+=("$2")
            shift 2
            ;;
        --duration)
            (($# >= 2)) || die "--duration requires a value"
            duration="$2"
            shift 2
            ;;
        --evidence-dir)
            (($# >= 2)) || die "--evidence-dir requires a value"
            evidence_dir="$2"
            shift 2
            ;;
        --toolchain)
            (($# >= 2)) || die "--toolchain requires a value"
            cargo_toolchain="$2"
            shift 2
            ;;
        --sanitizer)
            (($# >= 2)) || die "--sanitizer requires a value"
            sanitizer="$2"
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        --list-targets)
            list_targets=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            while (($# > 0)); do
                selected_targets+=("$1")
                shift
            done
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            selected_targets+=("$1")
            shift
            ;;
        esac
    done
}

select_targets() {
    local target
    local -A seen_targets=()
    if ((list_targets)); then
        printf '%s\n' "${known_targets[@]}"
        exit 0
    fi

    if ((all_targets)) && ((${#selected_targets[@]} > 0)); then
        die "use --all or select explicit targets, not both"
    fi

    if ((all_targets)) || ((${#selected_targets[@]} == 0)); then
        selected_targets=("${known_targets[@]}")
    fi

    for target in "${selected_targets[@]}"; do
        contains_target "$target" || die "unknown fuzz target: $target"
        [[ -z "${seen_targets[$target]:-}" ]] || die "duplicate fuzz target: $target"
        seen_targets[$target]=1
    done
}

run_target() {
    local target="$1"
    local target_log="$evidence_dir/logs/$target.log"
    local artifact_dir="$evidence_dir/artifacts/$target"
    local corpus_dir="$evidence_dir/corpus/$target"
    local command_file="$evidence_dir/logs/$target.command"
    local -a cmd

    campaign_prepare_contained_directory "$evidence_dir/artifacts" "$artifact_dir" "target artifact directory" ||
        die "unsafe target artifact directory: $target"
    if [[ ! -e "$evidence_dir/corpus" ]]; then
        mkdir "$evidence_dir/corpus"
    fi
    campaign_require_owned_real_directory "$evidence_dir/corpus" "fuzz corpus root" || die "unsafe fuzz corpus root"
    campaign_prepare_contained_directory "$evidence_dir/corpus" "$corpus_dir" "target corpus directory" ||
        die "unsafe target corpus directory: $target"
    cmd=("$authenticated_cargo_path" fuzz run)
    if [[ -n "$sanitizer" ]]; then
        # Recent nightly compilers reject mixing an instrumented fuzz crate
        # with an uninstrumented prebuilt standard library (notably for
        # ThreadSanitizer). Build std with the same sanitizer whenever the
        # caller explicitly selects one.
        cmd+=(--sanitizer "$sanitizer" --build-std)
    fi
    cmd+=(
        "$target"
        "$corpus_dir"
        --
        "-max_total_time=$duration"
        "-artifact_prefix=$artifact_dir/"
    )

    {
        printf 'target=%s\n' "$target"
        printf 'command='
        printf '%q ' "${cmd[@]}"
        printf '\n'
    } >"$command_file"

    if ((dry_run)); then
        printf 'DRY RUN: '
        printf '%q ' "${cmd[@]}"
        printf '\n'
        local dry_run_epoch
        dry_run_epoch="$(date +%s)"
        append_summary_row "$target" "dry-run" "0" "$dry_run_epoch" "$dry_run_epoch" 0 "$target_log" "$artifact_dir" "$command_file"
        return 0
    fi

    printf 'Running %s for %ss; log: %s\n' "$target" "$duration" "$target_log"
    verify_authenticated_rust_tools
    local wall_clock_timeout=$((duration + fuzz_wall_clock_grace))
    local started_epoch ended_epoch started_monotonic ended_monotonic elapsed_nanoseconds target_status
    started_epoch="$(date +%s)"
    started_monotonic="$(monotonic_nanoseconds)" || die "cannot capture monotonic fuzz start time"
    set +e
    (
        cd "$repo_root"
        timeout --preserve-status --kill-after="$fuzz_wall_clock_kill_after" "$wall_clock_timeout" \
            env PATH="$(authenticated_tool_path)" "${cmd[@]}"
    ) >"$target_log" 2>&1
    target_status=$?
    set -e
    ended_monotonic="$(monotonic_nanoseconds)" || die "cannot capture monotonic fuzz end time"
    ended_epoch="$(date +%s)"
    elapsed_nanoseconds=$((ended_monotonic - started_monotonic))
    ((elapsed_nanoseconds >= 0)) || die "monotonic fuzz execution clock moved backwards"
    if ((target_status != 0)); then
        append_summary_row "$target" "failed" "$target_status" "$started_epoch" "$ended_epoch" "$elapsed_nanoseconds" "$target_log" "$artifact_dir" "$command_file"
        printf 'target failed: %s (exit %s)\n' "$target" "$target_status" >&2
        printf -- '---- %s tail ----\n' "$target_log" >&2
        tail -120 "$target_log" >&2 || true
        return "$target_status"
    fi
    local minimum_elapsed_nanoseconds=$((duration * 1000000000 - fuzz_elapsed_tolerance_nanoseconds))
    local wall_elapsed_seconds=$((ended_epoch - started_epoch))
    local minimum_wall_seconds=$((duration - 1))
    ((minimum_wall_seconds >= 1)) || minimum_wall_seconds=1
    if ((wall_elapsed_seconds < minimum_wall_seconds)); then
        append_summary_row "$target" "failed" 70 "$started_epoch" "$ended_epoch" "$elapsed_nanoseconds" "$target_log" "$artifact_dir" "$command_file"
        printf 'target wall-clock window was shorter than its authenticated duration: %s wall_seconds=%s required_seconds=%s\n' \
            "$target" "$wall_elapsed_seconds" "$minimum_wall_seconds" >&2
        return 70
    fi
    if ((elapsed_nanoseconds < minimum_elapsed_nanoseconds)); then
        append_summary_row "$target" "failed" 70 "$started_epoch" "$ended_epoch" "$elapsed_nanoseconds" "$target_log" "$artifact_dir" "$command_file"
        printf 'target exited successfully before its authenticated duration: %s elapsed_ns=%s required_ns=%s\n' \
            "$target" "$elapsed_nanoseconds" "$minimum_elapsed_nanoseconds" >&2
        return 70
    fi
    local wall_elapsed_nanoseconds=$((wall_elapsed_seconds * 1000000000))
    if ((elapsed_nanoseconds + fuzz_wall_monotonic_tolerance_nanoseconds < wall_elapsed_nanoseconds || \
        elapsed_nanoseconds > wall_elapsed_nanoseconds + fuzz_wall_monotonic_tolerance_nanoseconds)); then
        append_summary_row "$target" "failed" 70 "$started_epoch" "$ended_epoch" "$elapsed_nanoseconds" "$target_log" "$artifact_dir" "$command_file"
        printf 'target wall and monotonic clocks disagree beyond evidence tolerance: %s wall_ns=%s elapsed_ns=%s tolerance_ns=%s\n' \
            "$target" "$wall_elapsed_nanoseconds" "$elapsed_nanoseconds" \
            "$fuzz_wall_monotonic_tolerance_nanoseconds" >&2
        return 70
    fi
    verify_authenticated_rust_tools
    append_summary_row "$target" "passed" "0" "$started_epoch" "$ended_epoch" "$elapsed_nanoseconds" "$target_log" "$artifact_dir" "$command_file"
}

main() {
    parse_args "$@"
    discover_targets
    validate_timing_bounds
    select_targets
    capture_source_identity

    resolve_rust_tools
    trap cleanup_early_fuzz_exit EXIT
    prepare_build_directory
    prepare_authenticated_rust_tools
    verify_source_identity "before evidence initialization"
    prepare_evidence_directory
    trap finalize_campaign_evidence EXIT
    write_config "$evidence_dir/config.txt"
    record_versions "$evidence_dir/tool-versions.txt"
    write_summary_header

    if ((!dry_run)); then
        verify_authenticated_rust_tools
        if [[ -n "$cargo_toolchain" ]]; then
            command -v rustup >/dev/null 2>&1 || die "rustup not found on PATH"
            PATH="$(authenticated_tool_path)" \
                run_fuzz_probe "$authenticated_cargo_path" fuzz --version >/dev/null 2>&1 ||
                die "cargo-fuzz is not installed or not runnable with toolchain $cargo_toolchain"
        else
            env PATH="$(authenticated_tool_path)" timeout --preserve-status --kill-after="$fuzz_probe_kill_after" \
                "$fuzz_probe_timeout" "$authenticated_cargo_path" fuzz --version >/dev/null 2>&1 ||
                die "cargo-fuzz is not installed or not runnable"
        fi
        verify_authenticated_rust_tools
    fi

    local target
    for target in "${selected_targets[@]}"; do
        verify_source_identity "before target $target"
        run_target "$target"
        verify_source_identity "after target $target"
    done

    verify_source_identity "terminal publication"

    printf 'fuzz evidence retained at %s\n' "$evidence_dir"
}

main "$@"
