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
  --toolchain TOOLCHAIN  Run cargo through rustup with this toolchain
  --sanitizer NAME       Pass a cargo-fuzz sanitizer mode, for example address or thread
  --dry-run              Write config and print commands without running cargo fuzz
  --list-targets         Print known targets and exit
  -h, --help             Show this help

Environment:
  CARGO                  Cargo executable to use (default: cargo)
  CARGO_TOOLCHAIN        Optional rustup toolchain, for example nightly
  CARGO_FUZZ_SANITIZER   Optional cargo-fuzz sanitizer mode
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_targets_dir="$repo_root/fuzz/fuzz_targets"
default_duration=10
duration="$default_duration"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="$repo_root/target/fuzz-evidence/$timestamp"
dry_run=0
list_targets=0
all_targets=0
cargo_bin="${CARGO:-cargo}"
cargo_toolchain="${CARGO_TOOLCHAIN:-}"
sanitizer="${CARGO_FUZZ_SANITIZER:-}"
selected_targets=()
known_targets=()

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

cargo_path_prefix_dir() {
    if [[ "$cargo_bin" == */* ]]; then
        cd "$(dirname "$cargo_bin")" && pwd
    elif [[ -n "$cargo_toolchain" ]] && command -v rustup >/dev/null 2>&1; then
        local selected_cargo
        selected_cargo="$(rustup which --toolchain "$cargo_toolchain" cargo 2>/dev/null || true)"
        if [[ -n "$selected_cargo" ]]; then
            cd "$(dirname "$selected_cargo")" && pwd
        fi
    fi
}

record_versions() {
    local versions_file="$1"
    local cargo_dir
    cargo_dir="$(cargo_path_prefix_dir)"
    {
        printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'repo_root=%s\n' "$repo_root"
        printf 'cargo=%s\n' "$cargo_bin"
        printf 'cargo_toolchain=%s\n' "${cargo_toolchain:-default}"
        if [[ -n "$cargo_toolchain" ]]; then
            if command -v rustup >/dev/null 2>&1; then
                PATH="${cargo_dir:+$cargo_dir:}$PATH" rustup run "$cargo_toolchain" "$cargo_bin" --version
                PATH="${cargo_dir:+$cargo_dir:}$PATH" rustup run "$cargo_toolchain" "$cargo_bin" fuzz --version 2>&1 || true
                rustup run "$cargo_toolchain" rustc --version 2>&1 || true
            else
                printf 'rustup not found on PATH\n'
            fi
        elif command -v "$cargo_bin" >/dev/null 2>&1; then
            PATH="${cargo_dir:+$cargo_dir:}$PATH" "$cargo_bin" --version
            PATH="${cargo_dir:+$cargo_dir:}$PATH" "$cargo_bin" fuzz --version 2>&1 || true
        else
            printf '%s not found on PATH\n' "$cargo_bin"
        fi
        if command -v rustc >/dev/null 2>&1; then
            rustc --version
        else
            printf 'rustc not found on PATH\n'
        fi
        if command -v rustup >/dev/null 2>&1; then
            rustup show active-toolchain 2>&1 || true
        else
            printf 'rustup not found on PATH\n'
        fi
    } >"$versions_file"
}

write_summary_header() {
    printf 'target\tstatus\texit_status\tduration_seconds\tlog_path\tartifact_dir\tcommand_file\n' \
        >"$evidence_dir/campaign-summary.tsv"
}

append_summary_row() {
    local target="$1"
    local status="$2"
    local exit_status="$3"
    local log_path="$4"
    local artifact_dir="$5"
    local command_file="$6"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$status" "$exit_status" "$duration" "$log_path" "$artifact_dir" "$command_file" \
        >>"$evidence_dir/campaign-summary.tsv"
}

write_config() {
    local config_file="$1"
    {
        printf 'duration_seconds=%s\n' "$duration"
        printf 'evidence_dir=%s\n' "$evidence_dir"
        printf 'dry_run=%s\n' "$dry_run"
        printf 'cargo=%s\n' "$cargo_bin"
        printf 'cargo_toolchain=%s\n' "${cargo_toolchain:-default}"
        printf 'sanitizer=%s\n' "${sanitizer:-cargo-fuzz-default}"
        printf 'targets=%s\n' "${selected_targets[*]}"
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
    done
}

run_target() {
    local target="$1"
    local target_log="$evidence_dir/logs/$target.log"
    local artifact_dir="$evidence_dir/artifacts/$target"
    local corpus_dir="$evidence_dir/corpus/$target"
    local command_file="$evidence_dir/logs/$target.command"
    local -a cmd

    mkdir -p "$artifact_dir" "$corpus_dir"
    if [[ -n "$cargo_toolchain" ]]; then
        cmd=(
            rustup run "$cargo_toolchain" "$cargo_bin" fuzz run
        )
    else
        cmd=(
            "$cargo_bin" fuzz run
        )
    fi
    if [[ -n "$sanitizer" ]]; then
        cmd+=(--sanitizer "$sanitizer")
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
        append_summary_row "$target" "dry-run" "0" "$target_log" "$artifact_dir" "$command_file"
        return 0
    fi

    printf 'Running %s for %ss; log: %s\n' "$target" "$duration" "$target_log"
    (
        cd "$repo_root"
        local cargo_dir
        cargo_dir="$(cargo_path_prefix_dir)"
        if [[ -n "$cargo_dir" ]]; then
            env PATH="$cargo_dir:$PATH" "${cmd[@]}"
        else
            "${cmd[@]}"
        fi
    ) >"$target_log" 2>&1 || {
        local status=$?
        append_summary_row "$target" "failed" "$status" "$target_log" "$artifact_dir" "$command_file"
        printf 'target failed: %s (exit %s)\n' "$target" "$status" >&2
        printf -- '---- %s tail ----\n' "$target_log" >&2
        tail -120 "$target_log" >&2 || true
        return "$status"
    }
    append_summary_row "$target" "passed" "0" "$target_log" "$artifact_dir" "$command_file"
}

main() {
    parse_args "$@"
    discover_targets
    require_positive_integer "--duration" "$duration"
    select_targets

    mkdir -p "$evidence_dir/logs" "$evidence_dir/artifacts"
    write_config "$evidence_dir/config.txt"
    record_versions "$evidence_dir/tool-versions.txt"
    write_summary_header

    if ((!dry_run)); then
        local cargo_dir
        cargo_dir="$(cargo_path_prefix_dir)"
        if [[ -n "$cargo_toolchain" ]]; then
            command -v rustup >/dev/null 2>&1 || die "rustup not found on PATH"
            env PATH="${cargo_dir:+$cargo_dir:}$PATH" \
                rustup run "$cargo_toolchain" "$cargo_bin" fuzz --version >/dev/null 2>&1 ||
                die "cargo-fuzz is not installed or not runnable with toolchain $cargo_toolchain"
        else
            command -v "$cargo_bin" >/dev/null 2>&1 || die "$cargo_bin not found on PATH"
            env PATH="${cargo_dir:+$cargo_dir:}$PATH" "$cargo_bin" fuzz --version >/dev/null 2>&1 ||
                die "cargo-fuzz is not installed or not runnable"
        fi
    fi

    local target
    for target in "${selected_targets[@]}"; do
        run_target "$target"
    done

    printf 'fuzz evidence retained at %s\n' "$evidence_dir"
}

main "$@"
