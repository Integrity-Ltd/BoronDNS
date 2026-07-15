#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/oxidedns-package-recovery.XXXXXX")"
cleanup() {
    local status=$?
    trap - EXIT
    trap '' INT TERM HUP
    rm -rf -- "$workdir"
    exit "$status"
}
trap cleanup EXIT

real_python="$(command -v python3)"
fake_bin="$workdir/bin"
mkdir -m 0700 "$fake_bin"
cat >"$fake_bin/python3" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == - ]]
shift
source_file="$(mktemp "${TMPDIR:-/tmp}/oxidedns-package-recovery-source.XXXXXX")"
combined_file="$(mktemp "${TMPDIR:-/tmp}/oxidedns-package-recovery-combined.XXXXXX")"
cleanup_wrapper() {
    rm -f -- "$source_file" "$combined_file"
}
trap cleanup_wrapper EXIT
cat >"$source_file"
cat >"$combined_file" <<'PY'
import os
import signal

fault_mode = os.environ["PACKAGE_RECOVERY_FAULT_MODE"]
fault_state = os.environ["PACKAGE_RECOVERY_FAULT_STATE"]
real_write = os.write
real_fsync = os.fsync
write_fired = False
fsync_fired = False


def injected_write(fd, payload):
    global write_fired
    if not write_fired and fault_mode in {"write", "signal", "foreign"}:
        write_fired = True
        prefix = payload[: min(7, len(payload))]
        if prefix:
            real_write(fd, prefix)
        if fault_mode == "write":
            raise OSError("injected package recovery write failure")
        if fault_mode == "signal":
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("SIGTERM handler returned")
        path = os.readlink(f"/proc/self/fd/{fd}")
        displaced = path + ".owned-displaced"
        os.rename(path, displaced)
        with open(path, "wb") as replacement:
            replacement.write(b"foreign replacement\n")
            replacement.flush()
            real_fsync(replacement.fileno())
        with open(fault_state, "w", encoding="utf-8") as marker:
            marker.write(path + "\n" + displaced + "\n")
        raise OSError("injected package recovery pathname replacement")
    return real_write(fd, payload)


def injected_fsync(fd):
    global fsync_fired
    if not fsync_fired and fault_mode == "fsync":
        fsync_fired = True
        raise OSError("injected package recovery fsync failure")
    return real_fsync(fd)


os.write = injected_write
os.fsync = injected_fsync
PY
cat "$source_file" >>"$combined_file"
status=0
"${PACKAGE_RECOVERY_REAL_PYTHON:?}" "$combined_file" "$@" || status=$?
if ((status == 0)); then
    case "${PACKAGE_RECOVERY_TRANSPORT_SUFFIX:-}" in
    empty-nul) printf '\0' ;;
    partial) printf 'trailing-partial' ;;
    esac
fi
exit "$status"
WRAPPER
chmod 0755 "$fake_bin/python3"

run_fault_case() {
    local mode="$1"
    local root="$workdir/$mode"
    local retain_root="$root/run"
    local fault_state="$root/fault-state"
    mkdir -p "$retain_root"

    set +e
    PATH="$fake_bin:$PATH" \
        PACKAGE_RECOVERY_REAL_PYTHON="$real_python" \
        PACKAGE_RECOVERY_FAULT_MODE="$mode" \
        PACKAGE_RECOVERY_FAULT_STATE="$fault_state" \
        bash -c '
            set -euo pipefail
            source "$1"
            package_publication_reset "$2"
            package_write_publication_recovery_diagnostic
        ' package-recovery-fault "$repo_root/scripts/package-common.sh" "$retain_root" \
        >"$root/run.log" 2>&1
    local status=$?
    set -e
    ((status != 0)) || {
        printf 'package recovery fault case unexpectedly succeeded: %s\n' "$mode" >&2
        return 1
    }
    [[ -z "$(find "$retain_root" -maxdepth 1 -type f \
        -name 'publication-recovery-*.env' -print -quit)" ]] || {
        printf 'package recovery fault published a partial public diagnostic: %s\n' "$mode" >&2
        return 1
    }

    if [[ "$mode" == foreign ]]; then
        local replacement displaced
        mapfile -t fault_paths <"$fault_state"
        ((${#fault_paths[@]} == 2))
        replacement="${fault_paths[0]}"
        displaced="${fault_paths[1]}"
        grep -Fqx 'foreign replacement' "$replacement"
        [[ -f "$displaced" ]]
        # Cleanup must neither adopt the pathname replacement nor chase the
        # originally owned inode after another actor moved it to an unknown name.
        [[ "$(stat -c '%d:%i' "$replacement")" != "$(stat -c '%d:%i' "$displaced")" ]]
        grep -Fq 'preserving namespace for privileged/manual reconciliation' "$root/run.log"
    else
        mapfile -t incomplete_paths < <(find "$retain_root" -maxdepth 1 -type f \
            -name '.publication-recovery-incomplete-*' -print)
        ((${#incomplete_paths[@]} == 1)) || {
            printf 'package recovery fault did not retain exactly one hidden staging inode: %s\n' \
                "$mode" >&2
            return 1
        }
        local incomplete_identity parent_identity
        incomplete_identity="$(stat -c '%d:%i:%u' "${incomplete_paths[0]}"):regular file"
        parent_identity="$(stat -c '%d:%i:%u' "$retain_root"):directory"
        grep -Fq "privileged/manual reconciliation: path=${incomplete_paths[0]}" "$root/run.log"
        grep -Fq "identity='$incomplete_identity'" "$root/run.log"
        grep -Fq "parent=$retain_root" "$root/run.log"
        grep -Fq "parent_identity=$parent_identity" "$root/run.log"
    fi
}

for fault_mode in write fsync signal foreign; do
    run_fault_case "$fault_mode"
done

run_transport_cardinality_case() {
    local suffix="$1"
    local expected="$2"
    local root="$workdir/transport-$suffix"
    local log="$root/run.log"
    mkdir -p -- "$root/recovery"
    set +e
    PATH="$fake_bin:$PATH" \
        PACKAGE_RECOVERY_REAL_PYTHON="$real_python" \
        PACKAGE_RECOVERY_FAULT_MODE=none \
        PACKAGE_RECOVERY_FAULT_STATE="$root/unused-state" \
        PACKAGE_RECOVERY_TRANSPORT_SUFFIX="$suffix" \
        bash -c '
            set -euo pipefail
            source "$1"
            package_publication_reset "$2"
            package_write_publication_recovery_diagnostic
        ' package-recovery-transport "$repo_root/scripts/package-common.sh" \
        "$root/recovery" >"$log" 2>&1
    local status=$?
    set -e
    ((status != 0)) || {
        printf 'package recovery transport cardinality case unexpectedly succeeded: %s\n' \
            "$suffix" >&2
        return 1
    }
    grep -Fq "$expected" "$log"
}

run_transport_cardinality_case empty-nul 'extra NUL-delimited field'
run_transport_cardinality_case partial 'trailing partial transport data'

run_durable_quarantine_case() {
    local root="$workdir/durable"
    local retain_root="$root/recovery"
    local first_state="$root/first-state"
    local first_log="$root/first.log"
    mkdir -p "$retain_root"

    bash -c '
        set -euo pipefail
        source "$1"
        root="$2"
        retain_root="$3"
        state="$4"
        printf "original retained object\n" >"$root/artifact"
        original_identity="$(stat -c "%d:%i:%u" "$root/artifact"):regular file"
        package_publication_reset "$retain_root"
        package_capture_publication_file "$root/artifact" "durable evidence fixture"
        package_remove_captured_publication_file "$root/artifact" "durable evidence fixture"
        quarantine="$PACKAGE_LAST_REMOVE_QUARANTINE"
        [[ -n "$quarantine" && "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" == 1 ]]
        package_write_publication_recovery_diagnostic
        diagnostic="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC"
        printf "%s\n%s\n%s\n" "$quarantine" "$diagnostic" "$original_identity" >"$state"
    ' package-recovery-durable "$repo_root/scripts/package-common.sh" "$root" \
        "$retain_root" "$first_state" >"$first_log" 2>&1

    local quarantine diagnostic original_identity parent parent_identity
    local diagnostic_complete=""
    local retained_removal_quarantine_0=""
    local retained_removal_quarantine_0_identity=""
    local retained_removal_quarantine_0_parent=""
    local retained_removal_quarantine_0_parent_identity=""
    mapfile -t first_values <"$first_state"
    ((${#first_values[@]} == 3))
    quarantine="${first_values[0]}"
    diagnostic="${first_values[1]}"
    original_identity="${first_values[2]}"
    parent="${quarantine%/*}"
    parent_identity="$(stat -c '%d:%i:%u' "$parent"):directory"
    [[ -f "$diagnostic" ]]
    # This journal is generated by package-common itself from controlled fixture
    # paths. Source it so shell quoting remains part of the regression surface.
    # shellcheck disable=SC1090
    source "$diagnostic"
    [[ "$diagnostic_complete" == 1 ]]
    [[ "$retained_removal_quarantine_0" == "$quarantine" ]]
    [[ "$retained_removal_quarantine_0_identity" == "$original_identity" ]]
    [[ "$retained_removal_quarantine_0_parent" == "$parent" ]]
    [[ "$retained_removal_quarantine_0_parent_identity" == "$parent_identity" ]]
    grep -Fq "path=$quarantine" "$first_log"
    grep -Fq "identity=${original_identity// /\\ }" "$first_log"
    grep -Fq "parent=$parent" "$first_log"
    grep -Fq "parent_identity=$parent_identity" "$first_log"

    mv -- "$quarantine" "$quarantine.original-displaced"
    printf 'foreign replacement after producer exit\n' >"$quarantine"
    local replacement_identity
    replacement_identity="$(stat -c '%d:%i:%u' "$quarantine"):regular file"
    [[ "$replacement_identity" != "$retained_removal_quarantine_0_identity" ]]
    grep -Fqx 'original retained object' "$quarantine.original-displaced"

    local second_state="$root/second-state"
    bash -c '
        set -euo pipefail
        source "$1"
        root="$2"
        old_quarantine="$3"
        state="$4"
        mkdir "$root/recovery-next"
        package_publication_reset "$root/recovery-next"
        ! package_is_retained_removal_quarantine "$old_quarantine"
        printf "next retained object\n" >"$root/artifact"
        package_capture_publication_file "$root/artifact" "later-run fixture"
        package_remove_captured_publication_file "$root/artifact" "later-run fixture"
        [[ "$PACKAGE_LAST_REMOVE_QUARANTINE" != "$old_quarantine" ]]
        printf "%s\n" "$PACKAGE_LAST_REMOVE_QUARANTINE" >"$state"
    ' package-recovery-later-run "$repo_root/scripts/package-common.sh" "$root" \
        "$quarantine" "$second_state" >"$root/second.log" 2>&1
    grep -Fqx 'foreign replacement after producer exit' "$quarantine"
    [[ "$(<"$second_state")" != "$quarantine" ]]
    grep -Fqx 'next retained object' "$(<"$second_state")"
}

run_nested_rebase_case() {
    local root="$workdir/nested"
    local retain_root="$root/recovery"
    local tree="$root/staging-tree"
    local state="$root/state"
    mkdir -p "$retain_root" "$tree"
    printf 'nested retained object\n' >"$tree/artifact"

    bash -c '
        set -euo pipefail
        source "$1"
        retain_root="$2"
        tree="$3"
        state="$4"
        package_publication_reset "$retain_root"
        package_capture_publication_file "$tree/artifact" "nested evidence fixture"
        package_remove_captured_publication_file "$tree/artifact" "nested evidence fixture"
        inner_identity="${PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[0]}"
        package_capture_cleanup_root "$tree" "outer evidence fixture"
        package_remove_captured_cleanup_root "$tree" "outer evidence fixture"
        [[ "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" == 2 ]]
        [[ "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[0]}" == \
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[1]}/"* ]]
        [[ "${PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[0]}" == "$inner_identity" ]]
        package_write_publication_recovery_diagnostic
        diagnostic="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC"
        printf "%s\n%s\n%s\n" "$diagnostic" \
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[0]}" \
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[1]}" >"$state"
    ' package-recovery-nested "$repo_root/scripts/package-common.sh" "$retain_root" \
        "$tree" "$state" >"$root/run.log" 2>&1

    mapfile -t nested_values <"$state"
    ((${#nested_values[@]} == 3))
    local diagnostic="${nested_values[0]}"
    local diagnostic_complete=""
    local retained_removal_quarantine_0=""
    local retained_removal_quarantine_0_identity=""
    local retained_removal_quarantine_0_parent=""
    local retained_removal_quarantine_0_parent_identity=""
    local retained_removal_quarantine_1=""
    local retained_removal_quarantine_1_identity=""
    local retained_removal_quarantine_1_parent=""
    local retained_removal_quarantine_1_parent_identity=""
    # shellcheck disable=SC1090
    source "$diagnostic"
    [[ "$diagnostic_complete" == 1 ]]
    [[ "$retained_removal_quarantine_0" == "${nested_values[1]}" ]]
    [[ "$retained_removal_quarantine_1" == "${nested_values[2]}" ]]
    [[ "$(stat -c '%d:%i:%u' "$retained_removal_quarantine_0"):regular file" == "$retained_removal_quarantine_0_identity" ]]
    [[ "$(stat -c '%d:%i:%u' "$retained_removal_quarantine_0_parent"):directory" == "$retained_removal_quarantine_0_parent_identity" ]]
    [[ "$(stat -c '%d:%i:%u:%F' "$retained_removal_quarantine_1")" == "$retained_removal_quarantine_1_identity" ]]
    [[ "$(stat -c '%d:%i:%u' "$retained_removal_quarantine_1_parent"):directory" == "$retained_removal_quarantine_1_parent_identity" ]]
    grep -Fq 'nested retained quarantine was rebased' "$root/run.log"
}

run_unverified_replacement_case() {
    local root="$workdir/unverified"
    local state="$root/state"
    mkdir -p "$root"
    printf 'foreign replacement\n' >"$root/victim"
    bash -c '
        set -euo pipefail
        source "$1"
        root="$2"
        state="$3"
        printf "captured object\n" >"$root/artifact"
        package_capture_publication_file "$root/artifact" "unverified fixture"
        package_identity_bound_hook() {
            [[ "$1" == after-quarantine-retain ]] || return 0
            mv -- "$4" "$root/displaced"
            mv -- "$root/victim" "$4"
        }
        status=0
        package_remove_captured_publication_file "$root/artifact" \
            "unverified fixture" || status=$?
        [[ "$status" != 0 ]]
        printf "%s\n%s\n" "$PACKAGE_LAST_REMOVE_QUARANTINE" \
            "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" >"$state"
    ' package-recovery-unverified "$repo_root/scripts/package-common.sh" "$root" \
        "$state" >"$root/run.log" 2>&1
    mapfile -t unverified_values <"$state"
    [[ -z "${unverified_values[0]}" && "${unverified_values[1]}" == 0 ]]
    grep -Fqx 'captured object' "$root/displaced"
    grep -Fqx 'foreign replacement' "$root"/artifact.oxidedns-remove.*
    grep -Fq 'retained quarantine identity changed; preserving the namespace' "$root/run.log"
    if grep -Fq 'identity=' "$root/run.log"; then
        printf 'unverified retained quarantine was reported as an exact identity\n' >&2
        return 1
    fi
}

run_journal_before_rebase_case() {
    local root="$workdir/journal-before-rebase"
    local state="$workdir/journal-before-rebase-state"
    local log="$workdir/journal-before-rebase.log"
    mkdir -p "$root"
    printf 'journal-before-rebase object\n' >"$root/artifact"

    bash -c '
        set -euo pipefail
        source "$1"
        root="$2"
        state="$3"
        package_publication_reset "$root"
        package_capture_publication_file "$root/artifact" \
            "journal-before-rebase fixture"
        package_remove_captured_publication_file "$root/artifact" \
            "journal-before-rebase fixture"
        package_write_publication_recovery_diagnostic
        diagnostic_before="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC"
        package_remove_captured_cleanup_root "$root" \
            "journal-before-rebase outer fixture"
        outer="$PACKAGE_LAST_REMOVE_QUARANTINE"
        diagnostic_after="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC"
        [[ "$diagnostic_after" == "$outer/${diagnostic_before#"$root/"}" ]]
        [[ -f "$diagnostic_after" && ! -L "$diagnostic_after" ]]
        [[ "$(stat -c "%d:%i:%u" "$diagnostic_after"):regular file" == \
            "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY" ]]
        printf "%s\n%s\n%s\n" "$diagnostic_after" \
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[0]}" "$outer" >"$state"
    ' package-recovery-journal-rebase "$repo_root/scripts/package-common.sh" \
        "$root" "$state" >"$log" 2>&1

    mapfile -t rebase_values <"$state"
    ((${#rebase_values[@]} == 3))
    local diagnostic="${rebase_values[0]}"
    local live_inner="${rebase_values[1]}"
    local outer="${rebase_values[2]}"
    local diagnostic_complete=""
    local publication_recovery_root=""
    local publication_recovery_root_identity=""
    local publication_recovery_root_binding=""
    local retained_removal_quarantine_0=""
    local retained_removal_quarantine_0_identity=""
    local retained_removal_quarantine_0_parent=""
    local retained_removal_quarantine_0_parent_identity=""
    local retained_removal_quarantine_0_root_relative=""
    local retained_removal_quarantine_0_parent_root_relative=""
    # shellcheck disable=SC1090
    source "$diagnostic"
    [[ "$diagnostic_complete" == 1 ]]
    [[ "$publication_recovery_root_binding" == journal-parent-directory ]]
    [[ "$publication_recovery_root" == "$root" ]]
    [[ ! -e "$publication_recovery_root" && ! -L "$publication_recovery_root" ]]
    local resolved_root="${diagnostic%/*}"
    [[ "$resolved_root" == "$outer" ]]
    [[ "$(stat -c '%d:%i:%u:%F' "$resolved_root")" == "$publication_recovery_root_identity" ]]
    local resolved="$resolved_root/$retained_removal_quarantine_0_root_relative"
    local resolved_parent="$resolved_root/$retained_removal_quarantine_0_parent_root_relative"
    [[ "$resolved" == "$live_inner" ]]
    [[ "$(stat -c '%d:%i:%u' "$resolved"):regular file" == "$retained_removal_quarantine_0_identity" ]]
    [[ "$(stat -c '%d:%i:%u' "$resolved_parent"):directory" == "$retained_removal_quarantine_0_parent_identity" ]]
    [[ ! -e "$retained_removal_quarantine_0" && ! -L "$retained_removal_quarantine_0" ]]
    grep -Fq 'retained recovery diagnostic was rebased by an outer terminal quarantine' \
        "$log"

    mkdir -p "${retained_removal_quarantine_0%/*}"
    printf 'foreign journal-path replacement\n' >"$retained_removal_quarantine_0"
    [[ "$(stat -c '%d:%i:%u' "$retained_removal_quarantine_0"):regular file" != "$retained_removal_quarantine_0_identity" ]]
    grep -Fqx 'journal-before-rebase object' "$resolved"

    bash -c '
        set -euo pipefail
        source "$1"
        replacement_root="$2"
        old_path="$3"
        resolved_path="$4"
        package_publication_reset "$replacement_root"
        ! package_is_retained_removal_quarantine "$old_path"
        ! package_is_retained_removal_quarantine "$resolved_path"
        grep -Fqx "foreign journal-path replacement" "$old_path"
        grep -Fqx "journal-before-rebase object" "$resolved_path"
    ' package-recovery-journal-later-run "$repo_root/scripts/package-common.sh" \
        "$root" "$retained_removal_quarantine_0" "$resolved"
}

run_delimiter_safe_path_case() {
    local label="$1"
    local retain_root="$2"
    local log="$3"
    mkdir -p -- "$retain_root"

    bash -c '
        set -euo pipefail
        source "$1"
        retain_root="$2"
        next_root="$retain_root-next-run"
        printf "delimiter-safe retained object\n" >"$retain_root/artifact"
        package_publication_reset "$retain_root"
        package_capture_publication_file "$retain_root/artifact" \
            "delimiter-safe fixture"
        package_remove_captured_publication_file "$retain_root/artifact" \
            "delimiter-safe fixture"
        retained="${PACKAGE_RETAINED_REMOVAL_QUARANTINES[0]}"
        package_write_publication_recovery_diagnostic
        diagnostic="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC"
        diagnostic_identity="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY"
        [[ "${diagnostic%/*}" == "$retain_root" ]]
        [[ -f "$diagnostic" && ! -L "$diagnostic" ]]
        [[ "$(stat -c "%d:%i:%u" "$diagnostic"):regular file" == \
            "$diagnostic_identity" ]]
        [[ "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$diagnostic]}" == \
            "$diagnostic_identity" ]]

        diagnostic_complete=""
        publication_recovery_root=""
        retained_removal_quarantine_0=""
        # This producer-controlled file is deliberately sourced to exercise
        # the shell quoting of tab/newline-bearing recovery paths.
        # shellcheck disable=SC1090
        source "$diagnostic"
        [[ "$diagnostic_complete" == 1 ]]
        [[ "$publication_recovery_root" == "$retain_root" ]]
        [[ "$retained_removal_quarantine_0" == "$retained" ]]

        displaced="$diagnostic.owned-displaced"
        mv -- "$diagnostic" "$displaced"
        printf "foreign recovery-path replacement\n" >"$diagnostic"
        [[ "$(stat -c "%d:%i:%u" "$diagnostic"):regular file" != \
            "$diagnostic_identity" ]]
        grep -Fqx "diagnostic_complete=1" "$displaced"
        mkdir -p -- "$next_root"
        package_publication_reset "$next_root"
        [[ -z "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC" ]]
        [[ -z "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$diagnostic]:-}" ]]
        ! package_is_retained_removal_quarantine "$retained"
        grep -Fqx "foreign recovery-path replacement" "$diagnostic"
        grep -Fqx "diagnostic_complete=1" "$displaced"
    ' "package-recovery-$label" "$repo_root/scripts/package-common.sh" "$retain_root" \
        >"$log" 2>&1
    # The retained-quarantine record and the final journal record must each be
    # one physical line even when their path contains a tab or newline.
    [[ "$(wc -l <"$log")" == 2 ]]
    grep -Fq 'package publication recovery diagnostic: ' "$log"
}

run_lock_output_collision_case() {
    local root="$workdir/output-collisions"
    mkdir -p -- "$root/publication"

    bash -c '
        set -euo pipefail
        source "$1"
        publication_root="$2/publication"
        docker_root="$2/docker"
        package_publication_reset "$publication_root"
        root=caller-root-sentinel
        id=caller-id-sentinel
        root_lock_fd=caller-root-lock-fd-sentinel
        publication_target=caller-publication-target-sentinel
        declare -n publication_alias=publication_target
        publication_array=(caller-publication-array-sentinel)
        root_identities_before="$(declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES)"
        root_fds_before="$(declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS)"
        fd_count_before="$(find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf x | wc -c)"

        for collision in root id root_lock_fd; do
            if package_acquire_publication_lock "$publication_root" \
                "collision-$collision" "$collision"; then
                printf "publication output collision unexpectedly succeeded: %s\n" \
                    "$collision" >&2
                exit 1
            fi
        done
        [[ "$root" == caller-root-sentinel ]]
        [[ "$id" == caller-id-sentinel ]]
        [[ "$root_lock_fd" == caller-root-lock-fd-sentinel ]]

        for unassignable in EUID publication_alias publication_array invalid-name; do
            if package_acquire_publication_lock "$publication_root" \
                "unassignable-${unassignable//[^A-Za-z0-9._+-]/-}" "$unassignable"; then
                printf "publication unassignable output unexpectedly succeeded: %s\n" \
                    "$unassignable" >&2
                exit 1
            fi
        done
        [[ "$publication_target" == caller-publication-target-sentinel ]]
        [[ "${publication_array[*]}" == caller-publication-array-sentinel ]]
        [[ ! -e "$publication_root/.oxidedns-package-locks" && \
            ! -L "$publication_root/.oxidedns-package-locks" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES)" == \
            "$root_identities_before" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS)" == \
            "$root_fds_before" ]]
        [[ "$(find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf x | wc -c)" == \
            "$fd_count_before" ]]

        docker_fd=caller-docker-fd-sentinel
        canonical_ref=caller-canonical-sentinel
        OXIDEDNS_PACKAGE_DOCKER_LOCK_ROOT="$docker_root" \
            package_acquire_docker_image_lock oxidedns:test docker_fd canonical_ref && {
                printf "Docker canonical output collision unexpectedly succeeded\n" >&2
                exit 1
            }
        [[ "$docker_fd" == caller-docker-fd-sentinel ]]
        [[ "$canonical_ref" == caller-canonical-sentinel ]]
        [[ ! -e "$docker_root" && ! -L "$docker_root" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES)" == \
            "$root_identities_before" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS)" == \
            "$root_fds_before" ]]
        [[ "$(find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf x | wc -c)" == \
            "$fd_count_before" ]]

        docker_target=caller-docker-target-sentinel
        declare -n docker_alias=docker_target
        docker_array=(caller-docker-array-sentinel)
        for outputs in \
            "EUID docker_canonical" \
            "docker_fd EUID" \
            "docker_alias docker_canonical" \
            "docker_fd docker_alias" \
            "docker_array docker_canonical" \
            "docker_fd docker_array" \
            "invalid-name docker_canonical" \
            "docker_fd invalid-name"; do
            read -r descriptor_output canonical_output <<<"$outputs"
            docker_fd=caller-docker-fd-sentinel
            docker_canonical=caller-docker-canonical-sentinel
            if OXIDEDNS_PACKAGE_DOCKER_LOCK_ROOT="$docker_root" \
                package_acquire_docker_image_lock oxidedns:test \
                    "$descriptor_output" "$canonical_output"; then
                printf "Docker unassignable output unexpectedly succeeded: %s %s\n" \
                    "$descriptor_output" "$canonical_output" >&2
                exit 1
            fi
            [[ "$docker_fd" == caller-docker-fd-sentinel ]]
            [[ "$docker_canonical" == caller-docker-canonical-sentinel ]]
        done
        [[ "$docker_target" == caller-docker-target-sentinel ]]
        [[ "${docker_array[*]}" == caller-docker-array-sentinel ]]
        [[ ! -e "$docker_root" && ! -L "$docker_root" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES)" == \
            "$root_identities_before" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS)" == \
            "$root_fds_before" ]]
        [[ "$(find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf x | wc -c)" == \
            "$fd_count_before" ]]
    ' package-lock-output-collisions "$repo_root/scripts/package-common.sh" "$root"
}

run_publication_root_fifo_swap_case() {
    local root="$workdir/publication-root-fifo-swap"
    mkdir -p -- "$root/publication"

    # The single-quoted program is intentionally evaluated by the isolated child shell.
    # shellcheck disable=SC2016
    timeout --signal=TERM --kill-after=1s 5s bash -c '
        set -euo pipefail
        source "$1"
        publication_root="$2/publication"
        displaced_root="$2/publication.displaced"
        package_publication_reset "$publication_root"
        acquired_fd=caller-fd-sentinel
        root_identities_before="$(declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES)"
        root_fds_before="$(declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS)"
        fd_count_before="$(find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf x | wc -c)"

        package_publication_lock_hook() {
            local phase="$1"
            local hooked_root="$2"
            local expected_identity="$3"
            [[ "$phase" == before-root-open ]]
            [[ "$hooked_root" == "$publication_root" ]]
            [[ "$expected_identity" == "$(stat -c "%d:%i" -- "$publication_root")" ]]
            mv -- "$publication_root" "$displaced_root"
            mkfifo -- "$publication_root"
        }

        set +e
        package_acquire_publication_lock "$publication_root" fifo-swap acquired_fd \
            >"$2/run.log" 2>&1
        lock_status=$?
        set -e
        ((lock_status != 0))
        [[ -p "$publication_root" && -d "$displaced_root" ]]
        [[ "$acquired_fd" == caller-fd-sentinel ]]
        [[ ! -e "$displaced_root/.oxidedns-package-locks" && \
            ! -L "$displaced_root/.oxidedns-package-locks" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES)" == \
            "$root_identities_before" ]]
        [[ "$(declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS)" == \
            "$root_fds_before" ]]
        [[ "$(find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf x | wc -c)" == \
            "$fd_count_before" ]]
    ' package-publication-root-fifo-swap "$repo_root/scripts/package-common.sh" "$root"
}

run_durable_quarantine_case
run_nested_rebase_case
run_unverified_replacement_case
run_journal_before_rebase_case
run_delimiter_safe_path_case tab "$workdir/path-transport/tab"$'\t'root \
    "$workdir/path-transport-tab.log"
run_delimiter_safe_path_case trailing-newline "$workdir/path-transport/newline-root"$'\n' \
    "$workdir/path-transport-newline.log"
run_lock_output_collision_case
run_publication_root_fifo_swap_case

printf 'package publication recovery fault fixtures passed\n'
