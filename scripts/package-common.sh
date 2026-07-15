#!/usr/bin/env bash

# Shared validation for release artifact names and deletion boundaries.
# Callers are expected to enable `set -euo pipefail` before sourcing this file.

# Bash defers a trapped signal while a foreground helper runs. Publication
# operations therefore need a small userspace critical section: the filesystem
# rename/removal and the shell bookkeeping that describes it must become
# visible to EXIT cleanup as one state transition.
PACKAGE_MUTATION_CRITICAL="${PACKAGE_MUTATION_CRITICAL:-0}"
PACKAGE_PENDING_SIGNAL_STATUS="${PACKAGE_PENDING_SIGNAL_STATUS:-0}"
PACKAGE_SIGNAL_CLEANUP_RUNNING="${PACKAGE_SIGNAL_CLEANUP_RUNNING:-0}"
PACKAGE_LAST_MOVE_COMMITTED=0
PACKAGE_LAST_REMOVE_COMMITTED=0
PACKAGE_LAST_RESTORE_COMMITTED=0
PACKAGE_LAST_REMOVE_QUARANTINE=""
PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC=""
PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY=""
declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINES=()
declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES=()
declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS=()
declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES=()

package_signal_handler() {
    local command_status=$?
    local status="$1"
    if [[ "$PACKAGE_MUTATION_CRITICAL" == 1 || "$PACKAGE_SIGNAL_CLEANUP_RUNNING" == 1 ]]; then
        if [[ "$PACKAGE_PENDING_SIGNAL_STATUS" == 0 ]]; then
            PACKAGE_PENDING_SIGNAL_STATUS="$status"
        fi
        return "$command_status"
    fi
    exit "$status"
}

package_begin_mutation_critical() {
    [[ "$PACKAGE_MUTATION_CRITICAL" == 0 ]] || {
        printf 'nested package mutation critical section\n' >&2
        return 70
    }
    PACKAGE_MUTATION_CRITICAL=1
}

package_end_mutation_critical() {
    local pending_status="$PACKAGE_PENDING_SIGNAL_STATUS"
    PACKAGE_MUTATION_CRITICAL=0
    if [[ "$pending_status" != 0 ]]; then
        PACKAGE_PENDING_SIGNAL_STATUS=0
        exit "$pending_status"
    fi
}

# EXIT cleanup is deliberately non-reentrant. In particular, a second TERM
# must not interrupt rollback after the first TERM has selected the exit code.
package_begin_signal_cleanup() {
    PACKAGE_SIGNAL_CLEANUP_RUNNING=1
    trap '' INT TERM HUP
}

package_require_safe_component() {
    local label="$1"
    local value="$2"
    local pattern="${3:-^[A-Za-z0-9][A-Za-z0-9._+-]*$}"
    if [[ -z "$value" || "$value" == "." || "$value" == ".." || ! "$value" =~ $pattern ]]; then
        printf '%s must be a canonical safe basename component: %s\n' "$label" "$value" >&2
        return 1
    fi
}

# Output parameters are assigned with ``printf -v`` after a lock has been
# acquired. Bash resolves that name through dynamically scoped function locals,
# so a caller-provided name that aliases any local in the lock helper stack can
# silently receive the descriptor in the wrong scope. Reject those names before
# opening a descriptor or creating a lock namespace.
package_require_noncolliding_output_name() {
    case "${1:-}" in
    '' | [0-9]* | *[!A-Za-z0-9_]*)
        printf '%s must be a valid Bash variable name: %s\n' "${3:-package output}" "${1:-}" >&2
        return 1
        ;;
    esac
    case " $2 " in
    *" $1 "*)
        printf '%s collides with package lock helper state: %s\n' \
            "${3:-package output}" "$1" >&2
        return 1
        ;;
    esac
    if declare -p "$1" >/dev/null 2>&1; then
        if [[ "$(declare -p "$1" 2>/dev/null)" =~ ^declare\ -[^[:space:]]*[rn] ]]; then
            printf '%s must not be a readonly or nameref variable: %s\n' \
                "${3:-package output}" "$1" >&2
            return 1
        fi
        if [[ "$(declare -p "$1" 2>/dev/null)" =~ ^declare\ -[^[:space:]]*[aA] ]]; then
            printf '%s must be a scalar variable: %s\n' \
                "${3:-package output}" "$1" >&2
            return 1
        fi
    fi
}

package_canonical_output_root() {
    local label="$1"
    local path="$2"
    [[ -n "$path" ]] || {
        printf '%s must not be empty\n' "$label" >&2
        return 1
    }
    mkdir -p -- "$path"
    local canonical owner mode
    canonical="$(realpath -e -- "$path")" || return 1
    [[ -d "$canonical" && "$canonical" != / ]] || {
        printf '%s must resolve to a non-root directory: %q\n' "$label" "$canonical" >&2
        return 1
    }
    owner="$(stat -c '%u' -- "$canonical")" || return 1
    mode="$(stat -c '%a' -- "$canonical")" || return 1
    [[ "$owner" == "$(id -u)" && "$mode" =~ ^[0-7]+$ ]] || {
        printf '%s must be owned by the packaging user: %q\n' "$label" "$canonical" >&2
        return 1
    }
    mode=$((8#$mode))
    ((!(mode & 0022))) || {
        printf '%s must not be group/world-writable: %q\n' "$label" "$canonical" >&2
        return 1
    }
    printf '%s\n' "$canonical"
}

package_safe_child_path() {
    local root="$1"
    local basename="$2"
    local label="$3"
    package_require_safe_component "$label basename" "$basename"
    local candidate="$root/$basename"
    local canonical
    canonical="$(realpath -m -- "$candidate")" || return 1
    [[ "$canonical" == "$candidate" && "$canonical" == "$root/"* ]] || {
        printf '%s escapes canonical output root %q: %q\n' "$label" "$root" "$canonical" >&2
        return 1
    }
    printf '%s\n' "$canonical"
}

if ! declare -p PACKAGE_CLEANUP_ROOT_IDENTITIES >/dev/null 2>&1; then
    declare -gA PACKAGE_CLEANUP_ROOT_IDENTITIES=()
fi
if ! declare -p PACKAGE_PUBLICATION_FILE_IDENTITIES >/dev/null 2>&1; then
    declare -gA PACKAGE_PUBLICATION_FILE_IDENTITIES=()
fi

package_cleanup_root_identity() {
    local candidate="$1"
    [[ -d "$candidate" && ! -L "$candidate" ]] || return 1
    # Bind the object and its type, but not mutable directory permissions.
    # Copying an archive tree into an existing private staging root can
    # legitimately update that root's mode while retaining the same object.
    LC_ALL=C stat -c '%d:%i:%u:%F' -- "$candidate"
}

package_capture_cleanup_root() {
    local candidate="$1"
    local label="$2"
    local identity owner
    identity="$(package_cleanup_root_identity "$candidate")" || {
        printf '%s must be a real directory before recursive cleanup: %q\n' "$label" "$candidate" >&2
        return 1
    }
    owner="$(stat -c '%u' -- "$candidate")" || return 1
    [[ "$owner" == "$(id -u)" ]] || {
        printf '%s must be owned by the packaging user before recursive cleanup: %q\n' \
            "$label" "$candidate" >&2
        return 1
    }
    if [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]:-}" &&
        "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]}" != "$identity" ]]; then
        printf '%s has a conflicting captured cleanup identity: %q\n' "$label" "$candidate" >&2
        return 1
    fi
    PACKAGE_CLEANUP_ROOT_IDENTITIES["$candidate"]="$identity"
}

package_require_cleanup_root_identity() {
    local candidate="$1"
    local label="$2"
    local expected="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]:-}"
    local actual=""
    [[ -n "$expected" ]] || {
        printf '%s has no captured recursive-cleanup identity: %q\n' "$label" "$candidate" >&2
        return 1
    }
    actual="$(package_cleanup_root_identity "$candidate" 2>/dev/null)" || true
    [[ -n "$actual" && "$actual" == "$expected" ]] || {
        printf '%s identity changed; refusing recursive cleanup: %q (expected=%s actual=%s)\n' \
            "$label" "$candidate" "$expected" "${actual:-missing}" >&2
        return 1
    }
}

package_identity_bound_remove() {
    local candidate="$1"
    local expected="$2"
    local kind="$3"
    local label="$4"
    local quarantine_path="$5"
    python3 - "$candidate" "$expected" "$kind" "$label" "$quarantine_path" <<'PY'
import ctypes
import errno
import os
import stat
import sys

candidate, encoded_identity, kind, label, quarantine_path = sys.argv[1:]
device, inode, owner, _ = encoded_identity.split(":", 3)
expected = (int(device), int(inode))
expected_owner = int(owner)
parent = os.path.dirname(candidate)
name = os.path.basename(candidate)
if name in {"", ".", ".."} or os.path.join(parent, name) != candidate:
    raise SystemExit(f"{label} is not a direct child path: {candidate!r}")
if kind not in {"file", "tree"}:
    raise SystemExit(f"invalid identity-bound removal kind: {kind}")

libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for identity-bound package cleanup")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int


def rename_noreplace(directory_fd, source, destination):
    if renameat2(directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise RuntimeError(f"package cleanup quarantine collision: {destination!r}")
        raise OSError(error, os.strerror(error), source)


parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    if os.path.dirname(quarantine_path) != parent:
        raise SystemExit(f"{label} removal quarantine is outside its captured parent: {quarantine_path}")
    quarantine = os.path.basename(quarantine_path)
    if quarantine in {"", ".", ".."} or os.path.join(parent, quarantine) != quarantine_path:
        raise SystemExit(f"{label} removal quarantine is not a canonical direct child")
    try:
        os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit(f"{label} removal quarantine already exists: {quarantine_path}")
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    if kind == "tree":
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    target_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(target_fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        expected_type = stat.S_ISREG if kind == "file" else stat.S_ISDIR
        if (
            not expected_type(opened.st_mode)
            or opened.st_uid != expected_owner
            or (opened.st_dev, opened.st_ino) != expected
            or (named.st_dev, named.st_ino) != expected
        ):
            raise SystemExit(f"{label} identity changed before cleanup: {candidate!r}")
        rename_noreplace(parent_fd, name, quarantine)
        quarantined = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if (quarantined.st_dev, quarantined.st_ino) != expected:
            raise SystemExit(f"{label} quarantine identity changed: {candidate!r}")
        # This directory is writable by another process with the packaging UID.
        # Linux has no conditional unlink-by-open-fd operation, so deleting this
        # pathname after validation could delete a replacement.  The exact
        # RENAME_NOREPLACE quarantine is terminal logical cleanup; privileged or
        # dedicated-UID reconciliation may remove it from a protected namespace.
        os.fsync(parent_fd)
    finally:
        os.close(target_fd)
finally:
    os.close(parent_fd)
PY
}

package_unused_removal_quarantine() {
    local candidate="$1" attempt quarantine
    for ((attempt = 0; attempt < 128; attempt++)); do
        quarantine="${candidate}.oxidedns-remove.$$.$RANDOM.$attempt"
        if [[ ! -e "$quarantine" && ! -L "$quarantine" ]]; then
            printf '%s\n' "$quarantine"
            return 0
        fi
    done
    printf 'could not allocate package removal quarantine beside %q\n' "$candidate" >&2
    return 1
}

# Reopen a retained quarantine through its immediate parent and bind both the
# named object and that parent in one dirfd-relative check.  The returned parent
# identity is durable evidence, not deletion authority: a later privileged or
# dedicated-UID reconciler must compare both recorded identities again.
package_retained_quarantine_parent_identity() {
    local quarantine="$1" expected="$2" kind="$3"
    python3 - "$quarantine" "$expected" "$kind" <<'PY'
import os
import stat
import sys

quarantine, encoded_identity, kind = sys.argv[1:]
device, inode, owner, _ = encoded_identity.split(":", 3)
expected = (int(device), int(inode), int(owner))
parent = os.path.dirname(quarantine)
name = os.path.basename(quarantine)
if (
    name in {"", ".", ".."}
    or os.path.join(parent, name) != quarantine
    or kind not in {"file", "tree"}
):
    raise SystemExit("invalid retained package quarantine evidence path")

parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    opened_parent = os.fstat(parent_fd)
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    if kind == "tree":
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    object_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(object_fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        expected_type = stat.S_ISREG if kind == "file" else stat.S_ISDIR
        if (
            not expected_type(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_uid) != expected
            or (named.st_dev, named.st_ino, named.st_uid) != expected
        ):
            raise SystemExit("retained package quarantine identity changed")
        print(
            f"{opened_parent.st_dev}:{opened_parent.st_ino}:"
            f"{opened_parent.st_uid}:directory"
        )
    finally:
        os.close(object_fd)
finally:
    os.close(parent_fd)
PY
}

package_append_verified_retained_removal_quarantine() {
    local quarantine="$1" expected="$2" kind="$3" label="$4"
    local parent="${quarantine%/*}" parent_identity
    [[ -n "$parent" ]] || parent=/
    parent_identity="$(
        package_retained_quarantine_parent_identity "$quarantine" "$expected" "$kind"
    )" || {
        printf '%s retained quarantine could not be revalidated; preserving its parent namespace without claiming an exact object identity: %q\n' \
            "$label" "$parent" >&2
        return 1
    }
    PACKAGE_RETAINED_REMOVAL_QUARANTINES+=("$quarantine")
    PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES+=("$expected")
    PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS+=("$parent")
    PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES+=("$parent_identity")
    printf '%s logical removal retained an identity-bound quarantine for privileged/manual reconciliation: path=%q identity=%q parent=%q parent_identity=%q\n' \
        "$label" "$quarantine" "$expected" "$parent" "$parent_identity" >&2
}

package_record_retained_removal_quarantine() {
    local candidate="$1" quarantine="$2" expected="$3" kind="$4" label="$5"
    local hook_status=0 index retained rebased identity parent parent_identity nested_kind
    local diagnostic_rebased diagnostic_identity
    if declare -F package_identity_bound_hook >/dev/null 2>&1; then
        package_identity_bound_hook after-quarantine-retain "$kind" "$candidate" "$quarantine" || hook_status=$?
    fi
    package_reconcile_artifact_location "$quarantine" "$expected" "$kind" || {
        printf '%s retained quarantine identity changed; preserving the namespace for privileged/manual reconciliation: %q\n' \
            "$label" "${quarantine%/*}" >&2
        return 1
    }
    package_append_verified_retained_removal_quarantine \
        "$quarantine" "$expected" "$kind" "$label" || return 1
    PACKAGE_LAST_REMOVE_QUARANTINE="$quarantine"
    # A retained staging tree can itself contain earlier terminal quarantines.
    # Rebase those diagnostic paths before recording the outer quarantine so a
    # successful logical cleanup never leaves recovery metadata naming paths
    # that disappeared only because their captured ancestor was renamed.
    if [[ "$kind" == tree ]]; then
        for ((index = 0; index < ${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}; index++)); do
            retained="${PACKAGE_RETAINED_REMOVAL_QUARANTINES[index]}"
            [[ "$retained" == "$candidate/"* ]] || continue
            rebased="$quarantine${retained:${#candidate}}"
            if [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$retained]:-}" ]]; then
                identity="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$retained]}"
                nested_kind="tree"
                unset 'PACKAGE_CLEANUP_ROOT_IDENTITIES[$retained]'
                PACKAGE_CLEANUP_ROOT_IDENTITIES["$rebased"]="$identity"
            elif [[ -n "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$retained]:-}" ]]; then
                identity="${PACKAGE_PUBLICATION_FILE_IDENTITIES[$retained]}"
                nested_kind="file"
                unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$retained]'
                PACKAGE_PUBLICATION_FILE_IDENTITIES["$rebased"]="$identity"
            else
                printf '%s nested retained quarantine lost its captured object identity; preserving the outer namespace without claiming an exact nested identity: %q\n' \
                    "$label" "$quarantine" >&2
                return 1
            fi
            parent="${rebased%/*}"
            [[ -n "$parent" ]] || parent=/
            parent_identity="$(
                package_retained_quarantine_parent_identity "$rebased" "$identity" "$nested_kind"
            )" || {
                printf '%s nested retained quarantine could not be revalidated after rebasing; preserving the outer namespace without claiming an exact nested identity: %q\n' \
                    "$label" "$quarantine" >&2
                unset 'PACKAGE_RETAINED_REMOVAL_QUARANTINES[index]'
                unset 'PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[index]'
                unset 'PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS[index]'
                unset 'PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES[index]'
                PACKAGE_RETAINED_REMOVAL_QUARANTINES=("${PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}")
                PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES=("${PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[@]}")
                PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS=("${PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS[@]}")
                PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES=("${PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES[@]}")
                return 1
            }
            PACKAGE_RETAINED_REMOVAL_QUARANTINES[index]="$rebased"
            PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS[index]="$parent"
            PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES[index]="$parent_identity"
            printf '%s nested retained quarantine was rebased by an outer terminal quarantine: path=%q identity=%q parent=%q parent_identity=%q\n' \
                "$label" "$rebased" \
                "${PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[index]}" "$parent" \
                "$parent_identity" >&2
        done
    fi
    if [[ -n "${PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC:-}" &&
        "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC" == "$candidate/"* ]]; then
        diagnostic_rebased="$quarantine${PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC:${#candidate}}"
        diagnostic_identity="${PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY:-}"
        if [[ -z "$diagnostic_identity" ]] ||
            ! parent_identity="$(
                package_retained_quarantine_parent_identity \
                    "$diagnostic_rebased" "$diagnostic_identity" file
            )"; then
            printf '%s retained recovery diagnostic could not be revalidated after ancestor rebasing; preserving the outer namespace without claiming an exact diagnostic path: %q\n' \
                "$label" "$quarantine" >&2
            PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC=""
            PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY=""
            return 1
        fi
        unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC]'
        PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC="$diagnostic_rebased"
        PACKAGE_PUBLICATION_FILE_IDENTITIES["$diagnostic_rebased"]="$diagnostic_identity"
        parent="${diagnostic_rebased%/*}"
        [[ -n "$parent" ]] || parent=/
        printf '%s retained recovery diagnostic was rebased by an outer terminal quarantine: path=%q identity=%q parent=%q parent_identity=%q\n' \
            "$label" "$diagnostic_rebased" "$diagnostic_identity" "$parent" \
            "$parent_identity" >&2
    fi
    unset 'PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]'
    unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$candidate]'
    if [[ "$kind" == tree ]]; then
        PACKAGE_CLEANUP_ROOT_IDENTITIES["$quarantine"]="$expected"
    else
        PACKAGE_PUBLICATION_FILE_IDENTITIES["$quarantine"]="$expected"
    fi
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        printf '%s original pathname reappeared after quarantine; refusing logical cleanup success: %q\n' \
            "$label" "$candidate" >&2
        return 1
    fi
    PACKAGE_LAST_REMOVE_COMMITTED=1
    ((hook_status == 0)) || return "$hook_status"
}

package_remove_captured_cleanup_root() {
    local candidate="$1"
    local label="$2"
    PACKAGE_LAST_REMOVE_COMMITTED=0
    PACKAGE_LAST_REMOVE_QUARANTINE=""
    package_require_cleanup_root_identity "$candidate" "$label" || return 1
    if declare -F package_identity_bound_hook >/dev/null 2>&1; then
        package_identity_bound_hook before-remove tree "$candidate" "" || return 1
    fi
    local expected="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]}" status=0 record_status=0 quarantine
    quarantine="$(package_unused_removal_quarantine "$candidate")" || return 1
    package_identity_bound_remove "$candidate" "$expected" tree "$label" "$quarantine" || status=$?
    if package_reconcile_artifact_location "$quarantine" "$expected" tree; then
        package_record_retained_removal_quarantine \
            "$candidate" "$quarantine" "$expected" tree "$label" || record_status=$?
        if ((record_status != 0)); then
            ((PACKAGE_LAST_REMOVE_COMMITTED == 1)) || return "$record_status"
            ((status != 0)) || status=$record_status
        fi
        ((status == 0)) || return "$status"
        return 0
    fi
    ((status != 0)) || {
        printf '%s cleanup helper lost its exact retained quarantine: %q\n' \
            "$label" "$quarantine" >&2
        return 1
    }
    return "$status"
}

package_remove_captured_publication_file() {
    local candidate="$1"
    local label="$2"
    PACKAGE_LAST_REMOVE_COMMITTED=0
    PACKAGE_LAST_REMOVE_QUARANTINE=""
    package_require_publication_file_identity "$candidate" "$label" || return 1
    if declare -F package_identity_bound_hook >/dev/null 2>&1; then
        package_identity_bound_hook before-remove file "$candidate" "" || return 1
    fi
    local expected="${PACKAGE_PUBLICATION_FILE_IDENTITIES[$candidate]}" status=0 record_status=0 quarantine
    quarantine="$(package_unused_removal_quarantine "$candidate")" || return 1
    package_identity_bound_remove "$candidate" "$expected" file "$label" "$quarantine" || status=$?
    if package_reconcile_artifact_location "$quarantine" "$expected" file; then
        package_record_retained_removal_quarantine \
            "$candidate" "$quarantine" "$expected" file "$label" || record_status=$?
        if ((record_status != 0)); then
            ((PACKAGE_LAST_REMOVE_COMMITTED == 1)) || return "$record_status"
            ((status != 0)) || status=$record_status
        fi
        ((status == 0)) || return "$status"
        return 0
    fi
    ((status != 0)) || {
        printf '%s cleanup helper lost its exact retained quarantine: %q\n' \
            "$label" "$quarantine" >&2
        return 1
    }
    return "$status"
}

package_is_retained_removal_quarantine() {
    local candidate="$1"
    local quarantine
    for quarantine in "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}"; do
        [[ "$candidate" != "$quarantine" ]] || return 0
    done
    return 1
}

package_write_publication_recovery_diagnostic() {
    local retain_root="${PACKAGE_PUBLICATION_RETAIN_ROOT:-}"
    [[ -n "$retain_root" ]] || {
        printf 'cannot write package publication recovery diagnostic without a retained root\n' >&2
        return 1
    }
    package_require_cleanup_root_identity "$retain_root" \
        "package publication recovery root" || return 1
    local expected="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$retain_root]}"
    local diagnostic diagnostic_identity diagnostic_parent_identity index
    local diagnostic_fd diagnostic_pid diagnostic_status diagnostic_extra
    local -a quarantine_records=()
    [[ "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" == "${#PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[@]}" &&
        "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" == "${#PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS[@]}" &&
        "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" == "${#PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES[@]}" ]] || {
        printf 'retained package quarantine evidence arrays are inconsistent; refusing recovery journal\n' >&2
        return 1
    }
    for ((index = 0; index < ${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}; index++)); do
        quarantine_records+=(
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[index]}"
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[index]}"
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS[index]}"
            "${PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES[index]}"
        )
    done
    exec {diagnostic_fd}< <(
        python3 - "$retain_root" "$expected" "$PACKAGE_PUBLICATION_TOKEN" \
            "$PACKAGE_PUBLICATION_COMPLETE" "$PACKAGE_PUBLICATION_COUNT" \
            "${PACKAGE_PUBLICATION_BACKUPS[@]}" \
            "${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]}" \
            "${quarantine_records[@]}" <<'PY'
import ctypes
import errno
import os
import secrets
import shlex
import signal
import stat
import sys

root, encoded_identity, token, complete, encoded_count, *values = sys.argv[1:]
device, inode, owner, _ = encoded_identity.split(":", 3)
expected = (int(device), int(inode), int(owner))
count = int(encoded_count)
backups = values[:count]
remaining = values[count:]
quarantine_count = int(remaining[0])
quarantine_values = remaining[1:]
if len(quarantine_values) != quarantine_count * 4:
    raise SystemExit("invalid retained quarantine recovery journal")
quarantines = [
    quarantine_values[index : index + 4]
    for index in range(0, len(quarantine_values), 4)
]


def diagnostic_quote(value):
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return ascii(value)
    return shlex.quote(value)


def relative_to_recovery_root(path):
    if path == root:
        return "."
    prefix = root + os.sep
    if path.startswith(prefix):
        relative = path[len(prefix) :]
        if relative and all(
            component not in {"", ".", ".."}
            for component in relative.split(os.sep)
        ):
            return relative
    return ""

libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for atomic package recovery diagnostics")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int


class RecoveryDiagnosticSignal(Exception):
    pass


def interrupt_recovery_diagnostic(signum, _frame):
    # The first signal selects failure; subsequent cancellation signals must not
    # interrupt the identity-checked hidden-inode cleanup in ``finally``.
    for ignored_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(ignored_signal, signal.SIG_IGN)
    raise RecoveryDiagnosticSignal(
        f"package publication recovery diagnostic interrupted by signal {signum}"
    )


for handled_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(handled_signal, interrupt_recovery_diagnostic)


def rename_noreplace(directory_fd, source, destination):
    if renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        1,
    ) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise RuntimeError("package publication recovery diagnostic collision")
        raise OSError(error, os.strerror(error), source)

root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
fd = None
staging_name = None
owned_staging = None
try:
    opened = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino, opened.st_uid) != expected
    ):
        raise SystemExit("package publication recovery root identity changed")
    for _ in range(128):
        nonce = secrets.token_hex(12)
        staging_name = f".publication-recovery-incomplete-{token}-{nonce}.env"
        name = f"publication-recovery-{token}-{nonce}.env"
        try:
            fd = os.open(
                staging_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
        except FileExistsError:
            continue
        created = os.fstat(fd)
        owned_staging = (created.st_dev, created.st_ino, created.st_uid)
        break
    else:
        raise SystemExit("cannot allocate package publication recovery diagnostic")
    try:
        lines = [
            f"publication_complete={shlex.quote(complete)}",
            f"publication_count={shlex.quote(str(count))}",
            f"publication_recovery_root={shlex.quote(root)}",
            f"publication_recovery_root_identity={shlex.quote(encoded_identity)}",
            "publication_recovery_root_binding=journal-parent-directory",
        ]
        lines.extend(
            f"publication_backup_{index}={shlex.quote(path)}"
            for index, path in enumerate(backups)
        )
        for index, (path, identity, parent, parent_identity) in enumerate(quarantines):
            fields = [
                f"retained_removal_quarantine_{index}={shlex.quote(path)}",
                f"retained_removal_quarantine_{index}_identity={shlex.quote(identity)}",
                f"retained_removal_quarantine_{index}_parent={shlex.quote(parent)}",
                f"retained_removal_quarantine_{index}_parent_identity="
                f"{shlex.quote(parent_identity)}",
            ]
            root_relative = relative_to_recovery_root(path)
            parent_root_relative = relative_to_recovery_root(parent)
            if root_relative and parent_root_relative:
                fields.extend(
                    (
                        f"retained_removal_quarantine_{index}_root_relative="
                        f"{shlex.quote(root_relative)}",
                        f"retained_removal_quarantine_{index}_parent_root_relative="
                        f"{shlex.quote(parent_root_relative)}",
                    )
                )
            lines.extend(fields)
        # Public recovery journals are valid only after this final marker and
        # the complete hidden inode have both reached stable storage.
        lines.append("diagnostic_complete=1")
        payload = memoryview(("\n".join(lines) + "\n").encode())
        while payload:
            written = os.write(fd, payload)
            if written <= 0:
                raise OSError("short write while creating package publication recovery diagnostic")
            payload = payload[written:]
        os.fsync(fd)
    finally:
        if fd is not None:
            os.close(fd)
            fd = None

    staged = os.stat(staging_name, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(staged.st_mode)
        or (staged.st_dev, staged.st_ino, staged.st_uid) != owned_staging
        or staged.st_uid != expected[2]
        or staged.st_nlink != 1
    ):
        raise RuntimeError("package publication recovery staging identity changed")
    # The directory is private and the random final basename is transaction
    # unique. Rename publishes the already-fsynced complete inode in one step.
    rename_noreplace(root_fd, staging_name, name)
    staging_name = None
    published = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if (published.st_dev, published.st_ino, published.st_uid) != owned_staging:
        raise RuntimeError("package publication recovery published identity changed")
    os.fsync(root_fd)
    diagnostic_identity = (
        f"{owned_staging[0]}:{owned_staging[1]}:"
        f"{owned_staging[2]}:regular file"
    )
    # NUL framing is byte-safe for every filesystem pathname. In particular,
    # tabs and newlines are valid pathname bytes and cannot delimit this
    # transport. Filesystem paths themselves cannot contain NUL.
    sys.stdout.buffer.write(os.fsencode(os.path.join(root, name)) + b"\0")
    sys.stdout.buffer.write(diagnostic_identity.encode("ascii") + b"\0")
finally:
    # Cleanup is non-reentrant even when rendering failed before the first
    # signal arrived. A same-UID peer can mutate this namespace between any
    # pathname validation and unlink, so an incomplete staging inode is
    # terminal evidence too: close it, retain it, and report the exact path
    # when it is still identity-bound.
    for cleanup_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(cleanup_signal, signal.SIG_IGN)
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
    if staging_name is not None:
        try:
            staged = os.stat(staging_name, dir_fd=root_fd, follow_symlinks=False)
            if (
                owned_staging is not None
                and stat.S_ISREG(staged.st_mode)
                and (staged.st_dev, staged.st_ino, staged.st_uid) == owned_staging
                and staged.st_nlink == 1
            ):
                retained_path = os.path.join(root, staging_name)
                retained_identity = (
                    f"{owned_staging[0]}:{owned_staging[1]}:"
                    f"{owned_staging[2]}:regular file"
                )
                print(
                    "retained incomplete package recovery staging for "
                    "privileged/manual reconciliation: "
                    f"path={diagnostic_quote(retained_path)} "
                    f"identity={diagnostic_quote(retained_identity)} "
                    f"parent={diagnostic_quote(root)} "
                    f"parent_identity={diagnostic_quote(encoded_identity)}",
                    file=sys.stderr,
                )
            else:
                print(
                    "package recovery staging identity changed; preserving namespace for "
                    f"privileged/manual reconciliation: {diagnostic_quote(root)}",
                    file=sys.stderr,
                )
        except FileNotFoundError:
            print(
                "package recovery staging pathname disappeared; preserving namespace for "
                f"privileged/manual reconciliation: {diagnostic_quote(root)}",
                file=sys.stderr,
            )
        try:
            os.fsync(root_fd)
        except OSError:
            pass
    os.close(root_fd)
PY
    ) || return 1
    diagnostic_pid=$!
    diagnostic_status=0
    IFS= read -r -d '' diagnostic <&"$diagnostic_fd" || diagnostic_status=$?
    if ((diagnostic_status == 0)); then
        IFS= read -r -d '' diagnostic_identity <&"$diagnostic_fd" || diagnostic_status=$?
    fi
    if ((diagnostic_status == 0)); then
        diagnostic_extra=""
        if IFS= read -r -d '' diagnostic_extra <&"$diagnostic_fd"; then
            printf 'package publication recovery diagnostic returned an extra NUL-delimited field: %q\n' \
                "$diagnostic_extra" >&2
            diagnostic_status=1
        elif [[ -n "$diagnostic_extra" ]]; then
            printf 'package publication recovery diagnostic returned trailing partial transport data: %q\n' \
                "$diagnostic_extra" >&2
            diagnostic_status=1
        fi
    fi
    wait "$diagnostic_pid" || diagnostic_status=$?
    exec {diagnostic_fd}<&-
    ((diagnostic_status == 0)) || return "$diagnostic_status"
    [[ -n "$diagnostic" && -n "$diagnostic_identity" ]] || {
        printf 'package publication recovery diagnostic returned incomplete identity evidence\n' >&2
        return 1
    }
    [[ "$diagnostic_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:regular\ file$ ]] || {
        printf 'package publication recovery diagnostic returned malformed identity evidence\n' >&2
        return 1
    }
    [[ "$(package_regular_file_identity "$diagnostic" 2>/dev/null)" == "$diagnostic_identity" ]] || {
        printf 'package publication recovery diagnostic path identity changed before acceptance: %q\n' \
            "$diagnostic" >&2
        return 1
    }
    diagnostic_parent_identity="$(
        package_retained_quarantine_parent_identity "$diagnostic" "$diagnostic_identity" file
    )" || {
        printf 'package publication recovery diagnostic could not be reopened exactly: %q\n' \
            "$diagnostic" >&2
        return 1
    }
    [[ "$diagnostic_parent_identity" == "$expected" ]] || {
        printf 'package publication recovery diagnostic escaped its bound recovery root: %q\n' \
            "$diagnostic" >&2
        return 1
    }
    PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC="$diagnostic"
    PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY="$diagnostic_identity"
    PACKAGE_PUBLICATION_FILE_IDENTITIES["$diagnostic"]="$diagnostic_identity"
    printf 'package publication recovery diagnostic: %q\n' "$diagnostic" >&2
}

package_regular_file_identity() {
    local candidate="$1"
    [[ -f "$candidate" && ! -L "$candidate" ]] || return 1
    # GNU stat reports an empty regular file as "regular empty file", then
    # changes %F to "regular file" as soon as a generator writes it. File
    # identity must remain stable across content updates to the same inode.
    printf '%s:regular file\n' "$(LC_ALL=C stat -c '%d:%i:%u' -- "$candidate")"
}

package_capture_publication_file() {
    local candidate="$1"
    local label="$2"
    local identity
    identity="$(package_regular_file_identity "$candidate")" || {
        printf '%s must be a regular file before transactional publication: %q\n' \
            "$label" "$candidate" >&2
        return 1
    }
    if [[ -n "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$candidate]:-}" &&
        "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$candidate]}" != "$identity" ]]; then
        printf '%s has a conflicting captured file identity: %q\n' "$label" "$candidate" >&2
        return 1
    fi
    PACKAGE_PUBLICATION_FILE_IDENTITIES["$candidate"]="$identity"
}

# Atomically claim one previously absent regular-file pathname and return the
# exact inode identity opened by O_EXCL. Callers can safely let a generator
# truncate/write this placeholder, then remove it only through the captured
# identity even when generation fails partway through.
package_create_owned_publication_file() {
    local candidate="$1"
    local label="$2"
    local identity
    identity="$(
        python3 - "$candidate" "$label" <<'PY'
import os
import stat
import sys

candidate, label = sys.argv[1:]
parent = os.path.dirname(candidate)
name = os.path.basename(candidate)
if name in {"", ".", ".."} or os.path.join(parent, name) != candidate:
    raise SystemExit(f"{label} is not a canonical direct child path: {candidate!r}")
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    try:
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise SystemExit(f"{label} identity changed while claiming: {candidate!r}")
        os.fsync(fd)
        os.fsync(parent_fd)
        print(f"{opened.st_dev}:{opened.st_ino}:{opened.st_uid}:regular file")
    finally:
        os.close(fd)
finally:
    os.close(parent_fd)
PY
    )" || return 1
    [[ -n "$identity" ]] || return 1
    PACKAGE_PUBLICATION_FILE_IDENTITIES["$candidate"]="$identity"
}

package_require_publication_file_identity() {
    local candidate="$1"
    local label="$2"
    local expected="${PACKAGE_PUBLICATION_FILE_IDENTITIES[$candidate]:-}"
    local actual=""
    [[ -n "$expected" ]] || {
        printf '%s has no captured regular-file identity: %q\n' "$label" "$candidate" >&2
        return 1
    }
    actual="$(package_regular_file_identity "$candidate" 2>/dev/null)" || true
    [[ -n "$actual" && "$actual" == "$expected" ]] || {
        printf '%s identity changed; refusing file mutation: %q (expected=%s actual=%s)\n' \
            "$label" "$candidate" "$expected" "${actual:-missing}" >&2
        return 1
    }
}

package_capture_publication_artifact() {
    local candidate="$1"
    local label="$2"
    if [[ -d "$candidate" && ! -L "$candidate" ]]; then
        package_capture_cleanup_root "$candidate" "$label"
    elif [[ -f "$candidate" && ! -L "$candidate" ]]; then
        package_capture_publication_file "$candidate" "$label"
    else
        printf '%s must be a regular file or real directory: %q\n' "$label" "$candidate" >&2
        return 1
    fi
}

package_require_publication_artifact_identity() {
    local candidate="$1"
    local label="$2"
    if [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]:-}" ]]; then
        package_require_cleanup_root_identity "$candidate" "$label"
    elif [[ -n "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$candidate]:-}" ]]; then
        package_require_publication_file_identity "$candidate" "$label"
    else
        printf '%s has no captured publication identity: %q\n' "$label" "$candidate" >&2
        return 1
    fi
}

package_identity_bound_restore() {
    local source="$1"
    local destination="$2"
    local expected="$3"
    local root="$4"
    local root_identity="$5"
    local label="$6"
    if declare -F package_identity_bound_hook >/dev/null 2>&1; then
        package_identity_bound_hook before-restore artifact "$source" "$destination" || return 1
    fi
    python3 - "$source" "$destination" "$expected" "$root" "$root_identity" "$label" <<'PY'
import ctypes
import errno
import os
import secrets
import sys

source, destination, encoded_identity, root, encoded_root_identity, label = sys.argv[1:]
device, inode, owner, _ = encoded_identity.split(":", 3)
expected = (int(device), int(inode))
expected_owner = int(owner)
root_device, root_inode = (int(value) for value in encoded_root_identity.split(":", 1))
expected_root = (root_device, root_inode)
source_name = os.path.basename(source)
destination_name = os.path.basename(destination)
if (
    os.path.dirname(source) != root
    or os.path.dirname(destination) != root
    or source_name in {"", ".", ".."}
    or destination_name in {"", ".", ".."}
    or os.path.join(root, source_name) != source
    or os.path.join(root, destination_name) != destination
):
    raise SystemExit(f"{label} restore paths are not canonical direct children of the locked root")

libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for identity-bound package restore")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int


def rename_noreplace(directory_fd, old, new):
    if renameat2(directory_fd, os.fsencode(old), directory_fd, os.fsencode(new), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise RuntimeError(f"identity-bound package restore destination exists: {new}")
        raise OSError(error, os.strerror(error), old)


directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    opened_root = os.fstat(directory_fd)
    if (opened_root.st_dev, opened_root.st_ino) != expected_root:
        raise SystemExit(f"{label} restore root identity changed: {root!r}")
    source_fd = os.open(source_name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        opened = os.fstat(source_fd)
        named = os.stat(source_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            opened.st_uid != expected_owner
            or (opened.st_dev, opened.st_ino) != expected
            or (named.st_dev, named.st_ino) != expected
        ):
            raise SystemExit(f"{label} identity changed before restore: {source!r}")
        quarantine = f".{source_name}.oxidedns-restore.{os.getpid()}.{secrets.token_hex(12)}"
        rename_noreplace(directory_fd, source_name, quarantine)
        quarantined = os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
        if (quarantined.st_dev, quarantined.st_ino) != expected:
            raise SystemExit(f"{label} quarantine identity changed before restore: {source!r}")
        try:
            rename_noreplace(directory_fd, quarantine, destination_name)
        except BaseException:
            try:
                rename_noreplace(directory_fd, quarantine, source_name)
            except BaseException:
                pass
            raise
        published = os.stat(destination_name, dir_fd=directory_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != expected:
            raise SystemExit(f"{label} restored destination identity changed: {destination!r}")
        os.fsync(directory_fd)
    finally:
        os.close(source_fd)
finally:
    os.close(directory_fd)
PY
}

package_reconcile_artifact_location() {
    local path="$1" expected="$2" kind="$3"
    local actual=""
    case "$kind" in
    tree) actual="$(package_cleanup_root_identity "$path" 2>/dev/null)" || true ;;
    file) actual="$(package_regular_file_identity "$path" 2>/dev/null)" || true ;;
    *) return 2 ;;
    esac
    [[ -n "$actual" && "$actual" == "$expected" ]]
}

# Move one already-captured publication artifact to an absent direct child of a
# locked publication root.  The opened source inode and destination-root inode
# are both checked inside the same dirfd-based operation that performs the
# no-replace rename, closing the final pathname race left by shell-level stat +
# mv sequences.
package_identity_bound_move() {
    local source="$1"
    local destination="$2"
    local expected="$3"
    local kind="$4"
    local root="$5"
    local root_identity="$6"
    local label="$7"
    if declare -F package_identity_bound_hook >/dev/null 2>&1; then
        package_identity_bound_hook before-move "$kind" "$source" "$destination" || return 1
    fi
    python3 - "$source" "$destination" "$expected" "$kind" "$root" "$root_identity" "$label" <<'PY'
import ctypes
import errno
import os
import stat
import sys

source, destination, encoded_identity, kind, root, encoded_root_identity, label = sys.argv[1:]
device, inode, owner, _ = encoded_identity.split(":", 3)
expected = (int(device), int(inode))
expected_owner = int(owner)
root_device, root_inode = (int(value) for value in encoded_root_identity.split(":", 1))
expected_root = (root_device, root_inode)
source_parent = os.path.dirname(source)
destination_parent = os.path.dirname(destination)
source_name = os.path.basename(source)
destination_name = os.path.basename(destination)
if (
    destination_parent != root
    or source_name in {"", ".", ".."}
    or destination_name in {"", ".", ".."}
    or os.path.join(source_parent, source_name) != source
    or os.path.join(destination_parent, destination_name) != destination
    or kind not in {"file", "tree"}
):
    raise SystemExit(f"{label} move paths are not canonical direct children")

libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for identity-bound package publication")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int

source_parent_fd = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    destination_parent_fd = os.open(
        destination_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        destination_parent_stat = os.fstat(destination_parent_fd)
        if (destination_parent_stat.st_dev, destination_parent_stat.st_ino) != expected_root:
            raise SystemExit(f"{label} destination root identity changed before publication")
        flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
        if kind == "tree":
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        source_fd = os.open(source_name, flags, dir_fd=source_parent_fd)
        try:
            opened = os.fstat(source_fd)
            named = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
            expected_type = stat.S_ISREG if kind == "file" else stat.S_ISDIR
            if (
                not expected_type(opened.st_mode)
                or opened.st_uid != expected_owner
                or (opened.st_dev, opened.st_ino) != expected
                or (named.st_dev, named.st_ino) != expected
            ):
                raise SystemExit(f"{label} source identity changed before publication: {source!r}")
            if renameat2(
                source_parent_fd,
                os.fsencode(source_name),
                destination_parent_fd,
                os.fsencode(destination_name),
                1,
            ) != 0:
                error = ctypes.get_errno()
                if error == errno.EEXIST:
                    raise SystemExit(f"{label} destination appeared during publication: {destination!r}")
                raise OSError(error, os.strerror(error), source)
            published = os.stat(destination_name, dir_fd=destination_parent_fd, follow_symlinks=False)
            if (published.st_dev, published.st_ino) != expected:
                raise SystemExit(f"{label} published destination identity changed: {destination!r}")
            os.fsync(source_parent_fd)
            if destination_parent_fd != source_parent_fd:
                os.fsync(destination_parent_fd)
        finally:
            os.close(source_fd)
    finally:
        os.close(destination_parent_fd)
finally:
    os.close(source_parent_fd)
PY
}

package_move_captured_publication_artifact() {
    local source="$1"
    local destination="$2"
    local root="$3"
    local label="$4"
    local kind expected
    PACKAGE_LAST_MOVE_COMMITTED=0
    package_require_publication_root_identity "$root" "$label root" || return 1
    package_require_publication_artifact_identity "$source" "$label source" || return 1
    if [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$source]:-}" ]]; then
        kind='tree'
        expected="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$source]}"
    else
        kind='file'
        expected="${PACKAGE_PUBLICATION_FILE_IDENTITIES[$source]}"
    fi
    local status=0
    package_identity_bound_move "$source" "$destination" "$expected" "$kind" "$root" \
        "${PACKAGE_PUBLICATION_ROOT_IDENTITIES[$root]}" "$label" || status=$?
    if ((status != 0)); then
        # The mutator may have completed and then been wrapped by a process
        # which returns an injected error. Only the exact expected inode at the
        # destination, with the source absent and the locked root unchanged,
        # is a committed move.
        if package_require_publication_root_identity "$root" "$label reconciliation root" &&
            [[ ! -e "$source" && ! -L "$source" ]] &&
            package_reconcile_artifact_location "$destination" "$expected" "$kind"; then
            PACKAGE_LAST_MOVE_COMMITTED=1
        fi
        if ((PACKAGE_LAST_MOVE_COMMITTED == 0)); then
            return "$status"
        fi
    else
        PACKAGE_LAST_MOVE_COMMITTED=1
    fi
    unset 'PACKAGE_CLEANUP_ROOT_IDENTITIES[$source]'
    unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$source]'
    unset 'PACKAGE_CLEANUP_ROOT_IDENTITIES[$destination]'
    unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$destination]'
    if [[ "$kind" == tree ]]; then
        PACKAGE_CLEANUP_ROOT_IDENTITIES["$destination"]="$expected"
    else
        PACKAGE_PUBLICATION_FILE_IDENTITIES["$destination"]="$expected"
    fi
    ((status == 0)) || return "$status"
}

package_safe_recursive_remove() {
    local root="$1"
    local candidate="$2"
    local label="$3"
    local basename="${candidate##*/}"
    local expected
    expected="$(package_safe_child_path "$root" "$basename" "$label")" || return 1
    [[ "$candidate" == "$expected" ]] || {
        printf '%s is not the validated direct child path: %q\n' "$label" "$candidate" >&2
        return 1
    }
    if [[ -L "$candidate" ]]; then
        printf '%s must not be a symlink before recursive removal: %q\n' "$label" "$candidate" >&2
        return 1
    fi
    package_remove_captured_cleanup_root "$candidate" "$label"
}

# Publication locks live below their output root, so retaining only the lock
# descriptor is insufficient when another same-UID process atomically replaces
# the root directory. Bind every locked root to its device/inode and reject all
# later pathname mutations if that identity changes.
if ! declare -p PACKAGE_PUBLICATION_ROOT_IDENTITIES >/dev/null 2>&1; then
    declare -gA PACKAGE_PUBLICATION_ROOT_IDENTITIES=()
fi
if ! declare -p PACKAGE_PUBLICATION_ROOT_LOCK_FDS >/dev/null 2>&1; then
    declare -gA PACKAGE_PUBLICATION_ROOT_LOCK_FDS=()
fi

package_publication_root_identity() {
    local root="$1"
    [[ -d "$root" && ! -L "$root" ]] || return 1
    stat -c '%d:%i' -- "$root"
}

package_require_publication_root_identity() {
    local root="$1"
    local label="${2:-package publication root}"
    local expected="${PACKAGE_PUBLICATION_ROOT_IDENTITIES[$root]:-}"
    local actual=""
    [[ -n "$expected" ]] || {
        printf '%s was not bound by a publication lock: %q\n' "$label" "$root" >&2
        return 1
    }
    actual="$(package_publication_root_identity "$root" 2>/dev/null)" || true
    [[ -n "$actual" && "$actual" == "$expected" ]] || {
        printf '%s identity changed; refusing pathname mutation: %q\n' "$label" "$root" >&2
        return 1
    }
}

package_require_all_publication_roots() {
    local root
    for root in "${PACKAGE_PUBLICATION_ROOTS[@]}"; do
        package_require_publication_root_identity "$root" "package publication root" || return 1
    done
}

# Acquire an advisory writer lock for one package identity in a canonical output
# root.  The descriptor remains open in the caller until the packaging process
# exits, so the lock covers terminal promotion and any EXIT-trap rollback.
package_acquire_publication_lock() {
    local root="$1"
    local identity="$2"
    local output_name="$3"
    package_require_noncolliding_output_name "$output_name" \
        'root identity id output_name root_identity_before root_identity_after root_lock_fd root_fd_identity lock_root owner mode lock_path lock_fd previous_umask path_identity fd_identity link_count label value pattern' \
        'package publication lock output' || return 1
    package_require_safe_component "publication lock identity" "$identity" || return 1

    command -v flock >/dev/null 2>&1 || {
        printf 'missing required packaging tool: flock\n' >&2
        return 1
    }

    local root_identity_before root_identity_after root_lock_fd root_fd_identity
    root_identity_before="$(package_publication_root_identity "$root")" || {
        printf 'package publication root is not a real directory: %q\n' "$root" >&2
        return 1
    }

    # The publication root itself is the non-splittable lock authority. A lock
    # file below it can be renamed away by another same-UID process, creating a
    # second inode and admitting two writers. Directory flock keeps all writers
    # for this exact root inode serialized even if the compatibility lock-file
    # namespace is replaced.
    if [[ -n "${PACKAGE_PUBLICATION_ROOT_LOCK_FDS[$root]:-}" ]]; then
        root_lock_fd="${PACKAGE_PUBLICATION_ROOT_LOCK_FDS[$root]}"
        root_fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$root_lock_fd")" || return 1
        [[ "$root_fd_identity" == "$root_identity_before" ]] || return 1
    else
        if declare -F package_publication_lock_hook >/dev/null 2>&1; then
            package_publication_lock_hook before-root-open "$root" "$root_identity_before" ||
                return 1
        fi
        # Resolve an explicit directory child rather than opening the bare
        # pathname. If a same-UID peer replaces the validated directory with a
        # FIFO (or any non-directory) at this boundary, path resolution fails
        # promptly instead of blocking in open(2). The descriptor and pathname
        # identity checks below remain authoritative for directory swaps.
        exec {root_lock_fd}<"$root/." || return 1
        root_fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$root_lock_fd")" || return 1
        [[ "$root_fd_identity" == "$root_identity_before" ]] || return 1
        flock -x "$root_lock_fd" || return 1
        PACKAGE_PUBLICATION_ROOT_LOCK_FDS["$root"]="$root_lock_fd"
    fi
    root_identity_after="$(package_publication_root_identity "$root")" || return 1
    [[ "$root_identity_after" == "$root_identity_before" ]] || {
        printf 'package publication root identity changed while acquiring root lock: %q\n' "$root" >&2
        return 1
    }

    local lock_root="$root/.oxidedns-package-locks"
    if [[ -e "$lock_root" || -L "$lock_root" ]]; then
        [[ -d "$lock_root" && ! -L "$lock_root" ]] || {
            printf 'package publication lock root is not a real directory: %q\n' "$lock_root" >&2
            return 1
        }
    else
        # Two first-time publishers can both observe an absent lock root.  A
        # failed mkdir is harmless when the competing publisher created the
        # exact safe directory; the ownership/mode checks below remain the
        # authority and reject every other winner-created object.
        mkdir -m 0700 -- "$lock_root" 2>/dev/null ||
            [[ -d "$lock_root" && ! -L "$lock_root" ]] || return 1
    fi
    local owner mode
    owner="$(stat -c '%u' -- "$lock_root")" || return 1
    mode="$(stat -c '%a' -- "$lock_root")" || return 1
    [[ "$owner" == "$(id -u)" && "$mode" =~ ^[0-7]+$ ]] || return 1
    mode=$((8#$mode))
    ((!(mode & 0077))) || {
        printf 'package publication lock root is not private: %q\n' "$lock_root" >&2
        return 1
    }

    local lock_path="$lock_root/$identity.lock"
    [[ ! -L "$lock_path" ]] || {
        printf 'package publication lock must not be a symlink: %q\n' "$lock_path" >&2
        return 1
    }
    local lock_fd previous_umask
    previous_umask="$(umask)" || return 1
    umask 077
    if ! exec {lock_fd}<>"$lock_path"; then
        umask "$previous_umask"
        return 1
    fi
    umask "$previous_umask"
    chmod 0600 -- "$lock_path" || return 1
    local path_identity fd_identity link_count
    [[ -f "$lock_path" && ! -L "$lock_path" ]] || return 1
    owner="$(stat -c '%u' -- "$lock_path")" || return 1
    mode="$(stat -c '%a' -- "$lock_path")" || return 1
    link_count="$(stat -c '%h' -- "$lock_path")" || return 1
    path_identity="$(stat -c '%d:%i' -- "$lock_path")" || return 1
    fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$lock_fd")" || return 1
    [[ "$owner" == "$(id -u)" && "$mode" == 600 && "$link_count" == 1 &&
    "$path_identity" == "$fd_identity" ]] || {
        printf 'package publication lock identity changed: %q\n' "$lock_path" >&2
        return 1
    }
    root_identity_after="$(package_publication_root_identity "$root")" || return 1
    [[ "$root_identity_after" == "$root_identity_before" ]] || {
        printf 'package publication root identity changed while acquiring lock: %q\n' "$root" >&2
        return 1
    }
    if [[ -n "${PACKAGE_PUBLICATION_ROOT_IDENTITIES[$root]:-}" &&
        "${PACKAGE_PUBLICATION_ROOT_IDENTITIES[$root]}" != "$root_identity_after" ]]; then
        printf 'package publication root has conflicting locked identities: %q\n' "$root" >&2
        return 1
    fi
    PACKAGE_PUBLICATION_ROOT_IDENTITIES["$root"]="$root_identity_after"
    # The root descriptor, rather than the replaceable lock-file descriptor, is
    # the lifetime authority returned to the caller.
    exec {lock_fd}>&-
    printf -v "$output_name" '%s' "$root_lock_fd"
}

package_canonical_docker_image_ref() {
    local image_ref="$1"
    python3 - "$image_ref" <<'PY'
import re
import sys

reference = sys.argv[1]
if not reference or any(character.isspace() for character in reference) or "@" in reference:
    raise SystemExit("Docker publication requires a mutable image tag, not an empty, spaced, or digest reference")

last_slash = reference.rfind("/")
last_colon = reference.rfind(":")
if last_colon > last_slash:
    name = reference[:last_colon]
    tag = reference[last_colon + 1 :]
else:
    name = reference
    tag = "latest"

parts = name.split("/")
if not all(parts) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", tag):
    raise SystemExit(f"invalid Docker image tag: {reference}")

first = parts[0]
if first in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
    registry = "docker.io"
    path = parts[1:]
elif "." in first or ":" in first or first == "localhost":
    registry = first.lower()
    path = parts[1:]
else:
    registry = "docker.io"
    path = parts

if registry == "docker.io" and len(path) == 1:
    path.insert(0, "library")
if not path or any(not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", component) for component in path):
    raise SystemExit(f"invalid Docker repository name: {reference}")

print(f"{registry}/{'/'.join(path)}:{tag}")
PY
}

# Derive a diagnostic tag that can never equal the caller-provided clean tag.
# Append even when the requested tag already carries the diagnostic marker: a
# clean publisher is allowed to choose such a tag explicitly, so reusing it
# would let a dirty run replace clean daemon state.
package_nonrelease_docker_image_ref() {
    local image_ref="$1"
    local last_component="${image_ref##*/}"
    local diagnostic_ref
    if [[ "$last_component" == *:* ]]; then
        diagnostic_ref="$image_ref-nonrelease-dirty"
    else
        diagnostic_ref="$image_ref:latest-nonrelease-dirty"
    fi
    package_canonical_docker_image_ref "$diagnostic_ref" >/dev/null || return 1
    printf '%s\n' "$diagnostic_ref"
}

package_nonrelease_dynamic_docker_image_ref() {
    local image_ref="$1"
    local last_component="${image_ref##*/}"
    local diagnostic_ref
    if [[ "$last_component" == *:* ]]; then
        diagnostic_ref="$image_ref-nonrelease-dynamic"
    else
        diagnostic_ref="$image_ref:latest-nonrelease-dynamic"
    fi
    package_canonical_docker_image_ref "$diagnostic_ref" >/dev/null || return 1
    printf '%s\n' "$diagnostic_ref"
}

# Dirty builds are published only under this reserved tag suffix. Clean builds
# must never be allowed to select the same namespace, otherwise a clean explicit
# tag can alias the transformed tag of a dirty build.
package_require_clean_docker_image_ref() {
    local image_ref="$1"
    local canonical_ref tag
    canonical_ref="$(package_canonical_docker_image_ref "$image_ref")" || return 1
    tag="${canonical_ref##*:}"
    [[ "$tag" != *-nonrelease-dirty && "$tag" != *-nonrelease-dynamic ]] || {
        printf 'clean Docker publication may not use the reserved diagnostic tag namespace: %q\n' \
            "$image_ref" >&2
        return 1
    }
}

# Bind a compressed Docker archive to its adjacent checksum and to the image
# identity authenticated by the archive verifier. Call this at every stable
# publication boundary; valid XZ padding and pathname replacement both change
# the content checksum even when the embedded Docker identity is unchanged.
package_verify_docker_archive_bundle() {
    local archive_path="$1" checksum_path="$2" verifier="$3"
    local expected_image_id="$4" expected_image_ref="$5"
    local observed observed_image_id observed_image_ref checksum_name
    local expected_checksum actual_checksum archive_name
    [[ -f "$archive_path" && ! -L "$archive_path" && -f "$checksum_path" &&
        ! -L "$checksum_path" && -f "$verifier" && ! -L "$verifier" ]] || return 1
    archive_name="$(basename "$archive_path")"
    checksum_name="$(basename "$checksum_path")"
    [[ "$checksum_name" == "$archive_name.sha256" ]] || return 1
    expected_checksum="$(<"$checksum_path")"
    if command -v sha256sum >/dev/null 2>&1; then
        actual_checksum="$(cd "$(dirname "$archive_path")" && sha256sum "$archive_name")" || return 1
    elif command -v shasum >/dev/null 2>&1; then
        actual_checksum="$(cd "$(dirname "$archive_path")" && shasum -a 256 "$archive_name")" || return 1
    else
        return 1
    fi
    [[ "$actual_checksum" == "$expected_checksum" ]] || return 1
    observed="$(python3 "$verifier" "$archive_path")" || return 1
    IFS=$'\t' read -r observed_image_id observed_image_ref <<<"$observed"
    [[ "$observed_image_id" == "$expected_image_id" &&
        "$observed_image_ref" == "$expected_image_ref" ]]
}

# Verify one archive into a private descriptor-backed staging file, stream only
# those verified bytes, and supervise the complete decompressor/daemon pipeline
# as one process group.  Both verifier backpressure and a Docker daemon that
# stops consuming input are therefore bounded by CLOCK_BOOTTIME cleanup.
package_load_verified_docker_archive() {
    local archive="$1" verifier="$2" supervisor="$3" output_name="$4"
    local timeout_seconds="${OXIDEDNS_DOCKER_LOAD_TIMEOUT_SECONDS:-600}"
    [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_name" in
    archive | verifier | supervisor | output_name | timeout_seconds | python_bin | xz_bin | docker_bin | loaded_output)
        return 1
        ;;
    esac
    [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
        printf 'OXIDEDNS_DOCKER_LOAD_TIMEOUT_SECONDS must be a canonical positive integer\n' >&2
        return 1
    }
    ((${#timeout_seconds} < 4 || (${#timeout_seconds} == 4 && timeout_seconds <= 3600))) || {
        printf 'OXIDEDNS_DOCKER_LOAD_TIMEOUT_SECONDS exceeds 3600\n' >&2
        return 1
    }
    [[ -f "$archive" && ! -L "$archive" && -f "$verifier" && ! -L "$verifier" &&
        -f "$supervisor" && ! -L "$supervisor" ]] || return 1
    local python_bin xz_bin docker_bin loaded_output=""
    python_bin="$(realpath -e "$(command -v python3)")" || return 1
    xz_bin="$(realpath -e "$(command -v xz)")" || return 1
    docker_bin="$(realpath -e "$(command -v docker)")" || return 1
    loaded_output="$(
        # The positional parameters are intentionally expanded by the isolated
        # child Bash, not by this packaging shell.
        # shellcheck disable=SC2016
        "$python_bin" "$supervisor" --timeout-seconds "$timeout_seconds" \
            --termination-grace-seconds 2 -- /usr/bin/bash -o pipefail -c \
            '"$1" "$2" --stream-verified-archive "$3" | "$4" -dc | "$5" load' \
            _ "$python_bin" "$verifier" "$archive" "$xz_bin" "$docker_bin"
    )" || return 1
    printf -v "$output_name" '%s' "$loaded_output"
}

package_acquire_docker_image_lock() {
    local image_ref="$1"
    local output_fd_name="$2"
    local output_canonical_name="${3:-}"
    local forbidden_output_names='image_ref output_fd_name output_canonical_name forbidden_output_names canonical_ref digest lock_root owner mode root identity id output_name root_identity_before root_identity_after root_lock_fd root_fd_identity lock_path lock_fd previous_umask path_identity fd_identity link_count label value pattern'
    package_require_noncolliding_output_name "$output_fd_name" "$forbidden_output_names" \
        'Docker image lock descriptor output' || return 1
    if [[ -n "$output_canonical_name" ]]; then
        package_require_noncolliding_output_name "$output_canonical_name" \
            "$forbidden_output_names" 'Docker canonical image output' || return 1
        [[ "$output_canonical_name" != "$output_fd_name" ]] || {
            printf 'Docker lock outputs must use distinct variable names: %s\n' \
                "$output_fd_name" >&2
            return 1
        }
    fi
    local canonical_ref digest lock_root owner mode
    canonical_ref="$(package_canonical_docker_image_ref "$image_ref")" || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        digest="$(printf '%s\0' "$canonical_ref" | sha256sum | awk '{ print $1 }')" || return 1
    elif command -v shasum >/dev/null 2>&1; then
        digest="$(printf '%s\0' "$canonical_ref" | shasum -a 256 | awk '{ print $1 }')" || return 1
    else
        printf 'Docker publication locking requires sha256sum or shasum\n' >&2
        return 1
    fi
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1

    lock_root="${OXIDEDNS_PACKAGE_DOCKER_LOCK_ROOT:-/tmp/oxidedns-package-docker-locks-$(id -u)}"
    if [[ -e "$lock_root" || -L "$lock_root" ]]; then
        [[ -d "$lock_root" && ! -L "$lock_root" ]] || {
            printf 'Docker publication lock root is not a real directory: %q\n' "$lock_root" >&2
            return 1
        }
    else
        mkdir -m 0700 -- "$lock_root" 2>/dev/null ||
            [[ -d "$lock_root" && ! -L "$lock_root" ]] || return 1
    fi
    lock_root="$(realpath -e -- "$lock_root")" || return 1
    owner="$(stat -c '%u' -- "$lock_root")" || return 1
    mode="$(stat -c '%a' -- "$lock_root")" || return 1
    [[ "$owner" == "$(id -u)" && "$mode" =~ ^[0-7]+$ ]] || return 1
    mode=$((8#$mode))
    ((!(mode & 0077))) || {
        printf 'Docker publication lock root is not private: %q\n' "$lock_root" >&2
        return 1
    }

    package_acquire_publication_lock "$lock_root" "image-ref-$digest" "$output_fd_name" || return 1
    if [[ -n "$output_canonical_name" ]]; then
        printf -v "$output_canonical_name" '%s' "$canonical_ref"
    fi
}

package_publication_reset() {
    PACKAGE_PUBLICATION_COMPLETE=0
    PACKAGE_PUBLICATION_COUNT=0
    PACKAGE_PUBLICATION_ROLLBACK_FAILED=0
    PACKAGE_PUBLICATION_RETAIN_ROOT="${1:-}"
    PACKAGE_PUBLICATION_TOKEN="$(basename -- "${1:-publication}")-$$"
    PACKAGE_MUTATION_CRITICAL=0
    PACKAGE_PENDING_SIGNAL_STATUS=0
    PACKAGE_SIGNAL_CLEANUP_RUNNING=0
    PACKAGE_LAST_MOVE_COMMITTED=0
    PACKAGE_LAST_REMOVE_COMMITTED=0
    PACKAGE_LAST_RESTORE_COMMITTED=0
    # Read by removal callers after this transaction reset returns.
    # shellcheck disable=SC2034
    PACKAGE_LAST_REMOVE_QUARANTINE=""
    PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC=""
    PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY=""
    declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINES=()
    declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES=()
    declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENTS=()
    declare -g -a PACKAGE_RETAINED_REMOVAL_QUARANTINE_PARENT_IDENTITIES=()
    declare -gA PACKAGE_PUBLICATION_ROOT_IDENTITIES=()
    declare -gA PACKAGE_CLEANUP_ROOT_IDENTITIES=()
    declare -gA PACKAGE_PUBLICATION_FILE_IDENTITIES=()
    declare -g -a PACKAGE_PUBLICATION_DESTINATIONS=()
    declare -g -a PACKAGE_PUBLICATION_BACKUPS=()
    declare -g -a PACKAGE_PUBLICATION_ROOTS=()
    declare -g -a PACKAGE_PUBLICATION_LABELS=()
    declare -g -a PACKAGE_PUBLICATION_PROMOTED=()
    if [[ -n "$PACKAGE_PUBLICATION_RETAIN_ROOT" ]]; then
        package_capture_cleanup_root "$PACKAGE_PUBLICATION_RETAIN_ROOT" \
            "package publication retained root" || return 1
    fi
}

package_publish_candidate() {
    local candidate="$1"
    local destination="$2"
    local root="$3"
    local label="$4"
    local index="$PACKAGE_PUBLICATION_COUNT"
    local basename="${destination##*/}"
    local expected
    package_require_publication_root_identity "$root" "$label root" || return 1
    expected="$(package_safe_child_path "$root" "$basename" "$label")" || return 1
    [[ "$destination" == "$expected" && ! -L "$destination" ]] || {
        printf 'refusing unsafe package publication target: %q\n' "$destination" >&2
        return 1
    }
    [[ -e "$candidate" && ! -L "$candidate" ]] || {
        printf 'package publication candidate is missing or symlinked: %q\n' "$candidate" >&2
        return 1
    }
    package_capture_publication_artifact "$candidate" "$label candidate" || return 1

    local backup="$root/.${basename}.previous.${PACKAGE_PUBLICATION_TOKEN}.${index}"
    [[ ! -e "$backup" && ! -L "$backup" ]] || {
        printf 'package publication backup path already exists: %q\n' "$backup" >&2
        return 1
    }
    PACKAGE_PUBLICATION_DESTINATIONS[index]="$destination"
    PACKAGE_PUBLICATION_BACKUPS[index]=""
    PACKAGE_PUBLICATION_ROOTS[index]="$root"
    PACKAGE_PUBLICATION_LABELS[index]="$label"
    PACKAGE_PUBLICATION_PROMOTED[index]=0
    PACKAGE_PUBLICATION_COUNT=$((PACKAGE_PUBLICATION_COUNT + 1))

    if [[ -e "$destination" || -L "$destination" ]]; then
        package_require_publication_root_identity "$root" "$label root" || return 1
        package_capture_publication_artifact "$destination" "$label previous artifact" || return 1
        package_begin_mutation_critical || return 1
        local move_status=0
        package_move_captured_publication_artifact "$destination" "$backup" "$root" \
            "$label backup" || move_status=$?
        if ((move_status != 0)); then
            if ((PACKAGE_LAST_MOVE_COMMITTED == 1)); then
                PACKAGE_PUBLICATION_BACKUPS[index]="$backup"
            fi
            package_end_mutation_critical
            return "$move_status"
        fi
        local transition_failed=0
        if declare -F package_publication_transition_hook >/dev/null 2>&1; then
            package_publication_transition_hook after-backup-move "$index" "$destination" "$backup" ||
                transition_failed=$?
        fi
        PACKAGE_PUBLICATION_BACKUPS[index]="$backup"
        package_end_mutation_critical
        ((transition_failed == 0)) || return "$transition_failed"
    fi
    if declare -F package_publication_hook >/dev/null 2>&1; then
        package_publication_hook after-backup "$index" "$candidate" "$destination" "$backup" || return 1
    fi
    package_require_publication_root_identity "$root" "$label root" || return 1
    package_begin_mutation_critical || return 1
    local move_status=0
    package_move_captured_publication_artifact "$candidate" "$destination" "$root" \
        "$label promotion" || move_status=$?
    if ((move_status != 0)); then
        if ((PACKAGE_LAST_MOVE_COMMITTED == 1)); then
            PACKAGE_PUBLICATION_PROMOTED[index]=1
        fi
        package_end_mutation_critical
        return "$move_status"
    fi
    local transition_failed=0
    if declare -F package_publication_transition_hook >/dev/null 2>&1; then
        package_publication_transition_hook after-promotion-move "$index" "$candidate" "$destination" ||
            transition_failed=$?
    fi
    PACKAGE_PUBLICATION_PROMOTED[index]=1
    package_end_mutation_critical
    ((transition_failed == 0)) || return "$transition_failed"
    if declare -F package_publication_hook >/dev/null 2>&1; then
        package_publication_hook after-promote "$index" "$candidate" "$destination" "$backup" || return 1
    fi
    package_require_publication_root_identity "$root" "$label root" || return 1
}

# Transactionally remove an obsolete stable output.  The destination is moved
# to the same rollback namespace used by package_publish_candidate(), but no
# replacement is promoted.  Commit deletes the backup; rollback restores it.
package_remove_destination() {
    local destination="$1"
    local root="$2"
    local label="$3"
    local index="$PACKAGE_PUBLICATION_COUNT"
    local basename="${destination##*/}"
    local expected
    package_require_publication_root_identity "$root" "$label root" || return 1
    expected="$(package_safe_child_path "$root" "$basename" "$label")" || return 1
    [[ "$destination" == "$expected" && ! -L "$destination" ]] || {
        printf 'refusing unsafe package removal target: %q\n' "$destination" >&2
        return 1
    }

    local backup="$root/.${basename}.previous.${PACKAGE_PUBLICATION_TOKEN}.${index}"
    [[ ! -e "$backup" && ! -L "$backup" ]] || {
        printf 'package publication backup path already exists: %q\n' "$backup" >&2
        return 1
    }
    PACKAGE_PUBLICATION_DESTINATIONS[index]="$destination"
    PACKAGE_PUBLICATION_BACKUPS[index]=""
    PACKAGE_PUBLICATION_ROOTS[index]="$root"
    PACKAGE_PUBLICATION_LABELS[index]="$label"
    PACKAGE_PUBLICATION_PROMOTED[index]=0
    PACKAGE_PUBLICATION_COUNT=$((PACKAGE_PUBLICATION_COUNT + 1))

    if [[ -e "$destination" || -L "$destination" ]]; then
        package_require_publication_root_identity "$root" "$label root" || return 1
        package_capture_publication_artifact "$destination" "$label previous artifact" || return 1
        package_begin_mutation_critical || return 1
        local move_status=0
        package_move_captured_publication_artifact "$destination" "$backup" "$root" \
            "$label removal backup" || move_status=$?
        if ((move_status != 0)); then
            if ((PACKAGE_LAST_MOVE_COMMITTED == 1)); then
                PACKAGE_PUBLICATION_BACKUPS[index]="$backup"
            fi
            package_end_mutation_critical
            return "$move_status"
        fi
        local transition_failed=0
        if declare -F package_publication_transition_hook >/dev/null 2>&1; then
            package_publication_transition_hook after-removal-backup-move "$index" "$destination" "$backup" ||
                transition_failed=$?
        fi
        PACKAGE_PUBLICATION_BACKUPS[index]="$backup"
        package_end_mutation_critical
        ((transition_failed == 0)) || return "$transition_failed"
    fi
    if declare -F package_publication_hook >/dev/null 2>&1; then
        package_publication_hook after-remove "$index" "" "$destination" "$backup" || return 1
    fi
    package_require_publication_root_identity "$root" "$label root" || return 1
}

package_rollback_publication() {
    local index destination backup root label rollback_failed=0 entry_failed
    for ((index = PACKAGE_PUBLICATION_COUNT - 1; index >= 0; index--)); do
        destination="${PACKAGE_PUBLICATION_DESTINATIONS[index]}"
        backup="${PACKAGE_PUBLICATION_BACKUPS[index]}"
        root="${PACKAGE_PUBLICATION_ROOTS[index]}"
        label="${PACKAGE_PUBLICATION_LABELS[index]}"
        if ! package_require_publication_root_identity "$root" "$label rollback root"; then
            rollback_failed=1
            continue
        fi
        if [[ "${PACKAGE_PUBLICATION_PROMOTED[index]}" == 1 ]]; then
            entry_failed=0
            if ! package_require_publication_root_identity "$root" "$label rollback root"; then
                rollback_failed=1
                continue
            fi
            package_begin_mutation_critical || return 1
            if [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$destination]:-}" ]]; then
                package_safe_recursive_remove "$root" "$destination" "$label rollback output" || {
                    ((PACKAGE_LAST_REMOVE_COMMITTED == 1)) || entry_failed=1
                }
            elif [[ -d "$destination" && ! -L "$destination" ]]; then
                printf 'could not remove unbound recursive %s after publication failure: %q\n' \
                    "$label" "$destination" >&2
                entry_failed=1
            elif [[ -n "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$destination]:-}" ]]; then
                package_remove_captured_publication_file "$destination" "$label rollback output" || {
                    ((PACKAGE_LAST_REMOVE_COMMITTED == 1)) || entry_failed=1
                }
            else
                printf 'could not remove unbound regular %s after publication failure: %q\n' \
                    "$label" "$destination" >&2
                entry_failed=1
            fi
            if ((entry_failed != 0)); then
                package_end_mutation_critical
                rollback_failed=1
                continue
            fi
            if declare -F package_publication_transition_hook >/dev/null 2>&1; then
                package_publication_transition_hook after-rollback-remove "$index" "$destination" "" ||
                    entry_failed=1
            fi
            PACKAGE_PUBLICATION_PROMOTED[index]=0
            package_end_mutation_critical
            if ((entry_failed != 0)); then
                rollback_failed=1
                continue
            fi
        fi
        if [[ -n "$backup" ]]; then
            if declare -F package_publication_hook >/dev/null 2>&1 &&
                ! package_publication_hook before-restore "$index" "$backup" "$destination" "$backup"; then
                rollback_failed=1
                continue
            fi
            if ! package_require_publication_root_identity "$root" "$label rollback root"; then
                rollback_failed=1
                continue
            fi
            if ! package_require_publication_artifact_identity "$backup" "$label rollback backup"; then
                rollback_failed=1
                continue
            fi
            local backup_identity="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$backup]:-${PACKAGE_PUBLICATION_FILE_IDENTITIES[$backup]:-}}"
            entry_failed=0
            package_begin_mutation_critical || return 1
            local restore_status=0 backup_kind=file
            [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$backup]:-}" ]] && backup_kind=tree
            PACKAGE_LAST_RESTORE_COMMITTED=0
            package_identity_bound_restore "$backup" "$destination" "$backup_identity" \
                "$root" "${PACKAGE_PUBLICATION_ROOT_IDENTITIES[$root]}" \
                "$label rollback backup" || restore_status=$?
            if ((restore_status != 0)) && package_require_publication_root_identity \
                "$root" "$label restore reconciliation root" &&
                [[ ! -e "$backup" && ! -L "$backup" ]] &&
                package_reconcile_artifact_location "$destination" "$backup_identity" "$backup_kind"; then
                PACKAGE_LAST_RESTORE_COMMITTED=1
            elif ((restore_status == 0)); then
                PACKAGE_LAST_RESTORE_COMMITTED=1
            fi
            if ((PACKAGE_LAST_RESTORE_COMMITTED == 0)); then
                package_end_mutation_critical
                printf 'could not restore previous %s after publication failure: %q\n' "$label" "$destination" >&2
                rollback_failed=1
            else
                unset 'PACKAGE_CLEANUP_ROOT_IDENTITIES[$backup]'
                unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$backup]'
                if [[ "$backup_kind" == tree ]]; then
                    PACKAGE_CLEANUP_ROOT_IDENTITIES["$destination"]="$backup_identity"
                else
                    PACKAGE_PUBLICATION_FILE_IDENTITIES["$destination"]="$backup_identity"
                fi
                if declare -F package_publication_transition_hook >/dev/null 2>&1; then
                    package_publication_transition_hook after-rollback-restore "$index" "$backup" "$destination" ||
                        entry_failed=1
                fi
                PACKAGE_PUBLICATION_BACKUPS[index]=""
                package_end_mutation_critical
                if ((entry_failed != 0)); then
                    rollback_failed=1
                fi
            fi
        fi
    done
    # Read by caller EXIT traps and recovery-focused harnesses after this
    # shared function returns.
    # shellcheck disable=SC2034
    PACKAGE_PUBLICATION_ROLLBACK_FAILED="$rollback_failed"
    ((rollback_failed == 0))
}

package_commit_publication() {
    package_require_all_publication_roots || return 1
    # Commit before deleting backups. An interruption during backup cleanup may
    # retain harmless previous artifacts but must not roll back a complete set.
    PACKAGE_PUBLICATION_COMPLETE=1
    if declare -F package_publication_hook >/dev/null 2>&1; then
        package_publication_hook after-commit "$PACKAGE_PUBLICATION_COUNT" "" "" "" || return 1
    fi
    package_discard_publication_backups
}

package_discard_publication_backups() {
    local index backup destination expected_backup root label discard_failed=0
    for ((index = 0; index < PACKAGE_PUBLICATION_COUNT; index++)); do
        backup="${PACKAGE_PUBLICATION_BACKUPS[index]}"
        [[ -n "$backup" ]] || continue
        root="${PACKAGE_PUBLICATION_ROOTS[index]}"
        label="${PACKAGE_PUBLICATION_LABELS[index]}"
        destination="${PACKAGE_PUBLICATION_DESTINATIONS[index]}"
        expected_backup="$root/.${destination##*/}.previous.${PACKAGE_PUBLICATION_TOKEN}.${index}"
        if package_is_retained_removal_quarantine "$backup"; then
            printf 'warning: retained identity-bound previous package artifact quarantine: %q\n' \
                "$backup" >&2
            discard_failed=1
            continue
        fi
        if [[ "$backup" != "$expected_backup" ]]; then
            printf 'warning: retained unexpected previous package artifact path: %q\n' "$backup" >&2
            discard_failed=1
            continue
        fi
        if ! package_require_publication_root_identity "$root" "$label commit-cleanup root"; then
            printf 'warning: retained previous package artifact after root identity change: %q\n' \
                "$backup" >&2
            discard_failed=1
            continue
        fi
        if [[ -n "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$backup]:-}" ]]; then
            package_begin_mutation_critical || return 1
            if package_remove_captured_cleanup_root "$backup" "$label previous artifact"; then
                if declare -F package_publication_transition_hook >/dev/null 2>&1; then
                    package_publication_transition_hook after-discard-remove "$index" "$backup" "" ||
                        discard_failed=1
                fi
                PACKAGE_PUBLICATION_BACKUPS[index]=""
                package_end_mutation_critical
            else
                if ((PACKAGE_LAST_REMOVE_COMMITTED == 1)); then
                    unset 'PACKAGE_CLEANUP_ROOT_IDENTITIES[$backup]'
                    PACKAGE_PUBLICATION_BACKUPS[index]=""
                elif [[ -n "$PACKAGE_LAST_REMOVE_QUARANTINE" ]]; then
                    PACKAGE_PUBLICATION_BACKUPS[index]="$PACKAGE_LAST_REMOVE_QUARANTINE"
                    printf 'warning: retained previous package artifact quarantine: %q\n' \
                        "$PACKAGE_LAST_REMOVE_QUARANTINE" >&2
                else
                    printf 'warning: retained previous package artifact: %q\n' "$backup" >&2
                fi
                package_end_mutation_critical
                discard_failed=1
            fi
        elif [[ -n "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$backup]:-}" ]]; then
            package_begin_mutation_critical || return 1
            if ! package_remove_captured_publication_file "$backup" "$label previous artifact"; then
                if ((PACKAGE_LAST_REMOVE_COMMITTED == 1)); then
                    unset 'PACKAGE_PUBLICATION_FILE_IDENTITIES[$backup]'
                    PACKAGE_PUBLICATION_BACKUPS[index]=""
                    printf 'warning: previous package artifact was logically removed into retained quarantine, but its cleanup helper reported failure: %q\n' \
                        "${PACKAGE_LAST_REMOVE_QUARANTINE:-$backup}" >&2
                elif [[ -n "$PACKAGE_LAST_REMOVE_QUARANTINE" ]]; then
                    PACKAGE_PUBLICATION_BACKUPS[index]="$PACKAGE_LAST_REMOVE_QUARANTINE"
                    printf 'warning: retained previous package artifact quarantine: %q\n' \
                        "$PACKAGE_LAST_REMOVE_QUARANTINE" >&2
                else
                    printf 'warning: retained previous package artifact: %q\n' "$backup" >&2
                fi
                package_end_mutation_critical
                discard_failed=1
            else
                if declare -F package_publication_transition_hook >/dev/null 2>&1; then
                    package_publication_transition_hook after-discard-remove "$index" "$backup" "" ||
                        discard_failed=1
                fi
                PACKAGE_PUBLICATION_BACKUPS[index]=""
                package_end_mutation_critical
            fi
        else
            printf 'warning: retained unbound previous package artifact: %q\n' "$backup" >&2
            discard_failed=1
        fi
    done
    ((discard_failed == 0))
}

package_cleanup_publication() {
    local status="${1:-$?}"
    local remove_retain_root="${2:-1}"
    [[ "$remove_retain_root" == 0 || "$remove_retain_root" == 1 ]] || return 64
    if [[ "${PACKAGE_PUBLICATION_COMPLETE:-0}" != 1 ]]; then
        if ! package_rollback_publication; then
            if ! package_write_publication_recovery_diagnostic; then
                printf 'warning: failed to write package publication recovery diagnostic under %q\n' \
                    "${PACKAGE_PUBLICATION_RETAIN_ROOT:-unknown}" >&2
            fi
            printf 'package publication rollback is incomplete; retained recovery diagnostic: %q\n' \
                "${PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC:-unavailable}" >&2
            return 74
        fi
    else
        if ! package_discard_publication_backups; then
            if ! package_write_publication_recovery_diagnostic; then
                printf 'warning: failed to write package publication recovery diagnostic under %q\n' \
                    "${PACKAGE_PUBLICATION_RETAIN_ROOT:-unknown}" >&2
            fi
            printf 'package publication cleanup is incomplete; retained recovery diagnostic: %q\n' \
                "${PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC:-unavailable}" >&2
            return 74
        fi
    fi
    if [[ -n "${PACKAGE_PUBLICATION_RETAIN_ROOT:-}" ]]; then
        if ! package_require_all_publication_roots; then
            printf 'package publication root identity changed; retained recovery state under %q\n' \
                "$PACKAGE_PUBLICATION_RETAIN_ROOT" >&2
            return 74
        fi
        if [[ "$remove_retain_root" == 1 ]]; then
            package_remove_captured_cleanup_root "$PACKAGE_PUBLICATION_RETAIN_ROOT" \
                "package publication retained root" || return 74
        fi
    fi
    return "$status"
}
