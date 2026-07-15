#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  borondns-perf-capture stat --pid PID --duration SECONDS --events EVENTS --output PATH
  borondns-perf-capture record --pid PID --duration SECONDS --frequency HZ --output PATH

This helper is intended to be installed root-owned and called through a narrow
sudoers rule. It only profiles processes owned by the invoking user.
EOF
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf 'borondns-perf-capture must run as root through sudo or pkexec\n' >&2
    exit 77
fi

target_uid="${SUDO_UID:-${PKEXEC_UID:-}}"
target_gid="${SUDO_GID:-}"
if [[ -z "$target_uid" || ! "$target_uid" =~ ^[0-9]+$ ]]; then
    printf 'missing invoking user uid in SUDO_UID or PKEXEC_UID\n' >&2
    exit 77
fi
if [[ -z "$target_gid" || ! "$target_gid" =~ ^[0-9]+$ ]]; then
    target_gid="$(awk -F: -v uid="$target_uid" '$3 == uid { print $4; exit }' /etc/passwd)"
fi
if [[ -z "$target_gid" || ! "$target_gid" =~ ^[0-9]+$ ]]; then
    printf 'could not resolve invoking user gid for uid %s\n' "$target_uid" >&2
    exit 77
fi

mode="${1:-}"
shift || true
case "$mode" in
stat | record) ;;
*)
    usage
    exit 64
    ;;
esac

pid=""
duration=""
events="cycles,instructions,branches,branch-misses"
frequency="99"
output=""
while (($# > 0)); do
    case "$1" in
    --pid)
        pid="${2:-}"
        shift 2
        ;;
    --duration)
        duration="${2:-}"
        shift 2
        ;;
    --events)
        events="${2:-}"
        shift 2
        ;;
    --frequency)
        frequency="${2:-}"
        shift 2
        ;;
    --output)
        output="${2:-}"
        shift 2
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 64
        ;;
    esac
done

if ! [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'invalid pid: %s\n' "$pid" >&2
    exit 64
fi
if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]]; then
    printf 'invalid duration seconds: %s\n' "$duration" >&2
    exit 64
fi
if ! [[ "$frequency" =~ ^[1-9][0-9]*$ ]]; then
    printf 'invalid perf record frequency: %s\n' "$frequency" >&2
    exit 64
fi
if [[ -z "$output" || "$output" == -* ]]; then
    printf 'invalid output path: %s\n' "$output" >&2
    exit 64
fi
if ! [[ "$events" =~ ^[A-Za-z0-9_.,:=-]+$ ]]; then
    printf 'perf events contain unsupported characters: %s\n' "$events" >&2
    exit 64
fi
if [[ ! -r "/proc/$pid/status" ]]; then
    printf 'target process is not readable: %s\n' "$pid" >&2
    exit 66
fi

process_uid="$(awk '/^Uid:/ { print $2; exit }' "/proc/$pid/status")"
if [[ "$process_uid" != "$target_uid" ]]; then
    printf 'refusing to profile pid %s owned by uid %s for invoking uid %s\n' \
        "$pid" "$process_uid" "$target_uid" >&2
    exit 77
fi

output_dir="$(dirname -- "$output")"
if [[ ! -d "$output_dir" ]]; then
    printf 'output directory does not exist: %s\n' "$output_dir" >&2
    exit 66
fi
dir_owner="$(stat -c '%u' "$output_dir")"
if [[ "$dir_owner" != "$target_uid" ]]; then
    printf 'refusing output directory owned by uid %s for invoking uid %s: %s\n' \
        "$dir_owner" "$target_uid" "$output_dir" >&2
    exit 77
fi

case "$mode" in
stat)
    perf stat -e "$events" -p "$pid" -o "$output" -- sleep "$duration"
    ;;
record)
    perf record -F "$frequency" -g -p "$pid" -o "$output" -- sleep "$duration"
    ;;
esac

chown "$target_uid:$target_gid" "$output" 2>/dev/null || true
