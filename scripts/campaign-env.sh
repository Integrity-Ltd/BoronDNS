#!/usr/bin/env bash

# Strict, non-executing campaign metadata codec. Values are canonical base64 so
# paths and lists remain lossless without ever sourcing plan-controlled text.

campaign_env_write() {
    local key="$1"
    local value="$2"
    [[ "$key" =~ ^[a-z][a-z0-9_]*$ ]] || {
        printf 'invalid campaign metadata key: %s\n' "$key" >&2
        return 1
    }
    local encoded
    encoded="$(printf '%s' "$value" | base64 | tr -d '\n')" || return 1
    printf '%s=base64:%s\n' "$key" "$encoded"
}

campaign_env_load() {
    local path="$1"
    shift
    local whitelist=" $* " line key encoded decoded canonical expected_key value item
    local -A seen=()
    local -A decoded_values=()
    local -a list_items=()
    local line_number=0
    # Output assignment follows Bash dynamic scope. Validate every requested
    # metadata key before unsetting caller state or reading the file, and reject
    # implementation locals that would otherwise absorb the decoded value.
    for expected_key in "$@"; do
        [[ "$expected_key" =~ ^[a-z][a-z0-9_]*$ ]] || {
            printf 'invalid campaign metadata output key: %s\n' "$expected_key" >&2
            return 1
        }
        case "$expected_key" in
        path | whitelist | line | key | encoded | decoded | canonical | expected_key | \
            value | item | seen | decoded_values | list_items | line_number)
            printf 'campaign metadata output key collides with helper state: %s\n' \
                "$expected_key" >&2
            return 1
            ;;
        esac
    done
    [[ -r "$path" ]] || {
        printf 'missing campaign metadata: %s\n' "$path" >&2
        return 1
    }
    for expected_key in "$@"; do
        unset -v "$expected_key"
    done
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ ! "$line" =~ ^([a-z][a-z0-9_]*)=base64:([A-Za-z0-9+/]*={0,2})$ ]]; then
            printf 'malformed campaign metadata at %s:%s\n' "$path" "$line_number" >&2
            return 1
        fi
        key="${BASH_REMATCH[1]}"
        encoded="${BASH_REMATCH[2]}"
        [[ "$whitelist" == *" $key "* ]] || {
            printf 'unknown campaign metadata key at %s:%s: %s\n' "$path" "$line_number" "$key" >&2
            return 1
        }
        [[ -z "${seen[$key]:-}" ]] || {
            printf 'duplicate campaign metadata key at %s:%s: %s\n' "$path" "$line_number" "$key" >&2
            return 1
        }
        if ! decoded="$(printf '%s' "$encoded" | base64 --decode 2>/dev/null)"; then
            printf 'invalid campaign metadata encoding at %s:%s\n' "$path" "$line_number" >&2
            return 1
        fi
        canonical="$(printf '%s' "$decoded" | base64 | tr -d '\n')" || return 1
        [[ "$canonical" == "$encoded" ]] || {
            printf 'non-canonical campaign metadata encoding at %s:%s\n' "$path" "$line_number" >&2
            return 1
        }
        decoded_values[$key]="$decoded"
        seen[$key]=1
    done <"$path"

    for expected_key in "$@"; do
        [[ -n "${seen[$expected_key]:-}" ]] || {
            printf 'missing campaign metadata key in %s: %s\n' "$path" "$expected_key" >&2
            return 1
        }
        value="${decoded_values[$expected_key]}"
        case "$expected_key" in
        source_commit)
            [[ "$value" =~ ^[0-9a-f]{40,64}$ ]] || {
                printf 'invalid campaign commit hash in %s: %s\n' "$path" "$value" >&2
                return 1
            }
            ;;
        source_clean | install_prereqs | allow_skip | sampler_enabled)
            [[ "$value" == 0 || "$value" == 1 ]] || {
                printf 'invalid campaign boolean %s in %s: %s\n' "$expected_key" "$path" "$value" >&2
                return 1
            }
            ;;
        duration_seconds | scenario_timeout_seconds | scenario_kill_after_seconds | docker_cleanup_timeout_seconds | cycle_sleep_seconds | sample_interval_seconds | target_repeat | sampler_interval_seconds | sampler_deadline_epoch_seconds)
            [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
                printf 'invalid campaign positive integer %s in %s: %s\n' "$expected_key" "$path" "$value" >&2
                return 1
            }
            ;;
        hosts | targets | scenarios)
            # In fuzz plans, hosts is an ordered assignment-slot schedule and
            # may intentionally repeat a physical host to express weighting.
            # Consumers that operate once per machine derive a stable unique
            # list; the encoded list itself remains exact and lossless.
            [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\t'* ]] || {
                printf 'invalid empty or multiline campaign list %s in %s\n' "$expected_key" "$path" >&2
                return 1
            }
            read -r -a list_items <<<"$value"
            ((${#list_items[@]} > 0)) && [[ "${list_items[*]}" == "$value" ]] || {
                printf 'invalid non-canonical campaign list %s in %s\n' "$expected_key" "$path" >&2
                return 1
            }
            for item in "${list_items[@]}"; do
                [[ "$item" =~ ^[A-Za-z0-9_.@:+-]+$ ]] || {
                    printf 'invalid campaign list item for %s in %s: %s\n' "$expected_key" "$path" "$item" >&2
                    return 1
                }
                if [[ "$expected_key" == hosts && "$item" == -* ]]; then
                    printf 'option-like campaign host is forbidden in %s: %s\n' "$path" "$item" >&2
                    return 1
                fi
            done
            ;;
        repo_root | remote_repo | remote_evidence)
            [[ "$value" == /* && "$value" != *$'\n'* && "$value" != *$'\t'* ]] || {
                printf 'invalid campaign absolute path %s in %s: %s\n' "$expected_key" "$path" "$value" >&2
                return 1
            }
            ;;
        campaign_id)
            [[ "$value" =~ ^[A-Za-z0-9_.-]+$ ]] || {
                printf 'invalid campaign id in %s: %s\n' "$path" "$value" >&2
                return 1
            }
            ;;
        created_utc)
            [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
                printf 'invalid campaign creation timestamp in %s: %s\n' "$path" "$value" >&2
                return 1
            }
            ;;
        toolchain | sanitizer)
            [[ "$value" =~ ^[A-Za-z0-9_.+-]+$ ]] || {
                printf 'invalid campaign tool selector %s in %s: %s\n' "$expected_key" "$path" "$value" >&2
                return 1
            }
            ;;
        cargo_sha256 | rustc_sha256 | cargo_fuzz_sha256)
            [[ "$value" =~ ^[0-9a-f]{64}$ ]] || {
                printf 'invalid campaign tool digest %s in %s: %s\n' "$expected_key" "$path" "$value" >&2
                return 1
            }
            ;;
        esac
    done
    for expected_key in "$@"; do
        printf -v "$expected_key" '%s' "${decoded_values[$expected_key]}"
    done
}

campaign_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    else
        printf 'missing required campaign SHA-256 implementation (sha256sum or shasum)\n' >&2
        return 1
    fi
}

campaign_scp_remote_path_is_safe() {
    local path="$1"
    # Legacy scp transports pass the remote path through a shell. Keep the
    # fallback narrower than the lossless campaign path codec; paths needing
    # whitespace or shell metacharacters must use the quoted rsync transport.
    [[ "$path" =~ ^/[A-Za-z0-9_./@:+-]+$ ]]
}

# rsync/scp use host:path operands, so a bare IPv6 literal must be bracketed to
# keep its address colons distinct from the remote-path separator. SSH itself
# continues to receive the unbracketed host from the caller.
campaign_remote_copy_host() {
    local host="$1"
    local user="" address="$host"
    [[ "$host" =~ ^[A-Za-z0-9_.@:+-]+$ && "$host" != -* ]] || return 1
    if [[ "$host" == *@* ]]; then
        user="${host%%@*}"
        address="${host#*@}"
        [[ -n "$user" && -n "$address" && "$address" != *@* ]] || return 1
    fi
    if [[ "$address" == *:* ]]; then
        printf '%s[%s]\n' "${user:+$user@}" "$address"
    else
        printf '%s\n' "$host"
    fi
}

campaign_require_transport_integer() {
    local name="$1"
    local value="$2"
    local maximum="$3"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid campaign remote transport %s: %s\n' "$name" "$value" >&2
        return 1
    }
    if ((${#value} > ${#maximum})) ||
        { ((${#value} == ${#maximum})) && [[ "$value" > "$maximum" ]]; }; then
        printf 'campaign remote transport %s exceeds supported maximum %s: %s\n' \
            "$name" "$maximum" "$value" >&2
        return 1
    fi
}

campaign_ssh_bounded() {
    local operation_timeout="$1"
    shift
    local connect_timeout="${BORONDNS_CAMPAIGN_SSH_CONNECT_TIMEOUT_SECONDS:-15}"
    local alive_interval="${BORONDNS_CAMPAIGN_SSH_ALIVE_INTERVAL_SECONDS:-15}"
    local alive_count="${BORONDNS_CAMPAIGN_SSH_ALIVE_COUNT_MAX:-3}"
    campaign_require_transport_integer operation-timeout "$operation_timeout" 86400 || return 1
    campaign_require_transport_integer connect-timeout "$connect_timeout" 300 || return 1
    campaign_require_transport_integer alive-interval "$alive_interval" 300 || return 1
    campaign_require_transport_integer alive-count "$alive_count" 100 || return 1
    local -a transport_argv=(timeout --preserve-status --kill-after=10 "$operation_timeout"
        ssh -o BatchMode=yes -o "ConnectTimeout=$connect_timeout"
        -o "ServerAliveInterval=$alive_interval" -o "ServerAliveCountMax=$alive_count" "$@")
    if [[ -n "${BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE:-}" ]]; then
        campaign_is_positive_signed_64 "$BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE" || return 1
        campaign_run_before_deadline "$BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE" "${transport_argv[@]}"
    else
        "${transport_argv[@]}"
    fi
}

campaign_rsync_bounded() {
    local operation_timeout="$1"
    shift
    local connect_timeout="${BORONDNS_CAMPAIGN_SSH_CONNECT_TIMEOUT_SECONDS:-15}"
    local alive_interval="${BORONDNS_CAMPAIGN_SSH_ALIVE_INTERVAL_SECONDS:-15}"
    local alive_count="${BORONDNS_CAMPAIGN_SSH_ALIVE_COUNT_MAX:-3}"
    local idle_timeout="${BORONDNS_CAMPAIGN_RSYNC_IDLE_TIMEOUT_SECONDS:-120}"
    campaign_require_transport_integer operation-timeout "$operation_timeout" 86400 || return 1
    campaign_require_transport_integer connect-timeout "$connect_timeout" 300 || return 1
    campaign_require_transport_integer alive-interval "$alive_interval" 300 || return 1
    campaign_require_transport_integer alive-count "$alive_count" 100 || return 1
    campaign_require_transport_integer rsync-idle-timeout "$idle_timeout" 3600 || return 1
    local remote_shell
    printf -v remote_shell 'ssh -o BatchMode=yes -o ConnectTimeout=%q -o ServerAliveInterval=%q -o ServerAliveCountMax=%q' \
        "$connect_timeout" "$alive_interval" "$alive_count"
    local -a transport_argv=(timeout --preserve-status --kill-after=10 "$operation_timeout"
        rsync --timeout="$idle_timeout" -e "$remote_shell" "$@")
    if [[ -n "${BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE:-}" ]]; then
        campaign_is_positive_signed_64 "$BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE" || return 1
        campaign_run_before_deadline "$BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE" "${transport_argv[@]}"
    else
        "${transport_argv[@]}"
    fi
}

campaign_scp_bounded() {
    local operation_timeout="$1"
    shift
    local connect_timeout="${BORONDNS_CAMPAIGN_SSH_CONNECT_TIMEOUT_SECONDS:-15}"
    local alive_interval="${BORONDNS_CAMPAIGN_SSH_ALIVE_INTERVAL_SECONDS:-15}"
    local alive_count="${BORONDNS_CAMPAIGN_SSH_ALIVE_COUNT_MAX:-3}"
    campaign_require_transport_integer operation-timeout "$operation_timeout" 86400 || return 1
    campaign_require_transport_integer connect-timeout "$connect_timeout" 300 || return 1
    campaign_require_transport_integer alive-interval "$alive_interval" 300 || return 1
    campaign_require_transport_integer alive-count "$alive_count" 100 || return 1
    local -a transport_argv=(timeout --preserve-status --kill-after=10 "$operation_timeout"
        scp -o BatchMode=yes -o "ConnectTimeout=$connect_timeout"
        -o "ServerAliveInterval=$alive_interval" -o "ServerAliveCountMax=$alive_count" "$@")
    if [[ -n "${BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE:-}" ]]; then
        campaign_is_positive_signed_64 "$BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE" || return 1
        campaign_run_before_deadline "$BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE" "${transport_argv[@]}"
    else
        "${transport_argv[@]}"
    fi
}

campaign_git_status_capture() {
    local output_variable="$1"
    local repository="$2"
    local captured
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_variable" in
    output_variable | repository | captured) return 1 ;;
    esac
    if ! captured="$(timeout --preserve-status --kill-after=5 30 git -C "$repository" status --short --untracked-files=all)"; then
        printf 'git status failed while checking campaign source: %s\n' "$repository" >&2
        return 1
    fi
    printf -v "$output_variable" '%s' "$captured"
}

campaign_lock_child_exited() {
    local pid="$1" stat_line stat_tail state
    if ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    if [[ -r "/proc/$pid/stat" ]]; then
        stat_line="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
        stat_tail="${stat_line##*) }"
        state="${stat_tail%% *}"
        [[ "$state" == Z || "$state" == X ]] && return 0
    fi
    return 1
}

campaign_process_starttime() {
    local pid="$1" output_variable="$2" process_stat process_tail
    local -a process_fields
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_variable" in
    pid | output_variable | process_stat | process_tail | process_fields) return 1 ;;
    esac
    IFS= read -r process_stat <"/proc/$pid/stat" 2>/dev/null || return 1
    process_tail="${process_stat##*) }"
    read -r -a process_fields <<<"$process_tail"
    ((${#process_fields[@]} > 19)) || return 1
    [[ "${process_fields[0]}" != Z && "${process_fields[0]}" != X &&
        "${process_fields[19]}" =~ ^[1-9][0-9]*$ ]] || return 1
    printf -v "$output_variable" '%s' "${process_fields[19]}"
}

campaign_process_matches_identity() {
    local pid="$1" expected_starttime="$2" current_starttime=""
    campaign_process_starttime "$pid" current_starttime || return 1
    [[ "$current_starttime" == "$expected_starttime" ]]
}

campaign_monotonic_nanoseconds() {
    # CLOCK_BOOTTIME, unlike CLOCK_MONOTONIC and relative timeout(1) timers,
    # includes system suspend. Every absolute campaign deadline uses this clock.
    python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))'
}

campaign_deadline_capped() {
    local absolute_deadline="$1" maximum_seconds="$2" now candidate
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    campaign_is_positive_signed_64 "$maximum_seconds" || return 1
    now="$(campaign_monotonic_nanoseconds)" || return 1
    ((maximum_seconds <= (9223372036854775807 - now) / 1000000000)) || return 1
    candidate=$((now + maximum_seconds * 1000000000))
    ((candidate <= absolute_deadline)) || candidate="$absolute_deadline"
    ((candidate > now)) || return 1
    printf '%s\n' "$candidate"
}

campaign_is_positive_signed_64() {
    local value="$1" maximum=9223372036854775807
    local LC_ALL=C
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
    ((${#value} < ${#maximum})) && return 0
    ((${#value} == ${#maximum})) || return 1
    # Equal-width ASCII decimal strings have the same order as their values;
    # arithmetic parsing here would itself overflow for MAX+1.
    # shellcheck disable=SC2071
    [[ "$value" == "$maximum" || "$value" < "$maximum" ]]
}

# Run one command under an absolute CLOCK_BOOTTIME timerfd deadline. GNU
# timeout(1) uses a relative CLOCK_MONOTONIC budget, which is replenished by a
# system suspend. The supervisor owns a process group and kills it on deadline
# or if the supervisor itself is interrupted.
campaign_deadline_forward_signal() {
    local signal_name="$1" signal_number="$2"
    campaign_deadline_forwarded_signal="$signal_number"
    [[ -n "${campaign_deadline_supervisor_pid:-}" &&
        -n "${campaign_deadline_supervisor_job:-}" ]] || return 0
    local active_pid
    active_pid="$(jobs -p "$campaign_deadline_supervisor_job" 2>/dev/null)" || return 0
    [[ "$active_pid" == "$campaign_deadline_supervisor_pid" ]] || return 0
    # The job-table reference is removed by wait before its PID can be reused.
    # Never send a post-wait signal through a bare numeric PID.
    kill -s "$signal_name" "$campaign_deadline_supervisor_job" 2>/dev/null || true
}

campaign_deadline_capture_forward_signal() {
    local signal_name="$1" signal_number="$2"
    campaign_deadline_capture_forwarded_signal="$signal_number"
    [[ -n "${campaign_deadline_capture_pid:-}" ]] || return 0
    # The process-substitution shell remains our unreaped child until the wait
    # below completes.  That pins this numeric PID while forwarding is active.
    kill -s "$signal_name" "$campaign_deadline_capture_pid" 2>/dev/null || true
    # Preserve normal shell cancellation semantics instead of keeping the
    # outer caller alive while Bash defers the process-substitution trap.  The
    # supervisor holds a pidfd for this exact Bash process and synchronously
    # kills/reaps the command group when this owner exits.
    trap - "$signal_name"
    kill -s "$signal_name" "$campaign_deadline_capture_owner_pid" 2>/dev/null || true
}

# Capture textual stdout without placing the deadline supervisor inside a
# command-substitution ancestry.  The caller owns the pipe child, forwards its
# cancellation signals, drains the descriptor, and waits before releasing the
# numeric PID identity.  Trailing newlines are removed to match shell command
# substitution semantics.
campaign_run_before_deadline_capture() {
    local output_variable="$1" absolute_deadline="$2"
    shift 2
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && $# -gt 0 ]] || return 1
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    case "$output_variable" in
    output_variable | absolute_deadline | campaign_deadline_capture_pid | \
        campaign_deadline_capture_fd | campaign_deadline_capture_owner_pid | \
        campaign_deadline_capture_forwarded_signal | captured | capture_status | \
        read_status | setup_status | close_status | spawned_pid | previous_background_pid | \
        previous_int | previous_term | previous_hup)
        return 1
        ;;
    esac
    local campaign_deadline_capture_pid="" campaign_deadline_capture_fd
    local campaign_deadline_capture_owner_pid="$BASHPID"
    local campaign_deadline_capture_forwarded_signal=0 captured="" capture_status=0 read_status=0
    local setup_status=0 close_status=0 spawned_pid="" previous_background_pid="${!:-}"
    local previous_int previous_term previous_hup
    previous_int="$(trap -p INT)"
    previous_term="$(trap -p TERM)"
    previous_hup="$(trap -p HUP)"
    trap 'campaign_deadline_capture_forward_signal INT 2' INT
    trap 'campaign_deadline_capture_forward_signal TERM 15' TERM
    trap 'campaign_deadline_capture_forward_signal HUP 1' HUP
    exec {campaign_deadline_capture_fd}< <(
        BORONDNS_CAMPAIGN_DEADLINE_OWNER_PID="$campaign_deadline_capture_owner_pid" \
            campaign_run_before_deadline "$absolute_deadline" "$@"
    ) || setup_status=$?
    spawned_pid="${!:-}"
    if [[ "$spawned_pid" =~ ^[1-9][0-9]*$ && "$spawned_pid" != "$previous_background_pid" ]]; then
        campaign_deadline_capture_pid="$spawned_pid"
    elif ((setup_status == 0)); then
        setup_status=1
    fi

    if ((setup_status == 0)); then
        if ((campaign_deadline_capture_forwarded_signal != 0)); then
            case "$campaign_deadline_capture_forwarded_signal" in
            1) campaign_deadline_capture_forward_signal HUP 1 ;;
            2) campaign_deadline_capture_forward_signal INT 2 ;;
            15) campaign_deadline_capture_forward_signal TERM 15 ;;
            esac
        fi
        IFS= read -r -d '' captured <&"$campaign_deadline_capture_fd" || read_status=$?
        exec {campaign_deadline_capture_fd}<&- || close_status=$?
        wait "$campaign_deadline_capture_pid" || capture_status=$?
    else
        if [[ "${campaign_deadline_capture_fd:-}" =~ ^[0-9]+$ ]]; then
            exec {campaign_deadline_capture_fd}<&- || true
        fi
        if [[ -n "$campaign_deadline_capture_pid" ]]; then
            # This is a new, unreaped direct process-substitution child. The
            # numeric PID cannot be reused until wait returns, so bounded TERM
            # forwarding cannot target an unrelated process.
            kill -TERM "$campaign_deadline_capture_pid" 2>/dev/null || true
            wait "$campaign_deadline_capture_pid" 2>/dev/null || true
        fi
    fi
    campaign_deadline_capture_pid=""
    trap - INT TERM HUP
    [[ -z "$previous_int" ]] || eval "$previous_int"
    [[ -z "$previous_term" ]] || eval "$previous_term"
    [[ -z "$previous_hup" ]] || eval "$previous_hup"
    # read returns one at normal EOF.  Other failures are meaningful unless a
    # forwarded signal already determines the operation's status.
    if ((campaign_deadline_capture_forwarded_signal != 0)); then
        return $((128 + campaign_deadline_capture_forwarded_signal))
    fi
    ((setup_status == 0)) || return "$setup_status"
    ((close_status == 0)) || return "$close_status"
    ((read_status == 0 || read_status == 1)) || return "$read_status"
    ((capture_status == 0)) || return "$capture_status"
    while [[ "$captured" == *$'\n' ]]; do
        captured="${captured%$'\n'}"
    done
    printf -v "$output_variable" '%s' "$captured"
}

campaign_run_before_deadline() {
    local absolute_deadline="$1"
    shift
    (($# > 0)) || return 1
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    local owner_pids="${BORONDNS_CAMPAIGN_DEADLINE_OWNER_PID:-$BASHPID}"
    if [[ ",$owner_pids," != *",$$,"* ]]; then
        owner_pids+=",$$"
    fi
    # Validate every caller-controlled owner before changing process-global
    # signal dispositions. An invalid override must be a side-effect-free
    # configuration error.
    [[ "$owner_pids" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || return 1
    local campaign_deadline_supervisor_pid="" campaign_deadline_supervisor_job=""
    local campaign_deadline_input_fd
    local termination_tail_seconds="${BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS:-5}"
    local campaign_deadline_forwarded_signal=0 supervisor_status=0 job_line active_pid
    local previous_int previous_term previous_hup
    previous_int="$(trap -p INT)"
    previous_term="$(trap -p TERM)"
    previous_hup="$(trap -p HUP)"
    campaign_require_bounded_positive_integer deadline-termination-tail-seconds \
        "$termination_tail_seconds" 30 || return 1
    # python3 consumes the supervisor program on stdin below. Retain an
    # inheritable duplicate of the caller's stdin so the supervised command
    # receives the original byte stream and EOF instead of the here-document.
    # Bash-managed descriptors are allocated above the standard/control range;
    # the supervisor validates that invariant before using the descriptor.
    exec {campaign_deadline_input_fd}<&0 || return 1
    # Install forwarding before the background supervisor exists. A signal in
    # that narrow window is remembered and forwarded once its owned job-table
    # entry has been captured.
    trap 'campaign_deadline_forward_signal INT 2' INT
    trap 'campaign_deadline_forward_signal TERM 15' TERM
    trap 'campaign_deadline_forward_signal HUP 1' HUP
    BORONDNS_CAMPAIGN_DEADLINE_INPUT_FD="$campaign_deadline_input_fd" \
        BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS="$termination_tail_seconds" \
        python3 - "$absolute_deadline" "$owner_pids" "$@" <<'PY' &
import ctypes
import os
import select
import signal
import sys
import time

deadline = int(sys.argv[1])
owner_pids = [int(value) for value in sys.argv[2].split(",")]
command = sys.argv[3:]
input_fd = int(os.environ["BORONDNS_CAMPAIGN_DEADLINE_INPUT_FD"])
if input_fd <= 2:
    raise RuntimeError("deadline supervisor input descriptor overlaps standard streams")
os.fstat(input_fd)
child_environment = os.environ.copy()
del child_environment["BORONDNS_CAMPAIGN_DEADLINE_INPUT_FD"]
if deadline <= time.clock_gettime_ns(time.CLOCK_BOOTTIME):
    raise SystemExit(124)

owner_fds = []
try:
    for owner_pid in owner_pids:
        owner_fds.append(os.pidfd_open(owner_pid, 0))
except ProcessLookupError:
    # An anchoring shell already exited. Do not start work for an orphaned
    # command-substitution descendant.
    for owner_fd in owner_fds:
        os.close(owner_fd)
    raise SystemExit(143)

libc = ctypes.CDLL(None, use_errno=True)
timerfd_create = libc.timerfd_create
timerfd_create.argtypes = [ctypes.c_int, ctypes.c_int]
timerfd_create.restype = ctypes.c_int
timerfd_settime = libc.timerfd_settime
timerfd_settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
timerfd_settime.restype = ctypes.c_int
signalfd = libc.signalfd
signalfd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
signalfd.restype = ctypes.c_int
sigemptyset = libc.sigemptyset
sigemptyset.argtypes = [ctypes.c_void_p]
sigemptyset.restype = ctypes.c_int
sigaddset = libc.sigaddset
sigaddset.argtypes = [ctypes.c_void_p, ctypes.c_int]
sigaddset.restype = ctypes.c_int


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("it_interval", Timespec), ("it_value", Timespec)]


class Sigset(ctypes.Structure):
    _fields_ = [("bits", ctypes.c_ulong * 16)]


timer_fd = timerfd_create(time.CLOCK_BOOTTIME, os.O_CLOEXEC | os.O_NONBLOCK)
if timer_fd < 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
specification = Itimerspec(
    Timespec(0, 0), Timespec(deadline // 1_000_000_000, deadline % 1_000_000_000)
)
if timerfd_settime(timer_fd, 1, ctypes.byref(specification), None) != 0:  # TFD_TIMER_ABSTIME
    error = ctypes.get_errno()
    os.close(timer_fd)
    raise OSError(error, os.strerror(error))

cancel_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
handled_signals = cancel_signals + (signal.SIGCHLD,)
previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
previous_dispositions = {
    handled_signal: signal.getsignal(handled_signal)
    for handled_signal in handled_signals
}
for handled_signal in handled_signals:
    signal.signal(handled_signal, signal.SIG_DFL)


def restore_signal_state():
    for restored_signal, previous_disposition in previous_dispositions.items():
        signal.signal(restored_signal, previous_disposition)
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


signal_set = Sigset()
if sigemptyset(ctypes.byref(signal_set)) != 0:
    error = ctypes.get_errno()
    restore_signal_state()
    os.close(timer_fd)
    raise OSError(error, os.strerror(error))
for handled_signal in handled_signals:
    if sigaddset(ctypes.byref(signal_set), handled_signal) != 0:
        error = ctypes.get_errno()
        restore_signal_state()
        os.close(timer_fd)
        raise OSError(error, os.strerror(error))
signal_fd = signalfd(-1, ctypes.byref(signal_set), os.O_CLOEXEC | os.O_NONBLOCK)
if signal_fd < 0:
    error = ctypes.get_errno()
    restore_signal_state()
    os.close(timer_fd)
    raise OSError(error, os.strerror(error))

child_pid = None
child_reaped = False
pid_fd = None
cleanup_attempted = False
termination_tail_seconds = int(
    os.environ["BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS"]
)
delay_reap_for_test = os.environ.get("BORONDNS_CAMPAIGN_DEADLINE_TEST_DELAY_REAP") == "1"


def test_pause(point):
    if os.environ.get("BORONDNS_CAMPAIGN_DEADLINE_TEST_PHASE") != point:
        return
    marker = os.environ.get("BORONDNS_CAMPAIGN_DEADLINE_TEST_MARKER", "")
    continuation = os.environ.get("BORONDNS_CAMPAIGN_DEADLINE_TEST_CONTINUE", "")
    if not marker or not continuation:
        raise RuntimeError("deadline supervisor test hook is incomplete")
    with open(marker, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
        output.flush()
        os.fsync(output.fileno())
    while not os.path.exists(continuation):
        pause_poller = select.poll()
        pause_poller.register(timer_fd, select.POLLIN)
        pause_poller.register(signal_fd, select.POLLIN)
        for owner_fd in owner_fds:
            pause_poller.register(owner_fd, select.POLLIN)
        events = pause_poller.poll(10)
        if any(fd == timer_fd for fd, _event in events):
            raise SystemExit(124)
        if any(fd == signal_fd for fd, _event in events):
            delivered_signal = consume_cancel_signal()
            if delivered_signal is not None:
                raise SystemExit(128 + delivered_signal)
        if any(fd in owner_fds for fd, _event in events):
            raise SystemExit(143)


def consume_cancel_signal():
    raw_signals = os.read(signal_fd, 128 * 16)
    delivered = [
        int.from_bytes(raw_signals[offset : offset + 4], sys.byteorder)
        for offset in range(0, len(raw_signals), 128)
    ]
    return next((value for value in delivered if value in cancel_signals), None)


def terminate():
    # The unreaped session leader is the identity anchor for this numeric
    # process-group ID.  Never signal the group after wait() releases that
    # anchor, because the kernel may immediately reuse the same number for an
    # unrelated group.
    if child_reaped:
        return
    killpg_marker = os.environ.get("BORONDNS_CAMPAIGN_DEADLINE_TEST_KILLPG_MARKER", "")
    if killpg_marker:
        with open(killpg_marker, "a", encoding="ascii") as output:
            output.write(f"{child_pid}\n")
    try:
        os.killpg(child_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def group_has_nonleader_members(cleanup_deadline):
    """Return group membership without letting /proc pin the cleanup tail.

    A CLOCK_BOOTTIME check inside the walk is not sufficient: opening or
    advancing procfs itself can block.  Perform the bounded walk in a helper
    process and retain pidfd authority over it.  ``None`` means enumeration
    was incomplete; callers must fail the cleanup tail rather than reap the
    leader and risk reusing its numeric process-group ID.
    """
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        scan_pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        return None
    if scan_pid == 0:
        os.close(read_fd)
        # Do not let a wedged scan retain any authority owned by the
        # supervisor. The result pipe is its only required inherited fd.
        for descriptor in (*owner_fds, pid_fd, signal_fd, timer_fd, input_fd):
            if descriptor is None or descriptor == write_fd:
                continue
            try:
                os.close(descriptor)
            except OSError:
                pass
        result = b"0"
        try:
            entry_cap_text = os.environ.get(
                "BORONDNS_CAMPAIGN_DEADLINE_TEST_PROC_ENTRY_CAP", "4194304"
            )
            if (
                not entry_cap_text.isascii()
                or not entry_cap_text.isdecimal()
                or entry_cap_text.startswith("0")
            ):
                raise RuntimeError("invalid deadline supervisor proc entry cap")
            entry_cap = int(entry_cap_text)
            if not 1 <= entry_cap <= 4_194_304:
                raise RuntimeError("invalid deadline supervisor proc entry cap")
            entry_count = 0
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit() or int(entry.name) == child_pid:
                    continue
                entry_count += 1
                # Linux pid_max cannot exceed 2^22.  Treat a larger or
                # synthetic inventory as indeterminate instead of spending an
                # unbounded cleanup tail on it.
                if entry_count > entry_cap:
                    result = b"?"
                    break
                try:
                    with open(f"/proc/{entry.name}/stat", encoding="ascii") as source:
                        raw = source.read()
                    fields = raw[raw.rfind(")") + 2 :].split()
                    if len(fields) > 2 and int(fields[2]) == child_pid:
                        result = b"1"
                        break
                except (FileNotFoundError, PermissionError, ValueError, IndexError):
                    continue
        except BaseException:
            result = b"?"
        try:
            os.write(write_fd, result)
        except OSError:
            pass
        os._exit(0)

    os.close(write_fd)
    scan_pid_fd = None
    scan_timer_fd = None
    try:
        scan_pid_fd = os.pidfd_open(scan_pid, 0)
        scan_timer_fd = timerfd_create(time.CLOCK_BOOTTIME, os.O_CLOEXEC | os.O_NONBLOCK)
        if scan_timer_fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        scan_specification = Itimerspec(
            Timespec(0, 0),
            Timespec(
                cleanup_deadline // 1_000_000_000,
                cleanup_deadline % 1_000_000_000,
            ),
        )
        if timerfd_settime(
            scan_timer_fd, 1, ctypes.byref(scan_specification), None
        ) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        scan_poller = select.poll()
        scan_poller.register(scan_pid_fd, select.POLLIN)
        scan_poller.register(scan_timer_fd, select.POLLIN)
        while True:
            events = scan_poller.poll()
            if any(descriptor == scan_timer_fd for descriptor, _event in events):
                try:
                    signal.pidfd_send_signal(scan_pid_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(scan_pid, os.WNOHANG)
                return None
            if any(descriptor == scan_pid_fd for descriptor, _event in events):
                result = os.read(read_fd, 1)
                waited_pid, _raw_status = os.waitpid(scan_pid, os.WNOHANG)
                if waited_pid not in {0, scan_pid}:
                    raise RuntimeError("deadline supervisor reaped an unexpected scan helper")
                if result == b"1":
                    return True
                if result == b"0":
                    return False
                return None
    except BaseException:
        if scan_pid_fd is not None:
            try:
                signal.pidfd_send_signal(scan_pid_fd, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        os.waitpid(scan_pid, os.WNOHANG)
        return None
    finally:
        os.close(read_fd)
        if scan_pid_fd is not None:
            os.close(scan_pid_fd)
        if scan_timer_fd is not None:
            os.close(scan_timer_fd)


def reap_leader_nonblocking():
    global child_reaped
    if child_reaped or delay_reap_for_test:
        return None
    waited_pid, raw_status = os.waitpid(child_pid, os.WNOHANG)
    if waited_pid == 0:
        return None
    if waited_pid != child_pid:
        raise RuntimeError("deadline supervisor reaped an unexpected child")
    child_reaped = True
    test_pause("after-reap-before-state")
    return raw_status


def terminate_group_and_reap_bounded():
    global cleanup_attempted
    cleanup_attempted = True
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    cleanup_deadline = min(
        9223372036854775807,
        now + termination_tail_seconds * 1_000_000_000,
    )
    cleanup_poller = select.poll()
    if pid_fd is not None:
        cleanup_poller.register(pid_fd, select.POLLIN)
    terminate()
    # SIGKILL may be delayed by uninterruptible sleep. Keep the unreaped leader
    # as the PGID anchor while there are in-group descendants, but never turn
    # that identity guarantee into an unbounded wait. If the tail expires, the
    # supervisor exits without reaping: the still-live or zombie leader is
    # reparented, every in-group task retains pending SIGKILL, and the kernel
    # keeps the process-group identity allocated until its final member exits.
    while True:
        group_members = group_has_nonleader_members(cleanup_deadline)
        if group_members is None:
            return False, None
        if not group_members:
            raw_status = reap_leader_nonblocking()
            if raw_status is not None:
                return True, raw_status
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if now >= cleanup_deadline:
            return False, None
        terminate()
        remaining_milliseconds = max(1, min(10, (cleanup_deadline - now + 999_999) // 1_000_000))
        if delay_reap_for_test or pid_fd is None:
            time.sleep(remaining_milliseconds / 1000)
        else:
            cleanup_poller.poll(remaining_milliseconds)


def finish_after_group_cleanup(success_status, reason, *, child_status=False):
    complete, raw_status = terminate_group_and_reap_bounded()
    if not complete:
        print(
            f"deadline command cleanup tail expired {reason}; SIGKILL remains pending",
            file=sys.stderr,
        )
        return 125
    if not child_status:
        return success_status
    if raw_status is None:
        raise RuntimeError("deadline command exited without a wait status")
    status = os.waitstatus_to_exitcode(raw_status)
    return status if status >= 0 else 128 - status

try:
    # Termination signals were blocked before Popen, so there is no
    # post-spawn/pre-handler leak window.  Unblock them in the child immediately
    # before exec; the supervisor consumes its copy synchronously via signalfd.
    test_pause("before-spawn")
    child_pid = os.posix_spawnp(
        command[0],
        command,
        child_environment,
        file_actions=(
            (os.POSIX_SPAWN_DUP2, input_fd, 0),
            (os.POSIX_SPAWN_CLOSE, input_fd),
        ),
        setsid=True,
        setsigmask=(),
        setsigdef=handled_signals,
    )
    os.close(input_fd)
    input_fd = None
    poller = select.poll()
    poller.register(timer_fd, select.POLLIN)
    poller.register(signal_fd, select.POLLIN)
    for owner_fd in owner_fds:
        poller.register(owner_fd, select.POLLIN)
    pid_fd = os.pidfd_open(child_pid, 0)
    poller.register(pid_fd, select.POLLIN)
    while True:
        events = poller.poll()
        if any(fd == signal_fd for fd, _event in events):
            delivered_signal = consume_cancel_signal()
            if delivered_signal is not None:
                raise SystemExit(
                    finish_after_group_cleanup(
                        128 + delivered_signal, "during cancellation"
                    )
                )
        if any(fd == timer_fd for fd, _event in events):
            raise SystemExit(finish_after_group_cleanup(124, "after operation deadline"))
        if any(fd in owner_fds for fd, _event in events):
            raise SystemExit(finish_after_group_cleanup(143, "after owner exit"))
        if any(fd == pid_fd for fd, _event in events):
            # pidfd readiness does not reap the leader.  Kill any descendants
            # while that zombie leader still pins the PGID, then release it.
            raise SystemExit(
                finish_after_group_cleanup(0, "after leader exit", child_status=True)
            )
finally:
    if input_fd is not None:
        os.close(input_fd)
    if child_pid is not None and not child_reaped and not cleanup_attempted:
        cleanup_complete, _raw_status = terminate_group_and_reap_bounded()
        if not cleanup_complete:
            print(
                "deadline command cleanup tail expired during exception cleanup; SIGKILL remains pending",
                file=sys.stderr,
            )
    if pid_fd is not None:
        os.close(pid_fd)
    for owner_fd in owner_fds:
        os.close(owner_fd)
    os.close(signal_fd)
    os.close(timer_fd)
    # No asynchronous Python handler can run between wait() and child_reaped.
    # Restore the caller's signal mask only after numeric PGID authority is no
    # longer used by this supervisor.
    restore_signal_state()
PY
    campaign_deadline_supervisor_pid=$!
    # The background supervisor inherited its own authority to this stream.
    # The shell must not retain an extra reference (which would delay EOF).
    exec {campaign_deadline_input_fd}<&-
    job_line="$(jobs -l %% 2>/dev/null)" || job_line=""
    if [[ "$job_line" =~ ^\[([0-9]+)\] ]]; then
        campaign_deadline_supervisor_job="%${BASH_REMATCH[1]}"
    else
        # The supervisor remains our unreaped child, so this setup failure can
        # still be cancelled safely before returning.
        kill -TERM "$campaign_deadline_supervisor_pid" 2>/dev/null || true
        wait "$campaign_deadline_supervisor_pid" 2>/dev/null || true
        supervisor_status=1
    fi
    if [[ -n "$campaign_deadline_supervisor_job" ]]; then
        if ((campaign_deadline_forwarded_signal != 0)); then
            case "$campaign_deadline_forwarded_signal" in
            1) campaign_deadline_forward_signal HUP 1 ;;
            2) campaign_deadline_forward_signal INT 2 ;;
            15) campaign_deadline_forward_signal TERM 15 ;;
            esac
        fi
        while true; do
            supervisor_status=0
            wait "$campaign_deadline_supervisor_pid" || supervisor_status=$?
            active_pid="$(jobs -p "$campaign_deadline_supervisor_job" 2>/dev/null)" || active_pid=""
            [[ "$active_pid" == "$campaign_deadline_supervisor_pid" ]] || break
        done
    fi
    # The job table no longer contains the reaped supervisor, so forwarding is
    # disabled before restoring the caller's dispositions.
    trap - INT TERM HUP
    [[ -z "$previous_int" ]] || eval "$previous_int"
    [[ -z "$previous_term" ]] || eval "$previous_term"
    [[ -z "$previous_hup" ]] || eval "$previous_hup"
    return "$supervisor_status"
}

campaign_deadline_from_timeout_seconds() {
    local timeout_seconds="$1" now
    campaign_is_positive_signed_64 "$timeout_seconds" || return 1
    now="$(campaign_monotonic_nanoseconds)" || return 1
    [[ "$now" =~ ^[0-9]+$ ]] || return 1
    ((timeout_seconds <= (9223372036854775807 - now) / 1000000000)) || return 1
    printf '%s\n' "$((now + timeout_seconds * 1000000000))"
}

campaign_deadline_remaining_seconds() {
    local deadline="$1" maximum_seconds="${2:-}" now remaining maximum_nanoseconds
    campaign_is_positive_signed_64 "$deadline" || return 1
    [[ -z "$maximum_seconds" ]] || campaign_is_positive_signed_64 "$maximum_seconds" || return 1
    now="$(campaign_monotonic_nanoseconds)" || return 1
    [[ "$now" =~ ^[0-9]+$ ]] || return 1
    remaining=$((deadline - now))
    ((remaining > 0)) || return 1
    if [[ -n "$maximum_seconds" ]]; then
        ((maximum_seconds <= 9223372036854775807 / 1000000000)) || return 1
        maximum_nanoseconds=$((maximum_seconds * 1000000000))
        ((remaining <= maximum_nanoseconds)) || remaining="$maximum_nanoseconds"
    fi
    printf '%s.%09d\n' "$((remaining / 1000000000))" "$((remaining % 1000000000))"
}

campaign_deadline_reserving_termination() {
    local deadline="$1" reserve_nanoseconds="${2:-300000000}" now reserved
    campaign_is_positive_signed_64 "$deadline" || return 1
    campaign_is_positive_signed_64 "$reserve_nanoseconds" || return 1
    now="$(campaign_monotonic_nanoseconds)" || return 1
    [[ "$now" =~ ^[0-9]+$ ]] || return 1
    reserved=$((deadline - reserve_nanoseconds))
    ((reserved > now)) || return 1
    printf '%s\n' "$reserved"
}

campaign_wait_child_before_deadline() {
    local pid="$1" deadline="$2" expected_starttime="${3:-}"
    local now remaining sleep_nanoseconds sleep_seconds
    campaign_is_positive_signed_64 "$deadline" || return 1
    while ! campaign_lock_child_exited "$pid"; do
        if [[ -n "$expected_starttime" ]] &&
            ! campaign_process_matches_identity "$pid" "$expected_starttime"; then
            return 0
        fi
        now="$(campaign_monotonic_nanoseconds)" || return 1
        [[ "$now" =~ ^[0-9]+$ ]] || return 1
        remaining=$((deadline - now))
        ((remaining > 0)) || return 1
        sleep_nanoseconds=50000000
        ((sleep_nanoseconds <= remaining)) || sleep_nanoseconds="$remaining"
        printf -v sleep_seconds '0.%09d' "$sleep_nanoseconds"
        sleep "$sleep_seconds"
    done
}

campaign_reap_exited_child() {
    local pid="$1" status=0
    campaign_lock_child_exited "$pid" || return 1
    wait "$pid" 2>/dev/null || status=$?
    return "$status"
}

campaign_terminate_child_before_deadline() {
    local pid="$1" deadline="$2" label="$3" expected_starttime="${4:-}"
    campaign_is_positive_signed_64 "$deadline" || return 1
    [[ "$expected_starttime" =~ ^[1-9][0-9]*$ ]] || return 1
    # A numeric PID plus a pre-signal /proc check is not process authority: the
    # task can exit and the PID can be reused between validation and kill(2).
    # One pidfd is opened first, authenticated afterwards, and retained for all
    # signals and exit polling. Unsupported kernels and ambiguous identities
    # fail closed rather than falling back to a numeric signal.
    local termination_status=0
    python3 - "$pid" "$expected_starttime" "$deadline" "$label" <<'PY' || termination_status=$?
import ctypes
import errno
import os
import select
import signal
import sys
import time

pid, expected_starttime, absolute_deadline = map(int, sys.argv[1:4])
label = sys.argv[4]
if os.environ.get("BORONDNS_CAMPAIGN_TEST_DISABLE_PIDFD") == "1":
    raise SystemExit(f"{label} termination test disabled pidfd support")
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(f"{label} termination requires pidfd support")
if absolute_deadline <= time.clock_gettime_ns(time.CLOCK_BOOTTIME):
    raise SystemExit(f"{label} termination deadline is exhausted")


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("it_interval", Timespec), ("it_value", Timespec)]


def timerfd(deadline: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    create = libc.timerfd_create
    create.argtypes = [ctypes.c_int, ctypes.c_int]
    create.restype = ctypes.c_int
    settime = libc.timerfd_settime
    settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    settime.restype = ctypes.c_int
    descriptor = create(time.CLOCK_BOOTTIME, os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    specification = Itimerspec(
        Timespec(0, 0),
        Timespec(deadline // 1_000_000_000, deadline % 1_000_000_000),
    )
    if settime(descriptor, 1, ctypes.byref(specification), None) != 0:
        error = ctypes.get_errno()
        os.close(descriptor)
        raise OSError(error, os.strerror(error))
    return descriptor


try:
    process_fd = os.pidfd_open(pid, 0)
except ProcessLookupError:
    raise SystemExit(0)

poller = select.poll()
poller.register(process_fd, select.POLLIN)


def process_exited() -> bool:
    return any(descriptor == process_fd for descriptor, _event in poller.poll(0))


def send_process_signal(value: int) -> bool:
    try:
        signal.pidfd_send_signal(process_fd, value)
    except ProcessLookupError:
        if process_exited():
            return False
        raise RuntimeError(f"{label} pidfd signal returned ESRCH before exit was observable")
    except PermissionError as error:
        raise RuntimeError(f"{label} pidfd signal was denied") from error
    return True


try:
    # The descriptor is already bound here. A PID reuse before open is rejected
    # by the starttime check; an exit/reuse after open cannot retarget the fd.
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as source:
            raw = source.read()
        fields = raw[raw.rfind(")") + 2 :].split()
        state = fields[0]
        starttime = int(fields[19])
    except (OSError, ValueError, IndexError) as error:
        raise RuntimeError(f"{label} bound process identity is unreadable") from error
    if state in {"Z", "X"} or starttime != expected_starttime:
        raise RuntimeError(f"{label} bound process identity does not match")

    test_bound = os.environ.get("BORONDNS_CAMPAIGN_PIDFD_BOUND_MARKER", "")
    test_continue = os.environ.get("BORONDNS_CAMPAIGN_PIDFD_CONTINUE_MARKER", "")
    if test_bound:
        open(test_bound, "x", encoding="ascii").close()
        while test_continue and not os.path.exists(test_continue):
            if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= absolute_deadline:
                raise RuntimeError(f"{label} termination test hook expired")
            time.sleep(0.01)

    term_deadline = min(
        absolute_deadline,
        time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 250_000_000,
    )
    if not send_process_signal(signal.SIGTERM):
        raise SystemExit(0)
    if not send_process_signal(signal.SIGCONT):
        raise SystemExit(0)
    term_fd = timerfd(term_deadline)
    try:
        poller.register(term_fd, select.POLLIN)
        while True:
            events = poller.poll()
            if any(descriptor == process_fd for descriptor, _event in events):
                raise SystemExit(0)
            if any(descriptor == term_fd for descriptor, _event in events):
                break
    finally:
        os.close(term_fd)

    if not send_process_signal(signal.SIGKILL):
        raise SystemExit(0)
    if not send_process_signal(signal.SIGCONT):
        raise SystemExit(0)
    deadline_fd = timerfd(absolute_deadline)
    try:
        final_poller = select.poll()
        final_poller.register(process_fd, select.POLLIN)
        final_poller.register(deadline_fd, select.POLLIN)
        while True:
            events = final_poller.poll()
            if any(descriptor == process_fd for descriptor, _event in events):
                raise SystemExit(0)
            if any(descriptor == deadline_fd for descriptor, _event in events):
                raise RuntimeError(f"{label} did not exit before its absolute deadline")
    finally:
        os.close(deadline_fd)
finally:
    os.close(process_fd)
PY
    # Reap an exited direct child even when identity validation reports that it
    # became a zombie before the pidfd termination handshake completed.
    if campaign_lock_child_exited "$pid"; then
        wait "$pid" 2>/dev/null || true
    fi
    return "$termination_status"
}

campaign_finish_protocol_child_before_deadline() {
    local pid="$1" read_fd="$2" write_fd="$3" deadline="$4" label="$5" expected_starttime="$6"
    local status=0 graceful_deadline
    exec {read_fd}<&-
    exec {write_fd}>&-
    graceful_deadline="$(campaign_deadline_reserving_termination "$deadline")" || graceful_deadline="$deadline"
    if campaign_wait_child_before_deadline "$pid" "$graceful_deadline" "$expected_starttime"; then
        campaign_reap_exited_child "$pid" || status=$?
        return "$status"
    fi
    campaign_terminate_child_before_deadline "$pid" "$deadline" "$label" "$expected_starttime" || true
    return 1
}

campaign_abort_protocol_child_before_deadline() {
    local pid="$1" read_fd="$2" write_fd="$3" deadline="$4" label="$5" expected_starttime="$6"
    exec {read_fd}<&-
    exec {write_fd}>&-
    campaign_terminate_child_before_deadline "$pid" "$deadline" "$label" "$expected_starttime"
}

campaign_wait_lock_child_bounded() {
    local pid="$1"
    local timeout_seconds="${2:-${BORONDNS_CAMPAIGN_LOCK_RELEASE_TIMEOUT_SECONDS:-2}}"
    [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid campaign lock release timeout: %s\n' "$timeout_seconds" >&2
        return 1
    }
    local deadline
    deadline="$(campaign_deadline_from_timeout_seconds "$timeout_seconds")" || return 1
    campaign_wait_child_before_deadline "$pid" "$deadline"
}

campaign_terminate_lock_child() {
    local pid="$1"
    local absolute_deadline="${2:-}"
    local expected_starttime="${3:-}"
    local timeout_seconds="${BORONDNS_CAMPAIGN_LOCK_RELEASE_TIMEOUT_SECONDS:-2}"
    [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid campaign lock release timeout: %s\n' "$timeout_seconds" >&2
        timeout_seconds=2
    }
    if [[ -z "$absolute_deadline" ]]; then
        absolute_deadline="$(campaign_deadline_from_timeout_seconds "$timeout_seconds")" || return 1
    fi
    [[ "$expected_starttime" =~ ^[1-9][0-9]*$ ]] || return 1
    campaign_terminate_child_before_deadline "$pid" "$absolute_deadline" \
        'campaign lock broker' "$expected_starttime"
}

campaign_acquire_private_lock() {
    local root="$1"
    local namespace="$2"
    local label="$3"
    local absolute_deadline="${4:-}"
    local cleanup_deadline="${5:-}"
    local helper helper_snapshot_b64 helper_snapshot=""
    helper="${BORONDNS_CAMPAIGN_LOCK_HELPER:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/campaign-lock-helper.py}"
    helper_snapshot_b64="${BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64:-}"
    command -v python3 >/dev/null 2>&1 || {
        printf 'missing required campaign lock runtime: python3\n' >&2
        return 1
    }
    if [[ -n "$helper_snapshot_b64" ]]; then
        [[ "$helper_snapshot_b64" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || {
            printf 'invalid authenticated campaign lock helper snapshot encoding\n' >&2
            return 1
        }
        helper_snapshot="$(printf '%s' "$helper_snapshot_b64" | base64 --decode)" || {
            printf 'cannot decode authenticated campaign lock helper snapshot\n' >&2
            return 1
        }
    elif [[ "$helper" =~ ^/proc/self/fd/[0-9]+$ ]]; then
        [[ -f "$helper" && -r "$helper" ]] || {
            printf 'missing authenticated campaign lock helper descriptor: %s\n' "$helper" >&2
            return 1
        }
    else
        [[ -f "$helper" && ! -L "$helper" ]] || {
            printf 'missing regular campaign lock helper: %s\n' "$helper" >&2
            return 1
        }
    fi
    [[ -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" &&
        -z "${campaign_lock_pid:-}" ]] || {
        printf 'campaign lock helper is already active in this process\n' >&2
        return 1
    }
    # Deadline metadata without live descriptors is not authority. This also
    # makes an intentionally detached child start from a clean lock state.
    campaign_lock_operation_deadline=""
    campaign_lock_cleanup_deadline=""
    campaign_lock_deadline_bounded=""
    campaign_lock_owner_pid=""

    local response broker_deadline broker_starttime caller_supplied_deadline=0
    local heartbeat_timeout="${BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS:-5}"
    [[ "$heartbeat_timeout" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid campaign lock heartbeat timeout: %s\n' "$heartbeat_timeout" >&2
        return 1
    }
    if [[ -z "$absolute_deadline" ]]; then
        absolute_deadline="$(campaign_deadline_from_timeout_seconds "$heartbeat_timeout")" || return 1
        absolute_deadline=$((absolute_deadline + 300000000))
        # This deadline bounds setup and the first heartbeat only. A caller
        # that did not supply a campaign deadline expects the held authority to
        # live until pipe EOF/release, not to expire one heartbeat interval
        # later. INT64_MAX nanoseconds is the timerfd representation of that
        # effectively unbounded broker lifetime.
        broker_deadline=9223372036854775807
    else
        caller_supplied_deadline=1
    fi
    [[ -n "$cleanup_deadline" ]] || cleanup_deadline="$absolute_deadline"
    if ! campaign_is_positive_signed_64 "$absolute_deadline" ||
        ! campaign_is_positive_signed_64 "$cleanup_deadline" ||
        ((cleanup_deadline < absolute_deadline)); then
        printf 'invalid %s operation/cleanup deadline pair: operation=%s cleanup=%s\n' \
            "$label" "$absolute_deadline" "$cleanup_deadline" >&2
        return 1
    fi
    if ((caller_supplied_deadline)); then
        # The broker is the authority for cleanup mutations too. Ordinary
        # callers remain bounded by absolute_deadline through
        # campaign_assert_private_lock; only an explicit cleanup path that
        # supplies cleanup_deadline as its mutation deadline can use the
        # reserved tail.
        broker_deadline="$cleanup_deadline"
    fi
    local handshake_timeout protocol_deadline
    protocol_deadline="$(campaign_deadline_reserving_termination "$absolute_deadline")" || protocol_deadline="$absolute_deadline"
    handshake_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$heartbeat_timeout")" || {
        printf '%s broker setup exhausted its absolute deadline before the lock handshake\n' "$label" >&2
        return 1
    }

    coproc CAMPAIGN_LOCK_BROKER {
        if [[ -n "$helper_snapshot_b64" ]]; then
            exec python3 -c "$helper_snapshot" "$root" "$namespace" "$label" "$broker_deadline"
        else
            exec python3 "$helper" "$root" "$namespace" "$label" "$broker_deadline"
        fi
    }
    local broker_pid="$CAMPAIGN_LOCK_BROKER_PID"
    local broker_read_fd="${CAMPAIGN_LOCK_BROKER[0]}"
    local broker_write_fd="${CAMPAIGN_LOCK_BROKER[1]}"
    if ! campaign_process_starttime "$broker_pid" broker_starttime; then
        exec {broker_read_fd}<&-
        exec {broker_write_fd}>&-
        wait "$broker_pid" 2>/dev/null || true
        printf '%s broker exited before its process identity could be captured\n' "$label" >&2
        return 1
    fi
    if ! IFS= read -r -t "$handshake_timeout" response <&"$broker_read_fd"; then
        printf '%s broker did not complete its lock handshake within %s seconds\n' "$label" "$heartbeat_timeout" >&2
        exec {broker_read_fd}<&-
        exec {broker_write_fd}>&-
        campaign_terminate_lock_child "$broker_pid" "$cleanup_deadline" "$broker_starttime" || true
        return 1
    fi
    if [[ "$response" != locked$'\t'* ]]; then
        printf 'invalid campaign lock helper response\n' >&2
        exec {broker_read_fd}<&-
        exec {broker_write_fd}>&-
        campaign_terminate_lock_child "$broker_pid" "$cleanup_deadline" "$broker_starttime" || true
        return 1
    fi
    campaign_lock_pid="$broker_pid"
    exec {campaign_lock_control_fd}>&"$broker_write_fd"
    exec {campaign_lock_response_fd}<&"$broker_read_fd"
    campaign_lock_label="$label"
    campaign_lock_operation_deadline="$absolute_deadline"
    campaign_lock_cleanup_deadline="$cleanup_deadline"
    campaign_lock_deadline_bounded="$caller_supplied_deadline"
    campaign_lock_owner_pid="$BASHPID"
    campaign_lock_starttime="$broker_starttime"
    exec {broker_read_fd}<&-
    exec {broker_write_fd}>&-
    campaign_assert_private_lock "$absolute_deadline" "$cleanup_deadline"
}

campaign_clear_private_lock_state() {
    campaign_lock_pid=""
    campaign_lock_label=""
    campaign_lock_operation_deadline=""
    campaign_lock_cleanup_deadline=""
    campaign_lock_deadline_bounded=""
    campaign_lock_owner_pid=""
    campaign_lock_starttime=""
}

campaign_detach_inherited_private_lock() {
    if [[ -n "${campaign_lock_control_fd:-}" ]]; then
        exec {campaign_lock_control_fd}>&-
        campaign_lock_control_fd=""
    fi
    if [[ -n "${campaign_lock_response_fd:-}" ]]; then
        exec {campaign_lock_response_fd}<&-
        campaign_lock_response_fd=""
    fi
    campaign_clear_private_lock_state
}

campaign_private_lock_is_inherited() {
    [[ -n "${campaign_lock_owner_pid:-}" && "${campaign_lock_owner_pid}" != "$BASHPID" ]]
}

campaign_abandon_private_lock() {
    local absolute_deadline="${1:-}"
    local broker_pid="${campaign_lock_pid:-}"
    local broker_starttime="${campaign_lock_starttime:-}"
    if campaign_private_lock_is_inherited; then
        campaign_detach_inherited_private_lock
        return 0
    fi
    if [[ -n "${campaign_lock_control_fd:-}" ]]; then
        exec {campaign_lock_control_fd}>&-
        campaign_lock_control_fd=""
    fi
    if [[ -n "${campaign_lock_response_fd:-}" ]]; then
        exec {campaign_lock_response_fd}<&-
        campaign_lock_response_fd=""
    fi
    if [[ -n "$broker_pid" ]]; then
        campaign_terminate_lock_child "$broker_pid" "$absolute_deadline" "$broker_starttime" || true
    fi
    campaign_clear_private_lock_state
}

campaign_assert_private_lock() {
    local absolute_deadline="${1:-}"
    local cleanup_deadline="${2:-}"
    local preserve_cleanup_authority=0
    local label="${campaign_lock_label:-campaign lock}"
    local heartbeat_timeout="${BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS:-5}"
    if campaign_private_lock_is_inherited; then
        printf '%s authority belongs to process %s, not inherited process %s\n' \
            "$label" "$campaign_lock_owner_pid" "$BASHPID" >&2
        campaign_detach_inherited_private_lock
        return 1
    fi
    [[ "$heartbeat_timeout" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid campaign lock heartbeat timeout: %s\n' "$heartbeat_timeout" >&2
        campaign_abandon_private_lock "${cleanup_deadline:-$absolute_deadline}"
        return 1
    }
    if [[ -z "$absolute_deadline" && "${campaign_lock_deadline_bounded:-}" == 1 ]]; then
        absolute_deadline="${campaign_lock_operation_deadline:-}"
        cleanup_deadline="${campaign_lock_cleanup_deadline:-}"
        preserve_cleanup_authority=1
    elif [[ -z "$absolute_deadline" ]]; then
        absolute_deadline="$(campaign_deadline_from_timeout_seconds "$heartbeat_timeout")" || return 1
        absolute_deadline=$((absolute_deadline + 300000000))
    fi
    if [[ -z "$cleanup_deadline" ]]; then
        if [[ "${campaign_lock_deadline_bounded:-}" == 1 ]]; then
            cleanup_deadline="${campaign_lock_cleanup_deadline:-}"
        else
            cleanup_deadline="$absolute_deadline"
        fi
    fi
    if ! campaign_is_positive_signed_64 "$absolute_deadline" ||
        ! campaign_is_positive_signed_64 "$cleanup_deadline" ||
        ((cleanup_deadline < absolute_deadline)); then
        printf 'invalid %s assertion deadline pair: operation=%s cleanup=%s\n' \
            "$label" "$absolute_deadline" "$cleanup_deadline" >&2
        return 1
    fi
    if [[ "${campaign_lock_deadline_bounded:-}" == 1 ]] &&
        ((absolute_deadline > campaign_lock_cleanup_deadline || \
        cleanup_deadline > campaign_lock_cleanup_deadline)); then
        printf '%s assertion exceeds its acquired cleanup deadline\n' "$label" >&2
        return 1
    fi
    local response response_timeout protocol_deadline
    protocol_deadline="$(campaign_deadline_reserving_termination "$absolute_deadline")" || protocol_deadline="$absolute_deadline"
    response_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$heartbeat_timeout")" || {
        printf '%s exhausted its absolute deadline before the protected mutation\n' "$label" >&2
        if ((preserve_cleanup_authority)) &&
            [[ -n "${campaign_lock_pid:-}" && -n "${campaign_lock_cleanup_deadline:-}" ]]; then
            local now
            now="$(campaign_monotonic_nanoseconds)" || now="${campaign_lock_cleanup_deadline}"
            if ((now < campaign_lock_cleanup_deadline)); then
                return 1
            fi
        fi
        campaign_abandon_private_lock "$cleanup_deadline"
        return 1
    }
    [[ -n "${campaign_lock_pid:-}" && -n "${campaign_lock_control_fd:-}" && -n "${campaign_lock_response_fd:-}" ]] || {
        printf '%s is not active at a protected mutation boundary\n' "$label" >&2
        return 1
    }
    kill -0 "$campaign_lock_pid" 2>/dev/null || {
        printf '%s broker exited before a protected mutation\n' "$label" >&2
        campaign_abandon_private_lock "${cleanup_deadline:-$absolute_deadline}"
        return 1
    }
    if ! printf 'ping\n' >&"$campaign_lock_control_fd"; then
        printf '%s broker control channel closed before a protected mutation\n' "$label" >&2
        campaign_abandon_private_lock "${cleanup_deadline:-$absolute_deadline}"
        return 1
    fi
    if ! IFS= read -r -t "$response_timeout" response <&"$campaign_lock_response_fd" || [[ "$response" != alive ]]; then
        printf '%s broker did not acknowledge the protected mutation within %s seconds\n' "$label" "$heartbeat_timeout" >&2
        campaign_abandon_private_lock "$cleanup_deadline"
        return 1
    fi
}

campaign_release_private_lock() {
    local absolute_deadline="${1:-}"
    local broker_pid="${campaign_lock_pid:-}"
    local broker_starttime="${campaign_lock_starttime:-}"
    local release_status=0
    if campaign_private_lock_is_inherited; then
        campaign_detach_inherited_private_lock
        return 0
    fi
    if [[ -n "${campaign_lock_control_fd:-}" ]]; then
        exec {campaign_lock_control_fd}>&-
        campaign_lock_control_fd=""
    fi
    if [[ -n "${campaign_lock_response_fd:-}" ]]; then
        exec {campaign_lock_response_fd}<&-
        campaign_lock_response_fd=""
    fi
    if [[ -n "$broker_pid" ]]; then
        campaign_terminate_lock_child "$broker_pid" "$absolute_deadline" "$broker_starttime" || release_status=1
    fi
    campaign_clear_private_lock_state
    return "$release_status"
}

campaign_rename_noreplace() {
    local source="$1"
    local destination="$2"
    python3 - "$source" "$destination" <<'PY'
import ctypes
import errno
import os
import sys

source, destination = (os.fsencode(value) for value in sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for collision-safe campaign publication")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
linkat = libc.linkat
linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
linkat.restype = ctypes.c_int
if renameat2(-100, source, -100, destination, 1) != 0:  # AT_FDCWD, RENAME_NOREPLACE
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise SystemExit(f"campaign publication destination reappeared: {os.fsdecode(destination)}")
    raise OSError(error, os.strerror(error), os.fsdecode(destination))
PY
}

campaign_identity_bound_replace_text() {
    local parent="$1"
    local staged="$2"
    local destination="$3"
    local expected_parent_device="$4"
    local expected_parent_inode="$5"
    local expected_staged_sha256="$6"
    local expected_staged_device="$7"
    local expected_staged_inode="$8"
    local expected_staged_size="$9"
    local expected_destination_state="${10:-absent}"
    local expected_destination_device="${11:-0}"
    local expected_destination_inode="${12:-0}"
    python3 - "$parent" "${staged##*/}" "${destination##*/}" \
        "$expected_parent_device" "$expected_parent_inode" \
        "$expected_staged_sha256" "$expected_staged_device" "$expected_staged_inode" \
        "$expected_staged_size" "$(id -u)" \
        "$expected_destination_state" "$expected_destination_device" "$expected_destination_inode" <<'PY'
import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
import sys
import time

(
    parent,
    staged_name,
    destination_name,
    expected_parent_device,
    expected_parent_inode,
    expected_sha256,
    expected_staged_device,
    expected_staged_inode,
    expected_staged_size,
    expected_owner,
    expected_destination_state,
    expected_destination_device,
    expected_destination_inode,
) = sys.argv[1:]
expected_parent = (int(expected_parent_device), int(expected_parent_inode))
expected_staged = (int(expected_staged_device), int(expected_staged_inode))
expected_staged_size = int(expected_staged_size)
expected_owner = int(expected_owner)
expected_destination = (int(expected_destination_device), int(expected_destination_inode))
if not 0 <= expected_staged_size <= 16 * 1024 * 1024:
    raise SystemExit("campaign atomic text staging size is outside the supported bound")
if expected_destination_state not in {"absent", "file"}:
    raise SystemExit("invalid identity-bound destination state")
if any(not name or name in {".", ".."} or "/" in name for name in (staged_name, destination_name)):
    raise SystemExit("invalid identity-bound publication basename")

directory_fd = os.open(
    parent,
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
)
bound_name = f".{destination_name}.borondns-bound.{os.getpid()}.{secrets.token_hex(8)}"
bound_created = False
exchange_pending = False
rejection_text = b"borondns publication rejected: authenticated content changed\n"
libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for identity-bound campaign publication")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int


def rename_with_flags(source, destination, flags):
    if renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        flags,
    ) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise RuntimeError("campaign publication destination identity changed")
        raise OSError(error, os.strerror(error), destination)


def destination_matches_expected(name):
    try:
        value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return expected_destination_state == "absent"
    return (
        expected_destination_state == "file"
        and stat.S_ISREG(value.st_mode)
        and value.st_uid == expected_owner
        and value.st_nlink == 1
        and (value.st_dev, value.st_ino) == expected_destination
    )


def test_pause(point):
    if os.environ.get("BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_PHASE", "") != point:
        return
    marker = os.environ.get("BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_MARKER", "")
    continuation = os.environ.get("BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_CONTINUE", "")
    if not marker or not continuation:
        raise RuntimeError("identity-bound publication test hook is incomplete")
    open(marker, "x", encoding="ascii").close()
    deadline = time.monotonic() + 30
    while not os.path.exists(continuation):
        if time.monotonic() >= deadline:
            raise RuntimeError("identity-bound publication test hook expired")
        time.sleep(0.01)


def rejection_test_pause():
    marker = os.environ.get("BORONDNS_CAMPAIGN_REPLACE_TEXT_REJECTION_TEST_MARKER", "")
    continuation = os.environ.get("BORONDNS_CAMPAIGN_REPLACE_TEXT_REJECTION_TEST_CONTINUE", "")
    if not marker and not continuation:
        return
    if not marker or not continuation:
        raise RuntimeError("identity-bound publication rejection test hook is incomplete")
    open(marker, "x", encoding="ascii").close()
    deadline = time.monotonic() + 30
    while not os.path.exists(continuation):
        if time.monotonic() >= deadline:
            raise RuntimeError("identity-bound publication rejection test hook expired")
        time.sleep(0.01)


def staged_bytes_match(staged_fd, name):
    before = os.fstat(staged_fd)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_owner
        or before.st_nlink != 1
        or before.st_size != expected_staged_size
        or (before.st_dev, before.st_ino) != expected_staged
        or (named.st_dev, named.st_ino) != expected_staged
        or named.st_uid != expected_owner
        or named.st_nlink != 1
    ):
        return False
    os.lseek(staged_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_staged_size
    while remaining:
        chunk = os.read(staged_fd, min(remaining, 1024 * 1024))
        if not chunk:
            return False
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(staged_fd, 1):
        return False
    after = os.fstat(staged_fd)
    return (
        (
            after.st_dev, after.st_ino, after.st_uid, after.st_mode,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        )
        == (
            before.st_dev, before.st_ino, before.st_uid, before.st_mode,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns,
        )
        and digest.hexdigest() == expected_sha256
    )


def displaced_destination_matches():
    try:
        displaced = os.stat(bound_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(displaced.st_mode)
        and displaced.st_uid == expected_owner
        and displaced.st_nlink == 1
        and (displaced.st_dev, displaced.st_ino) == expected_destination
    )


def reject_published_destination():
    # Fence a content-authentication failure with a fresh, known placeholder.
    # RENAME_EXCHANGE moves whatever currently occupies the destination to an
    # unpredictable retained quarantine name in the same atomic operation;
    # there is no stat-then-unlink window and no unauthenticated rollback.
    rejection_test_pause()
    rejected_name = (
        f".{destination_name}.borondns-rejected.{os.getpid()}.{secrets.token_hex(8)}"
    )
    rejected_fd = os.open(
        rejected_name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        written = 0
        while written < len(rejection_text):
            count = os.write(rejected_fd, rejection_text[written:])
            if count <= 0:
                raise RuntimeError("campaign rejection placeholder write made no progress")
            written += count
        os.fsync(rejected_fd)
        rejected = os.fstat(rejected_fd)
        rejected_identity = (rejected.st_dev, rejected.st_ino)
        rename_with_flags(rejected_name, destination_name, 2)  # RENAME_EXCHANGE
        named = os.stat(destination_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_uid != expected_owner
            or named.st_nlink != 1
            or (named.st_dev, named.st_ino) != rejected_identity
        ):
            raise RuntimeError("campaign rejection placeholder identity changed during commit")
        os.lseek(rejected_fd, 0, os.SEEK_SET)
        if os.read(rejected_fd, len(rejection_text) + 1) != rejection_text:
            raise RuntimeError("campaign rejection placeholder bytes changed during commit")
        os.fsync(directory_fd)
    finally:
        os.close(rejected_fd)


try:
    parent_stat = os.fstat(directory_fd)
    if (parent_stat.st_dev, parent_stat.st_ino) != expected_parent or parent_stat.st_uid != expected_owner:
        raise SystemExit("campaign atomic text parent identity changed before commit")
    staged_fd = os.open(
        staged_name,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(staged_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner
            or before.st_nlink != 1
            or before.st_size != expected_staged_size
            or (before.st_dev, before.st_ino) != expected_staged
        ):
            raise SystemExit("campaign atomic text staging identity changed before commit")
        if not staged_bytes_match(staged_fd, staged_name):
            raise SystemExit("campaign atomic text staging bytes changed before commit")

        if not destination_matches_expected(destination_name):
            raise SystemExit("campaign atomic text destination identity changed before commit")

        # Move, rather than hard-link, the validated staging inode to its private
        # bound name.  There is then only one writable pathname for the inode;
        # the original implementation left a second hard-link through which a
        # concurrent writer could change already-hashed bytes.
        rename_with_flags(staged_name, bound_name, 1)  # RENAME_NOREPLACE
        bound_created = True
        test_pause("post-bound-move")
        if not staged_bytes_match(staged_fd, bound_name):
            raise SystemExit("campaign atomic text bound staging bytes changed during commit")
        if expected_destination_state == "absent":
            rename_with_flags(bound_name, destination_name, 1)  # RENAME_NOREPLACE
            bound_created = False
        else:
            rename_with_flags(bound_name, destination_name, 2)  # RENAME_EXCHANGE
            bound_created = False
            exchange_pending = True
            test_pause("post-exchange")
            # Never exchange an unauthenticated bound pathname back into the
            # destination.  If the displaced name was replaced, the trusted new
            # inode remains published and the foreign object is retained.
            if not staged_bytes_match(staged_fd, destination_name):
                reject_published_destination()
                # The displaced destination and every rejected object remain
                # named for fail-closed inspection after the trusted fence.
                exchange_pending = False
                raise SystemExit("campaign atomic text published staging bytes changed during commit")
            if not displaced_destination_matches():
                raise SystemExit("campaign atomic text destination changed during commit")
            os.unlink(bound_name, dir_fd=directory_fd)
            exchange_pending = False
        if not staged_bytes_match(staged_fd, destination_name):
            reject_published_destination()
            exchange_pending = False
            raise SystemExit("campaign atomic text published an unexpected object")
        os.fsync(directory_fd)
    finally:
        os.close(staged_fd)
finally:
    if bound_created:
        # A pre-publication failure restores only the exact captured staging
        # inode and never removes a replacement at either pathname.
        try:
            bound = os.stat(bound_name, dir_fd=directory_fd, follow_symlinks=False)
            if (bound.st_dev, bound.st_ino) == expected_staged:
                rename_with_flags(bound_name, staged_name, 1)
                bound_created = False
        except (FileNotFoundError, OSError, RuntimeError):
            pass
    if exchange_pending:
        # The first exchange already placed the authenticated staging inode at
        # the destination.  Do not attempt a pathname-only rollback.  Remove the
        # displaced object only when it is still the exact expected destination;
        # otherwise retain both objects for fail-closed inspection.
        try:
            if displaced_destination_matches():
                os.unlink(bound_name, dir_fd=directory_fd)
        except (FileNotFoundError, OSError):
            pass
    os.close(directory_fd)
PY
}

campaign_identity_bound_unlink_file() {
    local parent="$1"
    local stale="$2"
    local expected_parent_device="$3"
    local expected_parent_inode="$4"
    local expected_stale_device="$5"
    local expected_stale_inode="$6"
    local expected_owner="$7"
    python3 - "$parent" "$stale" "$expected_parent_device" "$expected_parent_inode" \
        "$expected_stale_device" "$expected_stale_inode" "$expected_owner" <<'PY'
import ctypes
import os
import secrets
import stat
import sys

parent, stale = sys.argv[1:3]
expected_parent = (int(sys.argv[3]), int(sys.argv[4]))
expected_stale = (int(sys.argv[5]), int(sys.argv[6]))
expected_owner = int(sys.argv[7])
stale_name = os.path.basename(stale)
if os.path.dirname(stale) != parent or stale_name in {"", ".", ".."}:
    raise SystemExit("campaign stale text path is not a direct child of its parent")

directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_stat = os.fstat(directory_fd)
    if (parent_stat.st_dev, parent_stat.st_ino) != expected_parent:
        raise SystemExit("campaign stale text parent identity changed before cleanup")
    stale_fd = os.open(
        stale_name,
        os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        opened = os.fstat(stale_fd)
        named = os.stat(stale_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_owner
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != expected_stale
            or (named.st_dev, named.st_ino) != expected_stale
        ):
            raise SystemExit("campaign stale text pathname identity changed before cleanup")
        quarantine_name = (
            f".{stale_name}.borondns-remove.{os.getpid()}.{secrets.token_hex(12)}"
        )
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if renameat2(
            directory_fd, os.fsencode(stale_name), directory_fd,
            os.fsencode(quarantine_name), 1,
        ) != 0:  # RENAME_NOREPLACE
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), quarantine_name)
        quarantined = os.stat(
            quarantine_name, dir_fd=directory_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(quarantined.st_mode)
            or quarantined.st_uid != expected_owner
            or quarantined.st_nlink != 1
            or (quarantined.st_dev, quarantined.st_ino) != expected_stale
        ):
            raise SystemExit("campaign stale text changed while entering quarantine")
        # This parent is writable by the same UID as the caller.  There is no
        # atomic unlink-by-open-fd operation, so a pathname unlink after this
        # check could delete a replacement.  Logical removal ends at the exact
        # NOREPLACE quarantine rename; a privileged operator may later collect
        # retained quarantines from an isolated namespace.
        os.fsync(directory_fd)
    finally:
        os.close(stale_fd)
finally:
    os.close(directory_fd)
PY
}

campaign_identity_bound_remove_impl() {
    local execution_kind="$1"
    shift
    local kind="$1"
    local parent="$2"
    local target="$3"
    local expected_parent_device="$4"
    local expected_parent_inode="$5"
    local expected_parent_owner="$6"
    local expected_target_device="$7"
    local expected_target_inode="$8"
    local expected_target_owner="$9"
    local absolute_deadline="${10:-}"
    local quarantine_override="${11:-}"
    local remove_timeout="${BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TIMEOUT_SECONDS:-}"
    local campaign_uid campaign_gids
    local test_phase="${BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TEST_PHASE:-}"
    local test_marker="${BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TEST_MARKER:-}"
    local test_continue="${BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TEST_CONTINUE:-}"
    campaign_uid="$(id -u)" || return 1
    campaign_gids="$(id -G)" || return 1
    if [[ -n "$remove_timeout" && ! "$remove_timeout" =~ ^[1-9][0-9]*$ ]]; then
        printf 'invalid identity-bound removal timeout: %s\n' "$remove_timeout" >&2
        return 1
    fi
    campaign_assert_private_lock "$absolute_deadline" || return 1
    local effective_timeout=""
    if [[ -n "$absolute_deadline" ]]; then
        effective_timeout="$(campaign_deadline_remaining_seconds "$absolute_deadline" "$remove_timeout")" || {
            printf 'identity-bound removal exhausted its absolute deadline: %s\n' "$target" >&2
            return 1
        }
    elif [[ -n "$remove_timeout" ]]; then
        effective_timeout="$remove_timeout"
    fi
    local -a python_command=(python3)
    if [[ "$execution_kind" == privileged ]]; then
        if [[ -n "$effective_timeout" ]]; then
            python_command=(timeout --preserve-status --signal=KILL "$effective_timeout" sudo python3)
        else
            python_command=(sudo python3)
        fi
    elif [[ "$execution_kind" != unprivileged ]]; then
        return 1
    elif [[ -n "$effective_timeout" ]]; then
        python_command=(timeout --preserve-status --signal=KILL "$effective_timeout" python3)
    fi
    [[ "$kind" == file || "$kind" == leaf || "$kind" == tree ]] || return 1
    local retain_quarantine=0
    if [[ "$execution_kind" == unprivileged || "$expected_parent_owner" != 0 ||
        "$expected_target_owner" != 0 ]]; then
        # sudo is not namespace authority. A privileged helper must still stop
        # at logical quarantine when the campaign UID owns either writable
        # boundary; that UID can retain directory fds and swap descendants.
        retain_quarantine=1
    fi
    "${python_command[@]}" - "$kind" "$parent" "$target" \
        "$expected_parent_device" "$expected_parent_inode" "$expected_parent_owner" \
        "$expected_target_device" "$expected_target_inode" "$expected_target_owner" \
        "$absolute_deadline" "$quarantine_override" "$retain_quarantine" \
        "$campaign_uid" "$campaign_gids" "$test_phase" "$test_marker" \
        "$test_continue" <<'PY'
import ctypes
import errno
import os
import re
import secrets
import stat
import sys
import time

(
    kind,
    parent,
    target,
    expected_parent_device,
    expected_parent_inode,
    expected_parent_owner,
    expected_target_device,
    expected_target_inode,
    expected_target_owner,
    absolute_deadline_text,
    quarantine_override,
    retain_quarantine_text,
    campaign_uid_text,
    campaign_gids_text,
    test_phase,
    test_marker,
    test_continue,
) = sys.argv[1:]
expected_parent = (int(expected_parent_device), int(expected_parent_inode))
expected_parent_owner = int(expected_parent_owner)
expected_target = (int(expected_target_device), int(expected_target_inode))
expected_target_owner = int(expected_target_owner)
absolute_deadline = int(absolute_deadline_text) if absolute_deadline_text else 0
retain_quarantine = retain_quarantine_text == "1"
campaign_uid = int(campaign_uid_text)
campaign_gids = {int(value) for value in campaign_gids_text.split()}
target_name = os.path.basename(target)
if os.path.dirname(target) != parent or target_name in {"", ".", ".."}:
    raise SystemExit("identity-bound campaign cleanup target is not a direct child of its parent")

libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    raise SystemExit("renameat2 is required for identity-bound campaign cleanup")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int


def rename_noreplace(directory_fd, source, destination):
    if renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    ) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise RuntimeError(f"identity-bound cleanup quarantine collision: {destination}")
        raise OSError(error, os.strerror(error), source)


def restore_quarantine(directory_fd, quarantine_name, original_name):
    try:
        rename_noreplace(directory_fd, quarantine_name, original_name)
    except (OSError, RuntimeError):
        # Never remove an identity-mismatched object merely to restore a
        # pathname.  The quarantined name is retained for manual recovery if a
        # concurrent actor also recreated the original name.
        pass


def quarantine_name_for(name, override=""):
    if override:
        if not re.fullmatch(rf"\.{re.escape(name)}\.borondns-remove\.[0-9]+\.[0-9a-f]{{24}}", override):
            raise RuntimeError("invalid identity-bound cleanup quarantine override")
        return override
    return f".{name}.borondns-remove.{os.getpid()}.{secrets.token_hex(12)}"


def check_deadline():
    if absolute_deadline and time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= absolute_deadline:
        raise RuntimeError("identity-bound cleanup absolute deadline expired")


def removal_test_pause(point):
    if test_phase != point:
        return
    if not test_marker or not test_continue:
        raise RuntimeError("identity-bound cleanup test hook is incomplete")
    with open(test_marker, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
        output.flush()
        os.fsync(output.fileno())
    hook_deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 30_000_000_000
    if absolute_deadline:
        hook_deadline = min(hook_deadline, absolute_deadline)
    while not os.path.exists(test_continue):
        if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= hook_deadline:
            raise RuntimeError("identity-bound cleanup test hook timed out")
        time.sleep(0.01)


def has_access_acl(file_descriptor):
    """Conservatively reject every explicit POSIX access ACL.

    The mode bits already encode the ACL mask, but they do not identify which
    named user or group receives it.  Without an ACL parser, treating any
    access ACL as writable is the only safe generic decision.
    """
    try:
        os.getxattr(file_descriptor, "system.posix_acl_access")
        return True
    except OSError as error:
        if error.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return False
        return True


def campaign_identity_can_write(directory_stat):
    if directory_stat.st_uid == campaign_uid:
        return bool(directory_stat.st_mode & stat.S_IWUSR)
    if directory_stat.st_gid in campaign_gids:
        return bool(directory_stat.st_mode & stat.S_IWGRP)
    return bool(directory_stat.st_mode & stat.S_IWOTH)


def namespace_tree_is_protected(directory_fd, root_device):
    """Prove every recursive directory-entry boundary immutable to campaign UID."""
    check_deadline()
    directory_stat = os.fstat(directory_fd)
    if (
        directory_stat.st_dev != root_device
        or campaign_identity_can_write(directory_stat)
        or has_access_acl(directory_fd)
    ):
        return False
    try:
        with os.scandir(directory_fd) as iterator:
            names = [entry.name for entry in iterator]
        for name in names:
            entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(entry_stat.st_mode):
                continue
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(child_fd)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    (opened.st_dev, opened.st_ino) != (entry_stat.st_dev, entry_stat.st_ino)
                    or (named.st_dev, named.st_ino) != (entry_stat.st_dev, entry_stat.st_ino)
                    or not namespace_tree_is_protected(child_fd, root_device)
                ):
                    return False
            finally:
                os.close(child_fd)
    except (OSError, RuntimeError):
        return False
    return True


def clear_directory(directory_fd, root_device):
    with os.scandir(directory_fd) as iterator:
        names = [entry.name for entry in iterator]
    for name in names:
        check_deadline()
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        before_identity = (before.st_dev, before.st_ino)
        quarantine_name = quarantine_name_for(name)
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(child_fd)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    (opened.st_dev, opened.st_ino) != before_identity
                    or (named.st_dev, named.st_ino) != before_identity
                    or opened.st_dev != root_device
                ):
                    raise RuntimeError("identity-bound cleanup child directory identity changed")
                rename_noreplace(directory_fd, name, quarantine_name)
                quarantined = os.stat(
                    quarantine_name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (quarantined.st_dev, quarantined.st_ino) != before_identity:
                    restore_quarantine(directory_fd, quarantine_name, name)
                    raise RuntimeError("identity-bound cleanup quarantined an unexpected directory")
                try:
                    clear_directory(child_fd, root_device)
                    current = os.stat(
                        quarantine_name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (current.st_dev, current.st_ino) != before_identity:
                        raise RuntimeError("identity-bound cleanup child quarantine identity changed")
                    os.rmdir(quarantine_name, dir_fd=directory_fd)
                except BaseException:
                    restore_quarantine(directory_fd, quarantine_name, name)
                    raise
            finally:
                os.close(child_fd)
        else:
            rename_noreplace(directory_fd, name, quarantine_name)
            quarantined = os.stat(
                quarantine_name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (quarantined.st_dev, quarantined.st_ino) != before_identity:
                restore_quarantine(directory_fd, quarantine_name, name)
                raise RuntimeError("identity-bound cleanup quarantined an unexpected file")
            os.unlink(quarantine_name, dir_fd=directory_fd)
    os.fsync(directory_fd)


parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    parent_stat = os.fstat(parent_fd)
    if (
        (parent_stat.st_dev, parent_stat.st_ino) != expected_parent
        or parent_stat.st_uid != expected_parent_owner
    ):
        raise SystemExit("identity-bound cleanup parent identity changed")
    # O_PATH binds a file inode without requiring read permission.  This also
    # keeps non-root harnesses faithful to sudo-backed production cleanup of
    # write-only or otherwise unreadable systemd staging files.
    target_flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    if kind == "tree":
        target_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    target_fd = os.open(target_name, target_flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(target_fd)
        named = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        expected_type = stat.S_ISDIR if kind == "tree" else (
            stat.S_ISREG if kind == "file" else lambda mode: not stat.S_ISDIR(mode)
        )
        if (
            not expected_type(opened.st_mode)
            or opened.st_uid != expected_target_owner
            or (opened.st_dev, opened.st_ino) != expected_target
            or (named.st_dev, named.st_ino) != expected_target
        ):
            raise SystemExit("identity-bound cleanup target identity changed")
        if kind == "file" and opened.st_nlink != 1:
            raise SystemExit("identity-bound cleanup file is no longer singly linked")

        removal_test_pause("after-target-stat-before-namespace-proof")
        if not retain_quarantine:
            # Root ownership is not namespace authority.  Group/world mode
            # bits and named ACL entries can still let the campaign identity
            # replace a checked child before recursive unlink.  Prove every
            # directory-entry boundary first or retain the whole root.
            parent_protected = not campaign_identity_can_write(parent_stat) and not has_access_acl(parent_fd)
            target_protected = True
            if kind == "tree":
                target_protected = namespace_tree_is_protected(target_fd, opened.st_dev)
            if not parent_protected or not target_protected:
                retain_quarantine = True

        quarantine_name = quarantine_name_for(target_name, quarantine_override)
        check_deadline()
        rename_noreplace(parent_fd, target_name, quarantine_name)
        if os.environ.get("BORONDNS_CAMPAIGN_IDENTITY_REMOVE_FAULT_PHASE") == "root-quarantined":
            os.kill(os.getpid(), 9)
        quarantined = os.stat(quarantine_name, dir_fd=parent_fd, follow_symlinks=False)
        if (quarantined.st_dev, quarantined.st_ino) != expected_target:
            restore_quarantine(parent_fd, quarantine_name, target_name)
            raise SystemExit("identity-bound cleanup quarantined an unexpected target")
        if retain_quarantine:
            # A same-UID peer can mutate this namespace after any identity
            # check. Retaining the exact quarantined inode is the only generic
            # fail-closed outcome without a dedicated-UID/root broker.
            os.fsync(parent_fd)
        else:
            try:
                if kind != "tree":
                    os.unlink(quarantine_name, dir_fd=parent_fd)
                else:
                    clear_directory(target_fd, opened.st_dev)
                    current = os.stat(
                        quarantine_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if (current.st_dev, current.st_ino) != expected_target:
                        raise RuntimeError("identity-bound cleanup tree quarantine identity changed")
                    os.rmdir(quarantine_name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except BaseException:
                restore_quarantine(parent_fd, quarantine_name, target_name)
                raise
    finally:
        os.close(target_fd)
finally:
    os.close(parent_fd)
PY
}

campaign_privileged_identity_bound_remove() {
    campaign_identity_bound_remove_impl privileged "$@"
}

campaign_identity_bound_remove() {
    campaign_identity_bound_remove_impl unprivileged "$@"
}

# Logically remove a tree from a campaign-UID-owned parent while retaining the
# exact inode under a preallocated quarantine name.  A prepared journal is
# durably published before the rename, so a crash cannot erase the
# original-to-quarantine mapping needed for later operator reconciliation.
campaign_retained_identity_bound_remove() {
    local execution_kind="$1" kind="$2" parent="$3" target="$4"
    local expected_parent_device="$5" expected_parent_inode="$6" expected_parent_owner="$7"
    local expected_target_device="$8" expected_target_inode="$9" expected_target_owner="${10}"
    local absolute_deadline="${11:-}" label="${12:-retained campaign cleanup}"
    [[ "$execution_kind" == privileged || "$execution_kind" == unprivileged ]] || return 1
    [[ "$kind" == file || "$kind" == leaf || "$kind" == tree ]] || return 1
    [[ "$target" != *$'\n'* && "$parent" != *$'\n'* && "$label" != *$'\n'* ]] || return 1
    campaign_assert_private_lock "$absolute_deadline" || return 1
    campaign_require_owned_real_directory "$parent" "$label parent" || return 1
    local target_name nonce quarantine_name quarantine_path journal content identity remainder
    target_name="$(basename "$target")"
    [[ "$(dirname "$target")" == "$parent" && "$target_name" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    nonce="$(python3 -c 'import secrets; print(secrets.token_hex(12))')" || return 1
    [[ "$nonce" =~ ^[0-9a-f]{24}$ ]] || return 1
    quarantine_name=".${target_name}.borondns-remove.${BASHPID}.${nonce}"
    quarantine_path="$parent/$quarantine_name"
    # Every cleanup attempt gets a distinct evidence inode. Earlier retained
    # mappings must remain inspectable and must not block a meaningful retry
    # that created a new canonical target with a different identity.
    journal="$parent/.borondns-retained-cleanup-${target_name}.${BASHPID}.${nonce}.env"
    [[ ! -e "$quarantine_path" && ! -L "$quarantine_path" &&
        ! -e "$journal" && ! -L "$journal" ]] || {
        printf '%s refused an existing quarantine or journal: %s\n' "$label" "$target" >&2
        return 1
    }
    content="schema=1
phase=prepared
kind=$kind
original_path=$target
quarantine_path=$quarantine_path
parent_device=$expected_parent_device
parent_inode=$expected_parent_inode
parent_owner=$expected_parent_owner
target_device=$expected_target_device
target_inode=$expected_target_inode
target_owner=$expected_target_owner
"
    campaign_publish_status_text "$parent" "$journal" "$content" "$label journal" || return 1
    if [[ "$execution_kind" == privileged ]]; then
        campaign_privileged_identity_bound_remove "$kind" "$parent" "$target" \
            "$expected_parent_device" "$expected_parent_inode" "$expected_parent_owner" \
            "$expected_target_device" "$expected_target_inode" "$expected_target_owner" \
            "$absolute_deadline" "$quarantine_name" || return 1
    else
        campaign_identity_bound_remove "$kind" "$parent" "$target" \
            "$expected_parent_device" "$expected_parent_inode" "$expected_parent_owner" \
            "$expected_target_device" "$expected_target_inode" "$expected_target_owner" \
            "$absolute_deadline" "$quarantine_name" || return 1
    fi
    [[ ! -e "$target" && ! -L "$target" ]] || return 1
    identity="$(stat -c '%d:%i:%u' "$quarantine_path")" || return 1
    remainder="${identity#*:}"
    [[ "${identity%%:*}" == "$expected_target_device" &&
        "${remainder%%:*}" == "$expected_target_inode" &&
        "${identity##*:}" == "$expected_target_owner" ]] || {
        printf '%s quarantine identity changed: %s\n' "$label" "$quarantine_path" >&2
        return 1
    }
    content="${content/phase=prepared/phase=retained}"
    campaign_publish_status_text "$parent" "$journal" "$content" "$label journal" || return 1
    CAMPAIGN_LAST_RETAINED_QUARANTINE="$quarantine_path"
    CAMPAIGN_LAST_RETAINED_JOURNAL="$journal"
    printf 'cleanup_retained\toriginal=%s\tquarantine=%s\tjournal=%s\tdevice=%s\tinode=%s\towner=%s\n' \
        "$target" "$quarantine_path" "$journal" "$expected_target_device" \
        "$expected_target_inode" "$expected_target_owner"
}

# Verify, but never delete, a retained-cleanup journal.  The exact recorded
# identity rejects lookalike quarantine siblings.  Because the journal lives in
# a campaign-UID-owned namespace, it is reconciliation evidence rather than
# durable destructive authority after the originating process exits.
campaign_verify_retained_cleanup_journal() {
    local journal="$1"
    python3 - "$journal" <<'PY'
import os
import stat
import sys

journal_size_limit = 16384
journal = sys.argv[1]
absolute = os.path.isabs(journal)
components = journal.split("/")
if absolute:
    components = components[1:]
if not components or any(component in {"", ".", ".."} for component in components):
    raise SystemExit("retained-cleanup journal path is not canonical")
journal_name = components[-1]
parent_components = components[:-1]
parent = ("/" if absolute else "") + "/".join(parent_components)
if absolute and not parent_components:
    parent = "/"
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
try:
    parent_fd = os.open("/" if absolute else ".", directory_flags)
    for component in parent_components:
        next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = next_fd
except OSError as error:
    if "parent_fd" in locals():
        os.close(parent_fd)
    raise SystemExit("retained-cleanup parent is not a real directory") from error
try:
    parent_stat = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise SystemExit("retained-cleanup parent is not a real directory")
    try:
        journal_fd = os.open(
            journal_name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as error:
        raise SystemExit("retained-cleanup journal cannot be opened safely") from error
    try:
        journal_stat = os.fstat(journal_fd)
        named_journal = os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False)
        journal_identity = (journal_stat.st_dev, journal_stat.st_ino, journal_stat.st_uid)
        journal_snapshot = (
            journal_stat.st_size, journal_stat.st_mtime_ns, journal_stat.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(journal_stat.st_mode)
            or journal_stat.st_nlink != 1
            or not 0 < journal_stat.st_size <= journal_size_limit
            or (named_journal.st_dev, named_journal.st_ino, named_journal.st_uid)
            != journal_identity
        ):
            raise SystemExit(
                "retained-cleanup journal is not a bound singly linked bounded regular file"
            )
        raw = bytearray()
        while len(raw) < journal_stat.st_size:
            chunk = os.read(journal_fd, journal_stat.st_size - len(raw))
            if not chunk:
                raise SystemExit("retained-cleanup journal was truncated while it was read")
            raw.extend(chunk)
        if os.read(journal_fd, 1):
            raise SystemExit("retained-cleanup journal grew while it was read")
        try:
            journal_text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SystemExit("retained-cleanup journal is not valid UTF-8") from error
        fields = {}
        journal_lines = journal_text.split("\n")
        if journal_lines and journal_lines[-1] == "":
            journal_lines.pop()
        for line in journal_lines:
            if not line or "=" not in line:
                raise SystemExit("retained-cleanup journal has invalid syntax")
            key, value = line.split("=", 1)
            if key in fields:
                raise SystemExit("retained-cleanup journal has duplicate fields")
            fields[key] = value
        current_journal = os.fstat(journal_fd)
        named_journal = os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            current_journal.st_nlink != 1
            or (
                current_journal.st_size,
                current_journal.st_mtime_ns,
                current_journal.st_ctime_ns,
            )
            != journal_snapshot
            or (current_journal.st_dev, current_journal.st_ino, current_journal.st_uid)
            != journal_identity
            or (named_journal.st_dev, named_journal.st_ino, named_journal.st_uid)
            != journal_identity
        ):
            raise SystemExit("retained-cleanup journal identity changed while it was read")
    finally:
        os.close(journal_fd)

    required = {
        "schema", "phase", "kind", "original_path", "quarantine_path",
        "parent_device", "parent_inode", "parent_owner", "target_device",
        "target_inode", "target_owner",
    }
    if (
        set(fields) != required
        or fields["schema"] != "1"
        or fields["phase"] not in {"prepared", "retained"}
    ):
        raise SystemExit("retained-cleanup journal is incomplete")
    if fields["kind"] not in {"file", "leaf", "tree"}:
        raise SystemExit("retained-cleanup journal has invalid kind")
    original_name = os.path.basename(fields["original_path"])
    quarantine_name = os.path.basename(fields["quarantine_path"])
    if (
        parent != os.path.dirname(fields["original_path"])
        or parent != os.path.dirname(fields["quarantine_path"])
        or original_name in {"", ".", ".."}
        or quarantine_name in {"", ".", ".."}
    ):
        raise SystemExit("retained-cleanup journal paths do not share one parent")
    expected_parent = (
        int(fields["parent_device"]), int(fields["parent_inode"]), int(fields["parent_owner"]),
    )
    expected_target = (
        int(fields["target_device"]), int(fields["target_inode"]), int(fields["target_owner"]),
    )
    if (parent_stat.st_dev, parent_stat.st_ino, parent_stat.st_uid) != expected_parent:
        raise SystemExit("retained-cleanup parent identity changed")
    try:
        os.stat(original_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("retained-cleanup original pathname exists")
    quarantine_stat = os.stat(quarantine_name, dir_fd=parent_fd, follow_symlinks=False)
    if (quarantine_stat.st_dev, quarantine_stat.st_ino, quarantine_stat.st_uid) != expected_target:
        raise SystemExit("retained-cleanup quarantine identity changed")
    if fields["kind"] == "tree" and not stat.S_ISDIR(quarantine_stat.st_mode):
        raise SystemExit("retained-cleanup quarantine type changed")
    if fields["kind"] == "file" and not stat.S_ISREG(quarantine_stat.st_mode):
        raise SystemExit("retained-cleanup quarantine type changed")
    if fields["kind"] == "leaf" and not stat.S_ISLNK(quarantine_stat.st_mode):
        raise SystemExit("retained-cleanup quarantine type changed")
    print(
        ("cleanup_retained_verified" if fields["phase"] == "retained" else "cleanup_prepared_verified")
        + f"\toriginal={fields['original_path']}"
        + f"\tquarantine={fields['quarantine_path']}"
        + f"\tdevice={fields['target_device']}"
        + f"\tinode={fields['target_inode']}"
        + f"\towner={fields['target_owner']}"
    )
finally:
    os.close(parent_fd)
PY
}

# shellcheck disable=SC2034 # Public result variables consumed by sourced callers.
CAMPAIGN_LAST_RETAINED_QUARANTINE=""
# shellcheck disable=SC2034 # Public result variables consumed by sourced callers.
CAMPAIGN_LAST_RETAINED_JOURNAL=""

declare -Ag CAMPAIGN_CLEANUP_IDENTITIES=()

campaign_capture_cleanup_identity() {
    local path="$1"
    local kind="$2"
    local output_prefix="$3"
    local label="$4"
    [[ "$kind" == file || "$kind" == tree ]] || return 1
    [[ "$output_prefix" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    local parent
    parent="$(dirname "$path")"
    campaign_require_owned_real_directory "$parent" "$label parent" || return 1
    if [[ "$kind" == tree ]]; then
        campaign_require_owned_real_directory "$path" "$label" || return 1
    else
        [[ -f "$path" && ! -L "$path" && "$(stat -c %u "$path")" == "$(id -u)" &&
        "$(stat -c %h "$path")" == 1 ]] || return 1
    fi
    [[ "$(dirname "$path")" == "$parent" ]] || return 1
    local parent_identity target_identity parent_remainder target_remainder
    parent_identity="$(stat -c '%d:%i:%u' "$parent")" || return 1
    target_identity="$(stat -c '%d:%i:%u' "$path")" || return 1
    parent_remainder="${parent_identity#*:}"
    target_remainder="${target_identity#*:}"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:kind"]="$kind"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:parent_device"]="${parent_identity%%:*}"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:parent_inode"]="${parent_remainder%%:*}"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:parent_owner"]="${parent_identity##*:}"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:target_device"]="${target_identity%%:*}"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:target_inode"]="${target_remainder%%:*}"
    CAMPAIGN_CLEANUP_IDENTITIES["$output_prefix:target_owner"]="${target_identity##*:}"
}

campaign_prepare_private_temporary_tree() {
    local base="$1"
    local family="$2"
    local identity_prefix="$3"
    local output_variable="$4"
    local absolute_deadline="${5:-}"
    local cleanup_deadline="${6:-}"
    [[ "$family" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    [[ "$identity_prefix" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    # `printf -v` follows Bash's dynamic scope. Reject every implementation
    # local (and the coprocess globals) before creating anything so a caller
    # cannot accidentally publish into this function's private scope and lose
    # the only pathname for the descriptor-bound tree.
    case "$output_variable" in
    base | family | identity_prefix | output_variable | absolute_deadline | cleanup_deadline | captured | encoded_tree | tree | encoded_journal | journal | \
        parent_device | parent_inode | parent_owner | target_device | target_inode | \
        target_owner | journal_device | journal_inode | journal_owner | extra | creator_response | creator_pid | creator_starttime | creator_read_fd | \
        commit_marker | committed_journal_device | committed_journal_inode | committed_journal_owner | commit_extra | \
        creator_write_fd | creator_status | CAMPAIGN_PRIVATE_TREE_CREATOR | \
        CAMPAIGN_PRIVATE_TREE_CREATOR_PID | CAMPAIGN_CLEANUP_IDENTITIES)
        printf 'private temporary tree output variable collides with helper state: %s\n' \
            "$output_variable" >&2
        return 1
        ;;
    esac
    command -v python3 >/dev/null 2>&1 || {
        printf 'missing required private temporary tree runtime: python3\n' >&2
        return 1
    }
    command -v base64 >/dev/null 2>&1 || {
        printf 'missing required private temporary tree path codec: base64\n' >&2
        return 1
    }
    local creator_timeout="${BORONDNS_CAMPAIGN_PRIVATE_TREE_TIMEOUT_SECONDS:-30}"
    [[ "$creator_timeout" =~ ^[1-9][0-9]*$ ]] || {
        printf 'invalid private temporary tree timeout: %s\n' "$creator_timeout" >&2
        return 1
    }
    if [[ -z "$absolute_deadline" ]]; then
        absolute_deadline="$(campaign_deadline_from_timeout_seconds "$creator_timeout")" || return 1
        absolute_deadline=$((absolute_deadline + 300000000))
    elif ! campaign_is_positive_signed_64 "$absolute_deadline"; then
        printf 'invalid private temporary tree absolute deadline: %s\n' "$absolute_deadline" >&2
        return 1
    fi
    [[ -n "$cleanup_deadline" ]] || cleanup_deadline="$absolute_deadline"
    local captured encoded_tree tree encoded_journal journal parent_device parent_inode parent_owner
    local target_device target_inode target_owner journal_device journal_inode journal_owner extra creator_response
    local automatic_owner_pid="$BASHPID"
    coproc CAMPAIGN_PRIVATE_TREE_CREATOR {
        # Keep stdin attached to the coprocess protocol and supply the Python
        # source on a separate descriptor. The creator retains the opened
        # parent and tree descriptors until Bash either publishes or rolls back.
        exec python3 /dev/fd/3 "$base" "$family" "$(id -u)" "$automatic_owner_pid" \
            "$absolute_deadline" 3<<'PY'
import base64
import ctypes
import fcntl
import hashlib
import os
import re
import secrets
import select
import socket
import stat
import sys
import time


base, family, expected_uid_text, owner_pid_text, absolute_deadline_text = sys.argv[1:]
expected_uid = int(expected_uid_text)
owner_pid = int(owner_pid_text)
absolute_deadline = int(absolute_deadline_text)
base_path = os.path.abspath(os.path.normpath(base))
parent_name = f"{family}-{expected_uid}"
parent_path = os.path.join(base_path, parent_name)
base_fd = None
parent_fd = None
tree_fd = None
tree_name = None
tree_identity = None
journal_name = None
journal_identity = None
lock_fd = None
lock_identity = None
family_authority = None
metadata_published = False
fault_phase = os.environ.get("BORONDNS_CAMPAIGN_PRIVATE_TREE_FAULT_PHASE", "")


def fault(point: str) -> None:
    if fault_phase == point:
        os.kill(os.getpid(), 9)


def journal_recovery_test_pause(point: str) -> None:
    if os.environ.get("BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_PHASE", "") != point:
        return
    marker = os.environ.get("BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_MARKER", "")
    continuation = os.environ.get("BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_CONTINUE", "")
    if not marker or not continuation:
        raise RuntimeError("automatic-tree journal recovery test hook is incomplete")
    open(marker, "x", encoding="ascii").close()
    while not os.path.exists(continuation):
        if boottime_now() >= absolute_deadline:
            raise RuntimeError("automatic-tree journal recovery test hook expired")
        time.sleep(0.01)


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("it_interval", Timespec), ("it_value", Timespec)]


def boottime_now() -> int:
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


enumeration_cap_text = os.environ.get("BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP", "4096")
if not enumeration_cap_text.isdigit() or enumeration_cap_text.startswith("0"):
    raise RuntimeError("invalid automatic-tree enumeration entry cap")
enumeration_entry_cap = int(enumeration_cap_text)
if not 1 <= enumeration_entry_cap <= 65536:
    raise RuntimeError("invalid automatic-tree enumeration entry cap")
enumeration_delay_text = os.environ.get(
    "BORONDNS_CAMPAIGN_ENUMERATION_TEST_DELAY_NANOSECONDS", "0"
)
if not enumeration_delay_text.isdigit() or int(enumeration_delay_text) > 1_000_000_000:
    raise RuntimeError("invalid automatic-tree enumeration test delay")
enumeration_test_delay = int(enumeration_delay_text) / 1_000_000_000


def bounded_directory_names(directory_fd: int, label: str) -> list[str]:
    names = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if boottime_now() >= absolute_deadline:
                raise RuntimeError(f"{label} enumeration deadline expired")
            if enumeration_test_delay:
                time.sleep(enumeration_test_delay)
                if boottime_now() >= absolute_deadline:
                    raise RuntimeError(f"{label} enumeration deadline expired")
            if len(names) >= enumeration_entry_cap:
                raise RuntimeError(f"{label} enumeration entry cap exceeded")
            names.append(entry.name)
    if boottime_now() >= absolute_deadline:
        raise RuntimeError(f"{label} enumeration deadline expired")
    return sorted(names, key=os.fsencode)


def arm_boottime_deadline(deadline: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    create = libc.timerfd_create
    create.argtypes = [ctypes.c_int, ctypes.c_int]
    create.restype = ctypes.c_int
    settime = libc.timerfd_settime
    settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    settime.restype = ctypes.c_int
    descriptor = create(time.CLOCK_BOOTTIME, os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    specification = Itimerspec(
        Timespec(0, 0), Timespec(deadline // 1_000_000_000, deadline % 1_000_000_000)
    )
    if settime(descriptor, 1, ctypes.byref(specification), None) != 0:
        error = ctypes.get_errno()
        os.close(descriptor)
        raise OSError(error, os.strerror(error))
    return descriptor


deadline_fd = arm_boottime_deadline(absolute_deadline)


def protocol_request() -> str:
    poller = select.poll()
    poller.register(sys.stdin.fileno(), select.POLLIN | select.POLLHUP)
    poller.register(deadline_fd, select.POLLIN)
    events = poller.poll()
    if any(descriptor == deadline_fd for descriptor, _event in events):
        raise RuntimeError("automatic-tree protocol deadline expired")
    return sys.stdin.readline().strip()


def identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, info.st_uid)


def same_named_identity(directory_fd: int, name: str, expected: tuple[int, int, int]) -> bool:
    try:
        return identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) == expected
    except OSError:
        return False


def rename_with_flags(directory_fd: int, source: str, destination: str, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise RuntimeError("renameat2 is required for automatic-tree journal recovery") from error
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(
        directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), flags
    ) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def require_family_authority() -> None:
    if family_authority is None or lock_fd is None or lock_identity is None:
        raise RuntimeError("automatic-tree family authority is not active")
    current_lock = os.fstat(lock_fd)
    if (
        identity(current_lock) != lock_identity
        or not stat.S_ISREG(current_lock.st_mode)
        or current_lock.st_uid != expected_uid
        or current_lock.st_nlink != 1
        or stat.S_IMODE(current_lock.st_mode) != 0o600
        or not same_named_identity(parent_fd, lock_name, lock_identity)
    ):
        raise RuntimeError("automatic-tree family lock pathname changed")
    if not same_named_identity(base_fd, parent_name, parent_identity):
        raise RuntimeError(f"private temporary parent identity changed: {parent_path}")
    if identity(os.stat(base_path, follow_symlinks=False)) != identity(base_info):
        raise RuntimeError(f"private temporary base identity changed: {base_path}")


def require_cleanup_authority(allow_detached_lock: bool) -> None:
    if not allow_detached_lock:
        require_family_authority()
        return
    # Before publication, the creator's bound abstract socket remains the
    # non-replaceable family authority even if a hostile actor replaced the
    # diagnostic lock pathname. Preserve rollback in that narrow state while
    # still binding both filesystem ancestors by descriptor identity.
    if family_authority is None or family_authority.fileno() < 0:
        raise RuntimeError("automatic-tree creator authority is not active")
    if not same_named_identity(base_fd, parent_name, parent_identity):
        raise RuntimeError(f"private temporary parent identity changed: {parent_path}")
    if identity(os.stat(base_path, follow_symlinks=False)) != identity(base_info):
        raise RuntimeError(f"private temporary base identity changed: {base_path}")


def process_starttime(pid: int) -> int | None:
    try:
        raw = open(f"/proc/{pid}/stat", encoding="ascii").read()
        fields = raw[raw.rfind(")") + 2 :].split()
        if fields[0] in {"Z", "X"}:
            return None
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def clear_directory(directory_fd: int, expected_device: int) -> None:
    for name in bounded_directory_names(directory_fd, "automatic-tree recovery"):
        if boottime_now() >= absolute_deadline:
            raise RuntimeError("automatic-tree recovery deadline expired")
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        expected = identity(info)
        quarantine = f".{name}.borondns-recovery-remove.{os.getpid()}.{secrets.token_hex(12)}"
        journal_recovery_test_pause("before-child-quarantine")
        require_family_authority()
        rename_with_flags(directory_fd, name, quarantine, 1)  # RENAME_NOREPLACE
        if not same_named_identity(directory_fd, quarantine, expected):
            raise RuntimeError("automatic-tree child changed while entering quarantine")
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                quarantine, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise RuntimeError("automatic-tree child identity changed")
                if opened.st_dev != expected_device:
                    raise RuntimeError("automatic-tree cleanup crossed a filesystem boundary")
                clear_directory(child_fd, expected_device)
                current = os.stat(quarantine, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise RuntimeError("automatic-tree child pathname changed")
                require_family_authority()
                os.rmdir(quarantine, dir_fd=directory_fd)
            finally:
                os.close(child_fd)
        else:
            require_family_authority()
            if not same_named_identity(directory_fd, quarantine, expected):
                raise RuntimeError("automatic-tree quarantined child identity changed")
            os.unlink(quarantine, dir_fd=directory_fd)


def remove_exact_file(
    directory_fd: int, name: str, expected: tuple[int, int, int], label: str,
    test_point: str, allow_detached_lock: bool = False,
) -> None:
    quarantine = f".{name}.borondns-remove.{os.getpid()}.{secrets.token_hex(12)}"
    journal_recovery_test_pause(test_point)
    require_cleanup_authority(allow_detached_lock)
    rename_with_flags(directory_fd, name, quarantine, 1)  # RENAME_NOREPLACE
    if not same_named_identity(directory_fd, quarantine, expected):
        raise RuntimeError(f"{label} changed while entering quarantine")
    # The directory is writable by the hostile same UID.  Retain the exact
    # quarantined inode: a later pathname unlink could delete a replacement.
    os.fsync(directory_fd)


def remove_exact_empty_directory(
    directory_fd: int, name: str, expected: tuple[int, int, int], label: str,
    allow_detached_lock: bool = False, quarantine_override: str = "",
) -> None:
    quarantine = quarantine_override or f".{name}.borondns-remove.{os.getpid()}.{secrets.token_hex(12)}"
    require_cleanup_authority(allow_detached_lock)
    rename_with_flags(directory_fd, name, quarantine, 1)  # RENAME_NOREPLACE
    if not same_named_identity(directory_fd, quarantine, expected):
        raise RuntimeError(f"{label} changed while entering quarantine")
    os.fsync(directory_fd)


def rollback_exact_tree_and_journal(allow_detached_lock: bool = False) -> None:
    global journal_identity
    if not same_named_identity(parent_fd, tree_name, tree_identity):
        raise RuntimeError("automatic-tree rollback target identity changed")
    quarantine = f".{tree_name}.borondns-remove.{owner_pid}.{secrets.token_hex(12)}"
    journal_identity = update_removal_journal(
        journal_name, journal_identity, parent_identity, tree_name, tree_identity,
        boot_id, owner_pid, owner_starttime, quarantine,
    )
    remove_exact_empty_directory(
        parent_fd, tree_name, tree_identity, "automatic-tree rollback target",
        allow_detached_lock, quarantine,
    )
    if journal_name is not None and journal_identity is not None:
        remove_exact_file(
            parent_fd, journal_name, journal_identity,
            "automatic-tree rollback journal", "before-rollback-journal-quarantine",
            allow_detached_lock,
        )
    os.fsync(parent_fd)


def read_journal(name: str, expected_final_name: str | None = None) -> tuple[dict[str, str], tuple[int, int, int]]:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        expected_identity = identity(info)
        snapshot = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_nlink != 1
            or not 0 < info.st_size <= 4096
            or identity(named) != expected_identity
        ):
            raise RuntimeError(f"unsafe automatic-tree journal: {name}")
        raw = b""
        while len(raw) < info.st_size:
            chunk = os.read(fd, info.st_size - len(raw))
            if not chunk:
                raise RuntimeError(f"automatic-tree journal was truncated while reading: {name}")
            raw += chunk
        if os.read(fd, 1):
            raise RuntimeError(f"automatic-tree journal grew while reading: {name}")
        current = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            identity(current) != expected_identity
            or identity(named) != expected_identity
            or (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != snapshot
            or current.st_nlink != 1
        ):
            raise RuntimeError(f"automatic-tree journal changed while reading: {name}")
        values: dict[str, str] = {}
        for line in raw.decode("utf-8").splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise RuntimeError(f"malformed automatic-tree journal: {name}")
            values[key] = value
        common = {
            "schema", "phase", "boot_id", "owner_pid", "owner_starttime",
            "parent_device", "parent_inode", "parent_owner", "tree_name",
            "tree_device", "tree_inode", "tree_owner",
        }
        if values.get("schema") == "1":
            if set(values) != common or values.get("phase") not in {"preparing", "ready"}:
                raise RuntimeError(f"invalid automatic-tree journal schema: {name}")
            values["quarantine_name"] = ""
        elif values.get("schema") == "2":
            if set(values) != common | {"quarantine_name"} or values.get("phase") not in {
                "allocating", "preparing", "ready"
            }:
                raise RuntimeError(f"invalid automatic-tree journal schema: {name}")
        elif values.get("schema") == "3":
            if set(values) != common | {"quarantine_name", "cleanup_deadline_ns"} or values.get("phase") != "removing":
                raise RuntimeError(f"invalid automatic-tree journal schema: {name}")
            if not values["cleanup_deadline_ns"].isdigit() or not 0 < int(values["cleanup_deadline_ns"]) <= 9223372036854775807:
                raise RuntimeError(f"invalid automatic-tree cleanup deadline: {name}")
        else:
            raise RuntimeError(f"invalid automatic-tree journal schema: {name}")
        if not re.fullmatch(r"run\.[0-9a-f]{16}", values["tree_name"]):
            raise RuntimeError(f"invalid automatic-tree journal target: {name}")
        final_name = expected_final_name or name
        if final_name != f'.automatic-{values["tree_name"]}.env':
            raise RuntimeError(f"automatic-tree journal name does not match target: {name}")
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", values["boot_id"]):
            raise RuntimeError(f"invalid automatic-tree journal boot ID: {name}")
        for key in common - {"schema", "phase", "boot_id", "tree_name"}:
            if not values[key].isdigit():
                raise RuntimeError(f"invalid automatic-tree journal numeric field: {name}")
        if values["phase"] == "allocating":
            if any(values[key] != "0" for key in ("tree_device", "tree_inode", "tree_owner")):
                raise RuntimeError(f"allocating automatic-tree journal has an identity: {name}")
        elif any(values[key] == "0" for key in ("tree_device", "tree_inode")):
            raise RuntimeError(f"automatic-tree journal has no target identity: {name}")
        quarantine = values["quarantine_name"]
        expected_quarantine = rf"\.{re.escape(values['tree_name'])}\.borondns-remove\.[0-9]+\.[0-9a-f]{{24}}"
        if values["phase"] == "removing":
            if re.fullmatch(expected_quarantine, quarantine) is None:
                raise RuntimeError(f"invalid automatic-tree quarantine name: {name}")
        elif quarantine:
            raise RuntimeError(f"unexpected automatic-tree quarantine name: {name}")
        return values, identity(info)
    finally:
        os.close(fd)


def reconcile_staged_journals() -> None:
    staged_pattern = re.compile(
        r"^\.(\.automatic-run\.[0-9a-f]{16}\.env)\."
        r"(allocating|preparing|ready|removing)\.[0-9a-f]{16}$"
    )
    grouped: dict[str, list[str]] = {}
    for staged_name in bounded_directory_names(parent_fd, "automatic-tree staged-journal"):
        match = staged_pattern.fullmatch(staged_name)
        if match is not None:
            grouped.setdefault(match.group(1), []).append(staged_name)
    for final_name, staged_names in grouped.items():
        if len(staged_names) != 1:
            raise RuntimeError(f"multiple automatic-tree staged journals: {final_name}")
        staged_name = staged_names[0]
        staged_values, staged_identity = read_journal(staged_name, final_name)
        try:
            final_values, final_identity = read_journal(final_name)
        except FileNotFoundError:
            if staged_values["phase"] != "allocating":
                raise RuntimeError(f"automatic-tree staged journal has no durable intent: {staged_name}")
            journal_recovery_test_pause("before-staged-promote")
            if not same_named_identity(parent_fd, staged_name, staged_identity):
                raise RuntimeError(f"automatic-tree staged journal changed before promotion: {staged_name}")
            try:
                os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError(f"automatic-tree final journal appeared before promotion: {final_name}")
            require_family_authority()
            rename_with_flags(parent_fd, staged_name, final_name, 1)  # RENAME_NOREPLACE
            if not same_named_identity(parent_fd, final_name, staged_identity):
                raise RuntimeError(f"automatic-tree promoted an unexpected staged journal: {final_name}")
            os.fsync(parent_fd)
            continue
        stable_keys = {
            "boot_id", "parent_device", "parent_inode", "parent_owner", "tree_name"
        }
        if any(staged_values[key] != final_values[key] for key in stable_keys):
            raise RuntimeError(f"automatic-tree staged journal disagrees with final journal: {staged_name}")
        # A staged rewrite is not committed until replace. The one exception is
        # preparing over allocating: it contains the only exact identity for a
        # directory that was necessarily created after the durable intent.
        if staged_values["phase"] == "preparing" and final_values["phase"] == "allocating":
            journal_recovery_test_pause("before-staged-replace")
            if (
                not same_named_identity(parent_fd, staged_name, staged_identity)
                or not same_named_identity(parent_fd, final_name, final_identity)
            ):
                raise RuntimeError(f"automatic-tree journal identity changed before recovery replace: {final_name}")
            require_family_authority()
            rename_with_flags(parent_fd, staged_name, final_name, 2)  # RENAME_EXCHANGE
            if (
                not same_named_identity(parent_fd, final_name, staged_identity)
                or not same_named_identity(parent_fd, staged_name, final_identity)
            ):
                raise RuntimeError(f"automatic-tree journal exchange changed identity: {final_name}")
            remove_exact_file(
                parent_fd, staged_name, final_identity,
                "automatic-tree displaced journal",
                "before-displaced-quarantine",
            )
        else:
            journal_recovery_test_pause("before-staged-unlink")
            if (
                not same_named_identity(parent_fd, staged_name, staged_identity)
                or not same_named_identity(parent_fd, final_name, final_identity)
            ):
                raise RuntimeError(f"automatic-tree journal identity changed before staged cleanup: {final_name}")
            remove_exact_file(
                parent_fd, staged_name, staged_identity,
                "automatic-tree stale staged journal",
                "before-staged-quarantine",
            )
        os.fsync(parent_fd)


def remove_recovered_tree(
    target_name: str, quarantine_name: str, expected_tree: tuple[int, int, int], label: str,
) -> None:
    journal_recovery_test_pause("before-tree-quarantine")
    require_family_authority()
    if target_name != quarantine_name:
        rename_with_flags(parent_fd, target_name, quarantine_name, 1)  # RENAME_NOREPLACE
    if not same_named_identity(parent_fd, quarantine_name, expected_tree):
        raise RuntimeError(f"dead automatic-tree changed while entering quarantine: {label}")
    # Crash journals in this same-UID-writable namespace are not durable
    # authentication. Recovery may recognize an already-retained quarantine,
    # but never recurse, unlink, overwrite, or promote based on it.
    os.fsync(parent_fd)


def reconcile_dead_journals(parent_identity: tuple[int, int, int], boot_id: str) -> None:
    reconcile_staged_journals()
    for name in bounded_directory_names(parent_fd, "automatic-tree journal"):
        if boottime_now() >= absolute_deadline:
            raise RuntimeError("automatic-tree journal reconciliation deadline expired")
        if not re.fullmatch(r"\.automatic-run\.[0-9a-f]{16}\.env", name):
            continue
        values, journal_expected = read_journal(name)
        if (
            (int(values["parent_device"]), int(values["parent_inode"]), int(values["parent_owner"]))
            != parent_identity
        ):
            raise RuntimeError(f"automatic-tree journal parent identity changed: {name}")
        saved_pid = int(values["owner_pid"])
        saved_starttime = int(values["owner_starttime"])
        owner_is_live = values["boot_id"] == boot_id and process_starttime(saved_pid) == saved_starttime
        if owner_is_live:
            if values["phase"] != "removing":
                continue
            if boottime_now() < int(values["cleanup_deadline_ns"]):
                continue
        # A disk journal owned by this UID can be forged after the live abstract
        # authority disappears.  It is evidence for privileged/manual
        # reconciliation only and never authorizes a destructive restart.
        print(
            "dead automatic-tree journal is unauthenticated; retained for privileged exact reconciliation: "
            f"{name}",
            file=sys.stderr,
        )
        continue


def journal_payload(
    phase: str, parent_identity: tuple[int, int, int], tree_name: str,
    tree_identity: tuple[int, int, int], boot_id: str, journal_owner_pid: int,
    journal_owner_starttime: int, quarantine_name: str = "",
) -> bytes:
    return "\n".join((
        "schema=2", f"phase={phase}", f"boot_id={boot_id}",
        f"owner_pid={journal_owner_pid}", f"owner_starttime={journal_owner_starttime}",
        f"parent_device={parent_identity[0]}", f"parent_inode={parent_identity[1]}",
        f"parent_owner={parent_identity[2]}", f"tree_name={tree_name}",
        f"tree_device={tree_identity[0]}", f"tree_inode={tree_identity[1]}",
        f"tree_owner={tree_identity[2]}", f"quarantine_name={quarantine_name}", "",
    )).encode("utf-8")


def write_journal(
    name: str, phase: str, payload: bytes,
    expected: tuple[int, int, int] | None,
) -> tuple[int, int, int]:
    temporary = f".{name}.{phase}.{secrets.token_hex(8)}"
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    linkat.restype = ctypes.c_int
    flags = os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC
    require_family_authority()
    try:
        fd = os.open(".", flags, 0o600, dir_fd=parent_fd)
    except OSError as error:
        raise RuntimeError("O_TMPFILE is required for exact automatic-tree journal publication") from error
    try:
        staged_identity = identity(os.fstat(fd))
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise RuntimeError("automatic-tree journal write stalled")
            view = view[written:]
        os.fsync(fd)
        fault(f"{phase}-stage-fsynced")
        require_family_authority()
        publish_name = name if expected is None else temporary
        if linkat(fd, b"", parent_fd, os.fsencode(publish_name), 0x1000) != 0:  # AT_EMPTY_PATH
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), publish_name)
        if not same_named_identity(parent_fd, publish_name, staged_identity):
            raise RuntimeError("automatic-tree journal exact-fd link changed")
        if expected is not None:
            require_family_authority()
            rename_with_flags(parent_fd, temporary, name, 2)  # RENAME_EXCHANGE
            if (
                not same_named_identity(parent_fd, name, staged_identity)
                or not same_named_identity(parent_fd, temporary, expected)
            ):
                # Both names are retained. Never unlink a possibly substituted
                # displaced entry in this same-UID-writable directory.
                raise RuntimeError("automatic-tree journal changed during publish exchange")
            retained = f".{temporary}.retained.{secrets.token_hex(8)}"
            rename_with_flags(parent_fd, temporary, retained, 1)  # RENAME_NOREPLACE
        os.fsync(parent_fd)
        fault(f"{phase}-published")
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if identity(info) != staged_identity:
            raise RuntimeError("automatic-tree journal destination is not the held staged inode")
        return staged_identity
    finally:
        os.close(fd)


def publish_intent_journal(
    parent_identity: tuple[int, int, int], tree_name: str, boot_id: str,
    journal_owner_pid: int, journal_owner_starttime: int,
) -> tuple[str, tuple[int, int, int]]:
    name = f".automatic-{tree_name}.env"
    payload = journal_payload(
        "allocating", parent_identity, tree_name, (0, 0, 0), boot_id,
        journal_owner_pid, journal_owner_starttime,
    )
    return name, write_journal(name, "allocating", payload, None)


def update_journal(
    name: str, expected: tuple[int, int, int], parent_identity: tuple[int, int, int],
    phase: str, tree_name: str, tree_identity: tuple[int, int, int], boot_id: str,
    journal_owner_pid: int, journal_owner_starttime: int, quarantine_name: str = "",
) -> tuple[int, int, int]:
    payload = journal_payload(
        phase, parent_identity, tree_name, tree_identity, boot_id,
        journal_owner_pid, journal_owner_starttime, quarantine_name,
    )
    return write_journal(name, phase, payload, expected)


def update_removal_journal(
    name: str, expected: tuple[int, int, int], parent_identity: tuple[int, int, int],
    tree_name: str, tree_identity: tuple[int, int, int], boot_id: str,
    journal_owner_pid: int, journal_owner_starttime: int, quarantine_name: str,
) -> tuple[int, int, int]:
    payload = "\n".join((
        "schema=3", "phase=removing", f"boot_id={boot_id}",
        f"owner_pid={journal_owner_pid}", f"owner_starttime={journal_owner_starttime}",
        f"parent_device={parent_identity[0]}", f"parent_inode={parent_identity[1]}",
        f"parent_owner={parent_identity[2]}", f"tree_name={tree_name}",
        f"tree_device={tree_identity[0]}", f"tree_inode={tree_identity[1]}",
        f"tree_owner={tree_identity[2]}", f"quarantine_name={quarantine_name}",
        f"cleanup_deadline_ns={absolute_deadline}", "",
    )).encode("utf-8")
    return write_journal(name, "removing", payload, expected)


try:
    if os.path.realpath(base) != base_path or os.path.islink(base):
        raise RuntimeError(f"private temporary base must be a canonical real directory: {base}")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    base_fd = os.open(base_path, directory_flags)
    base_info = os.fstat(base_fd)
    if not stat.S_ISDIR(base_info.st_mode):
        raise RuntimeError(f"private temporary base is not a directory: {base_path}")
    if identity(os.stat(base_path, follow_symlinks=False)) != identity(base_info):
        raise RuntimeError(f"private temporary base identity changed: {base_path}")

    try:
        os.mkdir(parent_name, 0o700, dir_fd=base_fd)
    except FileExistsError:
        pass
    parent_fd = os.open(parent_name, directory_flags, dir_fd=base_fd)
    parent_info = os.fstat(parent_fd)
    parent_identity = identity(parent_info)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != expected_uid
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise RuntimeError(f"private temporary parent is not owned and private: {parent_path}")
    if not same_named_identity(base_fd, parent_name, parent_identity):
        raise RuntimeError(f"private temporary parent identity changed: {parent_path}")

    boot_id = open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id):
        raise RuntimeError("cannot authenticate the automatic-tree owner boot ID")
    owner_starttime = process_starttime(owner_pid)
    if owner_starttime is None:
        raise RuntimeError("cannot authenticate the automatic-tree owner process")
    # This kernel namespace is the non-replaceable family authority. The
    # filesystem lock remains useful for diagnostics and recovery across
    # cooperating processes, but cannot split authority if a same-UID process
    # renames its inode and creates a replacement at the published pathname.
    authority_digest = hashlib.sha256(
        os.fsencode(parent_path) + b"\0" + os.fsencode(family)
    ).hexdigest()
    family_authority = socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0)
    )
    family_authority.bind(f"\0borondns-automatic-{expected_uid}-{authority_digest}")
    lock_name = ".automatic-recovery.lock"
    lock_fd = os.open(
        lock_name, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600, dir_fd=parent_fd,
    )
    os.fchmod(lock_fd, 0o600)
    lock_info = os.fstat(lock_fd)
    if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != expected_uid or lock_info.st_nlink != 1:
        raise RuntimeError("automatic-tree family lock is unsafe")
    if stat.S_IMODE(lock_info.st_mode) != 0o600:
        raise RuntimeError("automatic-tree family lock mode is unsafe")
    lock_identity = identity(lock_info)
    named_lock = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
    if (named_lock.st_dev, named_lock.st_ino) != (lock_info.st_dev, lock_info.st_ino):
        raise RuntimeError("automatic-tree family lock pathname changed")
    while True:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            now = boottime_now()
            if now >= absolute_deadline:
                raise RuntimeError("automatic-tree family lock deadline expired")
            time.sleep(min(0.02, (absolute_deadline - now) / 1_000_000_000))
    require_family_authority()
    reconcile_dead_journals(parent_identity, boot_id)

    creator_starttime = process_starttime(os.getpid())
    if creator_starttime is None:
        raise RuntimeError("cannot authenticate the automatic-tree creator process")

    for _attempt in range(128):
        candidate = f"run.{secrets.token_hex(8)}"
        try:
            os.stat(candidate, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            journal_candidate = f".automatic-{candidate}.env"
            try:
                os.stat(journal_candidate, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                tree_name = candidate
                break
        if tree_name is None:
            continue
    if tree_name is None:
        raise RuntimeError(f"cannot allocate a unique private temporary tree below {parent_path}")

    # The fsynced intent exists before the directory allocation. A crash can no
    # longer create an invisible run.* tree; recovery either removes an empty
    # intent or retains an ambiguous post-mkdir/pre-identity inode fail-closed.
    journal_name, journal_identity = publish_intent_journal(
        parent_identity, tree_name, boot_id, os.getpid(), creator_starttime
    )
    require_family_authority()
    os.mkdir(tree_name, 0o700, dir_fd=parent_fd)
    fault("tree-created-before-identity")

    tree_fd = os.open(tree_name, directory_flags, dir_fd=parent_fd)
    require_family_authority()
    os.fchmod(tree_fd, 0o700)
    tree_info = os.fstat(tree_fd)
    tree_identity = identity(tree_info)
    if (
        not stat.S_ISDIR(tree_info.st_mode)
        or tree_info.st_uid != expected_uid
        or stat.S_IMODE(tree_info.st_mode) != 0o700
        or not same_named_identity(parent_fd, tree_name, tree_identity)
    ):
        raise RuntimeError("new private temporary tree identity changed during creation")
    if not same_named_identity(base_fd, parent_name, parent_identity):
        raise RuntimeError(f"private temporary parent identity changed: {parent_path}")
    if identity(os.stat(base_path, follow_symlinks=False)) != identity(base_info):
        raise RuntimeError(f"private temporary base identity changed: {base_path}")

    journal_identity = update_journal(
        journal_name, journal_identity, parent_identity, "preparing", tree_name,
        tree_identity, boot_id, os.getpid(), creator_starttime,
    )

    tree_path = os.path.join(parent_path, tree_name)
    journal_path = os.path.join(parent_path, journal_name)
    encoded_path = base64.b64encode(os.fsencode(tree_path)).decode("ascii")
    encoded_journal = base64.b64encode(os.fsencode(journal_path)).decode("ascii")
    require_family_authority()
    print(
        "\t".join(
            (
                encoded_path,
                str(parent_identity[0]),
                str(parent_identity[1]),
                str(parent_identity[2]),
                str(tree_identity[0]),
                str(tree_identity[1]),
                str(tree_identity[2]),
                encoded_journal,
                str(journal_identity[0]),
                str(journal_identity[1]),
                str(journal_identity[2]),
            )
        ),
        flush=True,
    )
    metadata_published = True

    request = protocol_request()
    if request == "rollback":
        require_family_authority()
        if identity(os.fstat(tree_fd)) == tree_identity:
            try:
                rollback_exact_tree_and_journal()
            except (OSError, RuntimeError):
                print("rollback-refused", flush=True)
                raise SystemExit(2)
            print("rolled-back", flush=True)
        else:
            print("rollback-refused", flush=True)
            raise SystemExit(2)
    elif request == "prepare-publication":
        require_family_authority()
        if (
            identity(os.fstat(tree_fd)) != tree_identity
            or not same_named_identity(parent_fd, tree_name, tree_identity)
        ):
            print("publication-refused", flush=True)
            raise SystemExit(2)
        require_family_authority()
        print("publication-ready", flush=True)
        if protocol_request() != "published":
            if same_named_identity(parent_fd, tree_name, tree_identity):
                try:
                    rollback_exact_tree_and_journal()
                except (OSError, RuntimeError):
                    pass
            raise SystemExit(2)
        journal_identity = update_journal(
            journal_name, journal_identity, parent_identity, "ready", tree_name,
            tree_identity, boot_id, owner_pid, owner_starttime,
        )
        require_family_authority()
        print(
            "\t".join((
                "committed", str(journal_identity[0]), str(journal_identity[1]),
                str(journal_identity[2]),
            )),
            flush=True,
        )
    else:
        # EOF or an invalid request before publication is a rollback request.
        require_family_authority()
        if same_named_identity(parent_fd, tree_name, tree_identity):
            try:
                rollback_exact_tree_and_journal()
            except (OSError, RuntimeError):
                pass
        raise SystemExit(2)
except BaseException as error:
    # Roll back only the exact empty inode created above, including a failure
    # after metadata was sent to the parent but before the publication protocol
    # committed. This rollback is descriptor/identity-bound and remains safe
    # under a replaced diagnostic lock pathname because this creator still
    # holds the non-replaceable abstract family authority. If a same-UID process
    # replaced or populated the tree name, retain that state instead.
    if (
        parent_fd is not None
        and tree_name is not None
        and tree_identity is not None
    ):
        try:
            if same_named_identity(parent_fd, tree_name, tree_identity):
                rollback_exact_tree_and_journal(True)
        except (OSError, RuntimeError):
            pass
    print(f"cannot create descriptor-bound private temporary tree: {error}", file=sys.stderr)
    raise SystemExit(1)
finally:
    for descriptor in (tree_fd, lock_fd, parent_fd, base_fd):
        if descriptor is not None:
            os.close(descriptor)
    if family_authority is not None:
        family_authority.close()
    os.close(deadline_fd)
PY
    }
    local creator_pid="$CAMPAIGN_PRIVATE_TREE_CREATOR_PID"
    local creator_read_fd="${CAMPAIGN_PRIVATE_TREE_CREATOR[0]}"
    local creator_write_fd="${CAMPAIGN_PRIVATE_TREE_CREATOR[1]}"
    local creator_starttime
    if ! campaign_process_starttime "$creator_pid" creator_starttime; then
        exec {creator_read_fd}<&-
        exec {creator_write_fd}>&-
        wait "$creator_pid" 2>/dev/null || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        printf 'private temporary tree creator exited before its process identity could be captured\n' >&2
        return 1
    fi
    # Tests use this hook to stop or otherwise fault the creator after spawn.
    # Production callers do not define it.
    if declare -F campaign_private_temporary_tree_creator_started_hook >/dev/null 2>&1; then
        if ! campaign_private_temporary_tree_creator_started_hook "$creator_pid"; then
            campaign_abort_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
                "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
                "$creator_starttime" || true
            unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
            return 1
        fi
    fi
    local protocol_timeout protocol_deadline
    protocol_deadline="$(campaign_deadline_reserving_termination "$absolute_deadline")" || protocol_deadline="$absolute_deadline"
    if ! protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")" ||
        ! IFS= read -r -t "$protocol_timeout" captured <&"$creator_read_fd"; then
        campaign_abort_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        return 1
    fi
    IFS=$'\t' read -r encoded_tree parent_device parent_inode parent_owner \
        target_device target_inode target_owner encoded_journal journal_device journal_inode \
        journal_owner extra <<<"$captured"
    [[ -n "$encoded_tree" && -z "$extra" && "$parent_device" =~ ^[0-9]+$ &&
        "$parent_inode" =~ ^[0-9]+$ && "$parent_owner" =~ ^[0-9]+$ &&
        "$target_device" =~ ^[0-9]+$ && "$target_inode" =~ ^[0-9]+$ &&
        "$target_owner" =~ ^[0-9]+$ && -n "$encoded_journal" &&
        "$journal_device" =~ ^[0-9]+$ && "$journal_inode" =~ ^[0-9]+$ &&
        "$journal_owner" =~ ^[0-9]+$ ]] || {
        printf 'rollback\n' >&"$creator_write_fd" || true
        if protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")"; then
            IFS= read -r -t "$protocol_timeout" creator_response <&"$creator_read_fd" || true
        fi
        campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        return 1
    }
    tree="$(printf '%s' "$encoded_tree" | base64 --decode)" || {
        printf 'rollback\n' >&"$creator_write_fd" || true
        if protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")"; then
            IFS= read -r -t "$protocol_timeout" creator_response <&"$creator_read_fd" || true
        fi
        campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        return 1
    }
    journal="$(printf '%s' "$encoded_journal" | base64 --decode)" || {
        printf 'rollback\n' >&"$creator_write_fd" || true
        campaign_abort_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        return 1
    }
    [[ -n "$tree" && "$tree" != *$'\n'* ]] || {
        printf 'rollback\n' >&"$creator_write_fd" || true
        if protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")"; then
            IFS= read -r -t "$protocol_timeout" creator_response <&"$creator_read_fd" || true
        fi
        campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        return 1
    }
    [[ -n "$journal" && "$journal" != *$'\n'* &&
        "$journal" == "$(dirname "$tree")/.automatic-$(basename "$tree").env" ]] || {
        printf 'rollback\n' >&"$creator_write_fd" || true
        campaign_abort_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        return 1
    }
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:kind"]="tree"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_device"]="$parent_device"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_inode"]="$parent_inode"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_owner"]="$parent_owner"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_device"]="$target_device"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_inode"]="$target_inode"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_owner"]="$target_owner"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_path"]="$journal"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_device"]="$journal_device"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_inode"]="$journal_inode"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_owner"]="$journal_owner"
    # Tests use this narrow seam to exercise failures after descriptor-bound
    # creation and identity journaling, but before the pathname is published to
    # the caller. Production callers do not define the hook.
    if declare -F campaign_private_temporary_tree_prepublication_hook >/dev/null 2>&1; then
        if ! campaign_private_temporary_tree_prepublication_hook "$tree" "$identity_prefix"; then
            printf 'rollback\n' >&"$creator_write_fd" || true
            creator_response=""
            if protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")"; then
                IFS= read -r -t "$protocol_timeout" creator_response <&"$creator_read_fd" || true
            fi
            if ! campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
                "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
                "$creator_starttime" ||
                [[ "$creator_response" != rolled-back ]]; then
                unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
                return 1
            fi
            unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
            campaign_forget_cleanup_identity "$identity_prefix"
            return 1
        fi
    fi
    if ! protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")" ||
        ! printf 'prepare-publication\n' >&"$creator_write_fd" ||
        ! IFS= read -r -t "$protocol_timeout" creator_response <&"$creator_read_fd" ||
        [[ "$creator_response" != publication-ready ]]; then
        campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        if [[ ! -e "$tree" && ! -L "$tree" && ! -e "$journal" && ! -L "$journal" ]]; then
            campaign_forget_cleanup_identity "$identity_prefix"
        fi
        return 1
    fi
    printf -v "$output_variable" '%s' "$tree"
    if ! protocol_timeout="$(campaign_deadline_remaining_seconds "$protocol_deadline" "$creator_timeout")" ||
        ! printf 'published\n' >&"$creator_write_fd" ||
        ! IFS= read -r -t "$protocol_timeout" creator_response <&"$creator_read_fd"; then
        campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
            "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
            "$creator_starttime" || true
        unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
        unset -v "$output_variable"
        if [[ ! -e "$tree" && ! -L "$tree" && ! -e "$journal" && ! -L "$journal" ]]; then
            campaign_forget_cleanup_identity "$identity_prefix"
        fi
        return 1
    fi
    local creator_status=0
    campaign_finish_protocol_child_before_deadline "$creator_pid" "$creator_read_fd" \
        "$creator_write_fd" "$cleanup_deadline" 'private temporary tree creator' \
        "$creator_starttime" || creator_status=$?
    unset CAMPAIGN_PRIVATE_TREE_CREATOR CAMPAIGN_PRIVATE_TREE_CREATOR_PID
    local commit_marker committed_journal_device committed_journal_inode committed_journal_owner commit_extra
    IFS=$'\t' read -r commit_marker committed_journal_device committed_journal_inode \
        committed_journal_owner commit_extra <<<"$creator_response"
    if ((creator_status != 0)) || [[ "$commit_marker" != committed || -n "$commit_extra" ||
        ! "$committed_journal_device" =~ ^[0-9]+$ || ! "$committed_journal_inode" =~ ^[0-9]+$ ||
        ! "$committed_journal_owner" =~ ^[0-9]+$ ]]; then
        unset -v "$output_variable"
        if [[ ! -e "$tree" && ! -L "$tree" && ! -e "$journal" && ! -L "$journal" ]]; then
            campaign_forget_cleanup_identity "$identity_prefix"
        fi
        return 1
    fi
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_device"]="$committed_journal_device"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_inode"]="$committed_journal_inode"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_owner"]="$committed_journal_owner"
}

campaign_forget_cleanup_identity() {
    local identity_prefix="$1"
    local field
    [[ "$identity_prefix" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    for field in kind parent_device parent_inode parent_owner target_device target_inode target_owner \
        journal_path journal_device journal_inode journal_owner; do
        unset 'CAMPAIGN_CLEANUP_IDENTITIES['"$identity_prefix:$field"']'
    done
}

# A private temporary tree may be atomically promoted out of its automatic
# parent instead of recursively removed. Prove that the promoted pathname still
# names the captured tree, then delete only the exact durable cleanup journal.
# This converts the published tree to ordinary caller-owned state without
# leaving recovery metadata that points at the now-absent temporary name.
campaign_disarm_published_private_temporary_tree() {
    local published_path="$1" identity_prefix="$2" label="$3"
    local journal_path="${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_path"]:-}"
    local published_identity
    [[ "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:kind"]:-}" == tree &&
        -n "$journal_path" && -d "$published_path" && ! -L "$published_path" ]] || return 1
    published_identity="$(stat -c '%d:%i:%u' "$published_path")" || return 1
    [[ "$published_identity" == "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_device"]}:${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_inode"]}:${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_owner"]}" ]] || {
        printf '%s published tree identity changed: %s\n' "$label" "$published_path" >&2
        return 1
    }
    campaign_assert_private_lock || return 1
    campaign_identity_bound_remove file "$(dirname "$journal_path")" "$journal_path" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_owner"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_owner"]}" || return 1
    campaign_forget_cleanup_identity "$identity_prefix"
}

campaign_mark_automatic_tree_removing() {
    local path="$1" identity_prefix="$2" output_variable="$3" absolute_deadline="$4"
    local journal_path="${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_path"]:-}"
    [[ -n "$journal_path" && "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
        "$absolute_deadline" =~ ^[1-9][0-9]*$ ]] || return 1
    case "$output_variable" in
    path | identity_prefix | output_variable | absolute_deadline | journal_path | \
        removal_owner_pid | removal_owner_stat | removal_owner_tail | \
        removal_owner_fields | removal_owner_starttime | result | quarantine | \
        journal_device | journal_inode | journal_owner | extra)
        return 1
        ;;
    esac
    local removal_owner_pid="$BASHPID" removal_owner_stat removal_owner_tail
    local -a removal_owner_fields
    IFS= read -r removal_owner_stat <"/proc/$removal_owner_pid/stat" || return 1
    removal_owner_tail="${removal_owner_stat##*) }"
    read -r -a removal_owner_fields <<<"$removal_owner_tail"
    ((${#removal_owner_fields[@]} > 19)) || return 1
    local removal_owner_starttime="${removal_owner_fields[19]}"
    [[ "$removal_owner_starttime" =~ ^[1-9][0-9]*$ ]] || return 1
    local result quarantine journal_device journal_inode journal_owner extra
    result="$(
        python3 - "$path" "$journal_path" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_device"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_inode"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_owner"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_device"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_inode"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_owner"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_device"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_inode"]}" \
            "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_owner"]}" \
            "$removal_owner_pid" "$removal_owner_starttime" "$absolute_deadline" <<'PY'
import ctypes
import os
import re
import secrets
import stat
import sys
import time

(
    path, journal_path, parent_device, parent_inode, parent_owner,
    tree_device, tree_inode, tree_owner, journal_device, journal_inode,
    journal_owner, owner_pid, owner_starttime, absolute_deadline,
) = sys.argv[1:]
parent = os.path.dirname(path)
tree_name = os.path.basename(path)
journal_name = os.path.basename(journal_path)
if os.path.dirname(journal_path) != parent or journal_name != f".automatic-{tree_name}.env":
    raise SystemExit("automatic-tree removal journal path is inconsistent")
expected_parent = (int(parent_device), int(parent_inode), int(parent_owner))
expected_tree = (int(tree_device), int(tree_inode), int(tree_owner))
expected_journal = (int(journal_device), int(journal_inode), int(journal_owner))
owner_pid = int(owner_pid)
owner_starttime = int(owner_starttime)
absolute_deadline = int(absolute_deadline)
if absolute_deadline <= 0 or absolute_deadline > 9223372036854775807:
    raise SystemExit("invalid automatic-tree removal deadline")
delay_phase = os.environ.get("BORONDNS_CAMPAIGN_MARK_REMOVING_DELAY_PHASE", "")
delay_until_text = os.environ.get("BORONDNS_CAMPAIGN_MARK_REMOVING_DELAY_UNTIL_NANOSECONDS", "")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid)


def process_starttime(pid):
    raw = open(f"/proc/{pid}/stat", encoding="ascii").read()
    fields = raw[raw.rfind(")") + 2:].split()
    if fields[0] in {"Z", "X"}:
        return None
    return int(fields[19])


def boottime_now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def check_deadline():
    if boottime_now() >= absolute_deadline:
        raise RuntimeError("automatic-tree removal journal deadline expired")


def test_delay(point):
    if delay_phase != point:
        return
    if not re.fullmatch(r"[1-9][0-9]*", delay_until_text):
        raise RuntimeError("invalid automatic-tree removal test delay")
    delay_until = int(delay_until_text)
    if delay_until > 9223372036854775807:
        raise RuntimeError("invalid automatic-tree removal test delay")
    while boottime_now() < delay_until:
        time.sleep(max(0, min(0.01, (delay_until - boottime_now()) / 1_000_000_000)))


libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError as error:
    raise RuntimeError("renameat2 is required for automatic-tree removal") from error
renameat2.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
linkat = libc.linkat
linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
linkat.restype = ctypes.c_int


def rename_exchange(directory_fd, source, destination):
    if renameat2(
        directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), 2,
    ) != 0:  # RENAME_EXCHANGE
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    if identity(os.fstat(parent_fd)) != expected_parent:
        raise SystemExit("automatic-tree removal parent identity changed")
    tree = os.stat(tree_name, dir_fd=parent_fd, follow_symlinks=False)
    journal = os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False)
    if identity(tree) != expected_tree or not stat.S_ISDIR(tree.st_mode):
        raise SystemExit("automatic-tree removal target identity changed")
    if identity(journal) != expected_journal or not stat.S_ISREG(journal.st_mode) or journal.st_nlink != 1:
        raise SystemExit("automatic-tree removal journal identity changed")
    boot_id = open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) is None:
        raise SystemExit("cannot authenticate automatic-tree removal boot ID")
    if process_starttime(owner_pid) != owner_starttime:
        raise SystemExit("automatic-tree removal owner identity changed")
    quarantine = f".{tree_name}.borondns-remove.{owner_pid}.{secrets.token_hex(12)}"
    temporary = f".{journal_name}.removing.{secrets.token_hex(8)}"
    payload = "\n".join((
        "schema=3", "phase=removing", f"boot_id={boot_id}",
        f"owner_pid={owner_pid}", f"owner_starttime={owner_starttime}",
        f"parent_device={expected_parent[0]}", f"parent_inode={expected_parent[1]}",
        f"parent_owner={expected_parent[2]}", f"tree_name={tree_name}",
        f"tree_device={expected_tree[0]}", f"tree_inode={expected_tree[1]}",
        f"tree_owner={expected_tree[2]}", f"quarantine_name={quarantine}",
        f"cleanup_deadline_ns={absolute_deadline}", "",
    )).encode()
    test_delay("pre-stage")
    check_deadline()
    try:
        fd = os.open(".", os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    except OSError as error:
        raise RuntimeError("O_TMPFILE is required for exact removal-journal publication") from error
    try:
        staged = os.fstat(fd)
        staged_identity = identity(staged)
        check_deadline()
        view = memoryview(payload)
        while view:
            check_deadline()
            count = os.write(fd, view)
            if count <= 0:
                raise RuntimeError("automatic-tree removal journal write stalled")
            view = view[count:]
        check_deadline()
        os.fsync(fd)
        if identity(os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False)) != expected_journal:
            raise SystemExit("automatic-tree removal journal changed before publish")
        test_delay("pre-replace")
        check_deadline()
        if linkat(fd, b"", parent_fd, os.fsencode(temporary), 0x1000) != 0:  # AT_EMPTY_PATH
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), temporary)
        if identity(os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)) != staged_identity:
            raise RuntimeError("automatic-tree removal exact-fd link changed")
        rename_exchange(parent_fd, temporary, journal_name)
        if (
            identity(os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False))
            != staged_identity
            or identity(os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False))
            != expected_journal
        ):
            raise RuntimeError("automatic-tree removal journal changed during exchange")
        retained = f".{temporary}.retained.{secrets.token_hex(8)}"
        if renameat2(
            parent_fd, os.fsencode(temporary), parent_fd, os.fsencode(retained), 1,
        ) != 0:  # RENAME_NOREPLACE
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), temporary)
        os.fsync(parent_fd)
    finally:
        os.close(fd)
    current = os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False)
    print(f"{quarantine}\t{current.st_dev}\t{current.st_ino}\t{current.st_uid}")
finally:
    os.close(parent_fd)
PY
    )" || return 1
    IFS=$'\t' read -r quarantine journal_device journal_inode journal_owner extra <<<"$result"
    [[ "$quarantine" =~ ^\..+\.borondns-remove\.[0-9]+\.[0-9a-f]{24}$ && -z "$extra" &&
        "$journal_device" =~ ^[0-9]+$ && "$journal_inode" =~ ^[0-9]+$ && "$journal_owner" =~ ^[0-9]+$ ]] || return 1
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_device"]="$journal_device"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_inode"]="$journal_inode"
    CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_owner"]="$journal_owner"
    printf -v "$output_variable" '%s' "$quarantine"
}

# Private mktemp trees can fail before a campaign publication lock exists. The
# captured parent/tree identities still make their cleanup safe without a
# pathname-only rm -rf. This helper is deliberately limited to trees created by
# campaign_prepare_private_temporary_tree.
campaign_remove_private_temporary_tree() {
    local path="$1"
    local identity_prefix="$2"
    local label="$3"
    local absolute_deadline="${4:-}"
    local journal_path="${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_path"]:-}"
    local quarantine_name=""
    local mutation_deadline="$absolute_deadline"
    local lock_state_present=0
    local automatic_cleanup_timeout="${BORONDNS_CAMPAIGN_AUTOMATIC_TREE_CLEANUP_TIMEOUT_SECONDS:-30}"
    [[ "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:kind"]:-}" == tree ]] || return 1
    if [[ -n "${campaign_lock_pid:-}" || -n "${campaign_lock_control_fd:-}" ||
        -n "${campaign_lock_response_fd:-}" || -n "${campaign_lock_owner_pid:-}" ||
        -n "${campaign_lock_operation_deadline:-}" ||
        -n "${campaign_lock_cleanup_deadline:-}" ||
        -n "${campaign_lock_deadline_bounded:-}" ]]; then
        lock_state_present=1
    fi
    # This tree can exist before the caller's publication lock does. Acquire a
    # narrow lock rooted in the automatic-tree family so the ordinary
    # identity-bound removal path retains its mutation-boundary guarantees.
    # Recursing once keeps all lock-present behavior on the single path below.
    if ((!lock_state_present)); then
        [[ "$automatic_cleanup_timeout" =~ ^[1-9][0-9]*$ ]] || {
            printf 'invalid automatic-tree cleanup timeout: %s\n' \
                "$automatic_cleanup_timeout" >&2
            return 1
        }
        local cleanup_deadline
        if [[ -z "$mutation_deadline" ]]; then
            mutation_deadline="$(campaign_deadline_from_timeout_seconds \
                "$automatic_cleanup_timeout")" || return 1
            cleanup_deadline=$((mutation_deadline + 2000000000))
        else
            cleanup_deadline="$mutation_deadline"
        fi
        campaign_acquire_private_lock "$(dirname "$path")" \
            "$path:automatic-cleanup" "$label cleanup" \
            "$mutation_deadline" "$cleanup_deadline" || return 1
        local cleanup_status=0
        campaign_remove_private_temporary_tree "$path" "$identity_prefix" \
            "$label" "$mutation_deadline" || cleanup_status=$?
        campaign_release_private_lock "$cleanup_deadline" || {
            ((cleanup_status != 0)) || cleanup_status=1
        }
        return "$cleanup_status"
    fi
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        # Absence is not proof of removal: the captured inode may have been
        # renamed away. Retain the identity journal and fail closed so callers
        # cannot publish success while the automatic tree still consumes disk.
        printf '%s pathname is missing; retaining its cleanup identity: %s\n' \
            "$label" "$path" >&2
        return 1
    fi
    # The ready journal is durable recovery state. Authenticate the cleanup
    # reserve before changing it to removing so an exhausted cleanup attempt is
    # byte-for-byte non-mutating and remains recoverable by a later owner.
    if [[ -z "$mutation_deadline" ]]; then
        if [[ "${campaign_lock_deadline_bounded:-}" == 1 ]]; then
            campaign_assert_private_lock || return 1
            mutation_deadline="${campaign_lock_operation_deadline:-}"
        else
            mutation_deadline="$(campaign_deadline_from_timeout_seconds \
                "${BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS:-5}")" || return 1
            mutation_deadline=$((mutation_deadline + 300000000))
            campaign_assert_private_lock "$mutation_deadline" "$mutation_deadline" || return 1
        fi
    else
        campaign_assert_private_lock "$mutation_deadline" "$mutation_deadline" || return 1
    fi
    absolute_deadline="$mutation_deadline"
    campaign_mark_automatic_tree_removing "$path" "$identity_prefix" quarantine_name \
        "$absolute_deadline" || {
        printf '%s could not publish its durable removing phase: %s\n' "$label" "$path" >&2
        return 1
    }
    campaign_identity_bound_remove tree "$(dirname "$path")" "$path" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_owner"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_owner"]}" \
        "$absolute_deadline" "$quarantine_name" || {
        printf '%s identity changed; retaining it: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ -n "$journal_path" ]] || {
        printf '%s persistent cleanup journal is missing from process state\n' "$label" >&2
        return 1
    }
    campaign_identity_bound_remove file "$(dirname "$journal_path")" "$journal_path" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_owner"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:journal_owner"]}" \
        "$absolute_deadline" || {
        printf '%s tree was removed but its persistent cleanup journal was retained: %s\n' \
            "$label" "$journal_path" >&2
        return 1
    }
    campaign_forget_cleanup_identity "$identity_prefix"
}

campaign_remove_captured_cleanup_object() {
    local path="$1"
    local identity_prefix="$2"
    local label="$3"
    [[ "$identity_prefix" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    [[ -e "$path" || -L "$path" ]] || return 0
    local kind="${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:kind"]:-}"
    [[ "$kind" == file || "$kind" == tree ]] || return 1
    campaign_assert_private_lock || return 1
    campaign_identity_bound_remove "$kind" "$(dirname "$path")" "$path" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:parent_owner"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_device"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_inode"]}" \
        "${CAMPAIGN_CLEANUP_IDENTITIES["$identity_prefix:target_owner"]}" || {
        printf '%s identity changed; retaining it: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_enumerate_direct_children_bounded() {
    local directory="$1" expected_device="$2" expected_inode="$3" expected_owner="$4"
    local prefix="$5" absolute_deadline="$6" output_variable="$7"
    [[ "$expected_device" =~ ^[0-9]+$ && "$expected_inode" =~ ^[0-9]+$ &&
        "$expected_owner" =~ ^[0-9]+$ && "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    case "$output_variable" in
    directory | expected_device | expected_inode | expected_owner | prefix | absolute_deadline | \
        output_variable | listing)
        return 1
        ;;
    esac
    local listing
    listing="$(
        python3 - "$directory" "$expected_device" "$expected_inode" "$expected_owner" \
            "$prefix" "$absolute_deadline" <<'PY'
import base64
import os
import stat
import sys
import time

directory, device, inode, owner, prefix, deadline_text = sys.argv[1:]
expected = (int(device), int(inode), int(owner))
deadline = int(deadline_text)
cap_text = os.environ.get("BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP", "4096")
if not cap_text.isdigit() or cap_text.startswith("0"):
    raise SystemExit("invalid campaign enumeration entry cap")
entry_cap = int(cap_text)
if not 1 <= entry_cap <= 65536:
    raise SystemExit("invalid campaign enumeration entry cap")


def check_deadline() -> None:
    if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= deadline:
        raise SystemExit("campaign directory enumeration deadline expired")


directory_fd = os.open(
    directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
)
try:
    opened = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino, opened.st_uid) != expected
    ):
        raise SystemExit("campaign enumeration directory identity changed")
    names = []
    count = 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            check_deadline()
            count += 1
            if count > entry_cap:
                raise SystemExit("campaign directory enumeration entry cap exceeded")
            if entry.name.startswith(prefix):
                names.append(entry.name)
    check_deadline()
    for name in sorted(names, key=os.fsencode):
        print(base64.b64encode(os.fsencode(name)).decode("ascii"))
finally:
    os.close(directory_fd)
PY
    )" || return 1
    printf -v "$output_variable" '%s' "$listing"
}

campaign_atomic_replace_text() {
    local destination="$1"
    local content="$2"
    local label="$3"
    local parent staged owner stale parent_identity parent_device parent_inode parent_owner
    local stale_identity stale_device stale_inode stale_owner stale_remainder
    local staged_sha256 staged_device staged_inode staged_size
    local destination_state=absent destination_device=0 destination_inode=0
    local enumeration_deadline stale_listing="" stale_encoded stale_name
    parent="$(dirname "$destination")"
    campaign_require_owned_real_directory "$parent" "$label parent" || return 1
    parent_identity="$(stat -c '%d:%i:%u' "$parent")" || return 1
    parent_device="${parent_identity%%:*}"
    parent_identity="${parent_identity#*:}"
    parent_inode="${parent_identity%%:*}"
    parent_owner="${parent_identity##*:}"
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] || return 1
        owner="$(stat -c %u "$destination")" || return 1
        [[ "$owner" == "$(id -u)" ]] || return 1
        [[ "$(stat -c %h "$destination")" == 1 ]] || return 1
        destination_state="file"
        destination_device="$(stat -c %d "$destination")" || return 1
        destination_inode="$(stat -c %i "$destination")" || return 1
    fi
    if [[ "${campaign_lock_deadline_bounded:-0}" == 1 ]]; then
        enumeration_deadline="${campaign_lock_operation_deadline:-}"
        campaign_is_positive_signed_64 "$enumeration_deadline" || return 1
    else
        enumeration_deadline="$(campaign_deadline_from_timeout_seconds \
            "${BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS:-5}")" || return 1
        enumeration_deadline=$((enumeration_deadline + 300000000))
    fi
    campaign_enumerate_direct_children_bounded "$parent" "$parent_device" "$parent_inode" \
        "$parent_owner" ".${destination##*/}.borondns-staged." \
        "$enumeration_deadline" stale_listing || return 1
    while IFS= read -r stale_encoded; do
        [[ -n "$stale_encoded" ]] || continue
        stale_name="$(printf '%s' "$stale_encoded" | base64 --decode 2>/dev/null)" || return 1
        stale="$parent/$stale_name"
        [[ -f "$stale" && ! -L "$stale" && "$(stat -c %u "$stale")" == "$(id -u)" ]] || {
            return 1
        }
        stale_identity="$(stat -c '%d:%i:%u' "$stale")" || {
            return 1
        }
        stale_device="${stale_identity%%:*}"
        stale_remainder="${stale_identity#*:}"
        stale_inode="${stale_remainder%%:*}"
        stale_owner="${stale_remainder##*:}"
        if declare -F campaign_atomic_replace_text_hook >/dev/null 2>&1; then
            campaign_atomic_replace_text_hook before-stale-delete "$stale" "$destination" || {
                return 1
            }
        fi
        campaign_assert_private_lock || {
            return 1
        }
        campaign_identity_bound_unlink_file "$parent" "$stale" "$parent_device" "$parent_inode" \
            "$stale_device" "$stale_inode" "$stale_owner" || {
            return 1
        }
    done <<<"$stale_listing"
    campaign_assert_private_lock || return 1
    staged="$(mktemp "$parent/.${destination##*/}.borondns-staged.XXXXXX")" || return 1
    if ! printf '%s\n' "$content" >"$staged"; then
        campaign_assert_private_lock && rm -f -- "$staged"
        return 1
    fi
    sync -f "$staged" 2>/dev/null || true
    campaign_capture_candidate_identity "$staged" staged || return 1
    staged_size="$(stat -c %s "$staged")" || return 1
    ((staged_size <= 16 * 1024 * 1024)) || return 1
    if declare -F campaign_atomic_replace_text_hook >/dev/null 2>&1; then
        campaign_atomic_replace_text_hook before-final-rename "$staged" "$destination" || return 1
    fi
    campaign_assert_private_lock || return 1
    campaign_identity_bound_replace_text "$parent" "$staged" "$destination" \
        "$parent_device" "$parent_inode" "$staged_sha256" "$staged_device" "$staged_inode" \
        "$staged_size" "$destination_state" "$destination_device" "$destination_inode" || return 1
}

campaign_capture_candidate_identity() {
    local candidate="$1"
    local output_prefix="$2"
    [[ "$output_prefix" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    [[ -f "$candidate" && ! -L "$candidate" && "$(stat -c %u "$candidate")" == "$(id -u)" &&
    "$(stat -c %h "$candidate")" == 1 ]] || return 1
    local before after digest
    before="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$candidate")" || return 1
    digest="$(campaign_sha256 "$candidate")" || return 1
    after="$(stat -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$candidate")" || return 1
    [[ "$before" == "$after" ]] || {
        printf 'campaign candidate changed while its identity was captured: %s\n' "$candidate" >&2
        return 1
    }
    printf -v "${output_prefix}_sha256" '%s' "$digest"
    printf -v "${output_prefix}_device" '%s' "${before%%:*}"
    local remainder="${before#*:}"
    printf -v "${output_prefix}_inode" '%s' "${remainder%%:*}"
}

campaign_candidate_identity_matches() {
    local candidate="$1"
    local expected_sha256="$2"
    local expected_device="$3"
    local expected_inode="$4"
    [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ && "$expected_device" =~ ^[0-9]+$ && "$expected_inode" =~ ^[0-9]+$ ]] || return 1
    [[ -f "$candidate" && ! -L "$candidate" && "$(stat -c %u "$candidate")" == "$(id -u)" &&
    "$(stat -c %h "$candidate")" == 1 && "$(stat -c %d "$candidate")" == "$expected_device" &&
    "$(stat -c %i "$candidate")" == "$expected_inode" ]] || return 1
    [[ "$(campaign_sha256 "$candidate")" == "$expected_sha256" ]]
}

campaign_validate_systemd_fragment_schema() {
    local fragment="$1"
    local expected_runner="$2"
    [[ -f "$fragment" && ! -L "$fragment" ]] || return 1
    local section="" line key value
    local -A seen=()
    local after="" wants="" limit="" supplementary="" runtime_max="" timeout_stop=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
        '[Unit]')
            [[ -z "$section" ]] || return 1
            section=Unit
            ;;
        '[Service]')
            [[ "$section" == Unit ]] || return 1
            section=Service
            ;;
        '[Install]')
            [[ "$section" == Service ]] || return 1
            section=Install
            ;;
        '') ;;
        *)
            [[ "$line" == *=* ]] || return 1
            key="${line%%=*}"
            value="${line#*=}"
            case "$section:$key" in
            Unit:Description)
                [[ -n "$value" && "$value" != *$'\t'* ]] || return 1
                ;;
            Unit:After)
                [[ "$value" == network-online.target || "$value" == 'network-online.target docker.service' ]] || return 1
                after="$value"
                ;;
            Unit:Wants)
                [[ "$value" == network-online.target || "$value" == 'network-online.target docker.service' ]] || return 1
                wants="$value"
                ;;
            Service:Type) [[ "$value" == simple ]] || return 1 ;;
            Service:User)
                [[ "$value" =~ ^[a-z_][a-z0-9_-]*$ && "$value" != root ]] || return 1
                ;;
            Service:WorkingDirectory) [[ "$value" =~ ^/[A-Za-z0-9_./@:+-]+$ && "$value" != *'/../'* && "$value" != */.. ]] || return 1 ;;
            Service:Environment)
                case "$value" in
                'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin') key=Environment_PATH ;;
                CARGO_HOME=/*)
                    [[ "${value#CARGO_HOME=}" =~ ^/[A-Za-z0-9_./@:+-]+$ && "$value" != *'/../'* && "$value" != */.. ]] || return 1
                    key=Environment_CARGO_HOME
                    ;;
                RUSTUP_HOME=/*)
                    [[ "${value#RUSTUP_HOME=}" =~ ^/[A-Za-z0-9_./@:+-]+$ && "$value" != *'/../'* && "$value" != */.. ]] || return 1
                    key=Environment_RUSTUP_HOME
                    ;;
                'CARGO_BUILD_JOBS=1') key=Environment_CARGO_BUILD_JOBS ;;
                *) return 1 ;;
                esac
                ;;
            Service:SupplementaryGroups)
                [[ "$value" == docker ]] || return 1
                supplementary="$value"
                ;;
            Service:LimitNOFILE)
                [[ "$value" == 65536 || "$value" == 1048576 ]] || return 1
                limit="$value"
                ;;
            Service:ExecStart) [[ "$value" == "$expected_runner" ]] || return 1 ;;
            Service:Restart) [[ "$value" == no ]] || return 1 ;;
            Service:StandardOutput) [[ "$value" == journal ]] || return 1 ;;
            Service:StandardError) [[ "$value" == journal ]] || return 1 ;;
            Service:SyslogIdentifier) [[ "$value" =~ ^[A-Za-z0-9_.@-]+$ ]] || return 1 ;;
            Service:KillMode) [[ "$value" == control-group ]] || return 1 ;;
            Service:RuntimeMaxSec)
                [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
                ((${#value} < 19 || ${#value} == 19 && value <= 9223372036854775807)) || return 1
                runtime_max="$value"
                ;;
            Service:TimeoutStopSec)
                [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
                ((${#value} < 19 || ${#value} == 19 && value <= 9223372036854775807)) || return 1
                timeout_stop="$value"
                ;;
            Install:WantedBy) [[ "$value" == multi-user.target ]] || return 1 ;;
            *) return 1 ;;
            esac
            [[ -z "${seen["$section:$key"]:-}" ]] || return 1
            seen["$section:$key"]=1
            ;;
        esac
    done <"$fragment"
    [[ "$section" == Install && "$after" == "$wants" ]] || return 1
    local required
    for required in Unit:Description Unit:After Unit:Wants Service:Type Service:User Service:WorkingDirectory \
        Service:Environment_PATH Service:LimitNOFILE Service:ExecStart Service:Restart Service:StandardOutput \
        Service:StandardError Service:SyslogIdentifier Service:KillMode Install:WantedBy; do
        [[ -n "${seen["$required"]:-}" ]] || return 1
    done
    if [[ "$limit" == 1048576 ]]; then
        [[ "$after" == 'network-online.target docker.service' && "$supplementary" == docker &&
            -n "${seen["Service:Environment_CARGO_HOME"]:-}" && -n "${seen["Service:Environment_RUSTUP_HOME"]:-}" ]] || return 1
    else
        [[ "$after" == network-online.target && -z "$supplementary" ]] || return 1
        if [[ -n "${seen["Service:Environment_CARGO_HOME"]:-}" ]]; then
            [[ -n "${seen["Service:Environment_RUSTUP_HOME"]:-}" ]] || return 1
        else
            [[ -z "${seen["Service:Environment_RUSTUP_HOME"]:-}" ]] || return 1
        fi
    fi
    [[ -z "$runtime_max" && -z "$timeout_stop" || -n "$runtime_max" && -n "$timeout_stop" ]] || return 1
    [[ -z "$runtime_max" ]] || ((timeout_stop <= runtime_max))
}

campaign_privileged_publish_bound_file() {
    local root="$1" destination="$2" staged="$3" expected_sha256="$4" expected_mode="$5"
    local expected_staged_size="$6"
    local expected_root_device="$7" expected_root_inode="$8" expected_root_owner="$9"
    local expected_destination_state="${10}" expected_destination_device="${11}" expected_destination_inode="${12}"
    sudo python3 - "$root" "${destination##*/}" "${staged##*/}" "$expected_sha256" \
        "$expected_mode" "$expected_staged_size" \
        "$expected_root_device" "$expected_root_inode" "$expected_root_owner" \
        "$expected_destination_state" "$expected_destination_device" "$expected_destination_inode" <<'PY'
import ctypes
import hashlib
import os
import secrets
import stat
import sys

(
    root, destination, staged, expected_sha256, expected_mode, expected_staged_size,
    root_device, root_inode, root_owner, destination_state,
    destination_device, destination_inode,
) = sys.argv[1:]
if any(not name or name in {".", ".."} or "/" in name for name in (destination, staged)):
    raise SystemExit("invalid privileged publication basename")
if destination_state not in {"absent", "file"}:
    raise SystemExit("invalid privileged publication destination state")
expected_root = (int(root_device), int(root_inode), int(root_owner))
expected_destination = (int(destination_device), int(destination_inode))
expected_mode = int(expected_mode, 8)
expected_staged_size = int(expected_staged_size)
if not 0 <= expected_staged_size <= 16 * 1024 * 1024:
    raise SystemExit("privileged publication staging size is outside the supported bound")
libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError as error:
    raise SystemExit("renameat2 is required for privileged publication") from error
renameat2.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
bound = f".{destination}.borondns-bound.{os.getpid()}.{secrets.token_hex(12)}"
bound_contains_staged = False
try:
    root_info = os.fstat(directory_fd)
    if (root_info.st_dev, root_info.st_ino, root_info.st_uid) != expected_root:
        raise SystemExit("privileged publication root identity changed")
    staged_fd = os.open(
        staged,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        staged_info = os.fstat(staged_fd)
        named_staged = os.stat(staged, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(staged_info.st_mode)
            or staged_info.st_uid != 0
            or staged_info.st_nlink != 1
            or stat.S_IMODE(staged_info.st_mode) != expected_mode
            or staged_info.st_size != expected_staged_size
            or (staged_info.st_dev, staged_info.st_ino)
            != (named_staged.st_dev, named_staged.st_ino)
        ):
            raise SystemExit("privileged publication staging identity changed")
        if renameat2(
            directory_fd, os.fsencode(staged), directory_fd, os.fsencode(bound), 1,
        ) != 0:  # RENAME_NOREPLACE
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), bound)
        bound_contains_staged = True
        named_bound = os.stat(bound, dir_fd=directory_fd, follow_symlinks=False)
        if (named_bound.st_dev, named_bound.st_ino) != (staged_info.st_dev, staged_info.st_ino):
            raise SystemExit("privileged publication bound staging identity changed")
        read_snapshot = os.fstat(staged_fd)
        if (
            read_snapshot.st_nlink != 1
            or read_snapshot.st_size != expected_staged_size
            or (read_snapshot.st_dev, read_snapshot.st_ino)
            != (staged_info.st_dev, staged_info.st_ino)
        ):
            raise SystemExit("privileged publication bound staging changed before reading")
        digest = hashlib.sha256()
        remaining = expected_staged_size
        while remaining:
            chunk = os.read(staged_fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise SystemExit("privileged publication staging was truncated while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(staged_fd, 1):
            raise SystemExit("privileged publication staging grew while reading")
        current_staged = os.fstat(staged_fd)
        if (
            current_staged.st_size != read_snapshot.st_size
            or current_staged.st_mtime_ns != read_snapshot.st_mtime_ns
            or current_staged.st_ctime_ns != read_snapshot.st_ctime_ns
            or current_staged.st_nlink != 1
        ):
            raise SystemExit("privileged publication staging changed while reading")
        if digest.hexdigest() != expected_sha256:
            raise SystemExit("privileged publication staging bytes changed")
        flags = 1 if destination_state == "absent" else 2
        if renameat2(
            directory_fd, os.fsencode(bound), directory_fd, os.fsencode(destination), flags,
        ) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), destination)
        published = os.stat(destination, dir_fd=directory_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != (staged_info.st_dev, staged_info.st_ino):
            raise SystemExit("privileged publication destination changed during commit")
        bound_contains_staged = False
        if destination_state == "file":
            displaced = os.stat(bound, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(displaced.st_mode)
                or displaced.st_nlink != 1
                or (displaced.st_dev, displaced.st_ino) != expected_destination
            ):
                raise SystemExit("privileged publication displaced destination changed")
            os.unlink(bound, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(staged_fd)
finally:
    if bound_contains_staged:
        try:
            retained = os.stat(bound, dir_fd=directory_fd, follow_symlinks=False)
            if (retained.st_dev, retained.st_ino) == (staged_info.st_dev, staged_info.st_ino):
                if renameat2(
                    directory_fd, os.fsencode(bound), directory_fd, os.fsencode(staged), 1,
                ) == 0:  # RENAME_NOREPLACE
                    bound_contains_staged = False
        except (FileNotFoundError, NameError):
            pass
    os.close(directory_fd)
PY
}

campaign_publish_systemd_fragment() {
    local unit_root="$1"
    local destination="$2"
    local candidate="$3"
    local expected_runner="$4"
    local expected_sha256="$5"
    local expected_device="$6"
    local expected_inode="$7"
    local label="$8"
    campaign_assert_private_lock || return 1
    campaign_require_real_directory "$unit_root" "$label unit root" || return 1
    [[ "$(dirname "$destination")" == "$unit_root" && "$(basename "$destination")" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || {
        printf '%s destination is not a direct systemd service fragment: %s\n' "$label" "$destination" >&2
        return 1
    }
    campaign_candidate_identity_matches "$candidate" "$expected_sha256" "$expected_device" "$expected_inode" || {
        printf '%s candidate identity no longer matches its precommitment\n' "$label" >&2
        return 1
    }
    campaign_validate_systemd_fragment_schema "$candidate" "$expected_runner" || {
        printf '%s candidate is not an exact supported systemd service schema\n' "$label" >&2
        return 1
    }
    campaign_remove_systemd_fragment_staging "$unit_root" "$destination" "$label" || return 1
    campaign_candidate_identity_matches "$candidate" "$expected_sha256" "$expected_device" "$expected_inode" || return 1
    if declare -F campaign_privileged_publication_hook >/dev/null 2>&1; then
        campaign_privileged_publication_hook before-fragment-copy "$candidate" "$destination" || return 1
    fi
    local root_identity root_remainder destination_state=absent destination_device=0 destination_inode=0
    root_identity="$(stat -c '%d:%i:%u' "$unit_root")" || return 1
    root_remainder="${root_identity#*:}"
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" && "$(stat -c %h "$destination")" == 1 ]] || return 1
        local destination_identity destination_remainder
        destination_identity="$(stat -c '%d:%i' "$destination")" || return 1
        destination_remainder="${destination_identity#*:}"
        destination_state="file"
        destination_device="${destination_identity%%:*}"
        destination_inode="$destination_remainder"
    fi
    local staged staged_size
    staged="$(sudo mktemp "$unit_root/.$(basename "$destination").borondns-staged.XXXXXX")" || return 1
    if ! sudo install -m 0644 -o root -g root -- "$candidate" "$staged" ||
        [[ "$(campaign_sha256 "$staged")" != "$expected_sha256" ]] ||
        ! campaign_validate_systemd_fragment_schema "$staged" "$expected_runner"; then
        sudo rm -f -- "$staged" || true
        return 1
    fi
    staged_size="$(stat -c %s "$staged")" || return 1
    ((staged_size <= 16 * 1024 * 1024)) || return 1
    campaign_assert_private_lock || {
        sudo rm -f -- "$staged" || true
        return 1
    }
    if declare -F campaign_privileged_publication_hook >/dev/null 2>&1; then
        campaign_privileged_publication_hook before-fragment-commit "$staged" "$destination" || return 1
    fi
    if ! campaign_privileged_publish_bound_file "$unit_root" "$destination" "$staged" \
        "$expected_sha256" 0644 "$staged_size" "${root_identity%%:*}" "${root_remainder%%:*}" \
        "${root_identity##*:}" "$destination_state" "$destination_device" "$destination_inode"; then
        return 1
    fi
    [[ "$(campaign_sha256 "$destination")" == "$expected_sha256" ]] || return 1
}

campaign_publish_root_runner() {
    local unit="$1"
    local candidate="$2"
    local expected_sha256="$3"
    local expected_device="$4"
    local expected_inode="$5"
    local label="$6"
    campaign_assert_private_lock || return 1
    [[ "$unit" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || return 1
    campaign_candidate_identity_matches "$candidate" "$expected_sha256" "$expected_device" "$expected_inode" || return 1
    local runner_root=/var/tmp/borondns-campaign-runners
    local unit_root="$runner_root/${unit%.service}"
    campaign_prepare_root_runner_tree "$runner_root" "$unit_root" "$label" || return 1
    local runner_dir runner identity_candidate
    runner_dir="$(sudo mktemp -d "$unit_root/attempt.XXXXXX")" || return 1
    runner="$runner_dir/run.sh"
    identity_candidate="$(mktemp)" || {
        sudo rm -rf -- "$runner_dir" || true
        return 1
    }
    campaign_candidate_identity_matches "$candidate" "$expected_sha256" "$expected_device" "$expected_inode" || {
        sudo rm -rf -- "$runner_dir" || true
        return 1
    }
    if declare -F campaign_privileged_publication_hook >/dev/null 2>&1; then
        campaign_privileged_publication_hook before-runner-copy "$candidate" "$runner" || {
            sudo rm -rf -- "$runner_dir" || true
            return 1
        }
    fi
    if ! sudo install -m 0555 -o root -g root -- "$candidate" "$runner" ||
        ! sudo chmod 0555 -- "$runner_dir" || [[ "$(campaign_sha256 "$runner")" != "$expected_sha256" ]]; then
        rm -f "$identity_candidate"
        sudo rm -rf -- "$runner_dir" || true
        return 1
    fi
    {
        printf 'path=%s\n' "$runner"
        printf 'sha256=%s\n' "$expected_sha256"
        printf 'device=%s\n' "$(stat -c %d "$runner")"
        printf 'inode=%s\n' "$(stat -c %i "$runner")"
    } >"$identity_candidate"
    if ! sudo install -m 0444 -o root -g root -- "$identity_candidate" "$runner.identity"; then
        rm -f "$identity_candidate"
        sudo rm -rf -- "$runner_dir" || true
        return 1
    fi
    rm -f "$identity_candidate"
    campaign_assert_private_lock || {
        sudo rm -rf -- "$runner_dir" || true
        return 1
    }
    campaign_validate_root_runner "$runner" "$unit_root/attempt." || {
        sudo rm -rf -- "$runner_dir" || true
        return 1
    }
    # shellcheck disable=SC2034 # output variable consumed by callers after publication
    campaign_published_runner="$runner"
}

campaign_validate_root_runner_directory() {
    local path="$1"
    local label="$2"
    [[ -d "$path" && ! -L "$path" ]] || {
        printf '%s is not a real privileged runner directory: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ "$(realpath -ms "$path")" == "$(realpath -e "$path")" ]] || {
        printf '%s traverses a symlink: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ "$(stat -c '%u:%g:%a' "$path")" == 0:0:755 ]] || {
        printf '%s must be root:root mode 0755: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_prepare_root_runner_tree() {
    local runner_root="$1"
    local unit_root="$2"
    local label="$3"
    local runner_parent
    runner_parent="$(dirname "$runner_root")"
    [[ "$runner_root" == "$runner_parent"/* && "$(dirname "$unit_root")" == "$runner_root" ]] || return 1
    [[ "$(basename "$runner_root")" == borondns-campaign-runners ]] || return 1
    [[ "$(basename "$unit_root")" =~ ^[A-Za-z0-9_.@-]+$ ]] || return 1
    [[ -d "$runner_parent" && ! -L "$runner_parent" && "$(realpath -ms "$runner_parent")" == "$(realpath -e "$runner_parent")" ]] || return 1
    [[ "$(stat -c %u "$runner_parent")" == 0 ]] || return 1

    local protected_root protected_label
    for protected_root in "$runner_root" "$unit_root"; do
        protected_label="$label privileged runner directory"
        if [[ -e "$protected_root" || -L "$protected_root" ]]; then
            campaign_validate_root_runner_directory "$protected_root" "$protected_label" || return 1
        else
            campaign_assert_private_lock || return 1
            # mkdir without -p is the privileged no-follow creation primitive:
            # an attacker-created final-component symlink makes it fail with
            # EEXIST rather than being followed and chmod/chown'd.
            if ! sudo mkdir -m 0755 -- "$protected_root"; then
                campaign_validate_root_runner_directory "$protected_root" "$protected_label" || return 1
            fi
            campaign_validate_root_runner_directory "$protected_root" "$protected_label" || return 1
        fi
    done
}

campaign_validate_root_runner() {
    local runner="$1"
    local expected_prefix="$2"
    [[ "$runner" == "$expected_prefix"*/run.sh && -f "$runner" && ! -L "$runner" ]] || return 1
    [[ "$(realpath -ms "$runner")" == "$(realpath -e "$runner")" ]] || return 1
    [[ "$(stat -c %u "$runner")" == 0 && "$(stat -c %a "$runner")" == 555 && "$(stat -c %h "$runner")" == 1 ]] || return 1
    local parent identity
    parent="$(dirname "$runner")"
    identity="$runner.identity"
    [[ -d "$parent" && ! -L "$parent" && "$(stat -c %u "$parent")" == 0 && "$(stat -c %a "$parent")" == 555 ]] || return 1
    [[ -f "$identity" && ! -L "$identity" && "$(stat -c %u "$identity")" == 0 && "$(stat -c %a "$identity")" == 444 && "$(stat -c %h "$identity")" == 1 ]] || return 1
    local -a lines=()
    mapfile -t lines <"$identity" || return 1
    ((${#lines[@]} == 4)) || return 1
    [[ "${lines[0]}" == "path=$runner" ]] || return 1
    [[ "${lines[1]}" == "sha256=$(campaign_sha256 "$runner")" ]] || return 1
    [[ "${lines[2]}" == "device=$(stat -c %d "$runner")" ]] || return 1
    [[ "${lines[3]}" == "inode=$(stat -c %i "$runner")" ]] || return 1
}

campaign_publish_root_bound_file() {
    local runner="$1"
    local candidate="$2"
    local basename="$3"
    local expected_sha256="$4"
    local expected_device="$5"
    local expected_inode="$6"
    local label="$7"
    campaign_assert_private_lock || return 1
    [[ "$basename" =~ ^[A-Za-z0-9_.-]+$ && "$basename" != run.sh && "$basename" != *.identity ]] || return 1
    local unit_root
    unit_root="$(dirname "$(dirname "$runner")")"
    campaign_validate_root_runner "$runner" "$unit_root/attempt." || return 1
    campaign_candidate_identity_matches "$candidate" "$expected_sha256" "$expected_device" "$expected_inode" || return 1
    local parent destination identity_candidate
    parent="$(dirname "$runner")"
    destination="$parent/$basename"
    [[ ! -e "$destination" && ! -L "$destination" && ! -e "$destination.identity" && ! -L "$destination.identity" ]] || return 1
    if declare -F campaign_privileged_publication_hook >/dev/null 2>&1; then
        campaign_privileged_publication_hook before-bound-file-copy "$candidate" "$destination" || return 1
    fi
    if ! sudo install -m 0444 -o root -g root -- "$candidate" "$destination" ||
        [[ "$(campaign_sha256 "$destination")" != "$expected_sha256" ]]; then
        sudo rm -f -- "$destination" || true
        return 1
    fi
    identity_candidate="$(mktemp)" || {
        sudo rm -f -- "$destination" || true
        return 1
    }
    {
        printf 'path=%s\n' "$destination"
        printf 'sha256=%s\n' "$expected_sha256"
        printf 'device=%s\n' "$(stat -c %d "$destination")"
        printf 'inode=%s\n' "$(stat -c %i "$destination")"
    } >"$identity_candidate"
    if ! sudo install -m 0444 -o root -g root -- "$identity_candidate" "$destination.identity"; then
        rm -f -- "$identity_candidate"
        sudo rm -f -- "$destination" "$destination.identity" || true
        return 1
    fi
    rm -f -- "$identity_candidate"
    campaign_assert_private_lock || {
        sudo rm -f -- "$destination" "$destination.identity" || true
        return 1
    }
    campaign_validate_root_bound_file "$destination" "$expected_sha256" || {
        sudo rm -f -- "$destination" "$destination.identity" || true
        return 1
    }
    # shellcheck disable=SC2034 # output variable consumed by callers
    campaign_published_bound_file="$destination"
}

campaign_validate_root_bound_file() {
    local path="$1"
    local expected_sha256="${2:-}"
    [[ -f "$path" && ! -L "$path" && "$(stat -c %u "$path")" == 0 &&
    "$(stat -c %a "$path")" == 444 && "$(stat -c %h "$path")" == 1 ]] || return 1
    [[ "$(realpath -ms "$path")" == "$(realpath -e "$path")" ]] || return 1
    local identity="$path.identity"
    [[ -f "$identity" && ! -L "$identity" && "$(stat -c %u "$identity")" == 0 &&
    "$(stat -c %a "$identity")" == 444 && "$(stat -c %h "$identity")" == 1 ]] || return 1
    local digest
    digest="$(campaign_sha256 "$path")" || return 1
    [[ -z "$expected_sha256" || "$digest" == "$expected_sha256" ]] || return 1
    local -a lines=()
    mapfile -t lines <"$identity" || return 1
    ((${#lines[@]} == 4)) || return 1
    [[ "${lines[0]}" == "path=$path" && "${lines[1]}" == "sha256=$digest" &&
        "${lines[2]}" == "device=$(stat -c %d "$path")" && "${lines[3]}" == "inode=$(stat -c %i "$path")" ]]
}

campaign_validate_systemd_fragment_runner() {
    local fragment="$1"
    local expected_prefix="$2"
    [[ -f "$fragment" && ! -L "$fragment" && "$(stat -c %u "$fragment")" == 0 ]] || return 1
    [[ "$(stat -c %a "$fragment")" == 644 && "$(stat -c %h "$fragment")" == 1 ]] || return 1
    local runner
    runner="$(sed -n 's/^ExecStart=//p' "$fragment")"
    [[ "$(grep -c '^ExecStart=' "$fragment")" == 1 ]] || return 1
    campaign_validate_systemd_fragment_schema "$fragment" "$runner" || return 1
    campaign_validate_root_runner "$runner" "$expected_prefix" || return 1
    printf '%s\n' "$runner"
}

campaign_remove_root_runner_tree() {
    local unit="$1"
    local label="$2"
    campaign_assert_private_lock || return 1
    [[ "$unit" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || return 1
    local unit_root="/var/tmp/borondns-campaign-runners/${unit%.service}"
    local unit_parent
    unit_parent="$(dirname "$unit_root")"
    [[ -e "$unit_root" || -L "$unit_root" ]] || return 0
    [[ -d "$unit_root" && ! -L "$unit_root" && "$(stat -c %u "$unit_root")" == 0 ]] || return 1
    [[ -d "$unit_parent" && ! -L "$unit_parent" && "$(stat -c %u "$unit_parent")" == 0 ]] || return 1
    [[ "$(realpath -ms "$unit_root")" == "$(realpath -e "$unit_root")" && -z "$(find "$unit_root" -type l -print -quit)" ]] || return 1
    while IFS= read -r -d '' runner; do
        campaign_validate_root_runner "$runner" "$unit_root/attempt." || {
            printf '%s runner tree contains an invalid runner: %s\n' "$label" "$runner" >&2
            return 1
        }
    done < <(find "$unit_root" -mindepth 2 -maxdepth 2 -type f -name run.sh -print0)
    local parent_identity parent_device parent_inode parent_owner
    local tree_identity tree_device tree_inode tree_owner
    parent_identity="$(stat -c '%d:%i:%u' "$unit_parent")" || return 1
    parent_device="${parent_identity%%:*}"
    parent_identity="${parent_identity#*:}"
    parent_inode="${parent_identity%%:*}"
    parent_owner="${parent_identity##*:}"
    tree_identity="$(stat -c '%d:%i:%u' "$unit_root")" || return 1
    tree_device="${tree_identity%%:*}"
    tree_identity="${tree_identity#*:}"
    tree_inode="${tree_identity%%:*}"
    tree_owner="${tree_identity##*:}"
    if declare -F campaign_privileged_cleanup_hook >/dev/null 2>&1; then
        campaign_privileged_cleanup_hook before-runner-tree-remove "$unit_root" || return 1
    fi
    campaign_assert_private_lock || return 1
    campaign_privileged_identity_bound_remove tree "$unit_parent" "$unit_root" \
        "$parent_device" "$parent_inode" "$parent_owner" \
        "$tree_device" "$tree_inode" "$tree_owner"
}

campaign_remove_systemd_fragment_staging() {
    local unit_root="$1"
    local destination="$2"
    local label="$3"
    campaign_assert_private_lock || return 1
    campaign_require_real_directory "$unit_root" "$label unit root" || return 1
    [[ "$(dirname "$destination")" == "$unit_root" ]] || return 1
    local path owner identity remainder enumeration_deadline staged_listing="" staged_encoded staged_name
    local -a staged=()
    local -a staged_devices=() staged_inodes=() staged_owners=()
    local parent_identity parent_device parent_inode parent_owner
    parent_identity="$(stat -c '%d:%i:%u' "$unit_root")" || return 1
    parent_device="${parent_identity%%:*}"
    parent_identity="${parent_identity#*:}"
    parent_inode="${parent_identity%%:*}"
    parent_owner="${parent_identity##*:}"
    if [[ "${campaign_lock_deadline_bounded:-0}" == 1 ]]; then
        enumeration_deadline="${campaign_lock_operation_deadline:-}"
        campaign_is_positive_signed_64 "$enumeration_deadline" || return 1
    else
        enumeration_deadline="$(campaign_deadline_from_timeout_seconds \
            "${BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS:-5}")" || return 1
        enumeration_deadline=$((enumeration_deadline + 300000000))
    fi
    campaign_enumerate_direct_children_bounded "$unit_root" "$parent_device" "$parent_inode" \
        "$parent_owner" ".$(basename "$destination").borondns-staged." \
        "$enumeration_deadline" staged_listing || return 1
    while IFS= read -r staged_encoded; do
        [[ -n "$staged_encoded" ]] || continue
        staged_name="$(printf '%s' "$staged_encoded" | base64 --decode 2>/dev/null)" || return 1
        path="$unit_root/$staged_name"
        [[ -f "$path" && ! -L "$path" ]] || {
            printf '%s staged fragment is unsafe: %s\n' "$label" "$path" >&2
            return 1
        }
        owner="$(stat -c %u "$path")" || return 1
        [[ "$owner" == 0 && "$(stat -c %h "$path")" == 1 ]] || return 1
        identity="$(stat -c '%d:%i:%u' "$path")" || return 1
        staged_devices+=("${identity%%:*}")
        remainder="${identity#*:}"
        staged_inodes+=("${remainder%%:*}")
        staged_owners+=("${remainder##*:}")
        staged+=("$path")
    done <<<"$staged_listing"
    if ((${#staged[@]} > 0)); then
        if declare -F campaign_privileged_cleanup_hook >/dev/null 2>&1; then
            campaign_privileged_cleanup_hook before-fragment-staging-remove "${staged[@]}" || return 1
        fi
        campaign_assert_private_lock || return 1
        local index
        for index in "${!staged[@]}"; do
            campaign_privileged_identity_bound_remove file "$unit_root" "${staged[$index]}" \
                "$parent_device" "$parent_inode" "$parent_owner" \
                "${staged_devices[$index]}" "${staged_inodes[$index]}" "${staged_owners[$index]}" || return 1
        done
    fi
}

campaign_systemd_query_state() {
    local query="$1"
    local service="$2"
    local value status=0
    value="$(timeout --preserve-status --kill-after=5 30 systemctl "$query" "$service" 2>/dev/null)" || status=$?
    value="${value%%$'\n'*}"
    [[ -n "$value" && "$value" != *$'\t'* && "$value" != *' '* ]] || {
        printf 'could not classify systemd %s state for %s (status=%s)\n' "$query" "$service" "$status" >&2
        return 1
    }
    case "$query:$value" in
    is-enabled:enabled | is-enabled:enabled-runtime | is-enabled:disabled | is-enabled:static | \
        is-enabled:indirect | is-enabled:alias | is-enabled:generated | is-enabled:masked | \
        is-enabled:masked-runtime | is-enabled:not-found) ;;
    is-active:active | is-active:inactive) ;;
    *)
        printf 'unsupported systemd %s state for %s: %s\n' "$query" "$service" "$value" >&2
        return 1
        ;;
    esac
    printf '%s\n' "$value"
}

campaign_capture_prerequisite_service_state() {
    local service enabled active
    printf 'service_state_version=1\n'
    for service in docker named bind9; do
        enabled="$(campaign_systemd_query_state is-enabled "$service")" || return 1
        active="$(campaign_systemd_query_state is-active "$service")" || return 1
        printf '%s_enabled=%s\n%s_active=%s\n' "$service" "$enabled" "$service" "$active"
    done
}

campaign_load_prerequisite_service_state() {
    local path="$1"
    [[ -f "$path" && ! -L "$path" && "$(stat -c %u "$path")" == 0 && "$(stat -c %a "$path")" == 444 &&
    "$(stat -c %h "$path")" == 1 ]] || return 1
    campaign_validate_prerequisite_service_state_schema "$path" || return 1
    campaign_decode_prerequisite_service_state "$path"
}

campaign_validate_prerequisite_service_state_schema() {
    local path="$1"
    [[ -f "$path" && ! -L "$path" ]] || return 1
    local -a lines=()
    mapfile -t lines <"$path" || return 1
    ((${#lines[@]} == 7)) || return 1
    [[ "${lines[0]}" == service_state_version=1 ]] || return 1
    local service index enabled active
    index=1
    for service in docker named bind9; do
        [[ "${lines[$index]}" == "${service}_enabled="* ]] || return 1
        enabled="${lines[$index]#*=}"
        index=$((index + 1))
        [[ "${lines[$index]}" == "${service}_active="* ]] || return 1
        active="${lines[$index]#*=}"
        index=$((index + 1))
        case "$enabled" in
        enabled | enabled-runtime | disabled | static | indirect | alias | generated | masked | masked-runtime | not-found) ;;
        *) return 1 ;;
        esac
        [[ "$active" == active || "$active" == inactive ]] || return 1
    done
}

campaign_decode_prerequisite_service_state() {
    local path="$1"
    local -a lines=()
    mapfile -t lines <"$path" || return 1
    local service index enabled active
    index=1
    for service in docker named bind9; do
        enabled="${lines[$index]#*=}"
        index=$((index + 1))
        active="${lines[$index]#*=}"
        index=$((index + 1))
        printf -v "campaign_prior_${service}_enabled" '%s' "$enabled"
        printf -v "campaign_prior_${service}_active" '%s' "$active"
    done
}

campaign_restore_prerequisite_service_state() {
    local path="$1"
    campaign_load_prerequisite_service_state "$path" || return 1
    local service enabled active actual_enabled actual_active enabled_variable active_variable
    for service in docker named bind9; do
        enabled_variable="campaign_prior_${service}_enabled"
        active_variable="campaign_prior_${service}_active"
        enabled="${!enabled_variable}"
        active="${!active_variable}"
        case "$enabled" in
        masked)
            timeout --preserve-status --kill-after=10 120 sudo systemctl disable --now "$service" >/dev/null 2>&1 || true
            timeout --preserve-status --kill-after=10 120 sudo systemctl mask "$service" >/dev/null
            ;;
        masked-runtime)
            timeout --preserve-status --kill-after=10 120 sudo systemctl disable --now "$service" >/dev/null 2>&1 || true
            timeout --preserve-status --kill-after=10 120 sudo systemctl mask --runtime "$service" >/dev/null
            ;;
        *)
            timeout --preserve-status --kill-after=10 120 sudo systemctl unmask "$service" >/dev/null 2>&1 || true
            case "$enabled" in
            enabled) timeout --preserve-status --kill-after=10 120 sudo systemctl enable "$service" >/dev/null ;;
            enabled-runtime) timeout --preserve-status --kill-after=10 120 sudo systemctl enable --runtime "$service" >/dev/null ;;
            disabled | not-found) timeout --preserve-status --kill-after=10 120 sudo systemctl disable "$service" >/dev/null 2>&1 || true ;;
            static | indirect | alias | generated) ;;
            esac
            ;;
        esac
        if [[ "$active" == active ]]; then
            timeout --preserve-status --kill-after=10 120 sudo systemctl start "$service" >/dev/null
        else
            timeout --preserve-status --kill-after=10 120 sudo systemctl stop "$service" >/dev/null 2>&1 || true
        fi
    done
    for service in docker named bind9; do
        enabled_variable="campaign_prior_${service}_enabled"
        active_variable="campaign_prior_${service}_active"
        enabled="${!enabled_variable}"
        active="${!active_variable}"
        actual_enabled="$(campaign_systemd_query_state is-enabled "$service")" || return 1
        actual_active="$(campaign_systemd_query_state is-active "$service")" || return 1
        if [[ "$enabled" == not-found ]]; then
            [[ "$actual_enabled" == disabled || "$actual_enabled" == not-found || "$actual_enabled" == static ||
                "$actual_enabled" == indirect || "$actual_enabled" == alias ]] || return 1
        else
            [[ "$actual_enabled" == "$enabled" ]] || return 1
        fi
        [[ "$actual_active" == "$active" ]] || return 1
    done
}

campaign_publish_root_atomic_text() {
    local root="$1"
    local destination="$2"
    local content="$3"
    local label="$4"
    local schema="${5:-opaque}"
    campaign_assert_private_lock || return 1
    [[ -d "$root" && ! -L "$root" && "$(stat -c %u "$root")" == 0 ]] || return 1
    [[ "$(realpath -ms "$root")" == "$(realpath -e "$root")" && "$(dirname "$destination")" == "$root" ]] || return 1
    [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
    local expected_sha256 candidate staged staged_size root_identity root_remainder
    root_identity="$(stat -c '%d:%i:%u' "$root")" || return 1
    root_remainder="${root_identity#*:}"
    expected_sha256="$(printf '%s\n' "$content" | sha256sum | awk '{ print $1 }')" || return 1
    [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    candidate="$(mktemp)" || return 1
    if ! printf '%s\n' "$content" >"$candidate" || ! sync -f "$candidate" 2>/dev/null; then
        rm -f -- "$candidate"
        return 1
    fi
    local candidate_sha256="" candidate_device="" candidate_inode=""
    campaign_capture_candidate_identity "$candidate" candidate || {
        rm -f -- "$candidate"
        return 1
    }
    [[ "$candidate_sha256" == "$expected_sha256" ]] || {
        rm -f -- "$candidate"
        return 1
    }
    case "$schema" in
    opaque) ;;
    prerequisite-service-state)
        campaign_validate_prerequisite_service_state_schema "$candidate" || {
            rm -f -- "$candidate"
            return 1
        }
        ;;
    restored-marker)
        [[ "$(<"$candidate")" == restored ]] || {
            rm -f -- "$candidate"
            return 1
        }
        ;;
    *)
        rm -f -- "$candidate"
        return 1
        ;;
    esac
    if declare -F campaign_root_atomic_text_hook >/dev/null 2>&1; then
        campaign_root_atomic_text_hook before-candidate-copy "$candidate" "$destination" || {
            rm -f -- "$candidate"
            return 1
        }
    fi
    campaign_candidate_identity_matches "$candidate" "$expected_sha256" "$candidate_device" "$candidate_inode" || {
        rm -f -- "$candidate"
        return 1
    }
    staged="$(sudo mktemp "$root/.$(basename "$destination").borondns-staged.XXXXXX")" || {
        rm -f -- "$candidate"
        return 1
    }
    if ! sudo install -m 0444 -o root -g root -- "$candidate" "$staged" ||
        [[ "$(campaign_sha256 "$staged")" != "$expected_sha256" ]]; then
        rm -f -- "$candidate"
        campaign_assert_private_lock && sudo rm -f -- "$staged"
        return 1
    fi
    staged_size="$(stat -c %s "$staged")" || return 1
    ((staged_size <= 16 * 1024 * 1024)) || return 1
    case "$schema" in
    prerequisite-service-state)
        campaign_validate_prerequisite_service_state_schema "$staged" || {
            rm -f -- "$candidate"
            campaign_assert_private_lock && sudo rm -f -- "$staged"
            return 1
        }
        ;;
    restored-marker)
        [[ "$(<"$staged")" == restored ]] || {
            rm -f -- "$candidate"
            campaign_assert_private_lock && sudo rm -f -- "$staged"
            return 1
        }
        ;;
    esac
    rm -f -- "$candidate"
    if declare -F campaign_root_atomic_text_hook >/dev/null 2>&1; then
        campaign_root_atomic_text_hook before-final-rename "$staged" "$destination" || return 1
    fi
    campaign_assert_private_lock || return 1
    campaign_privileged_publish_bound_file "$root" "$destination" "$staged" \
        "$expected_sha256" 0444 "$staged_size" "${root_identity%%:*}" "${root_remainder%%:*}" \
        "${root_identity##*:}" absent 0 0 || return 1
    [[ -f "$destination" && ! -L "$destination" && "$(stat -c %u "$destination")" == 0 &&
    "$(stat -c %a "$destination")" == 444 && "$(stat -c %h "$destination")" == 1 ]] || {
        printf '%s publication validation failed: %s\n' "$label" "$destination" >&2
        return 1
    }
    [[ "$(campaign_sha256 "$destination")" == "$expected_sha256" ]] || return 1
    case "$schema" in
    prerequisite-service-state) campaign_validate_prerequisite_service_state_schema "$destination" || return 1 ;;
    restored-marker) [[ "$(<"$destination")" == restored ]] || return 1 ;;
    esac
}

campaign_manifest_write() {
    local root="$1"
    local manifest="$root/campaign-manifest.sha256"
    local staged path relative digest
    staged="$(mktemp "$root/.campaign-manifest.XXXXXX")" || return 1
    while IFS= read -r -d '' path; do
        relative="${path#"$root"/}"
        [[ "$relative" != campaign-manifest.sha256 && "$relative" != .campaign-manifest.* ]] || continue
        if [[ -L "$path" ]]; then
            printf 'campaign manifest refuses symlink plan entry: %s\n' "$path" >&2
            rm -f "$staged"
            return 1
        fi
        if [[ -d "$path" ]]; then
            [[ "$relative" == commands || "$relative" == remotes || "$relative" == remotes/* ]] || {
                printf 'campaign manifest refuses unknown plan directory: %s\n' "$path" >&2
                rm -f "$staged"
                return 1
            }
            continue
        fi
        [[ -f "$path" ]] || {
            printf 'campaign manifest refuses special plan entry: %s\n' "$path" >&2
            rm -f "$staged"
            return 1
        }
        case "$relative" in
        README.md | assignments.tsv | campaign.env | collect-command.txt | host-samplers.tsv | plan-complete | status-command.txt | validate-collected-campaign.py | commands/*.sh) ;;
        *)
            printf 'campaign manifest refuses unknown plan file: %s\n' "$path" >&2
            rm -f "$staged"
            return 1
            ;;
        esac
        digest="$(campaign_sha256 "$path")" || {
            rm -f "$staged"
            return 1
        }
        printf '%s  %s\n' "$digest" "$relative" >>"$staged"
    done < <(find "$root" -mindepth 1 -print0 | sort -z)
    [[ -s "$staged" ]] || {
        printf 'campaign manifest would be empty: %s\n' "$root" >&2
        rm -f "$staged"
        return 1
    }
    mv "$staged" "$manifest"
}

campaign_manifest_verify() {
    local root="$1"
    local manifest="$root/campaign-manifest.sha256"
    [[ -f "$manifest" && ! -L "$manifest" ]] || {
        printf 'missing canonical campaign manifest: %s\n' "$manifest" >&2
        return 1
    }
    local line_number=0 line digest relative actual previous="" count=0
    local -A authenticated=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        [[ "$line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9_.@/+:-]+)$ ]] || {
            printf 'malformed canonical campaign manifest at %s:%s\n' "$manifest" "$line_number" >&2
            return 1
        }
        digest="${BASH_REMATCH[1]}"
        relative="${BASH_REMATCH[2]}"
        [[ "$relative" != /* && "$relative" != *..* && "$relative" != campaign-manifest.sha256 ]] || {
            printf 'unsafe canonical campaign manifest path at %s:%s: %s\n' "$manifest" "$line_number" "$relative" >&2
            return 1
        }
        [[ -z "$previous" || "$relative" > "$previous" ]] || {
            printf 'non-canonical or duplicate campaign manifest ordering at %s:%s\n' "$manifest" "$line_number" >&2
            return 1
        }
        [[ -f "$root/$relative" && ! -L "$root/$relative" ]] || {
            printf 'campaign manifest entry is missing or not regular: %s\n' "$root/$relative" >&2
            return 1
        }
        actual="$(campaign_sha256 "$root/$relative")" || return 1
        [[ "$actual" == "$digest" ]] || {
            printf 'campaign manifest digest mismatch: %s\n' "$root/$relative" >&2
            return 1
        }
        authenticated[$relative]=1
        previous="$relative"
        count=$((count + 1))
    done <"$manifest"
    ((count > 0)) || {
        printf 'empty canonical campaign manifest: %s\n' "$manifest" >&2
        return 1
    }
    local path
    while IFS= read -r -d '' path; do
        relative="${path#"$root"/}"
        [[ "$relative" != campaign-manifest.sha256 ]] || continue
        if [[ -L "$path" ]]; then
            printf 'canonical campaign tree contains a symlink: %s\n' "$path" >&2
            return 1
        fi
        if [[ -d "$path" ]]; then
            [[ "$relative" == commands || "$relative" == remotes || "$relative" == remotes/* ]] || {
                printf 'canonical campaign tree contains an unknown directory: %s\n' "$path" >&2
                return 1
            }
            continue
        fi
        [[ -f "$path" ]] || {
            printf 'canonical campaign tree contains a special node: %s\n' "$path" >&2
            return 1
        }
        if [[ "$relative" == remotes/* ]]; then
            continue
        fi
        case "$relative" in
        README.md | assignments.tsv | campaign.env | collect-command.txt | host-samplers.tsv | plan-complete | status-command.txt | validate-collected-campaign.py | commands/*.sh) ;;
        *)
            printf 'canonical campaign tree contains an unknown file: %s\n' "$path" >&2
            return 1
            ;;
        esac
        [[ -n "${authenticated[$relative]:-}" ]] || {
            printf 'unauthenticated campaign plan file: %s\n' "$path" >&2
            return 1
        }
    done < <(find "$root" -mindepth 1 -print0 | sort -z)
}

campaign_validate_tsv() {
    local path="$1"
    local expected_header="$2"
    local expected_columns="$3"
    [[ -f "$path" && ! -L "$path" ]] || {
        printf 'missing regular campaign TSV: %s\n' "$path" >&2
        return 1
    }
    local header fields row_count=0
    IFS= read -r header <"$path" || true
    [[ "$header" == "$expected_header" ]] || {
        printf 'invalid campaign TSV header: %s\n' "$path" >&2
        return 1
    }
    while IFS= read -r fields || [[ -n "$fields" ]]; do
        [[ -n "$fields" && "$fields" != *$'\r'* ]] || {
            printf 'blank or malformed campaign TSV row: %s\n' "$path" >&2
            return 1
        }
        [[ "$(awk -F '\t' '{ print NF }' <<<"$fields")" == "$expected_columns" ]] || {
            printf 'invalid campaign TSV column count: %s\n' "$path" >&2
            return 1
        }
        row_count=$((row_count + 1))
    done < <(tail -n +2 "$path")
    ((row_count > 0)) || {
        printf 'campaign TSV has no assignment rows: %s\n' "$path" >&2
        return 1
    }
}

campaign_require_real_directory() {
    local path="$1"
    local label="$2"
    [[ -d "$path" && ! -L "$path" ]] || {
        printf '%s must be a real directory, not a symlink: %s\n' "$label" "$path" >&2
        return 1
    }
    local lexical real
    lexical="$(realpath -ms "$path")" || return 1
    real="$(realpath -e "$path")" || return 1
    [[ "$real" == "$lexical" ]] || {
        printf '%s path traverses a symlink: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_require_owned_real_directory() {
    local path="$1"
    local label="$2"
    campaign_require_real_directory "$path" "$label" || return 1
    local lexical real owner
    lexical="$(realpath -ms "$path")" || return 1
    real="$(realpath -e "$path")" || return 1
    [[ "$real" == "$lexical" ]] || {
        printf '%s path traverses a symlink: %s\n' "$label" "$path" >&2
        return 1
    }
    owner="$(stat -c %u "$real")" || return 1
    [[ "$owner" == "$(id -u)" ]] || {
        printf '%s is not owned by the campaign user: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_require_contained_file() {
    local root="$1"
    local path="$2"
    local label="$3"
    campaign_require_real_directory "$root" "$label parent" || return 1
    [[ -f "$path" && ! -L "$path" ]] || {
        printf '%s must be a regular non-symlink file: %s\n' "$label" "$path" >&2
        return 1
    }
    local root_real path_real path_lexical
    root_real="$(realpath -e "$root")" || return 1
    path_real="$(realpath -e "$path")" || return 1
    path_lexical="$(realpath -ms "$path")" || return 1
    [[ "$path_real" == "$path_lexical" ]] || {
        printf '%s path traverses a symlink: %s\n' "$label" "$path" >&2
        return 1
    }
    [[ "$path_real" == "$root_real"/* ]] || {
        printf '%s escapes its campaign directory: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_require_owned_nonwritable_plan_tree() {
    local root="$1"
    local label="$2"
    campaign_require_owned_real_directory "$root" "$label" || return 1
    local root_real path path_real path_lexical owner mode relative
    root_real="$(realpath -e "$root")" || return 1
    mode="$(stat -c %a "$root_real")" || return 1
    (((8#$mode & 022) == 0)) || {
        printf '%s root is group/world-writable: %s\n' "$label" "$root" >&2
        return 1
    }
    while IFS= read -r -d '' path; do
        relative="${path#"$root"/}"
        # Collected remote evidence is deliberately mutable and is not part of
        # the executable plan. The manifest verifier separately excludes it
        # from authenticated plan inputs.
        [[ "$relative" != remotes && "$relative" != remotes/* ]] || continue
        [[ ! -L "$path" && (-f "$path" || -d "$path") ]] || {
            printf '%s contains an unsafe node: %s\n' "$label" "$path" >&2
            return 1
        }
        path_real="$(realpath -e "$path")" || return 1
        path_lexical="$(realpath -ms "$path")" || return 1
        [[ "$path_real" == "$path_lexical" && "$path_real" == "$root_real"/* ]] || {
            printf '%s contains a symlink-traversing or escaping path: %s\n' "$label" "$path" >&2
            return 1
        }
        owner="$(stat -c %u "$path_real")" || return 1
        mode="$(stat -c %a "$path_real")" || return 1
        [[ "$owner" == "$(id -u)" ]] || {
            printf '%s contains a path not owned by the campaign user: %s\n' "$label" "$path" >&2
            return 1
        }
        (((8#$mode & 022) == 0)) || {
            printf '%s contains a group/world-writable path: %s\n' "$label" "$path" >&2
            return 1
        }
    done < <(find "$root" -mindepth 1 -print0 | sort -z)
}

campaign_clear_owned_directory() {
    local path="$1"
    local label="$2"
    campaign_require_owned_real_directory "$path" "$label" || return 1
    campaign_assert_private_lock || return 1
    local child identity remainder target_remainder target_kind parent_identity
    parent_identity="$(stat -c '%d:%i:%u' "$path")" || return 1
    while IFS= read -r -d '' child; do
        [[ "$(dirname "$child")" == "$path" && "$(basename "$child")" != . &&
        "$(basename "$child")" != .. ]] || return 1
        if [[ -L "$child" ]]; then
            target_kind="leaf"
        elif [[ -d "$child" ]]; then
            target_kind="tree"
        elif [[ -f "$child" ]]; then
            target_kind="file"
        else
            printf '%s contains an unsafe cleanup node: %s\n' "$label" "$child" >&2
            return 1
        fi
        identity="$(stat -c '%d:%i:%u' "$child")" || return 1
        if declare -F campaign_identity_bound_remove_hook >/dev/null 2>&1; then
            campaign_identity_bound_remove_hook before-remove "$child" "$label" || return 1
        fi
        campaign_assert_private_lock || return 1
        remainder="${parent_identity#*:}"
        target_remainder="${identity#*:}"
        campaign_identity_bound_remove "$target_kind" "$path" "$child" \
            "${parent_identity%%:*}" "${remainder%%:*}" "${parent_identity##*:}" \
            "${identity%%:*}" "${target_remainder%%:*}" "${identity##*:}" || return 1
    done < <(find "$path" -mindepth 1 -maxdepth 1 -print0)
}

campaign_prepare_contained_directory() {
    local root="$1"
    local path="$2"
    local label="$3"
    campaign_require_owned_real_directory "$root" "$label root" || return 1
    if [[ -e "$path" || -L "$path" ]]; then
        campaign_require_owned_real_directory "$path" "$label" || return 1
    else
        mkdir "$path" || return 1
        campaign_require_owned_real_directory "$path" "$label" || return 1
    fi
    local root_real path_real
    root_real="$(realpath -e "$root")" || return 1
    path_real="$(realpath -e "$path")" || return 1
    [[ "$path_real" == "$root_real"/* ]] || {
        printf '%s escapes its campaign root: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_prepare_owned_fresh_directory() {
    local root="$1"
    local path="$2"
    local label="$3"
    campaign_prepare_contained_directory "$root" "$path" "$label" || return 1
    [[ -z "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
        printf '%s must be empty before first write: %s\n' "$label" "$path" >&2
        return 1
    }
}

campaign_require_bounded_positive_integer() {
    local name="$1" value="$2" maximum="$3"
    local LC_ALL=C
    [[ "$value" =~ ^[1-9][0-9]*$ && "$maximum" =~ ^[1-9][0-9]*$ ]] || return 1
    if ((${#value} > ${#maximum})) ||
        { ((${#value} == ${#maximum})) && [[ "$value" > "$maximum" ]]; }; then
        printf 'campaign %s exceeds supported maximum %s: %s\n' "$name" "$maximum" "$value" >&2
        return 1
    fi
}

campaign_prepare_collection_budget() {
    local output_variable="$1"
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_variable" in
    output_variable | timeout_seconds | computed_deadline | \
        campaign_collection_max_entries | campaign_collection_max_depth | \
        campaign_collection_max_file_bytes | campaign_collection_max_total_bytes)
        return 1
        ;;
    esac
    local timeout_seconds="${BORONDNS_CAMPAIGN_COLLECTION_TIMEOUT_SECONDS:-10800}"
    campaign_collection_max_entries="${BORONDNS_CAMPAIGN_COLLECTION_MAX_ENTRIES:-100000}"
    campaign_collection_max_depth="${BORONDNS_CAMPAIGN_COLLECTION_MAX_DEPTH:-64}"
    campaign_collection_max_file_bytes="${BORONDNS_CAMPAIGN_COLLECTION_MAX_FILE_BYTES:-2147483648}"
    campaign_collection_max_total_bytes="${BORONDNS_CAMPAIGN_COLLECTION_MAX_TOTAL_BYTES:-68719476736}"
    campaign_require_bounded_positive_integer collection-timeout-seconds "$timeout_seconds" 86400 || return 1
    campaign_require_bounded_positive_integer collection-entry-cap "$campaign_collection_max_entries" 1000000 || return 1
    campaign_require_bounded_positive_integer collection-depth-cap "$campaign_collection_max_depth" 128 || return 1
    campaign_require_bounded_positive_integer collection-per-file-byte-cap "$campaign_collection_max_file_bytes" 17179869184 || return 1
    campaign_require_bounded_positive_integer collection-total-byte-cap "$campaign_collection_max_total_bytes" 1099511627776 || return 1
    ((campaign_collection_max_file_bytes <= campaign_collection_max_total_bytes)) || return 1
    local computed_deadline
    computed_deadline="$(campaign_deadline_from_timeout_seconds "$timeout_seconds")" || return 1
    printf -v "$output_variable" '%s' "$computed_deadline"
}

campaign_collection_phase_timeout_seconds() {
    local output_variable="$1" absolute_deadline="$2" configured_maximum="$3"
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_variable" in
    output_variable | absolute_deadline | configured_maximum | remaining | whole | fraction)
        return 1
        ;;
    esac
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    campaign_require_bounded_positive_integer collection-phase-timeout "$configured_maximum" 86400 || return 1
    local remaining whole fraction
    remaining="$(campaign_deadline_remaining_seconds "$absolute_deadline" "$configured_maximum")" || return 1
    whole="${remaining%%.*}"
    fraction="${remaining#*.}"
    if [[ "$fraction" != 000000000 ]]; then
        whole=$((whole + 1))
    fi
    ((whole > 0)) || whole=1
    ((whole <= configured_maximum)) || whole="$configured_maximum"
    printf -v "$output_variable" '%s' "$whole"
}

campaign_local_tree_snapshot() {
    local root="$1"
    local absolute_deadline="$2"
    local validator="$3"
    campaign_require_owned_real_directory "$root" "local collection snapshot root" || return 1
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    [[ -f "$validator" && ! -L "$validator" ]] || return 1
    local snapshot=""
    campaign_run_before_deadline_capture snapshot "$absolute_deadline" \
        python3 "$validator" tree-snapshot "$root" \
        --absolute-deadline-nanoseconds "$absolute_deadline" \
        --max-entries "$campaign_collection_max_entries" \
        --max-depth "$campaign_collection_max_depth" \
        --max-file-bytes "$campaign_collection_max_file_bytes" \
        --max-total-bytes "$campaign_collection_max_total_bytes" || return 1
    [[ "$snapshot" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$snapshot"
}

campaign_collection_generation_matches() {
    local root="$1" expected_snapshot="$2" absolute_deadline="$3" validator="$4"
    [[ "$expected_snapshot" =~ ^[0-9a-f]{64}$ ]] || return 1
    local observed_snapshot=""
    observed_snapshot="$(campaign_local_tree_snapshot "$root" "$absolute_deadline" "$validator")" || return 1
    [[ "$observed_snapshot" == "$expected_snapshot" ]]
}

campaign_collection_read_bounded_file() {
    local path="$1" absolute_deadline="$2" maximum_bytes="$3"
    local digest_variable="$4" content_variable="$5" device_variable="$6"
    local inode_variable="$7" size_variable="$8"
    [[ "$digest_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
        "$content_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
        "$device_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
        "$inode_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
        "$size_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    campaign_require_bounded_positive_integer collection-metadata-bytes \
        "$maximum_bytes" 16777216 || return 1
    case " $digest_variable $content_variable $device_variable $inode_variable $size_variable " in
    *" path "* | *" absolute_deadline "* | *" maximum_bytes "* | *" result "* | \
        *" digest "* | *" encoded "* | *" device "* | *" inode "* | *" size "* | *" extra "*)
        return 1
        ;;
    esac
    local result="" digest encoded device inode size extra
    campaign_run_before_deadline_capture result "$absolute_deadline" \
        python3 - "$path" "$absolute_deadline" "$maximum_bytes" <<'PY' || return 1
import base64
import hashlib
import os
import stat
import sys
import time

path, deadline_text, maximum_text = sys.argv[1:]
deadline = int(deadline_text)
maximum = int(maximum_text)
if deadline <= time.clock_gettime_ns(time.CLOCK_BOOTTIME):
    raise SystemExit("collection metadata deadline is exhausted")
if not 1 <= maximum <= 16 * 1024 * 1024:
    raise SystemExit("collection metadata byte cap is invalid")


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def check_deadline():
    if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= deadline:
        raise SystemExit("collection metadata deadline expired")


check_deadline()
descriptor = os.open(
    path,
    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
)
try:
    opened = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    expected = identity(opened)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_uid != os.getuid()
        or opened.st_nlink != 1
        or identity(named) != expected
        or opened.st_size > maximum
    ):
        raise SystemExit("collection metadata file is unsafe or oversized")
    test_marker = os.environ.get(
        "BORONDNS_CAMPAIGN_COLLECTION_METADATA_TEST_MARKER", ""
    )
    test_continue = os.environ.get(
        "BORONDNS_CAMPAIGN_COLLECTION_METADATA_TEST_CONTINUE", ""
    )
    if bool(test_marker) != bool(test_continue):
        raise SystemExit("collection metadata test hook is incomplete")
    if test_marker:
        with open(test_marker, "x", encoding="ascii") as marker_output:
            marker_output.write(f"{os.getpid()}\n")
            marker_output.flush()
            os.fsync(marker_output.fileno())
        while not os.path.exists(test_continue):
            check_deadline()
            time.sleep(0.01)
    payload = bytearray()
    while True:
        check_deadline()
        chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > maximum:
            raise SystemExit("collection metadata file grew beyond its byte cap")
    check_deadline()
    held_after = os.fstat(descriptor)
    named_after = os.stat(path, follow_symlinks=False)
    if (
        identity(held_after) != expected
        or identity(named_after) != expected
        or len(payload) != expected[6]
    ):
        raise SystemExit("collection metadata identity or content changed while read")
    if b"\0" in payload:
        raise SystemExit("collection metadata contains a NUL byte")
    print(
        "\t".join(
            (
                hashlib.sha256(payload).hexdigest(),
                str(opened.st_dev),
                str(opened.st_ino),
                str(opened.st_size),
                base64.b64encode(payload).decode("ascii"),
            )
        )
    )
finally:
    os.close(descriptor)
PY
    IFS=$'\t' read -r digest device inode size encoded extra <<<"$result" || return 1
    [[ "$digest" =~ ^[0-9a-f]{64}$ && "$device" =~ ^[0-9]+$ &&
        "$inode" =~ ^[0-9]+$ && "$size" =~ ^[0-9]+$ &&
        "$encoded" =~ ^[A-Za-z0-9+/]*={0,2}$ && -z "$extra" ]] || return 1
    printf -v "$digest_variable" '%s' "$digest"
    printf -v "$content_variable" '%s' "$encoded"
    printf -v "$device_variable" '%s' "$device"
    printf -v "$inode_variable" '%s' "$inode"
    printf -v "$size_variable" '%s' "$size"
}

# The separately promoted status commit binds the exact status bytes and the
# validator-approved evidence digest.  Its hashes detect independent drift, but
# the explicit unprivileged scheme is not an authenticity claim: a hostile
# process with the campaign UID can rewrite all three user-owned objects.
campaign_collection_status_commit_text() {
    local status_file="$1" evidence_snapshot="$2" absolute_deadline="${3:-}"
    [[ "$evidence_snapshot" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ -n "$absolute_deadline" ]] ||
        absolute_deadline="$(campaign_deadline_from_timeout_seconds 5)" || return 1
    local status_sha256 status_content status_device status_inode status_size
    campaign_collection_read_bounded_file "$status_file" "$absolute_deadline" 8388608 \
        status_sha256 status_content status_device status_inode status_size || return 1
    : "$status_content" "$status_device" "$status_inode" "$status_size"
    [[ "$status_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf 'collection-status-commit-v1\tunprivileged-sha256\t%s\t%s\n' \
        "$evidence_snapshot" "$status_sha256"
}

campaign_collection_status_accepts_generation() {
    local evidence="$1" status_file="$2" absolute_deadline="$3" validator="$4"
    local commit_file="$status_file.commit"
    local observed_commit_sha256 observed_commit_content commit_device commit_inode commit_size
    campaign_collection_read_bounded_file "$commit_file" "$absolute_deadline" 1024 \
        observed_commit_sha256 observed_commit_content commit_device commit_inode commit_size || return 1
    local commit_text
    commit_text="$(printf '%s' "$observed_commit_content" | base64 --decode 2>/dev/null)" || return 1
    [[ -n "$commit_text" && "$commit_text" != *$'\n'* ]] || return 1
    local commit_version commit_scheme commit_snapshot commit_status_sha256 commit_extra
    IFS=$'\t' read -r commit_version commit_scheme commit_snapshot commit_status_sha256 commit_extra \
        <<<"$commit_text" || return 1
    [[ "$commit_version" == collection-status-commit-v1 &&
        "$commit_scheme" == unprivileged-sha256 &&
        "$commit_snapshot" =~ ^[0-9a-f]{64}$ &&
        "$commit_status_sha256" =~ ^[0-9a-f]{64}$ && -z "$commit_extra" ]] || return 1
    local observed_status_sha256 observed_status_content status_device status_inode status_size
    campaign_collection_read_bounded_file "$status_file" "$absolute_deadline" 8388608 \
        observed_status_sha256 observed_status_content status_device status_inode status_size || return 1
    [[ "$observed_status_sha256" == "$commit_status_sha256" ]] || return 1
    local status_text
    status_text="$(printf '%s' "$observed_status_content" | base64 --decode 2>/dev/null)" || return 1
    local kind host source classification expected_snapshot extra
    IFS=$'\t' read -r kind host source classification expected_snapshot extra <<<"$status_text" || return 1
    [[ "$kind" == collection && -n "$host" && "$source" == remote-snapshot &&
        ("$classification" == complete || "$classification" == incomplete) &&
        "$expected_snapshot" == "$commit_snapshot" && -z "$extra" ]] || return 1
    campaign_collection_generation_matches "$evidence" "$commit_snapshot" \
        "$absolute_deadline" "$validator" || return 1
    local final_status_sha256 final_status_content final_status_device final_status_inode final_status_size
    local final_commit_sha256 final_commit_content final_commit_device final_commit_inode final_commit_size
    campaign_collection_read_bounded_file "$status_file" "$absolute_deadline" 8388608 \
        final_status_sha256 final_status_content final_status_device final_status_inode \
        final_status_size || return 1
    campaign_collection_read_bounded_file "$commit_file" "$absolute_deadline" 1024 \
        final_commit_sha256 final_commit_content final_commit_device final_commit_inode \
        final_commit_size || return 1
    [[ "$final_status_sha256" == "$observed_status_sha256" &&
        "$final_status_content" == "$observed_status_content" &&
        "$final_status_device:$final_status_inode:$final_status_size" == "$status_device:$status_inode:$status_size" &&
        "$final_commit_sha256" == "$observed_commit_sha256" &&
        "$final_commit_content" == "$observed_commit_content" &&
        "$final_commit_device:$final_commit_inode:$final_commit_size" == "$commit_device:$commit_inode:$commit_size" ]]
}

campaign_remote_tree_snapshot() {
    local host="$1"
    local root="$2"
    local absolute_deadline="$3"
    local snapshot operation_timeout
    campaign_collection_phase_timeout_seconds operation_timeout "$absolute_deadline" \
        "${BORONDNS_CAMPAIGN_REMOTE_SNAPSHOT_TIMEOUT_SECONDS:-1800}" || return 1
    snapshot="$(
        BORONDNS_CAMPAIGN_ACTIVE_ABSOLUTE_DEADLINE="$absolute_deadline" \
            campaign_ssh_bounded "$operation_timeout" \
            -- "$host" bash -s -- "$root" <<'REMOTE'
set -euo pipefail
root="$1"
[[ -d "$root" && ! -L "$root" ]] || { printf 'unsafe remote collection root: %s\n' "$root" >&2; exit 1; }
lexical="$(realpath -ms "$root")"
real="$(realpath -e "$root")"
[[ "$lexical" == "$real" ]] || { printf 'remote collection root traverses a symlink: %s\n' "$root" >&2; exit 1; }
(
	set -o pipefail
	while IFS= read -r -d '' path; do
		relative="${path#"$root"/}"
		if [[ -L "$path" ]]; then
			printf 'unsafe remote collection symlink: %s\n' "$path" >&2
			exit 1
		elif [[ -d "$path" ]]; then
			printf 'd\0%s\0' "$relative"
		elif [[ -f "$path" ]]; then
			digest="$(sha256sum "$path" | awk '{ print $1 }')"
			printf 'f\0%s\0%s\0' "$relative" "$digest"
		else
			printf 'unsafe remote collection special node: %s\n' "$path" >&2
			exit 1
		fi
	done < <(find "$root" -mindepth 1 -print0 | sort -z)
) | sha256sum | awk '{ print $1 }'
REMOTE
    )" || return 1
    [[ "$snapshot" =~ ^[0-9a-f]{64}$ ]] || {
        printf 'invalid remote collection snapshot for %s:%s\n' "$host" "$root" >&2
        return 1
    }
    printf '%s\n' "$snapshot"
}

campaign_publish_validated_collection() {
    local root="$1"
    local staging="$2"
    local destination="$3"
    local label="$4"
    local backup=""
    local root_real staging_real destination_parent_real
    campaign_require_owned_real_directory "$root" "$label root" || return 1
    campaign_require_owned_real_directory "$staging" "$label staging" || return 1
    root_real="$(realpath -e "$root")" || return 1
    staging_real="$(realpath -e "$staging")" || return 1
    destination_parent_real="$(realpath -e "$(dirname "$destination")")" || return 1
    [[ "$staging_real" == "$root_real"/* && "$destination_parent_real" == "$root_real" ]] || {
        printf '%s publication paths escape their collection root\n' "$label" >&2
        return 1
    }
    if [[ -e "$destination" || -L "$destination" ]]; then
        campaign_require_owned_real_directory "$destination" "$label destination" || return 1
        backup="$(mktemp -d "$root/.collection-backup.XXXXXX")" || return 1
        rmdir "$backup" || return 1
        mv "$destination" "$backup" || return 1
    fi
    if ! mv "$staging" "$destination"; then
        if [[ -n "$backup" ]]; then
            mv "$backup" "$destination" ||
                printf 'could not restore previous %s after publication failure: %s\n' "$label" "$destination" >&2
        fi
        return 1
    fi
    if [[ -n "$backup" ]]; then
        campaign_clear_owned_directory "$backup" "$label backup" || return 1
        rmdir "$backup" || return 1
    fi
}

campaign_publish_status_text() {
    local root="$1"
    local destination="$2"
    local content="$3"
    local label="$4"
    campaign_assert_private_lock || return 1
    campaign_require_owned_real_directory "$root" "$label root" || return 1
    local root_real destination_parent_real staged owner parent_identity parent_device parent_inode
    local staged_sha256 staged_device staged_inode staged_size
    local destination_state=absent destination_device=0 destination_inode=0
    root_real="$(realpath -e "$root")" || return 1
    destination_parent_real="$(realpath -e "$(dirname "$destination")")" || return 1
    [[ "$destination_parent_real" == "$root_real" ]] || {
        printf '%s status path escapes its root: %s\n' "$label" "$destination" >&2
        return 1
    }
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] || {
            printf '%s status destination is unsafe: %s\n' "$label" "$destination" >&2
            return 1
        }
        owner="$(stat -c %u "$destination")" || return 1
        [[ "$owner" == "$(id -u)" ]] || return 1
        [[ "$(stat -c %h "$destination")" == 1 ]] || return 1
        destination_state="file"
        destination_device="$(stat -c %d "$destination")" || return 1
        destination_inode="$(stat -c %i "$destination")" || return 1
    fi
    parent_identity="$(stat -c '%d:%i' "$root")" || return 1
    parent_device="${parent_identity%%:*}"
    parent_inode="${parent_identity#*:}"
    campaign_assert_private_lock || return 1
    staged="$(mktemp "$root/.collection-status.XXXXXX")" || return 1
    if ! printf '%s' "$content" >"$staged"; then
        campaign_assert_private_lock || return 1
        rm -f "$staged"
        return 1
    fi
    sync -f "$staged" 2>/dev/null || true
    campaign_capture_candidate_identity "$staged" staged || return 1
    staged_size="$(stat -c %s "$staged")" || return 1
    ((staged_size <= 16 * 1024 * 1024)) || return 1
    if declare -F campaign_publish_status_text_hook >/dev/null 2>&1; then
        campaign_publish_status_text_hook before-final-rename "$staged" "$destination" || return 1
    fi
    campaign_assert_private_lock || {
        return 1
    }
    campaign_identity_bound_replace_text "$root" "$staged" "$destination" \
        "$parent_device" "$parent_inode" "$staged_sha256" "$staged_device" "$staged_inode" \
        "$staged_size" "$destination_state" "$destination_device" "$destination_inode"
}

campaign_collection_transaction_path() {
    local root="$1"
    shift
    local digest
    digest="$(printf '%s\0' "$@" | sha256sum | awk '{ print $1 }')" || return 1
    printf '%s/.collection-transaction-%s\n' "$root" "$digest"
}

campaign_collection_commit_path() {
    local transaction="$1"
    printf '%s.committed\n' "$transaction"
}

# These descriptors are the live authority for collection transaction markers.
# They intentionally do not survive exec/crash; disk markers alone never regain
# destructive authority in a same-UID-writable namespace.
declare -Ag CAMPAIGN_COLLECTION_MARKER_FDS=()
declare -Ag CAMPAIGN_COLLECTION_MARKER_WRITE_FDS=()
declare -Ag CAMPAIGN_COLLECTION_MARKER_PIDS=()
declare -Ag CAMPAIGN_COLLECTION_MARKER_STARTTIMES=()
declare -Ag CAMPAIGN_COLLECTION_MARKER_IDENTITIES=()
declare -Ag CAMPAIGN_COLLECTION_MARKER_CONTENTS=()
declare -Ag CAMPAIGN_COLLECTION_TRANSACTION_FDS=()

campaign_collection_stop_marker_broker() {
    local marker="$1"
    local read_fd="${CAMPAIGN_COLLECTION_MARKER_FDS[$marker]:-}"
    local write_fd="${CAMPAIGN_COLLECTION_MARKER_WRITE_FDS[$marker]:-}"
    local broker_pid="${CAMPAIGN_COLLECTION_MARKER_PIDS[$marker]:-}"
    local broker_starttime="${CAMPAIGN_COLLECTION_MARKER_STARTTIMES[$marker]:-}"
    local stop_status=0 stop_timeout="${BORONDNS_CAMPAIGN_MARKER_STOP_TIMEOUT_SECONDS:-2}"
    local stop_deadline=""
    campaign_require_bounded_positive_integer marker-broker-stop-timeout "$stop_timeout" 60 || stop_status=1
    if ((stop_status == 0)); then
        stop_deadline="$(campaign_deadline_from_timeout_seconds "$stop_timeout")" || stop_status=1
    fi
    if [[ "$broker_pid" =~ ^[1-9][0-9]*$ && "$broker_starttime" =~ ^[1-9][0-9]*$ &&
        "$read_fd" =~ ^[0-9]+$ && "$write_fd" =~ ^[0-9]+$ && -n "$stop_deadline" ]]; then
        { printf 'close\n' >&"$write_fd"; } 2>/dev/null || true
        if ! campaign_finish_protocol_child_before_deadline "$broker_pid" "$read_fd" "$write_fd" \
            "$stop_deadline" 'collection marker broker' "$broker_starttime"; then
            campaign_lock_child_exited "$broker_pid" || stop_status=1
        fi
    else
        [[ ! "$write_fd" =~ ^[0-9]+$ ]] || exec {write_fd}>&-
        [[ ! "$read_fd" =~ ^[0-9]+$ ]] || exec {read_fd}<&-
        if [[ "$broker_pid" =~ ^[1-9][0-9]*$ && "$broker_starttime" =~ ^[1-9][0-9]*$ &&
            -n "$stop_deadline" ]]; then
            if campaign_wait_child_before_deadline "$broker_pid" "$stop_deadline" "$broker_starttime"; then
                campaign_reap_exited_child "$broker_pid" || true
            else
                campaign_terminate_child_before_deadline "$broker_pid" "$stop_deadline" \
                    'collection marker broker' "$broker_starttime" || stop_status=1
            fi
        elif [[ -n "$broker_pid" ]]; then
            stop_status=1
        fi
    fi
    unset 'CAMPAIGN_COLLECTION_MARKER_FDS[$marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_WRITE_FDS[$marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_PIDS[$marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_STARTTIMES[$marker]'
    return "$stop_status"
}

campaign_collection_assert_marker_broker() {
    local marker="$1" label="$2"
    local read_fd="${CAMPAIGN_COLLECTION_MARKER_FDS[$marker]:-}"
    local write_fd="${CAMPAIGN_COLLECTION_MARKER_WRITE_FDS[$marker]:-}"
    local broker_pid="${CAMPAIGN_COLLECTION_MARKER_PIDS[$marker]:-}"
    local response=""
    [[ "$read_fd" =~ ^[0-9]+$ && "$write_fd" =~ ^[0-9]+$ &&
        "$broker_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    if ! kill -0 "$broker_pid" 2>/dev/null ||
        ! { printf 'ping\n' >&"$write_fd"; } 2>/dev/null ||
        ! IFS= read -r -t 5 -u "$read_fd" response || [[ "$response" != ok ]]; then
        printf '%s marker broker lost descriptor authority: %s\n' "$label" "$marker" >&2
        campaign_collection_stop_marker_broker "$marker"
        return 1
    fi
}

campaign_collection_rebind_marker_broker() {
    local old_marker="$1" new_marker="$2"
    local read_fd="${CAMPAIGN_COLLECTION_MARKER_FDS[$old_marker]:-}"
    local write_fd="${CAMPAIGN_COLLECTION_MARKER_WRITE_FDS[$old_marker]:-}"
    local response="" new_basename="${new_marker##*/}"
    [[ "$(dirname "$old_marker")" == "$(dirname "$new_marker")" &&
    "$new_basename" != . && "$new_basename" != .. && "$new_basename" != */* &&
    "$read_fd" =~ ^[0-9]+$ && "$write_fd" =~ ^[0-9]+$ ]] || return 1
    { printf 'rebind\t%s\n' "$new_basename" >&"$write_fd"; } 2>/dev/null || return 1
    IFS= read -r -t 5 -u "$read_fd" response || return 1
    [[ "$response" == ok ]] || return 1
    CAMPAIGN_COLLECTION_MARKER_FDS["$new_marker"]="$read_fd"
    CAMPAIGN_COLLECTION_MARKER_WRITE_FDS["$new_marker"]="$write_fd"
    CAMPAIGN_COLLECTION_MARKER_PIDS["$new_marker"]="${CAMPAIGN_COLLECTION_MARKER_PIDS[$old_marker]}"
    CAMPAIGN_COLLECTION_MARKER_STARTTIMES["$new_marker"]="${CAMPAIGN_COLLECTION_MARKER_STARTTIMES[$old_marker]}"
    CAMPAIGN_COLLECTION_MARKER_IDENTITIES["$new_marker"]="${CAMPAIGN_COLLECTION_MARKER_IDENTITIES[$old_marker]}"
    CAMPAIGN_COLLECTION_MARKER_CONTENTS["$new_marker"]="${CAMPAIGN_COLLECTION_MARKER_CONTENTS[$old_marker]}"
    unset 'CAMPAIGN_COLLECTION_MARKER_FDS[$old_marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_WRITE_FDS[$old_marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_PIDS[$old_marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_STARTTIMES[$old_marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_IDENTITIES[$old_marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_CONTENTS[$old_marker]'
}

campaign_collection_write_exclusive_marker() {
    local directory="$1" marker="$2" content="$3"
    local expected_device="$4" expected_inode="$5" expected_owner="$6"
    if declare -F campaign_collection_marker_hook >/dev/null 2>&1; then
        campaign_collection_marker_hook before-exclusive-create "$directory" "$marker" || return 1
    fi
    local broker_source broker_pid broker_starttime broker_read_fd broker_write_fd original_read_fd original_write_fd
    local created_identity created_size response
    read -r -d '' broker_source <<'PY' || true
import os
import stat
import sys

directory, marker, content, device, inode, owner, expected_uid = sys.argv[1:]
if not marker or marker in {".", ".."} or "/" in marker:
    raise SystemExit("invalid collection marker basename")
expected_directory = (int(device), int(inode), int(owner))
expected_uid = int(expected_uid)
directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    directory_info = os.fstat(directory_fd)
    if (directory_info.st_dev, directory_info.st_ino, directory_info.st_uid) != expected_directory:
        raise SystemExit("collection marker directory identity changed")
    descriptor = os.open(
        marker,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        opened = os.fstat(descriptor)
        named = os.stat(marker, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise SystemExit("collection marker identity changed during creation")
        payload = content.encode("utf-8")
        if len(payload) > 65536:
            raise SystemExit("collection marker payload exceeds the supported bound")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("collection marker write stalled")
            view = view[written:]
        os.fsync(descriptor)
        os.fsync(directory_fd)
        expected_identity = (opened.st_dev, opened.st_ino, opened.st_uid)
        expected_size = len(payload)

        def verify(initial: bool) -> None:
            directory_now = os.fstat(directory_fd)
            held = os.fstat(descriptor)
            named = os.stat(marker, dir_fd=directory_fd, follow_symlinks=False)
            if (directory_now.st_dev, directory_now.st_ino, directory_now.st_uid) != expected_directory:
                raise RuntimeError("collection marker directory identity changed")
            if (
                not stat.S_ISREG(held.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or held.st_uid != expected_uid
                or named.st_uid != expected_uid
                or held.st_nlink != 1
                or named.st_nlink != 1
                or (held.st_dev, held.st_ino, held.st_uid) != expected_identity
                or (named.st_dev, named.st_ino, named.st_uid) != expected_identity
                or (initial and (held.st_size != expected_size or named.st_size != expected_size))
            ):
                raise RuntimeError("collection marker descriptor or pathname identity changed")

        verify(True)
        sys.stdout.reconfigure(line_buffering=True)
        print(f"ready\t{opened.st_dev}:{opened.st_ino}:{opened.st_uid}\t{expected_size}")
        for command in sys.stdin:
            command = command.rstrip("\n")
            try:
                if command == "initial":
                    verify(True)
                    print("ok")
                elif command == "ping":
                    verify(False)
                    print("ok")
                elif command.startswith("rebind\t"):
                    candidate = command.split("\t", 1)[1]
                    if not candidate or candidate in {".", ".."} or "/" in candidate:
                        raise RuntimeError("invalid collection marker rebind basename")
                    previous = marker
                    marker = candidate
                    try:
                        verify(False)
                    except Exception:
                        marker = previous
                        raise
                    print("ok")
                elif command == "close":
                    break
                else:
                    raise RuntimeError("invalid collection marker broker command")
            except Exception as error:
                print(f"error\t{error}")
                raise SystemExit(1)
    finally:
        os.close(descriptor)
finally:
    os.close(directory_fd)
PY
    coproc CAMPAIGN_COLLECTION_MARKER_BROKER {
        exec python3 -c "$broker_source" "$directory" "${marker##*/}" "$content" \
            "$expected_device" "$expected_inode" "$expected_owner" "$(id -u)"
    }
    broker_pid="$CAMPAIGN_COLLECTION_MARKER_BROKER_PID"
    original_read_fd="${CAMPAIGN_COLLECTION_MARKER_BROKER[0]}"
    original_write_fd="${CAMPAIGN_COLLECTION_MARKER_BROKER[1]}"
    if ! campaign_process_starttime "$broker_pid" broker_starttime; then
        exec {original_read_fd}<&-
        exec {original_write_fd}>&-
        wait "$broker_pid" 2>/dev/null || true
        return 1
    fi
    exec {broker_read_fd}<&"$original_read_fd" || {
        exec {original_read_fd}<&-
        exec {original_write_fd}>&-
        local setup_deadline
        setup_deadline="$(campaign_deadline_from_timeout_seconds 2)" || return 1
        campaign_terminate_child_before_deadline "$broker_pid" "$setup_deadline" \
            'collection marker broker setup' "$broker_starttime" || true
        return 1
    }
    exec {broker_write_fd}>&"$original_write_fd" || {
        exec {broker_read_fd}<&-
        exec {original_read_fd}<&-
        exec {original_write_fd}>&-
        local setup_deadline
        setup_deadline="$(campaign_deadline_from_timeout_seconds 2)" || return 1
        campaign_terminate_child_before_deadline "$broker_pid" "$setup_deadline" \
            'collection marker broker setup' "$broker_starttime" || true
        return 1
    }
    exec {original_read_fd}<&-
    exec {original_write_fd}>&-
    unset CAMPAIGN_COLLECTION_MARKER_BROKER CAMPAIGN_COLLECTION_MARKER_BROKER_PID
    if ! IFS=$'\t' read -r -t 5 -u "$broker_read_fd" response created_identity created_size ||
        [[ "$response" != ready || ! "$created_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ||
            ! "$created_size" =~ ^[0-9]+$ ]]; then
        exec {broker_read_fd}<&-
        exec {broker_write_fd}>&-
        local setup_deadline
        setup_deadline="$(campaign_deadline_from_timeout_seconds 2)" || return 1
        campaign_terminate_child_before_deadline "$broker_pid" "$setup_deadline" \
            'collection marker broker handshake' "$broker_starttime" || true
        return 1
    fi
    if declare -F campaign_collection_marker_hook >/dev/null 2>&1; then
        campaign_collection_marker_hook after-exclusive-create "$directory" "$marker" || {
            exec {broker_read_fd}<&-
            exec {broker_write_fd}>&-
            local setup_deadline
            setup_deadline="$(campaign_deadline_from_timeout_seconds 2)" || return 1
            campaign_terminate_child_before_deadline "$broker_pid" "$setup_deadline" \
                'collection marker broker hook failure' "$broker_starttime" || true
            return 1
        }
    fi
    if ! { printf 'initial\n' >&"$broker_write_fd"; } 2>/dev/null ||
        ! IFS= read -r -t 5 -u "$broker_read_fd" response || [[ "$response" != ok ]]; then
        exec {broker_read_fd}<&-
        exec {broker_write_fd}>&-
        local setup_deadline
        setup_deadline="$(campaign_deadline_from_timeout_seconds 2)" || return 1
        campaign_terminate_child_before_deadline "$broker_pid" "$setup_deadline" \
            'collection marker broker initial validation' "$broker_starttime" || true
        return 1
    fi
    CAMPAIGN_COLLECTION_MARKER_FDS["$marker"]="$broker_read_fd"
    CAMPAIGN_COLLECTION_MARKER_WRITE_FDS["$marker"]="$broker_write_fd"
    CAMPAIGN_COLLECTION_MARKER_PIDS["$marker"]="$broker_pid"
    CAMPAIGN_COLLECTION_MARKER_STARTTIMES["$marker"]="$broker_starttime"
    CAMPAIGN_COLLECTION_MARKER_IDENTITIES["$marker"]="$created_identity"
    # Disk bytes are diagnostic only. The same UID can retain a writable fd to
    # this inode and change them after any hash check, so every live decision
    # consumes this creation-time in-process snapshot instead.
    CAMPAIGN_COLLECTION_MARKER_CONTENTS["$marker"]="$content"
}

campaign_collection_record_object_identity() {
    local path="$1"
    local marker="$2"
    local expected_kind="$3"
    local label="$4"
    local expected_marker_parent_device="${5:-}" expected_marker_parent_inode="${6:-}"
    local expected_marker_parent_owner="${7:-}"
    [[ "$expected_kind" == directory || "$expected_kind" == file ]] || return 1
    [[ ! -e "$marker" && ! -L "$marker" ]] || return 1
    if [[ "$expected_kind" == directory ]]; then
        campaign_require_owned_real_directory "$path" "$label" || return 1
    else
        [[ -f "$path" && ! -L "$path" && "$(stat -c %u "$path")" == "$(id -u)" ]] || return 1
    fi
    local before after marker_parent marker_parent_identity marker_parent_remainder content
    before="$(stat -c '%d:%i:%u' "$path")" || return 1
    local remainder="${before#*:}"
    printf -v content 'kind=%s\ndevice=%s\ninode=%s\nowner=%s\n' \
        "$expected_kind" "${before%%:*}" "${remainder%%:*}" "${before##*:}"
    marker_parent="$(dirname "$marker")"
    if [[ -n "$expected_marker_parent_device" ]]; then
        [[ "$expected_marker_parent_device" =~ ^[0-9]+$ && "$expected_marker_parent_inode" =~ ^[0-9]+$ &&
            "$expected_marker_parent_owner" =~ ^[0-9]+$ ]] || return 1
        marker_parent_identity="$expected_marker_parent_device:$expected_marker_parent_inode:$expected_marker_parent_owner"
    else
        marker_parent_identity="$(stat -c '%d:%i:%u' "$marker_parent")" || return 1
    fi
    marker_parent_remainder="${marker_parent_identity#*:}"
    campaign_collection_write_exclusive_marker "$marker_parent" "$marker" "$content" \
        "${marker_parent_identity%%:*}" "${marker_parent_remainder%%:*}" \
        "${marker_parent_identity##*:}" || return 1
    after="$(stat -c '%d:%i:%u' "$path")" || return 1
    [[ "$before" == "$after" && -f "$marker" && ! -L "$marker" &&
        "$(stat -c %u "$marker")" == "$(id -u)" && "$(stat -c %h "$marker")" == 1 ]] || return 1
    sync -f "$marker" 2>/dev/null || true
}

campaign_collection_object_identity_matches() {
    local path="$1"
    local marker="$2"
    local label="$3"
    local marker_fd="${CAMPAIGN_COLLECTION_MARKER_FDS[$marker]:-}"
    local expected_marker="${CAMPAIGN_COLLECTION_MARKER_IDENTITIES[$marker]:-}"
    local marker_content="${CAMPAIGN_COLLECTION_MARKER_CONTENTS[$marker]+present}"
    [[ "$marker_fd" =~ ^[0-9]+$ && -n "$expected_marker" && "$marker_content" == present ]] || {
        printf '%s marker has no live descriptor authority; retaining transaction: %s\n' \
            "$label" "$marker" >&2
        return 1
    }
    campaign_collection_assert_marker_broker "$marker" "$label" || return 1
    [[ "$(stat -Lc '%d:%i:%u' "$marker")" == "$expected_marker" ]] || return 1
    local -a marker_lines=()
    mapfile -t marker_lines < <(printf '%s' "${CAMPAIGN_COLLECTION_MARKER_CONTENTS[$marker]}") || return 1
    ((${#marker_lines[@]} == 4)) || return 1
    local kind="${marker_lines[0]#kind=}" device="${marker_lines[1]#device=}"
    local inode="${marker_lines[2]#inode=}" owner="${marker_lines[3]#owner=}"
    [[ "${marker_lines[0]}" == kind=* && "${marker_lines[1]}" == device=* &&
        "${marker_lines[2]}" == inode=* && "${marker_lines[3]}" == owner=* ]] || return 1
    [[ "$kind" == directory || "$kind" == file ]] || return 1
    [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ && "$owner" =~ ^[0-9]+$ &&
        "$owner" == "$(id -u)" ]] || return 1
    if [[ "$kind" == directory ]]; then
        campaign_require_owned_real_directory "$path" "$label" || return 1
    else
        [[ -f "$path" && ! -L "$path" && "$(stat -c %u "$path")" == "$owner" ]] || return 1
    fi
    [[ "$(stat -c %d "$path")" == "$device" && "$(stat -c %i "$path")" == "$inode" ]]
}

campaign_collection_read_live_marker() {
    local marker="$1" output_variable="$2" label="$3"
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_variable" in
    marker | output_variable | label | marker_fd | expected_marker | marker_content | resolved_marker_value)
        return 1
        ;;
    esac
    local marker_fd="${CAMPAIGN_COLLECTION_MARKER_FDS[$marker]:-}"
    local expected_marker="${CAMPAIGN_COLLECTION_MARKER_IDENTITIES[$marker]:-}"
    local marker_content="${CAMPAIGN_COLLECTION_MARKER_CONTENTS[$marker]:-}"
    [[ "$marker_fd" =~ ^[0-9]+$ && -n "$expected_marker" && -n "$marker_content" ]] &&
        campaign_collection_assert_marker_broker "$marker" "$label" &&
        [[ "$(stat -Lc '%d:%i:%u' "$marker")" == "$expected_marker" ]] || {
        printf '%s marker lacks live descriptor authority: %s\n' "$label" "$marker" >&2
        return 1
    }
    local resolved_marker_value="$marker_content"
    resolved_marker_value="${resolved_marker_value%$'\n'}"
    printf -v "$output_variable" '%s' "$resolved_marker_value"
}

campaign_collection_require_destination_identity() {
    local destination="$1"
    local marker="$2"
    local label="$3"
    campaign_collection_object_identity_matches "$destination" "$marker" "$label" || {
        printf '%s identity drift; retaining collection transaction: %s\n' "$label" "$destination" >&2
        return 1
    }
}

campaign_collection_identity_bound_remove() {
    local path="$1"
    local marker="$2"
    local label="$3"
    campaign_collection_require_destination_identity "$path" "$marker" "$label" || return 1
    local marker_fd="${CAMPAIGN_COLLECTION_MARKER_FDS[$marker]:-}"
    local -a marker_lines=()
    [[ "$marker_fd" =~ ^[0-9]+$ ]] || return 1
    mapfile -t marker_lines < <(printf '%s' "${CAMPAIGN_COLLECTION_MARKER_CONTENTS[$marker]:-}") || return 1
    ((${#marker_lines[@]} == 4)) || return 1
    local kind="${marker_lines[0]#kind=}" device="${marker_lines[1]#device=}"
    local inode="${marker_lines[2]#inode=}" owner="${marker_lines[3]#owner=}"
    local parent parent_identity parent_remainder
    [[ "$kind" == directory || "$kind" == file ]] || return 1
    [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ && "$owner" =~ ^[0-9]+$ ]] || return 1
    parent="$(dirname "$path")"
    campaign_require_owned_real_directory "$parent" "$label parent" || return 1
    parent_identity="$(stat -c '%d:%i:%u' "$parent")" || return 1
    if declare -F campaign_identity_bound_remove_hook >/dev/null 2>&1; then
        campaign_identity_bound_remove_hook before-remove "$path" "$label" || return 1
    fi
    campaign_assert_private_lock || return 1
    parent_remainder="${parent_identity#*:}"
    [[ "$kind" != directory ]] || kind=tree
    campaign_identity_bound_remove "$kind" "$parent" "$path" \
        "${parent_identity%%:*}" "${parent_remainder%%:*}" "${parent_identity##*:}" \
        "$device" "$inode" "$owner"
}

campaign_collection_retire_live_marker() {
    local marker="$1"
    local retained="$marker.retained.$BASHPID.$RANDOM.$RANDOM"
    if [[ -e "$marker" || -L "$marker" ]]; then
        campaign_rename_noreplace "$marker" "$retained" || return 1
    fi
    campaign_collection_stop_marker_broker "$marker"
    unset 'CAMPAIGN_COLLECTION_MARKER_IDENTITIES[$marker]'
    unset 'CAMPAIGN_COLLECTION_MARKER_CONTENTS[$marker]'
}

campaign_collection_release_transaction_authority() {
    local transaction="$1" marker
    for marker in "${!CAMPAIGN_COLLECTION_MARKER_FDS[@]}"; do
        [[ "$marker" == "$transaction/"* ]] || continue
        campaign_collection_stop_marker_broker "$marker"
        unset 'CAMPAIGN_COLLECTION_MARKER_IDENTITIES[$marker]'
        unset 'CAMPAIGN_COLLECTION_MARKER_CONTENTS[$marker]'
    done
    local transaction_fd="${CAMPAIGN_COLLECTION_TRANSACTION_FDS[$transaction]:-}"
    if [[ "$transaction_fd" =~ ^[0-9]+$ ]]; then
        exec {transaction_fd}<&- || true
    fi
    unset 'CAMPAIGN_COLLECTION_TRANSACTION_FDS[$transaction]'
}

campaign_collection_capture_and_remove() {
    local path="$1"
    local expected_kind="$2"
    local label="$3"
    local marker
    marker="$(dirname "$path")/.collection-remove-identity.$BASHPID.$RANDOM.$RANDOM"
    [[ ! -e "$marker" && ! -L "$marker" ]] || return 1
    if ! campaign_collection_record_object_identity "$path" "$marker" "$expected_kind" "$label"; then
        return 1
    fi
    if ! campaign_collection_identity_bound_remove "$path" "$marker" "$label"; then
        campaign_collection_retire_live_marker "$marker" || true
        return 1
    fi
    campaign_collection_retire_live_marker "$marker"
}

campaign_collection_discard_committed_backups() {
    local transaction="$1"
    local label="$2"
    local object_count="${3:-3}"
    local index backup identity
    for ((index = 0; index < object_count; index++)); do
        backup="$transaction/old-$index"
        identity="$transaction/old-$index.identity"
        if declare -F campaign_collection_publication_hook >/dev/null 2>&1; then
            campaign_collection_publication_hook "commit-cleanup-$index" "$transaction" || return 1
        fi
        campaign_assert_private_lock || return 1
        if [[ -e "$backup" || -L "$backup" ]]; then
            campaign_collection_identity_bound_remove "$backup" "$identity" \
                "$label committed transaction backup" || return 1
        fi
    done
}

campaign_recover_collection_bundle() {
    local root="$1"
    local evidence_destination="$2"
    local journal_destination="$3"
    local status_destination="$4"
    local status_commit_destination="" label absolute_deadline="" object_count=3
    if (($# == 5)); then
        label="$5"
    elif (($# == 6)); then
        status_commit_destination="$5"
        label="$6"
        object_count=4
    elif (($# == 7)); then
        status_commit_destination="$5"
        label="$6"
        absolute_deadline="$7"
        object_count=4
    else
        return 1
    fi
    [[ -n "$absolute_deadline" ]] ||
        absolute_deadline="$(campaign_deadline_from_timeout_seconds 5)" || return 1
    campaign_is_positive_signed_64 "$absolute_deadline" || return 1
    local transaction commit_decision destination backup index had_marker
    local -a destinations=("$evidence_destination" "$journal_destination" "$status_destination")
    if ((object_count == 4)); then
        destinations+=("$status_commit_destination")
    fi
    transaction="$(campaign_collection_transaction_path "$root" "${destinations[@]}")" || return 1
    commit_decision="$(campaign_collection_commit_path "$transaction")" || return 1
    if [[ -e "$transaction" || -L "$transaction" || -e "$commit_decision" || -L "$commit_decision" ]]; then
        local transaction_fd="${CAMPAIGN_COLLECTION_TRANSACTION_FDS[$transaction]:-}"
        local held_transaction_identity="" named_transaction_identity=""
        if [[ "$transaction_fd" =~ ^[0-9]+$ && -e "/proc/$BASHPID/fd/$transaction_fd" ]]; then
            held_transaction_identity="$(stat -Lc '%d:%i:%u' "/proc/$BASHPID/fd/$transaction_fd")" || return 1
            named_transaction_identity="$(stat -Lc '%d:%i:%u' "$transaction")" || return 1
        fi
        [[ "$transaction_fd" =~ ^[0-9]+$ && -e "/proc/$BASHPID/fd/$transaction_fd" &&
            -d "$transaction" && ! -L "$transaction" &&
            "$held_transaction_identity" == "$named_transaction_identity" ]] || {
            printf '%s durable collection transaction has no live descriptor authority; retaining it: %s\n' \
                "$label" "$transaction" >&2
            return 1
        }
    fi
    if [[ -e "$commit_decision" || -L "$commit_decision" ]]; then
        local commit_value
        campaign_collection_read_live_marker "$commit_decision" commit_value \
            "$label commit decision" || return 1
        [[ "$commit_value" == committed ]] || return 1
        for ((index = 0; index < object_count; index++)); do
            destination="${destinations[$index]}"
            campaign_collection_require_destination_identity "$destination" \
                "$transaction/new-$index.identity" "$label committed destination" || return 1
        done
        campaign_collection_discard_committed_backups "$transaction" "$label" "$object_count" || return 1
        campaign_assert_private_lock || return 1
        campaign_collection_capture_and_remove "$commit_decision" file \
            "$label commit decision" || return 1
        campaign_collection_retire_live_marker "$commit_decision" || return 1
        campaign_assert_private_lock || return 1
        if [[ -e "$transaction" || -L "$transaction" ]]; then
            campaign_require_owned_real_directory "$transaction" "$label committed transaction" || return 1
            campaign_collection_capture_and_remove "$transaction" directory \
                "$label committed transaction" || return 1
        fi
        campaign_collection_release_transaction_authority "$transaction"
        return 0
    fi
    [[ -e "$transaction" || -L "$transaction" ]] || return 0
    campaign_assert_private_lock "$absolute_deadline" || return 1
    campaign_require_owned_real_directory "$transaction" "$label transaction" || return 1
    if [[ -f "$transaction/committed" && ! -L "$transaction/committed" ]]; then
        # Transactions from the pre-identity format cannot be recovered
        # without risking unrelated replacement paths.  Retain them for
        # explicit operator inspection instead of guessing.
        for ((index = 0; index < object_count; index++)); do
            [[ -f "$transaction/new-$index.identity" && ! -L "$transaction/new-$index.identity" ]] || {
                printf '%s legacy transaction lacks promoted identity; retaining it: %s\n' "$label" "$transaction" >&2
                return 1
            }
        done
        for ((index = 0; index < object_count; index++)); do
            destination="${destinations[$index]}"
            campaign_collection_require_destination_identity "$destination" \
                "$transaction/new-$index.identity" "$label committed destination" || return 1
        done
        campaign_collection_discard_committed_backups "$transaction" "$label" "$object_count" || return 1
        campaign_assert_private_lock || return 1
        campaign_collection_capture_and_remove "$transaction" directory \
            "$label legacy committed transaction" || return 1
        campaign_collection_release_transaction_authority "$transaction"
        return 0
    fi
    local initialized=1 marker_value
    for ((index = 0; index < object_count; index++)); do
        had_marker="$transaction/had-$index"
        if [[ ! -f "$had_marker" || -L "$had_marker" ]]; then
            initialized=0
            break
        fi
        campaign_collection_read_live_marker "$had_marker" marker_value \
            "$label transaction presence" || {
            initialized=0
            break
        }
        if [[ "$marker_value" != present && "$marker_value" != absent ]]; then
            initialized=0
            break
        fi
        if [[ ! -f "$transaction/new-$index.identity" || -L "$transaction/new-$index.identity" ]]; then
            initialized=0
            break
        fi
        if [[ "$marker_value" == present ]] &&
            [[ ! -f "$transaction/old-$index.identity" || -L "$transaction/old-$index.identity" ]]; then
            initialized=0
            break
        fi
    done
    if ((initialized == 0)); then
        local transaction_remainder transaction_old_listing=""
        transaction_remainder="${held_transaction_identity#*:}"
        [[ -n "$held_transaction_identity" &&
            "${held_transaction_identity%%:*}" =~ ^[0-9]+$ &&
            "${transaction_remainder%%:*}" =~ ^[0-9]+$ &&
            "${held_transaction_identity##*:}" =~ ^[0-9]+$ ]] || return 1
        BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP=64 \
            campaign_enumerate_direct_children_bounded "$transaction" \
            "${held_transaction_identity%%:*}" "${transaction_remainder%%:*}" \
            "${held_transaction_identity##*:}" 'old-' "$absolute_deadline" \
            transaction_old_listing || return 1
        [[ -z "$transaction_old_listing" ]] || return 1
        campaign_assert_private_lock "$absolute_deadline" || return 1
        campaign_collection_capture_and_remove "$transaction" directory \
            "$label uninitialized transaction" || return 1
        campaign_collection_release_transaction_authority "$transaction"
        return 0
    fi
    for ((index = 0; index < object_count; index++)); do
        destination="${destinations[$index]}"
        backup="$transaction/old-$index"
        had_marker="$transaction/had-$index"
        [[ -f "$had_marker" && ! -L "$had_marker" ]] || return 1
        if [[ -e "$backup" || -L "$backup" ]]; then
            campaign_collection_require_destination_identity "$backup" \
                "$transaction/old-$index.identity" "$label transaction backup" || return 1
            if [[ -e "$destination" || -L "$destination" ]]; then
                campaign_collection_require_destination_identity "$destination" \
                    "$transaction/new-$index.identity" "$label promoted destination" || return 1
                campaign_assert_private_lock || return 1
                campaign_collection_identity_bound_remove "$destination" \
                    "$transaction/new-$index.identity" "$label promoted destination" || return 1
            fi
            campaign_assert_private_lock || return 1
            campaign_rename_noreplace "$backup" "$destination" || return 1
            campaign_collection_require_destination_identity "$destination" \
                "$transaction/old-$index.identity" "$label restored destination" || return 1
        elif campaign_collection_read_live_marker "$had_marker" marker_value \
            "$label transaction presence" && [[ "$marker_value" == absent ]]; then
            if [[ -e "$destination" || -L "$destination" ]]; then
                campaign_collection_require_destination_identity "$destination" \
                    "$transaction/new-$index.identity" "$label promoted destination" || return 1
                campaign_assert_private_lock || return 1
                campaign_collection_identity_bound_remove "$destination" \
                    "$transaction/new-$index.identity" "$label promoted destination" || return 1
            fi
        elif [[ -e "$destination" || -L "$destination" ]]; then
            campaign_collection_require_destination_identity "$destination" \
                "$transaction/old-$index.identity" "$label original destination" || return 1
        elif ! campaign_collection_read_live_marker "$had_marker" marker_value \
            "$label transaction presence" || [[ "$marker_value" != present ]]; then
            return 1
        else
            printf '%s transaction lost both its original destination and backup: %s\n' "$label" "$destination" >&2
            return 1
        fi
    done
    campaign_assert_private_lock || return 1
    campaign_collection_capture_and_remove "$transaction" directory \
        "$label recovered transaction" || return 1
    campaign_collection_release_transaction_authority "$transaction"
}

campaign_publish_collection_bundle() {
    local root="$1"
    local evidence_staging="$2"
    local evidence_destination="$3"
    local journal_staging="$4"
    local journal_destination="$5"
    local status_staging="$6"
    local status_destination="$7"
    local label="$8"
    local expected_evidence_snapshot="${9:-}" absolute_deadline="${10:-}" validator="${11:-}"
    local status_commit_staging="${12:-}" status_commit_destination="${13:-}"
    local content_bound=0
    if [[ -n "$expected_evidence_snapshot" || -n "$absolute_deadline" || -n "$validator" ]]; then
        [[ "$expected_evidence_snapshot" =~ ^[0-9a-f]{64}$ && -n "$absolute_deadline" &&
            -n "$validator" ]] || return 1
        campaign_is_positive_signed_64 "$absolute_deadline" || return 1
        campaign_collection_generation_matches "$evidence_staging" "$expected_evidence_snapshot" \
            "$absolute_deadline" "$validator" || return 1
        local preflight_status_sha256 preflight_status_content preflight_status_device
        local preflight_status_inode preflight_status_size preflight_status_text
        campaign_collection_read_bounded_file "$status_staging" "$absolute_deadline" 8388608 \
            preflight_status_sha256 preflight_status_content preflight_status_device \
            preflight_status_inode preflight_status_size || return 1
        preflight_status_text="$(printf '%s' "$preflight_status_content" |
            base64 --decode 2>/dev/null)" || return 1
        local status_kind status_host status_source status_classification status_snapshot status_extra
        IFS=$'\t' read -r status_kind status_host status_source status_classification status_snapshot status_extra \
            <<<"$preflight_status_text" || return 1
        [[ "$status_kind" == collection && -n "$status_host" && "$status_source" == remote-snapshot &&
            ("$status_classification" == complete || "$status_classification" == incomplete) &&
            "$status_snapshot" == "$expected_evidence_snapshot" && -z "$status_extra" ]] || return 1
        [[ -n "$status_commit_staging" && -n "$status_commit_destination" ]] || return 1
        content_bound=1
    elif [[ -n "$status_commit_staging" || -n "$status_commit_destination" ]]; then
        return 1
    fi
    campaign_assert_private_lock || return 1
    campaign_require_owned_real_directory "$root" "$label root" || return 1
    campaign_require_owned_real_directory "$evidence_staging" "$label evidence staging" || return 1
    campaign_require_owned_real_directory "$journal_staging" "$label journal staging" || return 1
    if ((!content_bound)); then
        [[ -f "$status_staging" && ! -L "$status_staging" &&
            "$(stat -c %u "$status_staging")" == "$(id -u)" ]] || return 1
    fi
    local destination backup index transaction commit_decision committed_staging
    local -a destinations=("$evidence_destination" "$journal_destination" "$status_destination")
    local -a stagings=("$evidence_staging" "$journal_staging" "$status_staging")
    local object_count=3
    if ((content_bound)); then
        destinations+=("$status_commit_destination")
        stagings+=("$status_commit_staging")
        object_count=4
    fi
    local root_real parent_real
    root_real="$(realpath -e "$root")" || return 1
    for ((index = 0; index < object_count; index++)); do
        campaign_assert_private_lock || return 1
        destination="${destinations[$index]}"
        parent_real="$(realpath -e "$(dirname "$destination")")" || return 1
        [[ "$parent_real" == "$root_real" ]] || return 1
        if [[ -e "$destination" || -L "$destination" ]]; then
            if ((index < 2)); then
                campaign_require_owned_real_directory "$destination" "$label destination" || return 1
            else
                [[ -f "$destination" && ! -L "$destination" && "$(stat -c %u "$destination")" == "$(id -u)" ]] || return 1
            fi
        fi
    done
    if ((content_bound)); then
        campaign_recover_collection_bundle "$root" "$evidence_destination" "$journal_destination" \
            "$status_destination" "$status_commit_destination" "$label" \
            "$absolute_deadline" || return 1
    else
        campaign_recover_collection_bundle "$root" "$evidence_destination" "$journal_destination" \
            "$status_destination" "$label" || return 1
    fi
    local collection_status_staging_sha256 collection_status_staging_device
    local collection_status_staging_inode collection_status_staging_size collection_status_staging_content
    local collection_commit_staging_sha256 collection_commit_staging_device
    local collection_commit_staging_inode collection_commit_staging_size collection_commit_staging_content
    local publication_root_identity publication_root_remainder
    if ((content_bound)); then
        campaign_collection_read_bounded_file "$status_staging" "$absolute_deadline" 8388608 \
            collection_status_staging_sha256 collection_status_staging_content \
            collection_status_staging_device collection_status_staging_inode \
            collection_status_staging_size || return 1
        campaign_collection_read_bounded_file "$status_commit_staging" "$absolute_deadline" 1024 \
            collection_commit_staging_sha256 collection_commit_staging_content \
            collection_commit_staging_device collection_commit_staging_inode \
            collection_commit_staging_size || return 1
        [[ "$collection_status_staging_sha256" == "$preflight_status_sha256" &&
            "$collection_status_staging_content" == "$preflight_status_content" &&
            "$collection_status_staging_device:$collection_status_staging_inode:$collection_status_staging_size" == "$preflight_status_device:$preflight_status_inode:$preflight_status_size" ]] || return 1
        local status_commit_text
        status_commit_text="$(printf '%s' "$collection_commit_staging_content" |
            base64 --decode 2>/dev/null)" || return 1
        [[ -n "$status_commit_text" && "$status_commit_text" != *$'\n'* ]] || return 1
        local commit_version commit_scheme commit_snapshot commit_status_sha256 commit_extra
        IFS=$'\t' read -r commit_version commit_scheme commit_snapshot commit_status_sha256 commit_extra \
            <<<"$status_commit_text" || return 1
        [[ "$commit_version" == collection-status-commit-v1 &&
            "$commit_scheme" == unprivileged-sha256 &&
            "$commit_snapshot" == "$expected_evidence_snapshot" &&
            "$commit_status_sha256" == "$collection_status_staging_sha256" &&
            -z "$commit_extra" ]] || return 1
        publication_root_identity="$(stat -c '%d:%i:%u' "$root")" || return 1
        publication_root_remainder="${publication_root_identity#*:}"
    fi
    transaction="$(campaign_collection_transaction_path "$root" "${destinations[@]}")" || return 1
    commit_decision="$(campaign_collection_commit_path "$transaction")" || return 1
    campaign_assert_private_lock || return 1
    mkdir -m 0700 -- "$transaction" || return 1
    campaign_require_owned_real_directory "$transaction" "$label transaction" || return 1
    local transaction_identity transaction_remainder transaction_fd
    transaction_identity="$(stat -c '%d:%i:%u' "$transaction")" || return 1
    if declare -F campaign_collection_publication_hook >/dev/null 2>&1; then
        campaign_collection_publication_hook transaction-created "$transaction" || return 1
    fi
    # Appending `/.` makes path resolution require a directory before Bash
    # performs its read-only open, so a FIFO replacement cannot block here.
    exec {transaction_fd}<"$transaction/." || return 1
    [[ -d "/proc/$BASHPID/fd/$transaction_fd" && -d "$transaction" && ! -L "$transaction" &&
        "$(stat -Lc '%d:%i:%u' "/proc/$BASHPID/fd/$transaction_fd")" == "$transaction_identity" &&
        "$(stat -Lc '%d:%i:%u' "$transaction")" == "$transaction_identity" &&
        "$(stat -Lc %a "/proc/$BASHPID/fd/$transaction_fd")" == 700 ]] || {
        exec {transaction_fd}<&-
        return 1
    }
    CAMPAIGN_COLLECTION_TRANSACTION_FDS["$transaction"]="$transaction_fd"
    transaction_remainder="${transaction_identity#*:}"
    for ((index = 0; index < object_count; index++)); do
        destination="${destinations[$index]}"
        local kind=file
        ((index < 2)) && kind=directory
        campaign_assert_private_lock || return 1
        if [[ -e "$destination" || -L "$destination" ]]; then
            campaign_collection_write_exclusive_marker "$transaction" "$transaction/had-$index" \
                $'present\n' "${transaction_identity%%:*}" "${transaction_remainder%%:*}" \
                "${transaction_identity##*:}" || return 1
            campaign_collection_record_object_identity "$destination" \
                "$transaction/old-$index.identity" "$kind" "$label original destination" \
                "${transaction_identity%%:*}" "${transaction_remainder%%:*}" \
                "${transaction_identity##*:}" || return 1
        else
            campaign_collection_write_exclusive_marker "$transaction" "$transaction/had-$index" \
                $'absent\n' "${transaction_identity%%:*}" "${transaction_remainder%%:*}" \
                "${transaction_identity##*:}" || return 1
        fi
        campaign_collection_record_object_identity "${stagings[$index]}" \
            "$transaction/new-$index.identity" "$kind" "$label staged destination" \
            "${transaction_identity%%:*}" "${transaction_remainder%%:*}" \
            "${transaction_identity##*:}" || return 1
    done
    sync -f "$transaction" 2>/dev/null || true
    for ((index = 0; index < object_count; index++)); do
        destination="${destinations[$index]}"
        [[ -e "$destination" || -L "$destination" ]] || continue
        backup="$transaction/old-$index"
        campaign_collection_require_destination_identity "$destination" \
            "$transaction/old-$index.identity" "$label original destination" || return 1
        campaign_assert_private_lock || return 1
        campaign_rename_noreplace "$destination" "$backup" || return 1
        campaign_collection_require_destination_identity "$backup" \
            "$transaction/old-$index.identity" "$label transaction backup" || return 1
        if declare -F campaign_collection_publication_hook >/dev/null 2>&1; then
            campaign_collection_publication_hook "backup-$index" "$transaction" || return 1
        fi
    done
    for ((index = 0; index < object_count; index++)); do
        if declare -F campaign_collection_publication_hook >/dev/null 2>&1; then
            campaign_collection_publication_hook "before-promote-$index" "$transaction" || return 1
        fi
        if ((content_bound && index == 0)); then
            campaign_collection_generation_matches "${stagings[0]}" "$expected_evidence_snapshot" \
                "$absolute_deadline" "$validator" || return 1
        fi
        campaign_collection_require_destination_identity "${stagings[$index]}" \
            "$transaction/new-$index.identity" "$label staged destination" || return 1
        campaign_assert_private_lock || return 1
        if ((content_bound && index >= 2)); then
            local staged_sha256 staged_device staged_inode staged_size
            if ((index == 2)); then
                staged_sha256="$collection_status_staging_sha256"
                staged_device="$collection_status_staging_device"
                staged_inode="$collection_status_staging_inode"
                staged_size="$collection_status_staging_size"
            else
                staged_sha256="$collection_commit_staging_sha256"
                staged_device="$collection_commit_staging_device"
                staged_inode="$collection_commit_staging_inode"
                staged_size="$collection_commit_staging_size"
            fi
            campaign_identity_bound_replace_text "$root" "${stagings[$index]}" \
                "${destinations[$index]}" "${publication_root_identity%%:*}" \
                "${publication_root_remainder%%:*}" "$staged_sha256" "$staged_device" \
                "$staged_inode" "$staged_size" absent 0 0 || return 1
        else
            campaign_rename_noreplace "${stagings[$index]}" "${destinations[$index]}" || return 1
        fi
        campaign_collection_require_destination_identity "${destinations[$index]}" \
            "$transaction/new-$index.identity" "$label promoted destination" || return 1
        if ((content_bound && index == 0)); then
            campaign_collection_generation_matches "${destinations[0]}" "$expected_evidence_snapshot" \
                "$absolute_deadline" "$validator" || return 1
        fi
        if declare -F campaign_collection_publication_hook >/dev/null 2>&1; then
            campaign_collection_publication_hook "promote-$index" "$transaction" || return 1
        fi
    done
    if ((content_bound)); then
        campaign_collection_status_accepts_generation "$evidence_destination" "$status_destination" \
            "$absolute_deadline" "$validator" || return 1
    fi
    campaign_collection_write_exclusive_marker "$transaction" "$transaction/committed" \
        $'committed\n' "${transaction_identity%%:*}" "${transaction_remainder%%:*}" \
        "${transaction_identity##*:}" || return 1
    local root_identity root_remainder committed_identity committed_remainder committed_sha256
    local committed_size
    root_identity="$(stat -c '%d:%i:%u' "$root")" || return 1
    root_remainder="${root_identity#*:}"
    committed_staging="$root/.collection-commit.$BASHPID.$RANDOM.$RANDOM"
    campaign_assert_private_lock || return 1
    campaign_collection_write_exclusive_marker "$root" "$committed_staging" $'committed\n' \
        "${root_identity%%:*}" "${root_remainder%%:*}" "${root_identity##*:}" || return 1
    committed_identity="$(stat -c '%d:%i:%u' "$committed_staging")" || return 1
    committed_remainder="${committed_identity#*:}"
    committed_sha256="$(campaign_sha256 "$committed_staging")" || return 1
    committed_size="$(stat -c %s "$committed_staging")" || return 1
    campaign_assert_private_lock || return 1
    campaign_identity_bound_replace_text "$root" "$committed_staging" "$commit_decision" \
        "${root_identity%%:*}" "${root_remainder%%:*}" "$committed_sha256" \
        "${committed_identity%%:*}" "${committed_remainder%%:*}" "$committed_size" \
        absent 0 0 || return 1
    campaign_collection_rebind_marker_broker "$committed_staging" "$commit_decision" || return 1
    [[ "$(stat -Lc '%d:%i:%u' "$commit_decision")" == "$committed_identity" ]] || return 1
    if declare -F campaign_collection_publication_hook >/dev/null 2>&1; then
        campaign_collection_publication_hook committed "$transaction" || return 1
    fi
    campaign_collection_discard_committed_backups "$transaction" "$label" "$object_count" || return 1
    campaign_assert_private_lock || return 1
    campaign_collection_capture_and_remove "$commit_decision" file \
        "$label commit decision" || return 1
    campaign_collection_retire_live_marker "$commit_decision" || return 1
    campaign_assert_private_lock || return 1
    campaign_collection_capture_and_remove "$transaction" directory \
        "$label committed transaction" || return 1
    campaign_collection_release_transaction_authority "$transaction"
}
