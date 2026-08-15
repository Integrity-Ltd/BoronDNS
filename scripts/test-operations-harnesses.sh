#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1
workdir="$(mktemp -d "${TMPDIR:-/tmp}/borondns-operations-tests.XXXXXX")"
# Automatic-tree journals intentionally retain unauthenticated crash evidence.
# Keep every harness-created family below this per-run root so repeated test
# executions cannot poison shared /tmp families or consume the production cap.
mkdir -m 0700 "$workdir/tmp"
export TMPDIR="$workdir/tmp"
# Published privileged-runner paths are global under /var/tmp. Keep fixture
# units process-unique so concurrent local/CI check invocations cannot delete
# or replace each other's runner trees.
fixture_unit_suffix="$$"
lock_holder_pids=()
cleanup() {
    local pid
    for pid in "${lock_holder_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        kill -CONT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$workdir"
}
trap cleanup EXIT

remove_readonly_test_tree() {
    local path
    for path in "$@"; do
        [[ -e "$path" || -L "$path" ]] || continue
        sudo -n rm -rf -- "$path"
    done
}

# shellcheck source=scripts/interop-dns-assertions.sh
# shellcheck disable=SC1091
source "$repo_root/scripts/interop-dns-assertions.sh"
# shellcheck source=scripts/campaign-env.sh
source "$repo_root/scripts/campaign-env.sh"

# Every collection marker is created through a descriptor-bound exclusive open.
# A symlink inserted at the final creation boundary must neither be followed nor
# truncate its victim.
marker_race_root="$workdir/collection-marker-race"
mkdir -m 0700 "$marker_race_root"
printf 'marker victim must survive\n' >"$marker_race_root/victim"
marker_victim_hash="$(campaign_sha256 "$marker_race_root/victim")"
marker_root_identity="$(stat -c '%d:%i:%u' "$marker_race_root")"
marker_root_remainder="${marker_root_identity#*:}"
campaign_collection_marker_hook() {
    [[ "$1" != before-exclusive-create ]] || ln -s "$marker_race_root/victim" "$3"
}
if campaign_collection_write_exclusive_marker "$marker_race_root" \
    "$marker_race_root/had-0" $'present\n' "${marker_root_identity%%:*}" \
    "${marker_root_remainder%%:*}" "${marker_root_identity##*:}"; then
    printf 'collection marker writer followed a boundary symlink\n' >&2
    exit 1
fi
unset -f campaign_collection_marker_hook
[[ -L "$marker_race_root/had-0" &&
    "$(campaign_sha256 "$marker_race_root/victim")" == "$marker_victim_hash" ]]

# Marker authority must stay on the descriptor-safe creator broker; there is no
# pathname reopen after the same-UID hook. Direct FIFO, symlink-to-FIFO (a
# blocking target for ordinary read opens), and oversized exact-inode poisons
# are all rejected promptly before live authority is published.
mkfifo "$marker_race_root/blocking-target"
for marker_reopen_poison in fifo blocking-symlink oversized; do
    marker_reopen_path="$marker_race_root/reopen-$marker_reopen_poison"
    set +e
    # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
    timeout --kill-after=1 3 bash --noprofile --norc -c '
        set -euo pipefail
        source "$1/scripts/campaign-env.sh"
        marker_poison="$7"
        campaign_collection_marker_hook() {
            [[ "$1" == after-exclusive-create ]] || return 0
            if [[ "$marker_poison" == fifo ]]; then
                mv -- "$3" "$3.original"
                mkfifo "$3"
            elif [[ "$marker_poison" == blocking-symlink ]]; then
                mv -- "$3" "$3.original"
                ln -s "$2/blocking-target" "$3"
            else
                truncate -s 65537 "$3"
            fi
        }
        campaign_collection_write_exclusive_marker "$2" "$3" $'"'"'present\n'"'"' \
            "$4" "$5" "$6"
    ' _ "$repo_root" "$marker_race_root" "$marker_reopen_path" \
        "${marker_root_identity%%:*}" "${marker_root_remainder%%:*}" \
        "${marker_root_identity##*:}" "$marker_reopen_poison" \
        >"$workdir/marker-reopen-$marker_reopen_poison.out" \
        2>"$workdir/marker-reopen-$marker_reopen_poison.err"
    marker_reopen_status=$?
    set -e
    if ((marker_reopen_status == 0 || marker_reopen_status == 124 || \
        marker_reopen_status == 137)); then
        printf 'collection marker reacquisition accepted or blocked on %s replacement\n' \
            "$marker_reopen_poison" >&2
        exit 1
    fi
    rm -f -- "$marker_reopen_path" "$marker_reopen_path.original"
done
rm -f -- "$marker_race_root/blocking-target"

# A held regular-file fd binds an inode, not its mutable bytes. Live collection
# authority must therefore use the creation-time in-process payload even when a
# same-UID writer rewrites that exact inode and swaps the recorded object.
marker_content_root="$workdir/collection-marker-content-race"
mkdir -m 0700 "$marker_content_root"
printf 'recorded object\n' >"$marker_content_root/object"
printf 'foreign replacement must survive\n' >"$marker_content_root/foreign"
marker_content_path="$marker_content_root/object.identity"
campaign_collection_record_object_identity "$marker_content_root/object" \
    "$marker_content_path" file "collection mutable marker fixture"
mv "$marker_content_root/object" "$marker_content_root/object.original"
mv "$marker_content_root/foreign" "$marker_content_root/object"
marker_content_foreign_identity="$(stat -c '%d:%i:%u' "$marker_content_root/object")"
marker_content_foreign_remainder="${marker_content_foreign_identity#*:}"
printf 'kind=file\ndevice=%s\ninode=%s\nowner=%s\n' \
    "${marker_content_foreign_identity%%:*}" "${marker_content_foreign_remainder%%:*}" \
    "${marker_content_foreign_identity##*:}" >"$marker_content_path"
if campaign_collection_object_identity_matches "$marker_content_root/object" \
    "$marker_content_path" "collection mutable marker fixture"; then
    printf 'collection authority trusted mutable marker bytes after object swap\n' >&2
    exit 1
fi
grep -Fqx 'foreign replacement must survive' "$marker_content_root/object"
grep -Fqx 'recorded object' "$marker_content_root/object.original"
campaign_collection_retire_live_marker "$marker_content_path"

# A stopped descriptor broker must be killed and reaped within its bounded
# absolute cleanup deadline rather than stranding the collection forever.
marker_stop_path="$marker_content_root/stopped.identity"
campaign_collection_record_object_identity "$marker_content_root/object.original" \
    "$marker_stop_path" file "stopped collection marker broker fixture"
marker_stop_pid="${CAMPAIGN_COLLECTION_MARKER_PIDS[$marker_stop_path]}"
kill -STOP "$marker_stop_pid"
marker_stop_started="$(date +%s%N)"
campaign_collection_stop_marker_broker "$marker_stop_path"
marker_stop_elapsed=$((($(date +%s%N) - marker_stop_started) / 1000000))
((marker_stop_elapsed < 3000))
[[ ! -e "/proc/$marker_stop_pid" ]]

# Transaction authority is rebound through a directory-only path. Replacing
# the freshly created directory with a FIFO must fail promptly before any
# destination is backed up or staging object promoted.
transaction_fifo_root="$workdir/collection-transaction-fifo"
mkdir -m 0700 "$transaction_fifo_root" "$transaction_fifo_root/evidence-new" \
    "$transaction_fifo_root/journal-new"
printf 'new status\n' >"$transaction_fifo_root/status-new"
set +e
# shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
timeout --kill-after=1 5 bash --noprofile --norc -c '
    set -euo pipefail
    source "$1/scripts/campaign-env.sh"
    campaign_acquire_private_lock "$2" "$2:transaction-fifo" "transaction FIFO fixture"
    campaign_collection_publication_hook() {
        [[ "$1" == transaction-created ]] || return 0
        mv -- "$2" "$2.original"
        mkfifo "$2"
    }
    campaign_publish_collection_bundle "$2" \
        "$2/evidence-new" "$2/evidence" "$2/journal-new" "$2/journal" \
        "$2/status-new" "$2/status" "transaction FIFO fixture"
' _ "$repo_root" "$transaction_fifo_root" \
    >"$workdir/transaction-fifo.out" 2>"$workdir/transaction-fifo.err"
transaction_fifo_status=$?
set -e
if ((transaction_fifo_status == 0 || transaction_fifo_status == 124 || \
    transaction_fifo_status == 137)); then
    printf 'collection transaction reacquisition accepted or blocked on a FIFO replacement\n' >&2
    exit 1
fi
transaction_fifo_path="$(find "$transaction_fifo_root" -mindepth 1 -maxdepth 1 \
    -type p -name '.collection-transaction-*' -print -quit)"
[[ -n "$transaction_fifo_path" && -d "$transaction_fifo_path.original" &&
    -d "$transaction_fifo_root/evidence-new" && -d "$transaction_fifo_root/journal-new" &&
    -f "$transaction_fifo_root/status-new" && ! -e "$transaction_fifo_root/evidence" &&
    ! -e "$transaction_fifo_root/journal" && ! -e "$transaction_fifo_root/status" ]]

publish_test_root_runner() {
    local unit="$1" candidate="$2" label="$3"
    local test_runner_candidate_sha256="" test_runner_candidate_device="" test_runner_candidate_inode=""
    campaign_capture_candidate_identity "$candidate" test_runner_candidate || return 1
    campaign_publish_root_runner "$unit" "$candidate" \
        "$test_runner_candidate_sha256" "$test_runner_candidate_device" "$test_runner_candidate_inode" "$label"
}

# The review worktree may contain the new lock helper before it is committed.
# Remote-repository fixtures still need the exact helper files while retaining
# the clean-HEAD semantics exercised by the generated launch commands.
materialize_campaign_helpers() {
    local fixture_repo="$1" relative
    for relative in scripts/campaign-env.sh scripts/campaign-lock-helper.py; do
        if git -C "$fixture_repo" ls-files --error-unmatch -- "$relative" >/dev/null 2>&1; then
            git -C "$fixture_repo" update-index --no-assume-unchanged -- "$relative"
            if ! cmp -s "$repo_root/$relative" "$fixture_repo/$relative"; then
                install -D -m "$(stat -c %a "$repo_root/$relative")" "$repo_root/$relative" "$fixture_repo/$relative"
                git -C "$fixture_repo" update-index --assume-unchanged -- "$relative"
            fi
        else
            install -D -m "$(stat -c %a "$repo_root/$relative")" "$repo_root/$relative" "$fixture_repo/$relative"
            printf '/%s\n' "$relative" >>"$fixture_repo/.git/info/exclude"
        fi
    done
}

test_cargo_sha256="$(campaign_sha256 "$(rustup which cargo)")"
test_rustc_sha256="$(campaign_sha256 "$(rustup which rustc)")"
test_cargo_fuzz_path="$(command -v cargo-fuzz 2>/dev/null || true)"
[[ -n "$test_cargo_fuzz_path" ]] || test_cargo_fuzz_path="${CARGO_HOME:-$HOME/.cargo}/bin/cargo-fuzz"
test_cargo_fuzz_sha256="$(campaign_sha256 "$(realpath -e "$test_cargo_fuzz_path")")"
fuzz_validator_policy=(
    --expected-toolchain default --expected-sanitizer cargo-fuzz-default
    --expected-cargo-sha256 "$test_cargo_sha256"
    --expected-rustc-sha256 "$test_rustc_sha256"
    --expected-cargo-fuzz-sha256 "$test_cargo_fuzz_sha256"
)
soak_validator_policy=(
    --expected-scenario-timeout 1
    --expected-scenario-kill-after 1
    --expected-docker-cleanup-timeout 1
    --expected-cycle-sleep 1
    --expected-sample-interval 1
    --expected-allow-skip 1
    --expected-cargo-sha256 "$test_cargo_sha256"
    --expected-rustc-sha256 "$test_rustc_sha256"
)

start_test_campaign_lock() {
    local root="$1" namespace="$2" ready="$3" release="$4"
    (
        unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_path campaign_lock_label
        campaign_acquire_private_lock "$root" "$namespace" "operations test lock"
        : >"$ready"
        while [[ ! -e "$release" ]]; do
            sleep 0.01
        done
        campaign_release_private_lock
    ) &
    lock_holder_pid=$!
    lock_holder_pids+=("$lock_holder_pid")
    local deadline=$((SECONDS + 5))
    until [[ -e "$ready" ]]; do
        kill -0 "$lock_holder_pid" 2>/dev/null || {
            wait "$lock_holder_pid" 2>/dev/null || true
            printf 'test campaign lock holder exited before readiness\n' >&2
            exit 1
        }
        ((SECONDS < deadline)) || {
            printf 'test campaign lock holder timed out before readiness\n' >&2
            exit 1
        }
        sleep 0.01
    done
}

stop_test_campaign_lock() {
    local release="$1" pid="$2"
    : >"$release"
    wait "$pid"
    local index
    for index in "${!lock_holder_pids[@]}"; do
        [[ "${lock_holder_pids[$index]}" != "$pid" ]] || lock_holder_pids[index]=""
    done
}

untrack_test_process() {
    local pid="$1" index
    for index in "${!lock_holder_pids[@]}"; do
        [[ "${lock_holder_pids[$index]}" != "$pid" ]] || lock_holder_pids[index]=""
    done
}

make_soak_sampler_fixture() {
    local root="$1" start="$2" deadline="$3" interval="$4"
    local attempt="$root/resource-sampler-attempts/attempt-0001"
    local start_utc deadline_utc
    start_utc="$(date -u -d "@$start" '+%Y-%m-%dT%H:%M:%SZ')"
    deadline_utc="$(date -u -d "@$deadline" '+%Y-%m-%dT%H:%M:%SZ')"
    mkdir -p "$attempt"
    printf '%s\n' \
        "started_utc=$start_utc" \
        "started_epoch_seconds=$start" \
        "deadline_epoch_seconds=$deadline" \
        "sample_interval_seconds=$interval" >"$attempt/resource-sampler.env"
    printf '%s\n' \
        $'timestamp_utc\tepoch_seconds\tload1\tload5\tload15\tmem_available_kib\tdocker_containers\tborondns_processes\ttotal_borondns_rss_kib' \
        "$(printf '%s\t%s\t0.1\t0.1\t0.1\t1024\t0\t0\t0' "$start_utc" "$start")" \
        "$(printf '%s\t%s\t0.1\t0.1\t0.1\t1024\t0\t0\t0' "$deadline_utc" "$deadline")" \
        >"$attempt/resource-samples.tsv"
    printf '%s\n' $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
        >"$attempt/process-samples.tsv"
    printf '%s\n' status=passed "completed_utc=$deadline_utc" "completed_epoch_seconds=$deadline" \
        "deadline_epoch_seconds=$deadline" "last_sample_epoch_seconds=$deadline" \
        >"$attempt/resource-sampler-completed.env"
}

campaign_scp_remote_path_is_safe /tmp/borondns-safe/path
[[ "$(campaign_remote_copy_host host.example)" == host.example ]]
[[ "$(campaign_remote_copy_host user@host.example)" == user@host.example ]]
[[ "$(campaign_remote_copy_host 2001:db8::53)" == '[2001:db8::53]' ]]
[[ "$(campaign_remote_copy_host user@2001:db8::53)" == 'user@[2001:db8::53]' ]]
if campaign_remote_copy_host user@host@example >/dev/null; then
    printf 'remote copy host formatter accepted multiple user separators\n' >&2
    exit 1
fi
# These are deliberately literal remote-shell metacharacter fixtures.
# shellcheck disable=SC2016
for hostile_scp_path in "/tmp/space path" '/tmp/semi;colon' '/tmp/$(touch-pwned)' '/tmp/back`tick'; do
    if campaign_scp_remote_path_is_safe "$hostile_scp_path"; then
        printf 'scp fallback accepted a remote-shell-sensitive path: %s\n' "$hostile_scp_path" >&2
        exit 1
    fi
done

transport_bin="$workdir/transport-bin"
transport_log="$workdir/transport.log"
mkdir "$transport_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "ssh %s\n" "$*" >>"$TRANSPORT_LOG"' 'sleep 30' \
    >"$transport_bin/ssh"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "rsync %s\n" "$*" >>"$TRANSPORT_LOG"' 'exit 0' \
    >"$transport_bin/rsync"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "scp %s\n" "$*" >>"$TRANSPORT_LOG"' 'exit 0' \
    >"$transport_bin/scp"
chmod +x "$transport_bin/ssh" "$transport_bin/rsync" "$transport_bin/scp"
transport_started="$SECONDS"
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_log" campaign_ssh_bounded 1 -- h1 true; then
    printf 'bounded SSH transport accepted a peer that exceeded its operation timeout\n' >&2
    exit 1
fi
((SECONDS - transport_started < 10))
grep -Fq 'ConnectTimeout=15' "$transport_log"
grep -Fq 'ServerAliveInterval=15' "$transport_log"
grep -Fq 'ServerAliveCountMax=3' "$transport_log"
PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_log" campaign_rsync_bounded 2 -a -- h1:/source/ /target/
PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_log" campaign_scp_bounded 2 -r -- h1:/source/. /target/
grep -Fq 'rsync --timeout=120 -e ssh -o BatchMode=yes -o ConnectTimeout=15' "$transport_log"
grep -Fq 'scp -o BatchMode=yes -o ConnectTimeout=15' "$transport_log"

# Every numeric transport control is bounded before timeout(1), ssh, scp, or
# rsync can see it. Overflow-sized hostile inputs must not invoke even the fake
# transports used by this harness.
transport_overflow_log="$workdir/transport-overflow.log"
transport_overflow_value=999999999999999999999999999999
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    campaign_ssh_bounded "$transport_overflow_value" -- h1 true >/dev/null 2>&1; then
    printf 'bounded SSH transport accepted an overflow-sized operation timeout\n' >&2
    exit 1
fi
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    campaign_scp_bounded "$transport_overflow_value" -r -- h1:/source/. /target/ >/dev/null 2>&1; then
    printf 'bounded SCP transport accepted an overflow-sized operation timeout\n' >&2
    exit 1
fi
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    campaign_rsync_bounded "$transport_overflow_value" -a -- h1:/source/ /target/ >/dev/null 2>&1; then
    printf 'bounded rsync transport accepted an overflow-sized operation timeout\n' >&2
    exit 1
fi
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    BORONDNS_CAMPAIGN_SSH_CONNECT_TIMEOUT_SECONDS="$transport_overflow_value" \
    campaign_ssh_bounded 1 -- h1 true >/dev/null 2>&1; then
    printf 'bounded SSH transport accepted an overflow-sized connect timeout\n' >&2
    exit 1
fi
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    BORONDNS_CAMPAIGN_SSH_ALIVE_INTERVAL_SECONDS="$transport_overflow_value" \
    campaign_scp_bounded 1 -r -- h1:/source/. /target/ >/dev/null 2>&1; then
    printf 'bounded SCP transport accepted an overflow-sized alive interval\n' >&2
    exit 1
fi
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    BORONDNS_CAMPAIGN_SSH_ALIVE_COUNT_MAX="$transport_overflow_value" \
    campaign_ssh_bounded 1 -- h1 true >/dev/null 2>&1; then
    printf 'bounded SSH transport accepted an overflow-sized alive count\n' >&2
    exit 1
fi
if PATH="$transport_bin:$PATH" TRANSPORT_LOG="$transport_overflow_log" \
    BORONDNS_CAMPAIGN_RSYNC_IDLE_TIMEOUT_SECONDS="$transport_overflow_value" \
    campaign_rsync_bounded 1 -a -- h1:/source/ /target/ >/dev/null 2>&1; then
    printf 'bounded rsync transport accepted an overflow-sized idle timeout\n' >&2
    exit 1
fi
[[ ! -e "$transport_overflow_log" ]]

# Pin exact accepted maxima and reject their immediate successors without
# handing them to a transport. This prevents accidental widening during edits.
campaign_require_transport_integer operation-timeout 86400 86400
campaign_require_transport_integer connect-timeout 300 300
campaign_require_transport_integer alive-interval 300 300
campaign_require_transport_integer alive-count 100 100
campaign_require_transport_integer rsync-idle-timeout 3600 3600
for transport_bound_fixture in \
    'operation-timeout 86401 86400' \
    'connect-timeout 301 300' \
    'alive-interval 301 300' \
    'alive-count 101 100' \
    'rsync-idle-timeout 3601 3600'; do
    # shellcheck disable=SC2086 # Deliberately split the exact three-field fixture.
    if campaign_require_transport_integer $transport_bound_fixture >/dev/null 2>&1; then
        printf 'campaign transport accepted an input above its exact bound: %s\n' \
            "$transport_bound_fixture" >&2
        exit 1
    fi
done

lock_security_root="$workdir/local-lock-security"
mkdir -m 0700 "$lock_security_root"
lock_namespace="$lock_security_root/evidence:runner"
lock_digest="$(printf '%s' "$lock_namespace" | sha256sum | awk '{ print $1 }')"
lock_private_root="$lock_security_root/.borondns-campaign-locks"
mkdir -m 0700 "$lock_private_root"
lock_path="$lock_private_root/$lock_digest.lock"
lock_victim="$workdir/local-lock-victim"
printf 'local lock victim sentinel\n' >"$lock_victim"
lock_victim_hash="$(sha256sum "$lock_victim")"
ln -s "$lock_victim" "$lock_path"
if (campaign_acquire_private_lock "$lock_security_root" "$lock_namespace" "symlink lock fixture"); then
    printf 'campaign lock helper accepted a symlink lock\n' >&2
    exit 1
fi
[[ "$lock_victim_hash" == "$(sha256sum "$lock_victim")" ]]

rm "$lock_path"
mkfifo "$lock_path"
# The single-quoted script is intentionally expanded only by the child shell.
# shellcheck disable=SC2016
if timeout 5 bash --noprofile --norc -c '
    set -euo pipefail
    source "$1/scripts/campaign-env.sh"
    campaign_acquire_private_lock "$2" "$3" "FIFO lock fixture"
' _ "$repo_root" "$lock_security_root" "$lock_namespace"; then
    printf 'campaign lock helper accepted a FIFO lock\n' >&2
    exit 1
fi
rm "$lock_path"

authenticated_helper_dir="$workdir/authenticated-helper-fds"
authenticated_helper_marker="$workdir/authenticated-helper-path-executed"
mkdir "$authenticated_helper_dir"
cp "$repo_root/scripts/campaign-env.sh" "$authenticated_helper_dir/campaign-env.sh"
cp "$repo_root/scripts/campaign-lock-helper.py" "$authenticated_helper_dir/campaign-lock-helper.py"
(
    exec {authenticated_env_fd}<"$authenticated_helper_dir/campaign-env.sh"
    exec {authenticated_lock_fd}<"$authenticated_helper_dir/campaign-lock-helper.py"
    authenticated_env_snapshot_b64="$(base64 -w0 "/proc/self/fd/$authenticated_env_fd")"
    authenticated_lock_snapshot_b64="$(base64 -w0 "/proc/self/fd/$authenticated_lock_fd")"
    authenticated_env_sha="$(printf '%s' "$authenticated_env_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')"
    authenticated_lock_sha="$(printf '%s' "$authenticated_lock_snapshot_b64" | base64 --decode | sha256sum | awk '{ print $1 }')"
    [[ "$authenticated_env_sha" == "$(campaign_sha256 "$repo_root/scripts/campaign-env.sh")" ]]
    [[ "$authenticated_lock_sha" == "$(campaign_sha256 "$repo_root/scripts/campaign-lock-helper.py")" ]]
    # Mutate the already-open inodes in place after authentication.  Executing
    # either live descriptor would create the marker; immutable snapshots must
    # retain the authenticated bytes instead.
    printf 'touch %q\n' "$authenticated_helper_marker" >"$authenticated_helper_dir/campaign-env.sh"
    printf 'from pathlib import Path\nPath("%s").touch()\n' "$authenticated_helper_marker" \
        >"$authenticated_helper_dir/campaign-lock-helper.py"
    [[ "$(sha256sum "/proc/self/fd/$authenticated_env_fd" | awk '{ print $1 }')" != "$authenticated_env_sha" ]]
    [[ "$(sha256sum "/proc/self/fd/$authenticated_lock_fd" | awk '{ print $1 }')" != "$authenticated_lock_sha" ]]
    exec {authenticated_env_fd}<&-
    exec {authenticated_lock_fd}<&-
    # shellcheck source=/dev/null
    source <(printf '%s' "$authenticated_env_snapshot_b64" | base64 --decode)
    # shellcheck disable=SC2030 # The authenticated helper binding is intentionally local to this fixture subshell.
    BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$authenticated_lock_snapshot_b64"
    export BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64
    campaign_acquire_private_lock "$lock_security_root" "$lock_namespace:authenticated-fd" \
        "authenticated descriptor fixture"
    campaign_release_private_lock
)
[[ ! -e "$authenticated_helper_marker" ]]

writable_lock_root="$workdir/world-writable-lock-root"
mkdir -m 0777 "$writable_lock_root"
if (campaign_acquire_private_lock "$writable_lock_root" "$writable_lock_root/evidence:runner" "writable-parent fixture"); then
    printf 'campaign lock helper accepted a world-writable parent\n' >&2
    exit 1
fi
[[ ! -e "$writable_lock_root/.borondns-campaign-locks" ]]

swap_lock_root="$workdir/swap-lock-root"
mkdir -m 0700 "$swap_lock_root" "$swap_lock_root/.borondns-campaign-locks"
swap_namespace="$swap_lock_root/evidence:runner"
swap_digest="$(printf '%s' "$swap_namespace" | sha256sum | awk '{ print $1 }')"
swap_lock="$swap_lock_root/.borondns-campaign-locks/$swap_digest.lock"
swap_stop="$workdir/swap-lock-stop"
(
    while [[ ! -e "$swap_stop" ]]; do
        rm -f "$swap_lock"
        ln -s "$lock_victim" "$swap_lock" 2>/dev/null || true
    done
) &
swap_pid=$!
for _ in {1..32}; do
    if (campaign_acquire_private_lock "$swap_lock_root" "$swap_namespace" "swap fixture"); then
        campaign_release_private_lock
    fi
done
: >"$swap_stop"
wait "$swap_pid"
[[ "$lock_victim_hash" == "$(sha256sum "$lock_victim")" ]]

broker_crash_root="$workdir/broker-crash-root"
mkdir -m 0700 "$broker_crash_root"
campaign_acquire_private_lock "$broker_crash_root" broker-crash "broker crash fixture"
kill "$campaign_lock_pid"
wait "$campaign_lock_pid" 2>/dev/null || true
if campaign_assert_private_lock; then
    printf 'campaign mutation boundary accepted a dead lock broker\n' >&2
    exit 1
fi
campaign_release_private_lock

handshake_helper="$workdir/handshake-stall-helper.py"
printf '%s\n' 'import time' 'time.sleep(30)' >"$handshake_helper"
chmod 0600 "$handshake_helper"
handshake_started=$SECONDS
if BORONDNS_CAMPAIGN_LOCK_HELPER="$handshake_helper" BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS=1 \
    campaign_acquire_private_lock "$broker_crash_root" handshake-stall "handshake stall fixture"; then
    printf 'campaign lock accepted a broker that stalled during handshake\n' >&2
    exit 1
fi
handshake_elapsed=$((SECONDS - handshake_started))
((handshake_elapsed >= 1 && handshake_elapsed <= 4)) || {
    printf 'campaign lock handshake timeout was not bounded: %s seconds\n' "$handshake_elapsed" >&2
    exit 1
}
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" ]]

# A heartbeat timeout bounds one protocol exchange, not the lifetime of a lock
# whose caller supplied no operation deadline.
campaign_acquire_private_lock "$broker_crash_root" default-lifetime \
    "default lifetime fixture"
sleep 6
campaign_assert_private_lock
campaign_release_private_lock

# Lock broker descriptors are inherited across Bash fork boundaries, but the
# acquiring BASHPID is the only process allowed to assert, abandon, or release
# that authority. Child cleanup must detach only its copied descriptors.
campaign_acquire_private_lock "$broker_crash_root" inherited-release \
    "inherited release fixture"
inherited_parent_broker="$campaign_lock_pid"
inherited_parent_starttime="$campaign_lock_starttime"
[[ "$campaign_lock_owner_pid" == "$BASHPID" && -n "$inherited_parent_starttime" ]]
(
    campaign_release_private_lock
    [[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" &&
        -z "${campaign_lock_response_fd:-}" && -z "${campaign_lock_owner_pid:-}" ]]
)
kill -0 "$inherited_parent_broker"
campaign_assert_private_lock
(
    if campaign_assert_private_lock; then
        printf 'inherited child asserted its parent lock authority\n' >&2
        exit 1
    fi
    [[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" &&
        -z "${campaign_lock_response_fd:-}" && -z "${campaign_lock_owner_pid:-}" ]]
)
kill -0 "$inherited_parent_broker"
campaign_assert_private_lock
inherited_release_state="$(
    campaign_abandon_private_lock
    printf '%s:%s:%s' "${campaign_lock_pid:-}" "${campaign_lock_control_fd:-}" \
        "${campaign_lock_response_fd:-}"
)"
[[ "$inherited_release_state" == :: ]]
kill -0 "$inherited_parent_broker"
campaign_assert_private_lock
campaign_release_private_lock

# A stale/reused numeric PID is not broker authority. The recorded process
# starttime must match before any termination signal is sent.
sleep 30 &
broker_pid_reuse_sentinel=$!
broker_pid_reuse_starttime=""
campaign_process_starttime "$broker_pid_reuse_sentinel" broker_pid_reuse_starttime
campaign_lock_pid="$broker_pid_reuse_sentinel"
campaign_lock_starttime=$((broker_pid_reuse_starttime + 1))
campaign_lock_owner_pid="$BASHPID"
campaign_lock_label="broker PID reuse sentinel fixture"
campaign_abandon_private_lock
kill -0 "$broker_pid_reuse_sentinel"
kill "$broker_pid_reuse_sentinel"
wait "$broker_pid_reuse_sentinel" 2>/dev/null || true

# The generic child terminator is also pidfd-bound. A stopped TERM-ignoring
# creator receives TERM+CONT through that descriptor, then KILL+CONT if needed.
bash --noprofile --norc -c 'trap "" TERM; kill -STOP $$; while :; do sleep 1; done' &
pidfd_stopped_child=$!
pidfd_stopped_deadline=$((SECONDS + 5))
until [[ "$(sed -n 's/^[^)]*) \([A-Z]\).*/\1/p' "/proc/$pidfd_stopped_child/stat" 2>/dev/null)" == T ]]; do
    ((SECONDS < pidfd_stopped_deadline)) || {
        printf 'pidfd stopped-child fixture did not stop\n' >&2
        exit 1
    }
    sleep 0.01
done
pidfd_stopped_starttime=""
campaign_process_starttime "$pidfd_stopped_child" pidfd_stopped_starttime
campaign_terminate_child_before_deadline "$pidfd_stopped_child" \
    "$(campaign_deadline_from_timeout_seconds 2)" 'pidfd stopped child fixture' \
    "$pidfd_stopped_starttime"
if kill -0 "$pidfd_stopped_child" 2>/dev/null; then
    printf 'pidfd stopped-child fixture remained alive after termination\n' >&2
    exit 1
fi

# Unsupported pidfd operation and an authenticated identity mismatch are both
# hard failures that send no signal and leave the unrelated process alive.
sleep 30 &
pidfd_fail_closed_child=$!
pidfd_fail_closed_starttime=""
campaign_process_starttime "$pidfd_fail_closed_child" pidfd_fail_closed_starttime
if BORONDNS_CAMPAIGN_TEST_DISABLE_PIDFD=1 \
    campaign_terminate_child_before_deadline "$pidfd_fail_closed_child" \
    "$(campaign_deadline_from_timeout_seconds 2)" 'pidfd unsupported fixture' \
    "$pidfd_fail_closed_starttime"; then
    printf 'pidfd terminator fell back after unsupported pidfd operation\n' >&2
    exit 1
fi
kill -0 "$pidfd_fail_closed_child"
if campaign_terminate_child_before_deadline "$pidfd_fail_closed_child" \
    "$(campaign_deadline_from_timeout_seconds 2)" 'pidfd mismatch fixture' \
    "$((pidfd_fail_closed_starttime + 1))"; then
    printf 'pidfd terminator accepted a mismatched bound process identity\n' >&2
    exit 1
fi
kill -0 "$pidfd_fail_closed_child"
kill "$pidfd_fail_closed_child"
wait "$pidfd_fail_closed_child" 2>/dev/null || true

# The supervisor itself reads a here-document, but the supervised command must
# receive the caller's stdin byte-for-byte, observe the caller's EOF, and retain
# its own exit status. Include NUL and non-UTF-8 bytes so text substitution
# cannot accidentally satisfy this contract.
deadline_stdin_expected="$workdir/deadline-stdin.expected"
deadline_stdin_actual="$workdir/deadline-stdin.actual"
deadline_stdin_eof="$workdir/deadline-stdin.eof"
python3 -c 'import os; os.write(1, b"\x00BoronDNS\xff\r\nlast")' \
    >"$deadline_stdin_expected"
deadline_stdin_status=0
python3 -c 'import os; os.write(1, b"\x00BoronDNS\xff\r\nlast")' |
    campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 5)" \
        python3 -c '
import os
import sys

payload = sys.stdin.buffer.read()
with open(sys.argv[1], "xb") as output:
    output.write(payload)
    output.flush()
    os.fsync(output.fileno())
with open(sys.argv[2], "x", encoding="ascii") as marker:
    marker.write("eof\n")
    marker.flush()
    os.fsync(marker.fileno())
raise SystemExit(37)
' "$deadline_stdin_actual" "$deadline_stdin_eof" || deadline_stdin_status=$?
if ((deadline_stdin_status != 37)) || ! cmp -s "$deadline_stdin_expected" "$deadline_stdin_actual" ||
    [[ "$(<"$deadline_stdin_eof")" != eof ]]; then
    printf 'deadline supervisor did not preserve stdin bytes, EOF, and exit status\n' >&2
    exit 1
fi

# Expiry while a stdin-consuming command is alive must still kill and reap its
# process group; the retained input descriptor is not cancellation authority.
deadline_stdin_timeout_pid="$workdir/deadline-stdin-timeout.pid"
deadline_stdin_timeout_status=0
printf x | campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 1)" \
    python3 -c '
import os
import sys
import time

if sys.stdin.buffer.read(1) != b"x":
    raise SystemExit(72)
with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_stdin_timeout_pid" || deadline_stdin_timeout_status=$?
if ((deadline_stdin_timeout_status != 124)); then
    printf 'deadline stdin timeout returned %s instead of 124\n' \
        "$deadline_stdin_timeout_status" >&2
    exit 1
fi
deadline_stdin_timeout_child="$(<"$deadline_stdin_timeout_pid")"
[[ "$deadline_stdin_timeout_child" =~ ^[1-9][0-9]*$ &&
    ! -e "/proc/$deadline_stdin_timeout_child" ]]

# Fault-injected delayed reaping must consume only the explicit termination
# tail. The supervisor returns an indeterminate cleanup status instead of
# entering an unconditional waitpid after the operation deadline.
deadline_delayed_reap_pid="$workdir/deadline-delayed-reap.pid"
deadline_delayed_reap_started="$(date +%s%N)"
deadline_delayed_reap_status=0
BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS=1 \
    BORONDNS_CAMPAIGN_DEADLINE_TEST_DELAY_REAP=1 \
    campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 1)" \
    python3 -c '
import os
import sys
import time

with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_delayed_reap_pid" 2>"$workdir/deadline-delayed-reap.err" ||
    deadline_delayed_reap_status=$?
deadline_delayed_reap_elapsed=$((($(date +%s%N) - deadline_delayed_reap_started) / 1000000))
if ((deadline_delayed_reap_status != 125 || deadline_delayed_reap_elapsed < 1500 || \
    deadline_delayed_reap_elapsed > 4000)); then
    printf 'delayed-reap deadline returned status=%s elapsed_ms=%s\n' \
        "$deadline_delayed_reap_status" "$deadline_delayed_reap_elapsed" >&2
    exit 1
fi
grep -Fq 'cleanup tail expired after operation deadline; SIGKILL remains pending' \
    "$workdir/deadline-delayed-reap.err"
deadline_delayed_reap_child="$(<"$deadline_delayed_reap_pid")"
deadline_delayed_reap_wait=$((SECONDS + 3))
while [[ -e "/proc/$deadline_delayed_reap_child" &&
    $SECONDS -lt $deadline_delayed_reap_wait ]]; do
    sleep 0.01
done
[[ ! -e "/proc/$deadline_delayed_reap_child" ]]

# A procfs walk used to decide whether the unreaped leader still anchors live
# group members must itself remain inside the explicit cleanup tail.  Delay the
# walk before it can yield even one entry; the scan worker is killed by its
# CLOCK_BOOTTIME timerfd and the supervisor reports indeterminate cleanup
# without waiting for the injected delay.
deadline_slow_proc_python="$workdir/deadline-slow-proc-python"
deadline_slow_proc_pid="$workdir/deadline-slow-proc-child.pid"
mkdir "$deadline_slow_proc_python"
printf '%s\n' \
    'import os, time' \
    '_real_scandir = os.scandir' \
    'def _slow_scandir(path):' \
    '    if path == "/proc":' \
    '        time.sleep(3)' \
    '    return _real_scandir(path)' \
    'os.scandir = _slow_scandir' >"$deadline_slow_proc_python/sitecustomize.py"
deadline_slow_proc_started="$(date +%s%N)"
deadline_slow_proc_status=0
PYTHONPATH="$deadline_slow_proc_python" \
    BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS=1 \
    campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 1)" \
    python3 -c '
import os
import sys
import time
with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_slow_proc_pid" 2>"$workdir/deadline-slow-proc.err" ||
    deadline_slow_proc_status=$?
deadline_slow_proc_elapsed=$((($(date +%s%N) - deadline_slow_proc_started) / 1000000))
if ((deadline_slow_proc_status != 125 || deadline_slow_proc_elapsed < 1500 || \
    deadline_slow_proc_elapsed > 3000)); then
    printf 'slow-proc deadline returned status=%s elapsed_ms=%s\n' \
        "$deadline_slow_proc_status" "$deadline_slow_proc_elapsed" >&2
    exit 1
fi
grep -Fq 'cleanup tail expired after operation deadline; SIGKILL remains pending' \
    "$workdir/deadline-slow-proc.err"

# The production hard cap is Linux pid_max. A narrow test-only cap exercises
# the same fail-tail path without creating millions of processes.
deadline_proc_cap_started="$(date +%s%N)"
deadline_proc_cap_status=0
BORONDNS_CAMPAIGN_DEADLINE_TEST_PROC_ENTRY_CAP=1 \
    BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS=1 \
    campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 1)" \
    sleep 30 2>"$workdir/deadline-proc-cap.err" || deadline_proc_cap_status=$?
deadline_proc_cap_elapsed=$((($(date +%s%N) - deadline_proc_cap_started) / 1000000))
if ((deadline_proc_cap_status != 125 || deadline_proc_cap_elapsed > 2500)); then
    printf 'proc-cap deadline returned status=%s elapsed_ms=%s\n' \
        "$deadline_proc_cap_status" "$deadline_proc_cap_elapsed" >&2
    exit 1
fi

# The deadline supervisor keeps the exited leader unreaped as the numeric PGID
# authority until every in-group descendant has observed SIGKILL. This fixture's
# descendant ignores TERM and outlives its leader, but may not outlive a
# successful supervisor return.
group_descendant_pid_file="$workdir/deadline-group-descendant.pid"
campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 5)" \
    python3 -c '
import os
import signal
import sys
import time

pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open(sys.argv[1], "w", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
        output.flush()
        os.fsync(output.fileno())
    while True:
        time.sleep(1)
deadline = time.monotonic() + 2
while not os.path.exists(sys.argv[1]):
    if time.monotonic() >= deadline:
        raise SystemExit(71)
    time.sleep(0.01)
' "$group_descendant_pid_file"
group_descendant_pid="$(<"$group_descendant_pid_file")"
[[ "$group_descendant_pid" =~ ^[1-9][0-9]*$ ]]
if [[ -e "/proc/$group_descendant_pid" ]]; then
    printf 'deadline supervisor returned with an in-group descendant alive\n' >&2
    exit 1
fi

# Cancellation is blocked before spawn and consumed through signalfd. A TERM
# delivered in that formerly racy window must be remembered, must terminate a
# subsequently spawned session, and must be reported as the cancelling signal.
deadline_pre_spawn_marker="$workdir/deadline-pre-spawn.marker"
deadline_pre_spawn_continue="$workdir/deadline-pre-spawn.continue"
deadline_pre_spawn_child="$workdir/deadline-pre-spawn-child.pid"
(
    BORONDNS_CAMPAIGN_DEADLINE_TEST_PHASE=before-spawn \
        BORONDNS_CAMPAIGN_DEADLINE_TEST_MARKER="$deadline_pre_spawn_marker" \
        BORONDNS_CAMPAIGN_DEADLINE_TEST_CONTINUE="$deadline_pre_spawn_continue" \
        campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 5)" \
        python3 -c '
import os
import sys
import time

with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_pre_spawn_child"
) &
deadline_pre_spawn_wrapper=$!
deadline_pre_spawn_limit=$((SECONDS + 5))
while [[ ! -f "$deadline_pre_spawn_marker" ]]; do
    ((SECONDS < deadline_pre_spawn_limit)) || {
        printf 'deadline pre-spawn signal fixture did not reach its pause\n' >&2
        exit 1
    }
    sleep 0.01
done
deadline_pre_spawn_supervisor="$(<"$deadline_pre_spawn_marker")"
[[ "$deadline_pre_spawn_supervisor" =~ ^[1-9][0-9]*$ ]]
kill -TERM "$deadline_pre_spawn_supervisor"
: >"$deadline_pre_spawn_continue"
deadline_pre_spawn_status=0
wait "$deadline_pre_spawn_wrapper" || deadline_pre_spawn_status=$?
if ((deadline_pre_spawn_status != 128 + 15)); then
    printf 'deadline pre-spawn signal fixture returned %s instead of 143\n' \
        "$deadline_pre_spawn_status" >&2
    exit 1
fi
if [[ -f "$deadline_pre_spawn_child" ]]; then
    deadline_pre_spawn_child_pid="$(<"$deadline_pre_spawn_child")"
    [[ "$deadline_pre_spawn_child_pid" =~ ^[1-9][0-9]*$ ]]
    if [[ -e "/proc/$deadline_pre_spawn_child_pid" ]]; then
        printf 'deadline pre-spawn signal fixture leaked its child\n' >&2
        exit 1
    fi
fi

# A cancellation arriving after waitpid may affect the supervisor's result,
# but it must never trigger another killpg against a now-unpinned numeric PGID.
deadline_post_wait_marker="$workdir/deadline-post-wait.marker"
deadline_post_wait_continue="$workdir/deadline-post-wait.continue"
deadline_post_wait_killpg="$workdir/deadline-post-wait.killpg"
(
    BORONDNS_CAMPAIGN_DEADLINE_TEST_PHASE=after-reap-before-state \
        BORONDNS_CAMPAIGN_DEADLINE_TEST_MARKER="$deadline_post_wait_marker" \
        BORONDNS_CAMPAIGN_DEADLINE_TEST_CONTINUE="$deadline_post_wait_continue" \
        BORONDNS_CAMPAIGN_DEADLINE_TEST_KILLPG_MARKER="$deadline_post_wait_killpg" \
        campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 5)" true
) &
deadline_post_wait_wrapper=$!
deadline_post_wait_limit=$((SECONDS + 5))
while [[ ! -f "$deadline_post_wait_marker" ]]; do
    ((SECONDS < deadline_post_wait_limit)) || {
        printf 'deadline post-wait signal fixture did not reach its pause\n' >&2
        exit 1
    }
    sleep 0.01
done
deadline_post_wait_supervisor="$(<"$deadline_post_wait_marker")"
[[ "$deadline_post_wait_supervisor" =~ ^[1-9][0-9]*$ ]]
deadline_post_wait_kills_before="$(wc -l <"$deadline_post_wait_killpg")"
kill -TERM "$deadline_post_wait_supervisor"
: >"$deadline_post_wait_continue"
deadline_post_wait_status=0
wait "$deadline_post_wait_wrapper" || deadline_post_wait_status=$?
if ((deadline_post_wait_status != 128 + 15)); then
    printf 'deadline post-wait signal fixture returned %s instead of 143\n' \
        "$deadline_post_wait_status" >&2
    exit 1
fi
deadline_post_wait_kills_after="$(wc -l <"$deadline_post_wait_killpg")"
if ((deadline_post_wait_kills_after != deadline_post_wait_kills_before)); then
    printf 'deadline post-wait signal fixture reused an unpinned process group\n' >&2
    exit 1
fi

# Service managers and caller traps see the Bash wrapper, not its internal
# Python PID. Cancelling that shell-visible process must forward through the
# owned, unreaped job and wait until the supervisor and command are both gone.
deadline_wrapper_child="$workdir/deadline-wrapper-child.pid"
(
    campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 5)" \
        python3 -c '
import os
import sys
import time

with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_wrapper_child"
) &
deadline_wrapper_pid=$!
deadline_wrapper_limit=$((SECONDS + 5))
while [[ ! -f "$deadline_wrapper_child" ]]; do
    ((SECONDS < deadline_wrapper_limit)) || {
        printf 'deadline wrapper cancellation fixture did not start its child\n' >&2
        exit 1
    }
    sleep 0.01
done
deadline_wrapper_child_pid="$(<"$deadline_wrapper_child")"
kill -TERM "$deadline_wrapper_pid"
deadline_wrapper_status=0
wait "$deadline_wrapper_pid" || deadline_wrapper_status=$?
if ((deadline_wrapper_status != 128 + 15)); then
    printf 'deadline wrapper cancellation fixture returned %s instead of 143\n' \
        "$deadline_wrapper_status" >&2
    exit 1
fi
[[ ! -e "/proc/$deadline_wrapper_child_pid" ]]

# Caller-controlled owner identities and capture output names are validated
# before process-global traps change or a command can be launched.
deadline_early_failure_child="$workdir/deadline-early-failure-child"
(
    trap 'deadline_early_failure_int=unexpected' INT
    trap 'deadline_early_failure_term=unexpected' TERM
    trap 'deadline_early_failure_hup=unexpected' HUP
    expected_int="$(trap -p INT)"
    expected_term="$(trap -p TERM)"
    expected_hup="$(trap -p HUP)"
    if BORONDNS_CAMPAIGN_DEADLINE_OWNER_PID=invalid \
        campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 5)" \
        touch "$deadline_early_failure_child"; then
        printf 'deadline wrapper accepted an invalid owner identity\n' >&2
        exit 1
    fi
    [[ "$(trap -p INT)" == "$expected_int" &&
    "$(trap -p TERM)" == "$expected_term" &&
    "$(trap -p HUP)" == "$expected_hup" ]]
)
[[ ! -e "$deadline_early_failure_child" ]]

captured=caller-sentinel
deadline_capture_collision_child="$workdir/deadline-capture-collision-child"
if campaign_run_before_deadline_capture captured \
    "$(campaign_deadline_from_timeout_seconds 5)" \
    touch "$deadline_capture_collision_child"; then
    printf 'deadline capture accepted an implementation-local output name\n' >&2
    exit 1
fi
[[ "$captured" == caller-sentinel && ! -e "$deadline_capture_collision_child" ]]

# A process substitution can start before its dynamic parent descriptor fails.
# Exhaust that descriptor range and require one failure teardown path to retain
# caller output/traps and reap any command that reached launch.
(
    deadline_capture_fd_deadline="$(campaign_deadline_from_timeout_seconds 5)"
    deadline_capture_fd_child="$workdir/deadline-capture-fd-child.pid"
    captured_fd_output=caller-sentinel
    trap 'deadline_capture_fd_int=unexpected' INT
    trap 'deadline_capture_fd_term=unexpected' TERM
    trap 'deadline_capture_fd_hup=unexpected' HUP
    expected_int="$(trap -p INT)"
    expected_term="$(trap -p TERM)"
    expected_hup="$(trap -p HUP)"
    ulimit -n 10
    if campaign_run_before_deadline_capture captured_fd_output \
        "$deadline_capture_fd_deadline" python3 -c '
import os
import sys
import time

with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_capture_fd_child" 2>/dev/null; then
        printf 'deadline capture reported success after descriptor setup failure\n' >&2
        exit 1
    fi
    [[ "$captured_fd_output" == caller-sentinel &&
        "$(trap -p INT)" == "$expected_int" &&
        "$(trap -p TERM)" == "$expected_term" &&
        "$(trap -p HUP)" == "$expected_hup" ]]
    if [[ -f "$deadline_capture_fd_child" ]]; then
        deadline_capture_fd_child_pid="$(<"$deadline_capture_fd_child")"
        [[ "$deadline_capture_fd_child_pid" =~ ^[1-9][0-9]*$ ]]
        deadline_capture_fd_limit=$((SECONDS + 3))
        while [[ -e "/proc/$deadline_capture_fd_child_pid" ]] &&
            ((SECONDS < deadline_capture_fd_limit)); do
            sleep 0.01
        done
        [[ ! -e "/proc/$deadline_capture_fd_child_pid" ]]
    fi
)

# Captured stdout must not put the deadline supervisor exclusively under an
# orphanable command-substitution shell. TERM the real outer Bash caller and
# require both signal status and descendant teardown well before the deadline.
deadline_capture_child="$workdir/deadline-capture-child.pid"
deadline_capture_start="$(campaign_monotonic_nanoseconds)"
deadline_capture_command_seconds=10
deadline_capture_reap_seconds=3
deadline_capture_scheduler_margin_ns=250000000
deadline_capture_elapsed_limit_ns=$((\
    deadline_capture_reap_seconds * 1000000000 + deadline_capture_scheduler_margin_ns))
# Cancellation must remain well inside the command's absolute deadline. The
# extra 250 ms covers scheduler latency after the three-second reap window; it
# does not weaken the exact TERM status or child-gone assertions below.
((deadline_capture_elapsed_limit_ns < deadline_capture_command_seconds * 1000000000))
(
    # shellcheck disable=SC2034 # Output-variable target; cancellation prevents inspection.
    captured_output=""
    campaign_run_before_deadline_capture captured_output \
        "$(campaign_deadline_from_timeout_seconds "$deadline_capture_command_seconds")" \
        python3 -c '
import os
import sys
import time

with open(sys.argv[1], "x", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
    output.flush()
    os.fsync(output.fileno())
time.sleep(30)
' "$deadline_capture_child"
) &
deadline_capture_outer_pid=$!
deadline_capture_limit=$((SECONDS + 5))
while [[ ! -f "$deadline_capture_child" ]]; do
    ((SECONDS < deadline_capture_limit)) || {
        printf 'deadline captured-output fixture did not start its child\n' >&2
        exit 1
    }
    sleep 0.01
done
deadline_capture_child_pid="$(<"$deadline_capture_child")"
kill -TERM "$deadline_capture_outer_pid"
deadline_capture_status=0
wait "$deadline_capture_outer_pid" || deadline_capture_status=$?
deadline_capture_reap_limit=$((SECONDS + deadline_capture_reap_seconds))
while [[ -e "/proc/$deadline_capture_child_pid" ]] &&
    ((SECONDS < deadline_capture_reap_limit)); do
    sleep 0.01
done
deadline_capture_elapsed=$(($(campaign_monotonic_nanoseconds) - deadline_capture_start))
if ((deadline_capture_status != 128 + 15 || \
    deadline_capture_elapsed > deadline_capture_elapsed_limit_ns)) ||
        [[ -e "/proc/$deadline_capture_child_pid" ]]; then
    printf 'deadline captured-output cancellation failed: status=%s elapsed_ns=%s child=%s\n' \
        "$deadline_capture_status" "$deadline_capture_elapsed" "$deadline_capture_child_pid" >&2
    exit 1
fi

# Test seams remain production-reachable environment inputs, so a missing
# continuation must obey the same timerfd deadline instead of pinning a blocked
# signal mask indefinitely.
deadline_missing_continue_marker="$workdir/deadline-missing-continue.marker"
deadline_missing_continue_path="$workdir/deadline-missing-continue.never"
deadline_missing_continue_start="$(campaign_monotonic_nanoseconds)"
deadline_missing_continue_status=0
BORONDNS_CAMPAIGN_DEADLINE_TEST_PHASE=before-spawn \
    BORONDNS_CAMPAIGN_DEADLINE_TEST_MARKER="$deadline_missing_continue_marker" \
    BORONDNS_CAMPAIGN_DEADLINE_TEST_CONTINUE="$deadline_missing_continue_path" \
    campaign_run_before_deadline "$(campaign_deadline_from_timeout_seconds 1)" true ||
    deadline_missing_continue_status=$?
deadline_missing_continue_elapsed=$(($(campaign_monotonic_nanoseconds) - deadline_missing_continue_start))
if ((deadline_missing_continue_status != 124 || deadline_missing_continue_elapsed > 2500000000)); then
    printf 'deadline missing-continuation fixture escaped its bound: status=%s elapsed_ns=%s\n' \
        "$deadline_missing_continue_status" "$deadline_missing_continue_elapsed" >&2
    exit 1
fi
[[ -f "$deadline_missing_continue_marker" ]]

# Automatic build roots are created before fuzz-campaign acquires its evidence
# publication lock. An error in that interval must still remove the exact
# descriptor/journal-bound tree without weakening any lock-present cleanup.
(
    campaign_detach_inherited_private_lock
    lockless_cleanup_trees="$workdir/lockless-cleanup-trees"
    mkdir -m 0700 "$lockless_cleanup_trees"
    lockless_cleanup_tree=""
    campaign_prepare_private_temporary_tree "$lockless_cleanup_trees" \
        lockless-cleanup lockless_cleanup_identity lockless_cleanup_tree
    lockless_cleanup_journal="${CAMPAIGN_CLEANUP_IDENTITIES["lockless_cleanup_identity:journal_path"]}"
    printf 'pre-lock cleanup payload\n' >"$lockless_cleanup_tree/payload"
    [[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" &&
        -z "${campaign_lock_response_fd:-}" ]]
    campaign_remove_private_temporary_tree "$lockless_cleanup_tree" \
        lockless_cleanup_identity "pre-lock automatic tree"
    [[ ! -e "$lockless_cleanup_tree" && ! -e "$lockless_cleanup_journal" ]]
)

# An explicit operation deadline still rejects ordinary protected mutations.
# The broker remains available only for a separately authenticated cleanup
# deadline, so this assertion deliberately abandons its now-unusable handle.
explicit_lock_deadline="$(campaign_deadline_from_timeout_seconds 1)"
campaign_acquire_private_lock "$broker_crash_root" explicit-lifetime \
    "explicit lifetime fixture" "$explicit_lock_deadline" "$((explicit_lock_deadline + 300000000))"
sleep 1.1
if campaign_assert_private_lock "$explicit_lock_deadline" "$((explicit_lock_deadline + 300000000))"; then
    printf 'campaign lock broker survived its explicit absolute deadline\n' >&2
    exit 1
fi
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" ]]

# Cleanup authority must survive the operation cutoff and remove the exact
# descriptor-bound tree during the reserved tail. No automatic journal or tree
# may remain after the protected cleanup and bounded broker release.
cleanup_reserve_root="$workdir/cleanup-reserve-lock-root"
cleanup_reserve_trees="$workdir/cleanup-reserve-trees"
mkdir -m 0700 "$cleanup_reserve_root" "$cleanup_reserve_trees"
cleanup_operation_deadline="$(campaign_deadline_from_timeout_seconds 1)"
cleanup_absolute_deadline=$((cleanup_operation_deadline + 2000000000))
campaign_acquire_private_lock "$cleanup_reserve_root" cleanup-reserve \
    "cleanup reserve fixture" "$cleanup_operation_deadline" "$cleanup_absolute_deadline"
cleanup_reserve_tree=""
campaign_prepare_private_temporary_tree "$cleanup_reserve_trees" cleanup-reserve \
    cleanup_reserve_identity cleanup_reserve_tree \
    "$cleanup_operation_deadline" "$cleanup_absolute_deadline"
printf 'cleanup payload\n' >"$cleanup_reserve_tree/payload"
sleep 1.1
if campaign_assert_private_lock; then
    printf 'ordinary campaign mutation used the reserved cleanup tail\n' >&2
    exit 1
fi
[[ -n "${campaign_lock_pid:-}" && "${campaign_lock_deadline_bounded:-}" == 1 ]]
campaign_remove_private_temporary_tree "$cleanup_reserve_tree" cleanup_reserve_identity \
    "cleanup reserve tree" "$cleanup_absolute_deadline"
campaign_release_private_lock "$cleanup_absolute_deadline"
cleanup_reserve_parent="$cleanup_reserve_trees/cleanup-reserve-$(id -u)"
[[ ! -e "$cleanup_reserve_tree" ]]
[[ -z "$(find "$cleanup_reserve_parent" -maxdepth 1 \
    \( -type d -name 'run.*' -o -type f -name '.automatic-run.*.env' \) -print -quit)" ]]
[[ -z "${campaign_lock_operation_deadline:-}" && -z "${campaign_lock_cleanup_deadline:-}" &&
    -z "${campaign_lock_deadline_bounded:-}" ]]

# Expired cleanup must not publish the durable removing phase. A later owner
# must be able to consume the unchanged ready journal and exact tree identity.
expired_cleanup_root="$workdir/expired-cleanup-lock-root"
expired_cleanup_trees="$workdir/expired-cleanup-trees"
mkdir -m 0700 "$expired_cleanup_root" "$expired_cleanup_trees"
expired_cleanup_deadline="$(campaign_deadline_from_timeout_seconds 1)"
campaign_acquire_private_lock "$expired_cleanup_root" expired-cleanup \
    "expired cleanup fixture" "$expired_cleanup_deadline" "$expired_cleanup_deadline"
expired_cleanup_tree=""
campaign_prepare_private_temporary_tree "$expired_cleanup_trees" expired-cleanup \
    expired_cleanup_identity expired_cleanup_tree \
    "$expired_cleanup_deadline" "$expired_cleanup_deadline"
expired_cleanup_journal="${CAMPAIGN_CLEANUP_IDENTITIES["expired_cleanup_identity:journal_path"]}"
expired_cleanup_journal_hash="$(sha256sum "$expired_cleanup_journal")"
sleep 1.1
if campaign_remove_private_temporary_tree "$expired_cleanup_tree" expired_cleanup_identity \
    "expired cleanup tree" "$expired_cleanup_deadline"; then
    printf 'automatic tree cleanup mutated after its cleanup deadline\n' >&2
    exit 1
fi
[[ -d "$expired_cleanup_tree" ]]
[[ "$expired_cleanup_journal_hash" == "$(sha256sum "$expired_cleanup_journal")" ]]
grep -Fqx phase=ready "$expired_cleanup_journal"
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_operation_deadline:-}" &&
    -z "${campaign_lock_cleanup_deadline:-}" && -z "${campaign_lock_deadline_bounded:-}" ]]
expired_recovery_operation="$(campaign_deadline_from_timeout_seconds 1)"
expired_recovery_cleanup=$((expired_recovery_operation + 2000000000))
campaign_acquire_private_lock "$expired_cleanup_root" expired-cleanup \
    "expired cleanup recovery fixture" "$expired_recovery_operation" "$expired_recovery_cleanup"
campaign_remove_private_temporary_tree "$expired_cleanup_tree" expired_cleanup_identity \
    "expired cleanup recovery tree" "$expired_recovery_cleanup"
campaign_release_private_lock "$expired_recovery_cleanup"
[[ ! -e "$expired_cleanup_tree" && ! -e "$expired_cleanup_journal" ]]

# Both marker staging boundaries enforce CLOCK_BOOTTIME themselves. Crossing
# the cleanup cutoff at either hook removes only the exact staged inode and
# leaves the durable ready journal byte-identical for a later owner.
for marker_deadline_phase in pre-stage pre-replace; do
    marker_deadline_root="$workdir/marker-deadline-$marker_deadline_phase-root"
    marker_deadline_trees="$workdir/marker-deadline-$marker_deadline_phase-trees"
    mkdir -m 0700 "$marker_deadline_root" "$marker_deadline_trees"
    marker_deadline="$(campaign_deadline_from_timeout_seconds 1)"
    campaign_acquire_private_lock "$marker_deadline_root" "marker-$marker_deadline_phase" \
        "marker $marker_deadline_phase deadline fixture" "$marker_deadline" "$marker_deadline"
    marker_deadline_tree=""
    campaign_prepare_private_temporary_tree "$marker_deadline_trees" \
        "marker-$marker_deadline_phase" marker_deadline_identity marker_deadline_tree \
        "$marker_deadline" "$marker_deadline"
    marker_deadline_journal="${CAMPAIGN_CLEANUP_IDENTITIES["marker_deadline_identity:journal_path"]}"
    marker_deadline_hash="$(sha256sum "$marker_deadline_journal")"
    marker_delay_until=$((marker_deadline + 100000000))
    if BORONDNS_CAMPAIGN_MARK_REMOVING_DELAY_PHASE="$marker_deadline_phase" \
        BORONDNS_CAMPAIGN_MARK_REMOVING_DELAY_UNTIL_NANOSECONDS="$marker_delay_until" \
        campaign_remove_private_temporary_tree "$marker_deadline_tree" \
        marker_deadline_identity "marker $marker_deadline_phase deadline tree" \
        "$marker_deadline" 2>"$workdir/marker-$marker_deadline_phase.err"; then
        printf 'automatic-tree marker crossed its %s deadline hook\n' \
            "$marker_deadline_phase" >&2
        exit 1
    fi
    [[ -d "$marker_deadline_tree" &&
        "$marker_deadline_hash" == "$(sha256sum "$marker_deadline_journal")" ]]
    grep -Fqx phase=ready "$marker_deadline_journal"
    [[ -z "$(find "$(dirname "$marker_deadline_journal")" -maxdepth 1 \
        -type f -name ".$(basename "$marker_deadline_journal").removing.*" -print -quit)" ]]
    campaign_release_private_lock "$marker_deadline" || true
    marker_recovery_operation="$(campaign_deadline_from_timeout_seconds 1)"
    marker_recovery_cleanup=$((marker_recovery_operation + 2000000000))
    campaign_acquire_private_lock "$marker_deadline_root" "marker-$marker_deadline_phase" \
        "marker $marker_deadline_phase recovery fixture" \
        "$marker_recovery_operation" "$marker_recovery_cleanup"
    campaign_remove_private_temporary_tree "$marker_deadline_tree" \
        marker_deadline_identity "marker $marker_deadline_phase recovery tree" \
        "$marker_recovery_cleanup"
    campaign_release_private_lock "$marker_recovery_cleanup"
    [[ ! -e "$marker_deadline_tree" && ! -e "$marker_deadline_journal" ]]
done

# A journal replacement after the final expected-inode check is displaced by an
# atomic exchange and retained, never unlinked by os.replace semantics.
journal_exchange_root="$workdir/journal-exchange-lock"
journal_exchange_trees="$workdir/journal-exchange-trees"
mkdir -m 0700 "$journal_exchange_root" "$journal_exchange_trees"
journal_exchange_operation="$(campaign_deadline_from_timeout_seconds 5)"
journal_exchange_cleanup=$((journal_exchange_operation + 5000000000))
campaign_acquire_private_lock "$journal_exchange_root" journal-exchange \
    "automatic journal exchange race fixture" "$journal_exchange_operation" "$journal_exchange_cleanup"
journal_exchange_tree=""
campaign_prepare_private_temporary_tree "$journal_exchange_trees" journal-exchange \
    journal_exchange_identity journal_exchange_tree \
    "$journal_exchange_operation" "$journal_exchange_cleanup"
journal_exchange_path="${CAMPAIGN_CLEANUP_IDENTITIES["journal_exchange_identity:journal_path"]}"
journal_exchange_original="$workdir/journal-exchange-original"
journal_exchange_delay=$(($(campaign_monotonic_nanoseconds) + 1500000000))
(
    sleep 0.4
    mv -- "$journal_exchange_path" "$journal_exchange_original"
    printf 'foreign journal victim must survive\n' >"$journal_exchange_path"
) &
journal_exchange_attacker=$!
lock_holder_pids+=("$journal_exchange_attacker")
if BORONDNS_CAMPAIGN_MARK_REMOVING_DELAY_PHASE=pre-replace \
    BORONDNS_CAMPAIGN_MARK_REMOVING_DELAY_UNTIL_NANOSECONDS="$journal_exchange_delay" \
    campaign_remove_private_temporary_tree "$journal_exchange_tree" \
    journal_exchange_identity "automatic journal exchange race fixture" \
    "$journal_exchange_cleanup" 2>"$workdir/journal-exchange.err"; then
    printf 'automatic journal exchange accepted a replacement destination\n' >&2
    exit 1
fi
wait "$journal_exchange_attacker"
untrack_test_process "$journal_exchange_attacker"
[[ -d "$journal_exchange_tree" && -f "$journal_exchange_original" ]]
journal_exchange_retained="$(find "$(dirname "$journal_exchange_path")" -maxdepth 1 -type f \
    -exec grep -lFx 'foreign journal victim must survive' {} +)"
[[ -n "$journal_exchange_retained" ]]
grep -Fq 'automatic-tree removal journal changed during exchange' "$workdir/journal-exchange.err"
campaign_release_private_lock "$journal_exchange_cleanup"

# The cleanup cutoff is also real: after it the kernel-held authority expires
# even if the caller still owns both protocol descriptors.
cleanup_expiry_operation="$(campaign_deadline_from_timeout_seconds 1)"
cleanup_expiry_deadline=$((cleanup_expiry_operation + 300000000))
campaign_acquire_private_lock "$broker_crash_root" cleanup-expiry \
    "cleanup expiry fixture" "$cleanup_expiry_operation" "$cleanup_expiry_deadline"
sleep 1.4
if campaign_assert_private_lock "$cleanup_expiry_deadline" "$cleanup_expiry_deadline"; then
    printf 'campaign lock broker survived its authenticated cleanup deadline\n' >&2
    exit 1
fi
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" ]]

invalid_deadline_now="$(campaign_monotonic_nanoseconds)"
if campaign_acquire_private_lock "$broker_crash_root" invalid-cleanup-deadline \
    "invalid cleanup deadline fixture" "$((invalid_deadline_now + 2000000000))" \
    "$((invalid_deadline_now + 1000000000))"; then
    printf 'campaign lock accepted cleanup deadline before operation deadline\n' >&2
    exit 1
fi
overflow_lock_deadline=999999999999999999999999999999
if campaign_acquire_private_lock "$broker_crash_root" overflow-cleanup-deadline \
    "overflow cleanup deadline fixture" "$overflow_lock_deadline" "$overflow_lock_deadline"; then
    printf 'campaign lock accepted overflow-sized operation/cleanup deadlines\n' >&2
    exit 1
fi
campaign_is_positive_signed_64 9223372036854775807
for overflow_lock_deadline in 9223372036854775808 9999999999999999999; do
    if campaign_is_positive_signed_64 "$overflow_lock_deadline"; then
        printf 'signed-64 validator accepted overflow deadline: %s\n' "$overflow_lock_deadline" >&2
        exit 1
    fi
    if campaign_acquire_private_lock "$broker_crash_root" overflow-cleanup-deadline \
        "overflow cleanup deadline fixture" "$overflow_lock_deadline" "$overflow_lock_deadline"; then
        printf 'campaign lock accepted signed-64 overflow deadline: %s\n' "$overflow_lock_deadline" >&2
        exit 1
    fi
done
for overflow_lock_deadline in 9223372036854775808 18446744073709551616 \
    18446744073709651616; do
    if campaign_deadline_from_timeout_seconds "$overflow_lock_deadline" >/dev/null 2>&1 ||
        campaign_deadline_remaining_seconds "$overflow_lock_deadline" 1 >/dev/null 2>&1 ||
        campaign_deadline_capped "$overflow_lock_deadline" 1 >/dev/null 2>&1 ||
        campaign_deadline_reserving_termination "$overflow_lock_deadline" >/dev/null 2>&1; then
        printf 'deadline arithmetic helper accepted wrapped signed-64 input: %s\n' \
            "$overflow_lock_deadline" >&2
        exit 1
    fi
done
deadline_multiplication_overflow=9223372037
if campaign_deadline_remaining_seconds 9223372036854775807 \
    "$deadline_multiplication_overflow" >/dev/null 2>&1; then
    printf 'deadline remaining helper accepted seconds-to-nanoseconds overflow\n' >&2
    exit 1
fi

campaign_acquire_private_lock "$broker_crash_root" broker-stall "broker heartbeat stall fixture"
stalled_broker_pid="$campaign_lock_pid"
kill -STOP "$stalled_broker_pid"
heartbeat_started=$SECONDS
if BORONDNS_CAMPAIGN_LOCK_HEARTBEAT_TIMEOUT_SECONDS=1 campaign_assert_private_lock; then
    printf 'campaign mutation boundary accepted a stopped lock broker\n' >&2
    exit 1
fi
heartbeat_elapsed=$((SECONDS - heartbeat_started))
((heartbeat_elapsed >= 1 && heartbeat_elapsed <= 4)) || {
    printf 'campaign lock heartbeat timeout was not bounded: %s seconds\n' "$heartbeat_elapsed" >&2
    exit 1
}
if kill -0 "$stalled_broker_pid" 2>/dev/null; then
    printf 'campaign lock left a stalled broker alive after heartbeat timeout\n' >&2
    exit 1
fi
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" ]]
campaign_acquire_private_lock "$broker_crash_root" broker-stall "broker heartbeat recovery fixture"
campaign_release_private_lock

replacement_lock_root="$workdir/replacement-lock-root"
mkdir -m 0700 "$replacement_lock_root"
campaign_acquire_private_lock "$replacement_lock_root" root-replacement "lock root replacement fixture"
replacement_broker_pid="$campaign_lock_pid"
mv "$replacement_lock_root/.borondns-campaign-locks" "$replacement_lock_root/.borondns-campaign-locks.detached"
mkdir -m 0700 "$replacement_lock_root/.borondns-campaign-locks"
if campaign_assert_private_lock; then
    printf 'campaign mutation boundary accepted a replaced lock directory\n' >&2
    exit 1
fi
if kill -0 "$replacement_broker_pid" 2>/dev/null; then
    printf 'campaign lock left a detached-root broker alive\n' >&2
    exit 1
fi
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" ]]
campaign_acquire_private_lock "$replacement_lock_root" root-replacement "lock root replacement recovery fixture"
campaign_release_private_lock

campaign_acquire_private_lock "$broker_crash_root" broker-release-stall "broker release stall fixture"
release_stalled_broker_pid="$campaign_lock_pid"
kill -STOP "$release_stalled_broker_pid"
release_started="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns())')"
BORONDNS_CAMPAIGN_LOCK_RELEASE_TIMEOUT_SECONDS=1 campaign_release_private_lock
release_finished="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns())')"
release_elapsed_ms=$(((release_finished - release_started) / 1000000))
((release_elapsed_ms <= 1750)) || {
    printf 'campaign lock release timeout was not bounded: %s ms\n' "$release_elapsed_ms" >&2
    exit 1
}
if kill -0 "$release_stalled_broker_pid" 2>/dev/null; then
    printf 'campaign lock release left a stopped broker alive\n' >&2
    exit 1
fi
[[ -z "${campaign_lock_pid:-}" && -z "${campaign_lock_control_fd:-}" && -z "${campaign_lock_response_fd:-}" ]]
campaign_acquire_private_lock "$broker_crash_root" broker-release-stall "broker release recovery fixture"
campaign_release_private_lock

campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" "operations harness mutation lock"

campaign_rebind_test_subshell_lock() {
    campaign_detach_inherited_private_lock
    campaign_acquire_private_lock "$workdir" "operations:test-subshell:$BASHPID" \
        "operations test subshell lock"
}

dead_status_root="$workdir/dead-status-root"
mkdir "$dead_status_root"
dead_status_file="$dead_status_root/status.tsv"
printf 'retained\n' >"$dead_status_file"
campaign_release_private_lock
campaign_acquire_private_lock "$dead_status_root" dead-status "dead status fixture"
kill "$campaign_lock_pid"
wait "$campaign_lock_pid" 2>/dev/null || true
if campaign_publish_status_text "$dead_status_root" "$dead_status_file" $'invalid\n' "dead status fixture"; then
    printf 'collection status publication accepted a dead lock broker\n' >&2
    exit 1
fi
grep -Fqx retained "$dead_status_file"
campaign_release_private_lock

status_swap_root="$workdir/status-publication-swaps"
mkdir "$status_swap_root"
status_swap_destination="$status_swap_root/status.tsv"
printf 'retained\n' >"$status_swap_destination"
campaign_acquire_private_lock "$status_swap_root" status-staging-swap "status staging swap fixture"
status_original_staged=""
status_substituted_staged=""
campaign_publish_status_text_hook() {
    [[ "$1" != before-final-rename ]] || {
        status_substituted_staged="$2"
        status_original_staged="$2.original"
        mv -- "$2" "$status_original_staged"
        printf 'forged staging\n' >"$status_substituted_staged"
    }
}
if campaign_publish_status_text "$status_swap_root" "$status_swap_destination" $'trusted staging\n' \
    "status staging swap fixture"; then
    printf 'status publication accepted a substituted staging file\n' >&2
    exit 1
fi
grep -Fqx retained "$status_swap_destination"
grep -Fqx 'trusted staging' "$status_original_staged"
grep -Fqx 'forged staging' "$status_substituted_staged"
rm -f -- "$status_original_staged" "$status_substituted_staged"
unset -f campaign_publish_status_text_hook
campaign_release_private_lock

campaign_acquire_private_lock "$status_swap_root" status-destination-swap "status destination swap fixture"
status_original_destination="$status_swap_destination.original"
campaign_publish_status_text_hook() {
    [[ "$1" != before-final-rename ]] || {
        mv -- "$3" "$status_original_destination"
        printf 'replacement victim\n' >"$3"
    }
}
if campaign_publish_status_text "$status_swap_root" "$status_swap_destination" $'trusted replacement\n' \
    "status destination swap fixture"; then
    printf 'status publication accepted a substituted destination file\n' >&2
    exit 1
fi
grep -Fqx retained "$status_original_destination"
grep -Fqx 'replacement victim' "$status_swap_destination"
unset -f campaign_publish_status_text_hook
campaign_release_private_lock

collection_staging_swap_root="$workdir/collection-staging-cleanup-swap"
mkdir -p "$collection_staging_swap_root/evidence" "$collection_staging_swap_root/journal" \
    "$collection_staging_swap_root/evidence-new" "$collection_staging_swap_root/journal-new" \
    "$collection_staging_swap_root/victim"
printf old >"$collection_staging_swap_root/evidence/value"
printf old >"$collection_staging_swap_root/journal/value"
printf old >"$collection_staging_swap_root/status"
printf new >"$collection_staging_swap_root/evidence-new/value"
printf new >"$collection_staging_swap_root/journal-new/value"
printf new >"$collection_staging_swap_root/status-new"
printf 'must survive rejected staging cleanup\n' >"$collection_staging_swap_root/victim/sentinel"
campaign_acquire_private_lock "$collection_staging_swap_root" collection-staging-cleanup-swap \
    "collection staging cleanup swap fixture"
campaign_capture_cleanup_identity "$collection_staging_swap_root/evidence-new" tree \
    collection_swap_evidence "collection swap evidence staging"
campaign_capture_cleanup_identity "$collection_staging_swap_root/journal-new" tree \
    collection_swap_journal "collection swap journal staging"
campaign_capture_cleanup_identity "$collection_staging_swap_root/status-new" file \
    collection_swap_status "collection swap status staging"
campaign_collection_publication_hook() {
    [[ "$1" == backup-0 ]] || return 0
    mv "$collection_staging_swap_root/journal-new" "$collection_staging_swap_root/journal-new.original"
    mv "$collection_staging_swap_root/victim" "$collection_staging_swap_root/journal-new"
}
if campaign_publish_collection_bundle "$collection_staging_swap_root" \
    "$collection_staging_swap_root/evidence-new" "$collection_staging_swap_root/evidence" \
    "$collection_staging_swap_root/journal-new" "$collection_staging_swap_root/journal" \
    "$collection_staging_swap_root/status-new" "$collection_staging_swap_root/status" \
    "collection staging cleanup swap fixture"; then
    printf 'collection publication accepted a replaced staging directory\n' >&2
    exit 1
fi
unset -f campaign_collection_publication_hook
campaign_remove_captured_cleanup_object "$collection_staging_swap_root/evidence-new" \
    collection_swap_evidence "collection swap evidence staging"
if campaign_remove_captured_cleanup_object "$collection_staging_swap_root/journal-new" \
    collection_swap_journal "collection swap journal staging"; then
    printf 'captured collection cleanup accepted a replacement staging directory\n' >&2
    exit 1
fi
campaign_remove_captured_cleanup_object "$collection_staging_swap_root/status-new" \
    collection_swap_status "collection swap status staging"
grep -Fqx 'must survive rejected staging cleanup' "$collection_staging_swap_root/journal-new/sentinel"
campaign_release_private_lock

campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" "operations harness mutation lock"

atomic_lock_root="$workdir/atomic-lock-root"
mkdir "$atomic_lock_root"
atomic_destination="$atomic_lock_root/marker.env"
printf 'retained\n' >"$atomic_destination"
printf 'stale\n' >"$atomic_lock_root/.marker.env.borondns-staged.hostile"
campaign_release_private_lock
campaign_acquire_private_lock "$atomic_lock_root" atomic-stale "atomic stale deletion fixture"
campaign_atomic_replace_text_hook() {
    [[ "$1" != before-stale-delete ]] || {
        kill "$campaign_lock_pid"
        wait "$campaign_lock_pid" 2>/dev/null || true
    }
}
if campaign_atomic_replace_text "$atomic_destination" replacement "atomic stale deletion fixture"; then
    printf 'atomic marker helper deleted staging after broker death\n' >&2
    exit 1
fi
grep -Fqx retained "$atomic_destination"
[[ -f "$atomic_lock_root/.marker.env.borondns-staged.hostile" ]]
unset -f campaign_atomic_replace_text_hook

atomic_stale_parent_root="$workdir/atomic-stale-parent-root"
atomic_stale_parent_displaced="$workdir/atomic-stale-parent-root.displaced"
atomic_stale_parent_destination="$atomic_stale_parent_root/marker.env"
atomic_stale_parent_name=".marker.env.borondns-staged.parent-swap"
mkdir "$atomic_stale_parent_root"
printf 'retained\n' >"$atomic_stale_parent_destination"
printf 'stale original\n' >"$atomic_stale_parent_root/$atomic_stale_parent_name"
campaign_atomic_replace_text_hook() {
    [[ "$1" != before-stale-delete ]] || {
        mv -- "$atomic_stale_parent_root" "$atomic_stale_parent_displaced"
        mkdir -- "$atomic_stale_parent_root"
        printf 'replacement parent victim\n' >"$atomic_stale_parent_root/$atomic_stale_parent_name"
    }
}
if campaign_atomic_replace_text "$atomic_stale_parent_destination" replacement \
    "atomic stale parent replacement fixture"; then
    printf 'atomic marker helper accepted a replaced stale-file parent\n' >&2
    exit 1
fi
grep -Fqx 'stale original' "$atomic_stale_parent_displaced/$atomic_stale_parent_name"
grep -Fqx 'replacement parent victim' "$atomic_stale_parent_root/$atomic_stale_parent_name"
rm -rf -- "$atomic_stale_parent_root"
mv -- "$atomic_stale_parent_displaced" "$atomic_stale_parent_root"
unset -f campaign_atomic_replace_text_hook

atomic_stale_name_root="$workdir/atomic-stale-name-root"
atomic_stale_name_destination="$atomic_stale_name_root/marker.env"
atomic_stale_name="$atomic_stale_name_root/.marker.env.borondns-staged.name-swap"
atomic_stale_name_original="$atomic_stale_name.original"
mkdir "$atomic_stale_name_root"
printf 'retained\n' >"$atomic_stale_name_destination"
printf 'stale original\n' >"$atomic_stale_name"
campaign_atomic_replace_text_hook() {
    [[ "$1" != before-stale-delete ]] || {
        mv -- "$atomic_stale_name" "$atomic_stale_name_original"
        printf 'replacement name victim\n' >"$atomic_stale_name"
    }
}
if campaign_atomic_replace_text "$atomic_stale_name_destination" replacement \
    "atomic stale name replacement fixture"; then
    printf 'atomic marker helper accepted a substituted stale-file name\n' >&2
    exit 1
fi
grep -Fqx 'stale original' "$atomic_stale_name_original"
grep -Fqx 'replacement name victim' "$atomic_stale_name"
grep -Fqx retained "$atomic_stale_name_destination"
unset -f campaign_atomic_replace_text_hook

atomic_stale_fifo="$atomic_stale_name_root/.marker.env.borondns-staged.fifo"
atomic_stale_fifo_original="$atomic_stale_fifo.original"
printf 'captured stale file\n' >"$atomic_stale_fifo"
atomic_stale_fifo_identity="$(stat -c '%d:%i:%u' "$atomic_stale_fifo")"
atomic_stale_fifo_remainder="${atomic_stale_fifo_identity#*:}"
mv -- "$atomic_stale_fifo" "$atomic_stale_fifo_original"
mkfifo "$atomic_stale_fifo"
set +e
# shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
timeout --kill-after=1 3 bash --noprofile --norc -c '
    source "$1/scripts/campaign-env.sh"
    campaign_identity_bound_unlink_file "$2" "$3" "$4" "$5" "$6" "$7" "$8"
' _ "$repo_root" "$atomic_stale_name_root" "$atomic_stale_fifo" \
    "$(stat -c %d "$atomic_stale_name_root")" "$(stat -c %i "$atomic_stale_name_root")" \
    "${atomic_stale_fifo_identity%%:*}" "${atomic_stale_fifo_remainder%%:*}" \
    "${atomic_stale_fifo_identity##*:}" \
    >"$workdir/atomic-stale-fifo.out" 2>"$workdir/atomic-stale-fifo.err"
atomic_stale_fifo_status=$?
set -e
if ((atomic_stale_fifo_status == 0 || atomic_stale_fifo_status == 124 || \
    atomic_stale_fifo_status == 137)); then
    printf 'identity-bound stale cleanup accepted or blocked on a FIFO replacement\n' >&2
    exit 1
fi
[[ -p "$atomic_stale_fifo" ]]
grep -Fqx 'captured stale file' "$atomic_stale_fifo_original"
rm -f -- "$atomic_stale_fifo" "$atomic_stale_fifo_original"

campaign_release_private_lock
campaign_acquire_private_lock "$atomic_lock_root" atomic-final "atomic final rename fixture"
campaign_atomic_replace_text_hook() {
    [[ "$1" != before-final-rename ]] || {
        kill "$campaign_lock_pid"
        wait "$campaign_lock_pid" 2>/dev/null || true
    }
}
if campaign_atomic_replace_text "$atomic_destination" replacement "atomic final rename fixture"; then
    printf 'atomic marker helper published after broker death\n' >&2
    exit 1
fi
grep -Fqx retained "$atomic_destination"
unset -f campaign_atomic_replace_text_hook
campaign_release_private_lock
campaign_acquire_private_lock "$atomic_lock_root" atomic-recovery "atomic publication recovery fixture"
campaign_atomic_replace_text "$atomic_destination" replacement "atomic publication recovery fixture"
grep -Fqx replacement "$atomic_destination"
campaign_release_private_lock

# Stale-status discovery must fail before deleting or publishing when its
# direct-child scan exceeds the authenticated cap. The underlying enumerator
# also rejects an expired CLOCK_BOOTTIME deadline without changing output.
atomic_enumeration_root="$workdir/atomic-enumeration-root"
atomic_enumeration_destination="$atomic_enumeration_root/marker.env"
mkdir "$atomic_enumeration_root"
printf 'retained enumeration destination\n' >"$atomic_enumeration_destination"
for atomic_enumeration_index in {0..7}; do
    printf 'retained stale %s\n' "$atomic_enumeration_index" \
        >"$atomic_enumeration_root/.marker.env.borondns-staged.$atomic_enumeration_index"
done
atomic_enumeration_before="$(sha256sum "$atomic_enumeration_destination" \
    "$atomic_enumeration_root"/.marker.env.borondns-staged.* | sort)"
set +e
# shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP=4 timeout --kill-after=1 3 \
    bash --noprofile --norc -c '
        set -euo pipefail
        source "$1/scripts/campaign-env.sh"
        campaign_acquire_private_lock "$2" atomic-enumeration "atomic enumeration fixture"
        campaign_atomic_replace_text "$2/marker.env" replacement "atomic enumeration fixture"
    ' _ "$repo_root" "$atomic_enumeration_root" \
    >"$workdir/atomic-enumeration.out" 2>"$workdir/atomic-enumeration.err"
atomic_enumeration_status=$?
set -e
if ((atomic_enumeration_status == 0 || atomic_enumeration_status == 124 || \
    atomic_enumeration_status == 137)); then
    printf 'atomic stale-status enumeration was accepted or not promptly bounded\n' >&2
    exit 1
fi
grep -Fq 'campaign directory enumeration entry cap exceeded' \
    "$workdir/atomic-enumeration.err"
[[ "$(sha256sum "$atomic_enumeration_destination" \
    "$atomic_enumeration_root"/.marker.env.borondns-staged.* | sort)" == "$atomic_enumeration_before" ]]

# Local evidence snapshotting and validation share one CLOCK_BOOTTIME deadline
# and explicit entry/depth/per-file/total-byte caps. Every hostile shape must
# fail promptly without reading a FIFO or materializing an unbounded sort.
collection_bounds_root="$workdir/collection-bounds-root"
mkdir -p "$collection_bounds_root/deep/one/two"
for collection_bound_index in {0..7}; do
    printf x >"$collection_bounds_root/entry-$collection_bound_index"
done
truncate -s 4096 "$collection_bounds_root/large"
mkfifo "$collection_bounds_root/blocking.fifo"
collection_bounds_deadline=""
campaign_prepare_collection_budget collection_bounds_deadline
computed_deadline=caller-sentinel
if campaign_prepare_collection_budget computed_deadline; then
    printf 'collection budget output accepted a callee-local name collision\n' >&2
    exit 1
fi
[[ "$computed_deadline" == caller-sentinel ]]
remaining=caller-sentinel
if campaign_collection_phase_timeout_seconds remaining "$collection_bounds_deadline" 5; then
    printf 'collection phase output accepted a callee-local name collision\n' >&2
    exit 1
fi
[[ "$remaining" == caller-sentinel ]]
for collection_bound_kind in entries depth file total blocking deadline; do
    set +e
    case "$collection_bound_kind" in
    entries)
        timeout --kill-after=1 3 python3 "$repo_root/scripts/validate-collected-campaign.py" \
            tree-snapshot "$collection_bounds_root" --max-entries 4
        ;;
    depth)
        timeout --kill-after=1 3 python3 "$repo_root/scripts/validate-collected-campaign.py" \
            tree-snapshot "$collection_bounds_root" --max-depth 2
        ;;
    file)
        timeout --kill-after=1 3 python3 "$repo_root/scripts/validate-collected-campaign.py" \
            tree-snapshot "$collection_bounds_root" --max-file-bytes 1024
        ;;
    total)
        timeout --kill-after=1 3 python3 "$repo_root/scripts/validate-collected-campaign.py" \
            tree-snapshot "$collection_bounds_root" --max-total-bytes 1024 \
            --max-file-bytes 1024
        ;;
    blocking)
        timeout --kill-after=1 3 python3 "$repo_root/scripts/validate-collected-campaign.py" \
            tree-snapshot "$collection_bounds_root"
        ;;
    deadline)
        timeout --kill-after=1 3 python3 "$repo_root/scripts/validate-collected-campaign.py" \
            tree-snapshot "$collection_bounds_root" --absolute-deadline-nanoseconds 1
        ;;
    esac >"$workdir/collection-bound-$collection_bound_kind.out" \
        2>"$workdir/collection-bound-$collection_bound_kind.err"
    collection_bound_status=$?
    set -e
    if ((collection_bound_status == 0 || collection_bound_status == 124 || \
        collection_bound_status == 137)); then
        printf 'collection %s bound was accepted or failed to terminate promptly\n' \
            "$collection_bound_kind" >&2
        exit 1
    fi
done
rm -f "$collection_bounds_root/blocking.fifo"

# Aggregate accounting must consume the bytes actually read, not stale sizes
# observed during the inventory pass.
collection_growth_root="$workdir/collection-growth-root"
collection_growth_marker="$workdir/collection-growth-inventoried"
collection_growth_continue="$workdir/collection-growth-continue"
mkdir "$collection_growth_root"
printf x >"$collection_growth_root/a"
printf x >"$collection_growth_root/b"
collection_growth_deadline="$(campaign_deadline_from_timeout_seconds 10)"
set +e
BORONDNS_COLLECTION_SNAPSHOT_TEST_PHASE=after-inventory \
    BORONDNS_COLLECTION_SNAPSHOT_TEST_MARKER="$collection_growth_marker" \
    BORONDNS_COLLECTION_SNAPSHOT_TEST_CONTINUE="$collection_growth_continue" \
    python3 "$repo_root/scripts/validate-collected-campaign.py" tree-snapshot \
    "$collection_growth_root" --absolute-deadline-nanoseconds "$collection_growth_deadline" \
    --max-file-bytes 100 --max-total-bytes 100 \
    >"$workdir/collection-growth.out" 2>"$workdir/collection-growth.err" &
collection_growth_pid=$!
set -e
collection_growth_wait=$((SECONDS + 5))
until [[ -e "$collection_growth_marker" ]]; do
    kill -0 "$collection_growth_pid" 2>/dev/null || break
    ((SECONDS < collection_growth_wait)) || break
    sleep 0.01
done
[[ -e "$collection_growth_marker" ]]
head -c 80 /dev/zero >"$collection_growth_root/a"
head -c 80 /dev/zero >"$collection_growth_root/b"
: >"$collection_growth_continue"
set +e
wait "$collection_growth_pid"
collection_growth_status=$?
set -e
if ((collection_growth_status == 0)); then
    printf 'collection snapshot accepted inventory-to-hash aggregate growth\n' >&2
    exit 1
fi
grep -Eq 'changed after collection inventory|streamed byte cap exceeded' \
    "$workdir/collection-growth.err"

# Every timerfd-facing primitive rejects a non-canonical or overflowing signed
# 64-bit deadline before spawning work.
deadline_rejection_started="$(date +%s%N)"
if campaign_run_before_deadline 18446744073709551616000000000 sleep 5; then
    printf 'deadline supervisor accepted a wrapping timerfd deadline\n' >&2
    exit 1
fi
deadline_rejection_elapsed=$((($(date +%s%N) - deadline_rejection_started) / 1000000))
((deadline_rejection_elapsed < 500))
if python3 "$repo_root/scripts/campaign-lock-helper.py" "$workdir" overflow-deadline \
    'overflow deadline fixture' 18446744073709551616000000000 </dev/null \
    >"$workdir/overflow-deadline.out" 2>"$workdir/overflow-deadline.err"; then
    printf 'lock broker accepted a wrapping timerfd deadline\n' >&2
    exit 1
fi
grep -Fq 'invalid overflow deadline fixture absolute deadline' "$workdir/overflow-deadline.err"

BORONDNS_CAMPAIGN_COLLECTION_MAX_ENTRIES=4 \
    campaign_prepare_collection_budget collection_bounds_deadline
if campaign_local_tree_snapshot "$collection_bounds_root" "$collection_bounds_deadline" \
    "$repo_root/scripts/validate-collected-campaign.py" >/dev/null 2>&1; then
    printf 'bounded local collection snapshot accepted an entry flood\n' >&2
    exit 1
fi
atomic_enumeration_identity="$(stat -c '%d:%i:%u' "$atomic_enumeration_root")"
atomic_enumeration_remainder="${atomic_enumeration_identity#*:}"
atomic_enumeration_output=caller-sentinel
if campaign_enumerate_direct_children_bounded "$atomic_enumeration_root" \
    "${atomic_enumeration_identity%%:*}" "${atomic_enumeration_remainder%%:*}" \
    "${atomic_enumeration_identity##*:}" '.marker.env.borondns-staged.' 1 \
    atomic_enumeration_output 2>"$workdir/atomic-enumeration-deadline.err"; then
    printf 'atomic stale-status enumerator accepted an expired deadline\n' >&2
    exit 1
fi
grep -Fq 'campaign directory enumeration deadline expired' \
    "$workdir/atomic-enumeration-deadline.err"
[[ "$atomic_enumeration_output" == caller-sentinel ]]
[[ "$(sha256sum "$atomic_enumeration_destination" \
    "$atomic_enumeration_root"/.marker.env.borondns-staged.* | sort)" == "$atomic_enumeration_before" ]]

campaign_acquire_private_lock "$workdir" "$workdir:atomic-identity-tests" \
    "atomic identity regression lock"

atomic_displaced_parent="$workdir/atomic-lock-root-displaced"
campaign_atomic_replace_text_hook() {
    [[ "$1" != before-final-rename ]] || {
        mv -- "$atomic_lock_root" "$atomic_displaced_parent"
        mkdir -- "$atomic_lock_root"
    }
}
if campaign_atomic_replace_text "$atomic_destination" parent-swap "atomic parent replacement fixture"; then
    printf 'atomic marker helper accepted a replaced parent directory\n' >&2
    exit 1
fi
grep -Fqx replacement "$atomic_displaced_parent/marker.env"
[[ ! -e "$atomic_lock_root/marker.env" ]]
rmdir -- "$atomic_lock_root"
mv -- "$atomic_displaced_parent" "$atomic_lock_root"
unset -f campaign_atomic_replace_text_hook

atomic_substituted_staged=""
atomic_original_staged=""
campaign_atomic_replace_text_hook() {
    [[ "$1" != before-final-rename ]] || {
        atomic_substituted_staged="$2"
        atomic_original_staged="$2.original"
        mv -- "$2" "$atomic_original_staged"
        printf 'forged\n' >"$atomic_substituted_staged"
    }
}
if campaign_atomic_replace_text "$atomic_destination" trusted "atomic staged substitution fixture"; then
    printf 'atomic marker helper accepted a substituted staged pathname\n' >&2
    exit 1
fi
grep -Fqx replacement "$atomic_destination"
grep -Fqx forged "$atomic_substituted_staged"
grep -Fqx trusted "$atomic_original_staged"
rm -f -- "$atomic_substituted_staged" "$atomic_original_staged"
unset -f campaign_atomic_replace_text_hook

# The low-level publisher must reject both a FIFO pathname replacement and
# growth of the exact captured inode without blocking or hashing unbounded
# bytes. The destination remains unchanged in either case.
for atomic_staged_poison in fifo oversized; do
    atomic_poison_staged="$atomic_lock_root/.atomic-$atomic_staged_poison-staged"
    atomic_poison_saved="$atomic_poison_staged.original"
    printf 'captured atomic staging\n' >"$atomic_poison_staged"
    atomic_poison_sha256="$(campaign_sha256 "$atomic_poison_staged")"
    atomic_poison_identity="$(stat -c '%d:%i' "$atomic_poison_staged")"
    atomic_poison_size="$(stat -c %s "$atomic_poison_staged")"
    if [[ "$atomic_staged_poison" == fifo ]]; then
        mv -- "$atomic_poison_staged" "$atomic_poison_saved"
        mkfifo "$atomic_poison_staged"
    else
        truncate -s 16777217 "$atomic_poison_staged"
    fi
    atomic_poison_parent_identity="$(stat -c '%d:%i' "$atomic_lock_root")"
    atomic_poison_destination_identity="$(stat -c '%d:%i' "$atomic_destination")"
    set +e
    # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
    timeout --kill-after=1 3 bash --noprofile --norc -c '
        source "$1/scripts/campaign-env.sh"
        campaign_identity_bound_replace_text "$2" "$3" "$4" "$5" "$6" "$7" \
            "$8" "$9" "${10}" "${11}" "${12}" "${13}"
    ' _ "$repo_root" "$atomic_lock_root" "$atomic_poison_staged" "$atomic_destination" \
        "${atomic_poison_parent_identity%%:*}" "${atomic_poison_parent_identity#*:}" \
        "$atomic_poison_sha256" "${atomic_poison_identity%%:*}" \
        "${atomic_poison_identity#*:}" "$atomic_poison_size" file \
        "${atomic_poison_destination_identity%%:*}" "${atomic_poison_destination_identity#*:}" \
        >"$workdir/atomic-staged-$atomic_staged_poison.out" \
        2>"$workdir/atomic-staged-$atomic_staged_poison.err"
    atomic_poison_status=$?
    set -e
    if ((atomic_poison_status == 0 || atomic_poison_status == 124 || \
        atomic_poison_status == 137)); then
        printf 'identity-bound text publication accepted or blocked on %s staging\n' \
            "$atomic_staged_poison" >&2
        exit 1
    fi
    grep -Fqx replacement "$atomic_destination"
    rm -f -- "$atomic_poison_staged" "$atomic_poison_saved"
done

# Pause after the staging inode is moved to its private bound name, mutate that
# inode, and prove the destination never observes the forged bytes.
atomic_bound_staged="$atomic_lock_root/.bound-mutation-staged"
printf 'trusted-bound-content\n' >"$atomic_bound_staged"
atomic_bound_sha256="$(sha256sum "$atomic_bound_staged" | awk '{ print $1 }')"
atomic_bound_parent_identity="$(stat -c '%d:%i' "$atomic_lock_root")"
atomic_bound_staged_identity="$(stat -c '%d:%i' "$atomic_bound_staged")"
atomic_bound_staged_size="$(stat -c %s "$atomic_bound_staged")"
atomic_bound_destination_identity="$(stat -c '%d:%i' "$atomic_destination")"
atomic_bound_marker="$workdir/atomic-bound-mutation.marker"
atomic_bound_continue="$workdir/atomic-bound-mutation.continue"
BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_PHASE=post-bound-move \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_MARKER="$atomic_bound_marker" \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_CONTINUE="$atomic_bound_continue" \
    campaign_identity_bound_replace_text "$atomic_lock_root" "$atomic_bound_staged" \
    "$atomic_destination" "${atomic_bound_parent_identity%%:*}" \
    "${atomic_bound_parent_identity#*:}" "$atomic_bound_sha256" \
    "${atomic_bound_staged_identity%%:*}" "${atomic_bound_staged_identity#*:}" \
    "$atomic_bound_staged_size" file \
    "${atomic_bound_destination_identity%%:*}" "${atomic_bound_destination_identity#*:}" \
    >"$workdir/atomic-bound-mutation.out" 2>"$workdir/atomic-bound-mutation.err" &
atomic_bound_pid=$!
for _ in {1..300}; do
    [[ -e "$atomic_bound_marker" ]] && break
    sleep 0.01
done
[[ -e "$atomic_bound_marker" ]]
atomic_bound_path="$(find "$atomic_lock_root" -maxdepth 1 -type f \
    -name '.marker.env.borondns-bound.*' -print -quit)"
[[ -n "$atomic_bound_path" ]]
printf 'forged-bound-content\n' >"$atomic_bound_path"
: >"$atomic_bound_continue"
if wait "$atomic_bound_pid"; then
    printf 'identity-bound publication accepted bytes changed through its bound name\n' >&2
    exit 1
fi
grep -Fqx replacement "$atomic_destination"
grep -Fqx forged-bound-content "$atomic_bound_staged"
rm -f -- "$atomic_bound_staged" "$atomic_bound_marker" "$atomic_bound_continue"

# A replacement of the displaced pathname after RENAME_EXCHANGE must never be
# exchanged back into the destination.
atomic_exchange_staged="$atomic_lock_root/.exchange-replacement-staged"
printf 'trusted-exchange-content\n' >"$atomic_exchange_staged"
atomic_exchange_sha256="$(sha256sum "$atomic_exchange_staged" | awk '{ print $1 }')"
atomic_exchange_staged_identity="$(stat -c '%d:%i' "$atomic_exchange_staged")"
atomic_exchange_staged_size="$(stat -c %s "$atomic_exchange_staged")"
atomic_exchange_destination_identity="$(stat -c '%d:%i' "$atomic_destination")"
atomic_exchange_marker="$workdir/atomic-exchange-replacement.marker"
atomic_exchange_continue="$workdir/atomic-exchange-replacement.continue"
atomic_exchange_saved="$atomic_lock_root/displaced-destination.saved"
BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_PHASE=post-exchange \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_MARKER="$atomic_exchange_marker" \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_CONTINUE="$atomic_exchange_continue" \
    campaign_identity_bound_replace_text "$atomic_lock_root" "$atomic_exchange_staged" \
    "$atomic_destination" "${atomic_bound_parent_identity%%:*}" \
    "${atomic_bound_parent_identity#*:}" "$atomic_exchange_sha256" \
    "${atomic_exchange_staged_identity%%:*}" "${atomic_exchange_staged_identity#*:}" \
    "$atomic_exchange_staged_size" file \
    "${atomic_exchange_destination_identity%%:*}" "${atomic_exchange_destination_identity#*:}" \
    >"$workdir/atomic-exchange-replacement.out" 2>"$workdir/atomic-exchange-replacement.err" &
atomic_exchange_pid=$!
for _ in {1..300}; do
    [[ -e "$atomic_exchange_marker" ]] && break
    sleep 0.01
done
[[ -e "$atomic_exchange_marker" ]]
atomic_exchange_bound="$(find "$atomic_lock_root" -maxdepth 1 -type f \
    -name '.marker.env.borondns-bound.*' -print -quit)"
[[ -n "$atomic_exchange_bound" ]]
mv -- "$atomic_exchange_bound" "$atomic_exchange_saved"
printf 'foreign-exchange-content\n' >"$atomic_exchange_bound"
: >"$atomic_exchange_continue"
if wait "$atomic_exchange_pid"; then
    printf 'identity-bound publication accepted a replaced displaced pathname\n' >&2
    exit 1
fi
grep -Fqx trusted-exchange-content "$atomic_destination"
grep -Fqx foreign-exchange-content "$atomic_exchange_bound"
grep -Fqx replacement "$atomic_exchange_saved"
rm -f -- "$atomic_exchange_bound" "$atomic_exchange_saved" \
    "$atomic_exchange_marker" "$atomic_exchange_continue"

# If the newly published inode is modified before its final content rehash,
# recovery atomically fences the destination with authenticated rejection text.
# A second swap at the failure boundary is quarantined rather than deleted.
atomic_rehash_staged="$atomic_lock_root/.rehash-failure-staged"
printf 'trusted-rehash-content\n' >"$atomic_rehash_staged"
atomic_rehash_sha256="$(sha256sum "$atomic_rehash_staged" | awk '{ print $1 }')"
atomic_rehash_staged_identity="$(stat -c '%d:%i' "$atomic_rehash_staged")"
atomic_rehash_staged_size="$(stat -c %s "$atomic_rehash_staged")"
atomic_rehash_destination_identity="$(stat -c '%d:%i' "$atomic_destination")"
atomic_rehash_marker="$workdir/atomic-rehash-failure.marker"
atomic_rehash_continue="$workdir/atomic-rehash-failure.continue"
atomic_rejection_marker="$workdir/atomic-rejection-cleanup.marker"
atomic_rejection_continue="$workdir/atomic-rejection-cleanup.continue"
atomic_rehash_saved="$atomic_lock_root/rehash-failure.saved"
BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_PHASE=post-exchange \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_MARKER="$atomic_rehash_marker" \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_TEST_CONTINUE="$atomic_rehash_continue" \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_REJECTION_TEST_MARKER="$atomic_rejection_marker" \
    BORONDNS_CAMPAIGN_REPLACE_TEXT_REJECTION_TEST_CONTINUE="$atomic_rejection_continue" \
    campaign_identity_bound_replace_text "$atomic_lock_root" "$atomic_rehash_staged" \
    "$atomic_destination" "${atomic_bound_parent_identity%%:*}" \
    "${atomic_bound_parent_identity#*:}" "$atomic_rehash_sha256" \
    "${atomic_rehash_staged_identity%%:*}" "${atomic_rehash_staged_identity#*:}" \
    "$atomic_rehash_staged_size" file \
    "${atomic_rehash_destination_identity%%:*}" "${atomic_rehash_destination_identity#*:}" \
    >"$workdir/atomic-rehash-failure.out" 2>"$workdir/atomic-rehash-failure.err" &
atomic_rehash_pid=$!
for _ in {1..300}; do
    [[ -e "$atomic_rehash_marker" ]] && break
    sleep 0.01
done
[[ -e "$atomic_rehash_marker" ]]
printf 'forged-published-content\n' >"$atomic_destination"
: >"$atomic_rehash_continue"
for _ in {1..300}; do
    [[ -e "$atomic_rejection_marker" ]] && break
    sleep 0.01
done
[[ -e "$atomic_rejection_marker" ]]
mv -- "$atomic_destination" "$atomic_rehash_saved"
printf 'foreign-rejection-race-content\n' >"$atomic_destination"
: >"$atomic_rejection_continue"
if wait "$atomic_rehash_pid"; then
    printf 'identity-bound publication accepted a post-publication content mutation\n' >&2
    exit 1
fi
grep -Fqx 'borondns publication rejected: authenticated content changed' "$atomic_destination"
atomic_rejected_path="$(find "$atomic_lock_root" -maxdepth 1 -type f \
    -name '.marker.env.borondns-rejected.*' -print -quit)"
atomic_rehash_bound="$(find "$atomic_lock_root" -maxdepth 1 -type f \
    -name '.marker.env.borondns-bound.*' -print -quit)"
[[ -n "$atomic_rejected_path" && -n "$atomic_rehash_bound" ]]
grep -Fqx foreign-rejection-race-content "$atomic_rejected_path"
grep -Fqx forged-published-content "$atomic_rehash_saved"
grep -Fqx trusted-exchange-content "$atomic_rehash_bound"
rm -f -- "$atomic_rejected_path" "$atomic_rehash_bound" "$atomic_rehash_saved" \
    "$atomic_rehash_marker" "$atomic_rehash_continue" \
    "$atomic_rejection_marker" "$atomic_rejection_continue"
campaign_release_private_lock

runner_bootstrap_target="$workdir/runner-bootstrap-target"
mkdir "$runner_bootstrap_target"
runner_bootstrap_target_identity="$(stat -c '%d:%i:%u:%g:%a' "$runner_bootstrap_target")"
runner_bootstrap_base="/var/tmp/borondns-runner-bootstrap-$fixture_unit_suffix"
runner_bootstrap_root="$runner_bootstrap_base/borondns-campaign-runners"
runner_bootstrap_unit="$runner_bootstrap_root/hostile.service"
sudo rm -rf -- "$runner_bootstrap_base"
mkdir "$runner_bootstrap_base"
ln -s "$runner_bootstrap_target" "$runner_bootstrap_root"
sudo chown root:root "$runner_bootstrap_base"
sudo chmod 0755 "$runner_bootstrap_base"
campaign_acquire_private_lock "$workdir" runner-bootstrap-symlink "runner bootstrap symlink fixture"
if campaign_prepare_root_runner_tree "$runner_bootstrap_root" "$runner_bootstrap_unit" \
    "runner bootstrap symlink fixture"; then
    printf 'root runner bootstrap followed a pre-existing runner-root symlink\n' >&2
    exit 1
fi
[[ "$(stat -c '%d:%i:%u:%g:%a' "$runner_bootstrap_target")" == "$runner_bootstrap_target_identity" ]]
campaign_release_private_lock
sudo rm -rf -- "$runner_bootstrap_base"

mkdir -p "$runner_bootstrap_root"
sudo chown root:root "$runner_bootstrap_base"
sudo chmod 0755 "$runner_bootstrap_base"
foreign_runner_identity="$(stat -c '%d:%i:%u:%g:%a' "$runner_bootstrap_root")"
campaign_acquire_private_lock "$workdir" runner-bootstrap-owner "runner bootstrap owner fixture"
if campaign_prepare_root_runner_tree "$runner_bootstrap_root" "$runner_bootstrap_unit" \
    "runner bootstrap owner fixture"; then
    printf 'root runner bootstrap accepted a foreign-owned runner root\n' >&2
    exit 1
fi
[[ "$(stat -c '%d:%i:%u:%g:%a' "$runner_bootstrap_root")" == "$foreign_runner_identity" ]]
campaign_release_private_lock
sudo rm -rf -- "$runner_bootstrap_base"

mkdir -p "$runner_bootstrap_root"
ln -s "$runner_bootstrap_target" "$runner_bootstrap_unit"
sudo chown root:root "$runner_bootstrap_base" "$runner_bootstrap_root"
sudo chmod 0755 "$runner_bootstrap_base" "$runner_bootstrap_root"
campaign_acquire_private_lock "$workdir" runner-bootstrap-child "runner bootstrap child symlink fixture"
if campaign_prepare_root_runner_tree "$runner_bootstrap_root" "$runner_bootstrap_unit" \
    "runner bootstrap child symlink fixture"; then
    printf 'root runner bootstrap followed a pre-existing unit-child symlink\n' >&2
    exit 1
fi
[[ "$(stat -c '%d:%i:%u:%g:%a' "$runner_bootstrap_target")" == "$runner_bootstrap_target_identity" ]]
campaign_release_private_lock
sudo rm -rf -- "$runner_bootstrap_base"

root_atomic_dir="$workdir/root-atomic-publication"
root_atomic_destination="$root_atomic_dir/prerequisite-service-state.env"
sudo install -d -m 0755 -o root -g root -- "$root_atomic_dir"

privileged_open_root="$workdir/privileged-open-hardening"
privileged_open_staged="$privileged_open_root/.staged"
privileged_open_destination="$privileged_open_root/destination"
sudo install -d -m 0755 -o root -g root -- "$privileged_open_root"
printf 'captured privileged staging\n' >"$workdir/privileged-open-candidate"
privileged_open_sha256="$(campaign_sha256 "$workdir/privileged-open-candidate")"
privileged_open_size="$(stat -c %s "$workdir/privileged-open-candidate")"
privileged_open_root_identity="$(stat -c '%d:%i:%u' "$privileged_open_root")"
privileged_open_root_remainder="${privileged_open_root_identity#*:}"
for privileged_open_poison in fifo oversized; do
    sudo rm -f -- "$privileged_open_staged" "$privileged_open_staged.original"
    if [[ "$privileged_open_poison" == fifo ]]; then
        sudo install -m 0444 -o root -g root -- "$workdir/privileged-open-candidate" \
            "$privileged_open_staged.original"
        sudo mkfifo -m 0444 "$privileged_open_staged"
        privileged_test_size="$privileged_open_size"
    else
        sudo install -m 0444 -o root -g root -- /dev/null "$privileged_open_staged"
        sudo truncate -s 16777217 "$privileged_open_staged"
        privileged_test_size=16777217
    fi
    set +e
    # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
    timeout --kill-after=1 3 bash --noprofile --norc -c '
        source "$1/scripts/campaign-env.sh"
        campaign_privileged_publish_bound_file "$2" "$3" "$4" "$5" "$6" "$7" \
            "$8" "$9" "${10}" "${11}" "${12}" "${13}"
    ' _ "$repo_root" "$privileged_open_root" "$privileged_open_destination" \
        "$privileged_open_staged" "$privileged_open_sha256" 0444 "$privileged_test_size" \
        "${privileged_open_root_identity%%:*}" \
        "${privileged_open_root_remainder%%:*}" "${privileged_open_root_identity##*:}" \
        absent 0 0 >"$workdir/privileged-open-$privileged_open_poison.out" \
        2>"$workdir/privileged-open-$privileged_open_poison.err"
    privileged_open_status=$?
    set -e
    if ((privileged_open_status == 0 || privileged_open_status == 124 || \
        privileged_open_status == 137)); then
        printf 'privileged publication accepted or blocked on %s staging\n' \
            "$privileged_open_poison" >&2
        exit 1
    fi
    [[ ! -e "$privileged_open_destination" && ! -L "$privileged_open_destination" ]]
done
sudo rm -rf -- "$privileged_open_root"

printf -v root_atomic_content '%s\n' \
    service_state_version=1 \
    docker_enabled=disabled docker_active=inactive \
    named_enabled=enabled named_active=active \
    bind9_enabled=masked bind9_active=inactive
root_atomic_content="${root_atomic_content%$'\n'}"
campaign_acquire_private_lock "$workdir" root-atomic-swap "root atomic candidate swap fixture"
campaign_root_atomic_text_hook() {
    if [[ "$1" == before-candidate-copy ]]; then
        printf '%s\n' \
            service_state_version=1 \
            docker_enabled=masked docker_active=active \
            named_enabled=masked named_active=active \
            bind9_enabled=masked bind9_active=active >"$2"
    fi
}
if campaign_publish_root_atomic_text "$root_atomic_dir" "$root_atomic_destination" \
    "$root_atomic_content" "root atomic candidate swap fixture" prerequisite-service-state; then
    printf 'root atomic text publication accepted a same-UID candidate swap\n' >&2
    exit 1
fi
unset -f campaign_root_atomic_text_hook
[[ ! -e "$root_atomic_destination" ]]
campaign_publish_root_atomic_text "$root_atomic_dir" "$root_atomic_destination" \
    "$root_atomic_content" "root atomic service-state fixture" prerequisite-service-state
campaign_load_prerequisite_service_state "$root_atomic_destination"
# shellcheck disable=SC2154 # populated by campaign_load_prerequisite_service_state
[[ "$campaign_prior_docker_enabled" == disabled && "$campaign_prior_named_active" == active &&
    "$campaign_prior_bind9_enabled" == masked ]]

root_atomic_race_destination="$root_atomic_dir/restored.marker"
printf 'foreign privileged marker must survive\n' >"$workdir/root-atomic-foreign"
campaign_root_atomic_text_hook() {
    if [[ "$1" == before-final-rename ]]; then
        sudo install -m 0444 -o root -g root -- "$workdir/root-atomic-foreign" "$3"
    fi
}
if campaign_publish_root_atomic_text "$root_atomic_dir" "$root_atomic_race_destination" \
    restored "root atomic destination race fixture" restored-marker; then
    printf 'root atomic publisher replaced a concurrent destination\n' >&2
    exit 1
fi
unset -f campaign_root_atomic_text_hook
grep -Fqx 'foreign privileged marker must survive' "$root_atomic_race_destination"
[[ -n "$(find "$root_atomic_dir" -maxdepth 1 -type f \
    -name '.restored.marker.borondns-staged.*' -print -quit)" ]]
campaign_release_private_lock
sudo rm -rf -- "$root_atomic_dir"

privileged_candidate="$workdir/privileged-runner.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$privileged_candidate"
chmod +x "$privileged_candidate"
privileged_unit="borondns-operations-broker-traversal-$fixture_unit_suffix.service"
campaign_acquire_private_lock "$workdir" privileged-traversal "privileged traversal fixture"
publish_test_root_runner "$privileged_unit" "$privileged_candidate" "privileged traversal fixture"
privileged_tree="/var/tmp/borondns-campaign-runners/${privileged_unit%.service}"

runner_swap_unit="borondns-operations-runner-swap-$fixture_unit_suffix.service"
runner_swap_candidate="$workdir/runner-swap.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$runner_swap_candidate"
chmod 0700 "$runner_swap_candidate"
runner_swap_identity_sha256=""
runner_swap_identity_device=""
runner_swap_identity_inode=""
campaign_capture_candidate_identity "$runner_swap_candidate" runner_swap_identity
campaign_privileged_publication_hook() {
    [[ "$1" != before-runner-copy ]] || printf '#!/usr/bin/env bash\nexec /bin/sh\n' >"$2"
}
if campaign_publish_root_runner "$runner_swap_unit" "$runner_swap_candidate" \
    "$runner_swap_identity_sha256" "$runner_swap_identity_device" "$runner_swap_identity_inode" \
    "same-UID runner swap fixture"; then
    printf 'root runner publication accepted a same-UID candidate swap\n' >&2
    exit 1
fi
unset -f campaign_privileged_publication_hook
[[ -z "$(find "/var/tmp/borondns-campaign-runners/${runner_swap_unit%.service}" -type f -name run.sh -print -quit 2>/dev/null)" ]]
campaign_remove_root_runner_tree "$runner_swap_unit" "same-UID runner swap fixture"

fragment_test_root="$workdir/fragment-publication-root"
mkdir "$fragment_test_root"
fragment_test_destination="$fragment_test_root/borondns-fragment-test.service"
fragment_test_candidate="$workdir/fragment-test.service"
cat >"$fragment_test_candidate" <<UNIT
[Unit]
Description=BoronDNS publication race fixture
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex
WorkingDirectory=/home/codex/borondns
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LimitNOFILE=65536
ExecStart=$campaign_published_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=borondns-fragment-test
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
fragment_test_identity_sha256=""
fragment_test_identity_device=""
fragment_test_identity_inode=""
campaign_capture_candidate_identity "$fragment_test_candidate" fragment_test_identity

printf 'foreign systemd fragment must survive\n' >"$workdir/fragment-race-foreign"
campaign_privileged_publication_hook() {
    if [[ "$1" == before-fragment-commit ]]; then
        sudo install -m 0644 -o root -g root -- "$workdir/fragment-race-foreign" "$3"
    fi
}
if campaign_publish_systemd_fragment "$fragment_test_root" "$fragment_test_destination" \
    "$fragment_test_candidate" "$campaign_published_runner" "$fragment_test_identity_sha256" \
    "$fragment_test_identity_device" "$fragment_test_identity_inode" \
    "systemd fragment destination race fixture"; then
    printf 'systemd fragment publisher replaced a concurrent destination\n' >&2
    exit 1
fi
unset -f campaign_privileged_publication_hook
grep -Fqx 'foreign systemd fragment must survive' "$fragment_test_destination"
[[ -n "$(find "$fragment_test_root" -maxdepth 1 -type f \
    -name '.borondns-fragment-test.service.borondns-staged.*' -print -quit)" ]]
sudo rm -f -- "$fragment_test_destination"
campaign_remove_systemd_fragment_staging "$fragment_test_root" "$fragment_test_destination" \
    "systemd fragment destination race fixture"

fragment_runtime_only="$workdir/fragment-runtime-only.service"
sed '/^\[Install\]$/i RuntimeMaxSec=60' "$fragment_test_candidate" >"$fragment_runtime_only"
if campaign_validate_systemd_fragment_schema "$fragment_runtime_only" "$campaign_published_runner"; then
    printf 'systemd fragment schema accepted RuntimeMaxSec without TimeoutStopSec\n' >&2
    exit 1
fi
fragment_runtime_pair="$workdir/fragment-runtime-pair.service"
sed '/^\[Install\]$/i RuntimeMaxSec=60\nTimeoutStopSec=30' "$fragment_test_candidate" >"$fragment_runtime_pair"
campaign_validate_systemd_fragment_schema "$fragment_runtime_pair" "$campaign_published_runner"
fragment_portable_user="$workdir/fragment-portable-user.service"
sed -e 's/^User=codex$/User=tibi/' \
    -e '/^LimitNOFILE=/i Environment=CARGO_HOME=/home/tibi/.cargo\nEnvironment=RUSTUP_HOME=/home/tibi/.rustup\nEnvironment=CARGO_BUILD_JOBS=1' \
    "$fragment_runtime_pair" >"$fragment_portable_user"
campaign_validate_systemd_fragment_schema "$fragment_portable_user" "$campaign_published_runner"
grep -Fq 'GIT_CONFIG_KEY_0=safe.directory' "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
# Assert literal generated-shell expressions.
# shellcheck disable=SC2016
grep -Fq 'GIT_CONFIG_VALUE_0="$source_dir"' "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
# Assert literal generated-shell expressions.
# shellcheck disable=SC2016
grep -Fq 'size_target_setup_reserve "$((${#targets[@]} * target_repeat))"' \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
grep -Fq 'fuzz_internal_artifact_dir' "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
fragment_derived_runtime_pair="$workdir/fragment-derived-runtime-pair.service"
sed '/^\[Install\]$/i RuntimeMaxSec=5745\nTimeoutStopSec=285' "$fragment_test_candidate" >"$fragment_derived_runtime_pair"
campaign_validate_systemd_fragment_schema "$fragment_derived_runtime_pair" "$campaign_published_runner"
fragment_excessive_stop="$workdir/fragment-excessive-stop.service"
sed '/^\[Install\]$/i RuntimeMaxSec=60\nTimeoutStopSec=61' "$fragment_test_candidate" >"$fragment_excessive_stop"
if campaign_validate_systemd_fragment_schema "$fragment_excessive_stop" "$campaign_published_runner"; then
    printf 'systemd fragment schema accepted TimeoutStopSec beyond RuntimeMaxSec\n' >&2
    exit 1
fi

campaign_privileged_publication_hook() {
    [[ "$1" != before-fragment-copy ]] || sed -i 's/^User=codex$/User=root/' "$2"
}
if campaign_publish_systemd_fragment "$fragment_test_root" "$fragment_test_destination" \
    "$fragment_test_candidate" "$campaign_published_runner" "$fragment_test_identity_sha256" \
    "$fragment_test_identity_device" "$fragment_test_identity_inode" "same-UID fragment swap fixture"; then
    printf 'systemd fragment publication accepted a same-UID candidate swap\n' >&2
    exit 1
fi
unset -f campaign_privileged_publication_hook
[[ ! -e "$fragment_test_destination" ]]

sed -i 's/^User=root$/User=codex/' "$fragment_test_candidate"
sed -i '/^ExecStart=/i ExecStartPre=/bin/true' "$fragment_test_candidate"
malicious_fragment_identity_sha256=""
malicious_fragment_identity_device=""
malicious_fragment_identity_inode=""
campaign_capture_candidate_identity "$fragment_test_candidate" malicious_fragment_identity
if campaign_publish_systemd_fragment "$fragment_test_root" "$fragment_test_destination" \
    "$fragment_test_candidate" "$campaign_published_runner" "$malicious_fragment_identity_sha256" \
    "$malicious_fragment_identity_device" "$malicious_fragment_identity_inode" "direct malicious fragment fixture"; then
    printf 'systemd fragment publication accepted an extra privileged execution directive\n' >&2
    exit 1
fi
[[ ! -e "$fragment_test_destination" ]]

# A cleanup hook models an atomic pathname replacement after all schema and
# ownership checks.  Privileged cleanup must refuse the replacement and retain
# both it and the displaced, previously validated object.
fragment_staging_root="$workdir/fragment-staging-cleanup-root"
fragment_staging_destination="$fragment_staging_root/borondns-staging-cleanup.service"
fragment_staging_file="$fragment_staging_root/.borondns-staging-cleanup.service.borondns-staged.fixture"
fragment_staging_displaced="$fragment_staging_file.displaced"
sudo install -d -m 0755 -o root -g root -- "$fragment_staging_root"
printf 'validated staging fragment\n' >"$workdir/fragment-staging-candidate"
sudo install -m 0644 -o root -g root -- "$workdir/fragment-staging-candidate" "$fragment_staging_file"
# shellcheck disable=SC2329 # Exported fault-injection hook consumed by campaign cleanup.
campaign_privileged_cleanup_hook() {
    if [[ "$1" == before-fragment-staging-remove ]]; then
        sudo mv -- "$2" "$fragment_staging_displaced"
        printf 'replacement staging fragment\n' >"$workdir/fragment-staging-replacement"
        sudo install -m 0644 -o root -g root -- \
            "$workdir/fragment-staging-replacement" "$2"
    fi
}
if campaign_remove_systemd_fragment_staging "$fragment_staging_root" \
    "$fragment_staging_destination" "staging cleanup identity fixture"; then
    printf 'privileged staging cleanup removed a replacement pathname\n' >&2
    exit 1
fi
[[ "$(cat "$fragment_staging_file")" == 'replacement staging fragment' ]]
[[ "$(cat "$fragment_staging_displaced")" == 'validated staging fragment' ]]
unset -f campaign_privileged_cleanup_hook
sudo rm -rf -- "$fragment_staging_root"

runner_cleanup_swap_unit="borondns-operations-runner-cleanup-swap-$fixture_unit_suffix.service"
publish_test_root_runner "$runner_cleanup_swap_unit" "$privileged_candidate" \
    "runner cleanup identity fixture"
runner_cleanup_swap_tree="/var/tmp/borondns-campaign-runners/${runner_cleanup_swap_unit%.service}"
runner_cleanup_swap_displaced="$runner_cleanup_swap_tree.displaced"
# shellcheck disable=SC2329 # Exported fault-injection hook consumed by campaign cleanup.
campaign_privileged_cleanup_hook() {
    if [[ "$1" == before-runner-tree-remove ]]; then
        sudo mv -- "$2" "$runner_cleanup_swap_displaced"
        sudo install -d -m 0755 -o root -g root -- "$2"
        printf 'replacement runner tree\n' >"$workdir/runner-cleanup-replacement"
        sudo install -m 0644 -o root -g root -- \
            "$workdir/runner-cleanup-replacement" "$2/replacement-marker"
    fi
}
if campaign_remove_root_runner_tree "$runner_cleanup_swap_unit" \
    "runner cleanup identity fixture"; then
    printf 'privileged runner cleanup removed a replacement pathname\n' >&2
    exit 1
fi
[[ "$(cat "$runner_cleanup_swap_tree/replacement-marker")" == 'replacement runner tree' ]]
[[ -n "$(find "$runner_cleanup_swap_displaced" -mindepth 2 -maxdepth 2 -type f -name run.sh -perm -0100 -print -quit)" ]]
unset -f campaign_privileged_cleanup_hook
sudo rm -rf -- "$runner_cleanup_swap_tree"
sudo mv -- "$runner_cleanup_swap_displaced" "$runner_cleanup_swap_tree"
campaign_remove_root_runner_tree "$runner_cleanup_swap_unit" \
    "runner cleanup identity recovery fixture"
[[ ! -e "$runner_cleanup_swap_tree" ]]

# shellcheck disable=SC2329 # Exported fault-injection hook consumed by campaign cleanup.
campaign_privileged_cleanup_hook() {
    [[ "$1" != before-runner-tree-remove ]] || {
        kill "$campaign_lock_pid"
        wait "$campaign_lock_pid" 2>/dev/null || true
    }
}
if campaign_remove_root_runner_tree "$privileged_unit" "privileged traversal fixture"; then
    printf 'privileged runner cleanup removed state after broker death\n' >&2
    exit 1
fi
[[ -d "$privileged_tree" ]]
unset -f campaign_privileged_cleanup_hook
campaign_release_private_lock
campaign_acquire_private_lock "$workdir" privileged-traversal "privileged traversal recovery fixture"
campaign_remove_root_runner_tree "$privileged_unit" "privileged traversal recovery fixture"
[[ ! -e "$privileged_tree" ]]
campaign_release_private_lock
campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" "operations harness mutation lock"

# Privilege does not make a current-UID-owned namespace immutable. Even when a
# child is replaced after the root identity was captured, sudo-backed cleanup
# must stop at whole-tree quarantine and preserve both the foreign child and the
# displaced original instead of recursively unlinking either pathname.
privileged_user_root="$workdir/privileged-user-owned-cleanup"
privileged_user_tree="$privileged_user_root/tree"
mkdir -m 0700 "$privileged_user_root" "$privileged_user_tree"
printf 'captured child\n' >"$privileged_user_tree/child"
printf 'foreign child must survive\n' >"$privileged_user_root/foreign"
privileged_user_parent_identity="$(stat -c '%d:%i:%u' "$privileged_user_root")"
privileged_user_parent_remainder="${privileged_user_parent_identity#*:}"
privileged_user_tree_identity="$(stat -c '%d:%i:%u' "$privileged_user_tree")"
privileged_user_tree_remainder="${privileged_user_tree_identity#*:}"
mv "$privileged_user_tree/child" "$privileged_user_root/child.original"
mv "$privileged_user_root/foreign" "$privileged_user_tree/child"
campaign_privileged_identity_bound_remove tree "$privileged_user_root" "$privileged_user_tree" \
    "${privileged_user_parent_identity%%:*}" "${privileged_user_parent_remainder%%:*}" \
    "${privileged_user_parent_identity##*:}" "${privileged_user_tree_identity%%:*}" \
    "${privileged_user_tree_remainder%%:*}" "${privileged_user_tree_identity##*:}"
[[ ! -e "$privileged_user_tree" ]]
privileged_user_quarantine="$(find "$privileged_user_root" -mindepth 1 -maxdepth 1 \
    -type d -name '.tree.borondns-remove.*' -print -quit)"
[[ -n "$privileged_user_quarantine" ]]
grep -Fqx 'foreign child must survive' "$privileged_user_quarantine/child"
grep -Fqx 'captured child' "$privileged_user_root/child.original"

# Root ownership alone is not namespace authority. A deterministic same-UID
# swap after the root stat must force whole-tree retention when any recursive
# boundary is mode-writable by the campaign identity.
privileged_mode_root="$workdir/privileged-mode-writable-cleanup"
privileged_mode_tree="$privileged_mode_root/tree"
privileged_mode_marker="$workdir/privileged-mode-writable.marker"
privileged_mode_continue="$workdir/privileged-mode-writable.continue"
sudo install -d -m 0755 -o root -g root -- "$privileged_mode_root"
sudo install -d -m 0777 -o root -g root -- "$privileged_mode_tree"
printf 'captured child\n' >"$privileged_mode_tree/child"
printf 'foreign child must survive\n' >"$workdir/privileged-mode-foreign"
privileged_mode_parent_identity="$(stat -c '%d:%i:%u' "$privileged_mode_root")"
privileged_mode_parent_remainder="${privileged_mode_parent_identity#*:}"
privileged_mode_tree_identity="$(stat -c '%d:%i:%u' "$privileged_mode_tree")"
privileged_mode_tree_remainder="${privileged_mode_tree_identity#*:}"
(
    while [[ ! -e "$privileged_mode_marker" ]]; do
        sleep 0.01
    done
    mv "$privileged_mode_tree/child" "$workdir/privileged-mode-child.original"
    mv "$workdir/privileged-mode-foreign" "$privileged_mode_tree/child"
    : >"$privileged_mode_continue"
) &
privileged_mode_swap_pid=$!
lock_holder_pids+=("$privileged_mode_swap_pid")
BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TEST_PHASE=after-target-stat-before-namespace-proof \
    BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TEST_MARKER="$privileged_mode_marker" \
    BORONDNS_CAMPAIGN_IDENTITY_REMOVE_TEST_CONTINUE="$privileged_mode_continue" \
    campaign_privileged_identity_bound_remove tree "$privileged_mode_root" "$privileged_mode_tree" \
    "${privileged_mode_parent_identity%%:*}" "${privileged_mode_parent_remainder%%:*}" \
    "${privileged_mode_parent_identity##*:}" "${privileged_mode_tree_identity%%:*}" \
    "${privileged_mode_tree_remainder%%:*}" "${privileged_mode_tree_identity##*:}" \
    "$(campaign_deadline_from_timeout_seconds 5)"
wait "$privileged_mode_swap_pid"
untrack_test_process "$privileged_mode_swap_pid"
privileged_mode_quarantine="$(find "$privileged_mode_root" -mindepth 1 -maxdepth 1 \
    -type d -name '.tree.borondns-remove.*' -print -quit)"
[[ -n "$privileged_mode_quarantine" && ! -e "$privileged_mode_tree" ]]
grep -Fqx 'foreign child must survive' "$privileged_mode_quarantine/child"
grep -Fqx 'captured child' "$workdir/privileged-mode-child.original"
sudo rm -rf -- "$privileged_mode_root"

# Named access ACLs are conservatively non-authoritative without a complete
# ACL principal proof. Exercise that branch when the host filesystem supports
# POSIX ACLs.
if command -v setfacl >/dev/null 2>&1; then
    privileged_acl_root="$workdir/privileged-acl-writable-cleanup"
    privileged_acl_tree="$privileged_acl_root/tree"
    sudo install -d -m 0755 -o root -g root -- "$privileged_acl_root" "$privileged_acl_tree"
    if sudo setfacl -m "u:$(id -u):rwx" "$privileged_acl_tree" 2>/dev/null; then
        printf 'ACL child must survive\n' >"$privileged_acl_tree/child"
        privileged_acl_parent_identity="$(stat -c '%d:%i:%u' "$privileged_acl_root")"
        privileged_acl_parent_remainder="${privileged_acl_parent_identity#*:}"
        privileged_acl_tree_identity="$(stat -c '%d:%i:%u' "$privileged_acl_tree")"
        privileged_acl_tree_remainder="${privileged_acl_tree_identity#*:}"
        campaign_privileged_identity_bound_remove tree "$privileged_acl_root" "$privileged_acl_tree" \
            "${privileged_acl_parent_identity%%:*}" "${privileged_acl_parent_remainder%%:*}" \
            "${privileged_acl_parent_identity##*:}" "${privileged_acl_tree_identity%%:*}" \
            "${privileged_acl_tree_remainder%%:*}" "${privileged_acl_tree_identity##*:}"
        privileged_acl_quarantine="$(find "$privileged_acl_root" -mindepth 1 -maxdepth 1 \
            -type d -name '.tree.borondns-remove.*' -print -quit)"
        [[ -n "$privileged_acl_quarantine" && ! -e "$privileged_acl_tree" ]]
        grep -Fqx 'ACL child must survive' "$privileged_acl_quarantine/child"
    fi
    sudo rm -rf -- "$privileged_acl_root"
fi

# Retained cleanups publish an exact mapping before rename. The verifier accepts
# that inode and rejects a lookalike sibling carrying a different identity.
retained_mapping_root="$workdir/retained-mapping"
retained_mapping_tree="$retained_mapping_root/tree"
mkdir -m 0700 "$retained_mapping_root" "$retained_mapping_tree"
printf 'retained payload\n' >"$retained_mapping_tree/payload"
retained_mapping_parent_identity="$(stat -c '%d:%i:%u' "$retained_mapping_root")"
retained_mapping_parent_remainder="${retained_mapping_parent_identity#*:}"
retained_mapping_tree_identity="$(stat -c '%d:%i:%u' "$retained_mapping_tree")"
retained_mapping_tree_remainder="${retained_mapping_tree_identity#*:}"
campaign_retained_identity_bound_remove unprivileged tree \
    "$retained_mapping_root" "$retained_mapping_tree" \
    "${retained_mapping_parent_identity%%:*}" "${retained_mapping_parent_remainder%%:*}" \
    "${retained_mapping_parent_identity##*:}" "${retained_mapping_tree_identity%%:*}" \
    "${retained_mapping_tree_remainder%%:*}" "${retained_mapping_tree_identity##*:}" \
    "" "retained mapping fixture" >"$workdir/retained-mapping.out"
grep -Fq $'cleanup_retained\toriginal=' "$workdir/retained-mapping.out"
campaign_verify_retained_cleanup_journal "$CAMPAIGN_LAST_RETAINED_JOURNAL" \
    >"$workdir/retained-mapping-verified.out"
grep -Fq $'cleanup_retained_verified\toriginal=' "$workdir/retained-mapping-verified.out"
retained_first_journal="$CAMPAIGN_LAST_RETAINED_JOURNAL"
retained_first_quarantine="$CAMPAIGN_LAST_RETAINED_QUARANTINE"
retained_forged_sibling="$retained_mapping_root/.tree.borondns-remove.$$.0123456789abcdef01234567"
mkdir -m 0700 "$retained_forged_sibling"
retained_forged_journal="$retained_mapping_root/.borondns-retained-cleanup-forged.env"
sed "s|^quarantine_path=.*|quarantine_path=$retained_forged_sibling|" \
    "$CAMPAIGN_LAST_RETAINED_JOURNAL" >"$retained_forged_journal"
if campaign_verify_retained_cleanup_journal "$retained_forged_journal" \
    >"$workdir/retained-forged.out" 2>"$workdir/retained-forged.err"; then
    printf 'retained-cleanup verifier accepted a forged sibling identity\n' >&2
    exit 1
fi
grep -Fq 'retained-cleanup quarantine identity changed' "$workdir/retained-forged.err"
[[ -d "$retained_forged_sibling" ]]

# A later campaign may legitimately recreate the same canonical build-root
# name with a new inode. Its cleanup must allocate a new mapping rather than
# overwrite, adopt, or be blocked by the earlier retained journal.
mkdir -m 0700 "$retained_mapping_tree"
printf 'second retained payload\n' >"$retained_mapping_tree/payload"
retained_second_tree_identity="$(stat -c '%d:%i:%u' "$retained_mapping_tree")"
retained_second_tree_remainder="${retained_second_tree_identity#*:}"
campaign_retained_identity_bound_remove unprivileged tree \
    "$retained_mapping_root" "$retained_mapping_tree" \
    "${retained_mapping_parent_identity%%:*}" "${retained_mapping_parent_remainder%%:*}" \
    "${retained_mapping_parent_identity##*:}" "${retained_second_tree_identity%%:*}" \
    "${retained_second_tree_remainder%%:*}" "${retained_second_tree_identity##*:}" \
    "" "retained mapping retry fixture" >"$workdir/retained-mapping-retry.out"
[[ "$CAMPAIGN_LAST_RETAINED_JOURNAL" != "$retained_first_journal" &&
    "$CAMPAIGN_LAST_RETAINED_QUARANTINE" != "$retained_first_quarantine" ]]
campaign_verify_retained_cleanup_journal "$retained_first_journal" >/dev/null
campaign_verify_retained_cleanup_journal "$CAMPAIGN_LAST_RETAINED_JOURNAL" >/dev/null
grep -Fqx 'retained payload' "$retained_first_quarantine/payload"
grep -Fqx 'second retained payload' "$CAMPAIGN_LAST_RETAINED_QUARANTINE/payload"

# A crash after the durable prepared record and rename leaves enough exact
# evidence to verify the retained inode. Prepared evidence is accepted only
# after the original pathname is absent and the recorded quarantine identity
# and type still match.
prepared_mapping_root="$workdir/prepared-mapping"
prepared_mapping_tree="$prepared_mapping_root/tree"
mkdir -m 0700 "$prepared_mapping_root" "$prepared_mapping_tree"
printf 'prepared payload\n' >"$prepared_mapping_tree/payload"
prepared_mapping_parent_identity="$(stat -c '%d:%i:%u' "$prepared_mapping_root")"
prepared_mapping_parent_remainder="${prepared_mapping_parent_identity#*:}"
prepared_mapping_tree_identity="$(stat -c '%d:%i:%u' "$prepared_mapping_tree")"
prepared_mapping_tree_remainder="${prepared_mapping_tree_identity#*:}"
if BORONDNS_CAMPAIGN_IDENTITY_REMOVE_FAULT_PHASE=root-quarantined \
    campaign_retained_identity_bound_remove unprivileged tree \
    "$prepared_mapping_root" "$prepared_mapping_tree" \
    "${prepared_mapping_parent_identity%%:*}" "${prepared_mapping_parent_remainder%%:*}" \
    "${prepared_mapping_parent_identity##*:}" "${prepared_mapping_tree_identity%%:*}" \
    "${prepared_mapping_tree_remainder%%:*}" "${prepared_mapping_tree_identity##*:}" \
    "" "prepared mapping fixture" >"$workdir/prepared-mapping.out" 2>"$workdir/prepared-mapping.err"; then
    printf 'prepared retained-cleanup fault fixture unexpectedly completed\n' >&2
    exit 1
fi
prepared_mapping_journal="$(find "$prepared_mapping_root" -mindepth 1 -maxdepth 1 \
    -type f -name '.borondns-retained-cleanup-tree.*.env' -print -quit)"
[[ -n "$prepared_mapping_journal" && ! -e "$prepared_mapping_tree" ]]
grep -Fqx phase=prepared "$prepared_mapping_journal"
prepared_mapping_quarantine="$(sed -n 's/^quarantine_path=//p' "$prepared_mapping_journal")"
[[ -d "$prepared_mapping_quarantine" ]]
campaign_verify_retained_cleanup_journal "$prepared_mapping_journal" \
    >"$workdir/prepared-mapping-verified.out"
grep -Fq $'cleanup_prepared_verified\toriginal=' "$workdir/prepared-mapping-verified.out"
grep -Fqx 'prepared payload' "$prepared_mapping_quarantine/payload"

# Reconciliation evidence is same-UID writable and may be corrupt. Special
# files must fail without blocking, and regular files must be singly linked and
# small enough to read as one bounded snapshot before any field is trusted.
for retained_journal_poison in fifo oversized hardlink; do
    retained_poison_journal="$prepared_mapping_root/.borondns-retained-cleanup-${retained_journal_poison}.env"
    retained_poison_alias="$retained_poison_journal.alias"
    case "$retained_journal_poison" in
    fifo)
        mkfifo "$retained_poison_journal"
        ;;
    oversized)
        truncate -s 16385 "$retained_poison_journal"
        ;;
    hardlink)
        cp "$prepared_mapping_journal" "$retained_poison_journal"
        ln "$retained_poison_journal" "$retained_poison_alias"
        ;;
    esac
    set +e
    # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
    timeout --kill-after=1 3 bash --noprofile --norc -c '
        source "$1/scripts/campaign-env.sh"
        campaign_verify_retained_cleanup_journal "$2"
    ' _ "$repo_root" "$retained_poison_journal" \
        >"$workdir/retained-${retained_journal_poison}.out" \
        2>"$workdir/retained-${retained_journal_poison}.err"
    retained_poison_status=$?
    set -e
    if ((retained_poison_status == 0 || retained_poison_status == 124 || \
        retained_poison_status == 137)); then
        printf 'retained-cleanup verifier accepted or blocked on %s journal evidence\n' \
            "$retained_journal_poison" >&2
        exit 1
    fi
    grep -Fq 'retained-cleanup journal is not a bound singly linked bounded regular file' \
        "$workdir/retained-${retained_journal_poison}.err"
    rm -f -- "$retained_poison_journal" "$retained_poison_alias"
done

prepared_forged_sibling="$prepared_mapping_root/.tree.borondns-remove.$$.fedcba9876543210fedcba98"
mkdir -m 0700 "$prepared_forged_sibling"
prepared_forged_journal="$prepared_mapping_root/.borondns-retained-cleanup-prepared-forged.env"
sed "s|^quarantine_path=.*|quarantine_path=$prepared_forged_sibling|" \
    "$prepared_mapping_journal" >"$prepared_forged_journal"
if campaign_verify_retained_cleanup_journal "$prepared_forged_journal" \
    >"$workdir/prepared-forged.out" 2>"$workdir/prepared-forged.err"; then
    printf 'prepared cleanup verifier accepted a forged sibling identity\n' >&2
    exit 1
fi
grep -Fq 'retained-cleanup quarantine identity changed' "$workdir/prepared-forged.err"

# Verification must bind the real parent directory once and resolve every
# journal/object name relative to it. A symlink parent can otherwise combine
# the symlink inode as parent evidence with an object reached through its target.
prepared_symlink_parent="$workdir/prepared-mapping-link"
ln -s "$prepared_mapping_root" "$prepared_symlink_parent"
prepared_symlink_identity="$(stat -c '%d:%i:%u' "$prepared_symlink_parent")"
prepared_symlink_remainder="${prepared_symlink_identity#*:}"
prepared_symlink_journal_real="$prepared_mapping_root/.borondns-retained-cleanup-symlink-parent.env"
sed \
    -e "s|^original_path=$prepared_mapping_root/|original_path=$prepared_symlink_parent/|" \
    -e "s|^quarantine_path=$prepared_mapping_root/|quarantine_path=$prepared_symlink_parent/|" \
    -e "s|^parent_device=.*|parent_device=${prepared_symlink_identity%%:*}|" \
    -e "s|^parent_inode=.*|parent_inode=${prepared_symlink_remainder%%:*}|" \
    -e "s|^parent_owner=.*|parent_owner=${prepared_symlink_identity##*:}|" \
    "$prepared_mapping_journal" >"$prepared_symlink_journal_real"
if campaign_verify_retained_cleanup_journal \
    "$prepared_symlink_parent/$(basename "$prepared_symlink_journal_real")" \
    >"$workdir/prepared-symlink.out" 2>"$workdir/prepared-symlink.err"; then
    printf 'prepared cleanup verifier accepted a symlink parent namespace\n' >&2
    exit 1
fi
grep -Fq 'retained-cleanup parent is not a real directory' "$workdir/prepared-symlink.err"

# O_NOFOLLOW on one complete parent pathname protects only its final component.
# Reject a symlink anywhere in the descriptor walk, even when the final parent
# itself is a real directory below that symlinked ancestor.
prepared_ancestor_link="$workdir/prepared-mapping-ancestor-link"
ln -s "$workdir" "$prepared_ancestor_link"
prepared_ancestor_parent="$prepared_ancestor_link/$(basename "$prepared_mapping_root")"
prepared_ancestor_journal_real="$prepared_mapping_root/.borondns-retained-cleanup-symlink-ancestor.env"
sed \
    -e "s|^original_path=$prepared_mapping_root/|original_path=$prepared_ancestor_parent/|" \
    -e "s|^quarantine_path=$prepared_mapping_root/|quarantine_path=$prepared_ancestor_parent/|" \
    "$prepared_mapping_journal" >"$prepared_ancestor_journal_real"
if campaign_verify_retained_cleanup_journal \
    "$prepared_ancestor_parent/$(basename "$prepared_ancestor_journal_real")" \
    >"$workdir/prepared-ancestor.out" 2>"$workdir/prepared-ancestor.err"; then
    printf 'prepared cleanup verifier accepted a symlinked ancestor namespace\n' >&2
    exit 1
fi
grep -Fq 'retained-cleanup parent is not a real directory' "$workdir/prepared-ancestor.err"

# Dot segments are lexical aliases and must be rejected before opening any
# journal. A canonical relative journal in a held current directory remains a
# supported operator workflow.
if campaign_verify_retained_cleanup_journal \
    "$prepared_mapping_root/../$(basename "$prepared_mapping_root")/$(basename "$prepared_mapping_journal")" \
    >"$workdir/prepared-dotdot.out" 2>"$workdir/prepared-dotdot.err"; then
    printf 'prepared cleanup verifier accepted a dotdot parent path\n' >&2
    exit 1
fi
grep -Fq 'retained-cleanup journal path is not canonical' "$workdir/prepared-dotdot.err"

prepared_relative_journal="$prepared_mapping_root/.borondns-retained-cleanup-relative.env"
sed \
    -e "s|^original_path=$prepared_mapping_root/|original_path=|" \
    -e "s|^quarantine_path=$prepared_mapping_root/|quarantine_path=|" \
    "$prepared_mapping_journal" >"$prepared_relative_journal"
(
    cd "$prepared_mapping_root"
    campaign_verify_retained_cleanup_journal "$(basename "$prepared_relative_journal")"
) >"$workdir/prepared-relative.out"
grep -Fq $'cleanup_prepared_verified\toriginal=' "$workdir/prepared-relative.out"

service_restore_root="$workdir/service-restore"
service_restore_bin="$service_restore_root/bin"
service_restore_state="$service_restore_root/state"
mkdir -p "$service_restore_bin" "$service_restore_state"
printf '%s\n' disabled >"$service_restore_state/docker.enabled"
printf '%s\n' inactive >"$service_restore_state/docker.active"
printf '%s\n' enabled >"$service_restore_state/named.enabled"
printf '%s\n' active >"$service_restore_state/named.active"
printf '%s\n' masked >"$service_restore_state/bind9.enabled"
printf '%s\n' inactive >"$service_restore_state/bind9.active"
service_restore_candidate="$service_restore_root/prior.candidate"
printf '%s\n' \
    service_state_version=1 \
    docker_enabled=disabled docker_active=inactive \
    named_enabled=enabled named_active=active \
    bind9_enabled=masked bind9_active=inactive >"$service_restore_candidate"
service_restore_record="$service_restore_root/prior.env"
sudo -n install -m 0444 -o root -g root "$service_restore_candidate" "$service_restore_record"
# Start from the campaign-mutated states.
printf '%s\n' enabled >"$service_restore_state/docker.enabled"
printf '%s\n' active >"$service_restore_state/docker.active"
printf '%s\n' disabled >"$service_restore_state/named.enabled"
printf '%s\n' inactive >"$service_restore_state/named.active"
printf '%s\n' disabled >"$service_restore_state/bind9.enabled"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'state="$SERVICE_RESTORE_STATE"; action="$1"; shift' \
    'case "$action" in' \
    'is-enabled) cat "$state/$1.enabled" ;;' \
    'is-active) cat "$state/$1.active" ;;' \
    'enable) service="${*: -1}"; if [[ "${FAIL_RESTORE_ONCE:-0}" == 1 && "$service" == named && ! -e "$state/failed-once" ]]; then touch "$state/failed-once"; exit 77; fi; if [[ " $* " == *" --runtime "* ]]; then printf "%s\n" enabled-runtime >"$state/$service.enabled"; else printf "%s\n" enabled >"$state/$service.enabled"; fi ;;' \
    'disable) service="${*: -1}"; printf "%s\n" disabled >"$state/$service.enabled"; [[ " $* " != *" --now "* ]] || printf "%s\n" inactive >"$state/$service.active" ;;' \
    'mask) service="${*: -1}"; if [[ " $* " == *" --runtime "* ]]; then printf "%s\n" masked-runtime >"$state/$service.enabled"; else printf "%s\n" masked >"$state/$service.enabled"; fi ;;' \
    'unmask) service="${*: -1}"; current="$(cat "$state/$service.enabled")"; [[ "$current" != masked && "$current" != masked-runtime ]] || printf "%s\n" disabled >"$state/$service.enabled" ;;' \
    'start) printf "%s\n" active >"$state/$1.active" ;;' \
    'stop) printf "%s\n" inactive >"$state/$1.active" ;;' \
    '*) exit 2 ;;' \
    'esac' >"$service_restore_bin/systemctl"
printf '%s\n' '#!/usr/bin/env bash' 'exec "$@"' >"$service_restore_bin/sudo"
chmod +x "$service_restore_bin/systemctl" "$service_restore_bin/sudo"
if PATH="$service_restore_bin:$PATH" SERVICE_RESTORE_STATE="$service_restore_state" FAIL_RESTORE_ONCE=1 \
    campaign_restore_prerequisite_service_state "$service_restore_record"; then
    printf 'prerequisite restoration ignored an interrupted service transition\n' >&2
    exit 1
fi
[[ -e "$service_restore_state/failed-once" ]]
PATH="$service_restore_bin:$PATH" SERVICE_RESTORE_STATE="$service_restore_state" FAIL_RESTORE_ONCE=1 \
    campaign_restore_prerequisite_service_state "$service_restore_record"
grep -Fqx disabled "$service_restore_state/docker.enabled"
grep -Fqx inactive "$service_restore_state/docker.active"
grep -Fqx enabled "$service_restore_state/named.enabled"
grep -Fqx active "$service_restore_state/named.active"
grep -Fqx masked "$service_restore_state/bind9.enabled"
grep -Fqx inactive "$service_restore_state/bind9.active"

rename_source="$workdir/rename-noreplace-source"
rename_destination="$workdir/rename-noreplace-destination"
mkdir "$rename_source" "$rename_destination"
printf source >"$rename_source/source.txt"
printf destination >"$rename_destination/destination.txt"
if campaign_rename_noreplace "$rename_source" "$rename_destination"; then
    printf 'collision-safe campaign promotion replaced an existing destination\n' >&2
    exit 1
fi
[[ -f "$rename_source/source.txt" && -f "$rename_destination/destination.txt" ]]
[[ ! -e "$rename_destination/$(basename "$rename_source")" ]]
# These are literal generated-script fragments.
# shellcheck disable=SC2016
grep -Fq 'campaign_rename_noreplace "$staging" "$final_evidence"' \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
# shellcheck disable=SC2016
grep -Fq 'campaign_rename_noreplace "$staging" "$final_evidence"' \
    "$repo_root/scripts/large-surface-soak-campaign.sh"

# The separately promoted unprivileged status commit binds exact status bytes
# and the validator-approved evidence snapshot.  It detects independent drift,
# while a coordinated same-UID rewrite remains intentionally non-authentic.
for collection_digest_phase in pre-transaction pre-promotion pre-status-promotion consumer; do
    collection_digest_root="$workdir/collection-digest-$collection_digest_phase"
    mkdir -m 0700 "$collection_digest_root" "$collection_digest_root/evidence-new" \
        "$collection_digest_root/journal-new"
    printf validated >"$collection_digest_root/evidence-new/value"
    printf journal >"$collection_digest_root/journal-new/value"
    collection_digest_deadline=""
    campaign_prepare_collection_budget collection_digest_deadline
    collection_digest="$(campaign_local_tree_snapshot "$collection_digest_root/evidence-new" \
        "$collection_digest_deadline" "$repo_root/scripts/validate-collected-campaign.py")"
    printf 'collection\tfixture\tremote-snapshot\tincomplete\t%s\n' "$collection_digest" \
        >"$collection_digest_root/status-new"
    campaign_collection_status_commit_text "$collection_digest_root/status-new" \
        "$collection_digest" >"$collection_digest_root/status-commit-new"
    campaign_release_private_lock
    campaign_acquire_private_lock "$collection_digest_root" "digest-$collection_digest_phase" \
        "collection digest $collection_digest_phase fixture"
    if [[ "$collection_digest_phase" == pre-transaction ]]; then
        printf unvalidated >"$collection_digest_root/evidence-new/value"
        if campaign_publish_collection_bundle "$collection_digest_root" \
            "$collection_digest_root/evidence-new" "$collection_digest_root/evidence" \
            "$collection_digest_root/journal-new" "$collection_digest_root/journal" \
            "$collection_digest_root/status-new" "$collection_digest_root/status" \
            "collection digest pre-transaction fixture" "$collection_digest" \
            "$collection_digest_deadline" "$repo_root/scripts/validate-collected-campaign.py" \
            "$collection_digest_root/status-commit-new" "$collection_digest_root/status.commit"; then
            printf 'collection publication accepted pre-transaction content mutation\n' >&2
            exit 1
        fi
        [[ ! -e "$collection_digest_root/status" ]]
    else
        if [[ "$collection_digest_phase" == pre-promotion ]]; then
            campaign_collection_publication_hook() {
                [[ "$1" != before-promote-0 ]] ||
                    printf unvalidated >"$collection_digest_root/evidence-new/value"
            }
        elif [[ "$collection_digest_phase" == pre-status-promotion ]]; then
            campaign_collection_publication_hook() {
                [[ "$1" != before-promote-2 ]] ||
                    sed -i 's/incomplete/complete/' "$collection_digest_root/status-new"
            }
        fi
        if ! campaign_publish_collection_bundle "$collection_digest_root" \
            "$collection_digest_root/evidence-new" "$collection_digest_root/evidence" \
            "$collection_digest_root/journal-new" "$collection_digest_root/journal" \
            "$collection_digest_root/status-new" "$collection_digest_root/status" \
            "collection digest $collection_digest_phase fixture" "$collection_digest" \
            "$collection_digest_deadline" "$repo_root/scripts/validate-collected-campaign.py" \
            "$collection_digest_root/status-commit-new" "$collection_digest_root/status.commit"; then
            if [[ "$collection_digest_phase" == pre-promotion ||
                "$collection_digest_phase" == pre-status-promotion ]]; then
                unset -f campaign_collection_publication_hook
                [[ ! -e "$collection_digest_root/status" ]]
                [[ ! -e "$collection_digest_root/status.commit" ]]
                campaign_release_private_lock
                campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" \
                    "operations harness mutation lock"
                continue
            fi
            printf 'content-bound collection publication unexpectedly failed\n' >&2
            exit 1
        fi
        if [[ "$collection_digest_phase" == consumer ]]; then
            campaign_collection_status_accepts_generation "$collection_digest_root/evidence" \
                "$collection_digest_root/status" "$collection_digest_deadline" \
                "$repo_root/scripts/validate-collected-campaign.py"
            cp "$collection_digest_root/status" "$collection_digest_root/status.original"
            sed -i 's/incomplete/complete/' "$collection_digest_root/status"
            if campaign_collection_status_accepts_generation "$collection_digest_root/evidence" \
                "$collection_digest_root/status" "$collection_digest_deadline" \
                "$repo_root/scripts/validate-collected-campaign.py"; then
                printf 'collection consumer accepted classification-only status mutation\n' >&2
                exit 1
            fi
            mv "$collection_digest_root/status.original" "$collection_digest_root/status"
            printf post-publication-mutation >"$collection_digest_root/evidence/value"
            if campaign_collection_status_accepts_generation "$collection_digest_root/evidence" \
                "$collection_digest_root/status" "$collection_digest_deadline" \
                "$repo_root/scripts/validate-collected-campaign.py"; then
                printf 'collection consumer accepted content not matching committed digest\n' >&2
                exit 1
            fi
            coordinated_digest="$(campaign_local_tree_snapshot \
                "$collection_digest_root/evidence" "$collection_digest_deadline" \
                "$repo_root/scripts/validate-collected-campaign.py")"
            printf 'collection\tfixture\tremote-snapshot\tcomplete\t%s\n' "$coordinated_digest" \
                >"$collection_digest_root/status"
            campaign_collection_status_commit_text "$collection_digest_root/status" \
                "$coordinated_digest" >"$collection_digest_root/status.commit"
            campaign_collection_status_accepts_generation "$collection_digest_root/evidence" \
                "$collection_digest_root/status" "$collection_digest_deadline" \
                "$repo_root/scripts/validate-collected-campaign.py" || {
                printf 'unprivileged commit unexpectedly claimed coordinated same-UID authenticity\n' >&2
                exit 1
            }
        fi
    fi
    campaign_release_private_lock
    campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" \
        "operations harness mutation lock"
done

# Status and status-commit objects are small control records, not evidence-tree
# payloads. Oversized sparse files and special nodes must be rejected before a
# hash/read can consume the collection deadline or allocate attacker-sized
# shell state.
collection_metadata_bounds_root="$workdir/collection-metadata-bounds"
mkdir "$collection_metadata_bounds_root" "$collection_metadata_bounds_root/evidence"
printf evidence >"$collection_metadata_bounds_root/evidence/value"
collection_metadata_deadline="$(campaign_deadline_from_timeout_seconds 2)"
collection_metadata_snapshot="$(campaign_local_tree_snapshot \
    "$collection_metadata_bounds_root/evidence" "$collection_metadata_deadline" \
    "$repo_root/scripts/validate-collected-campaign.py")"
printf 'collection\tfixture\tremote-snapshot\tincomplete\t%s\n' \
    "$collection_metadata_snapshot" >"$collection_metadata_bounds_root/status"
cp "$collection_metadata_bounds_root/status" "$collection_metadata_bounds_root/status.oversized"
truncate -s 8388609 "$collection_metadata_bounds_root/status.oversized"
collection_metadata_started="$(date +%s%N)"
if campaign_collection_status_commit_text "$collection_metadata_bounds_root/status.oversized" \
    "$collection_metadata_snapshot" "$(campaign_deadline_from_timeout_seconds 2)" \
    >"$collection_metadata_bounds_root/oversized.commit"; then
    printf 'collection status producer accepted an oversized sparse status file\n' >&2
    exit 1
fi
collection_metadata_elapsed=$((($(date +%s%N) - collection_metadata_started) / 1000000))
((collection_metadata_elapsed < 1500))

campaign_collection_status_commit_text "$collection_metadata_bounds_root/status" \
    "$collection_metadata_snapshot" "$(campaign_deadline_from_timeout_seconds 2)" \
    >"$collection_metadata_bounds_root/status.commit"
mv "$collection_metadata_bounds_root/status.commit" \
    "$collection_metadata_bounds_root/status.commit.regular"
mkfifo "$collection_metadata_bounds_root/status.commit"
collection_metadata_started="$(date +%s%N)"
if campaign_collection_status_accepts_generation "$collection_metadata_bounds_root/evidence" \
    "$collection_metadata_bounds_root/status" "$(campaign_deadline_from_timeout_seconds 2)" \
    "$repo_root/scripts/validate-collected-campaign.py"; then
    printf 'collection consumer accepted a FIFO status commit\n' >&2
    exit 1
fi
collection_metadata_elapsed=$((($(date +%s%N) - collection_metadata_started) / 1000000))
((collection_metadata_elapsed < 1500))
rm "$collection_metadata_bounds_root/status.commit"
mv "$collection_metadata_bounds_root/status.commit.regular" \
    "$collection_metadata_bounds_root/status.commit"
truncate -s 1025 "$collection_metadata_bounds_root/status.commit"
if campaign_collection_status_accepts_generation "$collection_metadata_bounds_root/evidence" \
    "$collection_metadata_bounds_root/status" "$(campaign_deadline_from_timeout_seconds 2)" \
    "$repo_root/scripts/validate-collected-campaign.py"; then
    printf 'collection consumer accepted an oversized sparse status commit\n' >&2
    exit 1
fi

# Bind the opened descriptor and the published name through the complete read.
# A same-UID pathname swap at the deterministic post-open barrier must fail and
# preserve both the captured inode and the replacement.
collection_metadata_swap="$collection_metadata_bounds_root/swap-status"
collection_metadata_swap_marker="$collection_metadata_bounds_root/swap-opened"
collection_metadata_swap_continue="$collection_metadata_bounds_root/swap-continue"
printf 'trusted status bytes\n' >"$collection_metadata_swap"
(
    BORONDNS_CAMPAIGN_COLLECTION_METADATA_TEST_MARKER="$collection_metadata_swap_marker" \
        BORONDNS_CAMPAIGN_COLLECTION_METADATA_TEST_CONTINUE="$collection_metadata_swap_continue" \
        campaign_collection_read_bounded_file "$collection_metadata_swap" \
        "$(campaign_deadline_from_timeout_seconds 3)" 8388608 \
        swap_digest swap_content swap_device swap_inode swap_size
) &
collection_metadata_swap_pid=$!
collection_metadata_swap_wait=$((SECONDS + 3))
while [[ ! -e "$collection_metadata_swap_marker" ]]; do
    kill -0 "$collection_metadata_swap_pid" 2>/dev/null || break
    ((SECONDS < collection_metadata_swap_wait)) || break
    sleep 0.01
done
[[ -e "$collection_metadata_swap_marker" ]]
mv "$collection_metadata_swap" "$collection_metadata_swap.original"
printf 'replacement must survive\n' >"$collection_metadata_swap"
: >"$collection_metadata_swap_continue"
set +e
wait "$collection_metadata_swap_pid"
collection_metadata_swap_status=$?
set -e
if ((collection_metadata_swap_status == 0)); then
    printf 'collection metadata reader accepted a pathname swap after safe open\n' >&2
    exit 1
fi
grep -Fqx 'trusted status bytes' "$collection_metadata_swap.original"
grep -Fqx 'replacement must survive' "$collection_metadata_swap"

# A transaction created by the current publisher retains live descriptor
# authority, but same-UID namespace flooding must not turn its recovery into an
# unbounded directory walk. The tiny transaction cap fails closed and retains
# the exact transaction for inspection.
collection_transaction_flood_root="$workdir/collection-transaction-flood"
mkdir "$collection_transaction_flood_root" \
    "$collection_transaction_flood_root/evidence-new" \
    "$collection_transaction_flood_root/journal-new"
printf evidence >"$collection_transaction_flood_root/evidence-new/value"
printf journal >"$collection_transaction_flood_root/journal-new/value"
collection_transaction_flood_deadline=
campaign_prepare_collection_budget collection_transaction_flood_deadline
collection_transaction_flood_snapshot="$(campaign_local_tree_snapshot \
    "$collection_transaction_flood_root/evidence-new" \
    "$collection_transaction_flood_deadline" \
    "$repo_root/scripts/validate-collected-campaign.py")"
printf 'collection\tfixture\tremote-snapshot\tincomplete\t%s\n' \
    "$collection_transaction_flood_snapshot" \
    >"$collection_transaction_flood_root/status-new"
campaign_collection_status_commit_text "$collection_transaction_flood_root/status-new" \
    "$collection_transaction_flood_snapshot" "$collection_transaction_flood_deadline" \
    >"$collection_transaction_flood_root/status-commit-new"
campaign_release_private_lock
campaign_acquire_private_lock "$collection_transaction_flood_root" \
    collection-transaction-flood "collection transaction flood fixture" \
    "$collection_transaction_flood_deadline" "$collection_transaction_flood_deadline"
campaign_collection_publication_hook() {
    [[ "$1" == transaction-created ]] || return 0
    : >"$2/had-0"
    local flood_index
    for ((flood_index = 0; flood_index < 65; flood_index++)); do
        : >"$2/noise-$flood_index"
    done
}
if campaign_publish_collection_bundle "$collection_transaction_flood_root" \
    "$collection_transaction_flood_root/evidence-new" \
    "$collection_transaction_flood_root/evidence" \
    "$collection_transaction_flood_root/journal-new" \
    "$collection_transaction_flood_root/journal" \
    "$collection_transaction_flood_root/status-new" \
    "$collection_transaction_flood_root/status" \
    "collection transaction flood fixture" "$collection_transaction_flood_snapshot" \
    "$collection_transaction_flood_deadline" \
    "$repo_root/scripts/validate-collected-campaign.py" \
    "$collection_transaction_flood_root/status-commit-new" \
    "$collection_transaction_flood_root/status.commit"; then
    printf 'collection transaction flood fixture unexpectedly published\n' >&2
    exit 1
fi
unset -f campaign_collection_publication_hook
collection_transaction_flood_path="$(find "$collection_transaction_flood_root" \
    -mindepth 1 -maxdepth 1 -type d -name '.collection-transaction-*' -print -quit)"
[[ -n "$collection_transaction_flood_path" ]]
collection_transaction_flood_started="$(date +%s%N)"
if campaign_recover_collection_bundle "$collection_transaction_flood_root" \
    "$collection_transaction_flood_root/evidence" \
    "$collection_transaction_flood_root/journal" \
    "$collection_transaction_flood_root/status" \
    "$collection_transaction_flood_root/status.commit" \
    "collection transaction flood recovery fixture" \
    "$collection_transaction_flood_deadline" \
    2>"$workdir/collection-transaction-flood.err"; then
    printf 'collection transaction recovery accepted an entry flood\n' >&2
    exit 1
fi
collection_transaction_flood_elapsed=$((($(date +%s%N) - collection_transaction_flood_started) / 1000000))
((collection_transaction_flood_elapsed < 1500))
grep -Fq 'campaign directory enumeration entry cap exceeded' \
    "$workdir/collection-transaction-flood.err"
[[ -d "$collection_transaction_flood_path" ]]
campaign_release_private_lock
campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" \
    "operations harness mutation lock"

# An all-absent publication interrupted before the first promotion must restore
# the all-absent bundle in the same process. This directly exercises marker
# output assignment through Bash dynamic scope and transaction retirement.
collection_absent_root="$workdir/collection-absent-promote-zero"
mkdir -m 0700 "$collection_absent_root" \
    "$collection_absent_root/evidence-new" "$collection_absent_root/journal-new"
printf new-evidence >"$collection_absent_root/evidence-new/value"
printf new-journal >"$collection_absent_root/journal-new/value"
printf new-status >"$collection_absent_root/status-new"
campaign_release_private_lock
campaign_acquire_private_lock "$collection_absent_root" collection-absent-promote-zero \
    "collection absent promote-zero fixture"
campaign_collection_publication_hook() {
    [[ "$1" != promote-0 ]] || return 73
}
if campaign_publish_collection_bundle "$collection_absent_root" \
    "$collection_absent_root/evidence-new" "$collection_absent_root/evidence" \
    "$collection_absent_root/journal-new" "$collection_absent_root/journal" \
    "$collection_absent_root/status-new" "$collection_absent_root/status" \
    "collection absent promote-zero fixture"; then
    printf 'collection promote-zero fault fixture unexpectedly completed\n' >&2
    exit 1
fi
unset -f campaign_collection_publication_hook
collection_absent_transaction="$(find "$collection_absent_root" -mindepth 1 -maxdepth 1 \
    -type d -name '.collection-transaction-*' -print -quit)"
[[ -n "$collection_absent_transaction" ]]
collection_absent_marker=sentinel
campaign_collection_read_live_marker "$collection_absent_transaction/had-0" \
    collection_absent_marker "collection absent marker fixture"
[[ "$collection_absent_marker" == absent ]]
campaign_recover_collection_bundle "$collection_absent_root" \
    "$collection_absent_root/evidence" "$collection_absent_root/journal" \
    "$collection_absent_root/status" "collection absent promote-zero recovery fixture"
[[ ! -e "$collection_absent_root/evidence" && ! -e "$collection_absent_root/journal" &&
    ! -e "$collection_absent_root/status" ]]
[[ -z "$(find "$collection_absent_root" -mindepth 1 -maxdepth 1 \
    -type d -name '.collection-transaction-*' -print -quit)" ]]
campaign_release_private_lock
campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" \
    "operations harness"

# Legacy automatic crash recovery intentionally mutated same-UID disk state.
# Keep the historical adversarial fixtures visible, but do not execute them
# under the descriptor-authority contract below.
# shellcheck disable=SC2317
if false; then
    collection_root="$workdir/collection-transaction"
    mkdir -p "$collection_root/evidence" "$collection_root/journal" \
        "$collection_root/evidence-new" "$collection_root/journal-new"
    printf old-evidence >"$collection_root/evidence/value"
    printf old-journal >"$collection_root/journal/value"
    printf old-status >"$collection_root/status"
    printf new-evidence >"$collection_root/evidence-new/value"
    printf new-journal >"$collection_root/journal-new/value"
    printf new-status >"$collection_root/status-new"
    campaign_release_private_lock
    (
        unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_label
        campaign_acquire_private_lock "$collection_root" collection-crash "collection crash fixture"
        campaign_collection_publication_hook() {
            [[ "$1" != promote-0 ]] || kill -KILL "$BASHPID"
        }
        campaign_publish_collection_bundle "$collection_root" \
            "$collection_root/evidence-new" "$collection_root/evidence" \
            "$collection_root/journal-new" "$collection_root/journal" \
            "$collection_root/status-new" "$collection_root/status" "collection crash fixture"
    ) >/dev/null 2>&1 &
    collection_crash_pid=$!
    set +e
    wait "$collection_crash_pid"
    collection_crash_status=$?
    set -e
    [[ "$collection_crash_status" -ne 0 ]]
    campaign_acquire_private_lock "$collection_root" collection-crash "collection recovery fixture"
    campaign_recover_collection_bundle "$collection_root" "$collection_root/evidence" \
        "$collection_root/journal" "$collection_root/status" "collection recovery fixture"
    grep -Fqx old-evidence "$collection_root/evidence/value"
    grep -Fqx old-journal "$collection_root/journal/value"
    grep -Fqx old-status "$collection_root/status"
    [[ -z "$(find "$collection_root" -maxdepth 1 -name '.collection-transaction-*' -print -quit)" ]]
    campaign_release_private_lock

    for collection_replacement_index in 0 1 2; do
        collection_replacement_root="$workdir/collection-replacement-$collection_replacement_index"
        mkdir -p "$collection_replacement_root/evidence" "$collection_replacement_root/journal" \
            "$collection_replacement_root/evidence-new" "$collection_replacement_root/journal-new"
        printf old-evidence >"$collection_replacement_root/evidence/value"
        printf old-journal >"$collection_replacement_root/journal/value"
        printf old-status >"$collection_replacement_root/status"
        printf new-evidence >"$collection_replacement_root/evidence-new/value"
        printf new-journal >"$collection_replacement_root/journal-new/value"
        printf new-status >"$collection_replacement_root/status-new"
        (
            unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_label
            campaign_acquire_private_lock "$collection_replacement_root" \
                "collection-replacement-$collection_replacement_index" "collection replacement crash fixture"
            campaign_collection_publication_hook() {
                [[ "$1" != "promote-$collection_replacement_index" ]] || kill -KILL "$BASHPID"
            }
            campaign_publish_collection_bundle "$collection_replacement_root" \
                "$collection_replacement_root/evidence-new" "$collection_replacement_root/evidence" \
                "$collection_replacement_root/journal-new" "$collection_replacement_root/journal" \
                "$collection_replacement_root/status-new" "$collection_replacement_root/status" \
                "collection replacement crash fixture"
        ) >/dev/null 2>&1 &
        collection_replacement_pid=$!
        set +e
        wait "$collection_replacement_pid"
        collection_replacement_status=$?
        set -e
        [[ "$collection_replacement_status" -ne 0 ]]
        case "$collection_replacement_index" in
        0)
            mv -- "$collection_replacement_root/evidence" "$collection_replacement_root/evidence.promoted"
            mkdir -- "$collection_replacement_root/evidence"
            printf unrelated-evidence >"$collection_replacement_root/evidence/sentinel"
            ;;
        1)
            mv -- "$collection_replacement_root/journal" "$collection_replacement_root/journal.promoted"
            mkdir -- "$collection_replacement_root/journal"
            printf unrelated-journal >"$collection_replacement_root/journal/sentinel"
            ;;
        2)
            mv -- "$collection_replacement_root/status" "$collection_replacement_root/status.promoted"
            printf unrelated-status >"$collection_replacement_root/status"
            ;;
        esac
        campaign_acquire_private_lock "$collection_replacement_root" \
            "collection-replacement-$collection_replacement_index" "collection replacement recovery fixture"
        if campaign_recover_collection_bundle "$collection_replacement_root" \
            "$collection_replacement_root/evidence" "$collection_replacement_root/journal" \
            "$collection_replacement_root/status" "collection replacement recovery fixture"; then
            printf 'collection recovery accepted replacement destination index %s\n' "$collection_replacement_index" >&2
            exit 1
        fi
        case "$collection_replacement_index" in
        0) grep -Fqx unrelated-evidence "$collection_replacement_root/evidence/sentinel" ;;
        1) grep -Fqx unrelated-journal "$collection_replacement_root/journal/sentinel" ;;
        2) grep -Fqx unrelated-status "$collection_replacement_root/status" ;;
        esac
        [[ -n "$(find "$collection_replacement_root" -maxdepth 1 -name '.collection-transaction-*' -print -quit)" ]]
        campaign_release_private_lock
    done

    collection_commit_root="$workdir/collection-committed-cleanup-transaction"
    mkdir -p "$collection_commit_root/evidence" "$collection_commit_root/journal" \
        "$collection_commit_root/evidence-new" "$collection_commit_root/journal-new"
    printf old-evidence >"$collection_commit_root/evidence/value"
    printf old-journal >"$collection_commit_root/journal/value"
    printf old-status >"$collection_commit_root/status"
    printf new-evidence >"$collection_commit_root/evidence-new/value"
    printf new-journal >"$collection_commit_root/journal-new/value"
    printf new-status >"$collection_commit_root/status-new"
    (
        unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_label
        campaign_acquire_private_lock "$collection_commit_root" collection-committed-crash \
            "committed collection cleanup crash fixture"
        campaign_collection_publication_hook() {
            [[ "$1" != commit-cleanup-0 ]] || kill -KILL "$BASHPID"
        }
        campaign_publish_collection_bundle "$collection_commit_root" \
            "$collection_commit_root/evidence-new" "$collection_commit_root/evidence" \
            "$collection_commit_root/journal-new" "$collection_commit_root/journal" \
            "$collection_commit_root/status-new" "$collection_commit_root/status" \
            "committed collection cleanup crash fixture"
    ) >/dev/null 2>&1 &
    collection_commit_crash_pid=$!
    set +e
    wait "$collection_commit_crash_pid"
    collection_commit_crash_status=$?
    set -e
    [[ "$collection_commit_crash_status" -ne 0 ]]
    [[ -n "$(find "$collection_commit_root" -maxdepth 1 -name '.collection-transaction-*' -print -quit)" ]]
    campaign_acquire_private_lock "$collection_commit_root" collection-committed-crash \
        "committed collection cleanup recovery fixture"
    campaign_recover_collection_bundle "$collection_commit_root" "$collection_commit_root/evidence" \
        "$collection_commit_root/journal" "$collection_commit_root/status" \
        "committed collection cleanup recovery fixture"
    grep -Fqx new-evidence "$collection_commit_root/evidence/value"
    grep -Fqx new-journal "$collection_commit_root/journal/value"
    grep -Fqx new-status "$collection_commit_root/status"
    [[ -z "$(find "$collection_commit_root" -maxdepth 1 -name '.collection-transaction-*' -print -quit)" ]]
    campaign_release_private_lock

    for collection_cleanup_replacement_index in 0 1 2; do
        collection_cleanup_replacement_root="$workdir/collection-committed-cleanup-replacement-$collection_cleanup_replacement_index"
        mkdir -p "$collection_cleanup_replacement_root/evidence" \
            "$collection_cleanup_replacement_root/journal" \
            "$collection_cleanup_replacement_root/evidence-new" \
            "$collection_cleanup_replacement_root/journal-new"
        printf old-evidence >"$collection_cleanup_replacement_root/evidence/value"
        printf old-journal >"$collection_cleanup_replacement_root/journal/value"
        printf old-status >"$collection_cleanup_replacement_root/status"
        printf new-evidence >"$collection_cleanup_replacement_root/evidence-new/value"
        printf new-journal >"$collection_cleanup_replacement_root/journal-new/value"
        printf new-status >"$collection_cleanup_replacement_root/status-new"
        campaign_acquire_private_lock "$collection_cleanup_replacement_root" \
            "collection-committed-cleanup-replacement-$collection_cleanup_replacement_index" \
            "committed collection cleanup replacement fixture"
        # shellcheck disable=SC2329 # Dynamic fault-injection hook consumed by campaign-env.sh.
        campaign_identity_bound_remove_hook() {
            local phase="$1" backup="$2"
            [[ "$phase" == before-remove &&
                "$(basename "$backup")" == "old-$collection_cleanup_replacement_index" ]] || return 0
            mv -- "$backup" "$backup.original"
            if ((collection_cleanup_replacement_index < 2)); then
                mkdir -- "$backup"
                printf 'replacement cleanup victim %s\n' "$collection_cleanup_replacement_index" \
                    >"$backup/sentinel"
            else
                printf 'replacement cleanup victim %s\n' "$collection_cleanup_replacement_index" >"$backup"
            fi
        }
        if campaign_publish_collection_bundle "$collection_cleanup_replacement_root" \
            "$collection_cleanup_replacement_root/evidence-new" "$collection_cleanup_replacement_root/evidence" \
            "$collection_cleanup_replacement_root/journal-new" "$collection_cleanup_replacement_root/journal" \
            "$collection_cleanup_replacement_root/status-new" "$collection_cleanup_replacement_root/status" \
            "committed collection cleanup replacement fixture"; then
            printf 'committed collection cleanup accepted replacement backup index %s\n' \
                "$collection_cleanup_replacement_index" >&2
            exit 1
        fi
        unset -f campaign_identity_bound_remove_hook
        collection_cleanup_transaction="$(find "$collection_cleanup_replacement_root" -mindepth 1 -maxdepth 1 \
            -type d -name '.collection-transaction-*' -print -quit)"
        [[ -n "$collection_cleanup_transaction" ]]
        if ((collection_cleanup_replacement_index < 2)); then
            grep -Fqx "replacement cleanup victim $collection_cleanup_replacement_index" \
                "$collection_cleanup_transaction/old-$collection_cleanup_replacement_index/sentinel"
        else
            grep -Fqx "replacement cleanup victim $collection_cleanup_replacement_index" \
                "$collection_cleanup_transaction/old-$collection_cleanup_replacement_index"
        fi
        [[ -e "$collection_cleanup_transaction/old-$collection_cleanup_replacement_index.original" ]]
        [[ -f "$collection_cleanup_transaction.committed" ]]
        campaign_release_private_lock
    done

    # A committed publisher that loses its broker must not clean a replacement
    # publisher's backups after the deterministic transaction path is reused.
    collection_reuse_root="$workdir/collection-stale-cleanup-reuse"
    mkdir -p "$collection_reuse_root/evidence" "$collection_reuse_root/journal" \
        "$collection_reuse_root/evidence-a" "$collection_reuse_root/journal-a" \
        "$collection_reuse_root/evidence-b" "$collection_reuse_root/journal-b"
    printf old-evidence >"$collection_reuse_root/evidence/value"
    printf old-journal >"$collection_reuse_root/journal/value"
    printf old-status >"$collection_reuse_root/status"
    printf a-evidence >"$collection_reuse_root/evidence-a/value"
    printf a-journal >"$collection_reuse_root/journal-a/value"
    printf a-status >"$collection_reuse_root/status-a"
    printf b-evidence >"$collection_reuse_root/evidence-b/value"
    printf b-journal >"$collection_reuse_root/journal-b/value"
    printf b-status >"$collection_reuse_root/status-b"
    collection_a_broker_lost="$collection_reuse_root/a-broker-lost"
    collection_b_backed="$collection_reuse_root/b-backed"
    collection_a_finished="$collection_reuse_root/a-finished"
    collection_a_status_file="$collection_reuse_root/a-status"
    (
        unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_label
        campaign_acquire_private_lock "$collection_reuse_root" collection-reused-path \
            "stale committed publisher A"
        campaign_collection_publication_hook() {
            [[ "$1" == committed ]] || return 0
            campaign_abandon_private_lock
            : >"$collection_a_broker_lost"
            local deadline=$((SECONDS + 5))
            until [[ -e "$collection_b_backed" ]]; do
                ((SECONDS < deadline)) || return 70
                sleep 0.01
            done
        }
        set +e
        campaign_publish_collection_bundle "$collection_reuse_root" \
            "$collection_reuse_root/evidence-a" "$collection_reuse_root/evidence" \
            "$collection_reuse_root/journal-a" "$collection_reuse_root/journal" \
            "$collection_reuse_root/status-a" "$collection_reuse_root/status" \
            "stale committed publisher A"
        collection_a_status=$?
        set -e
        printf '%s\n' "$collection_a_status" >"$collection_a_status_file"
        : >"$collection_a_finished"
        exit "$collection_a_status"
    ) >"$collection_reuse_root/a.log" 2>&1 &
    collection_a_pid=$!
    collection_wait_deadline=$((SECONDS + 5))
    until [[ -e "$collection_a_broker_lost" ]]; do
        kill -0 "$collection_a_pid" 2>/dev/null || {
            cat "$collection_reuse_root/a.log" >&2
            printf 'stale committed publisher A exited before broker-loss barrier\n' >&2
            exit 1
        }
        ((SECONDS < collection_wait_deadline)) || {
            printf 'stale committed publisher A did not reach broker-loss barrier\n' >&2
            exit 1
        }
        sleep 0.01
    done
    (
        unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_label
        campaign_acquire_private_lock "$collection_reuse_root" collection-reused-path \
            "replacement publisher B"
        campaign_collection_publication_hook() {
            case "$1" in
            backup-2)
                : >"$collection_b_backed"
                local deadline=$((SECONDS + 5))
                until [[ -e "$collection_a_finished" ]]; do
                    ((SECONDS < deadline)) || return 71
                    sleep 0.01
                done
                ;;
            promote-0) kill -KILL "$BASHPID" ;;
            esac
        }
        campaign_publish_collection_bundle "$collection_reuse_root" \
            "$collection_reuse_root/evidence-b" "$collection_reuse_root/evidence" \
            "$collection_reuse_root/journal-b" "$collection_reuse_root/journal" \
            "$collection_reuse_root/status-b" "$collection_reuse_root/status" \
            "replacement publisher B"
    ) >"$collection_reuse_root/b.log" 2>&1 &
    collection_b_pid=$!
    set +e
    wait "$collection_a_pid"
    collection_a_status=$?
    wait "$collection_b_pid"
    collection_b_status=$?
    set -e
    [[ "$collection_a_status" -ne 0 && "$(<"$collection_a_status_file")" -ne 0 ]]
    [[ "$collection_b_status" -ne 0 ]]
    grep -Fq 'protected mutation boundary' "$collection_reuse_root/a.log"
    campaign_acquire_private_lock "$collection_reuse_root" collection-reused-path \
        "replacement publisher C recovery"
    campaign_recover_collection_bundle "$collection_reuse_root" "$collection_reuse_root/evidence" \
        "$collection_reuse_root/journal" "$collection_reuse_root/status" \
        "replacement publisher C recovery"
    grep -Fqx a-evidence "$collection_reuse_root/evidence/value"
    grep -Fqx a-journal "$collection_reuse_root/journal/value"
    grep -Fqx a-status "$collection_reuse_root/status"
    [[ -z "$(find "$collection_reuse_root" -maxdepth 1 -name '.collection-transaction-*' -print -quit)" ]]
    campaign_release_private_lock
fi

# A crashed collection transaction has lost every live marker/transaction fd.
# Its schema-valid disk markers are evidence only and authorize no mutation.
collection_root="$workdir/collection-transaction-retained"
mkdir -p "$collection_root/evidence" "$collection_root/journal" \
    "$collection_root/evidence-new" "$collection_root/journal-new"
printf old-evidence >"$collection_root/evidence/value"
printf old-journal >"$collection_root/journal/value"
printf old-status >"$collection_root/status"
printf new-evidence >"$collection_root/evidence-new/value"
printf new-journal >"$collection_root/journal-new/value"
printf new-status >"$collection_root/status-new"
campaign_release_private_lock
(
    unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_label
    campaign_acquire_private_lock "$collection_root" collection-crash-retained \
        "collection crash retained fixture"
    campaign_collection_publication_hook() {
        [[ "$1" != promote-0 ]] || kill -KILL "$BASHPID"
    }
    campaign_publish_collection_bundle "$collection_root" \
        "$collection_root/evidence-new" "$collection_root/evidence" \
        "$collection_root/journal-new" "$collection_root/journal" \
        "$collection_root/status-new" "$collection_root/status" \
        "collection crash retained fixture"
) >/dev/null 2>&1 &
collection_crash_pid=$!
set +e
wait "$collection_crash_pid"
collection_crash_status=$?
set -e
[[ "$collection_crash_status" -ne 0 ]]
collection_crash_transaction="$(find "$collection_root" -mindepth 1 -maxdepth 1 \
    -type d -name '.collection-transaction-*' -print -quit)"
[[ -n "$collection_crash_transaction" ]]
collection_crash_snapshot="$(find "$collection_root" -mindepth 1 -printf '%P %y %D:%i\n' | sort)"
campaign_acquire_private_lock "$collection_root" collection-crash-retained \
    "collection crash retained successor"
if campaign_recover_collection_bundle "$collection_root" "$collection_root/evidence" \
    "$collection_root/journal" "$collection_root/status" \
    "collection crash retained successor" 2>"$workdir/collection-crash-recovery.err"; then
    printf 'unauthenticated collection crash state authorized recovery\n' >&2
    exit 1
fi
grep -Fq 'has no live descriptor authority; retaining it' "$workdir/collection-crash-recovery.err"
[[ "$(find "$collection_root" -mindepth 1 -printf '%P %y %D:%i\n' | sort)" == "$collection_crash_snapshot" ]]
mkdir "$collection_root/evidence-fresh" "$collection_root/journal-fresh" \
    "$collection_root/evidence-fresh-new" "$collection_root/journal-fresh-new"
printf fresh-old >"$collection_root/evidence-fresh/value"
printf fresh-old >"$collection_root/journal-fresh/value"
printf fresh-old >"$collection_root/status-fresh"
printf fresh-new >"$collection_root/evidence-fresh-new/value"
printf fresh-new >"$collection_root/journal-fresh-new/value"
printf fresh-new >"$collection_root/status-fresh-new"
campaign_publish_collection_bundle "$collection_root" \
    "$collection_root/evidence-fresh-new" "$collection_root/evidence-fresh" \
    "$collection_root/journal-fresh-new" "$collection_root/journal-fresh" \
    "$collection_root/status-fresh-new" "$collection_root/status-fresh" \
    "collection fresh generation fixture"
grep -Fqx fresh-new "$collection_root/evidence-fresh/value"
grep -Fqx fresh-new "$collection_root/journal-fresh/value"
grep -Fqx fresh-new "$collection_root/status-fresh"
[[ -d "$collection_crash_transaction" ]]
campaign_release_private_lock
campaign_acquire_private_lock "$workdir" "$workdir:operations-harness" "operations harness mutation lock"

runner_tamper_candidate="$workdir/runner-tamper.sh"
runner_tamper_unit="borondns-runner-tamper-test-$fixture_unit_suffix.service"
runner_tamper_root="/var/tmp/borondns-campaign-runners/${runner_tamper_unit%.service}"
printf '#!/usr/bin/env bash\nexit 0\n' >"$runner_tamper_candidate"
chmod 0700 "$runner_tamper_candidate"
publish_test_root_runner "$runner_tamper_unit" "$runner_tamper_candidate" "runner tamper fixture"
runner_tamper_path="$campaign_published_runner"
campaign_validate_root_runner "$runner_tamper_path" "$runner_tamper_root/attempt."
if printf '#!/usr/bin/env bash\nexit 9\n' >"$runner_tamper_path" 2>/dev/null; then
    printf 'campaign UID could mutate a published systemd runner\n' >&2
    exit 1
fi
sudo -n chmod 0755 "$runner_tamper_path"
if campaign_validate_root_runner "$runner_tamper_path" "$runner_tamper_root/attempt."; then
    printf 'runner identity validation accepted mode drift\n' >&2
    exit 1
fi
sudo -n chmod 0555 "$runner_tamper_path"
campaign_remove_root_runner_tree "$runner_tamper_unit" "runner tamper fixture"

collection_lock_root="$workdir/collection-lock-root"
collection_lock_ready="$workdir/collection-lock.ready"
collection_lock_release="$workdir/collection-lock.release"
mkdir -m 0700 "$collection_lock_root"
start_test_campaign_lock "$collection_lock_root" plan:collect:h1 "$collection_lock_ready" "$collection_lock_release"
collection_holder_pid="$lock_holder_pid"
if bash --noprofile --norc -c '
    set -euo pipefail
    source "$1/scripts/campaign-env.sh"
    campaign_acquire_private_lock "$2" "$3" "concurrent collection fixture"
' _ "$repo_root" "$collection_lock_root" plan:collect:h1; then
    printf 'concurrent collection acquired an already-held host lock\n' >&2
    exit 1
fi
stop_test_campaign_lock "$collection_lock_release" "$collection_holder_pid"

clear_fixture="$workdir/clear-owned-directory"
mkdir -p "$clear_fixture/nested"
printf stale >"$clear_fixture/stale.txt"
ln -s "$workdir" "$clear_fixture/nested/link"
campaign_clear_owned_directory "$clear_fixture" "collection clear fixture"
[[ ! -e "$clear_fixture/stale.txt" && ! -e "$clear_fixture/nested" ]]
clear_retained_stale="$(find "$clear_fixture" -mindepth 1 -maxdepth 1 \
    -name '.stale.txt.borondns-remove.*' -print -quit)"
clear_retained_nested="$(find "$clear_fixture" -mindepth 1 -maxdepth 1 \
    -name '.nested.borondns-remove.*' -print -quit)"
[[ -n "$clear_retained_stale" && -n "$clear_retained_nested" ]]
grep -Fqx stale "$clear_retained_stale"
[[ -L "$clear_retained_nested/link" ]]

clear_race_fixture="$workdir/clear-owned-directory-race"
mkdir -p "$clear_race_fixture/target"
printf original >"$clear_race_fixture/target/value"
campaign_identity_bound_remove_hook() {
    local phase="$1" path="$2"
    [[ "$phase" == before-remove && "$path" == "$clear_race_fixture/target" ]] || return 0
    mv "$path" "$clear_race_fixture/original-target"
    mkdir "$path"
    printf protected >"$path/value"
}
if campaign_clear_owned_directory "$clear_race_fixture" "collection clear replacement-race fixture"; then
    printf 'identity-bound directory cleanup accepted an after-validation pathname replacement\n' >&2
    exit 1
fi
unset -f campaign_identity_bound_remove_hook
grep -Fqx protected "$clear_race_fixture/target/value"
grep -Fqx original "$clear_race_fixture/original-target/value"

codec_fixture="$workdir/codec-missing.env"
campaign_env_write foo value >"$codec_fixture"
foo=stale
bar=stale
if campaign_env_load "$codec_fixture" foo bar; then
    printf 'campaign codec accepted an incomplete schema\n' >&2
    exit 1
fi
[[ ! -v foo && ! -v bar ]]

codec_collision_fixture="$workdir/codec-collision.env"
campaign_env_write value payload >"$codec_collision_fixture"
value=caller-sentinel
if campaign_env_load "$codec_collision_fixture" value; then
    printf 'campaign codec accepted an implementation-local output key\n' >&2
    exit 1
fi
[[ "$value" == caller-sentinel ]]
codec_unsafe_output_marker="$workdir/codec-unsafe-output.marker"
# shellcheck disable=SC2016 # Deliberately pass an unexpanded injection expression.
codec_unsafe_output_expression='unsafe[$(touch "$codec_unsafe_output_marker")]'
if campaign_env_load "$codec_collision_fixture" "$codec_unsafe_output_expression"; then
    printf 'campaign codec accepted an unsafe output expression\n' >&2
    exit 1
fi
[[ ! -e "$codec_unsafe_output_marker" ]]

refused_output=';; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1'
servfail_output=';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1'
dns_output_has_rcode "$refused_output" REFUSED
if dns_output_has_rcode "$servfail_output" REFUSED; then
    printf 'SERVFAIL was accepted as REFUSED\n' >&2
    exit 1
fi

mkdir -p "$workdir/fakebin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf ";; ->>HEADER<<- opcode: QUERY, status: %s, id: 1\n" "$FAKE_DNS_RCODE"' \
    >"$workdir/fakebin/dig"
chmod +x "$workdir/fakebin/dig"
PATH="$workdir/fakebin:$PATH" FAKE_DNS_RCODE=REFUSED \
    dig_until_rcode "$workdir/refused.out" REFUSED 1 1 @127.0.0.1 example. A
if PATH="$workdir/fakebin:$PATH" FAKE_DNS_RCODE=SERVFAIL \
    dig_until_rcode "$workdir/servfail.out" REFUSED 1 1 @127.0.0.1 example. A; then
    printf 'dig assertion accepted a SERVFAIL response\n' >&2
    exit 1
fi

# shellcheck source=scripts/large-surface-soak.sh
# shellcheck disable=SC1091
source "$repo_root/scripts/large-surface-soak.sh"

temporary_tree_base="$workdir/private-temporary-trees"
operations_auto_tree_path=""
operations_replaced_tree_path=""
mkdir -m 0700 "$temporary_tree_base"

# Automatic-tree recovery scans same-UID journal names before allocating a new
# run. Poisoned candidates must be rejected promptly rather than blocking the
# creator or admitting aliased/oversized evidence.
for automatic_journal_poison in fifo oversized hardlink; do
    automatic_poison_family="operations-journal-${automatic_journal_poison}"
    automatic_poison_parent="$temporary_tree_base/$automatic_poison_family-$(id -u)"
    automatic_poison_journal="$automatic_poison_parent/.automatic-run.0123456789abcdef.env"
    automatic_poison_alias="$automatic_poison_journal.alias"
    mkdir -m 0700 "$automatic_poison_parent"
    case "$automatic_journal_poison" in
    fifo)
        mkfifo "$automatic_poison_journal"
        ;;
    oversized)
        truncate -s 4097 "$automatic_poison_journal"
        ;;
    hardlink)
        printf 'invalid but bounded journal\n' >"$automatic_poison_journal"
        ln "$automatic_poison_journal" "$automatic_poison_alias"
        ;;
    esac
    set +e
    # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
    timeout --kill-after=1 3 bash --noprofile --norc -c '
        set -euo pipefail
        source "$1/scripts/campaign-env.sh"
        poisoned_tree=""
        campaign_prepare_private_temporary_tree "$2" "$3" \
            automatic_poison_identity poisoned_tree
    ' _ "$repo_root" "$temporary_tree_base" "$automatic_poison_family" \
        >"$workdir/automatic-${automatic_journal_poison}.out" \
        2>"$workdir/automatic-${automatic_journal_poison}.err"
    automatic_poison_status=$?
    set -e
    if ((automatic_poison_status == 0 || automatic_poison_status == 124 || \
        automatic_poison_status == 137)); then
        printf 'automatic-tree recovery accepted or blocked on %s journal evidence\n' \
            "$automatic_journal_poison" >&2
        exit 1
    fi
    grep -Fq 'unsafe automatic-tree journal' \
        "$workdir/automatic-${automatic_journal_poison}.err"
    rm -f -- "$automatic_poison_journal" "$automatic_poison_alias" \
        "$automatic_poison_parent/.automatic-recovery.lock"
    rmdir "$automatic_poison_parent"
done

# Automatic-tree reconciliation must never materialize an attacker-controlled
# unbounded directory listing. Entry-cap and expired-deadline failures retain
# every preexisting entry and return before allocating a run tree or journal.
for automatic_enumeration_case in cap deadline; do
    automatic_enumeration_family="operations-enumeration-$automatic_enumeration_case"
    automatic_enumeration_parent="$temporary_tree_base/$automatic_enumeration_family-$(id -u)"
    mkdir -m 0700 "$automatic_enumeration_parent"
    : >"$automatic_enumeration_parent/.automatic-recovery.lock"
    chmod 0600 "$automatic_enumeration_parent/.automatic-recovery.lock"
    for automatic_enumeration_index in {0..15}; do
        printf 'retained %s\n' "$automatic_enumeration_index" \
            >"$automatic_enumeration_parent/retained-$automatic_enumeration_index"
    done
    automatic_enumeration_before="$(find "$automatic_enumeration_parent" -mindepth 1 \
        -maxdepth 1 -printf '%f %y %D:%i %s\n' | sort)"
    set +e
    if [[ "$automatic_enumeration_case" == cap ]]; then
        # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
        BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP=8 timeout --kill-after=1 3 \
            bash --noprofile --norc -c '
                set -euo pipefail
                source "$1/scripts/campaign-env.sh"
                result=""
                campaign_prepare_private_temporary_tree "$2" "$3" enumeration_cap result
            ' _ "$repo_root" "$temporary_tree_base" "$automatic_enumeration_family" \
            >"$workdir/automatic-enumeration-cap.out" \
            2>"$workdir/automatic-enumeration-cap.err"
    else
        # shellcheck disable=SC2016 # The single-quoted body is a child-shell fixture.
        BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP=64 \
            BORONDNS_CAMPAIGN_ENUMERATION_TEST_DELAY_NANOSECONDS=500000000 \
            timeout --kill-after=1 5 \
            bash --noprofile --norc -c '
                set -euo pipefail
                source "$1/scripts/campaign-env.sh"
                result=""
                deadline=$(( $(campaign_monotonic_nanoseconds) + 2000000000 ))
                campaign_prepare_private_temporary_tree "$2" "$3" enumeration_deadline \
                    result "$deadline" "$deadline"
            ' _ "$repo_root" "$temporary_tree_base" "$automatic_enumeration_family" \
            >"$workdir/automatic-enumeration-deadline.out" \
            2>"$workdir/automatic-enumeration-deadline.err"
    fi
    automatic_enumeration_status=$?
    set -e
    if ((automatic_enumeration_status == 0 || automatic_enumeration_status == 124 || \
        automatic_enumeration_status == 137)); then
        printf 'automatic-tree %s enumeration was accepted or not promptly bounded\n' \
            "$automatic_enumeration_case" >&2
        exit 1
    fi
    if [[ "$automatic_enumeration_case" == cap ]]; then
        grep -Fq 'enumeration entry cap exceeded' \
            "$workdir/automatic-enumeration-$automatic_enumeration_case.err"
    fi
    [[ "$(find "$automatic_enumeration_parent" -mindepth 1 -maxdepth 1 \
        -printf '%f %y %D:%i %s\n' | sort)" == "$automatic_enumeration_before" ]]
    rm -f -- "$automatic_enumeration_parent"/* \
        "$automatic_enumeration_parent/.automatic-recovery.lock"
    rmdir "$automatic_enumeration_parent"
done

# Bash's dynamic scoping must not let an implementation-local output name
# create an orphaned tree while returning success.
tree=caller-sentinel
if campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-output-collision \
    operations_output_collision tree; then
    printf 'private temporary tree helper accepted a colliding output variable\n' >&2
    exit 1
fi
[[ "$tree" == caller-sentinel ]]
[[ ! -d "$temporary_tree_base/operations-output-collision-$(id -u)" ||
-z "$(find "$temporary_tree_base/operations-output-collision-$(id -u)" \
    -mindepth 1 -print -quit)" ]]
[[ ! -v 'CAMPAIGN_CLEANUP_IDENTITIES[operations_output_collision:kind]' ]]
prepublication_tree_path=""
prepublication_journal_path=""
prepublication_output=unchanged
campaign_private_temporary_tree_prepublication_hook() {
    prepublication_tree_path="$1"
    prepublication_journal_path="${CAMPAIGN_CLEANUP_IDENTITIES["$2:journal_path"]}"
    [[ -f "$prepublication_journal_path" ]]
    return 91
}
if campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-prepublication \
    operations_prepublication_tree prepublication_output; then
    printf 'private temporary tree creation accepted a prepublication failure\n' >&2
    exit 1
fi
unset -f campaign_private_temporary_tree_prepublication_hook
[[ "$prepublication_output" == unchanged ]]
[[ -n "$prepublication_tree_path" && ! -e "$prepublication_tree_path" ]]
[[ -n "$prepublication_journal_path" && ! -e "$prepublication_journal_path" ]]
[[ ! -v 'CAMPAIGN_CLEANUP_IDENTITIES[operations_prepublication_tree:kind]' ]]

# Replacing the advisory lock pathname must not create a second family
# authority. The abstract AF_UNIX authority rejects the concurrent creator;
# the first creator then notices pathname drift and rolls back its exact
# prepublication tree and journal without touching either hostile lock inode.
split_brain_second_result="$workdir/automatic-split-brain-second.result"
split_brain_parent=""
split_brain_output=unchanged
campaign_private_temporary_tree_prepublication_hook() {
    local first_tree="$1" parent
    parent="$(dirname "$first_tree")"
    split_brain_parent="$parent"
    mv "$parent/.automatic-recovery.lock" "$parent/.automatic-recovery.lock.detached"
    : >"$parent/.automatic-recovery.lock"
    chmod 0600 "$parent/.automatic-recovery.lock"
    if bash --noprofile --norc -c '
        set -euo pipefail
        source "$1/scripts/campaign-env.sh"
        second_tree=""
        campaign_prepare_private_temporary_tree "$2" operations-split-brain \
            split_brain_second second_tree
        printf "%s\n" "$second_tree" >"$3"
    ' _ "$repo_root" "$temporary_tree_base" "$split_brain_second_result"; then
        printf 'automatic family lock replacement admitted a split-brain creator\n' >&2
        return 94
    fi
}
if campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-split-brain \
    operations_split_brain split_brain_output; then
    printf 'automatic family lock replacement let the first creator publish\n' >&2
    exit 1
fi
unset -f campaign_private_temporary_tree_prepublication_hook
[[ "$split_brain_output" == unchanged && ! -e "$split_brain_second_result" ]]
[[ -f "$split_brain_parent/.automatic-recovery.lock" ]]
[[ -f "$split_brain_parent/.automatic-recovery.lock.detached" ]]
split_brain_retained_tree="$(find "$split_brain_parent" -mindepth 1 -maxdepth 1 -type d \
    \( -name 'run.*' -o -name '.run.*.borondns-remove.*' \) -print -quit)"
[[ -n "$split_brain_retained_tree" ]]
split_brain_retained_journal="$(find "$split_brain_parent" -maxdepth 1 \
    -type f -name '.automatic-run.*.env' -print -quit)"
[[ -n "$split_brain_retained_journal" ]]
[[ -v 'CAMPAIGN_CLEANUP_IDENTITIES[operations_split_brain:kind]' ]]
[[ "${CAMPAIGN_CLEANUP_IDENTITIES["operations_split_brain:target_device"]}:${CAMPAIGN_CLEANUP_IDENTITIES["operations_split_brain:target_inode"]}" == "$(stat -Lc '%d:%i' "$split_brain_retained_tree")" ]]

phase_crash_tree_path=""
phase_crash_output=unchanged
campaign_private_temporary_tree_prepublication_hook() {
    phase_crash_tree_path="$1"
    kill -KILL "$CAMPAIGN_PRIVATE_TREE_CREATOR_PID"
    return 93
}
if campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-phase-crash \
    operations_phase_crash phase_crash_output; then
    printf 'private temporary tree accepted a creator crash between journal phases\n' >&2
    exit 1
fi
unset -f campaign_private_temporary_tree_prepublication_hook
[[ "$phase_crash_output" == unchanged && -d "$phase_crash_tree_path" ]]
phase_recovered_tree_path=""
campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-phase-crash \
    operations_phase_recovered phase_recovered_tree_path
[[ -d "$phase_crash_tree_path" && -d "$phase_recovered_tree_path" ]]
campaign_remove_private_temporary_tree "$phase_recovered_tree_path" operations_phase_recovered \
    "phase-crash recovered automatic tree"
[[ -v 'CAMPAIGN_CLEANUP_IDENTITIES[operations_phase_crash:kind]' ]]

# Historical tests below exercised destructive recovery from same-UID-owned
# disk journals. Disk state is now evidence-only without live fd authority.
# shellcheck disable=SC2317
if false; then
    # A removing journal is leased to the stable remover shell only until its
    # authenticated cleanup cutoff. Recovery refuses the live owner before that
    # point, then consumes the exact tree even while that same shell remains alive.
    removing_lease_deadline="$(campaign_deadline_from_timeout_seconds 1)"
    removing_lease_tree=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-removing-lease \
        removing_lease_identity removing_lease_tree
    removing_lease_journal="${CAMPAIGN_CLEANUP_IDENTITIES["removing_lease_identity:journal_path"]}"
    campaign_assert_private_lock "$removing_lease_deadline" "$removing_lease_deadline"
    removing_lease_quarantine=""
    campaign_mark_automatic_tree_removing "$removing_lease_tree" removing_lease_identity \
        removing_lease_quarantine "$removing_lease_deadline"
    [[ "$removing_lease_quarantine" =~ ^\.run\.[0-9a-f]{16}\.borondns-remove\.[0-9]+\.[0-9a-f]{24}$ ]]
    grep -Fqx schema=3 "$removing_lease_journal"
    grep -Fqx phase=removing "$removing_lease_journal"
    grep -Fqx "owner_pid=$BASHPID" "$removing_lease_journal"
    grep -Fqx "cleanup_deadline_ns=$removing_lease_deadline" "$removing_lease_journal"
    removing_lease_owner_starttime=""
    campaign_process_starttime "$BASHPID" removing_lease_owner_starttime
    grep -Fqx "owner_starttime=$removing_lease_owner_starttime" "$removing_lease_journal"
    removing_lease_live_successor=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-removing-lease \
        removing_lease_live_successor_identity removing_lease_live_successor
    [[ -d "$removing_lease_tree" && -f "$removing_lease_journal" ]]
    campaign_remove_private_temporary_tree "$removing_lease_live_successor" \
        removing_lease_live_successor_identity "live removing-lease successor"
    sleep 1.1
    removing_lease_recovered=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-removing-lease \
        removing_lease_recovered_identity removing_lease_recovered
    [[ ! -e "$removing_lease_tree" && ! -e "$removing_lease_journal" &&
        -d "$removing_lease_recovered" ]]
    campaign_remove_private_temporary_tree "$removing_lease_recovered" \
        removing_lease_recovered_identity "expired removing-lease successor"
    campaign_forget_cleanup_identity removing_lease_identity

    # An unreaped zombie has a stable /proc starttime but cannot perform cleanup.
    # Recovery treats Z/X as dead instead of allowing it to strand a ready journal.
    zombie_owner_tree=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-zombie-owner \
        zombie_owner_identity zombie_owner_tree
    zombie_owner_journal="${CAMPAIGN_CLEANUP_IDENTITIES["zombie_owner_identity:journal_path"]}"
    zombie_owner_info="$workdir/zombie-owner.info"
    zombie_owner_release="$workdir/zombie-owner.release"
    python3 - "$zombie_owner_info" "$zombie_owner_release" <<'PY' &
import os
from pathlib import Path
import time
import sys

info, release = map(Path, sys.argv[1:])
child = os.fork()
if child == 0:
    os._exit(0)
for _ in range(500):
    raw = Path(f"/proc/{child}/stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2:].split()
    if fields[0] == "Z":
        info.write_text(f"{child}\t{fields[19]}\n", encoding="ascii")
        break
    time.sleep(0.01)
else:
    raise SystemExit("child did not become a zombie")
while not release.exists():
    time.sleep(0.01)
os.waitpid(child, 0)
PY
    zombie_holder_pid=$!
    zombie_wait_deadline=$((SECONDS + 6))
    until [[ -s "$zombie_owner_info" ]]; do
        kill -0 "$zombie_holder_pid" 2>/dev/null || {
            printf 'zombie owner fixture exited before publishing identity\n' >&2
            exit 1
        }
        ((SECONDS < zombie_wait_deadline)) || {
            printf 'zombie owner fixture did not publish its identity\n' >&2
            exit 1
        }
        sleep 0.01
    done
    IFS=$'\t' read -r zombie_owner_pid zombie_owner_starttime <"$zombie_owner_info"
    [[ "$(sed -n 's/^[^)]*) \([A-Z]\).*/\1/p' "/proc/$zombie_owner_pid/stat")" == Z ]]
    sed -i -e "s/^owner_pid=.*/owner_pid=$zombie_owner_pid/" \
        -e "s/^owner_starttime=.*/owner_starttime=$zombie_owner_starttime/" \
        "$zombie_owner_journal"
    zombie_owner_recovered=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-zombie-owner \
        zombie_owner_recovered_identity zombie_owner_recovered
    [[ ! -e "$zombie_owner_tree" && ! -e "$zombie_owner_journal" &&
        -d "$zombie_owner_recovered" ]]
    : >"$zombie_owner_release"
    wait "$zombie_holder_pid"
    campaign_remove_private_temporary_tree "$zombie_owner_recovered" \
        zombie_owner_recovered_identity "zombie-owner recovered successor"
    campaign_forget_cleanup_identity zombie_owner_identity

    # Every durable journal phase has a kill boundary. Staged allocating journals
    # are promoted and removed, identity-bearing preparing/ready states recover the
    # exact inode, and the unavoidable post-mkdir/pre-identity window is visible and
    # retained until an operator explicitly captures/removes that current inode.
    journal_fault_base="$workdir/automatic-tree-journal-faults"
    manual_lock_root="$workdir/automatic-tree-manual-lock"
    mkdir -m 0700 "$journal_fault_base" "$manual_lock_root"
    for journal_fault_phase in \
        allocating-stage-fsynced allocating-published tree-created-before-identity \
        preparing-stage-fsynced preparing-published ready-stage-fsynced ready-published; do
        journal_fault_family="journal-fault-${journal_fault_phase//[^A-Za-z0-9_.-]/-}"
        set +e
        BORONDNS_CAMPAIGN_PRIVATE_TREE_FAULT_PHASE="$journal_fault_phase" \
            bash --noprofile --norc -c '
            set -euo pipefail
            source "$1/scripts/campaign-env.sh"
            fault_tree=""
            campaign_prepare_private_temporary_tree "$2" "$3" fault_identity fault_tree
        ' _ "$repo_root" "$journal_fault_base" "$journal_fault_family" \
            >"$workdir/$journal_fault_family.out" 2>"$workdir/$journal_fault_family.err"
        journal_fault_status=$?
        set -e
        [[ "$journal_fault_status" -ne 0 ]]
        journal_fault_parent="$journal_fault_base/$journal_fault_family-$(id -u)"
        [[ -d "$journal_fault_parent" ]]
        successor_tree=""
        campaign_prepare_private_temporary_tree "$journal_fault_base" "$journal_fault_family" \
            journal_fault_successor successor_tree \
            2>"$workdir/$journal_fault_family.recovery.err"
        [[ -d "$successor_tree" ]]
        [[ -z "$(find "$journal_fault_parent" -maxdepth 1 -type f \
            \( -name '..automatic-*.allocating.*' -o -name '..automatic-*.preparing.*' \
            -o -name '..automatic-*.ready.*' -o -name '..automatic-*.removing.*' \) -print -quit)" ]]
        if [[ "$journal_fault_phase" == tree-created-before-identity ]]; then
            grep -Fq 'manual exact reconciliation required: target=' \
                "$workdir/$journal_fault_family.recovery.err"
            allocating_journal="$(grep -l '^phase=allocating$' "$journal_fault_parent"/.automatic-run.*.env)"
            allocating_tree_name="$(sed -n 's/^tree_name=//p' "$allocating_journal")"
            allocating_tree="$journal_fault_parent/$allocating_tree_name"
            [[ -d "$allocating_tree" && "$allocating_tree" != "$successor_tree" ]]
            campaign_capture_cleanup_identity "$allocating_tree" tree manual_allocating_tree \
                "manual allocating-intent reconciliation"
            # The operations-harness mutation authority acquired above remains
            # live while this explicit adoption/removal is performed.
            campaign_assert_private_lock
            campaign_remove_captured_cleanup_object "$allocating_tree" manual_allocating_tree \
                "manually adopted allocating-intent tree"
            campaign_forget_cleanup_identity manual_allocating_tree
            allocating_cleanup_successor=""
            campaign_prepare_private_temporary_tree "$journal_fault_base" "$journal_fault_family" \
                journal_fault_cleanup_successor allocating_cleanup_successor
            [[ ! -e "$allocating_journal" && -d "$allocating_cleanup_successor" ]]
            campaign_forget_cleanup_identity journal_fault_cleanup_successor
        else
            [[ "$(find "$journal_fault_parent" -maxdepth 1 -type d -name 'run.*' | wc -l)" == 1 ]]
        fi
        campaign_forget_cleanup_identity journal_fault_successor
    done

    # Recovery retains the descriptor-authenticated staged/final identities across
    # every mutation boundary. A same-UID actor that replaces a staged pathname
    # after parsing cannot make recovery promote, replace, or unlink its object.
    test_staged_journal_recovery_swap() {
        local recovery_hook="$1" fault_phase="$2" staged_phase="$3" final_phase="$4"
        local recovery_family="journal-recovery-swap-${recovery_hook//[^A-Za-z0-9_.-]/-}"
        local recovery_parent
        recovery_parent="$journal_fault_base/$recovery_family-$(id -u)"
        local fault_output="$workdir/$recovery_family.fault.out"
        local fault_error="$workdir/$recovery_family.fault.err"
        local recovery_output="$workdir/$recovery_family.recovery.out"
        local recovery_error="$workdir/$recovery_family.recovery.err"
        local marker="$workdir/$recovery_family.marker"
        local continuation="$workdir/$recovery_family.continue"
        local staged trusted final tree_name tree_path staged_identity staged_sha256
        local final_identity="" final_sha256="" recovery_pid recovery_status
        local recovered_tree="" recovery_identity="journal_recovery_${recovery_hook//[^A-Za-z0-9_]/_}"

        set +e
        BORONDNS_CAMPAIGN_PRIVATE_TREE_FAULT_PHASE="$fault_phase" \
            bash --noprofile --norc -c '
            set -euo pipefail
            source "$1/scripts/campaign-env.sh"
            fault_tree=""
            campaign_prepare_private_temporary_tree "$2" "$3" fault_identity fault_tree
        ' _ "$repo_root" "$journal_fault_base" "$recovery_family" \
            >"$fault_output" 2>"$fault_error"
        recovery_status=$?
        set -e
        [[ "$recovery_status" -ne 0 && -d "$recovery_parent" ]]

        staged="$(find "$recovery_parent" -maxdepth 1 -type f \
            -name "..automatic-run.*.env.$staged_phase.*" -print -quit)"
        [[ -n "$staged" ]]
        tree_name="$(sed -n 's/^tree_name=//p' "$staged")"
        [[ "$tree_name" =~ ^run\.[0-9a-f]{16}$ ]]
        final="$recovery_parent/.automatic-$tree_name.env"
        tree_path="$recovery_parent/$tree_name"
        staged_identity="$(stat -Lc '%d:%i:%u' -- "$staged")"
        staged_sha256="$(campaign_sha256 "$staged")"
        if [[ "$final_phase" == absent ]]; then
            [[ ! -e "$final" ]]
        else
            [[ -f "$final" && "$(sed -n 's/^phase=//p' "$final")" == "$final_phase" ]]
            final_identity="$(stat -Lc '%d:%i:%u' -- "$final")"
            final_sha256="$(campaign_sha256 "$final")"
        fi

        BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_PHASE="$recovery_hook" \
            BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_MARKER="$marker" \
            BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_CONTINUE="$continuation" \
            bash --noprofile --norc -c '
            set -euo pipefail
            source "$1/scripts/campaign-env.sh"
            recovered=""
            campaign_prepare_private_temporary_tree "$2" "$3" recovered_identity recovered
        ' _ "$repo_root" "$journal_fault_base" "$recovery_family" \
            >"$recovery_output" 2>"$recovery_error" &
        recovery_pid=$!
        lock_holder_pids+=("$recovery_pid")
        local marker_deadline=$((SECONDS + 6))
        until [[ -e "$marker" ]]; do
            kill -0 "$recovery_pid" 2>/dev/null || {
                wait "$recovery_pid" 2>/dev/null || true
                printf 'staged journal recovery exited before %s hook\n' "$recovery_hook" >&2
                exit 1
            }
            ((SECONDS < marker_deadline)) || {
                printf 'staged journal recovery did not reach %s hook\n' "$recovery_hook" >&2
                exit 1
            }
            sleep 0.01
        done

        trusted="$staged.trusted"
        mv -- "$staged" "$trusted"
        printf 'foreign staged journal must be preserved\n' >"$staged"
        : >"$continuation"
        set +e
        wait "$recovery_pid"
        recovery_status=$?
        set -e
        untrack_test_process "$recovery_pid"
        [[ "$recovery_status" -ne 0 ]]
        local retained_foreign=""
        if [[ "$recovery_hook" == before-staged-quarantine ]]; then
            [[ ! -e "$staged" ]]
            retained_foreign="$(find "$recovery_parent" -maxdepth 1 -type f \
                -exec grep -lFx 'foreign staged journal must be preserved' {} +)"
            [[ -n "$retained_foreign" ]]
        else
            grep -Fqx 'foreign staged journal must be preserved' "$staged"
        fi
        [[ "$(stat -Lc '%d:%i:%u' -- "$trusted")" == "$staged_identity" ]]
        [[ "$(campaign_sha256 "$trusted")" == "$staged_sha256" ]]
        if [[ "$final_phase" == absent ]]; then
            [[ ! -e "$final" ]]
            grep -Fq 'staged journal changed before promotion' "$recovery_error"
        else
            [[ "$(stat -Lc '%d:%i:%u' -- "$final")" == "$final_identity" ]]
            [[ "$(campaign_sha256 "$final")" == "$final_sha256" ]]
            if [[ "$recovery_hook" == before-staged-replace ]]; then
                grep -Fq 'journal identity changed before recovery replace' "$recovery_error"
            elif [[ "$recovery_hook" == before-staged-quarantine ]]; then
                grep -Fq 'stale staged journal changed while entering quarantine' "$recovery_error"
            else
                grep -Fq 'journal identity changed before staged cleanup' "$recovery_error"
            fi
        fi

        if [[ -n "$retained_foreign" ]]; then
            rm -- "$retained_foreign"
        else
            rm -- "$staged"
        fi
        mv -- "$trusted" "$staged"
        campaign_prepare_private_temporary_tree "$journal_fault_base" "$recovery_family" \
            "$recovery_identity" recovered_tree
        [[ -d "$recovered_tree" && ! -e "$staged" ]]
        [[ "$tree_path" == "$recovered_tree" || ! -e "$tree_path" ]]
        campaign_remove_private_temporary_tree "$recovered_tree" "$recovery_identity" \
            "staged journal recovery swap successor"
    }

    test_staged_journal_recovery_swap \
        before-staged-promote allocating-stage-fsynced allocating absent
    test_staged_journal_recovery_swap \
        before-staged-replace preparing-stage-fsynced preparing allocating
    test_staged_journal_recovery_swap \
        before-staged-unlink ready-stage-fsynced ready preparing
    test_staged_journal_recovery_swap \
        before-staged-quarantine ready-stage-fsynced ready preparing
    unset -f test_staged_journal_recovery_swap

    # Recursive recovery quarantines a child before deletion. A replacement after
    # enumeration is retained under the quarantine name and recovery fails closed.
    child_quarantine_family='journal-child-quarantine-race'
    child_quarantine_ready="$workdir/child-quarantine.ready"
    bash --noprofile --norc -c '
    set -euo pipefail
    source "$1/scripts/campaign-env.sh"
    owned_tree=""
    campaign_prepare_private_temporary_tree "$2" "$3" child_quarantine_owner owned_tree
    printf "trusted child\n" >"$owned_tree/payload"
    printf "%s\n" "$owned_tree" >"$4"
    while true; do sleep 1; done
' _ "$repo_root" "$journal_fault_base" "$child_quarantine_family" "$child_quarantine_ready" &
    child_quarantine_owner_pid=$!
    lock_holder_pids+=("$child_quarantine_owner_pid")
    child_quarantine_wait_deadline=$((SECONDS + 6))
    until [[ -s "$child_quarantine_ready" ]]; do
        kill -0 "$child_quarantine_owner_pid" 2>/dev/null || {
            printf 'child quarantine owner exited before readiness\n' >&2
            exit 1
        }
        ((SECONDS < child_quarantine_wait_deadline)) || exit 1
        sleep 0.01
    done
    child_quarantine_tree="$(<"$child_quarantine_ready")"
    kill -KILL "$child_quarantine_owner_pid"
    wait "$child_quarantine_owner_pid" 2>/dev/null || true
    untrack_test_process "$child_quarantine_owner_pid"
    child_quarantine_marker="$workdir/child-quarantine.marker"
    child_quarantine_continue="$workdir/child-quarantine.continue"
    BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_PHASE=before-child-quarantine \
        BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_MARKER="$child_quarantine_marker" \
        BORONDNS_CAMPAIGN_JOURNAL_RECOVERY_TEST_CONTINUE="$child_quarantine_continue" \
        bash --noprofile --norc -c '
        set -euo pipefail
        source "$1/scripts/campaign-env.sh"
        successor=""
        campaign_prepare_private_temporary_tree "$2" "$3" child_quarantine_successor successor
    ' _ "$repo_root" "$journal_fault_base" "$child_quarantine_family" \
        >"$workdir/child-quarantine.out" 2>"$workdir/child-quarantine.err" &
    child_quarantine_recovery_pid=$!
    lock_holder_pids+=("$child_quarantine_recovery_pid")
    child_quarantine_wait_deadline=$((SECONDS + 6))
    until [[ -e "$child_quarantine_marker" ]]; do
        kill -0 "$child_quarantine_recovery_pid" 2>/dev/null || {
            printf 'child quarantine recovery exited before mutation hook\n' >&2
            exit 1
        }
        ((SECONDS < child_quarantine_wait_deadline)) || exit 1
        sleep 0.01
    done
    child_quarantine_parent="$(dirname "$child_quarantine_tree")"
    child_quarantine_recovered_tree="$(find "$child_quarantine_parent" -maxdepth 1 -type d \
        -name '.*.borondns-recovered-remove.*' -print -quit)"
    [[ -n "$child_quarantine_recovered_tree" ]]
    mv -- "$child_quarantine_recovered_tree/payload" "$workdir/child-quarantine-trusted"
    printf 'foreign child victim must survive\n' >"$child_quarantine_recovered_tree/payload"
    : >"$child_quarantine_continue"
    set +e
    wait "$child_quarantine_recovery_pid"
    child_quarantine_recovery_status=$?
    set -e
    untrack_test_process "$child_quarantine_recovery_pid"
    [[ "$child_quarantine_recovery_status" -ne 0 ]]
    child_quarantine_foreign="$(find "$child_quarantine_recovered_tree" -maxdepth 1 -type f \
        -exec grep -lFx 'foreign child victim must survive' {} +)"
    [[ -n "$child_quarantine_foreign" && -f "$workdir/child-quarantine-trusted" ]]
    grep -Fq 'automatic-tree child changed while entering quarantine' \
        "$workdir/child-quarantine.err"

    # SIGKILL after the root rename is recovered from the exact quarantine identity
    # recorded and fsynced before the rename.
    quarantine_crash_family='journal-quarantine-crash'
    set +e
    BORONDNS_CAMPAIGN_IDENTITY_REMOVE_FAULT_PHASE=root-quarantined \
        bash --noprofile --norc -c '
        set -euo pipefail
        source "$1/scripts/campaign-env.sh"
        mkdir -m 0700 "$2" 2>/dev/null || true
        campaign_acquire_private_lock "$2" quarantine-crash "quarantine crash lock"
        quarantine_tree_path=""
        campaign_prepare_private_temporary_tree "$3" "$4" quarantine_tree quarantine_tree_path
        printf "payload\n" >"$quarantine_tree_path/payload"
        campaign_remove_private_temporary_tree "$quarantine_tree_path" quarantine_tree "quarantine crash tree"
    ' _ "$repo_root" "$manual_lock_root" "$journal_fault_base" "$quarantine_crash_family" \
        >"$workdir/quarantine-crash.out" 2>"$workdir/quarantine-crash.err"
    quarantine_crash_status=$?
    set -e
    [[ "$quarantine_crash_status" -ne 0 ]]
    quarantine_parent="$journal_fault_base/$quarantine_crash_family-$(id -u)"
    [[ -d "$quarantine_parent" ]]
    [[ -n "$(find "$quarantine_parent" -maxdepth 1 -type d -name '.run.*.borondns-remove.*' -print -quit)" ]]
    quarantine_successor=""
    campaign_prepare_private_temporary_tree "$journal_fault_base" "$quarantine_crash_family" \
        quarantine_successor_identity quarantine_successor
    [[ -d "$quarantine_successor" ]]
    [[ -z "$(find "$quarantine_parent" -maxdepth 1 -type d -name '.run.*.borondns-remove.*' -print -quit)" ]]
    [[ "$(find "$quarantine_parent" -maxdepth 1 -type f -name '.automatic-run.*.env' | wc -l)" == 1 ]]
    campaign_forget_cleanup_identity quarantine_successor_identity

    prepublication_foreign_path=""
    prepublication_foreign_output=unchanged
    campaign_private_temporary_tree_prepublication_hook() {
        prepublication_foreign_path="$1"
        mv "$1" "$1.original"
        mkdir -m 0700 "$1"
        printf 'foreign replacement must survive\n' >"$1/sentinel"
        return 92
    }
    if campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-prepublication-foreign \
        operations_prepublication_foreign prepublication_foreign_output; then
        printf 'private temporary tree rollback accepted a foreign named tree\n' >&2
        exit 1
    fi
    unset -f campaign_private_temporary_tree_prepublication_hook
    [[ "$prepublication_foreign_output" == unchanged ]]
    grep -Fqx 'foreign replacement must survive' "$prepublication_foreign_path/sentinel"
    [[ -d "$prepublication_foreign_path.original" ]]
    [[ "${CAMPAIGN_CLEANUP_IDENTITIES["operations_prepublication_foreign:kind"]:-}" == tree ]]
    campaign_forget_cleanup_identity operations_prepublication_foreign

    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-auto-tree \
        operations_auto_tree operations_auto_tree_path
    printf 'automatic tree payload\n' >"$operations_auto_tree_path/payload"
    campaign_remove_private_temporary_tree "$operations_auto_tree_path" operations_auto_tree \
        "operations automatic tree"
    [[ ! -e "$operations_auto_tree_path" ]]

    # Published plan/reference cleanup is disarmed only while the published name
    # still resolves to the exact descriptor-bound tree. A same-UID pathname swap
    # must retain the journal and the foreign replacement.
    published_swap_tree=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-published-swap \
        operations_published_swap published_swap_tree
    published_swap_destination="$workdir/published-swap-plan"
    campaign_rename_noreplace "$published_swap_tree" "$published_swap_destination"
    mv "$published_swap_destination" "$published_swap_destination.original"
    mkdir -m 0700 "$published_swap_destination"
    printf 'foreign published plan replacement\n' >"$published_swap_destination/sentinel"
    if campaign_disarm_published_private_temporary_tree "$published_swap_destination" \
        operations_published_swap "published plan swap fixture"; then
        printf 'published automatic-tree disarm accepted a replacement pathname\n' >&2
        exit 1
    fi
    grep -Fqx 'foreign published plan replacement' "$published_swap_destination/sentinel"
    [[ -f "${CAMPAIGN_CLEANUP_IDENTITIES["operations_published_swap:journal_path"]}" ]]
    mv "$published_swap_destination.original" "$published_swap_tree"
    campaign_remove_private_temporary_tree "$published_swap_tree" operations_published_swap \
        "published plan swap original tree"
    rm "$published_swap_destination/sentinel"
    rmdir "$published_swap_destination"

    # A persistent owner/identity journal survives SIGKILL and lets the next
    # creator, under the canonical per-family lock, remove only the exact dead
    # owner's inode before publishing a new tree.
    crash_tree_path_file="$workdir/automatic-tree-crash.path"
    set +e
    bash -c '
    set -e
    source "$1/scripts/campaign-env.sh"
    crashed_tree=""
    campaign_prepare_private_temporary_tree "$2" operations-crash-recovery \
        operations_crashed_tree crashed_tree
    printf "%s\n" "$crashed_tree" >"$3"
    printf "crash payload\n" >"$crashed_tree/payload"
    kill -KILL $$
' _ "$repo_root" "$temporary_tree_base" "$crash_tree_path_file" >/dev/null 2>&1
    crash_tree_status=$?
    set -e
    [[ "$crash_tree_status" == 137 ]]
    crashed_tree_path="$(<"$crash_tree_path_file")"
    [[ -d "$crashed_tree_path" ]]
    recovered_tree_path=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-crash-recovery \
        operations_recovered_tree recovered_tree_path
    [[ ! -e "$crashed_tree_path" && -d "$recovered_tree_path" ]]
    campaign_remove_private_temporary_tree "$recovered_tree_path" operations_recovered_tree \
        "recovered automatic tree"

    # A live owner is never reclaimed. A mismatched starttime (the PID-reuse case)
    # and a prior boot ID are dead-owner identities and are reclaimed.
    live_tree_path=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-live-owner \
        operations_live_tree live_tree_path
    second_live_tree_path=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-live-owner \
        operations_second_live_tree second_live_tree_path
    [[ -d "$live_tree_path" && -d "$second_live_tree_path" ]]
    campaign_remove_private_temporary_tree "$second_live_tree_path" operations_second_live_tree \
        "second live automatic tree"
    live_tree_journal="${CAMPAIGN_CLEANUP_IDENTITIES["operations_live_tree:journal_path"]}"
    sed -i 's/^owner_starttime=.*/owner_starttime=0/' "$live_tree_journal"
    pid_reuse_tree_path=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-live-owner \
        operations_pid_reuse_tree pid_reuse_tree_path
    [[ ! -e "$live_tree_path" && -d "$pid_reuse_tree_path" ]]
    campaign_remove_private_temporary_tree "$pid_reuse_tree_path" operations_pid_reuse_tree \
        "PID-reuse automatic tree"

    boot_mismatch_tree_path=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-boot-mismatch \
        operations_boot_mismatch_tree boot_mismatch_tree_path
    boot_mismatch_journal="${CAMPAIGN_CLEANUP_IDENTITIES["operations_boot_mismatch_tree:journal_path"]}"
    sed -i 's/^boot_id=.*/boot_id=00000000-0000-0000-0000-000000000000/' "$boot_mismatch_journal"
    boot_recovered_tree_path=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-boot-mismatch \
        operations_boot_recovered_tree boot_recovered_tree_path
    [[ ! -e "$boot_mismatch_tree_path" && -d "$boot_recovered_tree_path" ]]
    campaign_remove_private_temporary_tree "$boot_recovered_tree_path" operations_boot_recovered_tree \
        "boot-mismatch automatic tree"

    # Legacy schema-2 has no authenticated cleanup lease, so a forged/remnant
    # removing phase is ambiguous and must fail closed without reclaiming a live
    # owner's exact tree.
    schema2_removing_tree=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-schema2-removing \
        operations_schema2_removing schema2_removing_tree
    schema2_removing_journal="${CAMPAIGN_CLEANUP_IDENTITIES["operations_schema2_removing:journal_path"]}"
    schema2_removing_name="$(basename "$schema2_removing_tree")"
    sed -i -e 's/^phase=ready$/phase=removing/' \
        -e "s/^quarantine_name=$/quarantine_name=.$schema2_removing_name.borondns-remove.$BASHPID.0123456789abcdef01234567/" \
        "$schema2_removing_journal"
    schema2_successor=unchanged
    if campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-schema2-removing \
        operations_schema2_successor schema2_successor; then
        printf 'automatic-tree recovery accepted legacy schema-2 removing state\n' >&2
        exit 1
    fi
    [[ "$schema2_successor" == unchanged && -d "$schema2_removing_tree" &&
        -f "$schema2_removing_journal" ]]
    sed -i -e 's/^phase=removing$/phase=ready/' \
        -e 's/^quarantine_name=.*/quarantine_name=/' "$schema2_removing_journal"
    schema2_restored_journal_identity="$(stat -c '%d:%i:%u' "$schema2_removing_journal")"
    CAMPAIGN_CLEANUP_IDENTITIES["operations_schema2_removing:journal_device"]="${schema2_restored_journal_identity%%:*}"
    schema2_restored_journal_identity="${schema2_restored_journal_identity#*:}"
    CAMPAIGN_CLEANUP_IDENTITIES["operations_schema2_removing:journal_inode"]="${schema2_restored_journal_identity%%:*}"
    CAMPAIGN_CLEANUP_IDENTITIES["operations_schema2_removing:journal_owner"]="${schema2_restored_journal_identity##*:}"
    campaign_remove_private_temporary_tree "$schema2_removing_tree" operations_schema2_removing \
        "schema-2 removing fail-closed tree"

    # Dead-owner recovery refuses both a foreign replacement and a renamed-away
    # exact inode. Neither object is deleted and the durable journal is retained.
    foreign_recovery_tree=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-foreign-recovery \
        operations_foreign_recovery foreign_recovery_tree
    foreign_recovery_journal="${CAMPAIGN_CLEANUP_IDENTITIES["operations_foreign_recovery:journal_path"]}"
    sed -i 's/^owner_starttime=.*/owner_starttime=0/' "$foreign_recovery_journal"
    mv "$foreign_recovery_tree" "$foreign_recovery_tree.original"
    mkdir -m 0700 "$foreign_recovery_tree"
    printf 'foreign recovery replacement\n' >"$foreign_recovery_tree/sentinel"
    foreign_recovery_candidate=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-foreign-recovery \
        operations_foreign_recovery_candidate foreign_recovery_candidate
    grep -Fqx 'foreign recovery replacement' "$foreign_recovery_tree/sentinel"
    [[ -d "$foreign_recovery_tree.original" && -f "$foreign_recovery_journal" &&
        -d "$foreign_recovery_candidate" ]]
    campaign_remove_private_temporary_tree "$foreign_recovery_candidate" \
        operations_foreign_recovery_candidate "foreign-recovery successor tree"
    campaign_forget_cleanup_identity operations_foreign_recovery
fi

campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-replaced-tree \
    operations_replaced_tree operations_replaced_tree_path
mv "$operations_replaced_tree_path" "$operations_replaced_tree_path.original"
mkdir -m 0700 "$operations_replaced_tree_path"
printf 'replacement must survive\n' >"$operations_replaced_tree_path/sentinel"
if campaign_remove_private_temporary_tree "$operations_replaced_tree_path" \
    operations_replaced_tree "operations replaced automatic tree"; then
    printf 'automatic build cleanup accepted a pathname replacement\n' >&2
    exit 1
fi
grep -Fqx 'replacement must survive' "$operations_replaced_tree_path/sentinel"

operations_missing_tree_path=""
campaign_prepare_private_temporary_tree "$temporary_tree_base" operations-missing-tree \
    operations_missing_tree operations_missing_tree_path
printf 'renamed tree must survive\n' >"$operations_missing_tree_path/payload"
mv "$operations_missing_tree_path" "$operations_missing_tree_path.renamed"
if campaign_remove_private_temporary_tree "$operations_missing_tree_path" \
    operations_missing_tree "operations missing automatic tree"; then
    printf 'automatic build cleanup accepted a renamed-away tree\n' >&2
    exit 1
fi
grep -Fqx 'renamed tree must survive' "$operations_missing_tree_path.renamed/payload"
[[ "${CAMPAIGN_CLEANUP_IDENTITIES["operations_missing_tree:kind"]:-}" == tree ]]
campaign_forget_cleanup_identity operations_missing_tree

# Exercise the large-soak runner's automatic and explicit build-root policies
# directly. Automatic roots are identity-bound and ephemeral; caller-provided
# roots remain caller-owned after finalization.
(
    campaign_detach_inherited_private_lock
    campaign_acquire_private_lock "$workdir" "operations:large-build-subshell" \
        "large build subshell fixture"
    # shellcheck disable=SC2030
    export TMPDIR="$temporary_tree_base"
    cargo_target_dir=""
    cargo_target_dir_auto=0
    prepare_build_directory
    automatic_large_build="$cargo_target_dir"
    printf 'large automatic payload\n' >"$automatic_large_build/payload"
    cleanup_automatic_build_directory
    [[ ! -e "$automatic_large_build" ]]
    campaign_release_private_lock
)
explicit_large_build="$workdir/explicit-large-build"
mkdir -m 0700 "$explicit_large_build"
(
    cargo_target_dir="$explicit_large_build"
    cargo_target_dir_auto=0
    prepare_build_directory
    printf 'caller-owned\n' >"$cargo_target_dir/sentinel"
    cleanup_automatic_build_directory
)
grep -Fqx caller-owned "$explicit_large_build/sentinel"

resume_provenance_fixture="$workdir/resume-provenance-fixture"
mkdir "$resume_provenance_fixture"
resume_provenance_commit="$(git -C "$repo_root" rev-parse HEAD)"
printf '%s\n' \
    "expected_commit=$resume_provenance_commit" \
    "cargo_sha256=$test_cargo_sha256" \
    "rustc_sha256=$test_rustc_sha256" \
    >"$resume_provenance_fixture/soak.env"
(
    evidence_dir="$resume_provenance_fixture"
    expected_commit=""
    expected_cargo_sha256=""
    expected_rustc_sha256=""
    selected_cargo_path="$(rustup which cargo)"
    selected_rustc_path="$(rustup which rustc)"
    verify_expected_clean_head() { [[ "$expected_commit" == "$resume_provenance_commit" ]]; }
    bind_resume_provenance
    [[ "$expected_commit" == "$resume_provenance_commit" ]]
    [[ "$expected_cargo_sha256" == "$test_cargo_sha256" ]]
    [[ "$expected_rustc_sha256" == "$test_rustc_sha256" ]]
)
resume_provenance_before="$(find "$resume_provenance_fixture" -printf '%P\n' | sort)"
if (
    evidence_dir="$resume_provenance_fixture"
    expected_commit=0000000000000000000000000000000000000000
    expected_cargo_sha256=""
    expected_rustc_sha256=""
    selected_cargo_path="$(rustup which cargo)"
    selected_rustc_path="$(rustup which rustc)"
    bind_resume_provenance
); then
    printf 'direct soak resume accepted a caller commit differing from retained provenance\n' >&2
    exit 1
fi
[[ "$(find "$resume_provenance_fixture" -printf '%P\n' | sort)" == "$resume_provenance_before" ]]
if (
    evidence_dir="$resume_provenance_fixture"
    expected_commit=""
    expected_cargo_sha256=""
    expected_rustc_sha256=""
    selected_cargo_path=/bin/true
    selected_rustc_path="$(rustup which rustc)"
    verify_expected_clean_head() { return 0; }
    bind_resume_provenance
); then
    printf 'direct soak resume accepted a selected Cargo binary differing from retained provenance\n' >&2
    exit 1
fi
[[ "$(find "$resume_provenance_fixture" -printf '%P\n' | sort)" == "$resume_provenance_before" ]]

resume_metadata_fixture="$workdir/resume-metadata-fixture"
mkdir "$resume_metadata_fixture"
resume_metadata_start="$(date +%s)"
resume_metadata_deadline=$((resume_metadata_start + 60))
resume_metadata_utc="$(date -u -d "@$resume_metadata_start" '+%Y-%m-%dT%H:%M:%SZ')"
resume_metadata_stamp="$(date -u -d "@$resume_metadata_start" '+%Y%m%dT%H%M%SZ')"
printf '%s\n' \
    evidence_schema=2 \
    "created_utc=$resume_metadata_utc" \
    "repo_root=$repo_root" \
    "cargo_target_dir=$workdir/resume-metadata-build-original" \
    duration_seconds=60 \
    "start_epoch_seconds=$resume_metadata_start" \
    "deadline_epoch_seconds=$resume_metadata_deadline" \
    scenario_timeout_seconds=1 \
    scenario_kill_after_seconds=1 \
    docker_cleanup_timeout_seconds=1 \
    cycle_sleep_seconds=1 \
    sample_interval_seconds=1 \
    allow_skip=1 \
    resume=0 \
    "expected_commit=$resume_provenance_commit" \
    "cargo_sha256=$test_cargo_sha256" \
    "rustc_sha256=$test_rustc_sha256" \
    scenarios=sentinel \
    >"$resume_metadata_fixture/soak.env"
sed 's|cargo_target_dir=.*|cargo_target_dir='"$workdir"'/resume-metadata-build-resume|; s/^resume=0$/resume=1/' \
    "$resume_metadata_fixture/soak.env" \
    >"$resume_metadata_fixture/soak-resume-$resume_metadata_stamp.env"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$resume_metadata_fixture/scenario-results.tsv"
python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$resume_metadata_fixture" "$resume_provenance_commit" --expected-duration 60 \
    --expected-scenario sentinel "${soak_validator_policy[@]}" \
    >"$workdir/resume-metadata-valid.tsv"
sed -i 's/^cargo_sha256=.*/cargo_sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
    "$resume_metadata_fixture/soak-resume-$resume_metadata_stamp.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$resume_metadata_fixture" "$resume_provenance_commit" --expected-duration 60 \
    --expected-scenario sentinel "${soak_validator_policy[@]}"; then
    printf 'soak validator accepted mixed-tool retained resume metadata\n' >&2
    exit 1
fi

fixed_timing_now=1783944000
largest_supported_soak_duration=$((9223372036 - fixed_timing_now))
(
    duration="$largest_supported_soak_duration"
    scenario_timeout=1
    scenario_kill_after=1
    cycle_sleep=1
    sample_interval=1
    docker_cleanup_timeout=1
    validate_timing_bounds "$fixed_timing_now"
    [[ "$(checked_campaign_deadline "$fixed_timing_now" "$duration")" == 9223372036 ]]
)
for rejected_soak_duration in \
    9223372036854775807 \
    "$((9223372036854775807 - fixed_timing_now))" \
    "$((largest_supported_soak_duration + 1))"; do
    if (
        duration="$rejected_soak_duration"
        scenario_timeout=1
        scenario_kill_after=1
        cycle_sleep=1
        sample_interval=1
        docker_cleanup_timeout=1
        validate_timing_bounds "$fixed_timing_now"
    ); then
        printf 'large soak timing validator accepted unsupported duration: %s\n' \
            "$rejected_soak_duration" >&2
        exit 1
    fi
done

deadline_before_allocation="$workdir/deadline-before-allocation"
mkdir -p "$deadline_before_allocation/scenarios"
(
    evidence_dir="$deadline_before_allocation"
    scenario_timeout=1
    scenario_kill_after=1
    campaign_deadline_epoch=$(($(date +%s) - 1))
    campaign_control_deadline_nanoseconds=$(($(monotonic_nanoseconds) - 1))
    scenario_names=(sentinel)
    scenario_scripts=(scripts/unused-deadline-fixture.sh)
    scenario_env_vars=(TEST_ARTIFACT)
    verify_expected_clean_head() { return 0; }
    verify_expected_tool_hashes() { return 0; }
    if run_scenario 1 0 1; then
        deadline_before_status=0
    else
        deadline_before_status=$?
    fi
    [[ "$deadline_before_status" == 75 ]]
    [[ -z "$(find "$deadline_before_allocation/scenarios" -type d -name 'attempt-*' -print -quit)" ]]
)

deadline_second_race="$workdir/deadline-second-race"
mkdir -p "$deadline_second_race/scenarios"
(
    campaign_detach_inherited_private_lock
    campaign_acquire_private_lock "$workdir" "operations:deadline-second-race" \
        "deadline second race fixture"
    evidence_dir="$deadline_second_race"
    scenario_timeout=1
    scenario_kill_after=1
    campaign_deadline_epoch=$(($(date +%s) + 60))
    printf -v campaign_control_deadline_nanoseconds '%s' \
        "$(($(monotonic_nanoseconds) + 60000000000))"
    scenario_names=(sentinel)
    scenario_scripts=(scripts/unused-deadline-fixture.sh)
    scenario_env_vars=(TEST_ARTIFACT)
    verify_expected_clean_head() { return 0; }
    verify_expected_tool_hashes() { return 0; }
    run_bounded_scenario_command() {
        touch "$7"
        return 75
    }
    if run_scenario 1 0 1; then
        deadline_second_status=0
    else
        deadline_second_status=$?
    fi
    [[ "$deadline_second_status" == 75 ]]
    [[ -z "$(find "$deadline_second_race/scenarios" -type d -name 'attempt-*' -print -quit)" ]]
    campaign_release_private_lock
)

deadline_term_zero_script="$workdir/deadline-term-zero.sh"
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'trap '\''exit 0'\'' TERM' \
    'printf partial >"$TEST_ARTIFACT/partial-output"' \
    'while :; do sleep 1; done' \
    >"$deadline_term_zero_script"
chmod +x "$deadline_term_zero_script"
deadline_term_zero_script_relative="$(realpath --relative-to="$repo_root" "$deadline_term_zero_script")"
deadline_term_zero_evidence="$workdir/deadline-term-zero-evidence"
deadline_term_zero_attempt="$deadline_term_zero_evidence/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
deadline_term_zero_prior_end_epoch="$(date +%s)"
deadline_term_zero_prior_start_utc="$(date -u -d "@$((deadline_term_zero_prior_end_epoch - 1))" '+%Y-%m-%dT%H:%M:%SZ')"
deadline_term_zero_prior_end_utc="$(date -u -d "@$deadline_term_zero_prior_end_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p "$deadline_term_zero_attempt" "$workdir/deadline-term-zero-build"
printf 'prior complete cycle\n' >"$deadline_term_zero_attempt/scenario.log"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    "$(printf '1\tsentinel\t1\tpassed\t0\t%s\t%s\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
        "$deadline_term_zero_prior_start_utc" "$deadline_term_zero_prior_end_utc")" \
    >"$deadline_term_zero_evidence/scenario-results.tsv"
(
    campaign_detach_inherited_private_lock
    campaign_acquire_private_lock "$workdir" "operations:deadline-term-zero" \
        "deadline TERM-zero fixture"
    evidence_dir="$deadline_term_zero_evidence"
    cargo_target_dir="$workdir/deadline-term-zero-build"
    scenario_timeout=300
    scenario_kill_after=1
    docker_cleanup_timeout=1
    campaign_deadline_epoch=$(($(date +%s) + 3))
    campaign_control_deadline_nanoseconds=$(($(monotonic_nanoseconds) + 3000000000))
    scenario_names=(sentinel)
    scenario_scripts=("$deadline_term_zero_script_relative")
    scenario_env_vars=(TEST_ARTIFACT)
    scenario_list_for_validation=sentinel
    sampler_pid=""
    verify_expected_clean_head() { return 0; }
    verify_expected_tool_hashes() { return 0; }
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    # Invoked indirectly by run_bounded_scenario_command.
    # shellcheck disable=SC2329
    command() {
        if [[ "$1" == -v && "${2:-}" == docker ]]; then
            return 1
        fi
        builtin command "$@"
    }
    trap finalize_soak_evidence EXIT
    if run_scenario 2 0 1; then
        deadline_term_zero_status=0
    else
        deadline_term_zero_status=$?
    fi
    [[ "$deadline_term_zero_status" == 75 ]]
    [[ "$(wc -l <"$deadline_term_zero_evidence/scenario-results.tsv")" == 2 ]]
    [[ -z "$(find "$deadline_term_zero_evidence/scenarios/cycle-0002" -type d -name 'attempt-*' -print -quit 2>/dev/null)" ]]
)
[[ -f "$deadline_term_zero_evidence/campaign-completed.env" ]]
grep -Fqx scenario_runs_total=1 "$deadline_term_zero_evidence/soak-summary.env"

fail_on_skip_evidence="$workdir/fail-on-skip-evidence"
mkdir -p "$fail_on_skip_evidence/scenarios"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$fail_on_skip_evidence/scenario-results.tsv"
(
    unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_path campaign_lock_label
    campaign_acquire_private_lock "$workdir" "operations:fail-on-skip" "fail-on-skip evidence lock"
    evidence_dir="$fail_on_skip_evidence"
    scenario_timeout=1
    scenario_kill_after=1
    campaign_deadline_epoch=$(($(date +%s) + 60))
    # This sourced-runner global is deliberately local to the fixture subshell.
    # shellcheck disable=SC2030
    campaign_control_deadline_nanoseconds=$(($(monotonic_nanoseconds) + 60000000000))
    scenario_names=(sentinel)
    scenario_scripts=(scripts/unused-fail-on-skip-fixture.sh)
    scenario_env_vars=(TEST_ARTIFACT)
    allow_skip=0
    verify_expected_clean_head() { return 0; }
    verify_expected_tool_hashes() { return 0; }
    run_bounded_scenario_command() {
        printf 'skipping sentinel fixture\n'
        return 0
    }
    if run_scenario 1 0 1; then
        fail_on_skip_status=0
    else
        fail_on_skip_status=$?
    fi
    [[ "$fail_on_skip_status" == 1 ]]
    grep -Eq $'^1\tsentinel\t1\tfailed\t1\t' "$evidence_dir/scenario-results.tsv"
    validate_scenario_results sentinel
    resume=1
    prepare_scenario_results sentinel
    [[ "$(next_scenario_work sentinel)" == "1 0 2" ]]

    fail_on_skip_commit="$(git -C "$repo_root" rev-parse HEAD)"
    fail_on_skip_start_utc="$(tail -n 1 "$evidence_dir/scenario-results.tsv" | cut -f6)"
    fail_on_skip_start="$(date -u -d "$fail_on_skip_start_utc" +%s)"
    fail_on_skip_deadline=$((fail_on_skip_start + 1))
    printf '%s\n' \
        evidence_schema=2 \
        "expected_commit=$fail_on_skip_commit" \
        duration_seconds=1 \
        "start_epoch_seconds=$fail_on_skip_start" \
        "deadline_epoch_seconds=$fail_on_skip_deadline" \
        scenario_timeout_seconds=1 \
        scenario_kill_after_seconds=1 \
        docker_cleanup_timeout_seconds=1 \
        cycle_sleep_seconds=1 \
        sample_interval_seconds=1 \
        allow_skip=0 \
        "cargo_sha256=$test_cargo_sha256" \
        "rustc_sha256=$test_rustc_sha256" \
        scenarios=sentinel \
        >"$evidence_dir/soak.env"
    python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
        "$evidence_dir" "$fail_on_skip_commit" --expected-duration 1 --expected-scenario sentinel \
        --expected-scenario-timeout 1 --expected-scenario-kill-after 1 --expected-cycle-sleep 1 \
        --expected-docker-cleanup-timeout 1 \
        --expected-sample-interval 1 --expected-allow-skip 0 \
        --expected-cargo-sha256 "$test_cargo_sha256" --expected-rustc-sha256 "$test_rustc_sha256" \
        >"$workdir/fail-on-skip-collection.tsv"
    grep -Fq $'soak\tfail-on-skip-evidence\tcurrent\tincomplete' \
        "$workdir/fail-on-skip-collection.tsv"
    : >"$evidence_dir/campaign-completed.env"
    if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
        "$evidence_dir" "$fail_on_skip_commit" --expected-duration 1 --expected-scenario sentinel \
        --expected-scenario-timeout 1 --expected-scenario-kill-after 1 --expected-cycle-sleep 1 \
        --expected-docker-cleanup-timeout 1 \
        --expected-sample-interval 1 --expected-allow-skip 0 \
        --expected-cargo-sha256 "$test_cargo_sha256" --expected-rustc-sha256 "$test_rustc_sha256" \
        >"$workdir/fail-on-skip-forged-collection.tsv" 2>"$workdir/fail-on-skip-forged-collection.err"; then
        printf 'soak collection validator accepted terminal completion over a fail-on-skip failure\n' >&2
        exit 1
    fi
    grep -Fq 'completed soak evidence has an unresolved scenario attempt' \
        "$workdir/fail-on-skip-forged-collection.err"
    campaign_release_private_lock
)

allow_skip_evidence="$workdir/allow-skip-evidence"
mkdir -p "$allow_skip_evidence/scenarios"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$allow_skip_evidence/scenario-results.tsv"
(
    unset campaign_lock_control_fd campaign_lock_response_fd campaign_lock_pid campaign_lock_path campaign_lock_label
    campaign_acquire_private_lock "$workdir" "operations:allow-skip" "allow-skip evidence lock"
    evidence_dir="$allow_skip_evidence"
    scenario_timeout=1
    scenario_kill_after=1
    campaign_deadline_epoch=$(($(date +%s) + 60))
    # This sourced-runner global is deliberately local to the fixture subshell.
    # shellcheck disable=SC2030
    campaign_control_deadline_nanoseconds=$(($(monotonic_nanoseconds) + 60000000000))
    scenario_names=(sentinel)
    scenario_scripts=(scripts/unused-allow-skip-fixture.sh)
    scenario_env_vars=(TEST_ARTIFACT)
    allow_skip=1
    verify_expected_clean_head() { return 0; }
    verify_expected_tool_hashes() { return 0; }
    run_bounded_scenario_command() {
        printf 'skipping sentinel fixture\n'
        return 0
    }
    run_scenario 1 0 1
    grep -Eq $'^1\tsentinel\t1\tskipped\t0\t' "$evidence_dir/scenario-results.tsv"
    validate_scenario_results sentinel
    [[ "$(next_scenario_work sentinel)" == "2 0 1" ]]
    campaign_release_private_lock
)

if "$repo_root/scripts/large-surface-soak.sh" --dry-run --scenario not-a-scenario; then
    printf 'direct soak runner accepted an unknown scenario\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak.sh" --dry-run \
    --scenario bind_catalog --scenario bind_catalog; then
    printf 'direct soak runner accepted a duplicate scenario\n' >&2
    exit 1
fi

sampler_validation_fixture="$workdir/resource-sampler-validation"
mkdir -p "$sampler_validation_fixture"
make_soak_sampler_fixture "$sampler_validation_fixture" 1 2 1
(
    evidence_dir="$sampler_validation_fixture"
    campaign_start_epoch=1
    campaign_deadline_epoch=2
    sample_interval=1
    validate_resource_sampler_evidence
)
torn_sampler_fixture="$workdir/resource-sampler-torn-terminal"
cp -a "$sampler_validation_fixture" "$torn_sampler_fixture"
printf 'status=passed\ncompleted_utc=2026-' \
    >"$torn_sampler_fixture/resource-sampler-attempts/attempt-0001/resource-sampler-completed.env"
(
    evidence_dir="$torn_sampler_fixture"
    campaign_start_epoch=1
    campaign_deadline_epoch=2
    sample_interval=1
    reconcile_interrupted_resource_samplers
    validate_resource_sampler_evidence
)
grep -Fqx status=passed \
    "$torn_sampler_fixture/resource-sampler-attempts/attempt-0001/resource-sampler-completed.env"
for sampler_mutation in schema cadence truncation ordering timestamp attempt-reversal \
    process-orphan process-duplicate process-count process-rss; do
    mutated_sampler="$workdir/resource-sampler-$sampler_mutation"
    cp -a "$sampler_validation_fixture" "$mutated_sampler"
    case "$sampler_mutation" in
    schema)
        sed -i '1s/timestamp_utc/bad_timestamp/' \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
        ;;
    cadence)
        sed -i '3s/\t2\t/\t5\t/' \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
        ;;
    truncation)
        sed -i '$d' "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
        ;;
    ordering)
        mv "$mutated_sampler/resource-sampler-attempts/attempt-0001" \
            "$mutated_sampler/resource-sampler-attempts/attempt-0002"
        ;;
    timestamp)
        sed -i '2s/^1970-01-01T00:00:01Z/2026-07-13T12:00:00Z/' \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
        ;;
    attempt-reversal)
        cp -a "$mutated_sampler/resource-sampler-attempts/attempt-0001" \
            "$mutated_sampler/resource-sampler-attempts/attempt-0002"
        rm "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-sampler-completed.env"
        printf '%s\n' status=failed failed_utc=1970-01-01T00:00:02Z \
            failed_epoch_seconds=2 exit_status=1 \
            >"$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-sampler-failed.env"
        ;;
    process-orphan)
        printf '%s\n' $'1970-01-01T00:00:01Z\t2\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/process-samples.tsv"
        ;;
    process-duplicate)
        awk -F '\t' -v OFS='\t' 'NR == 2 { $8 = 2; $9 = 4 } { print }' \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv" \
            >"$mutated_sampler/process-hosts.new"
        mv "$mutated_sampler/process-hosts.new" \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
        printf '%s\n' \
            $'1970-01-01T00:00:01Z\t1\t123\t0.1\t0.1\t2\t00:01\tborondns' \
            $'1970-01-01T00:00:01Z\t1\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/process-samples.tsv"
        ;;
    process-count)
        printf '%s\n' $'1970-01-01T00:00:01Z\t1\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/process-samples.tsv"
        ;;
    process-rss)
        awk -F '\t' -v OFS='\t' 'NR == 2 { $8 = 1; $9 = 3 } { print }' \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv" \
            >"$mutated_sampler/process-hosts.new"
        mv "$mutated_sampler/process-hosts.new" \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
        printf '%s\n' $'1970-01-01T00:00:01Z\t1\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$mutated_sampler/resource-sampler-attempts/attempt-0001/process-samples.tsv"
        ;;
    esac
    if (
        evidence_dir="$mutated_sampler"
        # This subshell deliberately shadows the sourced runner's global start.
        # shellcheck disable=SC2030
        campaign_start_epoch=1
        campaign_deadline_epoch=2
        sample_interval=1
        validate_resource_sampler_evidence
    ); then
        printf 'resource sampler validator accepted %s mutation\n' "$sampler_mutation" >&2
        exit 1
    fi
done
same_pid_sampler="$workdir/resource-sampler-same-pid-next-epoch"
cp -a "$sampler_validation_fixture" "$same_pid_sampler"
awk -F '\t' -v OFS='\t' 'NR > 1 { $8 = 1; $9 = 2 } { print }' \
    "$same_pid_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv" \
    >"$same_pid_sampler/process-hosts.new"
mv "$same_pid_sampler/process-hosts.new" \
    "$same_pid_sampler/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
printf '%s\n' \
    $'1970-01-01T00:00:01Z\t1\t123\t0.1\t0.1\t2\t00:01\tborondns' \
    $'1970-01-01T00:00:02Z\t2\t123\t0.2\t0.1\t2\t00:02\tborondns' >> \
    "$same_pid_sampler/resource-sampler-attempts/attempt-0001/process-samples.tsv"
(
    evidence_dir="$same_pid_sampler"
    # This subshell deliberately shadows the sourced runner's sampler globals.
    # shellcheck disable=SC2030
    campaign_start_epoch=1
    campaign_deadline_epoch=2
    sample_interval=1
    validate_resource_sampler_evidence
)
(
    # This subshell deliberately shadows the sourced runner's sampler globals.
    # shellcheck disable=SC2030
    sampler_attempt_dir="$workdir/terminated-resource-sampler"
    mkdir "$sampler_attempt_dir"
    (exit 77) &
    # shellcheck disable=SC2030
    sampler_pid=$!
    sleep 0.1
    if require_resource_sampler_alive; then
        printf 'resource sampler supervisor accepted an early-dead sampler\n' >&2
        exit 1
    fi
)
sampler_failure_fixture="$workdir/resource-sampler-command-failure"
mkdir "$sampler_failure_fixture"
(
    campaign_rebind_test_subshell_lock
    evidence_dir="$sampler_failure_fixture"
    sample_interval=1
    sample_resources() { return 77; }
    start_resource_sampler 2
    set +e
    # Both variables are populated dynamically by start_resource_sampler above.
    # shellcheck disable=SC2031
    wait "$sampler_pid"
    sampler_command_status=$?
    set -e
    [[ "$sampler_command_status" == 77 ]]
    # shellcheck disable=SC2031
    grep -Fqx 'exit_status=77' "$sampler_attempt_dir/resource-sampler-failed.env"
    # shellcheck disable=SC2031
    [[ ! -e "$sampler_attempt_dir/resource-sampler-completed.env" ]]
)

# Realtime is retained in sampler evidence, but it must not control campaign
# progress. A frozen or reversing fixture-local date function cannot extend
# the derived monotonic budget or the sampler's bounded sleep.
soak_clock_blocking_command="$workdir/large-soak-clock-blocking.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exec sleep 30' >"$soak_clock_blocking_command"
chmod +x "$soak_clock_blocking_command"
for soak_clock_mode in frozen backward; do
    soak_clock_sampler="$workdir/resource-sampler-$soak_clock_mode-clock"
    soak_clock_state="$workdir/resource-sampler-$soak_clock_mode-clock.state"
    mkdir "$soak_clock_sampler"
    : >"$soak_clock_state"
    soak_clock_started="$(monotonic_nanoseconds)"
    (
        campaign_rebind_test_subshell_lock
        date() {
            if [[ "${1:-}" == +%s ]]; then
                if [[ "$soak_clock_mode" == frozen ]]; then
                    printf '%s\n' 2000000000
                else
                    local count=0
                    [[ ! -s "$soak_clock_state" ]] || count="$(<"$soak_clock_state")"
                    printf '%s\n' "$((count + 1))" >"$soak_clock_state"
                    printf '%s\n' "$((2000000000 - count))"
                fi
            else
                /usr/bin/date "$@"
            fi
        }
        campaign_deadline_epoch=2000000001
        sample_interval=1
        # Keep this clock-control fixture independent of the host awk variant;
        # process enumeration itself is covered by the sampler schema tests.
        awk() {
            if [[ "$*" == *'selected[root]'* ]]; then
                printf '%s\n' "$$"
            else
                command awk "$@"
            fi
        }
        initialize_campaign_control_deadline
        # Populated by initialize_campaign_control_deadline in this subshell.
        # shellcheck disable=SC2031
        sample_resources "$soak_clock_sampler" "$campaign_deadline_epoch" \
            "$campaign_control_deadline_nanoseconds"
    )
    soak_clock_ended="$(monotonic_nanoseconds)"
    ((soak_clock_ended - soak_clock_started <= 4000000000))
    grep -Fqx status=passed "$soak_clock_sampler/resource-sampler-completed.env"
    (($(wc -l <"$soak_clock_sampler/resource-samples.tsv") >= 2))
    if scenario_timeout_within_campaign 1 "$((soak_clock_started + 1000000000))" \
        "$(monotonic_nanoseconds)" 0 0 >/dev/null; then
        printf 'large-soak cycle sleep replenished after a %s realtime clock mutation\n' \
            "$soak_clock_mode" >&2
        exit 1
    fi

    soak_clock_scenario="$workdir/scenario-$soak_clock_mode-clock"
    soak_clock_marker="$soak_clock_scenario/.deadline-exhausted"
    mkdir "$soak_clock_scenario"
    soak_scenario_deadline=$(($(monotonic_nanoseconds) + 1500000000))
    set +e
    run_bounded_scenario_command 30 1 TEST_ARTIFACT "$soak_clock_scenario" \
        "$soak_clock_blocking_command" "$soak_scenario_deadline" "$soak_clock_marker"
    soak_clock_scenario_status=$?
    set -e
    [[ "$soak_clock_scenario_status" == 75 && -f "$soak_clock_marker" ]]
done

# Final sampler supervision and its TERM-to-KILL grace use the same monotonic
# clock even when realtime is frozen.
soak_final_wait_started="$(monotonic_nanoseconds)"
if (
    date() {
        if [[ "${1:-}" == +%s ]]; then
            printf '%s\n' 2000000000
        else
            /usr/bin/date "$@"
        fi
    }
    host_probe_timeout=1
    host_probe_kill_after=1
    (
        trap '' TERM
        exec sleep 30
    ) &
    sampler_pid=$!
    expired_control_deadline=$(($(monotonic_nanoseconds) - 12000000000))
    wait_for_resource_sampler_bounded 2000000000 "$expired_control_deadline"
); then
    printf 'large-soak final sampler wait accepted an unbounded frozen realtime clock\n' >&2
    exit 1
fi
soak_final_wait_ended="$(monotonic_nanoseconds)"
((soak_final_wait_ended - soak_final_wait_started <= 4000000000))

grep -Fq 'ulimit -n 65536' "$repo_root/scripts/interop-chaos-queries.sh"
mapfile -t borondns_docker_interops < <(
    rg -l 'package-docker-image\.sh' "$repo_root"/scripts/interop-*-docker.sh "$repo_root/scripts/test-docker-image.sh"
)
for borondns_docker_interop in "${borondns_docker_interops[@]}"; do
    grep -Fq -- '--ulimit nofile=65536:65536' "$borondns_docker_interop"
done

nonresume_evidence="$workdir/nonresume-existing"
mkdir -p "$nonresume_evidence"
printf 'operator sentinel\n' >"$nonresume_evidence/sentinel.txt"
printf 'completed_utc=already\n' >"$nonresume_evidence/campaign-completed.env"
if "$repo_root/scripts/large-surface-soak.sh" \
    --evidence-dir "$nonresume_evidence" \
    --duration 1 \
    --scenario-timeout 1 \
    --scenario-kill-after 1 \
    --cycle-sleep 1 \
    --sample-interval 1; then
    printf 'non-resume runner accepted a preinitialized evidence directory\n' >&2
    exit 1
fi
grep -Fqx 'operator sentinel' "$nonresume_evidence/sentinel.txt"
grep -Fqx 'completed_utc=already' "$nonresume_evidence/campaign-completed.env"
[[ ! -e "$nonresume_evidence/scenarios" ]]

soak_symlink_victim="$workdir/soak-symlink-victim"
mkdir "$soak_symlink_victim"
ln -s "$soak_symlink_victim" "$workdir/soak-symlink-evidence"
if "$repo_root/scripts/large-surface-soak.sh" \
    --evidence-dir "$workdir/soak-symlink-evidence" --duration 1 --scenario-timeout 1 \
    --scenario-kill-after 1 --cycle-sleep 1 --sample-interval 1; then
    printf 'direct soak runner accepted a symlinked evidence directory\n' >&2
    exit 1
fi
[[ -z "$(find "$soak_symlink_victim" -mindepth 1 -print -quit)" ]]

locked_evidence="$workdir/locked-evidence"
locked_ready="$workdir/locked-evidence.ready"
locked_release="$workdir/locked-evidence.release"
start_test_campaign_lock "$workdir" "$(realpath -ms "$locked_evidence"):runner" \
    "$locked_ready" "$locked_release"
locked_holder_pid="$lock_holder_pid"
if "$repo_root/scripts/large-surface-soak.sh" \
    --evidence-dir "$locked_evidence" \
    --duration 1 \
    --scenario-timeout 1 \
    --scenario-kill-after 1 \
    --cycle-sleep 1 \
    --sample-interval 1; then
    printf 'runner accepted an evidence directory whose ownership lock was held\n' >&2
    exit 1
fi
[[ ! -e "$locked_evidence" ]]
stop_test_campaign_lock "$locked_release" "$locked_holder_pid"

evidence_dir="$workdir/resume-evidence"
mkdir -p "$evidence_dir/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
touch "$evidence_dir/scenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'1\tsentinel\t1\tpassed\t0\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
    >"$evidence_dir/scenario-results.tsv"
resume=1
prepare_scenario_results sentinel
grep -Fqx $'1\tsentinel\t1\tpassed\t0\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
    "$evidence_dir/scenario-results.tsv"
[[ "$(next_scenario_work sentinel)" == "2 0 1" ]]

malformed_results="$workdir/malformed-resume-evidence"
mkdir -p "$malformed_results"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'999\tsentinel\tpassed' >"$malformed_results/scenario-results.tsv"
if (
    evidence_dir="$malformed_results"
    resume=1
    prepare_scenario_results sentinel
); then
    printf 'resume accepted a truncated retained scenario result\n' >&2
    exit 1
fi

partial_resume="$workdir/partial-scenario-resume"
mkdir -p "$partial_resume/scenarios/cycle-0001/first/attempts/attempt-0001"
touch "$partial_resume/scenarios/cycle-0001/first/attempts/attempt-0001/scenario.log"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'1\tfirst\t1\tpassed\t0\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/first/attempts/attempt-0001\tscenarios/cycle-0001/first/attempts/attempt-0001/scenario.log' \
    >"$partial_resume/scenario-results.tsv"
(
    evidence_dir="$partial_resume"
    validate_scenario_results "first second"
    [[ "$(next_scenario_work 'first second')" == "1 1 1" ]]
)

retry_resume="$workdir/failed-scenario-retry"
mkdir -p \
    "$retry_resume/scenarios/cycle-0001/sentinel/attempts/attempt-0001" \
    "$retry_resume/scenarios/cycle-0001/sentinel/attempts/attempt-0002"
touch \
    "$retry_resume/scenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log" \
    "$retry_resume/scenarios/cycle-0001/sentinel/attempts/attempt-0002/scenario.log"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'1\tsentinel\t1\tfailed\t1\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
    $'1\tsentinel\t2\tpassed\t0\t2026-07-13T12:00:02Z\t2026-07-13T12:00:03Z\tscenarios/cycle-0001/sentinel/attempts/attempt-0002\tscenarios/cycle-0001/sentinel/attempts/attempt-0002/scenario.log' \
    >"$retry_resume/scenario-results.tsv"
(
    evidence_dir="$retry_resume"
    validate_scenario_results sentinel
    [[ "$(next_scenario_work sentinel)" == "2 0 1" ]]
    [[ "$(complete_scenario_cycle_count sentinel)" == 1 ]]
)
retry_reversal="$workdir/failed-scenario-retry-reversal"
cp -a "$retry_resume" "$retry_reversal"
sed -i \
    '3s/2026-07-13T12:00:02Z\t2026-07-13T12:00:03Z/2026-07-13T11:59:58Z\t2026-07-13T11:59:59Z/' \
    "$retry_reversal/scenario-results.tsv"
if (
    evidence_dir="$retry_reversal"
    validate_scenario_results sentinel
); then
    printf 'scenario validator accepted a retry whose clock reverses behind the prior attempt\n' >&2
    exit 1
fi

interrupted_resume="$workdir/interrupted-scenario-resume"
interrupted_attempt="$interrupted_resume/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
interrupted_started_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p "$interrupted_attempt"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$interrupted_resume/scenario-results.tsv"
printf '%s\n' cycle=1 scenario=sentinel attempt=1 "started_utc=$interrupted_started_utc" \
    >"$interrupted_attempt/attempt-started.env"
printf 'status=interrupted\nrecorded_ut' >"$interrupted_attempt/attempt-interrupted.env"
(
    campaign_rebind_test_subshell_lock
    evidence_dir="$interrupted_resume"
    resume=1
    prepare_scenario_results sentinel
    grep -Fq "$(printf '1\tsentinel\t1\tinterrupted\t255\t%s\t' "$interrupted_started_utc")" \
        "$interrupted_resume/scenario-results.tsv"
    grep -Eq '^recorded_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
        "$interrupted_attempt/attempt-interrupted.env"
    [[ "$(tail -c 1 "$interrupted_attempt/attempt-interrupted.env" | od -An -t u1 | tr -d ' ')" == 10 ]]
    [[ "$(next_scenario_work sentinel)" == "1 0 2" ]]
)

torn_resume="$workdir/torn-scenario-resume"
torn_attempt="$torn_resume/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
torn_started_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p "$torn_attempt"
printf '%s\n' cycle=1 scenario=sentinel attempt=1 "started_utc=$torn_started_utc" \
    >"$torn_attempt/attempt-started.env"
printf '%s\n' $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$torn_resume/scenario-results.tsv"
printf '1\tsentinel\t1\tfai' >>"$torn_resume/scenario-results.tsv"
(
    campaign_rebind_test_subshell_lock
    evidence_dir="$torn_resume"
    resume=1
    prepare_scenario_results sentinel
    [[ "$(grep -Fc "$(printf '1\tsentinel\t1\tinterrupted\t255\t%s\t' "$torn_started_utc")" \
        "$torn_resume/scenario-results.tsv")" == 1 ]]
    [[ "$(tail -c 1 "$torn_resume/scenario-results.tsv" | od -An -t u1 | tr -d ' ')" == 10 ]]
)

incomplete_cycle_results="$workdir/incomplete-cycle-resume-evidence"
mkdir -p \
    "$incomplete_cycle_results/scenarios/cycle-0001/first/attempts/attempt-0001" \
    "$incomplete_cycle_results/scenarios/cycle-0002/first/attempts/attempt-0001"
touch \
    "$incomplete_cycle_results/scenarios/cycle-0001/first/attempts/attempt-0001/scenario.log" \
    "$incomplete_cycle_results/scenarios/cycle-0002/first/attempts/attempt-0001/scenario.log"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'1\tfirst\t1\tpassed\t0\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/first/attempts/attempt-0001\tscenarios/cycle-0001/first/attempts/attempt-0001/scenario.log' \
    $'2\tfirst\t1\tpassed\t0\t2026-07-13T12:00:02Z\t2026-07-13T12:00:03Z\tscenarios/cycle-0002/first/attempts/attempt-0001\tscenarios/cycle-0002/first/attempts/attempt-0001/scenario.log' \
    >"$incomplete_cycle_results/scenario-results.tsv"
if (
    evidence_dir="$incomplete_cycle_results"
    resume=1
    prepare_scenario_results "first second"
); then
    printf 'resume accepted a later cycle after an incomplete cycle\n' >&2
    exit 1
fi

finalize_failure_evidence="$workdir/finalize-failure-evidence"
mkdir -p "$finalize_failure_evidence/scenarios" "$workdir/finalize-build"
printf '%s\n' $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$finalize_failure_evidence/scenario-results.tsv"
if (
    campaign_rebind_test_subshell_lock
    evidence_dir="$finalize_failure_evidence"
    cargo_target_dir="$workdir/finalize-build"
    scenario_list_for_validation=sentinel
    sampler_pid=""
    # This subshell deliberately shadows the sourced runner's global deadline.
    # shellcheck disable=SC2030
    campaign_deadline_epoch="$(date +%s)"
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    campaign_sha256() { return 1; }
    trap finalize_soak_evidence EXIT
); then
    printf 'soak finalizer accepted a failed artifact hash\n' >&2
    exit 1
fi
[[ ! -e "$finalize_failure_evidence/campaign-completed.env" ]]

marker_failure_evidence="$workdir/marker-failure-evidence"
mkdir "$marker_failure_evidence"
touch "$marker_failure_evidence/soak-summary.env" "$marker_failure_evidence/artifact-manifest.sha256"
if (
    campaign_rebind_test_subshell_lock
    evidence_dir="$marker_failure_evidence"
    campaign_deadline_epoch="$(date +%s)"
    campaign_sha256() {
        [[ "$1" != */artifact-manifest.sha256 ]] || return 1
        sha256sum "$1" | awk '{ print $1 }'
    }
    mark_campaign_completed
); then
    printf 'soak completion marker accepted a failed terminal digest\n' >&2
    exit 1
fi
[[ ! -e "$marker_failure_evidence/campaign-completed.env" ]]

finalize_success_evidence="$workdir/finalize-success-evidence"
mkdir -p "$finalize_success_evidence/scenarios" "$workdir/finalize-success-build"
printf '%s\n' $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$finalize_success_evidence/scenario-results.tsv"
if (
    campaign_rebind_test_subshell_lock
    evidence_dir="$finalize_success_evidence"
    cargo_target_dir="$workdir/finalize-success-build"
    scenario_list_for_validation=sentinel
    sampler_pid=""
    # This subshell deliberately shadows the sourced runner's global deadline.
    # shellcheck disable=SC2030
    campaign_deadline_epoch="$(date +%s)"
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    trap finalize_soak_evidence EXIT
); then
    printf 'soak finalizer published terminal success without a complete scenario cycle\n' >&2
    exit 1
fi
[[ ! -e "$finalize_success_evidence/campaign-completed.env" ]]
mkdir -p "$finalize_success_evidence/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
printf 'passed scenario\n' >"$finalize_success_evidence/scenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log"
finalize_success_end_epoch="$(date +%s)"
finalize_success_start_utc="$(date -u -d "@$((finalize_success_end_epoch - 1))" '+%Y-%m-%dT%H:%M:%SZ')"
finalize_success_end_utc="$(date -u -d "@$finalize_success_end_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
printf '%s\n' \
    "$(printf '1\tsentinel\t1\tpassed\t0\t%s\t%s\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
        "$finalize_success_start_utc" "$finalize_success_end_utc")" \
    >>"$finalize_success_evidence/scenario-results.tsv"
finalize_signal_marker="$workdir/finalize-success-signals-ignored"
(
    campaign_rebind_test_subshell_lock
    evidence_dir="$finalize_success_evidence"
    # shellcheck disable=SC2030
    cargo_target_dir="$workdir/finalize-success-build"
    scenario_list_for_validation=sentinel
    sampler_pid=""
    campaign_deadline_epoch="$(date +%s)"
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    # Once terminal evidence publication starts, repeated termination signals
    # must not interrupt or re-enter the EXIT finalizer.
    # shellcheck disable=SC2329
    large_soak_finalize_started_hook() {
        local signal_attempt
        for ((signal_attempt = 0; signal_attempt < 20; signal_attempt++)); do
            kill -TERM "$BASHPID"
        done
        : >"$finalize_signal_marker"
    }
    trap finalize_soak_evidence EXIT
)
[[ -f "$finalize_signal_marker" ]]
[[ "$(wc -l <"$finalize_success_evidence/campaign-completed.env")" == 7 ]]
grep -Fqx status=passed "$finalize_success_evidence/campaign-completed.env"
grep -Fqx evidence_schema=2 "$finalize_success_evidence/campaign-completed.env"
grep -Fqx "summary_sha256=$(sha256sum "$finalize_success_evidence/soak-summary.env" | awk '{ print $1 }')" \
    "$finalize_success_evidence/campaign-completed.env"
grep -Fqx "artifact_manifest_sha256=$(sha256sum "$finalize_success_evidence/artifact-manifest.sha256" | awk '{ print $1 }')" \
    "$finalize_success_evidence/campaign-completed.env"

# Automatic build-root cleanup is part of terminal success. A pathname
# replacement must make cleanup fail and no authoritative marker may predate
# that failure.
finalize_cleanup_failure_evidence="$workdir/finalize-cleanup-failure-evidence"
cp -a "$finalize_success_evidence" "$finalize_cleanup_failure_evidence"
rm -f "$finalize_cleanup_failure_evidence/campaign-completed.env"
finalize_cleanup_path_file="$workdir/finalize-cleanup-path"
if (
    campaign_rebind_test_subshell_lock
    evidence_dir="$finalize_cleanup_failure_evidence"
    scenario_list_for_validation=sentinel
    sampler_pid=""
    campaign_deadline_epoch="$(date +%s)"
    campaign_prepare_private_temporary_tree "$temporary_tree_base" round50-large-finalize \
        large_soak_auto_build cargo_target_dir
    cargo_target_dir_auto=1
    # cargo_target_dir is intentionally rebound by the creator inside this
    # independent finalizer subshell.
    # shellcheck disable=SC2031
    finalize_cleanup_build="$cargo_target_dir"
    printf '%s\n' "$finalize_cleanup_build" >"$finalize_cleanup_path_file"
    mv "$finalize_cleanup_build" "$finalize_cleanup_build.original"
    mkdir -m 0700 "$finalize_cleanup_build"
    printf 'replacement must survive\n' >"$finalize_cleanup_build/sentinel"
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    trap finalize_soak_evidence EXIT
); then
    printf 'soak finalizer published success before automatic build cleanup\n' >&2
    exit 1
fi
finalize_cleanup_path="$(<"$finalize_cleanup_path_file")"
[[ ! -e "$finalize_cleanup_failure_evidence/campaign-completed.env" ]]
grep -Fqx 'replacement must survive' "$finalize_cleanup_path/sentinel"
[[ -d "$finalize_cleanup_path.original" ]]

# Absence of the original pathname is also ambiguous: the captured inode may
# merely have been renamed. It must leave completion unpublished.
finalize_missing_cleanup_evidence="$workdir/finalize-missing-cleanup-evidence"
cp -a "$finalize_success_evidence" "$finalize_missing_cleanup_evidence"
rm -f "$finalize_missing_cleanup_evidence/campaign-completed.env"
finalize_missing_path_file="$workdir/finalize-missing-cleanup-path"
if (
    campaign_rebind_test_subshell_lock
    evidence_dir="$finalize_missing_cleanup_evidence"
    scenario_list_for_validation=sentinel
    sampler_pid=""
    campaign_deadline_epoch="$(date +%s)"
    finalize_missing_build=""
    campaign_prepare_private_temporary_tree "$temporary_tree_base" round51-large-finalize-missing \
        large_soak_auto_build finalize_missing_build
    cargo_target_dir_auto=1
    cargo_target_dir="$finalize_missing_build"
    printf '%s\n' "$finalize_missing_build" >"$finalize_missing_path_file"
    printf 'renamed automatic build must survive\n' >"$finalize_missing_build/sentinel"
    mv "$finalize_missing_build" "$finalize_missing_build.renamed"
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    trap finalize_soak_evidence EXIT
); then
    printf 'soak finalizer accepted a renamed-away automatic build root\n' >&2
    exit 1
fi
finalize_missing_path="$(<"$finalize_missing_path_file")"
[[ ! -e "$finalize_missing_cleanup_evidence/campaign-completed.env" ]]
grep -Fqx 'renamed automatic build must survive' "$finalize_missing_path.renamed/sentinel"

stopped_runner_evidence="$workdir/stopped-runner-inactivity-evidence"
stopped_runner_attempt="$stopped_runner_evidence/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
stopped_runner_ready="$workdir/stopped-runner.ready"
stopped_runner_start_epoch="$(date +%s)"
stopped_runner_deadline=$((stopped_runner_start_epoch + 7))
stopped_runner_start_utc="$(date -u -d "@$stopped_runner_start_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p "$stopped_runner_attempt" "$workdir/stopped-runner-build"
printf 'passed before suspension\n' >"$stopped_runner_attempt/scenario.log"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    "$(printf '1\tsentinel\t1\tpassed\t0\t%s\t%s\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
        "$stopped_runner_start_utc" "$stopped_runner_start_utc")" \
    >"$stopped_runner_evidence/scenario-results.tsv"
(
    campaign_rebind_test_subshell_lock
    evidence_dir="$stopped_runner_evidence"
    cargo_target_dir="$workdir/stopped-runner-build"
    scenario_list_for_validation=sentinel
    scenario_timeout=1
    scenario_kill_after=1
    cycle_sleep=1
    sampler_pid=""
    campaign_deadline_epoch="$stopped_runner_deadline"
    # finalize_soak_evidence invokes these callback names indirectly from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() {
        return 0
    }
    # shellcheck disable=SC2329
    verify_expected_clean_head() {
        return 0
    }
    # shellcheck disable=SC2329
    verify_expected_tool_hashes() {
        return 0
    }
    trap finalize_soak_evidence EXIT
    : >"$stopped_runner_ready"
    kill -STOP "$BASHPID"
) &
stopped_runner_pid=$!
stopped_runner_wait_deadline=$((SECONDS + 5))
until [[ -e "$stopped_runner_ready" ]]; do
    kill -0 "$stopped_runner_pid" 2>/dev/null
    ((SECONDS < stopped_runner_wait_deadline))
    sleep 0.01
done
while (($(date +%s) <= stopped_runner_deadline)); do
    sleep 0.1
done
kill -CONT "$stopped_runner_pid"
if wait "$stopped_runner_pid"; then
    printf 'soak finalizer accepted a runner suspended through its terminal activity window\n' >&2
    exit 1
fi
[[ ! -e "$stopped_runner_evidence/campaign-completed.env" ]]

header_only_validation="$workdir/header-only-validation"
cp -a "$finalize_success_evidence" "$header_only_validation"
printf '%s\n' \
    "expected_commit=$(git -C "$repo_root" rev-parse HEAD)" \
    duration_seconds=1 \
    start_epoch_seconds=1 \
    deadline_epoch_seconds=2 \
    "cargo_sha256=$test_cargo_sha256" \
    "rustc_sha256=$test_rustc_sha256" \
    scenarios=sentinel \
    >"$header_only_validation/soak.env"
printf '%s\n' $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    >"$header_only_validation/scenario-results.tsv"
rm "$header_only_validation/artifact-manifest.sha256" "$header_only_validation/campaign-completed.env"
(
    cd "$header_only_validation"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$header_only_validation/artifact-manifest.sha256"
printf '%s\n' \
    completed_utc=1970-01-01T00:00:02Z \
    completed_epoch_seconds=2 \
    deadline_epoch_seconds=2 \
    "summary_sha256=$(sha256sum "$header_only_validation/soak-summary.env" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$header_only_validation/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$header_only_validation/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$header_only_validation" "$(git -C "$repo_root" rev-parse HEAD)" \
    --expected-duration 1 --expected-scenario sentinel "${soak_validator_policy[@]}"; then
    printf 'soak validator accepted header-only terminal evidence\n' >&2
    exit 1
fi

retained_failure_evidence="$workdir/retained-failure-evidence"
retained_failure_build="$workdir/retained-failure-build"
mkdir -p "$retained_failure_evidence/scenarios/cycle-0001/sentinel/attempts/attempt-0001" "$retained_failure_build"
printf 'failed scenario\n' >"$retained_failure_evidence/scenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log"
retained_failure_commit="$(git -C "$repo_root" rev-parse HEAD)"
printf '%s\n' \
    "expected_commit=$retained_failure_commit" \
    duration_seconds=1 \
    start_epoch_seconds=1 \
    deadline_epoch_seconds=2 \
    "cargo_sha256=$test_cargo_sha256" \
    "rustc_sha256=$test_rustc_sha256" \
    'scenarios=sentinel' \
    >"$retained_failure_evidence/soak.env"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'1\tsentinel\t1\tfailed\t1\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
    >"$retained_failure_evidence/scenario-results.tsv"
if (
    campaign_rebind_test_subshell_lock
    evidence_dir="$retained_failure_evidence"
    cargo_target_dir="$retained_failure_build"
    scenario_list_for_validation=sentinel
    sampler_pid=""
    # This subshell deliberately shadows the sourced runner's global deadline.
    # shellcheck disable=SC2030
    campaign_deadline_epoch="$(date +%s)"
    # Invoked indirectly by finalize_soak_evidence from the EXIT trap.
    # shellcheck disable=SC2329
    validate_resource_sampler_evidence() { return 0; }
    trap finalize_soak_evidence EXIT
); then
    printf 'soak finalizer published terminal success over a retained failed scenario\n' >&2
    exit 1
fi
[[ ! -e "$retained_failure_evidence/campaign-completed.env" ]]
grep -Fqx 'failed_count=1' "$retained_failure_evidence/soak-summary.env"
printf '%s\n' \
    completed_utc=1970-01-01T00:00:02Z \
    completed_epoch_seconds=2 \
    deadline_epoch_seconds=2 \
    "summary_sha256=$(sha256sum "$retained_failure_evidence/soak-summary.env" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$retained_failure_evidence/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$retained_failure_evidence/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$retained_failure_evidence" "$retained_failure_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak validator classified forged terminal completion with retained failures as complete\n' >&2
    exit 1
fi

soak_policy_fixture="$workdir/soak-policy-fixture"
soak_policy_commit="$(git -C "$repo_root" rev-parse HEAD)"
soak_policy_start=1783944000
soak_policy_deadline=$((soak_policy_start + 1))
soak_policy_deadline_utc="$(date -u -d "@$soak_policy_deadline" '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p "$soak_policy_fixture/scenarios/cycle-0001/sentinel/attempts/attempt-0001"
printf 'scenario self-skip\n' >"$soak_policy_fixture/scenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log"
printf '%s\n' cycle=1 scenario=sentinel attempt=1 started_utc=2026-07-13T12:00:00Z \
    >"$soak_policy_fixture/scenarios/cycle-0001/sentinel/attempts/attempt-0001/attempt-started.env"
printf '%s\n' \
    evidence_schema=1 \
    "expected_commit=$soak_policy_commit" \
    duration_seconds=1 \
    "start_epoch_seconds=$soak_policy_start" \
    "deadline_epoch_seconds=$soak_policy_deadline" \
    scenario_timeout_seconds=1 \
    scenario_kill_after_seconds=1 \
    docker_cleanup_timeout_seconds=1 \
    cycle_sleep_seconds=1 \
    sample_interval_seconds=1 \
    allow_skip=1 \
    "cargo_sha256=$test_cargo_sha256" \
    "rustc_sha256=$test_rustc_sha256" \
    scenarios=sentinel \
    >"$soak_policy_fixture/soak.env"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    $'1\tsentinel\t1\tskipped\t0\t2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
    >"$soak_policy_fixture/scenario-results.tsv"
printf '%s\n' scenario_runs_total=1 status_skipped=1 failed_count=0 \
    >"$soak_policy_fixture/soak-summary.env"
make_soak_sampler_fixture "$soak_policy_fixture" "$soak_policy_start" "$soak_policy_deadline" 1
(
    cd "$soak_policy_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_policy_fixture/artifact-manifest.sha256"
printf '%s\n' \
    evidence_schema=1 \
    "completed_utc=$soak_policy_deadline_utc" \
    "completed_epoch_seconds=$soak_policy_deadline" \
    "deadline_epoch_seconds=$soak_policy_deadline" \
    "summary_sha256=$(sha256sum "$soak_policy_fixture/soak-summary.env" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$soak_policy_fixture/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$soak_policy_fixture/campaign-completed.env"
python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_policy_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}" >/dev/null

refresh_soak_fixture_manifest() {
    local fixture="$1"
    (
        cd "$fixture"
        find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
            LC_ALL=C sort -z | xargs -0 sha256sum
    ) >"$fixture/artifact-manifest.sha256"
    sed -i \
        "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
        "$fixture/campaign-completed.env"
}

for soak_process_mutation in orphan duplicate count rss; do
    soak_process_fixture="$workdir/soak-process-$soak_process_mutation-fixture"
    cp -a "$soak_policy_fixture" "$soak_process_fixture"
    soak_process_hosts="$soak_process_fixture/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
    soak_process_details="$soak_process_fixture/resource-sampler-attempts/attempt-0001/process-samples.tsv"
    case "$soak_process_mutation" in
    orphan)
        printf '%s\n' $'2026-07-13T12:00:00Z\t1783944001\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$soak_process_details"
        ;;
    duplicate)
        awk -F '\t' -v OFS='\t' 'NR == 2 { $8 = 2; $9 = 4 } { print }' \
            "$soak_process_hosts" >"$soak_process_fixture/process-hosts.new"
        mv "$soak_process_fixture/process-hosts.new" "$soak_process_hosts"
        printf '%s\n' \
            $'2026-07-13T12:00:00Z\t1783944000\t123\t0.1\t0.1\t2\t00:01\tborondns' \
            $'2026-07-13T12:00:00Z\t1783944000\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$soak_process_details"
        ;;
    count)
        printf '%s\n' $'2026-07-13T12:00:00Z\t1783944000\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$soak_process_details"
        ;;
    rss)
        awk -F '\t' -v OFS='\t' 'NR == 2 { $8 = 1; $9 = 3 } { print }' \
            "$soak_process_hosts" >"$soak_process_fixture/process-hosts.new"
        mv "$soak_process_fixture/process-hosts.new" "$soak_process_hosts"
        printf '%s\n' $'2026-07-13T12:00:00Z\t1783944000\t123\t0.1\t0.1\t2\t00:01\tborondns' >> \
            "$soak_process_details"
        ;;
    esac
    refresh_soak_fixture_manifest "$soak_process_fixture"
    if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
        "$soak_process_fixture" "$soak_policy_commit" --expected-duration 1 \
        --expected-scenario sentinel "${soak_validator_policy[@]}"; then
        printf 'soak collection validator accepted %s process-detail mutation\n' \
            "$soak_process_mutation" >&2
        exit 1
    fi
done

soak_same_pid_fixture="$workdir/soak-process-same-pid-next-epoch-fixture"
cp -a "$soak_policy_fixture" "$soak_same_pid_fixture"
soak_same_pid_hosts="$soak_same_pid_fixture/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
soak_same_pid_details="$soak_same_pid_fixture/resource-sampler-attempts/attempt-0001/process-samples.tsv"
awk -F '\t' -v OFS='\t' 'NR > 1 { $8 = 1; $9 = 2 } { print }' \
    "$soak_same_pid_hosts" >"$soak_same_pid_fixture/process-hosts.new"
mv "$soak_same_pid_fixture/process-hosts.new" "$soak_same_pid_hosts"
printf '%s\n' \
    $'2026-07-13T12:00:00Z\t1783944000\t123\t0.1\t0.1\t2\t00:01\tborondns' \
    $'2026-07-13T12:00:01Z\t1783944001\t123\t0.2\t0.1\t2\t00:02\tborondns' >> \
    "$soak_same_pid_details"
refresh_soak_fixture_manifest "$soak_same_pid_fixture"
python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_same_pid_fixture" "$soak_policy_commit" --expected-duration 1 \
    --expected-scenario sentinel "${soak_validator_policy[@]}" >/dev/null
unset -f refresh_soak_fixture_manifest

# Schema absence is not proof of legacy provenance. Even the historical
# statusless shape must carry an explicit schema-1 migration label.
soak_unversioned_fixture="$workdir/soak-unversioned-fixture"
cp -a "$soak_policy_fixture" "$soak_unversioned_fixture"
sed -i '/^evidence_schema=/d' "$soak_unversioned_fixture/soak.env" \
    "$soak_unversioned_fixture/campaign-completed.env"
(
    cd "$soak_unversioned_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_unversioned_fixture/artifact-manifest.sha256"
sed -i "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_unversioned_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_unversioned_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_unversioned_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}" >/dev/null 2>&1; then
    printf 'soak validator treated an unversioned statusless marker as authenticated legacy evidence\n' >&2
    exit 1
fi

# Schema-v2 evidence must carry an explicit passed status.
soak_schema_fixture="$workdir/soak-schema-fixture"
cp -a "$soak_policy_fixture" "$soak_schema_fixture"
sed -i 's/^evidence_schema=1$/evidence_schema=2/' "$soak_schema_fixture/soak.env"
(
    cd "$soak_schema_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_schema_fixture/artifact-manifest.sha256"
printf '%s\n' \
    status=passed evidence_schema=2 \
    "completed_utc=$soak_policy_deadline_utc" \
    "completed_epoch_seconds=$soak_policy_deadline" \
    "deadline_epoch_seconds=$soak_policy_deadline" \
    "summary_sha256=$(sha256sum "$soak_schema_fixture/soak-summary.env" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$soak_schema_fixture/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$soak_schema_fixture/campaign-completed.env"
python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_schema_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}" >/dev/null
sed -i '/^status=/d' "$soak_schema_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_schema_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}" >/dev/null 2>&1; then
    printf 'schema-v2 soak validator accepted a statusless completion marker\n' >&2
    exit 1
fi

soak_long_attempt_fixture="$workdir/soak-long-attempt-fixture"
soak_long_attempt_deadline=$((soak_policy_start + 100))
soak_long_attempt_deadline_utc="$(date -u -d "@$soak_long_attempt_deadline" '+%Y-%m-%dT%H:%M:%SZ')"
cp -a "$soak_policy_fixture" "$soak_long_attempt_fixture"
sed -i \
    -e 's/^duration_seconds=1$/duration_seconds=100/' \
    -e "s/^deadline_epoch_seconds=.*/deadline_epoch_seconds=$soak_long_attempt_deadline/" \
    -e 's/^sample_interval_seconds=1$/sample_interval_seconds=100/' \
    "$soak_long_attempt_fixture/soak.env"
printf '%s\n' \
    $'cycle\tscenario\tattempt\tstatus\texit_status\tstarted_utc\tended_utc\tscenario_artifact_dir\tlog_path' \
    "$(printf '1\tsentinel\t1\tskipped\t0\t2026-07-13T12:00:00Z\t%s\tscenarios/cycle-0001/sentinel/attempts/attempt-0001\tscenarios/cycle-0001/sentinel/attempts/attempt-0001/scenario.log' \
        "$soak_long_attempt_deadline_utc")" \
    >"$soak_long_attempt_fixture/scenario-results.tsv"
rm -rf "$soak_long_attempt_fixture/resource-sampler-attempts"
make_soak_sampler_fixture "$soak_long_attempt_fixture" "$soak_policy_start" "$soak_long_attempt_deadline" 100
(
    cd "$soak_long_attempt_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_long_attempt_fixture/artifact-manifest.sha256"
printf '%s\n' \
    "completed_utc=$soak_long_attempt_deadline_utc" \
    "completed_epoch_seconds=$soak_long_attempt_deadline" \
    "deadline_epoch_seconds=$soak_long_attempt_deadline" \
    "summary_sha256=$(sha256sum "$soak_long_attempt_fixture/soak-summary.env" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$soak_long_attempt_fixture/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$soak_long_attempt_fixture/campaign-completed.env"
if (
    evidence_dir="$soak_long_attempt_fixture"
    scenario_timeout=1
    scenario_kill_after=1
    docker_cleanup_timeout=1
    validate_scenario_results sentinel
); then
    printf 'local soak validator accepted an attempt beyond its derived runtime bound\n' >&2
    exit 1
fi
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_long_attempt_fixture" "$soak_policy_commit" --expected-duration 100 --expected-scenario sentinel \
    --expected-scenario-timeout 1 --expected-scenario-kill-after 1 \
    --expected-docker-cleanup-timeout 1 --expected-cycle-sleep 1 \
    --expected-sample-interval 100 --expected-allow-skip 1 \
    --expected-cargo-sha256 "$test_cargo_sha256" --expected-rustc-sha256 "$test_rustc_sha256"; then
    printf 'collected soak validator accepted an attempt beyond its derived runtime bound\n' >&2
    exit 1
fi

soak_inactive_fixture="$workdir/soak-terminal-inactivity-fixture"
soak_inactive_deadline=$((soak_policy_start + 20))
soak_inactive_deadline_utc="$(date -u -d "@$soak_inactive_deadline" '+%Y-%m-%dT%H:%M:%SZ')"
cp -a "$soak_policy_fixture" "$soak_inactive_fixture"
sed -i \
    -e 's/^duration_seconds=1$/duration_seconds=20/' \
    -e "s/^deadline_epoch_seconds=.*/deadline_epoch_seconds=$soak_inactive_deadline/" \
    -e 's/^sample_interval_seconds=1$/sample_interval_seconds=20/' \
    "$soak_inactive_fixture/soak.env"
rm -rf "$soak_inactive_fixture/resource-sampler-attempts"
make_soak_sampler_fixture "$soak_inactive_fixture" "$soak_policy_start" "$soak_inactive_deadline" 20
(
    cd "$soak_inactive_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_inactive_fixture/artifact-manifest.sha256"
printf '%s\n' \
    "completed_utc=$soak_inactive_deadline_utc" \
    "completed_epoch_seconds=$soak_inactive_deadline" \
    "deadline_epoch_seconds=$soak_inactive_deadline" \
    "summary_sha256=$(sha256sum "$soak_inactive_fixture/soak-summary.env" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$soak_inactive_fixture/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$soak_inactive_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_inactive_fixture" "$soak_policy_commit" --expected-duration 20 --expected-scenario sentinel \
    --expected-scenario-timeout 1 --expected-scenario-kill-after 1 \
    --expected-docker-cleanup-timeout 1 --expected-cycle-sleep 1 \
    --expected-sample-interval 20 --expected-allow-skip 1 \
    --expected-cargo-sha256 "$test_cargo_sha256" --expected-rustc-sha256 "$test_rustc_sha256"; then
    printf 'soak collector accepted terminal evidence with most of the campaign scenario-inactive\n' >&2
    exit 1
fi
soak_before_start_fixture="$workdir/soak-before-start-fixture"
cp -a "$soak_policy_fixture" "$soak_before_start_fixture"
sed -i \
    '2s/2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z/2026-07-13T11:59:59Z\t2026-07-13T12:00:00Z/' \
    "$soak_before_start_fixture/scenario-results.tsv"
sed -i 's/^started_utc=2026-07-13T12:00:00Z$/started_utc=2026-07-13T11:59:59Z/' \
    "$soak_before_start_fixture/scenarios/cycle-0001/sentinel/attempts/attempt-0001/attempt-started.env"
(
    cd "$soak_before_start_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_before_start_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_before_start_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_before_start_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_before_start_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak validator accepted a scenario cycle before the campaign start\n' >&2
    exit 1
fi
soak_after_deadline_fixture="$workdir/soak-after-deadline-fixture"
cp -a "$soak_policy_fixture" "$soak_after_deadline_fixture"
sed -i \
    '2s/2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z/2026-07-13T12:00:01Z\t2026-07-13T12:00:02Z/' \
    "$soak_after_deadline_fixture/scenario-results.tsv"
sed -i 's/^started_utc=2026-07-13T12:00:00Z$/started_utc=2026-07-13T12:00:01Z/' \
    "$soak_after_deadline_fixture/scenarios/cycle-0001/sentinel/attempts/attempt-0001/attempt-started.env"
(
    cd "$soak_after_deadline_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_after_deadline_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_after_deadline_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_after_deadline_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_after_deadline_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak validator accepted a scenario starting at or after the campaign deadline\n' >&2
    exit 1
fi
soak_timestamp_fixture="$workdir/soak-timestamp-fixture"
cp -a "$soak_policy_fixture" "$soak_timestamp_fixture"
sed -i '2s/^2026-07-13T12:00:00Z/2026-07-13T12:00:02Z/' \
    "$soak_timestamp_fixture/resource-sampler-attempts/attempt-0001/resource-samples.tsv"
(
    cd "$soak_timestamp_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_timestamp_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_timestamp_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_timestamp_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_timestamp_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak collection validator accepted a sampler UTC timestamp inconsistent with its epoch\n' >&2
    exit 1
fi
soak_scenario_reversal_fixture="$workdir/soak-scenario-reversal-fixture"
cp -a "$soak_policy_fixture" "$soak_scenario_reversal_fixture"
sed -i \
    '2s/2026-07-13T12:00:00Z\t2026-07-13T12:00:01Z/2026-07-13T12:00:01Z\t2026-07-13T12:00:00Z/' \
    "$soak_scenario_reversal_fixture/scenario-results.tsv"
(
    cd "$soak_scenario_reversal_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_scenario_reversal_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_scenario_reversal_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_scenario_reversal_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_scenario_reversal_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak collection validator accepted a scenario ending before it started\n' >&2
    exit 1
fi
soak_sampler_reversal_fixture="$workdir/soak-sampler-reversal-fixture"
cp -a "$soak_policy_fixture" "$soak_sampler_reversal_fixture"
cp -a "$soak_sampler_reversal_fixture/resource-sampler-attempts/attempt-0001" \
    "$soak_sampler_reversal_fixture/resource-sampler-attempts/attempt-0002"
rm "$soak_sampler_reversal_fixture/resource-sampler-attempts/attempt-0001/resource-sampler-completed.env"
printf '%s\n' status=failed "failed_utc=$soak_policy_deadline_utc" \
    "failed_epoch_seconds=$soak_policy_deadline" exit_status=1 \
    >"$soak_sampler_reversal_fixture/resource-sampler-attempts/attempt-0001/resource-sampler-failed.env"
(
    cd "$soak_sampler_reversal_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_sampler_reversal_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_sampler_reversal_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_sampler_reversal_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_sampler_reversal_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak collection validator accepted a sampler retry before the prior terminal boundary\n' >&2
    exit 1
fi
unledgered_soak_fixture="$workdir/unledgered-soak-fixture"
cp -a "$soak_policy_fixture" "$unledgered_soak_fixture"
unledgered_attempt="$unledgered_soak_fixture/scenarios/cycle-0002/sentinel/attempts/attempt-0001"
mkdir -p "$unledgered_attempt"
printf '%s\n' cycle=2 scenario=sentinel attempt=1 started_utc=2026-07-13T12:00:02Z \
    >"$unledgered_attempt/attempt-started.env"
printf 'unledgered attempt\n' >"$unledgered_attempt/scenario.log"
(
    cd "$unledgered_soak_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$unledgered_soak_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$unledgered_soak_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$unledgered_soak_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$unledgered_soak_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    "${soak_validator_policy[@]}"; then
    printf 'soak validator accepted an authenticated but unledgered attempt directory\n' >&2
    exit 1
fi
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_policy_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    --expected-scenario-timeout 2 --expected-scenario-kill-after 1 --expected-cycle-sleep 1 \
    --expected-docker-cleanup-timeout 1 \
    --expected-sample-interval 1 --expected-allow-skip 1; then
    printf 'soak validator accepted evidence from a different timeout policy\n' >&2
    exit 1
fi
sed -i 's/^allow_skip=1$/allow_skip=0/' "$soak_policy_fixture/soak.env"
(
    cd "$soak_policy_fixture"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$soak_policy_fixture/artifact-manifest.sha256"
sed -i \
    "s/^artifact_manifest_sha256=.*/artifact_manifest_sha256=$(sha256sum "$soak_policy_fixture/artifact-manifest.sha256" | awk '{ print $1 }')/" \
    "$soak_policy_fixture/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" soak-host \
    "$soak_policy_fixture" "$soak_policy_commit" --expected-duration 1 --expected-scenario sentinel \
    --expected-scenario-timeout 1 --expected-scenario-kill-after 1 --expected-cycle-sleep 1 \
    --expected-docker-cleanup-timeout 1 \
    --expected-sample-interval 1 --expected-allow-skip 0; then
    printf 'soak validator accepted a skipped row for fail-on-skip evidence\n' >&2
    exit 1
fi

missing_evidence="$workdir/missing-resume"
if (
    evidence_dir="$missing_evidence"
    # Consumed dynamically by prepare_scenario_results from the sourced runner.
    # shellcheck disable=SC2034
    resume=1
    prepare_scenario_results sentinel
); then
    printf 'resume accepted missing scenario evidence\n' >&2
    exit 1
fi

deadline_evidence="$workdir/deadline-resume"
mkdir -p "$deadline_evidence"
deadline_start="$(date +%s)"
deadline_end=$((deadline_start + 60))
printf '%s\n' \
    "created_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "duration_seconds=60" \
    "start_epoch_seconds=$deadline_start" \
    "deadline_epoch_seconds=$deadline_end" \
    >"$deadline_evidence/soak.env"
evidence_dir="$deadline_evidence"
duration=60
resume=1
prepare_campaign_deadline
# The earlier shadow is confined to its subshell; this is the resumed start.
# shellcheck disable=SC2031
[[ "$campaign_start_epoch" == "$deadline_start" ]]
# The earlier shadow is confined to its subshell; this is the resumed deadline.
# shellcheck disable=SC2031
[[ "$campaign_deadline_epoch" == "$deadline_end" ]]

# Same-boot resume is bound only to the authenticated CLOCK_BOOTTIME deadline;
# a realtime rollback cannot replenish it. Cross-boot release resume fails
# closed, while the explicit diagnostic mode starts a fresh full-duration
# non-release window and credits none of the earlier active time.
boot_deadline_evidence="$workdir/boot-deadline-resume"
mkdir -p "$boot_deadline_evidence"
printf '%s\n' \
    created_utc=1970-01-01T00:33:20Z \
    duration_seconds=60 \
    start_epoch_seconds=2000 \
    deadline_epoch_seconds=2060 \
    boot_id=11111111-1111-1111-1111-111111111111 \
    control_deadline_boottime_nanoseconds=5000000000 \
    cross_boot_diagnostic=0 \
    >"$boot_deadline_evidence/soak.env"
(
    evidence_dir="$boot_deadline_evidence"
    duration=60
    resume=1
    date() {
        if [[ "$*" == +%s ]]; then
            printf '%s\n' 1000
        else
            /usr/bin/date "$@"
        fi
    }
    current_boot_id() { printf '%s\n' 11111111-1111-1111-1111-111111111111; }
    monotonic_nanoseconds() { printf '%s\n' 1000000000; }
    campaign_start_epoch=2000
    campaign_deadline_epoch=2060
    initialize_campaign_control_deadline
    # Populated dynamically by initialize_campaign_control_deadline above.
    # shellcheck disable=SC2031
    [[ "$campaign_control_deadline_nanoseconds" == 5000000000 ]]
)
if (
    evidence_dir="$boot_deadline_evidence"
    duration=60
    resume=1
    resume_cross_boot_diagnostic=0
    current_boot_id() { printf '%s\n' 22222222-2222-2222-2222-222222222222; }
    monotonic_nanoseconds() { printf '%s\n' 1000000000; }
    campaign_start_epoch=2000
    campaign_deadline_epoch=2060
    initialize_campaign_control_deadline
) >/dev/null 2>&1; then
    printf 'release-evidence resume accepted a cross-boot CLOCK_BOOTTIME deadline\n' >&2
    exit 1
fi
(
    evidence_dir="$boot_deadline_evidence"
    duration=60
    resume=1
    resume_cross_boot_diagnostic=1
    date() {
        if [[ "$*" == +%s ]]; then
            printf '%s\n' 3000
        else
            /usr/bin/date "$@"
        fi
    }
    current_boot_id() { printf '%s\n' 22222222-2222-2222-2222-222222222222; }
    monotonic_nanoseconds() { printf '%s\n' 1000000000; }
    campaign_start_epoch=2000
    campaign_deadline_epoch=2060
    initialize_campaign_control_deadline
    [[ "$cross_boot_diagnostic_active" == 1 ]]
    [[ "$campaign_start_epoch" == 3000 && "$campaign_deadline_epoch" == 3060 ]]
    # Populated dynamically by initialize_campaign_control_deadline above.
    # shellcheck disable=SC2031
    [[ "$campaign_control_deadline_nanoseconds" == 61000000000 ]]
)

expired_evidence="$workdir/expired-resume"
mkdir -p "$expired_evidence"
expired_start=$(($(date +%s) - 120))
expired_end=$((expired_start + 60))
printf '%s\n' \
    "created_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "duration_seconds=60" \
    "start_epoch_seconds=$expired_start" \
    "deadline_epoch_seconds=$expired_end" \
    >"$expired_evidence/soak.env"
if (
    evidence_dir="$expired_evidence"
    duration=60
    resume=1
    prepare_campaign_deadline
    enforce_campaign_deadline
); then
    printf 'resume accepted an expired campaign deadline\n' >&2
    exit 1
fi

touch "$deadline_evidence/campaign-completed.env"
if (
    evidence_dir="$deadline_evidence"
    duration=60
    resume=1
    prepare_campaign_deadline
); then
    printf 'resume accepted a completed campaign\n' >&2
    exit 1
fi

timeout_fixture="$workdir/ignore-term.sh"
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'trap "" TERM' \
    'sleep 300 &' \
    'child=$!' \
    'printf "%s %s\n" "$$" "$child" >"$TEST_ARTIFACT/pids"' \
    'wait "$child"' \
    >"$timeout_fixture"
chmod +x "$timeout_fixture"
mkdir -p "$workdir/timeout-artifact"
deadline_now_nanoseconds="$(monotonic_nanoseconds)"
deadline_nanoseconds=$((deadline_now_nanoseconds + 4000000000))
deadline_timeout_without_kill="$(scenario_timeout_within_campaign 300 "$deadline_nanoseconds" "$deadline_now_nanoseconds" 500000000 0)"
deadline_timeout="$(scenario_timeout_within_campaign 300 "$deadline_nanoseconds" "$deadline_now_nanoseconds" 500000000 1)"
python3 - "$deadline_timeout_without_kill" "$deadline_timeout" <<'PY'
import decimal
import sys

without_kill, with_kill = map(decimal.Decimal, sys.argv[1:])
if without_kill - with_kill != decimal.Decimal("1"):
    raise SystemExit("scenario timeout did not reserve the full kill-after grace")
PY
if scenario_timeout_within_campaign 300 "$deadline_now_nanoseconds" "$deadline_now_nanoseconds" 0 >/dev/null; then
    printf 'campaign timeout helper accepted an exhausted deadline\n' >&2
    exit 1
fi
bounded_cycle_sleep="$(scenario_timeout_within_campaign 5 \
    "$((deadline_now_nanoseconds + 1000000000))" "$deadline_now_nanoseconds" 0)"
python3 - "$bounded_cycle_sleep" <<'PY'
import decimal
import sys

bounded = decimal.Decimal(sys.argv[1])
if not decimal.Decimal("0") < bounded <= decimal.Decimal("1"):
    raise SystemExit("cycle sleep was not bounded by the remaining campaign deadline")
PY
provenance_guard_evidence="$workdir/provenance-guard"
if (
    # shellcheck disable=SC2030
    expected_commit="$(git -C "$repo_root" rev-parse HEAD)"
    evidence_dir="$provenance_guard_evidence"
    scenario_names=(must_not_run)
    scenario_scripts=(scripts/does-not-exist.sh)
    scenario_env_vars=(MUST_NOT_RUN_ARTIFACTS)
    run_scenario 1 0 1
); then
    printf 'scenario execution accepted a dirty expected-commit checkout\n' >&2
    exit 1
fi
[[ ! -e "$provenance_guard_evidence" ]]
execution_deadline_now="$(monotonic_nanoseconds)"
execution_deadline_nanoseconds=$((execution_deadline_now + 4000000000))
execution_timeout="$(scenario_timeout_within_campaign 300 \
    "$execution_deadline_nanoseconds" "$execution_deadline_now" 500000000 1)"
started="$(monotonic_nanoseconds)"
set +e
run_bounded_scenario_command "$execution_timeout" 1 TEST_ARTIFACT \
    "$workdir/timeout-artifact" "$timeout_fixture"
timeout_status=$?
set -e
ended_nanoseconds="$(monotonic_nanoseconds)"
elapsed=$((ended_nanoseconds - started))
[[ "$timeout_status" -ne 0 ]]
((elapsed <= 4000000000))
((ended_nanoseconds < execution_deadline_nanoseconds))
read -r fixture_pid fixture_child <"$workdir/timeout-artifact/pids"
for pid in "$fixture_pid" "$fixture_child"; do
    if kill -0 "$pid" 2>/dev/null; then
        printf 'hard timeout left process alive: %s\n' "$pid" >&2
        exit 1
    fi
done

fake_docker_state="$workdir/fake-docker-state"
mkdir -p "$fake_docker_state"
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'state=${FAKE_DOCKER_STATE:?}' \
    'command=${1:-}' \
    'shift || true' \
    'case "$command" in' \
    'run)' \
    '  label=""' \
    '  while (($# > 0)); do case "$1" in --label) label="$2"; shift 2 ;; *) shift ;; esac; done' \
    '  printf "%s\n" "$label" >"$state/last-label"' \
    '  touch "$state/container"' \
    '  printf "fake-container\n"' \
    '  ;;' \
    'ps) [[ "${FAKE_DOCKER_PS_HANG:-0}" != "1" ]] || sleep 300; test ! -e "$state/container" || printf "fake-container\n" ;;' \
    'rm) [[ "${FAKE_DOCKER_RM_FAIL:-0}" != "1" ]] || exit 42; rm -f "$state/container" ;;' \
    'network|volume) ;;' \
    '*) ;;' \
    'esac' \
    >"$workdir/fakebin/docker"
chmod +x "$workdir/fakebin/docker"
detached_fixture="$workdir/detached-container.sh"
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'docker run -d --name soak-detached fixture sleep 300 >/dev/null' \
    'trap "" TERM' \
    'sleep 300' \
    >"$detached_fixture"
chmod +x "$detached_fixture"
set +e
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" \
    run_bounded_scenario_command 1 1 TEST_ARTIFACT "$workdir/timeout-artifact" "$detached_fixture"
detached_status=$?
set -e
[[ "$detached_status" -ne 0 ]]
[[ ! -e "$fake_docker_state/container" ]]
grep -Eq '^io\.borondns\.soak\.run=run-' "$fake_docker_state/last-label"

resume_cleanup_evidence="$workdir/resume-cleanup-evidence"
cleanup_failure_artifact="$resume_cleanup_evidence/scenarios/cycle-0001/failure/artifacts"
cleanup_failure_log="$workdir/cleanup-failure.log"
mkdir -p "$cleanup_failure_artifact"
set +e
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" FAKE_DOCKER_RM_FAIL=1 \
    run_bounded_scenario_command 1 1 TEST_ARTIFACT "$cleanup_failure_artifact" "$detached_fixture" \
    >"$cleanup_failure_log" 2>&1
cleanup_failure_status=$?
set -e
[[ "$cleanup_failure_status" -ne 0 ]]
[[ -e "$fake_docker_state/container" ]]
grep -Eq 'docker cleanup failed: ownership_label=io\.borondns\.soak\.run=run-' "$cleanup_failure_log"
cleanup_failure_evidence="$cleanup_failure_artifact/docker-cleanup-failure.env"
grep -Eq '^ownership_label=io\.borondns\.soak\.run=run-' "$cleanup_failure_evidence"
grep -Fqx "primary_exit_status=$cleanup_failure_status" "$cleanup_failure_evidence"
grep -Fqx 'cleanup_exit_status=42' "$cleanup_failure_evidence"
evidence_dir="$resume_cleanup_evidence"
resume=1
docker_cleanup_timeout=1
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" \
    reconcile_retained_docker_cleanup_failures
[[ ! -e "$fake_docker_state/container" ]]
grep -Eq '^ownership_label=io\.borondns\.soak\.run=run-' \
    "$cleanup_failure_artifact/docker-cleanup-reconciled.env"

crash_cleanup_artifact="$resume_cleanup_evidence/scenarios/cycle-0004/crash/artifacts"
mkdir -p "$crash_cleanup_artifact"
touch "$fake_docker_state/container"
record_docker_cleanup_active "$crash_cleanup_artifact" 'io.borondns.soak.run=crash-before-cleanup'
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" \
    reconcile_retained_docker_cleanup_failures
[[ ! -e "$fake_docker_state/container" ]]
grep -Fqx 'ownership_label=io.borondns.soak.run=crash-before-cleanup' \
    "$crash_cleanup_artifact/docker-cleanup-reconciled.env"

persistent_cleanup_artifact="$resume_cleanup_evidence/scenarios/cycle-0002/persistent/artifacts"
mkdir -p "$persistent_cleanup_artifact"
touch "$fake_docker_state/container"
record_docker_cleanup_failure "$persistent_cleanup_artifact" \
    'io.borondns.soak.run=persistent-fixture' 0 42
set +e
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" FAKE_DOCKER_RM_FAIL=1 \
    reconcile_retained_docker_cleanup_failures >"$workdir/persistent-cleanup.log" 2>&1
persistent_cleanup_status=$?
set -e
[[ "$persistent_cleanup_status" -ne 0 ]]
[[ -e "$fake_docker_state/container" ]]
[[ -x "$persistent_cleanup_artifact/docker-cleanup-recovery.sh" ]]
grep -Fq 'run recovery command, then retry --resume' "$workdir/persistent-cleanup.log"
[[ ! -e "$persistent_cleanup_artifact/docker-cleanup-reconciled.env" ]]
# This is a literal fragment of the generated recovery script.
# shellcheck disable=SC2016
grep -Fq 'timeout --preserve-status --kill-after=5 "$cleanup_timeout"' \
    "$persistent_cleanup_artifact/docker-cleanup-recovery.sh"

second_persistent_artifact="$resume_cleanup_evidence/scenarios/cycle-0003/persistent-two/artifacts"
mkdir -p "$second_persistent_artifact"
record_docker_cleanup_failure "$second_persistent_artifact" \
    'io.borondns.soak.run=persistent-fixture-two' 0 42
set +e
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" FAKE_DOCKER_RM_FAIL=1 \
    reconcile_retained_docker_cleanup_failures >/dev/null 2>&1
all_cleanup_status=$?
set -e
[[ "$all_cleanup_status" -ne 0 ]]
[[ -x "$persistent_cleanup_artifact/docker-cleanup-recovery.sh" ]]
[[ -x "$second_persistent_artifact/docker-cleanup-recovery.sh" ]]
rm -f "$fake_docker_state/container"

marker_failure_evidence="$workdir/marker-failure-evidence"
marker_failure_one="$marker_failure_evidence/scenarios/cycle-0001/marker-fail/artifacts"
marker_failure_two="$marker_failure_evidence/scenarios/cycle-0002/marker-pass/artifacts"
mkdir -p "$marker_failure_one" "$marker_failure_two" "$workdir/marker-fail-bin"
record_docker_cleanup_failure "$marker_failure_one" 'io.borondns.soak.run=marker-fail' 0 42
record_docker_cleanup_failure "$marker_failure_two" 'io.borondns.soak.run=marker-pass' 0 42
# shellcheck disable=SC2016
# shellcheck disable=SC2016
# shellcheck disable=SC2016
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'destination="${!#}"' \
    '[[ "$destination" != *"marker-fail/artifacts/docker-cleanup-reconciled.env" ]] || exit 77' \
    'exec /usr/bin/mv "$@"' >"$workdir/marker-fail-bin/mv"
chmod +x "$workdir/marker-fail-bin/mv"
set +e
evidence_dir="$marker_failure_evidence" PATH="$workdir/marker-fail-bin:$workdir/fakebin:$PATH" \
    FAKE_DOCKER_STATE="$fake_docker_state" reconcile_retained_docker_cleanup_failures \
    >"$workdir/marker-failure.log" 2>&1
marker_failure_status=$?
set -e
[[ "$marker_failure_status" -ne 0 ]]
[[ ! -e "$marker_failure_one/docker-cleanup-reconciled.env" ]]
[[ -e "$marker_failure_two/docker-cleanup-reconciled.env" ]]
grep -Fq 'failed to publish Docker reconciliation marker; continuing' "$workdir/marker-failure.log"
evidence_dir="$resume_cleanup_evidence"

expired_cleanup_evidence="$workdir/expired-cleanup"
expired_cleanup_artifact="$expired_cleanup_evidence/scenarios/cycle-0001/failure/artifacts"
mkdir -p "$expired_cleanup_artifact"
touch "$fake_docker_state/container"
record_docker_cleanup_failure "$expired_cleanup_artifact" 'io.borondns.soak.run=expired-fixture' 0 42
expired_cleanup_start=$(($(date +%s) - 120))
printf '%s\n' \
    "created_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    'duration_seconds=60' \
    "start_epoch_seconds=$expired_cleanup_start" \
    "deadline_epoch_seconds=$((expired_cleanup_start + 60))" \
    >"$expired_cleanup_evidence/soak.env"
set +e
(
    evidence_dir="$expired_cleanup_evidence"
    duration=60
    resume=1
    docker_cleanup_timeout=1
    prepare_campaign_deadline
    PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" reconcile_retained_docker_cleanup_failures
    enforce_campaign_deadline
) >/dev/null 2>&1
expired_cleanup_status=$?
set -e
[[ "$expired_cleanup_status" -ne 0 ]]
[[ ! -e "$fake_docker_state/container" ]]
[[ -e "$expired_cleanup_artifact/docker-cleanup-reconciled.env" ]]

# Label injection no longer allocates a same-UID PATH wrapper directory, so an
# unusable TMPDIR cannot block or divert the scenario command.
wrapper_setup_fixture="$workdir/wrapper-setup-without-path-directory.sh"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'touch "$TEST_ARTIFACT/ran"' >"$wrapper_setup_fixture"
chmod +x "$wrapper_setup_fixture"
wrapper_setup_artifact="$workdir/wrapper-setup-artifact"
mkdir -p "$wrapper_setup_artifact"
set +e
TMPDIR=/proc PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" \
    run_bounded_scenario_command 1 1 TEST_ARTIFACT "$wrapper_setup_artifact" "$wrapper_setup_fixture"
wrapper_setup_status=$?
set -e
[[ "$wrapper_setup_status" == 0 ]]
[[ -e "$wrapper_setup_artifact/ran" ]]

cleanup_hang_artifact="$workdir/cleanup-hang-artifact"
cleanup_hang_log="$workdir/cleanup-hang.log"
mkdir -p "$cleanup_hang_artifact"
cleanup_hang_fixture="$workdir/cleanup-hang-fixture.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$cleanup_hang_fixture"
chmod +x "$cleanup_hang_fixture"
docker_cleanup_timeout=1
cleanup_hang_started="$(date +%s)"
set +e
PATH="$workdir/fakebin:$PATH" FAKE_DOCKER_STATE="$fake_docker_state" FAKE_DOCKER_PS_HANG=1 \
    run_bounded_scenario_command 5 1 TEST_ARTIFACT "$cleanup_hang_artifact" "$cleanup_hang_fixture" \
    >"$cleanup_hang_log" 2>&1
cleanup_hang_status=$?
set -e
cleanup_hang_elapsed=$(($(date +%s) - cleanup_hang_started))
[[ "$cleanup_hang_status" -ne 0 ]]
((cleanup_hang_elapsed <= 4))
grep -Fqx 'primary_exit_status=0' "$cleanup_hang_artifact/docker-cleanup-failure.env"
grep -Fqx "cleanup_exit_status=$cleanup_hang_status" "$cleanup_hang_artifact/docker-cleanup-failure.env"

# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"
image_setup_bin="$workdir/image-setup-bin"
image_setup_state="$workdir/image-setup-state"
image_lock_runtime="$workdir/image-lock-runtime"
image_owner_xdg="$image_lock_runtime/owner-xdg"
image_owner_tmp="$image_lock_runtime/owner-tmp"
image_contender_xdg="$image_lock_runtime/contender-xdg"
image_contender_tmp="$image_lock_runtime/contender-tmp"
mkdir -p "$image_setup_bin" "$image_setup_state/images" \
    "$image_owner_xdg" "$image_owner_tmp" "$image_contender_xdg" "$image_contender_tmp"
chmod 0700 "$image_lock_runtime" "$image_owner_xdg" "$image_owner_tmp" \
    "$image_contender_xdg" "$image_contender_tmp"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'printf "%s\n" "$*" >>"$FAKE_IMAGE_SETUP_STATE/invocations"' \
    'if [[ "${1:-} ${2:-}" == "image inspect" ]]; then' \
    '  if [[ "${FAKE_IMAGE_INSPECT_HANG_ONCE:-0}" == 1 && ! -e "$FAKE_IMAGE_SETUP_STATE/inspect-hung" ]]; then' \
    '    : >"$FAKE_IMAGE_SETUP_STATE/inspect-hung"; sleep 300' \
    '  fi' \
    '  tag="${*: -1}"' \
    '  key="$(printf "%s" "$tag" | sha256sum | awk '\''{ print $1 }'\'')"' \
    '  [[ -f "$FAKE_IMAGE_SETUP_STATE/images/$key" ]] || exit 1' \
    '  cat "$FAKE_IMAGE_SETUP_STATE/images/$key"' \
    '  exit 0' \
    'fi' \
    'if [[ "${1:-}" == build ]]; then' \
    '  tag=""' \
    '  for ((index = 1; index <= $#; index++)); do' \
    '    if [[ "${!index}" == -t ]]; then next=$((index + 1)); tag="${!next}"; fi' \
    '  done' \
    '  context="${*: -1}"' \
    '  [[ -z "${FAKE_IMAGE_BUILD_CONTEXT_FILE:-}" ]] || printf "%s\n" "$context" >"$FAKE_IMAGE_BUILD_CONTEXT_FILE"' \
    '  recipe="$(sed -n '\''s/^LABEL io\.borondns\.interop\.recipe-sha256="\([^"]*\)"$/\1/p'\'' "$context/Dockerfile")"' \
    '  base="$(sed -n '\''s/^LABEL io\.borondns\.interop\.base-image="\([^"]*\)"$/\1/p'\'' "$context/Dockerfile")"' \
    '  packages="$(sed -n '\''s/^LABEL io\.borondns\.interop\.packages="\([^"]*\)"$/\1/p'\'' "$context/Dockerfile")"' \
    '  image_id="sha256:$(printf "%s" "$recipe|$base|$packages" | sha256sum | awk '\''{ print $1 }'\'')"' \
    '  key="$(printf "%s" "$tag" | sha256sum | awk '\''{ print $1 }'\'')"' \
    '  if [[ -n "${FAKE_IMAGE_BUILD_READY:-}" ]]; then' \
    '    : >"$FAKE_IMAGE_BUILD_READY"' \
    '    until [[ -e "$FAKE_IMAGE_BUILD_RELEASE" ]]; do sleep 0.01; done' \
    '  fi' \
    '  count=0; [[ ! -f "$FAKE_IMAGE_SETUP_STATE/build-count" ]] || read -r count <"$FAKE_IMAGE_SETUP_STATE/build-count"' \
    '  printf "%s\n" "$((count + 1))" >"$FAKE_IMAGE_SETUP_STATE/build-count"' \
    '  printf "%s\t%s\t%s\t%s\n" "$image_id" "$recipe" "$base" "$packages" >"$FAKE_IMAGE_SETUP_STATE/images/$key"' \
    '  if [[ "${FAKE_IMAGE_MOVE_CONTEXT:-0}" == 1 ]]; then mv "$context" "$context.renamed"; fi' \
    '  exit 0' \
    'fi' \
    'exit 1' >"$image_setup_bin/docker"
chmod +x "$image_setup_bin/docker"
image_setup_started="$(date +%s)"
image_setup_id="$(PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_lock_runtime" FAKE_IMAGE_INSPECT_HANG_ONCE=1 \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=1 \
    ensure_alpine_interop_image round49-fixture fixture-package)"
image_setup_elapsed=$(($(date +%s) - image_setup_started))
((image_setup_elapsed <= 4))
[[ "$image_setup_id" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$(<"$image_setup_state/build-count")" == 1 ]]

# Repeated termination signals during EXIT cleanup cannot interrupt exact build
# context removal or broker release.
image_cleanup_signal_marker="$workdir/image-cleanup-signals"
# shellcheck disable=SC2329
interop_image_cleanup_started_hook() {
    local signal_index
    for ((signal_index = 0; signal_index < 20; signal_index++)); do
        kill -TERM "$BASHPID"
    done
    : >"$image_cleanup_signal_marker"
}
signalled_image_setup_id="$(PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_lock_runtime" TMPDIR="$image_owner_tmp" \
    ensure_alpine_interop_image round54-signal-cleanup fixture-package)"
unset -f interop_image_cleanup_started_hook
[[ -f "$image_cleanup_signal_marker" && "$signalled_image_setup_id" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ -z "$(find "$image_owner_tmp/borondns-interop-builds-$(id -u)" -maxdepth 1 \
    \( -type d -name 'run.*' -o -type f -name '.automatic-run.*.env' \) -print -quit 2>/dev/null)" ]]
image_build_count_after_signal="$(<"$image_setup_state/build-count")"
[[ "$image_build_count_after_signal" == 2 ]]

# An exactly labelled recipe cache is reused and callers receive its immutable
# content ID rather than the mutable local tag.
cached_image_setup_id="$(PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_lock_runtime" ensure_alpine_interop_image round49-fixture fixture-package)"
[[ "$cached_image_setup_id" == "$image_setup_id" ]]
[[ "$(<"$image_setup_state/build-count")" == "$image_build_count_after_signal" ]]

# A foreign or partially labelled image at the recipe tag is never silently
# accepted. It is rebuilt and re-authenticated from the pinned base and recipe.
image_setup_recipe="$(interop_image_recipe_sha256 round49-fixture \
    "$BORONDNS_INTEROP_ALPINE_BASE_IMAGE_EXPECTED" fixture-package)"
image_setup_tag="borondns-interop-alpine-round49-fixture:recipe-${image_setup_recipe:0:20}"
image_setup_key="$(printf '%s' "$image_setup_tag" | sha256sum | awk '{ print $1 }')"
printf '%s\t%s\t%s\t%s\n' \
    'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
    foreign-recipe foreign-base foreign-packages >"$image_setup_state/images/$image_setup_key"
rebuilt_image_setup_id="$(PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_lock_runtime" ensure_alpine_interop_image round49-fixture fixture-package)"
[[ "$rebuilt_image_setup_id" == "$image_setup_id" ]]
[[ "$(<"$image_setup_state/build-count")" == "$((image_build_count_after_signal + 1))" ]]

image_setup_invocations_before="$(wc -l <"$image_setup_state/invocations")"
if PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_lock_runtime" BORONDNS_INTEROP_ALPINE_BASE_IMAGE=alpine:latest \
    ensure_alpine_interop_image unsupported-base fixture-package >/dev/null 2>&1; then
    printf 'Docker image helper accepted an unpinned or unsupported base image\n' >&2
    exit 1
fi
[[ "$(wc -l <"$image_setup_state/invocations")" == "$image_setup_invocations_before" ]]

# A stopped owner still holds the descriptor-backed broker lock. The second
# caller deliberately has different XDG_RUNTIME_DIR and TMPDIR values: Docker
# tags are daemon-global, so both callers must still contend on one UID-global
# lock namespace.
paused_image_ready="$workdir/paused-image.ready"
paused_image_release="$workdir/paused-image.release"
(
    PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
        XDG_RUNTIME_DIR="$image_owner_xdg" TMPDIR="$image_owner_tmp" \
        FAKE_IMAGE_BUILD_READY="$paused_image_ready" \
        FAKE_IMAGE_BUILD_RELEASE="$paused_image_release" \
        ensure_alpine_interop_image round49-paused fixture-package >"$workdir/paused-image.id"
) &
paused_image_pid=$!
lock_holder_pids+=("$paused_image_pid")
until [[ -e "$paused_image_ready" ]]; do
    kill -0 "$paused_image_pid"
    sleep 0.01
done
kill -STOP "$paused_image_pid"
set +e
PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_contender_xdg" TMPDIR="$image_contender_tmp" \
    ensure_alpine_interop_image round49-paused fixture-package >/dev/null 2>&1
paused_contender_status=$?
set -e
[[ "$paused_contender_status" -ne 0 ]]
: >"$paused_image_release"
kill -CONT "$paused_image_pid"
wait "$paused_image_pid"
untrack_test_process "$paused_image_pid"
[[ "$(<"$workdir/paused-image.id")" =~ ^sha256:[0-9a-f]{64}$ ]]

# Replacing the published lock pathname while a build is active invalidates
# the broker heartbeat. Cleanup retains the replacement instead of unlinking a
# path it no longer owns.
replacement_image_ready="$workdir/replacement-image.ready"
replacement_image_release="$workdir/replacement-image.release"
replacement_recipe="$(interop_image_recipe_sha256 round49-replacement \
    "$BORONDNS_INTEROP_ALPINE_BASE_IMAGE_EXPECTED" fixture-package)"
replacement_lock_digest="$(printf '%s' "interop-image:$replacement_recipe" | sha256sum | awk '{ print $1 }')"
replacement_lock="/tmp/borondns-interop-image-locks-$(id -u)/.borondns-campaign-locks/$replacement_lock_digest.lock"
(
    PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
        XDG_RUNTIME_DIR="$image_lock_runtime" FAKE_IMAGE_BUILD_READY="$replacement_image_ready" \
        FAKE_IMAGE_BUILD_RELEASE="$replacement_image_release" \
        ensure_alpine_interop_image round49-replacement fixture-package >/dev/null
) &
replacement_image_pid=$!
lock_holder_pids+=("$replacement_image_pid")
until [[ -e "$replacement_image_ready" ]]; do
    kill -0 "$replacement_image_pid"
    sleep 0.01
done
[[ -f "$replacement_lock" ]]
rm -f -- "$replacement_lock"
printf 'replacement-must-survive\n' >"$replacement_lock"
chmod 0600 "$replacement_lock"
# The filesystem lock inode is now replaceable, but the first broker's abstract
# AF_UNIX authority is not. A second builder must not overlap the active first
# build by locking the replacement inode.
if PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_lock_runtime" \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=1 \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=3 \
    ensure_alpine_interop_image round49-replacement fixture-package >/dev/null 2>&1; then
    printf 'replacement lock inode admitted a split-brain interop image builder\n' >&2
    exit 1
fi
: >"$replacement_image_release"
set +e
wait "$replacement_image_pid"
replacement_image_status=$?
set -e
untrack_test_process "$replacement_image_pid"
[[ "$replacement_image_status" -ne 0 ]]
grep -Fqx replacement-must-survive "$replacement_lock"

# Docker build contexts have the same inode-bound cleanup contract. Replacing
# the context after docker has opened it must preserve the replacement and
# turn an otherwise successful build into a non-zero helper result.
build_context_ready="$workdir/build-context.ready"
build_context_release="$workdir/build-context.release"
build_context_path_file="$workdir/build-context.path"
set +e
(
    PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
        XDG_RUNTIME_DIR="$image_owner_xdg" TMPDIR="$image_owner_tmp" \
        FAKE_IMAGE_BUILD_READY="$build_context_ready" \
        FAKE_IMAGE_BUILD_RELEASE="$build_context_release" \
        FAKE_IMAGE_BUILD_CONTEXT_FILE="$build_context_path_file" \
        ensure_alpine_interop_image round50-build-context fixture-package \
        >"$workdir/build-context.id"
) &
build_context_pid=$!
lock_holder_pids+=("$build_context_pid")
set -e
until [[ -e "$build_context_ready" ]]; do
    kill -0 "$build_context_pid"
    sleep 0.01
done
build_context_path="$(<"$build_context_path_file")"
mv "$build_context_path" "$build_context_path.original"
mkdir -m 0700 "$build_context_path"
printf 'replacement must survive\n' >"$build_context_path/sentinel"
: >"$build_context_release"
set +e
wait "$build_context_pid"
build_context_status=$?
set -e
untrack_test_process "$build_context_pid"
[[ "$build_context_status" -ne 0 ]]
grep -Fqx 'replacement must survive' "$build_context_path/sentinel"
[[ -d "$build_context_path.original" ]]

# A context renamed away without a replacement is not already-cleaned state.
# The helper must fail and retain the moved context instead of returning an
# authenticated image while silently leaking the tree.
missing_context_path_file="$workdir/missing-build-context.path"
set +e
PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    XDG_RUNTIME_DIR="$image_owner_xdg" TMPDIR="$image_owner_tmp" \
    FAKE_IMAGE_BUILD_CONTEXT_FILE="$missing_context_path_file" \
    FAKE_IMAGE_MOVE_CONTEXT=1 \
    ensure_alpine_interop_image round51-missing-build-context fixture-package \
    >"$workdir/missing-build-context.id"
missing_context_status=$?
set -e
[[ "$missing_context_status" -ne 0 ]]
missing_context_path="$(<"$missing_context_path_file")"
[[ ! -e "$missing_context_path" && -d "$missing_context_path.renamed" ]]

printf '%s\n' '#!/usr/bin/env bash' 'sleep 300' >"$image_setup_bin/docker"
chmod +x "$image_setup_bin/docker"
image_deadline_started="$(date +%s)"
if PATH="$image_setup_bin:$PATH" XDG_RUNTIME_DIR="$image_lock_runtime" \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=30 \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=2 \
    ensure_alpine_interop_image round49-deadline fixture-package >/dev/null; then
    printf 'Docker image setup accepted an exhausted absolute deadline\n' >&2
    exit 1
fi
image_deadline_elapsed=$(($(date +%s) - image_deadline_started))
((image_deadline_elapsed <= 4))

# Realtime movement cannot replenish the absolute setup budget. This fake
# clock would keep the old date-based implementation one second before its
# deadline across every retry.
image_clock_bin="$workdir/image-clock-bin"
mkdir "$image_clock_bin"
# This is the literal body of the generated fake date executable.
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == +%s ]]; then printf "%s\n" "$FAKE_IMAGE_REALTIME"; else exec /usr/bin/date "$@"; fi' \
    >"$image_clock_bin/date"
chmod +x "$image_clock_bin/date"
image_clock_started="$(/usr/bin/date +%s)"
if PATH="$image_clock_bin:$image_setup_bin:$PATH" \
    FAKE_IMAGE_REALTIME="$((image_clock_started - 86400))" \
    XDG_RUNTIME_DIR="$image_lock_runtime" \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=30 \
    BORONDNS_INTEROP_DOCKER_BUILD_TIMEOUT_SECONDS=30 \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=2 \
    ensure_alpine_interop_image round51-monotonic-deadline fixture-package >/dev/null; then
    printf 'Docker image setup accepted a monotonic deadline exhaustion\n' >&2
    exit 1
fi
image_clock_elapsed=$(($(/usr/bin/date +%s) - image_clock_started))
((image_clock_elapsed <= 4))

# Lock broker handshake time is part of the same monotonic absolute setup
# budget. A stalled authenticated helper must not inherit the generic five
# second heartbeat after the shorter image-setup budget is selected.
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$image_setup_bin/docker"
chmod +x "$image_setup_bin/docker"
stalled_image_lock_helper="$(printf '%s' 'import time; time.sleep(300)' | base64 -w0)"
image_lock_deadline_started="$(/usr/bin/date +%s)"
if PATH="$image_setup_bin:$PATH" \
    BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$stalled_image_lock_helper" \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=1 \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=3 \
    ensure_alpine_interop_image round52-stalled-lock fixture-package >/dev/null 2>&1; then
    printf 'Docker image setup accepted a stalled lock broker\n' >&2
    exit 1
fi
image_lock_deadline_elapsed=$(($(/usr/bin/date +%s) - image_lock_deadline_started))
((image_lock_deadline_elapsed <= 3))

# STOP and TERM-ignore must not turn broker close/TERM/KILL/reap into additive
# timeout phases. The cleanup reserve is part of the same four-second
# monotonic setup deadline; allow 750 ms of scheduler and harness overhead.
stopped_ignoring_broker_pid_file="$workdir/stopped-ignoring-broker.pid"
stopped_ignoring_broker_helper="$(printf '%s\n' \
    'import os, signal, time' \
    'signal.signal(signal.SIGTERM, signal.SIG_IGN)' \
    'open(os.environ["FAKE_STOPPED_BROKER_PID_FILE"], "w", encoding="ascii").write(str(os.getpid()))' \
    'print("locked\t/stopped-term-ignoring-broker", flush=True)' \
    'os.kill(os.getpid(), signal.SIGSTOP)' \
    'time.sleep(300)' | base64 -w0)"
stopped_ignoring_broker_started="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns())')"
if PATH="$image_setup_bin:$PATH" \
    FAKE_STOPPED_BROKER_PID_FILE="$stopped_ignoring_broker_pid_file" \
    BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$stopped_ignoring_broker_helper" \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=1 \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=4 \
    ensure_alpine_interop_image round53-stopped-ignoring-broker fixture-package >/dev/null 2>&1; then
    printf 'Docker image setup accepted a stopped TERM-ignoring lock broker\n' >&2
    exit 1
fi
stopped_ignoring_broker_finished="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns())')"
stopped_ignoring_broker_elapsed_ms=$(((stopped_ignoring_broker_finished - stopped_ignoring_broker_started) / 1000000))
((stopped_ignoring_broker_elapsed_ms >= 2000 && stopped_ignoring_broker_elapsed_ms <= 4750)) || {
    printf 'stopped TERM-ignoring broker exceeded one absolute setup deadline: %s ms\n' \
        "$stopped_ignoring_broker_elapsed_ms" >&2
    exit 1
}
stopped_ignoring_broker_pid="$(<"$stopped_ignoring_broker_pid_file")"
if kill -0 "$stopped_ignoring_broker_pid" 2>/dev/null; then
    printf 'Docker image setup left its stopped TERM-ignoring lock broker alive\n' >&2
    exit 1
fi

# The descriptor-bound tree creator has the same single-deadline rule. This
# Python shim affects only the creator invocation, stops after installing a
# TERM-ignore disposition, and delegates lock/clock Python calls unchanged.
stopped_creator_bin="$workdir/stopped-creator-bin"
stopped_creator_pid_file="$workdir/stopped-ignoring-creator.pid"
mkdir "$stopped_creator_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == /dev/fd/3 ]]; then' \
    '  printf "%s\n" "$$" >"$FAKE_STOPPED_CREATOR_PID_FILE"' \
    '  trap "" TERM' \
    '  kill -STOP "$$"' \
    '  exec /bin/sleep 300' \
    'fi' \
    'exec /usr/bin/python3 "$@"' >"$stopped_creator_bin/python3"
chmod +x "$stopped_creator_bin/python3"
stopped_creator_started="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns())')"
if PATH="$stopped_creator_bin:$image_setup_bin:$PATH" \
    FAKE_STOPPED_CREATOR_PID_FILE="$stopped_creator_pid_file" \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS=1 \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=4 \
    ensure_alpine_interop_image round53-stopped-ignoring-creator fixture-package >/dev/null 2>&1; then
    printf 'Docker image setup accepted a stopped TERM-ignoring private-tree creator\n' >&2
    exit 1
fi
stopped_creator_finished="$(/usr/bin/python3 -c 'import time; print(time.monotonic_ns())')"
stopped_creator_elapsed_ms=$(((stopped_creator_finished - stopped_creator_started) / 1000000))
((stopped_creator_elapsed_ms >= 2000 && stopped_creator_elapsed_ms <= 4750)) || {
    printf 'stopped TERM-ignoring creator exceeded one absolute setup deadline: %s ms\n' \
        "$stopped_creator_elapsed_ms" >&2
    exit 1
}
stopped_creator_pid="$(<"$stopped_creator_pid_file")"
if kill -0 "$stopped_creator_pid" 2>/dev/null; then
    printf 'Docker image setup left its stopped TERM-ignoring private-tree creator alive\n' >&2
    exit 1
fi

# A one-second request cannot reserve a safe cleanup window and is rejected
# before touching Docker or allocating a build context.
image_setup_invocations_before="$(wc -l <"$image_setup_state/invocations")"
if PATH="$image_setup_bin:$PATH" FAKE_IMAGE_SETUP_STATE="$image_setup_state" \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS=1 \
    ensure_alpine_interop_image round52-no-cleanup-reserve fixture-package >/dev/null 2>&1; then
    printf 'Docker image setup accepted a budget with no safe cleanup reserve\n' >&2
    exit 1
fi
[[ "$(wc -l <"$image_setup_state/invocations")" == "$image_setup_invocations_before" ]]

for oversized_timeout_name in \
    BORONDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS \
    BORONDNS_INTEROP_DOCKER_BUILD_TIMEOUT_SECONDS \
    BORONDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS; do
    if (
        export "$oversized_timeout_name=999999999999999999999999999999"
        ensure_alpine_interop_image "oversized-${oversized_timeout_name##*_}" fixture-package
    ) >/dev/null 2>&1; then
        printf 'Docker image helper accepted overflow-sized timeout: %s\n' "$oversized_timeout_name" >&2
        exit 1
    fi
done

plan_dir="$workdir/plan"
plan_lock_ready="$workdir/plan-lock.ready"
plan_lock_release="$workdir/plan-lock.release"
start_test_campaign_lock "$workdir" "$(realpath -ms "$plan_dir"):plan" \
    "$plan_lock_ready" "$plan_lock_release"
plan_holder_pid="$lock_holder_pid"
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$plan_dir" --campaign-id operations-test --host fake-host --duration 60; then
    printf 'campaign planner accepted a concurrently held plan lock\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$workdir/unknown-scenario-plan" --campaign-id unknown-scenario \
    --host fake-host --duration 60 --scenario definitely_unknown; then
    printf 'large-surface planner accepted an unknown scenario\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$workdir/duplicate-scenario-plan" --campaign-id duplicate-scenario \
    --host fake-host --duration 60 --scenario bind_axfr --scenario bind_axfr; then
    printf 'large-surface planner accepted a duplicate scenario\n' >&2
    exit 1
fi

assert_large_plan_rejected_without_writes() {
    local name="$1"
    shift
    local rejected_root="$workdir/round47-large-reject-$name"
    if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
        --evidence-dir "$rejected_root/plan" --campaign-id "valid-$name" \
        --host fake-host --duration 60 "$@"; then
        printf 'large-surface planner accepted invalid canonical field fixture: %s\n' "$name" >&2
        exit 1
    fi
    [[ ! -e "$rejected_root" ]]
}
assert_large_plan_rejected_without_writes unsafe-id --campaign-id '../unsafe'
assert_large_plan_rejected_without_writes relative-repo --remote-repo relative/repo
assert_large_plan_rejected_without_writes noncanonical-remote \
    --remote-evidence "$workdir/round47-remote/../escaped"
assert_large_plan_rejected_without_writes unknown-scenario --scenario no_such_scenario
if (
    cd "$workdir"
    "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
        --evidence-dir relative-large-plan --campaign-id relative-evidence \
        --host fake-host --duration 60
); then
    printf 'large-surface planner accepted a relative evidence path\n' >&2
    exit 1
fi
[[ ! -e "$workdir/relative-large-plan" ]]

blocking_rustup_bin="$workdir/blocking-rustup-bin"
mkdir "$blocking_rustup_bin"
printf '%s\n' '#!/usr/bin/env bash' 'sleep 30' >"$blocking_rustup_bin/rustup"
chmod +x "$blocking_rustup_bin/rustup"
blocking_rustup_started="$SECONDS"
blocking_rustup_plan="$workdir/blocking-rustup-plan"
if PATH="$blocking_rustup_bin:$PATH" BORONDNS_LARGE_SOAK_PREFLIGHT_TIMEOUT_SECONDS=1 \
    BORONDNS_LARGE_SOAK_PREFLIGHT_KILL_AFTER_SECONDS=1 \
    "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$blocking_rustup_plan" --campaign-id blocking-rustup \
    --host fake-host --duration 1; then
    printf 'large-surface planner accepted a hanging rustup probe\n' >&2
    exit 1
fi
((SECONDS - blocking_rustup_started <= 4))
[[ ! -e "$blocking_rustup_plan" ]]

source_preflight_bin="$workdir/source-preflight-bin"
mkdir "$source_preflight_bin"
cat >"$source_preflight_bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${3:-} ${4:-}" in
'rev-parse HEAD')
    if [[ "${FAKE_GIT_SOURCE_MODE:-clean}" == invalid-head ]]; then
        printf 'not-a-commit\n'
    else
        printf '%s\n' "$FAKE_GIT_HEAD"
    fi
    ;;
'status --short')
    if [[ "${FAKE_GIT_SOURCE_MODE:-clean}" == dirty ]]; then
        printf ' M hostile-dirty-source\n'
    fi
    ;;
*)
    printf 'unexpected fake git invocation: %s\n' "$*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$source_preflight_bin/git"
source_preflight_head="$(git -C "$repo_root" rev-parse HEAD)"
for source_preflight_mode in dirty invalid-head; do
    source_preflight_root="$workdir/large-source-preflight-$source_preflight_mode"
    if env -u BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY \
        PATH="$source_preflight_bin:$PATH" FAKE_GIT_HEAD="$source_preflight_head" \
        FAKE_GIT_SOURCE_MODE="$source_preflight_mode" \
        "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
        --evidence-dir "$source_preflight_root/plan" \
        --campaign-id "source-preflight-$source_preflight_mode" \
        --host fake-host --duration 1; then
        printf 'large-surface planner accepted invalid preflight source: %s\n' \
            "$source_preflight_mode" >&2
        exit 1
    fi
    [[ ! -e "$source_preflight_root" ]]
done

stop_test_campaign_lock "$plan_lock_release" "$plan_holder_pid"
# The private lock inode remains, but no process owns its flock.
[[ -n "$(find "$workdir/.borondns-campaign-locks" -type f -name '*.lock' -print -quit)" ]]
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$plan_dir" --campaign-id operations-test --host fake-host --duration 60
[[ -f "$plan_dir/plan-complete" ]]
grep -Eq '  plan-complete$' "$plan_dir/campaign-manifest.sha256"
[[ -x "$plan_dir/validate-collected-campaign.py" ]]
grep -Eq '  validate-collected-campaign\.py$' "$plan_dir/campaign-manifest.sha256"
large_cleanup_budget_plan="$workdir/large-cleanup-budget-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$large_cleanup_budget_plan" --campaign-id cleanup-budget \
    --host fake-host --duration 1 --docker-cleanup-timeout 1000
large_cleanup_budget_command="$large_cleanup_budget_plan/commands/fake-host-launch.sh"
grep -Fqx 'docker_cleanup_total_budget_seconds=6030' "$large_cleanup_budget_command"
grep -Fqx 'service_runtime_max_seconds=11506' "$large_cleanup_budget_command"
grep -Fqx 'service_stop_timeout_seconds=6105' "$large_cleanup_budget_command"
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$workdir/overflow-cleanup-budget-plan" --campaign-id overflow-cleanup-budget \
    --host fake-host --duration 1 --docker-cleanup-timeout 2147483647; then
    printf 'large-surface planner accepted an overflowing aggregate Docker cleanup budget\n' >&2
    exit 1
fi
large_validator_tamper_plan="$workdir/large-validator-tamper-plan"
cp -a "$plan_dir" "$large_validator_tamper_plan"
chmod u+w "$large_validator_tamper_plan/validate-collected-campaign.py"
printf '\n# authenticated but semantically drifted validator\n' \
    >>"$large_validator_tamper_plan/validate-collected-campaign.py"
chmod 0755 "$large_validator_tamper_plan/validate-collected-campaign.py"
campaign_manifest_write "$large_validator_tamper_plan"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$large_validator_tamper_plan"; then
    printf 'large-surface status accepted recomputed-manifest validator drift\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$workdir/option-host-plan" --campaign-id option-host --host -V --duration 60; then
    printf 'large-surface planner accepted an option-like SSH host\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$workdir/colliding-large-host-plan" --campaign-id colliding-hosts \
    --host 'user@host' --host user_host --duration 60; then
    printf 'large-surface planner accepted colliding canonical host identities\n' >&2
    exit 1
fi
command_file="$plan_dir/commands/fake-host-launch.sh"
grep -Fq 'resume_arg=--resume' "$command_file"
grep -Fq -- '--scenario-kill-after' "$command_file"
grep -Fq 'remote_runner=' "$command_file"
grep -Fq 'remote_build_root=/var/tmp/borondns-large-' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'export CARGO_TARGET_DIR="\$build_dir"' "$command_file"
grep -Fq '/launch/' "$command_file"
grep -Fq 'expected_commit=' "$command_file"
grep -Fq 'remote repository commit mismatch' "$command_file"
if grep -Fq 'git pull' "$command_file"; then
    printf 'large-surface launch still permits source commit drift\n' >&2
    exit 1
fi
grep -Fq 'timeout --preserve-status --kill-after=30 900 sudo apt-get update' "$command_file"
grep -Fq 'docker_command=(sudo /usr/bin/docker)' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'sudo install -m 0555 -o root -g root -- "$docker_wrapper_candidate" "$authenticated_tool_dir/docker"' \
    "$command_file"
grep -Fq 'BORONDNS_LARGE_SOAK_AUTHENTICATED_DOCKER_SHIM=' "$command_file"
grep -Fq 'SupplementaryGroups=docker' "$command_file"
# The generated unit must use the fully derived worst-case cleanup and sampler
# budgets, not a single Docker timeout or an unrelated fixed stop timeout.
grep -Fqx 'docker_cleanup_total_budget_seconds=210' "$command_file"
grep -Fqx 'service_runtime_max_seconds=5745' "$command_file"
grep -Fqx 'service_stop_timeout_seconds=285' "$command_file"
# shellcheck disable=SC2016 # Literal fragments of the generated service script.
grep -Fq 'RuntimeMaxSec=$service_runtime_max_seconds' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'TimeoutStopSec=$service_stop_timeout_seconds' "$command_file"
grep -Fq 'campaign_lock_helper_sha256=' "$command_file"
dirty_check_line="$(grep -n 'status --short --untracked-files=all' "$command_file" | head -1 | cut -d: -f1)"
# shellcheck disable=SC2016
helper_source_line="$(grep -nF 'source <(printf '\''%s'\'' "$campaign_env_snapshot_b64" | base64 --decode)' "$command_file" | head -1 | cut -d: -f1)"
((dirty_check_line < helper_source_line))
# shellcheck disable=SC2016
grep -Fq 'campaign_lock_helper_snapshot_b64=' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"' "$command_file"
if grep -Fq 'usermod -aG docker' "$command_file"; then
    printf 'large-soak prerequisite plan persistently mutates docker group membership\n' >&2
    exit 1
fi
grep -Fq 'BORONDNS_LARGE_SOAK_AUTHENTICATED_CARGO=' "$command_file"
grep -Fq 'exec 7<' "$command_file"

blocking_probe_bin="$workdir/blocking-large-probe-bin"
blocking_probe_dir="$workdir/blocking-large-probe-evidence"
mkdir "$blocking_probe_bin" "$blocking_probe_dir"
printf '%s\n' '#!/usr/bin/env bash' 'sleep 30' >"$blocking_probe_bin/docker"
chmod +x "$blocking_probe_bin/docker"
# The single-quoted program is intentionally evaluated by the isolated child shell.
# shellcheck disable=SC2016
if timeout 5 env PATH="$blocking_probe_bin:$PATH" \
    BORONDNS_LARGE_SOAK_HOST_PROBE_TIMEOUT_SECONDS=1 \
    BORONDNS_LARGE_SOAK_HOST_PROBE_KILL_AFTER_SECONDS=1 \
    bash --noprofile --norc -c '
        source "$1/scripts/large-surface-soak.sh"
        evidence_dir="$2"
        sample_interval=1
        sample_resources "$2" "$(date +%s)"
    ' _ "$repo_root" "$blocking_probe_dir"; then
    printf 'large-soak sampler accepted a blocking Docker probe\n' >&2
    exit 1
fi
# The single-quoted program is intentionally evaluated by the isolated child shell.
# shellcheck disable=SC2016
if timeout 5 env \
    BORONDNS_LARGE_SOAK_HOST_PROBE_TIMEOUT_SECONDS=1 \
    BORONDNS_LARGE_SOAK_HOST_PROBE_KILL_AFTER_SECONDS=1 \
    bash --noprofile --norc -c '
        source "$1/scripts/large-surface-soak.sh"
        (trap "" TERM; sleep 30) &
        sampler_pid=$!
        wait_for_resource_sampler_bounded 1
    ' _ "$repo_root"; then
    printf 'large-soak sampler final wait accepted an indefinitely blocking sampler\n' >&2
    exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'sudo ln -s -- /proc/self/fd/7 "$authenticated_tool_dir/cargo"' "$command_file"
# shellcheck disable=SC2016
grep -Fq '[[ "\$(command -v cargo)" == "\$authenticated_tool_dir/cargo" ]]' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'ln -s -- "$build_dir" "$source_snapshot/target"' "$command_file"
grep -Fq 'campaign_capture_prerequisite_service_state' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'campaign_publish_root_atomic_text "$remote_build_root" "$prerequisite_state_file"' "$command_file"
if grep -Fq 'Environment=PATH=/home/codex/.cargo/bin:' "$command_file"; then
    printf 'large-soak unit retained a user-writable executable search path\n' >&2
    exit 1
fi
grep -Fq -- '--expected-commit' "$command_file"
# These are literal fragments of the generated remote script.
# shellcheck disable=SC2016
grep -Fq 'cat >"$remote_runner"' "$command_file"
# shellcheck disable=SC2016
grep -Fq 'ExecStart=$remote_runner' "$command_file"
# shellcheck disable=SC2016
if grep -Fq 'cat >"$host_evidence/run-soak.sh"' "$command_file"; then
    printf 'fresh campaign still writes its runner inside owned evidence\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$plan_dir" --campaign-id operations-test --host fake-host --duration 60; then
    printf 'campaign plan overwrite was not refused\n' >&2
    exit 1
fi

malicious_plan="$workdir/malicious-plan"
cp -a "$plan_dir" "$malicious_plan"
printf 'unknown_key=base64:ZWNobyBwd25lZA==\n' >>"$malicious_plan/campaign.env"
if PATH="$workdir/fakebin:$PATH" "$repo_root/scripts/large-surface-soak-campaign.sh" status \
    --evidence-dir "$malicious_plan"; then
    printf 'large-surface status accepted unknown executable campaign metadata\n' >&2
    exit 1
fi
command_tamper_plan="$workdir/command-tamper-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$command_tamper_plan" --campaign-id command-tamper --host fake-host --duration 60
printf '\nprintf tampered\n' >>"$command_tamper_plan/commands/fake-host-launch.sh"
campaign_manifest_write "$command_tamper_plan"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$command_tamper_plan"; then
    printf 'large-surface status accepted a tampered authenticated command file\n' >&2
    exit 1
fi
extra_command_plan="$workdir/extra-command-plan"
cp -a "$plan_dir" "$extra_command_plan"
printf '#!/usr/bin/env bash\nexit 0\n' >"$extra_command_plan/commands/unreferenced.sh"
chmod +x "$extra_command_plan/commands/unreferenced.sh"
campaign_manifest_write "$extra_command_plan"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$extra_command_plan"; then
    printf 'large-surface status accepted an authenticated but unreferenced command\n' >&2
    exit 1
fi
symlink_commands_plan="$workdir/symlink-commands-plan"
cp -a "$plan_dir" "$symlink_commands_plan"
mv "$symlink_commands_plan/commands" "$workdir/external-commands"
ln -s "$workdir/external-commands" "$symlink_commands_plan/commands"
if campaign_manifest_write "$symlink_commands_plan"; then
    printf 'canonical manifest was recomputed across a symlinked commands directory\n' >&2
    exit 1
fi
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$symlink_commands_plan"; then
    printf 'large-surface status accepted a symlinked commands directory with a recomputed manifest\n' >&2
    exit 1
fi
unknown_node_plan="$workdir/unknown-node-plan"
cp -a "$plan_dir" "$unknown_node_plan"
mkdir "$unknown_node_plan/operator-added"
if campaign_manifest_write "$unknown_node_plan"; then
    printf 'canonical manifest accepted an unknown directory node\n' >&2
    exit 1
fi
special_node_plan="$workdir/special-node-plan"
cp -a "$plan_dir" "$special_node_plan"
mkfifo "$special_node_plan/operator.fifo"
if campaign_manifest_write "$special_node_plan"; then
    printf 'canonical manifest accepted a special node\n' >&2
    exit 1
fi
ln -s "$plan_dir" "$workdir/symlink-plan-root"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$workdir/symlink-plan-root"; then
    printf 'large-surface status accepted a symlinked plan root\n' >&2
    exit 1
fi
mkdir "$workdir/real-plan-ancestor"
cp -a "$plan_dir" "$workdir/real-plan-ancestor/plan"
ln -s "$workdir/real-plan-ancestor" "$workdir/symlink-plan-ancestor"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status \
    --evidence-dir "$workdir/symlink-plan-ancestor/plan"; then
    printf 'large-surface status accepted a plan through a symlinked ancestor\n' >&2
    exit 1
fi
writable_plan="$workdir/world-writable-plan"
cp -a "$plan_dir" "$writable_plan"
chmod 0777 "$writable_plan/commands"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$writable_plan"; then
    printf 'large-surface status accepted a world-writable command directory\n' >&2
    exit 1
fi
symlink_remotes_plan="$workdir/symlink-remotes-plan"
cp -a "$plan_dir" "$symlink_remotes_plan"
mkdir "$workdir/collection-victim"
ln -s "$workdir/collection-victim" "$symlink_remotes_plan/remotes"
rm -f "$workdir/rsync-invoked"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'touch "$RSYNC_INVOKED"' 'exit 0' >"$workdir/fakebin/rsync"
chmod +x "$workdir/fakebin/rsync"
if PATH="$workdir/fakebin:$PATH" RSYNC_INVOKED="$workdir/rsync-invoked" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" collect --evidence-dir "$symlink_remotes_plan"; then
    printf 'large-surface collect accepted a symlinked remotes directory\n' >&2
    exit 1
fi
[[ ! -e "$workdir/rsync-invoked" ]]
large_unit_plan="$workdir/large-unit-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$large_unit_plan" --campaign-id unit-test --host h1 --duration 60
awk -F '\t' 'BEGIN { OFS="\t" } NR == 2 { $3="borondns-soak-unit-test-wrong.service" } { print }' \
    "$large_unit_plan/assignments.tsv" >"$large_unit_plan/assignments.tsv.mutated"
mv "$large_unit_plan/assignments.tsv.mutated" "$large_unit_plan/assignments.tsv"
campaign_manifest_write "$large_unit_plan"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$large_unit_plan"; then
    printf 'large-surface status accepted a wrong valid-looking unit identity\n' >&2
    exit 1
fi
large_duplicate_plan="$workdir/large-duplicate-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$large_duplicate_plan" --campaign-id duplicate-test --host h1 --host h2 --duration 60
awk -F '\t' 'BEGIN { OFS="\t" } NR == 3 { $1="h1" } { print }' \
    "$large_duplicate_plan/assignments.tsv" >"$large_duplicate_plan/assignments.tsv.mutated"
mv "$large_duplicate_plan/assignments.tsv.mutated" "$large_duplicate_plan/assignments.tsv"
campaign_manifest_write "$large_duplicate_plan"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$large_duplicate_plan"; then
    printf 'large-surface status accepted duplicate h1 with omitted h2\n' >&2
    exit 1
fi
semantic_plan="$workdir/semantic-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$semantic_plan" --campaign-id semantic-test --host fake-host --duration 60
sed -i '2s/^fake-host/host0-injection/' "$semantic_plan/assignments.tsv"
campaign_manifest_write "$semantic_plan"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$semantic_plan"; then
    printf 'large-surface status accepted an authenticated assignment host injection\n' >&2
    exit 1
fi

concurrent_remote_repo="$workdir/concurrent-remote-repo"
concurrent_remote_evidence="$workdir/concurrent-remote-evidence"
concurrent_plan="$workdir/concurrent-plan"
concurrent_state="$workdir/concurrent-state"
concurrent_bin="$workdir/concurrent-bin"
remove_readonly_test_tree /var/tmp/borondns-large-concurrent-resume
git clone -q --no-hardlinks "$repo_root" "$concurrent_remote_repo"
materialize_campaign_helpers "$concurrent_remote_repo"
mkdir -p "$concurrent_state/units" "$concurrent_bin"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$concurrent_plan" --campaign-id concurrent-resume --host fake-host \
    --remote-repo "$concurrent_remote_repo" --remote-evidence "$concurrent_remote_evidence" --duration 60
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'case "${1:-}" in' \
    'show) unit="$2"; fragment="$CONCURRENT_STATE/units/$unit"; if test -e "$CONCURRENT_STATE/active"; then runner="$(sed -n "s/^ExecStart=//p" "$fragment")"; printf "LoadState=loaded\nActiveState=active\nFragmentPath=%s\nExecStart={ path=%s ; }\n" "$fragment" "$runner"; else printf "LoadState=not-found\nActiveState=inactive\nFragmentPath=\nExecStart=\n"; fi ;;' \
    'start) count=0; test ! -f "$CONCURRENT_STATE/start-count" || read -r count <"$CONCURRENT_STATE/start-count"; printf "%s\n" "$((count + 1))" >"$CONCURRENT_STATE/start-count"; sleep 1; touch "$CONCURRENT_STATE/active" ;;' \
    '*) exit 0 ;;' \
    'esac' >"$concurrent_bin/systemctl"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'if [[ "${1:-}" == tee ]]; then cat >"$2"; exit 0; fi' \
    'case "${1:-}" in install|chown|chmod|rm|mkdir|mktemp|mv|cmp|ln|python3) exec /usr/bin/sudo -n "$@" ;; esac' \
    'exec "$@"' >"$concurrent_bin/sudo"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$concurrent_bin/docker"
chmod +x "$concurrent_bin/systemctl" "$concurrent_bin/sudo" "$concurrent_bin/docker"
concurrent_command="$concurrent_plan/commands/fake-host-launch.sh"
PATH="$concurrent_bin:$PATH" CONCURRENT_STATE="$concurrent_state" BORONDNS_CAMPAIGN_UNIT_ROOT="$concurrent_state/units" BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 \
    "$concurrent_command" >"$workdir/concurrent-one.log" 2>&1 &
concurrent_one=$!
PATH="$concurrent_bin:$PATH" CONCURRENT_STATE="$concurrent_state" BORONDNS_CAMPAIGN_UNIT_ROOT="$concurrent_state/units" BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 \
    "$concurrent_command" >"$workdir/concurrent-two.log" 2>&1 &
concurrent_two=$!
set +e
wait "$concurrent_one"
concurrent_one_status=$?
wait "$concurrent_two"
concurrent_two_status=$?
set -e
if ((concurrent_one_status == 0 && concurrent_two_status == 0)) ||
    ((concurrent_one_status != 0 && concurrent_two_status != 0)); then
    cat "$workdir/concurrent-one.log" "$workdir/concurrent-two.log" >&2
    printf 'concurrent launch did not admit exactly one lock owner\n' >&2
    exit 1
fi
cat "$workdir/concurrent-one.log" "$workdir/concurrent-two.log" |
    grep -Fq 'another process holds remote large-soak campaign lock'
grep -Fqx '1' "$concurrent_state/start-count"
concurrent_runner="$(find "$concurrent_remote_evidence/launch/borondns-soak-concurrent-resume-fake-host-attempts" \
    -mindepth 2 -maxdepth 2 -type f -name run.sh | head -1)"
# The first-stage remote script must render a real variable reference into the
# systemd runner, not a backslash-literal placeholder.
# shellcheck disable=SC2016
grep -Fq 'export CARGO_TARGET_DIR="$build_dir"' "$concurrent_runner"
immutable_source="$(find /var/tmp/borondns-large-concurrent-resume/fake-host -mindepth 1 -maxdepth 1 -type d -name 'source-*' -print -quit)"
immutable_probe="$immutable_source/Cargo.toml"
[[ "$(stat -c %u "$immutable_source")" == 0 && "$(stat -c %u "$(dirname "$immutable_source")")" == 0 ]]
if chmod u+w "$immutable_probe" 2>/dev/null || printf '\n# hostile edit\n' >>"$immutable_probe" 2>/dev/null; then
    printf 'campaign UID mutated the root-owned large-soak source snapshot\n' >&2
    exit 1
fi
if mv "$immutable_source" "$immutable_source.replaced" 2>/dev/null; then
    printf 'campaign UID replaced the root-owned large-soak source snapshot entry\n' >&2
    exit 1
fi
immutable_runtime_link="$immutable_source/target"
immutable_runtime="$(realpath -e "$immutable_runtime_link")"
[[ -L "$immutable_runtime_link" && "$(stat -c %u "$immutable_runtime_link")" == 0 ]]
[[ "$immutable_runtime" == /var/tmp/borondns-large-concurrent-resume/fake-host/targets/target.* ]]
printf 'writable runtime sentinel\n' >"$immutable_runtime/interop-runtime-sentinel"
grep -Fqx 'writable runtime sentinel' "$immutable_source/target/interop-runtime-sentinel"
authenticated_tool_dir="$(find /var/tmp/borondns-large-concurrent-resume/fake-host -mindepth 1 -maxdepth 1 \
    -type d -name 'tools-attempt.*' -print -quit)"
[[ -d "$authenticated_tool_dir" && "$(stat -c %u "$authenticated_tool_dir")" == 0 &&
"$(stat -c %a "$authenticated_tool_dir")" == 555 ]]
[[ -L "$authenticated_tool_dir/cargo" && "$(readlink "$authenticated_tool_dir/cargo")" == /proc/self/fd/7 ]]

fd_tool_fixture="$workdir/fd-tool-fixture"
mkdir -p "$fd_tool_fixture/exact" "$fd_tool_fixture/poison"
# shellcheck disable=SC2016
printf '#!/usr/bin/env bash\nprintf trusted >"$FD_TOOL_LOG"\n' >"$fd_tool_fixture/trusted-cargo"
# shellcheck disable=SC2016
printf '#!/usr/bin/env bash\nprintf poison >"$FD_TOOL_LOG"\n' >"$fd_tool_fixture/poison/cargo"
chmod +x "$fd_tool_fixture/trusted-cargo" "$fd_tool_fixture/poison/cargo"
(
    exec 7<"$fd_tool_fixture/trusted-cargo"
    ln -s /proc/self/fd/7 "$fd_tool_fixture/exact/cargo"
    FD_TOOL_LOG="$fd_tool_fixture/result" PATH="$fd_tool_fixture/exact:$fd_tool_fixture/poison:/usr/bin:/bin" cargo
)
grep -Fqx trusted "$fd_tool_fixture/result"
remove_readonly_test_tree /var/tmp/borondns-large-concurrent-resume
partial_plan="$workdir/partial-plan"
mkdir -p "$partial_plan"
cp "$plan_dir/campaign.env" "$partial_plan/campaign.env"
if "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$partial_plan"; then
    printf 'large-surface status accepted an incomplete plan\n' >&2
    exit 1
fi

# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$*" >"$FAKE_SSH_LOG"' \
    'case "$*" in *"systemctl is-active"*) [[ "${FAKE_SSH_ACTIVE:-0}" == 1 ]] && exit 0 || exit 1 ;; *"test -f"*|*"test -s"*) [[ "${FAKE_SSH_RESULTS_MISSING:-0}" == 1 ]] && exit 1 || exit 0 ;; esac' \
    '[[ -z "${MUTATE_SAVED_COMMAND:-}" ]] || printf "#!/usr/bin/env bash\nprintf pinned-plan-race-won\n" >"$MUTATE_SAVED_COMMAND"' \
    'cat >"$FAKE_SSH_STDIN"' \
    >"$workdir/fakebin/ssh"
chmod +x "$workdir/fakebin/ssh"
PATH="$workdir/fakebin:$PATH" FAKE_SSH_LOG="$workdir/ssh.log" FAKE_SSH_STDIN="$workdir/ssh.stdin" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" resume --evidence-dir "$plan_dir"
grep -Fq 'BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 bash -s' "$workdir/ssh.log"
# This is a literal fragment of the generated remote script.
# shellcheck disable=SC2016
grep -Fq 'remote_lock_root="/tmp/borondns-campaign-locks-$(id -u)"' "$workdir/ssh.stdin"
grep -Fq -- '--resume' "$workdir/ssh.stdin"
PATH="$workdir/fakebin:$PATH" FAKE_SSH_LOG="$workdir/ssh.log" FAKE_SSH_STDIN="$workdir/ssh.stdin" \
    FAKE_SSH_RESULTS_MISSING=1 "$repo_root/scripts/large-surface-soak-campaign.sh" resume \
    --evidence-dir "$plan_dir"
grep -Fq 'expected_commit=' "$workdir/ssh.stdin"
head -1 "$workdir/ssh.stdin" | grep -Fqx '#!/usr/bin/env bash'
pin_plan="$workdir/pin-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$pin_plan" --campaign-id pin-test --host fake-host --duration 60
PATH="$workdir/fakebin:$PATH" FAKE_SSH_LOG="$workdir/ssh.log" FAKE_SSH_STDIN="$workdir/pin-ssh.stdin" \
    MUTATE_SAVED_COMMAND="$pin_plan/commands/fake-host-launch.sh" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" resume --evidence-dir "$pin_plan"
grep -Fq pinned-plan-race-won "$pin_plan/commands/fake-host-launch.sh"
if grep -Fq pinned-plan-race-won "$workdir/pin-ssh.stdin"; then
    printf 'resume executed a saved command replaced after validation\n' >&2
    exit 1
fi
if PATH="$workdir/fakebin:$PATH" FAKE_SSH_LOG="$workdir/ssh.log" FAKE_SSH_STDIN="$workdir/ssh.stdin" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" resume \
    --evidence-dir "$plan_dir" --duration 61; then
    printf 'resume accepted a campaign parameter override\n' >&2
    exit 1
fi

fuzz_existing="$workdir/fuzz-existing"
mkdir -p "$fuzz_existing"
printf 'operator sentinel\n' >"$fuzz_existing/sentinel.txt"
if BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    "$repo_root/scripts/fuzz-campaign.sh" --dry-run --duration 1 --target dns_datagram \
    --evidence-dir "$fuzz_existing"; then
    printf 'fuzz runner accepted a non-empty evidence directory\n' >&2
    exit 1
fi
grep -Fqx 'operator sentinel' "$fuzz_existing/sentinel.txt"
[[ ! -e "$fuzz_existing/campaign-summary.tsv" ]]

duplicate_fuzz_evidence="$workdir/duplicate-fuzz-evidence"
duplicate_fuzz_build="$workdir/duplicate-fuzz-build"
if BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 CARGO_TARGET_DIR="$duplicate_fuzz_build" \
    "$repo_root/scripts/fuzz-campaign.sh" \
    --dry-run --duration 1 --target dns_datagram --target dns_datagram \
    --evidence-dir "$duplicate_fuzz_evidence"; then
    printf 'fuzz runner accepted duplicate target identities\n' >&2
    exit 1
fi
[[ ! -e "$duplicate_fuzz_evidence" && ! -e "$duplicate_fuzz_build" ]]

fuzz_symlink_victim="$workdir/fuzz-symlink-victim"
mkdir "$fuzz_symlink_victim"
ln -s "$fuzz_symlink_victim" "$workdir/fuzz-symlink-evidence"
if BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    "$repo_root/scripts/fuzz-campaign.sh" --dry-run --duration 1 --target dns_datagram \
    --evidence-dir "$workdir/fuzz-symlink-evidence"; then
    printf 'fuzz runner accepted a symlinked evidence directory\n' >&2
    exit 1
fi
[[ -z "$(find "$fuzz_symlink_victim" -mindepth 1 -print -quit)" ]]
fuzz_build_victim="$workdir/fuzz-build-victim"
mkdir "$fuzz_build_victim"
ln -s "$fuzz_build_victim" "$workdir/fuzz-build-link"
if BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 CARGO_TARGET_DIR="$workdir/fuzz-build-link" \
    "$repo_root/scripts/fuzz-campaign.sh" \
    --dry-run --duration 1 --target dns_datagram --evidence-dir "$workdir/fuzz-build-evidence"; then
    printf 'fuzz runner accepted a symlinked build directory\n' >&2
    exit 1
fi
[[ -z "$(find "$fuzz_build_victim" -mindepth 1 -print -quit)" ]]

poison_repo="$workdir/poison-repo"
git clone -q --no-hardlinks "$repo_root" "$poison_repo"
materialize_campaign_helpers "$poison_repo"
cp "$repo_root/scripts/fuzz-campaign.sh" "$poison_repo/scripts/fuzz-campaign.sh"
cp "$repo_root/scripts/campaign-env.sh" "$poison_repo/scripts/campaign-env.sh"
cp "$repo_root/scripts/campaign-lock-helper.py" "$poison_repo/scripts/campaign-lock-helper.py"
git -C "$poison_repo" add -f scripts/fuzz-campaign.sh scripts/campaign-env.sh scripts/campaign-lock-helper.py
git -C "$poison_repo" -c user.name=BoronDNS -c user.email=tests@borondns.invalid \
    commit -qm 'materialize current fuzz campaign harness' --allow-empty
mkdir -p "$poison_repo/target" "$poison_repo/fuzz/target" "$workdir/poison-build" "$workdir/poison-evidence" "$workdir/poison-bin" "$workdir/trusted-fuzz-bin"
touch "$poison_repo/target/operator-sentinel" "$poison_repo/fuzz/target/operator-sentinel"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "fake cargo %s\\n" "$*"' \
    'if [[ "${1:-}" == fuzz ]]; then shift; exec cargo-fuzz "$@"; fi' 'exit 0' >"$workdir/poison-bin/cargo"
printf '%s\n' '#!/usr/bin/env bash' 'printf "fake rustc %s\\n" "$*"' 'exit 0' \
    >"$workdir/poison-bin/rustc"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "malicious\\n" >>"$MALICIOUS_FUZZ_LOG"' 'exit 99' \
    >"$workdir/poison-bin/cargo-fuzz"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "trusted %s\\n" "$*" >>"$TRUSTED_FUZZ_LOG"' \
    '[[ "${MUTATE_FUZZ_SOURCE:-0}" != 1 || "${1:-}" != run ]] || printf "mutation\\n" >"$MUTATE_FUZZ_REPO/source-mutation"' \
    'for argument in "$@"; do case "$argument" in -artifact_prefix=*) artifact_dir="${argument#*=}"; mkdir -p "$artifact_dir/nested-controls"; printf "nested fuzz completion\\n" >"$artifact_dir/nested-controls/campaign-completed.env"; printf "nested fuzz manifest\\n" >"$artifact_dir/nested-controls/artifact-manifest.sha256" ;; esac; done' \
    'if [[ "${REPLACE_FUZZ_BUILD_ON_RUN:-0}" == 1 && "${1:-}" == run ]]; then mv "$CARGO_TARGET_DIR" "$CARGO_TARGET_DIR.original"; mkdir -m 0700 "$CARGO_TARGET_DIR"; mv "$CARGO_TARGET_DIR.original"/.authenticated-rust-tools.* "$CARGO_TARGET_DIR/"; printf "replacement must survive\\n" >"$CARGO_TARGET_DIR/sentinel"; fi' \
    '[[ "${1:-}" == --version ]] || sleep "${TRUSTED_FUZZ_SLEEP_SECONDS:-1}"' \
    'exit 0' \
    >"$workdir/trusted-fuzz-bin/cargo-fuzz"
chmod +x "$workdir/poison-bin/cargo" "$workdir/poison-bin/rustc" \
    "$workdir/poison-bin/cargo-fuzz" "$workdir/trusted-fuzz-bin/cargo-fuzz"
PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/trusted-cargo-fuzz.log" MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" \
    CARGO_TARGET_DIR="$workdir/poison-build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$workdir/poison-evidence"
grep -Fqx "cargo_target_dir=$workdir/poison-build" "$workdir/poison-evidence/config.txt"
grep -Fqx "cargo_path=$(realpath -e "$workdir/poison-bin/cargo")" "$workdir/poison-evidence/tool-versions.txt"
grep -Fqx "cargo_sha256=$(sha256sum "$workdir/poison-bin/cargo" | awk '{ print $1 }')" \
    "$workdir/poison-evidence/tool-versions.txt"
[[ -f "$workdir/poison-evidence/build-artifacts.sha256" ]]
[[ -f "$workdir/poison-evidence/artifact-manifest.sha256" ]]
grep -Fqx status=passed "$workdir/poison-evidence/campaign-completed.env"
grep -Fqx "summary_sha256=$(sha256sum "$workdir/poison-evidence/campaign-summary.tsv" | awk '{ print $1 }')" \
    "$workdir/poison-evidence/campaign-completed.env"
grep -Fqx "artifact_manifest_sha256=$(sha256sum "$workdir/poison-evidence/artifact-manifest.sha256" | awk '{ print $1 }')" \
    "$workdir/poison-evidence/campaign-completed.env"
grep -Fq 'artifacts/dns_datagram/nested-controls/campaign-completed.env' \
    "$workdir/poison-evidence/artifact-manifest.sha256"
grep -Fq 'artifacts/dns_datagram/nested-controls/artifact-manifest.sha256' \
    "$workdir/poison-evidence/artifact-manifest.sha256"
[[ -f "$poison_repo/target/operator-sentinel" && -f "$poison_repo/fuzz/target/operator-sentinel" ]]
[[ -s "$workdir/trusted-cargo-fuzz.log" && ! -e "$workdir/malicious-cargo-fuzz.log" ]]
grep -Fqx "cargo_fuzz_executed_sha256=$(sha256sum "$workdir/trusted-fuzz-bin/cargo-fuzz" | awk '{ print $1 }')" \
    "$workdir/poison-evidence/config.txt"

fuzz_cleanup_failure_evidence="$workdir/fuzz-cleanup-failure-evidence"
fuzz_cleanup_tmp="$workdir/fuzz-cleanup-tmp"
mkdir -m 0700 "$fuzz_cleanup_tmp"
set +e
PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/fuzz-cleanup-trusted.log" \
    MALICIOUS_FUZZ_LOG="$workdir/fuzz-cleanup-malicious.log" \
    TMPDIR="$fuzz_cleanup_tmp" REPLACE_FUZZ_BUILD_ON_RUN=1 \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$fuzz_cleanup_failure_evidence"
fuzz_cleanup_status=$?
set -e
[[ "$fuzz_cleanup_status" == 74 ]]
[[ ! -e "$fuzz_cleanup_failure_evidence/campaign-completed.env" ]]
[[ -s "$fuzz_cleanup_failure_evidence/build-artifacts.sha256" ]]
[[ -s "$fuzz_cleanup_failure_evidence/artifact-manifest.sha256" ]]
grep -Fq $'dns_datagram\tpassed\t0\t' "$fuzz_cleanup_failure_evidence/campaign-summary.tsv"
fuzz_cleanup_path="$(sed -n 's/^cargo_target_dir=//p' "$fuzz_cleanup_failure_evidence/config.txt")"
[[ -n "$fuzz_cleanup_path" ]]
grep -Fqx 'replacement must survive' "$fuzz_cleanup_path/sentinel"
[[ -d "$fuzz_cleanup_path.original" ]]

fuzz_missing_cleanup_evidence="$workdir/fuzz-missing-cleanup-evidence"
cp -a "$workdir/poison-evidence" "$fuzz_missing_cleanup_evidence"
rm -f "$fuzz_missing_cleanup_evidence/campaign-completed.env"
fuzz_missing_tmp="$workdir/fuzz-missing-cleanup-tmp"
mkdir -m 0700 "$fuzz_missing_tmp"
fuzz_library="$poison_repo/scripts/fuzz-campaign-library.sh"
sed '$d' "$poison_repo/scripts/fuzz-campaign.sh" >"$fuzz_library"
fuzz_missing_path_file="$workdir/fuzz-missing-cleanup-path"
if (
    # shellcheck source=/dev/null
    source "$fuzz_library"
    evidence_dir="$fuzz_missing_cleanup_evidence"
    # Read indirectly by finalize_campaign_evidence from the sourced library.
    # shellcheck disable=SC2034
    selected_targets=(dns_datagram)
    dry_run=0
    # Read indirectly by finalize_campaign_evidence from the sourced library.
    # shellcheck disable=SC2034
    release_eligible=1
    fuzz_missing_build=""
    campaign_prepare_private_temporary_tree "$fuzz_missing_tmp" round51-fuzz-finalize-missing \
        fuzz_auto_build fuzz_missing_build
    cargo_target_dir_auto=1
    cargo_target_dir="$fuzz_missing_build"
    printf '%s\n' "$fuzz_missing_build" >"$fuzz_missing_path_file"
    printf 'renamed fuzz build must survive\n' >"$fuzz_missing_build/sentinel"
    mv "$fuzz_missing_build" "$fuzz_missing_build.renamed"
    trap finalize_campaign_evidence EXIT
); then
    printf 'fuzz finalizer accepted a renamed-away automatic build root\n' >&2
    exit 1
fi
fuzz_missing_path="$(<"$fuzz_missing_path_file")"
[[ ! -e "$fuzz_missing_cleanup_evidence/campaign-completed.env" ]]
grep -Fqx 'renamed fuzz build must survive' "$fuzz_missing_path.renamed/sentinel"
rm -f "$fuzz_library"

# Cargo and rustc are snapshotted through opened descriptors before any
# preflight command executes. Replacing their selected pathnames concurrently
# must neither change the bytes executed nor make the retained digests lie.
drift_fuzz_bin="$workdir/drift-fuzz-bin"
drift_fuzz_build="$workdir/drift-fuzz-build"
drift_fuzz_evidence="$workdir/drift-fuzz-evidence"
drift_fuzz_state="$workdir/drift-fuzz-mutated"
mkdir "$drift_fuzz_bin" "$drift_fuzz_build"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ ! -e "$DRIFT_FUZZ_STATE" ]]; then' \
    '  touch "$DRIFT_FUZZ_STATE"' \
    '  printf "#!/usr/bin/env bash\\nprintf malicious-cargo >>\\\"\\$DRIFT_MALICIOUS_LOG\\\"\\nexit 91\\n" >"$DRIFT_FUZZ_BIN/cargo"' \
    '  printf "#!/usr/bin/env bash\\nprintf malicious-rustc >>\\\"\\$DRIFT_MALICIOUS_LOG\\\"\\nexit 92\\n" >"$DRIFT_FUZZ_BIN/rustc"' \
    'fi' \
    'printf "snapshotted cargo %s\\n" "$*" >>"$DRIFT_TRUSTED_LOG"' \
    'if [[ "${1:-}" == fuzz ]]; then shift; exec cargo-fuzz "$@"; fi' \
    'exit 0' >"$drift_fuzz_bin/cargo"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'printf "snapshotted rustc %s\\n" "$*" >>"$DRIFT_TRUSTED_LOG"' \
    'exit 0' >"$drift_fuzz_bin/rustc"
chmod +x "$drift_fuzz_bin/cargo" "$drift_fuzz_bin/rustc"
drift_cargo_digest="$(sha256sum "$drift_fuzz_bin/cargo" | awk '{ print $1 }')"
drift_rustc_digest="$(sha256sum "$drift_fuzz_bin/rustc" | awk '{ print $1 }')"
PATH="$workdir/trusted-fuzz-bin:$drift_fuzz_bin:$PATH" CARGO="$drift_fuzz_bin/cargo" \
    DRIFT_FUZZ_BIN="$drift_fuzz_bin" DRIFT_FUZZ_STATE="$drift_fuzz_state" \
    DRIFT_TRUSTED_LOG="$workdir/drift-trusted.log" DRIFT_MALICIOUS_LOG="$workdir/drift-malicious.log" \
    TRUSTED_FUZZ_LOG="$workdir/drift-cargo-fuzz.log" CARGO_TARGET_DIR="$drift_fuzz_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$drift_fuzz_evidence"
grep -Fqx "cargo_executed_sha256=$drift_cargo_digest" "$drift_fuzz_evidence/config.txt"
grep -Fqx "rustc_executed_sha256=$drift_rustc_digest" "$drift_fuzz_evidence/config.txt"
[[ "$(sha256sum "$drift_fuzz_bin/cargo" | awk '{ print $1 }')" != "$drift_cargo_digest" ]]
[[ "$(sha256sum "$drift_fuzz_bin/rustc" | awk '{ print $1 }')" != "$drift_rustc_digest" ]]
grep -Fq 'snapshotted cargo fuzz run' "$workdir/drift-trusted.log"
grep -Fq 'snapshotted rustc --version' "$workdir/drift-trusted.log"
[[ ! -e "$workdir/drift-malicious.log" ]]
grep -Fqx status=passed "$drift_fuzz_evidence/campaign-completed.env"

runtime_drift_root="$workdir/runtime-drift-toolchain"
runtime_drift_bin="$runtime_drift_root/bin"
runtime_drift_lib="$runtime_drift_root/lib"
runtime_drift_build="$workdir/runtime-drift-build"
runtime_drift_evidence="$workdir/runtime-drift-evidence"
mkdir -p "$runtime_drift_bin" "$runtime_drift_lib/rustlib" "$runtime_drift_build"
printf 'runtime-old\n' >"$runtime_drift_lib/librustc_driver-fixture.so"
printf 'sysroot-old\n' >"$runtime_drift_lib/rustlib/sysroot-fixture"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ ! -e "$RUNTIME_DRIFT_STATE" ]]; then' \
    '  touch "$RUNTIME_DRIFT_STATE"' \
    '  printf "runtime-new\\n" >"$RUNTIME_DRIFT_SOURCE_LIB/librustc_driver-fixture.so"' \
    '  printf "sysroot-new\\n" >"$RUNTIME_DRIFT_SOURCE_LIB/rustlib/sysroot-fixture"' \
    'fi' \
    'if [[ "${1:-}" == fuzz ]]; then shift; exec cargo-fuzz "$@"; fi' \
    'exit 0' >"$runtime_drift_bin/cargo"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'tool_root="$(cd "$(dirname "$0")/.." && pwd)"' \
    'cat "$tool_root/lib/librustc_driver-fixture.so" >>"$RUNTIME_DRIFT_LOG"' \
    'cat "$tool_root/lib/rustlib/sysroot-fixture" >>"$RUNTIME_DRIFT_LOG"' \
    'exit 0' >"$runtime_drift_bin/rustc"
chmod +x "$runtime_drift_bin/cargo" "$runtime_drift_bin/rustc"
runtime_tree_digest="$(
    (
        cd "$runtime_drift_lib"
        find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum -b -z
    ) | sha256sum | awk '{ print $1 }'
)"
PATH="$workdir/trusted-fuzz-bin:$runtime_drift_bin:$PATH" CARGO="$runtime_drift_bin/cargo" \
    RUNTIME_DRIFT_STATE="$workdir/runtime-drift-mutated" \
    RUNTIME_DRIFT_SOURCE_LIB="$runtime_drift_lib" RUNTIME_DRIFT_LOG="$workdir/runtime-drift.log" \
    TRUSTED_FUZZ_LOG="$workdir/runtime-drift-cargo-fuzz.log" CARGO_TARGET_DIR="$runtime_drift_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$runtime_drift_evidence"
grep -Fqx "rustc_runtime_tree_sha256=$runtime_tree_digest" "$runtime_drift_evidence/config.txt"
grep -Fqx runtime-old "$workdir/runtime-drift.log"
grep -Fqx sysroot-old "$workdir/runtime-drift.log"
if grep -Eq 'runtime-new|sysroot-new' "$workdir/runtime-drift.log"; then
    printf 'fuzz runner loaded a concurrently replaced rustc runtime tree\n' >&2
    exit 1
fi

immediate_fuzz_build="$workdir/immediate-fuzz-build"
immediate_fuzz_evidence="$workdir/immediate-fuzz-evidence"
mkdir "$immediate_fuzz_build"
if PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_SLEEP_SECONDS=0 TRUSTED_FUZZ_LOG="$workdir/immediate-cargo-fuzz.log" \
    MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" CARGO_TARGET_DIR="$immediate_fuzz_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$immediate_fuzz_evidence"; then
    printf 'fuzz runner accepted an immediate zero-exit target as a completed duration\n' >&2
    exit 1
fi
grep -Fq $'dns_datagram\tfailed\t70\t1\t' "$immediate_fuzz_evidence/campaign-summary.tsv"
[[ ! -e "$immediate_fuzz_evidence/campaign-completed.env" ]]

dirty_fuzz_build="$workdir/dirty-fuzz-build"
dirty_fuzz_evidence="$workdir/dirty-fuzz-evidence"
dirty_fuzz_ci_evidence="$workdir/dirty-fuzz-ci-evidence"
dirty_fuzz_dry_build="$workdir/dirty-fuzz-dry-build"
dirty_fuzz_dry_evidence="$workdir/dirty-fuzz-dry-evidence"
mkdir "$dirty_fuzz_build"
mkdir "$dirty_fuzz_dry_build"
printf 'untracked fuzz mutation\n' >"$poison_repo/untracked-fuzz-input"
PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/dirty-fuzz-dry.log" MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" \
    CARGO_TARGET_DIR="$dirty_fuzz_dry_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --dry-run --duration 1 --target dns_datagram \
    --evidence-dir "$dirty_fuzz_dry_evidence" >"$workdir/dirty-fuzz-dry.stderr" 2>&1
grep -Fq 'dirty-source fuzz dry-run evidence is non-release validation only' "$workdir/dirty-fuzz-dry.stderr"
grep -Fqx source_clean=0 "$dirty_fuzz_dry_evidence/config.txt"
grep -Fqx release_eligible=0 "$dirty_fuzz_dry_evidence/config.txt"
grep -Fqx dirty_source_override=0 "$dirty_fuzz_dry_evidence/config.txt"
grep -Fqx status=dry-run "$dirty_fuzz_dry_evidence/campaign-completed.env"
grep -Fq $'dns_datagram\tdry-run\t0\t' "$dirty_fuzz_dry_evidence/campaign-summary.tsv"
[[ ! -e "$dirty_fuzz_dry_evidence/logs/dns_datagram.log" ]]
if grep -Fq 'trusted run ' "$workdir/dirty-fuzz-dry.log"; then
    printf 'dirty fuzz dry-run executed its target\n' >&2
    exit 1
fi
if PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/dirty-fuzz-default.log" MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" \
    CARGO_TARGET_DIR="$dirty_fuzz_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$dirty_fuzz_evidence" >"$workdir/dirty-fuzz-default.stderr" 2>&1; then
    printf 'fuzz campaign accepted dirty source by default\n' >&2
    exit 1
fi
grep -Fq 'refusing fuzz campaign from dirty or untracked source' "$workdir/dirty-fuzz-default.stderr"
[[ ! -e "$dirty_fuzz_evidence" ]]

if GITHUB_ACTIONS=true BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/dirty-fuzz-ci.log" MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" \
    CARGO_TARGET_DIR="$dirty_fuzz_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$dirty_fuzz_ci_evidence" >"$workdir/dirty-fuzz-ci.stderr" 2>&1; then
    printf 'fuzz campaign accepted dirty-source override in CI\n' >&2
    exit 1
fi
grep -Fq 'dirty-source fuzz override is forbidden in CI and release contexts' "$workdir/dirty-fuzz-ci.stderr"
[[ ! -e "$dirty_fuzz_ci_evidence" ]]

set +e
BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/dirty-fuzz-override.log" MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" \
    CARGO_TARGET_DIR="$dirty_fuzz_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$dirty_fuzz_evidence" >"$workdir/dirty-fuzz-override.stderr" 2>&1
dirty_fuzz_status=$?
set -e
[[ "$dirty_fuzz_status" == 2 ]]
grep -Fqx source_clean=0 "$dirty_fuzz_evidence/config.txt"
grep -Fqx release_eligible=0 "$dirty_fuzz_evidence/config.txt"
grep -Fqx dirty_source_override=1 "$dirty_fuzz_evidence/config.txt"
grep -Fqx status=non-release-diagnostic "$dirty_fuzz_evidence/campaign-completed.env"
if grep -Fqx status=passed "$dirty_fuzz_evidence/campaign-completed.env"; then
    printf 'dirty fuzz diagnostic published an authoritative passing marker\n' >&2
    exit 1
fi
rm "$poison_repo/untracked-fuzz-input"

mutated_fuzz_build="$workdir/mutated-fuzz-build"
mutated_fuzz_evidence="$workdir/mutated-fuzz-evidence"
mkdir "$mutated_fuzz_build"
if PATH="$workdir/trusted-fuzz-bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    TRUSTED_FUZZ_LOG="$workdir/mutated-fuzz.log" MALICIOUS_FUZZ_LOG="$workdir/malicious-cargo-fuzz.log" \
    MUTATE_FUZZ_SOURCE=1 MUTATE_FUZZ_REPO="$poison_repo" CARGO_TARGET_DIR="$mutated_fuzz_build" \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$mutated_fuzz_evidence" >"$workdir/mutated-fuzz.stderr" 2>&1; then
    printf 'fuzz campaign accepted source mutation during target execution\n' >&2
    exit 1
fi
grep -Fq 'fuzz source identity changed at after target dns_datagram' "$workdir/mutated-fuzz.stderr"
[[ ! -e "$mutated_fuzz_evidence/campaign-completed.env" ]]
rm "$poison_repo/source-mutation"

bounded_fuzz_bin="$workdir/bounded-fuzz-bin"
bounded_fuzz_build="$workdir/bounded-fuzz-build"
bounded_fuzz_evidence="$workdir/bounded-fuzz-evidence"
mkdir "$bounded_fuzz_bin" "$bounded_fuzz_build"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    '[[ "${1:-}" != --version && "${1:-}" != build ]] || exit 0' \
    'sleep 30' \
    >"$bounded_fuzz_bin/cargo-fuzz"
chmod +x "$bounded_fuzz_bin/cargo-fuzz"
bounded_fuzz_started="$SECONDS"
PATH="$bounded_fuzz_bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    CARGO_TARGET_DIR="$bounded_fuzz_build" BORONDNS_FUZZ_BUILD_TIMEOUT_SECONDS=5 \
    BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS=1 \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$bounded_fuzz_evidence"
((SECONDS - bounded_fuzz_started < 10))
grep -Fqx build_timeout_seconds=5 "$bounded_fuzz_evidence/config.txt"
grep -Fq $'dns_datagram\tpassed\t0\t' "$bounded_fuzz_evidence/campaign-summary.tsv"
grep -Fqx status=passed "$bounded_fuzz_evidence/campaign-completed.env"

preflight_hang_bin="$workdir/preflight-hang-bin"
preflight_hang_evidence="$workdir/preflight-hang-evidence"
preflight_hang_build="$workdir/preflight-hang-build"
mkdir "$preflight_hang_bin" "$preflight_hang_build"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' '[[ "${1:-}" != --version ]] || sleep 300' 'exit 0' \
    >"$preflight_hang_bin/cargo-fuzz"
chmod +x "$preflight_hang_bin/cargo-fuzz"
preflight_hang_started="$SECONDS"
set +e
PATH="$preflight_hang_bin:$workdir/poison-bin:$PATH" CARGO="$workdir/poison-bin/cargo" \
    CARGO_TARGET_DIR="$preflight_hang_build" BORONDNS_FUZZ_PREFLIGHT_TIMEOUT_SECONDS=1 \
    BORONDNS_FUZZ_PREFLIGHT_KILL_AFTER_SECONDS=1 \
    "$poison_repo/scripts/fuzz-campaign.sh" --duration 1 --target dns_datagram \
    --evidence-dir "$preflight_hang_evidence" >/dev/null 2>&1
preflight_hang_status=$?
set -e
[[ "$preflight_hang_status" -ne 0 ]]
((SECONDS - preflight_hang_started < 10))

provenance_bin="$workdir/provenance-bin"
provenance_build="$workdir/provenance-build"
provenance_evidence="$workdir/provenance-evidence"
mkdir "$provenance_bin" "$provenance_build"
printf '%s\n' '#!/usr/bin/env bash' 'printf "selected cargo %s\\n" "$*"' 'exit 0' >"$provenance_bin/selected-cargo"
printf '%s\n' '#!/usr/bin/env bash' 'printf "selected rustc %s\\n" "$*"' 'exit 0' >"$provenance_bin/selected-rustc"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == which ]]; then case "${*: -1}" in cargo) printf "%s\n" "$PROVENANCE_BIN/selected-cargo" ;; rustc) printf "%s\n" "$PROVENANCE_BIN/selected-rustc" ;; esac; exit 0; fi' \
    'printf "fake rustup %s\\n" "$*"' 'exit 0' >"$provenance_bin/rustup"
chmod +x "$provenance_bin/selected-cargo" "$provenance_bin/selected-rustc" "$provenance_bin/rustup"
PATH="$provenance_bin:$PATH" PROVENANCE_BIN="$provenance_bin" CARGO_TARGET_DIR="$provenance_build" \
    BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    "$repo_root/scripts/fuzz-campaign.sh" --toolchain nightly --dry-run --duration 1 \
    --target dns_datagram --evidence-dir "$provenance_evidence"
grep -Fqx "cargo_path=$provenance_bin/selected-cargo" "$provenance_evidence/tool-versions.txt"
grep -Fqx "rustc_path=$provenance_bin/selected-rustc" "$provenance_evidence/tool-versions.txt"
grep -Fqx "cargo_sha256=$(sha256sum "$provenance_bin/selected-cargo" | awk '{ print $1 }')" \
    "$provenance_evidence/tool-versions.txt"
grep -Fqx "rustc_sha256=$(sha256sum "$provenance_bin/selected-rustc" | awk '{ print $1 }')" \
    "$provenance_evidence/tool-versions.txt"
grep -Fqx status=dry-run "$provenance_evidence/campaign-completed.env"
[[ -d "$provenance_build" ]]

automatic_fuzz_tmp="$workdir/automatic-fuzz-tmp"
automatic_fuzz_evidence="$workdir/automatic-fuzz-evidence"
mkdir -m 0700 "$automatic_fuzz_tmp"
TMPDIR="$automatic_fuzz_tmp" PATH="$provenance_bin:$PATH" PROVENANCE_BIN="$provenance_bin" \
    BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    "$repo_root/scripts/fuzz-campaign.sh" --toolchain nightly --dry-run --duration 1 \
    --target dns_datagram --evidence-dir "$automatic_fuzz_evidence"
automatic_fuzz_build="$(sed -n 's/^cargo_target_dir=//p' "$automatic_fuzz_evidence/config.txt")"
[[ "$automatic_fuzz_build" == "$automatic_fuzz_tmp/borondns-fuzz-builds-$(id -u)/run."* ]]
[[ ! -e "$automatic_fuzz_build" ]]
[[ -z "$(find "$automatic_fuzz_tmp/borondns-fuzz-builds-$(id -u)" \
    -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]

automatic_fuzz_failure_tmp="$workdir/automatic-fuzz-failure-tmp"
automatic_fuzz_failure_evidence="$workdir/automatic-fuzz-failure-evidence"
mkdir -m 0700 "$automatic_fuzz_failure_tmp" "$automatic_fuzz_failure_evidence"
printf 'operator-owned evidence\n' >"$automatic_fuzz_failure_evidence/sentinel"
set +e
TMPDIR="$automatic_fuzz_failure_tmp" PATH="$provenance_bin:$PATH" PROVENANCE_BIN="$provenance_bin" \
    BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    "$repo_root/scripts/fuzz-campaign.sh" --toolchain nightly --dry-run --duration 1 \
    --target dns_datagram --evidence-dir "$automatic_fuzz_failure_evidence" >/dev/null 2>&1
automatic_fuzz_failure_status=$?
set -e
[[ "$automatic_fuzz_failure_status" -ne 0 ]]
grep -Fqx 'operator-owned evidence' "$automatic_fuzz_failure_evidence/sentinel"
[[ -z "$(find "$automatic_fuzz_failure_tmp/borondns-fuzz-builds-$(id -u)" \
    -mindepth 1 -maxdepth 1 -name 'run.*' -print -quit)" ]]

provenance_saved_path="$PATH"
PATH="$provenance_bin:$PATH"
PROVENANCE_BIN="$provenance_bin"
export PATH PROVENANCE_BIN
resolve_rust_tools
record_tool_versions "$workdir/large-tool-versions.txt"
PATH="$provenance_saved_path"
unset PROVENANCE_BIN RUSTC
grep -Fqx "cargo_path=$provenance_bin/selected-cargo" "$workdir/large-tool-versions.txt"
grep -Fqx "rustc_path=$provenance_bin/selected-rustc" "$workdir/large-tool-versions.txt"

fuzz_plan_dir="$workdir/fuzz-plan"
fuzz_remote_repo="$workdir/fuzz-remote-repo"
fuzz_remote_evidence="$workdir/fuzz-remote-evidence"
git clone -q --no-hardlinks "$repo_root" "$fuzz_remote_repo"
materialize_campaign_helpers "$fuzz_remote_repo"

for source_preflight_mode in dirty invalid-head; do
    source_preflight_root="$workdir/fuzz-source-preflight-$source_preflight_mode"
    if env -u BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY \
        PATH="$source_preflight_bin:$PATH" FAKE_GIT_HEAD="$source_preflight_head" \
        FAKE_GIT_SOURCE_MODE="$source_preflight_mode" \
        "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
        --evidence-dir "$source_preflight_root/plan" \
        --campaign-id "source-preflight-$source_preflight_mode" \
        --host fake-host --remote-repo "$fuzz_remote_repo" \
        --remote-evidence "$fuzz_remote_evidence" --duration 1 --target dns_datagram; then
        printf 'fuzz planner accepted invalid preflight source: %s\n' \
            "$source_preflight_mode" >&2
        exit 1
    fi
    [[ ! -e "$source_preflight_root" ]]
done

assert_fuzz_plan_rejected_without_writes() {
    local name="$1"
    shift
    local rejected_root="$workdir/round47-fuzz-reject-$name"
    if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
        --evidence-dir "$rejected_root/plan" --campaign-id "valid-$name" \
        --host fake-host --remote-repo "$fuzz_remote_repo" \
        --remote-evidence "$fuzz_remote_evidence" --duration 1 --target dns_datagram "$@"; then
        printf 'fuzz planner accepted invalid canonical field fixture: %s\n' "$name" >&2
        exit 1
    fi
    [[ ! -e "$rejected_root" ]]
}
assert_fuzz_plan_rejected_without_writes unsafe-id --campaign-id '../unsafe'
assert_fuzz_plan_rejected_without_writes relative-repo --remote-repo relative/repo
assert_fuzz_plan_rejected_without_writes noncanonical-remote \
    --remote-evidence "$workdir/round47-fuzz-remote/../escaped"
assert_fuzz_plan_rejected_without_writes unknown-target --target no_such_target
assert_fuzz_plan_rejected_without_writes unsafe-toolchain --toolchain 'nightly;unsafe'
assert_fuzz_plan_rejected_without_writes unsafe-sanitizer --sanitizer 'address unsafe'
if (
    cd "$workdir"
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
        --evidence-dir relative-fuzz-plan --campaign-id relative-evidence \
        --host fake-host --remote-repo "$fuzz_remote_repo" \
        --remote-evidence "$fuzz_remote_evidence" --duration 1 --target dns_datagram
); then
    printf 'fuzz planner accepted a relative evidence path\n' >&2
    exit 1
fi
[[ ! -e "$workdir/relative-fuzz-plan" ]]

for rejected_fuzz_duration in \
    9223372036854775807 \
    "$((9223372036854775807 - $(date +%s)))"; do
    rejected_fuzz_evidence="$workdir/rejected-fuzz-$rejected_fuzz_duration"
    if BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
        "$repo_root/scripts/fuzz-campaign.sh" --list-targets --duration "$rejected_fuzz_duration" \
        --evidence-dir "$rejected_fuzz_evidence" >/dev/null; then
        printf 'direct fuzz runner accepted unsupported duration: %s\n' "$rejected_fuzz_duration" >&2
        exit 1
    fi
    [[ ! -e "$rejected_fuzz_evidence" ]]
done
largest_fuzz_boundary_evidence="$workdir/largest-fuzz-boundary"
BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1 \
    "$repo_root/scripts/fuzz-campaign.sh" --list-targets --duration 9223372036 \
    --evidence-dir "$largest_fuzz_boundary_evidence" >/dev/null
[[ ! -e "$largest_fuzz_boundary_evidence" ]]

for rejected_plan_duration in \
    9223372036854775807 \
    "$((9223372036854775807 - $(date +%s)))"; do
    rejected_plan_dir="$workdir/rejected-fuzz-plan-$rejected_plan_duration"
    if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
        --evidence-dir "$rejected_plan_dir" --campaign-id rejected-timing \
        --host fake-host --remote-repo "$fuzz_remote_repo" --remote-evidence "$fuzz_remote_evidence" \
        --duration "$rejected_plan_duration" --target dns_datagram --no-sampler; then
        printf 'fuzz campaign planner accepted unsupported duration: %s\n' "$rejected_plan_duration" >&2
        exit 1
    fi
    [[ ! -e "$rejected_plan_dir" ]]
done

for fuzz_overflow_case in target-repeat sampler-interval; do
    fuzz_overflow_plan="$workdir/rejected-fuzz-$fuzz_overflow_case-overflow"
    fuzz_overflow_args=(
        plan --evidence-dir "$fuzz_overflow_plan" --campaign-id "rejected-$fuzz_overflow_case"
        --host fake-host --remote-repo "$fuzz_remote_repo" --remote-evidence "$fuzz_remote_evidence"
        --duration 1 --target dns_datagram
    )
    if [[ "$fuzz_overflow_case" == target-repeat ]]; then
        fuzz_overflow_args+=(--target-repeat 9223372036854775808 --no-sampler)
    else
        fuzz_overflow_args+=(--sampler-interval 9223372036854775808)
    fi
    if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" "${fuzz_overflow_args[@]}"; then
        printf 'fuzz campaign planner accepted overflowing %s\n' "$fuzz_overflow_case" >&2
        exit 1
    fi
    [[ ! -e "$fuzz_overflow_plan" ]]
done

fuzz_aggregate_overflow_plan="$workdir/rejected-fuzz-expanded-target-overflow"
fuzz_aggregate_overflow_args=(
    plan --evidence-dir "$fuzz_aggregate_overflow_plan" --campaign-id rejected-expanded-targets
    --host fake-host --remote-repo "$fuzz_remote_repo" --remote-evidence "$fuzz_remote_evidence"
    --duration 1 --target-repeat 1000 --no-sampler
)
for _ in {1..11}; do
    fuzz_aggregate_overflow_args+=(--target dns_datagram)
done
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" "${fuzz_aggregate_overflow_args[@]}"; then
    printf 'fuzz campaign planner accepted an oversized expanded target schedule\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_aggregate_overflow_plan" ]]

largest_fuzz_plan="$workdir/largest-fuzz-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$largest_fuzz_plan" --campaign-id largest-timing \
    --host fake-host --remote-repo "$fuzz_remote_repo" --remote-evidence "$fuzz_remote_evidence" \
    --duration 9223372036 --target dns_datagram --no-sampler
(
    campaign_env_load "$largest_fuzz_plan/campaign.env" \
        campaign_id created_utc repo_root source_commit source_clean remote_repo remote_evidence \
        duration_seconds toolchain sanitizer cargo_sha256 rustc_sha256 cargo_fuzz_sha256 \
        target_repeat sampler_interval_seconds sampler_deadline_epoch_seconds sampler_enabled \
        hosts targets
    [[ "$duration_seconds" == 9223372036 ]]
)

"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_plan_dir" --campaign-id operations-fuzz-test \
    --host fake-host --remote-repo "$fuzz_remote_repo" --remote-evidence "$fuzz_remote_evidence" \
    --duration 1 --target dns_datagram
[[ -f "$fuzz_plan_dir/plan-complete" ]]
[[ -x "$fuzz_plan_dir/validate-collected-campaign.py" ]]
grep -Eq '  validate-collected-campaign\.py$' "$fuzz_plan_dir/campaign-manifest.sha256"
(
    campaign_env_load "$fuzz_plan_dir/campaign.env" \
        campaign_id created_utc repo_root source_commit source_clean remote_repo remote_evidence \
        duration_seconds toolchain sanitizer cargo_sha256 rustc_sha256 cargo_fuzz_sha256 \
        target_repeat sampler_interval_seconds sampler_deadline_epoch_seconds sampler_enabled \
        hosts targets
    fuzz_created_epoch="$(date -u -d "$created_utc" +%s)"
    [[ "$((sampler_deadline_epoch_seconds - fuzz_created_epoch - duration_seconds - 3600))" == 600 ]]
)
fuzz_target_command="$fuzz_plan_dir/commands/fake-host-000-dns_datagram.sh"
grep -Fqx target_setup_reserve_seconds=600 "$fuzz_target_command"
grep -Fqx target_activation_reserve_seconds=300 "$fuzz_target_command"
# These are literal generated-script fragments proving both remote launch gates.
# shellcheck disable=SC2016
grep -Fq 'sampler_deadline_epoch - duration - target_setup_reserve_seconds' "$fuzz_target_command"
# shellcheck disable=SC2016
grep -Fq 'sampler_deadline_epoch - duration - target_activation_reserve_seconds' "$fuzz_target_command"
grep -Fq 'NF >= 6 { printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n"' \
    "$fuzz_plan_dir/commands/fake-host-host-sampler.sh"
if grep -Fq '/launch/' "$fuzz_target_command" ||
    grep -Fq '/launch/' "$fuzz_plan_dir/commands/fake-host-host-sampler.sh"; then
    printf 'fuzz planner still creates an unauthenticated launch evidence directory\n' >&2
    exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'RuntimeMaxSec=$((duration + 3600 + target_setup_reserve_seconds))' "$fuzz_target_command"

expired_fuzz_created_epoch=$(($(date +%s) - 7200))
expired_fuzz_created_utc="$(date -u -d "@$expired_fuzz_created_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
expired_window_bin="$workdir/expired-window-bin"
expired_window_ssh_log="$workdir/expired-window-ssh.log"
expired_window_mutation_log="$workdir/expired-window-mutation.log"
mkdir "$expired_window_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'input="$(mktemp)"; trap '\''rm -f "$input"'\'' EXIT; cat >"$input"' \
    'if [[ "$*" == *BORONDNS_CAMPAIGN_CLASSIFY_ONLY=1* ]]; then if grep -Fq -- "-host-sampler-" "$input"; then printf "sampler\n" >>"$EXPIRED_WINDOW_SSH_LOG"; printf "sampler_resume_classification=%s\n" "$EXPIRED_WINDOW_SAMPLER_CLASSIFICATION"; else printf "target\n" >>"$EXPIRED_WINDOW_SSH_LOG"; printf "target_resume_classification=%s\n" "$EXPIRED_WINDOW_TARGET_CLASSIFICATION"; fi; else printf "mutation\n" >>"$EXPIRED_WINDOW_MUTATION_LOG"; fi' \
    >"$expired_window_bin/ssh"
chmod +x "$expired_window_bin/ssh"
expired_launch_plan="$workdir/expired-fuzz-launch-plan"
if PATH="$expired_window_bin:$PATH" \
    BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 \
    BORONDNS_FUZZ_SOAK_INTERNAL_CREATED_UTC="$expired_fuzz_created_utc" \
    EXPIRED_WINDOW_SSH_LOG="$expired_window_ssh_log" \
    EXPIRED_WINDOW_MUTATION_LOG="$expired_window_mutation_log" \
    EXPIRED_WINDOW_SAMPLER_CLASSIFICATION=active \
    EXPIRED_WINDOW_TARGET_CLASSIFICATION=launch-required \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" launch \
    --evidence-dir "$expired_launch_plan" --campaign-id expired-launch --host fake-host \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$workdir/expired-launch-remote" \
    --duration 1 --target dns_datagram; then
    printf 'fuzz launch accepted an authenticated sampler window too short for a new target\n' >&2
    exit 1
fi
[[ ! -e "$expired_window_ssh_log" && ! -e "$expired_window_mutation_log" ]]

expired_resume_plan="$workdir/expired-fuzz-resume-plan"
BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 \
    BORONDNS_FUZZ_SOAK_INTERNAL_CREATED_UTC="$expired_fuzz_created_utc" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$expired_resume_plan" --campaign-id expired-resume --host fake-host \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$workdir/expired-resume-remote" \
    --duration 1 --target dns_datagram
if PATH="$expired_window_bin:$PATH" \
    BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 \
    EXPIRED_WINDOW_SSH_LOG="$expired_window_ssh_log" \
    EXPIRED_WINDOW_MUTATION_LOG="$expired_window_mutation_log" \
    EXPIRED_WINDOW_SAMPLER_CLASSIFICATION=active \
    EXPIRED_WINDOW_TARGET_CLASSIFICATION=launch-required \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" resume --evidence-dir "$expired_resume_plan"; then
    printf 'fuzz resume launched a new target outside its authenticated sampler window\n' >&2
    exit 1
fi
[[ "$(wc -l <"$expired_window_ssh_log")" == 2 ]]
grep -Fqx sampler "$expired_window_ssh_log"
grep -Fqx target "$expired_window_ssh_log"
[[ ! -e "$expired_window_mutation_log" ]]
rm "$expired_window_ssh_log"
PATH="$expired_window_bin:$PATH" \
    BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 \
    EXPIRED_WINDOW_SSH_LOG="$expired_window_ssh_log" \
    EXPIRED_WINDOW_MUTATION_LOG="$expired_window_mutation_log" \
    EXPIRED_WINDOW_SAMPLER_CLASSIFICATION=active \
    EXPIRED_WINDOW_TARGET_CLASSIFICATION=active \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" resume --evidence-dir "$expired_resume_plan"
[[ "$(wc -l <"$expired_window_ssh_log")" == 2 ]]
[[ ! -e "$expired_window_mutation_log" ]]
for expired_sampler_state in absent failed hard-stopped; do
    rm "$expired_window_ssh_log"
    if PATH="$expired_window_bin:$PATH" \
        BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 \
        EXPIRED_WINDOW_SSH_LOG="$expired_window_ssh_log" \
        EXPIRED_WINDOW_MUTATION_LOG="$expired_window_mutation_log" \
        EXPIRED_WINDOW_SAMPLER_CLASSIFICATION="$expired_sampler_state" \
        EXPIRED_WINDOW_TARGET_CLASSIFICATION=active \
        "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" resume --evidence-dir "$expired_resume_plan"; then
        printf 'expired fuzz resume accepted incompatible sampler state: %s\n' "$expired_sampler_state" >&2
        exit 1
    fi
    [[ "$(wc -l <"$expired_window_ssh_log")" == 2 ]]
    [[ ! -e "$expired_window_mutation_log" ]]
done
rm "$expired_window_ssh_log"
PATH="$expired_window_bin:$PATH" \
    BORONDNS_CAMPAIGN_TEST_ALLOW_DIRTY=1 \
    EXPIRED_WINDOW_SSH_LOG="$expired_window_ssh_log" \
    EXPIRED_WINDOW_MUTATION_LOG="$expired_window_mutation_log" \
    EXPIRED_WINDOW_SAMPLER_CLASSIFICATION=complete \
    EXPIRED_WINDOW_TARGET_CLASSIFICATION=complete \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" resume --evidence-dir "$expired_resume_plan"
[[ "$(wc -l <"$expired_window_ssh_log")" == 2 ]]
[[ ! -e "$expired_window_mutation_log" ]]

fuzz_validator_tamper_plan="$workdir/fuzz-validator-tamper-plan"
cp -a "$fuzz_plan_dir" "$fuzz_validator_tamper_plan"
chmod u+w "$fuzz_validator_tamper_plan/validate-collected-campaign.py"
printf '\n# authenticated but semantically drifted validator\n' \
    >>"$fuzz_validator_tamper_plan/validate-collected-campaign.py"
chmod 0755 "$fuzz_validator_tamper_plan/validate-collected-campaign.py"
campaign_manifest_write "$fuzz_validator_tamper_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_validator_tamper_plan"; then
    printf 'fuzz status accepted recomputed-manifest validator drift\n' >&2
    exit 1
fi
status_probe_bin="$workdir/status-probe-bin"
status_probe_log="$workdir/status-probe-hosts.log"
mkdir "$status_probe_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'host=""; after_separator=0; for argument in "$@"; do if ((after_separator)); then host="$argument"; break; fi; [[ "$argument" != -- ]] || after_separator=1; done' \
    'printf "%s\n" "$host" >>"$STATUS_PROBE_LOG"' \
    'cat >/dev/null || true' \
    '[[ "$host" != h1 ]]' \
    >"$status_probe_bin/ssh"
chmod +x "$status_probe_bin/ssh"
large_status_plan="$workdir/large-status-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$large_status_plan" --campaign-id status-probe --host h1 --host h2 --duration 1
if PATH="$status_probe_bin:$PATH" STATUS_PROBE_LOG="$status_probe_log" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$large_status_plan"; then
    printf 'large-surface status returned success despite a failed host probe\n' >&2
    exit 1
fi
grep -Fqx h1 "$status_probe_log"
grep -Fqx h2 "$status_probe_log"

tool_drift_bin="$workdir/tool-drift-bin"
mkdir "$tool_drift_bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$tool_drift_bin/drift-cargo"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$tool_drift_bin/drift-rustc"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == which ]]; then case "${*: -1}" in cargo) printf "%s\n" "$TOOL_DRIFT_BIN/drift-cargo" ;; rustc) printf "%s\n" "$TOOL_DRIFT_BIN/drift-rustc" ;; esac; exit 0; fi' \
    'exit 0' >"$tool_drift_bin/rustup"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$tool_drift_bin/cargo-fuzz"
printf '%s\n' '#!/usr/bin/env bash' 'cat >/dev/null || true' 'exit 0' >"$tool_drift_bin/ssh"
chmod +x "$tool_drift_bin"/*
PATH="$tool_drift_bin:$PATH" TOOL_DRIFT_BIN="$tool_drift_bin" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$large_status_plan"

remote_probe_bin="$workdir/remote-probe-bin"
mkdir "$remote_probe_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'while [[ "$1" != -- ]]; do shift; done; shift 2; exec "$@"' \
    >"$remote_probe_bin/ssh"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    '[[ "${1:-}" != show ]] || exit 71' \
    'exit 3' \
    >"$remote_probe_bin/systemctl"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$remote_probe_bin/journalctl"
chmod +x "$remote_probe_bin/ssh" "$remote_probe_bin/systemctl" "$remote_probe_bin/journalctl"
if PATH="$remote_probe_bin:$PATH" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_plan_dir" \
    >"$workdir/remote-probe-status.log" 2>&1; then
    printf 'fuzz status returned success despite a remote systemctl probe error\n' >&2
    exit 1
fi
grep -Fq 'systemctl_status_probe_failed=' "$workdir/remote-probe-status.log"
: >"$status_probe_log"
fuzz_status_plan="$workdir/fuzz-status-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_status_plan" --campaign-id status-probe --host h1 --host h2 \
    --duration 1 --target dns_datagram --target transfer_stream --no-sampler
if PATH="$status_probe_bin:$PATH" STATUS_PROBE_LOG="$status_probe_log" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_status_plan"; then
    printf 'fuzz status returned success despite a failed host probe\n' >&2
    exit 1
fi
grep -Fqx h1 "$status_probe_log"
grep -Fqx h2 "$status_probe_log"
PATH="$tool_drift_bin:$PATH" TOOL_DRIFT_BIN="$tool_drift_bin" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_status_plan"
(
    cd "$(dirname "$fuzz_status_plan")"
    PATH="$tool_drift_bin:$PATH" TOOL_DRIFT_BIN="$tool_drift_bin" \
        "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status \
        --evidence-dir "$(basename "$fuzz_status_plan")"
)
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$workdir/colliding-fuzz-host-plan" --campaign-id colliding-hosts \
    --host 'user@host' --host user_host --duration 1 --target dns_datagram; then
    printf 'fuzz planner accepted colliding canonical host identities\n' >&2
    exit 1
fi
weighted_fuzz_plan="$workdir/weighted-fuzz-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$weighted_fuzz_plan" --campaign-id weighted-fuzz-test \
    --host h1 --host h1 --host h2 --host h2 --host h2 \
    --duration 1 --target dns_datagram --target-repeat 5
weighted_assignment_hosts="$(tail -n +2 "$weighted_fuzz_plan/assignments.tsv" | cut -f1 | paste -sd ' ' -)"
[[ "$weighted_assignment_hosts" == "h1 h1 h2 h2 h2" ]]
weighted_sampler_hosts="$(tail -n +2 "$weighted_fuzz_plan/host-samplers.tsv" | cut -f1 | paste -sd ' ' -)"
[[ "$weighted_sampler_hosts" == "h1 h2" ]]
awk -F '\t' 'BEGIN { OFS="\t" } NR == 3 { $1="h1" } { print }' \
    "$weighted_fuzz_plan/host-samplers.tsv" >"$weighted_fuzz_plan/host-samplers.tsv.mutated"
mv "$weighted_fuzz_plan/host-samplers.tsv.mutated" "$weighted_fuzz_plan/host-samplers.tsv"
campaign_manifest_write "$weighted_fuzz_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$weighted_fuzz_plan"; then
    printf 'fuzz status accepted a duplicate physical-host sampler row\n' >&2
    exit 1
fi
fuzz_unit_plan="$workdir/fuzz-unit-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_unit_plan" --campaign-id fuzz-unit-test --host h1 \
    --duration 1 --target dns_datagram --no-sampler
awk -F '\t' 'BEGIN { OFS="\t" } NR == 2 { $5="borondns-fuzz-fuzz-unit-test-0-wrong.service" } { print }' \
    "$fuzz_unit_plan/assignments.tsv" >"$fuzz_unit_plan/assignments.tsv.mutated"
mv "$fuzz_unit_plan/assignments.tsv.mutated" "$fuzz_unit_plan/assignments.tsv"
campaign_manifest_write "$fuzz_unit_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_unit_plan"; then
    printf 'fuzz status accepted a wrong valid-looking unit identity\n' >&2
    exit 1
fi
fuzz_command_tamper_plan="$workdir/fuzz-command-tamper-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_command_tamper_plan" --campaign-id fuzz-command-tamper --host h1 \
    --duration 1 --target dns_datagram --no-sampler
printf '\nprintf tampered\n' >>"$fuzz_command_tamper_plan/commands/h1-000-dns_datagram.sh"
campaign_manifest_write "$fuzz_command_tamper_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_command_tamper_plan"; then
    printf 'fuzz status accepted recomputed-manifest command content drift\n' >&2
    exit 1
fi
fuzz_sampler_unit_plan="$workdir/fuzz-sampler-unit-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_sampler_unit_plan" --campaign-id fuzz-sampler-unit-test --host h1 \
    --duration 1 --target dns_datagram
awk -F '\t' 'BEGIN { OFS="\t" } NR == 2 { $3="borondns-fuzz-fuzz-sampler-unit-test-wrong.service" } { print }' \
    "$fuzz_sampler_unit_plan/host-samplers.tsv" >"$fuzz_sampler_unit_plan/host-samplers.tsv.mutated"
mv "$fuzz_sampler_unit_plan/host-samplers.tsv.mutated" "$fuzz_sampler_unit_plan/host-samplers.tsv"
campaign_manifest_write "$fuzz_sampler_unit_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_sampler_unit_plan"; then
    printf 'fuzz status accepted a wrong valid-looking sampler unit identity\n' >&2
    exit 1
fi
fuzz_sampler_command_plan="$workdir/fuzz-sampler-command-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_sampler_command_plan" --campaign-id fuzz-sampler-command --host h1 \
    --duration 1 --target dns_datagram
printf '\nprintf tampered\n' >>"$fuzz_sampler_command_plan/commands/h1-host-sampler.sh"
campaign_manifest_write "$fuzz_sampler_command_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_sampler_command_plan"; then
    printf 'fuzz status accepted recomputed-manifest sampler command content drift\n' >&2
    exit 1
fi
fuzz_sampler_deadline_plan="$workdir/fuzz-sampler-deadline-plan"
cp -a "$fuzz_plan_dir" "$fuzz_sampler_deadline_plan"
saved_sampler_deadline="$(tail -n +2 "$fuzz_sampler_deadline_plan/host-samplers.tsv" | cut -f5)"
saved_sampler_deadline_encoding="$(printf '%s' "$saved_sampler_deadline" | base64 | tr -d '\n')"
extended_sampler_deadline_encoding="$(printf '%s' "$((saved_sampler_deadline + 1))" | base64 | tr -d '\n')"
sed -i "s|^sampler_deadline_epoch_seconds=base64:$saved_sampler_deadline_encoding$|sampler_deadline_epoch_seconds=base64:$extended_sampler_deadline_encoding|" \
    "$fuzz_sampler_deadline_plan/campaign.env"
campaign_manifest_write "$fuzz_sampler_deadline_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_sampler_deadline_plan"; then
    printf 'fuzz status accepted an extended authenticated sampler deadline\n' >&2
    exit 1
fi
fuzz_swap_plan="$workdir/fuzz-swap-plan"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_swap_plan" --campaign-id fuzz-swap-test --host h1 --host h2 \
    --duration 1 --target dns_datagram --target transfer_stream --no-sampler
awk -F '\t' 'BEGIN { OFS="\t" } NR == 2 { $1="h2"; $2="transfer_stream" } NR == 3 { $1="h1"; $2="dns_datagram" } { print }' \
    "$fuzz_swap_plan/assignments.tsv" >"$fuzz_swap_plan/assignments.tsv.mutated"
mv "$fuzz_swap_plan/assignments.tsv.mutated" "$fuzz_swap_plan/assignments.tsv"
campaign_manifest_write "$fuzz_swap_plan"
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$fuzz_swap_plan"; then
    printf 'fuzz status accepted swapped target/index/host assignments\n' >&2
    exit 1
fi
source_commit="$(git -C "$repo_root" rev-parse HEAD)"
(
    created_utc=""
    duration_seconds=""
    sampler_deadline_epoch_seconds=""
    campaign_env_load "$fuzz_plan_dir/campaign.env" \
        campaign_id created_utc repo_root source_commit source_clean remote_repo remote_evidence \
        duration_seconds toolchain sanitizer cargo_sha256 rustc_sha256 cargo_fuzz_sha256 \
        target_repeat sampler_interval_seconds sampler_deadline_epoch_seconds sampler_enabled \
        hosts targets
    [[ "$source_commit" == "$(git -C "$repo_root" rev-parse HEAD)" ]]
    [[ "$sampler_deadline_epoch_seconds" == "$(($(date -u -d "$created_utc" +%s) + duration_seconds + 3600 + 600))" ]]
)
fuzz_command_file="$fuzz_plan_dir/commands/fake-host-000-dns_datagram.sh"
fuzz_sampler_command_file="$fuzz_plan_dir/commands/fake-host-host-sampler.sh"
fuzz_sample_dir="$fuzz_remote_evidence/host/fake-host"
grep -Fqx "expected_commit=$source_commit" "$fuzz_command_file"
[[ "$(grep -Fc 'LimitNOFILE=65536' "$fuzz_command_file")" -eq 1 ]]
[[ "$(grep -Fc 'LimitNOFILE=65536' "$fuzz_sampler_command_file")" -eq 1 ]]
# shellcheck disable=SC2016
[[ "$(grep -Fc 'RuntimeMaxSec=$((duration + 3600 + target_setup_reserve_seconds))' "$fuzz_command_file")" -eq 1 ]]
# shellcheck disable=SC2016
[[ "$(grep -Fc 'RuntimeMaxSec=$((duration + 3600 + target_setup_reserve_seconds + sampler_terminal_reserve_seconds))' "$fuzz_sampler_command_file")" -eq 1 ]]
grep -Fqx target_setup_reserve_seconds=600 "$fuzz_sampler_command_file"
grep -Fqx sampler_probe_budget_seconds=10 "$fuzz_sampler_command_file"
grep -Fqx sampler_terminal_overhead_seconds=5 "$fuzz_sampler_command_file"
grep -Fqx sampler_units_planned_count=1 "$fuzz_sampler_command_file"
grep -Fqx sampler_command_probe_timeout_seconds=30 "$fuzz_sampler_command_file"
grep -Fqx sampler_command_probe_kill_after_seconds=5 "$fuzz_sampler_command_file"
grep -Fq 'fixed_probe_count * (sampler_command_probe_timeout_seconds + sampler_command_probe_kill_after_seconds)' \
    "$fuzz_sampler_command_file"
grep -Fq 'sampler_units_planned_count * sampler_probe_budget_seconds + sampler_terminal_overhead_seconds' \
    "$fuzz_sampler_command_file"
sampler_first_sample_budget=$((11 * (30 + 5) + 1 * 10 + 5))
((sampler_first_sample_budget == 400 && sampler_first_sample_budget > 180))
grep -Fq 'campaign_lock_helper_sha256=' "$fuzz_command_file"
grep -Fq 'campaign_lock_helper_sha256=' "$fuzz_sampler_command_file"
grep -Fq 'campaign_env_snapshot_b64=' "$fuzz_command_file"
grep -Fq 'campaign_lock_helper_snapshot_b64=' "$fuzz_command_file"
grep -Fq 'campaign_env_snapshot_b64=' "$fuzz_sampler_command_file"
grep -Fq 'campaign_lock_helper_snapshot_b64=' "$fuzz_sampler_command_file"
# shellcheck disable=SC2016 # Literal fragments of the generated remote scripts.
grep -Fq 'BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"' "$fuzz_command_file"
# shellcheck disable=SC2016
grep -Fq 'BORONDNS_CAMPAIGN_LOCK_HELPER_SNAPSHOT_B64="$campaign_lock_helper_snapshot_b64"' "$fuzz_sampler_command_file"
[[ "$(grep -Fc 'TimeoutStopSec=30' "$fuzz_command_file")" -eq 1 ]]
[[ "$(grep -Fc 'TimeoutStopSec=30' "$fuzz_sampler_command_file")" -eq 1 ]]
grep -Fq 'BORONDNS_FUZZ_AUTHENTICATED_CARGO=' "$fuzz_command_file"
grep -Fq 'exec 9<' "$fuzz_command_file"
if grep -Fq 'Environment=PATH=/home/codex/.cargo/bin:' "$fuzz_command_file"; then
    printf 'fuzz unit retained a user-writable executable search path\n' >&2
    exit 1
fi
# This is a literal fragment of the generated sampler script.
# shellcheck disable=SC2016
grep -Fq 'timeout --preserve-status --signal=KILL "$probe_timeout" systemctl is-active' \
    "$fuzz_sampler_command_file"
# This is a literal fragment of the generated remote script.
# shellcheck disable=SC2016
grep -Fq 'lock_root="/tmp/borondns-campaign-locks-$(id -u)"' "$fuzz_command_file"
# shellcheck disable=SC2016
grep -Fq 'campaign_acquire_private_lock "$lock_root" "$systemd_unit:campaign"' "$fuzz_command_file"
PATH="$workdir/fakebin:$PATH" FAKE_SSH_LOG="$workdir/ssh.log" FAKE_SSH_STDIN="$workdir/ssh.stdin" \
    FAKE_SSH_RESULTS_MISSING=1 "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" resume \
    --evidence-dir "$fuzz_plan_dir"
head -1 "$workdir/ssh.stdin" | grep -Fqx '#!/usr/bin/env bash'
commit_check_line="$(grep -n 'actual_commit=.*rev-parse HEAD' "$fuzz_command_file" | head -1 | cut -d: -f1)"
dirty_check_line="$(grep -n 'status --short --untracked-files=all' "$fuzz_command_file" | head -1 | cut -d: -f1)"
# shellcheck disable=SC2016 # Literal fragment of the generated remote script.
helper_source_line="$(grep -nF 'source <(printf '\''%s'\'' "$campaign_env_snapshot_b64" | base64 --decode)' "$fuzz_command_file" | head -1 | cut -d: -f1)"
# This is a literal fragment of the generated remote script.
# shellcheck disable=SC2016
first_remote_write_line="$(grep -nF 'ensure_owned_dir "$remote_parent" "$remote_evidence"' "$fuzz_command_file" | cut -d: -f1)"
((commit_check_line < first_remote_write_line))
((dirty_check_line < first_remote_write_line))
((dirty_check_line < helper_source_line))
[[ "$(grep -c 'actual_commit=.*rev-parse HEAD' "$fuzz_command_file")" -eq 2 ]]
grep -Fq 'immutable fuzz snapshot is dirty; refusing evidence writes' "$fuzz_command_file"
grep -Fq 'remote_build_root=/var/tmp/borondns-fuzz-' "$fuzz_command_file"
# shellcheck disable=SC2016
grep -Fq 'export CARGO_TARGET_DIR="$target_dir"' "$fuzz_command_file"
active_check_line="$(grep -n 'unit_is_exactly_active.*systemd_unit' "$fuzz_command_file" | head -1 | cut -d: -f1)"
((dirty_check_line < active_check_line))

launch_order_bin="$workdir/launch-order-bin"
launch_order_log="$workdir/launch-order.log"
mkdir "$launch_order_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'input="$(mktemp)"' 'trap '\''rm -f "$input"'\'' EXIT' 'cat >"$input"' \
    'if grep -Fq wait_for_sampler_first_sample "$input"; then printf "sampler\n"; else printf "target\n"; fi >>"$LAUNCH_ORDER_LOG"' \
    >"$launch_order_bin/ssh"
chmod +x "$launch_order_bin/ssh"
PATH="$launch_order_bin:$PATH" LAUNCH_ORDER_LOG="$launch_order_log" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" resume --evidence-dir "$fuzz_plan_dir"
[[ "$(sed -n '1p' "$launch_order_log")" == sampler ]]
[[ "$(sed -n '2p' "$launch_order_log")" == target ]]

failing_git_bin="$workdir/failing-git-bin"
mkdir "$failing_git_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'for arg in "$@"; do if [[ "$arg" == status ]]; then exit 73; fi; done' \
    'exec /usr/bin/git "$@"' >"$failing_git_bin/git"
chmod +x "$failing_git_bin/git"
grep -Fqx 'git_path=/usr/bin/git' "$fuzz_command_file"
grep -Fqx 'git_path=/usr/bin/git' "$fuzz_sampler_command_file"
failed_status_plan="$workdir/failed-status-plan"
if PATH="$failing_git_bin:$PATH" "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$failed_status_plan" --campaign-id failed-status --host h1 \
    --duration 1 --target dns_datagram; then
    printf 'fuzz planner interpreted failed git status with empty stdout as clean\n' >&2
    exit 1
fi
[[ ! -e "$failed_status_plan" ]]
failed_large_status_plan="$workdir/failed-large-status-plan"
if PATH="$failing_git_bin:$PATH" "$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$failed_large_status_plan" --campaign-id failed-status --host h1 --duration 1; then
    printf 'large-surface planner interpreted failed git status with empty stdout as clean\n' >&2
    exit 1
fi
[[ ! -e "$failed_large_status_plan" ]]
large_failed_remote="$workdir/large-failed-remote"
large_failed_plan="$workdir/large-failed-plan"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$large_failed_plan" --campaign-id failed-remote-status --host h1 \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$large_failed_remote" --duration 1
grep -Fqx 'git_path=/usr/bin/git' "$large_failed_plan/commands/h1-launch.sh"
ancestor_remote_real="$workdir/ancestor-remote-real"
ancestor_remote_link="$workdir/ancestor-remote-link"
ancestor_remote_plan="$workdir/ancestor-remote-plan"
mkdir -p "$ancestor_remote_real/subdir"
ln -s "$ancestor_remote_real" "$ancestor_remote_link"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$ancestor_remote_plan" --campaign-id ancestor-remote --host h1 \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$ancestor_remote_link/subdir/evidence" --duration 1
if "$ancestor_remote_plan/commands/h1-launch.sh"; then
    printf 'large-surface remote helper accepted a symlinked evidence ancestor\n' >&2
    exit 1
fi
[[ -z "$(find "$ancestor_remote_real/subdir" -mindepth 1 -print -quit)" ]]
large_host_victim="$workdir/large-host-victim"
mkdir -p "$large_failed_remote/host" "$large_host_victim"
ln -s "$large_host_victim" "$large_failed_remote/host/h1"
if "$large_failed_plan/commands/h1-launch.sh"; then
    printf 'large-surface launch accepted a symlinked host evidence directory\n' >&2
    exit 1
fi
[[ -z "$(find "$large_host_victim" -mindepth 1 -print -quit)" ]]
rm "$large_failed_remote/host/h1"
large_build_parent=/var/tmp/borondns-large-failed-remote-status
large_build_victim="$workdir/large-build-victim"
remove_readonly_test_tree "$large_build_parent"
mkdir "$large_build_victim"
ln -s "$large_build_victim" "$large_build_parent"
if "$large_failed_plan/commands/h1-launch.sh"; then
    printf 'large-surface launch accepted a symlinked remote build parent\n' >&2
    exit 1
fi
[[ -z "$(find "$large_build_victim" -mindepth 1 -print -quit)" ]]
rm "$large_build_parent"
if PATH="$failing_git_bin:$PATH" EXPECTED_TEST_COMMIT="$source_commit" \
    bash -c 'source "$1"; expected_commit="$EXPECTED_TEST_COMMIT"; verify_expected_clean_head' \
    _ "$repo_root/scripts/large-surface-soak.sh"; then
    printf 'direct soak runner interpreted failed git status with empty stdout as clean\n' >&2
    exit 1
fi
printf 'dirty fixture\n' >"$fuzz_remote_repo/untracked-fixture"
if "$fuzz_command_file"; then
    printf 'fuzz launch accepted a dirty remote repository\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_remote_evidence" ]]
if "$fuzz_sampler_command_file"; then
    printf 'sampler launch accepted a dirty remote repository\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_remote_evidence" ]]
rm -f "$fuzz_remote_repo/untracked-fixture"
git -C "$fuzz_remote_repo" -c user.name=BoronDNS -c user.email=tests@borondns.invalid \
    commit -qm 'mismatch fixture' --allow-empty
if "$fuzz_command_file"; then
    printf 'fuzz launch accepted a mismatched remote commit\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_remote_evidence" ]]
if "$fuzz_sampler_command_file"; then
    printf 'sampler launch accepted a mismatched remote commit\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_remote_evidence" ]]
git -C "$fuzz_remote_repo" reset -q --hard "$source_commit"
materialize_campaign_helpers "$fuzz_remote_repo"

fake_sampler_bin="$workdir/fake-sampler-bin"
fake_sampler_state="$workdir/fake-sampler-state"
mkdir -p "$fake_sampler_bin" "$fake_sampler_state" "$(dirname "$fuzz_sample_dir")"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'case "${1:-}" in' \
    'tee) mkdir -p "$(dirname "$2")"; cat >"$2" ;;' \
    'systemctl) if [[ "${FAKE_SAMPLER_SYSTEMCTL_FAIL_ONCE:-0}" == 1 && ! -e "$FAKE_SAMPLER_STATE/failed-once" ]]; then touch "$FAKE_SAMPLER_STATE/failed-once"; exit 55; fi; if [[ "${2:-}" == daemon-reload ]]; then if [[ "${FAKE_DAEMON_RELOAD_FAIL_ONCE:-0}" == 1 && ! -e "$FAKE_SAMPLER_STATE/daemon-reload-failed-once" ]]; then touch "$FAKE_SAMPLER_STATE/daemon-reload-failed-once"; exit 56; fi; rm -f "$FAKE_SAMPLER_STATE"/loaded-*; touch "$FAKE_SAMPLER_STATE/daemon-reloaded"; fi; if [[ "${2:-}" == start ]]; then unit="${3:-}"; if [[ "$unit" == *host-sampler* ]]; then count=0; [[ ! -f "$FAKE_SAMPLER_STATE/sampler-start-count" ]] || read -r count <"$FAKE_SAMPLER_STATE/sampler-start-count"; printf "%s\n" "$((count + 1))" >"$FAKE_SAMPLER_STATE/sampler-start-count"; sleep "${FAKE_SAMPLER_START_DELAY:-0}"; if [[ -n "${FAKE_SAMPLER_READY_ROOT:-}" ]]; then latest="$(find "$FAKE_SAMPLER_READY_ROOT/attempts" -mindepth 1 -maxdepth 1 -type d -name "attempt.*" -printf "%T@ %p\n" | sort -n | tail -1 | cut -d" " -f2-)"; printf "header\nready\n" >"$latest/host-samples.tsv"; fi; fi; [[ "${FAKE_SYSTEMCTL_START_INACTIVE:-0}" == 1 ]] || touch "$FAKE_SAMPLER_STATE/active-${unit//\//_}"; fi; exit 0 ;;' \
    'install|chown|chmod|rm|mkdir|mktemp|mv|cmp|ln|python3) exec /usr/bin/sudo -n "$@" ;;' \
    '*) exec "$@" ;;' \
    'esac' >"$fake_sampler_bin/sudo"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == show ]]; then' \
    '  if [[ "${FAKE_SYSTEMCTL_PROBE_FAIL:-0}" == 1 ]]; then exit 71; fi' \
    '  unit="$2"; fragment="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}/$unit"; active="$FAKE_SAMPLER_STATE/active-${unit//\//_}"; loaded_state="$FAKE_SAMPLER_STATE/loaded-${unit//\//_}"' \
    '  if [[ "${FAKE_SYSTEMCTL_CLEANUP_LOADED:-0}" == 1 ]]; then if [[ -f "$fragment" ]]; then runner="$(sed -n "s/^ExecStart=//p" "$fragment")"; printf "%s\n" "$runner" >"$loaded_state"; elif [[ -f "$loaded_state" ]]; then runner="$(cat "$loaded_state")"; else runner=""; fi; if [[ "${FAKE_SYSTEMCTL_POST_ACTIVE:-0}" == 1 && -f "$FAKE_SAMPLER_STATE/daemon-reloaded" && -z "$runner" ]]; then printf "LoadState=not-found\nActiveState=active\nSubState=running\nMainPID=4242\nControlPID=0\nJob=\nControlGroup=\nFragmentPath=\nExecStart=\n"; elif [[ -n "$runner" ]]; then printf "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nControlGroup=\nFragmentPath=%s\nExecStart={ path=%s ; }\n" "$fragment" "$runner"; else printf "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nControlGroup=\nFragmentPath=\nExecStart=\n"; fi; elif [[ "${FAKE_SYSTEMCTL_ACTIVE:-0}" == 1 ]]; then printf "LoadState=loaded\nActiveState=active\nFragmentPath=/wrong/unit\nExecStart={ path=/wrong/runner ; }\n"; elif [[ "${FAKE_SYSTEMCTL_FOREIGN_INACTIVE:-0}" == 1 ]]; then printf "LoadState=loaded\nActiveState=inactive\nFragmentPath=/wrong/unit\nExecStart={ path=/wrong/runner ; }\n"; elif [[ "${FAKE_SYSTEMCTL_LOADED_INACTIVE:-0}" == 1 ]]; then runner="$(sed -n "s/^ExecStart=//p" "$fragment")"; printf "LoadState=loaded\nActiveState=inactive\nFragmentPath=%s\nExecStart={ path=/wrapper%ssuffix ; }\n" "$fragment" "$runner"; elif [[ -e "$active" ]]; then runner="$(sed -n "s/^ExecStart=//p" "$fragment")"; if [[ "${FAKE_SYSTEMCTL_WRAPPED:-0}" == 1 ]]; then loaded="/wrapper${runner}suffix"; else loaded="$runner"; fi; printf "LoadState=loaded\nActiveState=active\nFragmentPath=%s\nExecStart={ path=%s ; }\n" "$fragment" "$loaded"; rm -f "$active"; else printf "LoadState=not-found\nActiveState=inactive\nFragmentPath=\nExecStart=\n"; fi' \
    '  exit 0' \
    'fi' \
    'exit 0' >"$fake_sampler_bin/systemctl"
chmod +x "$fake_sampler_bin/sudo" "$fake_sampler_bin/systemctl"
ln -s /usr/bin/true "$fake_sampler_bin/docker"
export BORONDNS_CAMPAIGN_UNIT_ROOT="$fake_sampler_state/units"
export FAKE_SAMPLER_READY_ROOT="$fuzz_sample_dir"
sampler_lock_root="/tmp/borondns-campaign-locks-$(id -u)"
sampler_lock_namespace="borondns-fuzz-operations-fuzz-test-host-sampler-fake-host:setup"
sampler_setup_lock="$sampler_lock_root/.borondns-campaign-locks/$(printf '%s' "$sampler_lock_namespace" | sha256sum | awk '{ print $1 }').lock"

if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SYSTEMCTL_ACTIVE=1 \
    "$fuzz_command_file"; then
    printf 'initial fuzz launch silently accepted an already-active unit identity\n' >&2
    exit 1
fi
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SYSTEMCTL_ACTIVE=1 \
    "$fuzz_sampler_command_file"; then
    printf 'initial sampler launch silently accepted an already-active unit identity\n' >&2
    exit 1
fi
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SYSTEMCTL_ACTIVE=1 \
    "$large_failed_plan/commands/h1-launch.sh"; then
    printf 'initial soak launch silently accepted an already-active unit identity\n' >&2
    exit 1
fi
for hostile_command in \
    "$fuzz_command_file" \
    "$fuzz_sampler_command_file" \
    "$large_failed_plan/commands/h1-launch.sh"; do
    if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SYSTEMCTL_FOREIGN_INACTIVE=1 \
        "$hostile_command"; then
        printf 'campaign launch accepted a foreign inactive same-name unit: %s\n' "$hostile_command" >&2
        exit 1
    fi
done
[[ ! -e "$fuzz_remote_evidence/fuzz/000-dns_datagram" ]]
[[ ! -e "$BORONDNS_CAMPAIGN_UNIT_ROOT" ]]
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SYSTEMCTL_PROBE_FAIL=1 \
    "$fuzz_command_file"; then
    printf 'fuzz launch treated a failed systemctl probe as inactivity\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_remote_evidence/fuzz/000-dns_datagram" ]]

hostile_unit="$(tail -n +2 "$fuzz_plan_dir/assignments.tsv" | cut -f5)"
hostile_target_root="$fuzz_remote_evidence/fuzz/000-dns_datagram"
hostile_attempt="$hostile_target_root/attempts/attempt.hostile"
hostile_runner="$hostile_attempt/run.sh"
hostile_fragment="$BORONDNS_CAMPAIGN_UNIT_ROOT/$hostile_unit"
mkdir -p "$hostile_attempt" "$BORONDNS_CAMPAIGN_UNIT_ROOT"
printf '#!/usr/bin/env bash\nexit 0\n' >"$hostile_runner"
chmod +x "$hostile_runner"
printf 'ExecStart=%s\n' "$hostile_runner" >"$hostile_fragment"
touch "$fake_sampler_state/active-${hostile_unit//\//_}"
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SYSTEMCTL_WRAPPED=1 \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_command_file"; then
    printf 'fuzz resume accepted a wrapper/suffix loaded ExecStart identity\n' >&2
    exit 1
fi
[[ "$(find "$hostile_target_root/attempts" -mindepth 1 -maxdepth 1 -type d | wc -l)" == 1 ]]

cleanup_ssh_bin="$workdir/cleanup-ssh-bin"
mkdir "$cleanup_ssh_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'while [[ "$1" != -- ]]; do shift; done; shift; host="$1"; shift; exec "$@"' \
    >"$cleanup_ssh_bin/ssh"
chmod +x "$cleanup_ssh_bin/ssh"
status_identity_plan="$workdir/status-identity-plan"
status_identity_remote="$workdir/status-identity-remote"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$status_identity_plan" --campaign-id status-identity --host h1 \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$status_identity_remote" \
    --duration 1 --scenario chaos_queries
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_ACTIVE=1 \
    "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$status_identity_plan"; then
    printf 'large-surface status accepted a replaced same-name unit\n' >&2
    exit 1
fi
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_LOADED_INACTIVE=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$fuzz_plan_dir"; then
    printf 'fuzz cleanup accepted a mismatched loaded ExecStart identity\n' >&2
    exit 1
fi
[[ -f "$hostile_fragment" && -f "$hostile_runner" ]]

cleanup_lock_root="/tmp/borondns-campaign-locks-$(id -u)"
mkdir -p "$cleanup_lock_root"
chmod 0700 "$cleanup_lock_root"
cleanup_fuzz_plan="$workdir/cleanup-fuzz-plan"
cleanup_fuzz_remote="$workdir/cleanup-fuzz-remote"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$cleanup_fuzz_plan" --campaign-id cleanup-retry --host h1 \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$cleanup_fuzz_remote" \
    --duration 1 --target dns_datagram --no-sampler
IFS=$'\t' read -r _ _ _ cleanup_fuzz_target_dir cleanup_fuzz_unit _ \
    < <(tail -n +2 "$cleanup_fuzz_plan/assignments.tsv")
cleanup_fuzz_attempt="$cleanup_fuzz_target_dir/attempts/attempt.cleanup"
cleanup_fuzz_fragment="$BORONDNS_CAMPAIGN_UNIT_ROOT/$cleanup_fuzz_unit"
cleanup_fuzz_build=/var/tmp/borondns-fuzz-cleanup-retry/000-dns_datagram
cleanup_fuzz_loaded="$fake_sampler_state/loaded-${cleanup_fuzz_unit//\//_}"
mkdir -p "$cleanup_fuzz_attempt" "$cleanup_fuzz_build" "$BORONDNS_CAMPAIGN_UNIT_ROOT"
cleanup_fuzz_candidate="$cleanup_fuzz_attempt/run.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$cleanup_fuzz_candidate"
chmod +x "$cleanup_fuzz_candidate"
publish_test_root_runner "$cleanup_fuzz_unit" "$cleanup_fuzz_candidate" "cleanup fuzz fixture"
cleanup_fuzz_runner="$campaign_published_runner"
cleanup_fuzz_fragment_candidate="$cleanup_fuzz_attempt/unit.service"
cat >"$cleanup_fuzz_fragment_candidate" <<UNIT
[Unit]
Description=BoronDNS cleanup fuzz fixture
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex
WorkingDirectory=/home/codex/borondns
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LimitNOFILE=65536
ExecStart=$cleanup_fuzz_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${cleanup_fuzz_unit%.service}
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
sudo -n install -m 0644 -o root -g root "$cleanup_fuzz_fragment_candidate" "$cleanup_fuzz_fragment"
cleanup_fuzz_staged="$BORONDNS_CAMPAIGN_UNIT_ROOT/.$(basename "$cleanup_fuzz_fragment").borondns-staged.interrupted"
printf '[Unit]\nDescription=interrupted' >"$cleanup_fuzz_fragment_candidate"
sudo -n install -m 0600 -o root -g root "$cleanup_fuzz_fragment_candidate" "$cleanup_fuzz_staged"
touch "$cleanup_lock_root/${cleanup_fuzz_unit%.service}.campaign.lock"
chmod 0600 "$cleanup_lock_root/${cleanup_fuzz_unit%.service}.campaign.lock"

printf dirty >"$fuzz_remote_repo/cleanup-dirty-fixture"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"; then
    printf 'fuzz cleanup accepted a dirty remote helper repository\n' >&2
    exit 1
fi
[[ -f "$cleanup_fuzz_fragment" && -d "$cleanup_fuzz_build" && -f "$cleanup_fuzz_runner" ]]
rm "$fuzz_remote_repo/cleanup-dirty-fixture"

cleanup_malicious_marker="$workdir/cleanup-malicious-helper-executed"
printf '\nprintf exploited >%q\n' "$cleanup_malicious_marker" \
    >>"$fuzz_remote_repo/scripts/campaign-env.sh"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"; then
    printf 'fuzz cleanup accepted a malicious dirty remote helper\n' >&2
    exit 1
fi
[[ ! -e "$cleanup_malicious_marker" && -f "$cleanup_fuzz_fragment" && -d "$cleanup_fuzz_build" ]]
git -C "$fuzz_remote_repo" reset -q --hard "$source_commit"
materialize_campaign_helpers "$fuzz_remote_repo"

mv "$cleanup_fuzz_build" "$cleanup_fuzz_build.renamed"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"; then
    printf 'fuzz cleanup accepted a renamed-away expected build root\n' >&2
    exit 1
fi
[[ -f "$cleanup_fuzz_fragment" && -d "$cleanup_fuzz_build.renamed" && -f "$cleanup_fuzz_runner" ]]
mv "$cleanup_fuzz_build.renamed" "$cleanup_fuzz_build"

ln -s "$workdir" "$cleanup_fuzz_build/unsafe-link"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"; then
    printf 'fuzz cleanup mutated through an unsafe build-root preflight failure\n' >&2
    exit 1
fi
[[ -f "$cleanup_fuzz_fragment" && -f "$cleanup_fuzz_staged" && -L "$cleanup_fuzz_build/unsafe-link" ]]
rm "$cleanup_fuzz_build/unsafe-link"
rm -f "$fake_sampler_state/daemon-reload-failed-once"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 FAKE_DAEMON_RELOAD_FAIL_ONCE=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"; then
    printf 'fuzz cleanup ignored a daemon-reload failure\n' >&2
    exit 1
fi
[[ ! -e "$cleanup_fuzz_fragment" && ! -e "$cleanup_fuzz_staged" && -d "$cleanup_fuzz_build" && -f "$cleanup_fuzz_runner" && -f "$cleanup_fuzz_loaded" ]]
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 FAKE_SYSTEMCTL_POST_ACTIVE=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"; then
    printf 'fuzz cleanup deleted retained trees after non-terminal post-reload state\n' >&2
    exit 1
fi
[[ -d "$cleanup_fuzz_build" && -f "$cleanup_fuzz_runner" && ! -e "$cleanup_fuzz_loaded" ]]
rm -f "$fake_sampler_state/daemon-reloaded"
PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 FAKE_DAEMON_RELOAD_FAIL_ONCE=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" cleanup --evidence-dir "$cleanup_fuzz_plan"
[[ ! -e "$cleanup_fuzz_loaded" ]]
cleanup_fuzz_retained="$(find "$(dirname "$cleanup_fuzz_build")" -mindepth 1 -maxdepth 1 \
    -type d -name '.000-dns_datagram.borondns-remove.*' -print -quit)"
[[ ! -e "$cleanup_fuzz_build" && -n "$cleanup_fuzz_retained" &&
    ! -e "$(dirname "$(dirname "$cleanup_fuzz_runner")")" ]]

cleanup_large_plan="$workdir/cleanup-large-plan"
cleanup_large_remote="$workdir/cleanup-large-remote"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$cleanup_large_plan" --campaign-id cleanup-large --host h1 \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$cleanup_large_remote" \
    --duration 1 --scenario chaos_queries
IFS=$'\t' read -r _ _ cleanup_large_unit _ \
    < <(tail -n +2 "$cleanup_large_plan/assignments.tsv")
cleanup_large_attempt="$cleanup_large_remote/launch/${cleanup_large_unit%.service}-attempts/attempt.cleanup"
cleanup_large_fragment="$BORONDNS_CAMPAIGN_UNIT_ROOT/$cleanup_large_unit"
cleanup_large_build=/var/tmp/borondns-large-cleanup-large/h1
mkdir -p "$cleanup_large_attempt" "$cleanup_large_build" "$BORONDNS_CAMPAIGN_UNIT_ROOT"
sudo -n chown root:root "$cleanup_large_build"
sudo -n chmod 0755 "$cleanup_large_build"
cleanup_large_candidate="$cleanup_large_attempt/run.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$cleanup_large_candidate"
chmod +x "$cleanup_large_candidate"
publish_test_root_runner "$cleanup_large_unit" "$cleanup_large_candidate" "cleanup large fixture"
cleanup_large_runner="$campaign_published_runner"
cleanup_large_fragment_candidate="$cleanup_large_attempt/unit.service"
cat >"$cleanup_large_fragment_candidate" <<UNIT
[Unit]
Description=BoronDNS cleanup large-soak fixture
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=codex
WorkingDirectory=/home/codex/borondns
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=CARGO_HOME=/home/codex/.cargo
Environment=RUSTUP_HOME=/home/codex/.rustup
SupplementaryGroups=docker
LimitNOFILE=1048576
ExecStart=$cleanup_large_runner
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${cleanup_large_unit%.service}
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
sudo -n install -m 0644 -o root -g root "$cleanup_large_fragment_candidate" "$cleanup_large_fragment"
touch "$cleanup_lock_root/${cleanup_large_unit}.campaign.lock"
chmod 0600 "$cleanup_lock_root/${cleanup_large_unit}.campaign.lock"
git -C "$fuzz_remote_repo" -c user.name=BoronDNS -c user.email=tests@borondns.invalid \
    commit -qm 'cleanup mismatch fixture' --allow-empty
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/large-surface-soak-campaign.sh" cleanup --evidence-dir "$cleanup_large_plan"; then
    printf 'large-surface cleanup accepted a mismatched remote helper commit\n' >&2
    exit 1
fi
[[ -f "$cleanup_large_fragment" && -d "$cleanup_large_build" && -f "$cleanup_large_runner" ]]
git -C "$fuzz_remote_repo" reset -q --hard "$source_commit"
materialize_campaign_helpers "$fuzz_remote_repo"
large_status_identity_bin="$workdir/large-status-identity-bin"
mkdir "$large_status_identity_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'while [[ "$1" != -- ]]; do shift; done; shift 2; exec "$@"' \
    >"$large_status_identity_bin/ssh"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'if [[ "${1:-}" == is-active ]]; then printf "active\n"; exit 0; fi' \
    'if [[ "${1:-}" == show ]]; then unit="$2"; fragment="${BORONDNS_CAMPAIGN_UNIT_ROOT:-/etc/systemd/system}/$unit"; runner="$(sed -n "s/^ExecStart=//p" "$fragment")"; printf "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nFragmentPath=%s\nExecStart={ path=%s ; }\nExecMainStatus=0\nExecMainStartTimestamp=\nExecMainExitTimestamp=\n" "$fragment" "$runner"; exit 0; fi' \
    'exit 1' >"$large_status_identity_bin/systemctl"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$large_status_identity_bin/journalctl"
chmod +x "$large_status_identity_bin/ssh" "$large_status_identity_bin/systemctl" \
    "$large_status_identity_bin/journalctl"
altered_large_fragment="$workdir/altered-large-status.service"
sed 's/^User=codex$/User=root/' "$cleanup_large_fragment_candidate" >"$altered_large_fragment"
sudo -n install -m 0644 -o root -g root "$altered_large_fragment" "$cleanup_large_fragment"
if PATH="$large_status_identity_bin:$PATH" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" status --evidence-dir "$cleanup_large_plan" \
    >"$workdir/altered-large-status.log" 2>&1; then
    printf 'large-surface status accepted an altered canonical unit directive\n' >&2
    exit 1
fi
grep -Fq unit_identity=mismatch "$workdir/altered-large-status.log"
sudo -n install -m 0644 -o root -g root "$cleanup_large_fragment_candidate" "$cleanup_large_fragment"
sudo -n mv "$cleanup_large_build" "$cleanup_large_build.renamed"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/large-surface-soak-campaign.sh" cleanup --evidence-dir "$cleanup_large_plan"; then
    printf 'large-surface cleanup accepted a renamed-away expected build root\n' >&2
    exit 1
fi
[[ -f "$cleanup_large_fragment" && -d "$cleanup_large_build.renamed" && -f "$cleanup_large_runner" ]]
sudo -n mv "$cleanup_large_build.renamed" "$cleanup_large_build"
sudo -n ln -s "$workdir" "$cleanup_large_build/unsafe-link"
if PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/large-surface-soak-campaign.sh" cleanup --evidence-dir "$cleanup_large_plan"; then
    printf 'large-surface cleanup mutated through an unsafe build-root preflight failure\n' >&2
    exit 1
fi
[[ -f "$cleanup_large_fragment" && -L "$cleanup_large_build/unsafe-link" ]]
sudo -n rm "$cleanup_large_build/unsafe-link"
PATH="$cleanup_ssh_bin:$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_CLEANUP_LOADED=1 \
    "$repo_root/scripts/large-surface-soak-campaign.sh" cleanup --evidence-dir "$cleanup_large_plan"
[[ ! -e "$cleanup_large_fragment" ]]

fuzz_target_dir="$fuzz_remote_evidence/fuzz/000-dns_datagram"
fuzz_build_parent=/var/tmp/borondns-fuzz-operations-fuzz-test
rm -rf "$fuzz_remote_evidence" "$fake_sampler_state/units"
mkdir -p "$fake_sampler_state/units"
remove_readonly_test_tree "$fuzz_build_parent"
set +e
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_START_INACTIVE=1 "$fuzz_command_file"
post_start_target_status=$?
set -e
[[ "$post_start_target_status" -ne 0 ]]
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 1 ]]
rm -rf "$fuzz_remote_evidence" "$fake_sampler_state/units"
mkdir -p "$fake_sampler_state/units"
remove_readonly_test_tree "$fuzz_build_parent"

set +e
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SYSTEMCTL_START_INACTIVE=1 "$large_failed_plan/commands/h1-launch.sh"
post_start_soak_status=$?
set -e
[[ "$post_start_soak_status" -ne 0 ]]
large_failed_unit="$(tail -n +2 "$large_failed_plan/assignments.tsv" | cut -f3)"
[[ -f "$BORONDNS_CAMPAIGN_UNIT_ROOT/$large_failed_unit" ]]
grep -Fq "/var/tmp/borondns-campaign-runners/${large_failed_unit%.service}/attempt." \
    "$BORONDNS_CAMPAIGN_UNIT_ROOT/$large_failed_unit"
rm -rf "$large_failed_remote/host/h1" "$fake_sampler_state/units"
mkdir -p "$fake_sampler_state/units"
remove_readonly_test_tree "$large_build_parent"

target_symlink_victim="$workdir/target-symlink-victim"
mkdir "$target_symlink_victim"
ln -s "$target_symlink_victim" "$fuzz_remote_evidence"
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" "$fuzz_command_file"; then
    printf 'fuzz setup accepted a symlinked remote evidence root\n' >&2
    exit 1
fi
[[ -z "$(find "$target_symlink_victim" -mindepth 1 -print -quit)" ]]
rm "$fuzz_remote_evidence"
fuzz_build_victim="$workdir/remote-build-symlink-victim"
mkdir "$fuzz_build_victim"
ln -s "$fuzz_build_victim" "$fuzz_build_parent"
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" "$fuzz_command_file"; then
    printf 'fuzz setup accepted a symlinked remote build root\n' >&2
    exit 1
fi
[[ -z "$(find "$fuzz_build_victim" -mindepth 1 -print -quit)" ]]
rm "$fuzz_build_parent"
rm -rf "$fuzz_remote_evidence"
rm -f "$fake_sampler_state/failed-once"
set +e
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SAMPLER_SYSTEMCTL_FAIL_ONCE=1 "$fuzz_command_file"
target_setup_failure_status=$?
set -e
[[ "$target_setup_failure_status" -ne 0 ]]
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 1 ]]
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_command_file"
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 2 ]]
header_attempt="$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
mkdir "$header_attempt/evidence"
printf 'target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file\n' \
    >"$header_attempt/evidence/campaign-summary.tsv"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_command_file"
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 3 ]]
complete_attempt="$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
mkdir "$complete_attempt/evidence"
printf '%s\n' \
    $'target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file' \
    $'dns_datagram\tpassed\t0\t1\t1\t2\t1000000000\tlog\tartifacts\tcommand' \
    >"$complete_attempt/evidence/campaign-summary.tsv"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_command_file"
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 4 ]]
complete_attempt="$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
mkdir -p "$complete_attempt/evidence/logs" "$complete_attempt/evidence/artifacts/dns_datagram"
touch "$complete_attempt/evidence/logs/dns_datagram.log"
printf 'target=dns_datagram\n' >"$complete_attempt/evidence/logs/dns_datagram.command"
printf '%s\n' \
    $'target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file' \
    $'dns_datagram\tpassed\t0\t1\t1\t2\t1000000000\tlogs/dns_datagram.log\tartifacts/dns_datagram\tlogs/dns_datagram.command' \
    >"$complete_attempt/evidence/campaign-summary.tsv"
(
    cd "$complete_attempt/evidence"
    find . -type f ! -name artifact-manifest.sha256 ! -name campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$complete_attempt/evidence/artifact-manifest.sha256"
printf '%s\n' \
    status=passed \
    completed_utc=2026-07-13T12:00:00Z \
    target_count=1 \
    "summary_sha256=$(sha256sum "$complete_attempt/evidence/campaign-summary.tsv" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$complete_attempt/evidence/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$complete_attempt/evidence/campaign-completed.env"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_command_file"
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 4 ]]
outside_manifest_file="$complete_attempt/outside-fuzz-manifest.txt"
printf 'outside evidence\n' >"$outside_manifest_file"
printf '%s  ../outside-fuzz-manifest.txt\n' "$(sha256sum "$outside_manifest_file" | awk '{ print $1 }')" \
    >>"$complete_attempt/evidence/artifact-manifest.sha256"
printf '%s\n' \
    status=passed \
    completed_utc=2026-07-13T12:00:00Z \
    target_count=1 \
    "summary_sha256=$(sha256sum "$complete_attempt/evidence/campaign-summary.tsv" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$complete_attempt/evidence/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$complete_attempt/evidence/campaign-completed.env"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_command_file"
[[ "$(find "$fuzz_target_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 5 ]]
remove_readonly_test_tree "$fuzz_build_parent"

rm -rf "$fuzz_sample_dir" "$fake_sampler_state/units"
mkdir -p "$fake_sampler_state/units"
rm -f "$sampler_setup_lock" "$fake_sampler_state"/active-* "$fake_sampler_state/sampler-start-count"
set +e
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SAMPLER_START_DELAY=1 \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file" \
    >"$workdir/concurrent-sampler-one.log" 2>&1 &
concurrent_sampler_one=$!
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" FAKE_SAMPLER_START_DELAY=1 \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file" \
    >"$workdir/concurrent-sampler-two.log" 2>&1 &
concurrent_sampler_two=$!
wait "$concurrent_sampler_one"
concurrent_sampler_one_status=$?
wait "$concurrent_sampler_two"
concurrent_sampler_two_status=$?
set -e
if ! { [[ "$concurrent_sampler_one_status" == 0 && "$concurrent_sampler_two_status" != 0 ]] ||
    [[ "$concurrent_sampler_one_status" != 0 && "$concurrent_sampler_two_status" == 0 ]]; }; then
    cat "$workdir/concurrent-sampler-one.log" "$workdir/concurrent-sampler-two.log" >&2
    printf 'concurrent sampler resumes did not produce exactly one successful setup: one=%s two=%s\n' \
        "$concurrent_sampler_one_status" "$concurrent_sampler_two_status" >&2
    exit 1
fi
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 1 ]]
grep -Fqx 1 "$fake_sampler_state/sampler-start-count"
rm -rf "$fuzz_sample_dir" "$fake_sampler_state/units"
mkdir -p "$fake_sampler_state/units"
rm -f "$sampler_setup_lock" "$fake_sampler_state"/active-* "$fake_sampler_state/sampler-start-count"

sampler_symlink_victim="$workdir/sampler-symlink-victim"
mkdir -p "$fuzz_remote_evidence/host" "$sampler_symlink_victim"
ln -s "$sampler_symlink_victim" "$fuzz_sample_dir"
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" "$fuzz_sampler_command_file"; then
    printf 'sampler setup accepted a symlinked host evidence path\n' >&2
    exit 1
fi
[[ -z "$(find "$sampler_symlink_victim" -mindepth 1 -print -quit)" ]]
rm "$fuzz_sample_dir"

exec 7>"$sampler_setup_lock"
flock -n 7
if PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    "$fuzz_sampler_command_file"; then
    printf 'sampler setup accepted a concurrently held evidence lock\n' >&2
    exit 1
fi
[[ ! -e "$fuzz_sample_dir" ]]
flock -u 7
exec 7>&-
rm -f "$sampler_setup_lock"
rm -f "$fake_sampler_state/failed-once"
set +e
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    FAKE_SAMPLER_SYSTEMCTL_FAIL_ONCE=1 "$fuzz_sampler_command_file"
sampler_setup_failure_status=$?
set -e
[[ "$sampler_setup_failure_status" -ne 0 ]]
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name fuzz-units.txt | wc -l)" == 1 ]]
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    "$fuzz_sampler_command_file"
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name fuzz-units.txt | wc -l)" == 2 ]]
planned_sampler_deadline="$(tail -n +2 "$fuzz_plan_dir/host-samplers.tsv" | cut -f5)"
[[ "$planned_sampler_deadline" =~ ^[1-9][0-9]*$ ]]
sampler_crash_bin="$workdir/sampler-crash-bin"
mkdir "$sampler_crash_bin"
# The generated runner only needs is-active for this abrupt-death fixture.
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == is-active ]]; then printf "inactive\n"; exit 3; fi' \
    'exit 1' >"$sampler_crash_bin/systemctl"
chmod +x "$sampler_crash_bin/systemctl"
for crash_number in 1 2; do
    sampler_crash_runner="$(sed -n 's/^ExecStart=//p' \
        "$BORONDNS_CAMPAIGN_UNIT_ROOT/borondns-fuzz-operations-fuzz-test-host-sampler-fake-host.service")"
    sampler_crash_attempt="$(sed -n 's/^sample_dir=//p' "$sampler_crash_runner")"
    PATH="$sampler_crash_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$sampler_crash_runner" >"$workdir/sampler-crash-$crash_number.log" 2>&1 &
    sampler_crash_pid=$!
    sampler_crash_deadline=$((SECONDS + 5))
    until [[ -s "$sampler_crash_attempt/host-samples.tsv" ]]; do
        kill -0 "$sampler_crash_pid" 2>/dev/null || {
            cat "$workdir/sampler-crash-$crash_number.log" >&2
            printf 'sampler crash fixture exited before producing evidence\n' >&2
            exit 1
        }
        ((SECONDS < sampler_crash_deadline)) || {
            printf 'sampler crash fixture did not start in time\n' >&2
            exit 1
        }
        sleep 0.05
    done
    kill -KILL "$sampler_crash_pid"
    wait "$sampler_crash_pid" 2>/dev/null || true
    [[ ! -e "$sampler_crash_attempt/sampler-completed.env" && ! -e "$sampler_crash_attempt/sampler-hard-stop.env" ]]
    PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
        BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file"
done
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name run.sh | wc -l)" == 4 ]]
while IFS= read -r retained_deadline; do
    [[ "$retained_deadline" == "deadline_epoch=$planned_sampler_deadline" ]]
done < <(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name run.sh \
    -exec sed -n 's/^deadline_epoch=/deadline_epoch=/p' {} \;)
fuzz_sampler_runner="$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name run.sh \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
grep -Fqx "expected_commit=$source_commit" "$fuzz_sampler_runner"
# This is a literal fragment of the generated sampler runner.
# shellcheck disable=SC2016
grep -Fq 'flock -n "$sampler_lock_fd"' "$fuzz_sampler_runner"
grep -Fq 'sampler-hard-stop.env' "$fuzz_sampler_runner"
sampler_probe_source_units="$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name fuzz-units.txt \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
publish_sampler_test_runner() {
    local unit="$1" runner_candidate="$2" units_candidate="$3"
    local sampler_runner_sha256="" sampler_runner_device="" sampler_runner_inode=""
    local sampler_units_sha256="" sampler_units_device="" sampler_units_inode=""
    campaign_capture_candidate_identity "$runner_candidate" sampler_runner || return 1
    campaign_publish_root_runner "$unit" "$runner_candidate" \
        "$sampler_runner_sha256" "$sampler_runner_device" "$sampler_runner_inode" "sampler probe runner" || return 1
    campaign_capture_candidate_identity "$units_candidate" sampler_units || return 1
    campaign_publish_root_bound_file "$campaign_published_runner" "$units_candidate" fuzz-units.txt \
        "$sampler_units_sha256" "$sampler_units_device" "$sampler_units_inode" "sampler probe unit allowlist"
}
sampler_probe_bin="$workdir/sampler-probe-bin"
mkdir "$sampler_probe_bin"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == is-active ]]; then printf "probe unavailable\n" >&2; exit "${FAKE_PROBE_STATUS:-69}"; fi' \
    'exec /usr/bin/systemctl "$@"' >"$sampler_probe_bin/systemctl"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$*" == "+%s" ]]; then count=0; [[ ! -f "$FAKE_DATE_STATE" ]] || read -r count <"$FAKE_DATE_STATE"; count=$((count + 1)); printf "%s\n" "$count" >"$FAKE_DATE_STATE"; if ((count == 1)); then printf "1000\n"; else printf "1001\n"; fi; elif [[ "$*" == *"+%Y-%m-%dT%H:%M:%SZ"* ]]; then printf "2026-07-13T12:00:00Z\n"; else exec /usr/bin/date "$@"; fi' \
    >"$sampler_probe_bin/date"
chmod +x "$sampler_probe_bin/systemctl" "$sampler_probe_bin/date"
for sampler_probe_status in 69 77; do
    sampler_probe_attempt="$workdir/sampler-probe-$sampler_probe_status"
    sampler_probe_units="$sampler_probe_attempt/fuzz-units.txt"
    sampler_probe_runner="$sampler_probe_attempt/run.sh"
    mkdir "$sampler_probe_attempt"
    cp "$sampler_probe_source_units" "$sampler_probe_units"
    cp "$fuzz_sampler_runner" "$sampler_probe_runner"
    sed -i -e "s|^sample_dir=.*|sample_dir=$(printf '%q' "$sampler_probe_attempt")|" "$sampler_probe_runner"
    sampler_probe_unit="borondns-sampler-probe-$fixture_unit_suffix-$sampler_probe_status.service"
    publish_sampler_test_runner "$sampler_probe_unit" "$sampler_probe_runner" "$sampler_probe_units"
    sampler_probe_runner="$campaign_published_runner"
    if PATH="$sampler_probe_bin:$PATH" FAKE_PROBE_STATUS="$sampler_probe_status" \
        FAKE_DATE_STATE="$sampler_probe_attempt/date-state" "$sampler_probe_runner"; then
        printf 'sampler accepted failed systemd probe status %s as inactivity\n' "$sampler_probe_status" >&2
        exit 1
    fi
    [[ ! -e "$sampler_probe_attempt/sampler-completed.env" ]]
    mapfile -t sampler_probe_marker <"$sampler_probe_attempt/sampler-hard-stop.env"
    [[ "${#sampler_probe_marker[@]}" == 3 ]]
    [[ "${sampler_probe_marker[0]}" == sampler_hard_stop_utc=2026-07-13T12:00:00Z ]]
    [[ "${sampler_probe_marker[1]}" == active_units=0 ]]
    [[ "${sampler_probe_marker[2]}" == probe_failed=1 ]]
    campaign_remove_root_runner_tree "$sampler_probe_unit" "sampler probe fixture"
done
pid_exit_attempt="$workdir/sampler-pid-exit"
pid_exit_bin="$pid_exit_attempt/bin"
mkdir -p "$pid_exit_attempt" "$pid_exit_bin"
cp "$sampler_probe_source_units" "$pid_exit_attempt/fuzz-units.txt"
cp "$fuzz_sampler_runner" "$pid_exit_attempt/run.sh"
sed -i \
    -e "s|^sample_dir=.*|sample_dir=$(printf '%q' "$pid_exit_attempt")|" \
    -e 's/^deadline_epoch=.*/deadline_epoch=1001/' \
    "$pid_exit_attempt/run.sh"
pid_exit_unit="borondns-sampler-pid-exit-$fixture_unit_suffix.service"
publish_sampler_test_runner "$pid_exit_unit" "$pid_exit_attempt/run.sh" "$pid_exit_attempt/fuzz-units.txt"
pid_exit_runner="$campaign_published_runner"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == is-active ]]; then printf "active\n"; exit 0; fi' \
    'if [[ "${1:-}" == show ]]; then printf "MainPID=999999999\nControlGroup=/\n"; exit 0; fi' \
    'exit 1' >"$pid_exit_bin/systemctl"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$*" == "+%s" ]]; then count=0; [[ ! -f "$PID_EXIT_DATE_STATE" ]] || read -r count <"$PID_EXIT_DATE_STATE"; count=$((count + 1)); printf "%s\n" "$count" >"$PID_EXIT_DATE_STATE"; if ((count <= 2)); then printf "%s\n" "$((999 + count))"; else printf "5000\n"; fi; elif [[ "$*" == *"+%Y-%m-%dT%H:%M:%SZ"* ]]; then printf "2026-07-13T12:00:00Z\n"; else exec /usr/bin/date "$@"; fi' \
    >"$pid_exit_bin/date"
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$pid_exit_bin/ps"
chmod +x "$pid_exit_bin/systemctl" "$pid_exit_bin/date" "$pid_exit_bin/ps"
set +e
PATH="$pid_exit_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    PID_EXIT_DATE_STATE="$pid_exit_attempt/date-state" "$pid_exit_runner"
pid_exit_status=$?
set -e
if [[ "$pid_exit_status" -eq 0 ]]; then
    printf 'sampler PID-exit fixture unexpectedly passed\n' >&2
    exit 1
fi
if ! grep -Fqx probe_deadline_exhausted=1 "$pid_exit_attempt/sampler-hard-stop.env"; then
    printf 'sampler PID-exit fixture did not authenticate deadline exhaustion\n' >&2
    sed -n '1,20p' "$pid_exit_attempt/sampler-hard-stop.env" >&2
    exit 1
fi
if [[ -e "$pid_exit_attempt/sampler-completed.env" ]]; then
    printf 'sampler PID-exit fixture wrote a false completion marker\n' >&2
    exit 1
fi
campaign_remove_root_runner_tree "$pid_exit_unit" "sampler PID-exit fixture" || {
    printf 'sampler PID-exit fixture cleanup failed\n' >&2
    exit 1
}
sampler_sleep_attempt="$workdir/sampler-capped-sleep"
sampler_sleep_bin="$sampler_sleep_attempt/bin"
sampler_sleep_log="$sampler_sleep_attempt/sleep.log"
mkdir -p "$sampler_sleep_attempt" "$sampler_sleep_bin"
cp "$sampler_probe_source_units" "$sampler_sleep_attempt/fuzz-units.txt"
cp "$fuzz_sampler_runner" "$sampler_sleep_attempt/run.sh"
sed -i \
    -e "s|^sample_dir=.*|sample_dir=$(printf '%q' "$sampler_sleep_attempt")|" \
    -e 's/^interval=.*/interval=999/' \
    -e 's/^deadline_epoch=.*/deadline_epoch=1001/' \
    "$sampler_sleep_attempt/run.sh"
sampler_sleep_unit="borondns-sampler-capped-sleep-$fixture_unit_suffix.service"
publish_sampler_test_runner "$sampler_sleep_unit" "$sampler_sleep_attempt/run.sh" "$sampler_sleep_attempt/fuzz-units.txt"
sampler_sleep_runner="$campaign_published_runner"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == is-active ]]; then printf "inactive\n"; exit 3; fi' \
    'exit 1' >"$sampler_sleep_bin/systemctl"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$*" == "+%s" ]]; then printf "1000\n"; elif [[ "$*" == *"+%Y-%m-%dT%H:%M:%SZ"* ]]; then printf "1970-01-01T00:16:40Z\n"; else exec /usr/bin/date "$@"; fi' \
    >"$sampler_sleep_bin/date"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$1" >>"$SAMPLER_SLEEP_LOG"' 'exit 77' \
    >"$sampler_sleep_bin/sleep"
chmod +x "$sampler_sleep_bin"/*
set +e
PATH="$sampler_sleep_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SAMPLER_SLEEP_LOG="$sampler_sleep_log" "$sampler_sleep_runner"
sampler_sleep_status=$?
set -e
if [[ "$sampler_sleep_status" -eq 0 ]]; then
    printf 'sampler capped-sleep fixture unexpectedly passed\n' >&2
    exit 1
fi
if ! grep -Fqx 1 "$sampler_sleep_log"; then
    printf 'sampler capped-sleep fixture did not cap sleep to one second (status=%s)\n' \
        "$sampler_sleep_status" >&2
    [[ ! -e "$sampler_sleep_log" ]] || sed -n '1,20p' "$sampler_sleep_log" >&2
    exit 1
fi
campaign_remove_root_runner_tree "$sampler_sleep_unit" "sampler capped sleep fixture"

# Execute the generated sampler loop through its ordinary sleep/deadline path.
# Inactive units must yield a real terminal row and completion marker within
# the derived post-deadline probe reserve, never a fabricated marker fixture.
sampler_terminal_attempt="$workdir/sampler-terminal-success"
sampler_terminal_bin="$sampler_terminal_attempt/bin"
sampler_terminal_sleep_log="$sampler_terminal_attempt/sleep.log"
sampler_terminal_date_state="$sampler_terminal_attempt/date-state"
mkdir -p "$sampler_terminal_attempt" "$sampler_terminal_bin"
cp "$sampler_probe_source_units" "$sampler_terminal_attempt/fuzz-units.txt"
cp "$fuzz_sampler_runner" "$sampler_terminal_attempt/run.sh"
sed -i \
    -e "s|^sample_dir=.*|sample_dir=$(printf '%q' "$sampler_terminal_attempt")|" \
    -e 's/^interval=.*/interval=999/' \
    -e 's/^deadline_epoch=.*/deadline_epoch=1001/' \
    "$sampler_terminal_attempt/run.sh"
sampler_terminal_unit="borondns-sampler-terminal-$fixture_unit_suffix.service"
publish_sampler_test_runner "$sampler_terminal_unit" "$sampler_terminal_attempt/run.sh" \
    "$sampler_terminal_attempt/fuzz-units.txt"
sampler_terminal_runner="$campaign_published_runner"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == is-active ]]; then printf "inactive\n"; exit 3; fi' \
    'exit 1' >"$sampler_terminal_bin/systemctl"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'epoch="$(<"$SAMPLER_TERMINAL_DATE_STATE")"' \
    'if [[ "$*" == "+%s" ]]; then printf "%s\n" "$epoch"; elif [[ "$*" == *"+%Y-%m-%dT%H:%M:%SZ"* ]]; then /usr/bin/date -u -d "@$epoch" "+%Y-%m-%dT%H:%M:%SZ"; else exec /usr/bin/date "$@"; fi' \
    >"$sampler_terminal_bin/date"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'printf "%s\n" "$1" >>"$SAMPLER_TERMINAL_SLEEP_LOG"' \
    'printf "1001\n" >"$SAMPLER_TERMINAL_DATE_STATE"' \
    >"$sampler_terminal_bin/sleep"
chmod +x "$sampler_terminal_bin"/*
printf '1000\n' >"$sampler_terminal_date_state"
PATH="$sampler_terminal_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SAMPLER_TERMINAL_DATE_STATE="$sampler_terminal_date_state" \
    SAMPLER_TERMINAL_SLEEP_LOG="$sampler_terminal_sleep_log" \
    "$sampler_terminal_runner"
grep -Fqx 1 "$sampler_terminal_sleep_log"
[[ ! -e "$sampler_terminal_attempt/sampler-hard-stop.env" ]]
grep -Fqx status=passed "$sampler_terminal_attempt/sampler-completed.env"
grep -Fqx completed_epoch_seconds=1001 "$sampler_terminal_attempt/sampler-completed.env"
grep -Fqx last_sample_epoch_seconds=1001 "$sampler_terminal_attempt/sampler-completed.env"
tail -n 1 "$sampler_terminal_attempt/host-samples.tsv" |
    awk -F '\t' '$2 == 1001 && $3 == 0 { found = 1 } END { exit !found }'
campaign_remove_root_runner_tree "$sampler_terminal_unit" "sampler terminal success fixture"
set +e
latest_units="$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name fuzz-units.txt \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
latest_units_status=$?
set -e
if [[ "$latest_units_status" -ne 0 || -z "$latest_units" || ! -f "$latest_units" ]]; then
    printf 'sampler rerun fixture could not select its latest allowlist: status=%s path=%s\n' \
        "$latest_units_status" "$latest_units" >&2
    exit 1
fi
printf 'operator sentinel\n' >>"$latest_units"
set +e
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    "$fuzz_sampler_command_file"
sampler_rerun_status=$?
set -e
if [[ "$sampler_rerun_status" -ne 0 ]]; then
    printf 'sampler rerun fixture failed before preserving its prior allowlist (status=%s)\n' \
        "$sampler_rerun_status" >&2
    exit 1
fi
if ! grep -Fqx 'operator sentinel' "$latest_units"; then
    printf 'sampler rerun overwrote a completed attempt allowlist: %s\n' "$latest_units" >&2
    exit 1
fi
sampler_attempt_count="$(find "$fuzz_sample_dir/attempts" -mindepth 2 -maxdepth 2 -type f -name fuzz-units.txt | wc -l)"
if [[ "$sampler_attempt_count" != 5 ]]; then
    printf 'sampler rerun created an unexpected attempt count: %s\n' "$sampler_attempt_count" >&2
    exit 1
fi
sampler_header_attempt="$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
printf 'timestamp_utc\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib\n' \
    >"$sampler_header_attempt/host-samples.tsv"
sampler_header_resume_status=0
if (PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file"); then
    sampler_header_resume_status=0
else
    sampler_header_resume_status=$?
fi
if [[ "$sampler_header_resume_status" -ne 0 ]]; then
    printf 'sampler invalid-header resume failed: status=%s\n' "$sampler_header_resume_status" >&2
    exit 1
fi
sampler_header_attempt_count="$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)"
if [[ "$sampler_header_attempt_count" != 6 ]]; then
    printf 'sampler invalid-header resume created an unexpected attempt count: %s\n' \
        "$sampler_header_attempt_count" >&2
    exit 1
fi
sampler_complete_attempt="$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' \
    -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
sampler_complete_started=$((planned_sampler_deadline - 1))
planned_sampler_interval="$(sed -n 's/^interval=//p' "$sampler_complete_attempt/run.sh")"
[[ "$planned_sampler_interval" =~ ^[1-9][0-9]*$ ]]
sampler_complete_started_utc="$(date -u -d "@$sampler_complete_started" '+%Y-%m-%dT%H:%M:%SZ')"
sampler_complete_utc="$(date -u -d "@$planned_sampler_deadline" '+%Y-%m-%dT%H:%M:%SZ')"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib' \
    "$(printf '%s\t%s\t0\t0\t0.00\t0\t0.0\t0.0\t0.0\t1' "$sampler_complete_utc" "$planned_sampler_deadline")" \
    >"$sampler_complete_attempt/host-samples.tsv"
printf '%s\n' $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
    >"$sampler_complete_attempt/process-samples.tsv"
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=%s\ndeadline_epoch_seconds=%s\nstarted_utc=%s\nstarted_epoch_seconds=%s\n' \
    "$source_commit" "$planned_sampler_interval" "$planned_sampler_deadline" \
    "$sampler_complete_started_utc" "$sampler_complete_started" \
    >"$sampler_complete_attempt/sampler.env"
printf '%s\n' status=passed "completed_utc=$sampler_complete_utc" \
    "completed_epoch_seconds=$planned_sampler_deadline" active_units=0 \
    "deadline_epoch_seconds=$planned_sampler_deadline" "last_sample_epoch_seconds=$planned_sampler_deadline" \
    >"$sampler_complete_attempt/sampler-completed.env"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file"
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 6 ]]
printf '%s\n' $'malformed\t0\t0\t0\t0\t0\t0\t0\t0\t0' >>"$sampler_complete_attempt/host-samples.tsv"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file"
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 7 ]]
sed -i '$d' "$sampler_complete_attempt/host-samples.tsv"
rm "$sampler_complete_attempt/sampler-completed.env"
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=1 \
    >"$sampler_complete_attempt/sampler-hard-stop.env"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file"
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 7 ]]
printf '%s\n' unexpected_terminal_field=1 >>"$sampler_complete_attempt/sampler-hard-stop.env"
PATH="$fake_sampler_bin:$PATH" FAKE_SAMPLER_STATE="$fake_sampler_state" \
    BORONDNS_CAMPAIGN_REQUIRE_RESUME=1 "$fuzz_sampler_command_file"
[[ "$(find "$fuzz_sample_dir/attempts" -mindepth 1 -maxdepth 1 -type d -name 'attempt.*' | wc -l)" == 8 ]]
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$fuzz_plan_dir" --campaign-id operations-fuzz-test \
    --host fake-host --remote-repo "$fuzz_remote_repo" --remote-evidence "$fuzz_remote_evidence" \
    --duration 1 --target dns_datagram; then
    printf 'fuzz campaign plan overwrite was not refused\n' >&2
    exit 1
fi

malicious_fuzz_plan="$workdir/malicious-fuzz-plan"
cp -a "$fuzz_plan_dir" "$malicious_fuzz_plan"
# Deliberately literal shell syntax must remain inert metadata.
# shellcheck disable=SC2016
printf 'campaign_id=$(touch /tmp/borondns-campaign-injection)\n' >"$malicious_fuzz_plan/campaign.env"
rm -f /tmp/borondns-campaign-injection
if "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" status --evidence-dir "$malicious_fuzz_plan"; then
    printf 'fuzz status accepted malformed executable campaign metadata\n' >&2
    exit 1
fi
[[ ! -e /tmp/borondns-campaign-injection ]]

validator_fixture="$workdir/validator-fuzz-host"
validator_attempt="$validator_fixture/fuzz/000-dns_datagram/attempts/attempt.complete/evidence"
mkdir -p "$(dirname "$validator_attempt")"
cp -a "$workdir/poison-evidence" "$validator_attempt"
sed -i \
    -e "s/^source_commit=.*/source_commit=$source_commit/" \
    -e 's/^source_clean=.*/source_clean=1/' \
    -e "s/^cargo_sha256=.*/cargo_sha256=$test_cargo_sha256/" \
    -e "s/^cargo_executed_sha256=.*/cargo_executed_sha256=$test_cargo_sha256/" \
    -e "s/^rustc_sha256=.*/rustc_sha256=$test_rustc_sha256/" \
    -e "s/^rustc_executed_sha256=.*/rustc_executed_sha256=$test_rustc_sha256/" \
    -e "s/^rustc_runtime_tree_sha256=.*/rustc_runtime_tree_sha256=$test_rustc_sha256/" \
    -e "s/^rustc_executed_sha256=.*/rustc_executed_sha256=$test_rustc_sha256/" \
    -e "s/^cargo_fuzz_sha256=.*/cargo_fuzz_sha256=$test_cargo_fuzz_sha256/" \
    -e "s/^cargo_fuzz_executed_sha256=.*/cargo_fuzz_executed_sha256=$test_cargo_fuzz_sha256/" \
    "$validator_attempt/config.txt"
rm -f "$validator_attempt/artifact-manifest.sha256" "$validator_attempt/campaign-completed.env"
mkdir -p "$validator_attempt/artifacts/dns_datagram/nested-controls"
printf 'nested completion evidence\n' >"$validator_attempt/artifacts/dns_datagram/nested-controls/campaign-completed.env"
printf 'nested manifest evidence\n' >"$validator_attempt/artifacts/dns_datagram/nested-controls/artifact-manifest.sha256"
printf 'nested staging evidence\n' >"$validator_attempt/artifacts/dns_datagram/nested-controls/.artifact-manifest.fixture"
(
    cd "$validator_attempt"
    find . -type f \
        ! -path ./artifact-manifest.sha256 \
        ! -path ./campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$validator_attempt/artifact-manifest.sha256"
printf '%s\n' \
    status=passed \
    completed_utc=2026-07-13T12:00:00Z \
    target_count=1 \
    "summary_sha256=$(sha256sum "$validator_attempt/campaign-summary.tsv" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$validator_attempt/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$validator_attempt/campaign-completed.env"
mkdir -p "$validator_fixture/fuzz/000-dns_datagram/attempts/attempt.partial/evidence" \
    "$validator_fixture/fuzz/000-dns_datagram/attempts/attempt.setup/evidence"
printf 'interrupted attempt\n' >"$validator_fixture/fuzz/000-dns_datagram/attempts/attempt.partial/evidence/partial.log"
printf '#!/usr/bin/env bash\nexit 1\n' \
    >"$validator_fixture/fuzz/000-dns_datagram/attempts/attempt.setup/run.sh"
printf '%s\n' \
    $'target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file' \
    >"$validator_fixture/fuzz/000-dns_datagram/attempts/attempt.setup/evidence/campaign-summary.tsv"
python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-target 001-transfer_stream \
    --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}" \
    >"$workdir/validator-fixture.tsv"
grep -Fq $'target\t000-dns_datagram\tattempt.complete\tcomplete' "$workdir/validator-fixture.tsv"
grep -Fq $'target\t001-transfer_stream\tnone\tincomplete' "$workdir/validator-fixture.tsv"
grep -Fq 'artifacts/dns_datagram/nested-controls/campaign-completed.env' "$validator_attempt/artifact-manifest.sha256"
grep -Fq 'artifacts/dns_datagram/nested-controls/artifact-manifest.sha256' "$validator_attempt/artifact-manifest.sha256"
grep -Fq 'artifacts/dns_datagram/nested-controls/.artifact-manifest.fixture' "$validator_attempt/artifact-manifest.sha256"
failed_then_passed_fixture="$workdir/validator-failed-then-passed-host"
cp -a "$validator_fixture" "$failed_then_passed_fixture"
failed_then_passed_attempt="$failed_then_passed_fixture/fuzz/000-dns_datagram/attempts/attempt.crashed/evidence"
mkdir -p "$failed_then_passed_attempt/artifacts/dns_datagram"
printf '%s\n' \
    $'target\tstatus\texit_status\tduration_seconds\tstarted_epoch_seconds\tended_epoch_seconds\telapsed_nanoseconds\tlog_path\tartifact_dir\tcommand_file' \
    $'dns_datagram\tfailed\t70\t1\t1\t2\t1000000000\tlogs/dns_datagram.log\tartifacts/dns_datagram\tlogs/dns_datagram.command' \
    >"$failed_then_passed_attempt/campaign-summary.tsv"
printf 'AddressSanitizer: hostile crash fixture\n' \
    >"$failed_then_passed_attempt/artifacts/dns_datagram/crash-input"
python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$failed_then_passed_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}" \
    >"$workdir/validator-failed-then-passed.tsv"
grep -Fq $'target\t000-dns_datagram\tattempt.crashed\tfailed' \
    "$workdir/validator-failed-then-passed.tsv"
IFS=$'\t' read -r _ _ _ _ validator_target_start validator_target_end _elapsed _ _ _ \
    < <(tail -n +2 "$validator_attempt/campaign-summary.tsv")

short_elapsed_fixture="$workdir/validator-short-elapsed-host"
cp -a "$validator_fixture" "$short_elapsed_fixture"
short_elapsed_attempt="$short_elapsed_fixture/fuzz/000-dns_datagram/attempts/attempt.complete/evidence"
awk -F '\t' -v OFS='\t' 'NR == 2 { $7 = 0 } { print }' \
    "$short_elapsed_attempt/campaign-summary.tsv" >"$short_elapsed_attempt/campaign-summary.tsv.new"
mv "$short_elapsed_attempt/campaign-summary.tsv.new" "$short_elapsed_attempt/campaign-summary.tsv"
rm "$short_elapsed_attempt/artifact-manifest.sha256" "$short_elapsed_attempt/campaign-completed.env"
(
    cd "$short_elapsed_attempt"
    find . -type f ! -path ./artifact-manifest.sha256 ! -path ./campaign-completed.env -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum
) >"$short_elapsed_attempt/artifact-manifest.sha256"
printf '%s\n' \
    status=passed \
    completed_utc=2026-07-13T12:00:00Z \
    target_count=1 \
    "summary_sha256=$(sha256sum "$short_elapsed_attempt/campaign-summary.tsv" | awk '{ print $1 }')" \
    "artifact_manifest_sha256=$(sha256sum "$short_elapsed_attempt/artifact-manifest.sha256" | awk '{ print $1 }')" \
    >"$short_elapsed_attempt/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$short_elapsed_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}"; then
    printf 'local collection validator accepted authenticated short-duration fuzz evidence\n' >&2
    exit 1
fi

refresh_fuzz_attempt_terminal_hashes() {
    local attempt="$1"
    rm -f "$attempt/artifact-manifest.sha256" "$attempt/campaign-completed.env"
    (
        cd "$attempt"
        find . -type f ! -path ./artifact-manifest.sha256 ! -path ./campaign-completed.env -printf '%P\0' |
            LC_ALL=C sort -z | xargs -0 sha256sum
    ) >"$attempt/artifact-manifest.sha256"
    printf '%s\n' \
        status=passed \
        completed_utc=2026-07-13T12:00:00Z \
        target_count=1 \
        "summary_sha256=$(sha256sum "$attempt/campaign-summary.tsv" | awk '{ print $1 }')" \
        "artifact_manifest_sha256=$(sha256sum "$attempt/artifact-manifest.sha256" | awk '{ print $1 }')" \
        >"$attempt/campaign-completed.env"
}

for fuzz_clock_mutation in zero-wall huge-elapsed; do
    fuzz_clock_fixture="$workdir/validator-$fuzz_clock_mutation-host"
    cp -a "$validator_fixture" "$fuzz_clock_fixture"
    fuzz_clock_attempt="$fuzz_clock_fixture/fuzz/000-dns_datagram/attempts/attempt.complete/evidence"
    case "$fuzz_clock_mutation" in
    zero-wall)
        awk -F '\t' -v OFS='\t' 'NR == 2 { $6 = $5 } { print }' \
            "$fuzz_clock_attempt/campaign-summary.tsv" >"$fuzz_clock_attempt/campaign-summary.tsv.new"
        ;;
    huge-elapsed)
        awk -F '\t' -v OFS='\t' 'NR == 2 { $7 = 999999999999999999 } { print }' \
            "$fuzz_clock_attempt/campaign-summary.tsv" >"$fuzz_clock_attempt/campaign-summary.tsv.new"
        ;;
    esac
    mv "$fuzz_clock_attempt/campaign-summary.tsv.new" "$fuzz_clock_attempt/campaign-summary.tsv"
    refresh_fuzz_attempt_terminal_hashes "$fuzz_clock_attempt"
    if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
        "$fuzz_clock_fixture" "$source_commit" --expected-target 000-dns_datagram \
        --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}"; then
        printf 'local collection validator accepted %s fuzz timing evidence\n' "$fuzz_clock_mutation" >&2
        exit 1
    fi
done
unset -f refresh_fuzz_attempt_terminal_hashes

validator_sampler_deadline=$((validator_target_end + 2))
validator_sampler_attempt="$validator_fixture/host/h1/attempts/attempt.coverage"
mkdir -p "$validator_sampler_attempt"
validator_target_start_utc="$(date -u -d "@$validator_target_start" '+%Y-%m-%dT%H:%M:%SZ')"
validator_sampler_deadline_utc="$(date -u -d "@$validator_sampler_deadline" '+%Y-%m-%dT%H:%M:%SZ')"
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=1\ndeadline_epoch_seconds=%s\nstarted_utc=%s\nstarted_epoch_seconds=%s\n' \
    "$source_commit" "$validator_sampler_deadline" "$validator_target_start_utc" "$validator_target_start" \
    >"$validator_sampler_attempt/sampler.env"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib' \
    "$(printf '%s\t%s\t1\t1\t0.00\t1\t0.0\t0.0\t0.0\t1' "$validator_target_start_utc" "$validator_target_start")" \
    "$(printf '%s\t%s\t0\t0\t0.00\t0\t0.0\t0.0\t0.0\t1' "$validator_sampler_deadline_utc" "$validator_sampler_deadline")" \
    >"$validator_sampler_attempt/host-samples.tsv"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
    "$(printf '%s\t%s\t123\t0.00\t0.0\t1\t00:01\tborondns' \
        "$validator_target_start_utc" "$validator_target_start")" \
    >"$validator_sampler_attempt/process-samples.tsv"
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service >"$validator_sampler_attempt/fuzz-units.txt"
printf '%s\n' status=passed "completed_utc=$validator_sampler_deadline_utc" \
    "completed_epoch_seconds=$validator_sampler_deadline" active_units=0 \
    "deadline_epoch_seconds=$validator_sampler_deadline" "last_sample_epoch_seconds=$validator_sampler_deadline" \
    >"$validator_sampler_attempt/sampler-completed.env"
python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}" >/dev/null
validator_delayed_sampler_start=$((validator_target_start - 7))
validator_delayed_sampler_start_utc="$(date -u -d "@$validator_delayed_sampler_start" '+%Y-%m-%dT%H:%M:%SZ')"
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=1\ndeadline_epoch_seconds=%s\nstarted_utc=%s\nstarted_epoch_seconds=%s\n' \
    "$source_commit" "$validator_sampler_deadline" "$validator_delayed_sampler_start_utc" \
    "$validator_delayed_sampler_start" >"$validator_sampler_attempt/sampler.env"
python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}" >/dev/null
validator_excessive_sampler_delay=$((validator_target_start - 16))
validator_excessive_sampler_delay_utc="$(date -u -d "@$validator_excessive_sampler_delay" '+%Y-%m-%dT%H:%M:%SZ')"
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=1\ndeadline_epoch_seconds=%s\nstarted_utc=%s\nstarted_epoch_seconds=%s\n' \
    "$source_commit" "$validator_sampler_deadline" "$validator_excessive_sampler_delay_utc" \
    "$validator_excessive_sampler_delay" >"$validator_sampler_attempt/sampler.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted a first row beyond its authenticated probe allowance\n' >&2
    exit 1
fi
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=1\ndeadline_epoch_seconds=%s\nstarted_utc=%s\nstarted_epoch_seconds=%s\n' \
    "$source_commit" "$validator_sampler_deadline" "$validator_target_start_utc" \
    "$validator_target_start" >"$validator_sampler_attempt/sampler.env"
printf '%s\n' borondns-fuzz-fixture-99-invented.service >"$validator_sampler_attempt/fuzz-units.txt"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted an invented evidence unit\n' >&2
    exit 1
fi
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service \
    borondns-fuzz-fixture-0-dns_datagram.service >"$validator_sampler_attempt/fuzz-units.txt"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted duplicate evidence units\n' >&2
    exit 1
fi
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service \
    borondns-fuzz-fixture-1-transfer_stream.service >"$validator_sampler_attempt/fuzz-units.txt"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted an extra evidence unit\n' >&2
    exit 1
fi
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service >"$validator_sampler_attempt/fuzz-units.txt"
validator_late_start=$((validator_target_start + 1))
validator_late_start_utc="$(date -u -d "@$validator_late_start" '+%Y-%m-%dT%H:%M:%SZ')"
sed -i "2s/$validator_target_start_utc/$validator_late_start_utc/;2s/$validator_target_start/$validator_late_start/" \
    "$validator_sampler_attempt/host-samples.tsv"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --expected-sampler h1 \
    --expected-sampler-interval 1 --expected-sampler-deadline "$validator_sampler_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted a first sample after the target execution began\n' >&2
    exit 1
fi
rm -rf "$validator_fixture/host"
printf 'tampered nested completion evidence\n' >"$validator_attempt/artifacts/dns_datagram/nested-controls/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-target 001-transfer_stream \
    --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}"; then
    printf 'local collection validator accepted tampered nested control-name evidence\n' >&2
    exit 1
fi
printf 'nested completion evidence\n' >"$validator_attempt/artifacts/dns_datagram/nested-controls/campaign-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-target 001-transfer_stream \
    --expected-duration 1 --no-sampler --expected-toolchain default \
    --expected-sanitizer cargo-fuzz-default \
    --expected-cargo-sha256 "$(printf '0%.0s' {1..64})" \
    --expected-rustc-sha256 "$test_rustc_sha256" \
    --expected-cargo-fuzz-sha256 "$test_cargo_fuzz_sha256"; then
    printf 'local collection validator accepted fuzz evidence from the wrong cargo binary\n' >&2
    exit 1
fi
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-target 001-transfer_stream \
    --expected-duration 1 --no-sampler --expected-toolchain nightly \
    --expected-sanitizer cargo-fuzz-default; then
    printf 'local collection validator accepted fuzz evidence from the wrong toolchain\n' >&2
    exit 1
fi
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-target 001-transfer_stream \
    --expected-duration 1 --no-sampler --expected-toolchain default \
    --expected-sanitizer thread; then
    printf 'local collection validator accepted fuzz evidence from the wrong sanitizer\n' >&2
    exit 1
fi
printf 'unexpected entity\n' >"$validator_fixture/fuzz/operator-note"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}"; then
    printf 'local collection validator accepted an unexpected regular entity\n' >&2
    exit 1
fi

sampler_validator_fixture="$workdir/validator-sampler-terminals"
sampler_validator_attempt="$sampler_validator_fixture/host/h1/attempts/attempt.invalid"
mkdir -p "$sampler_validator_fixture/fuzz/000-dns_datagram/attempts" "$sampler_validator_attempt"
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service >"$sampler_validator_attempt/fuzz-units.txt"
sampler_validator_start=1783944000
sampler_validator_deadline=1783944001
sampler_validator_schedule=(
    --expected-sampler-interval 1 --expected-sampler-deadline "$sampler_validator_deadline"
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service
)
sampler_terminal_fixture_validates() {
    python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
        "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
        --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" \
        "${fuzz_validator_policy[@]}" >/dev/null
}
printf 'source_commit=%s\nsource_clean=1\nsample_interval_seconds=1\ndeadline_epoch_seconds=%s\nstarted_utc=2026-07-13T12:00:00Z\nstarted_epoch_seconds=%s\n' \
    "$source_commit" "$sampler_validator_deadline" "$sampler_validator_start" \
    >"$sampler_validator_attempt/sampler.env"
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=0 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted hard stop with no active unit or exhausted probe\n' >&2
    exit 1
fi
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=0 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}" >/dev/null
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=2 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
if sampler_terminal_fixture_validates; then
    printf 'sampler validator accepted active units beyond its exact allowlist\n' >&2
    exit 1
fi
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=0 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"

printf '%s\n' sampler_hard_stop_utc=2099-01-01T00:00:00Z active_units=0 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted a hard-stop timestamp after terminal reserve\n' >&2
    exit 1
fi
printf '%s\n' sampler_hard_stop_utc=2026-07-13T11:59:59Z active_units=0 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted a hard-stop timestamp before sampler start\n' >&2
    exit 1
fi

# A valid hard stop may have header-only files when its first probe fails, and
# may contain canonical samples that end no later than the terminal marker.
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=0 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib' \
    $'2026-07-13T12:00:00Z\t1783944000\t1\t0\t0.00\t0\t0.0\t0.0\t0.0\t1' \
    >"$sampler_validator_attempt/host-samples.tsv"
printf '%s\n' $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
    >"$sampler_validator_attempt/process-samples.tsv"
python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" \
    "${fuzz_validator_policy[@]}" >/dev/null
printf 'malformed\n' >>"$sampler_validator_attempt/host-samples.tsv"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted malformed present hard-stop samples\n' >&2
    exit 1
fi
rm "$sampler_validator_attempt/host-samples.tsv" "$sampler_validator_attempt/process-samples.tsv"

printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=0 probe_failed=0 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted a noncanonical probe-failure marker\n' >&2
    exit 1
fi
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
printf '%s\n' status=passed completed_utc=2026-07-13T12:00:01Z \
    "completed_epoch_seconds=$sampler_validator_deadline" active_units=0 \
    "deadline_epoch_seconds=$sampler_validator_deadline" "last_sample_epoch_seconds=$sampler_validator_deadline" \
    >"$sampler_validator_attempt/sampler-completed.env"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib' \
    $'2026-07-13T12:00:00Z\t1783944000\t1\t2\t0.30\t4\t0.0\t0.0\t0.0\t1' \
    $'2026-07-13T12:00:01Z\t1783944001\t0\t1\t0.20\t3\t0.0\t0.0\t0.0\t1' \
    >"$sampler_validator_attempt/host-samples.tsv"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
    $'2026-07-13T12:00:00Z\t1783944000\t123\t0.10\t0.1\t2\t00:01\tborondns' \
    $'2026-07-13T12:00:00Z\t1783944000\t456\t0.20\t0.1\t2\t00:01\tborondns' \
    $'2026-07-13T12:00:01Z\t1783944001\t123\t0.20\t0.1\t3\t00:02\tborondns' \
    >"$sampler_validator_attempt/process-samples.tsv"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted simultaneous completion and hard-stop markers\n' >&2
    exit 1
fi
rm "$sampler_validator_attempt/sampler-hard-stop.env"
sampler_terminal_fixture_validates
fuzz_sampler_valid_hosts="$workdir/fuzz-sampler-valid-hosts.tsv"
fuzz_sampler_valid_processes="$workdir/fuzz-sampler-valid-processes.tsv"
cp "$sampler_validator_attempt/host-samples.tsv" "$fuzz_sampler_valid_hosts"
cp "$sampler_validator_attempt/process-samples.tsv" "$fuzz_sampler_valid_processes"

# The embedded resume classifier must authenticate marker-only hard stops
# against the canonical unit allowlist even when no sampler TSV exists.
eval "$(sed -n '/^sampler_process_evidence_consistent() {/,/^}/p' \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh")"
eval "$(sed -n '/^sampler_attempt_hard_stopped() {/,/^}/p' \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh")"
inline_hard_stop_attempt="$workdir/inline-marker-only-hard-stop"
mkdir "$inline_hard_stop_attempt"
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service \
    >"$inline_hard_stop_attempt/fuzz-units.txt"
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=2 probe_failed=1 \
    >"$inline_hard_stop_attempt/sampler-hard-stop.env"
if sampler_attempt_hard_stopped "$inline_hard_stop_attempt"; then
    printf 'inline sampler classifier accepted marker active units beyond its allowlist\n' >&2
    exit 1
fi
sed -i 's/^active_units=2$/active_units=1/' \
    "$inline_hard_stop_attempt/sampler-hard-stop.env"
sampler_attempt_hard_stopped "$inline_hard_stop_attempt"
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service \
    >>"$inline_hard_stop_attempt/fuzz-units.txt"
if sampler_attempt_hard_stopped "$inline_hard_stop_attempt"; then
    printf 'inline sampler classifier accepted a duplicate unit allowlist\n' >&2
    exit 1
fi

# GNU awk emits the half-up edge 0.005 as 0.01. Both embedded and external
# validators must enforce that exact aggregate rather than Decimal half-even.
[[ "$(LC_ALL=C awk 'BEGIN { printf "%.2f", 0.005 }')" == 0.01 ]]
inline_rounding_attempt="$workdir/inline-round-half-up"
mkdir "$inline_rounding_attempt"
printf '%s\n' borondns-fuzz-fixture-0-dns_datagram.service \
    >"$inline_rounding_attempt/fuzz-units.txt"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib' \
    $'2026-07-13T12:00:00Z\t1783944000\t1\t1\t0.01\t2\t0.0\t0.0\t0.0\t1' \
    >"$inline_rounding_attempt/host-samples.tsv"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
    $'2026-07-13T12:00:00Z\t1783944000\t123\t0.005\t0.1\t2\t00:01\tborondns' \
    >"$inline_rounding_attempt/process-samples.tsv"
sampler_process_evidence_consistent "$inline_rounding_attempt"
sed -i 's/\t0[.]01\t2\t/\t0.00\t2\t/' "$inline_rounding_attempt/host-samples.tsv"
if sampler_process_evidence_consistent "$inline_rounding_attempt"; then
    printf 'inline sampler validator accepted half-even CPU evidence at 0.005\n' >&2
    exit 1
fi

# Exercise the same edge through the complete collection validator.
awk -F '\t' 'BEGIN { OFS="\t" } NR == 1 || NR == 2 || NR == 4 { print }' \
    "$fuzz_sampler_valid_processes" >"$sampler_validator_attempt/process-samples.tsv"
sed -i -e '2s/\t2\t0[.]30\t4\t/\t1\t0.01\t2\t/' \
    -e '2s/\t0[.]10\t/\t0.005\t/' \
    "$sampler_validator_attempt/process-samples.tsv" \
    "$sampler_validator_attempt/host-samples.tsv"
sampler_terminal_fixture_validates
sed -i '2s/\t0[.]01\t2\t/\t0.00\t2\t/' "$sampler_validator_attempt/host-samples.tsv"
if sampler_terminal_fixture_validates; then
    printf 'collection validator accepted half-even CPU evidence at 0.005\n' >&2
    exit 1
fi
cp "$fuzz_sampler_valid_hosts" "$sampler_validator_attempt/host-samples.tsv"
cp "$fuzz_sampler_valid_processes" "$sampler_validator_attempt/process-samples.tsv"

# A PID may recur in a later sample, but never twice in one exact sample key.
duplicate_fuzz_process_row="$(sed -n '2p' "$sampler_validator_attempt/process-samples.tsv")"
printf '%s\n' "$duplicate_fuzz_process_row" >>"$sampler_validator_attempt/process-samples.tsv"
if sampler_terminal_fixture_validates; then
    printf 'sampler validator accepted a duplicate PID within one sample\n' >&2
    exit 1
fi
cp "$fuzz_sampler_valid_processes" "$sampler_validator_attempt/process-samples.tsv"

# Process detail must use an authenticated host timestamp+epoch key.
printf '%s\n' $'2099-01-01T00:00:00Z\t4070908800\t999\t0.10\t0.1\t1\t00:01\tborondns' >> \
    "$sampler_validator_attempt/process-samples.tsv"
if sampler_terminal_fixture_validates; then
    printf 'sampler validator accepted a future orphan process sample\n' >&2
    exit 1
fi
cp "$fuzz_sampler_valid_processes" "$sampler_validator_attempt/process-samples.tsv"

for fuzz_aggregate_mutation in count cpu rss zero; do
    cp "$fuzz_sampler_valid_hosts" "$sampler_validator_attempt/host-samples.tsv"
    case "$fuzz_aggregate_mutation" in
    count) sed -i '2s/\t2\t0.30\t4\t/\t3\t0.30\t4\t/' "$sampler_validator_attempt/host-samples.tsv" ;;
    cpu) sed -i '2s/\t0.30\t4\t/\t0.31\t4\t/' "$sampler_validator_attempt/host-samples.tsv" ;;
    rss) sed -i '2s/\t0.30\t4\t/\t0.30\t5\t/' "$sampler_validator_attempt/host-samples.tsv" ;;
    zero) sed -i '2s/\t2\t0.30\t4\t/\t0\t0.00\t0\t/' "$sampler_validator_attempt/host-samples.tsv" ;;
    esac
    if sampler_terminal_fixture_validates; then
        printf 'sampler validator accepted %s aggregate mismatch\n' "$fuzz_aggregate_mutation" >&2
        exit 1
    fi
done
cp "$fuzz_sampler_valid_hosts" "$sampler_validator_attempt/host-samples.tsv"

# Header-only hard-stop evidence cannot carry detached process detail.
rm "$sampler_validator_attempt/sampler-completed.env"
printf '%s\n' sampler_hard_stop_utc=2026-07-13T12:00:01Z active_units=0 probe_failed=1 \
    >"$sampler_validator_attempt/sampler-hard-stop.env"
sed -i '2,$d' "$sampler_validator_attempt/host-samples.tsv"
if sampler_terminal_fixture_validates; then
    printf 'sampler validator accepted process detail with header-only hard-stop samples\n' >&2
    exit 1
fi
cp "$fuzz_sampler_valid_hosts" "$sampler_validator_attempt/host-samples.tsv"
cp "$fuzz_sampler_valid_processes" "$sampler_validator_attempt/process-samples.tsv"
rm "$sampler_validator_attempt/sampler-hard-stop.env"
printf '%s\n' status=passed completed_utc=2026-07-13T12:00:01Z \
    "completed_epoch_seconds=$sampler_validator_deadline" active_units=0 \
    "deadline_epoch_seconds=$sampler_validator_deadline" "last_sample_epoch_seconds=$sampler_validator_deadline" \
    >"$sampler_validator_attempt/sampler-completed.env"
sampler_terminal_fixture_validates
sampler_after_terminal_reserve=$((sampler_validator_deadline + 16))
sampler_after_terminal_reserve_utc="$(date -u -d "@$sampler_after_terminal_reserve" '+%Y-%m-%dT%H:%M:%SZ')"
sed -i \
    -e "s/2026-07-13T12:00:01Z/$sampler_after_terminal_reserve_utc/" \
    -e "s/1783944001/$sampler_after_terminal_reserve/g" \
    "$sampler_validator_attempt/host-samples.tsv"
printf '%s\n' status=passed "completed_utc=$sampler_after_terminal_reserve_utc" \
    "completed_epoch_seconds=$sampler_after_terminal_reserve" active_units=0 \
    "deadline_epoch_seconds=$sampler_validator_deadline" "last_sample_epoch_seconds=$sampler_after_terminal_reserve" \
    >"$sampler_validator_attempt/sampler-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted terminal evidence beyond the derived reserve\n' >&2
    exit 1
fi
sed -i \
    -e "s/$sampler_after_terminal_reserve_utc/2026-07-13T12:00:01Z/" \
    -e "s/$sampler_after_terminal_reserve/1783944001/g" \
    "$sampler_validator_attempt/host-samples.tsv"
sed -i \
    -e 's/2026-07-13T12:00:01Z/2026-07-13T12:00:00Z/' \
    -e 's/1783944001/1783944000/g' \
    "$sampler_validator_attempt/host-samples.tsv"
printf '%s\n' status=passed completed_utc=2026-07-13T12:00:00Z \
    "completed_epoch_seconds=$sampler_validator_start" active_units=0 \
    "deadline_epoch_seconds=$sampler_validator_deadline" "last_sample_epoch_seconds=$sampler_validator_start" \
    >"$sampler_validator_attempt/sampler-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 "${sampler_validator_schedule[@]}" \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted immediate completion before the authenticated deadline\n' >&2
    exit 1
fi

sampler_cadence_deadline=$((sampler_validator_start + 30))
printf '%s\n' $'timestamp_utc\tepoch_seconds\tpid\tpcpu\tpmem\trss_kib\tetime\tcomm' \
    >"$sampler_validator_attempt/process-samples.tsv"
printf '%s\n' \
    $'timestamp_utc\tepoch_seconds\tactive_units\tfuzz_processes\ttotal_fuzz_pcpu\ttotal_fuzz_rss_kib\tload1\tload5\tload15\tmem_available_kib' \
    $'2026-07-13T12:00:00Z\t1783944000\t1\t0\t0.00\t0\t0.0\t0.0\t0.0\t1' \
    $'2026-07-13T12:00:20Z\t1783944020\t1\t0\t0.00\t0\t0.0\t0.0\t0.0\t1' \
    $'2026-07-13T12:00:30Z\t1783944030\t0\t0\t0.00\t0\t0.0\t0.0\t0.0\t1' \
    >"$sampler_validator_attempt/host-samples.tsv"
sed -i "s/^deadline_epoch_seconds=.*/deadline_epoch_seconds=$sampler_cadence_deadline/" \
    "$sampler_validator_attempt/sampler.env"
printf '%s\n' status=passed completed_utc=2026-07-13T12:00:30Z \
    "completed_epoch_seconds=$sampler_cadence_deadline" active_units=0 \
    "deadline_epoch_seconds=$sampler_cadence_deadline" "last_sample_epoch_seconds=$sampler_cadence_deadline" \
    >"$sampler_validator_attempt/sampler-completed.env"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host \
    "$sampler_validator_fixture" "$source_commit" --expected-target 000-dns_datagram \
    --expected-sampler h1 --expected-duration 1 --expected-sampler-interval 1 \
    --expected-sampler-deadline "$sampler_cadence_deadline" \
    --expected-sampler-unit borondns-fuzz-fixture-0-dns_datagram.service \
    "${fuzz_validator_policy[@]}"; then
    printf 'sampler validator accepted a cadence gap beyond the authenticated bound\n' >&2
    exit 1
fi
rm "$validator_fixture/fuzz/operator-note"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 "${fuzz_validator_policy[@]}"; then
    printf 'local collection validator accepted an implicit sampler expectation\n' >&2
    exit 1
fi
printf corruption >>"$validator_attempt/logs/dns_datagram.log"
if python3 "$repo_root/scripts/validate-collected-campaign.py" fuzz-host "$validator_fixture" "$source_commit" \
    --expected-target 000-dns_datagram --expected-duration 1 --no-sampler "${fuzz_validator_policy[@]}"; then
    printf 'local collection validator accepted a post-manifest byte change\n' >&2
    exit 1
fi

collection_remote="$workdir/collection-remote"
collection_plan="$workdir/collection-plan"
collection_bin="$workdir/collection-bin"
mkdir -p "$collection_remote" "$collection_bin"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$collection_plan" --campaign-id collection-test --host local-fixture \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$collection_remote" \
    --duration 1 --target dns_datagram --no-sampler
# Execute remote snapshot scripts locally and provide a deterministic rsync
# stand-in so the real collection transaction can be exercised without SSH.
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'if [[ "$*" == *"bash -s --"* ]]; then root="${!#}"; exec bash -s -- "$root"; fi' \
    'exit 0' >"$collection_bin/ssh"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    '[[ "${FAIL_COLLECTION_COPY:-0}" != 1 ]] || exit 72' \
    '[[ -z "${EXPECTED_REMOTE_OPERAND:-}" || "${@: -2:1}" == "$EXPECTED_REMOTE_OPERAND" ]] || exit 73' \
    'destination="${!#}"' 'cp -a "$COLLECTION_SOURCE/." "$destination/"' \
    '[[ "${MUTATE_COLLECTION_SOURCE:-0}" != 1 ]] || printf mutation >>"$COLLECTION_SOURCE/concurrent.txt"' \
    >"$collection_bin/rsync"
chmod +x "$collection_bin/ssh" "$collection_bin/rsync"
PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$collection_remote" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect --evidence-dir "$collection_plan"
grep -Fq $'collection\tlocal-fixture\tremote-snapshot\tincomplete' \
    "$collection_plan/remotes/local-fixture.collection-status.tsv"
[[ -d "$collection_plan/remotes/local-fixture.journal" ]]
printf 'obsolete journal\n' >"$collection_plan/remotes/local-fixture.journal/obsolete.log"
PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$collection_remote" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect --evidence-dir "$collection_plan"
[[ ! -e "$collection_plan/remotes/local-fixture.journal/obsolete.log" ]]
if PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$collection_remote" FAIL_COLLECTION_COPY=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect --evidence-dir "$collection_plan"; then
    printf 'collection accepted a failed transfer\n' >&2
    exit 1
fi
grep -Fq $'invalid\tremote-copy-failed' "$collection_plan/remotes/local-fixture.collection-status.tsv"
[[ -z "$(find "$collection_plan/remotes" -maxdepth 1 -type d -name '.local-fixture.collection.*' -print -quit)" ]]
status_victim="$workdir/status-symlink-victim"
printf 'operator status sentinel\n' >"$status_victim"
rm "$collection_plan/remotes/local-fixture.collection-status.tsv"
ln -s "$status_victim" "$collection_plan/remotes/local-fixture.collection-status.tsv"
if PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$collection_remote" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect --evidence-dir "$collection_plan"; then
    printf 'collection followed or replaced a symlinked status destination\n' >&2
    exit 1
fi
grep -Fqx 'operator status sentinel' "$status_victim"
rm "$collection_plan/remotes/local-fixture.collection-status.tsv"
printf 'preserved collection\n' >"$collection_plan/remotes/local-fixture/preserved.txt"
ln -s "$workdir" "$collection_remote/unsafe-link"
if PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$collection_remote" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect --evidence-dir "$collection_plan"; then
    printf 'collection accepted a remote symlink\n' >&2
    exit 1
fi
grep -Fqx 'preserved collection' "$collection_plan/remotes/local-fixture/preserved.txt"
grep -Fq $'invalid\tremote-preflight-failed' "$collection_plan/remotes/local-fixture.collection-status.tsv"
rm "$collection_remote/unsafe-link"
printf 'stable source\n' >"$collection_remote/stable.txt"
if PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$collection_remote" MUTATE_COLLECTION_SOURCE=1 \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect --evidence-dir "$collection_plan"; then
    printf 'collection accepted source mutation during copy\n' >&2
    exit 1
fi
grep -Fqx 'preserved collection' "$collection_plan/remotes/local-fixture/preserved.txt"
grep -Fq $'invalid\tconcurrent-mutation-or-copy-mismatch' \
    "$collection_plan/remotes/local-fixture.collection-status.tsv"

large_collection_remote="$workdir/large-collection-remote"
large_collection_host="$large_collection_remote/host/local-fixture"
large_collection_plan="$workdir/large-collection-plan"
mkdir -p "$large_collection_host"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$large_collection_plan" --campaign-id large-collection-test --host local-fixture \
    --remote-repo "$fuzz_remote_repo" --remote-evidence "$large_collection_remote" --duration 1
PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$large_collection_host" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" collect --evidence-dir "$large_collection_plan"
grep -Fq $'collection\tlocal-fixture\tremote-snapshot\tincomplete' \
    "$large_collection_plan/remotes/local-fixture.collection-status.tsv"
[[ -d "$large_collection_plan/remotes/local-fixture.journal" ]]

# Bare IPv6 literals are valid SSH destinations, but rsync/scp require brackets
# in their host:path operand so address colons are not parsed as path separators.
ipv6_fuzz_collection_remote="$workdir/ipv6-fuzz-collection-remote"
ipv6_fuzz_collection_plan="$workdir/ipv6-fuzz-collection-plan"
mkdir -p "$ipv6_fuzz_collection_remote"
"$repo_root/scripts/fuzz-soak-two-host-campaign.sh" plan \
    --evidence-dir "$ipv6_fuzz_collection_plan" --campaign-id ipv6-fuzz-collection \
    --host 2001:db8::53 --remote-repo "$fuzz_remote_repo" \
    --remote-evidence "$ipv6_fuzz_collection_remote" --duration 1 --target dns_datagram --no-sampler
PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$ipv6_fuzz_collection_remote" \
    EXPECTED_REMOTE_OPERAND="[2001:db8::53]:$ipv6_fuzz_collection_remote/" \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh" collect \
    --evidence-dir "$ipv6_fuzz_collection_plan"
grep -Fq $'collection\t2001_db8__53\tremote-snapshot\tincomplete' \
    "$ipv6_fuzz_collection_plan/remotes/2001_db8__53.collection-status.tsv"

ipv6_large_collection_remote="$workdir/ipv6-large-collection-remote"
ipv6_large_collection_host="$ipv6_large_collection_remote/host/2001_db8__53"
ipv6_large_collection_plan="$workdir/ipv6-large-collection-plan"
mkdir -p "$ipv6_large_collection_host"
"$repo_root/scripts/large-surface-soak-campaign.sh" plan \
    --evidence-dir "$ipv6_large_collection_plan" --campaign-id ipv6-large-collection \
    --host 2001:db8::53 --remote-repo "$fuzz_remote_repo" \
    --remote-evidence "$ipv6_large_collection_remote" --duration 1
PATH="$collection_bin:$PATH" COLLECTION_SOURCE="$ipv6_large_collection_host" \
    EXPECTED_REMOTE_OPERAND="[2001:db8::53]:$ipv6_large_collection_host/" \
    "$repo_root/scripts/large-surface-soak-campaign.sh" collect \
    --evidence-dir "$ipv6_large_collection_plan"
grep -Fq $'collection\t2001_db8__53\tremote-snapshot\tincomplete' \
    "$ipv6_large_collection_plan/remotes/2001_db8__53.collection-status.tsv"

grep -Fq 'rc_ulimit="-n 65536"' "$repo_root/packaging/installer/share/borondns/openrc/borondns"

no_sha_bin="$workdir/no-sha-bin"
mkdir -p "$no_sha_bin"
ln -s /usr/bin/bash "$no_sha_bin/bash"
ln -s /usr/bin/dirname "$no_sha_bin/dirname"
ln -s /usr/bin/realpath "$no_sha_bin/realpath"
for required_tool in cargo rustup tar xz python3 flock; do
    ln -s /usr/bin/true "$no_sha_bin/$required_tool"
done
if CARGO=/usr/bin/true RUSTC=/usr/bin/true PATH="$no_sha_bin" \
    "$repo_root/scripts/package-installer.sh" >"$workdir/no-sha.log" 2>&1; then
    printf 'package installer accepted a build environment without SHA-256\n' >&2
    exit 1
fi
grep -Fq 'missing required packaging tools: sha256sum-or-shasum' "$workdir/no-sha.log"

foreign_workspace="$workdir/foreign-cargo-workspace"
package_fake_bin="$workdir/package-fake-bin"
package_fake_dist="$workdir/package-fake-dist"
package_fake_target="$workdir/package-fake-target"
package_docker_input="$workdir/package-docker-input"
package_cargo_log="$workdir/package-cargo.log"
package_fake_layer_digest="$(printf '%s' fixture-layer | sha256sum | awk '{ print $1 }')"
package_fake_config_payload="$(printf '{"rootfs":{"diff_ids":["sha256:%s"]},"fixture":"default"}' \
    "$package_fake_layer_digest")"
package_fake_image_id="sha256:$(printf '%s' "$package_fake_config_payload" | sha256sum | awk '{ print $1 }')"
package_fake_second_config_payload="$(printf '{"rootfs":{"diff_ids":["sha256:%s"]},"fixture":"second"}' \
    "$package_fake_layer_digest")"
package_fake_second_image_id="sha256:$(printf '%s' "$package_fake_second_config_payload" | sha256sum | awk '{ print $1 }')"
mkdir -p "$foreign_workspace" "$package_fake_bin" "$package_fake_dist" "$package_fake_target" \
    "$package_docker_input"
# Reading an archive is allowed to update only its access time. Keep this
# regression independent of Docker and the filesystem's atime mount policy by
# exercising the descriptor-bound staging primitive, then comparing the stable
# identity with a synthetic atime-only stat change. The latter is required on
# noatime filesystems, where a real read cannot force an atime update.
python3 - "$repo_root/scripts/verify-docker-archive.py" "$workdir" <<'PY'
import importlib.util
import os
import pathlib
import sys

module_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("verify_docker_archive", module_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load Docker archive verifier")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
archive = pathlib.Path(sys.argv[2]) / "archive-atime-regression.tar.xz"
archive.write_bytes(b"descriptor-bound archive fixture")
current = archive.stat()
os.utime(
    archive,
    ns=(current.st_mtime_ns - 1_000_000_000, current.st_mtime_ns),
)
descriptor, before = module.open_archive(str(archive), 1024 * 1024)
try:
    staged = module.stage_archive(
        descriptor,
        before,
        module.time.monotonic_ns() + 5_000_000_000,
    )
    staged.close()
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if module.stable_archive_identity(after) != module.stable_archive_identity(before):
    raise SystemExit("atime-only archive read changed the stable identity")
atime_only = type(
    "AtimeOnlyStat",
    (),
    {
        field: getattr(before, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    }
)()
atime_only.st_atime_ns = before.st_atime_ns + 1
if module.stable_archive_identity(atime_only) != module.stable_archive_identity(before):
    raise SystemExit("synthetic atime-only change altered the stable identity")
PY
printf '%s\n' '[package]' 'name = "foreign-workspace"' 'version = "9.9.9"' 'edition = "2024"' \
    >"$foreign_workspace/Cargo.toml"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    "fixture_build_env_log=$(printf '%q' "$workdir/package-build-env.log")" \
    "fixture_clean_dist=$(printf '%q' "$workdir/package-clean-dist")" \
    "fixture_isolated_dist_a=$(printf '%q' "$workdir/package-isolated-dist-a")" \
    "fixture_isolated_dist_b=$(printf '%q' "$workdir/package-isolated-dist-b")" \
    "fixture_isolated_log_a=$(printf '%q' "$workdir/package-isolated-a.log")" \
    "fixture_isolated_log_b=$(printf '%q' "$workdir/package-isolated-b.log")" \
    "fixture_main_cargo_log=$(printf '%q' "$workdir/package-cargo.log")" \
    "fixture_main_manifest=$(printf '%q' "$workdir/package-dirty-repo/Cargo.toml")" \
    "fixture_mutated_docker_dist=$(printf '%q' "$workdir/package-mutated-docker-dist")" \
    "fixture_mutated_installer_dist=$(printf '%q' "$workdir/package-mutated-installer-dist")" \
    "fixture_source_root=$(printf '%q' "$workdir/package-dirty-repo")" \
    "fixture_transient_sbom_dist=$(printf '%q' "$workdir/package-transient-dist")" \
    "fixture_transient_sbom_mutated=$(printf '%q' "$workdir/package-transient-sbom-mutated")" \
    'fixture_manifest=""; fixture_arguments=("$@"); for ((fixture_index = 0; fixture_index < ${#fixture_arguments[@]}; fixture_index++)); do if [[ "${fixture_arguments[$fixture_index]}" == --manifest-path ]]; then fixture_manifest="${fixture_arguments[$((fixture_index + 1))]:-}"; fi; done' \
    'fixture_root="${fixture_manifest%/Cargo.toml}"' \
    'if [[ "$fixture_manifest" == "$fixture_main_manifest" ]]; then printf "%s\n" "$*" >>"$fixture_main_cargo_log"; fi' \
    'case "${1:-}" in' \
    'metadata) [[ -n "$fixture_manifest" && -f "$fixture_manifest" && " $* " == *" --locked "* ]] || exit 92; printf "%s\n" "{\"packages\":[{\"name\":\"borondns-core\",\"version\":\"0.9.0\"}]}" ;;' \
    'build) target=""; target_dir="${CARGO_TARGET_DIR:-}"; package=""; while (($#)); do case "$1" in --target-dir) target_dir="$2"; shift 2 ;; --target) target="$2"; shift 2 ;; -p) package="$2"; shift 2 ;; *) shift ;; esac; done; [[ -n "$target_dir" ]]; case "$package" in borondns-cli) binary=borondns ;; boron-gun) binary=boron-gun ;; *) exit 93 ;; esac; if [[ "$target_dir" == "$fixture_clean_dist"/* ]]; then printf "%s|%s|%s\n" "${BORONDNS_BUILD_COMMIT-unset}" "${BORONDNS_BUILD_RUST_VERSION-unset}" "${BORONDNS_BUILD_TIMESTAMP-unset}" >>"$fixture_build_env_log"; elif [[ "$target_dir" == "$fixture_isolated_dist_a"/* ]]; then printf "%s\n" "${fixture_arguments[*]}" >>"$fixture_isolated_log_a"; elif [[ "$target_dir" == "$fixture_isolated_dist_b"/* ]]; then printf "%s\n" "${fixture_arguments[*]}" >>"$fixture_isolated_log_b"; fi; mkdir -p "$target_dir/$target/release"; printf "%s\n" "#!/usr/bin/env bash" "printf \"%s fake\\n\" \"$binary\"" >"$target_dir/$target/release/$binary"; chmod +x "$target_dir/$target/release/$binary"; if [[ "$package" == boron-gun && "$target_dir" == "$fixture_mutated_installer_dist"/* ]]; then printf mutation >"$fixture_source_root/transient-build-mutation"; fi ;;' \
    'cyclonedx) if [[ " $* " == *" --help "* || "${2:-}" == "--help" ]]; then exit 0; fi; if [[ " $* " == *" -V "* ]]; then if [[ -n "${PACKAGE_CYCLONEDX_VERSION_MARKER:-}" ]]; then : >"$PACKAGE_CYCLONEDX_VERSION_MARKER"; sleep "${PACKAGE_CYCLONEDX_VERSION_DELAY:-0}"; fi; printf "cargo-cyclonedx 0.5.9\n"; exit 0; fi; [[ -n "$fixture_manifest" && -f "$fixture_manifest" && -n "$fixture_root" ]] || exit 94; [[ -z "${PACKAGE_CYCLONEDX_STARTED_MARKER:-}" ]] || : >"$PACKAGE_CYCLONEDX_STARTED_MARKER"; active="${PACKAGE_CYCLONEDX_ACTIVE_DIR:-}"; if [[ -n "$active" ]]; then if ! mkdir "$active" 2>/dev/null; then : >"${PACKAGE_CYCLONEDX_OVERLAP:?}"; exit 99; fi; trap '\''rmdir "$active"'\'' EXIT; fi; [[ -z "${PACKAGE_CYCLONEDX_DELAY:-}" ]] || sleep "$PACKAGE_CYCLONEDX_DELAY"; if [[ "${BORONDNS_DIST_DIR:-}" == "$fixture_transient_sbom_dist" && ! -e "$fixture_transient_sbom_mutated" ]]; then : >"$fixture_transient_sbom_mutated"; printf mutation >"$fixture_root/transient-mutation"; fi; printf "%s\n" "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"metadata\":{\"component\":{\"name\":\"borondns\"}}}" >"$fixture_root/crates/borondns-cli/borondns_bin.cdx.json"; [[ "${PACKAGE_CYCLONEDX_FAIL_AFTER_FIRST:-0}" != 1 ]] || exit 97; printf "%s\n" "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"metadata\":{\"component\":{\"name\":\"boron-gun\"}}}" >"$fixture_root/crates/boron-gun/boron-gun_bin.cdx.json" ;;' \
    '*) exit 95 ;;' \
    'esac' >"$package_fake_bin/cargo"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "${1:-}" == --version ]]; then printf "rustc 1.88.0 (fake 2025-06-23)\n"; fi' \
    'exit 0' >"$package_fake_bin/rustc"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'if [[ "$*" == "target list --installed" ]]; then printf "x86_64-unknown-linux-musl\n"; exit 0; fi' \
    'if [[ "${1:-}" == target && "${2:-}" == add ]]; then exit 0; fi' \
    'exit 96' >"$package_fake_bin/rustup"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    "fixture_mutated_docker_dist=$(printf '%q' "$workdir/package-mutated-docker-dist")" \
    "fixture_source_root=$(printf '%q' "$workdir/package-dirty-repo")" \
    'layer_payload=fixture-layer' \
    'layer_hex="$(printf "%s" "$layer_payload" | sha256sum | awk '\''{ print $1 }'\'')"' \
    'config_variant="${PACKAGE_DOCKER_CONFIG_VARIANT:-default}"' \
    'config_payload="$(printf '\''{"rootfs":{"diff_ids":["sha256:%s"]},"fixture":"%s"}'\'' "$layer_hex" "$config_variant")"' \
    'config_hex="$(printf "%s" "$config_payload" | sha256sum | awk '\''{ print $1 }'\'')"' \
    'image_id="${PACKAGE_DOCKER_IMAGE_ID:-sha256:$config_hex}"' \
    'drift_id="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    'tag_state="${PACKAGE_DOCKER_TAG_STATE:-}"' \
    'tag_value() { if [[ -n "$tag_state" ]]; then [[ -f "$tag_state" ]] || return 1; cat "$tag_state"; else printf "%s\n" "$image_id"; fi; }' \
    'case "${1:-}" in' \
    'info) exit 0 ;;' \
    'build) iid=""; context="${@: -1}"; while (($#)); do case "$1" in --iidfile) iid="$2"; shift 2 ;; -t|--tag) printf "stable Docker tag was passed to build\n" >&2; exit 98 ;; *) shift ;; esac; done; [[ -n "$iid" ]]; if [[ "${PACKAGE_DOCKER_IID_NO_NEWLINE:-0}" == 1 ]]; then printf "%s" "$image_id" >"$iid"; else printf "%s\n" "$image_id" >"$iid"; fi; if [[ "$context" == "$fixture_mutated_docker_dist"/* ]]; then printf mutation >"$fixture_source_root/transient-docker-mutation"; fi ;;' \
    'save) image_ref="${2:-}"; [[ -n "$image_ref" && "$(tag_value)" == "$image_id" && "$image_id" == "sha256:$config_hex" ]]; tmp="$(mktemp -d)"; trap '\''rm -rf "$tmp"'\'' EXIT; if [[ "${PACKAGE_DOCKER_SAVE_LAYOUT:-legacy}" == oci ]]; then mkdir -p "$tmp/blobs/sha256"; printf '\''[{"Config":"blobs/sha256/%s","RepoTags":["%s"],"Layers":["blobs/sha256/%s"]}]\n'\'' "$config_hex" "$image_ref" "$layer_hex" >"$tmp/manifest.json"; printf "%s" "$config_payload" >"$tmp/blobs/sha256/$config_hex"; printf "%s" "$layer_payload" >"$tmp/blobs/sha256/$layer_hex"; tar -C "$tmp" -cf - manifest.json "blobs/sha256/$config_hex" "blobs/sha256/$layer_hex"; else mkdir -p "$tmp/$layer_hex"; printf '\''[{"Config":"%s.json","RepoTags":["%s"],"Layers":["%s/layer.tar"]}]\n'\'' "$config_hex" "$image_ref" "$layer_hex" >"$tmp/manifest.json"; printf "%s" "$config_payload" >"$tmp/$config_hex.json"; printf "%s" "$layer_payload" >"$tmp/$layer_hex/layer.tar"; tar -C "$tmp" -cf - manifest.json "$config_hex.json" "$layer_hex/layer.tar"; fi ;;' \
    'load) cat >/dev/null; [[ -z "$tag_state" ]] || printf "%s\n" "$image_id" >"$tag_state"; printf "Loaded image ID: %s\n" "$image_id" ;;' \
    'image) sub="${2:-}"; shift 2; case "$sub" in' \
    '  inspect) if [[ "${1:-}" == --format ]]; then format="$2"; ref="$3"; if [[ "$ref" == "$image_id" || "$ref" == "$drift_id" ]]; then selected="$ref"; else selected="$(tag_value)" || exit 1; fi; if [[ "$format" == "{{.Id}}" ]]; then printf "%s\n" "$selected"; else printf "image_id=%s\nimage_size_bytes=1\n" "$selected"; fi; else ref="${1:-}"; if [[ -n "$ref" && "$ref" != "$image_id" && "$ref" != "$drift_id" ]]; then tag_value >/dev/null || exit 1; fi; printf "[]\n"; fi ;;' \
    '  tag) source="$1"; target="$2"; [[ "$source" == "$image_id" || "$source" == "$drift_id" ]]; if [[ -n "$tag_state" ]]; then printf "%s\n" "$source" >"$tag_state"; fi; if [[ -n "${PACKAGE_DOCKER_TAG_READY:-}" && "$source" == "$image_id" ]]; then : >"$PACKAGE_DOCKER_TAG_READY"; while [[ ! -e "${PACKAGE_DOCKER_TAG_RELEASE:?}" ]]; do sleep 0.01; done; fi; if [[ "${PACKAGE_DOCKER_FAIL_AFTER_TAG:-0}" == 1 && "$source" == "$image_id" ]]; then exit 98; fi ;;' \
    '  rm) ref="$1"; if [[ -n "$tag_state" ]]; then rm -f "$tag_state"; fi; printf "%s\n" "$ref" ;;' \
    '  *) exit 97 ;; esac ;;' \
    '*) exit 97 ;;' \
    'esac' >"$package_fake_bin/docker"
chmod +x "$package_fake_bin/cargo" "$package_fake_bin/rustc" "$package_fake_bin/rustup" "$package_fake_bin/docker"

# Every first-use contender must accept the one safe directory created by the
# mkdir winner, then proceed with its independently named lock.
package_first_use_root="$workdir/package-first-use-lock"
package_first_use_gate="$workdir/package-first-use-go"
mkdir -p "$package_first_use_root"
package_first_use_pids=()
for package_first_use_index in {1..16}; do
    bash -c '
        set -euo pipefail
        source "$1"
        while [[ ! -e "$3" ]]; do :; done
        fd=""
        package_acquire_publication_lock "$2" "first-use-$4" fd
        [[ -n "$fd" ]]
    ' package-first-use "$repo_root/scripts/package-common.sh" "$package_first_use_root" \
        "$package_first_use_gate" "$package_first_use_index" &
    package_first_use_pids+=("$!")
done
: >"$package_first_use_gate"
for package_first_use_pid in "${package_first_use_pids[@]}"; do
    wait "$package_first_use_pid"
done
[[ "$(stat -c '%a:%u' "$package_first_use_root/.borondns-package-locks")" == "700:$(id -u)" ]]

# Package writers for the same output identity must serialize before replacing
# any stable artifact name.
package_publication_lock_root="$workdir/package-publication-lock"
mkdir -m 0700 "$package_publication_lock_root"
package_publication_release="$workdir/package-publication-release"
package_publication_first="$workdir/package-publication-first"
package_publication_second="$workdir/package-publication-second"
bash -c '
    set -euo pipefail
    source "$1"
    fd=""
    package_acquire_publication_lock "$2" fixture-package fd
    : >"$3"
    while [[ ! -e "$4" ]]; do sleep 0.01; done
' package-lock-first "$repo_root/scripts/package-common.sh" "$package_publication_lock_root" \
    "$package_publication_first" "$package_publication_release" &
package_first_pid=$!
for _ in {1..200}; do
    [[ -e "$package_publication_first" ]] && break
    sleep 0.01
done
[[ -e "$package_publication_first" ]]
bash -c '
    set -euo pipefail
    source "$1"
    fd=""
    package_acquire_publication_lock "$2" fixture-package fd
    : >"$3"
' package-lock-second "$repo_root/scripts/package-common.sh" "$package_publication_lock_root" \
    "$package_publication_second" &
package_second_pid=$!
sleep 0.1
[[ ! -e "$package_publication_second" ]] || {
    printf 'concurrent package publisher entered an already-held terminal transaction\n' >&2
    exit 1
}
: >"$package_publication_release"
wait "$package_first_pid"
wait "$package_second_pid"
[[ -e "$package_publication_second" ]]

# Replacing only the pathname-local lock directory must not split the writer
# authority while the publication-root inode remains unchanged.
package_split_lock_root="$workdir/package-split-lock-root"
package_split_lock_held="$workdir/package-split-lock-held"
package_split_lock_release="$workdir/package-split-lock-release"
package_split_lock_second="$workdir/package-split-lock-second"
mkdir -m 0700 "$package_split_lock_root"
bash -c '
    set -euo pipefail
    source "$1"
    fd=""
    package_acquire_publication_lock "$2" split-lock-fixture fd
    : >"$3"
    while [[ ! -e "$4" ]]; do sleep 0.01; done
' package-split-lock-first "$repo_root/scripts/package-common.sh" "$package_split_lock_root" \
    "$package_split_lock_held" "$package_split_lock_release" &
package_split_lock_pid=$!
for _ in {1..200}; do
    [[ -e "$package_split_lock_held" ]] && break
    sleep 0.01
done
[[ -e "$package_split_lock_held" ]]
mv "$package_split_lock_root/.borondns-package-locks" \
    "$package_split_lock_root/.borondns-package-locks.detached"
mkdir -m 0700 "$package_split_lock_root/.borondns-package-locks"
# shellcheck disable=SC2016 # The single-quoted script expands only inside the child shell.
if timeout 0.2 bash -c '
    set -euo pipefail
    source "$1"
    fd=""
    package_acquire_publication_lock "$2" split-lock-fixture fd
    : >"$3"
' package-split-lock-second "$repo_root/scripts/package-common.sh" "$package_split_lock_root" \
    "$package_split_lock_second"; then
    printf 'replacement package lock directory admitted a concurrent writer\n' >&2
    exit 1
else
    package_split_lock_status=$?
fi
[[ "$package_split_lock_status" == 124 && ! -e "$package_split_lock_second" ]]
: >"$package_split_lock_release"
wait "$package_split_lock_pid"

# Docker tag writers and scanners must serialize on the daemon identity, not on
# a target-specific dist name. Docker Hub aliases resolve to one canonical lock.
package_docker_lock_root="$workdir/package-docker-global-lock"
package_docker_lock_release="$workdir/package-docker-lock-release"
package_docker_lock_first="$workdir/package-docker-lock-first"
package_docker_lock_second="$workdir/package-docker-lock-second"
bash -c '
    set -euo pipefail
    source "$1"
    fd="" canonical=""
    BORONDNS_PACKAGE_DOCKER_LOCK_ROOT="$2" package_acquire_docker_image_lock \
        borondns:0.9.0 fd canonical
    [[ "$canonical" == docker.io/library/borondns:0.9.0 ]]
    : >"$3"
    while [[ ! -e "$4" ]]; do sleep 0.01; done
' package-docker-lock-first "$repo_root/scripts/package-common.sh" "$package_docker_lock_root" \
    "$package_docker_lock_first" "$package_docker_lock_release" &
package_docker_lock_first_pid=$!
for _ in {1..200}; do
    [[ -e "$package_docker_lock_first" ]] && break
    sleep 0.01
done
[[ -e "$package_docker_lock_first" ]]
bash -c '
    set -euo pipefail
    source "$1"
    fd="" canonical=""
    BORONDNS_PACKAGE_DOCKER_LOCK_ROOT="$2" package_acquire_docker_image_lock \
        docker.io/library/borondns:0.9.0 fd canonical
    : >"$3"
' package-docker-lock-second "$repo_root/scripts/package-common.sh" "$package_docker_lock_root" \
    "$package_docker_lock_second" &
package_docker_lock_second_pid=$!
sleep 0.1
[[ ! -e "$package_docker_lock_second" ]] || {
    printf 'Docker Hub aliases acquired different image-reference locks\n' >&2
    exit 1
}
: >"$package_docker_lock_release"
wait "$package_docker_lock_first_pid"
wait "$package_docker_lock_second_pid"
[[ -e "$package_docker_lock_second" ]]

# A failed restore must retain both the previous artifact and the transaction
# root for explicit recovery; it must never be suppressed by EXIT cleanup.
# shellcheck source=scripts/package-common.sh
source "$repo_root/scripts/package-common.sh"
[[ "$(package_nonrelease_docker_image_ref borondns)" == 'borondns:latest-nonrelease-dirty' ]]
[[ "$(package_nonrelease_docker_image_ref borondns:clean-nonrelease-dirty)" == 'borondns:clean-nonrelease-dirty-nonrelease-dirty' ]]
if package_require_clean_docker_image_ref borondns:clean-nonrelease-dirty; then
    printf 'clean Docker reference entered the reserved dirty diagnostic namespace\n' >&2
    exit 1
fi
package_require_clean_docker_image_ref borondns:clean

package_umask_root="$workdir/package-umask-root"
mkdir -m 0700 "$package_umask_root"
package_saved_umask="$(umask)"
umask 000
package_umask_lock_fd=""
package_acquire_publication_lock "$package_umask_root" umask-fixture package_umask_lock_fd
[[ -n "$package_umask_lock_fd" ]]
package_after_lock_umask="$(umask)"
umask "$package_saved_umask"
[[ "$package_after_lock_umask" == 0000 || "$package_after_lock_umask" == 000 ]]
[[ "$(stat -c '%a' "$package_umask_root/.borondns-package-locks/umask-fixture.lock")" == 600 ]]

# Package publication roots are mutation boundaries, not arbitrary output
# paths. Reject writable or foreign-owned roots before creating staging/locks.
package_private_output="$workdir/package-private-output"
package_writable_output="$workdir/package-writable-output"
mkdir -m 0700 "$package_private_output"
mkdir -m 0777 "$package_writable_output"
[[ "$(package_canonical_output_root fixture "$package_private_output")" == "$package_private_output" ]]
if package_canonical_output_root fixture "$package_writable_output" >/dev/null 2>&1; then
    printf 'package output validation accepted a group/world-writable root\n' >&2
    exit 1
fi
package_foreign_id_bin="$workdir/package-foreign-id-bin"
mkdir -m 0700 "$package_foreign_id_bin"
# The single-quoted bodies are intentional: this fixture writes a child script.
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' '[[ "${1:-}" == -u ]] || exec /usr/bin/id "$@"' \
    'printf "%s\n" "$(( $(/usr/bin/id -u) + 1 ))"' >"$package_foreign_id_bin/id"
chmod 0700 "$package_foreign_id_bin/id"
if PATH="$package_foreign_id_bin:$PATH" \
    package_canonical_output_root fixture "$package_private_output" >/dev/null 2>&1; then
    printf 'package output validation accepted a root owned by another UID\n' >&2
    exit 1
fi

# These hooks fire after the shell-level identity check. The dirfd/openat
# helpers must still reject a same-UID pathname replacement and preserve both
# the replacement victim and the displaced transaction object.
package_post_stat_root="$workdir/package-post-stat-root"
package_post_stat_target="$package_post_stat_root/target"
package_post_stat_displaced="$package_post_stat_root/displaced"
package_post_stat_victim="$package_post_stat_root/victim"
mkdir -p "$package_post_stat_target" "$package_post_stat_victim"
printf 'captured tree\n' >"$package_post_stat_target/sentinel"
printf 'replacement tree victim\n' >"$package_post_stat_victim/sentinel"
package_capture_cleanup_root "$package_post_stat_target" "post-stat tree fixture"
# shellcheck disable=SC2329 # Exported fault-injection hook consumed by package cleanup.
package_identity_bound_hook() {
    [[ "$1" == before-remove && "$2" == tree && "$3" == "$package_post_stat_target" ]] || return 0
    mv -- "$package_post_stat_target" "$package_post_stat_displaced"
    mv -- "$package_post_stat_victim" "$package_post_stat_target"
}
if package_remove_captured_cleanup_root "$package_post_stat_target" "post-stat tree fixture"; then
    printf 'package tree cleanup removed a post-stat replacement victim\n' >&2
    exit 1
fi
grep -Fqx 'replacement tree victim' "$package_post_stat_target/sentinel"
grep -Fqx 'captured tree' "$package_post_stat_displaced/sentinel"
unset -f package_identity_bound_hook

# Publication moves themselves must retain their captured inode authority after
# the shell-level check. Exercise both file backup and tree promotion sources.
package_move_race_root="$workdir/package-move-race-root"
package_move_race_source_root="$workdir/package-move-race-sources"
mkdir -m 0700 "$package_move_race_root" "$package_move_race_source_root"
package_publication_reset ""
# shellcheck disable=SC2034 # Descriptor lifetime holds the publication-root lock.
package_move_race_lock_fd=""
package_acquire_publication_lock "$package_move_race_root" move-race-fixture \
    package_move_race_lock_fd
for package_move_race_kind in file tree; do
    package_move_race_source="$package_move_race_source_root/$package_move_race_kind"
    package_move_race_victim="$package_move_race_source_root/$package_move_race_kind.victim"
    package_move_race_displaced="$package_move_race_source_root/$package_move_race_kind.displaced"
    package_move_race_destination="$package_move_race_root/$package_move_race_kind"
    if [[ "$package_move_race_kind" == file ]]; then
        printf 'captured file move\n' >"$package_move_race_source"
        printf 'replacement file move victim\n' >"$package_move_race_victim"
    else
        mkdir "$package_move_race_source" "$package_move_race_victim"
        printf 'captured tree move\n' >"$package_move_race_source/sentinel"
        printf 'replacement tree move victim\n' >"$package_move_race_victim/sentinel"
    fi
    package_capture_publication_artifact "$package_move_race_source" \
        "$package_move_race_kind move source"
    # shellcheck disable=SC2329 # Exported fault-injection hook consumed by package move.
    package_identity_bound_hook() {
        [[ "$1" == before-move && "$3" == "$package_move_race_source" ]] || return 0
        mv -- "$package_move_race_source" "$package_move_race_displaced"
        mv -- "$package_move_race_victim" "$package_move_race_source"
    }
    if package_move_captured_publication_artifact "$package_move_race_source" \
        "$package_move_race_destination" "$package_move_race_root" \
        "$package_move_race_kind move race fixture"; then
        printf 'identity-bound %s publication moved a replacement victim\n' \
            "$package_move_race_kind" >&2
        exit 1
    fi
    unset -f package_identity_bound_hook
    [[ ! -e "$package_move_race_destination" ]]
    if [[ "$package_move_race_kind" == file ]]; then
        grep -Fqx 'replacement file move victim' "$package_move_race_source"
        grep -Fqx 'captured file move' "$package_move_race_displaced"
    else
        grep -Fqx 'replacement tree move victim' "$package_move_race_source/sentinel"
        grep -Fqx 'captured tree move' "$package_move_race_displaced/sentinel"
    fi
done

package_post_stat_file="$package_post_stat_root/file"
package_post_stat_file_displaced="$package_post_stat_root/file.displaced"
package_post_stat_file_victim="$package_post_stat_root/file.victim"
printf 'captured file\n' >"$package_post_stat_file"
printf 'replacement file victim\n' >"$package_post_stat_file_victim"
package_capture_publication_file "$package_post_stat_file" "post-stat file fixture"
# shellcheck disable=SC2329 # Exported fault-injection hook consumed by package cleanup.
package_identity_bound_hook() {
    [[ "$1" == before-remove && "$2" == file && "$3" == "$package_post_stat_file" ]] || return 0
    mv -- "$package_post_stat_file" "$package_post_stat_file_displaced"
    mv -- "$package_post_stat_file_victim" "$package_post_stat_file"
}
if package_remove_captured_publication_file "$package_post_stat_file" "post-stat file fixture"; then
    printf 'package file cleanup removed a post-stat replacement victim\n' >&2
    exit 1
fi
grep -Fqx 'replacement file victim' "$package_post_stat_file"
grep -Fqx 'captured file' "$package_post_stat_file_displaced"
unset -f package_identity_bound_hook

# A same-UID peer can also replace the unpredictable quarantine after the
# helper validated it. Logical cleanup must never issue a later pathname delete;
# both the exact displaced object and the foreign replacement must survive.
for package_post_quarantine_kind in file tree; do
    package_post_quarantine_source="$package_post_stat_root/post-quarantine-$package_post_quarantine_kind"
    package_post_quarantine_victim="$package_post_stat_root/post-quarantine-$package_post_quarantine_kind.victim"
    package_post_quarantine_displaced="$package_post_stat_root/post-quarantine-$package_post_quarantine_kind.displaced"
    package_post_quarantine_observed=""
    if [[ "$package_post_quarantine_kind" == file ]]; then
        printf 'captured post-quarantine file\n' >"$package_post_quarantine_source"
        printf 'foreign post-quarantine file\n' >"$package_post_quarantine_victim"
        package_capture_publication_file "$package_post_quarantine_source" \
            "post-quarantine file fixture"
    else
        mkdir "$package_post_quarantine_source" "$package_post_quarantine_victim"
        printf 'captured post-quarantine tree\n' >"$package_post_quarantine_source/sentinel"
        printf 'foreign post-quarantine tree\n' >"$package_post_quarantine_victim/sentinel"
        package_capture_cleanup_root "$package_post_quarantine_source" \
            "post-quarantine tree fixture"
    fi
    # shellcheck disable=SC2329 # Exported deterministic post-validation hook.
    package_identity_bound_hook() {
        [[ "$1" == after-quarantine-retain && "$2" == "$package_post_quarantine_kind" &&
            "$3" == "$package_post_quarantine_source" ]] || return 0
        package_post_quarantine_observed="$4"
        mv -- "$4" "$package_post_quarantine_displaced"
        mv -- "$package_post_quarantine_victim" "$4"
    }
    if [[ "$package_post_quarantine_kind" == file ]]; then
        if package_remove_captured_publication_file "$package_post_quarantine_source" \
            "post-quarantine file fixture"; then
            printf 'package file cleanup accepted a replaced retained quarantine\n' >&2
            exit 1
        fi
        grep -Fqx 'captured post-quarantine file' "$package_post_quarantine_displaced"
        grep -Fqx 'foreign post-quarantine file' "$package_post_quarantine_observed"
    else
        if package_remove_captured_cleanup_root "$package_post_quarantine_source" \
            "post-quarantine tree fixture"; then
            printf 'package tree cleanup accepted a replaced retained quarantine\n' >&2
            exit 1
        fi
        grep -Fqx 'captured post-quarantine tree' "$package_post_quarantine_displaced/sentinel"
        grep -Fqx 'foreign post-quarantine tree' "$package_post_quarantine_observed/sentinel"
    fi
    [[ ! -e "$package_post_quarantine_source" && ! -L "$package_post_quarantine_source" ]]
    unset -f package_identity_bound_hook
done

package_post_stat_restore="$package_post_stat_root/restore"
package_post_stat_restore_displaced="$package_post_stat_root/restore.displaced"
package_post_stat_restore_victim="$package_post_stat_root/restore.victim"
package_post_stat_destination="$package_post_stat_root/restored"
printf 'captured restore input\n' >"$package_post_stat_restore"
printf 'replacement restore victim\n' >"$package_post_stat_restore_victim"
package_capture_publication_file "$package_post_stat_restore" "post-stat restore fixture"
# shellcheck disable=SC2329 # Exported fault-injection hook consumed by package restore.
package_identity_bound_hook() {
    [[ "$1" == before-restore && "$3" == "$package_post_stat_restore" ]] || return 0
    mv -- "$package_post_stat_restore" "$package_post_stat_restore_displaced"
    mv -- "$package_post_stat_restore_victim" "$package_post_stat_restore"
}
if package_identity_bound_restore "$package_post_stat_restore" "$package_post_stat_destination" \
    "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$package_post_stat_restore]}" "$package_post_stat_root" \
    "$(package_publication_root_identity "$package_post_stat_root")" "post-stat restore fixture"; then
    printf 'package restore published a post-stat replacement victim\n' >&2
    exit 1
fi
[[ ! -e "$package_post_stat_destination" ]]
grep -Fqx 'replacement restore victim' "$package_post_stat_restore"
grep -Fqx 'captured restore input' "$package_post_stat_restore_displaced"
unset -f package_identity_bound_hook

# The restore syscall must remain bound to the publication-root inode after the
# caller's last shell-level check. Moving the captured backup inode into a
# replacement pathname root must not let rollback report success in the wrong
# namespace.
package_restore_root_race="$workdir/package-restore-root-race"
package_restore_root_race_displaced="$workdir/package-restore-root-race-displaced"
package_restore_root_race_backup="$package_restore_root_race/backup"
mkdir -m 0700 "$package_restore_root_race"
printf 'captured root-race backup\n' >"$package_restore_root_race_backup"
package_publication_reset ""
# shellcheck disable=SC2034 # Descriptor lifetime holds the original root lock.
package_restore_root_race_lock_fd=""
package_acquire_publication_lock "$package_restore_root_race" restore-root-race \
    package_restore_root_race_lock_fd
package_capture_publication_file "$package_restore_root_race_backup" \
    "restore root-race backup"
package_restore_root_race_identity="${PACKAGE_PUBLICATION_FILE_IDENTITIES[$package_restore_root_race_backup]}"
package_restore_root_race_root_identity="${PACKAGE_PUBLICATION_ROOT_IDENTITIES[$package_restore_root_race]}"
# shellcheck disable=SC2329 # Exported fault-injection hook consumed by package restore.
package_identity_bound_hook() {
    [[ "$1" == before-restore && "$3" == "$package_restore_root_race_backup" ]] || return 0
    mv -- "$package_restore_root_race" "$package_restore_root_race_displaced"
    mkdir -m 0700 "$package_restore_root_race"
    printf 'replacement root sentinel\n' >"$package_restore_root_race/sentinel"
    mv -- "$package_restore_root_race_displaced/backup" "$package_restore_root_race/backup"
}
if package_identity_bound_restore "$package_restore_root_race_backup" \
    "$package_restore_root_race/artifact" "$package_restore_root_race_identity" \
    "$package_restore_root_race" "$package_restore_root_race_root_identity" \
    "restore root-race fixture"; then
    printf 'package restore published into a replacement root inode\n' >&2
    exit 1
fi
unset -f package_identity_bound_hook
[[ ! -e "$package_restore_root_race/artifact" ]]
grep -Fqx 'captured root-race backup' "$package_restore_root_race_backup"
grep -Fqx 'replacement root sentinel' "$package_restore_root_race/sentinel"

package_restore_root="$workdir/package-restore-root"
package_restore_run="$package_restore_root/run"
mkdir -p "$package_restore_run"
printf 'previous artifact\n' >"$package_restore_root/artifact"
printf 'candidate artifact\n' >"$package_restore_run/candidate"
package_publication_reset "$package_restore_run"
package_restore_lock_fd=""
package_acquire_publication_lock "$package_restore_root" restore-fixture package_restore_lock_fd
[[ -n "$package_restore_lock_fd" ]]
package_publication_hook() {
    [[ "$1" != after-promote ]] || return 91
    [[ "$1" != before-restore ]] || return 92
}
if package_publish_candidate "$package_restore_run/candidate" "$package_restore_root/artifact" \
    "$package_restore_root" 'restore fixture'; then
    printf 'forced publication failure unexpectedly succeeded\n' >&2
    exit 1
fi
if package_cleanup_publication 1; then
    printf 'package publication suppressed a forced restore failure\n' >&2
    exit 1
else
    package_restore_status=$?
fi
[[ "$package_restore_status" == 74 && -d "$package_restore_run" ]]
package_restore_backup="${PACKAGE_PUBLICATION_BACKUPS[0]}"
grep -Fqx 'previous artifact' "$package_restore_backup"
[[ ! -e "$package_restore_root/artifact" ]]
package_restore_run_identity="${PACKAGE_CLEANUP_ROOT_IDENTITIES[$package_restore_run]}"
package_restore_diagnostic_before="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC"
package_restore_diagnostic_identity_before="$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY"
[[ "$package_restore_run_identity" == "$(stat -c '%d:%i:%u:%F' "$package_restore_run")" &&
"$package_restore_diagnostic_identity_before" == "$(stat -c '%d:%i:%u:%F' "$package_restore_diagnostic_before")" ]]
unset -f package_publication_hook
package_restore_retry_status=0
package_cleanup_publication 1 || package_restore_retry_status=$?
if [[ "$package_restore_retry_status" != 1 ]]; then
    printf 'package restore retry returned an unexpected status: %s\n' \
        "$package_restore_retry_status" >&2
    exit 1
fi
if ! grep -Fqx 'previous artifact' "$package_restore_root/artifact"; then
    printf 'package restore retry did not restore the previous artifact: %s\n' \
        "$package_restore_root/artifact" >&2
    exit 1
fi
if [[ -e "$package_restore_run" || -L "$package_restore_run" ]]; then
    printf 'package restore retry left its original retained root pathname: %s\n' \
        "$package_restore_run" >&2
    exit 1
fi
package_restore_retained_run="$PACKAGE_LAST_REMOVE_QUARANTINE"
package_restore_expected_diagnostic="$package_restore_retained_run/${package_restore_diagnostic_before#"$package_restore_run/"}"
if [[ ! -d "$package_restore_retained_run" || -L "$package_restore_retained_run" ]]; then
    printf 'package restore retained root is not a real directory: %s\n' \
        "$package_restore_retained_run" >&2
    exit 1
fi
if [[ "$(stat -c '%d:%i:%u:%F' "$package_restore_retained_run")" != "$package_restore_run_identity" ]]; then
    printf 'package restore retained root lost its captured identity: %s\n' \
        "$package_restore_retained_run" >&2
    exit 1
fi
if ((${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]} == 0)); then
    printf 'package restore retained root was not recorded\n' >&2
    exit 1
fi
package_restore_retained_index=$((${#PACKAGE_RETAINED_REMOVAL_QUARANTINES[@]} - 1))
if [[ "${PACKAGE_RETAINED_REMOVAL_QUARANTINES[$package_restore_retained_index]}" != "$package_restore_retained_run" ||
    "${PACKAGE_RETAINED_REMOVAL_QUARANTINE_IDENTITIES[$package_restore_retained_index]}" != "$package_restore_run_identity" ]]; then
    printf 'package restore retained root evidence is stale: %s\n' \
        "$package_restore_retained_run" >&2
    exit 1
fi
if [[ "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC" != "$package_restore_expected_diagnostic" ]]; then
    printf 'package restore retained recovery diagnostic was not rebased: expected=%q actual=%q\n' \
        "$package_restore_expected_diagnostic" "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC" >&2
    exit 1
fi
if [[ "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC_IDENTITY" != "$package_restore_diagnostic_identity_before" ||
    "$(stat -c '%d:%i:%u:%F' "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC")" != "$package_restore_diagnostic_identity_before" ]]; then
    printf 'package restore retained recovery diagnostic lost its captured identity: %s\n' \
        "$PACKAGE_PUBLICATION_RECOVERY_DIAGNOSTIC" >&2
    exit 1
fi

# Signals at the exact filesystem/bookkeeping boundary must observe either the
# complete old generation or a rollback-capable new generation. Exercise file
# and tree replacement, absent publication, transactional removal, and a
# second signal delivered while rollback is already cleaning up.
for package_signal_case in file-existing tree-existing file-absent remove second-signal; do
    package_signal_root="$workdir/package-signal-$package_signal_case"
    mkdir -p "$package_signal_root/run"
    PACKAGE_SIGNAL_CASE="$package_signal_case" PACKAGE_SIGNAL_ROOT="$package_signal_root" \
        PACKAGE_COMMON="$repo_root/scripts/package-common.sh" bash -c '
        set -euo pipefail
        source "$PACKAGE_COMMON"
        root="$PACKAGE_SIGNAL_ROOT"
        case "$PACKAGE_SIGNAL_CASE" in
        tree-existing)
            mkdir "$root/artifact" "$root/run/candidate"
            printf "previous tree\n" >"$root/artifact/value"
            printf "candidate tree\n" >"$root/run/candidate/value"
            ;;
        remove)
            printf "previous removed file\n" >"$root/artifact"
            ;;
        *)
            [[ "$PACKAGE_SIGNAL_CASE" == file-absent ]] ||
                printf "previous file\n" >"$root/artifact"
            printf "candidate file\n" >"$root/run/candidate"
            ;;
        esac
        package_publication_reset "$root/run"
        package_signal_lock_output_fd=""
        package_acquire_publication_lock "$root" signal-fixture package_signal_lock_output_fd
        cleanup() {
            status=$?
            trap - EXIT
            package_begin_signal_cleanup
            package_cleanup_publication "$status" || status=$?
            exit "$status"
        }
        trap cleanup EXIT
        trap "package_signal_handler 130" INT
        trap "package_signal_handler 143" TERM
        trap "package_signal_handler 129" HUP
        package_publication_transition_hook() {
            event="$1"
            case "$PACKAGE_SIGNAL_CASE:$event" in
            file-existing:after-backup-move|tree-existing:after-backup-move|remove:after-removal-backup-move|file-absent:after-promotion-move|second-signal:after-promotion-move)
                kill -TERM "$$"
                ;;
            esac
        }
        package_identity_bound_hook() {
            if [[ "$PACKAGE_SIGNAL_CASE" == second-signal && "$1" == before-remove ]]; then
                kill -TERM "$$"
                kill -HUP "$$"
            fi
        }
        if [[ "$PACKAGE_SIGNAL_CASE" == remove ]]; then
            package_remove_destination "$root/artifact" "$root" signal-remove
        else
            package_publish_candidate "$root/run/candidate" "$root/artifact" "$root" signal-publish
        fi
        exit 99
    ' >"$package_signal_root/run.log" 2>&1 && {
        printf 'signal-atomic package case unexpectedly succeeded: %s\n' "$package_signal_case" >&2
        exit 1
    }
    package_signal_status=$?
    [[ "$package_signal_status" == 143 ]]
    case "$package_signal_case" in
    tree-existing) grep -Fqx 'previous tree' "$package_signal_root/artifact/value" ;;
    file-existing | second-signal) grep -Fqx 'previous file' "$package_signal_root/artifact" ;;
    remove) grep -Fqx 'previous removed file' "$package_signal_root/artifact" ;;
    file-absent) [[ ! -e "$package_signal_root/artifact" ]] ;;
    esac
    [[ ! -e "$package_signal_root/run" ]]
    [[ -z "$(find "$package_signal_root" -name '*.previous.*' -print -quit)" ]]
done

# Transactional publication binds regular files as strictly as recursive
# directory roots. A same-UID replacement planted after promotion must survive
# rollback, and the prior/candidate files must remain available for recovery.
package_file_promote_root="$workdir/package-file-promote-root"
package_file_promote_run="$package_file_promote_root/run"
package_file_promote_displaced="$workdir/package-file-promote-displaced"
package_file_promote_victim="$workdir/package-file-promote-victim"
mkdir -p "$package_file_promote_run"
printf 'previous file artifact\n' >"$package_file_promote_root/artifact"
printf 'candidate file artifact\n' >"$package_file_promote_run/candidate"
printf 'replacement file victim\n' >"$package_file_promote_victim"
package_publication_reset "$package_file_promote_run"
package_file_promote_lock_fd=""
package_acquire_publication_lock "$package_file_promote_root" file-promote-fixture \
    package_file_promote_lock_fd
[[ -n "$package_file_promote_lock_fd" ]]
package_publication_hook() {
    [[ "$1" == after-promote ]] || return 0
    mv -- "$package_file_promote_root/artifact" "$package_file_promote_displaced"
    mv -- "$package_file_promote_victim" "$package_file_promote_root/artifact"
    return 91
}
if package_publish_candidate "$package_file_promote_run/candidate" \
    "$package_file_promote_root/artifact" "$package_file_promote_root" 'file promote fixture'; then
    printf 'regular-file publication accepted an after-promote replacement victim\n' >&2
    exit 1
fi
unset -f package_publication_hook
if package_cleanup_publication 1; then
    printf 'regular-file rollback removed an after-promote replacement victim\n' >&2
    exit 1
else
    package_file_promote_status=$?
fi
[[ "$package_file_promote_status" == 74 ]]
grep -Fqx 'replacement file victim' "$package_file_promote_root/artifact"
grep -Fqx 'candidate file artifact' "$package_file_promote_displaced"
package_file_promote_backup="${PACKAGE_PUBLICATION_BACKUPS[0]}"
grep -Fqx 'previous file artifact' "$package_file_promote_backup"
rm -rf "$package_file_promote_root" "$package_file_promote_displaced"

# Commit cleanup must also refuse a replaced regular-file backup. The new
# generation remains committed while both the planted victim and displaced
# prior generation are preserved for diagnosis.
package_file_commit_root="$workdir/package-file-commit-root"
package_file_commit_run="$package_file_commit_root/run"
package_file_commit_displaced="$workdir/package-file-commit-displaced"
package_file_commit_victim="$workdir/package-file-commit-victim"
mkdir -p "$package_file_commit_run"
printf 'previous commit artifact\n' >"$package_file_commit_root/artifact"
printf 'candidate commit artifact\n' >"$package_file_commit_run/candidate"
printf 'replacement commit victim\n' >"$package_file_commit_victim"
package_publication_reset "$package_file_commit_run"
package_file_commit_lock_fd=""
package_acquire_publication_lock "$package_file_commit_root" file-commit-fixture \
    package_file_commit_lock_fd
[[ -n "$package_file_commit_lock_fd" ]]
package_publication_hook() {
    [[ "$1" == after-commit ]] || return 0
    package_file_commit_backup="${PACKAGE_PUBLICATION_BACKUPS[0]}"
    mv -- "$package_file_commit_backup" "$package_file_commit_displaced"
    mv -- "$package_file_commit_victim" "$package_file_commit_backup"
}
package_publish_candidate "$package_file_commit_run/candidate" \
    "$package_file_commit_root/artifact" "$package_file_commit_root" 'file commit fixture'
if package_commit_publication; then
    printf 'commit cleanup removed an after-commit regular-file replacement victim\n' >&2
    exit 1
fi
unset -f package_publication_hook
if package_cleanup_publication 0; then
    printf 'committed cleanup accepted an after-commit regular-file replacement victim\n' >&2
    exit 1
else
    package_file_commit_status=$?
fi
[[ "$package_file_commit_status" == 74 ]]
grep -Fqx 'candidate commit artifact' "$package_file_commit_root/artifact"
package_file_commit_backup="${PACKAGE_PUBLICATION_BACKUPS[0]}"
grep -Fqx 'replacement commit victim' "$package_file_commit_backup"
grep -Fqx 'previous commit artifact' "$package_file_commit_displaced"
rm -rf "$package_file_commit_root" "$package_file_commit_displaced"

# Replacing the entire output root splits pathname-local lock files. The first
# publisher must detect its bound root inode changed and retain its displaced
# transaction without touching any file planted in the replacement root.
package_root_swap="$workdir/package-root-swap"
package_root_swap_displaced="$workdir/package-root-swap-displaced"
package_root_swap_run="$package_root_swap/run"
package_root_swap_second="$workdir/package-root-swap-second"
mkdir -m 0700 "$package_root_swap" "$package_root_swap_run"
printf 'previous root-swap artifact\n' >"$package_root_swap/artifact"
printf 'candidate root-swap artifact\n' >"$package_root_swap_run/candidate"
package_publication_reset "$package_root_swap_run"
package_root_swap_lock_fd=""
package_acquire_publication_lock "$package_root_swap" root-swap-fixture package_root_swap_lock_fd
[[ -n "$package_root_swap_lock_fd" ]]
package_publication_hook() {
    [[ "$1" == after-promote ]] || return 0
    mv "$package_root_swap" "$package_root_swap_displaced"
    mkdir -m 0700 "$package_root_swap"
    printf 'replacement root sentinel\n' >"$package_root_swap/artifact"
    bash -c '
        set -euo pipefail
        source "$1"
        package_publication_reset ""
        fd=""
        package_acquire_publication_lock "$2" root-swap-fixture fd
        : >"$3"
    ' package-root-swap-second "$repo_root/scripts/package-common.sh" \
        "$package_root_swap" "$package_root_swap_second"
    return 91
}
if package_publish_candidate "$package_root_swap_run/candidate" "$package_root_swap/artifact" \
    "$package_root_swap" 'root swap fixture'; then
    printf 'package publication accepted an output-root inode replacement\n' >&2
    exit 1
fi
unset -f package_publication_hook
if package_cleanup_publication 1; then
    printf 'package cleanup accepted an output-root inode replacement\n' >&2
    exit 1
else
    package_root_swap_status=$?
fi
[[ "$package_root_swap_status" == 74 && -e "$package_root_swap_second" ]]
grep -Fqx 'replacement root sentinel' "$package_root_swap/artifact"
grep -Fqx 'candidate root-swap artifact' "$package_root_swap_displaced/artifact"
package_root_swap_backup="${PACKAGE_PUBLICATION_BACKUPS[0]}"
package_root_swap_displaced_backup="$package_root_swap_displaced/${package_root_swap_backup#"$package_root_swap/"}"
grep -Fqx 'previous root-swap artifact' "$package_root_swap_displaced_backup"
rm -rf "$package_root_swap" "$package_root_swap_displaced"

package_dirty_repo="$workdir/package-dirty-repo"
package_clean_dist="$workdir/package-clean-dist"
package_clean_target="$workdir/package-clean-target"
package_clean_docker_input="$workdir/package-clean-docker-input"
package_clean_cargo_log="$workdir/package-clean-cargo.log"
mkdir -p "$package_dirty_repo/scripts" "$package_dirty_repo/config" \
    "$package_dirty_repo/crates/borondns-cli" "$package_dirty_repo/crates/boron-gun" "$package_clean_dist" \
    "$package_clean_target" "$package_clean_docker_input"
cp "$repo_root/scripts/package-common.sh" "$repo_root/scripts/package-installer.sh" \
    "$repo_root/scripts/package-docker-image.sh" "$repo_root/scripts/package-sbom.sh" \
    "$repo_root/scripts/release-api-supervisor.py" "$repo_root/scripts/verify-docker-archive.py" \
    "$package_dirty_repo/scripts/"
cp "$repo_root/Cargo.toml" "$package_dirty_repo/Cargo.toml"
cp "$repo_root/LICENSE-MIT" "$repo_root/LICENSE-APACHE" "$package_dirty_repo/"
cp "$repo_root/config/borondns.example.toml" "$package_dirty_repo/config/"
cp -R "$repo_root/packaging" "$package_dirty_repo/packaging"
git -C "$package_dirty_repo" init -q
git -C "$package_dirty_repo" add .
git -C "$package_dirty_repo" -c user.name=Test -c user.email=test@example.invalid commit -qm fixture

# cargo-cyclonedx writes two fixed workspace placeholders. TERM/HUP at either
# create/map/ownership boundary must remove every inode the current SBOM run
# claimed, without touching any pre-existing path.
# shellcheck disable=SC2329 # Exported fault-injection hook used by child Bash.
package_owned_file_transition_hook() {
    [[ "$1" == after-create ]] || return 0
    case "${PACKAGE_SBOM_PLACEHOLDER_SIGNAL:?}" in
    first) [[ "$2" == */crates/borondns-cli/borondns_bin.cdx.json ]] || return 0 ;;
    second) [[ "$2" == */crates/boron-gun/boron-gun_bin.cdx.json ]] || return 0 ;;
    *) return 90 ;;
    esac
    kill -TERM "$BASHPID"
    kill -HUP "$BASHPID"
}
export -f package_owned_file_transition_hook
for package_sbom_placeholder_signal in first second; do
    package_sbom_signal_dist="$workdir/package-sbom-placeholder-$package_sbom_placeholder_signal"
    package_sbom_signal_repo="$workdir/package-sbom-placeholder-repo-$package_sbom_placeholder_signal"
    cp -a "$package_dirty_repo" "$package_sbom_signal_repo"
    mkdir -p "$package_sbom_signal_dist"
    set +e
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_sbom_signal_dist" \
        BORONDNS_SBOM_DOCKER=0 PACKAGE_SBOM_PLACEHOLDER_SIGNAL="$package_sbom_placeholder_signal" \
        PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_sbom_signal_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_sbom_signal_repo/Cargo.toml" \
        "$package_sbom_signal_repo/scripts/package-sbom.sh" \
        >"$package_sbom_signal_dist/run.log" 2>&1
    package_sbom_signal_status=$?
    set -e
    [[ "$package_sbom_signal_status" == 143 ]]
    [[ ! -e "$package_sbom_signal_repo/crates/borondns-cli/borondns_bin.cdx.json" ]]
    [[ ! -e "$package_sbom_signal_repo/crates/boron-gun/boron-gun_bin.cdx.json" ]]
    mapfile -t package_sbom_signal_quarantines < <(find "$package_sbom_signal_repo/.git" \
        -type f -name '*_bin.cdx.json.borondns-remove.*' -print)
    if [[ "$package_sbom_placeholder_signal" == first ]]; then
        ((${#package_sbom_signal_quarantines[@]} == 1))
    else
        ((${#package_sbom_signal_quarantines[@]} == 2))
    fi
    [[ -z "$(find "$package_sbom_signal_dist" -mindepth 1 -maxdepth 1 \
        -name '*.sbom-package.*' ! -name '*.borondns-remove.*' -print -quit)" ]]
done
unset -f package_owned_file_transition_hook

# EXIT owns the private installer run root before allocation. Failures during
# identity capture, immediate termination, or first-child creation must not leak
# the freshly allocated package tree.
package_early_mkdir_bin="$workdir/package-early-mkdir-bin"
package_early_mkdir_dist="$workdir/package-early-mkdir-dist"
mkdir -p "$package_early_mkdir_bin" "$package_early_mkdir_dist"
# shellcheck disable=SC2016 # Wrapper arguments expand when the generated fixture runs.
printf '%s\n' '#!/usr/bin/env bash' \
    'for argument in "$@"; do [[ "$argument" != */build-target ]] || exit 93; done' \
    'exec /usr/bin/mkdir "$@"' >"$package_early_mkdir_bin/mkdir"
chmod +x "$package_early_mkdir_bin/mkdir"
if PATH="$package_early_mkdir_bin:$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" \
    RUSTC="$package_fake_bin/rustc" BORONDNS_DIST_DIR="$package_early_mkdir_dist" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-early-mkdir.log" 2>&1; then
    printf 'package installer ignored its injected first-child mkdir failure\n' >&2
    exit 1
fi
[[ -z "$(find "$package_early_mkdir_dist" -mindepth 1 -maxdepth 1 \
    -name '*.package.*' ! -name '*.borondns-remove.*' -print -quit)" ]]

package_early_capture_bin="$workdir/package-early-capture-bin"
package_early_capture_dist="$workdir/package-early-capture-dist"
mkdir -p "$package_early_capture_bin" "$package_early_capture_dist"
# shellcheck disable=SC2016 # Generated wrapper state expands in the fixture.
printf '%s\n' '#!/usr/bin/env bash' \
    'count=0; [[ ! -e "${PACKAGE_EARLY_STAT_COUNT:?}" ]] || read -r count <"$PACKAGE_EARLY_STAT_COUNT"' \
    'count=$((count + 1)); printf "%s\n" "$count" >"$PACKAGE_EARLY_STAT_COUNT"' \
    '[[ "$count" != 3 ]] || exit 97' \
    'exec /usr/bin/stat "$@"' >"$package_early_capture_bin/stat"
chmod +x "$package_early_capture_bin/stat"
if PATH="$package_early_capture_bin:$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" \
    RUSTC="$package_fake_bin/rustc" BORONDNS_DIST_DIR="$package_early_capture_dist" \
    PACKAGE_EARLY_STAT_COUNT="$workdir/package-early-stat-count" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-early-capture.log" 2>&1; then
    printf 'package installer ignored its injected run-root identity-capture failure\n' >&2
    exit 1
fi
[[ -z "$(find "$package_early_capture_dist" -mindepth 1 -maxdepth 1 \
    -name '*.package.*' ! -name '*.borondns-remove.*' -print -quit)" ]]

package_early_signal_bin="$workdir/package-early-signal-bin"
package_early_signal_dist="$workdir/package-early-signal-dist"
mkdir -p "$package_early_signal_bin" "$package_early_signal_dist"
# shellcheck disable=SC2016 # Generated wrapper arguments expand in the fixture.
printf '%s\n' '#!/usr/bin/env bash' \
    '/usr/bin/mkdir "$@" || exit' \
    'for argument in "$@"; do' \
    '  if [[ "${PACKAGE_EARLY_SIGNAL_MODE:-run}" == docker-input ]]; then' \
    '    [[ "$argument" != *.docker-input.* ]] || kill -TERM "$PPID"' \
    '  elif [[ "$argument" == *.package.* || "$argument" == *.sbom-package.* || "$argument" == *.docker-package.* ]]; then' \
    '    kill -TERM "$PPID"' \
    '  fi' \
    'done' >"$package_early_signal_bin/mkdir"
chmod +x "$package_early_signal_bin/mkdir"
if PATH="$package_early_signal_bin:$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" \
    RUSTC="$package_fake_bin/rustc" BORONDNS_DIST_DIR="$package_early_signal_dist" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-early-signal.log" 2>&1; then
    printf 'package installer ignored termination during run-root allocation\n' >&2
    exit 1
fi
[[ -z "$(find "$package_early_signal_dist" -mindepth 1 -maxdepth 1 \
    -name '*.package.*' ! -name '*.borondns-remove.*' -print -quit)" ]]

# SBOM and Docker builders must install the same EXIT ownership before their
# first private-root mkdir. Termination from the allocating child must not leave
# a generated staging directory whose name was never captured afterward.
for package_early_signal_script in sbom docker; do
    package_early_signal_case="$workdir/package-early-signal-$package_early_signal_script"
    package_early_signal_case_dist="$package_early_signal_case/dist"
    package_early_signal_case_input="$package_early_signal_case/input"
    mkdir -p "$package_early_signal_case_dist" "$package_early_signal_case_input"
    package_early_signal_env=(
        PATH="$package_early_signal_bin:$package_fake_bin:$PATH"
        CARGO="$package_fake_bin/cargo"
        RUSTC="$package_fake_bin/rustc"
        BORONDNS_DIST_DIR="$package_early_signal_case_dist"
        PACKAGE_CARGO_LOG="$package_clean_cargo_log"
        EXPECTED_PACKAGE_ROOT="$package_dirty_repo"
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml"
    )
    if [[ "$package_early_signal_script" == sbom ]]; then
        package_early_signal_env+=(BORONDNS_SBOM_DOCKER=0)
        package_early_signal_command=("$package_dirty_repo/scripts/package-sbom.sh")
    else
        package_early_signal_env+=(
            BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_early_signal_case_input"
            PACKAGE_DOCKER_TAG_STATE="$package_early_signal_case/tag.state"
        )
        package_early_signal_command=("$package_dirty_repo/scripts/package-docker-image.sh")
    fi
    if env "${package_early_signal_env[@]}" "${package_early_signal_command[@]}" \
        >"$package_early_signal_case/run.log" 2>&1; then
        printf '%s package builder ignored termination during run-root allocation\n' \
            "$package_early_signal_script" >&2
        exit 1
    fi
    [[ -z "$(find "$package_early_signal_case_dist" -mindepth 1 -maxdepth 1 \
        \( -name '*.sbom-package.*' -o -name '*.docker-package.*' \) \
        ! -name '*.borondns-remove.*' -print -quit)" ]]
done

# Docker owns a second private root on the installer-input filesystem. Its
# allocation must be recoverable even when the mkdir child terminates the
# parent before the following identity-capture command can run.
package_early_input_case="$workdir/package-early-signal-docker-input"
package_early_input_dist="$package_early_input_case/dist"
package_early_input_root="$package_early_input_case/input"
mkdir -p "$package_early_input_dist" "$package_early_input_root"
if PATH="$package_early_signal_bin:$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" \
    RUSTC="$package_fake_bin/rustc" BORONDNS_DIST_DIR="$package_early_input_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_early_input_root" \
    PACKAGE_EARLY_SIGNAL_MODE=docker-input PACKAGE_DOCKER_TAG_STATE="$package_early_input_case/tag.state" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$package_early_input_case/run.log" 2>&1; then
    printf 'Docker package builder ignored termination during installer-input allocation\n' >&2
    exit 1
fi
[[ -z "$(find "$package_early_input_dist" -mindepth 1 -maxdepth 1 \
    -name '*.docker-package.*' ! -name '*.borondns-remove.*' -print -quit)" ]]
[[ -z "$(find "$package_early_input_root" -mindepth 1 -maxdepth 1 \
    -name '*.docker-input.*' ! -name '*.borondns-remove.*' -print -quit)" ]]

# Docker must reject identical publication/input roots before it creates any
# private run directory. This deterministic preflight failure previously left
# .docker-package staging behind because the EXIT trap was installed too late.
package_same_root="$workdir/package-docker-same-root"
mkdir -p "$package_same_root"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_same_root" BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_same_root" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-docker-same-root.log" 2>&1; then
    printf 'Docker package builder accepted a shared output and installer-input root\n' >&2
    exit 1
fi
grep -Fq 'Docker installer input directory must be isolated from published dist' \
    "$workdir/package-docker-same-root.log"
[[ -z "$(find "$package_same_root" -maxdepth 1 \
    \( -name '*.docker-package.*' -o -name '*.docker-input.*' \) \
    ! -name '*.borondns-remove.*' -print -quit)" ]]

# Recursive package cleanup must bind the private directory object, not merely
# trust its random pathname. Exercise both the normal committed path and the
# failed-publication EXIT path for every package builder. The exported hook
# returns success for post-commit cases, so only the cleanup identity check can
# prevent deletion of the replacement victim.
# shellcheck disable=SC2329 # Exported fault-injection hook used by child Bash.
package_publication_hook() {
    local event="$1"
    local expected_event='after-promote'
    [[ "${PACKAGE_CLEANUP_SWAP_PHASE:?}" != success ]] || expected_event='after-commit'
    [[ "$event" == "$expected_event" && ! -e "${PACKAGE_CLEANUP_SWAP_MARKER:?}" ]] || return 0

    local retain_basename target
    retain_basename="$(basename -- "${PACKAGE_PUBLICATION_RETAIN_ROOT:-}")"
    case "${PACKAGE_CLEANUP_SWAP_SCRIPT:?}" in
    installer) [[ "$retain_basename" == *.package.* ]] || return 0 ;;
    sbom) [[ "$retain_basename" == *.sbom-package.* ]] || return 0 ;;
    docker) [[ "$retain_basename" == *.docker-package.* ]] || return 0 ;;
    *) return 90 ;;
    esac
    case "${PACKAGE_CLEANUP_SWAP_ROOT_KIND:-run}" in
    run) target="$PACKAGE_PUBLICATION_RETAIN_ROOT" ;;
    installer-publish)
        [[ "${PACKAGE_CLEANUP_SWAP_SCRIPT}" == docker && -n "${installer_publish_root:-}" ]] || return 0
        target="$installer_publish_root"
        ;;
    *) return 90 ;;
    esac

    printf '%s\n' "$target" >"${PACKAGE_CLEANUP_SWAP_PATH:?}"
    mv -- "$target" "${PACKAGE_CLEANUP_SWAP_DISPLACED:?}"
    mv -- "${PACKAGE_CLEANUP_SWAP_VICTIM:?}" "$target"
    : >"$PACKAGE_CLEANUP_SWAP_MARKER"
    [[ "$PACKAGE_CLEANUP_SWAP_PHASE" != failure ]] || return 91
}
export -f package_publication_hook
for package_cleanup_swap_script in installer sbom docker; do
    for package_cleanup_swap_phase in success failure; do
        package_cleanup_swap_case="$package_cleanup_swap_script-$package_cleanup_swap_phase-run"
        package_cleanup_swap_root="$workdir/package-cleanup-swap-$package_cleanup_swap_case"
        package_cleanup_swap_dist="$package_cleanup_swap_root/dist"
        package_cleanup_swap_input="$package_cleanup_swap_root/input"
        package_cleanup_swap_victim="$package_cleanup_swap_root/victim"
        package_cleanup_swap_displaced="$package_cleanup_swap_root/displaced"
        package_cleanup_swap_path="$package_cleanup_swap_root/target-path"
        package_cleanup_swap_marker="$package_cleanup_swap_root/swapped"
        package_cleanup_swap_log="$package_cleanup_swap_root/run.log"
        mkdir -p "$package_cleanup_swap_dist" "$package_cleanup_swap_input" "$package_cleanup_swap_victim"
        printf 'replacement cleanup victim\n' >"$package_cleanup_swap_victim/sentinel"
        case "$package_cleanup_swap_script" in
        docker) package_cleanup_swap_command=("$package_dirty_repo/scripts/package-docker-image.sh") ;;
        *) package_cleanup_swap_command=("$package_dirty_repo/scripts/package-$package_cleanup_swap_script.sh") ;;
        esac
        package_cleanup_swap_env=(
            PATH="$package_fake_bin:$PATH"
            CARGO="$package_fake_bin/cargo"
            RUSTC="$package_fake_bin/rustc"
            CARGO_TARGET_DIR="$package_clean_target"
            BORONDNS_DIST_DIR="$package_cleanup_swap_dist"
            PACKAGE_CARGO_LOG="$package_clean_cargo_log"
            EXPECTED_PACKAGE_ROOT="$package_dirty_repo"
            EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml"
            PACKAGE_CLEANUP_SWAP_SCRIPT="$package_cleanup_swap_script"
            PACKAGE_CLEANUP_SWAP_PHASE="$package_cleanup_swap_phase"
            PACKAGE_CLEANUP_SWAP_ROOT_KIND=run
            PACKAGE_CLEANUP_SWAP_VICTIM="$package_cleanup_swap_victim"
            PACKAGE_CLEANUP_SWAP_DISPLACED="$package_cleanup_swap_displaced"
            PACKAGE_CLEANUP_SWAP_PATH="$package_cleanup_swap_path"
            PACKAGE_CLEANUP_SWAP_MARKER="$package_cleanup_swap_marker"
        )
        case "$package_cleanup_swap_script" in
        sbom) package_cleanup_swap_env+=(BORONDNS_SBOM_DOCKER=0) ;;
        docker)
            package_cleanup_swap_env+=(
                BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_cleanup_swap_input"
                PACKAGE_DOCKER_TAG_STATE="$package_cleanup_swap_root/tag.state"
            )
            ;;
        esac
        set +e
        env "${package_cleanup_swap_env[@]}" "${package_cleanup_swap_command[@]}" \
            >"$package_cleanup_swap_log" 2>&1
        package_cleanup_swap_status=$?
        set -e
        [[ "$package_cleanup_swap_status" -ne 0 ]]
        if [[ ! -s "$package_cleanup_swap_path" ]]; then
            printf 'package cleanup-swap hook did not publish its target: script=%s phase=%s status=%s\n' \
                "$package_cleanup_swap_script" "$package_cleanup_swap_phase" \
                "$package_cleanup_swap_status" >&2
            sed -n '1,160p' "$package_cleanup_swap_log" >&2
            exit 1
        fi
        package_cleanup_swap_target="$(<"$package_cleanup_swap_path")"
        grep -Fqx 'replacement cleanup victim' "$package_cleanup_swap_target/sentinel"
        [[ -d "$package_cleanup_swap_displaced" ]]
        grep -Fq 'identity changed; refusing recursive cleanup' "$package_cleanup_swap_log"
    done
done

# Docker has a second independently created recursive-cleanup root used to copy
# the fresh nested installer generation onto the requested input filesystem.
for package_cleanup_swap_phase in success failure; do
    package_cleanup_swap_case="docker-$package_cleanup_swap_phase-installer-publish"
    package_cleanup_swap_root="$workdir/package-cleanup-swap-$package_cleanup_swap_case"
    package_cleanup_swap_dist="$package_cleanup_swap_root/dist"
    package_cleanup_swap_input="$package_cleanup_swap_root/input"
    package_cleanup_swap_victim="$package_cleanup_swap_root/victim"
    package_cleanup_swap_displaced="$package_cleanup_swap_root/displaced"
    package_cleanup_swap_path="$package_cleanup_swap_root/target-path"
    package_cleanup_swap_marker="$package_cleanup_swap_root/swapped"
    package_cleanup_swap_log="$package_cleanup_swap_root/run.log"
    mkdir -p "$package_cleanup_swap_dist" "$package_cleanup_swap_input" "$package_cleanup_swap_victim"
    printf 'replacement installer-publish victim\n' >"$package_cleanup_swap_victim/sentinel"
    set +e
    env PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_cleanup_swap_dist" \
        BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_cleanup_swap_input" \
        PACKAGE_DOCKER_TAG_STATE="$package_cleanup_swap_root/tag.state" \
        PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" PACKAGE_CLEANUP_SWAP_SCRIPT=docker \
        PACKAGE_CLEANUP_SWAP_PHASE="$package_cleanup_swap_phase" \
        PACKAGE_CLEANUP_SWAP_ROOT_KIND=installer-publish \
        PACKAGE_CLEANUP_SWAP_VICTIM="$package_cleanup_swap_victim" \
        PACKAGE_CLEANUP_SWAP_DISPLACED="$package_cleanup_swap_displaced" \
        PACKAGE_CLEANUP_SWAP_PATH="$package_cleanup_swap_path" \
        PACKAGE_CLEANUP_SWAP_MARKER="$package_cleanup_swap_marker" \
        "$package_dirty_repo/scripts/package-docker-image.sh" >"$package_cleanup_swap_log" 2>&1
    package_cleanup_swap_status=$?
    set -e
    [[ "$package_cleanup_swap_status" -ne 0 && -s "$package_cleanup_swap_path" ]]
    package_cleanup_swap_target="$(<"$package_cleanup_swap_path")"
    grep -Fqx 'replacement installer-publish victim' "$package_cleanup_swap_target/sentinel"
    [[ -d "$package_cleanup_swap_displaced" ]]
    grep -Fq 'identity changed; refusing recursive cleanup' "$package_cleanup_swap_log"
done
unset -f package_publication_hook

package_build_env_log="$workdir/package-build-env.log"
(
    umask 000
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_clean_dist" \
        BORONDNS_BUILD_COMMIT=forged BORONDNS_BUILD_RUST_VERSION=forged BORONDNS_BUILD_TIMESTAMP=forged \
        PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-installer.sh"
)
package_clean_manifest="$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl/manifest.txt"
grep -Fqx 'source_clean=1' "$package_clean_manifest"
grep -Fqx 'release_eligible=1' "$package_clean_manifest"
grep -Fqx 'dirty_source_override=0' "$package_clean_manifest"
package_clean_prefix="$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl"
[[ "$(stat -c '%a' "$package_clean_prefix")" == 755 ]]
[[ "$(stat -c '%a' "$package_clean_manifest")" == 644 ]]
[[ "$(stat -c '%a' "$package_clean_prefix.tar.xz")" == 644 ]]
[[ "$(stat -c '%a' "$package_clean_prefix.tar.xz.sha256")" == 644 ]]
[[ "$(stat -c '%a' "$package_clean_prefix.bin")" == 755 ]]
[[ "$(stat -c '%a' "$package_clean_prefix-boron-gun.bin")" == 755 ]]
python3 - "$package_clean_prefix.tar.xz" <<'PY'
import pathlib
import sys
import tarfile

with tarfile.open(sys.argv[1], mode="r:xz") as archive:
    for member in archive.getmembers():
        if member.isdir():
            expected_mode = 0o755
        elif member.isfile():
            expected_mode = (
                0o755
                if pathlib.PurePosixPath(member.name).name
                in {"borondns", "boron-gun", "install.sh"}
                else 0o644
            )
        else:
            raise SystemExit(f"unexpected installer archive member type: {member.name}")
        actual_mode = member.mode & 0o777
        if actual_mode != expected_mode:
            raise SystemExit(
                f"installer archive mode mismatch: {member.name} "
                f"actual={actual_mode:o} expected={expected_mode:o}"
            )
PY
clean_commit="$(git -C "$package_dirty_repo" rev-parse --short=12 HEAD)"
clean_epoch="$(git -C "$package_dirty_repo" show -s --format=%ct HEAD)"
clean_timestamp="$(
    python3 - "$clean_epoch" <<'PY'
import datetime, sys
print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
test "$(wc -l <"$package_build_env_log")" -eq 2
grep -Fqx "$clean_commit|rustc 1.88.0 (fake 2025-06-23)|$clean_timestamp" "$package_build_env_log"
if grep -Fq forged "$package_build_env_log"; then
    printf 'package installer propagated forged BORONDNS_BUILD metadata\n' >&2
    exit 1
fi

# cargo-cyclonedx writes fixed paths in the source workspace. A pre-existing
# operator file must be rejected intact, while a partial output created by the
# owned generator invocation must be removed on failure.
package_generated_borondns="$package_dirty_repo/crates/borondns-cli/borondns_bin.cdx.json"
package_generated_boron_gun="$package_dirty_repo/crates/boron-gun/boron-gun_bin.cdx.json"
printf 'operator CycloneDX sentinel\n' >"$package_generated_borondns"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$workdir/package-preexisting-sbom-dist" BORONDNS_SBOM_DOCKER=0 \
    BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-preexisting-sbom.log" 2>&1; then
    printf 'SBOM builder replaced a pre-existing cargo-cyclonedx output\n' >&2
    exit 1
fi
grep -Fq 'refusing to replace pre-existing cargo-cyclonedx workspace output' \
    "$workdir/package-preexisting-sbom.log"

grep -Fqx 'operator CycloneDX sentinel' "$package_generated_borondns"
rm "$package_generated_borondns"

# Generated cargo-cyclonedx paths remain hostile pathname boundaries after the
# tool returns. Cleanup must remove only the two captured output inodes, never a
# same-UID replacement planted after capture.
package_sbom_swap_env="$workdir/package-sbom-swap-env.sh"
cat >"$package_sbom_swap_env" <<'EOF'
package_sbom_generated_hook() {
    [[ "$1" == before-cleanup ]] || return 0
    mv -- "$2" "$2.original"
    printf 'generated SBOM replacement victim\n' >"$2"
}
EOF
if BASH_ENV="$package_sbom_swap_env" PATH="$package_fake_bin:$PATH" \
    CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    BORONDNS_DIST_DIR="$workdir/package-swapped-sbom-dist" BORONDNS_SBOM_DOCKER=0 \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-swapped-sbom.log" 2>&1; then
    printf 'SBOM cleanup accepted a generated-path replacement victim\n' >&2
    exit 1
fi
grep -Fqx 'generated SBOM replacement victim' "$package_generated_borondns"
test -f "$package_generated_borondns.original"
rm -f -- "$package_generated_borondns" "$package_generated_borondns.original" \
    "$package_generated_boron_gun"

if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$workdir/package-failed-sbom-dist" BORONDNS_SBOM_DOCKER=0 \
    PACKAGE_CYCLONEDX_FAIL_AFTER_FIRST=1 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-failed-sbom.log" 2>&1; then
    printf 'SBOM builder accepted a partial cargo-cyclonedx generation\n' >&2
    exit 1
fi
[[ ! -e "$package_generated_borondns" && ! -e "$package_generated_boron_gun" ]]
package_dirty_git_root="$(git -C "$package_dirty_repo" rev-parse --absolute-git-dir)"
mapfile -t package_failed_sbom_retained_lines < <(
    grep -F 'logical removal retained an identity-bound quarantine for privileged/manual reconciliation: path=' \
        "$workdir/package-failed-sbom.log" |
        grep -F "path=$package_dirty_git_root/."
)
((${#package_failed_sbom_retained_lines[@]} == 2))
for package_failed_sbom_retained_line in "${package_failed_sbom_retained_lines[@]}"; do
    package_failed_sbom_retained_path="${package_failed_sbom_retained_line#*path=}"
    package_failed_sbom_retained_path="${package_failed_sbom_retained_path%% identity=*}"
    [[ -f "$package_failed_sbom_retained_path" ]]
    package_failed_sbom_retained_identity="$(stat -c '%d:%i:%u' \
        "$package_failed_sbom_retained_path"):regular file"
    printf -v package_failed_sbom_retained_identity_quoted '%q' \
        "$package_failed_sbom_retained_identity"
    package_failed_sbom_parent_identity="$(stat -c '%d:%i:%u' \
        "$package_dirty_git_root"):directory"
    [[ "$package_failed_sbom_retained_line" == *" identity=$package_failed_sbom_retained_identity_quoted parent=$package_dirty_git_root parent_identity=$package_failed_sbom_parent_identity" ]]
done

# Concurrent installer invocations must never share Cargo's release output,
# even when their callers supply the same CARGO_TARGET_DIR.
package_isolated_dist_a="$workdir/package-isolated-dist-a"
package_isolated_dist_b="$workdir/package-isolated-dist-b"
package_isolated_log_a="$workdir/package-isolated-a.log"
package_isolated_log_b="$workdir/package-isolated-b.log"
declare -A package_isolated_pid=()
for isolated_name in a b; do
    isolated_dist_var="package_isolated_dist_$isolated_name"
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="${!isolated_dist_var}" \
        EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-installer.sh" >/dev/null &
    package_isolated_pid[$isolated_name]=$!
done
wait "${package_isolated_pid[a]}"
wait "${package_isolated_pid[b]}"
package_isolated_target_a="$(awk '$1 == "build" { for (field = 1; field <= NF; field++) if ($field == "--target-dir") print $(field + 1) }' \
    "$package_isolated_log_a" | sort -u)"
package_isolated_target_b="$(awk '$1 == "build" { for (field = 1; field <= NF; field++) if ($field == "--target-dir") print $(field + 1) }' \
    "$package_isolated_log_b" | sort -u)"
[[ -n "$package_isolated_target_a" && -n "$package_isolated_target_b" &&
    "$package_isolated_target_a" != "$package_isolated_target_b" &&
    "$package_isolated_target_a" != "$package_clean_target" &&
    "$package_isolated_target_b" != "$package_clean_target" ]]
[[ "$package_isolated_target_a" == "$package_isolated_dist_a"/.borondns-*.package.*/build-target ]]
[[ "$package_isolated_target_b" == "$package_isolated_dist_b"/.borondns-*.package.*/build-target ]]

PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_clean_dist" BORONDNS_SBOM_DOCKER=0 \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh"
package_clean_sbom_manifest="$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl-sbom-manifest.tsv"
grep -Fq '# source_clean=1' "$package_clean_sbom_manifest"
grep -Fq '# release_eligible=1' "$package_clean_sbom_manifest"
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_clean_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_clean_docker_input" \
    PACKAGE_DOCKER_SAVE_LAYOUT=oci PACKAGE_DOCKER_IID_NO_NEWLINE=1 \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh"
package_clean_image_manifest="$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-image.manifest.txt"
grep -Fqx "image_id=$package_fake_image_id" \
    "$package_clean_image_manifest"
grep -Fqx 'source_clean=1' "$package_clean_image_manifest"
grep -Fqx 'release_eligible=1' "$package_clean_image_manifest"
grep -Fqx 'dirty_source_override=0' "$package_clean_image_manifest"
for _ in 1 2; do
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_clean_dist" \
        BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_clean_docker_input" \
        PACKAGE_DOCKER_SAVE_LAYOUT=oci PACKAGE_DOCKER_IID_NO_NEWLINE=1 \
        PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-docker-image.sh" >/dev/null
done
[[ -z "$(find "$package_clean_dist" "$package_clean_docker_input" -maxdepth 1 \
    \( -name '*.docker-package.*' -o -name '*.docker-input.*' -o -name '*.previous.*' \) \
    ! -name '*.borondns-remove.*' -print -quit)" ]]

# The dynamic-link escape hatch is always diagnostic, even from a clean tree.
# It must use an isolated name/tag namespace and carry explicit non-release
# provenance through the nested Docker package and SBOM.
package_dynamic_tool_bin="$workdir/package-dynamic-tool-bin"
package_dynamic_dist="$workdir/package-dynamic-dist"
package_dynamic_input="$workdir/package-dynamic-input"
mkdir -p "$package_dynamic_tool_bin" "$package_dynamic_dist" "$package_dynamic_input"
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s: ELF 64-bit dynamically linked\\n" "$@"' \
    >"$package_dynamic_tool_bin/file"
printf '%s\n' '#!/usr/bin/env bash' 'printf "libc.so.6 => /lib/libc.so.6\\n"' \
    >"$package_dynamic_tool_bin/ldd"
chmod 0755 "$package_dynamic_tool_bin/file" "$package_dynamic_tool_bin/ldd"
if BORONDNS_PACKAGE_ALLOW_DYNAMIC=invalid "$package_dirty_repo/scripts/package-installer.sh" \
    >"$workdir/package-invalid-dynamic.log" 2>&1; then
    printf 'package installer accepted an invalid dynamic-link override\n' >&2
    exit 1
fi
grep -Fq 'BORONDNS_PACKAGE_ALLOW_DYNAMIC must be 0 or 1' "$workdir/package-invalid-dynamic.log"
if GITHUB_ACTIONS=true BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-dynamic-actions.log" 2>&1; then
    printf 'package installer accepted dynamic-link override in GitHub Actions\n' >&2
    exit 1
fi
grep -Fq 'dynamic-link packaging override is forbidden in GitHub Actions release paths' \
    "$workdir/package-dynamic-actions.log"
PATH="$package_dynamic_tool_bin:$package_fake_bin:$PATH" \
    CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_dynamic_dist" \
    BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh"
package_dynamic_prefix=borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dynamic
package_dynamic_manifest="$package_dynamic_dist/$package_dynamic_prefix/manifest.txt"
grep -Fqx 'source_clean=1' "$package_dynamic_manifest"
grep -Fqx 'release_eligible=0' "$package_dynamic_manifest"
grep -Fqx 'dynamic_link_override=1' "$package_dynamic_manifest"
[[ ! -e "$package_dynamic_dist/borondns-0.9.0-x86_64-unknown-linux-musl.tar.xz" ]]
PATH="$package_dynamic_tool_bin:$package_fake_bin:$PATH" \
    CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_dynamic_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_dynamic_input" \
    BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh"
package_dynamic_image_manifest="$package_dynamic_dist/$package_dynamic_prefix-docker-image.manifest.txt"
grep -Fqx 'release_eligible=0' "$package_dynamic_image_manifest"
grep -Fqx 'dynamic_link_override=1' "$package_dynamic_image_manifest"
grep -Fq 'canonical_image_ref=docker.io/library/borondns:0.9.0-nonrelease-dynamic' \
    "$package_dynamic_image_manifest"
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_dynamic_dist" BORONDNS_SBOM_DOCKER=0 \
    BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh"
grep -Fq '# release_eligible=0' "$package_dynamic_dist/$package_dynamic_prefix-sbom-manifest.tsv"
grep -Fq '# dynamic_link_override=1' "$package_dynamic_dist/$package_dynamic_prefix-sbom-manifest.tsv"

# Dirty-tag transformation owns a reserved namespace. A later clean invocation
# choosing the dirty alias explicitly must fail before it can replace the tag.
package_diagnostic_dist="$workdir/package-diagnostic-dist"
package_diagnostic_input="$workdir/package-diagnostic-input"
package_diagnostic_state="$workdir/package-diagnostic.state"
printf 'dirty source\n' >"$package_dirty_repo/diagnostic-dirty-source"
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_diagnostic_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_diagnostic_input" \
    BORONDNS_DOCKER_IMAGE_REF=borondns:0.9.0 BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 \
    PACKAGE_DOCKER_TAG_STATE="$package_diagnostic_state" PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >/dev/null
grep -Fqx "$package_fake_image_id" \
    "$package_diagnostic_state"
rm "$package_dirty_repo/diagnostic-dirty-source"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_diagnostic_dist-clean" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_diagnostic_input-clean" \
    BORONDNS_DOCKER_IMAGE_REF=borondns:0.9.0-nonrelease-dirty \
    PACKAGE_DOCKER_IMAGE_ID="$package_fake_second_image_id" PACKAGE_DOCKER_CONFIG_VARIANT=second \
    PACKAGE_DOCKER_TAG_STATE="$package_diagnostic_state" PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-clean-diagnostic-ref.log" 2>&1; then
    printf 'clean Docker package accepted the reserved dirty diagnostic tag\n' >&2
    exit 1
fi
grep -Fq 'reserved diagnostic tag namespace' "$workdir/package-clean-diagnostic-ref.log"
grep -Fqx "$package_fake_image_id" \
    "$package_diagnostic_state"

package_syft_log="$workdir/package-syft.log"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'if [[ "${1:-}" == version ]]; then printf "Version: 1.27.1\n"; exit 0; fi' \
    '[[ "${PACKAGE_SYFT_FAIL:-0}" != 1 ]] || exit 99' \
    'if [[ -n "${PACKAGE_SYFT_LOG:-}" ]]; then printf "%s\n" "${1:-}" >>"$PACKAGE_SYFT_LOG"; fi' \
    'printf "%s\n" '\''{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"docker-image"}}}'\''' \
    >"$package_fake_bin/syft"
chmod +x "$package_fake_bin/syft"
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_clean_dist" BORONDNS_SBOM_DOCKER=1 \
    PACKAGE_SYFT_LOG="$package_syft_log" PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh"
grep -Fqx "$package_fake_image_id" \
    "$package_syft_log"

package_retag_dist="$workdir/package-retag-dist"
package_retag_input="$workdir/package-retag-input"
package_retag_state="$workdir/package-retag.state"
printf '%s\n' 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    >"$package_retag_state"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_retag_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_retag_input" \
    PACKAGE_DOCKER_TAG_STATE="$package_retag_state" PACKAGE_DOCKER_FAIL_AFTER_TAG=1 \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-retag.log" 2>&1; then
    printf 'Docker package builder accepted a forced terminal tag failure\n' >&2
    exit 1
fi
grep -Fqx 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    "$package_retag_state"
[[ -z "$(find "$package_retag_dist" "$package_retag_input" \
    \( -path '*/.borondns-package-locks' -o -name '*.borondns-remove.*' \) -prune -o \
    -type f -print -quit)" ]]

# The package commit flag is the single commit point for both filesystem
# outputs and the daemon tag. A TERM immediately after that point must retain
# the complete new generation, never restore only the old tag.
package_postcommit_dist="$workdir/package-postcommit-dist"
package_postcommit_input="$workdir/package-postcommit-input"
package_postcommit_state="$workdir/package-postcommit.state"
printf '%s\n' 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    >"$package_postcommit_state"
# shellcheck disable=SC2329 # Exported fault-injection hook used by child Bash.
package_publication_hook() {
    [[ "$1" != after-commit || "$2" != 12 ]] || kill -TERM "$BASHPID"
}
export -f package_publication_hook
set +e
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_postcommit_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_postcommit_input" \
    BORONDNS_PACKAGE_DOCKER_LOCK_ROOT="$workdir/package-postcommit-lock" \
    PACKAGE_DOCKER_TAG_STATE="$package_postcommit_state" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-postcommit.log" 2>&1
package_postcommit_status=$?
set -e
unset -f package_publication_hook
[[ "$package_postcommit_status" -ne 0 ]]
grep -Fqx "$package_fake_image_id" \
    "$package_postcommit_state"
grep -Fqx "image_id=$package_fake_image_id" \
    "$package_postcommit_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-image.manifest.txt"
[[ -z "$(find "$package_postcommit_dist" "$package_postcommit_input" \
    -name '*.previous.*' ! -name '*.borondns-remove.*' -print -quit)" ]]

# A failed publisher must finish tag rollback while retaining the canonical
# image-reference lock. Otherwise it can restore stale state over a later
# successful publisher for another target/output root.
package_tag_race_state="$workdir/package-tag-race.state"
package_tag_race_ready="$workdir/package-tag-race.ready"
package_tag_race_release="$workdir/package-tag-race.release"
package_tag_race_lock="$workdir/package-tag-race-lock"
package_tag_race_dist_a="$workdir/package-tag-race-dist-a"
package_tag_race_dist_b="$workdir/package-tag-race-dist-b"
package_tag_race_input_a="$workdir/package-tag-race-input-a"
package_tag_race_input_b="$workdir/package-tag-race-input-b"
package_tag_race_image_b="$package_fake_second_image_id"
printf '%s\n' 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    >"$package_tag_race_state"
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_PACKAGE_TARGET=target-a BORONDNS_DIST_DIR="$package_tag_race_dist_a" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_tag_race_input_a" \
    BORONDNS_DOCKER_IMAGE_REF=shared/borondns:0.9.0 \
    BORONDNS_PACKAGE_DOCKER_LOCK_ROOT="$package_tag_race_lock" \
    PACKAGE_DOCKER_TAG_STATE="$package_tag_race_state" \
    PACKAGE_DOCKER_TAG_READY="$package_tag_race_ready" PACKAGE_DOCKER_TAG_RELEASE="$package_tag_race_release" \
    PACKAGE_DOCKER_FAIL_AFTER_TAG=1 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-tag-race-a.log" 2>&1 &
package_tag_race_pid_a=$!
for _ in {1..1000}; do
    [[ -e "$package_tag_race_ready" ]] && break
    sleep 0.01
done
[[ -e "$package_tag_race_ready" ]]
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_PACKAGE_TARGET=target-b BORONDNS_DIST_DIR="$package_tag_race_dist_b" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_tag_race_input_b" \
    BORONDNS_DOCKER_IMAGE_REF=docker.io/shared/borondns:0.9.0 \
    BORONDNS_PACKAGE_DOCKER_LOCK_ROOT="$package_tag_race_lock" \
    PACKAGE_DOCKER_IMAGE_ID="$package_tag_race_image_b" PACKAGE_DOCKER_CONFIG_VARIANT=second \
    PACKAGE_DOCKER_TAG_STATE="$package_tag_race_state" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-tag-race-b.log" 2>&1 &
package_tag_race_pid_b=$!
sleep 0.1
grep -Fqx "$package_fake_image_id" \
    "$package_tag_race_state"
: >"$package_tag_race_release"
set +e
wait "$package_tag_race_pid_a"
package_tag_race_status_a=$?
set -e
[[ "$package_tag_race_status_a" -ne 0 ]]
wait "$package_tag_race_pid_b"
grep -Fqx "$package_tag_race_image_b" "$package_tag_race_state"
grep -Fqx "image_id=$package_tag_race_image_b" \
    "$package_tag_race_dist_b/borondns-0.9.0-target-b-docker-image.manifest.txt"

package_mutated_installer_dist="$workdir/package-mutated-installer-dist"
package_mutated_installer_target="$workdir/package-mutated-installer-target"
mkdir -p "$package_mutated_installer_dist/borondns-0.9.0-x86_64-unknown-linux-musl"
printf 'prior installer tree\n' >"$package_mutated_installer_dist/borondns-0.9.0-x86_64-unknown-linux-musl/prior-sentinel"
printf 'prior installer archive\n' >"$package_mutated_installer_dist/borondns-0.9.0-x86_64-unknown-linux-musl.tar.xz"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_mutated_installer_target" BORONDNS_DIST_DIR="$package_mutated_installer_dist" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-mutated-installer.log" 2>&1; then
    printf 'installer package builder accepted source mutation during build\n' >&2
    exit 1
fi
grep -Fq 'installer packaging source changed at after build' "$workdir/package-mutated-installer.log"
grep -Fqx 'prior installer tree' \
    "$package_mutated_installer_dist/borondns-0.9.0-x86_64-unknown-linux-musl/prior-sentinel"
grep -Fqx 'prior installer archive' \
    "$package_mutated_installer_dist/borondns-0.9.0-x86_64-unknown-linux-musl.tar.xz"
rm "$package_dirty_repo/transient-build-mutation"

package_mutated_docker_dist="$workdir/package-mutated-docker-dist"
package_mutated_docker_input="$workdir/package-mutated-docker-input"
mkdir -p "$package_mutated_docker_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-context"
printf 'prior Docker context\n' \
    >"$package_mutated_docker_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-context/prior-sentinel"
printf 'prior Docker archive\n' \
    >"$package_mutated_docker_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-image.tar.xz"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_mutated_docker_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_mutated_docker_input" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-mutated-docker.log" 2>&1; then
    printf 'Docker package builder accepted source mutation during build\n' >&2
    exit 1
fi
grep -Fq 'Docker packaging source changed at terminal publication' "$workdir/package-mutated-docker.log"
grep -Fqx 'prior Docker context' \
    "$package_mutated_docker_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-context/prior-sentinel"
grep -Fqx 'prior Docker archive' \
    "$package_mutated_docker_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-image.tar.xz"
[[ -z "$(find "$package_mutated_docker_input" \
    \( -path '*/.borondns-package-locks' -o -name '*.borondns-remove.*' \) -prune -o \
    -type f -print -quit)" ]]
rm "$package_dirty_repo/transient-docker-mutation"
package_recursive_sentinel="$workdir/package-recursive-sentinel"
mkdir "$package_recursive_sentinel"
printf 'preserve recursive sentinel\n' >"$package_recursive_sentinel/sentinel"
rm -rf "$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl"
ln -s "$package_recursive_sentinel" \
    "$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_clean_dist" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-staging-symlink.log" 2>&1; then
    printf 'package installer accepted a staging symlink outside canonical dist\n' >&2
    exit 1
fi
grep -Fqx 'preserve recursive sentinel' "$package_recursive_sentinel/sentinel"
rm "$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl"
rm -rf "$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-context"
ln -s "$package_recursive_sentinel" \
    "$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-context"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    CARGO_TARGET_DIR="$package_clean_target" BORONDNS_DIST_DIR="$package_clean_dist" \
    BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_clean_docker_input" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-context-symlink.log" 2>&1; then
    printf 'Docker package builder accepted a context symlink outside canonical dist\n' >&2
    exit 1
fi
grep -Fqx 'preserve recursive sentinel' "$package_recursive_sentinel/sentinel"
rm "$package_clean_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-context"
printf 'untracked packaging input\n' >"$package_dirty_repo/untracked-fixture"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-dirty-installer.log" 2>&1; then
    printf 'package installer accepted dirty source by default\n' >&2
    exit 1
fi
grep -Fq 'refusing installer packaging from dirty or untracked source' "$workdir/package-dirty-installer.log"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-docker-image.sh" >"$workdir/package-dirty-docker.log" 2>&1; then
    printf 'Docker package builder accepted dirty source by default\n' >&2
    exit 1
fi
grep -Fq 'refusing Docker packaging from dirty or untracked source' "$workdir/package-dirty-docker.log"
if GITHUB_ACTIONS=true BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 \
    "$package_dirty_repo/scripts/package-installer.sh" >"$workdir/package-dirty-actions.log" 2>&1; then
    printf 'package installer accepted dirty-source override in GitHub Actions\n' >&2
    exit 1
fi
grep -Fq 'dirty-source packaging override is forbidden in GitHub Actions release paths' \
    "$workdir/package-dirty-actions.log"
if GITHUB_ACTIONS=true BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-dirty-sbom-actions.log" 2>&1; then
    printf 'SBOM builder accepted dirty-source override in GitHub Actions\n' >&2
    exit 1
fi
grep -Fq 'dirty-source SBOM override is forbidden in GitHub Actions release paths' \
    "$workdir/package-dirty-sbom-actions.log"

package_transient_dist="$workdir/package-transient-dist"
rm "$package_dirty_repo/untracked-fixture"
package_sbom_prefix=borondns-0.9.0-x86_64-unknown-linux-musl
mkdir -p "$package_transient_dist"
cp "$package_clean_dist/$package_sbom_prefix-sbom-manifest.tsv" \
    "$package_clean_dist/$package_sbom_prefix-borondns.cdx.json" \
    "$package_clean_dist/$package_sbom_prefix-borondns.cdx.json.sha256" \
    "$package_clean_dist/$package_sbom_prefix-boron-gun.cdx.json" \
    "$package_clean_dist/$package_sbom_prefix-boron-gun.cdx.json.sha256" \
    "$package_clean_dist/$package_sbom_prefix-docker-image.cdx.json" \
    "$package_clean_dist/$package_sbom_prefix-docker-image.cdx.json.sha256" \
    "$package_clean_dist/$package_sbom_prefix-docker-image.manifest.txt" \
    "$package_transient_dist/"
package_sbom_snapshot() {
    local root="$1"
    (
        cd "$root"
        for artifact in \
            "$package_sbom_prefix-sbom-manifest.tsv" \
            "$package_sbom_prefix-borondns.cdx.json" \
            "$package_sbom_prefix-borondns.cdx.json.sha256" \
            "$package_sbom_prefix-boron-gun.cdx.json" \
            "$package_sbom_prefix-boron-gun.cdx.json.sha256" \
            "$package_sbom_prefix-docker-image.cdx.json" \
            "$package_sbom_prefix-docker-image.cdx.json.sha256"; do
            sha256sum "$artifact"
        done
    )
}
package_transient_sbom_before="$(package_sbom_snapshot "$package_transient_dist")"
if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_transient_dist" BORONDNS_SBOM_DOCKER=0 \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-transient-sbom.log" 2>&1; then
    printf 'SBOM builder accepted source mutation during generation\n' >&2
    exit 1
fi
grep -Fq 'SBOM source changed at terminal publication' "$workdir/package-transient-sbom.log"
[[ "$(package_sbom_snapshot "$package_transient_dist")" == "$package_transient_sbom_before" ]]
rm "$package_dirty_repo/transient-mutation"

if PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_transient_dist" BORONDNS_SBOM_DOCKER=1 PACKAGE_SYFT_FAIL=1 \
    PACKAGE_SYFT_LOG="$package_syft_log" PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-late-sbom.log" 2>&1; then
    printf 'SBOM builder accepted a forced late Docker scan failure\n' >&2
    exit 1
fi
[[ "$(package_sbom_snapshot "$package_transient_dist")" == "$package_transient_sbom_before" ]]

package_concurrent_sbom_dist="$workdir/package-concurrent-sbom-dist"
package_concurrent_sbom_pids=()
for package_concurrent_index in 1 2; do
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        BORONDNS_DIST_DIR="$package_concurrent_sbom_dist" BORONDNS_SBOM_DOCKER=0 \
        PACKAGE_CYCLONEDX_DELAY=0.2 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
        EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-sbom.sh" \
        >"$workdir/package-concurrent-sbom-$package_concurrent_index.log" 2>&1 &
    package_concurrent_sbom_pids+=("$!")
done
for package_concurrent_sbom_pid in "${package_concurrent_sbom_pids[@]}"; do
    wait "$package_concurrent_sbom_pid"
done
(
    cd "$package_concurrent_sbom_dist"
    sha256sum -c "$package_sbom_prefix-borondns.cdx.json.sha256"
    sha256sum -c "$package_sbom_prefix-boron-gun.cdx.json.sha256"
)
grep -Fq $'borondns\tCycloneDX 1.5 JSON' \
    "$package_concurrent_sbom_dist/$package_sbom_prefix-sbom-manifest.tsv"

# Different targets have different publication locks but cargo-cyclonedx writes
# fixed files inside the shared workspace. Its generation/cleanup region must
# therefore be serialized independently of the target artifact identity.
package_cross_target_sbom_dist="$workdir/package-cross-target-sbom-dist"
package_cyclonedx_active="$workdir/package-cyclonedx-active"
package_cyclonedx_overlap="$workdir/package-cyclonedx-overlap"
package_cyclonedx_lock_root="$workdir/package-cyclonedx-lock-root"
package_cross_target_sbom_pids=()
for package_cross_target in target-a target-b; do
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        BORONDNS_PACKAGE_TARGET="$package_cross_target" \
        BORONDNS_DIST_DIR="$package_cross_target_sbom_dist" BORONDNS_SBOM_DOCKER=0 \
        BORONDNS_CYCLONEDX_LOCK_ROOT="$package_cyclonedx_lock_root" \
        PACKAGE_CYCLONEDX_ACTIVE_DIR="$package_cyclonedx_active" \
        PACKAGE_CYCLONEDX_OVERLAP="$package_cyclonedx_overlap" PACKAGE_CYCLONEDX_DELAY=0.2 \
        PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-sbom.sh" \
        >"$workdir/package-cross-target-sbom-$package_cross_target.log" 2>&1 &
    package_cross_target_sbom_pids+=("$!")
done

for package_cross_target_sbom_pid in "${package_cross_target_sbom_pids[@]}"; do
    wait "$package_cross_target_sbom_pid"
done
[[ ! -e "$package_cyclonedx_overlap" && ! -e "$package_cyclonedx_active" ]]
for package_cross_target in target-a target-b; do
    [[ -f "$package_cross_target_sbom_dist/borondns-0.9.0-$package_cross_target-sbom-manifest.tsv" ]]
    (
        cd "$package_cross_target_sbom_dist"
        sha256sum -c "borondns-0.9.0-$package_cross_target-borondns.cdx.json.sha256"
        sha256sum -c "borondns-0.9.0-$package_cross_target-boron-gun.cdx.json.sha256"
    )
done

# Package names affect artifact basenames but not cargo-cyclonedx's fixed
# workspace outputs. Distinct names must therefore share the same generation
# lock just like distinct targets.
package_cross_name_cyclonedx_active="$workdir/package-cross-name-cyclonedx-active"
package_cross_name_cyclonedx_overlap="$workdir/package-cross-name-cyclonedx-overlap"
package_cross_name_cyclonedx_lock="$workdir/package-cross-name-cyclonedx-lock"
package_cross_name_sbom_pids=()
for package_cross_name in alpha beta; do
    PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        BORONDNS_PACKAGE_NAME="$package_cross_name" \
        BORONDNS_DIST_DIR="$workdir/package-cross-name-$package_cross_name" BORONDNS_SBOM_DOCKER=0 \
        BORONDNS_CYCLONEDX_LOCK_ROOT="$package_cross_name_cyclonedx_lock" \
        PACKAGE_CYCLONEDX_ACTIVE_DIR="$package_cross_name_cyclonedx_active" \
        PACKAGE_CYCLONEDX_OVERLAP="$package_cross_name_cyclonedx_overlap" PACKAGE_CYCLONEDX_DELAY=0.2 \
        PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-sbom.sh" \
        >"$workdir/package-cross-name-$package_cross_name.log" 2>&1 &
    package_cross_name_sbom_pids+=("$!")
done
for package_cross_name_sbom_pid in "${package_cross_name_sbom_pids[@]}"; do
    wait "$package_cross_name_sbom_pid"
done
[[ ! -e "$package_cross_name_cyclonedx_overlap" && ! -e "$package_cross_name_cyclonedx_active" ]]
for package_cross_name in alpha beta; do
    package_cross_name_prefix="$package_cross_name-0.9.0-x86_64-unknown-linux-musl"
    package_cross_name_dist="$workdir/package-cross-name-$package_cross_name"
    [[ -f "$package_cross_name_dist/$package_cross_name_prefix-sbom-manifest.tsv" ]]
    (
        cd "$package_cross_name_dist"
        sha256sum -c "$package_cross_name_prefix-borondns.cdx.json.sha256"
        sha256sum -c "$package_cross_name_prefix-boron-gun.cdx.json.sha256"
    )
done

# A caller may deliberately colocate the cargo-cyclonedx lock root with dist.
# The shared root descriptor must remain locked through terminal publication;
# unlocking it after generated-file cleanup would leave the cached SBOM
# publication authority falsely marked as held.
package_same_root_sbom_dist="$workdir/package-same-root-sbom-dist"
package_same_root_version_marker="$workdir/package-same-root-version-marker"
package_same_root_second_started="$workdir/package-same-root-second-started"
mkdir -m 0700 "$package_same_root_sbom_dist"
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_same_root_sbom_dist" BORONDNS_SBOM_DOCKER=0 \
    BORONDNS_CYCLONEDX_LOCK_ROOT="$package_same_root_sbom_dist" \
    PACKAGE_CYCLONEDX_VERSION_MARKER="$package_same_root_version_marker" \
    PACKAGE_CYCLONEDX_VERSION_DELAY=0.5 PACKAGE_CARGO_LOG="$package_clean_cargo_log" \
    EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-same-root-first.log" 2>&1 &
package_same_root_first_pid=$!
for _ in {1..200}; do
    [[ ! -e "$package_same_root_version_marker" ]] || break
    sleep 0.01
done
[[ -e "$package_same_root_version_marker" ]]
PATH="$package_fake_bin:$PATH" CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
    BORONDNS_DIST_DIR="$package_same_root_sbom_dist" BORONDNS_SBOM_DOCKER=0 \
    BORONDNS_CYCLONEDX_LOCK_ROOT="$package_same_root_sbom_dist" \
    PACKAGE_CYCLONEDX_STARTED_MARKER="$package_same_root_second_started" \
    PACKAGE_CARGO_LOG="$package_clean_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
    EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
    "$package_dirty_repo/scripts/package-sbom.sh" >"$workdir/package-same-root-second.log" 2>&1 &
package_same_root_second_pid=$!
sleep 0.1
[[ ! -e "$package_same_root_second_started" ]] || {
    printf 'SBOM same-root publisher entered after cached root authority was unlocked\n' >&2
    exit 1
}
wait "$package_same_root_first_pid"
wait "$package_same_root_second_pid"
[[ -e "$package_same_root_second_started" ]]
(
    cd "$package_same_root_sbom_dist"
    sha256sum -c "$package_sbom_prefix-borondns.cdx.json.sha256"
    sha256sum -c "$package_sbom_prefix-boron-gun.cdx.json.sha256"
)
[[ -z "$(find "$package_same_root_sbom_dist" -maxdepth 1 \
    \( -name '*.previous.*' -o -name '*.sbom-package.*' \) \
    ! -name '*.borondns-remove.*' -print -quit)" ]]

package_nogit_repo="$workdir/package-nogit-repo"
cp -a "$package_dirty_repo" "$package_nogit_repo"
rm -rf "$package_nogit_repo/.git"
if BORONDNS_DIST_DIR="$workdir/package-nogit-dist" "$package_nogit_repo/scripts/package-sbom.sh" \
    >"$workdir/package-nogit-sbom.log" 2>&1; then
    printf 'SBOM builder accepted a non-Git source tree\n' >&2
    exit 1
fi
grep -Fq 'SBOM packaging requires a Git-bound source checkout' "$workdir/package-nogit-sbom.log"
[[ ! -e "$workdir/package-nogit-dist" ]]

package_path_sentinel="$workdir/package-path-sentinel"
printf 'preserve\n' >"$package_path_sentinel"
for package_script in package-installer.sh package-docker-image.sh package-sbom.sh; do
    if BORONDNS_PACKAGE_NAME='../package-path-sentinel' \
        "$package_dirty_repo/scripts/$package_script" >"$workdir/$package_script-path.log" 2>&1; then
        printf '%s accepted a traversing package name\n' "$package_script" >&2
        exit 1
    fi
    grep -Fq 'BORONDNS_PACKAGE_NAME must be a canonical safe basename component' \
        "$workdir/$package_script-path.log"
    grep -Fqx preserve "$package_path_sentinel"
    if BORONDNS_PACKAGE_TARGET='../package-path-sentinel' \
        "$package_dirty_repo/scripts/$package_script" >"$workdir/$package_script-target-path.log" 2>&1; then
        printf '%s accepted a traversing package target\n' "$package_script" >&2
        exit 1
    fi
    grep -Fq 'BORONDNS_PACKAGE_TARGET must be a canonical safe basename component' \
        "$workdir/$package_script-target-path.log"
    grep -Fqx preserve "$package_path_sentinel"
done
printf 'untracked packaging input\n' >"$package_dirty_repo/untracked-fixture"
printf 'preserved clean installer\n' \
    >"$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl.tar.xz"
printf 'preserved clean Docker archive\n' \
    >"$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-image.tar.xz"
(
    cd "$foreign_workspace"
    PATH="$package_fake_bin:$PATH" \
        CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_fake_target" BORONDNS_DIST_DIR="$package_fake_dist" \
        BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 PACKAGE_CARGO_LOG="$package_cargo_log" \
        BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 \
        EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-installer.sh"
    set +e
    PATH="$package_fake_bin:$PATH" \
        CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        BORONDNS_DIST_DIR="$package_fake_dist" BORONDNS_SBOM_DOCKER=0 \
        BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 \
        PACKAGE_CARGO_LOG="$package_cargo_log" EXPECTED_PACKAGE_ROOT="$package_dirty_repo" \
        EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" "$package_dirty_repo/scripts/package-sbom.sh"
    sbom_status=$?
    set -e
    [[ "$sbom_status" == 2 ]]
    [[ -f "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty-sbom-manifest.tsv" ]]
    printf '%s\n' '#!/usr/bin/env bash' 'printf "stale substituted binary\n"' \
        >"$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl.bin"
    chmod +x "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl.bin"
    PATH="$package_fake_bin:$PATH" \
        CARGO="$package_fake_bin/cargo" RUSTC="$package_fake_bin/rustc" \
        CARGO_TARGET_DIR="$package_fake_target" BORONDNS_DIST_DIR="$package_fake_dist" \
        BORONDNS_DOCKER_INSTALLER_DIST_DIR="$package_docker_input" \
        BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 PACKAGE_CARGO_LOG="$package_cargo_log" \
        BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 \
        EXPECTED_PACKAGE_ROOT="$package_dirty_repo" EXPECTED_PACKAGE_MANIFEST="$package_dirty_repo/Cargo.toml" \
        "$package_dirty_repo/scripts/package-docker-image.sh"
)
[[ -f "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty.tar.xz" ]]
[[ -f "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty-borondns.cdx.json" ]]
[[ -f "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty-docker-image.tar.xz" ]]
grep -Fqx 'preserved clean installer' \
    "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl.tar.xz"
grep -Fqx 'preserved clean Docker archive' \
    "$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-docker-image.tar.xz"
[[ "$("$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl.bin")" == "stale substituted binary" ]]
[[ "$("$package_docker_input/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty.bin")" == "borondns fake" ]]
[[ "$("$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty-docker-context/borondns")" == "borondns fake" ]]
package_docker_manifest="$package_docker_input/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty/manifest.txt"
package_docker_binary_sha256="$(sha256sum "$package_docker_input/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty.bin" | awk '{ print $1 }')"
grep -Fqx "commit=$(git -C "$package_dirty_repo" rev-parse --short=12 HEAD)" "$package_docker_manifest"
grep -Fqx 'source_clean=0' "$package_docker_manifest"
grep -Fqx 'release_eligible=0' "$package_docker_manifest"
grep -Fqx 'dirty_source_override=1' "$package_docker_manifest"
grep -Fqx "binary_sha256=$package_docker_binary_sha256" "$package_docker_manifest"
package_image_manifest="$package_fake_dist/borondns-0.9.0-x86_64-unknown-linux-musl-nonrelease-dirty-docker-image.manifest.txt"
grep -Fqx 'source_clean=0' "$package_image_manifest"
grep -Fqx 'release_eligible=0' "$package_image_manifest"
grep -Fqx 'dirty_source_override=1' "$package_image_manifest"
grep -Fqx 'image_ref=borondns:0.9.0-nonrelease-dirty' "$package_image_manifest"
[[ -z "$(find "$package_fake_dist" -maxdepth 1 -name 'borondns-9.9.9-*' -print -quit)" ]]
if grep -F 'metadata' "$package_cargo_log" | grep -Fv -- "--manifest-path $package_dirty_repo/Cargo.toml"; then
    printf 'packaging metadata escaped to the foreign caller workspace\n' >&2
    exit 1
fi

repro_fixture_repo="$workdir/repro-dirty-repo"
repro_fixture_bin="$workdir/repro-fake-bin"
repro_fixture_evidence="$workdir/repro-dirty-evidence"
mkdir -p "$repro_fixture_repo/scripts" "$repro_fixture_bin"
cp "$repo_root/scripts/reproducible-build-compare.sh" \
    "$repo_root/scripts/package-common.sh" "$repro_fixture_repo/scripts/"
chmod +x "$repro_fixture_repo/scripts/reproducible-build-compare.sh" \
    "$repro_fixture_repo/scripts/package-common.sh"
printf '%s\n' '[workspace]' 'members = []' >"$repro_fixture_repo/Cargo.toml"
printf '%s\n' '# fake lock' >"$repro_fixture_repo/Cargo.lock"
git -C "$repro_fixture_repo" init -q
git -C "$repro_fixture_repo" add .
git -C "$repro_fixture_repo" -c user.name=BoronDNS -c user.email=tests@borondns.invalid \
    commit -qm 'reproducible fixture'
printf 'untracked source mutation\n' >"$repro_fixture_repo/untracked.txt"
if BORONDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR="$repro_fixture_evidence" \
    "$repro_fixture_repo/scripts/reproducible-build-compare.sh" >"$workdir/repro-dirty.log" 2>&1; then
    printf 'reproducible comparison accepted dirty source by default\n' >&2
    exit 1
fi
grep -Fq 'refusing reproducible-build comparison from dirty or untracked source' "$workdir/repro-dirty.log"
[[ ! -e "$repro_fixture_evidence" ]]

# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'case "${1:-}" in' \
    '--version) printf "cargo 1.96.1 (fixture)\n" ;;' \
    'metadata) printf "%s\n" "{\"packages\":[]}" ;;' \
    'build) target_dir=""; target=""; package=""; while (($#)); do case "$1" in --target-dir) target_dir="$2"; shift 2 ;; --target) target="$2"; shift 2 ;; -p) package="$2"; shift 2 ;; *) shift ;; esac; done; case "$package" in borondns-cli) binary=borondns ;; boron-gun) binary=boron-gun ;; *) exit 91 ;; esac; mkdir -p "$target_dir/$target/release"; printf "%s\n" "#!/usr/bin/env bash" "printf \"fixture $binary\\n\"" >"$target_dir/$target/release/$binary"; chmod +x "$target_dir/$target/release/$binary" ;;' \
    '*) exit 92 ;;' \
    'esac' >"$repro_fixture_bin/cargo"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' \
    'case "${1:-}" in --version) printf "rustc 1.96.1 (fixture)\n" ;; -vV) printf "rustc 1.96.1 (fixture)\nhost: x86_64-unknown-linux-gnu\n" ;; *) exit 93 ;; esac' \
    >"$repro_fixture_bin/rustc"
chmod +x "$repro_fixture_bin/cargo" "$repro_fixture_bin/rustc"
set +e
BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE=1 \
    BORONDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR="$repro_fixture_evidence" \
    BORONDNS_REPRODUCIBLE_BUILD_CARGO="$repro_fixture_bin/cargo" \
    BORONDNS_REPRODUCIBLE_BUILD_RUSTC="$repro_fixture_bin/rustc" \
    "$repro_fixture_repo/scripts/reproducible-build-compare.sh" >"$workdir/repro-dirty-override.log" 2>&1
repro_dirty_status=$?
set -e
[[ "$repro_dirty_status" == 2 ]]
grep -Fqx 'reproducible_build_status=false' "$repro_fixture_evidence/reproducible-build-summary.env"
grep -Fqx 'artifact_match=true' "$repro_fixture_evidence/reproducible-build-summary.env"
grep -Fqx 'release_eligible=false' "$repro_fixture_evidence/reproducible-build-summary.env"
grep -Fqx 'dirty_source_override=1' "$repro_fixture_evidence/reproducible-build-summary.env"
grep -Fq 'must not be used as release provenance' "$repro_fixture_evidence/README.md"

repro_stale_evidence="$workdir/repro-stale-evidence"
mkdir "$repro_stale_evidence"
printf 'reproducible_build_status=true\n' >"$repro_stale_evidence/reproducible-build-summary.env"
repro_stale_hash="$(sha256sum "$repro_stale_evidence/reproducible-build-summary.env" | awk '{ print $1 }')"
if BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE=1 \
    BORONDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR="$repro_stale_evidence" \
    BORONDNS_REPRODUCIBLE_BUILD_CARGO="$repro_fixture_bin/cargo" \
    BORONDNS_REPRODUCIBLE_BUILD_RUSTC="$repro_fixture_bin/rustc" \
    "$repro_fixture_repo/scripts/reproducible-build-compare.sh" >"$workdir/repro-stale.log" 2>&1; then
    printf 'reproducible comparison reused a stale evidence destination\n' >&2
    exit 1
fi
grep -Fq 'refusing to reuse an existing reproducible-build evidence destination' "$workdir/repro-stale.log"
[[ "$(sha256sum "$repro_stale_evidence/reproducible-build-summary.env" | awk '{ print $1 }')" == "$repro_stale_hash" ]]
[[ "$(find "$repro_stale_evidence" -mindepth 1 -maxdepth 1 -type f | wc -l)" == 1 ]]

format_repo="$workdir/format-repo"
mkdir -p "$format_repo"
git -C "$format_repo" init -q
printf '%s\n' '#!/usr/bin/env bash' 'if true;then' ' echo format-drift' 'fi' >"$format_repo/drift.sh"
git -C "$format_repo" add drift.sh
git -C "$format_repo" -c user.name=BoronDNS -c user.email=tests@borondns.invalid \
    commit -qm 'format drift fixture'
format_hash_before="$(sha256sum "$format_repo/drift.sh" | awk '{ print $1 }')"
format_status_before="$(git -C "$format_repo" status --short)"
if "$repo_root/scripts/check-shell-format.sh" "$format_repo/drift.sh" >"$workdir/format.diff"; then
    printf 'shell format gate accepted an unformatted script\n' >&2
    exit 1
fi
format_hash_after="$(sha256sum "$format_repo/drift.sh" | awk '{ print $1 }')"
format_status_after="$(git -C "$format_repo" status --short)"
[[ -s "$workdir/format.diff" ]]
[[ "$format_hash_before" == "$format_hash_after" ]]
[[ "$format_status_before" == "$format_status_after" ]]

[[ "$(grep -Fc 'if fields[0] in {"Z", "X"}:' "$repo_root/scripts/campaign-env.sh")" -ge 2 ]]
if grep -Fq 'create_soak_docker_wrapper' "$repo_root/scripts/large-surface-soak.sh"; then
    printf 'large-surface runner retained a writable-path Docker wrapper helper\n' >&2
    exit 1
fi
if grep -Fq 'docker_wrapper_dir=' "$repo_root/scripts/large-surface-soak-campaign.sh"; then
    printf 'large-surface campaign retained a writable Docker wrapper directory\n' >&2
    exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'campaign_prepare_private_temporary_tree "$plan_parent" borondns-fuzz-plan-staging' \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
# shellcheck disable=SC2016
grep -Fq 'campaign_prepare_private_temporary_tree "$plan_parent" borondns-large-plan-staging' \
    "$repo_root/scripts/large-surface-soak-campaign.sh"
# shellcheck disable=SC2016
grep -Fq 'post_active" == inactive && "$post_sub" == dead' \
    "$repo_root/scripts/fuzz-soak-two-host-campaign.sh"
# shellcheck disable=SC2016
grep -Fq 'post_active" == inactive && "$post_sub" == dead' \
    "$repo_root/scripts/large-surface-soak-campaign.sh"

bounded_load_harness="$repo_root/scripts/boron-gen-bounded-load.sh"
grep -Fq 'BORON_LOAD_IXFR_DELTA_RRSETS' "$bounded_load_harness"
grep -Fq 'BORON_LOAD_IXFR_CHURN_INTERVAL_MS' "$bounded_load_harness"
grep -Fq 'BORON_LOAD_IXFR_CHURN_START_DELAY_MS' "$bounded_load_harness"
grep -Fq 'BORON_LOAD_SOA_REFRESH_SECONDS' "$bounded_load_harness"
grep -Fq 'BORON_LOAD_ZSM_MIN_INTERVAL_SECONDS' "$bounded_load_harness"
grep -Fq 'BORON_LOAD_ZONE_PUBLICATION_STRATEGY' "$bounded_load_harness"
grep -Fq -- '--ixfr-max-generations "$ixfr_max_generations"' "$bounded_load_harness"
grep -Fq 'IXFR churn unexpectedly fell back to AXFR after readiness' "$bounded_load_harness"
grep -Fq 'BoronDNS did not complete a member IXFR before performance measurement' \
    "$bounded_load_harness"

printf 'operations harness regressions passed\n'
