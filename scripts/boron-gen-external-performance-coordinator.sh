#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
server_ssh="${BORON_COORD_SERVER_SSH:-}"
client_ssh="${BORON_COORD_CLIENT_SSH:-}"
remote_artifact_root="${BORON_COORD_REMOTE_ARTIFACT_ROOT:-}"
local_artifact_root="${BORON_COORD_LOCAL_ARTIFACT_ROOT:-$repo_root/target/evidence/boron-gen-external-performance-$timestamp}"
poll_seconds="${BORON_COORD_POLL_SECONDS:-5}"
timeout_seconds="${BORON_COORD_TIMEOUT_SECONDS:-604800}"
ssh_connect_timeout="${BORON_COORD_SSH_CONNECT_TIMEOUT_SECONDS:-5}"
max_drop_override="${BORON_COORD_MAX_DROP_PERMILLE_OVERRIDE:-}"
preflight_only="${BORON_COORD_PREFLIGHT_ONLY:-false}"
performance_runner="$repo_root/scripts/boron-gen-query-performance.sh"

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

for pair in \
    "BORON_COORD_POLL_SECONDS:$poll_seconds" \
    "BORON_COORD_TIMEOUT_SECONDS:$timeout_seconds" \
    "BORON_COORD_SSH_CONNECT_TIMEOUT_SECONDS:$ssh_connect_timeout"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
if [[ -n "$max_drop_override" ]] &&
    { ! [[ "$max_drop_override" =~ ^[0-9]+$ ]] ||
        ((max_drop_override > 1000)); }; then
    printf 'BORON_COORD_MAX_DROP_PERMILLE_OVERRIDE must be empty or an integer from 0 to 1000\n' >&2
    exit 64
fi
case "$preflight_only" in
true | false) ;;
*)
    echo "BORON_COORD_PREFLIGHT_ONLY must be true or false" >&2
    exit 64
    ;;
esac
for pair in \
    "BORON_COORD_SERVER_SSH:$server_ssh" \
    "BORON_COORD_CLIENT_SSH:$client_ssh"; do
    if [[ -z "${pair#*:}" || "${pair#*:}" =~ [[:space:]] ]]; then
        printf '%s must be non-empty and contain no whitespace\n' "${pair%%:*}" >&2
        exit 64
    fi
done
if [[ "$remote_artifact_root" != /* || "$remote_artifact_root" == "/" ||
    "$remote_artifact_root" =~ [[:space:]] ]]; then
    echo "BORON_COORD_REMOTE_ARTIFACT_ROOT must be an absolute non-root path without whitespace" >&2
    exit 64
fi
if [[ ! -x "$performance_runner" ]]; then
    printf 'missing executable performance runner: %s\n' "$performance_runner" >&2
    exit 69
fi
for tool in jq scp sha256sum ssh tar; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing coordinator tool: %s\n' "$tool" >&2
        exit 69
    fi
done

connection_options=(-o BatchMode=yes -o "ConnectTimeout=$ssh_connect_timeout")
# The request loop is fed through stdin. Every SSH process must detach from it,
# otherwise SSH consumes the remaining request paths while checking the first
# request in the sorted list.
ssh_options=(-n "${connection_options[@]}")
scp_options=("${connection_options[@]}")

remote_file_exists() {
    local path="$1"
    local status

    # shellcheck disable=SC2029
    if ssh "${ssh_options[@]}" "$server_ssh" \
        "test -f $(printf '%q' "$path")"; then
        return 0
    else
        status=$?
    fi
    if ((status == 1)); then
        return 1
    fi
    printf 'SSH transport failed while checking remote file %s (status %s)\n' \
        "$path" "$status" >&2
    return "$status"
}

ssh "${ssh_options[@]}" "$server_ssh" true
ssh "${ssh_options[@]}" "$client_ssh" true
server_host_id="$(
    ssh "${ssh_options[@]}" "$server_ssh" \
        'if [ -r /proc/sys/kernel/random/boot_id ]; then cat /proc/sys/kernel/random/boot_id; else hostname; fi' |
        tr -d '\r'
)"
client_host_id="$(
    ssh "${ssh_options[@]}" "$client_ssh" \
        'if [ -r /proc/sys/kernel/random/boot_id ]; then cat /proc/sys/kernel/random/boot_id; else hostname; fi' |
        tr -d '\r'
)"
if [[ "$server_host_id" == "$client_host_id" ]]; then
    echo "coordinator server and client targets resolve to the same host" >&2
    exit 64
fi
# shellcheck disable=SC2029
if ! ssh "${ssh_options[@]}" "$server_ssh" \
    "test -d $(printf '%q' "$remote_artifact_root") && test ! -L $(printf '%q' "$remote_artifact_root")"; then
    printf 'remote campaign artifact root is absent or a symlink: %s\n' \
        "$remote_artifact_root" >&2
    exit 69
fi

if [[ "$preflight_only" == "true" ]]; then
    printf 'boron_gen_external_coordinator_preflight=passed\n'
    printf 'server_ssh=%s\n' "$server_ssh"
    printf 'client_ssh=%s\n' "$client_ssh"
    printf 'remote_artifact_root=%s\n' "$remote_artifact_root"
    exit 0
fi

mkdir -p "$local_artifact_root"
chmod 700 "$local_artifact_root"
cat >"$local_artifact_root/coordinator.env" <<EOF
started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
server_ssh=$server_ssh
client_ssh=$client_ssh
remote_artifact_root=$remote_artifact_root
poll_seconds=$poll_seconds
timeout_seconds=$timeout_seconds
max_drop_permille_override=${max_drop_override:-none}
EOF

process_request() {
    local request_path="$1"
    local relative_path request_relative evidence_relative remote_evidence
    local local_attempt request_file performance_dir archive archive_sha
    local stale_marker failed_marker policy_file remote_status
    local server_address server_port server_device client_bind client_device
    local profile origin zones names warmup duration repetitions threads window
    local sockets client_timeout client_cpu_list requested_max_drop max_drop metrics_url

    relative_path="${request_path#"$remote_artifact_root"/}"
    if [[ "$relative_path" == "$request_path" ||
        ! "$relative_path" =~ ^runs/[A-Za-z0-9._-]+/attempt-[0-9]+/evidence/performance-request[.]json$ ]]; then
        printf 'refusing unexpected performance request path: %s\n' "$request_path" >&2
        return 1
    fi
    request_relative="${relative_path%/performance-request.json}"
    evidence_relative="$request_relative"
    remote_evidence="$remote_artifact_root/$evidence_relative"
    local_attempt="$local_artifact_root/$request_relative"
    stale_marker="$local_attempt/stale-request.txt"
    failed_marker="$local_attempt/failed-request.txt"
    if [[ -f "$stale_marker" || -f "$failed_marker" ]]; then
        return 0
    fi
    if remote_file_exists "$remote_evidence/performance-complete"; then
        return 0
    else
        remote_status=$?
        ((remote_status == 1)) || return "$remote_status"
    fi
    # A summary without a completion marker means the bounded server for this
    # request is already gone. Replaying it could benchmark a later scenario
    # that reused the same address and port.
    if remote_file_exists "$remote_evidence/run-summary.json"; then
        mkdir -p "$local_attempt"
        if [[ ! -e "$stale_marker" ]]; then
            printf 'skipped_utc=%s\nreason=run summary exists without performance completion\nremote_request=%s\n' \
                "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$request_path" >"$stale_marker"
            printf 'skipping stale performance request whose server run has ended: %s\n' \
                "$request_path" >&2
        fi
        return 0
    else
        remote_status=$?
        ((remote_status == 1)) || return "$remote_status"
    fi
    mkdir -p "$local_attempt"
    request_file="$local_attempt/performance-request.json"
    scp -q "${scp_options[@]}" "$server_ssh:$request_path" "$request_file"
    jq -e '.format == "boron-gen-external-performance-request-v1"' \
        "$request_file" >/dev/null

    profile="$(jq -er '.profile' "$request_file")"
    origin="$(jq -er '.origin' "$request_file")"
    zones="$(jq -er '.zones' "$request_file")"
    names="$(jq -er '.names_per_zone' "$request_file")"
    server_address="$(jq -er '.server_address' "$request_file")"
    server_port="$(jq -er '.server_port' "$request_file")"
    server_device="$(jq -er '.server_device' "$request_file")"
    client_bind="$(jq -er '.client_bind' "$request_file")"
    client_device="$(jq -er '.client_device' "$request_file")"
    warmup="$(jq -er '.warmup_seconds' "$request_file")"
    duration="$(jq -er '.duration_seconds' "$request_file")"
    repetitions="$(jq -er '.repetitions' "$request_file")"
    threads="$(jq -er '.client_threads' "$request_file")"
    window="$(jq -er '.client_window' "$request_file")"
    sockets="$(jq -er '.client_sockets_per_thread' "$request_file")"
    client_timeout="$(jq -er '.client_timeout_ms' "$request_file")"
    client_cpu_list="$(jq -r '.client_cpu_list // ""' "$request_file")"
    requested_max_drop="$(jq -er '.max_drop_permille' "$request_file")"
    max_drop="${max_drop_override:-$requested_max_drop}"
    metrics_url="$(jq -er '.metrics_url' "$request_file")"
    performance_dir="$local_attempt/performance"
    if [[ -e "$performance_dir" ]]; then
        printf 'local performance evidence path already exists: %s\n' \
            "$performance_dir" >&2
        return 1
    fi

    BORON_GEN_PERF_ARTIFACT_DIR="$performance_dir" \
        BORON_GEN_PERF_PROFILE="$profile" \
        BORON_GEN_PERF_ORIGIN="$origin" \
        BORON_GEN_PERF_ZONES="$zones" \
        BORON_GEN_PERF_NAMES_PER_ZONE="$names" \
        BORON_GEN_PERF_SERVER_ADDRESS="$server_address" \
        BORON_GEN_PERF_SERVER_PORT="$server_port" \
        BORON_GEN_PERF_SERVER_DEVICE="$server_device" \
        BORON_GEN_PERF_SERVER_SSH="$server_ssh" \
        BORON_GEN_PERF_MODE=ssh \
        BORON_GEN_PERF_CLIENT_BIND="$client_bind" \
        BORON_GEN_PERF_CLIENT_DEVICE="$client_device" \
        BORON_GEN_PERF_REMOTE_SSH="$client_ssh" \
        BORON_GEN_PERF_WARMUP_SECONDS="$warmup" \
        BORON_GEN_PERF_DURATION_SECONDS="$duration" \
        BORON_GEN_PERF_REPETITIONS="$repetitions" \
        BORON_GEN_PERF_CLIENT_THREADS="$threads" \
        BORON_GEN_PERF_CLIENT_WINDOW="$window" \
        BORON_GEN_PERF_CLIENT_SOCKETS_PER_THREAD="$sockets" \
        BORON_GEN_PERF_CLIENT_TIMEOUT_MS="$client_timeout" \
        BORON_GEN_PERF_CLIENT_CPU_LIST="$client_cpu_list" \
        BORON_GEN_PERF_MAX_DROP_PERMILLE="$max_drop" \
        BORON_GEN_PERF_METRICS_URL="$metrics_url" \
        "$performance_runner"

    policy_file="$performance_dir/coordinator-policy.env"
    printf 'requested_max_drop_permille=%s\neffective_max_drop_permille=%s\noverride_source=%s\n' \
        "$requested_max_drop" "$max_drop" \
        "$([[ -n "$max_drop_override" ]] && printf BORON_COORD_MAX_DROP_PERMILLE_OVERRIDE || printf request)" \
        >"$policy_file"
    (
        cd "$performance_dir"
        sha256sum coordinator-policy.env >>evidence.sha256
    )
    archive="$local_attempt/performance-evidence.tar"
    tar -C "$performance_dir" -cf "$archive" .
    archive_sha="$(sha256sum "$archive" | awk '{ print $1 }')"
    # Refuse partial or pre-existing destinations. The archive is extracted
    # only after its digest is checked on the server host.
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$server_ssh" \
        "test -d $(printf '%q' "$remote_evidence") && test ! -L $(printf '%q' "$remote_evidence") && test ! -e $(printf '%q' "$remote_evidence/performance") && test ! -e $(printf '%q' "$remote_evidence/performance-evidence.tar")"
    scp -q "${scp_options[@]}" "$archive" \
        "$server_ssh:$remote_evidence/performance-evidence.tar"
    # shellcheck disable=SC2029
    ssh "${ssh_options[@]}" "$server_ssh" \
        "test \"\$(sha256sum $(printf '%q' "$remote_evidence/performance-evidence.tar") | awk '{print \$1}')\" = $(printf '%q' "$archive_sha") && mkdir -m 700 -- $(printf '%q' "$remote_evidence/performance") && tar --warning=no-timestamp -xf $(printf '%q' "$remote_evidence/performance-evidence.tar") -C $(printf '%q' "$remote_evidence/performance") && cd $(printf '%q' "$remote_evidence/performance") && sha256sum -c evidence.sha256 && rm -f -- $(printf '%q' "$remote_evidence/performance-evidence.tar") && sha256sum performance-summary.json > $(printf '%q' "$remote_evidence/performance-complete")"
    printf '%s\t%s\t%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$request_relative" "$archive_sha" \
        >>"$local_artifact_root/completed-requests.tsv"
}

record_request_failure() {
    local request_path="$1"
    local exit_status="$2"
    local relative_path request_relative local_attempt failed_marker failed_utc

    relative_path="${request_path#"$remote_artifact_root"/}"
    if [[ "$relative_path" == "$request_path" ||
        ! "$relative_path" =~ ^runs/[A-Za-z0-9._-]+/attempt-[0-9]+/evidence/performance-request[.]json$ ]]; then
        printf 'cannot record failure for unexpected request path: %s\n' \
            "$request_path" >&2
        return 1
    fi
    request_relative="${relative_path%/performance-request.json}"
    local_attempt="$local_artifact_root/$request_relative"
    failed_marker="$local_attempt/failed-request.txt"
    mkdir -p "$local_attempt"
    if [[ -e "$failed_marker" ]]; then
        return 0
    fi
    failed_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'failed_utc=%s\nexit_status=%s\nremote_request=%s\n' \
        "$failed_utc" "$exit_status" "$request_path" >"$failed_marker"
    printf '%s\t%s\t%s\n' "$failed_utc" "$request_relative" "$exit_status" \
        >>"$local_artifact_root/failed-requests.tsv"
    printf 'performance request failed with status %s; retaining evidence and continuing coordination: %s\n' \
        "$exit_status" "$request_path" >&2
}

record_transport_failure() {
    local request_path="$1"
    local exit_status="$2"
    local relative_path request_relative local_attempt failed_utc suffix candidate

    relative_path="${request_path#"$remote_artifact_root"/}"
    if [[ "$relative_path" == "$request_path" ||
        ! "$relative_path" =~ ^runs/[A-Za-z0-9._-]+/attempt-[0-9]+/evidence/performance-request[.]json$ ]]; then
        printf 'cannot record transport failure for unexpected request path: %s\n' \
            "$request_path" >&2
        return 1
    fi
    request_relative="${relative_path%/performance-request.json}"
    local_attempt="$local_artifact_root/$request_relative"
    failed_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    suffix="$(date -u '+%Y%m%dT%H%M%SZ')"
    for candidate in performance performance-evidence.tar; do
        if [[ -e "$local_attempt/$candidate" ]]; then
            mv -- "$local_attempt/$candidate" \
                "$local_attempt/$candidate.transport-failed-$suffix"
        fi
    done
    printf '%s\t%s\t%s\n' "$failed_utc" "$request_relative" "$exit_status" \
        >>"$local_artifact_root/transport-failures.tsv"
    printf 'performance request transport failed with status %s; retained partial evidence and will retry: %s\n' \
        "$exit_status" "$request_path" >&2
}

deadline=$((SECONDS + timeout_seconds))
while true; do
    # shellcheck disable=SC2029
    if requests="$(
        ssh "${ssh_options[@]}" "$server_ssh" \
            "find $(printf '%q' "$remote_artifact_root/runs") -type f -name performance-request.json -print 2>/dev/null" |
            sort
    )"; then
        :
    else
        request_status=$?
        printf 'performance request enumeration failed with status %s; retrying after %ss\n' \
            "$request_status" "$poll_seconds" >&2
        sleep "$poll_seconds"
        continue
    fi
    while IFS= read -r request_path; do
        [[ -n "$request_path" ]] || continue
        # Run each request in its own errexit-enabled worker. A performance
        # acceptance failure belongs to that request and must not terminate
        # coordination for all later campaign rows.
        process_request "$request_path" &
        request_pid=$!
        if wait "$request_pid"; then
            :
        else
            request_status=$?
            if ((request_status == 255)); then
                record_transport_failure "$request_path" "$request_status"
            else
                record_request_failure "$request_path" "$request_status"
            fi
        fi
    done <<<"$requests"

    if remote_file_exists "$remote_artifact_root/completed-utc.txt"; then
        printf 'finished_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            >>"$local_artifact_root/coordinator.env"
        printf 'external performance coordination completed; evidence: %s\n' \
            "$local_artifact_root"
        exit 0
    else
        request_status=$?
        if ((request_status != 1)); then
            sleep "$poll_seconds"
            continue
        fi
    fi
    if ((SECONDS >= deadline)); then
        printf 'external performance coordinator timed out after %ss\n' \
            "$timeout_seconds" >&2
        exit 1
    fi
    sleep "$poll_seconds"
done
