#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/borondns-external-coordinator.XXXXXX")"
cleanup() {
    local status=$?
    trap - EXIT
    rm -rf -- "$workdir"
    exit "$status"
}
trap cleanup EXIT

fixture_repo="$workdir/repo"
fake_bin="$workdir/bin"
state="$workdir/state"
local_artifacts="$workdir/artifacts"
mkdir -p "$fixture_repo/scripts" "$fake_bin" "$state"
chmod 0700 "$workdir" "$fixture_repo" "$fixture_repo/scripts" "$fake_bin" "$state"
cp "$repo_root/scripts/boron-gen-external-performance-coordinator.sh" \
    "$fixture_repo/scripts/"

cat >"$state/performance-request.json" <<'JSON'
{
  "format": "boron-gen-external-performance-request-v1",
  "profile": "large-rrset",
  "origin": "coordinator.test.",
  "zones": 1,
  "names_per_zone": 1,
  "server_address": "192.0.2.1",
  "server_port": 15300,
  "server_device": "eth0",
  "client_bind": "192.0.2.2:0",
  "client_device": "eth0",
  "warmup_seconds": 1,
  "duration_seconds": 1,
  "repetitions": 1,
  "client_threads": 1,
  "client_window": 1,
  "client_sockets_per_thread": 1,
  "client_timeout_ms": 1000,
  "client_cpu_list": null,
  "max_drop_permille": 1000,
  "metrics_url": "http://192.0.2.1:9100/metrics"
}
JSON

cat >"$fake_bin/ssh" <<'FAKE_SSH'
#!/usr/bin/env bash
set -euo pipefail

has_stdin_null=false
while (($# > 0)); do
    case "$1" in
    -n)
        has_stdin_null=true
        shift
        ;;
    -o)
        shift 2
        ;;
    *)
        host="$1"
        shift
        break
        ;;
    esac
done
if [[ "$has_stdin_null" != true ]]; then
    cat >/dev/null
    echo "SSH invocation inherited coordinator stdin" >&2
    exit 97
fi
command_text="$*"
case "$command_text" in
true)
    exit 0
    ;;
*"random/boot_id"*)
    printf '%s-id\n' "$host"
    ;;
test\ -d*)
    exit 0
    ;;
find\ *performance-request.json*)
    if [[ "${TEST_COORD_FAIL_FIND_ONCE:-false}" == true &&
        ! -e "${TEST_COORD_STATE:?}/find-failed-once" ]]; then
        : >"${TEST_COORD_STATE:?}/find-failed-once"
        exit 255
    fi
    printf '%s\n' \
        /remote/evidence/runs/01-active/attempt-001/evidence/performance-request.json \
        /remote/evidence/runs/02-stale/attempt-001/evidence/performance-request.json \
        /remote/evidence/runs/03-active/attempt-001/evidence/performance-request.json \
        /remote/evidence/runs/04-failing/attempt-001/evidence/performance-request.json
    ;;
test\ -f*performance-complete)
    exit 1
    ;;
test\ -f*/02-stale/*/run-summary.json)
    exit 0
    ;;
test\ -f*run-summary.json)
    exit 1
    ;;
test\ -f*/completed-utc.txt)
    exit 0
    ;;
*)
    exit 0
    ;;
esac
FAKE_SSH

cat >"$fake_bin/scp" <<'FAKE_SCP'
#!/usr/bin/env bash
set -euo pipefail

while (($# > 0)); do
    case "$1" in
    -q)
        shift
        ;;
    -o)
        shift 2
        ;;
    *)
        break
        ;;
    esac
done
source_path="$1"
destination="$2"
if [[ "$source_path" == *:*/performance-request.json ]]; then
    if [[ "$source_path" == */04-failing/* ]]; then
        jq '.origin = "failure.test."' \
            "${TEST_COORD_STATE:?}/performance-request.json" >"$destination"
    else
        cp "${TEST_COORD_STATE:?}/performance-request.json" "$destination"
    fi
else
    printf '%s -> %s\n' "$source_path" "$destination" \
        >>"${TEST_COORD_STATE:?}/uploads.log"
fi
FAKE_SCP

cat >"$fixture_repo/scripts/boron-gen-query-performance.sh" <<'FAKE_RUNNER'
#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${BORON_GEN_PERF_ARTIFACT_DIR:?}"
mkdir -p "$artifact_dir"
printf '{}\n' >"$artifact_dir/performance-summary.json"
(
    cd "$artifact_dir"
    sha256sum performance-summary.json >evidence.sha256
)
printf '%s\n' "${BORON_GEN_PERF_ORIGIN:?}" >>"${TEST_COORD_STATE:?}/runner.log"
if [[ "${BORON_GEN_PERF_ORIGIN:?}" == failure.test. ]]; then
    printf 'retained failed performance evidence\n' >"$artifact_dir/failure.log"
    exit 42
fi
FAKE_RUNNER
chmod +x "$fake_bin/ssh" "$fake_bin/scp" \
    "$fixture_repo/scripts/boron-gen-query-performance.sh"

PATH="$fake_bin:$PATH" \
TEST_COORD_STATE="$state" \
TEST_COORD_FAIL_FIND_ONCE=true \
BORON_COORD_SERVER_SSH=server-test \
BORON_COORD_CLIENT_SSH=client-test \
BORON_COORD_REMOTE_ARTIFACT_ROOT=/remote/evidence \
BORON_COORD_LOCAL_ARTIFACT_ROOT="$local_artifacts" \
BORON_COORD_POLL_SECONDS=1 \
BORON_COORD_TIMEOUT_SECONDS=30 \
BORON_COORD_MAX_DROP_PERMILLE_OVERRIDE=200 \
    "$fixture_repo/scripts/boron-gen-external-performance-coordinator.sh" \
    >"$state/coordinator.stdout" 2>"$state/coordinator.stderr"

[[ "$(wc -l <"$state/runner.log")" -eq 3 ]]
[[ "$(wc -l <"$local_artifacts/completed-requests.tsv")" -eq 2 ]]
[[ "$(wc -l <"$local_artifacts/failed-requests.tsv")" -eq 1 ]]
grep -Fq 'runs/01-active/attempt-001/evidence' \
    "$local_artifacts/completed-requests.tsv"
grep -Fq 'runs/03-active/attempt-001/evidence' \
    "$local_artifacts/completed-requests.tsv"
grep -Fq 'requested_max_drop_permille=1000' \
    "$local_artifacts/runs/03-active/attempt-001/evidence/performance/coordinator-policy.env"
grep -Fq 'effective_max_drop_permille=200' \
    "$local_artifacts/runs/03-active/attempt-001/evidence/performance/coordinator-policy.env"
[[ -f "$local_artifacts/runs/02-stale/attempt-001/evidence/stale-request.txt" ]]
grep -Fq 'run summary exists without performance completion' \
    "$local_artifacts/runs/02-stale/attempt-001/evidence/stale-request.txt"
failure_root="$local_artifacts/runs/04-failing/attempt-001/evidence"
grep -Fq 'exit_status=42' "$failure_root/failed-request.txt"
grep -Fq 'retained failed performance evidence' \
    "$failure_root/performance/failure.log"
grep -Fq 'runs/04-failing/attempt-001/evidence' \
    "$local_artifacts/failed-requests.tsv"
grep -Fq 'retaining evidence and continuing coordination' \
    "$state/coordinator.stderr"
grep -Fq 'performance request enumeration failed with status 255' \
    "$state/coordinator.stderr"
grep -Fq 'external performance coordination completed' "$state/coordinator.stdout"

printf 'boron-gen external performance coordinator tests passed\n'
