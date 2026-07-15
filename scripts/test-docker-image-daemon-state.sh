#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/package-common.sh"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/oxidedns-docker-smoke-state.XXXXXX")"
background_pids=()
cleanup() {
    local status=$?
    trap - EXIT
    trap '' INT TERM HUP
    local pid
    for pid in "${background_pids[@]}"; do
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf -- "$workdir"
    exit "$status"
}
trap cleanup EXIT

fake_bin="$workdir/bin"
archive_root="$workdir/archive"
archive="$workdir/image.tar.xz"
missing_blob_archive="$workdir/image-missing-blob.tar.xz"
image_ref="oxidedns-smoke-fixture:0.2.0"
old_id="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
mkdir -m 0700 "$fake_bin" "$archive_root"

# shellcheck disable=SC2016 # The generated fake expands these at runtime.
printf '%s\n' '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'case "${1:-}" in' \
    'metadata) printf "%s\n" '\''{"packages":[{"version":"0.2.0"}]}'\'' ;;' \
    '*) exit 97 ;;' \
    'esac' >"$fake_bin/cargo"

cat >"$fake_bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail

state="${FAKE_SMOKE_STATE:?}"
stable="$state/stable"
backup="$state/backup"
old_id="${FAKE_SMOKE_OLD_ID:?}"
new_id="${FAKE_SMOKE_NEW_ID:?}"
image_ref="${FAKE_SMOKE_REF:?}"

resolve_ref() {
    case "$1" in
    "$old_id" | "$new_id") printf '%s\n' "$1" ;;
    "$image_ref") [[ -f "$stable" ]] && cat "$stable" ;;
    oxidedns-smoke-backup-*) [[ -f "$backup" ]] && cat "$backup" ;;
    *) return 1 ;;
    esac
}

pause_after_mutation() {
    local phase="$1"
    [[ "${FAKE_SMOKE_PAUSE:-}" == "$phase" ]] || return 0
    : >"${FAKE_SMOKE_MARKER:?}"
    sleep 0.5
}

case "${1:-}" in
info) exit 0 ;;
ps) exit 0 ;;
load)
    cat >/dev/null
    printf '%s\n' "$new_id" >"$stable"
    printf 'Loaded image: %s\n' "$image_ref"
    ;;
run)
    if [[ "${FAKE_SMOKE_FAIL_AFTER_LOAD:-0}" == 1 ]]; then
        exit 97
    fi
    printf 'fake-container\n'
    ;;
image)
    subcommand="${2:-}"
    shift 2
    case "$subcommand" in
    inspect)
        if [[ "${1:-}" == --format ]]; then
            format="$2"
            ref="$3"
            value="$(resolve_ref "$ref")" || exit 1
            [[ "$format" == '{{.Id}}' ]] || exit 96
            printf '%s\n' "$value"
        else
            resolve_ref "${1:-}" >/dev/null
        fi
        ;;
    tag)
        source_id="$(resolve_ref "$1")" || exit 1
        target="$2"
        case "$target" in
        "$image_ref")
            if [[ "$source_id" == "$old_id" && -f "$backup" &&
                "${FAKE_SMOKE_RESTORE_FAILURE:-}" == before ]]; then
                exit 97
            fi
            printf '%s\n' "$source_id" >"$stable"
            if [[ "$source_id" == "$old_id" && -f "$backup" &&
                "${FAKE_SMOKE_RESTORE_FAILURE:-}" == after ]]; then
                exit 97
            fi
            if [[ "$source_id" == "$old_id" && -f "$backup" ]]; then
                pause_after_mutation restore
            fi
            ;;
        oxidedns-smoke-backup-*)
            printf '%s\n' "$source_id" >"$backup"
            pause_after_mutation backup
            ;;
        *) exit 95 ;;
        esac
        ;;
    rm)
        case "$1" in
        "$image_ref") rm -f -- "$stable" ;;
        oxidedns-smoke-backup-*) rm -f -- "$backup" ;;
        *) exit 94 ;;
        esac
        ;;
    *) exit 93 ;;
    esac
    ;;
*) exit 92 ;;
esac
FAKE_DOCKER
chmod 0755 "$fake_bin/cargo" "$fake_bin/docker"

mkdir -p "$archive_root/blobs/sha256"
printf '{}\n' >"$archive_root/config"
config_digest="$(sha256sum "$archive_root/config" | awk '{print $1}')"
new_id="sha256:$config_digest"
printf 'fixture layer\n' >"$archive_root/layer"
layer_digest="$(sha256sum "$archive_root/layer" | awk '{print $1}')"
mv "$archive_root/config" "$archive_root/blobs/sha256/$config_digest"
mv "$archive_root/layer" "$archive_root/blobs/sha256/$layer_digest"
printf '[{"Config":"blobs/sha256/%s","RepoTags":["%s"],"Layers":["blobs/sha256/%s"]}]\n' \
    "$config_digest" "$image_ref" "$layer_digest" >"$archive_root/manifest.json"
tar -C "$archive_root" -cf - manifest.json \
    "blobs/sha256/$config_digest" "blobs/sha256/$layer_digest" | xz >"$archive"
tar -C "$archive_root" -cf - manifest.json "blobs/sha256/$config_digest" | xz >"$missing_blob_archive"

make_special_member_archive() {
    local kind="$1"
    local output="$2"
    python3 - "$archive" "$output" "$kind" <<'PY'
import lzma
import shutil
import sys
import tarfile
import tempfile

source, output, kind = sys.argv[1:]
with tempfile.NamedTemporaryFile() as raw:
    with lzma.open(source, "rb") as compressed:
        shutil.copyfileobj(compressed, raw)
    raw.flush()
    with tarfile.open(raw.name, "a") as archive:
        member = tarfile.TarInfo(f"unsupported-{kind}")
        member.mode = 0o600
        if kind == "hardlink":
            member.type = tarfile.LNKTYPE
            member.linkname = "manifest.json"
        elif kind == "symlink":
            member.type = tarfile.SYMTYPE
            member.linkname = "manifest.json"
        elif kind == "fifo":
            member.type = tarfile.FIFOTYPE
        elif kind == "device":
            # Tar metadata is enough to exercise device-node rejection; the
            # fixture never calls mknod and is safe for unprivileged CI.
            member.type = tarfile.CHRTYPE
            member.devmajor = 1
            member.devminor = 3
        else:
            raise SystemExit(f"unknown special archive member kind: {kind}")
        archive.addfile(member)
    raw.seek(0)
    with lzma.open(output, "wb") as compressed:
        shutil.copyfileobj(raw, compressed)
PY
}

for special_kind in hardlink symlink fifo device; do
    special_archive="$workdir/image-$special_kind.tar.xz"
    make_special_member_archive "$special_kind" "$special_archive"
    if python3 "$repo_root/scripts/verify-docker-archive.py" "$special_archive" \
        >"$workdir/$special_kind.out" 2>"$workdir/$special_kind.err"; then
        printf 'Docker archive verifier accepted a %s member\n' "$special_kind" >&2
        exit 1
    fi
    grep -Fq "unsupported archive member type: unsupported-$special_kind" \
        "$workdir/$special_kind.err"
done

make_bound_archive() {
    local kind="$1"
    local output="$2"
    python3 - "$output" "$kind" <<'PY'
import io
import lzma
import sys
import tarfile

output, kind = sys.argv[1:]
if kind == "high-dictionary":
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 128 * 1024 * 1024}]
    with lzma.open(output, "wb", format=lzma.FORMAT_XZ, filters=filters) as compressed:
        compressed.write(b"\0" * 10240)
    raise SystemExit(0)
archive_format = tarfile.PAX_FORMAT if kind == "pax-metadata" else tarfile.DEFAULT_FORMAT
with tarfile.open(output, "w:xz", format=archive_format) as archive:
    def add(name: str, payload: bytes = b"", *, directory: bool = False) -> None:
        member = tarfile.TarInfo(name)
        member.mode = 0o700 if directory else 0o600
        member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
        member.size = 0 if directory else len(payload)
        archive.addfile(member, None if directory else io.BytesIO(payload))

    if kind == "member-bytes":
        add("manifest.json", b"[]\n")
        # Highly compressible content proves the limit applies to expanded
        # member bytes, not merely the small .xz input size.
        add("compressed-bomb", b"\0" * (2 * 1024 * 1024))
    elif kind == "total-bytes":
        add("manifest.json", b"[]\n")
        add("first", b"a" * 700)
        add("second", b"b" * 700)
    elif kind == "member-count":
        for index in range(4):
            add(f"directory-{index}", directory=True)
    elif kind == "retained-json":
        add("manifest.json", b"[" + b" " * 2048 + b"]\n")
    elif kind == "pax-metadata":
        add("x" * 200, b"metadata extension")
    else:
        raise SystemExit(f"unknown bounded archive fixture: {kind}")
PY
}

expect_bound_rejection() {
    local label="$1"
    local archive_path="$2"
    local expected="$3"
    shift 3
    if env "$@" python3 "$repo_root/scripts/verify-docker-archive.py" "$archive_path" \
        >"$workdir/$label.out" 2>"$workdir/$label.err"; then
        printf 'Docker archive verifier accepted the %s fixture\n' "$label" >&2
        exit 1
    fi
    grep -Fq "$expected" "$workdir/$label.err"
}

member_bytes_archive="$workdir/image-member-bytes.tar.xz"
total_bytes_archive="$workdir/image-total-bytes.tar.xz"
member_count_archive="$workdir/image-member-count.tar.xz"
retained_json_archive="$workdir/image-retained-json.tar.xz"
pax_metadata_archive="$workdir/image-pax-metadata.tar.xz"
high_dictionary_archive="$workdir/image-high-dictionary.tar.xz"
make_bound_archive member-bytes "$member_bytes_archive"
make_bound_archive total-bytes "$total_bytes_archive"
make_bound_archive member-count "$member_count_archive"
make_bound_archive retained-json "$retained_json_archive"
make_bound_archive pax-metadata "$pax_metadata_archive"
make_bound_archive high-dictionary "$high_dictionary_archive"

expect_bound_rejection deadline "$archive" \
    "absolute verification deadline expired" \
    OXIDEDNS_DOCKER_ARCHIVE_DEADLINE_NS=1
expect_bound_rejection member-bytes "$member_bytes_archive" \
    "archive member exceeds byte bound: compressed-bomb" \
    OXIDEDNS_DOCKER_ARCHIVE_MAX_MEMBER_BYTES=1048576
expect_bound_rejection total-bytes "$total_bytes_archive" \
    "archive decompressed bytes exceed hard bound 1000" \
    OXIDEDNS_DOCKER_ARCHIVE_MAX_TOTAL_BYTES=1000
expect_bound_rejection member-count "$member_count_archive" \
    "archive member count exceeds hard bound 3" \
    OXIDEDNS_DOCKER_ARCHIVE_MAX_MEMBERS=3
expect_bound_rejection retained-json "$retained_json_archive" \
    "retained JSON bytes exceed hard bound 1000" \
    OXIDEDNS_DOCKER_ARCHIVE_MAX_RETAINED_JSON_BYTES=1000
expect_bound_rejection pax-metadata "$pax_metadata_archive" \
    "unsupported extended tar metadata record"
expect_bound_rejection high-dictionary "$high_dictionary_archive" \
    "XZ decompression failed within its memory limit"

archive_symlink="$workdir/image-symlink-input.tar.xz"
ln -s "$archive" "$archive_symlink"
expect_bound_rejection symlink-input "$archive_symlink" \
    "cannot safely open archive"
archive_fifo="$workdir/image-fifo-input.tar.xz"
mkfifo "$archive_fifo"
expect_bound_rejection fifo-input "$archive_fifo" \
    "archive must be one caller-owned, linked, bounded regular file"

run_staged_mutation_case() {
    local kind="$1"
    local source="$workdir/staged-$kind.tar.xz"
    local original="$workdir/staged-$kind.original.tar.xz"
    local replacement="$workdir/staged-$kind.replacement.tar.xz"
    local streamed="$workdir/staged-$kind.streamed.tar.xz"
    local marker="$workdir/staged-$kind.marker"
    local continuation="$workdir/staged-$kind.continue"
    cp "$archive" "$source"
    cp "$archive" "$original"
    cp "$missing_blob_archive" "$replacement"
    OXIDEDNS_DOCKER_ARCHIVE_TEST_STAGE_MARKER="$marker" \
        OXIDEDNS_DOCKER_ARCHIVE_TEST_CONTINUE="$continuation" \
        python3 "$repo_root/scripts/verify-docker-archive.py" \
        --stream-verified-archive "$source" >"$streamed" &
    local verifier_pid=$!
    for _ in {1..300}; do
        [[ -e "$marker" ]] && break
        kill -0 "$verifier_pid" 2>/dev/null || break
        sleep 0.01
    done
    [[ -e "$marker" ]] || {
        wait "$verifier_pid" || true
        printf 'archive verifier did not reach private-stage seam: %s\n' "$kind" >&2
        return 1
    }
    if [[ "$kind" == in-place ]]; then
        cp "$replacement" "$source"
    else
        mv "$source" "$workdir/staged-$kind.displaced.tar.xz"
        mv "$replacement" "$source"
    fi
    : >"$continuation"
    wait "$verifier_pid"
    cmp "$original" "$streamed"
}

run_staged_mutation_case in-place
run_staged_mutation_case pathname-swap

# The archive verifier deliberately accepts canonical all-zero XZ stream
# padding. Publication must nevertheless bind the exact compressed bytes to
# the adjacent checksum, including across in-place writes and pathname swaps.
bundle_archive="$workdir/bundle.tar.xz"
bundle_checksum="$bundle_archive.sha256"
bundle_original="$workdir/bundle.original.tar.xz"
cp "$archive" "$bundle_archive"
cp "$archive" "$bundle_original"
(
    cd "$workdir"
    sha256sum "$(basename "$bundle_archive")" >"$(basename "$bundle_checksum")"
)
package_verify_docker_archive_bundle "$bundle_archive" "$bundle_checksum" \
    "$repo_root/scripts/verify-docker-archive.py" "$new_id" "$image_ref"

printf '\0\0\0\0' >>"$bundle_archive"
python3 "$repo_root/scripts/verify-docker-archive.py" "$bundle_archive" >/dev/null
if package_verify_docker_archive_bundle "$bundle_archive" "$bundle_checksum" \
    "$repo_root/scripts/verify-docker-archive.py" "$new_id" "$image_ref"; then
    printf 'Docker bundle verification accepted appended XZ padding\n' >&2
    exit 1
fi

cp "$missing_blob_archive" "$bundle_archive"
if package_verify_docker_archive_bundle "$bundle_archive" "$bundle_checksum" \
    "$repo_root/scripts/verify-docker-archive.py" "$new_id" "$image_ref"; then
    printf 'Docker bundle verification accepted in-place archive replacement\n' >&2
    exit 1
fi

cp "$bundle_original" "$workdir/bundle.pathname-replacement.tar.xz"
printf '\0\0\0\0' >>"$workdir/bundle.pathname-replacement.tar.xz"
mv -f "$workdir/bundle.pathname-replacement.tar.xz" "$bundle_archive"
python3 "$repo_root/scripts/verify-docker-archive.py" "$bundle_archive" >/dev/null
if package_verify_docker_archive_bundle "$bundle_archive" "$bundle_checksum" \
    "$repo_root/scripts/verify-docker-archive.py" "$new_id" "$image_ref"; then
    printf 'Docker bundle verification accepted pathname-swapped archive bytes\n' >&2
    exit 1
fi

# A non-reading consumer must not turn the verifier's internal BOOTTIME limit
# into an unbounded blocking stdout write. Use incompressible layer bytes so
# the verified compressed payload exceeds the FIFO buffer.
backpressure_root="$workdir/backpressure-root"
backpressure_archive="$workdir/backpressure.tar.xz"
mkdir -p "$backpressure_root/blobs/sha256"
dd if=/dev/urandom of="$backpressure_root/layer" bs=1048576 count=1 status=none
backpressure_layer_digest="$(sha256sum "$backpressure_root/layer" | awk '{print $1}')"
cp "$archive_root/blobs/sha256/$config_digest" \
    "$backpressure_root/blobs/sha256/$config_digest"
mv "$backpressure_root/layer" "$backpressure_root/blobs/sha256/$backpressure_layer_digest"
printf '[{"Config":"blobs/sha256/%s","RepoTags":["%s"],"Layers":["blobs/sha256/%s"]}]\n' \
    "$config_digest" "$image_ref" "$backpressure_layer_digest" \
    >"$backpressure_root/manifest.json"
tar -C "$backpressure_root" -cf - manifest.json \
    "blobs/sha256/$config_digest" "blobs/sha256/$backpressure_layer_digest" |
    xz >"$backpressure_archive"
backpressure_fifo="$workdir/nonreading.fifo"
mkfifo "$backpressure_fifo"
python3 -c 'import os,sys,time; fd=os.open(sys.argv[1], os.O_RDONLY); time.sleep(30)' \
    "$backpressure_fifo" &
nonreader_pid=$!
background_pids+=("$nonreader_pid")
SECONDS=0
set +e
OXIDEDNS_DOCKER_ARCHIVE_TIMEOUT_SECONDS=1 \
    python3 "$repo_root/scripts/verify-docker-archive.py" \
    --stream-verified-archive "$backpressure_archive" \
    >"$backpressure_fifo" 2>"$workdir/backpressure.err"
backpressure_status=$?
set -e
backpressure_elapsed=$SECONDS
((backpressure_status != 0 && backpressure_elapsed <= 4)) || {
    cat "$workdir/backpressure.err" >&2
    printf 'Docker archive verifier stdout backpressure was not bounded: status=%s elapsed=%ss\n' \
        "$backpressure_status" "$backpressure_elapsed" >&2
    exit 1
}
grep -Fq 'absolute verification deadline expired' "$workdir/backpressure.err"
kill -KILL "$nonreader_pid" 2>/dev/null || true
wait "$nonreader_pid" 2>/dev/null || true

# Supervise the whole verifier/decompressor/daemon pipeline. This fake daemon
# ignores TERM and never reads stdin, forcing the supervisor's KILL-and-reap
# path rather than a cooperative exit.
hung_bin="$workdir/hung-bin"
hung_pid_file="$workdir/hung-docker.pid"
mkdir -m 0700 "$hung_bin"
cat >"$hung_bin/docker" <<'HUNG_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == load ]] || exit 97
printf '%s\n' "$$" >"${HUNG_DOCKER_PID_FILE:?}"
trap '' TERM
while :; do sleep 30; done
HUNG_DOCKER
chmod 0755 "$hung_bin/docker"
hung_loaded_images=""
SECONDS=0
set +e
PATH="$hung_bin:$PATH" HUNG_DOCKER_PID_FILE="$hung_pid_file" \
    OXIDEDNS_DOCKER_LOAD_TIMEOUT_SECONDS=1 \
    package_load_verified_docker_archive "$archive" \
    "$repo_root/scripts/verify-docker-archive.py" \
    "$repo_root/scripts/release-api-supervisor.py" hung_loaded_images \
    >"$workdir/hung-load.out" 2>"$workdir/hung-load.err"
hung_status=$?
set -e
hung_elapsed=$SECONDS
[[ -z "$hung_loaded_images" ]]
((hung_status != 0 && hung_elapsed <= 6)) || {
    cat "$workdir/hung-load.err" >&2
    printf 'hung Docker load pipeline was not bounded: status=%s elapsed=%ss\n' \
        "$hung_status" "$hung_elapsed" >&2
    exit 1
}
[[ -s "$hung_pid_file" ]]
hung_pid="$(<"$hung_pid_file")"
for _ in {1..100}; do
    kill -0 "$hung_pid" 2>/dev/null || break
    sleep 0.01
done
if kill -0 "$hung_pid" 2>/dev/null; then
    printf 'hung Docker daemon helper survived supervised timeout: pid=%s\n' "$hung_pid" >&2
    exit 1
fi

run_signal_case() {
    local phase="$1"
    local expected_status="$2"
    local state="$workdir/state-$phase"
    local marker="$state/mutation-complete"
    mkdir -m 0700 "$state"
    printf '%s\n' "$old_id" >"$state/stable"

    set +e
    PATH="$fake_bin:$PATH" \
        FAKE_SMOKE_STATE="$state" \
        FAKE_SMOKE_OLD_ID="$old_id" \
        FAKE_SMOKE_NEW_ID="$new_id" \
        FAKE_SMOKE_REF="$image_ref" \
        FAKE_SMOKE_PAUSE="$phase" \
        FAKE_SMOKE_RESTORE_FAILURE='' \
        FAKE_SMOKE_MARKER="$marker" \
        FAKE_SMOKE_FAIL_AFTER_LOAD="$([[ "$phase" == restore ]] && printf 1 || printf 0)" \
        OXIDEDNS_DOCKER_IMAGE_ARCHIVE="$archive" \
        OXIDEDNS_DOCKER_IMAGE_REF="$image_ref" \
        OXIDEDNS_PACKAGE_TARGET=x86_64-unknown-linux-musl \
        "$repo_root/scripts/test-docker-image.sh" >"$state/run.log" 2>&1 &
    local smoke_pid=$!
    set -e

    for _ in {1..300}; do
        [[ ! -e "$marker" ]] || break
        kill -0 "$smoke_pid" 2>/dev/null || break
        sleep 0.01
    done
    [[ -e "$marker" ]] || {
        cat "$state/run.log" >&2
        printf 'Docker smoke fixture did not reach %s mutation window\n' "$phase" >&2
        return 1
    }

    local signal_flood_pid=""
    if [[ "$phase" == backup ]]; then
        kill -TERM "$smoke_pid"
    else
        (
            for _ in {1..200}; do
                kill -TERM "$smoke_pid" 2>/dev/null || exit 0
                sleep 0.005
            done
        ) &
        signal_flood_pid=$!
    fi

    set +e
    wait "$smoke_pid"
    local status=$?
    set -e
    if [[ -n "$signal_flood_pid" ]]; then
        wait "$signal_flood_pid"
    fi
    [[ "$status" == "$expected_status" ]] || {
        cat "$state/run.log" >&2
        printf 'Docker smoke %s signal status mismatch: expected=%s actual=%s\n' \
            "$phase" "$expected_status" "$status" >&2
        return 1
    }
    [[ "$(cat "$state/stable")" == "$old_id" ]]
    [[ ! -e "$state/backup" ]]
}

run_signal_case backup 143
run_signal_case restore 97

run_restore_failure_case() {
    local failure_mode="$1"
    local expected_status="$2"
    local state="$workdir/state-restore-$failure_mode"
    mkdir -m 0700 "$state"
    printf '%s\n' "$old_id" >"$state/stable"

    set +e
    PATH="$fake_bin:$PATH" \
        FAKE_SMOKE_STATE="$state" \
        FAKE_SMOKE_OLD_ID="$old_id" \
        FAKE_SMOKE_NEW_ID="$new_id" \
        FAKE_SMOKE_REF="$image_ref" \
        FAKE_SMOKE_PAUSE='' \
        FAKE_SMOKE_MARKER="$state/unused-marker" \
        FAKE_SMOKE_RESTORE_FAILURE="$failure_mode" \
        FAKE_SMOKE_FAIL_AFTER_LOAD=1 \
        OXIDEDNS_DOCKER_IMAGE_ARCHIVE="$archive" \
        OXIDEDNS_DOCKER_IMAGE_REF="$image_ref" \
        OXIDEDNS_PACKAGE_TARGET=x86_64-unknown-linux-musl \
        "$repo_root/scripts/test-docker-image.sh" >"$state/run.log" 2>&1
    local status=$?
    set -e
    [[ "$status" == "$expected_status" ]] || {
        cat "$state/run.log" >&2
        printf 'Docker smoke restore-%s status mismatch: expected=%s actual=%s\n' \
            "$failure_mode" "$expected_status" "$status" >&2
        return 1
    }

    if [[ "$failure_mode" == before ]]; then
        [[ "$(cat "$state/stable")" == "$new_id" ]]
        [[ "$(cat "$state/backup")" == "$old_id" ]]
        grep -Fq 'retained previous Docker smoke-test image under recovery tag:' "$state/run.log"
    else
        [[ "$(cat "$state/stable")" == "$old_id" ]]
        [[ ! -e "$state/backup" ]]
    fi
}

run_restore_failure_case before 74
run_restore_failure_case after 97

run_missing_blob_case() {
    local state="$workdir/state-missing-blob"
    mkdir -m 0700 "$state"
    printf '%s\n' "$old_id" >"$state/stable"

    set +e
    PATH="$fake_bin:$PATH" \
        FAKE_SMOKE_STATE="$state" \
        FAKE_SMOKE_OLD_ID="$old_id" \
        FAKE_SMOKE_NEW_ID="$new_id" \
        FAKE_SMOKE_REF="$image_ref" \
        FAKE_SMOKE_PAUSE='' \
        FAKE_SMOKE_MARKER="$state/unused-marker" \
        FAKE_SMOKE_RESTORE_FAILURE='' \
        FAKE_SMOKE_FAIL_AFTER_LOAD=0 \
        OXIDEDNS_DOCKER_IMAGE_ARCHIVE="$missing_blob_archive" \
        OXIDEDNS_DOCKER_IMAGE_REF="$image_ref" \
        OXIDEDNS_PACKAGE_TARGET=x86_64-unknown-linux-musl \
        "$repo_root/scripts/test-docker-image.sh" >"$state/run.log" 2>&1
    local status=$?
    set -e
    ((status != 0))
    grep -Fq 'archive is missing regular layer object:' "$state/run.log"
    [[ "$(cat "$state/stable")" == "$old_id" ]]
    [[ ! -e "$state/backup" ]]
}

run_missing_blob_case
printf 'Docker smoke daemon-state and archive fixtures passed\n'
