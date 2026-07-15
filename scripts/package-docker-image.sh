#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/package-common.sh"
# Release artifact modes must not depend on a caller's permissive umask.
umask 022
target_triple="${BORONDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
dist_dir="${BORONDNS_DIST_DIR:-$repo_root/target/dist}"
package_name="${BORONDNS_PACKAGE_NAME:-borondns}"
package_require_safe_component BORONDNS_PACKAGE_NAME "$package_name" '^[a-z0-9][a-z0-9._-]*$'
package_require_safe_component BORONDNS_PACKAGE_TARGET "$target_triple" '^[A-Za-z0-9][A-Za-z0-9._-]*$'
allow_dynamic="${BORONDNS_PACKAGE_ALLOW_DYNAMIC:-0}"
allow_dirty_non_release="${BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE:-0}"
[[ "$allow_dynamic" == 0 || "$allow_dynamic" == 1 ]] || {
    printf 'BORONDNS_PACKAGE_ALLOW_DYNAMIC must be 0 or 1\n' >&2
    exit 1
}
[[ "$allow_dirty_non_release" == 0 || "$allow_dirty_non_release" == 1 ]] || {
    printf 'BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE must be 0 or 1\n' >&2
    exit 1
}
if [[ "$allow_dynamic" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then
    printf 'dynamic-link Docker packaging override is forbidden in GitHub Actions release paths\n' >&2
    exit 1
fi
if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then
    printf 'dirty-source packaging override is forbidden in GitHub Actions release paths\n' >&2
    exit 1
fi
cargo_bin="${CARGO:-}"
rustc_bin="${RUSTC:-}"
[[ -n "$cargo_bin" ]] || cargo_bin="$(command -v cargo 2>/dev/null || true)"
[[ -n "$rustc_bin" ]] || rustc_bin="$(command -v rustc 2>/dev/null || true)"
[[ -n "$cargo_bin" && -n "$rustc_bin" ]] || {
    printf 'missing required Docker packaging Rust tools: cargo rustc\n' >&2
    exit 1
}
cargo_bin="$(realpath -e "$cargo_bin")"
rustc_bin="$(realpath -e "$rustc_bin")"
[[ -x "$cargo_bin" && -f "$cargo_bin" && -x "$rustc_bin" && -f "$rustc_bin" ]] || {
    printf 'selected Docker packaging Rust tools must be executable regular files\n' >&2
    exit 1
}
source_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
    printf 'Docker packaging requires a Git-bound source checkout\n' >&2
    exit 1
}
source_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no 2>/dev/null)" || {
    printf 'cannot determine Docker packaging source status\n' >&2
    exit 1
}
source_clean=1
release_eligible=1
if [[ "$allow_dynamic" == 1 ]]; then
    release_eligible=0
    printf 'warning: dynamic-link Docker packaging override enabled; image artifacts are non-release diagnostics\n' >&2
fi
if [[ -n "$source_status" ]]; then
    source_clean=0
    release_eligible=0
    if [[ "$allow_dirty_non_release" != 1 ]]; then
        printf 'refusing Docker packaging from dirty or untracked source:\n%s\n' "$source_status" >&2
        exit 1
    fi
    printf 'warning: dirty-source packaging override enabled; image artifacts are non-release diagnostics\n' >&2
fi
commit="${source_commit:0:12}"

verify_source_identity() {
    local boundary="$1"
    local actual_commit actual_status
    actual_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
        printf 'cannot resolve Docker packaging source at %s\n' "$boundary" >&2
        return 1
    }
    actual_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no 2>/dev/null)" || {
        printf 'cannot determine Docker packaging source status at %s\n' "$boundary" >&2
        return 1
    }
    if [[ "$actual_commit" != "$source_commit" || "$actual_status" != "$source_status" ]]; then
        printf 'Docker packaging source changed at %s\n' "$boundary" >&2
        return 1
    fi
}
version="$(env RUSTC="$rustc_bin" "$cargo_bin" metadata --no-deps --locked --format-version 1 \
    --manifest-path "$repo_root/Cargo.toml" |
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
build_date="${BORONDNS_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
archive_root="$package_name-$version-$target_triple"
if [[ "$source_clean" != 1 ]]; then
    archive_root="$archive_root-nonrelease-dirty"
elif [[ "$allow_dynamic" == 1 ]]; then
    archive_root="$archive_root-nonrelease-dynamic"
fi
package_require_safe_component package-version "$version" '^[0-9][A-Za-z0-9.+-]*$'
package_require_safe_component archive-root "$archive_root"
image_ref="${BORONDNS_DOCKER_IMAGE_REF:-$package_name:$version}"
if [[ "$source_clean" != 1 ]]; then
    image_ref="$(package_nonrelease_docker_image_ref "$image_ref")"
elif [[ "$allow_dynamic" == 1 ]]; then
    image_ref="$(package_nonrelease_dynamic_docker_image_ref "$image_ref")"
else
    package_require_clean_docker_image_ref "$image_ref"
fi
dist_dir="$(package_canonical_output_root BORONDNS_DIST_DIR "$dist_dir")"
# Docker packaging performs its own fresh installer build to bind the image
# input to the current source and toolchain. Build privately, then publish the
# isolated input directory only with the rest of the terminal transaction.
docker_installer_dist_dir="${BORONDNS_DOCKER_INSTALLER_DIST_DIR:-$repo_root/target/docker-installer-input}"
docker_installer_dist_dir="$(package_canonical_output_root BORONDNS_DOCKER_INSTALLER_DIST_DIR "$docker_installer_dist_dir")"
if [[ "$(realpath -m -- "$docker_installer_dist_dir")" == "$(realpath -m -- "$dist_dir")" ]]; then
    printf 'Docker installer input directory must be isolated from published dist: %s\n' "$dist_dir" >&2
    exit 1
fi
alpine_base_image="${BORONDNS_DOCKER_ALPINE_BASE_IMAGE:-alpine:3.22@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6}"
docker_context="$(package_safe_child_path "$dist_dir" "$archive_root-docker-context" 'Docker build context')"
image_archive="$(package_safe_child_path "$dist_dir" "$archive_root-docker-image.tar.xz" 'Docker image archive')"
image_manifest="$(package_safe_child_path "$dist_dir" "$archive_root-docker-image.manifest.txt" 'Docker image manifest')"
image_inspect="$(package_safe_child_path "$dist_dir" "$archive_root-docker-image.inspect.json" 'Docker image inspection')"

missing=()
for tool in docker python3 xz flock; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required Docker packaging tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

if [[ "$alpine_base_image" != "alpine:3.22@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6" ]]; then
    printf 'error: BORONDNS_DOCKER_ALPINE_BASE_IMAGE must equal the reviewed Alpine base image digest\n' >&2
    exit 1
fi
alpine_base_digest="${alpine_base_image##*@}"

if ! docker info >/dev/null 2>&1; then
    printf 'Docker daemon is unavailable\n' >&2
    exit 1
fi

# Create private recursive-cleanup roots only after every fallible preflight.
# The EXIT trap is armed first and each chosen path is assigned before its
# atomic mkdir, so termination always leaves cleanup with the exact name.
run_root=""
private_installer_dist_dir=""
docker_binary_asset=""
run_docker_context=""
run_image_archive=""
run_image_manifest=""
run_image_inspect=""
image_iid_file=""
installer_root=""
installer_publish_root=""
prior_image_id=""
docker_tag_activation_attempted=0
package_publication_initialized=0

restore_previous_image_tag() {
    ((docker_tag_activation_attempted == 0 || PACKAGE_PUBLICATION_COMPLETE == 1)) && return 0
    local current=""
    if [[ -n "$prior_image_id" ]]; then
        docker image tag "$prior_image_id" "$image_ref" || return 1
        current="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)" || return 1
        [[ "$current" == "$prior_image_id" ]] || return 1
    else
        if current="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)"; then
            docker image rm "$image_ref" >/dev/null || return 1
        fi
        if docker image inspect "$image_ref" >/dev/null 2>&1; then
            return 1
        fi
    fi
}

cleanup_private_root() {
    local candidate="$1"
    local label="$2"
    [[ -n "$candidate" && (-e "$candidate" || -L "$candidate") ]] || return 0
    if [[ -z "${PACKAGE_CLEANUP_ROOT_IDENTITIES[$candidate]:-}" ]]; then
        package_capture_cleanup_root "$candidate" "$label" || return 1
    fi
    package_remove_captured_cleanup_root "$candidate" "$label"
}

cleanup_failed_publication() {
    local status=$?
    trap - EXIT
    package_begin_signal_cleanup
    if ! restore_previous_image_tag; then
        printf 'could not restore previous Docker image tag after publication failure: %s\n' "$image_ref" >&2
        status=74
    fi
    if [[ "$package_publication_initialized" == 1 ]]; then
        # Finalize publication first, but defer its retained-root deletion so
        # both independently created private roots are removed deterministically.
        package_cleanup_publication "$status" 0 || status=$?
        if [[ "${PACKAGE_PUBLICATION_ROLLBACK_FAILED:-0}" != 1 ]]; then
            cleanup_private_root "$installer_publish_root" \
                "Docker installer publication staging root" || status=74
            cleanup_private_root "$run_root" "Docker package run root" || status=74
        fi
    else
        cleanup_private_root "$installer_publish_root" \
            "Docker installer publication staging root" || status=74
        cleanup_private_root "$run_root" "Docker package run root" || status=74
    fi
    exit "$status"
}
trap cleanup_failed_publication EXIT
trap 'package_signal_handler 130' INT
trap 'package_signal_handler 143' TERM
trap 'package_signal_handler 129' HUP

for run_root_attempt in {1..128}; do
    run_root="$dist_dir/.${archive_root}.docker-package.$$.$RANDOM.$run_root_attempt"
    if mkdir -m 0700 -- "$run_root" 2>/dev/null; then
        break
    fi
    run_root=""
done
[[ -n "$run_root" && -d "$run_root" && ! -L "$run_root" ]] || {
    printf 'cannot allocate private Docker package run root under %s\n' "$dist_dir" >&2
    exit 1
}
private_installer_dist_dir="$run_root/installer-input"
docker_binary_asset="$private_installer_dist_dir/$archive_root.bin"
run_docker_context="$run_root/$archive_root-docker-context"
run_image_archive="$run_root/$archive_root-docker-image.tar.xz"
run_image_manifest="$run_root/$archive_root-docker-image.manifest.txt"
run_image_inspect="$run_root/$archive_root-docker-image.inspect.json"
image_iid_file="$run_root/image.iid"
installer_root="$private_installer_dist_dir/$archive_root"
for installer_publish_attempt in {1..128}; do
    installer_publish_root="$docker_installer_dist_dir/.${archive_root}.docker-input.$$.$RANDOM.$installer_publish_attempt"
    if mkdir -m 0700 -- "$installer_publish_root" 2>/dev/null; then
        break
    fi
    installer_publish_root=""
done
[[ -n "$installer_publish_root" && -d "$installer_publish_root" && ! -L "$installer_publish_root" ]] || {
    printf 'cannot allocate private Docker installer publication root under %s\n' \
        "$docker_installer_dist_dir" >&2
    exit 1
}
package_publication_reset "$run_root"
package_publication_initialized=1
package_capture_cleanup_root "$installer_publish_root" "Docker installer publication staging root"
mkdir -p "$private_installer_dist_dir"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        return 1
    fi
}

verify_source_identity "before installer build"

# Never infer provenance from a version-shaped executable already present in
# dist. Rebuild the installer payload in this invocation, then bind the Docker
# input to the freshly generated package manifest and current Git commit.
CARGO="$cargo_bin" RUSTC="$rustc_bin" \
    BORONDNS_PACKAGE_TARGET="$target_triple" \
    BORONDNS_PACKAGE_ALLOW_DYNAMIC="$allow_dynamic" \
    BORONDNS_DIST_DIR="$private_installer_dist_dir" \
    BORONDNS_PACKAGE_NAME="$package_name" \
    "$repo_root/scripts/package-installer.sh"

installer_manifest="$installer_root/manifest.txt"
[[ -f "$installer_manifest" && ! -L "$installer_manifest" && -x "$docker_binary_asset" && ! -L "$docker_binary_asset" ]] || {
    printf 'fresh installer payload is incomplete or unsafe\n' >&2
    exit 1
}

manifest_value() {
    local key="$1"
    local expected_pattern="$2"
    local count value
    count="$(awk -F= -v key="$key" '$1 == key { count += 1 } END { print count + 0 }' "$installer_manifest")"
    [[ "$count" == 1 ]] || {
        printf 'installer manifest must contain exactly one %s entry\n' "$key" >&2
        return 1
    }
    value="$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$installer_manifest")"
    [[ "$value" =~ $expected_pattern ]] || {
        printf 'installer manifest contains invalid %s\n' "$key" >&2
        return 1
    }
    printf '%s\n' "$value"
}

manifest_commit="$(manifest_value commit '^[0-9a-f]{12}$')"
manifest_version="$(manifest_value version '^[0-9]+\.[0-9]+\.[0-9]+([-.+][A-Za-z0-9.-]+)?$')"
manifest_target="$(manifest_value target '^[A-Za-z0-9_.-]+$')"
manifest_binary_sha256="$(manifest_value binary_sha256 '^[0-9a-f]{64}$')"
manifest_source_clean="$(manifest_value source_clean '^[01]$')"
manifest_release_eligible="$(manifest_value release_eligible '^[01]$')"
manifest_dirty_override="$(manifest_value dirty_source_override '^[01]$')"
manifest_dynamic_override="$(manifest_value dynamic_link_override '^[01]$')"
[[ "$manifest_commit" == "$commit" && "$manifest_version" == "$version" && "$manifest_target" == "$target_triple" ]] || {
    printf 'fresh installer manifest does not bind the current Docker package source\n' >&2
    exit 1
}
[[ "$manifest_source_clean" == "$source_clean" && "$manifest_release_eligible" == "$release_eligible" &&
    "$manifest_dirty_override" == "$allow_dirty_non_release" &&
    "$manifest_dynamic_override" == "$allow_dynamic" ]] || {
    printf 'fresh installer manifest does not bind Docker package source cleanliness\n' >&2
    exit 1
}
[[ "$(sha256_file "$docker_binary_asset" | awk '{ print $1 }')" == "$manifest_binary_sha256" ]] || {
    printf 'Docker binary does not match the freshly generated installer manifest\n' >&2
    exit 1
}

mkdir -p "$run_docker_context"
install -m 0755 "$docker_binary_asset" "$run_docker_context/borondns"
install -m 0644 "$repo_root/config/borondns.example.toml" "$run_docker_context/borondns.example.toml"

docker build \
    --iidfile "$image_iid_file" \
    --build-arg "ALPINE_BASE_IMAGE=$alpine_base_image" \
    --build-arg "VERSION=$version" \
    --build-arg "VCS_REF=$commit" \
    --build-arg "BUILD_DATE=$build_date" \
    --build-arg "SOURCE_CLEAN=$source_clean" \
    --build-arg "RELEASE_ELIGIBLE=$release_eligible" \
    -f "$repo_root/packaging/docker/Dockerfile" \
    "$run_docker_context"

[[ -f "$image_iid_file" && ! -L "$image_iid_file" ]] || {
    printf 'Docker build did not publish an immutable image ID\n' >&2
    exit 1
}
image_id="$(<"$image_iid_file")"
rm -f -- "$image_iid_file"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'Docker build returned an invalid immutable image ID: %s\n' "$image_id" >&2
    exit 1
}
docker image inspect "$image_id" >"$run_image_inspect"

# The release archive promises that a fresh `docker load` publishes this exact
# tag. Activate it only while holding the canonical daemon-tag lock, preserve
# the previous generation for EXIT rollback, and save by the reviewed tag while
# continuing to authenticate the archive by immutable config/image ID below.
docker_image_lock_fd=""
package_acquire_docker_image_lock "$image_ref" docker_image_lock_fd
[[ -n "$docker_image_lock_fd" ]]
if prior_image_id="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)"; then
    [[ "$prior_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'existing Docker image tag has an invalid immutable image ID: %s\n' "$image_ref" >&2
        exit 1
    }
else
    prior_image_id=""
fi
docker_tag_activation_attempted=1
docker image tag "$image_id" "$image_ref"
tag_image_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"
[[ "$tag_image_id" == "$image_id" ]] || {
    printf 'Docker image tag activation failed: expected=%s actual=%s\n' "$image_id" "$tag_image_id" >&2
    exit 1
}

docker save "$image_ref" | xz -T0 -c >"$run_image_archive"
(
    cd "$run_root"
    sha256_file "$(basename "$run_image_archive")" >"$(basename "$run_image_archive").sha256"
)

archive_image_id="$(python3 "$repo_root/scripts/verify-docker-archive.py" "$run_image_archive")"
IFS=$'\t' read -r archive_image_id archive_image_ref <<<"$archive_image_id"
[[ "$archive_image_id" == "$image_id" ]] || {
    printf 'saved Docker archive identity mismatch: expected=%s actual=%s\n' "$image_id" "$archive_image_id" >&2
    exit 1
}
[[ "$archive_image_ref" == "$image_ref" ]] || {
    printf 'saved Docker archive tag mismatch: expected=%s actual=%s\n' \
        "$image_ref" "$archive_image_ref" >&2
    exit 1
}
package_verify_docker_archive_bundle "$run_image_archive" "$run_image_archive.sha256" \
    "$repo_root/scripts/verify-docker-archive.py" "$image_id" "$image_ref" || {
    printf 'saved Docker archive/checksum bundle failed content validation\n' >&2
    exit 1
}
loaded_images=""
package_load_verified_docker_archive "$run_image_archive" \
    "$repo_root/scripts/verify-docker-archive.py" \
    "$repo_root/scripts/release-api-supervisor.py" loaded_images
docker image inspect "$image_id" >/dev/null
loaded_tag_image_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"
[[ "$loaded_tag_image_id" == "$image_id" ]] || {
    printf 'reloaded Docker archive tag identity mismatch: expected=%s actual=%s\n' \
        "$image_id" "$loaded_tag_image_id" >&2
    exit 1
}
[[ -n "$loaded_images" ]] || {
    printf 'Docker archive reload returned no image identity\n' >&2
    exit 1
}

{
    printf 'name=%s\n' "$package_name"
    printf 'version=%s\n' "$version"
    printf 'target=%s\n' "$target_triple"
    printf 'image_ref=%s\n' "$image_ref"
    printf 'canonical_image_ref=%s\n' "$(package_canonical_docker_image_ref "$image_ref")"
    printf 'base_image=%s\n' "$alpine_base_image"
    printf 'base_image_digest=%s\n' "$alpine_base_digest"
    printf 'commit=%s\n' "$commit"
    printf 'source_clean=%s\n' "$source_clean"
    printf 'release_eligible=%s\n' "$release_eligible"
    printf 'dirty_source_override=%s\n' "$allow_dirty_non_release"
    printf 'dynamic_link_override=%s\n' "$allow_dynamic"
    printf 'built_at=%s\n' "$build_date"
    printf 'archive=%s\n' "$(basename "$image_archive")"
    sha256_file "$run_image_archive" | awk '{print "archive_sha256="$1}'
    docker image inspect \
        --format 'image_id={{.Id}}
image_size_bytes={{.Size}}' \
        "$image_id"
} >"$run_image_manifest"

dist_publication_lock_fd=""
installer_publication_lock_fd=""
# The daemon tag is shared across targets, output roots, and repository aliases.
# Acquire its canonical global lock before the per-output locks and retain every
# descriptor through EXIT-trap rollback or commit cleanup.
package_acquire_publication_lock "$dist_dir" "$archive_root-docker" dist_publication_lock_fd
package_acquire_publication_lock "$docker_installer_dist_dir" "$archive_root" installer_publication_lock_fd
[[ -n "$docker_image_lock_fd" && -n "$dist_publication_lock_fd" && -n "$installer_publication_lock_fd" ]]

verify_source_identity "terminal publication"
package_verify_docker_archive_bundle "$run_image_archive" "$run_image_archive.sha256" \
    "$repo_root/scripts/verify-docker-archive.py" "$image_id" "$image_ref" || {
    printf 'Docker archive/checksum changed before terminal publication\n' >&2
    exit 1
}

# Copy the successful nested package into a private directory on the requested
# installer-input filesystem before any stable name is replaced.
cp -a -- "$private_installer_dist_dir/." "$installer_publish_root/"
for installer_name in \
    "$archive_root" "$archive_root.tar.xz" "$archive_root.tar.xz.sha256" \
    "$archive_root.bin" "$archive_root.bin.sha256" \
    "$archive_root-oxide-gun.bin" "$archive_root-oxide-gun.bin.sha256"; do
    package_publish_candidate "$installer_publish_root/$installer_name" \
        "$docker_installer_dist_dir/$installer_name" "$docker_installer_dist_dir" 'Docker installer input'
done
package_publish_candidate "$run_docker_context" "$docker_context" "$dist_dir" 'Docker build context'
package_publish_candidate "$run_image_archive" "$image_archive" "$dist_dir" 'Docker image archive'
package_publish_candidate "$run_image_archive.sha256" "$image_archive.sha256" "$dist_dir" 'Docker image checksum'
package_verify_docker_archive_bundle "$image_archive" "$image_archive.sha256" \
    "$repo_root/scripts/verify-docker-archive.py" "$image_id" "$image_ref" || {
    printf 'published Docker archive/checksum failed content validation\n' >&2
    exit 1
}
package_publish_candidate "$run_image_manifest" "$image_manifest" "$dist_dir" 'Docker image manifest'
package_publish_candidate "$run_image_inspect" "$image_inspect" "$dist_dir" 'Docker image inspection'
package_verify_docker_archive_bundle "$image_archive" "$image_archive.sha256" \
    "$repo_root/scripts/verify-docker-archive.py" "$image_id" "$image_ref" || {
    printf 'Docker archive/checksum changed before publication commit\n' >&2
    exit 1
}
tag_image_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"
[[ "$tag_image_id" == "$image_id" ]] || {
    printf 'Docker image tag promotion failed: expected=%s actual=%s\n' "$image_id" "$tag_image_id" >&2
    exit 1
}
package_commit_publication

printf 'created %s\n' "$image_archive"
printf 'created %s\n' "$image_archive.sha256"
printf 'created %s\n' "$image_manifest"
printf 'created %s\n' "$image_inspect"
