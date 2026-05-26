#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
package_name="${OXIDEDNS_PACKAGE_NAME:-oxidedns}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
commit="$(git -C "$repo_root" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"
build_date="${OXIDEDNS_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
archive_root="$package_name-$version-$target_triple"
binary_asset="$dist_dir/$archive_root.bin"
image_ref="${OXIDEDNS_DOCKER_IMAGE_REF:-$package_name:$version}"
alpine_version="${OXIDEDNS_DOCKER_ALPINE_VERSION:-3.22}"
docker_context="$dist_dir/$archive_root-docker-context"
image_archive="$dist_dir/$archive_root-docker-image.tar.xz"
image_manifest="$dist_dir/$archive_root-docker-image.manifest.txt"
image_inspect="$dist_dir/$archive_root-docker-image.inspect.json"

missing=()
for tool in cargo docker python3 xz; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required Docker packaging tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        return 1
    fi
}

if ! docker info >/dev/null 2>&1; then
    printf 'Docker daemon is unavailable\n' >&2
    exit 1
fi

if [[ ! -x "$binary_asset" ]]; then
    "$repo_root/scripts/package-installer.sh"
fi

rm -rf "$docker_context"
mkdir -p "$docker_context"
install -m 0755 "$binary_asset" "$docker_context/oxidedns"
install -m 0644 "$repo_root/config/oxidedns.example.toml" "$docker_context/oxidedns.example.toml"

docker build \
    --build-arg "ALPINE_VERSION=$alpine_version" \
    --build-arg "VERSION=$version" \
    --build-arg "VCS_REF=$commit" \
    --build-arg "BUILD_DATE=$build_date" \
    -f "$repo_root/packaging/docker/Dockerfile" \
    -t "$image_ref" \
    "$docker_context"

docker image inspect "$image_ref" >"$image_inspect"

rm -f "$image_archive" "$image_archive.sha256" "$image_manifest"
docker save "$image_ref" | xz -T0 -c >"$image_archive"
(
    cd "$dist_dir"
    sha256_file "$(basename "$image_archive")" >"$(basename "$image_archive").sha256"
)

{
    printf 'name=%s\n' "$package_name"
    printf 'version=%s\n' "$version"
    printf 'target=%s\n' "$target_triple"
    printf 'image_ref=%s\n' "$image_ref"
    printf 'base_image=%s\n' "alpine:$alpine_version"
    printf 'commit=%s\n' "$commit"
    printf 'built_at=%s\n' "$build_date"
    printf 'archive=%s\n' "$(basename "$image_archive")"
    sha256_file "$image_archive" | awk '{print "archive_sha256="$1}'
    docker image inspect \
        --format 'image_id={{.Id}}
image_size_bytes={{.Size}}' \
        "$image_ref"
} >"$image_manifest"

printf 'created %s\n' "$image_archive"
printf 'created %s\n' "$image_archive.sha256"
printf 'created %s\n' "$image_manifest"
printf 'created %s\n' "$image_inspect"
