#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/package-common.sh"
# Release artifact modes must not depend on a caller's permissive umask.
umask 022
target_triple="${BORONDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
dist_dir="${BORONDNS_DIST_DIR:-$repo_root/target/dist}"
cargo_bin="${CARGO:-}"
rustc_bin="${RUSTC:-}"
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
    printf 'dynamic-link packaging override is forbidden in GitHub Actions release paths\n' >&2
    exit 1
fi
if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then
    printf 'dirty-source packaging override is forbidden in GitHub Actions release paths\n' >&2
    exit 1
fi

missing=()
for tool in rustup tar xz python3 flock; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
[[ -n "$cargo_bin" ]] || cargo_bin="$(rustup which cargo 2>/dev/null)"
[[ -n "$rustc_bin" ]] || rustc_bin="$(rustup which rustc 2>/dev/null)"
cargo_bin="$(realpath -e "$cargo_bin")" || {
    printf 'cannot resolve verified cargo executable\n' >&2
    exit 1
}
rustc_bin="$(realpath -e "$rustc_bin")" || {
    printf 'cannot resolve verified rustc executable\n' >&2
    exit 1
}
[[ -x "$cargo_bin" && -f "$cargo_bin" && -x "$rustc_bin" && -f "$rustc_bin" ]] || {
    printf 'verified Rust tool paths must be executable regular files\n' >&2
    exit 1
}
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    missing+=("sha256sum-or-shasum")
fi
if ((${#missing[@]} > 0)); then
    printf 'missing required packaging tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

source_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
    printf 'installer packaging requires a Git-bound source checkout\n' >&2
    exit 1
}
source_epoch="$(git -C "$repo_root" show -s --format=%ct "$source_commit" 2>/dev/null)" || {
    printf 'cannot determine installer packaging source timestamp\n' >&2
    exit 1
}
[[ "$source_epoch" =~ ^[0-9]+$ ]] || {
    printf 'installer packaging source timestamp is invalid\n' >&2
    exit 1
}
source_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no 2>/dev/null)" || {
    printf 'cannot determine installer packaging source status\n' >&2
    exit 1
}
source_clean=1
release_eligible=1
if [[ "$allow_dynamic" == 1 ]]; then
    release_eligible=0
    printf 'warning: dynamic-link packaging override enabled; artifacts are non-release diagnostics\n' >&2
fi
if [[ -n "$source_status" ]]; then
    source_clean=0
    release_eligible=0
    if [[ "$allow_dirty_non_release" != 1 ]]; then
        printf 'refusing installer packaging from dirty or untracked source:\n%s\n' "$source_status" >&2
        exit 1
    fi
    printf 'warning: dirty-source packaging override enabled; artifacts are non-release diagnostics\n' >&2
fi

verify_source_identity() {
    local boundary="$1"
    local actual_commit actual_status
    actual_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
        printf 'cannot resolve installer packaging source at %s\n' "$boundary" >&2
        return 1
    }
    actual_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no 2>/dev/null)" || {
        printf 'cannot determine installer packaging source status at %s\n' "$boundary" >&2
        return 1
    }
    if [[ "$actual_commit" != "$source_commit" || "$actual_status" != "$source_status" ]]; then
        printf 'installer packaging source changed at %s\n' "$boundary" >&2
        return 1
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        return 1
    fi
}
verified_cargo_sha256="$(sha256_file "$cargo_bin" | awk '{ print $1 }')"
verified_rustc_sha256="$(sha256_file "$rustc_bin" | awk '{ print $1 }')"
verified_rust_version="$("$rustc_bin" --version)"
build_timestamp="$(
    python3 - "$source_epoch" <<'PY'
import datetime
import sys

print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"

version="$(env RUSTC="$rustc_bin" "$cargo_bin" metadata --no-deps --locked --format-version 1 \
    --manifest-path "$repo_root/Cargo.toml" |
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
commit="${source_commit:0:12}"
archive_root="$package_name-$version-$target_triple"
if [[ "$source_clean" != 1 ]]; then
    archive_root="$archive_root-nonrelease-dirty"
elif [[ "$allow_dynamic" == 1 ]]; then
    archive_root="$archive_root-nonrelease-dynamic"
fi
package_require_safe_component package-version "$version" '^[0-9][A-Za-z0-9.+-]*$'
package_require_safe_component archive-root "$archive_root"
dist_dir="$(package_canonical_output_root BORONDNS_DIST_DIR "$dist_dir")"
archive="$(package_safe_child_path "$dist_dir" "$archive_root.tar.xz" 'installer archive')"
binary_asset="$(package_safe_child_path "$dist_dir" "$archive_root.bin" 'installer binary asset')"
boron_gun_asset="$(package_safe_child_path "$dist_dir" "$archive_root-boron-gun.bin" 'installer tool binary asset')"
staging="$(package_safe_child_path "$dist_dir" "$archive_root" 'installer staging directory')"
run_root=""
package_publication_initialized=0

cleanup_failed_publication() {
    local status=$?
    trap - EXIT
    package_begin_signal_cleanup
    if [[ "$package_publication_initialized" == 1 ]]; then
        package_cleanup_publication "$status" || status=$?
    elif [[ -n "$run_root" && (-e "$run_root" || -L "$run_root") ]]; then
        if ! package_capture_cleanup_root "$run_root" "installer package run root" ||
            ! package_remove_captured_cleanup_root "$run_root" "installer package run root"; then
            status=74
        fi
    fi
    exit "$status"
}
trap cleanup_failed_publication EXIT
trap 'package_signal_handler 130' INT
trap 'package_signal_handler 143' TERM
trap 'package_signal_handler 129' HUP

# Install EXIT ownership before allocating the private tree. Assign the full
# candidate pathname before atomic mkdir so termination can never strand a
# mktemp-created directory whose name the parent shell has not received yet.
for run_root_attempt in {1..128}; do
    run_root="$dist_dir/.${archive_root}.package.$$.$RANDOM.$run_root_attempt"
    if mkdir -m 0700 -- "$run_root" 2>/dev/null; then
        break
    fi
    run_root=""
done
[[ -n "$run_root" && -d "$run_root" && ! -L "$run_root" ]] || {
    printf 'cannot allocate private installer package run root under %s\n' "$dist_dir" >&2
    exit 1
}
package_capture_cleanup_root "$run_root" "installer package run root"

run_staging="$run_root/$archive_root"
run_archive="$run_root/$archive_root.tar.xz"
run_binary_asset="$run_root/$archive_root.bin"
run_boron_gun_asset="$run_root/$archive_root-boron-gun.bin"
run_build_target="$run_root/build-target"
run_build_home="$run_root/hermetic-home"
run_cargo_home="$run_root/hermetic-cargo-home"
toolchain_bin="$(dirname "$rustc_bin")"
toolchain_root="$(dirname "$toolchain_bin")"
mkdir -m 0700 "$run_build_target" "$run_build_home" "$run_cargo_home"
release_encoded_rustflags="$(package_release_encoded_rustflags \
    "$repo_root" "$run_cargo_home" "$run_build_target" "$toolchain_root")"
package_publication_reset "$run_root"
package_publication_initialized=1

verify_source_identity "before build"

if ! rustup target list --installed | grep -Fx "$target_triple" >/dev/null 2>&1; then
    rustup target add "$target_triple"
fi

(
    cd "$repo_root"
    [[ "$(sha256_file "$cargo_bin" | awk '{ print $1 }')" == "$verified_cargo_sha256" ]]
    [[ "$(sha256_file "$rustc_bin" | awk '{ print $1 }')" == "$verified_rustc_sha256" ]]
    env -i HOME="$run_build_home" CARGO_HOME="$run_cargo_home" \
        PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \
        CARGO_ENCODED_RUSTFLAGS="$release_encoded_rustflags" \
        BORONDNS_BUILD_COMMIT="$commit" \
        BORONDNS_BUILD_RUST_VERSION="$verified_rust_version" \
        BORONDNS_BUILD_TIMESTAMP="$build_timestamp" \
        SOURCE_DATE_EPOCH="$source_epoch" CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$run_build_target" "$cargo_bin" build --locked --release \
        --target-dir "$run_build_target" --target "$target_triple" -p borondns-cli
    env -i HOME="$run_build_home" CARGO_HOME="$run_cargo_home" \
        PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \
        CARGO_ENCODED_RUSTFLAGS="$release_encoded_rustflags" \
        BORONDNS_BUILD_COMMIT="$commit" \
        BORONDNS_BUILD_RUST_VERSION="$verified_rust_version" \
        BORONDNS_BUILD_TIMESTAMP="$build_timestamp" \
        SOURCE_DATE_EPOCH="$source_epoch" CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$run_build_target" "$cargo_bin" build --locked --release \
        --target-dir "$run_build_target" --target "$target_triple" -p boron-gun --features xdp
    [[ "$(sha256_file "$cargo_bin" | awk '{ print $1 }')" == "$verified_cargo_sha256" ]]
    [[ "$(sha256_file "$rustc_bin" | awk '{ print $1 }')" == "$verified_rustc_sha256" ]]
)
verify_source_identity "after build"

binary="$run_build_target/$target_triple/release/borondns"
boron_gun_binary="$run_build_target/$target_triple/release/boron-gun"
[[ -x "$binary" ]] || {
    printf 'missing built binary: %s\n' "$binary" >&2
    exit 1
}
[[ -x "$boron_gun_binary" ]] || {
    printf 'missing built binary: %s\n' "$boron_gun_binary" >&2
    exit 1
}

mkdir -p "$run_staging/bin" "$run_staging/share/borondns"
install -m 0755 "$binary" "$run_staging/bin/borondns"
install -m 0755 "$boron_gun_binary" "$run_staging/bin/boron-gun"
install -m 0755 "$repo_root/packaging/installer/install.sh" "$run_staging/install.sh"
cp -R "$repo_root/packaging/installer/share/borondns/." "$run_staging/share/borondns/"
install -m 0644 "$repo_root/packaging/installer/README.install.md" "$run_staging/README.install.md"
install -m 0644 "$repo_root/config/borondns.example.toml" "$run_staging/share/borondns/borondns.example.toml"
install -m 0644 "$repo_root/LICENSE-MIT" "$run_staging/LICENSE-MIT"
install -m 0644 "$repo_root/LICENSE-APACHE" "$run_staging/LICENSE-APACHE"

{
    printf 'name=%s\n' "$package_name"
    printf 'version=%s\n' "$version"
    printf 'target=%s\n' "$target_triple"
    printf 'commit=%s\n' "$commit"
    printf 'source_clean=%s\n' "$source_clean"
    printf 'release_eligible=%s\n' "$release_eligible"
    printf 'dirty_source_override=%s\n' "$allow_dirty_non_release"
    printf 'dynamic_link_override=%s\n' "$allow_dynamic"
    printf 'built_at=%s\n' "$build_timestamp"
    printf 'rust_version=%s\n' "$verified_rust_version"
    printf 'cargo_executable=cargo\n'
    sha256_file "$cargo_bin" | awk '{print "cargo_sha256="$1}'
    printf 'rustc_executable=rustc\n'
    sha256_file "$rustc_bin" | awk '{print "rustc_sha256="$1}'
    printf 'binary=bin/borondns\n'
    printf 'binary_features=default\n'
    printf 'tool_binary=bin/boron-gun\n'
    printf 'tool_binary_features=xdp\n'
    sha256_file "$run_staging/install.sh" | awk '{print "installer_sha256="$1}'
    sha256_file "$run_staging/bin/borondns" | awk '{print "binary_sha256="$1}'
    sha256_file "$run_staging/bin/boron-gun" | awk '{print "tool_binary_sha256="$1}'
    sha256_file "$run_staging/share/borondns/systemd/borondns.service" |
        awk '{print "systemd_template_sha256="$1}'
    sha256_file "$run_staging/share/borondns/openrc/borondns" |
        awk '{print "openrc_template_sha256="$1}'
    sha256_file "$run_staging/README.install.md" | awk '{print "readme_sha256="$1}'
} >"$run_staging/manifest.txt"

if command -v file >/dev/null 2>&1; then
    (
        cd "$run_staging"
        file bin/borondns
        file bin/boron-gun
    ) >"$run_staging/file.txt"
else
    printf 'file not available\n' >"$run_staging/file.txt"
fi

static_link_confirmed() {
    local checked_binary="$1"
    local ldd_file="$2"
    local file_report="$3"
    local checked_label="${checked_binary#"$run_staging/"}"
    if grep -Eiq 'not a dynamic executable|statically linked' "$ldd_file"; then
        return 0
    fi
    if [[ -f "$file_report" ]] && grep -F "$checked_label" "$file_report" | grep -Eiq 'statically linked|static-pie linked'; then
        return 0
    fi
    return 1
}

if command -v ldd >/dev/null 2>&1; then
    (cd "$run_staging" && ldd bin/borondns) >"$run_staging/ldd-borondns.txt" 2>&1 || true
    (cd "$run_staging" && ldd bin/boron-gun) >"$run_staging/ldd-boron-gun.txt" 2>&1 || true
    {
        printf '== bin/borondns ==\n'
        cat "$run_staging/ldd-borondns.txt"
        printf '\n== bin/boron-gun ==\n'
        cat "$run_staging/ldd-boron-gun.txt"
    } >"$run_staging/ldd.txt"
else
    printf 'ldd not available\n' >"$run_staging/ldd-borondns.txt"
    printf 'ldd not available\n' >"$run_staging/ldd-boron-gun.txt"
    printf 'ldd not available\n' >"$run_staging/ldd.txt"
fi

for checked_binary in "$run_staging/bin/borondns" "$run_staging/bin/boron-gun"; do
    ldd_report="$run_staging/ldd-$(basename "$checked_binary").txt"
    if static_link_confirmed "$checked_binary" "$ldd_report" "$run_staging/file.txt"; then
        continue
    fi
    if [[ "$target_triple" == "x86_64-unknown-linux-musl" && "$allow_dynamic" != "1" ]]; then
        printf 'error: static-link verification failed for release target %s binary %s\n' "$target_triple" "$checked_binary" >&2
        printf 'inspect %s and %s\n' "$run_staging/ldd.txt" "$run_staging/file.txt" >&2
        printf 'set BORONDNS_PACKAGE_ALLOW_DYNAMIC=1 only for non-release developer artifacts\n' >&2
        exit 1
    fi
    printf 'warning: static linking not confirmed for %s; inspect %s and %s\n' "$checked_binary" "$run_staging/ldd.txt" "$run_staging/file.txt" >&2
done

# Package modes must not inherit the caller's umask.  Preserve only the
# reviewed executable bit from installed inputs while making every directory
# traversable and every ordinary data file readable in the published archive.
if find "$run_staging" -mindepth 1 ! -type d ! -type f -print -quit | grep -q .; then
    printf 'installer staging tree contains an unsupported file type\n' >&2
    exit 1
fi
find "$run_staging" -type d -exec chmod 0755 {} +
find "$run_staging" -type f -perm /0111 -exec chmod 0755 {} +
find "$run_staging" -type f ! -perm /0111 -exec chmod 0644 {} +

verify_source_identity "before artifact publication"

install -m 0755 "$binary" "$run_binary_asset"
install -m 0755 "$boron_gun_binary" "$run_boron_gun_asset"
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$run_root" -cJf "$run_archive" "$archive_root"
(
    cd "$run_root"
    sha256_file "$(basename "$run_archive")" >"$(basename "$run_archive").sha256"
    sha256_file "$(basename "$run_binary_asset")" >"$(basename "$run_binary_asset").sha256"
    sha256_file "$(basename "$run_boron_gun_asset")" >"$(basename "$run_boron_gun_asset").sha256"
)
publication_lock_fd=""
package_acquire_publication_lock "$dist_dir" "$archive_root" publication_lock_fd
[[ -n "$publication_lock_fd" ]]
verify_source_identity "terminal publication"

package_publish_candidate "$run_staging" "$staging" "$dist_dir" 'installer staging directory'
package_publish_candidate "$run_archive" "$archive" "$dist_dir" 'installer archive'
package_publish_candidate "$run_archive.sha256" "$archive.sha256" "$dist_dir" 'installer archive checksum'
package_publish_candidate "$run_binary_asset" "$binary_asset" "$dist_dir" 'installer binary asset'
package_publish_candidate "$run_binary_asset.sha256" "$binary_asset.sha256" "$dist_dir" 'installer binary checksum'
package_publish_candidate "$run_boron_gun_asset" "$boron_gun_asset" "$dist_dir" 'installer tool binary asset'
package_publish_candidate "$run_boron_gun_asset.sha256" "$boron_gun_asset.sha256" "$dist_dir" 'installer tool binary checksum'
package_commit_publication
package_remove_captured_cleanup_root "$run_root" "installer package run root"
PACKAGE_PUBLICATION_RETAIN_ROOT=""

printf 'created %s\n' "$archive"
printf 'created %s\n' "$archive.sha256"
printf 'created %s\n' "$binary_asset"
printf 'created %s\n' "$binary_asset.sha256"
printf 'created %s\n' "$boron_gun_asset"
printf 'created %s\n' "$boron_gun_asset.sha256"
