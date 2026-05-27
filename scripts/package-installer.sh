#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
package_name="${OXIDEDNS_PACKAGE_NAME:-oxidedns}"
allow_dynamic="${OXIDEDNS_PACKAGE_ALLOW_DYNAMIC:-0}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
commit="$(git -C "$repo_root" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"
archive_root="$package_name-$version-$target_triple"
staging="$dist_dir/$archive_root"
archive="$dist_dir/$archive_root.tar.xz"
binary_asset="$dist_dir/$archive_root.bin"

missing=()
for tool in cargo rustup tar xz python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required packaging tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

mkdir -p "$dist_dir"

if ! rustup target list --installed | grep -Fx "$target_triple" >/dev/null 2>&1; then
    rustup target add "$target_triple"
fi

(
    cd "$repo_root"
    cargo build --locked --release --target "$target_triple" -p oxidedns-cli
)

binary="$repo_root/target/$target_triple/release/oxidedns"
[[ -x "$binary" ]] || {
    printf 'missing built binary: %s\n' "$binary" >&2
    exit 1
}

rm -rf "$staging"
mkdir -p "$staging/bin" "$staging/share/oxidedns"
install -m 0755 "$binary" "$staging/bin/oxidedns"
install -m 0755 "$repo_root/packaging/installer/install.sh" "$staging/install.sh"
cp -R "$repo_root/packaging/installer/share/oxidedns/." "$staging/share/oxidedns/"
install -m 0644 "$repo_root/packaging/installer/README.install.md" "$staging/README.install.md"
install -m 0644 "$repo_root/config/oxidedns.example.toml" "$staging/share/oxidedns/oxidedns.example.toml"
install -m 0644 "$repo_root/LICENSE-MIT" "$staging/LICENSE-MIT"
install -m 0644 "$repo_root/LICENSE-APACHE" "$staging/LICENSE-APACHE"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        return 1
    fi
}

{
    printf 'name=%s\n' "$package_name"
    printf 'version=%s\n' "$version"
    printf 'target=%s\n' "$target_triple"
    printf 'commit=%s\n' "$commit"
    printf 'built_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'binary=bin/oxidedns\n'
    if sha256_file "$staging/bin/oxidedns" >/dev/null 2>&1; then
        sha256_file "$staging/bin/oxidedns" | awk '{print "binary_sha256="$1}'
    fi
} >"$staging/manifest.txt"

if command -v file >/dev/null 2>&1; then
    file "$staging/bin/oxidedns" >"$staging/file.txt"
else
    printf 'file not available\n' >"$staging/file.txt"
fi

static_link_confirmed=0
if command -v ldd >/dev/null 2>&1; then
    ldd "$staging/bin/oxidedns" >"$staging/ldd.txt" 2>&1 || true
else
    printf 'ldd not available\n' >"$staging/ldd.txt"
fi

if grep -Eiq 'not a dynamic executable|statically linked' "$staging/ldd.txt"; then
    static_link_confirmed=1
elif [[ -f "$staging/file.txt" ]] && grep -Eiq 'statically linked|static-pie linked' "$staging/file.txt"; then
    static_link_confirmed=1
fi

if [[ "$target_triple" == "x86_64-unknown-linux-musl" && "$static_link_confirmed" != "1" && "$allow_dynamic" != "1" ]]; then
    printf 'error: static-link verification failed for release target %s\n' "$target_triple" >&2
    printf 'inspect %s and %s\n' "$staging/ldd.txt" "$staging/file.txt" >&2
    printf 'set OXIDEDNS_PACKAGE_ALLOW_DYNAMIC=1 only for non-release developer artifacts\n' >&2
    exit 1
fi

if [[ "$static_link_confirmed" != "1" ]]; then
    printf 'warning: static linking not confirmed for %s; inspect %s and %s\n' "$staging/bin/oxidedns" "$staging/ldd.txt" "$staging/file.txt" >&2
fi

rm -f "$archive" "$archive.sha256" "$binary_asset" "$binary_asset.sha256"
install -m 0755 "$binary" "$binary_asset"
tar -C "$dist_dir" -cJf "$archive" "$archive_root"
if sha256_file "$archive" >/dev/null 2>&1; then
    (
        cd "$dist_dir"
        sha256_file "$(basename "$archive")" >"$(basename "$archive").sha256"
        sha256_file "$(basename "$binary_asset")" >"$(basename "$binary_asset").sha256"
    )
fi

printf 'created %s\n' "$archive"
[[ -f "$archive.sha256" ]] && printf 'created %s\n' "$archive.sha256"
printf 'created %s\n' "$binary_asset"
[[ -f "$binary_asset.sha256" ]] && printf 'created %s\n' "$binary_asset.sha256"
