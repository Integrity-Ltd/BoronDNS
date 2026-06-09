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
oxide_gun_asset="$dist_dir/$archive_root-oxide-gun.bin"

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
    cargo build --locked --release --target "$target_triple" -p oxidedns-cli --features af-xdp
    cargo build --locked --release --target "$target_triple" -p oxide-gun --features xdp
)

binary="$repo_root/target/$target_triple/release/oxidedns"
oxide_gun_binary="$repo_root/target/$target_triple/release/oxide-gun"
[[ -x "$binary" ]] || {
    printf 'missing built binary: %s\n' "$binary" >&2
    exit 1
}
[[ -x "$oxide_gun_binary" ]] || {
    printf 'missing built binary: %s\n' "$oxide_gun_binary" >&2
    exit 1
}

rm -rf "$staging"
mkdir -p "$staging/bin" "$staging/share/oxidedns"
install -m 0755 "$binary" "$staging/bin/oxidedns"
install -m 0755 "$oxide_gun_binary" "$staging/bin/oxide-gun"
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
    printf 'binary_features=af-xdp\n'
    printf 'tool_binary=bin/oxide-gun\n'
    printf 'tool_binary_features=xdp\n'
    if sha256_file "$staging/bin/oxidedns" >/dev/null 2>&1; then
        sha256_file "$staging/bin/oxidedns" | awk '{print "binary_sha256="$1}'
    fi
    if sha256_file "$staging/bin/oxide-gun" >/dev/null 2>&1; then
        sha256_file "$staging/bin/oxide-gun" | awk '{print "tool_binary_sha256="$1}'
    fi
} >"$staging/manifest.txt"

if command -v file >/dev/null 2>&1; then
    {
        file "$staging/bin/oxidedns"
        file "$staging/bin/oxide-gun"
    } >"$staging/file.txt"
else
    printf 'file not available\n' >"$staging/file.txt"
fi

static_link_confirmed() {
    local checked_binary="$1"
    local ldd_file="$2"
    local file_report="$3"
    if grep -Eiq 'not a dynamic executable|statically linked' "$ldd_file"; then
        return 0
    fi
    if [[ -f "$file_report" ]] && grep -F "$checked_binary" "$file_report" | grep -Eiq 'statically linked|static-pie linked'; then
        return 0
    fi
    return 1
}

if command -v ldd >/dev/null 2>&1; then
    ldd "$staging/bin/oxidedns" >"$staging/ldd-oxidedns.txt" 2>&1 || true
    ldd "$staging/bin/oxide-gun" >"$staging/ldd-oxide-gun.txt" 2>&1 || true
    {
        printf '== %s ==\n' "$staging/bin/oxidedns"
        cat "$staging/ldd-oxidedns.txt"
        printf '\n== %s ==\n' "$staging/bin/oxide-gun"
        cat "$staging/ldd-oxide-gun.txt"
    } >"$staging/ldd.txt"
else
    printf 'ldd not available\n' >"$staging/ldd-oxidedns.txt"
    printf 'ldd not available\n' >"$staging/ldd-oxide-gun.txt"
    printf 'ldd not available\n' >"$staging/ldd.txt"
fi

for checked_binary in "$staging/bin/oxidedns" "$staging/bin/oxide-gun"; do
    ldd_report="$staging/ldd-$(basename "$checked_binary").txt"
    if static_link_confirmed "$checked_binary" "$ldd_report" "$staging/file.txt"; then
        continue
    fi
    if [[ "$target_triple" == "x86_64-unknown-linux-musl" && "$allow_dynamic" != "1" ]]; then
        printf 'error: static-link verification failed for release target %s binary %s\n' "$target_triple" "$checked_binary" >&2
        printf 'inspect %s and %s\n' "$staging/ldd.txt" "$staging/file.txt" >&2
        printf 'set OXIDEDNS_PACKAGE_ALLOW_DYNAMIC=1 only for non-release developer artifacts\n' >&2
        exit 1
    fi
    printf 'warning: static linking not confirmed for %s; inspect %s and %s\n' "$checked_binary" "$staging/ldd.txt" "$staging/file.txt" >&2
done

rm -f "$archive" "$archive.sha256" "$binary_asset" "$binary_asset.sha256" "$oxide_gun_asset" "$oxide_gun_asset.sha256"
install -m 0755 "$binary" "$binary_asset"
install -m 0755 "$oxide_gun_binary" "$oxide_gun_asset"
tar -C "$dist_dir" -cJf "$archive" "$archive_root"
if sha256_file "$archive" >/dev/null 2>&1; then
    (
        cd "$dist_dir"
        sha256_file "$(basename "$archive")" >"$(basename "$archive").sha256"
        sha256_file "$(basename "$binary_asset")" >"$(basename "$binary_asset").sha256"
        sha256_file "$(basename "$oxide_gun_asset")" >"$(basename "$oxide_gun_asset").sha256"
    )
fi

printf 'created %s\n' "$archive"
[[ -f "$archive.sha256" ]] && printf 'created %s\n' "$archive.sha256"
printf 'created %s\n' "$binary_asset"
[[ -f "$binary_asset.sha256" ]] && printf 'created %s\n' "$binary_asset.sha256"
printf 'created %s\n' "$oxide_gun_asset"
[[ -f "$oxide_gun_asset.sha256" ]] && printf 'created %s\n' "$oxide_gun_asset.sha256"
