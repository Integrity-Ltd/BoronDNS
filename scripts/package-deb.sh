#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
umask 022

workspace_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)"
version="${BORONDNS_DEB_VERSION:-$workspace_version}"
revision="${BORONDNS_DEB_REVISION:-1}"
architecture="${BORONDNS_DEB_ARCHITECTURE:-amd64}"
dist_dir="${BORONDNS_DIST_DIR:-$repo_root/target/dist}"
borondns_bin="${BORONDNS_DEB_BORONDNS_BIN:-}"
boron_gun_bin="${BORONDNS_DEB_BORON_GUN_BIN:-}"
source_date_epoch="${SOURCE_DATE_EPOCH:-}"

[[ "$version" =~ ^[0-9][0-9A-Za-z.+:~-]*$ ]]
[[ "$revision" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]
[[ "$architecture" =~ ^[a-z0-9][a-z0-9-]*$ ]]
command -v dpkg-deb >/dev/null || {
    printf 'package-deb requires dpkg-deb (install dpkg-dev)\n' >&2
    exit 1
}
command -v gzip >/dev/null || {
    printf 'package-deb requires gzip\n' >&2
    exit 1
}

if [[ -z "$source_date_epoch" ]]; then
    source_date_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD)"
fi
[[ "$source_date_epoch" =~ ^[0-9]+$ ]]

if [[ -z "$borondns_bin" ]]; then
    candidates=("$dist_dir"/borondns-*-x86_64-unknown-linux-musl.bin)
    ((${#candidates[@]} == 1)) || {
        printf 'expected one packaged BoronDNS binary\n' >&2
        exit 1
    }
    borondns_bin="${candidates[0]}"
fi
if [[ -z "$boron_gun_bin" ]]; then
    candidates=("$dist_dir"/borondns-*-x86_64-unknown-linux-musl-boron-gun.bin)
    ((${#candidates[@]} == 1)) || {
        printf 'expected one packaged BoronGun binary\n' >&2
        exit 1
    }
    boron_gun_bin="${candidates[0]}"
fi
for binary in "$borondns_bin" "$boron_gun_bin"; do
    [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] || {
        printf 'Debian package input must be an executable regular file: %s\n' "$binary" >&2
        exit 1
    }
done

mkdir -p "$dist_dir"
dist_dir="$(realpath -e "$dist_dir")"
output="$dist_dir/borondns_${version}-${revision}_${architecture}.deb"
checksum="$output.sha256"
staging="$(mktemp -d "${TMPDIR:-/tmp}/borondns-deb.XXXXXXXX")"
trap 'rm -rf -- "$staging"' EXIT INT TERM HUP
chmod 0755 "$staging"

install -d -m 0755 \
    "$staging/DEBIAN" "$staging/usr/bin" "$staging/usr/lib/systemd/system" \
    "$staging/usr/share/doc/borondns/examples"
install -m 0755 "$borondns_bin" "$staging/usr/bin/borondns"
install -m 0755 "$boron_gun_bin" "$staging/usr/bin/boron-gun"
install -m 0644 "$repo_root/packaging/deb/borondns.service" \
    "$staging/usr/lib/systemd/system/borondns.service"
install -m 0644 "$repo_root/packaging/deb/README.Debian" \
    "$staging/usr/share/doc/borondns/README.Debian"
install -m 0644 "$repo_root/packaging/installer/README.install.md" \
    "$staging/usr/share/doc/borondns/README.install.md"
install -m 0644 "$repo_root/config/borondns.example.toml" \
    "$staging/usr/share/doc/borondns/examples/config.toml"
install -m 0644 "$repo_root/LICENSE-MIT" "$repo_root/LICENSE-APACHE" \
    "$staging/usr/share/doc/borondns/"
install -m 0644 "$repo_root/packaging/deb/copyright" \
    "$staging/usr/share/doc/borondns/copyright"
changelog_date="$(LC_ALL=C date --utc --date="@$source_date_epoch" \
    '+%a, %d %b %Y %H:%M:%S +0000')"
cat >"$staging/usr/share/doc/borondns/changelog.Debian" <<EOF
borondns (${version}-${revision}) stable; urgency=medium

  * Package the BoronDNS ${version} release.

 -- Tibor Dravecz <t.gthb+17@integrity.hu>  ${changelog_date}
EOF
gzip -n -9 "$staging/usr/share/doc/borondns/changelog.Debian"
for script in preinst postinst prerm postrm; do
    install -m 0755 "$repo_root/packaging/deb/$script" "$staging/DEBIAN/$script"
done

installed_size="$(du -sk "$staging/usr" | awk '{print $1}')"
cat >"$staging/DEBIAN/control" <<EOF
Package: borondns
Version: ${version}-${revision}
Architecture: ${architecture}
Maintainer: Tibor Dravecz <t.gthb+17@integrity.hu>
Installed-Size: ${installed_size}
Depends: adduser, init-system-helpers (>= 1.18~)
Section: net
Priority: optional
Homepage: https://github.com/Integrity-Ltd/BoronDNS
Description: high-performance secondary authoritative DNS server
 BoronDNS is a secondary-only authoritative DNS server with static MUSL
 executables. This package also includes the BoronGun load generator.
EOF

find "$staging" -print0 | xargs -0 touch --no-dereference --date="@$source_date_epoch"
rm -f -- "$output" "$checksum"
SOURCE_DATE_EPOCH="$source_date_epoch" dpkg-deb --root-owner-group \
    --build --uniform-compression -Zxz -z9 \
    "$staging" "$output"
(
    cd "$dist_dir"
    sha256sum -- "${output##*/}" >"${checksum##*/}"
)

printf '%s\n' "$output"
