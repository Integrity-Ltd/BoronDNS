#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/native-package-common.sh"
version="$(native_package_version "$repo_root")"
command -v docker >/dev/null || {
    printf 'skipping RPM lifecycle: Docker is unavailable\n'
    exit 0
}
docker info >/dev/null 2>&1 || {
    printf 'skipping RPM lifecycle: Docker daemon is unavailable\n'
    exit 0
}

workdir="$(mktemp -d "${TMPDIR:-/tmp}/borondns-rpm-test.XXXXXXXX")"
trap 'rm -rf -- "$workdir"' EXIT INT TERM HUP
mkdir -p "$workdir/bin" "$workdir/dist-r1" "$workdir/dist-r2"
# Keep Git/worktree metadata out of the minimal builder; the checkout version
# was validated above and each build receives its explicit matching tag.
mkdir -p "$workdir/source/scripts"
cp "$repo_root/Cargo.toml" "$repo_root/LICENSE-MIT" "$repo_root/LICENSE-APACHE" "$workdir/source/"
cp -R "$repo_root/packaging" "$repo_root/config" "$workdir/source/"
cp "$repo_root/scripts/package-rpm.sh" "$repo_root/scripts/native-package-common.sh" "$workdir/source/scripts/"
fedora_image="${BORONDNS_RPM_FEDORA_IMAGE:-fedora@sha256:99e203b80b1c3d8f7e161ec10a68fd02b081ef83a3963553e513c82846b97814}"
rocky_image="${BORONDNS_RPM_ROCKY_IMAGE:-rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6}"

cat >"$workdir/bin/borondns" <<EOF
#!/bin/sh
test "\${1:-}" != --version || echo 'borondns $version'
EOF
cat >"$workdir/bin/boron-gun" <<EOF
#!/bin/sh
test "\${1:-}" != --version || echo 'boron-gun $version'
EOF
chmod 0755 "$workdir/bin/borondns" "$workdir/bin/boron-gun"

build_package() {
    local image="$1" release="$2" output="$3"
    docker run --rm -e SOURCE_DATE_EPOCH=1700000000 \
        -e BORONDNS_RELEASE_TAG="v$version" \
        -e BORONDNS_RPM_RELEASE="$release" -e BORONDNS_DIST_DIR=/output \
        -e BORONDNS_RPM_BORONDNS_BIN=/inputs/borondns \
        -e BORONDNS_RPM_BORON_GUN_BIN=/inputs/boron-gun \
        -v "$workdir/source:/src:ro" -v "$workdir/bin:/inputs:ro" -v "$output:/output" \
        "$image" /bin/bash -euxc 'dnf -y install rpm-build >/dev/null; /src/scripts/package-rpm.sh' >/dev/null
}

build_package "$fedora_image" 1 "$workdir/dist-r1"
build_package "$fedora_image" 2 "$workdir/dist-r2"

for image_case in "Fedora 42|$fedora_image" "Rocky Linux 9|$rocky_image"; do
    label="${image_case%%|*}"
    image="${image_case#*|}"
    printf 'Testing RPM package lifecycle on %s\n' "$label"
    docker run --rm -v "$workdir/dist-r1:/packages/r1:ro" \
        -e BORONDNS_PACKAGE_VERSION="$version" \
        -v "$workdir/dist-r2:/packages/r2:ro" -v "$workdir/bin:/inputs:ro" \
        "$image" /bin/bash -euxc '
            dnf -y install /packages/r1/borondns-"$BORONDNS_PACKAGE_VERSION"-1.*.rpm
            test "$(rpm -q --qf "%{VERSION}-%{RELEASE}" borondns)" = "$BORONDNS_PACKAGE_VERSION-1"
            test "$(borondns --version)" = "borondns $BORONDNS_PACKAGE_VERSION"
            test "$(boron-gun --version)" = "boron-gun $BORONDNS_PACKAGE_VERSION"
            test "$(sha256sum /usr/bin/borondns | sed "s/ .*//")" = "$(sha256sum /inputs/borondns | sed "s/ .*//")"
            test "$(sha256sum /usr/bin/boron-gun | sed "s/ .*//")" = "$(sha256sum /inputs/boron-gun | sed "s/ .*//")"
            getent passwd borondns
            getent group borondns
            test "$(stat -c %a /var/lib/borondns/zone-cache)" = 770
            printf "[server]\n" > /etc/borondns-secondary/config.toml
            chown root:borondns /etc/borondns-secondary/config.toml
            chmod 0640 /etc/borondns-secondary/config.toml
            printf retained > /var/lib/borondns/zone-cache/lifecycle-test
            dnf -y upgrade /packages/r2/borondns-"$BORONDNS_PACKAGE_VERSION"-2.*.rpm
            test "$(rpm -q --qf "%{VERSION}-%{RELEASE}" borondns)" = "$BORONDNS_PACKAGE_VERSION-2"
            test -s /etc/borondns-secondary/config.toml
            test -s /var/lib/borondns/zone-cache/lifecycle-test
            rpm -e borondns
            test ! -e /usr/bin/borondns
            test -s /etc/borondns-secondary/config.toml
            test -s /var/lib/borondns/zone-cache/lifecycle-test
        '
done

printf 'RPM package Docker lifecycle tests passed\n'
