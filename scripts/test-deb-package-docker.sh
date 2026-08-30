#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v docker >/dev/null || {
    printf 'skipping Debian package lifecycle: Docker is unavailable\n'
    exit 0
}
docker info >/dev/null 2>&1 || {
    printf 'skipping Debian package lifecycle: Docker daemon is unavailable\n'
    exit 0
}

workdir="$(mktemp -d "${TMPDIR:-/tmp}/borondns-deb-test.XXXXXXXX")"
trap 'rm -rf -- "$workdir"' EXIT INT TERM HUP
mkdir -p "$workdir/bin" "$workdir/dist-r1" "$workdir/dist-r2"
debian_bookworm="debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
debian_trixie="debian@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8"
ubuntu_2204="ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
ubuntu_2404="ubuntu@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54"

cat >"$workdir/bin/borondns" <<'EOF'
#!/bin/sh
case "${1:-}" in
--version) echo 'borondns 1.0.0' ;;
check-config) exit 0 ;;
*) exit 0 ;;
esac
EOF
cat >"$workdir/bin/boron-gun" <<'EOF'
#!/bin/sh
case "${1:-}" in
--version) echo 'boron-gun 1.0.0' ;;
*) exit 0 ;;
esac
EOF
chmod 0755 "$workdir/bin/borondns" "$workdir/bin/boron-gun"

build_package() {
    local revision="$1" output="$2"
    docker run --rm \
        -e SOURCE_DATE_EPOCH=1700000000 \
        -e BORONDNS_DEB_REVISION="$revision" \
        -e BORONDNS_DIST_DIR=/output \
        -e BORONDNS_DEB_BORONDNS_BIN=/inputs/borondns \
        -e BORONDNS_DEB_BORON_GUN_BIN=/inputs/boron-gun \
        -v "$repo_root:/src:ro" -v "$workdir/bin:/inputs:ro" -v "$output:/output" \
        "$debian_bookworm" \
        /bin/bash /src/scripts/package-deb.sh >/dev/null
}

build_package 1 "$workdir/dist-r1"
build_package 2 "$workdir/dist-r2"

for image_case in \
    "Debian 12|$debian_bookworm" "Debian 13|$debian_trixie" \
    "Ubuntu 22.04|$ubuntu_2204" "Ubuntu 24.04|$ubuntu_2404"; do
    image_label="${image_case%%|*}"
    image="${image_case#*|}"
    printf 'Testing Debian package lifecycle on %s\n' "$image_label"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "$workdir/dist-r1:/packages/r1:ro" -v "$workdir/dist-r2:/packages/r2:ro" \
        -v "$workdir/bin:/inputs:ro" \
        "$image" /bin/sh -euxc '
            apt-get update
            apt-get install -y /packages/r1/borondns_1.0.0-1_amd64.deb
            dpkg-query -W borondns | grep -q "^borondns[[:space:]]"
            cmp /usr/bin/borondns /inputs/borondns
            cmp /usr/bin/boron-gun /inputs/boron-gun
            getent passwd borondns
            getent group borondns
            test "$(stat -c %a /var/lib/borondns/zone-cache)" = 770
            test ! -e /etc/borondns-secondary/config.toml
            printf "[server]\n" > /etc/borondns-secondary/config.toml
            chown root:borondns /etc/borondns-secondary/config.toml
            chmod 0640 /etc/borondns-secondary/config.toml
            printf retained > /var/lib/borondns/zone-cache/lifecycle-test
            apt-get install -y /packages/r2/borondns_1.0.0-2_amd64.deb
            test -s /etc/borondns-secondary/config.toml
            test -s /var/lib/borondns/zone-cache/lifecycle-test
            dpkg --remove borondns
            test ! -e /usr/bin/borondns
            test -s /etc/borondns-secondary/config.toml
            test -s /var/lib/borondns/zone-cache/lifecycle-test
            dpkg --purge borondns
            test ! -e /etc/borondns-secondary/config.toml
            test -s /var/lib/borondns/zone-cache/lifecycle-test
        '
done

# A legacy archive-installed unit would shadow the packaged service definition.
docker run --rm -e DEBIAN_FRONTEND=noninteractive \
    -v "$workdir/dist-r1:/packages:ro" "$debian_bookworm" /bin/sh -euxc '
        apt-get update
        apt-get install -y adduser init-system-helpers
        mkdir -p /etc/systemd/system
        : > /etc/systemd/system/borondns.service
        if dpkg --install /packages/borondns_1.0.0-1_amd64.deb; then
            echo "package accepted a shadowing archive-installer unit" >&2
            exit 1
        fi
        dpkg --purge borondns || true
    '

printf 'Debian package Docker lifecycle tests passed\n'
