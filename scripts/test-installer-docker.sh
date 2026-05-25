#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
archive="${OXIDEDNS_INSTALLER_ARCHIVE:-$dist_dir/oxidedns-$version-$target_triple.tar.xz}"
image="${OXIDEDNS_INSTALLER_TEST_IMAGE:-ubuntu:24.04}"
workdir="$repo_root/target/installer-docker-test/$$"

if ! command -v docker >/dev/null 2>&1; then
    printf 'missing required tool: docker\n' >&2
    exit 1
fi

if [[ ! -f "$archive" ]]; then
    "$repo_root/scripts/package-installer.sh"
fi

rm -rf "$workdir"
mkdir -p "$workdir"
tar -xJf "$archive" -C "$workdir"
payload_dir="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "$payload_dir" ]] || {
    printf 'failed to extract installer payload from %s\n' "$archive" >&2
    exit 1
}

docker run --rm \
    -v "$payload_dir:/pkg:ro" \
    -e OXIDEDNS_ZONE=installer-smoke.example. \
    -e OXIDEDNS_PRIMARY=127.0.0.1:9 \
    -e OXIDEDNS_NOTIFY_SOURCE=127.0.0.1 \
    -e OXIDEDNS_DNS_LISTEN=127.0.0.1:5300 \
    -e OXIDEDNS_MGMT_LISTEN=127.0.0.1:18080 \
    -e OXIDEDNS_TRANSFER_SOURCE=127.0.0.1:0 \
    "$image" \
    /bin/bash -euo pipefail -c '
		/pkg/install.sh --yes --init none --no-start
		/usr/local/bin/oxidedns --version
		/usr/local/bin/oxidedns check-config --config /etc/oxidedns-secondary/config.toml
		grep -q "installer-smoke.example." /etc/oxidedns-secondary/config.toml

		/pkg/install.sh update --yes --init none --no-start
		/usr/local/bin/oxidedns check-config --config /etc/oxidedns-secondary/config.toml

		/usr/local/bin/oxidedns serve --config /etc/oxidedns-secondary/config.toml >/tmp/oxidedns.log 2>&1 &
		pid=$!
		sleep 1
		kill -0 "$pid"
		kill "$pid"
		wait "$pid" || true
		grep -q "OxideDNS runtime initialized" /tmp/oxidedns.log
	'

printf 'installer Docker smoke passed: %s on %s\n' "$archive" "$image"
