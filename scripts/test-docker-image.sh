#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
image_archive="${OXIDEDNS_DOCKER_IMAGE_ARCHIVE:-$dist_dir/oxidedns-$version-$target_triple-docker-image.tar.xz}"
image_ref="${OXIDEDNS_DOCKER_IMAGE_REF:-oxidedns:$version}"
container="oxidedns-image-smoke-$$"
workdir="$repo_root/target/docker-image-test/$$"

missing=()
for tool in cargo curl docker python3 xz; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required Docker image smoke tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    printf 'Docker daemon is unavailable\n' >&2
    exit 1
fi

cleanup() {
    local status=$?
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

if [[ ! -f "$image_archive" ]]; then
    "$repo_root/scripts/package-docker-image.sh"
fi

rm -rf "$workdir"
mkdir -p "$workdir"

read -r host_dns_port host_health_port < <(
    python3 - <<'PY'
import socket

sockets = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

xz -dc "$image_archive" | docker load >/dev/null

docker run --rm "$image_ref" --version >/dev/null

cat >"$workdir/oxidedns.toml" <<'EOF'
[server]
log_level = "debug"
log_format = "json"
nsid = "docker-smoke"

[interfaces]
dns = ["0.0.0.0:5300"]
mgmt = ["0.0.0.0:8080"]
transfer = ["0.0.0.0:0"]

[health]
bind_address = "0.0.0.0"
bind_port = 8080

[rrl]
enabled = false

[[zones]]
name = "docker-smoke.example."
primaries = ["127.0.0.1:9"]
notify_sources = ["127.0.0.1"]
EOF

docker run -d \
    --name "$container" \
    --read-only \
    --ulimit nofile=65536:65536 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 128 \
    --memory 128m \
    -p "127.0.0.1:$host_dns_port:5300/udp" \
    -p "127.0.0.1:$host_dns_port:5300/tcp" \
    -p "127.0.0.1:$host_health_port:8080/tcp" \
    -v "$workdir/oxidedns.toml:/etc/oxidedns-secondary/config.toml:ro" \
    "$image_ref" >/dev/null

for _ in {1..100}; do
    if curl -fsS "http://127.0.0.1:$host_health_port/livez" >/dev/null 2>&1; then
        break
    fi
    sleep 0.05
done

curl -fsS "http://127.0.0.1:$host_health_port/livez" >/dev/null
curl -fsS "http://127.0.0.1:$host_health_port/metrics" | grep -F 'oxidedns_secondary_build_info' >/dev/null

test "$(docker exec "$container" id -u)" = "53053"
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = "true"
docker inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -F '"ALL"' >/dev/null
docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -F 'no-new-privileges' >/dev/null
if docker exec "$container" sh -c 'touch /tmp/oxidedns-readonly-probe' >/dev/null 2>&1; then
    printf 'container accepted a write under read-only root filesystem\n' >&2
    exit 1
fi

printf 'Docker image smoke passed: %s (%s)\n' "$image_archive" "$image_ref"
