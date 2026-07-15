#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/package-common.sh"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
image_archive="${OXIDEDNS_DOCKER_IMAGE_ARCHIVE:-$dist_dir/oxidedns-$version-$target_triple-docker-image.tar.xz}"
image_ref="${OXIDEDNS_DOCKER_IMAGE_REF:-oxidedns:$version}"
container="oxidedns-image-smoke-$$"
workdir="$repo_root/target/docker-image-test/$$"
prior_image_id=""
prior_backup_ref=""
daemon_state_armed=0
daemon_cleanup_running=0
image_lock_fd=""

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
    if ((daemon_cleanup_running)); then
        return
    fi
    daemon_cleanup_running=1
    trap - EXIT
    trap '' INT TERM HUP
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if ((daemon_state_armed)); then
        if [[ -n "$prior_image_id" ]]; then
            local prior_tag_restored=0
            docker image tag "$prior_image_id" "$image_ref" >/dev/null 2>&1 || true
            if [[ "$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null || true)" == "$prior_image_id" ]]; then
                prior_tag_restored=1
            else
                printf 'failed to restore previous Docker smoke-test tag: %s -> %s\n' \
                    "$image_ref" "$prior_image_id" >&2
                status=74
            fi
            if [[ -n "$prior_backup_ref" ]]; then
                if ((prior_tag_restored)) && docker image inspect "$prior_backup_ref" >/dev/null 2>&1; then
                    docker image rm "$prior_backup_ref" >/dev/null 2>&1 || status=74
                elif ((prior_tag_restored == 0)) && docker image inspect "$prior_backup_ref" >/dev/null 2>&1; then
                    printf 'retained previous Docker smoke-test image under recovery tag: %s (%s)\n' \
                        "$prior_backup_ref" "$prior_image_id" >&2
                fi
            fi
        elif docker image inspect "$image_ref" >/dev/null 2>&1; then
            docker image rm "$image_ref" >/dev/null 2>&1 || status=74
        fi
    fi
    rm -rf "$workdir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [[ ! -f "$image_archive" ]]; then
    "$repo_root/scripts/package-docker-image.sh"
fi

rm -rf "$workdir"
mkdir -p "$workdir"

IFS=$'\t' read -r archive_image_id archive_image_ref < <(
    python3 "$repo_root/scripts/verify-docker-archive.py" "$image_archive"
)
[[ "$archive_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$archive_image_ref" == "$image_ref" ]] || {
    printf 'Docker smoke archive tag mismatch: expected=%s actual=%s\n' \
        "$image_ref" "$archive_image_ref" >&2
    exit 1
}

# Prove the release archive is independently loadable. Preserve any previous
# stable tag under a collision-proof private tag while holding the same global
# lock as packagers/SBOM scans, then remove the stable name before docker load.
package_acquire_docker_image_lock "$image_ref" image_lock_fd
[[ -n "$image_lock_fd" ]]
if prior_image_id="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)"; then
    [[ "$prior_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]
    for backup_attempt in {1..128}; do
        prior_backup_ref="oxidedns-smoke-backup-$(id -u):$version-$$-$RANDOM-$backup_attempt"
        if ! docker image inspect "$prior_backup_ref" >/dev/null 2>&1; then
            # Arm recovery before the first daemon mutation. If docker commits
            # the tag and then reports failure or delivers a deferred signal,
            # EXIT cleanup already knows the intended private backup name.
            daemon_state_armed=1
            docker image tag "$prior_image_id" "$prior_backup_ref"
            break
        fi
        prior_backup_ref=""
    done
    [[ -n "$prior_backup_ref" ]] || {
        printf 'could not allocate a private Docker smoke-test backup tag\n' >&2
        exit 1
    }
else
    # Removing a previously absent stable tag must also be journaled before a
    # subsequently loaded image can make that name visible.
    daemon_state_armed=1
fi
if docker image inspect "$image_ref" >/dev/null 2>&1; then
    docker image rm "$image_ref" >/dev/null
fi
if docker image inspect "$image_ref" >/dev/null 2>&1; then
    printf 'Docker smoke could not remove the pre-existing stable tag: %s\n' "$image_ref" >&2
    exit 1
fi

docker_load_output=""
package_load_verified_docker_archive "$image_archive" \
    "$repo_root/scripts/verify-docker-archive.py" \
    "$repo_root/scripts/release-api-supervisor.py" docker_load_output
[[ -n "$docker_load_output" ]] || {
    printf 'verified Docker archive load returned no image identity\n' >&2
    exit 1
}

loaded_image_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"
[[ "$loaded_image_id" == "$archive_image_id" ]] || {
    printf 'freshly loaded Docker tag identity mismatch: expected=%s actual=%s\n' \
        "$archive_image_id" "$loaded_image_id" >&2
    exit 1
}

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
    -p "127.0.0.1::5300/udp" \
    -p "127.0.0.1::5300/tcp" \
    -p "127.0.0.1::8080/tcp" \
    -v "$workdir/oxidedns.toml:/etc/oxidedns-secondary/config.toml:ro" \
    "$image_ref" >/dev/null

published_loopback_port() {
    local container_port="$1" mapping host_port
    mapping="$(docker port "$container" "$container_port")" || return 1
    [[ "$mapping" != *$'\n'* && "$mapping" =~ ^127\.0\.0\.1:([1-9][0-9]{0,4})$ ]] || {
        printf 'Docker published an unexpected %s mapping: %q\n' \
            "$container_port" "$mapping" >&2
        return 1
    }
    host_port="${BASH_REMATCH[1]}"
    ((host_port <= 65535)) || {
        printf 'Docker published an out-of-range %s mapping: %s\n' \
            "$container_port" "$host_port" >&2
        return 1
    }
    printf '%s\n' "$host_port"
}

# Docker owns the protocol-specific ephemeral allocation. This closes both the
# close-before-bind race and the earlier TCP-only reservation gap for the UDP
# mapping, while still proving every advertised listener was published on IPv4
# loopback only.
host_dns_udp_port="$(published_loopback_port 5300/udp)"
host_dns_tcp_port="$(published_loopback_port 5300/tcp)"
host_health_port="$(published_loopback_port 8080/tcp)"

for _ in {1..100}; do
    if curl -fsS "http://127.0.0.1:$host_health_port/livez" >/dev/null 2>&1; then
        break
    fi
    sleep 0.05
done

curl -fsS "http://127.0.0.1:$host_health_port/livez" >/dev/null
curl -fsS "http://127.0.0.1:$host_health_port/metrics" | grep -F 'oxidedns_secondary_build_info' >/dev/null

python3 - "$host_dns_udp_port" "$host_dns_tcp_port" <<'PY'
import socket
import struct
import sys

udp_port, tcp_port = (int(value) for value in sys.argv[1:])
transaction_id = 0x4F58
query = (
    struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    + b"\x0cdocker-smoke\x07example\x00"
    + struct.pack("!HH", 1, 1)
)


def require_response(payload: bytes, transport: str) -> None:
    if len(payload) < 12:
        raise SystemExit(f"short {transport} DNS smoke response")
    response_id, flags = struct.unpack("!HH", payload[:4])
    if response_id != transaction_id or not flags & 0x8000:
        raise SystemExit(f"invalid {transport} DNS smoke response")


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.settimeout(2)
    udp.sendto(query, ("127.0.0.1", udp_port))
    response, _ = udp.recvfrom(65535)
    require_response(response, "UDP")


with socket.create_connection(("127.0.0.1", tcp_port), timeout=2) as tcp:
    tcp.sendall(struct.pack("!H", len(query)) + query)
    header = tcp.recv(2)
    if len(header) != 2:
        raise SystemExit("short TCP DNS smoke length prefix")
    remaining = struct.unpack("!H", header)[0]
    chunks = bytearray()
    while len(chunks) < remaining:
        chunk = tcp.recv(remaining - len(chunks))
        if not chunk:
            raise SystemExit("short TCP DNS smoke response")
        chunks.extend(chunk)
    require_response(bytes(chunks), "TCP")
PY

test "$(docker exec "$container" id -u)" = "53053"
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = "true"
docker inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -F '"ALL"' >/dev/null
docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -F 'no-new-privileges' >/dev/null
if docker exec "$container" sh -c 'touch /tmp/oxidedns-readonly-probe' >/dev/null 2>&1; then
    printf 'container accepted a write under read-only root filesystem\n' >&2
    exit 1
fi

printf 'Docker image smoke passed: %s (%s)\n' "$image_archive" "$image_ref"
