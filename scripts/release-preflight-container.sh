#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${BORONDNS_RELEASE_PREFLIGHT_SOURCE:-$repo_root}"
memory_limit="${BORONDNS_RELEASE_PREFLIGHT_MEMORY:-32g}"
image="${BORONDNS_RELEASE_PREFLIGHT_IMAGE:-borondns-release-preflight:ubuntu-24.04}"

usage() {
    cat <<'EOF'
Usage: scripts/release-preflight-container.sh

Build and run the complete release packaging rehearsal in a clean Ubuntu 24.04
container. The selected source checkout must be clean and committed. Nothing is
published. The trusted preflight container uses the host Docker daemon so nested
container resource limits retain their normal cgroup-v2 behavior.

Environment:
  BORONDNS_RELEASE_PREFLIGHT_SOURCE  clean Git checkout to test (default: repo)
  BORONDNS_RELEASE_PREFLIGHT_MEMORY  container memory/swap limit (default: 32g)
  BORONDNS_RELEASE_PREFLIGHT_IMAGE   local preflight image tag
  BORONDNS_RELEASE_PREFLIGHT_NO_CACHE=1  rebuild the tool image without cache
EOF
}

if (($# != 0)); then
    if (($# == 1)) && [[ "$1" == --help ]]; then
        usage
        exit 0
    fi
    usage >&2
    exit 2
fi

for tool in docker git realpath; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing release preflight host tool: %s\n' "$tool" >&2
        exit 1
    }
done

source_root="$(realpath -e "$source_root")"
[[ -d "$source_root/.git" || -f "$source_root/.git" ]] || {
    printf 'release preflight source is not a Git checkout: %s\n' "$source_root" >&2
    exit 1
}
source_commit="$(git -C "$source_root" rev-parse HEAD)"
source_status="$(git -C "$source_root" status --porcelain=v1 --untracked-files=all --ignored=no)"
[[ -z "$source_status" ]] || {
    printf 'release preflight requires a clean committed source checkout:\n%s\n' \
        "$source_status" >&2
    exit 1
}
[[ "$memory_limit" =~ ^[1-9][0-9]*[mMgG]$ ]] || {
    printf 'invalid BORONDNS_RELEASE_PREFLIGHT_MEMORY: %s\n' "$memory_limit" >&2
    exit 1
}
docker info >/dev/null 2>&1 || {
    printf 'release preflight requires an available host Docker daemon\n' >&2
    exit 1
}
docker_endpoint="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}' "$(docker context show)")}"
case "$docker_endpoint" in
unix:///*) docker_socket="${docker_endpoint#unix://}" ;;
*)
    printf 'release preflight requires a local Unix Docker endpoint, found: %s\n' \
        "$docker_endpoint" >&2
    exit 1
    ;;
esac
docker_socket="$(realpath -e "$docker_socket")"
[[ -S "$docker_socket" ]] || {
    printf 'release preflight Docker endpoint is not a Unix socket: %s\n' \
        "$docker_socket" >&2
    exit 1
}

build_args=(
    --file "$source_root/scripts/release-preflight.Dockerfile"
    --tag "$image"
    --progress plain
)
if [[ "${BORONDNS_RELEASE_PREFLIGHT_NO_CACHE:-0}" == 1 ]]; then
    build_args+=(--no-cache)
elif [[ "${BORONDNS_RELEASE_PREFLIGHT_NO_CACHE:-0}" != 0 ]]; then
    printf 'BORONDNS_RELEASE_PREFLIGHT_NO_CACHE must be 0 or 1\n' >&2
    exit 1
fi
docker build "${build_args[@]}" "$source_root"

printf 'release_preflight_source_commit=%s\n' "$source_commit"
printf 'release_preflight_memory_limit=%s\n' "$memory_limit"
bundle="$(mktemp "${TMPDIR:-/tmp}/borondns-release-preflight.XXXXXX.bundle")"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/borondns-release-preflight-work.XXXXXX")"
cleanup() {
    local status=$?
    trap - EXIT
    rm -f -- "$bundle"
    case "$workspace" in
    "${TMPDIR:-/tmp}"/borondns-release-preflight-work.*) rm -rf -- "$workspace" ;;
    *)
        printf 'refusing unsafe preflight workspace cleanup: %s\n' "$workspace" >&2
        status=74
        ;;
    esac
    exit "$status"
}
trap cleanup EXIT
git -C "$source_root" bundle create --quiet "$bundle" HEAD
chmod 0444 "$bundle"

docker run --rm \
    --memory "$memory_limit" --memory-swap "$memory_limit" --pids-limit 8192 \
    --network host \
    --volume "$bundle:/source.bundle:ro" \
    --volume "$docker_socket:/var/run/borondns-host-docker.sock" \
    --volume "$workspace:$workspace" \
    --env "BORONDNS_PREFLIGHT_EXPECTED_COMMIT=$source_commit" \
    --env "BORONDNS_PREFLIGHT_WORKSPACE=$workspace" \
    --env DOCKER_HOST=unix:///var/run/borondns-host-docker.sock \
    "$image"
