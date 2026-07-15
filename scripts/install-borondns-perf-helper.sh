#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="$repo_root/scripts/install-borondns-perf-helper.sh"
source_helper="$repo_root/scripts/borondns-perf-capture-root.sh"
installed_helper="/usr/local/libexec/borondns-perf-capture"

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/install-borondns-perf-helper.sh

Installs a root-owned BoronDNS perf helper and a narrow sudoers rule for the
current user. The installer uses one pkexec authorization. Benchmark runs can
then set:

  BORONDNS_BENCH_PERF_PRIVILEGED_HELPER=true

The sudoers rule allows the current user to run only:

  /usr/local/libexec/borondns-perf-capture *
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "${1:-}" != "--as-root" ]]; then
    command -v pkexec >/dev/null
    current_user="$(id -un)"
    current_uid="$(id -u)"
    current_gid="$(id -g)"
    exec pkexec "$script_path" --as-root "$current_user" "$current_uid" "$current_gid" "$source_helper"
fi

shift
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf 'installer root phase must run as root\n' >&2
    exit 77
fi

target_user="${1:-}"
target_uid="${2:-}"
target_gid="${3:-}"
source_helper="${4:-}"
if [[ -z "$target_user" || -z "$target_uid" || -z "$target_gid" || -z "$source_helper" ]]; then
    usage
    exit 64
fi
if ! [[ "$target_uid" =~ ^[0-9]+$ && "$target_gid" =~ ^[0-9]+$ ]]; then
    printf 'invalid target uid/gid\n' >&2
    exit 64
fi
if [[ "$(id -u "$target_user")" != "$target_uid" ]]; then
    printf 'target user and uid do not match: %s %s\n' "$target_user" "$target_uid" >&2
    exit 64
fi
if [[ ! -f "$source_helper" ]]; then
    printf 'helper source not found: %s\n' "$source_helper" >&2
    exit 66
fi

install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$source_helper" "$installed_helper"

sudoers_path="/etc/sudoers.d/borondns-perf-capture-$target_user"
tmp_sudoers="$(mktemp)"
cat >"$tmp_sudoers" <<EOF
# Installed by BoronDNS scripts/install-borondns-perf-helper.sh.
# The helper validates target pid ownership and output directory ownership.
$target_user ALL=(root) NOPASSWD: $installed_helper *
EOF
chmod 0440 "$tmp_sudoers"
visudo -cf "$tmp_sudoers" >/dev/null
install -o root -g root -m 0440 "$tmp_sudoers" "$sudoers_path"
rm -f "$tmp_sudoers"

printf 'installed_helper=%s\n' "$installed_helper"
printf 'installed_sudoers=%s\n' "$sudoers_path"
printf 'usage=BORONDNS_BENCH_PERF_PRIVILEGED_HELPER=true BORONDNS_BENCH_PERF_STAT=true scripts/benchmark-dns-clients.sh\n'
