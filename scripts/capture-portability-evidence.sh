#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${OXIDEDNS_PORTABILITY_EVIDENCE_DIR:-$repo_root/target/evidence/portability-$$}"
mkdir -p "$artifact_dir"

write_command() {
  local name="$1"
  shift
  local out="$artifact_dir/$name.txt"
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@" 2>&1 || true
  } >"$out"
}

require_command() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$tool" >&2
    exit 1
  fi
}

require_command cargo
require_command rustc
require_command python3
require_command rg

cargo build -p oxidedns-cli >/dev/null

write_command uname uname -a
write_command rustc rustc -vV
write_command cargo cargo --version
write_command oxidedns-version "$repo_root/target/debug/oxidedns" --version

if [[ -r /etc/os-release ]]; then
  cp /etc/os-release "$artifact_dir/os-release.txt"
else
  printf 'missing /etc/os-release\n' >"$artifact_dir/os-release.txt"
fi

if command -v ldd >/dev/null 2>&1; then
  write_command ldd-version ldd --version
  write_command oxidedns-ldd ldd "$repo_root/target/debug/oxidedns"
else
  printf 'missing ldd\n' >"$artifact_dir/ldd-version.txt"
  printf 'missing ldd\n' >"$artifact_dir/oxidedns-ldd.txt"
fi

{
  printf 'tool\tstatus\tversion\n'
  for tool in docker podman containerd ctr crictl crio runc; do
    if command -v "$tool" >/dev/null 2>&1; then
      version="$("$tool" --version 2>&1 | head -n 1 || true)"
      printf '%s\tpresent\t%s\n' "$tool" "$version"
    else
      printf '%s\tmissing\t\n' "$tool"
    fi
  done
} >"$artifact_dir/container-runtime-inventory.tsv"

python3 >"$artifact_dir/network-probes.tsv" <<'PY'
import socket
import sys

probes = [
    ("ipv4", socket.AF_INET, "127.0.0.1"),
    ("ipv6", socket.AF_INET6, "::1"),
]


def tcp_probe(family, address):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = socket.socket(family, socket.SOCK_STREAM)
    client.settimeout(2.0)
    client.connect((address, port))
    conn, peer = server.accept()
    client.close()
    conn.close()
    server.close()
    return f"port={port} peer={peer[0]}"


def udp_probe(family, address):
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.bind((address, 0))
    port = server.getsockname()[1]
    client = socket.socket(family, socket.SOCK_DGRAM)
    client.settimeout(2.0)
    server.settimeout(2.0)
    client.sendto(b"ok", (address, port))
    data, peer = server.recvfrom(16)
    client.close()
    server.close()
    if data != b"ok":
        raise AssertionError("unexpected UDP payload")
    return f"port={port} peer={peer[0]}"


print("operation\tfamily\tstatus\tdetail")
failures = []
for label, family, address in probes:
    for operation, probe in (("tcp_loopback", tcp_probe), ("udp_loopback", udp_probe)):
        try:
            detail = probe(family, address)
            print(f"{operation}\t{label}\tpass\t{detail}")
        except OSError as exc:
            print(f"{operation}\t{label}\tunavailable\t{exc}")
            if label == "ipv4":
                failures.append((operation, label, str(exc)))

if failures:
    sys.exit(1)
PY

runtime_scan="$artifact_dir/init-package-runtime-scan.txt"
if rg -n \
  -e 'systemd' \
  -e 'sysvinit' \
  -e 'OpenRC' \
  -e 'apt(-get)?\b' \
  -e '\byum\b' \
  -e '\bdnf\b' \
  -e '\bapk\b' \
  -e '/etc/(debian|redhat|alpine|systemd)' \
  "$repo_root/crates/oxidedns-cli/src" \
  "$repo_root/crates/oxidedns-core/src" \
  "$repo_root/crates/oxidedns-server/src" \
  "$repo_root/config" >"$runtime_scan"; then
  printf 'runtime portability scan found distribution/init coupling; see %s\n' "$runtime_scan" >&2
  exit 1
else
  printf 'no first-party runtime references to init systems or distro package managers\n' >"$runtime_scan"
fi

{
  printf 'requirement_id\tevidence_state\tartifact\treview_note\n'
  printf 'ODS-NFR-PORT-001\tcurrent-host-runtime\tos-release.txt; uname.txt; rustc.txt; cargo.txt; oxidedns-version.txt\tCurrent Linux host build/run facts captured; full per-distribution CI matrix remains release-gate work.\n'
  printf 'ODS-NFR-PORT-002\tcurrent-host-runtime\tuname.txt; rustc.txt; oxidedns-version.txt\tCurrent host architecture and Rust host target captured; full x86_64/aarch64 CI matrix remains release-gate work.\n'
  printf 'ODS-NFR-PORT-003\tinventory\tcontainer-runtime-inventory.tsv\tOCI runtime availability is inventoried for the release host; runtime/container deployment tests remain separate artifacts.\n'
  printf 'ODS-NFR-PORT-004\tcurrent-host-runtime\tnetwork-probes.tsv\tCurrent host IPv4/IPv6 TCP and UDP loopback capability is probed; full per-operation dual-stack tests remain acceptance work.\n'
  printf 'ODS-NFR-PORT-005\tstatic-audit\tinit-package-runtime-scan.txt\tFirst-party runtime/config source is scanned for init-system, package-manager, and distribution-layout coupling.\n'
} >"$artifact_dir/portability-traceability.tsv"

printf 'portability_evidence_dir=%s\n' "$artifact_dir"
