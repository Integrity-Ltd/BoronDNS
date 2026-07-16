#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
from pathlib import Path
import os
import sys

repo_root = Path(sys.argv[1])
min_lines = 5_000
max_lines = 15_000

source_files = [
    path
    for path in sorted((repo_root / "crates").glob("*/src/**/*.rs"))
    if path.name != "tests.rs" and "/tests/" not in path.as_posix()
]
source_files.extend(sorted((repo_root / "crates").glob("*/build.rs")))
line_counts: list[tuple[Path, int]] = []
total = 0


def count_braces(line: str) -> int:
    return line.count("{") - line.count("}")


def production_lines(lines: list[str]) -> list[str]:
    """Exclude cfg(test) blocks from the SRS line-count measurement."""
    result: list[str] = []
    pending_cfg_test = False
    skip_depth: int | None = None

    for line in lines:
        stripped = line.strip()

        if skip_depth is not None:
            skip_depth += count_braces(line)
            if skip_depth <= 0:
                skip_depth = None
            continue

        if pending_cfg_test:
            if stripped.startswith("#["):
                continue
            depth = count_braces(line)
            pending_cfg_test = False
            if depth > 0:
                skip_depth = depth
            continue

        if stripped == "#[cfg(test)]":
            pending_cfg_test = True
            continue

        result.append(line)

    return result

for path in source_files:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"failed to read Rust source as UTF-8: {path}") from exc
    count = len(production_lines(text.splitlines()))
    line_counts.append((path.relative_to(repo_root), count))
    total += count

if total < min_lines:
    status = "under_target"
elif total > max_lines:
    status = "over_target"
else:
    status = "within_target"

print(f"first_party_rust_source_lines={total}")
print(f"srs_target_min={min_lines}")
print(f"srs_target_max={max_lines}")
print(f"status={status}")
print()
print("per_file_lines:")
for path, count in line_counts:
    print(f"  {path}: {count}")

print()
print("module_map:")
module_map = [
    ("crates/borondns-core/src/dns.rs", "DNS wire parsing, EDNS handling, and authoritative response construction"),
    ("crates/borondns-core/src/axfr.rs", "AXFR/IXFR query construction, transfer parsing, and zone publication validation"),
    ("crates/borondns-core/src/catalog.rs", "RFC 9432 catalog-zone schema and member parsing"),
    ("crates/borondns-core/src/config.rs", "static TOML configuration model and validation"),
    ("crates/borondns-core/src/tsig.rs", "TSIG signing, verification, and error response helpers"),
    ("crates/borondns-core/src/zone.rs", "memory-resident zone snapshots and lookup state"),
    ("crates/borondns-core/src/zone_image.rs", "experimental immutable zone image, semantic lookup plans, and wire-section response prototype"),
    ("crates/borondns-core/src/lib.rs", "core crate public API boundary"),
    ("crates/borondns-server/src/lib.rs", "runtime orchestration, catalog reconciliation, refresh scheduling, and NOTIFY/TSIG integration"),
    ("crates/borondns-server/src/udp.rs", "UDP listener and packet serving path"),
    ("crates/borondns-server/src/tcp.rs", "TCP listener, connection limits, and DNS-over-TCP framing"),
    ("crates/borondns-server/src/health_metrics.rs", "health endpoints, metrics rendering, and runtime counters"),
    ("crates/borondns-server/src/observability.rs", "in-process JSON observability/management API with bearer-token auth"),
    ("crates/borondns-server/src/rate_limit.rs", "RRL, notify log limiting, and packet response categorisation helpers"),
    ("crates/borondns-server/src/transfer.rs", "SOA polling, AXFR/IXFR transfer sessions, and XoT transport"),
    ("crates/borondns-server/src/transfer_plan.rs", "transfer target planning and primary rotation"),
    ("crates/borondns-server/src/secret_store.rs", "reloadable filesystem-backed TSIG/XoT secret store"),
    ("crates/borondns-server/src/dns_cookie.rs", "DNS Cookie secret and runtime settings helpers"),
    ("crates/borondns-server/src/config_validation.rs", "runtime configuration validation and warnings"),
    ("crates/borondns-server/src/runtime_status.rs", "runtime readiness/draining status model"),
    ("crates/borondns-server/src/shutdown.rs", "graceful shutdown and task draining helpers"),
    ("crates/borondns-server/src/errors.rs", "runtime and transfer error types"),
    ("crates/borondns-server/src/build_info.rs", "build metadata constants"),
    ("crates/borondns-server/src/af_xdp.rs", "feature-gated server AF_XDP packet-I/O adapter"),
    ("crates/borondns-server/src/std_udp_mmsg.rs", "standard UDP recvmmsg/sendmmsg batch adapter"),
    ("crates/borondns-server/src/std_udp_socket.rs", "standard UDP socket creation, reuseport, and CPU affinity adapter"),
    ("crates/borondns-server/src/privilege.rs", "audited POSIX privilege-drop FFI boundary"),
    ("crates/borondns-server/src/process_hardening.rs", "audited POSIX process-hardening FFI boundary"),
    ("crates/borondns-server/src/process_signals.rs", "audited POSIX signal disposition FFI boundary"),
    ("crates/borondns-server/src/resource_limits.rs", "audited POSIX file-descriptor limit FFI boundary"),
    ("crates/borondns-server/build.rs", "build metadata embedding for version and metrics labels"),
    ("crates/borondns-cli/src/main.rs", "command-line entrypoints"),
    ("crates/boron-gun/src/main.rs", "BoronGun load-generator CLI and portable UDP backend"),
    ("crates/boron-gun/src/xdp_backend.rs", "BoronGun lab-only AF_XDP backend"),
    ("crates/boron-gun-ebpf/src/lib.rs", "BoronGun lab-only XDP drop program"),
    ("crates/borondns-server-ebpf/src/lib.rs", "feature-gated BoronDNS XDP redirect program"),
]
for path, purpose in module_map:
    print(f"  {path}: {purpose}")

print()
print(f"module_count={len(module_map)}")
if not 8 <= len(module_map) <= 40:
    print("error=BDS-NFR-MAINT-002 module count outside 8-40 target")
    raise SystemExit(1)

architecture = (repo_root / "docs" / "architecture.md").read_text(encoding="utf-8")
missing_architecture_entries = [
    path for path, _purpose in module_map if f"| `{path}` |" not in architecture
]
if missing_architecture_entries:
    print()
    print("error=architecture module mapping is missing entries")
    for path in missing_architecture_entries:
        print(f"  missing={path}")
    raise SystemExit(1)

if status != "within_target":
    print()
    print(
        "warning=BDS-NFR-MAINT-001 line count is outside the 5,000-15,000 "
        "target; release review needs an architecture/release-note "
        "justification or a refactor plan"
    )
    required_rationale = "Current BDS-NFR-MAINT-001 over-target rationale"
    if required_rationale not in architecture:
        print()
        print(
            "error=architecture missing current BDS-NFR-MAINT-001 "
            "over-target rationale"
        )
        raise SystemExit(1)
    if os.environ.get("BORONDNS_MAINT_ENFORCE") == "1":
        raise SystemExit(1)
PY
