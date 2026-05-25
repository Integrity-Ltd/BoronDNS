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

source_files = sorted((repo_root / "crates").glob("*/src/**/*.rs"))
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
    ("crates/oxidedns-core/src/dns.rs", "DNS wire parsing, EDNS handling, and authoritative response construction"),
    ("crates/oxidedns-core/src/axfr.rs", "AXFR/IXFR query construction, transfer parsing, and zone publication validation"),
    ("crates/oxidedns-core/src/config.rs", "static TOML configuration model and validation"),
    ("crates/oxidedns-core/src/tsig.rs", "TSIG signing, verification, and error response helpers"),
    ("crates/oxidedns-core/src/zone.rs", "memory-resident zone snapshots and lookup state"),
    ("crates/oxidedns-core/src/lib.rs", "core crate public API boundary"),
    ("crates/oxidedns-server/src/lib.rs", "runtime listeners, refresh scheduling, health/metrics, interop-facing behavior"),
    ("crates/oxidedns-server/src/process_signals.rs", "audited POSIX signal disposition FFI boundary"),
    ("crates/oxidedns-server/src/resource_limits.rs", "audited POSIX file-descriptor limit FFI boundary"),
    ("crates/oxidedns-server/build.rs", "build metadata embedding for version and metrics labels"),
    ("crates/oxidedns-cli/src/main.rs", "command-line entrypoints"),
]
for path, purpose in module_map:
    print(f"  {path}: {purpose}")

print()
print(f"module_count={len(module_map)}")
if not 8 <= len(module_map) <= 20:
    print("error=ODS-NFR-MAINT-002 module count outside 8-20 target")
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
        "warning=ODS-NFR-MAINT-001 line count is outside the 5,000-15,000 "
        "target; release review needs an architecture/release-note "
        "justification or a refactor plan"
    )
    if os.environ.get("OXIDEDNS_MAINT_ENFORCE") == "1":
        raise SystemExit(1)
PY
