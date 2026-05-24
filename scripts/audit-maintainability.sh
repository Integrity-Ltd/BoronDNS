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
line_counts: list[tuple[Path, int]] = []
total = 0

for path in source_files:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"failed to read Rust source as UTF-8: {path}") from exc
    count = len(text.splitlines())
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
    ("crates/oxidedns-server/src/lib.rs", "runtime listeners, refresh scheduling, health/metrics, interop-facing behavior"),
    ("crates/oxidedns-cli/src/main.rs", "command-line entrypoints"),
]
for path, purpose in module_map:
    print(f"  {path}: {purpose}")

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
