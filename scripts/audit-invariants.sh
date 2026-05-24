#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
from pathlib import Path
import re
import sys

repo_root = Path(sys.argv[1])
runtime_files = sorted((repo_root / "crates").glob("*/src/**/*.rs"))

def runtime_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    marker = "\n#[cfg(test)]\nmod tests"
    if marker in text:
        text = text.split(marker, 1)[0]
    return text

runtime_sources = {
    path.relative_to(repo_root): runtime_text(path) for path in runtime_files
}

checks: list[tuple[str, str, list[re.Pattern[str]], list[Path]]] = [
    (
        "ODS-INV-001 secondary-only prohibited runtime surfaces",
        "No DNS UPDATE/catalog/admin/primary-serving surface terms found in runtime Rust source.",
        [
            re.compile(r"\bOpcode::Update\b"),
            re.compile(r"\bDynamicUpdate\b", re.IGNORECASE),
            re.compile(r"\bcatalog[_ -]?zone\b", re.IGNORECASE),
            re.compile(r"\badmin(istrative)?[_ -]?(api|socket|port|interface)\b", re.IGNORECASE),
            re.compile(r"\bserve[_ -]?as[_ -]?primary\b", re.IGNORECASE),
        ],
        list(runtime_sources),
    ),
    (
        "ODS-INV-002 query path filesystem isolation",
        "No filesystem API use found in the runtime DNS query/zone lookup path.",
        [
            re.compile(r"\bstd::fs\b"),
            re.compile(r"\btokio::fs\b"),
            re.compile(r"\bFile::\b"),
            re.compile(r"\bOpenOptions\b"),
        ],
        [
            Path("crates/oxidedns-core/src/dns.rs"),
            Path("crates/oxidedns-core/src/zone.rs"),
        ],
    ),
    (
        "ODS-INV-004 no persistent operational state writes",
        "No runtime filesystem write/delete/rename APIs found before test-only code.",
        [
            re.compile(r"\bstd::fs::write\b"),
            re.compile(r"\btokio::fs::write\b"),
            re.compile(r"\bFile::create\b"),
            re.compile(r"\bOpenOptions\b"),
            re.compile(r"\bcreate_dir(?:_all)?\b"),
            re.compile(r"\bremove_(?:file|dir|dir_all)\b"),
            re.compile(r"\brename\b"),
            re.compile(r"\bset_permissions\b"),
        ],
        list(runtime_sources),
    ),
    (
        "ODS-INV-005 static configuration/control surface",
        "No SIGHUP/reload/runtime configuration/admin control surface terms found in runtime Rust source.",
        [
            re.compile(r"\bSIGHUP\b"),
            re.compile(r"\breload\b", re.IGNORECASE),
            re.compile(r"\breread\b", re.IGNORECASE),
            re.compile(r"\bre-read\b", re.IGNORECASE),
            re.compile(r"\badmin(istrative)?[_ -]?(api|socket|port|interface)\b", re.IGNORECASE),
        ],
        list(runtime_sources),
    ),
    (
        "ODS-INV-006 first-party safe-Rust discipline",
        "No first-party runtime unsafe constructs found.",
        [
            re.compile(r"\bunsafe\s*(?:\{|fn|impl|trait|extern)"),
        ],
        list(runtime_sources),
    ),
]

failures: list[str] = []

print("architectural_invariant_audit=started")
print("runtime_source_files:")
for path in runtime_sources:
    print(f"  {path}")

for title, success, patterns, paths in checks:
    matches: list[str] = []
    for path in paths:
        text = runtime_sources.get(path)
        if text is None:
            failures.append(f"{title}: expected source file missing: {path}")
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in patterns:
                if pattern.search(line):
                    matches.append(f"{path}:{line_number}: {line.strip()}")
    print()
    print(f"check={title}")
    if matches:
        print("status=failed")
        for match in matches:
            print(f"  {match}")
        failures.append(f"{title}: {len(matches)} finding(s)")
    else:
        print("status=passed")
        print(f"evidence={success}")

zone_text = runtime_sources[Path("crates/oxidedns-core/src/zone.rs")]
server_text = runtime_sources[Path("crates/oxidedns-server/src/lib.rs")]

print()
print("check=ODS-INV-003 atomic publish evidence")
required_fragments = [
    ("ZoneStore RwLock", "RwLock<HashMap<String, Arc<ZoneSnapshot>>>", zone_text),
    ("insert_loading method", "pub fn insert_loading", zone_text),
    ("insert_snapshot method", "pub fn insert_snapshot", zone_text),
    ("Arc snapshot publication", "Arc::new(snapshot)", zone_text),
    ("runtime publishes after transfer", "zones.insert_snapshot(snapshot.clone())", server_text),
]
missing = [label for label, fragment, text in required_fragments if fragment not in text]
if missing:
    print("status=failed")
    for label in missing:
        print(f"  missing={label}")
    failures.append(f"ODS-INV-003 atomic publish evidence missing: {', '.join(missing)}")
else:
    print("status=passed")
    print("evidence=ZoneStore publishes complete Arc<ZoneSnapshot> values through RwLock-protected map replacement.")

print()
print("allowed_startup_file_reads:")
allowed_reads = [
    "crates/oxidedns-core/src/config.rs: configuration file read at startup",
    "crates/oxidedns-server/src/lib.rs: XoT certificate/key/trust-anchor reads during startup validation or transfer setup",
]
for item in allowed_reads:
    print(f"  {item}")

if failures:
    print()
    print("architectural_invariant_audit=failed")
    for failure in failures:
        print(f"failure={failure}")
    raise SystemExit(1)

print()
print("architectural_invariant_audit=passed")
PY
