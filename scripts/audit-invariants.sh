#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
import csv
from pathlib import Path
import re
import sys

repo_root = Path(sys.argv[1])
unsafe_registry = repo_root / "docs" / "unsafe-boundaries.tsv"
runtime_files = sorted(
    path
    for path in (repo_root / "crates").glob("*/src/**/*.rs")
    if "crates/oxide-gun/" not in path.relative_to(repo_root).as_posix()
    and "crates/oxide-gun-ebpf/" not in path.relative_to(repo_root).as_posix()
)

def runtime_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    marker = "\n#[cfg(test)]\nmod tests"
    if marker in text:
        text = text.split(marker, 1)[0]
    return text

runtime_sources = {
    path.relative_to(repo_root): runtime_text(path) for path in runtime_files
}
with unsafe_registry.open(newline="", encoding="utf-8") as handle:
    current_unsafe_adapter_paths = {
        Path(row["path"])
        for row in csv.DictReader(handle, delimiter="\t")
        if row["status"] == "current" and not row["path"].startswith("future:")
    }
audited_unsafe_adapter_paths = {
    path for path in current_unsafe_adapter_paths if path in runtime_sources
}
tool_unsafe_adapter_paths = current_unsafe_adapter_paths - audited_unsafe_adapter_paths
expected_current_unsafe_adapters = {
    Path("crates/oxidedns-server/src/privilege.rs"),
    Path("crates/oxidedns-server/src/process_hardening.rs"),
    Path("crates/oxidedns-server/src/process_signals.rs"),
    Path("crates/oxidedns-server/src/resource_limits.rs"),
}
if audited_unsafe_adapter_paths != expected_current_unsafe_adapters:
    raise SystemExit(
        "docs/unsafe-boundaries.tsv current unsafe adapter set changed; "
        "update invariant audit expectations and parser/TSIG/response safe-core checks "
        f"before accepting: {sorted(str(path) for path in audited_unsafe_adapter_paths)}"
    )
runtime_sources_without_unsafe_adapters = [
    path for path in runtime_sources if path not in audited_unsafe_adapter_paths
]

checks: list[tuple[str, str, list[re.Pattern[str]], list[Path]]] = [
    (
        "ODS-INV-001 secondary-only prohibited runtime surfaces",
        "No DNS UPDATE/admin/primary-serving surface terms found in runtime Rust source; RFC 9432 catalog-zone secondary support is allowed.",
        [
            re.compile(r"\bOpcode::Update\b"),
            re.compile(r"\bDynamicUpdate\b", re.IGNORECASE),
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
        "No reload/runtime configuration/admin control surface terms found outside the audited POSIX signal-disposition adapter; RFC 9432 catalog members are dynamic zone data from configured transfer primaries.",
        [
            re.compile(r"\bSIGHUP\b"),
            re.compile(r"\breload\b", re.IGNORECASE),
            re.compile(r"\breread\b", re.IGNORECASE),
            re.compile(r"\bre-read\b", re.IGNORECASE),
            re.compile(r"\badmin(istrative)?[_ -]?(api|socket|port|interface)\b", re.IGNORECASE),
        ],
        runtime_sources_without_unsafe_adapters,
    ),
    (
        "ODS-INV-006 first-party safe-Rust discipline",
        "No first-party runtime unsafe constructs found outside audited OS adapter files.",
        [
            re.compile(r"\bunsafe\s*(?:\{|fn|impl|trait|extern)"),
        ],
        runtime_sources_without_unsafe_adapters,
    ),
    (
        "ODS-INV-007 authoritative-only response composition",
        "No resolver, forwarding, or external lookup surface found in runtime Rust source.",
        [
            re.compile(r"\bresolv\.conf\b", re.IGNORECASE),
            re.compile(r"\btrust[-_]dns[-_]resolver\b", re.IGNORECASE),
            re.compile(r"\bhickory[-_]resolver\b", re.IGNORECASE),
            re.compile(r"\bforward(?:er|ing)?\b", re.IGNORECASE),
            re.compile(r"\brecursive\b", re.IGNORECASE),
            re.compile(r"\bstub[_ -]?resolver\b", re.IGNORECASE),
        ],
        list(runtime_sources),
    ),
    (
        "ODS-INV-008 single-process architecture",
        "No runtime subprocess, fork, or exec invocation surface found in runtime Rust source.",
        [
            re.compile(r"\bstd::process::Command\b"),
            re.compile(r"\btokio::process::Command\b"),
            re.compile(r"\bCommand::new\b"),
            re.compile(r"\bfork\b"),
            re.compile(r"\bexec[lvpe]*\b"),
        ],
        list(runtime_sources),
    ),
    (
        "ODS-INV-009 static composition and no runtime code loading",
        "No plugin, embedded interpreter, or dynamic-library loading surface found in runtime Rust source.",
        [
            re.compile(r"\blibloading\b", re.IGNORECASE),
            re.compile(r"\bdlopen\b", re.IGNORECASE),
            re.compile(r"\bplugin\b", re.IGNORECASE),
            re.compile(r"\bwasmtime\b", re.IGNORECASE),
            re.compile(r"\bdeno_core\b", re.IGNORECASE),
            re.compile(r"\brhai\b", re.IGNORECASE),
            re.compile(r"\bmlua\b", re.IGNORECASE),
            re.compile(r"\bpython\b", re.IGNORECASE),
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
    "crates/oxidedns-core/src/config.rs: configuration and TSIG secret file reads at startup validation or config dump",
    "crates/oxidedns-server/src/lib.rs: XoT certificate/key/trust-anchor reads during startup validation or transfer setup",
]
for item in allowed_reads:
    print(f"  {item}")

print()
print("audited_unsafe_boundaries:")
for item in sorted(audited_unsafe_adapter_paths):
    print(f"  {item}: reviewed by scripts/audit-safe-rust.sh and excluded from network-input parsing paths")
if tool_unsafe_adapter_paths:
    print("audited_tool_unsafe_boundaries:")
    for item in sorted(tool_unsafe_adapter_paths):
        print(f"  {item}: reviewed by scripts/audit-safe-rust.sh and excluded from OxideDNS runtime invariant scope")

if failures:
    print()
    print("architectural_invariant_audit=failed")
    for failure in failures:
        print(f"failure={failure}")
    raise SystemExit(1)

print()
print("architectural_invariant_audit=passed")
PY
