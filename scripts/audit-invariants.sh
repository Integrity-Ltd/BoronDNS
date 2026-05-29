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
dns_text = runtime_sources[Path("crates/oxidedns-core/src/dns.rs")]
config_text = runtime_sources[Path("crates/oxidedns-core/src/config.rs")]
server_text = runtime_sources[Path("crates/oxidedns-server/src/lib.rs")]

print()
print("check=ODS-INV-003 atomic publish evidence")
required_fragments = [
    ("ZoneStore ArcSwap", "ArcSwap<ZoneDirectory>", zone_text),
    ("ZoneDirectory suffix index", "suffix_index: HashMap<Vec<u8>, Arc<ZoneStoreEntry>>", zone_text),
    ("suffix-index lookup", "fn find_best_match", zone_text),
    ("writer publish lock", "publish_lock: Arc<Mutex<()>>", zone_text),
    ("published zone handle", "pub struct PublishedZone", zone_text),
    ("snapshot entry", "snapshot: Arc<ZoneSnapshot>", zone_text),
    ("published ZoneImage entry", "image: Option<Arc<ZoneImage>>", zone_text),
    ("borrowed canonical wire suffix lookup", "fn canonical_wire_suffix_key", dns_text),
    (
        "runtime ZoneImage metrics observer",
        "answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image",
        server_text,
    ),
    (
        "fixed ZoneImage serve-failure reason metrics",
        "oxidedns_zone_image_serve_failures_by_reason_total",
        server_text,
    ),
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
    print("evidence=ZoneStore publishes complete snapshot plus ZoneImage entries through a suffix-indexed ArcSwap directory with writer-side serialized replacement.")

print()
print("check=ZoneImage always-on serving promotion")
promotion_failures = []
if "zone_image_serve_enabled" in config_text:
    promotion_failures.append("QuerySettings still exposes zone_image_serve_enabled")
if "zone_image_serve_enabled" in server_text:
    promotion_failures.append("runtime server still branches on zone_image_serve_enabled")
if "answer_message_with_notify_hooks_lookup_metrics_observer_snapshot_rollback" in server_text:
    promotion_failures.append("runtime server still imports or calls snapshot rollback serving")
if promotion_failures:
    print("status=failed")
    for failure in promotion_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage serving is not always-on in the runtime: "
        + ", ".join(promotion_failures)
    )
else:
    print("status=passed")
    print("evidence=QuerySettings no longer exposes a live snapshot-serving rollback switch; UDP/TCP runtime serving always enters the required-provider ZoneImage path.")

print()
print("check=ZoneImage packet-hot-path materialization")
materialization_markers = [
    "materialize_lookup_result",
    "materialize_answers",
    "lookup_response(",
]
materialization_hits = [
    marker for marker in materialization_markers if marker in dns_text
]
if materialization_hits:
    print("status=failed")
    for marker in materialization_hits:
        print(f"  marker={marker}")
    failures.append(
        "ZoneImage packet response code still references materializing lookup APIs: "
        + ", ".join(materialization_hits)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage packet response code observes plan metrics and emits wire records without materializing LookupResult or ResourceRecord vectors.")

print()
print("check=ZoneImage default hot-path snapshot isolation")
answer_query_start = dns_text.find("fn answer_query_message")
answer_query_end = dns_text.find("enum ZoneImageAnswerAttempt", answer_query_start)
if answer_query_start >= 0 and answer_query_end >= 0:
    answer_query_text = dns_text[answer_query_start:answer_query_end]
else:
    answer_query_text = ""
snapshot_isolation_failures = []
if "pub fn origin(&self) -> &DomainName" not in zone_text:
    snapshot_isolation_failures.append("missing PublishedZone origin accessor")
if "pub fn state(&self) -> ZoneState" not in zone_text:
    snapshot_isolation_failures.append("missing PublishedZone state accessor")
if "Option<ZoneImageProvider" in dns_text:
    snapshot_isolation_failures.append("ZoneImage provider is still optional")
if "answer_message_with_notify_hooks_lookup_metrics_observer_snapshot_rollback" in dns_text:
    snapshot_isolation_failures.append("snapshot rollback lookup-metrics API still exists")
if "answer_message_with_notify_hooks_snapshot_rollback_and_query_observer" in dns_text:
    snapshot_isolation_failures.append("snapshot rollback query-observer API still exists")
if "fn answer_query_message_snapshot_rollback" in dns_text:
    snapshot_isolation_failures.append("snapshot rollback helper still exists")
if "QueryServingPath" in dns_text:
    snapshot_isolation_failures.append("query serving still carries runtime path selection")
if "snapshot_for_rollback_or_oracle" in answer_query_text:
    snapshot_isolation_failures.append("answer_query_message uses rollback/oracle snapshot accessor")
if ".lookup_with_options(" in answer_query_text:
    snapshot_isolation_failures.append("answer_query_message runs old snapshot lookup")
if snapshot_isolation_failures:
    print("status=failed")
    for failure in snapshot_isolation_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage default hot path is not isolated from snapshot lookup: "
        + ", ".join(snapshot_isolation_failures)
    )
else:
    print("status=passed")
    print("evidence=Default ZoneImage serving requires a provider, checks published state directly, and has no snapshot rollback serving API, runtime path selector, snapshot clone, or lookup_with_options call.")

print()
print("check=Core convenience answer APIs default to ZoneImage")
hooks_start = dns_text.find("pub fn answer_message_with_notify_hooks(")
observer_start = dns_text.find("#[allow(clippy::too_many_arguments)]", hooks_start)
if hooks_start >= 0 and observer_start >= 0:
    hooks_text = dns_text[hooks_start:observer_start]
else:
    hooks_text = ""
convenience_failures = []
if "answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image" not in hooks_text:
    convenience_failures.append("answer_message_with_notify_hooks does not enter ZoneImage serving")
if "answer_message_with_notify_hooks_and_query_observer" in hooks_text:
    convenience_failures.append("answer_message_with_notify_hooks still delegates to materializing LookupResult observer")
if "published.active_zone_image()" not in hooks_text:
    convenience_failures.append("answer_message_with_notify_hooks does not require active published ZoneImage")
if "pub fn answer_message_with_notify_hooks_and_query_observer" in dns_text:
    convenience_failures.append("ambiguous materialized query observer API still exists")
if "pub fn answer_message_with_notify_hooks_snapshot_rollback_and_query_observer" in dns_text:
    convenience_failures.append("snapshot rollback query observer API still exists")
if "pub fn answer_message_with_notify_hooks_lookup_metrics_observer_snapshot_rollback" in dns_text:
    convenience_failures.append("snapshot rollback lookup-metrics API still exists")
if convenience_failures:
    print("status=failed")
    for failure in convenience_failures:
        print(f"  failure={failure}")
    failures.append(
        "Core convenience answer APIs still default to the old query layout: "
        + ", ".join(convenience_failures)
    )
else:
    print("status=passed")
    print("evidence=answer_datagram/answer_message convenience calls enter required-provider ZoneImage serving and no materialized LookupResult snapshot rollback observer APIs remain.")

print()
print("check=Runtime metric observation avoids default snapshot clone")
observe_query_start = server_text.find("fn observe_query_metrics")
observe_query_end = server_text.find("fn observe_dns_cookie_metrics", observe_query_start)
if observe_query_start >= 0 and observe_query_end >= 0:
    observe_query_text = server_text[observe_query_start:observe_query_end]
else:
    observe_query_text = ""
observation_failures = []
if "published_zone.snapshot()" in observe_query_text:
    observation_failures.append("observe_query_metrics clones PublishedZone snapshot")
if "snapshot_for_rollback_or_oracle" in observe_query_text:
    observation_failures.append("observe_query_metrics uses rollback/oracle snapshot accessor")
if "lookup_with_options" in observe_query_text:
    observation_failures.append("observe_query_metrics runs old snapshot lookup")
if "published_zone.origin()" not in observe_query_text:
    observation_failures.append("observe_query_metrics does not use PublishedZone origin accessor")
if "zone_image_shadow" in observe_query_text:
    observation_failures.append("observe_query_metrics still invokes live shadow validation")
if observation_failures:
    print("status=failed")
    for failure in observation_failures:
        print(f"  failure={failure}")
    failures.append(
        "Runtime metric observation still depends on old snapshot clone: "
        + ", ".join(observation_failures)
    )
else:
    print("status=passed")
    print("evidence=Runtime query observation records zone metrics through PublishedZone metadata accessors and contains no snapshot clone, old snapshot lookup, or live shadow-validation oracle.")

print()
print("check=ZoneStore query lookup exposes PublishedZone handle")
zone_store_api_failures = []
if "pub fn find_zone" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes query-suffix lookup as Arc<ZoneSnapshot>")
if "zone_image_for_snapshot" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes snapshot-to-ZoneImage bridge")
if "pub fn find_published_zone" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing PublishedZone query lookup")
if "pub fn snapshot(&self)" in zone_text:
    zone_store_api_failures.append("PublishedZone still exposes generic snapshot accessor")
if "snapshot_for_rollback_or_oracle" in zone_text:
    zone_store_api_failures.append("PublishedZone still exposes rollback/oracle snapshot accessor")
if zone_store_api_failures:
    print("status=failed")
    for failure in zone_store_api_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneStore still exposes old query-time layout lookup APIs: "
        + ", ".join(zone_store_api_failures)
    )
else:
    print("status=passed")
    print("evidence=Query-suffix lookup returns PublishedZone handles without exposing snapshot rollback accessors; exact-origin snapshot lookup remains for transfer/catalog builder work.")

print()
print("check=ZoneImage live shadow oracle retired")
live_shadow_hits = [
    marker
    for marker in [
        "zone_image_shadow",
        "ZoneImageShadowValidator",
        "snapshot_lookup_summary",
        "oxidedns_zone_image_shadow",
    ]
    if marker in server_text or marker in config_text
]
if live_shadow_hits:
    print("status=failed")
    for marker in live_shadow_hits:
        print(f"  marker={marker}")
    failures.append(
        "Runtime still exposes live shadow/oracle diagnostics: "
        + ", ".join(live_shadow_hits)
    )
else:
    print("status=passed")
    print("evidence=Live runtime shadow validation and its metrics/config surface are retired; snapshot comparison remains in offline tests and benchmarks only.")

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
