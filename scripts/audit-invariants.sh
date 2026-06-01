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
axfr_text = runtime_sources[Path("crates/oxidedns-core/src/axfr.rs")]
catalog_text = runtime_sources[Path("crates/oxidedns-core/src/catalog.rs")]
config_text = runtime_sources[Path("crates/oxidedns-core/src/config.rs")]
server_text = runtime_sources[Path("crates/oxidedns-server/src/lib.rs")]
bench_text = (repo_root / "crates/oxidedns-core/examples/zone_image_bench.rs").read_text(
    encoding="utf-8"
)

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
    ("published metadata entry", "shape: Option<ZoneShapeSummary>", zone_text),
    ("published metadata iterator", "pub fn zone_metadata", zone_text),
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
    (
        "transfer Arc snapshot publication",
        "pub fn insert_snapshot_arc_for_transfer(&self, snapshot: Arc<ZoneSnapshot>) -> ZoneMetadata",
        zone_text,
    ),
    (
        "runtime publishes shared transfer snapshot and consumes cached metadata",
        "let metadata = zones.insert_snapshot_arc_for_transfer(snapshot.clone())",
        server_text,
    ),
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
print("check=Question parse avoids question-wire copy")
question_start = dns_text.find("pub struct Question")
question_end = dns_text.find("impl Question", question_start)
if question_start >= 0 and question_end >= 0:
    question_text = dns_text[question_start:question_end]
else:
    question_text = ""
question_copy_failures = []
if "wire: Vec" in question_text:
    question_copy_failures.append("Question stores copied question wire Vec")
if "\n    wire_len: usize," in question_text:
    question_copy_failures.append("Question stores total question wire length instead of QNAME wire length")
if "qname_wire_len: usize" not in question_text:
    question_copy_failures.append("Question does not store parsed QNAME wire length")
if "qtype_qclass_wire: [u8; 4]" not in question_text:
    question_copy_failures.append("Question does not carry parsed QTYPE/QCLASS response bytes")
if "qname_wire_len: qname_len" not in dns_text:
    question_copy_failures.append("Question parse does not carry parsed QNAME wire length")
if (
    "fn wire_len(&self) -> usize {\n        self.qname_wire_len + self.qtype_qclass_wire.len()\n    }"
    not in dns_text
):
    question_copy_failures.append("Question::wire_len does not derive total length from carried QNAME length")
if "fn qname_wire_len(&self) -> usize {\n        self.qname_wire_len\n    }" not in dns_text:
    question_copy_failures.append("Question::qname_wire_len does not return the carried QNAME wire length")
encode_question_start = dns_text.find("fn encode_question(")
encode_question_end = dns_text.find("fn encode_name_labels", encode_question_start)
encode_question_text = (
    dns_text[encode_question_start:encode_question_end]
    if encode_question_start >= 0 and encode_question_end >= 0
    else ""
)
if "response.extend_from_slice(&question.qtype_qclass_wire)" not in encode_question_text:
    question_copy_failures.append("response question echo does not copy parsed QTYPE/QCLASS bytes")
if "question.qtype.to_be_bytes()" in encode_question_text or "question.qclass.to_be_bytes()" in encode_question_text:
    question_copy_failures.append("response question echo reencodes QTYPE/QCLASS")
if question_copy_failures:
    print("status=failed")
    for failure in question_copy_failures:
        print(f"  failure={failure}")
    failures.append(
        "Question parsing reintroduced per-packet question-wire copying: "
        + ", ".join(question_copy_failures)
    )
else:
    print("status=passed")
    print("evidence=Question stores the parsed QNAME wire length and parsed QTYPE/QCLASS bytes needed for response echo, compression seeding, and section offsets; total question length is derived only where needed, and responses re-encode parsed labels without a copied question-wire buffer or QTYPE/QCLASS byte conversion.")

print()
print("check=EDNS record parsing avoids owner and RDATA copies")
parsed_record_start = dns_text.find("struct ParsedRecordView")
parsed_record_end = dns_text.find("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\nenum EdnsError", parsed_record_start)
parsed_record_text = (
    dns_text[parsed_record_start:parsed_record_end]
    if parsed_record_start >= 0 and parsed_record_end >= 0
    else ""
)
parse_additional_start = dns_text.find("fn parse_record_view(")
parse_additional_end = dns_text.find("fn parse_edns_options", parse_additional_start)
parse_additional_text = (
    dns_text[parse_additional_start:parse_additional_end]
    if parse_additional_start >= 0 and parse_additional_end >= 0
    else ""
)
edns_rdata_copy_failures = []
if "struct ParsedRecordView<'a>" not in parsed_record_text:
    edns_rdata_copy_failures.append("ParsedRecord is not a borrowed packet view")
if "rdata: &'a [u8]" not in parsed_record_text:
    edns_rdata_copy_failures.append("ParsedRecord does not borrow RDATA from the packet")
if "owner_is_root: bool" not in parsed_record_text:
    edns_rdata_copy_failures.append("ParsedRecord does not carry scanned root-owner metadata")
if "DomainName::parse" in parse_additional_text:
    edns_rdata_copy_failures.append("parse_record_view materializes record owner labels")
if ".to_vec()" in parse_additional_text or ".to_owned()" in parse_additional_text:
    edns_rdata_copy_failures.append("parse_record_view copies record RDATA or owner data")
if "let rdata = &packet[offset..offset + rdlength];" not in parse_additional_text:
    edns_rdata_copy_failures.append("parse_record_view does not slice RDATA directly from the packet")
if edns_rdata_copy_failures:
    print("status=failed")
    for failure in edns_rdata_copy_failures:
        print(f"  failure={failure}")
    failures.append(
        "EDNS/NOTIFY record parsing reintroduced per-query owner or RDATA allocation: "
        + ", ".join(edns_rdata_copy_failures)
    )
else:
    print("status=passed")
    print("evidence=Record parsing keeps EDNS and NOTIFY SOA RDATA as borrowed packet slices and scans owner metadata without allocating DomainName labels per parsed record.")

print()
print("check=EDNS skipped record headers avoid owner allocation")
parse_record_header_start = dns_text.find("fn parse_record_header(")
parse_record_header_end = dns_text.find("fn parse_record_view(", parse_record_header_start)
parse_record_header_text = (
    dns_text[parse_record_header_start:parse_record_header_end]
    if parse_record_header_start >= 0 and parse_record_header_end >= 0
    else ""
)
edns_record_header_failures = []
if "fn skip_compressed_name(" not in dns_text:
    edns_record_header_failures.append("skip_compressed_name helper is missing")
if "skip_compressed_name(packet, offset)" not in parse_record_header_text:
    edns_record_header_failures.append("parse_record_header does not skip owner names with skip_compressed_name")
if "DomainName::parse" in parse_record_header_text:
    edns_record_header_failures.append("parse_record_header materializes owner labels while scanning record headers")
if edns_record_header_failures:
    print("status=failed")
    for failure in edns_record_header_failures:
        print(f"  failure={failure}")
    failures.append(
        "EDNS answer/authority record-header scans reintroduced owner allocation: "
        + ", ".join(edns_record_header_failures)
    )
else:
    print("status=passed")
    print("evidence=Answer and authority record-header scans skip compressed owner names without materializing DomainName labels.")

print()
print("check=NOTIFY SOA validation avoids owner and SOA-name allocation")
validate_notify_start = dns_text.find("fn validate_notify_answer_soa(")
validate_notify_end = dns_text.find("fn parse_echoable_question", validate_notify_start)
validate_notify_text = (
    dns_text[validate_notify_start:validate_notify_end]
    if validate_notify_start >= 0 and validate_notify_end >= 0
    else ""
)
soa_serial_start = dns_text.find("fn soa_serial(")
soa_serial_end = dns_text.find("fn parse_echoable_question", soa_serial_start)
soa_serial_text = (
    dns_text[soa_serial_start:soa_serial_end]
    if soa_serial_start >= 0 and soa_serial_end >= 0
    else ""
)
notify_soa_failures = []
if "parse_record_view_with_owner_match(packet, offset, &question.qname)" not in validate_notify_text:
    notify_soa_failures.append("NOTIFY SOA validation does not combine borrowed record parsing with owner matching")
if "owner_matches_question" not in validate_notify_text:
    notify_soa_failures.append("NOTIFY SOA owner validation does not consume the single-scan owner match")
if "compressed_name_eq_ignore_ascii_case" in dns_text:
    notify_soa_failures.append("NOTIFY SOA validation retained a second compressed-owner scan helper")
if "DomainName::parse" in validate_notify_text or "DomainName::parse" in soa_serial_text:
    notify_soa_failures.append("NOTIFY SOA validation materializes owner, MNAME, or RNAME labels")
if "skip_compressed_name(packet, rdata_offset)" not in soa_serial_text:
    notify_soa_failures.append("SOA serial parser does not skip MNAME without allocation")
if "skip_compressed_name(packet, rname_offset)" not in soa_serial_text:
    notify_soa_failures.append("SOA serial parser does not skip RNAME without allocation")
if notify_soa_failures:
    print("status=failed")
    for failure in notify_soa_failures:
        print(f"  failure={failure}")
    failures.append(
        "NOTIFY SOA validation reintroduced owner or SOA-name allocation: "
        + ", ".join(notify_soa_failures)
    )
else:
    print("status=passed")
    print("evidence=NOTIFY SOA validation combines borrowed record parsing with single-scan compressed owner matching and skips SOA MNAME/RNAME directly to the serial field without allocating DomainName labels.")

print()
print("check=EDNS response option fixed prefixes are preencoded")
encode_opt_start = dns_text.find("fn encode_opt_record(")
encode_opt_end = dns_text.find("fn edns_response_base_shape(", encode_opt_start)
encode_opt_text = (
    dns_text[encode_opt_start:encode_opt_end]
    if encode_opt_start >= 0 and encode_opt_end >= 0
    else ""
)
append_edns_start = dns_text.find("fn append_edns_response_options(")
append_edns_end = dns_text.find("fn append_edns_padding(", append_edns_start)
append_edns_text = (
    dns_text[append_edns_start:append_edns_end]
    if append_edns_start >= 0 and append_edns_end >= 0
    else ""
)
edns_prefix_failures = []
for const_name in [
    "OPT_OWNER_AND_TYPE_WIRE",
    "EDNS_TCP_KEEPALIVE_RESPONSE_OPTION_PREFIX",
    "EDNS_COOKIE_RESPONSE_OPTION_PREFIX",
    "EDNS_EXTENDED_DNS_ERROR_RESPONSE_OPTION_PREFIX",
]:
    if f"const {const_name}:" not in dns_text:
        edns_prefix_failures.append(f"{const_name} constant is missing")
if "response.extend_from_slice(&OPT_OWNER_AND_TYPE_WIRE)" not in encode_opt_text:
    edns_prefix_failures.append("OPT owner/type prefix is not copied from preencoded bytes")
if "(RecordType::Opt as u16).to_be_bytes()" in encode_opt_text:
    edns_prefix_failures.append("OPT type is rebuilt from scalar bytes per response")
for prefix_name in [
    "EDNS_TCP_KEEPALIVE_RESPONSE_OPTION_PREFIX",
    "EDNS_COOKIE_RESPONSE_OPTION_PREFIX",
    "EDNS_EXTENDED_DNS_ERROR_RESPONSE_OPTION_PREFIX",
]:
    if f"response.extend_from_slice(&{prefix_name})" not in append_edns_text:
        edns_prefix_failures.append(f"{prefix_name} is not used by EDNS option emission")
if "EDNS_TCP_KEEPALIVE_OPTION.to_be_bytes()" in append_edns_text:
    edns_prefix_failures.append("TCP keepalive option prefix is rebuilt per response")
if "EDNS_COOKIE_OPTION.to_be_bytes()" in append_edns_text:
    edns_prefix_failures.append("DNS Cookie option prefix is rebuilt per response")
if "EDNS_EXTENDED_DNS_ERROR_OPTION.to_be_bytes()" in append_edns_text:
    edns_prefix_failures.append("EDE option prefix is rebuilt per response")
if "2u16.to_be_bytes()" in append_edns_text:
    edns_prefix_failures.append("fixed two-byte EDNS option lengths are rebuilt per response")
if edns_prefix_failures:
    print("status=failed")
    for failure in edns_prefix_failures:
        print(f"  failure={failure}")
    failures.append(
        "EDNS response option emission lost fixed-prefix preencoding: "
        + ", ".join(edns_prefix_failures)
    )
else:
    print("status=passed")
    print("evidence=EDNS OPT owner/type and fixed-length response option prefixes are copied from preencoded byte constants; only dynamic payload lengths remain encoded at runtime.")

print()
print("check=EDNS padding sizing uses current response length")
append_padding_start = dns_text.find("fn append_edns_padding(")
append_padding_end = dns_text.find("pub fn request_has_valid_dns_server_cookie(", append_padding_start)
append_padding_text = (
    dns_text[append_padding_start:append_padding_end]
    if append_padding_start >= 0 and append_padding_end >= 0
    else ""
)
padding_sizing_failures = []
if append_padding_start < 0:
    padding_sizing_failures.append("append_edns_padding function is missing")
if "response_len_before_opt" in append_edns_text or "response_len_before_opt" in append_padding_text:
    padding_sizing_failures.append("EDNS padding still carries response_len_before_opt bookkeeping")
if "rdata_start" in append_edns_text or "rdata_start" in append_padding_text:
    padding_sizing_failures.append("EDNS padding still carries rdata_start bookkeeping")
if "padding_len: usize" not in append_padding_text:
    padding_sizing_failures.append("EDNS padding emission does not consume carried padding length")
if padding_sizing_failures:
    print("status=failed")
    for failure in padding_sizing_failures:
        print(f"  failure={failure}")
    failures.append(
        "EDNS padding sizing reintroduced redundant OPT-offset bookkeeping: "
        + ", ".join(padding_sizing_failures)
    )
else:
    print("status=passed")
    print("evidence=EDNS padding emission consumes the carried padding length from the response option shape, without carrying OPT-start or RDATA-start offsets through the append path.")

print()
print("check=EDNS response option shape is computed once before emission")
shape_start = dns_text.find("fn edns_response_base_shape(")
shape_end = dns_text.find("fn append_edns_response_options(", shape_start)
shape_text = (
    dns_text[shape_start:shape_end]
    if shape_start >= 0 and shape_end >= 0
    else ""
)
edns_shape_failures = []
if "struct EdnsResponseBaseShape" not in dns_text:
    edns_shape_failures.append("EDNS fixed response option base shape struct is missing")
if "struct EdnsResponseOptionsShape" not in dns_text:
    edns_shape_failures.append("EDNS response option shape struct is missing")
if "let base_shape = edns_response_base_shape(" not in encode_opt_text:
    edns_shape_failures.append("OPT encoder does not compute a carried fixed response option base shape")
if "let shape = edns_response_options_shape_from_base(" not in encode_opt_text:
    edns_shape_failures.append("OPT encoder does not compute a carried response option shape")
if "shape.rdata_len as u16" not in encode_opt_text:
    edns_shape_failures.append("OPT RDLENGTH is not written from carried option shape")
if "rdlength_offset" in encode_opt_text or "copy_from_slice(&(rdlength as u16).to_be_bytes())" in encode_opt_text:
    edns_shape_failures.append("OPT encoder still patches RDLENGTH after option emission")
if "append_edns_response_options(edns, options, shape, response)" not in encode_opt_text:
    edns_shape_failures.append("OPT encoder does not pass carried option shape into emission")
for shape_field in [
    "tcp_keepalive_response",
    "nsid_len",
    "cookie_response",
    "extended_dns_error",
    "padding_len",
    "rdata_len",
]:
    if shape_field not in shape_text:
        edns_shape_failures.append(f"EDNS response option shape does not compute {shape_field}")
if "shape.tcp_keepalive_response" not in append_edns_text:
    edns_shape_failures.append("TCP keepalive emission does not consume carried shape")
if "shape.nsid_len" not in append_edns_text:
    edns_shape_failures.append("NSID emission does not consume carried shape")
if "shape.cookie_response" not in append_edns_text:
    edns_shape_failures.append("DNS Cookie emission does not consume carried shape")
if "shape.extended_dns_error" not in append_edns_text:
    edns_shape_failures.append("EDE emission does not consume carried shape")
if "shape.padding_len" not in append_edns_text:
    edns_shape_failures.append("padding emission does not consume carried shape")
if edns_shape_failures:
    print("status=failed")
    for failure in edns_shape_failures:
        print(f"  failure={failure}")
    failures.append(
        "EDNS response option emission lost carried shape discipline: "
        + ", ".join(edns_shape_failures)
    )
else:
    print("status=passed")
    print("evidence=The OPT encoder computes one EDNS fixed-option base shape and one final response option shape, writes OPT RDLENGTH from the carried RDATA length, and option emission consumes the carried shape fields instead of rechecking response-option presence.")

print()
print("check=Direct ZoneImage answer uses exact-plan invariant")
zone_image_text = runtime_sources[Path("crates/oxidedns-core/src/zone_image.rs")]
direct_start = dns_text.find("fn build_direct_zone_image_answer_response")
direct_end = dns_text.find("#[allow(clippy::too_many_arguments)]", direct_start)
if direct_start >= 0 and direct_end >= 0:
    direct_text = dns_text[direct_start:direct_end]
else:
    direct_text = ""
try_answer_start = dns_text.find("fn try_answer_with_zone_image")
try_answer_end = dns_text.find("pub fn chaos_query_observation", try_answer_start)
try_answer_text = (
    dns_text[try_answer_start:try_answer_end]
    if try_answer_start >= 0 and try_answer_end >= 0
    else ""
)
lookup_direct_plan_start = zone_image_text.find("    pub fn lookup_direct_answer_plan(")
lookup_direct_plan_end = zone_image_text.find("    pub fn lookup_response_plan(", lookup_direct_plan_start)
lookup_direct_plan_text = (
    zone_image_text[lookup_direct_plan_start:lookup_direct_plan_end]
    if lookup_direct_plan_start >= 0 and lookup_direct_plan_end >= 0
    else ""
)
direct_failures = []
if "direct_answer_candidate()" not in direct_text:
    direct_failures.append("direct answer helper does not use cached direct-answer plan eligibility")
if "if metadata.dnssec_requested() || !plan.direct_answer_candidate()" in direct_text:
    direct_failures.append("direct answer helper rechecks DNSSEC request state after caller-side DO-bit gating")
if '"direct ZoneImage answer builder is only called for non-DNSSEC requests"' not in direct_text:
    direct_failures.append("direct answer helper does not document the caller-side non-DNSSEC contract")
if "direct_rrset_wire(*rrset_id)" not in direct_text:
    direct_failures.append("direct answer helper does not fetch compiled RRset metadata through the single direct view")
if "direct_copy_eligible" in direct_text:
    direct_failures.append("direct answer helper/view reintroduced a post-view eligibility branch")
if "direct_copy_rrset_flags" in zone_image_text:
    direct_failures.append("direct-copy eligibility reintroduced a separate RRset side-bitset")
if "if rrset.direct_answer_body_len == 0" not in zone_image_text:
    direct_failures.append("direct RRset view does not reject ineligible RRsets from compiled direct body length")
if "answer_count == 0" in direct_text:
    direct_failures.append("direct answer helper reintroduced redundant zero-record guard after eligible direct view")
if '"eligible direct-answer RRset must contain at least one record"' not in zone_image_text:
    direct_failures.append("direct RRset view does not document the non-empty eligible-view invariant")
if "plan.rcode(),\n        plan.authoritative()," in direct_text:
    direct_failures.append("direct answer helper reintroduced dynamic flag reads after direct-plan invariant")
if "rrset_type(" in direct_text or "rrset_wire_record_count" in direct_text:
    direct_failures.append("direct answer helper reintroduced separate compiled RRset metadata lookups")
if "wire_labels_match_name_suffix(rrset.owner_wire, question.qname.labels())" in direct_text:
    direct_failures.append("direct answer helper reparses compiled owner wire instead of trusting exact direct-plan construction")
if "low_rrtype_bitmap: [u64; LOW_RRTYPE_BITMAP_WORDS]" not in zone_image_text:
    direct_failures.append("ZoneImage does not carry the compiled low-RRtype bitmap for direct-preflight misses")
if "build_low_rrtype_bitmap(&self.image_rrsets)" not in zone_image_text:
    direct_failures.append("ZoneImage builder does not compile the low-RRtype bitmap from immutable RRsets")
if "lookup_direct_answer_plan_with_ascii_lowercase_hint(" not in lookup_direct_plan_text:
    direct_failures.append("direct answer planning does not expose parser-carried lowercase QNAME hint")
if "self.find_node_with_ascii_lowercase_hint(qname, qname_ascii_lowercase)" not in lookup_direct_plan_text:
    direct_failures.append("direct answer planning does not use lowercase-hinted trie lookup")
if (
    "lookup_direct_answer_plan_with_ascii_lowercase_hint(" not in try_answer_text
    or "question.qname_ascii_lowercase()," not in try_answer_text
):
    direct_failures.append("query path does not pass the parser-carried lowercase QNAME fact into direct planning")
if "if !self.low_rrtype_may_exist(qtype)" not in lookup_direct_plan_text:
    direct_failures.append("direct answer planning does not skip RR types known absent from the compiled image")
if lookup_direct_plan_text.find("if !self.low_rrtype_may_exist(qtype)") > lookup_direct_plan_text.find("let node_index = self.find_node_with_ascii_lowercase_hint"):
    direct_failures.append("direct absent-RRtype precheck runs after the trie lookup")
if lookup_direct_plan_text.find("let rrset_id = self.find_rrset_at_node(node_index, qtype, qclass)?") > lookup_direct_plan_text.find("self.covering_delegation_blocks_direct_answer"):
    direct_failures.append("direct answer planning checks cut/DNAME policy before proving the queried RRset exists")
if "fn covering_dname_blocks_direct_answer" in zone_image_text:
    dname_direct_guard_start = zone_image_text.find("fn covering_dname_blocks_direct_answer")
    dname_direct_guard_end = zone_image_text.find("fn nearest_inherited_in_dname", dname_direct_guard_start)
    dname_direct_guard_text = zone_image_text[dname_direct_guard_start:dname_direct_guard_end]
    if "if !self.low_rrtype_may_exist(RecordType::Dname as u16)" not in dname_direct_guard_text:
        direct_failures.append("direct DNAME covering guard does not skip images with no compiled DNAME RRsets")
direct_view_start = zone_image_text.find("pub(crate) struct ZoneImageDirectRrset")
direct_view_end = zone_image_text.find("#[derive(Debug, Clone, Copy, PartialEq, Eq)]", direct_view_start)
direct_view_text = (
    zone_image_text[direct_view_start:direct_view_end]
    if direct_view_start >= 0 and direct_view_end >= 0
    else ""
)
direct_rrset_wire_start = zone_image_text.find("    pub(crate) fn direct_rrset_wire(")
direct_rrset_wire_end = zone_image_text.find(
    "    pub(crate) fn append_eligible_direct_answer_wire", direct_rrset_wire_start
)
direct_rrset_wire_text = (
    zone_image_text[direct_rrset_wire_start:direct_rrset_wire_end]
    if direct_rrset_wire_start >= 0 and direct_rrset_wire_end >= 0
    else ""
)
direct_prefix_start = zone_image_text.find("fn direct_answer_record_prefix")
direct_prefix_end = zone_image_text.find("fn push_direct_answer_body", direct_prefix_start)
direct_prefix_text = (
    zone_image_text[direct_prefix_start:direct_prefix_end]
    if direct_prefix_start >= 0 and direct_prefix_end >= 0
    else ""
)
if "owner_wire" in direct_view_text:
    direct_failures.append("direct RRset view still carries owner wire used only for redundant hot-path prechecks")
if "direct_copy_eligible" in direct_view_text:
    direct_failures.append("direct RRset view still carries a post-view eligibility flag")
if (
    "fn push_direct_answer_body(" not in zone_image_text
    or "let record_prefix = direct_answer_record_prefix(fixed_fields);" not in zone_image_text
    or "ZoneImageDirectRrsetBody::Template" not in zone_image_text
    or "out.extend_from_slice(body_wire)" not in zone_image_text
):
    direct_failures.append("direct answer path does not use the compile-built compressed-owner body template")
if "let (body, body_wire_len) =" not in direct_rrset_wire_text:
    direct_failures.append("direct RRset view does not compute body kind and emitted length in one branch")
if "section_count_header_bytes: [u8; 6]" not in direct_view_text:
    direct_failures.append("direct RRset view does not carry preencoded no-EDNS section-count bytes")
if "section_count_header_bytes_with_edns: [u8; 6]" not in direct_view_text:
    direct_failures.append("direct RRset view does not carry preencoded EDNS-adjusted section-count bytes")
if "rrset.section_count_header_bytes(response_sizing.edns.additional_count != 0)" not in direct_text:
    direct_failures.append("direct answer helper does not consume direct-view section-count bytes")
if "zone_image_section_count_header_bytes(answer_count, 0" in direct_text:
    direct_failures.append("direct answer helper reencodes direct response section-count bytes")
fallback_branch = direct_rrset_wire_text.find(
    "if rrset.direct_answer_body_len == DIRECT_ANSWER_BODY_RECORDS_FALLBACK"
)
records_lookup = direct_rrset_wire_text.find("let records = self")
if records_lookup >= 0 and fallback_branch >= 0 and records_lookup < fallback_branch:
    direct_failures.append("direct RRset template path still fetches the record slice before selecting template body")
if "fn direct_answer_body_wire_len(" in zone_image_text:
    direct_failures.append("direct answer emitted-body length is still recomputed by a separate helper")
if "zone_image_record_fixed_fields(" in direct_prefix_text:
    direct_failures.append("direct answer prefix still rebuilds TYPE/CLASS/TTL from scalar metadata")
if "wire_names_equal_ignore_ascii_case" in direct_text:
    direct_failures.append("direct answer helper reintroduced post-encode owner comparison")
if "answer_count_offset" in direct_text:
    direct_failures.append("direct answer helper patches answer count after copying records")
if "zone_image_response_capacity_hint(" not in direct_text:
    direct_failures.append("direct answer helper does not share precise ZoneImage response capacity sizing")
if "if metadata.edns.is_some() { 64 } else { 0 }" in direct_text:
    direct_failures.append("direct answer helper still reserves fixed EDNS slack")
if "zone_image_response_prefix(" not in direct_text:
    direct_failures.append("direct answer helper does not share known-count ZoneImage response prefix assembly")
if "append_zone_image_response_edns(" not in direct_text:
    direct_failures.append("direct answer helper does not share ZoneImage EDNS append helper")
if "encode_opt_record(" in direct_text:
    direct_failures.append("direct answer helper reintroduced inline EDNS OPT encoding")
if "let mut rejected_direct_plan = None" not in try_answer_text:
    direct_failures.append("ZoneImage query path does not retain rejected direct semantic plans")
if "rejected_direct_plan = Some(plan)" not in try_answer_text:
    direct_failures.append("ZoneImage query path throws away direct semantic plans rejected by direct-copy emission")
if "rejected_direct_plan.unwrap_or_else" not in try_answer_text:
    direct_failures.append("ZoneImage query path does not reuse rejected direct plans before generic planning")
if direct_failures:
    print("status=failed")
    for failure in direct_failures:
        print(f"  failure={failure}")
    failures.append(
        "Direct ZoneImage answer fast path lost exact-plan discipline: "
        + ", ".join(direct_failures)
    )
else:
    print("status=passed")
    print("evidence=Direct exact-owner ZoneImage responses rely on the private direct-plan invariant instead of reparsing compiled owner wire, pass parser-carried lowercase QNAME facts into trie lookup, skip direct preflight before trie lookup when a compiled low-RRtype bitmap proves the queried low RR type is absent, prove the queried RRset exists before cut/DNAME policy guards, skip inherited-DNAME direct guard work when the same bitmap proves the image has no DNAME RRsets, fetch immutable RRset metadata through one eligible-only non-empty direct view, keep compiled body-template responses off the fallback record-slice lookup, reject ineligible RRsets from compiled direct body length without a side-bitset lookup or post-view branch, retain rejected direct semantic plans for the generic composer instead of replanning, write known NoError/authoritative flags from the direct invariant, build the compressed-owner record prefix from immutable TYPE/CLASS/TTL fixed fields, consume direct-view section-count bytes, write the DNS header through the shared known-count ZoneImage prefix helper, append OPT records through the shared ZoneImage EDNS helper, and size response capacity through the shared precise ZoneImage EDNS/capacity helper.")

print()
print("check=ZoneImage DNAME target hint avoids unnecessary synthesized lookup")
dname_hint_start = zone_image_text.find("    fn dname_synthesized_target_node_hint(")
dname_hint_end = zone_image_text.find("    fn query_node_handles(", dname_hint_start)
dname_hint_text = (
    zone_image_text[dname_hint_start:dname_hint_end]
    if dname_hint_start >= 0 and dname_hint_end >= 0
    else ""
)
target_hint_start = zone_image_text.find("    fn target_node_hint(")
target_hint_end = zone_image_text.find("    fn dname_synthesized_target_node_hint(", target_hint_start)
target_hint_text = (
    zone_image_text[target_hint_start:target_hint_end]
    if target_hint_start >= 0 and target_hint_end >= 0
    else ""
)
build_target_hint_start = zone_image_text.find("    fn build_target_node_hint(")
build_target_hint_end = zone_image_text.find("    fn precompute_nsec_ranges(", build_target_hint_start)
build_target_hint_text = (
    zone_image_text[build_target_hint_start:build_target_hint_end]
    if build_target_hint_start >= 0 and build_target_hint_end >= 0
    else ""
)
resolve_indirection_start = zone_image_text.find("    fn resolve_indirection_target")
resolve_indirection_end = zone_image_text.find("    fn add_glue_for_ns_rrset", resolve_indirection_start)
resolve_indirection_text = (
    zone_image_text[resolve_indirection_start:resolve_indirection_end]
    if resolve_indirection_start >= 0 and resolve_indirection_end >= 0
    else ""
)
dname_hint_failures = []
if "OutOfZoneParentSuffix" not in zone_image_text:
    dname_hint_failures.append("DNAME target hint does not distinguish parent-suffix out-of-zone targets")
if "fn domain_is_suffix_parent_of_origin(" not in zone_image_text:
    dname_hint_failures.append("parent-suffix origin helper is missing")
if "domain_is_suffix_parent_of_origin(qname, &self.origin)" not in target_hint_text:
    dname_hint_failures.append("runtime target hint does not classify parent-suffix out-of-zone names")
if "domain_is_suffix_parent_of_origin(name, &self.origin)" not in build_target_hint_text:
    dname_hint_failures.append("builder target hint does not precompute parent-suffix out-of-zone names")
if "ImageTargetNode::OutOfZoneParentSuffix => self.target_node_hint(synthesized_target)" not in dname_hint_text:
    dname_hint_failures.append("parent-suffix DNAME targets do not keep synthesized-target lookup")
if "ImageTargetNode::OutOfZone => ImageTargetNode::OutOfZone" not in dname_hint_text:
    dname_hint_failures.append("unrelated out-of-zone DNAME targets still fall through to synthesized-target lookup")
if "ImageTargetNode::OutOfZone | ImageTargetNode::OutOfZoneParentSuffix => {}" not in resolve_indirection_text:
    dname_hint_failures.append("indirection additional lookup does not treat both out-of-zone target hints as out-of-zone")
if dname_hint_failures:
    print("status=failed")
    for failure in dname_hint_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage DNAME target hint optimization regressed: "
        + ", ".join(dname_hint_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage precomputes parent-suffix out-of-zone DNAME targets as the only out-of-zone class that may synthesize back into the zone, while unrelated out-of-zone DNAME targets stay out-of-zone without a synthesized target trie lookup.")

print()
print("check=ZoneImage wire append helper surface stays narrow")
zone_image_text = runtime_sources[Path("crates/oxidedns-core/src/zone_image.rs")]
wire_helper_failures = []
if "pub fn append_plan_wire" not in zone_image_text:
    wire_helper_failures.append("benchmark append_plan_wire hook is missing")
for helper in (
    "pub fn rrset_wire",
    "pub fn append_answer_wire",
    "pub fn append_authority_wire",
    "pub fn append_additional_wire",
    "pub fn plan_section_record_counts",
):
    if helper in zone_image_text:
        wire_helper_failures.append(f"{helper} remains public in runtime ZoneImage source")
for helper in (
    "rrset_wire",
    "rrset_owner_wire",
    "plan_wire_upper_bound",
):
    if f"#[cfg(test)]\n    pub(crate) fn {helper}" not in zone_image_text:
        wire_helper_failures.append(f"{helper} is not restricted to test builds")
if wire_helper_failures:
    print("status=failed")
    for failure in wire_helper_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage wire append helper surface drifted: "
        + ", ".join(wire_helper_failures)
    )
else:
    print("status=passed")
    print("evidence=Only append_plan_wire remains as the prototype benchmark hook; raw RRset wire and legacy post-plan wire-bound helpers are test-only, while compact runtime plan accounting stays private to the image/plan internals.")

print()
print("check=ZoneImage plan summary owner digest avoids DomainName reparsing")
canonical_summary_start = zone_image_text.find("fn canonical_owner_key_from_wire(")
canonical_summary_end = zone_image_text.find("fn owner_override_wire(", canonical_summary_start)
canonical_summary_text = (
    zone_image_text[canonical_summary_start:canonical_summary_end]
    if canonical_summary_start >= 0 and canonical_summary_end >= 0
    else ""
)
summary_owner_failures = []
if "canonical_key_from_uncompressed_wire(owner_wire)" not in canonical_summary_text:
    summary_owner_failures.append("plan summary owner digest does not reuse the direct owner-wire canonical-key helper")
if "DomainName::parse" in canonical_summary_text or ".canonical_key()" in canonical_summary_text:
    summary_owner_failures.append("plan summary owner digest reparses owner wire into DomainName")
if summary_owner_failures:
    print("status=failed")
    for failure in summary_owner_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage plan summary owner digest regressed to DomainName reparsing: "
        + ", ".join(summary_owner_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage plan-summary validation builds canonical owner keys from stored uncompressed owner wire without allocating a DomainName.")

print()
print("check=ZoneImage generic packet composer avoids runtime pre-accounting walk")
try_answer_start = dns_text.find("fn try_answer_with_zone_image(")
try_answer_end = dns_text.find("pub fn chaos_query_observation", try_answer_start)
try_answer_text = (
    dns_text[try_answer_start:try_answer_end]
    if try_answer_start >= 0 and try_answer_end >= 0
    else ""
)
composer_start = dns_text.find("fn build_zone_image_response(")
composer_end = dns_text.find("fn build_truncated_zone_image_response", composer_start)
composer_text = (
    dns_text[composer_start:composer_end]
    if composer_start >= 0 and composer_end >= 0
    else ""
)
truncation_start = dns_text.find("fn build_truncated_zone_image_response")
truncation_end = dns_text.find("#[allow(clippy::too_many_arguments)]\nfn build_zone_image_response_from_plan_records", truncation_start)
truncation_text = (
    dns_text[truncation_start:truncation_end]
    if truncation_start >= 0 and truncation_end >= 0
    else ""
)
known_count_start = dns_text.find("fn build_zone_image_response_from_plan_records")
known_count_end = dns_text.find("fn zone_image_response_prefix", known_count_start)
known_count_text = (
    dns_text[known_count_start:known_count_end]
    if known_count_start >= 0 and known_count_end >= 0
    else ""
)
wire_rebuild_start = dns_text.find("fn build_zone_image_response_from_wire_records")
wire_rebuild_end = dns_text.find("fn zone_image_wire_record_uncompressed_len", wire_rebuild_start)
wire_rebuild_text = (
    dns_text[wire_rebuild_start:wire_rebuild_end]
    if wire_rebuild_start >= 0 and wire_rebuild_end >= 0
    else ""
)
capacity_hint_start = dns_text.find("fn zone_image_response_capacity_hint")
capacity_hint_end = dns_text.find("struct ZoneImageEdnsSizing", capacity_hint_start)
capacity_hint_text = (
    dns_text[capacity_hint_start:capacity_hint_end]
    if capacity_hint_start >= 0 and capacity_hint_end >= 0
    else ""
)
one_pass_composer_failures = []
if "pub(crate) fn visit_plan_records<'a>" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImage encode-only record visitor is missing")
if "pub(crate) fn visit_plan_record_sections" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImage split-section record visitor is missing")
if "pub(crate) enum ZoneImageRecordSection" in zone_image_text:
    one_pass_composer_failures.append("ZoneImage still exposes the removed record-section enum")
if "visit_plan_records_with_sections" in zone_image_text:
    one_pass_composer_failures.append("ZoneImage still routes split visits through section enum matching")
if "let response_shape = plan.response_shape()" not in composer_text:
    one_pass_composer_failures.append("generic response builder does not read the immutable plan response shape once")
for carried_count in (
    "answer_record_count: u32",
    "authority_record_count: u32",
    "additional_record_count: u32",
    "answer_wire_upper_bound: u32",
):
    if carried_count not in zone_image_text:
        one_pass_composer_failures.append(f"ZoneImageLookupPlan does not carry {carried_count}")
if "fn add_plan_record_count(count: &mut u32, record_count: usize)" not in zone_image_text:
    one_pass_composer_failures.append("compact plan record-count helper is missing")
if "u32::try_from(record_count).unwrap_or(u32::MAX)" not in zone_image_text:
    one_pass_composer_failures.append("compact plan record counts do not saturate oversized usize inputs")
if "fn add_plan_wire_upper_bound(bytes: &mut u32, wire_upper_bound: usize)" not in zone_image_text:
    one_pass_composer_failures.append("compact plan wire-bound helper is missing")
if "u32::try_from(wire_upper_bound).unwrap_or(u32::MAX)" not in zone_image_text:
    one_pass_composer_failures.append("compact plan wire bounds do not saturate oversized usize inputs")
if "pub(crate) struct ZoneImagePlanResponseShape" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan does not expose a bundled response-shape view")
for response_shape_field in (
    "response_flag_bits: self.rcode.response_flag_bits(self.authoritative())",
    "let answer_count = u16::try_from(self.answer_record_count).ok()?",
    "let authority_count = u16::try_from(self.authority_record_count).ok()?",
    "let additional_count = u16::try_from(self.additional_record_count).ok()?",
    "section_count_header_bytes: section_count_header_bytes(",
    "body_wire_upper_bound: self.body_wire_upper_bound as usize",
):
    if response_shape_field not in zone_image_text:
        one_pass_composer_failures.append(
            f"response_shape does not expose compact counter field: {response_shape_field}"
        )
if "#[cfg(test)]\n    pub(crate) fn section_record_counts(&self) -> (usize, usize, usize)" not in zone_image_text:
    one_pass_composer_failures.append("old individual section-count accessor is not restricted to tests")
if "#[cfg(test)]\n    pub(crate) fn response_body_wire_upper_bound(&self) -> usize" not in zone_image_text:
    one_pass_composer_failures.append("old individual body wire-bound accessor is not restricted to tests")
if "body_wire_upper_bound: u32" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan does not carry compact total body wire bounds")
if "\n    record_count: u32," in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan still carries redundant aggregate total record count")
if "\n    authority_wire_upper_bound: u32," in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan still carries redundant authority wire bounds")
if "\n    additional_wire_upper_bound: u32," in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan still carries redundant additional wire bounds")
if "fn total_record_count(&self) -> usize {\n        self.answer_record_count" not in zone_image_text:
    one_pass_composer_failures.append("append_plan_wire total count does not derive from section counters")
if "add_plan_record_count(&mut self.record_count" in zone_image_text:
    one_pass_composer_failures.append("plan push paths still update redundant aggregate total record count")
if "add_plan_wire_upper_bound(&mut self.authority_wire_upper_bound" in zone_image_text:
    one_pass_composer_failures.append("authority push paths still update redundant authority wire bounds")
if "add_plan_wire_upper_bound(&mut self.additional_wire_upper_bound" in zone_image_text:
    one_pass_composer_failures.append("additional push paths still update redundant additional wire bounds")
if "self.body_wire_upper_bound as usize" not in zone_image_text:
    one_pass_composer_failures.append("response_body_wire_upper_bound does not expose the compact total body wire counter as usize")
if "self.body_wire_upper_bound = self.answer_wire_upper_bound" not in zone_image_text:
    one_pass_composer_failures.append("SERVFAIL conversion does not preserve carried answer wire bounds after section clearing")
if "self.record_count = self.answer_record_count" in zone_image_text:
    one_pass_composer_failures.append("SERVFAIL conversion still updates redundant aggregate total record count")
if "add_plan_wire_upper_bound(&mut self.body_wire_upper_bound" not in zone_image_text:
    one_pass_composer_failures.append("plan push paths do not update the compact total body wire bound")
if "dnssec_record_count" in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan still carries dead DNSSEC record-count bookkeeping")
if "response_shape.response_flag_bits" not in known_count_text:
    one_pass_composer_failures.append("known-count packet builder does not consume carried plan response flag bits")
if (
    "section_count_header_bytes_with_extra_additional(response_sizing.edns.additional_count)"
    not in known_count_text
):
    one_pass_composer_failures.append("known-count packet builder does not consume carried plan section-count header bytes")
if "response_shape.response_flag_bits" not in truncation_text:
    one_pass_composer_failures.append("truncation retry path does not consume carried plan response flag bits")
if "section_count_header_bytes: [u8; 6]" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImagePlanResponseShape does not carry preencoded section-count header bytes")
if "response_shape.answer_count.to_be_bytes()" in known_count_text or "response_shape.authority_count.to_be_bytes()" in known_count_text:
    one_pass_composer_failures.append("known-count packet builder reencodes response-shape counts instead of copying header bytes")
if "plan.rcode()" in known_count_text or "plan.authoritative()" in known_count_text:
    one_pass_composer_failures.append("known-count packet builder rereads plan response semantics after response_shape")
if "plan.rcode()" in truncation_text or "plan.authoritative()" in truncation_text:
    one_pass_composer_failures.append("truncation retry path rereads plan response semantics after response_shape")
if "rcode: Rcode,\n    authoritative: bool," in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record retry composer still accepts separate rcode/authoritative inputs")
if "PLAN_FLAG_AUTHORITY_FIRST_RRSET_IS_SOA" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan does not carry the first-authority-SOA fast-path bit")
if "authority_soa_index: u16" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan does not carry the authority SOA position as compact u16 storage")
if "const NO_AUTHORITY_SOA_INDEX: u16 = u16::MAX" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan authority SOA position does not use a compact section-index sentinel")
if "pub(crate) fn answer_has_records(&self) -> bool" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan missing answer-presence plan-bit accessor")
if "fn plan_has_answer_records(&self, plan: &ZoneImageLookupPlan) -> bool" in zone_image_text:
    one_pass_composer_failures.append("answer-presence plan-bit access regressed to a ZoneImage helper")
if "let answer_has_records = plan.answer_has_records()" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC denial classifier does not read answer presence directly from the plan")
if "fn plan_needs_dnssec_denial_query_node_handles" in zone_image_text:
    one_pass_composer_failures.append("DNSSEC denial query-node gating regressed to a duplicate classifier helper")
if "let referral_candidate = self.dnssec_referral_augmentation_possible" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC augmentation does not compute referral candidacy before allocating augmentation state")
if (
    "if !referral_candidate\n            && !self.dnssec_rrsig_augmentation_possible\n            && !nodata_candidate\n            && !nxdomain_candidate\n            && !wildcard_candidate" not in zone_image_text
):
    one_pass_composer_failures.append("DNSSEC augmentation missing pre-state no-candidate return for proof-family-only positive plans")
if "if referral_candidate {\n            self.add_referral_dnssec_augmentations" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC referral augmentation is not gated by the precomputed referral candidate")
if "let denial_candidate = nodata_candidate || nxdomain_candidate" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC denial query-node gating does not reuse the computed denial candidate")
if "let (exact_qname_node, closest_qname_node) = if denial_has_authority_soa" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC denial query-node lookup is not gated behind the authority-SOA proof precondition")
if "if nodata_candidate && denial_has_authority_soa" not in zone_image_text:
    one_pass_composer_failures.append("NODATA proof helper is not gated at the DNSSEC augmentation callsite")
if "if nxdomain_candidate && denial_has_authority_soa" not in zone_image_text:
    one_pass_composer_failures.append("NXDOMAIN proof helper is not gated at the DNSSEC augmentation callsite")
if "if wildcard_candidate {" not in zone_image_text:
    one_pass_composer_failures.append("wildcard proof helper is not gated at the DNSSEC augmentation callsite")
dnssec_augment_start = zone_image_text.find("    pub fn augment_lookup_plan_with_dnssec(")
dnssec_augment_end = zone_image_text.find("    #[cfg(test)]", dnssec_augment_start)
dnssec_augment_text = (
    zone_image_text[dnssec_augment_start:dnssec_augment_end]
    if dnssec_augment_start >= 0 and dnssec_augment_end >= 0
    else ""
)
if "augment_lookup_plan_with_dnssec_ascii_lowercase_hint" not in dnssec_augment_text:
    one_pass_composer_failures.append("DNSSEC augmentation does not expose a parser-carried lowercase QNAME hint")
if "self.query_node_handles(qname, qname_ascii_lowercase)" not in dnssec_augment_text:
    one_pass_composer_failures.append("DNSSEC denial augmentation does not pass the lowercase QNAME hint into trie lookup")
if "qname_ascii_lowercase: bool" not in dnssec_augment_text:
    one_pass_composer_failures.append("DNSSEC denial augmentation does not carry the lowercase QNAME hint through proof selection")
if (
    "exact_qname_node,\n                    qname_ascii_lowercase," not in dnssec_augment_text
    or "closest_qname_node,\n                    qname_ascii_lowercase," not in dnssec_augment_text
    or "qclass,\n                    qname_ascii_lowercase," not in dnssec_augment_text
):
    one_pass_composer_failures.append("DNSSEC denial augmentation does not pass the lowercase QNAME hint into proof helpers")
nodata_helper_start = zone_image_text.find("    fn add_nodata_nsec_augmentations(")
nodata_helper_end = zone_image_text.find("    fn add_nxdomain_nsec_augmentations(", nodata_helper_start)
nodata_helper_text = (
    zone_image_text[nodata_helper_start:nodata_helper_end]
    if nodata_helper_start >= 0 and nodata_helper_end >= 0
    else ""
)
nxdomain_helper_start = zone_image_text.find("    fn add_nxdomain_nsec_augmentations(")
nxdomain_helper_end = zone_image_text.find("    fn add_wildcard_nsec_augmentations(", nxdomain_helper_start)
nxdomain_helper_text = (
    zone_image_text[nxdomain_helper_start:nxdomain_helper_end]
    if nxdomain_helper_start >= 0 and nxdomain_helper_end >= 0
    else ""
)
wildcard_helper_start = zone_image_text.find("    fn add_wildcard_nsec_augmentations(")
wildcard_helper_end = zone_image_text.find("    fn add_rrsig_augmentations(", wildcard_helper_start)
wildcard_helper_text = (
    zone_image_text[wildcard_helper_start:wildcard_helper_end]
    if wildcard_helper_start >= 0 and wildcard_helper_end >= 0
    else ""
)
for helper_name, helper_text in (
    ("NODATA", nodata_helper_text),
    ("NXDOMAIN", nxdomain_helper_text),
    ("wildcard", wildcard_helper_text),
):
    if "_candidate: bool" in helper_text or "denial_has_authority_soa: bool" in helper_text:
        one_pass_composer_failures.append(f"{helper_name} DNSSEC proof helper still accepts callsite candidate booleans")
if "self.push_nsec3_for_name(qname, qclass, qname_ascii_lowercase" not in zone_image_text:
    one_pass_composer_failures.append("NSEC3 proof selection does not reuse the parser-carried lowercase QNAME fact")
if "ascii_lowercase: qname_ascii_lowercase" not in zone_image_text:
    one_pass_composer_failures.append("NSEC/NSEC3 label-view proof selection does not carry lowercase-label state")
if "fn update_sha1_with_canonical_label_view" not in zone_image_text or "if name.ascii_lowercase {\n            digest.update(label);" not in zone_image_text:
    one_pass_composer_failures.append("NSEC3 label-view hashing still lowercases already-lowercase query labels")
if "cmp_lowercase_label_with_ascii_lowercase_hint(\n                left,\n                right,\n                name.ascii_lowercase," not in zone_image_text:
    one_pass_composer_failures.append("NSEC range label-view comparison still lowercases already-lowercase query labels")
if (
    "augment_lookup_plan_with_dnssec_ascii_lowercase_hint(" not in dns_text
    or "question.qname_ascii_lowercase()," not in dns_text
):
    one_pass_composer_failures.append("packet DNSSEC augmentation does not pass the parser-carried lowercase QNAME fact")
nodata_nsec_start = zone_image_text.find("    fn add_nodata_nsec_augmentations(")
nodata_nsec_end = zone_image_text.find("    fn add_nxdomain_nsec_augmentations(", nodata_nsec_start)
nodata_nsec_text = (
    zone_image_text[nodata_nsec_start:nodata_nsec_end]
    if nodata_nsec_start >= 0 and nodata_nsec_end >= 0
    else ""
)
nxdomain_nsec_start = zone_image_text.find("    fn add_nxdomain_nsec_augmentations(")
nxdomain_nsec_end = zone_image_text.find("    fn add_wildcard_nsec_augmentations(", nxdomain_nsec_start)
nxdomain_nsec_text = (
    zone_image_text[nxdomain_nsec_start:nxdomain_nsec_end]
    if nxdomain_nsec_start >= 0 and nxdomain_nsec_end >= 0
    else ""
)
wildcard_nsec_start = zone_image_text.find("    fn add_wildcard_nsec_augmentations(")
wildcard_nsec_end = zone_image_text.find("    fn add_rrsig_augmentations(", wildcard_nsec_start)
wildcard_nsec_text = (
    zone_image_text[wildcard_nsec_start:wildcard_nsec_end]
    if wildcard_nsec_start >= 0 and wildcard_nsec_end >= 0
    else ""
)
if "qtype: u16" in nodata_nsec_text:
    one_pass_composer_failures.append("NODATA DNSSEC augmentation still accepts qtype for a duplicate exact-RRset check")
if "find_rrset_at_node(qname_node, qtype" in nodata_nsec_text:
    one_pass_composer_failures.append("NODATA DNSSEC augmentation still repeats exact qtype lookup instead of trusting plan answer presence")
if "find_rrset_at_node(qname_node, RecordType::Nsec as u16, qclass)" not in nodata_nsec_text:
    one_pass_composer_failures.append("NODATA DNSSEC augmentation no longer uses the exact qname node only for the NSEC proof lookup")
if "!self.nsec_ranges.is_empty()" not in nodata_nsec_text:
    one_pass_composer_failures.append("NODATA DNSSEC augmentation probes exact-name NSEC even when the compiled image has no NSEC proof family")
if "let has_nsec_ranges = !self.nsec_ranges.is_empty()" not in nxdomain_nsec_text:
    one_pass_composer_failures.append("NXDOMAIN DNSSEC augmentation missing a compiled NSEC proof-family gate")
if "let has_nsec3_ranges = !self.nsec3_ranges.is_empty()" not in nxdomain_nsec_text:
    one_pass_composer_failures.append("NXDOMAIN DNSSEC augmentation missing a compiled NSEC3 proof-family gate")
if "if has_nsec_ranges" not in nxdomain_nsec_text:
    one_pass_composer_failures.append("NXDOMAIN DNSSEC augmentation still enters NSEC helpers without the compiled NSEC gate")
if "if has_nsec3_ranges" not in nxdomain_nsec_text:
    one_pass_composer_failures.append("NXDOMAIN DNSSEC augmentation still enters NSEC3 helpers without the compiled NSEC3 gate")
if "(has_nsec_ranges || has_nsec3_ranges)" not in nxdomain_nsec_text:
    one_pass_composer_failures.append("NXDOMAIN closest-encloser proof work is not guarded by proof-family presence")
if "if !self.nsec_ranges.is_empty()" not in wildcard_nsec_text:
    one_pass_composer_failures.append("wildcard DNSSEC augmentation still enters NSEC helpers without the compiled NSEC gate")
if "if !self.nsec3_ranges.is_empty()" not in wildcard_nsec_text:
    one_pass_composer_failures.append("wildcard DNSSEC augmentation still enters NSEC3 helpers without the compiled NSEC3 gate")
if "pub(crate) fn authority_first_rrset_is_soa(&self) -> bool" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan missing first-authority-SOA plan-bit accessor")
if "pub(crate) fn authority_soa_index(&self) -> Option<usize>" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImageLookupPlan missing authority SOA index accessor")
if "usize::from(self.authority_soa_index)" not in zone_image_text:
    one_pass_composer_failures.append("authority SOA index accessor does not widen from compact u16 at the boundary")
if "fn plan_authority_first_rrset_is_soa(&self, plan: &ZoneImageLookupPlan) -> bool" in zone_image_text:
    one_pass_composer_failures.append("first-authority-SOA plan-bit access regressed to a ZoneImage helper")
if "plan.authority_first_rrset_is_soa()" not in zone_image_text:
    one_pass_composer_failures.append("authority composer does not read first-SOA state directly from the plan")
if "plan.authority_has_soa()" not in zone_image_text:
    one_pass_composer_failures.append("authority composer does not read authority-SOA state directly from the plan")
if "plan.authority_soa_index()" not in zone_image_text:
    one_pass_composer_failures.append("authority composer does not read authority SOA position directly from the plan")
if "self.authority_rrsets.is_empty()" not in zone_image_text:
    one_pass_composer_failures.append("authority SOA plan bit is not tied to first authority RRset position")
if "self.authority_soa_index =" not in zone_image_text:
    one_pass_composer_failures.append("authority SOA index is not set when authority SOA is pushed")
if "u16::try_from(self.authority_rrsets.len()).unwrap_or(NO_AUTHORITY_SOA_INDEX)" not in zone_image_text:
    one_pass_composer_failures.append("authority SOA index is not stored through DNS-section-bounded u16 conversion")
if "append_authority_wire_with_first_soa" not in zone_image_text:
    one_pass_composer_failures.append("authority composer does not have the first-SOA negative-TTL fast path")
if "append_authority_wire_with_scanned_soa" in zone_image_text:
    one_pass_composer_failures.append("authority composer reintroduced scanned-SOA emission")
if "visit_authority_records_with_scanned_soa" in zone_image_text:
    one_pass_composer_failures.append("authority visitor reintroduced scanned-SOA emission")
if "authority_rrset_fixed_fields_override" in zone_image_text:
    one_pass_composer_failures.append("authority SOA override still uses per-RRset type checks")
if "visit_authority_records_with_first_soa" not in zone_image_text:
    one_pass_composer_failures.append("authority visitor does not have the first-SOA negative-TTL fast path")
if "append_authority_wire_with_indexed_soa" not in zone_image_text:
    one_pass_composer_failures.append("authority composer does not have indexed SOA negative-TTL path")
if "visit_authority_records_with_indexed_soa" not in zone_image_text:
    one_pass_composer_failures.append("authority visitor does not have indexed SOA negative-TTL path")
if "struct ZoneImageRrsetPlanMetrics" not in zone_image_text:
    one_pass_composer_failures.append("runtime RRset plan-count/wire-bound metrics helper is missing")
if "rr_type: u16" not in zone_image_text:
    one_pass_composer_failures.append("RRset plan metrics do not carry the compiled RR type")
if "dnssec_plan_record_count" in zone_image_text:
    one_pass_composer_failures.append("RRset plan metrics still compute dead DNSSEC record counts")
image_rrset_start = zone_image_text.find("struct ImageRrset")
image_rrset_end = zone_image_text.find(
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]", image_rrset_start + 1
)
image_rrset_layout_text = (
    zone_image_text[image_rrset_start:image_rrset_end]
    if image_rrset_start >= 0 and image_rrset_end >= 0
    else ""
)
if "ownerless_wire_len: u32" not in image_rrset_layout_text:
    one_pass_composer_failures.append("ImageRrset does not carry compiled ownerless wire length")
if "rr_type: u16" in image_rrset_layout_text or "class: u16" in image_rrset_layout_text:
    one_pass_composer_failures.append("ImageRrset still duplicates RR type/class outside fixed fields")
if "fn rr_type(self) -> u16" not in zone_image_text or "fn class(self) -> u16" not in zone_image_text:
    one_pass_composer_failures.append("ImageRrset fixed-field RR type/class accessors are missing")
if "fn rrset_plan_metrics(&self, rrset_id: ZoneImageRrsetId) -> ZoneImageRrsetPlanMetrics" not in zone_image_text:
    one_pass_composer_failures.append("ordinary RRset plan metrics do not use a single compiled-RRset read")
if "fn rrset_plan_metrics_with_owner_len(" not in zone_image_text:
    one_pass_composer_failures.append("owner-override RRset plan metrics do not use a single compiled-RRset read")
owner_metrics_start = zone_image_text.find("    fn rrset_plan_metrics_with_owner_len(")
owner_metrics_end = zone_image_text.find("    fn push_answer_rrset_to_plan", owner_metrics_start)
owner_metrics_text = (
    zone_image_text[owner_metrics_start:owner_metrics_end]
    if owner_metrics_start >= 0 and owner_metrics_end >= 0
    else ""
)
if "rrset.ownerless_wire_len as usize" not in owner_metrics_text:
    one_pass_composer_failures.append("owner-override metrics do not read compiled ownerless wire length")
if "blob_len(rrset.owner_wire)" in owner_metrics_text or "direct_answer_non_owner_wire_len(" in owner_metrics_text:
    one_pass_composer_failures.append("owner-override metrics still derive non-owner bytes while planning")
owner_override_start = zone_image_text.find("fn owner_override_wire(")
owner_override_end = zone_image_text.find("fn hash_record_identity", owner_override_start)
owner_override_text = (
    zone_image_text[owner_override_start:owner_override_end]
    if owner_override_start >= 0 and owner_override_end >= 0
    else ""
)
if "OwnerOverrideWire::new()" not in owner_override_text:
    one_pass_composer_failures.append("owner-override wire construction does not start from the inline owner buffer")
if "owner.wire_len()" in owner_override_text:
    one_pass_composer_failures.append("owner-override wire construction still walks owner labels just to pre-size")
owner_push_start = zone_image_text.find("    fn push_answer_rrset_with_owner_to_plan(")
owner_push_end = zone_image_text.find("    fn push_answer_rrset_with_owner_index_to_plan", owner_push_start)
owner_push_text = (
    zone_image_text[owner_push_start:owner_push_end]
    if owner_push_start >= 0 and owner_push_end >= 0
    else ""
)
if "let owner_wire = owner_override_wire(owner)" not in owner_push_text:
    one_pass_composer_failures.append("single-owner wildcard planning does not build owner override wire once before accounting")
if "rrset_plan_metrics_with_owner_len(rrset, owner_wire.len())" not in owner_push_text:
    one_pass_composer_failures.append("single-owner wildcard planning does not account from the built owner override wire length")
if "owner.wire_len()" in owner_push_text:
    one_pass_composer_failures.append("single-owner wildcard planning still walks owner labels separately for wire length")
if "fn ownerless_wire_len(" not in zone_image_text:
    one_pass_composer_failures.append("ZoneImage builder does not precompute ownerless wire length")
authority_push_start = zone_image_text.find("    fn push_authority_rrset(")
authority_push_end = zone_image_text.find("    fn push_additional_rrset(", authority_push_start)
authority_push_text = (
    zone_image_text[authority_push_start:authority_push_end]
    if authority_push_start >= 0 and authority_push_end >= 0
    else ""
)
if "metrics.rr_type == RecordType::Soa as u16" not in authority_push_text:
    one_pass_composer_failures.append("authority RRset planning does not derive SOA state from compiled metrics")
if "rr_type: u16" in authority_push_text:
    one_pass_composer_failures.append("authority RRset planning still accepts a duplicate RR type scalar")
if re.search(r"push_authority_rrset\([^;\n]*RecordType::", zone_image_text):
    one_pass_composer_failures.append("authority RRset callers still pass explicit RecordType scalars")
for plan_push_helper in (
    "fn push_answer_rrset_to_plan",
    "fn push_answer_rrset_with_owner_to_plan",
    "fn push_answer_rrset_with_owner_index_to_plan",
    "fn push_authority_rrset_to_plan",
    "fn push_additional_rrset_to_plan",
):
    if plan_push_helper not in zone_image_text:
        one_pass_composer_failures.append(f"ZoneImage missing single-read plan push helper: {plan_push_helper}")
if "owner_index: u16" not in zone_image_text:
    one_pass_composer_failures.append("PlanAnswer owner-override indexes are no longer compact u16 storage")
if "DynamicRecord(u16)" not in zone_image_text:
    one_pass_composer_failures.append("PlanAnswer dynamic-record indexes are no longer compact u16 storage")
if "DynamicAnswer(u16)" not in zone_image_text:
    one_pass_composer_failures.append("DNAME indirection target dynamic-answer handle is no longer compact u16 storage")
if 'expect("owner override index is DNS-answer-count bounded")' not in zone_image_text:
    one_pass_composer_failures.append("owner-override plan indexes do not document the DNS answer-count bound")
if 'expect("dynamic answer index is DNS-answer-count bounded")' not in zone_image_text:
    one_pass_composer_failures.append("dynamic-answer plan indexes do not document the DNS answer-count bound")
if ".get(usize::from(index))" not in zone_image_text:
    one_pass_composer_failures.append("DNAME indirection target dynamic-answer lookup does not widen compact u16 at the boundary")
if "self.rrset_record_count(" in zone_image_text:
    one_pass_composer_failures.append("runtime planning still reads RRset record counts through a standalone helper")
if "self.rrset_plan_wire_upper_bound(" in zone_image_text:
    one_pass_composer_failures.append("runtime planning still reads RRset wire bounds through a standalone helper")
if "rrset_plan_wire_upper_bound_with_owner_len" in zone_image_text:
    one_pass_composer_failures.append("runtime planning still has the removed standalone owner-override wire-bound helper")
if "pub(crate) fn plan_section_record_counts" in zone_image_text:
    one_pass_composer_failures.append("ZoneImage still exposes post-plan section-count recomputation")
if "fn answer_record_count(&self, plan:" in zone_image_text:
    one_pass_composer_failures.append("ZoneImage still recomputes answer record counts from plan handles")
if "fn rrset_list_record_count(" in zone_image_text:
    one_pass_composer_failures.append("ZoneImage still walks RRset lists to compute section counts")
if "build_zone_image_response_from_plan_records(" not in composer_text:
    one_pass_composer_failures.append("generic response builder does not use the known-count composer helper")
if "let dnssec_requested = metadata.dnssec_requested();" not in try_answer_text:
    one_pass_composer_failures.append("ZoneImage answer path does not cache DO-bit state before planning")
if "let allow_direct_answer_retry = !direct_plan_rejected && !dnssec_requested;" not in try_answer_text:
    one_pass_composer_failures.append("DNSSEC-requested responses can still retry the impossible direct-answer composer")
if "let udp_ceiling = metadata.udp_ceiling(options);" not in try_answer_text:
    one_pass_composer_failures.append("ZoneImage answer path does not compute the request UDP ceiling once before direct/generic composition")
if "udp_ceiling," not in try_answer_text:
    one_pass_composer_failures.append("ZoneImage answer path does not thread the cached UDP ceiling into response builders")
if "struct ZoneImageEdnsSizing" not in dns_text:
    one_pass_composer_failures.append("ZoneImage EDNS sizing is missing")
if "struct ZoneImageResponseSizing" not in dns_text:
    one_pass_composer_failures.append("ZoneImage response sizing is not bundled into one carried value")
if "minimum_capacity: usize" not in dns_text or "udp_ceiling: usize" not in dns_text:
    one_pass_composer_failures.append("ZoneImage response sizing does not carry UDP ceiling and fixed minimum response capacity")
if "minimum_capacity: DNS_HEADER_LEN + question.wire_len()" not in dns_text:
    one_pass_composer_failures.append("ZoneImage response sizing does not precompute the fixed header-plus-question capacity base")
if (
    "additional_count: u16" not in dns_text
    or "capacity_hint: usize" not in dns_text
    or "reserve_full_udp_capacity: bool" not in dns_text
):
    one_pass_composer_failures.append("ZoneImage EDNS sizing does not carry additional-count, capacity hint, and reserve decision")
if "base_shape: Option<EdnsResponseBaseShape>" not in dns_text:
    one_pass_composer_failures.append("ZoneImage EDNS sizing does not carry the fixed OPT response base shape")
if "fn zone_image_edns_sizing(" not in dns_text:
    one_pass_composer_failures.append("ZoneImage missing single helper for EDNS response sizing decisions")
if "additional_count: 1" not in dns_text:
    one_pass_composer_failures.append("ZoneImage EDNS sizing does not cache the EDNS additional-record count")
if "let base_shape = edns_response_base_shape(edns, options, metadata.extended_dns_error)" not in dns_text:
    one_pass_composer_failures.append("ZoneImage EDNS sizing does not reuse the shared fixed OPT response base-shape helper")
if "fn zone_image_reserve_full_udp_capacity(" in dns_text:
    one_pass_composer_failures.append("ZoneImage still carries a separate full-UDP-capacity reserve helper")
if "fn zone_image_edns_capacity_hint(" in dns_text:
    one_pass_composer_failures.append("ZoneImage still carries a separate EDNS capacity-hint helper")
if "response_sizing: ZoneImageResponseSizing" not in composer_text:
    one_pass_composer_failures.append("generic ZoneImage response builder does not thread bundled response sizing")
if "let direct_response_sizing =" not in try_answer_text:
    one_pass_composer_failures.append("ZoneImage answer path does not cache bundled response sizing before direct composition")
if (
    "direct_response_sizing" not in try_answer_text
    or "unwrap_or_else(|| {\n            zone_image_response_sizing(question, udp_ceiling, &metadata, options)\n        })" not in try_answer_text
):
    one_pass_composer_failures.append("ZoneImage answer path does not reuse direct-path bundled response sizing for ordinary generic composition")
if "let response_sizing = if plan.nsec3_iterations_exceeded()" not in try_answer_text:
    one_pass_composer_failures.append("ZoneImage answer path does not recompute bundled response sizing only when EDE metadata changes it")
if "let udp_ceiling = metadata.udp_ceiling(options);" in composer_text:
    one_pass_composer_failures.append("generic ZoneImage response builder recomputes the request UDP ceiling")
if ".plan_accounting_direct(plan)" in composer_text:
    one_pass_composer_failures.append("generic response builder still runs direct plan accounting before encoding")
if "plan_wire_upper_bound" in composer_text:
    one_pass_composer_failures.append("generic response builder still computes wire upper bounds before encoding")
if "fn build_zone_image_response_from_plan_records_counting" in dns_text:
    one_pass_composer_failures.append("generic response path still carries the removed counting composer helper")
if "patch_dns_section_counts" in dns_text:
    one_pass_composer_failures.append("generic response path still patches DNS header counts after encoding")
if "let section_count_header_bytes =" not in known_count_text or "section_count_header_bytes," not in known_count_text:
    one_pass_composer_failures.append("known-count plan-record rebuild does not write carried response-shape section-count header bytes")
if "section_count_header_bytes_with_extra_additional(response_sizing.edns.additional_count)" not in known_count_text:
    one_pass_composer_failures.append("known-count plan-record rebuild does not consume caller-carried EDNS additional count")
if "let edns_count = u16::from(metadata.edns.is_some())" in known_count_text:
    one_pass_composer_failures.append("known-count plan-record rebuild still reconverts EDNS presence into an additional count")
if "response_shape.additional_count.checked_add(edns_count)" in known_count_text:
    one_pass_composer_failures.append("known-count plan-record rebuild performs EDNS count adjustment outside response-shape byte helper")
if "u16::try_from(response_shape." in known_count_text:
    one_pass_composer_failures.append("known-count plan-record rebuild reconverts DNS-width response-shape section counts")
if "zone_image_response_capacity_hint(" not in known_count_text:
    one_pass_composer_failures.append("known-count plan-record rebuild does not use carried accounting for response capacity sizing")
if "response_shape.body_wire_upper_bound" not in known_count_text:
    one_pass_composer_failures.append("response capacity hint does not consume the bundled response-shape wire bound")
if ".saturating_add(sizing.edns.capacity_hint)" not in capacity_hint_text:
    one_pass_composer_failures.append("response capacity hint does not consume the caller-carried EDNS capacity hint")
if "zone_image_edns_sizing(" in capacity_hint_text:
    one_pass_composer_failures.append("response capacity hint recomputes EDNS sizing internally")
if "question: &Question" in capacity_hint_text or "DNS_HEADER_LEN + question.wire_len()" in capacity_hint_text:
    one_pass_composer_failures.append("response capacity hint recomputes fixed question capacity instead of consuming ZoneImageResponseSizing")
if "metadata:" in capacity_hint_text or "options:" in capacity_hint_text:
    one_pass_composer_failures.append("response capacity hint still accepts metadata/options instead of caller-carried sizing state")
if "edns.padding_requested" in capacity_hint_text:
    one_pass_composer_failures.append("response capacity hint still rechecks EDNS padding instead of consuming the cached reserve decision")
if "sizing.edns.reserve_full_udp_capacity" not in capacity_hint_text:
    one_pass_composer_failures.append("response capacity hint does not consume the caller-carried full-UDP reserve decision")
if "zone_image_section_count_header_bytes(0, 0, response_sizing.edns.additional_count)" not in dns_text:
    one_pass_composer_failures.append("ZoneImage failure response does not consume caller-carried EDNS additional count")
if "fn append_zone_image_response_edns(" not in dns_text or "edns_sizing: ZoneImageEdnsSizing" not in dns_text[dns_text.find("fn append_zone_image_response_edns("):dns_text.find("fn decrement_dns_section_count", dns_text.find("fn append_zone_image_response_edns("))]:
    one_pass_composer_failures.append("ZoneImage EDNS append does not consume the carried EDNS sizing value")
if "encode_opt_record_with_base_shape(" not in dns_text[dns_text.find("fn append_zone_image_response_edns("):dns_text.find("fn decrement_dns_section_count", dns_text.find("fn append_zone_image_response_edns("))]:
    one_pass_composer_failures.append("ZoneImage EDNS append does not reuse the carried fixed OPT response base shape")
if "edns_response_base_shape(" in dns_text[dns_text.find("fn append_zone_image_response_edns("):dns_text.find("fn decrement_dns_section_count", dns_text.find("fn append_zone_image_response_edns("))]:
    one_pass_composer_failures.append("ZoneImage EDNS append recomputes the fixed OPT response base shape")
if "udp_ceiling.max(minimum_capacity)" in known_count_text:
    one_pass_composer_failures.append("ordinary known-count response builder still reserves the full UDP ceiling")
if "visit_plan_records(plan, |record|" not in known_count_text:
    one_pass_composer_failures.append("known-count composer does not encode through the encode-only record visitor")
if "visit_plan_record_sections_with_authority_removability" not in truncation_text:
    one_pass_composer_failures.append("truncation scratch collection does not use the plan-carried authority removability visitor")
if "zone_image_wire_record_rr_type(record) != RecordType::Soa as u16" in truncation_text:
    one_pass_composer_failures.append("truncation scratch collection reintroduced per-authority-record SOA type classification")
if "zone_image_last_non_soa_authority_index(&kept_authorities, kept_authorities.len())" in truncation_text:
    one_pass_composer_failures.append("truncation scratch collection still scans authority records for the initial removable index after collection")
if "zone_image_last_non_soa_authority_index(" in truncation_text:
    one_pass_composer_failures.append("truncation retry still rescans authority records for removable non-SOA indices")
if "SmallVec::<[u16; 4]>::new()" not in truncation_text:
    one_pass_composer_failures.append("truncation retry removable authority index stack is not compact u16 storage")
if "if removable_authority" not in truncation_text:
    one_pass_composer_failures.append("truncation scratch collection does not use plan-carried authority removability")
if (
    "let stripped_edns_sizing = zone_image_edns_sizing(&metadata, options);" not in truncation_text
    or "response_sizing = stripped_response_sizing;" not in truncation_text
    or "response_sizing.with_edns_sizing(stripped_edns_sizing)" not in truncation_text
):
    one_pass_composer_failures.append("truncation EDE stripping does not carry stripped EDNS sizing into record-removal retry")
if "removable_authority_indices.push(kept_authorities.len() as u16)" not in truncation_text:
    one_pass_composer_failures.append("truncation scratch collection does not retain removable authority indices while collecting")
if "truncation authority index is bounded by DNS section count" not in truncation_text:
    one_pass_composer_failures.append("truncation removable authority u16 index bound is not explicit")
if "original_authority_rrset_count: u16" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC original authority prefix count is not compact u16 scratch storage")
if "original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC original authority prefix count is not stored through DNS-section-bounded u16 conversion")
if "usize::from(state.original_authority_rrset_count)" not in zone_image_text:
    one_pass_composer_failures.append("DNSSEC original authority prefix count does not widen from compact u16 at the slice boundary")
if "if index + 1 == kept_authorities.len()" not in truncation_text or "kept_authorities.pop()" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not pop last removable authority records without shifting")
if "kept_authorities.remove(index)" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not remove retained non-tail removable authority indices")
if "response_shape.body_wire_upper_bound" not in truncation_text:
    one_pass_composer_failures.append("truncation scratch setup does not start from carried response-shape body wire bound")
if "let mut section_counts = ZoneImageRetrySectionCounts::from_response_shape(response_shape)" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not carry DNS-width section counts as one mutable response-shape-derived value")
for carried_retry_count in (
    "answer_count: u16",
    "authority_count: u16",
    "additional_count: u16",
    "section_count_header_bytes: [u8; 6]",
):
    if carried_retry_count not in dns_text:
        one_pass_composer_failures.append(f"truncation retry count carrier does not retain {carried_retry_count}")
if "section_counts.decrement_answer()" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not decrement carried answer counts")
if "section_counts.decrement_authority()" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not decrement carried authority counts")
if "section_counts.decrement_additional()" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not decrement carried additional counts")
if "let stripped_edns_sizing = zone_image_edns_sizing(&metadata, options)" not in truncation_text:
    one_pass_composer_failures.append("EDE-stripped truncation retry does not recompute bundled EDNS sizing after metadata changes")
if "std::cell::Cell" in truncation_text:
    one_pass_composer_failures.append("truncation scratch collection still accumulates counters through per-record cells")
if "with_dnssec_augmented" in dns_text or "truncated_dnssec_augmented" in dns_text:
    one_pass_composer_failures.append("response truncation still carries dead DNSSEC-augmented response metadata bookkeeping")
if "zone_image_wire_record_is_dnssec" in dns_text:
    one_pass_composer_failures.append("truncation retry still classifies removed wire records for dead DNSSEC bookkeeping")
if "body_wire_upper_bound.saturating_sub(zone_image_wire_record_uncompressed_len(record))" not in truncation_text:
    one_pass_composer_failures.append("truncation retry does not decrement kept-record wire bounds when records are removed")
if "body_wire_upper_bound: usize" not in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild does not accept carried body wire bounds")
if "body_wire_upper_bound," not in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild does not pass carried body wire bounds into capacity sizing")
if "section_counts: ZoneImageRetrySectionCounts" not in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild does not accept carried mutable retry section counts")
if "section_count_header_bytes_with_extra_additional(response_sizing.edns.additional_count)" not in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild does not consume caller-carried section-count bytes and EDNS additional count")
if "zone_image_section_count_header_bytes(answer_count, authority_count" in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild reencodes retry section-count bytes from separate counters")
if "u16::from(metadata.edns.is_some())" in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild still reconverts EDNS presence into an additional count")
if "u16::try_from(answers.len())" in wire_rebuild_text or "u16::try_from(authorities.len())" in wire_rebuild_text or "u16::try_from(additionals.len()" in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild reconverts DNS section counts from scratch-vector lengths")
if "debug_assert_eq!(usize::from(section_counts.answer_count), answers.len())" not in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild does not assert carried answer count parity")
if ".chain(authorities).chain(additionals)" in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild still uses chained section iterators")
if "encode_zone_image_wire_record_section(answers" not in wire_rebuild_text or "encode_zone_image_wire_record_section(authorities" not in wire_rebuild_text or "encode_zone_image_wire_record_section(additionals" not in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild does not encode retained records through section-local loops")
if ".saturating_mul(96)" in wire_rebuild_text:
    one_pass_composer_failures.append("wire-record response rebuild still uses a per-record capacity heuristic")
if "fn zone_image_wire_record_uncompressed_len(record: ZoneImageWireRecord<'_>) -> usize" not in dns_text:
    one_pass_composer_failures.append("wire-record uncompressed length helper is missing")
if "usize::from(u16::from_be_bytes(record.rdlength_bytes))" not in dns_text[dns_text.find("fn zone_image_wire_record_uncompressed_len"):dns_text.find("fn build_direct_zone_image_answer_response")]:
    one_pass_composer_failures.append("wire-record uncompressed length helper does not use carried rdlength bytes")
if "zone_image_wire_record_uncompressed_len(record: ZoneImageWireRecord<'_>) -> usize" in dns_text and ".saturating_add(record.rdata.len())" in dns_text[dns_text.find("fn zone_image_wire_record_uncompressed_len"):dns_text.find("fn build_direct_zone_image_answer_response")]:
    one_pass_composer_failures.append("wire-record uncompressed length helper recomputes length from runtime RDATA slice")
for stale_counter in (
    "answer_dnssec_record_count",
    "authority_dnssec_record_count",
    "additional_dnssec_record_count",
):
    if stale_counter in truncation_text:
        one_pass_composer_failures.append(f"truncation scratch collection still carries {stale_counter}")
if "#[cfg(test)]\n    pub(crate) fn plan_accounting_direct" not in zone_image_text:
    one_pass_composer_failures.append("direct plan accounting helper is not test-only")
if "#[cfg(test)]\n    fn selected_record_wire_len" not in zone_image_text:
    one_pass_composer_failures.append("selected record wire-length accounting helper is not test-only")
if one_pass_composer_failures:
    print("status=failed")
    for failure in one_pass_composer_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage generic packet composer reintroduced runtime pre-accounting: "
        + ", ".join(one_pass_composer_failures)
    )
else:
    print("status=passed")
    print("evidence=Generic ZoneImage packet responses read one bundled response-shape view for DNS-width section counts and response-capacity wire bounds from compact counters carried by the immutable plan, cache the UDP ceiling plus bundled EDNS sizing, EDNS additional-count, and fixed OPT base shape as response-path inputs instead of recomputing them inside capacity sizing, section-count assembly, or ZoneImage OPT append, remove dead DNSSEC record-count and response-metadata bookkeeping from truncation composition, use private single-read RRset plan metrics helpers when constructing retained counters, keep owner-override, dynamic-answer, DNAME indirection dynamic-answer, authority-SOA, and DNSSEC original-authority prefix indexes in DNS-count-bounded u16 storage, read compiled ownerless RRset wire length for owner-override metrics without deriving non-owner bytes while planning, avoid duplicate RR type/class scalars by reading them from compiled fixed fields, encode through one encode-only immutable-record visit with final DNS header counts already known, carry those counts into truncation retry, collect truncation scratch records with a split-section visitor that carries plan-derived authority removability and a removable-authority index stack, decrement carried retry section counts as records are removed, encode retry scratch sections through section-local loops, pop tail removable authority records without shifting, rebuild EDE-stripped immutable-plan retries from known counts, use first-SOA and indexed-SOA paths to avoid scanning authority RRsets for the negative-TTL override path, and keep the older post-plan wire-bound accounting helpers test-only.")

print()
print("check=ZoneImage NSEC range-key metadata avoids DomainName reparsing")
nsec_precompute_start = zone_image_text.find("    fn precompute_nsec_ranges(")
nsec_precompute_end = zone_image_text.find("    fn precompute_nsec3_ranges(", nsec_precompute_start)
nsec_precompute_text = (
    zone_image_text[nsec_precompute_start:nsec_precompute_end]
    if nsec_precompute_start >= 0 and nsec_precompute_end >= 0
    else ""
)
nsec_key_failures = []
if "fn push_canonical_order_name_arena_key(" not in zone_image_text:
    nsec_key_failures.append("same-arena NSEC owner canonical-order key helper is missing")
if "fn push_canonical_order_wire_key(" not in zone_image_text:
    nsec_key_failures.append("NSEC next-owner canonical-order wire helper is missing")
if "fn canonical_wire_label_ranges(" not in zone_image_text:
    nsec_key_failures.append("NSEC canonical wire-label scanner is missing")
if "owner_from_wire(blob_from_arena(&self.names, rrset.owner_wire))" in nsec_precompute_text:
    nsec_key_failures.append("NSEC range compiler reparses owner wire into DomainName")
if "nsec_next_owner_rdata(" in nsec_precompute_text or "fn nsec_next_owner_rdata(" in zone_image_text:
    nsec_key_failures.append("NSEC range compiler reparses next-owner RDATA into DomainName")
if "push_canonical_order_name_arena_key(&mut self.names, rrset.owner_wire, \"names\")" not in nsec_precompute_text:
    nsec_key_failures.append("NSEC range compiler does not build owner range keys directly from stored owner wire")
if "push_canonical_order_wire_key(&mut self.names, rdata, false, \"names\")" not in nsec_precompute_text:
    nsec_key_failures.append("NSEC range compiler does not build next-owner range keys directly from NSEC RDATA wire")
if "match len & 0xc0" not in zone_image_text or "_ => return None" not in zone_image_text[zone_image_text.find("fn canonical_wire_label_ranges("):zone_image_text.find("fn blob_from_arena(", zone_image_text.find("fn canonical_wire_label_ranges("))]:
    nsec_key_failures.append("NSEC canonical wire-label scanner does not reject compressed or extended labels")
if nsec_key_failures:
    print("status=failed")
    for failure in nsec_key_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage NSEC range-key metadata regressed to DomainName reparsing: "
        + ", ".join(nsec_key_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage NSEC range compilation builds owner canonical-order keys directly from stored owner wire, builds next-owner keys directly from NSEC RDATA wire, and rejects compressed or malformed wire labels without allocating DomainName values.")

print()
print("check=ZoneImage NSEC3 owner-hash metadata avoids string/vector decode")
nsec3_owner_start = zone_image_text.find("fn nsec3_owner_wire_hash_bytes(")
nsec3_owner_end = zone_image_text.find("\n#[cfg(test)]\nfn nsec3_owner_hash_bytes(", nsec3_owner_start)
nsec3_owner_text = (
    zone_image_text[nsec3_owner_start:nsec3_owner_end]
    if nsec3_owner_start >= 0 and nsec3_owner_end >= 0
    else ""
)
nsec3_precompute_start = zone_image_text.find("    fn precompute_nsec3_ranges(")
nsec3_precompute_end = zone_image_text.find("    fn precompute_rrset_relation_spans(", nsec3_precompute_start)
nsec3_precompute_text = (
    zone_image_text[nsec3_precompute_start:nsec3_precompute_end]
    if nsec3_precompute_start >= 0 and nsec3_precompute_end >= 0
    else ""
)
nsec3_lookup_start = zone_image_text.find("    fn nsec3_rrset_for_wire_name(")
nsec3_lookup_end = zone_image_text.find("    fn nsec3_param_set(", nsec3_lookup_start)
nsec3_lookup_text = (
    zone_image_text[nsec3_lookup_start:nsec3_lookup_end]
    if nsec3_lookup_start >= 0 and nsec3_lookup_end >= 0
    else ""
)
nsec3_param_cache_start = zone_image_text.find("    fn nsec3_hash_label_view_param_cache_index(")
nsec3_param_cache_end = zone_image_text.find("    fn push_rrsig_for_rrset(", nsec3_param_cache_start)
nsec3_param_cache_text = (
    zone_image_text[nsec3_param_cache_start:nsec3_param_cache_end]
    if nsec3_param_cache_start >= 0 and nsec3_param_cache_end >= 0
    else ""
)
nsec3_owner_failures = []
if "fn nsec3_owner_wire_hash_bytes(" not in nsec3_owner_text:
    nsec3_owner_failures.append("NSEC3 owner-hash compiler helper is missing")
if ".canonical_key()" in nsec3_owner_text:
    nsec3_owner_failures.append("NSEC3 owner-hash compiler helper rebuilds canonical strings")
if "base32hex_no_padding_decode_lower(" in nsec3_owner_text:
    nsec3_owner_failures.append("NSEC3 owner-hash compiler helper decodes through a temporary Vec")
if "base32hex_sha1_no_padding_decode_lower(hash_label)" not in nsec3_owner_text:
    nsec3_owner_failures.append("NSEC3 owner-hash compiler helper does not decode directly into fixed SHA-1 bytes")
if "suffix_wire != [0]" not in nsec3_owner_text:
    nsec3_owner_failures.append("NSEC3 owner-hash compiler helper does not require exactly one owner hash label above the origin")
if "owner_label.eq_ignore_ascii_case(origin_label)" not in nsec3_owner_text:
    nsec3_owner_failures.append("NSEC3 owner-hash compiler helper does not match the origin suffix case-insensitively")
if "fn base32hex_sha1_no_padding_decode_lower(encoded: &[u8]) -> Option<[u8; 20]>" not in zone_image_text:
    nsec3_owner_failures.append("fixed SHA-1 base32hex decoder is missing")
if "(out_len == out.len()).then_some(out)" not in zone_image_text:
    nsec3_owner_failures.append("fixed SHA-1 base32hex decoder does not enforce exact hash length")
if "owner_from_wire(blob_from_arena(&self.names, rrset.owner_wire))" in nsec3_precompute_text:
    nsec3_owner_failures.append("NSEC3 range compiler reparses owner wire into DomainName")
if (
    "nsec3_owner_wire_hash_bytes(" not in nsec3_precompute_text
    or "blob_from_arena(&self.names, rrset.owner_wire)" not in nsec3_precompute_text
):
    nsec3_owner_failures.append("NSEC3 range compiler does not decode owner hashes directly from stored owner wire")
if "struct ImageNsec3ParamSet" not in zone_image_text:
    nsec3_owner_failures.append("NSEC3 parameter-set side table is missing")
if "nsec3_param_sets: Box<[ImageNsec3ParamSet]>" not in zone_image_text:
    nsec3_owner_failures.append("ZoneImage does not carry compiled NSEC3 parameter sets")
if "param_set: u16" not in zone_image_text:
    nsec3_owner_failures.append("NSEC3 ranges do not carry compact parameter-set indexes")
if "intern_nsec3_param_set(hash_algorithm, iterations, salt)" not in nsec3_precompute_text:
    nsec3_owner_failures.append("NSEC3 range compiler does not intern shared parameter sets")
if "SmallVec::<[(u16, Option<[u8; 20]>); 1]>" not in nsec3_lookup_text:
    nsec3_owner_failures.append("NSEC3 runtime hash cache is not keyed by compact parameter indexes")
if "nsec3_hash_label_view_param_cache_index(" not in nsec3_lookup_text:
    nsec3_owner_failures.append("NSEC3 label-view lookup does not use parameter-index hash cache")
if "nsec3_hash_wire_name_param_cache_index(" not in nsec3_lookup_text:
    nsec3_owner_failures.append("NSEC3 wire-name lookup does not use parameter-index hash cache")
if "SmallVec::<[(Nsec3Params" in nsec3_lookup_text:
    nsec3_owner_failures.append("NSEC3 runtime lookup cache still searches by full parameter tuple")
if "self.nsec3_params_from_set(param_set)" in nsec3_lookup_text:
    nsec3_owner_failures.append("NSEC3 range loop materializes parameter salt before cache lookup")
if "fn nsec3_hash_label_view_param_cache_index(" not in nsec3_param_cache_text:
    nsec3_owner_failures.append("NSEC3 lazy label-view parameter cache helper is missing")
if "fn nsec3_hash_wire_name_param_cache_index(" not in nsec3_param_cache_text:
    nsec3_owner_failures.append("NSEC3 lazy wire-name parameter cache helper is missing")
if "self.nsec3_params_from_set(param_set)" not in nsec3_param_cache_text:
    nsec3_owner_failures.append("NSEC3 parameter cache helpers do not materialize parameters inside the miss path")
if "param_set: &ImageNsec3ParamSet" not in nsec3_param_cache_text:
    nsec3_owner_failures.append("NSEC3 parameter cache helpers do not reuse the range-loop parameter descriptor")
if "self.nsec3_params_from_set(self.nsec3_param_set(param_set_index))" in nsec3_param_cache_text:
    nsec3_owner_failures.append("NSEC3 parameter cache helpers re-index the parameter table on cache miss")
if nsec3_owner_failures:
    print("status=failed")
    for failure in nsec3_owner_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage NSEC3 owner-hash metadata regressed to allocation-heavy decode: "
        + ", ".join(nsec3_owner_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage NSEC3 range compilation extracts the owner hash directly from stored owner wire, interns shared NSEC3 algorithm/iteration/salt parameter sets, stores compact parameter indexes in range metadata, lazily materializes parameter salt only on hash-cache misses, and decodes base32hex directly into fixed SHA-1 bytes without rebuilding canonical strings, allocating a DomainName, or using a temporary decoded vector.")

print()
print("check=ZoneImage failure responses stay on ZoneImage composer helpers")
failure_response_start = dns_text.find("fn build_zone_image_failure_response")
failure_response_end = dns_text.find("fn build_zone_image_response", failure_response_start)
failure_response_text = (
    dns_text[failure_response_start:failure_response_end]
    if failure_response_start >= 0 and failure_response_end >= 0
    else ""
)
failure_response_failures = []
if "fn build_zone_image_failure_response" not in failure_response_text:
    failure_response_failures.append("ZoneImage failure response builder not found")
if "zone_image_response_prefix(" not in failure_response_text:
    failure_response_failures.append("ZoneImage failure responses do not use the ZoneImage DNS-header prefix helper")
if "append_zone_image_response_edns(" not in failure_response_text:
    failure_response_failures.append("ZoneImage failure responses do not use the ZoneImage EDNS append helper")
if "build_response(" in failure_response_text or "build_response_inner(" in failure_response_text:
    failure_response_failures.append("ZoneImage failure responses still fall back through the old ResourceRecord composer")
if "NameCompressor" in failure_response_text:
    failure_response_failures.append("ZoneImage failure responses still instantiate the old name compressor")
if failure_response_failures:
    print("status=failed")
    for failure in failure_response_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage failure response composer boundary regressed: "
        + ", ".join(failure_response_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage SERVFAIL fallback responses use the shared ZoneImage DNS-header prefix and EDNS append helpers instead of routing through the old ResourceRecord response composer.")

print()
print("check=Empty protocol responses avoid ResourceRecord composer")
build_response_start = dns_text.find("fn build_response(")
build_response_end = dns_text.find("fn build_empty_response", build_response_start)
build_response_text = (
    dns_text[build_response_start:build_response_end]
    if build_response_start >= 0 and build_response_end >= 0
    else ""
)
empty_response_start = dns_text.find("fn build_empty_response")
empty_response_end = dns_text.find("fn build_zone_image_failure_response", empty_response_start)
empty_response_text = (
    dns_text[empty_response_start:empty_response_end]
    if empty_response_start >= 0 and empty_response_end >= 0
    else ""
)
empty_response_failures = []
if (
    "answers.is_empty() && authorities.is_empty() && additionals.is_empty()"
    not in build_response_text
):
    empty_response_failures.append("build_response does not fast-path empty record sections")
if "return build_empty_response(" not in build_response_text:
    empty_response_failures.append("empty record sections do not return through build_empty_response")
if "fn build_empty_response" not in empty_response_text:
    empty_response_failures.append("empty response builder is missing")
if "fn build_empty_response_inner" not in empty_response_text:
    empty_response_failures.append("empty response inner builder is missing")
if "append_zone_image_response_edns(" not in empty_response_text:
    empty_response_failures.append("empty responses do not use the shared ZoneImage EDNS append helper")
if "zone_image_section_count_header_bytes(" not in empty_response_text:
    empty_response_failures.append("empty responses do not use the shared section-count header helper")
if "NameCompressor" in empty_response_text or "build_response_inner(" in empty_response_text:
    empty_response_failures.append("empty responses still route through the old ResourceRecord/name-compressor composer")
if empty_response_failures:
    print("status=failed")
    for failure in empty_response_failures:
        print(f"  failure={failure}")
    failures.append(
        "Empty protocol response composer boundary regressed: "
        + ", ".join(empty_response_failures)
    )
else:
    print("status=passed")
    print("evidence=No-record protocol responses use the shared ZoneImage DNS-header and EDNS helpers before the old ResourceRecord composer is needed.")

print()
print("check=ZoneImage RDATA compression shape is precomputed")
rdata_encoding_failures = []
rdata_encoding_start = zone_image_text.find("pub(crate) struct PackedRdataEncoding")
rdata_encoding_end = zone_image_text.find("impl PackedRdataEncoding", rdata_encoding_start)
rdata_encoding_text = (
    zone_image_text[rdata_encoding_start:rdata_encoding_end]
    if rdata_encoding_start >= 0 and rdata_encoding_end >= 0
    else ""
)
wire_record_start = zone_image_text.find("pub(crate) struct ZoneImageWireRecord")
wire_record_end = zone_image_text.find(
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(crate) struct PackedRdataEncoding",
    wire_record_start,
)
wire_record_text = (
    zone_image_text[wire_record_start:wire_record_end]
    if wire_record_start >= 0 and wire_record_end >= 0
    else ""
)
rdata_range_start = zone_image_text.find("struct RdataRange")
rdata_range_end = zone_image_text.find("impl RdataRange", rdata_range_start)
rdata_range_text = (
    zone_image_text[rdata_range_start:rdata_range_end]
    if rdata_range_start >= 0 and rdata_range_end >= 0
    else ""
)
image_rrset_start = zone_image_text.find("struct ImageRrset")
image_rrset_end = zone_image_text.find(
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]", image_rrset_start + 1
)
image_rrset_text = (
    zone_image_text[image_rrset_start:image_rrset_end]
    if image_rrset_start >= 0 and image_rrset_end >= 0
    else ""
)
compile_rrset_start = zone_image_text.find("    fn push_rrset(")
compile_rrset_end = zone_image_text.find("    fn build_target_node_hint", compile_rrset_start)
compile_rrset_text = (
    zone_image_text[compile_rrset_start:compile_rrset_end]
    if compile_rrset_start >= 0 and compile_rrset_end >= 0
    else ""
)
soa_minimum_start = zone_image_text.find("fn soa_minimum(")
soa_minimum_end = zone_image_text.find("\n#[cfg(test)]\nmod tests", soa_minimum_start)
if soa_minimum_start >= 0 and soa_minimum_end < 0:
    soa_minimum_end = len(zone_image_text)
soa_minimum_text = (
    zone_image_text[soa_minimum_start:soa_minimum_end]
    if soa_minimum_start >= 0 and soa_minimum_end >= 0
    else ""
)
push_synthesized_encoding_start = zone_image_text.find("    fn push_synthesized_answer(")
push_synthesized_encoding_end = zone_image_text.find("    fn push_selected_record_section", push_synthesized_encoding_start)
push_synthesized_encoding_text = (
    zone_image_text[push_synthesized_encoding_start:push_synthesized_encoding_end]
    if push_synthesized_encoding_start >= 0 and push_synthesized_encoding_end >= 0
    else ""
)
rdata_encode_start = dns_text.find("fn encode_zone_image_wire_record_rdata")
rdata_encode_end = dns_text.find("fn encode_record_rdata", rdata_encode_start)
rdata_encode_text = (
    dns_text[rdata_encode_start:rdata_encode_end]
    if rdata_encode_start >= 0 and rdata_encode_end >= 0
    else ""
)
if "pub(crate) struct PackedRdataEncoding(u16)" not in rdata_encoding_text:
    rdata_encoding_failures.append("PackedRdataEncoding is no longer a two-byte packed value")
for constructor in ("copy", "single_name", "soa", "mx"):
    if f"const fn {constructor}(" not in zone_image_text:
        rdata_encoding_failures.append(f"PackedRdataEncoding missing {constructor} constructor")
if "pub(crate) const fn soa_lengths(self) -> Option<(u8, u8)>" not in zone_image_text:
    rdata_encoding_failures.append("PackedRdataEncoding does not carry both SOA name spans")
if "rdata_encoding: PackedRdataEncoding" not in rdata_range_text:
    rdata_encoding_failures.append("RdataRange does not store compact precomputed RDATA encoding shape")
if "rdata_encoding: PackedRdataEncoding" not in wire_record_text:
    rdata_encoding_failures.append("ZoneImageWireRecord does not carry compact precomputed RDATA encoding shape")
synthesized_struct_start = zone_image_text.find("struct ZoneImageSynthesizedRecord")
synthesized_struct_end = zone_image_text.find(
    "struct ZoneImageSelectedRecord", synthesized_struct_start
)
synthesized_struct_text = (
    zone_image_text[synthesized_struct_start:synthesized_struct_end]
    if synthesized_struct_start >= 0 and synthesized_struct_end >= 0
    else ""
)
if "rdata_encoding: PackedRdataEncoding" not in synthesized_struct_text:
    rdata_encoding_failures.append("synthesized records do not store compact precomputed RDATA encoding shape")
if "rr_type: u16" in synthesized_struct_text:
    rdata_encoding_failures.append("synthesized records still duplicate RR type outside fixed fields")
if ".decode(record.rdata.len())" in zone_image_text or "fn decode(" in rdata_encoding_text or ".decode(" in rdata_encode_text:
    rdata_encoding_failures.append("stored record visits still decode compact RDATA encoding before the composer branch")
if "rdlength_bytes: [u8; 2]" not in wire_record_text:
    rdata_encoding_failures.append("ZoneImageWireRecord does not carry prevalidated RDATA length bytes")
if "fixed_fields: ZoneImageRecordFixedFields" not in wire_record_text:
    rdata_encoding_failures.append("ZoneImageWireRecord does not carry precomputed TYPE/CLASS/TTL fields")
if "rr_type: u16" in wire_record_text:
    rdata_encoding_failures.append("ZoneImageWireRecord still duplicates RR type outside fixed fields")
if "fixed_fields: ZoneImageRecordFixedFields" not in image_rrset_text:
    rdata_encoding_failures.append("ImageRrset does not carry compiled TYPE/CLASS/TTL fields")
if "negative_ttl_bytes: [u8; 4]" not in image_rrset_text:
    rdata_encoding_failures.append("ImageRrset does not carry compiled negative-response SOA TTL bytes")
if "let fixed_fields = zone_image_record_fixed_fields(rr_type, class, ttl)" not in compile_rrset_text or "fixed_fields," not in compile_rrset_text:
    rdata_encoding_failures.append("ZoneImage compiler does not store RRset TYPE/CLASS/TTL fields")
if "negative_ttl_bytes: negative_ttl.to_be_bytes()" not in compile_rrset_text:
    rdata_encoding_failures.append("ZoneImage compiler does not store negative-response SOA TTL bytes")
if "wire_name_len_at(rdata, 0)" not in soa_minimum_text or "wire_name_len_at(rdata, rname_offset)" not in soa_minimum_text:
    rdata_encoding_failures.append("SOA minimum precompute does not use direct validated wire-name spans")
if "DomainName::parse" in soa_minimum_text:
    rdata_encoding_failures.append("SOA minimum precompute reparses RDATA names into DomainName")
if "rrset_fixed_fields_from_wire" in zone_image_text:
    rdata_encoding_failures.append("ZoneImage still slices immutable RRset wire to recover fixed fields")
if "rrset_fixed_fields_with_ttl" in zone_image_text:
    rdata_encoding_failures.append("ZoneImage still rebuilds fixed fields from runtime TTL override scalars")
if "rdata_encoding: zone_image_rdata_encoding(rr_type, rdata)" not in compile_rrset_text:
    rdata_encoding_failures.append("ZoneImage compiler does not classify stored RDATA encoding shape once")
if "rdata_encoding: PackedRdataEncoding" not in push_synthesized_encoding_text:
    rdata_encoding_failures.append("synthesized records do not accept prevalidated RDATA encoding shape")
if "rdata_encoding," not in push_synthesized_encoding_text:
    rdata_encoding_failures.append("synthesized records do not store the caller-provided RDATA encoding shape")
if "zone_image_rdata_encoding(" in push_synthesized_encoding_text:
    rdata_encoding_failures.append("synthesized records reparse generated RDATA encoding shape when pushed")
if "PackedRdataEncoding::single_name()" not in zone_image_text:
    rdata_encoding_failures.append("DNAME synthesized CNAMEs do not carry a prevalidated single-name RDATA encoding")
if "fixed_fields," not in push_synthesized_encoding_text:
    rdata_encoding_failures.append("synthesized records do not store carried precomputed TYPE/CLASS/TTL fields when pushed")
if "zone_image_record_fixed_fields(" in push_synthesized_encoding_text:
    rdata_encoding_failures.append("synthesized records rebuild TYPE/CLASS/TTL fields when pushed")
if "wire_name_len_at" in rdata_encode_text:
    rdata_encoding_failures.append("runtime ZoneImage wire-record RDATA encoder still reparses name lengths")
if ".checked_sub(20)" in rdata_encode_text or ".and_then(|names_len| names_len.checked_sub(mname_len))" in rdata_encode_text or "rdata.len() - mname_len - 20" in rdata_encode_text:
    rdata_encoding_failures.append("runtime SOA RDATA encoder still recomputes the validated second-name span")
if "rdata_encoding.soa_lengths()" not in rdata_encode_text:
    rdata_encoding_failures.append("runtime SOA RDATA encoder does not use carried SOA name spans")
if "match rdata_encoding" not in rdata_encode_text:
    if "rdata_encoding.is_copy()" not in rdata_encode_text:
        rdata_encoding_failures.append("runtime ZoneImage wire-record RDATA encoder does not use precomputed encoding shape")
wire_record_encode_start = dns_text.find("fn encode_zone_image_wire_record(")
wire_record_encode_end = dns_text.find("fn encode_zone_image_wire_record_rdata", wire_record_encode_start)
wire_record_encode_text = (
    dns_text[wire_record_encode_start:wire_record_encode_end]
    if wire_record_encode_start >= 0 and wire_record_encode_end >= 0
    else ""
)
if "record.rdata_encoding.is_copy()" not in wire_record_encode_text:
    rdata_encoding_failures.append("copy RDATA records do not bypass the compressed-RDATA rdlength patch path")
if "record.rdlength_bytes" not in wire_record_encode_text:
    rdata_encoding_failures.append("copy RDATA fast path does not write carried validated rdlength bytes directly")
if "(record.rdata.len() as u16).to_be_bytes()" in wire_record_encode_text:
    rdata_encoding_failures.append("copy RDATA fast path recomputes rdlength bytes from the runtime slice length")
if "record.fixed_fields" not in wire_record_encode_text:
    rdata_encoding_failures.append("wire-record encoder does not write precomputed TYPE/CLASS/TTL fields")
for scalar_field_rebuild in (
    "record.rr_type.to_be_bytes()",
    "record.class.to_be_bytes()",
    "record.ttl.to_be_bytes()",
):
    if scalar_field_rebuild in wire_record_encode_text:
        rdata_encoding_failures.append(f"wire-record encoder rebuilds {scalar_field_rebuild} at runtime")
if rdata_encoding_failures:
    print("status=failed")
    for failure in rdata_encoding_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage RDATA compression classification is still query-time work: "
        + ", ".join(rdata_encoding_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage stores per-record RDATA compression shape for copy, single-name, SOA, and MX records during image compilation or synthesized-record construction, carries that compact packed shape directly through transient wire-record views without a second decoded enum, carries both SOA name spans inside the two-byte packed encoding, carries RRset TYPE/CLASS/TTL fields in compiled RRset metadata plus preencoded negative-response SOA TTL bytes, stores generated-record TYPE/CLASS/TTL wire fields when synthesized without duplicating scalar RR type, and passes prevalidated synthesized RDATA encoding from the planner instead of reparsing generated CNAME RDATA; the runtime wire-record encoder matches that shape without reparsing wire name lengths or recomputing the compiled SOA second-name span, writes carried fixed fields, and copy RDATA records write validated rdlength plus bytes directly without the compressed-RDATA patch path.")

print()
print("check=ZoneImage synthesized dynamic appends stay infallible")
synthesized_append_failures = []
synthesized_struct_start = zone_image_text.find("struct ZoneImageSynthesizedRecord")
synthesized_struct_end = zone_image_text.find("struct ZoneImageSelectedRecord", synthesized_struct_start)
synthesized_struct_text = (
    zone_image_text[synthesized_struct_start:synthesized_struct_end]
    if synthesized_struct_start >= 0 and synthesized_struct_end >= 0
    else ""
)
push_synthesized_start = zone_image_text.find("    fn push_synthesized_answer(")
push_synthesized_end = zone_image_text.find("    fn push_selected_record_section", push_synthesized_start)
push_synthesized_text = (
    zone_image_text[push_synthesized_start:push_synthesized_end]
    if push_synthesized_start >= 0 and push_synthesized_end >= 0
    else ""
)
append_synthesized_start = zone_image_text.find("fn append_synthesized_record_wire")
append_synthesized_end = zone_image_text.find("fn synthesized_record_wire_len", append_synthesized_start)
append_synthesized_text = (
    zone_image_text[append_synthesized_start:append_synthesized_end]
    if append_synthesized_start >= 0 and append_synthesized_end >= 0
    else ""
)
append_plan_match = re.search(
    r"pub fn append_plan_wire\([^)]*\)\s*->\s*usize",
    zone_image_text,
    flags=re.DOTALL,
)
if "rdlength_bytes: [u8; 2]" not in synthesized_struct_text:
    synthesized_append_failures.append("synthesized dynamic records do not store precomputed rdlength bytes")
if "owner_wire: InlineNameWire" not in synthesized_struct_text:
    synthesized_append_failures.append("synthesized dynamic owners are not stored in inline wire buffers")
if "rdata: InlineNameWire" not in synthesized_struct_text:
    synthesized_append_failures.append("synthesized dynamic RDATA is not stored in inline wire buffers")
if "u16::try_from(rdata.len())" not in push_synthesized_text or "rdlength.to_be_bytes()" not in push_synthesized_text:
    synthesized_append_failures.append("synthesized dynamic records do not validate rdlength when pushed into the plan")
if "owner_wire: owner_override_wire(owner)" not in push_synthesized_text and (
    "let owner_wire = owner_override_wire(owner)" not in push_synthesized_text
    or "owner_wire," not in push_synthesized_text
):
    synthesized_append_failures.append("synthesized dynamic owner wire is not stored in the inline plan buffer")
if "record.rdlength_bytes" not in append_synthesized_text:
    synthesized_append_failures.append("synthesized append does not write precomputed rdlength bytes")
if "ZoneImageBuildError" in append_synthesized_text or "Result<" in append_synthesized_text:
    synthesized_append_failures.append("synthesized append helper is fallible again")
if not append_plan_match:
    synthesized_append_failures.append("benchmark append_plan_wire no longer returns an infallible count")
if synthesized_append_failures:
    print("status=failed")
    for failure in synthesized_append_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage synthesized dynamic appends lost rdlength/infallible discipline: "
        + ", ".join(synthesized_append_failures)
    )
else:
    print("status=passed")
    print("evidence=Dynamic synthesized records keep common owner and RDATA wire inline, validate DNS rdlength once when pushed into the plan, store the big-endian rdlength bytes, and the append_plan_wire benchmark hook plus synthesized append helper return infallible counts.")

print()
print("check=ZoneImage selected DNSSEC records carry wire length")
selected_record_failures = []
selected_struct_start = zone_image_text.find("struct ZoneImageSelectedRecord")
selected_struct_end = zone_image_text.find("#[derive(Debug, Clone, PartialEq, Eq)]", selected_struct_start + 1)
selected_struct_text = (
    zone_image_text[selected_struct_start:selected_struct_end]
    if selected_struct_start >= 0 and selected_struct_end >= 0
    else ""
)
selected_len_start = zone_image_text.find("    fn selected_record_wire_len(")
selected_len_end = zone_image_text.find("    fn selected_wire_record", selected_len_start)
selected_len_text = (
    zone_image_text[selected_len_start:selected_len_end]
    if selected_len_start >= 0 and selected_len_end >= 0
    else ""
)
selected_from_relation_start = zone_image_text.find("    fn selected_record_from_relation(")
selected_from_relation_end = zone_image_text.find("    fn precomputed_rrsig_relations", selected_from_relation_start)
selected_from_relation_text = (
    zone_image_text[selected_from_relation_start:selected_from_relation_end]
    if selected_from_relation_start >= 0 and selected_from_relation_end >= 0
    else ""
)
push_rrsig_start = zone_image_text.find("    fn push_rrsig_relations_for_rrset(")
push_rrsig_end = zone_image_text.find("    fn push_additional_relations_for_rrset", push_rrsig_start)
push_rrsig_text = (
    zone_image_text[push_rrsig_start:push_rrsig_end]
    if push_rrsig_start >= 0 and push_rrsig_end >= 0
    else ""
)
push_rrsig_runtime_start = zone_image_text.find("    fn push_rrsig_for_rrset(")
push_rrsig_runtime_end = zone_image_text.find("    fn precomputed_rrsig_records", push_rrsig_runtime_start)
push_rrsig_runtime_text = (
    zone_image_text[push_rrsig_runtime_start:push_rrsig_runtime_end]
    if push_rrsig_runtime_start >= 0 and push_rrsig_runtime_end >= 0
    else ""
)
precomputed_rrsig_start = zone_image_text.find("    fn precomputed_rrsig_relations(")
precomputed_rrsig_end = zone_image_text.find("    fn initial_dnssec_seen_selected_records(", precomputed_rrsig_start)
precomputed_rrsig_text = (
    zone_image_text[precomputed_rrsig_start:precomputed_rrsig_end]
    if precomputed_rrsig_start >= 0 and precomputed_rrsig_end >= 0
    else ""
)
test_precomputed_rrsig_start = zone_image_text.find("    fn precomputed_rrsig_records(")
test_precomputed_rrsig_prefix = (
    zone_image_text[max(0, test_precomputed_rrsig_start - 32):test_precomputed_rrsig_start]
    if test_precomputed_rrsig_start >= 0
    else ""
)
if "wire_len: u32" not in selected_struct_text:
    selected_record_failures.append("selected DNSSEC records do not carry precomputed wire length")
if "fixed_fields: ZoneImageRecordFixedFields" not in selected_struct_text:
    selected_record_failures.append("selected DNSSEC records do not carry precomputed TYPE/CLASS/TTL fields")
if "rdata: RdataRange" not in selected_struct_text:
    selected_record_failures.append("selected DNSSEC records do not carry the immutable RDATA range")
if "record_index: u32" in selected_struct_text:
    selected_record_failures.append("selected DNSSEC records still retain the stale record table index after carrying RDATA")
if "selected.wire_len as usize" not in selected_len_text:
    selected_record_failures.append("selected_record_wire_len does not read the selected-record handle length")
if "fixed_fields: rrset.fixed_fields" not in selected_from_relation_text:
    selected_record_failures.append("selected-record handle does not copy immutable RRset fixed fields")
if "rdata: record.rdata" not in selected_from_relation_text:
    selected_record_failures.append("selected-record handle does not copy immutable record RDATA range")
if "selected.fixed_fields" not in zone_image_text[zone_image_text.find("    fn append_selected_record_wire("):zone_image_text.find("    fn selected_record_wire_len", selected_len_start)]:
    selected_record_failures.append("selected-record emission does not use carried fixed fields")
if "selected.rdata" not in zone_image_text[zone_image_text.find("    fn append_selected_record_wire("):zone_image_text.find("    fn selected_record_wire_len", selected_len_start)]:
    selected_record_failures.append("selected-record emission does not use the carried RDATA range")
relation_struct_text = zone_image_text[zone_image_text.find("struct ImageRrsetRelation"):zone_image_text.find("struct ImageRrsetRelationSpan")]
if "wire_len: u32" in relation_struct_text:
    selected_record_failures.append("RRSIG relation stores full wire length despite retained memory rejection")
if "rdata_len: u16" not in relation_struct_text:
    selected_record_failures.append("RRSIG relation does not carry precomputed RDATA length")
if "owner_wire_len: u8" not in relation_struct_text:
    selected_record_failures.append("RRSIG relation does not carry precomputed owner wire length")
if "usize::from(relation.owner_wire_len)" not in selected_from_relation_text or "usize::from(relation.rdata_len)" not in selected_from_relation_text:
    selected_record_failures.append("selected-record handle does not use relation-carried owner/RDATA lengths")
if 'checked_u8(\n                        blob_len(rrsig_rrset.owner_wire),\n                        "selected RRSIG owner wire length",' not in push_rrsig_text:
    selected_record_failures.append("RRSIG relation owner wire length is not checked and copied from immutable metadata")
if "rdata_len: record.rdata.len" not in push_rrsig_text:
    selected_record_failures.append("RRSIG relation RDATA length is not copied from immutable record metadata")
if "let covered_type = covered_rrset.rr_type();" not in push_rrsig_text or "covered_type == RecordType::Rrsig as u16" not in push_rrsig_text:
    selected_record_failures.append("RRSIG relation compiler does not skip RRSIG RRsets")
if "covered_rrset.rr_type() == RecordType::Rrsig as u16" in push_rrsig_runtime_text:
    selected_record_failures.append("runtime RRSIG augmentation reintroduced a covered-RRSIG type guard instead of trusting empty relation slices")
if "precomputed_rrsig_relations(covered_rrset_id)" not in push_rrsig_runtime_text:
    selected_record_failures.append("runtime RRSIG augmentation does not consume the compiled relation slice directly")
if ".precomputed_rrsig_records(" in push_rrsig_runtime_text:
    selected_record_failures.append("runtime RRSIG augmentation still enters the test RRset iterator wrapper")
if "#[cfg(test)]" not in test_precomputed_rrsig_prefix:
    selected_record_failures.append("RRSIG relation iterator wrapper is not test-only")
if "rrsig_rrset_flags: Box<[u64]>" not in zone_image_text:
    selected_record_failures.append("ZoneImage missing compact RRSIG relation bitmap")
if "rrsig_rrset_flags: Vec<u64>" not in zone_image_text:
    selected_record_failures.append("ZoneImage builder missing compact RRSIG relation bitmap")
if "fn has_precomputed_rrsig_relations(&self, rrset_index: usize) -> bool" not in zone_image_text:
    selected_record_failures.append("ZoneImage missing RRSIG relation bitmap accessor")
if "set_rrset_flag(\n                &mut self.rrsig_rrset_flags,\n                rrset_index,\n                span.rrsig_offset != NO_RELATION_OFFSET," not in zone_image_text:
    selected_record_failures.append("ZoneImage builder does not mark RRsets with precomputed RRSIG relations")
if "if !self.has_precomputed_rrsig_relations(rrset_id.0 as usize)" not in precomputed_rrsig_text:
    selected_record_failures.append("runtime RRSIG relation lookup does not use the compiled bitmap fast gate")
if selected_record_failures:
    print("status=failed")
    for failure in selected_record_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage selected DNSSEC records lost carried wire-length accounting: "
        + ", ".join(selected_record_failures)
    )
else:
    print("status=passed")
    print("evidence=Immutable RRSIG relations carry checked owner-wire length plus precomputed RDATA length in a guarded compact relation layout; selected DNSSEC handles derive carried wire length from those relation fields, carry immutable RRset TYPE/CLASS/TTL fields plus the immutable record RDATA range, and do not retain a stale selected-record table index after construction. Plan accounting plus selected-record emission read those handle fields instead of re-indexing the selected RRset/record for accounting, fixed fields, or RDATA metadata. The relation compiler skips RRSIG RRsets, and runtime RRSIG augmentation consumes compiled relation slices directly with a compact bitmap fast gate before relation-span lookup while still trusting empty relation slices instead of rereading covered RRset type.")

print()
print("check=ZoneImage additional planning consumes relation slices directly")
additional_single_start = zone_image_text.find(
    "    fn add_precomputed_additionals_for_single_answer_rrset("
)
additional_single_end = zone_image_text.find(
    "    fn push_additionals_for_rrset_targets(", additional_single_start
)
additional_single_text = (
    zone_image_text[additional_single_start:additional_single_end]
    if additional_single_start >= 0 and additional_single_end >= 0
    else ""
)
additional_push_start = zone_image_text.find("    fn push_additionals_for_rrset_targets(")
additional_push_end = zone_image_text.find(
    "    #[cfg(test)]\n    fn precomputed_additional_rrsets(", additional_push_start
)
additional_push_text = (
    zone_image_text[additional_push_start:additional_push_end]
    if additional_push_start >= 0 and additional_push_end >= 0
    else ""
)
full_any_push_start = zone_image_text.find("    fn push_full_any_rrsets_at_node(")
full_any_push_end = zone_image_text.find("    fn push_full_any_rrsets_with_owner_at_node(", full_any_push_start)
full_any_push_text = (
    zone_image_text[full_any_push_start:full_any_push_end]
    if full_any_push_start >= 0 and full_any_push_end >= 0
    else ""
)
wildcard_full_any_push_start = zone_image_text.find(
    "    fn push_full_any_rrsets_with_owner_at_node("
)
wildcard_full_any_push_end = zone_image_text.find(
    "    fn append_selected_record_wire(", wildcard_full_any_push_start
)
wildcard_full_any_push_text = (
    zone_image_text[wildcard_full_any_push_start:wildcard_full_any_push_end]
    if wildcard_full_any_push_start >= 0 and wildcard_full_any_push_end >= 0
    else ""
)
additional_relation_gate_start = zone_image_text.find(
    "    fn precomputed_additional_relations_if_present("
)
additional_relation_gate_end = zone_image_text.find(
    "    fn precomputed_additional_relations(", additional_relation_gate_start
)
additional_relation_gate_text = (
    zone_image_text[additional_relation_gate_start:additional_relation_gate_end]
    if additional_relation_gate_start >= 0 and additional_relation_gate_end >= 0
    else ""
)
referral_glue_append_start = zone_image_text.find("    fn add_glue_for_ns_rrset(")
referral_glue_append_end = zone_image_text.find(
    "    fn add_precomputed_additionals_for_single_answer_rrset(",
    referral_glue_append_start,
)
referral_glue_append_text = (
    zone_image_text[referral_glue_append_start:referral_glue_append_end]
    if referral_glue_append_start >= 0 and referral_glue_append_end >= 0
    else ""
)
test_referral_rrsets_start = zone_image_text.find(
    "    fn precomputed_referral_glue_rrsets("
)
test_referral_rrsets_prefix = (
    zone_image_text[max(0, test_referral_rrsets_start - 32):test_referral_rrsets_start]
    if test_referral_rrsets_start >= 0
    else ""
)
additional_relation_failures = []
if "precomputed_referral_glue_relations(ns_rrset)" not in referral_glue_append_text:
    additional_relation_failures.append("referral-glue planner does not consume the compiled relation slice directly")
if "relation.rrset_id" not in referral_glue_append_text:
    additional_relation_failures.append("referral-glue planner no longer reads RRset handles from relations")
if ".precomputed_referral_glue_rrsets(" in referral_glue_append_text:
    additional_relation_failures.append("referral-glue planner still enters the RRset iterator wrapper")
if "#[cfg(test)]" not in test_referral_rrsets_prefix:
    additional_relation_failures.append("referral-glue RRset iterator wrapper is not test-only")
if "precomputed_additional_relations_if_present(rrset_id)" not in additional_single_text:
    additional_relation_failures.append("single-answer additional planner does not consume the compiled relation slice directly")
if "rr_type_may_have_additional_address_target(self.rrsets[rrset_id.0 as usize].rr_type())" not in additional_single_text:
    additional_relation_failures.append("single-answer additional planner does not skip relation lookup for non-target RR types")
if "return false" not in additional_single_text or "added = true" not in additional_single_text:
    additional_relation_failures.append("single-answer additional planner does not report whether compiled additionals were appended")
if ".precomputed_additional_rrsets(" in additional_single_text:
    additional_relation_failures.append("single-answer additional planner still enters the RRset iterator wrapper")
if "precomputed_additional_relations_if_present(rrset_id)" not in additional_push_text:
    additional_relation_failures.append("multi-answer additional dedupe helper does not consume relation slices directly")
if "let rrset = relation.rrset_id" not in additional_push_text:
    additional_relation_failures.append("multi-answer additional dedupe helper no longer reads RRset handles from relations")
if ".precomputed_additional_rrsets(" in additional_push_text:
    additional_relation_failures.append("multi-answer additional dedupe helper still enters the RRset iterator wrapper")
if "self.for_each_any_rrset_at_node(node_index, qclass, |rrset|" not in full_any_push_text:
    additional_relation_failures.append("exact full-ANY planning does not stream compiled-order RRsets")
if "self.push_additionals_for_rrset_targets(rrset, &mut seen_additionals, plan)" not in full_any_push_text:
    additional_relation_failures.append("exact full-ANY planning does not dedupe additionals during the streamed pass")
if "self.for_each_any_rrset_at_node(node_index, qclass, |rrset|" not in wildcard_full_any_push_text:
    additional_relation_failures.append("wildcard full-ANY planning does not stream compiled-order RRsets")
if "self.push_additionals_for_rrset_targets(rrset, &mut seen_additionals, plan)" not in wildcard_full_any_push_text:
    additional_relation_failures.append("wildcard full-ANY planning does not dedupe additionals during the streamed pass")
if "has_precomputed_additional_address_relations" not in additional_relation_gate_text:
    additional_relation_failures.append("relation-slice helper does not keep the bitmap fast gate for empty relation sets")
if "return &[]" not in additional_relation_gate_text:
    additional_relation_failures.append("relation-slice helper does not return an empty slice for non-target RRsets")
if "self.precomputed_additional_relations(rrset_id)" not in additional_relation_gate_text:
    additional_relation_failures.append("relation-slice helper does not return compiled additional-address relations")
if additional_relation_failures:
    print("status=failed")
    for failure in additional_relation_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage additional planning lost direct relation-slice discipline: "
        + ", ".join(additional_relation_failures)
    )
else:
    print("status=passed")
    print("evidence=Referral-glue, single-answer, and streamed full-ANY additional planning keep the compiled bitmap fast gate for empty relation sets where applicable, single-answer planning first skips relation lookup for RR types that cannot legally have address additionals and reports whether additionals were appended for direct-plan marking, then append or dedupe additional RRset handles directly from immutable relation slices while walking compiled-order answer RRsets once; the RRset iterator wrappers are retained only for test assertions.")

print()
print("check=ZoneImage additional-address relation compilation avoids target DomainName parsing")
additional_compile_start = zone_image_text.find("    fn push_additional_relations_for_rrset(")
additional_compile_end = zone_image_text.find(
    "    fn push_referral_glue_relations_for_rrset(", additional_compile_start
)
additional_compile_text = (
    zone_image_text[additional_compile_start:additional_compile_end]
    if additional_compile_start >= 0 and additional_compile_end >= 0
    else ""
)
target_wire_helpers_start = zone_image_text.find("fn additional_address_target_wire_rdata(")
target_wire_helpers_end = zone_image_text.find("fn skip_character_string(", target_wire_helpers_start)
target_wire_helpers_text = (
    zone_image_text[target_wire_helpers_start:target_wire_helpers_end]
    if target_wire_helpers_start >= 0 and target_wire_helpers_end >= 0
    else ""
)
target_relation_failures = []
if "additional_address_target_wire_rdata(rr_type, rdata)" not in additional_compile_text:
    target_relation_failures.append("additional-address relation compiler does not borrow target wire from RDATA")
if "wire_name_is_equal_or_subdomain_of_domain(target_wire, &self.origin)" not in additional_compile_text:
    target_relation_failures.append("additional-address relation compiler does not check target suffix from wire")
if "push_address_relations_for_target_wire(" not in additional_compile_text:
    target_relation_failures.append("additional-address relation compiler does not look up address relations from target wire")
if "fn additional_address_target_rdata(" in zone_image_text:
    target_relation_failures.append("stale DomainName-returning additional target parser remains")
for stale_helper in [
    "fn mx_exchange_rdata(",
    "fn srv_target_rdata(",
    "fn naptr_replacement_rdata(",
    "fn svcb_target_name_rdata(",
]:
    if stale_helper in zone_image_text:
        target_relation_failures.append(f"stale DomainName-returning helper remains: {stale_helper}")
if "DomainName::parse" in target_wire_helpers_text:
    target_relation_failures.append("target-wire RDATA helper reparses target names into DomainName")
if "wire_name_slice_at(" not in target_wire_helpers_text:
    target_relation_failures.append("target-wire RDATA helper does not use validated wire-name slices")
if target_relation_failures:
    print("status=failed")
    for failure in target_relation_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage additional-address relation compilation regressed to target DomainName parsing: "
        + ", ".join(target_relation_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage additional-address relation compilation borrows target names as validated wire slices, checks in-zone suffixes from wire, and builds address lookups from direct owner-wire canonical keys without materializing target DomainName values.")

print()
print("check=ZoneImage referral-glue relation compilation avoids delegation-owner parsing")
referral_glue_start = zone_image_text.find("    fn push_referral_glue_relations_for_rrset(")
referral_glue_end = zone_image_text.find("    fn push_referral_dnssec_relations_for_rrset(", referral_glue_start)
referral_glue_text = (
    zone_image_text[referral_glue_start:referral_glue_end]
    if referral_glue_start >= 0 and referral_glue_end >= 0
    else ""
)
referral_glue_failures = []
if "fn push_referral_glue_relations_for_rrset(" not in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler helper is missing")
if "owner_from_wire(" in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler reparses delegation owner wire into DomainName")
if "single_name_rdata_wire(rdata)" not in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler does not borrow NS target wire from RDATA")
if "wire_name_is_equal_or_subdomain_of_wire(target_wire, owner_wire, owner_label_count)" not in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler does not filter NS target wire against stored owner wire")
if "push_address_relations_for_target_wire(" not in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler does not look up glue from target wire")
if "wire_name_equals_domain_with_label_count_ignore_ascii_case(" not in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler does not compare apex owner directly from wire")
if "fn wire_name_is_equal_or_subdomain_of_wire(" not in zone_image_text:
    referral_glue_failures.append("wire-name suffix helper is missing")
if "DomainName::parse" in referral_glue_text or ".canonical_key()" in referral_glue_text:
    referral_glue_failures.append("referral-glue relation compiler reparses NS target wire into DomainName")
if "fn owner_from_wire(" in zone_image_text:
    referral_glue_failures.append("stale owner_from_wire DomainName parser remains in ZoneImage")
if referral_glue_failures:
    print("status=failed")
    for failure in referral_glue_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage referral-glue relation compilation regressed to delegation-owner parsing: "
        + ", ".join(referral_glue_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage referral-glue relation compilation compares delegation apex and glue target suffixes against stored owner wire and builds glue lookups from target wire without materializing the delegation owner or NS target as DomainName values.")

print()
print("check=ZoneImage referral DNSSEC uses plan-carried NS handle")
referral_dnssec_start = zone_image_text.find("    fn add_referral_dnssec_augmentations(")
referral_dnssec_end = zone_image_text.find(
    "    fn add_referral_dnssec_for_ns_rrset", referral_dnssec_start
)
referral_dnssec_text = (
    zone_image_text[referral_dnssec_start:referral_dnssec_end]
    if referral_dnssec_start >= 0 and referral_dnssec_end >= 0
    else ""
)
referral_plan_handle_failures = []
if "fn add_referral_dnssec_augmentations" not in referral_dnssec_text:
    referral_plan_handle_failures.append("referral DNSSEC augmentation helper not found")
if "plan.referral_ns_rrset()" not in referral_dnssec_text:
    referral_plan_handle_failures.append("referral DNSSEC augmentation does not read the plan-carried referral NS handle")
if "self.add_referral_dnssec_for_ns_rrset(rrset_id, plan, state)" not in referral_dnssec_text:
    referral_plan_handle_failures.append("referral DNSSEC augmentation does not jump directly through the carried NS handle")
for marker in [
    "authority_rrset_count",
    "plan.authority_rrsets[index]",
    "for index in 0..",
    "rrset.rr_type() != RecordType::Ns",
]:
    if marker in referral_dnssec_text:
        referral_plan_handle_failures.append(
            f"referral DNSSEC augmentation still scans the authority section: {marker}"
        )
if referral_plan_handle_failures:
    print("status=failed")
    for failure in referral_plan_handle_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage referral DNSSEC lost plan-handle discipline: "
        + ", ".join(referral_plan_handle_failures)
    )
else:
    print("status=passed")
    print("evidence=Referral DNSSEC augmentation uses the referral NS RRset carried by the immutable plan and no longer scans authority RRsets to rediscover the delegation NS handle.")

print()
print("check=ZoneImage signed-referral relation compilation avoids owner DomainName reparsing")
referral_relation_start = zone_image_text.find("    fn push_referral_dnssec_relations_for_rrset(")
referral_relation_end = zone_image_text.find("    fn find_rrset_by_owner_key(", referral_relation_start)
referral_relation_text = (
    zone_image_text[referral_relation_start:referral_relation_end]
    if referral_relation_start >= 0 and referral_relation_end >= 0
    else ""
)
canonical_wire_key_start = zone_image_text.find("fn canonical_key_from_uncompressed_wire(")
canonical_wire_key_end = zone_image_text.find("\nfn blob_from_arena(", canonical_wire_key_start)
canonical_wire_key_text = (
    zone_image_text[canonical_wire_key_start:canonical_wire_key_end]
    if canonical_wire_key_start >= 0 and canonical_wire_key_end >= 0
    else ""
)
referral_relation_failures = []
if "fn push_referral_dnssec_relations_for_rrset(" not in referral_relation_text:
    referral_relation_failures.append("signed-referral relation compiler helper is missing")
if "owner_from_wire(owner_wire)" in referral_relation_text or "delegation_owner.canonical_key()" in referral_relation_text:
    referral_relation_failures.append("signed-referral relation compiler reparses NS owner wire into DomainName")
if "wire_name_equals_domain_with_label_count_ignore_ascii_case(" not in referral_relation_text:
    referral_relation_failures.append("signed-referral relation compiler does not compare apex owner directly from wire")
if "canonical_key_from_uncompressed_wire(owner_wire)" not in referral_relation_text:
    referral_relation_failures.append("signed-referral relation compiler does not build rrset-index key directly from owner wire")
if "fn canonical_key_from_uncompressed_wire(" not in canonical_wire_key_text:
    referral_relation_failures.append("direct canonical owner-wire key helper is missing")
if "DomainName::parse" in canonical_wire_key_text or ".canonical_key()" in canonical_wire_key_text:
    referral_relation_failures.append("direct canonical owner-wire key helper uses DomainName parsing")
if "consumed != wire_name.len()" not in canonical_wire_key_text:
    referral_relation_failures.append("direct canonical owner-wire key helper does not reject trailing bytes")
if referral_relation_failures:
    print("status=failed")
    for failure in referral_relation_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage signed-referral relation compilation regressed to owner parsing: "
        + ", ".join(referral_relation_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage signed-referral DS/NSEC relation compilation compares apex NS owners directly from wire and builds the rrset-index owner key from uncompressed owner wire without allocating a DomainName.")

print()
print("check=ZoneImage DNSSEC authority proof dedupe uses inline state")
dnssec_state_start = zone_image_text.find("struct ZoneImageDnssecState")
dnssec_state_end = zone_image_text.find("#[derive(Debug, Clone, Copy)]", dnssec_state_start)
dnssec_state_text = (
    zone_image_text[dnssec_state_start:dnssec_state_end]
    if dnssec_state_start >= 0 and dnssec_state_end >= 0
    else ""
)
push_authority_start = zone_image_text.find("    fn push_authority_rrset(")
push_authority_end = zone_image_text.find("    fn push_nsec_covering_name(", push_authority_start)
push_authority_text = (
    zone_image_text[push_authority_start:push_authority_end]
    if push_authority_start >= 0 and push_authority_end >= 0
    else ""
)
dnssec_authority_dedupe_failures = []
if "appended_authority_rrsets: SmallVec<[ZoneImageRrsetId; 2]>" not in dnssec_state_text:
    dnssec_authority_dedupe_failures.append("DNSSEC authority proof appended set is not a two-entry inline SmallVec")
if "Option<SmallVec" in dnssec_state_text:
    dnssec_authority_dedupe_failures.append("DNSSEC authority proof appended set reintroduced optional state")
if "appended_authority_rrsets: SmallVec::new()" not in zone_image_text:
    dnssec_authority_dedupe_failures.append("DNSSEC augmentation state does not initialize the inline appended-proof set directly")
if "if let Some(appended_authority_rrsets)" in push_authority_text:
    dnssec_authority_dedupe_failures.append("authority proof insertion reintroduced optional appended-set branching")
if "state.appended_authority_rrsets.contains(&rrset_id)" not in push_authority_text:
    dnssec_authority_dedupe_failures.append("authority proof insertion does not check the inline appended-proof set")
if "original_authority_rrsets.contains(&rrset_id)" not in push_authority_text:
    dnssec_authority_dedupe_failures.append("authority proof insertion does not check the original authority prefix")
if "state.appended_authority_rrsets.push(rrset_id)" not in push_authority_text:
    dnssec_authority_dedupe_failures.append("authority proof insertion does not push newly appended proofs into inline state")
if dnssec_authority_dedupe_failures:
    print("status=failed")
    for failure in dnssec_authority_dedupe_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage DNSSEC authority proof dedupe lost inline-state discipline: "
        + ", ".join(dnssec_authority_dedupe_failures)
    )
else:
    print("status=passed")
    print("evidence=DNSSEC authority proof insertion uses an always-inline two-entry appended-proof set, checks that set before the original authority prefix, and avoids optional-state branching on the query path.")

print()
print("check=ZoneImage semantic planning is infallible")
dnssec_infallible_failures = []
response_plan_start = zone_image_text.find("pub fn lookup_response_plan")
response_plan_end = zone_image_text.find("pub fn augment_lookup_plan_with_dnssec", response_plan_start)
response_plan_text = (
    zone_image_text[response_plan_start:response_plan_end]
    if response_plan_start >= 0 and response_plan_end >= 0
    else ""
)
augment_start = zone_image_text.find("pub fn augment_lookup_plan_with_dnssec")
augment_end = zone_image_text.find("#[cfg(test)]", augment_start)
augment_text = (
    zone_image_text[augment_start:augment_end]
    if augment_start >= 0 and augment_end >= 0
    else ""
)
if "pub fn lookup_response_plan" not in response_plan_text:
    dnssec_infallible_failures.append("ZoneImage response-planning API not found")
if "Result<ZoneImageLookupPlan" in response_plan_text:
    dnssec_infallible_failures.append("response planning still returns a fallible Result")
if "pub fn augment_lookup_plan_with_dnssec" not in augment_text:
    dnssec_infallible_failures.append("ZoneImage DNSSEC augmentation API not found")
if "Result<ZoneImageLookupPlan" in augment_text:
    dnssec_infallible_failures.append("DNSSEC augmentation still returns a fallible Result")
if "qtype: u16" in augment_text:
    dnssec_infallible_failures.append("DNSSEC augmentation still accepts qtype after planning already classified answer presence")
if "PlanError" in dns_text:
    dnssec_infallible_failures.append("dead response plan-error metric label remains")
if "DnssecPlanError" in dns_text:
    dnssec_infallible_failures.append("dead DNSSEC plan-error metric label remains")
if "pub const COUNT: usize = 1;" not in dns_text:
    dnssec_infallible_failures.append("ZoneImage serve-failure metric count was not reduced to the single reachable reason")
if dnssec_infallible_failures:
    print("status=failed")
    for failure in dnssec_infallible_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage semantic planning reintroduced unreachable fallible planning: "
        + ", ".join(dnssec_infallible_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage response planning and DNSSEC augmentation return plans directly, leaving only response_build_failed as a reachable ZoneImage serve-failure metric label.")

print()
print("check=ZoneImage compiled RDATA rdlength is checked")
rdlength_failures = []
push_rrset_start = zone_image_text.find("    fn push_rrset(")
push_rrset_end = zone_image_text.find("    fn attach_rrset", push_rrset_start)
push_rrset_text = (
    zone_image_text[push_rrset_start:push_rrset_end]
    if push_rrset_start >= 0 and push_rrset_end >= 0
    else ""
)
if "    fn push_rrset(" not in push_rrset_text:
    rdlength_failures.append("ZoneImage builder push_rrset body not found")
if "u16::try_from(rdata.len())" not in push_rrset_text:
    rdlength_failures.append("compiled RR wire rdlength is not checked from RDATA length")
if "(rdata.len() as u16)" in push_rrset_text:
    rdlength_failures.append("compiled RR wire rdlength still uses a lossy cast")
if "RdataTooLarge" not in push_rrset_text:
    rdlength_failures.append("oversized RDATA does not fail ZoneImage compilation")
if rdlength_failures:
    print("status=failed")
    for failure in rdlength_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage compiled RDATA rdlength check regressed: "
        + ", ".join(rdlength_failures)
    )
else:
    print("status=passed")
    print("evidence=ZoneImage compilation rejects RDATA that cannot fit the DNS RR rdlength field before preencoding immutable wire records.")

print()
print("check=ZoneImage DNAME synthesis uses precomputed owner label count")
dname_failures = []
image_rrset_start = zone_image_text.find("struct ImageRrset")
image_rrset_end = zone_image_text.find(
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]", image_rrset_start + 1
)
image_rrset_text = (
    zone_image_text[image_rrset_start:image_rrset_end]
    if image_rrset_start >= 0 and image_rrset_end >= 0
    else ""
)
lookup_dname_start = zone_image_text.find("    fn lookup_dname(")
lookup_dname_end = zone_image_text.find(
    "    fn lookup_wildcard_at_closest_node", lookup_dname_start
)
lookup_dname_text = (
    zone_image_text[lookup_dname_start:lookup_dname_end]
    if lookup_dname_start >= 0 and lookup_dname_end >= 0
    else ""
)
if "owner_label_count: u16" not in image_rrset_text:
    dname_failures.append("ImageRrset does not carry compiled owner label count")
if 'owner_label_count: checked_u16(owner.labels().len(), "owner labels")?' not in push_rrset_text:
    dname_failures.append("ZoneImage builder does not precompute RRset owner label count")
if "synthesized_cname_fixed_fields_from_rrset(self.rrsets[dname.0 as usize])" not in lookup_dname_text:
    dname_failures.append("DNAME synthesis does not reuse compiled RRset fixed fields for generated CNAME records")
if "with_replaced_wire_suffix_and_stored_wire_parts_counted" not in lookup_dname_text:
    dname_failures.append("DNAME synthesis does not consume the counted suffix-replacement helper")
if "with_replaced_wire_suffix_wire_counted" not in lookup_dname_text:
    dname_failures.append("DNAME synthesis does not use the wire-only replacement path for terminal out-of-zone targets")
if "target.node_hint == ImageTargetNode::OutOfZone" not in lookup_dname_text:
    dname_failures.append("DNAME synthesis does not split literal unrelated out-of-zone targets before building a synthesized DomainName")
if "usize::from(self.rrsets[dname.0 as usize].owner_label_count)" not in lookup_dname_text:
    dname_failures.append("DNAME synthesis does not use the compiled DNAME owner label count")
wire_replacement_start = dns_text.find("    pub(crate) fn with_replaced_wire_suffix_wire_counted(")
wire_replacement_end = dns_text.find("    pub fn canonical_key", wire_replacement_start)
wire_replacement_text = (
    dns_text[wire_replacement_start:wire_replacement_end]
    if wire_replacement_start >= 0 and wire_replacement_end >= 0
    else ""
)
if "let mut wire = InlineNameWire::new()" not in wire_replacement_text:
    dname_failures.append("DNAME suffix replacement does not write generated target wire into the inline buffer directly")
if ".sum::<usize>()" in wire_replacement_text:
    dname_failures.append("DNAME suffix replacement still walks prefix labels just to pre-size generated target wire")
if "wire_label_count(dname_owner_wire)" in lookup_dname_text:
    dname_failures.append("DNAME synthesis still parses owner wire just to count labels")
if "zone_image_record_fixed_fields(" in lookup_dname_text or "rrset_ttl(" in lookup_dname_text:
    dname_failures.append("DNAME synthesis rebuilds generated CNAME fixed fields on the query path")
if dname_failures:
    print("status=failed")
    for failure in dname_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage DNAME synthesis lost precomputed owner label-count discipline: "
        + ", ".join(dname_failures)
    )
else:
    print("status=passed")
    print("evidence=DNAME synthesis consumes the owner label count compiled into ImageRrset, so target suffix replacement does not parse stored DNAME owner wire just to find the query-prefix boundary; literal unrelated out-of-zone DNAME targets use the wire-only replacement path and avoid building a synthesized DomainName, and generated target wire is serialized directly into the inline buffer without a prefix-length sizing walk.")

print()
print("check=ZoneImage CNAME/DNAME loop checks use target wire")
target_loop_failures = []
target_loop_start = zone_image_text.find("fn target_matches_original_query(")
target_loop_end = zone_image_text.find("fn insert_selected_record", target_loop_start)
target_loop_text = (
    zone_image_text[target_loop_start:target_loop_end]
    if target_loop_start >= 0 and target_loop_end >= 0
    else ""
)
single_name_wire_start = zone_image_text.find("fn single_name_target_wire")
single_name_wire_end = zone_image_text.find("#[cfg(test)]", single_name_wire_start)
single_name_wire_text = (
    zone_image_text[single_name_wire_start:single_name_wire_end]
    if single_name_wire_start >= 0 and single_name_wire_end >= 0
    else ""
)
if "enum IndirectionTargetWire" not in zone_image_text:
    target_loop_failures.append("indirection target wire source enum is missing")
if "IndirectionTargetWire::Borrowed(self.single_name_target_wire(target))" not in zone_image_text:
    target_loop_failures.append("compiled CNAME/DNAME targets are not passed as borrowed target wire")
if "struct ImageSingleNameTarget" not in zone_image_text or "rdata: RdataRange" not in zone_image_text:
    target_loop_failures.append("precomputed CNAME/DNAME target view does not carry its RDATA range")
if "let record = self.records[rrset.first_record as usize]" in single_name_wire_text:
    target_loop_failures.append("single-name target wire access still re-indexes the RRset first record")
if "self.rdata_blob(target.rdata)" not in single_name_wire_text:
    target_loop_failures.append("single-name target wire access does not slice the carried RDATA range directly")
if "IndirectionTargetWire::DynamicAnswer(synthesized_index)" not in zone_image_text:
    target_loop_failures.append("DNAME synthesized targets are not checked through their dynamic-answer wire")
if "wire_name_equals_domain_with_label_count_ignore_ascii_case" not in target_loop_text:
    target_loop_failures.append("loop checks do not compare target wire to the original query labels")
if "domain_names_equal_ignore_ascii_case" in zone_image_text:
    target_loop_failures.append("loop checks still carry the old DomainName label-vector comparison helper")
if target_loop_failures:
    print("status=failed")
    for failure in target_loop_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage CNAME/DNAME loop checks lost target-wire discipline: "
        + ", ".join(target_loop_failures)
    )
else:
    print("status=passed")
    print("evidence=CNAME/DNAME loop checks compare compiled or synthesized target wire directly against the original query labels, precomputed single-name target views carry their RDATA range for one arena-slice target-wire access, and existing in-zone targets still use node-handle equality.")

print()
print("check=ZoneImage CNAME/DNAME target resolution uses low-RRtype gates")
resolve_target_start = zone_image_text.find("    fn resolve_indirection_target")
resolve_target_end = zone_image_text.find("    fn add_glue_for_ns_rrset", resolve_target_start)
resolve_target_text = (
    zone_image_text[resolve_target_start:resolve_target_end]
    if resolve_target_start >= 0 and resolve_target_end >= 0
    else ""
)
target_resolution_failures = []
if "if self.low_rrtype_may_exist(qtype)" not in resolve_target_text:
    target_resolution_failures.append("indirection target resolution does not skip absent low-RRtype exact probes")
if "&& self.low_rrtype_may_exist(RecordType::Cname as u16)" not in resolve_target_text:
    target_resolution_failures.append("indirection target resolution does not skip CNAME fallback probes when the compiled image has no CNAME RRsets")
if "qtype != RecordType::Cname as u16" not in resolve_target_text:
    target_resolution_failures.append("indirection target resolution can repeat CNAME lookup for QTYPE=CNAME")
if target_resolution_failures:
    print("status=failed")
    for failure in target_resolution_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage CNAME/DNAME target resolution lost compiled low-RRtype gate discipline: "
        + ", ".join(target_resolution_failures)
    )
else:
    print("status=passed")
    print("evidence=CNAME/DNAME target resolution skips requested-type target-node probes when the compiled low-RRtype bitmap proves the low RR type is absent, skips target CNAME fallback probes when the compiled image has no CNAME RRsets, and avoids repeating the CNAME lookup for QTYPE=CNAME.")

print()
print("check=ZoneImage CNAME/DNAME target precompute avoids generic DNS name parser")
single_name_precompute_failures = []
single_name_helper_start = zone_image_text.find("fn single_name_rdata_bytes(")
single_name_helper_end = zone_image_text.find("fn single_name_rdata_wire(", single_name_helper_start)
single_name_helper_text = (
    zone_image_text[single_name_helper_start:single_name_helper_end]
    if single_name_helper_start >= 0 and single_name_helper_end >= 0
    else ""
)
single_name_precompute_start = zone_image_text.find("    fn precompute_single_name_targets(")
single_name_precompute_end = zone_image_text.find(
    "    fn build_target_node_hint(", single_name_precompute_start
)
single_name_precompute_text = (
    zone_image_text[single_name_precompute_start:single_name_precompute_end]
    if single_name_precompute_start >= 0 and single_name_precompute_end >= 0
    else ""
)
domain_uncompressed_start = dns_text.find("    pub(crate) fn from_uncompressed_wire(")
domain_uncompressed_end = dns_text.find(
    "    pub fn is_equal_or_subdomain_of", domain_uncompressed_start
)
domain_uncompressed_text = (
    dns_text[domain_uncompressed_start:domain_uncompressed_end]
    if domain_uncompressed_start >= 0 and domain_uncompressed_end >= 0
    else ""
)
if "DomainName::parse" in single_name_helper_text:
    single_name_precompute_failures.append("single-name target helper still invokes the generic DNS name parser")
if "DomainName::from_uncompressed_wire(rdata)" not in single_name_helper_text:
    single_name_precompute_failures.append("single-name target helper does not use the uncompressed wire constructor")
if "single_name_rdata_bytes(rdata)" not in single_name_precompute_text:
    single_name_precompute_failures.append("single-name target precompute does not flow through the guarded helper")
if "len & 0xc0 != 0" not in domain_uncompressed_text:
    single_name_precompute_failures.append("uncompressed wire constructor does not reject compressed/pointer labels")
if "pos == wire.len()" not in domain_uncompressed_text:
    single_name_precompute_failures.append("uncompressed wire constructor does not require whole-name consumption")
if single_name_precompute_failures:
    print("status=failed")
    for failure in single_name_precompute_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage CNAME/DNAME target precompute regressed to generic DNS name parsing: "
        + ", ".join(single_name_precompute_failures)
    )
else:
    print("status=passed")
    print("evidence=CNAME/DNAME single-name target precompute builds DomainName values from whole uncompressed RDATA wire only, rejecting compression pointers and trailing bytes without invoking the generic DNS message-name parser.")

print()
print("check=ZoneImage DS-at-delegation owner comparison uses compiled node ownership")
ds_owner_failures = []
ds_owner_helper_start = zone_image_text.find("    fn query_is_ds_at_delegation_owner(")
ds_owner_helper_end = zone_image_text.find("    fn covering_dname_blocks_direct_answer", ds_owner_helper_start)
ds_owner_helper_text = (
    zone_image_text[ds_owner_helper_start:ds_owner_helper_end]
    if ds_owner_helper_start >= 0 and ds_owner_helper_end >= 0
    else ""
)
if "self.query_is_ds_at_delegation_owner(exact_node, node_index, qtype, delegation)" not in response_plan_text:
    ds_owner_failures.append("response planner does not use the compiled-node DS-at-delegation owner check")
if "wire_name_equals_domain_with_label_count_ignore_ascii_case(" in response_plan_text:
    ds_owner_failures.append("response planner still scans stored owner wire for the DS-at-delegation exception")
if "wire_name_equals_domain_ignore_ascii_case(" in response_plan_text:
    ds_owner_failures.append("response planner still uses the uncounted DS-at-delegation owner comparison")
if "exact_node == Some(node_index)" not in ds_owner_helper_text:
    ds_owner_failures.append("compiled-node DS-at-delegation check does not require an exact query node")
if "self.node_owns_policy_rrset(node_index, delegation)" not in ds_owner_helper_text:
    ds_owner_failures.append("compiled-node DS-at-delegation check does not compare node depth with RRset owner depth")
if ds_owner_failures:
    print("status=failed")
    for failure in ds_owner_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage DS-at-delegation owner comparison lost compiled node-ownership discipline: "
        + ", ".join(ds_owner_failures)
    )
else:
    print("status=passed")
    print("evidence=DS-at-delegation exception planning uses exact trie-node state plus compiled policy-owner depth, avoiding a stored-owner wire scan while still rejecting below-cut DS queries.")

print()
print("check=ZoneImage QCLASS ANY policy handles stay conservative")
any_policy_failures = []
zone_struct_start = zone_image_text.find("pub struct ZoneImage")
zone_struct_end = zone_image_text.find("#[derive(Debug, Clone, Copy, PartialEq, Eq)]", zone_struct_start)
zone_struct_text = (
    zone_image_text[zone_struct_start:zone_struct_end]
    if zone_struct_start >= 0 and zone_struct_end >= 0
    else ""
)
finish_start = zone_image_text.find("    fn finish(mut self")
finish_end = zone_image_text.find("    fn precompute_single_name_targets", finish_start)
finish_text = (
    zone_image_text[finish_start:finish_end]
    if finish_start >= 0 and finish_end >= 0
    else ""
)
delegation_start = zone_image_text.find("    fn delegation_for_node(")
delegation_end = zone_image_text.find("    fn dname_for_node", delegation_start)
delegation_text = (
    zone_image_text[delegation_start:delegation_end]
    if delegation_start >= 0 and delegation_end >= 0
    else ""
)
dname_policy_start = zone_image_text.find("    fn dname_for_node(")
dname_policy_end = zone_image_text.find("    fn covering_delegation_blocks_direct_answer", dname_policy_start)
dname_policy_text = (
    zone_image_text[dname_policy_start:dname_policy_end]
    if dname_policy_start >= 0 and dname_policy_end >= 0
    else ""
)
cover_delegation_start = zone_image_text.find("    fn covering_delegation_blocks_direct_answer(")
cover_delegation_end = zone_image_text.find("    fn node_owns_policy_rrset", cover_delegation_start)
cover_delegation_text = (
    zone_image_text[cover_delegation_start:cover_delegation_end]
    if cover_delegation_start >= 0 and cover_delegation_end >= 0
    else ""
)
node_policy_owner_start = zone_image_text.find("    fn node_owns_policy_rrset(")
node_policy_owner_end = zone_image_text.find("    fn covering_dname_blocks_direct_answer", node_policy_owner_start)
node_policy_owner_text = (
    zone_image_text[node_policy_owner_start:node_policy_owner_end]
    if node_policy_owner_start >= 0 and node_policy_owner_end >= 0
    else ""
)
cover_dname_start = zone_image_text.find("    fn covering_dname_blocks_direct_answer(")
cover_dname_end = zone_image_text.find("    fn nearest_inherited_in_dname", cover_dname_start)
cover_dname_text = (
    zone_image_text[cover_dname_start:cover_dname_end]
    if cover_dname_start >= 0 and cover_dname_end >= 0
    else ""
)
if "any_class_delegation_policy_is_in_only: bool" not in zone_struct_text:
    any_policy_failures.append("ZoneImage does not carry the QCLASS=ANY delegation policy gate")
if "any_class_dname_policy_is_in_only: bool" not in zone_struct_text:
    any_policy_failures.append("ZoneImage does not carry the QCLASS=ANY DNAME policy gate")
if "build_node_has_non_in_rrset" not in zone_image_text:
    any_policy_failures.append("builder helper for detecting non-IN policy RRsets is missing")
if "RecordType::Ns" not in finish_text or "any_class_delegation_policy_is_in_only" not in finish_text:
    any_policy_failures.append("ZoneImage finish does not derive the non-IN delegation policy gate")
if "RecordType::Dname" not in finish_text or "any_class_dname_policy_is_in_only" not in finish_text:
    any_policy_failures.append("ZoneImage finish does not derive the non-IN DNAME policy gate")
if "qclass == 1 || (qclass == 255 && self.any_class_delegation_policy_is_in_only)" not in delegation_text:
    any_policy_failures.append("delegation lookup does not reuse IN policy handles for safe QCLASS=ANY images")
if "qclass == 1 || (qclass == 255 && self.any_class_delegation_policy_is_in_only)" not in cover_delegation_text:
    any_policy_failures.append("direct-answer delegation guard does not reuse IN policy handles for safe QCLASS=ANY images")
if "self.node_owns_policy_rrset(node_index, delegation)" not in cover_delegation_text:
    any_policy_failures.append("direct-answer DS delegation guard does not use compiled policy ownership")
if "rrset.owner_label_count" not in node_policy_owner_text or "node.depth" not in node_policy_owner_text:
    any_policy_failures.append("compiled policy ownership helper does not compare rrset owner depth to node depth")
if "qclass == 1 || (qclass == 255 && self.any_class_dname_policy_is_in_only)" not in dname_policy_text:
    any_policy_failures.append("DNAME lookup does not reuse IN policy handles for safe QCLASS=ANY images")
if "qclass == 1 || (qclass == 255 && self.any_class_dname_policy_is_in_only)" not in cover_dname_text:
    any_policy_failures.append("direct-answer DNAME guard does not reuse IN policy handles for safe QCLASS=ANY images")
if any_policy_failures:
    print("status=failed")
    for failure in any_policy_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage QCLASS=ANY policy-handle gating regressed: "
        + ", ".join(any_policy_failures)
    )
else:
    print("status=passed")
    print("evidence=QCLASS=ANY delegation and DNAME lookup plus direct-answer delegation/DNAME guards reuse compiled IN policy handles only when the compiled image contains no non-IN delegation or DNAME policy RRsets; the DS-at-delegation direct guard compares compiled policy-owner depth instead of rescanning the current node, while mixed-class images keep the conservative ancestor scan.")

print()
print("check=ZoneImage question compression uses parsed labels")
generic_start = dns_text.find("fn build_zone_image_response(")
generic_end = dns_text.find("fn build_truncated_zone_image_response", generic_start)
truncated_start = dns_text.find("fn build_zone_image_response_from_wire_records")
truncated_end = dns_text.find("fn zone_image_wire_record_uncompressed_len", truncated_start)
generic_text = dns_text[generic_start:generic_end] if generic_start >= 0 and generic_end >= 0 else ""
known_count_start = dns_text.find("fn build_zone_image_response_from_plan_records")
known_count_end = dns_text.find("#[allow(clippy::too_many_arguments)]\nfn zone_image_response_prefix", known_count_start)
if known_count_start >= 0 and known_count_end >= 0:
    generic_text += dns_text[known_count_start:known_count_end]
truncated_text = (
    dns_text[truncated_start:truncated_end]
    if truncated_start >= 0 and truncated_end >= 0
    else ""
)
label_seed = "register_name_labels_at_offset(\n        question.qname.labels(),\n        question.qname_wire_len(),\n        question.qname_ascii_lowercase(),\n        DNS_HEADER_LEN,"
compression_failures = []
for label, text in [
    ("generic ZoneImage response", generic_text),
    ("truncated ZoneImage response rebuild", truncated_text),
]:
    if label_seed not in text:
        compression_failures.append(f"{label} does not seed compression from parsed labels")
    if "register_wire_name_at_offset(" in text:
        compression_failures.append(f"{label} scans serialized question wire for compression")
label_register_start = dns_text.find("fn register_name_labels_at_offset")
label_register_end = dns_text.find("fn write_wire_name", label_register_start)
label_register_text = (
    dns_text[label_register_start:label_register_end]
    if label_register_start >= 0 and label_register_end >= 0
    else ""
)
if "suffix_wire_len" not in label_register_text:
    compression_failures.append("parsed-label compression registration does not track suffix length incrementally")
if "fn qname_wire_len(&self) -> usize" not in dns_text:
    compression_failures.append("Question does not expose parsed QNAME wire length for compressor seeding")
if "name_wire_len(labels)" in label_register_text:
    compression_failures.append("parsed-label compression registration recomputes full QNAME wire length")
if "name_wire_len(&labels[index..])" in label_register_text:
    compression_failures.append("parsed-label compression registration recomputes suffix wire length per label")
if "labels_are_ascii_lowercase: bool" not in label_register_text:
    compression_failures.append("parsed-label compression registration does not accept the carried lowercase QNAME fact")
if "self.push_label_suffix_offset(\n                    &labels[index..],\n                    suffix_wire_len,\n                    labels_are_ascii_lowercase," not in label_register_text:
    compression_failures.append("parsed-label suffix key construction does not reuse the carried suffix wire length and lowercase fact")
label_key_start = dns_text.find("fn label_suffix_small_key")
label_key_end = dns_text.find("fn wire_suffix_matches_key", label_key_start)
label_key_text = (
    dns_text[label_key_start:label_key_end]
    if label_key_start >= 0 and label_key_end >= 0
    else ""
)
if "labels_are_ascii_lowercase: bool" not in label_key_text:
    compression_failures.append("parsed-label suffix key helper does not accept the carried lowercase QNAME fact")
if "wire_len: usize" not in label_key_text:
    compression_failures.append("parsed-label suffix key helper does not accept the carried wire length")
if "SmallVec::with_capacity(wire_len)" not in label_key_text:
    compression_failures.append("parsed-label suffix key helper does not size from the carried wire length")
if "name_wire_len(labels)" in label_key_text:
    compression_failures.append("parsed-label suffix key helper recomputes suffix wire length")
if "if labels_are_ascii_lowercase {" not in label_key_text:
    compression_failures.append("parsed-label suffix keys do not fast-path the carried lowercase QNAME fact")
if "key.extend_from_slice(label)" not in label_key_text:
    compression_failures.append("parsed-label lowercase suffix keys are not copied directly")
if "pub(crate) fn parse_with_ascii_lowercase(" not in dns_text:
    compression_failures.append("DomainName parser does not expose the carried lowercase-name fact")
parse_lowercase_start = dns_text.find("pub(crate) fn parse_with_ascii_lowercase(")
parse_lowercase_end = dns_text.find("    pub(crate) fn from_uncompressed_wire", parse_lowercase_start)
parse_lowercase_text = (
    dns_text[parse_lowercase_start:parse_lowercase_end]
    if parse_lowercase_start >= 0 and parse_lowercase_end >= 0
    else ""
)
if "let mut ascii_lowercase = true" not in parse_lowercase_text:
    compression_failures.append("DomainName parser does not initialize lowercase tracking during parse")
if "let mut visited_pointers = SmallVec::<[usize; 4]>::new()" not in parse_lowercase_text:
    compression_failures.append("DomainName parser does not keep compressed-name pointer tracking inline")
if "ascii_lowercase &= packet[pos..pos + label_len]" not in parse_lowercase_text:
    compression_failures.append("DomainName parser does not update lowercase tracking while walking label bytes")
if "return Ok((Self { labels }, consumed, ascii_lowercase))" not in parse_lowercase_text:
    compression_failures.append("DomainName parser does not return the carried lowercase-name fact")
if "DomainName::parse_with_ascii_lowercase(packet, DNS_HEADER_LEN)" not in dns_text:
    compression_failures.append("Question parse does not consume the parser-carried QNAME lowercase fact")
if "labels_are_ascii_lowercase(qname.labels())" in dns_text:
    compression_failures.append("Question parse still rescans parsed labels for lowercase status")
wire_suffix_key_start = dns_text.find("fn wire_suffix_small_key")
wire_suffix_key_end = dns_text.find("fn label_suffix_small_key", wire_suffix_key_start)
wire_suffix_key_text = (
    dns_text[wire_suffix_key_start:wire_suffix_key_end]
    if wire_suffix_key_start >= 0 and wire_suffix_key_end >= 0
    else ""
)
wire_suffix_match_start = dns_text.find("fn wire_suffix_matches_key")
wire_suffix_match_end = dns_text.find("fn wire_label_matches_key", wire_suffix_match_start)
wire_suffix_match_text = (
    dns_text[wire_suffix_match_start:wire_suffix_match_end]
    if wire_suffix_match_start >= 0 and wire_suffix_match_end >= 0
    else ""
)
if "SmallVec::with_capacity(wire_suffix.len())" not in wire_suffix_key_text:
    compression_failures.append("stored-wire suffix key helper does not size from the carried wire suffix length")
if "if label.iter().any(u8::is_ascii_uppercase)" not in wire_suffix_key_text:
    compression_failures.append("stored-wire suffix key helper does not branch per label on uppercase presence")
if "key.extend_from_slice(label)" not in wire_suffix_key_text:
    compression_failures.append("stored-wire lowercase labels are not copied directly")
if "wire_suffix_is_ascii_lowercase(wire_suffix)" in wire_suffix_key_text:
    compression_failures.append("stored-wire suffix key helper reintroduced a separate full-suffix lowercase pre-scan")
if "SmallVec::from_slice(wire_suffix)" in wire_suffix_key_text:
    compression_failures.append("stored-wire suffix key helper reintroduced full-suffix copy after a pre-scan")
if "if wire_suffix == key {\n        return true;\n    }" not in wire_suffix_match_text:
    compression_failures.append("stored-wire suffix matching does not fast-path direct whole-suffix equality before label parsing")
if compression_failures:
    print("status=failed")
    for failure in compression_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage question compression seed reintroduced serialized-wire scanning: "
        + ", ".join(compression_failures)
    )
else:
    print("status=passed")
    print("evidence=Generic and truncated ZoneImage response composers seed question-name compression directly from parsed labels after writing the question, start from the parsed QNAME wire length stored on Question, reuse the carried suffix wire length plus the once-parsed lowercase-QNAME fact when building canonical suffix keys, avoid full-name or per-label suffix-length recomputation, copy already-lowercase parsed-label suffix keys directly, build stored-wire suffix keys in one pass by lowercasing only labels that contain uppercase bytes, and match already-canonical stored suffixes with direct whole-suffix equality before label parsing.")

print()
print("check=ZoneImage ANY selection uses compiled order without query-time sort")
zone_image_text = runtime_sources[Path("crates/oxidedns-core/src/zone_image.rs")]
lookup_plan_start = zone_image_text.find("pub fn lookup_response_plan")
lookup_plan_end = zone_image_text.find("pub fn augment_lookup_plan_with_dnssec", lookup_plan_start)
lookup_plan_text = (
    zone_image_text[lookup_plan_start:lookup_plan_end]
    if lookup_plan_start >= 0 and lookup_plan_end >= 0
    else ""
)
wildcard_start = zone_image_text.find("fn lookup_wildcard_at_closest_node")
wildcard_end = zone_image_text.find("fn resolve_cname_at", wildcard_start)
wildcard_text = (
    zone_image_text[wildcard_start:wildcard_end]
    if wildcard_start >= 0 and wildcard_end >= 0
    else ""
)
minimal_start = zone_image_text.find("fn minimal_any_rrset_at_node")
minimal_end = zone_image_text.find("fn for_each_any_rrset_at_node", minimal_start)
minimal_text = (
    zone_image_text[minimal_start:minimal_end]
    if minimal_start >= 0 and minimal_end >= 0
    else ""
)
any_start = zone_image_text.find("fn for_each_any_rrset_at_node")
any_end = zone_image_text.find("fn soa_rrset", any_start)
any_text = zone_image_text[any_start:any_end] if any_start >= 0 and any_end >= 0 else ""
any_failures = []
if "return Some(rrset_id);" not in minimal_text:
    any_failures.append("minimal ANY helper does not return directly from the first compiled-order match")
if "if let [rrset] = &self.rrsets[rrset_start..rrset_end]" not in minimal_text:
    any_failures.append("minimal ANY helper does not bypass the scan for single-RRset owners")
if "is_dnssec_proof_or_signature_type(rrset.rr_type())" not in minimal_text:
    any_failures.append("minimal ANY single-RRset path does not preserve DNSSEC-proof filtering")
if "SmallVec" in minimal_text:
    any_failures.append("minimal ANY helper still builds a collected RRset list")
if "minimal_any_rrset_at_node(node_index, qclass)" not in lookup_plan_text:
    any_failures.append("exact minimal ANY planning does not use scalar RRset selection")
if "minimal_any_rrset_at_node(wildcard_node, qclass)" not in wildcard_text:
    any_failures.append("wildcard minimal ANY planning does not use scalar RRset selection")
if "} else if self.low_rrtype_may_exist(qtype)" not in lookup_plan_text:
    any_failures.append("semantic response planning does not skip absent low-RRtype exact probes before CNAME/DNAME fallback")
if "} else if self.low_rrtype_may_exist(qtype)" not in wildcard_text:
    any_failures.append("wildcard response planning does not skip absent low-RRtype probes before CNAME fallback")
if "&& self.low_rrtype_may_exist(RecordType::Cname as u16)" not in lookup_plan_text:
    any_failures.append("semantic response planning does not skip CNAME fallback probes when the compiled image has no CNAME RRsets")
if "&& self.low_rrtype_may_exist(RecordType::Cname as u16)" not in wildcard_text:
    any_failures.append("wildcard response planning does not skip CNAME fallback probes when the compiled image has no CNAME RRsets")
if "if self.low_rrtype_may_exist(RecordType::Dname as u16)" not in lookup_plan_text:
    any_failures.append("semantic response planning does not skip DNAME fallback probes when the compiled image has no DNAME RRsets")
if "fn any_rrsets_at_node" in zone_image_text:
    any_failures.append("full ANY planning reintroduced a collected RRset-list helper")
if "AnyResponseMode::Minimal" in any_text:
    any_failures.append("collected ANY helper still carries the minimal ANY branch")
if "if let [rrset] = &self.rrsets[rrset_start..rrset_end]" not in any_text:
    any_failures.append("full ANY walker does not bypass the scan for single-RRset owners")
if "visit(ZoneImageRrsetId(node.first_rrset))" not in any_text:
    any_failures.append("full ANY single-RRset path does not stream the single compiled RRset directly")
if "SmallVec" in any_text:
    any_failures.append("full ANY compiled-order walker still builds a collected RRset list")
if ".truncate(1)" in any_text:
    any_failures.append("minimal ANY branch reintroduced collect/sort/truncate")
if "rrsets.sort_by_key" in any_text or ".sort_by_key" in any_text:
    any_failures.append("ANY planning reintroduced query-time RRset sorting")
if any_failures:
    print("status=failed")
    for failure in any_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage ANY planning lost compiled-order no-sort discipline: "
        + ", ".join(any_failures)
    )
else:
    print("status=passed")
    print("evidence=Minimal QTYPE=ANY planning uses scalar compiled-order RRset selection for exact and wildcard answers, semantic and wildcard planning skip exact/wildcard RRset probes when the compiled low-RRtype bitmap proves the requested low type is absent and skip CNAME/DNAME fallback probes when the compiled image has no matching indirection RRsets, while preserving later CNAME/DNAME fallback semantics where applicable; both minimal and full ANY bypass scans for single-RRset owners while preserving DNSSEC-proof filtering, and full ANY streams matching compiled-order RRsets into the plan without a query-time sort or temporary RRset list.")

print()
print("check=ZoneImage trie child lookup keeps low-fanout fast path")
find_child_start = zone_image_text.find("    fn find_child(&self")
find_child_end = zone_image_text.find("    fn find_child_in_hash", find_child_start)
find_child_text = (
    zone_image_text[find_child_start:find_child_end]
    if find_child_start >= 0 and find_child_end >= 0
    else ""
)
find_child_hash_start = zone_image_text.find("    fn find_child_in_hash", find_child_end)
find_child_hash_end = zone_image_text.find("    fn find_node", find_child_hash_start)
find_child_hash_text = (
    zone_image_text[find_child_hash_start:find_child_hash_end]
    if find_child_hash_start >= 0 and find_child_hash_end >= 0
    else ""
)
child_lookup_failures = []
if "if node.edge_count == 0" not in find_child_text:
    child_lookup_failures.append("find_child does not return before hash/binary lookup for leaf nodes")
if "if let [edge] = edges" not in find_child_text:
    child_lookup_failures.append("find_child does not bypass binary search for single-child nodes")
if "lowercase_stored_label_eq_with_ascii_lowercase_hint" not in find_child_text:
    child_lookup_failures.append("single-child lookup does not preserve hinted case-insensitive label comparison")
if "const SMALL_CHILD_LINEAR_SCAN_THRESHOLD: u16 = 4" not in zone_image_text:
    child_lookup_failures.append("small-child linear scan threshold is not fixed at fanout 4")
if "if node.edge_count <= SMALL_CHILD_LINEAR_SCAN_THRESHOLD" not in find_child_text:
    child_lookup_failures.append("find_child does not use the small-child linear scan before hash/binary lookup")
if "fn find_child_by_linear_scan" not in find_child_text:
    child_lookup_failures.append("small-child linear scan helper is missing from child lookup path")
if "self.find_child_with_ascii_lowercase_hint(node_index, label, false)" not in find_child_text:
    child_lookup_failures.append("public child lookup wrapper does not keep conservative canonicalization")
if "self.find_child_in_hash(*node, edges, label, label_ascii_lowercase)" not in find_child_text:
    child_lookup_failures.append("high-fanout child hash probe is not preserved after the single-child fast path")
if "child_label_hash_with_ascii_lowercase_hint(label, label_ascii_lowercase)" not in find_child_hash_text:
    child_lookup_failures.append("high-fanout child hash does not consume the lowercase-label hint")
if "slot_mask: u32" not in zone_image_text or "let mask = hash.slot_mask as usize" not in find_child_hash_text:
    child_lookup_failures.append("high-fanout child hash does not carry a precomputed slot mask")
if "for _ in 0..=mask" not in find_child_hash_text:
    child_lookup_failures.append("high-fanout child hash probe loop does not use the precomputed slot mask")
if "cmp_lowercase_label_with_ascii_lowercase_hint(" not in find_child_text:
    child_lookup_failures.append("binary-search child comparison does not consume the lowercase-label hint")
if "query_node_handles(qname, qname_ascii_lowercase)" not in lookup_plan_text:
    child_lookup_failures.append("semantic response planning does not pass parser-carried lowercase QNAME facts into trie lookup")
if child_lookup_failures:
    print("status=failed")
    for failure in child_lookup_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage trie child lookup low-fanout fast path regressed: "
        + ", ".join(child_lookup_failures)
    )
else:
    print("status=passed")
    print("evidence=Trie child lookup returns immediately for leaf nodes, handles single-child nodes with one hinted case-insensitive edge check, scans fanout 2-4 nodes linearly before broader indexes, then falls back to retained generated hash and binary-search paths that carry a precomputed slot mask and can skip per-byte lowercasing when the packet parser proved the QNAME was already lowercase.")

print()
print("check=ZoneImage RRset lookup keeps single-RRset fast path")
rrset_lookup_start = zone_image_text.find("    fn find_rrset_at_node(")
rrset_lookup_end = zone_image_text.find("    fn minimal_any_rrset_at_node", rrset_lookup_start)
rrset_lookup_text = (
    zone_image_text[rrset_lookup_start:rrset_lookup_end]
    if rrset_lookup_start >= 0 and rrset_lookup_end >= 0
    else ""
)
rrset_lookup_failures = []
if "if node.rrset_count == 0" not in rrset_lookup_text:
    rrset_lookup_failures.append("find_rrset_at_node does not preserve empty-node handling before slicing RRsets")
if "low_rrtype_bitmap: u16" not in zone_image_text:
    rrset_lookup_failures.append("NameNode does not carry a compact node-local low-RRtype bitmap handle")
if "node_low_rrtype_bitmaps: Box<[u64]>" not in zone_image_text:
    rrset_lookup_failures.append("ZoneImage does not carry sparse node-local low-RRtype bitmaps")
if "build_node_low_rrtype_bitmaps(&self.image_rrsets, &self.build_nodes, &mut nodes)" not in zone_image_text:
    rrset_lookup_failures.append("ZoneImage builder does not precompute sparse node-local low-RRtype bitmaps")
if "node.rrsets.len() <= 1" not in zone_image_text:
    rrset_lookup_failures.append("node-local low-RRtype bitmaps are not limited to multi-RRset nodes")
if "if let Some(bitmap) = self.node_low_rrtype_bitmap(node_index)" not in rrset_lookup_text:
    rrset_lookup_failures.append("find_rrset_at_node does not skip scans for node-local absent low RR types")
node_bitmap_lookup_start = zone_image_text.find("    fn node_low_rrtype_bitmap(&self")
node_bitmap_lookup_end = zone_image_text.find("    fn minimal_any_rrset_at_node", node_bitmap_lookup_start)
node_bitmap_lookup_text = (
    zone_image_text[node_bitmap_lookup_start:node_bitmap_lookup_end]
    if node_bitmap_lookup_start >= 0 and node_bitmap_lookup_end >= 0
    else ""
)
if "binary_search_by_key" in node_bitmap_lookup_text:
    rrset_lookup_failures.append("node-local low-RRtype bitmap lookup still binary-searches the side table")
if "self.nodes[node_index as usize].low_rrtype_bitmap" not in node_bitmap_lookup_text:
    rrset_lookup_failures.append("node-local low-RRtype bitmap lookup does not use the NameNode handle")
if "if let [rrset] = &self.rrsets[rrset_start..rrset_end]" not in rrset_lookup_text:
    rrset_lookup_failures.append("find_rrset_at_node does not bypass ordered scan for single-RRset owners")
if "qclass_matches(rrset.class(), qclass)" not in rrset_lookup_text:
    rrset_lookup_failures.append("single-RRset lookup does not preserve QCLASS/ANY matching")
if "Ordering::Greater => break" not in rrset_lookup_text:
    rrset_lookup_failures.append("multi-RRset lookup lost compiled-order early exit")
if rrset_lookup_failures:
    print("status=failed")
    for failure in rrset_lookup_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage RRset lookup single-owner fast path regressed: "
        + ", ".join(rrset_lookup_failures)
    )
else:
    print("status=passed")
    print("evidence=RRset lookup preserves empty-node handling, uses node-local low-RRtype bitmaps to skip scans when common RR types are absent at that owner, then handles single-RRset owners with one QTYPE/QCLASS check before falling back to the retained compiled-order scan for multi-RRset owners.")

print()
print("check=ZoneImage exact lookup uses compiled RRset handle for concrete class")
exact_lookup_start = zone_image_text.find("    pub fn lookup_exact_plan(")
exact_lookup_end = zone_image_text.find("    pub fn lookup_direct_answer_plan", exact_lookup_start)
exact_lookup_text = (
    zone_image_text[exact_lookup_start:exact_lookup_end]
    if exact_lookup_start >= 0 and exact_lookup_end >= 0
    else ""
)
exact_lookup_failures = []
if "if qclass != 255" not in exact_lookup_text:
    exact_lookup_failures.append("lookup_exact_plan does not split concrete-class lookup from QCLASS=ANY")
if "self.find_rrset_at_node(node_index, qtype, qclass)" not in exact_lookup_text:
    exact_lookup_failures.append("concrete-class exact lookup does not reuse compiled RRset lookup")
if "if !self.low_rrtype_may_exist(qtype)" not in exact_lookup_text:
    exact_lookup_failures.append("lookup_exact_plan does not skip exact-owner RRset scans for globally absent low RR types")
if (
    exact_lookup_text.find("if !self.low_rrtype_may_exist(qtype)")
    < exact_lookup_text.find("let Some(node_index) = self.find_node(qname)")
    or exact_lookup_text.find("if !self.low_rrtype_may_exist(qtype)")
    > exact_lookup_text.find("if qclass != 255")
):
    exact_lookup_failures.append("lookup_exact_plan absent-low-RRtype gate is not after node classification and before RRset scanning")
if "for offset in 0..node.rrset_count" not in exact_lookup_text:
    exact_lookup_failures.append("QCLASS=ANY exact lookup no longer preserves multi-class RRset collection")
if "if let Some(bitmap) = self.node_low_rrtype_bitmap(node_index)" not in exact_lookup_text:
    exact_lookup_failures.append("QCLASS=ANY exact lookup does not use the node-local absent-RRtype gate")
if "qclass_matches(rrset.class(), qclass)" not in exact_lookup_text:
    exact_lookup_failures.append("QCLASS=ANY exact lookup lost class matching")
if exact_lookup_failures:
    print("status=failed")
    for failure in exact_lookup_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneImage exact lookup concrete-class fast path regressed: "
        + ", ".join(exact_lookup_failures)
    )
else:
    print("status=passed")
    print("evidence=Concrete-class exact lookup classifies exact node/missing/out-of-zone first, then uses the compiled low-RRtype bitmap to skip exact-owner scans for globally absent low RR types before reusing compiled RRset lookup and early exit; QCLASS=ANY uses the node-local absent-RRtype gate before keeping the retained multi-class collection scan when the type may exist.")

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
if (
    "pub type ZoneImageProvider<'a> =\n"
    "    &'a dyn for<'published> Fn(&'published PublishedZone) -> &'published ZoneImage;"
    not in dns_text
):
    snapshot_isolation_failures.append("ZoneImage provider does not borrow the published image")
if "pub fn default_zone_image_provider(published: &PublishedZone) -> &ZoneImage" not in dns_text:
    snapshot_isolation_failures.append("missing borrowed default ZoneImage provider")
if "published.active_zone_image_ref()" not in dns_text:
    snapshot_isolation_failures.append("default ZoneImage provider does not use borrowed image accessor")
if "pub fn active_zone_image(&self) -> Arc<ZoneImage>" in zone_text:
    snapshot_isolation_failures.append("PublishedZone still exposes active ZoneImage Arc-clone accessor")
if "pub fn zone_image(&self) -> Option<Arc<ZoneImage>>" in zone_text:
    snapshot_isolation_failures.append("PublishedZone still exposes optional ZoneImage Arc-clone accessor")
if "pub fn active_zone_image_ref(&self) -> &ZoneImage" not in zone_text:
    snapshot_isolation_failures.append("PublishedZone missing borrowed active ZoneImage accessor")
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
for marker in [".offline_oracle()", ".oracle_lookup_with_options(", ".oracle_lookup("]:
    if marker in answer_query_text:
        snapshot_isolation_failures.append(
            f"answer_query_message runs snapshot oracle lookup: {marker}"
        )
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
    print("evidence=Default ZoneImage serving requires a borrowed provider and borrowed active ZoneImage accessor, checks published state directly, and has no active or optional ZoneImage Arc-clone accessor, snapshot rollback serving API, runtime path selector, snapshot clone, or offline-oracle call.")

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
if "default_zone_image_provider" not in hooks_text:
    convenience_failures.append("answer_message_with_notify_hooks does not use the borrowed default ZoneImage provider")
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
print("check=NOTIFY SOA validation avoids canonical string keys")
notify_soa_start = dns_text.find("fn validate_notify_answer_soa")
notify_soa_end = dns_text.find("fn soa_serial", notify_soa_start)
notify_soa_text = (
    dns_text[notify_soa_start:notify_soa_end]
    if notify_soa_start >= 0 and notify_soa_end >= 0
    else ""
)
notify_soa_failures = []
if ".canonical_key()" in notify_soa_text:
    notify_soa_failures.append("validate_notify_answer_soa still materializes canonical owner keys")
if "parse_record_view_with_owner_match(packet, offset, &question.qname)" not in notify_soa_text:
    notify_soa_failures.append("validate_notify_answer_soa does not compare packet owner wire against the question during record parsing")
if notify_soa_failures:
    print("status=failed")
    for failure in notify_soa_failures:
        print(f"  failure={failure}")
    failures.append(
        "NOTIFY SOA validation still does per-packet canonical-key work: "
        + ", ".join(notify_soa_failures)
    )
else:
    print("status=passed")
    print("evidence=NOTIFY SOA answer-owner validation compares packet owner wire against the parsed question during borrowed record parsing and does not allocate canonical owner strings.")

print()
print("check=CHAOS TXT classification avoids canonical string keys")
chaos_answer_start = dns_text.find("fn answer_chaos_query")
chaos_answer_end = dns_text.find("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\nstruct ChaosClassification", chaos_answer_start)
chaos_answer_text = (
    dns_text[chaos_answer_start:chaos_answer_end]
    if chaos_answer_start >= 0 and chaos_answer_end >= 0
    else ""
)
chaos_classify_start = dns_text.find("fn classify_chaos_query")
chaos_classify_end = dns_text.find("impl<'a> ChaosClassification", chaos_classify_start)
chaos_classify_text = (
    dns_text[chaos_classify_start:chaos_classify_end]
    if chaos_classify_start >= 0 and chaos_classify_end >= 0
    else ""
)
chaos_classify_failures = []
if "pub(crate) fn matches_ascii_labels_ignore_case(&self, labels: &[&[u8]]) -> bool" not in dns_text:
    chaos_classify_failures.append("DomainName is missing direct ASCII-label matching")
if ".canonical_key()" in chaos_classify_text:
    chaos_classify_failures.append("classify_chaos_query still materializes a canonical QNAME")
if "is_chaos_version_name(&question.qname)" not in chaos_classify_text:
    chaos_classify_failures.append("classify_chaos_query does not use direct version-name matching")
if "is_chaos_hostname_name(&question.qname)" not in chaos_classify_text:
    chaos_classify_failures.append("classify_chaos_query does not use direct hostname-name matching")
if "build_chaos_txt_response(" not in chaos_answer_text:
    chaos_classify_failures.append("answered CHAOS TXT does not use the direct response builder")
if "ResourceRecord" in chaos_answer_text or "txt_character_string(" in chaos_answer_text:
    chaos_classify_failures.append("answered CHAOS TXT still materializes ResourceRecord/TXT RDATA")
if "build_response(" in chaos_answer_text and "Rcode::NoError" in chaos_answer_text:
    chaos_classify_failures.append("answered CHAOS TXT still routes through the old ResourceRecord composer")
if "fn build_chaos_txt_response" not in dns_text or "fn encode_chaos_txt_answer" not in dns_text:
    chaos_classify_failures.append("direct CHAOS TXT response writer is missing")
if chaos_classify_failures:
    print("status=failed")
    for failure in chaos_classify_failures:
        print(f"  failure={failure}")
    failures.append(
        "CHAOS TXT classification still does per-packet canonical-key work: "
        + ", ".join(chaos_classify_failures)
    )
else:
    print("status=passed")
    print("evidence=CHAOS TXT classification matches parsed QNAME labels directly, and answered CHAOS TXT writes the packet directly without materializing ResourceRecord values or TXT RDATA buffers.")

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
for marker in [".offline_oracle()", "oracle_lookup_with_options", "oracle_lookup("]:
    if marker in observe_query_text:
        observation_failures.append(f"observe_query_metrics runs snapshot oracle lookup: {marker}")
if "published_zone.origin().canonical_key()" in observe_query_text:
    observation_failures.append("observe_query_metrics rebuilds the zone canonical key from snapshot origin")
if "published_zone.origin_key()" not in observe_query_text:
    observation_failures.append("observe_query_metrics does not use PublishedZone cached canonical key")
if "find_published_zone_with_ascii_lowercase_hint(\n        &question.qname,\n        question.qname_ascii_lowercase()," not in observe_query_text:
    observation_failures.append("observe_query_metrics does not pass parser-carried lowercase QNAME fact into zone suffix lookup")
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
    print("evidence=Runtime query observation records zone metrics through PublishedZone cached canonical keys, carries the parser lowercase-QNAME hint into suffix lookup, and contains no snapshot clone, old snapshot/offline-oracle lookup, per-query origin canonical-key rebuild, or live shadow-validation oracle.")

print()
print("check=ZoneStore query lookup exposes PublishedZone handle")
zone_store_api_failures = []
if "pub fn find_zone" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes query-suffix lookup as Arc<ZoneSnapshot>")
if "pub fn get(&self, origin: &str)" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes stringly exact snapshot accessor")
if "pub fn find_exact_zone" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes generic exact-zone snapshot accessor")
if "find_exact_zone(" in server_text or "find_exact_zone(" in dns_text:
    zone_store_api_failures.append("runtime source still calls generic exact-zone snapshot accessor")
if "find_exact_snapshot_for_control" in zone_text or "find_exact_snapshot_for_control" in server_text or "find_exact_snapshot_for_control" in dns_text:
    zone_store_api_failures.append("generic exact snapshot control accessor was restored")
if "pub fn exact_snapshot_for_transfer" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing explicitly transfer-specific snapshot accessor")
if "zone_image_for_snapshot" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes snapshot-to-ZoneImage bridge")
if "pub fn find_published_zone" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing PublishedZone query lookup")
if "pub fn find_published_zone_with_ascii_lowercase_hint" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing lowercase-hinted PublishedZone query lookup")
published_lookup_start = zone_text.find("    pub fn find_published_zone_with_ascii_lowercase_hint")
published_lookup_end = zone_text.find("    /// Return cheap published-zone metadata", published_lookup_start)
published_lookup_text = (
    zone_text[published_lookup_start:published_lookup_end]
    if published_lookup_start >= 0 and published_lookup_end >= 0
    else ""
)
if ".filter(|entry| !entry.hidden)" in published_lookup_text:
    zone_store_api_failures.append("PublishedZone lookup repeats hidden-zone filtering after suffix match")
find_best_start = zone_text.find("    fn find_best_match(")
find_best_end = zone_text.find("fn canonical_reverse_label_key", find_best_start)
find_best_text = (
    zone_text[find_best_start:find_best_end]
    if find_best_start >= 0 and find_best_end >= 0
    else ""
)
if "&& !entry.hidden" not in find_best_text:
    zone_store_api_failures.append("ZoneDirectory suffix lookup does not own hidden-zone filtering")
if "find_published_zone_with_ascii_lowercase_hint(\n        &question.qname,\n        question.qname_ascii_lowercase()," not in dns_text:
    zone_store_api_failures.append("query serving does not pass the parser-carried lowercase QNAME fact into zone suffix lookup")
if "SmallVec::<[usize; 8]>::new()" not in zone_text:
    zone_store_api_failures.append("ZoneDirectory suffix lookup does not keep common prefix-length scratch inline")
if "SmallVec::<[u8; 128]>::with_capacity(key_capacity)" not in zone_text:
    zone_store_api_failures.append("ZoneDirectory suffix lookup does not keep common reverse-label key scratch inline")
if "labels_are_ascii_lowercase: bool" not in zone_text or "key.extend_from_slice(label)" not in zone_text:
    zone_store_api_failures.append("ZoneDirectory suffix key builder does not fast-path parser-proven lowercase labels")
if "pub fn contains_exact_zone(&self" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes generic exact-zone presence helper")
if "contains_exact_zone(" in server_text or "contains_exact_zone(" in dns_text:
    zone_store_api_failures.append("runtime source still calls generic exact-zone presence helper")
if "pub fn contains_exact_zone_for_control" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing explicitly named non-cloning control presence helper")
if "pub fn zone_metadata" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing non-cloning metadata iterator")
if "pub origin_key: Arc<str>" not in zone_text:
    zone_store_api_failures.append("ZoneMetadata does not carry the cached published origin key")
if "pub origin_name: Arc<str>" not in zone_text:
    zone_store_api_failures.append("ZoneMetadata does not carry the cached display origin name")
entry_start = zone_text.find("struct ZoneStoreEntry")
entry_end = zone_text.find("impl Default for ZoneStore", entry_start)
entry_text = zone_text[entry_start:entry_end] if entry_start >= 0 and entry_end >= 0 else ""
for cached_field in (
    "origin: DomainName",
    "origin_label_count: usize",
    "serial: Option<u32>",
    "soa_timers: Option<SoaTimers>",
):
    if cached_field not in entry_text:
        zone_store_api_failures.append(
            f"ZoneStoreEntry does not cache published scalar field: {cached_field}"
        )
published_zone_start = zone_text.find("impl PublishedZone")
published_zone_end = zone_text.find("impl ZoneDirectory", published_zone_start)
published_zone_text = (
    zone_text[published_zone_start:published_zone_end]
    if published_zone_start >= 0 and published_zone_end >= 0
    else ""
)
if "self.entry.snapshot.origin" in published_zone_text:
    zone_store_api_failures.append("PublishedZone origin accessor still reads the old snapshot layout")
if "self.entry.snapshot.serial" in published_zone_text:
    zone_store_api_failures.append("PublishedZone serial accessor still reads the old snapshot layout")
if "pub fn origin_label_count(&self) -> usize" not in published_zone_text:
    zone_store_api_failures.append("PublishedZone does not expose cached origin label count")
if "self.entry.origin_label_count" not in published_zone_text:
    zone_store_api_failures.append("PublishedZone origin label count does not read the cached entry scalar")
if "active_count: usize" not in zone_text:
    zone_store_api_failures.append("ZoneDirectory does not cache active-zone count")
if "fn active_count(&self) -> usize {\n        self.active_count\n    }" not in zone_text:
    zone_store_api_failures.append("ZoneDirectory active-zone count is not read from cached state")
active_count_start = zone_text.find("    pub fn active_count(&self) -> usize")
active_count_end = zone_text.find("    pub fn has_active_zone", active_count_start)
active_count_text = (
    zone_text[active_count_start:active_count_end]
    if active_count_start >= 0 and active_count_end >= 0
    else ""
)
if ".values()" in active_count_text or ".filter(" in active_count_text:
    zone_store_api_failures.append("ZoneStore active_count still scans directory entries")
if "self.zones.load().active_count()" not in active_count_text:
    zone_store_api_failures.append("ZoneStore active_count does not use cached directory count")
zone_metadata_start = zone_text.find("    pub fn zone_metadata(&self) -> Vec<ZoneMetadata>")
zone_metadata_end = zone_text.find("    /// Return all snapshots", zone_metadata_start)
zone_metadata_text = (
    zone_text[zone_metadata_start:zone_metadata_end]
    if zone_metadata_start >= 0 and zone_metadata_end >= 0
    else ""
)
if "entries.sort_by(|left, right| left.origin_key.cmp(&right.origin_key))" not in zone_metadata_text:
    zone_store_api_failures.append("ZoneStore metadata ordering does not use cached origin keys")
if "metadata.origin.canonical_key()" in zone_metadata_text:
    zone_store_api_failures.append("ZoneStore metadata ordering rebuilds canonical origin keys")
metadata_impl_start = zone_text.find("    fn metadata(&self) -> ZoneMetadata")
metadata_impl_end = zone_text.find("    fn snapshot_for_control", metadata_impl_start)
metadata_impl_text = (
    zone_text[metadata_impl_start:metadata_impl_end]
    if metadata_impl_start >= 0 and metadata_impl_end >= 0
    else ""
)
for stale_metadata_read in (
    "self.snapshot.origin.clone()",
    "self.snapshot.serial",
    "self.snapshot.soa_timers",
):
    if stale_metadata_read in metadata_impl_text:
        zone_store_api_failures.append(
            f"ZoneStore metadata/control view still reads the old snapshot layout: {stale_metadata_read}"
        )
scheduler_metrics_start = server_text.find("fn append_zone_scheduler_metrics")
scheduler_metrics_end = server_text.find("fn append_zone_query_metrics", scheduler_metrics_start)
scheduler_metrics_text = (
    server_text[scheduler_metrics_start:scheduler_metrics_end]
    if scheduler_metrics_start >= 0 and scheduler_metrics_end >= 0
    else ""
)
query_metrics_start = server_text.find("fn append_zone_query_metrics")
query_metrics_end = server_text.find("fn append_zone_rcode_metrics", query_metrics_start)
query_metrics_text = (
    server_text[query_metrics_start:query_metrics_end]
    if query_metrics_start >= 0 and query_metrics_end >= 0
    else ""
)
if "metadata.origin.canonical_key()" in scheduler_metrics_text:
    zone_store_api_failures.append("zone scheduler metrics rebuild ZoneMetadata origin canonical keys")
if "metadata.origin.canonical_key()" in query_metrics_text:
    zone_store_api_failures.append("zone query metrics rebuild ZoneMetadata origin canonical keys")
if "statuses.get(metadata.origin_key.as_ref())" not in scheduler_metrics_text:
    zone_store_api_failures.append("zone scheduler metrics do not use cached ZoneMetadata origin keys")
if "let zone_key = metadata.origin_key.as_ref();" not in query_metrics_text:
    zone_store_api_failures.append("zone query metrics do not use cached ZoneMetadata origin keys")
status_metrics_start = server_text.find("fn append_zone_status_metrics")
status_metrics_end = server_text.find("fn zone_loading_seconds", status_metrics_start)
status_metrics_text = (
    server_text[status_metrics_start:status_metrics_end]
    if status_metrics_start >= 0 and status_metrics_end >= 0
    else ""
)
shape_metrics_start = server_text.find("fn append_zone_shape_metrics")
shape_metrics_end = server_text.find("fn append_zone_shape_histogram_metrics", shape_metrics_start)
shape_metrics_text = (
    server_text[shape_metrics_start:shape_metrics_end]
    if shape_metrics_start >= 0 and shape_metrics_end >= 0
    else ""
)
for name, text in (
    ("zone status metrics", status_metrics_text),
    ("zone shape metrics", shape_metrics_text),
    ("zone scheduler metrics", scheduler_metrics_text),
    ("zone query metrics", query_metrics_text),
):
    if "metadata.origin.to_string()" in text:
        zone_store_api_failures.append(f"{name} rebuild ZoneMetadata origin display names")
    if "prometheus_label_value(metadata.origin_name.as_ref())" not in text:
        zone_store_api_failures.append(f"{name} do not use cached ZoneMetadata origin display names")
if "pub fn exact_zone_metadata" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing non-cloning exact status metadata lookup")
if "pub fn exact_zone_control_metadata" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing narrow exact control metadata lookup")
if "pub fn exact_snapshot_for_transfer(&self, origin: &DomainName) -> Option<TransferZoneSnapshot>" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing transfer-specific snapshot plus cached metadata lookup")
transfer_view_start = zone_text.find("pub struct TransferZoneSnapshot")
transfer_view_end = zone_text.find("#[derive(Debug, Clone, PartialEq, Eq)]", transfer_view_start)
transfer_view_text = (
    zone_text[transfer_view_start:transfer_view_end]
    if transfer_view_start >= 0 and transfer_view_end >= 0
    else ""
)
if "pub snapshot:" in transfer_view_text or "pub metadata:" in transfer_view_text:
    zone_store_api_failures.append("TransferZoneSnapshot still exposes public snapshot or metadata fields")
for marker in [
    "pub fn metadata(&self) -> &ZoneMetadata",
    "pub fn into_metadata(self) -> ZoneMetadata",
    "pub fn snapshot_for_transfer(&self) -> &ZoneSnapshot",
    "pub fn snapshot_arc_for_transfer(&self) -> &Arc<ZoneSnapshot>",
]:
    if marker not in zone_text:
        zone_store_api_failures.append(f"TransferZoneSnapshot missing explicit accessor: {marker}")
if "pub fn exact_snapshot_with_serial_for_transfer(" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing serial-gated IXFR transfer snapshot lookup")
serial_transfer_start = zone_text.find("    pub fn exact_snapshot_with_serial_for_transfer(")
serial_transfer_end = zone_text.find("    /// Check exact-origin presence", serial_transfer_start)
serial_transfer_text = (
    zone_text[serial_transfer_start:serial_transfer_end]
    if serial_transfer_start >= 0 and serial_transfer_end >= 0
    else ""
)
if ".filter(|entry| entry.serial.is_some())" not in serial_transfer_text:
    zone_store_api_failures.append("serial-gated IXFR transfer lookup does not check cached entry serial before exposing the snapshot")
if "snapshot: entry.snapshot_for_control()" not in serial_transfer_text or "metadata: entry.control_metadata()" not in serial_transfer_text:
    zone_store_api_failures.append("serial-gated IXFR transfer lookup does not return snapshot plus cached control metadata")
if "impl Deref for TransferZoneSnapshot" in zone_text:
    zone_store_api_failures.append("TransferZoneSnapshot still derefs implicitly to the old ZoneSnapshot layout")
if "type Target = ZoneSnapshot" in zone_text and "TransferZoneSnapshot" in zone_text:
    zone_store_api_failures.append("TransferZoneSnapshot still exposes a Deref Target to ZoneSnapshot")
if "state: ZoneState" not in zone_text[zone_text.find("struct ZoneStoreEntry"):zone_text.find("impl Default for ZoneStore")]:
    zone_store_api_failures.append("ZoneStoreEntry does not carry publication state separately from the old snapshot layout")
expire_zone_start = zone_text.find("    pub fn expire_zone(&self, origin: &DomainName) -> bool")
expire_zone_end = zone_text.find("    /// Return the exact-origin snapshot plus cached control metadata", expire_zone_start)
expire_zone_text = (
    zone_text[expire_zone_start:expire_zone_end]
    if expire_zone_start >= 0 and expire_zone_end >= 0
    else ""
)
if ".snapshot.with_state(ZoneState::Expired)" in expire_zone_text:
    zone_store_api_failures.append("ZoneStore expiration still clones the full snapshot to flip publication state")
if "entry.with_state(ZoneState::Expired)" not in expire_zone_text:
    zone_store_api_failures.append("ZoneStore expiration does not update publication state through the entry")
if "fn snapshot_for_control(&self) -> Arc<ZoneSnapshot>" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing lazy control snapshot state adapter for old-layout callers")
if "state: self.state" not in zone_text:
    zone_store_api_failures.append("ZoneMetadata does not read cached publication state")
if "pub fn snapshots" in zone_text:
    zone_store_api_failures.append("ZoneStore still exposes broad snapshots clone iterator")
if "pub fn offline_snapshots" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing explicitly offline snapshot iterator")
if "pub fn offline_snapshots(&self) -> Vec<Arc<ZoneSnapshot>>" in zone_text:
    zone_store_api_failures.append("ZoneStore offline snapshot iterator still exposes raw Arc<ZoneSnapshot> handles")
if "pub struct OfflineZoneSnapshot" not in zone_text:
    zone_store_api_failures.append("ZoneStore missing explicit offline snapshot oracle handle")
offline_view_start = zone_text.find("pub struct OfflineZoneSnapshot")
offline_view_end = zone_text.find("#[derive(Debug, Clone, Copy)]", offline_view_start)
offline_view_text = (
    zone_text[offline_view_start:offline_view_end]
    if offline_view_start >= 0 and offline_view_end >= 0
    else ""
)
if "pub snapshot:" in offline_view_text:
    zone_store_api_failures.append("OfflineZoneSnapshot still exposes public snapshot fields")
for marker in [
    "pub fn origin(&self) -> &DomainName",
    "pub fn state(&self) -> ZoneState",
    "pub fn serial(&self) -> Option<u32>",
    "pub fn snapshot_for_offline_oracle(&self) -> &ZoneSnapshot",
]:
    if marker not in offline_view_text:
        zone_store_api_failures.append(f"OfflineZoneSnapshot missing explicit accessor: {marker}")
offline_snapshots_start = zone_text.find("    pub fn offline_snapshots(&self) -> Vec<OfflineZoneSnapshot>")
offline_snapshots_end = zone_text.find("    pub fn len(&self) -> usize", offline_snapshots_start)
offline_snapshots_text = (
    zone_text[offline_snapshots_start:offline_snapshots_end]
    if offline_snapshots_start >= 0 and offline_snapshots_end >= 0
    else ""
)
if offline_snapshots_start < 0:
    zone_store_api_failures.append("ZoneStore offline snapshot iterator does not return OfflineZoneSnapshot handles")
if "entries.sort_by(|left, right| left.origin_key.cmp(&right.origin_key))" not in offline_snapshots_text:
    zone_store_api_failures.append("ZoneStore offline snapshot iterator does not sort by cached origin keys")
if ".canonical_key()" in offline_snapshots_text:
    zone_store_api_failures.append("ZoneStore offline snapshot iterator rebuilds origin canonical keys while sorting")
if "entry.snapshot_for_control()" not in offline_snapshots_text:
    zone_store_api_failures.append("ZoneStore offline snapshot iterator bypasses the publication-state control adapter")
if "canonical_reverse_label_key(&entry.snapshot.origin)" in zone_text:
    zone_store_api_failures.append("ZoneDirectory suffix index still rebuilds keys from snapshot origin")
if "published.origin().label_count()" in bench_text:
    zone_store_api_failures.append("ZoneDirectory suffix benchmark still derives label count through PublishedZone origin")
if "zones.snapshots()" in server_text:
    zone_store_api_failures.append("runtime server status/metrics still iterate cloned snapshots")
if "append_zone_status_metrics" in server_text and "zones.zone_metadata()" not in server_text:
    zone_store_api_failures.append("runtime status/metrics do not use ZoneStore metadata view")
if "zones.find_exact_snapshot_for_control(&request.zone)" in server_text:
    zone_store_api_failures.append("NOTIFY/refresh control still clones snapshots for serial or failure metadata")
if "zones.find_exact_snapshot_for_control(zone_apex)" in server_text:
    zone_store_api_failures.append("initial-load failure control still clones snapshots for failure metadata")
if "zones.find_exact_snapshot_for_control(&status.origin)" in server_text:
    zone_store_api_failures.append("loading-warning control still clones snapshots for zone state")
if "zone_store.find_exact_snapshot_for_control(&question.qname)" in dns_text:
    zone_store_api_failures.append("NOTIFY handling clones a ZoneSnapshot for exact-zone presence")
if "zones.find_exact_snapshot_for_control(&member_origin).is_none()" in server_text:
    zone_store_api_failures.append("catalog membership insertion clones a ZoneSnapshot for presence")
if "fn record_success_at(&self, snapshot: &ZoneSnapshot" in server_text:
    zone_store_api_failures.append("refresh registry test helper accepts ZoneSnapshot instead of cached ZoneMetadata")
if "fn record_success_at_with_timestamp(\n        &self,\n        snapshot: &ZoneSnapshot" in server_text:
    zone_store_api_failures.append("refresh registry timestamp test helper accepts ZoneSnapshot instead of cached ZoneMetadata")
if "refresh_registry.record_success_at_with_timestamp(\n            zones\n                .exact_snapshot_for_transfer" in server_text:
    zone_store_api_failures.append("metrics test seeds refresh status through transfer snapshot instead of cached control metadata")
if "pub fn snapshot(&self)" in zone_text:
    zone_store_api_failures.append("PublishedZone still exposes generic snapshot accessor")
if "snapshot_for_rollback_or_oracle" in zone_text:
    zone_store_api_failures.append("PublishedZone still exposes rollback/oracle snapshot accessor")
zone_snapshot_direct_impl_start = zone_text.find("impl ZoneSnapshot")
zone_snapshot_direct_impl_end = zone_text.find(
    "impl ZoneSnapshotOfflineOracle", zone_snapshot_direct_impl_start
)
zone_snapshot_direct_impl_text = (
    zone_text[zone_snapshot_direct_impl_start:zone_snapshot_direct_impl_end]
    if zone_snapshot_direct_impl_start >= 0 and zone_snapshot_direct_impl_end >= 0
    else ""
)
for marker in ["pub fn lookup(", "pub fn lookup_with_options("]:
    if marker in zone_snapshot_direct_impl_text:
        zone_store_api_failures.append(f"ZoneSnapshot still exposes generic serving lookup API: {marker}")
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
    print("evidence=Query-suffix lookup returns PublishedZone handles with parser-carried lowercase-QNAME hints, inline common-name reverse-key and prefix scratch, and directory-owned hidden filtering without a second post-match branch; PublishedZone and metadata views read cached entry origin/serial/SOA/state fields, status/metrics use cached ZoneStore metadata plus a cached directory active-zone count, publication state lives on ZoneStoreEntry so expiration does not clone the full snapshot, broad exact snapshot control access is removed, transfer snapshot fields are private behind explicit metadata and transfer-snapshot accessors, IXFR has a serial-gated transfer snapshot view, and presence-only NOTIFY/catalog checks use explicitly named non-cloning control membership probes.")

print()
print("check=Refresh serial decisions avoid eager snapshot clone")
refresh_start = server_text.find("async fn refresh_zone_from_primaries_with_outcome")
refresh_end = server_text.find("impl Drop for TcpConnectionPermit", refresh_start)
refresh_text = (
    server_text[refresh_start:refresh_end]
    if refresh_start >= 0 and refresh_end >= 0
    else ""
)
refresh_clone_failures = []
metadata_index = refresh_text.find(".exact_zone_control_metadata(&plan.origin)")
snapshot_index = refresh_text.find(".exact_snapshot_for_transfer(&plan.origin)")
transfer_snapshot_index = refresh_text.find(".exact_snapshot_with_serial_for_transfer(&plan.origin)")
if not refresh_text:
    refresh_clone_failures.append("refresh_zone_from_primaries_with_outcome not found")
if metadata_index < 0:
    refresh_clone_failures.append("refresh path does not read narrow exact-zone control metadata before serial decisions")
if snapshot_index >= 0 and metadata_index >= 0 and snapshot_index < metadata_index:
    refresh_clone_failures.append("refresh path clones exact snapshot before metadata serial checks")
if transfer_snapshot_index < 0:
    refresh_clone_failures.append("IXFR path does not use serial-gated transfer-specific exact snapshot plus cached metadata lookup")
if snapshot_index >= 0:
    refresh_clone_failures.append("IXFR path still uses the broad transfer snapshot lookup before serial gating")
if ".exact_zone_metadata(&plan.origin)" in refresh_text:
    refresh_clone_failures.append("refresh serial decisions use full status metadata instead of narrow control metadata")
if "zones.exact_zone_metadata(&request.zone)" in server_text:
    refresh_clone_failures.append("NOTIFY refresh control uses full status metadata instead of narrow control metadata")
if "zones.exact_zone_metadata(zone_apex)" in server_text:
    refresh_clone_failures.append("initial refresh failure control uses full status metadata instead of narrow control metadata")
if "zones.exact_zone_metadata(&status.origin)" in server_text:
    refresh_clone_failures.append("loading-warning control uses full status metadata instead of narrow control metadata")
if "pub fn exact_zone_control_metadata" not in zone_text or "fn control_metadata(&self) -> ZoneMetadata" not in zone_text:
    refresh_clone_failures.append("ZoneStore does not expose narrow exact-zone control metadata")
if "let current_snapshot = zones" in refresh_text:
    refresh_clone_failures.append("refresh path reintroduced eager current_snapshot clone")
if "Current(ZoneMetadata)" not in server_text:
    refresh_clone_failures.append("refresh current outcome does not carry narrow ZoneMetadata")
if "Current(Arc<ZoneSnapshot>)" in server_text:
    refresh_clone_failures.append("refresh current outcome still carries Arc<ZoneSnapshot>")
if "Updated {\n        snapshot: Arc<ZoneSnapshot>,\n        metadata: ZoneMetadata,\n    }" not in server_text:
    refresh_clone_failures.append("refresh updated outcome does not carry shared transfer snapshot plus narrow metadata")
if "fn into_metadata_and_updated_snapshot(self) -> (ZoneMetadata, Option<Arc<ZoneSnapshot>>)" not in server_text:
    refresh_clone_failures.append("refresh success outcome does not consume into narrow metadata plus updated-only snapshot access")
if "Self::Updated { snapshot, metadata } => (metadata, Some(snapshot))" not in server_text:
    refresh_clone_failures.append("refresh updated success handling rebuilds metadata instead of consuming carried metadata")
if "fn into_owned(self, zones: &ZoneStore) -> Option<ZoneSnapshot>" in server_text:
    refresh_clone_failures.append("test refresh success helper still clones outcomes back into owned ZoneSnapshot")
if "async fn refresh_zone_metadata_from_primaries(\n    zones: &ZoneStore,\n    plan: &ZoneTransferPlan,\n    primary_serial_hint: Option<u32>,\n    context: RefreshAttemptContext<'_>,\n) -> Option<ZoneSnapshot>" in server_text:
    refresh_clone_failures.append("test refresh helper returns an owned ZoneSnapshot instead of carried ZoneMetadata")
if "fn zone_metadata_from_snapshot(" in server_text:
    refresh_clone_failures.append("server refresh code still has a hand-built snapshot-to-metadata adapter")
if ".filter(|current| current.snapshot.serial.is_some())" in refresh_text:
    refresh_clone_failures.append("IXFR current transfer view checks serial through the old snapshot layout")
if ".filter(|current| current.metadata.serial.is_some())" in refresh_text:
    refresh_clone_failures.append("IXFR current transfer view filters cached metadata serial after exposing the snapshot")
if "&current.snapshot" in refresh_text or "current.snapshot." in refresh_text:
    refresh_clone_failures.append("IXFR current transfer view accesses the old snapshot field directly")
if "current.metadata" in refresh_text and "current.metadata()" not in refresh_text:
    refresh_clone_failures.append("IXFR current transfer view accesses cached metadata field directly")
if ".snapshot\n                        .serial\n                        .expect(\"IXFR current snapshot has a serial\")" in refresh_text:
    refresh_clone_failures.append("IXFR current transfer view reads current serial from the old snapshot layout")
if ".metadata()\n                        .serial\n                        .expect(\"IXFR current snapshot metadata has a serial\")" not in refresh_text:
    refresh_clone_failures.append("IXFR current transfer view does not read current serial from cached metadata")
if "current.snapshot_for_transfer()" not in refresh_text:
    refresh_clone_failures.append("IXFR current transfer path does not use the explicit transfer snapshot accessor")
if "current.into_metadata()" not in refresh_text:
    refresh_clone_failures.append("IXFR current outcome does not consume cached metadata through the explicit transfer view accessor")
if "success.metadata()" in server_text:
    refresh_clone_failures.append("refresh success handling clones current metadata through borrowed metadata accessor")
if "success.updated_snapshot()" in server_text:
    refresh_clone_failures.append("refresh success handling borrows updated snapshots through separate accessor")
if "current_metadata.clone()" in refresh_text:
    refresh_clone_failures.append("refresh current path clones narrow current metadata instead of consuming it on return")
if ".record_success(&snapshot)" in server_text:
    refresh_clone_failures.append("refresh success handling records success through full snapshot")
if "success.as_snapshot()" in server_text:
    refresh_clone_failures.append("refresh success handling applies full snapshot without updated-only gate")
if "RefreshZoneOutcome::success((*snapshot).clone())" in refresh_text:
    refresh_clone_failures.append("refresh current path clones full snapshot into success outcome")
if "RefreshZoneOutcome::success((*current_snapshot).clone())" in refresh_text:
    refresh_clone_failures.append("IXFR current path clones full snapshot into success outcome")
if "zone_metadata_from_snapshot(&current_snapshot)" in refresh_text or "zone_metadata_from_snapshot(&current.snapshot" in refresh_text:
    refresh_clone_failures.append("IXFR current path rebuilds control metadata from the cloned snapshot")
if "return RefreshZoneOutcome::current(snapshot)" in refresh_text:
    refresh_clone_failures.append("refresh current path returns a full snapshot outcome")
if "return RefreshZoneOutcome::current(metadata)" not in refresh_text:
    refresh_clone_failures.append("refresh current path does not return narrow metadata outcome")
if "zones.insert_snapshot((*snapshot).clone())" in refresh_text:
    refresh_clone_failures.append("IXFR updated path clones full transferred snapshot before publication")
if "zones.insert_snapshot(snapshot.clone())" in refresh_text:
    refresh_clone_failures.append("AXFR updated path clones full transferred snapshot before publication")
if "let metadata = zones.insert_snapshot_arc_for_transfer(snapshot.clone())" not in refresh_text:
    refresh_clone_failures.append("refresh updated path does not consume cached metadata returned by shared Arc transfer publication")
if "let serial = snapshot.serial;" in refresh_text:
    refresh_clone_failures.append("refresh updated path still reads completion serial from the old snapshot layout")
if "let serial = metadata.serial;" not in refresh_text:
    refresh_clone_failures.append("refresh updated path does not read completion serial from carried metadata")
if ".filter(|snapshot| catalog_runtime.manager.is_catalog(&snapshot.origin))" in server_text or "catalog_runtime.manager.is_catalog(&snapshot.origin)" in server_text:
    refresh_clone_failures.append("catalog follow-up detection still reads updated snapshot origin instead of carried metadata")
if ".is_catalog_key(metadata.origin_key.as_ref())" not in server_text:
    refresh_clone_failures.append("catalog follow-up detection does not use carried metadata origin key")
if "fn is_catalog(&self, origin: &DomainName)" in server_text:
    refresh_clone_failures.append("catalog manager still exposes origin-based catalog lookup for updated transfer follow-up")
if "fn is_catalog_key(&self, origin_key: &str) -> bool" not in server_text:
    refresh_clone_failures.append("catalog manager does not expose cached-key catalog lookup")
apply_snapshot_start = server_text.find("    async fn apply_snapshot(")
apply_snapshot_end = server_text.find("        if catalog.config.serve_catalog_zone", apply_snapshot_start)
apply_snapshot_text = (
    server_text[apply_snapshot_start:apply_snapshot_end]
    if apply_snapshot_start >= 0 and apply_snapshot_end >= 0
    else ""
)
if "metadata: &ZoneMetadata" not in apply_snapshot_text:
    refresh_clone_failures.append("catalog snapshot application does not accept carried metadata")
if "catalog_view: CatalogZoneView<'_>" not in apply_snapshot_text:
    refresh_clone_failures.append("catalog snapshot application accepts a full ZoneSnapshot instead of a narrow CatalogZoneView")
if "snapshot: &ZoneSnapshot" in apply_snapshot_text:
    refresh_clone_failures.append("catalog snapshot application still names a full ZoneSnapshot parameter")
if "self.catalogs_by_key.get(metadata.origin_key.as_ref())" not in apply_snapshot_text:
    refresh_clone_failures.append("catalog snapshot application rebuilds catalog key from updated snapshot")
if "parse_catalog_members(catalog_view)" not in server_text:
    refresh_clone_failures.append("catalog snapshot application does not parse through the passed CatalogZoneView")
if refresh_clone_failures:
    print("status=failed")
    for failure in refresh_clone_failures:
        print(f"  failure={failure}")
    failures.append(
        "Refresh transfer control reintroduced eager snapshot clone: "
        + ", ".join(refresh_clone_failures)
    )
else:
    print("status=passed")
    print("evidence=Refresh transfer control uses exact-zone control metadata without status-only shape clones for serial hint/SOA-poll/NOTIFY/loading decisions, consumes current successes into narrow ZoneMetadata without cloning, checks cached serial metadata before exposing the IXFR transfer snapshot view, reads IXFR current serials through transfer-view cached metadata while borrowing snapshots only for delta comparison, and publishes newly transferred builder snapshots through a shared Arc with carried metadata instead of cloning or rebuilding the full old layout in success handling.")

zone_snapshot_start = zone_text.find("impl ZoneSnapshot")
zone_snapshot_end = zone_text.find("impl ZoneSnapshotIndexes", zone_snapshot_start)
zone_snapshot_text = (
    zone_text[zone_snapshot_start:zone_snapshot_end]
    if zone_snapshot_start >= 0 and zone_snapshot_end >= 0
    else ""
)

print()
print("check=ZoneSnapshot oracle lookup remains outside runtime serving")
snapshot_lookup_failures = []
runtime_lookup_hits = []
for path, text in runtime_sources.items():
    if path == Path("crates/oxidedns-core/src/zone.rs"):
        continue
    for marker in [".offline_oracle()", ".oracle_lookup_with_options(", ".oracle_lookup("]:
        if marker in text:
            runtime_lookup_hits.append(f"{path}:{marker}")
if runtime_lookup_hits:
    snapshot_lookup_failures.append(
        "runtime non-test source calls ZoneSnapshot offline-oracle APIs: "
        + ", ".join(runtime_lookup_hits)
    )
if "Result<ZoneSnapshot, TransferError>" not in server_text:
    snapshot_lookup_failures.append("transfer workers no longer expose ZoneSnapshot builder output")
if "parse_axfr_response" not in axfr_text or "ZoneSnapshot::active" not in axfr_text:
    snapshot_lookup_failures.append("AXFR ingestion no longer builds ZoneSnapshot state")
if "augment_lookup_result_with_dnssec" in zone_text:
    snapshot_lookup_failures.append("ZoneSnapshot still exposes old materialized DNSSEC augmentation")
for marker in [
    "DnssecAugmentationState",
    "nsec3_hash_name",
    "nsec3_owner_hash_label",
    "nsec3_next_hash_label",
]:
    if marker in zone_text:
        snapshot_lookup_failures.append(f"ZoneSnapshot old DNSSEC oracle helper remains: {marker}")
if snapshot_lookup_failures:
    print("status=failed")
    for failure in snapshot_lookup_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneSnapshot oracle/builder boundary is not isolated: "
        + ", ".join(snapshot_lookup_failures)
    )
else:
    print("status=passed")
    print("evidence=Non-test runtime source outside ZoneSnapshot itself contains no offline-oracle lookup calls; transfer ingestion still produces ZoneSnapshot builder state for publication into ZoneImage.")

print()
print("check=ZoneSnapshot offline oracle API stays explicitly hidden")
snapshot_oracle_surface_failures = []
if not re.search(
    r"#\[doc\(hidden\)\]\s+pub fn offline_oracle\(&self\) -> ZoneSnapshotOfflineOracle<'_>",
    zone_snapshot_text,
    re.MULTILINE,
):
    snapshot_oracle_surface_failures.append(
        "ZoneSnapshot::offline_oracle is missing the #[doc(hidden)] public oracle handle annotation"
    )
if "pub struct ZoneSnapshotOfflineOracle" not in zone_text:
    snapshot_oracle_surface_failures.append("ZoneSnapshotOfflineOracle handle type not found")
if not re.search(
    r"#\[doc\(hidden\)\]\s+pub struct ZoneSnapshotOfflineOracle",
    zone_text,
    re.MULTILINE,
):
    snapshot_oracle_surface_failures.append("ZoneSnapshotOfflineOracle handle type is not doc-hidden")
if "impl ZoneSnapshotOfflineOracle<'_>" not in zone_snapshot_text:
    snapshot_oracle_surface_failures.append("ZoneSnapshotOfflineOracle public handle implementation not found")
if "pub fn lookup(&self, qname: &DomainName, qtype: u16, qclass: u16) -> LookupResult" not in zone_snapshot_text:
    snapshot_oracle_surface_failures.append("ZoneSnapshotOfflineOracle::lookup not found")
if "pub fn lookup_with_options(" not in zone_snapshot_text:
    snapshot_oracle_surface_failures.append("ZoneSnapshotOfflineOracle::lookup_with_options not found")
for name in ["oracle_lookup", "oracle_lookup_with_options"]:
    if re.search(rf"^\s+pub fn {name}\(", zone_snapshot_text, re.MULTILINE):
        snapshot_oracle_surface_failures.append(
            f"ZoneSnapshot still exposes direct public {name} method"
        )
if snapshot_oracle_surface_failures:
    print("status=failed")
    for failure in snapshot_oracle_surface_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneSnapshot offline oracle API is no longer clearly marked as offline-only: "
        + ", ".join(snapshot_oracle_surface_failures)
    )
else:
    print("status=passed")
    print("evidence=The old materialized query functions are reachable only through the explicit #[doc(hidden)] ZoneSnapshot::offline_oracle() handle, so ZoneSnapshot no longer exposes direct public lookup-style oracle methods.")

print()
print("check=Catalog parsing avoids full snapshot record materialization")
catalog_materialization_failures = []
if ".records()" in catalog_text:
    catalog_materialization_failures.append("catalog parser calls ZoneSnapshot::records()")
if ".rrsets()" not in catalog_text or ".rdatas()" not in catalog_text:
    catalog_materialization_failures.append("catalog parser does not use borrowed RRset/RDATA iteration")
if "pub fn parse_catalog_members(" not in catalog_text or "catalog_view: CatalogZoneView" not in catalog_text:
    catalog_materialization_failures.append("catalog parser does not take the narrow CatalogZoneView")
if "ZoneSnapshot" in catalog_text:
    catalog_materialization_failures.append("catalog parser runtime source imports or names ZoneSnapshot directly")
if catalog_materialization_failures:
    print("status=failed")
    for failure in catalog_materialization_failures:
        print(f"  failure={failure}")
    failures.append(
        "Catalog parser reintroduced full snapshot record materialization: "
        + ", ".join(catalog_materialization_failures)
    )
else:
    print("status=passed")
    print("evidence=Catalog-zone reconciliation parses member PTR and version TXT records through a narrow CatalogZoneView with borrowed RRset/RDATA iteration instead of materializing all ResourceRecord values or depending on the full snapshot API.")

print()
print("check=ZoneSnapshot full record materialization stays crate-internal")
snapshot_records_failures = []
if "    pub fn records(&self) -> Vec<ResourceRecord>" in zone_snapshot_text:
    snapshot_records_failures.append("ZoneSnapshot::records() is public")
if "    pub(crate) fn records(&self) -> Vec<ResourceRecord>" in zone_snapshot_text:
    snapshot_records_failures.append("ZoneSnapshot still exposes a generic crate-internal records() materializer")
if "    pub(crate) fn transfer_records(&self) -> Vec<ResourceRecord>" not in zone_snapshot_text:
    snapshot_records_failures.append("ZoneSnapshot::transfer_records() transfer materialization helper not found")
if "current_zone.transfer_records()" not in axfr_text:
    snapshot_records_failures.append("IXFR incremental transfer does not use the transfer-specific snapshot materializer")
if "current_zone.records()" in axfr_text:
    snapshot_records_failures.append("IXFR incremental transfer still calls generic current_zone.records()")
if "    pub fn records(&self) -> Vec<ResourceRecord>" in zone_text:
    snapshot_records_failures.append("Rrset::records() is public")
if "    pub fn records_with_owner(&self, owner: &DomainName) -> Vec<ResourceRecord>" in zone_text:
    snapshot_records_failures.append("Rrset::records_with_owner() is public")
if "    pub(crate) fn records(&self) -> Vec<ResourceRecord>" not in zone_text:
    snapshot_records_failures.append("Rrset::records() crate-internal materialization helper not found")
if "    pub(crate) fn records_with_owner(&self, owner: &DomainName) -> Vec<ResourceRecord>" not in zone_text:
    snapshot_records_failures.append("Rrset::records_with_owner() crate-internal materialization helper not found")
if snapshot_records_failures:
    print("status=failed")
    for failure in snapshot_records_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneSnapshot full materialized record API boundary regressed: "
        + ", ".join(snapshot_records_failures)
    )
else:
    print("status=passed")
    print("evidence=Whole-snapshot ResourceRecord materialization is crate-internal and transfer-named for IXFR rebuilds, while RRset materialization helpers remain crate-internal for transfer and offline oracle use, not public serving APIs.")

print()
print("check=ZoneSnapshot SOA access avoids public owned materialization")
snapshot_soa_failures = []
if re.search(r"^\s+pub fn soa_record\(", zone_snapshot_text, re.MULTILINE):
    snapshot_soa_failures.append("ZoneSnapshot still exposes public owned SOA record materialization")
if "    pub fn soa_record_view(&self, qclass: u16) -> Option<SoaRecordView<'_>>" not in zone_snapshot_text:
    snapshot_soa_failures.append("ZoneSnapshot missing borrowed SOA view")
if "    pub(crate) fn transfer_soa_record(&self, qclass: u16) -> Option<ResourceRecord>" not in zone_snapshot_text:
    snapshot_soa_failures.append("ZoneSnapshot missing crate-internal transfer SOA materialization helper")
if ".soa_record(" in server_text:
    snapshot_soa_failures.append("server transfer path materializes owned SOA through ZoneSnapshot::soa_record")
if "build_ixfr_query_from_soa_view" not in server_text:
    snapshot_soa_failures.append("server IXFR query path does not use borrowed SOA view builder")
if snapshot_soa_failures:
    print("status=failed")
    for failure in snapshot_soa_failures:
        print(f"  failure={failure}")
    failures.append(
        "ZoneSnapshot SOA access reintroduced public owned materialization: "
        + ", ".join(snapshot_soa_failures)
    )
else:
    print("status=passed")
    print("evidence=Cross-crate transfer query construction reads a borrowed SOA view; owned SOA materialization remains crate-internal for IXFR delta validation only.")

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
