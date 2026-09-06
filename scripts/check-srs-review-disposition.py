#!/usr/bin/env python3
"""Keep SRS review scope-trim disposition aligned with current code paths."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DISPOSITION_PATH = ROOT / "docs" / "srs-review-disposition.md"
FEATURE_SCOPE_PATH = ROOT / "docs" / "implemented-feature-scope.md"
SRS_CURRENT_PATH = ROOT / "docs" / "BoronDNS-Secondary-SRS-v1.0.0.md"
MVP_SCOPE_PATH = ROOT / "docs" / "engineering-mvp-scope.md"
IMPLEMENTATION_PLAN_PATH = ROOT / "docs" / "implementation-plan.md"
README_PATH = ROOT / "README.md"
DOCS_README_PATH = ROOT / "docs" / "README.md"
GAP_REGISTER_PATH = ROOT / "docs" / "release-acceptance-gap-register.md"
VERIFICATION_LEDGER_PATH = ROOT / "docs" / "verification-ledger.md"
OPERATOR_GUIDE_PATH = ROOT / "docs" / "operator-deployment-guide.md"

SCOPE_POINTER_DOCUMENTS = [
    MVP_SCOPE_PATH,
    IMPLEMENTATION_PLAN_PATH,
    README_PATH,
    DOCS_README_PATH,
    GAP_REGISTER_PATH,
    VERIFICATION_LEDGER_PATH,
    OPERATOR_GUIDE_PATH,
]


def references_file(document: Path, text: str, target: Path) -> bool:
    """Accept repository-relative code references and document-relative links."""
    if str(target.relative_to(ROOT)) in text:
        return True
    for destination in re.findall(r"\]\(([^)]+)\)", text):
        destination = destination.split("#", 1)[0].strip("<>")
        if "://" not in destination and (document.parent / destination).resolve() == target:
            return True
    return False


REQUIRED_REVIEW_DISPOSITIONS = [
    "BDS/RDS namespace mismatch",
    "Suffixed functional IDs violated the numeric scheme",
    "UPDATE rejection cross-reference pointed at `CORE-007`",
    "Response DO-bit semantics were wrong",
    "CD-bit handling needed authoritative-server context",
    "RRSIG records were incorrectly covered by ordinary RRset wording",
    "Static binary wording contradicted dynamic-link allowances",
    "SRS prescribed `ZoneProvider`/`ZoneSpec`/`ZoneSetDelta` internals",
    "Catalog zones should be deferred from MVP",
    "Verification governance is too heavy for local MVP",
    "Performance numbers should be targets rather than immediate local MVP blockers",
    "NSEC3 cap creates a DNSSEC authentication downgrade",
    "SRS mixed audit findings into normative requirements",
    "Panic isolation wording prescribed `catch_unwind` internals",
    "Exit-code table claimed controlled panic recovery",
    "Requirements claimed absolute atomicity while grouping many operational cases",
    "Health and metrics requirement mixed endpoint contract detail into one requirement",
    "SRS claimed v0.7 structural finality",
    "Catalog metrics catalogue exceeded implemented observability surface",
    "XoT TLS-version wording over-counted TLS 1.2",
]

REVIEW_SUGGESTED_DEFER_ITEMS = [
    "Catalog zones",
    "XoT",
    "DNS Cookies",
    "RRL beyond a simple first version",
    "Extended DNS Errors",
    "CHAOS `version.bind` / `id.server`",
    "Full DNSSEC negative proof synthesis",
    "Full Prometheus metric catalogue",
    "Packed zone store / pre-baked response cache",
    "Fixed 30-day soak test",
    "Full three-primary interop matrix",
    "Exact performance MUSTs",
    "Release signing",
    "CVE governance",
    "External operator acceptance",
]

REVIEW_BASELINE_SCOPE = {
    "secondary-only authoritative": {
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-server/src/lib.rs",
            "scripts/audit-invariants.sh",
        ],
        "evidence_paths": [
            "scripts/check.sh",
            "docs/architecture.md",
            "docs/engineering-mvp-readiness.md",
        ],
        "source_needles": [
            "Opcode::Notify",
            "BDS-INV-001 secondary-only prohibited runtime surfaces",
            "BDS-INV-007 authoritative-only response composition",
        ],
    },
    "static toml config and tsig": {
        "paths": [
            "crates/borondns-core/src/config.rs",
            "crates/borondns-core/src/tsig.rs",
            "crates/borondns-cli/src/main.rs",
            "config/borondns.example.toml",
        ],
        "evidence_paths": [
            "docs/devops-getting-started.md",
            "docs/operator-deployment-guide.md",
            "scripts/check.sh",
        ],
        "source_needles": [
            "pub struct ServerConfig",
            "pub struct ZoneConfig",
            "pub struct TransferPrimaryConfig",
            "pub struct TsigKey",
            "require_tsig",
        ],
    },
    "udp tcp edns": {
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/tcp.rs",
            "crates/borondns-server/src/udp.rs",
        ],
        "evidence_paths": [
            "scripts/interop-edns-behavior.sh",
            "scripts/interop-tcp-truncation-retry.sh",
        ],
        "source_needles": [
            "async fn serve_udp",
            "async fn serve_tcp",
            "parse_edns_options",
            "build_truncated_response",
        ],
    },
    "axfr zsm notify tsig": {
        "paths": [
            "crates/borondns-core/src/axfr.rs",
            "crates/borondns-core/src/tsig.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/transfer.rs",
        ],
        "evidence_paths": [
            "scripts/interop-bind-axfr.sh",
            "scripts/interop-bind-notify-refresh.sh",
            "scripts/interop-notify-negative.sh",
            "docs/zsm-engineering-mvp-matrix.tsv",
        ],
        "source_needles": [
            "pub fn build_axfr_query",
            "parse_axfr_response",
            "insert_snapshot_arc_for_transfer",
            "ZoneRefreshRegistry",
            "NotifyAuthority",
            "maybe_sign_transfer_query",
        ],
    },
    "rr unknown dnssec": {
        "paths": [
            "crates/borondns-core/src/axfr.rs",
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-core/src/zone.rs",
            "docs/rr-type-catalogue.md",
        ],
        "evidence_paths": [
            "scripts/interop-unknown-rr.sh",
            "scripts/interop-dnssec-serve.sh",
            "scripts/interop-dnssec-nsec3-serve.sh",
            "scripts/interop-bind-packet-torture-docker.sh",
        ],
        "source_needles": [
            "Unknown transfer RDATA",
            "nsec3_iterations_exceeded",
            "RecordType::Rrsig",
            "RecordType::Nsec3",
        ],
    },
    "health metrics structured logs": {
        "paths": [
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/health_metrics.rs",
            "crates/borondns-cli/src/main.rs",
            "docs/health-metrics-interface.md",
        ],
        "evidence_paths": [
            "scripts/capture-health-metrics-evidence.sh",
            "scripts/check-interface-compatibility.py",
            "scripts/audit-log-fields.py",
            "scripts/audit-log-lazy-formatting.py",
        ],
        "source_needles": [
            "async fn livez",
            "async fn readyz",
            "async fn metrics",
            "borondns_secondary_build_info",
            "logfmt",
        ],
    },
}

# The code/test registries below validate these owners independently of prose.
REVIEW_DEFER_CODE_BACKING = {
    "Catalog zones": ["crates/borondns-core/src/catalog.rs"],
    "XoT": ["crates/borondns-server/src/transfer.rs"],
    "DNS Cookies": ["scripts/interop-dns-cookie-dig.sh"],
    "RRL beyond a simple first version": ["scripts/interop-rrl-udp.sh"],
    "Extended DNS Errors": ["crates/borondns-core/src/dns.rs"],
    "CHAOS `version.bind` / `id.server`": ["scripts/interop-chaos-queries.sh"],
    "Full DNSSEC negative proof synthesis": ["scripts/audit-dnssec-passive.sh"],
    "Full Prometheus metric catalogue": ["docs/health-metrics-interface.md"],
    "Packed zone store / pre-baked response cache": ["docs/future-optimization-tracks.md"],
    "Exact performance MUSTs": ["scripts/capture-benchmark-handoff.sh"],
    "Release signing": [".github/workflows/release-installer.yml"],
    "Full three-primary interop matrix": ["docs/manual-bind-interop.md"],
}

PROCESS_ONLY_REVIEW_DEFER_ITEMS = [
    "Fixed 30-day soak test",
    "CVE governance",
    "External operator acceptance",
]

FEATURES = {
    "IXFR": {
        "aliases": ["IXFR"],
        "paths": [
            "crates/borondns-core/src/axfr.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/transfer.rs",
        ],
        "test_paths": [
            "crates/borondns-core/src/axfr.rs",
            "crates/borondns-server/src/tests/transfer_protocol.rs",
        ],
        "evidence_paths": [
            "scripts/interop-bind-ixfr-refresh.sh",
            "scripts/interop-knot-ixfr-refresh-docker.sh",
            "scripts/interop-ixfr-notimp-fallback.sh",
        ],
        "srs_needles": ["BDS-FR-IXFR-001", "BDS-FR-AXFR-001"],
        "source_needles": [
            "pub enum IxfrResponse",
            "build_ixfr_query",
            "IXFR failed; falling back to AXFR",
        ],
        "test_needles": [
            "parses_ixfr_mode1_incremental_diff_into_active_zone",
            "transfer_ixfr_from_primary_applies_mode1_incremental_diff",
        ],
    },
    "XoT": {
        "aliases": ["XoT"],
        "paths": [
            "Cargo.toml",
            "crates/borondns-core/src/config.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/transfer.rs",
        ],
        "test_paths": [
            "crates/borondns-server/src/tests/refresh_xot_runtime.rs",
        ],
        "evidence_paths": [
            "scripts/interop-knot-xot-docker.sh",
            "scripts/interop-knot-xot-tsig-docker.sh",
            "scripts/interop-bind-xot-catalog-zone-docker.sh",
            "scripts/audit-xot-revocation.sh",
        ],
        "srs_needles": ["BDS-FR-XOT-001", "BDS-FR-XOT-012"],
        "source_needles": [
            "connect_xot_stream",
            "alpn_protocols = vec![b\"dot\".to_vec()]",
            "ClientConfig::builder_with_protocol_versions(&[&version::TLS13])",
        ],
        "test_needles": [
            "refresh_xot_handshake_failure_does_not_retry_cleartext",
            "refresh_xot_uses_configured_client_certificate",
        ],
    },
    "passive DNSSEC": {
        "aliases": ["Passive DNSSEC", "passive DNSSEC"],
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-core/src/zone.rs",
        ],
        "test_paths": [
            "crates/borondns-core/src/dns_tests/any_negative_dnssec.rs",
            "crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs",
        ],
        "evidence_paths": [
            "scripts/interop-dnssec-serve.sh",
            "scripts/interop-dnssec-nsec3-serve.sh",
            "scripts/interop-knot-dnssec-docker.sh",
            "scripts/audit-dnssec-passive.sh",
            "docs/dnssec-conformance-matrix.tsv",
        ],
        "srs_needles": ["BDS-FR-DNSSEC-001", "BDS-FR-DNSSEC-014"],
        "source_needles": [
            "nsec3_iterations_exceeded",
            "nsec3_max_iterations",
            "u32::from(edns.do_bit) << 15",
        ],
        "test_needles": [
            "do_nxdomain_includes_nsec3_denial_proofs_and_covering_rrsigs",
            "nsec3_iterations_over_cap_fails_closed_and_emits_ede_when_enabled",
        ],
    },
    "RRL": {
        "aliases": ["RRL"],
        "paths": [
            "crates/borondns-core/src/config.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/health_metrics.rs",
            "crates/borondns-server/src/rate_limit.rs",
            "crates/borondns-server/src/udp.rs",
        ],
        "test_paths": [
            "crates/borondns-server/src/tests/metrics_rrl_udp.rs",
        ],
        "evidence_paths": [
            "scripts/interop-rrl-udp.sh",
            "scripts/rrl-evidence-campaign.sh",
            "docs/rrl-release-thresholds.md",
        ],
        "srs_needles": ["BDS-FR-RRL-001", "BDS-FR-RRL-012"],
        "source_needles": [
            "struct RrlLimiter",
            "rrl_truncated_response",
            "borondns_rrl_responses_dropped_total",
            "cookie_validated",
        ],
        "test_needles": [
            "rrl_response_categories_follow_srs_buckets",
            "udp_rrl_slips_and_drops_limited_query_responses",
            "udp_valid_dns_cookie_bypasses_rrl_accounting",
        ],
    },
    "DNS Cookies": {
        "aliases": ["DNS Cookies"],
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/udp.rs",
        ],
        "test_paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs",
            "crates/borondns-server/src/tests/metrics_rrl_udp.rs",
        ],
        "evidence_paths": [
            "scripts/interop-dns-cookie-dig.sh",
        ],
        "srs_needles": ["BDS-FR-COOKIE-001", "BDS-FR-COOKIE-011"],
        "source_needles": [
            "EDNS_COOKIE_OPTION",
            "compute_dns_server_cookie",
            "request_has_valid_dns_server_cookie",
        ],
        "test_needles": [
            "edns_cookie_server_cookie_validates_for_same_client_ip",
            "udp_valid_dns_cookie_bypasses_rrl_accounting",
        ],
    },
    "catalog zones": {
        "aliases": ["catalog zones", "catalog-zone"],
        "paths": [
            "crates/borondns-core/src/catalog.rs",
            "crates/borondns-core/src/config.rs",
            "crates/borondns-core/src/zone.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/health_metrics.rs",
        ],
        "test_paths": [
            "crates/borondns-server/src/tests/catalog_and_plan.rs",
        ],
        "evidence_paths": [
            "docs/catalog-zone-rfc9432.md",
            "scripts/interop-bind-catalog-zone-docker.sh",
            "scripts/interop-powerdns-postgres-catalog-tsig-docker.sh",
            "scripts/interop-bind-xot-catalog-zone-docker.sh",
        ],
        "srs_needles": [
            "BDS-FR-PROV-001",
            "BDS-IF-CONF-013",
            "BDS-NFR-OBS-008",
        ],
        "source_needles": [
            "parse_catalog_members",
            "max_member_zones",
            "insert_loading_batch",
            "is_catalog",
            "catalog_member_limit_exceeded",
            "catalog_member_added",
            "borondns_catalog_member_info",
        ],
        "test_needles": [
            "catalog_snapshot_adds_member_transfer_plan_and_hides_catalog",
            "catalog_snapshot_enforces_member_zone_cap",
        ],
    },
    "EDNS response behavior": {
        "aliases": ["EDNS"],
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-core/src/config.rs",
            "crates/borondns-server/src/lib.rs",
        ],
        "test_paths": [
            "crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs",
        ],
        "evidence_paths": [
            "scripts/interop-edns-behavior.sh",
        ],
        "srs_needles": ["BDS-FR-EDNS-001", "BDS-FR-EDNS-017"],
        "source_needles": [
            "parse_edns_options",
            "EDNS_NSID_OPTION",
            "EDNS_TCP_KEEPALIVE_OPTION",
            "append_edns_padding",
            "metadata.udp_ceiling(options)",
            "u32::from(edns.do_bit) << 15",
        ],
        "test_needles": [
            "edns_nsid_request_returns_configured_identifier",
            "tcp_edns_keepalive_request_gets_timeout_response",
            "udp_edns_keepalive_request_is_ignored",
            "configured_encrypted_edns_padding_aligns_response_to_block_size",
            "configured_udp_edns_padding_is_omitted_when_it_would_exceed_ceiling",
            "malformed_edns_options_get_formerr",
            "unsupported_edns_version_gets_badvers_opt_response",
            "non_edns_udp_response_over_512_octets_is_truncated_without_opt",
            "response_opt_copies_query_do_bit_without_dnssec_augmentation",
        ],
    },
    "EDE": {
        "aliases": ["EDE", "Extended DNS Errors"],
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-server/src/lib.rs",
        ],
        "test_paths": [
            "crates/borondns-core/src/dns_tests/any_negative_dnssec.rs",
            "crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs",
        ],
        "evidence_paths": [
            "scripts/interop-dnssec-serve.sh",
            "scripts/interop-dnssec-nsec3-serve.sh",
            "docs/dnssec-conformance-matrix.tsv",
        ],
        "srs_needles": ["BDS-FR-EDNS-018", "BDS-IF-CONF-017"],
        "source_needles": [
            "EDNS_EXTENDED_DNS_ERROR_OPTION",
            "EDE_NOT_READY",
            "UnsupportedNsec3Iterations",
        ],
        "test_needles": [
            "ede_not_ready_is_opt_in_for_loading_zones",
            "nsec3_iterations_over_cap_fails_closed_and_emits_ede_when_enabled",
        ],
    },
    "CHAOS": {
        "aliases": ["CHAOS"],
        "paths": [
            "crates/borondns-core/src/dns.rs",
            "crates/borondns-core/src/config.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/health_metrics.rs",
        ],
        "test_paths": [
            "crates/borondns-core/src/dns_tests/message_parse_notify.rs",
        ],
        "evidence_paths": [
            "scripts/interop-chaos-queries.sh",
        ],
        "srs_needles": ["BDS-FR-CHAS-001", "BDS-FR-CHAS-006", "BDS-IF-CONF-018"],
        "source_needles": [
            "answer_chaos_query",
            "is_chaos_version_name",
            "is_chaos_hostname_name",
            "b\"version\".as_slice(), b\"bind\".as_slice()",
            "b\"version\".as_slice(), b\"server\".as_slice()",
            "b\"hostname\".as_slice(), b\"bind\".as_slice()",
            "b\"id\".as_slice(), b\"server\".as_slice()",
            "borondns_chaos_queries_total",
        ],
        "test_needles": [
            "chaos_version_txt_defaults_to_refused",
            "chaos_hostname_txt_uses_config_then_printable_nsid_fallback",
            "chaos_unsupported_names_and_non_txt_types_are_refused",
            "chaos_query_observation_classifies_supported_cases",
        ],
    },
}

SUPPORT_TOOLING = {
    "release packaging": {
        "paths": [
            "scripts/package-installer.sh",
            "scripts/package-docker-image.sh",
            ".github/workflows/release-installer.yml",
        ],
        "evidence_paths": [
            "scripts/test-installer-docker.sh",
            "scripts/test-docker-image.sh",
            "docs/devops-getting-started.md",
            "docs/release-evidence-guide.md",
        ],
        "source_needles": [
            "x86_64-unknown-linux-musl",
            "tar.xz",
            "sha256",
            "static_link_confirmed",
            "BORONDNS_PACKAGE_ALLOW_DYNAMIC",
            "BORONDNS_DOCKER_ALPINE_BASE_IMAGE",
            "base_image_digest",
            "alpine:3.22@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6",
        ],
        "evidence_needles": [
            "package_load_verified_docker_archive",
            "verify-docker-archive.py",
        ],
    },
    "boron-gun": {
        "paths": [
            "crates/boron-gun/src/main.rs",
            "crates/boron-gun/src/xdp_backend.rs",
            "docs/unsafe-boundaries.tsv",
        ],
        "evidence_paths": [
            "docs/boron-gun.md",
            "scripts/boron-gun-self-test.sh",
            "scripts/boron-gun-xdp-veth-smoke.sh",
            "crates/boron-gun/tests/cli.rs",
        ],
        "source_needles": [
            "backend xdp requires",
            "AF_XDP",
            "borongun-xdp-af-xdp",
        ],
        "evidence_needles": [
            "pkexec",
            "boron-gun self-test",
            "veth",
        ],
    },
    "benchmark tooling": {
        "paths": [
            "scripts/benchmark-dns-clients.sh",
            "scripts/benchmark-large-catalog-zones.sh",
            "crates/borondns-core/src/config.rs",
            "crates/borondns-server/src/lib.rs",
            "crates/borondns-server/src/health_metrics.rs",
        ],
        "evidence_paths": [
            "docs/dns-client-benchmark.md",
            "docs/future-optimization-tracks.md",
            "scripts/capture-benchmark-handoff.sh",
            "scripts/check-perf-regression.py",
        ],
        "source_needles": [
            "BORONDNS_BENCH_PIPELINE_TIMING_ENABLED",
            "BORONDNS_LARGE_BENCH_PIPELINE_TIMING_ENABLED",
            "pipeline_timing_enabled",
            "response_cache_candidate",
        ],
        "evidence_needles": [
            "Reference Hardware/Profile",
            "check-perf-regression.py",
        ],
    },
    "supplemental interop": {
        "paths": [
            "scripts/interop-bind-packet-torture-docker.sh",
            "scripts/interop-powerdns-postgres-catalog-tsig-docker.sh",
            "docs/manual-bind-interop.md",
        ],
        "evidence_paths": [
            "docs/manual-bind-interop.md",
        ],
        "source_needles": [
            "dumpcap",
            "dns-torture.pcapng",
            "PowerDNS Authoritative",
            "gpgsql",
        ],
        "evidence_needles": [
            "interop-powerdns-postgres-catalog-tsig-docker.sh",
            "target/evidence",
        ],
    },
}


def main() -> int:
    errors: list[str] = []
    disposition = DISPOSITION_PATH.read_text(encoding="utf-8")
    feature_scope = FEATURE_SCOPE_PATH.read_text(encoding="utf-8")
    srs_current = SRS_CURRENT_PATH.read_text(encoding="utf-8")
    # Review labels are stable identifiers; explanations may be edited freely.
    rows: dict[str, list[str]] = {}
    required_labels = set(REQUIRED_REVIEW_DISPOSITIONS + REVIEW_SUGGESTED_DEFER_ITEMS)
    review_table = False
    for line in disposition.splitlines():
        if not line.startswith("|"):
            review_table = False
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if columns[0] in {"Review finding", "Review-suggested defer item"}:
            review_table = True
            continue
        if not review_table:
            continue
        if columns[0] not in required_labels:
            continue
        label = columns[0]
        if label in rows:
            errors.append(f"duplicate review disposition: {label!r}")
        rows[label] = columns
        if len(columns) != 3 or not all(columns):
            errors.append(f"review disposition needs explanation and evidence: {label!r}")
    for label in sorted(required_labels - rows.keys()):
        errors.append(f"{DISPOSITION_PATH.relative_to(ROOT)} omits review item {label!r}")

    for item, backing_paths in REVIEW_DEFER_CODE_BACKING.items():
        for relative_path in backing_paths:
            if not references_file(FEATURE_SCOPE_PATH, feature_scope, ROOT / relative_path):
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not tie "
                    f"review item {item!r} to {relative_path}"
                )
    covered_review_items = set(REVIEW_DEFER_CODE_BACKING) | set(PROCESS_ONLY_REVIEW_DEFER_ITEMS)
    if covered_review_items != set(REVIEW_SUGGESTED_DEFER_ITEMS):
        errors.append("review items must have a code-backed or process-only classification")

    for scope_path in SCOPE_POINTER_DOCUMENTS:
        scope_text = scope_path.read_text(encoding="utf-8")
        if not references_file(scope_path, scope_text, FEATURE_SCOPE_PATH):
            errors.append(
                f"{scope_path.relative_to(ROOT)} does not link to implemented feature scope"
            )

    for baseline, spec in REVIEW_BASELINE_SCOPE.items():
        paths = spec["paths"]
        evidence_paths = spec["evidence_paths"]
        source = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in paths
            if (ROOT / relative_path).exists()
        )
        for relative_path in paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} for review baseline {baseline}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(
                    f"missing review baseline path for {baseline}: {relative_path}"
                )
        for relative_path in evidence_paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} evidence for review baseline {baseline}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(
                    f"missing review baseline evidence path for {baseline}: "
                    f"{relative_path}"
                )
        for needle in spec["source_needles"]:
            if needle not in source:
                errors.append(
                    f"source cited for review baseline {baseline} lacks "
                    f"implementation evidence needle {needle!r}"
                )

    for feature, spec in FEATURES.items():
        aliases = spec["aliases"]
        paths = spec["paths"]
        test_paths = spec.get("test_paths", paths)
        evidence_paths = spec["evidence_paths"]
        test_needles = spec["test_needles"]
        source = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in paths
            if (ROOT / relative_path).exists()
        )
        test_source = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in test_paths
            if (ROOT / relative_path).exists()
        )
        if not any(alias in disposition for alias in aliases):
            errors.append(f"{DISPOSITION_PATH.relative_to(ROOT)} omits {feature!r}")
        if not any(alias in feature_scope for alias in aliases):
            errors.append(f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} omits {feature!r}")
        for relative_path in paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} for {feature}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(f"missing code path for {feature}: {relative_path}")
        for relative_path in evidence_paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} evidence for {feature}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(f"missing evidence path for {feature}: {relative_path}")
        for relative_path in test_paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} representative tests for {feature}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(f"missing representative test path for {feature}: {relative_path}")
        for needle in spec["srs_needles"]:
            if needle not in srs_current:
                errors.append(
                    f"{SRS_CURRENT_PATH.relative_to(ROOT)} lacks SRS owner "
                    f"needle {needle!r} for retained feature {feature}"
                )
        for needle in spec["source_needles"]:
            if needle not in source:
                errors.append(
                    f"source cited for {feature} lacks implementation evidence "
                    f"needle {needle!r}"
                )
        for needle in test_needles:
            if needle not in test_source:
                errors.append(
                    f"source cited for {feature} lacks representative test "
                    f"marker {needle!r}"
                )

    for tooling, spec in SUPPORT_TOOLING.items():
        paths = spec["paths"]
        evidence_paths = spec["evidence_paths"]
        source = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in paths
            if (ROOT / relative_path).exists()
        )
        evidence = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in evidence_paths
            if (ROOT / relative_path).exists()
        )
        for relative_path in paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} for support tooling {tooling}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(
                    f"missing support tooling path for {tooling}: {relative_path}"
                )
        for relative_path in evidence_paths:
            if relative_path not in feature_scope:
                errors.append(
                    f"{FEATURE_SCOPE_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} evidence for support tooling {tooling}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(
                    f"missing support tooling evidence path for {tooling}: "
                    f"{relative_path}"
                )
        for needle in spec["source_needles"]:
            if needle not in source:
                errors.append(
                    f"support tooling {tooling} lacks source marker "
                    f"{needle!r}"
                )
        for needle in spec["evidence_needles"]:
            if needle not in evidence:
                errors.append(
                    f"support tooling {tooling} lacks evidence marker "
                    f"{needle!r}"
                )

    if errors:
        for error in errors:
            print(f"srs_review_disposition_check=failed {error}", file=sys.stderr)
        return 1

    print(
        "srs_review_disposition_check=passed "
        f"review_baseline={len(REVIEW_BASELINE_SCOPE)} "
        f"features={len(FEATURES)} support_tooling={len(SUPPORT_TOOLING)} "
        f"review_defer_items={len(REVIEW_SUGGESTED_DEFER_ITEMS)} "
        f"code_backed_review_defer_items={len(REVIEW_DEFER_CODE_BACKING)} "
        f"process_only_review_defer_items={len(PROCESS_ONLY_REVIEW_DEFER_ITEMS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
