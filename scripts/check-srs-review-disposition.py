#!/usr/bin/env python3
"""Keep SRS review scope-trim disposition aligned with current code paths."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DISPOSITION_PATH = ROOT / "docs" / "srs-review-disposition.md"
SRS_CURRENT_PATH = ROOT / "docs" / "OxideDNS-Secondary-SRS-v0.9.1.md"
MVP_SCOPE_PATH = ROOT / "docs" / "engineering-mvp-scope.md"
IMPLEMENTATION_PLAN_PATH = ROOT / "docs" / "implementation-plan.md"
README_PATH = ROOT / "README.md"
DOCS_README_PATH = ROOT / "docs" / "README.md"
GAP_REGISTER_PATH = ROOT / "docs" / "mvp-gap-register.md"
VERIFICATION_LEDGER_PATH = ROOT / "docs" / "verification-ledger.md"

SCOPE_DOCUMENTS = [
    SRS_CURRENT_PATH,
    DISPOSITION_PATH,
    MVP_SCOPE_PATH,
    IMPLEMENTATION_PLAN_PATH,
    README_PATH,
    DOCS_README_PATH,
    GAP_REGISTER_PATH,
    VERIFICATION_LEDGER_PATH,
]


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())

REQUIRED_REVIEW_DISPOSITIONS = [
    "ODS/RDS namespace mismatch",
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
    "Requirements claimed absolute atomicity while grouping many operational cases",
]

REQUIRED_SCOPE_TRIM_BOUNDARY_TERMS = [
    "MVP Trim Reconciliation",
    "not as a deletion list for already-implemented code",
    "mirrors the review's \"defer these\" list item by item",
    "Current Implementation Slice",
    "code-alignment lock for the review's MVP-trim advice",
    "Opt-in pipeline timing and response-cache candidate metrics are measurement aids, not a response-cache backend.",
    "It does not sign, validate, generate DNSSEC records, or synthesize new denial-proof material.",
    "Setup/runbooks may remain in Git, but completed evidence belongs to later SRS acceptance execution.",
    "implementation-specific source and test markers",
]

REQUIRED_CODE_ALIGNMENT_BOUNDARIES = [
    "fall back to AXFR when IXFR is unavailable or unsuitable",
    "Client-query DoT, DoH, DoQ, inbound XoT listeners",
    "copies the query DO bit into the response OPT",
    "Per-zone RRL, distributed/shared RRL state across processes",
    "Durable client authentication, TSIG replacement",
    "automatic discovery without catalog configuration",
    "EDNS Refresh, DNS Stateful Operations",
    "Minimal EDE output is available for `Not Ready` and `Unsupported NSEC3 Iterations` only",
    "Automatic host disclosure, arbitrary CHAOS namespaces",
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
    "30-day soak test",
    "Full three-primary interop matrix",
    "Exact performance MUSTs",
    "Release signing",
    "CVE governance",
    "External operator acceptance",
]

FEATURES = {
    "IXFR": {
        "aliases": ["IXFR"],
        "paths": [
            "crates/oxidedns-core/src/axfr.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-bind-ixfr-refresh.sh",
            "scripts/interop-knot-ixfr-refresh-docker.sh",
            "scripts/interop-ixfr-notimp-fallback.sh",
        ],
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
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-knot-xot-docker.sh",
            "scripts/interop-knot-xot-tsig-docker.sh",
            "scripts/interop-bind-xot-catalog-zone-docker.sh",
            "scripts/audit-xot-revocation.sh",
        ],
        "source_needles": [
            "connect_xot_stream",
            "alpn_protocols = vec![b\"dot\".to_vec()]",
            "refresh_xot_uses_configured_client_certificate",
        ],
        "test_needles": [
            "refresh_xot_handshake_failure_does_not_retry_cleartext",
            "refresh_xot_uses_configured_client_certificate",
        ],
    },
    "passive DNSSEC": {
        "aliases": ["Passive DNSSEC", "passive DNSSEC"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-core/src/zone.rs",
        ],
        "evidence_paths": [
            "scripts/interop-dnssec-serve.sh",
            "scripts/interop-dnssec-nsec3-serve.sh",
            "scripts/interop-knot-dnssec-docker.sh",
            "scripts/audit-dnssec-passive.sh",
            "docs/dnssec-conformance-matrix.tsv",
        ],
        "source_needles": [
            "augment_lookup_result_with_dnssec",
            "nsec3_max_iterations",
            "response_opt_copies_query_do_bit_without_dnssec_augmentation",
        ],
        "test_needles": [
            "do_nxdomain_includes_nsec3_denial_proofs_and_covering_rrsigs",
            "nsec3_iterations_over_cap_omits_proofs_and_emits_ede_when_enabled",
        ],
    },
    "RRL": {
        "aliases": ["RRL"],
        "paths": [
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-rrl-udp.sh",
            "scripts/rrl-evidence-campaign.sh",
            "docs/rrl-release-thresholds.md",
        ],
        "source_needles": [
            "struct RrlLimiter",
            "rrl_truncated_response",
            "oxidedns_rrl_responses_dropped_total",
        ],
        "test_needles": [
            "rrl_response_categories_follow_srs_buckets",
            "udp_rrl_slips_and_drops_limited_query_responses",
        ],
    },
    "DNS Cookies": {
        "aliases": ["DNS Cookies"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-dns-cookie-dig.sh",
        ],
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
            "crates/oxidedns-core/src/catalog.rs",
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "docs/catalog-zone-mvp-rfc9432.md",
            "scripts/interop-bind-catalog-zone-docker.sh",
            "scripts/interop-powerdns-postgres-catalog-tsig-docker.sh",
            "scripts/interop-bind-xot-catalog-zone-docker.sh",
        ],
        "source_needles": [
            "parse_catalog_members",
            "max_member_zones",
            "catalog_member_limit_exceeded",
            "catalog_member_added",
            "oxidedns_catalog_member_info",
        ],
        "test_needles": [
            "catalog_snapshot_adds_member_transfer_plan_and_hides_catalog",
            "catalog_snapshot_enforces_member_zone_cap",
        ],
    },
    "EDNS response behavior": {
        "aliases": ["EDNS"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-edns-behavior.sh",
        ],
        "source_needles": [
            "parse_edns_options",
            "EDNS_TCP_KEEPALIVE_OPTION",
            "append_edns_padding_if_it_fits",
            "response_opt_copies_query_do_bit_without_dnssec_augmentation",
        ],
        "test_needles": [
            "tcp_edns_keepalive_request_gets_timeout_response",
            "unsupported_edns_version_gets_badvers_opt_response",
            "response_opt_copies_query_do_bit_without_dnssec_augmentation",
        ],
    },
    "EDE": {
        "aliases": ["EDE", "Extended DNS Errors"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-dnssec-serve.sh",
            "scripts/interop-dnssec-nsec3-serve.sh",
            "docs/dnssec-conformance-matrix.tsv",
        ],
        "source_needles": [
            "EDNS_EXTENDED_DNS_ERROR_OPTION",
            "EDE_NOT_READY",
            "UnsupportedNsec3Iterations",
        ],
        "test_needles": [
            "ede_not_ready_is_opt_in_for_loading_zones",
            "nsec3_iterations_over_cap_omits_proofs_and_emits_ede_when_enabled",
        ],
    },
    "CHAOS": {
        "aliases": ["CHAOS"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "evidence_paths": [
            "scripts/interop-chaos-queries.sh",
        ],
        "source_needles": [
            "answer_chaos_query",
            "version.bind.",
            "oxidedns_chaos_queries_total",
        ],
        "test_needles": [
            "chaos_version_txt_defaults_to_refused",
            "chaos_query_observation_classifies_supported_cases",
        ],
    },
}


def main() -> int:
    errors: list[str] = []
    disposition = DISPOSITION_PATH.read_text(encoding="utf-8")
    scope_document_texts = {
        path: normalize_whitespace(path.read_text(encoding="utf-8"))
        for path in SCOPE_DOCUMENTS
    }

    for finding in REQUIRED_REVIEW_DISPOSITIONS:
        if finding not in disposition:
            errors.append(
                f"{DISPOSITION_PATH.relative_to(ROOT)} omits review finding "
                f"{finding!r}"
            )
    for term in REQUIRED_SCOPE_TRIM_BOUNDARY_TERMS:
        if term not in disposition:
            errors.append(
                f"{DISPOSITION_PATH.relative_to(ROOT)} omits scope-trim "
                f"boundary term {term!r}"
            )
    for term in REQUIRED_CODE_ALIGNMENT_BOUNDARIES:
        if term not in disposition:
            errors.append(
                f"{DISPOSITION_PATH.relative_to(ROOT)} omits code-alignment "
                f"boundary term {term!r}"
            )
    for item in REVIEW_SUGGESTED_DEFER_ITEMS:
        if item not in disposition:
            errors.append(
                f"{DISPOSITION_PATH.relative_to(ROOT)} omits review-suggested "
                f"defer item {item!r}"
            )

    for feature, spec in FEATURES.items():
        aliases = spec["aliases"]
        paths = spec["paths"]
        evidence_paths = spec["evidence_paths"]
        test_needles = spec["test_needles"]
        source = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in paths
            if (ROOT / relative_path).exists()
        )
        if not any(alias in disposition for alias in aliases):
            errors.append(f"{DISPOSITION_PATH.relative_to(ROOT)} omits {feature!r}")
        for scope_path, scope_text in scope_document_texts.items():
            if not any(alias in scope_text for alias in aliases):
                errors.append(
                    f"{scope_path.relative_to(ROOT)} omits implemented "
                    f"post-Alpha feature {feature!r}"
                )
        for relative_path in paths:
            if relative_path not in disposition:
                errors.append(
                    f"{DISPOSITION_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} for {feature}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(f"missing code path for {feature}: {relative_path}")
        for relative_path in evidence_paths:
            if relative_path not in disposition:
                errors.append(
                    f"{DISPOSITION_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} evidence for {feature}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(f"missing evidence path for {feature}: {relative_path}")
        for needle in spec["source_needles"]:
            if needle not in source:
                errors.append(
                    f"source cited for {feature} lacks implementation evidence "
                    f"needle {needle!r}"
                )
        for needle in test_needles:
            if needle not in source:
                errors.append(
                    f"source cited for {feature} lacks representative test "
                    f"marker {needle!r}"
                )

    if errors:
        for error in errors:
            print(f"srs_review_disposition_check=failed {error}", file=sys.stderr)
        return 1

    print(f"srs_review_disposition_check=passed features={len(FEATURES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
