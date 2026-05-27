#!/usr/bin/env python3
"""Keep SRS review scope-trim disposition aligned with current code paths."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DISPOSITION_PATH = ROOT / "docs" / "srs-review-disposition.md"
MVP_SCOPE_PATH = ROOT / "docs" / "engineering-mvp-scope.md"
IMPLEMENTATION_PLAN_PATH = ROOT / "docs" / "implementation-plan.md"

FEATURES = {
    "IXFR": {
        "aliases": ["IXFR"],
        "paths": [
            "crates/oxidedns-core/src/axfr.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "pub enum IxfrResponse",
            "build_ixfr_query",
            "IXFR failed; falling back to AXFR",
        ],
    },
    "XoT": {
        "aliases": ["XoT"],
        "paths": [
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "connect_xot_stream",
            "alpn_protocols = vec![b\"dot\".to_vec()]",
            "refresh_xot_uses_configured_client_certificate",
        ],
    },
    "passive DNSSEC": {
        "aliases": ["Passive DNSSEC", "passive DNSSEC"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-core/src/zone.rs",
        ],
        "source_needles": [
            "augment_lookup_result_with_dnssec",
            "nsec3_max_iterations",
            "response_opt_copies_query_do_bit_without_dnssec_augmentation",
        ],
    },
    "RRL": {
        "aliases": ["RRL"],
        "paths": [
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "struct RrlLimiter",
            "rrl_truncated_response",
            "oxidedns_rrl_responses_dropped_total",
        ],
    },
    "DNS Cookies": {
        "aliases": ["DNS Cookies"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "EDNS_COOKIE_OPTION",
            "compute_dns_server_cookie",
            "request_has_valid_dns_server_cookie",
        ],
    },
    "catalog zones": {
        "aliases": ["catalog zones", "catalog-zone"],
        "paths": [
            "crates/oxidedns-core/src/catalog.rs",
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "parse_catalog_members",
            "catalog_member_added",
            "oxidedns_catalog_member_info",
        ],
    },
    "EDE": {
        "aliases": ["EDE", "Extended DNS Errors"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "EDNS_EXTENDED_DNS_ERROR_OPTION",
            "EDE_NOT_READY",
            "UnsupportedNsec3Iterations",
        ],
    },
    "CHAOS": {
        "aliases": ["CHAOS"],
        "paths": [
            "crates/oxidedns-core/src/dns.rs",
            "crates/oxidedns-core/src/config.rs",
            "crates/oxidedns-server/src/lib.rs",
        ],
        "source_needles": [
            "answer_chaos_query",
            "version.bind.",
            "oxidedns_chaos_queries_total",
        ],
    },
}


def main() -> int:
    errors: list[str] = []
    disposition = DISPOSITION_PATH.read_text(encoding="utf-8")
    mvp_scope = MVP_SCOPE_PATH.read_text(encoding="utf-8")
    implementation_plan = IMPLEMENTATION_PLAN_PATH.read_text(encoding="utf-8")

    for feature, spec in FEATURES.items():
        aliases = spec["aliases"]
        paths = spec["paths"]
        source = "\n".join(
            (ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in paths
            if (ROOT / relative_path).exists()
        )
        if not any(alias in disposition for alias in aliases):
            errors.append(f"{DISPOSITION_PATH.relative_to(ROOT)} omits {feature!r}")
        if not any(alias in mvp_scope for alias in aliases):
            errors.append(f"{MVP_SCOPE_PATH.relative_to(ROOT)} omits {feature!r}")
        if not any(alias in implementation_plan for alias in aliases):
            errors.append(
                f"{IMPLEMENTATION_PLAN_PATH.relative_to(ROOT)} omits {feature!r}"
            )
        for relative_path in paths:
            if relative_path not in disposition:
                errors.append(
                    f"{DISPOSITION_PATH.relative_to(ROOT)} does not cite "
                    f"{relative_path} for {feature}"
                )
            if not (ROOT / relative_path).exists():
                errors.append(f"missing code path for {feature}: {relative_path}")
        for needle in spec["source_needles"]:
            if needle not in source:
                errors.append(
                    f"source cited for {feature} lacks implementation evidence "
                    f"needle {needle!r}"
                )

    if errors:
        for error in errors:
            print(f"srs_review_disposition_check=failed {error}", file=sys.stderr)
        return 1

    print(f"srs_review_disposition_check=passed features={len(FEATURES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
