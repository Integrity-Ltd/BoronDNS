#!/usr/bin/env python3
"""Static evidence audit for SRS BDS-FR-SPOOF-001..007."""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


CHECKS = [
    (
        "BDS-FR-SPOOF-001",
        [
            REPO_ROOT / "crates/borondns-server/src/transfer.rs",
            REPO_ROOT / "crates/borondns-server/src/tests/transfer_protocol.rs",
        ],
        [
            "fn transfer_query_id() -> Result<u16, TransferError>",
            "getrandom::fill(&mut bytes)",
            "fn transfer_query_id_uses_full_sixteen_bit_range()",
            "fn transfer_query_id_reads_os_randomness()",
        ],
    ),
    (
        "BDS-FR-SPOOF-002",
        [
            REPO_ROOT / "crates/borondns-server/src/transfer.rs",
            REPO_ROOT / "crates/borondns-server/src/tests/transfer_protocol.rs",
        ],
        [
            "UdpSocket::bind(outbound_udp_bind_addr(primary, transfer_source))",
            '"0.0.0.0:0"',
            '"[::]:0"',
            "async fn soa_poll_binds_configured_transfer_source()",
            "async fn axfr_binds_configured_transfer_source()",
            "async fn concurrent_soa_polls_use_distinct_ephemeral_source_ports()",
        ],
    ),
    (
        "BDS-FR-SPOOF-003..004",
        [
            REPO_ROOT / "crates/borondns-server/src/transfer.rs",
            REPO_ROOT / "crates/borondns-server/src/tests/transfer_protocol.rs",
            REPO_ROOT / "crates/borondns-server/src/tests/support.rs",
        ],
        [
            ".connect(primary)",
            "async fn poll_soa_from_primary_ignores_udp_packet_from_unconnected_peer()",
            "spawn_soa_primary_with_spoofed_malformed_packet",
        ],
    ),
    (
        "BDS-FR-SPOOF-005",
        [REPO_ROOT / "crates/borondns-core/src/axfr.rs"],
        [
            "if header.id != qid",
            "fn rejects_ixfr_response_with_mismatched_qid()",
            "fn rejects_soa_response_with_mismatched_qid()",
            "fn rejects_mismatched_qid()",
        ],
    ),
    (
        "BDS-FR-SPOOF-006",
        [REPO_ROOT / "crates/borondns-core/src/axfr.rs"],
        [
            "fn validate_response_question(",
            "qname.canonical_key() != zone_apex.canonical_key()",
            "fn rejects_ixfr_response_with_mismatched_question()",
            "fn rejects_axfr_response_with_mismatched_question()",
            "fn accepts_soa_response_question_qname_case_insensitively()",
        ],
    ),
    (
        "BDS-FR-SPOOF-007",
        [
            REPO_ROOT / "crates/borondns-server/src/transfer.rs",
            REPO_ROOT / "crates/borondns-server/src/tests/transfer_protocol.rs",
        ],
        [
            "async fn poll_soa_from_primary_records_warning_evidence_for_malformed_response()",
            '"SOA poll response rejected"',
            '"qid=4660"',
            '"SOA response message is malformed"',
        ],
    ),
]


def main() -> int:
    print("spoof_evidence_audit=started")
    failures: list[str] = []

    for requirement, paths, fragments in CHECKS:
        source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        missing = [fragment for fragment in fragments if fragment not in source]
        rel_paths = ";".join(str(path.relative_to(REPO_ROOT)) for path in paths)
        if missing:
            for fragment in missing:
                failures.append(f"{requirement}: missing {fragment!r} in {rel_paths}")
            continue
        print(f"{requirement}=present paths={rel_paths}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print("spoof_evidence_audit=failed")
        return 1

    print(f"spoof_evidence_checks={len(CHECKS)}")
    print("spoof_evidence_audit=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
