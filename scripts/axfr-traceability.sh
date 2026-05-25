#!/usr/bin/env bash

write_axfr_traceability_tsv() {
    local output="$1"
    local primary_name="$2"
    local primary_log_artifact="$3"
    local primary_version_artifact="${4:-primary-version.txt}"

    cat >"$output" <<EOF
requirement_id	evidence_state	runtime_case	artifacts	review_note
ODS-FR-AXFR-001	retained-runtime	tcp_axfr_only	primary-axfr.out; $primary_version_artifact; oxidedns.log	The real-primary $primary_name run serves AXFR over TCP and OxideDNS reaches ready only after the transfer completes; UDP non-emission remains supported by code inspection and transfer API shape.
ODS-FR-AXFR-002	retained-runtime-plus-support	outbound_axfr_query_construction	primary-axfr.out; $primary_version_artifact; crates/oxidedns-core/src/axfr.rs::builds_axfr_query_wire_message	The run proves $primary_name accepted the OxideDNS AXFR query for alpha.test.; focused wire-construction tests cover exact QNAME/QTYPE/QCLASS/opcode/RD fields.
ODS-FR-AXFR-003	retained-runtime	fresh_tcp_connection_to_primary	$primary_version_artifact; $primary_log_artifact; oxidedns.log	The $primary_name primary is configured on a dynamic transfer port and the OxideDNS transfer succeeds against that configured endpoint.
ODS-FR-AXFR-004	retained-runtime-plus-support	real_primary_axfr_stream_ingested	primary-axfr.out; readyz.txt; oxidedns.log; crates/oxidedns-core/src/axfr.rs AXFR parser tests	The $primary_name AXFR stream is ingested and published; multi-message boundary variation remains covered by focused parser/runtime tests.
ODS-FR-AXFR-005	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_mismatched_qid; crates/oxidedns-core/src/axfr.rs::rejects_axfr_response_with_mismatched_opcode	This happy-path interop run does not inject mismatched QID/opcode failures.
ODS-FR-AXFR-006	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs AXFR parser tests	AXFR flag tolerance is covered by parser tests; this retained run does not vary insignificant bits.
ODS-FR-AXFR-007	retained-runtime-plus-support	leading_soa_validated	primary-axfr.out; tcp-soa.out; crates/oxidedns-core/src/axfr.rs::rejects_missing_initial_soa; crates/oxidedns-core/src/axfr.rs::rejects_soa_response_without_apex_soa	The transferred $primary_name zone publishes the expected apex SOA; malformed leading-SOA failures remain covered by focused tests.
ODS-FR-AXFR-008	retained-runtime	terminating_soa_completion	primary-axfr.out; readyz.txt; metrics.txt	Readiness and active-zone metrics are reached after $primary_name AXFR completion; the raw AXFR output includes the duplicated SOA envelope.
ODS-FR-AXFR-009	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_mismatched_terminating_soa	The retained real-primary run is happy path; mismatched terminating SOA failure is covered by focused tests.
ODS-FR-AXFR-010	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_records_after_terminating_soa; crates/oxidedns-core/src/axfr.rs AXFR parser tests	The retained real-primary run contains no mid-stream SOA fault; parser tests cover invalid SOA placement.
ODS-FR-AXFR-011	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_axfr_record_with_mismatched_class	Class mismatch rejection is covered by a focused AXFR parser test; this fixture uses IN class consistently.
ODS-FR-AXFR-012	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_out_of_zone_record	Out-of-zone rejection is covered by focused parser tests; the fixture contains in-zone names only.
ODS-FR-AXFR-013	retained-runtime-plus-support	glue_records_ingested	primary-axfr.out; crates/oxidedns-core/src/dns.rs referral/glue tests	The fixture transfers ns1/ns2 address records; referral glue inclusion remains covered by query unit tests.
ODS-FR-AXFR-014	supporting-unit	not_exercised_by_fixture	crates/oxidedns-core/src/dns.rs::occluded_non_glue_below_delegation_is_not_served	Occluded non-glue query suppression is covered by focused query tests; this fixture does not include occluded data.
ODS-FR-AXFR-015	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs AXFR compression tests	Cross-message compression pointer faults require synthetic parser coverage and are not generated in this retained run.
ODS-FR-AXFR-016	supporting-unit	single_primary_run	crates/oxidedns-server/src/lib.rs transfer-plan primary-rotation tests	This harness uses one primary; multi-primary random initial selection and stable rotation are covered by focused runtime tests.
ODS-FR-AXFR-017	out-of-scope-for-this-run	no_tsig_configured	scripts/interop-bind-tsig-axfr.sh; scripts/interop-nsd-tsig-axfr-docker.sh; scripts/interop-knot-tsig-axfr-docker.sh	This plain AXFR run has transfer_security=none; TSIG AXFR signing evidence is retained by TSIG-specific interop harnesses.
ODS-FR-AXFR-018	out-of-scope-for-this-run	no_tsig_configured	scripts/interop-bind-tsig-axfr.sh; crates/oxidedns-core/src/tsig.rs	This plain AXFR run has transfer_security=none; TSIG stream verification is covered by TSIG-specific tests and harnesses.
ODS-FR-AXFR-019	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs AXFR rejection tests; crates/oxidedns-server/src/lib.rs transfer failure tests	This retained run proves successful publication, not abort semantics; fault-injection tests cover discard/abort paths.
ODS-FR-AXFR-020	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_axfr_response_with_error_rcode; crates/oxidedns-server/src/lib.rs transfer failure tests	Error RCODE abort evidence is covered by focused tests; this real-primary run returns NOERROR.
ODS-FR-AXFR-021	supporting-config	happy_path_with_configured_timeout	oxidedns.toml; docs/implementation-plan.md	The retained config sets axfr_timeout_secs=5 and the transfer completes within it; stalled-timeout failure needs separate fault evidence.
ODS-FR-AXFR-022	supporting-unit	single_zone_run	oxidedns.toml; crates/oxidedns-server/src/lib.rs::runtime_initial_load_honors_transfer_concurrency_limit	This harness has one zone; concurrency limiting is covered by focused runtime tests.
ODS-FR-AXFR-023	retained-runtime	successful_atomic_publication	readyz.txt; answer-a.out; answer-cname.out; tcp-soa.out; metrics.txt	After successful AXFR, OxideDNS serves A, CNAME-chain, and TCP SOA answers and exposes active-zone serial metrics.
ODS-FR-AXFR-024	supporting-unit	not_fault_injected_here	crates/oxidedns-server/src/lib.rs::transfer_axfr_enforces_ingestion_size_cap; crates/oxidedns-core/src/config.rs transfer-ingest-cap tests	This happy-path fixture is below the cap; over-cap abort/discard behavior is covered by focused runtime/config tests.
EOF
}
