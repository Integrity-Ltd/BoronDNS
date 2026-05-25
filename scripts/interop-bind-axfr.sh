#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in named named-checkconf named-checkzone dig curl python3 cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping BIND interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
zone_file="$repo_root/tests/interop/bind/alpha.test.zone"
template_file="$repo_root/tests/interop/bind/named.conf.template"
workdir="$repo_root/target/interop/bind-axfr-$$"
artifact_dir="${OXIDEDNS_BIND_AXFR_ARTIFACT_DIR:-}"
mkdir -p "$workdir"

cleanup() {
  local status=$?
  if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
    kill "$oxidedns_pid" 2>/dev/null || true
    wait "$oxidedns_pid" 2>/dev/null || true
  fi
  if [[ -n "${named_pid:-}" ]] && kill -0 "$named_pid" 2>/dev/null; then
    kill "$named_pid" 2>/dev/null || true
    wait "$named_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    [[ -f "$workdir/named.log" ]] && { echo "---- named.log ----" >&2; tail -100 "$workdir/named.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -100 "$workdir/oxidedns.log" >&2; }
  fi
}
trap cleanup EXIT

read -r bind_port oxidedns_dns_port oxidedns_health_port < <(
  python3 - <<'PY'
import socket

sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

named_conf="$workdir/named.conf"
oxidedns_conf="$workdir/oxidedns.toml"
primary_soa_out="$workdir/primary-soa.out"
primary_axfr_out="$workdir/primary-axfr.out"
readyz_out="$workdir/readyz.txt"
answer_a_out="$workdir/answer-a.out"
answer_cname_out="$workdir/answer-cname.out"
tcp_soa_out="$workdir/tcp-soa.out"
metrics_out="$workdir/metrics.txt"
traceability_tsv="$workdir/axfr-traceability.tsv"

named-checkzone alpha.test. "$zone_file" >/dev/null
python3 - "$template_file" "$named_conf" "$workdir" "$bind_port" "$zone_file" <<'PY'
from pathlib import Path
import sys

template, output, workdir, port, zonefile = sys.argv[1:]
text = Path(template).read_text()
text = text.replace("__WORKDIR__", workdir)
text = text.replace("__PORT__", port)
text = text.replace("__ZONEFILE__", zonefile)
Path(output).write_text(text)
PY
named-checkconf -z "$named_conf" >/dev/null
record_bind_primary_version "$workdir" "bind-axfr" "tcp-axfr" "none" "$named_conf" "$zone_file"

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$bind_port"]
notify_sources = ["127.0.0.1"]
EOF

named -g -c "$named_conf" -n 1 >"$workdir/named.log" 2>&1 &
named_pid=$!

for _ in {1..50}; do
  if dig "@127.0.0.1" -p "$bind_port" alpha.test. SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

primary_soa="$(dig "@127.0.0.1" -p "$bind_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$primary_soa" >"$primary_soa_out"
if [[ -z "$primary_soa" ]]; then
  echo "BIND primary did not answer SOA" >&2
  exit 1
fi

primary_axfr="$(dig "@127.0.0.1" -p "$bind_port" alpha.test. AXFR +time=2 +tries=1)"
printf '%s\n' "$primary_axfr" >"$primary_axfr_out"
if [[ "$primary_axfr" != *"www.alpha.test."* ]] || [[ "$primary_axfr" != *"alias.alpha.test."* ]]; then
  echo "BIND primary AXFR did not include expected fixture records" >&2
  exit 1
fi

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=""
for _ in {1..100}; do
  if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
    [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
  fi
  sleep 0.1
done

if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
  echo "OxideDNS did not become ready after BIND AXFR" >&2
  exit 1
fi
printf '%s\n' "$ready" >"$readyz_out"

answer_a="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
printf '%s\n' "$answer_a" >"$answer_a_out"
if [[ "$answer_a" != *"www.alpha.test."* ]] || [[ "$answer_a" != *"192.0.2.10"* ]]; then
  echo "OxideDNS did not serve expected A response" >&2
  exit 1
fi

answer_cname="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alias.alpha.test. A +norecurse +noall +answer)"
printf '%s\n' "$answer_cname" >"$answer_cname_out"
if [[ "$answer_cname" != *"alias.alpha.test."* ]] || [[ "$answer_cname" != *"www.alpha.test."* ]] || [[ "$answer_cname" != *"192.0.2.10"* ]]; then
  echo "OxideDNS did not serve expected CNAME chain response" >&2
  exit 1
fi

tcp_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
printf '%s\n' "$tcp_soa" >"$tcp_soa_out"
if [[ "$tcp_soa" != *"2026052401"* ]]; then
  echo "OxideDNS did not serve expected TCP SOA response" >&2
  exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
if [[ "$metrics" != *'oxidedns_zones_active 1'* ]] || [[ "$metrics" != *'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052401'* ]]; then
  echo "OxideDNS metrics did not expose active BIND-transferred zone" >&2
  exit 1
fi

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_state	runtime_case	artifacts	review_note
ODS-FR-AXFR-001	retained-runtime	tcp_axfr_only	primary-axfr.out; primary-version.txt; oxidedns.log	The real-primary BIND run serves AXFR over TCP and OxideDNS reaches ready only after the transfer completes; UDP non-emission remains supported by code inspection and transfer API shape.
ODS-FR-AXFR-002	retained-runtime-plus-support	outbound_axfr_query_construction	primary-axfr.out; primary-version.txt; crates/oxidedns-core/src/axfr.rs::builds_axfr_query_wire_message	The run proves BIND accepted the OxideDNS AXFR query for alpha.test.; focused wire-construction tests cover exact QNAME/QTYPE/QCLASS/opcode/RD fields.
ODS-FR-AXFR-003	retained-runtime	fresh_tcp_connection_to_primary	primary-version.txt; named.log; oxidedns.log	The BIND primary is configured on a dynamic transfer port and the OxideDNS transfer succeeds against that configured endpoint.
ODS-FR-AXFR-004	retained-runtime-plus-support	bind_axfr_stream_ingested	primary-axfr.out; readyz.txt; oxidedns.log; crates/oxidedns-core/src/axfr.rs AXFR parser tests	The BIND AXFR stream is ingested and published; multi-message boundary variation remains covered by focused parser/runtime tests.
ODS-FR-AXFR-005	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_mismatched_qid; crates/oxidedns-core/src/axfr.rs::rejects_axfr_response_with_mismatched_opcode	This happy-path interop run does not inject mismatched QID/opcode failures.
ODS-FR-AXFR-006	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs AXFR parser tests	AXFR flag tolerance is covered by parser tests; BIND does not vary insignificant bits for this retained run.
ODS-FR-AXFR-007	retained-runtime-plus-support	leading_soa_validated	primary-axfr.out; tcp-soa.out; crates/oxidedns-core/src/axfr.rs::rejects_missing_initial_soa; crates/oxidedns-core/src/axfr.rs::rejects_soa_response_without_apex_soa	The transferred BIND zone publishes the expected apex SOA; malformed leading-SOA failures remain covered by focused tests.
ODS-FR-AXFR-008	retained-runtime	terminating_soa_completion	primary-axfr.out; readyz.txt; metrics.txt	Readiness and active-zone metrics are reached after BIND AXFR completion; the raw AXFR output includes the duplicated SOA envelope.
ODS-FR-AXFR-009	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_mismatched_terminating_soa	The retained real-primary run is happy path; mismatched terminating SOA failure is covered by focused tests.
ODS-FR-AXFR-010	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_records_after_terminating_soa; crates/oxidedns-core/src/axfr.rs AXFR parser tests	The retained real-primary run contains no mid-stream SOA fault; parser tests cover invalid SOA placement.
ODS-FR-AXFR-011	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_axfr_record_with_mismatched_class	Class mismatch rejection is covered by a focused AXFR parser test; this BIND fixture uses IN class consistently.
ODS-FR-AXFR-012	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_out_of_zone_record	Out-of-zone rejection is covered by focused parser tests; the BIND fixture contains in-zone names only.
ODS-FR-AXFR-013	retained-runtime-plus-support	glue_records_ingested	primary-axfr.out; crates/oxidedns-core/src/dns.rs referral/glue tests	The BIND fixture transfers ns1/ns2 address records; referral glue inclusion remains covered by query unit tests.
ODS-FR-AXFR-014	supporting-unit	not_exercised_by_bind_fixture	crates/oxidedns-core/src/dns.rs::occluded_non_glue_below_delegation_is_not_served	Occluded non-glue query suppression is covered by focused query tests; this BIND fixture does not include occluded data.
ODS-FR-AXFR-015	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs AXFR compression tests	Cross-message compression pointer faults require synthetic parser coverage and are not generated by BIND in this retained run.
ODS-FR-AXFR-016	supporting-unit	single_primary_run	crates/oxidedns-server/src/lib.rs transfer-plan primary-rotation tests	This BIND harness uses one primary; multi-primary random initial selection and stable rotation are covered by focused runtime tests.
ODS-FR-AXFR-017	out-of-scope-for-this-run	no_tsig_configured	scripts/interop-bind-tsig-axfr.sh; scripts/interop-nsd-tsig-axfr-docker.sh; scripts/interop-knot-tsig-axfr-docker.sh	This plain AXFR run has transfer_security=none; TSIG AXFR signing evidence is retained by TSIG-specific interop harnesses.
ODS-FR-AXFR-018	out-of-scope-for-this-run	no_tsig_configured	scripts/interop-bind-tsig-axfr.sh; crates/oxidedns-core/src/tsig.rs	This plain AXFR run has transfer_security=none; TSIG stream verification is covered by TSIG-specific tests and harnesses.
ODS-FR-AXFR-019	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs AXFR rejection tests; crates/oxidedns-server/src/lib.rs transfer failure tests	This retained run proves successful publication, not abort semantics; fault-injection tests cover discard/abort paths.
ODS-FR-AXFR-020	supporting-unit	not_fault_injected_here	crates/oxidedns-core/src/axfr.rs::rejects_axfr_response_with_error_rcode; crates/oxidedns-server/src/lib.rs transfer failure tests	Error RCODE abort evidence is covered by focused tests; BIND returns NOERROR in this happy-path run.
ODS-FR-AXFR-021	supporting-config	happy_path_with_configured_timeout	oxidedns.toml; docs/implementation-plan.md	The retained config sets axfr_timeout_secs=5 and the transfer completes within it; stalled-timeout failure needs separate fault evidence.
ODS-FR-AXFR-022	supporting-unit	single_zone_run	oxidedns.toml; crates/oxidedns-server/src/lib.rs::runtime_initial_load_honors_transfer_concurrency_limit	This BIND harness has one zone; concurrency limiting is covered by focused runtime tests.
ODS-FR-AXFR-023	retained-runtime	successful_atomic_publication	readyz.txt; answer-a.out; answer-cname.out; tcp-soa.out; metrics.txt	After successful AXFR, OxideDNS serves A, CNAME-chain, and TCP SOA answers and exposes active-zone serial metrics.
ODS-FR-AXFR-024	supporting-unit	not_fault_injected_here	crates/oxidedns-server/src/lib.rs::transfer_axfr_enforces_ingestion_size_cap; crates/oxidedns-core/src/config.rs transfer-ingest-cap tests	This happy-path fixture is below the cap; over-cap abort/discard behavior is covered by focused runtime/config tests.
EOF

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$named_conf" "$artifact_dir/named.conf"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cp "$workdir/named.log" "$artifact_dir/named.log"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$workdir/primary-version.txt" "$artifact_dir/primary-version.txt"
  cp "$primary_soa_out" "$artifact_dir/primary-soa.out"
  cp "$primary_axfr_out" "$artifact_dir/primary-axfr.out"
  cp "$readyz_out" "$artifact_dir/readyz.txt"
  cp "$answer_a_out" "$artifact_dir/answer-a.out"
  cp "$answer_cname_out" "$artifact_dir/answer-cname.out"
  cp "$tcp_soa_out" "$artifact_dir/tcp-soa.out"
  cp "$metrics_out" "$artifact_dir/metrics.txt"
  cp "$traceability_tsv" "$artifact_dir/axfr-traceability.tsv"
fi

echo "BIND AXFR interop passed"
