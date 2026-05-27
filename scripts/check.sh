#!/usr/bin/env bash
set -euo pipefail

scripts/check-test-plan.sh
scripts/check-shell-scripts.sh
scripts/check-security-policy.sh
python3 -m py_compile scripts/check-perf-regression.py
python3 -m py_compile scripts/check-rrl-thresholds.py
python3 -m py_compile scripts/check-appendix-a-traceability.py
python3 scripts/check-rrl-thresholds.py
python3 -m py_compile scripts/check-operator-guide.py
python3 -m py_compile scripts/check-unsafe-boundaries.py
python3 -m py_compile scripts/check-unsafe-prone-dependencies.py
python3 -m py_compile scripts/check-interface-compatibility.py
python3 -m py_compile scripts/check-dnssec-conformance-matrix.py
python3 -m py_compile scripts/check-engineering-mvp-scope.py
python3 -m py_compile scripts/check-engineering-mvp-readiness.py
python3 -m py_compile scripts/check-zsm-engineering-mvp-matrix.py
python3 -m py_compile scripts/check-functional-requirement-references.py
python3 -m py_compile scripts/check-rfc-compliance-assertions.py
python3 -m py_compile scripts/check-srs-identifier-registry.py
python3 -m py_compile scripts/check-doc-hygiene.py
python3 -m py_compile scripts/check-srs-review-disposition.py
python3 scripts/check-operator-guide.py
python3 scripts/check-verification-ledger.py
python3 scripts/check-appendix-a-traceability.py
python3 scripts/check-unsafe-boundaries.py
python3 scripts/check-unsafe-prone-dependencies.py
python3 scripts/check-interface-compatibility.py
python3 scripts/check-dnssec-conformance-matrix.py
python3 scripts/check-engineering-mvp-scope.py
python3 scripts/check-engineering-mvp-readiness.py
python3 scripts/check-zsm-engineering-mvp-matrix.py
python3 scripts/check-functional-requirement-references.py
python3 scripts/check-rfc-compliance-assertions.py
python3 scripts/check-srs-identifier-registry.py
python3 scripts/check-doc-hygiene.py
python3 scripts/check-srs-review-disposition.py
python3 scripts/audit-spoof-evidence.py
python3 scripts/audit-log-fields.py
python3 scripts/audit-log-lazy-formatting.py
scripts/audit-invariants.sh
scripts/audit-safe-rust.sh
bash -n scripts/audit-unused-code.sh
bash -n scripts/capture-log-evidence.sh
bash -n scripts/capture-signal-evidence.sh
bash -n scripts/capture-health-metrics-evidence.sh
bash -n scripts/capture-malformed-query-evidence.sh
bash -n scripts/capture-portability-evidence.sh
bash -n scripts/capture-resource-evidence.sh
bash -n scripts/capture-coverage-evidence.sh
bash -n scripts/capture-unsafe-dependency-evidence.sh
bash -n scripts/capture-interface-compatibility-evidence.sh
bash -n scripts/fuzz-campaign.sh
bash -n scripts/engineering-mvp-evidence.sh
bash -n scripts/package-docker-image.sh
bash -n scripts/axfr-traceability.sh
bash -n scripts/interop-bind-axfr.sh
bash -n scripts/interop-bind-axfr-docker.sh
bash -n scripts/interop-bind-packet-torture-docker.sh
bash -n scripts/interop-nsd-axfr-docker.sh
bash -n scripts/interop-knot-axfr-docker.sh
bash -n scripts/interop-bind-tsig-axfr.sh
bash -n scripts/interop-nsd-tsig-axfr-docker.sh
bash -n scripts/interop-knot-tsig-axfr-docker.sh
bash -n scripts/interop-bind-ixfr-refresh.sh
bash -n scripts/interop-knot-ixfr-refresh-docker.sh
bash -n scripts/interop-unknown-rr.sh
bash -n scripts/interop-unknown-rr-bad-transfer.sh
bash -n scripts/interop-negative-responses.sh
bash -n scripts/interop-notify-negative.sh
bash -n scripts/interop-chaos-queries.sh
bash -n scripts/interop-powerdns-postgres-catalog-tsig-docker.sh
bash -n scripts/test-docker-image.sh
bash -n scripts/interop-dns-cookie-dig.sh
bash -n scripts/interop-ixfr-notimp-fallback.sh
bash -n scripts/interop-dnssec-serve.sh
bash -n scripts/interop-dnssec-nsec3-serve.sh
bash -n scripts/interop-rrl-udp.sh
bash -n scripts/rrl-evidence-campaign.sh
bash -n scripts/benchmark-large-catalog-zones.sh
scripts/audit-xot-revocation.sh
scripts/audit-dnssec-passive.sh
scripts/interop-chaos-queries.sh
scripts/capture-unsafe-dependency-evidence.sh
scripts/audit-unused-code.sh
scripts/capture-resource-evidence.sh
scripts/capture-coverage-evidence.sh
scripts/capture-interface-compatibility-evidence.sh
scripts/fuzz-campaign.sh --dry-run --duration 1 --target dns_datagram
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
