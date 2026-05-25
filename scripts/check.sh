#!/usr/bin/env bash
set -euo pipefail

scripts/check-test-plan.sh
scripts/check-security-policy.sh
python3 -m py_compile scripts/check-perf-regression.py
python3 -m py_compile scripts/check-rrl-thresholds.py
python3 scripts/check-rrl-thresholds.py
python3 -m py_compile scripts/check-operator-guide.py
python3 scripts/check-operator-guide.py
python3 scripts/check-verification-ledger.py
python3 scripts/audit-spoof-evidence.py
python3 scripts/audit-log-fields.py
python3 scripts/audit-log-lazy-formatting.py
bash -n scripts/capture-log-evidence.sh
bash -n scripts/capture-signal-evidence.sh
bash -n scripts/capture-health-metrics-evidence.sh
bash -n scripts/capture-malformed-query-evidence.sh
bash -n scripts/engineering-mvp-evidence.sh
bash -n scripts/axfr-traceability.sh
bash -n scripts/interop-bind-axfr.sh
bash -n scripts/interop-nsd-axfr-docker.sh
bash -n scripts/interop-knot-axfr-docker.sh
bash -n scripts/interop-bind-tsig-axfr.sh
bash -n scripts/interop-nsd-tsig-axfr-docker.sh
bash -n scripts/interop-knot-tsig-axfr-docker.sh
bash -n scripts/interop-bind-ixfr-refresh.sh
bash -n scripts/interop-knot-ixfr-refresh-docker.sh
bash -n scripts/interop-unknown-rr.sh
bash -n scripts/interop-negative-responses.sh
bash -n scripts/interop-notify-negative.sh
bash -n scripts/interop-dns-cookie-dig.sh
bash -n scripts/interop-ixfr-notimp-fallback.sh
bash -n scripts/interop-dnssec-serve.sh
bash -n scripts/interop-dnssec-nsec3-serve.sh
bash -n scripts/interop-rrl-udp.sh
bash -n scripts/rrl-evidence-campaign.sh
scripts/audit-xot-revocation.sh
scripts/audit-dnssec-passive.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
