#!/usr/bin/env bash
set -euo pipefail

scripts/check-test-plan.sh
scripts/check-security-policy.sh
python3 -m py_compile scripts/check-perf-regression.py
python3 scripts/check-verification-ledger.py
python3 scripts/audit-log-fields.py
bash -n scripts/capture-log-evidence.sh
bash -n scripts/capture-signal-evidence.sh
bash -n scripts/capture-health-metrics-evidence.sh
scripts/audit-xot-revocation.sh
scripts/audit-dnssec-passive.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
