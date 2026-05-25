#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check-verification-ledger.py
scripts/audit-xot-revocation.sh
scripts/audit-dnssec-passive.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
