#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check-verification-ledger.py
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
