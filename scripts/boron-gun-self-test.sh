#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$repo_root/target/boron-gun-self-test"
out_file="$out_dir/summary.json"

mkdir -p "$out_dir"

cargo run --quiet -p boron-gun -- \
    --self-test \
    --max-packets 8 \
    --target-qps 1000 \
    --flush-interval-ms 0 >"$out_file"

python3 - "$out_file" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    summary = json.load(handle)

expected = {
    "record_type": "summary",
    "summary": True,
    "backend": "std_udp_socket",
    "recv_mode": "process",
    "tx_packets_total": 8,
    "rx_dns_responses_total": 8,
    "positive_total": 8,
    "errors_total": 0,
}
for key, value in expected.items():
    if summary.get(key) != value:
        raise SystemExit(f"{key}: expected {value!r}, got {summary.get(key)!r}")

print(f"boron-gun self-test passed: {path}")
PY
