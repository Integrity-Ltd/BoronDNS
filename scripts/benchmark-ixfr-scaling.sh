#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

records="${BORONDNS_IXFR_BENCH_RECORDS:-1000000}"
delta="${BORONDNS_IXFR_BENCH_DELTA:-100}"
delta_mode="${BORONDNS_IXFR_BENCH_DELTA_MODE:-add}"
query_threads="${BORONDNS_IXFR_BENCH_QUERY_THREADS:-0}"
query_engine="${BORONDNS_IXFR_BENCH_QUERY_ENGINE:-image}"
publication_strategy="${BORONDNS_IXFR_BENCH_PUBLICATION_STRATEGY:-compact}"
publication_threshold="${BORONDNS_IXFR_BENCH_PUBLICATION_THRESHOLD:-1000000}"
sample_seconds="${BORONDNS_IXFR_BENCH_SAMPLE_SECONDS:-2}"
profile="${BORONDNS_IXFR_BENCH_PROFILE:-profiling}"
artifact="${BORONDNS_IXFR_BENCH_ARTIFACT:-target/ixfr-scaling/ixfr-${records}-${delta}-q${query_threads}.tsv}"

for numeric in "$records" "$delta" "$query_threads" "$sample_seconds" "$publication_threshold"; do
    if ! [[ "$numeric" =~ ^[0-9]+$ ]]; then
        printf 'IXFR benchmark numeric values must contain decimal digits only, got %q\n' "$numeric" >&2
        exit 2
    fi
done
if [[ "$records" == 0 || "$sample_seconds" == 0 || "$publication_threshold" == 0 ]]; then
    printf 'IXFR benchmark records, sample seconds, and publication threshold must be positive\n' >&2
    exit 2
fi
if [[ "$query_engine" != image && "$query_engine" != snapshot && "$query_engine" != overlay ]]; then
    printf 'IXFR benchmark query engine must be image, snapshot, or overlay, got %q\n' "$query_engine" >&2
    exit 2
fi
if [[ "$delta_mode" != add && "$delta_mode" != replace && "$delta_mode" != mixed ]]; then
    printf 'IXFR benchmark delta mode must be add, replace, or mixed, got %q\n' "$delta_mode" >&2
    exit 2
fi
if [[ "$publication_strategy" != compact && "$publication_strategy" != sharded && "$publication_strategy" != auto ]]; then
    printf 'IXFR benchmark publication strategy must be compact, sharded, or auto, got %q\n' "$publication_strategy" >&2
    exit 2
fi
if [[ "$artifact" != /* ]]; then
    artifact="$repo_root/$artifact"
fi
mkdir -p "$(dirname "$artifact")"

cargo run --profile "$profile" -p borondns-core --example ixfr_scaling_bench -- \
    --records "$records" \
    --delta "$delta" \
    --delta-mode "$delta_mode" \
    --query-threads "$query_threads" \
    --query-engine "$query_engine" \
    --publication-strategy "$publication_strategy" \
    --publication-threshold "$publication_threshold" \
    --sample-seconds "$sample_seconds" \
    --artifact "$artifact"
