#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

record_csv="${BORONDNS_IXFR_MATRIX_RECORDS:-1000000,10000000,50000000}"
delta_csv="${BORONDNS_IXFR_MATRIX_DELTAS:-1,100,100000}"
query_thread_csv="${BORONDNS_IXFR_MATRIX_QUERY_THREADS:-0}"
sample_seconds="${BORONDNS_IXFR_MATRIX_SAMPLE_SECONDS:-2}"
profile="${BORONDNS_IXFR_MATRIX_PROFILE:-profiling}"
artifact_dir="${BORONDNS_IXFR_MATRIX_ARTIFACT_DIR:-target/ixfr-scaling/matrix}"

if [[ "$artifact_dir" != /* ]]; then
    artifact_dir="$repo_root/$artifact_dir"
fi
mkdir -p "$artifact_dir/rows"
progress="$artifact_dir/progress.log"
combined="$artifact_dir/results.tsv"
: >"$progress"
: >"$combined"

IFS=, read -r -a record_values <<<"$record_csv"
IFS=, read -r -a delta_values <<<"$delta_csv"
IFS=, read -r -a query_thread_values <<<"$query_thread_csv"
for value in "${record_values[@]}" "${delta_values[@]}" \
    "${query_thread_values[@]}" "$sample_seconds"; do
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        printf 'IXFR matrix values must contain decimal digits only, got %q\n' "$value" >&2
        exit 2
    fi
done
if [[ "$sample_seconds" == 0 ]]; then
    printf 'IXFR matrix sample seconds must be positive\n' >&2
    exit 2
fi

cargo build --profile "$profile" -p borondns-core --example ixfr_scaling_bench
binary="$repo_root/target/$profile/examples/ixfr_scaling_bench"
first=true
for query_threads in "${query_thread_values[@]}"; do
    for records in "${record_values[@]}"; do
        if [[ "$records" == 0 ]]; then
            printf 'IXFR matrix record counts must be positive\n' >&2
            exit 2
        fi
        for delta in "${delta_values[@]}"; do
            row="$artifact_dir/rows/records-${records}-delta-${delta}-q${query_threads}.tsv"
            printf '%s start records=%s delta=%s query_threads=%s\n' \
                "$(date --iso-8601=seconds)" "$records" "$delta" "$query_threads" | tee -a "$progress"
            "$binary" \
                --records "$records" \
                --delta "$delta" \
                --query-threads "$query_threads" \
                --sample-seconds "$sample_seconds" \
                --artifact "$row"
            if [[ "$first" == true ]]; then
                cp "$row" "$combined"
                first=false
            else
                tail -n 1 "$row" >>"$combined"
            fi
            printf '%s finish records=%s delta=%s query_threads=%s\n' \
                "$(date --iso-8601=seconds)" "$records" "$delta" "$query_threads" | tee -a "$progress"
        done
    done
done

printf 'results=%s\n' "$combined" | tee -a "$progress"
