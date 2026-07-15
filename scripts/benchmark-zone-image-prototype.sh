#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export BORONDNS_ZONE_IMAGE_BENCH_RECORDS="${BORONDNS_ZONE_IMAGE_BENCH_RECORDS:-10000}"
export BORONDNS_ZONE_IMAGE_BENCH_ZONE_DIRECTORY_ZONES="${BORONDNS_ZONE_IMAGE_BENCH_ZONE_DIRECTORY_ZONES:-1000}"
export BORONDNS_ZONE_IMAGE_BENCH_STRESS_CANDIDATES="${BORONDNS_ZONE_IMAGE_BENCH_STRESS_CANDIDATES:-2000}"
export BORONDNS_ZONE_IMAGE_BENCH_ITERATIONS="${BORONDNS_ZONE_IMAGE_BENCH_ITERATIONS:-200000}"
export BORONDNS_ZONE_IMAGE_BENCH_BUILD_PROFILE="${BORONDNS_ZONE_IMAGE_BENCH_BUILD_PROFILE:-profiling}"
export BORONDNS_ZONE_IMAGE_BENCH_GIT_REVISION="${BORONDNS_ZONE_IMAGE_BENCH_GIT_REVISION:-$(git rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')}"
if [[ -n "${BORONDNS_ZONE_IMAGE_BENCH_GIT_DIRTY:-}" ]]; then
    export BORONDNS_ZONE_IMAGE_BENCH_GIT_DIRTY
else
    git_status_output=""
    if ! git_status_output="$(git status --porcelain 2>/dev/null)"; then
        export BORONDNS_ZONE_IMAGE_BENCH_GIT_DIRTY="unknown"
    elif [[ -n "$git_status_output" ]]; then
        export BORONDNS_ZONE_IMAGE_BENCH_GIT_DIRTY="true"
    else
        export BORONDNS_ZONE_IMAGE_BENCH_GIT_DIRTY="false"
    fi
fi
export BORONDNS_ZONE_IMAGE_BENCH_KERNEL="${BORONDNS_ZONE_IMAGE_BENCH_KERNEL:-$(uname -srmo)}"
export BORONDNS_ZONE_IMAGE_BENCH_RUSTC="${BORONDNS_ZONE_IMAGE_BENCH_RUSTC:-$(rustc -V)}"
export BORONDNS_ZONE_IMAGE_BENCH_RUST_TARGET="${BORONDNS_ZONE_IMAGE_BENCH_RUST_TARGET:-$(rustc -Vv | awk -F': ' '/^host: / { print $2; exit }')}"
export BORONDNS_ZONE_IMAGE_BENCH_CPU_MODEL="${BORONDNS_ZONE_IMAGE_BENCH_CPU_MODEL:-$(awk -F': ' '/^model name[[:space:]]*: / { print $2; exit }' /proc/cpuinfo 2>/dev/null || uname -m)}"
export BORONDNS_ZONE_IMAGE_BENCH_NETWORK_DEVICE="${BORONDNS_ZONE_IMAGE_BENCH_NETWORK_DEVICE:-not-applicable-in-process-benchmark}"
export BORONDNS_ZONE_IMAGE_BENCH_OUTPUT="${BORONDNS_ZONE_IMAGE_BENCH_OUTPUT:-target/zone-image-bench/prototype-latest.tsv}"
export BORONDNS_ZONE_IMAGE_BENCH_TRACE="${BORONDNS_ZONE_IMAGE_BENCH_TRACE:-crates/borondns-core/examples/zone_image_reference_trace.tsv}"

mkdir -p "$(dirname "$BORONDNS_ZONE_IMAGE_BENCH_OUTPUT")"

cargo run --profile "$BORONDNS_ZONE_IMAGE_BENCH_BUILD_PROFILE" -p borondns-core --example zone_image_bench -- \
    --records "$BORONDNS_ZONE_IMAGE_BENCH_RECORDS" \
    --zone-directory-zones "$BORONDNS_ZONE_IMAGE_BENCH_ZONE_DIRECTORY_ZONES" \
    --stress-candidates "$BORONDNS_ZONE_IMAGE_BENCH_STRESS_CANDIDATES" \
    --iterations "$BORONDNS_ZONE_IMAGE_BENCH_ITERATIONS" \
    --build-profile "$BORONDNS_ZONE_IMAGE_BENCH_BUILD_PROFILE" \
    --git-revision "$BORONDNS_ZONE_IMAGE_BENCH_GIT_REVISION" \
    --git-dirty "$BORONDNS_ZONE_IMAGE_BENCH_GIT_DIRTY" \
    --kernel "$BORONDNS_ZONE_IMAGE_BENCH_KERNEL" \
    --rustc "$BORONDNS_ZONE_IMAGE_BENCH_RUSTC" \
    --rust-target "$BORONDNS_ZONE_IMAGE_BENCH_RUST_TARGET" \
    --cpu-model "$BORONDNS_ZONE_IMAGE_BENCH_CPU_MODEL" \
    --network-device "$BORONDNS_ZONE_IMAGE_BENCH_NETWORK_DEVICE" \
    --artifact "$BORONDNS_ZONE_IMAGE_BENCH_OUTPUT" \
    --trace "$BORONDNS_ZONE_IMAGE_BENCH_TRACE" |
    tee "$BORONDNS_ZONE_IMAGE_BENCH_OUTPUT"
