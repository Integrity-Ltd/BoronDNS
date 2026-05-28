#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/crates/oxide-gun-ebpf/Cargo.toml"

linker="$(command -v bpf-linker || true)"
if [[ -z "$linker" ]]; then
    echo "bpf-linker is required to build the Rust eBPF object." >&2
    echo "Install it with: cargo install bpf-linker" >&2
    exit 127
fi

CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="$linker" rustup run nightly cargo build \
    --manifest-path "$manifest" \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

target_dir="$repo_root/crates/oxide-gun-ebpf/target/bpfel-unknown-none/release"
artifact="$target_dir/liboxide_gun_ebpf.so"
object="$target_dir/oxide-gun-drop.bpf.o"

if [[ ! -f "$artifact" ]]; then
    echo "expected eBPF artifact was not produced: $artifact" >&2
    exit 1
fi

cp -f "$artifact" "$object"
printf '%s\n' "$object"
