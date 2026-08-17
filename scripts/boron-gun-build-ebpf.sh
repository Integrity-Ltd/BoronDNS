#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/crates/boron-gun-ebpf/Cargo.toml"
toolchain="nightly-2026-06-12"
bpf_linker_version="0.11.0"
bpf_linker_x86_64_linux_sha256="99740280d5c4962b7110e56e23f63adbe575baeaaa9e764d8ee765b1444f5ee6"

linker="$(command -v bpf-linker || true)"
if [[ -z "$linker" ]]; then
    echo "bpf-linker is required to build the Rust eBPF object." >&2
    echo "Install it with: cargo install bpf-linker --version $bpf_linker_version --locked" >&2
    exit 127
fi
linker_version="$($linker --version)"
linker_digest="$(sha256sum "$linker" | awk '{print $1}')"
if [[ "$linker_version" != "bpf-linker $bpf_linker_version" ]] &&
    ! { [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] &&
        [[ "$linker_version" == "bpf-linker 0.0.0" ]] &&
        [[ "$linker_digest" == "$bpf_linker_x86_64_linux_sha256" ]]; }; then
    echo "bpf-linker $bpf_linker_version is required; found: $($linker --version)" >&2
    exit 1
fi

CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="$linker" rustup run "$toolchain" cargo build \
    --manifest-path "$manifest" \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --locked \
    --release

target_dir="$repo_root/crates/boron-gun-ebpf/target/bpfel-unknown-none/release"
artifact="$target_dir/libboron_gun_ebpf.so"
object="$target_dir/boron-gun-xdp.bpf.o"
drop_compat_object="$target_dir/boron-gun-drop.bpf.o"

if [[ ! -f "$artifact" ]]; then
    echo "expected eBPF artifact was not produced: $artifact" >&2
    exit 1
fi

cp -f "$artifact" "$object"
cp -f "$artifact" "$drop_compat_object"
printf '%s\n' "$object"
