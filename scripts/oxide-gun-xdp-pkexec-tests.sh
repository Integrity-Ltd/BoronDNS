#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="$repo_root/scripts/oxide-gun-xdp-pkexec-tests.sh"
smoke_binary="${OXIDE_GUN_SMOKE_BIN:-${OXIDE_GUN_BIN:-$repo_root/target/debug/oxide-gun}}"
throughput_binary="${OXIDE_GUN_THROUGHPUT_BIN:-${OXIDE_GUN_BIN:-$repo_root/target/release/oxide-gun}}"
drop_object="${OXIDE_GUN_XDP_DROP_OBJECT:-}"

usage() {
    cat >&2 <<'EOF'
Usage:
  ./scripts/oxide-gun-xdp-pkexec-tests.sh [oxide-gun-binary]

Builds the debug XDP binary, release XDP binary, and Rust eBPF drop object as
the current user, then uses one pkexec authorization to run the privileged veth
smoke, XDP_DROP smoke, and release-backed veth throughput evidence checks.

Optional environment:
  OXIDE_GUN_BIN                    override both smoke and throughput binaries
  OXIDE_GUN_SMOKE_BIN              default target/debug/oxide-gun
  OXIDE_GUN_THROUGHPUT_BIN         default target/release/oxide-gun
  OXIDE_GUN_XDP_DROP_OBJECT        use an existing compiled drop object
  OXIDE_GUN_SKIP_XDP_BUILDS        skip cargo/eBPF builds, default 0
  OXIDE_GUN_VETH_DURATION_SECONDS  veth throughput duration, default 1
  OXIDE_GUN_VETH_MAX_PACKETS       veth throughput cap, default 20000
  OXIDE_GUN_VETH_TARGET_QPS        veth throughput target, default 0
  OXIDE_GUN_VETH_MIN_TX_QPS        veth threshold, default 100000
  OXIDE_GUN_VETH_MIN_TX_PACKETS    veth threshold, default 1
  OXIDE_GUN_VETH_MIN_IF_TX_PACKETS veth threshold, default 1
  OXIDE_GUN_VETH_MIN_IF_TX_RATIO   veth threshold, default 0.90
EOF
}

run_step() {
    local name="$1"
    shift
    printf '\n==> %s\n' "$name"
    "$@"
}

chown_outputs_back() {
    local uid="${PKEXEC_UID:-}"
    if [[ -z "$uid" || ! "$uid" =~ ^[0-9]+$ ]]; then
        return
    fi
    local gid
    gid="$(stat -c '%g' "$repo_root")"
    chown -R "$uid:$gid" \
        "$repo_root/target/oxide-gun-xdp-veth-smoke" \
        "$repo_root/target/oxide-gun-xdp-drop-veth-smoke" \
        "$repo_root/target/oxide-gun-xdp-veth-throughput" \
        2>/dev/null || true
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "${1:-}" == "--as-root" ]]; then
    shift
    smoke_binary="${1:?oxide-gun smoke binary is required}"
    throughput_binary="${2:?oxide-gun throughput binary is required}"
    drop_object="${3:?compiled eBPF drop object is required}"

    if [[ "$(id -u)" -ne 0 ]]; then
        echo "--as-root stage must run as root" >&2
        exit 77
    fi
    if [[ ! -x "$smoke_binary" ]]; then
        echo "oxide-gun smoke binary is not executable: $smoke_binary" >&2
        exit 1
    fi
    if [[ ! -x "$throughput_binary" ]]; then
        echo "oxide-gun throughput binary is not executable: $throughput_binary" >&2
        exit 1
    fi
    if [[ ! -f "$drop_object" ]]; then
        echo "compiled eBPF drop object does not exist: $drop_object" >&2
        exit 1
    fi

    trap chown_outputs_back EXIT
    run_step "privileged AF_XDP veth smoke" \
        "$repo_root/scripts/oxide-gun-xdp-veth-smoke.sh" "$smoke_binary"
    run_step "privileged XDP_DROP veth smoke" \
        "$repo_root/scripts/oxide-gun-xdp-drop-veth-smoke.sh" "$smoke_binary" "$drop_object"
    run_step "release veth throughput evidence harness" env \
        OXIDE_GUN_VETH_DURATION_SECONDS="${OXIDE_GUN_VETH_DURATION_SECONDS:-1}" \
        OXIDE_GUN_VETH_MAX_PACKETS="${OXIDE_GUN_VETH_MAX_PACKETS:-20000}" \
        OXIDE_GUN_VETH_TARGET_QPS="${OXIDE_GUN_VETH_TARGET_QPS:-0}" \
        OXIDE_GUN_VETH_MIN_TX_QPS="${OXIDE_GUN_VETH_MIN_TX_QPS:-100000}" \
        OXIDE_GUN_VETH_MIN_TX_PACKETS="${OXIDE_GUN_VETH_MIN_TX_PACKETS:-1}" \
        OXIDE_GUN_VETH_MIN_IF_TX_PACKETS="${OXIDE_GUN_VETH_MIN_IF_TX_PACKETS:-1}" \
        OXIDE_GUN_VETH_MIN_IF_TX_RATIO="${OXIDE_GUN_VETH_MIN_IF_TX_RATIO:-0.90}" \
        bash "$repo_root/scripts/oxide-gun-xdp-veth-throughput.sh" "$throughput_binary"
    printf '\noxide-gun privileged XDP test bundle passed\n'
    exit 0
fi

if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi
if [[ $# -eq 1 ]]; then
    smoke_binary="$1"
    throughput_binary="$1"
fi

if [[ "${OXIDE_GUN_SKIP_XDP_BUILDS:-0}" != "1" ]]; then
    run_step "build debug oxide-gun with XDP feature" \
        cargo build -p oxide-gun --features xdp
    if [[ "$throughput_binary" == "$repo_root/target/release/oxide-gun" ]]; then
        run_step "build release oxide-gun with XDP feature" \
            cargo build -p oxide-gun --release --features xdp
    fi
    if [[ -z "$drop_object" ]]; then
        printf '\n==> build Rust eBPF XDP_DROP object\n'
        drop_object="$("$repo_root/scripts/oxide-gun-build-ebpf.sh")"
    fi
fi

if [[ -z "$drop_object" ]]; then
    drop_object="$repo_root/crates/oxide-gun-ebpf/target/bpfel-unknown-none/release/oxide-gun-drop.bpf.o"
fi
if [[ ! -x "$smoke_binary" ]]; then
    echo "oxide-gun smoke binary is not executable: $smoke_binary" >&2
    exit 1
fi
if [[ ! -x "$throughput_binary" ]]; then
    echo "oxide-gun throughput binary is not executable: $throughput_binary" >&2
    exit 1
fi
if [[ ! -f "$drop_object" ]]; then
    echo "compiled eBPF drop object does not exist: $drop_object" >&2
    echo "build it with: ./scripts/oxide-gun-build-ebpf.sh" >&2
    exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
    exec "$script_path" --as-root "$smoke_binary" "$throughput_binary" "$drop_object"
fi

command -v pkexec >/dev/null
printf '\n==> requesting one pkexec authorization for privileged XDP tests\n'
exec pkexec "$script_path" --as-root "$smoke_binary" "$throughput_binary" "$drop_object"
