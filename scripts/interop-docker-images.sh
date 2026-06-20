#!/usr/bin/env bash

ensure_alpine_interop_image() {
    local name="$1"
    shift
    local packages=("$@")
    local tag="oxidedns-interop-alpine-$name:latest"
    local lockdir="${TMPDIR:-/tmp}/oxidedns-interop-image-$name.lock"
    local wait_count=0
    local package

    for package in "${packages[@]}"; do
        if [[ ! "$package" =~ ^[A-Za-z0-9_.+-]+$ ]]; then
            printf 'invalid Alpine package name for %s image: %s\n' "$name" "$package" >&2
            return 1
        fi
    done

    if docker image inspect "$tag" >/dev/null 2>&1; then
        printf '%s\n' "$tag"
        return 0
    fi

    while ! mkdir "$lockdir" 2>/dev/null; do
        if docker image inspect "$tag" >/dev/null 2>&1; then
            printf '%s\n' "$tag"
            return 0
        fi
        wait_count=$((wait_count + 1))
        if ((wait_count > 600)); then
            printf 'timed out waiting for Docker image build lock: %s\n' "$lockdir" >&2
            return 1
        fi
        sleep 1
    done

    if docker image inspect "$tag" >/dev/null 2>&1; then
        rmdir "$lockdir" 2>/dev/null || true
        printf '%s\n' "$tag"
        return 0
    fi

    local build_dir
    build_dir="$(mktemp -d)"
    {
        printf 'FROM alpine:latest\n'
        printf 'RUN set -eu; for attempt in 1 2 3 4 5; do apk add --no-cache'
        for package in "${packages[@]}"; do
            printf ' %s' "$package"
        done
        # shellcheck disable=SC2016
        printf ' && exit 0; sleep $((attempt * 3)); done; exit 1\n'
    } >"$build_dir/Dockerfile"

    local status=1
    local attempt
    for attempt in 1 2 3 4 5; do
        if docker build --pull -t "$tag" "$build_dir" >&2; then
            status=0
            break
        fi
        sleep $((attempt * 5))
    done

    rm -rf "$build_dir"
    rmdir "$lockdir" 2>/dev/null || true

    if ((status != 0)); then
        printf 'failed to build Docker interop image: %s\n' "$tag" >&2
        return "$status"
    fi

    printf '%s\n' "$tag"
}

ensure_alpine_bind_image() {
    ensure_alpine_interop_image bind bind bind-tools
}

ensure_alpine_knot_image() {
    ensure_alpine_interop_image knot knot
}

ensure_alpine_nsd_image() {
    ensure_alpine_interop_image nsd nsd
}

ensure_alpine_nsd_notify_image() {
    ensure_alpine_interop_image nsd-notify gcompat libgcc nsd python3
}

ensure_alpine_packet_torture_image() {
    ensure_alpine_interop_image packet-torture python3 wireshark-common
}
