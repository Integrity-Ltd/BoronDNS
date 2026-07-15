#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
    printf 'usage: %s SHELL_FILE...\n' "$0" >&2
    exit 64
fi

if ! command -v shfmt >/dev/null 2>&1; then
    printf 'missing required tool: shfmt\n' >&2
    exit 1
fi

exec shfmt -d "$@"
