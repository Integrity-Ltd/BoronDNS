#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v actionlint >/dev/null 2>&1; then
    printf 'missing required tool: actionlint\n' >&2
    exit 1
fi

actionlint "$repo_root"/.github/workflows/*.yml
printf 'GitHub Actions workflow check passed\n'
