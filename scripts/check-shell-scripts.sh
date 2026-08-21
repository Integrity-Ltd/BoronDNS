#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_shellcheck_files() {
    local file
    for file in "$@"; do
        if [[ "$file" == "$repo_root/scripts/test-operations-harnesses.sh" ]]; then
            # This monolithic fault-injection fixture peaks above 20 GiB RSS in
            # ShellCheck 0.11.0. Keep its syntax and formatting gates here;
            # scripts/check.sh executes the complete behavioral suite below.
            bash -n "$file"
            continue
        fi
        # Every sourced repository file is checked by this loop in its own
        # right. Suppress cross-source diagnostics which become false when
        # files are intentionally parsed in separate processes.
        shellcheck --exclude=SC1091,SC2034,SC2154,SC2329 "$file"
    done
}

if [[ "${1:-}" == "--shellcheck-only" ]]; then
    shift
    run_shellcheck_files "$@"
    exit 0
fi

missing=()
for tool in shfmt shellcheck; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required shell check tools: %s\n' "${missing[*]}" >&2
    printf 'install shfmt and shellcheck before running shell-script checks\n' >&2
    exit 1
fi

shell_files=()
while IFS= read -r -d '' file; do
    shell_files+=("$file")
done < <(
    find "$repo_root/scripts" "$repo_root/packaging" \
        -type f \
        \( -name '*.sh' -o -path '*/openrc/borondns' \) \
        -print0
)

if ((${#shell_files[@]} == 0)); then
    echo "shell script check passed: no shell files found"
    exit 0
fi

"$repo_root/scripts/check-shell-format.sh" "${shell_files[@]}"
# ShellCheck retains the parsed AST for every input in one process. Passing the
# complete repository set at once has exceeded 29 GiB RSS on the development
# host. Check one file per process so repository growth cannot turn this
# preflight into an unbounded aggregate allocation.
if command -v systemd-run >/dev/null 2>&1 &&
    command -v systemctl >/dev/null 2>&1 &&
    [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" == "cgroup2fs" ]] &&
    systemctl --user show-environment >/dev/null 2>&1; then
    systemd-run --user --scope --quiet \
        -p MemoryHigh=22G \
        -p MemoryMax=24G \
        -p MemorySwapMax=0 \
        -p OOMPolicy=stop \
        "$0" --shellcheck-only "${shell_files[@]}"
else
    run_shellcheck_files "${shell_files[@]}"
fi
python3 "$repo_root/scripts/check-release-signing-policy.py"

printf 'shell script check passed: shfmt validated %s files; ShellCheck validated production scripts and bounded fixtures; the 20 GiB operations fixture passed bash -n and its runtime suite\n' \
    "${#shell_files[@]}"
