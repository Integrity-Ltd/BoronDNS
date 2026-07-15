#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
        \( -name '*.sh' -o -path '*/openrc/oxidedns' \) \
        -print0
)

if ((${#shell_files[@]} == 0)); then
    echo "shell script check passed: no shell files found"
    exit 0
fi

"$repo_root/scripts/check-shell-format.sh" "${shell_files[@]}"
shellcheck "${shell_files[@]}"
python3 "$repo_root/scripts/check-release-signing-policy.py"

printf 'shell script check passed: shfmt and shellcheck validated %s files\n' "${#shell_files[@]}"
