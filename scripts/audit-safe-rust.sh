#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_manifest="$repo_root/Cargo.toml"
unsafe_boundary_registry="$repo_root/docs/unsafe-boundaries.tsv"

python3 - "$workspace_manifest" <<'PY'
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError as exc:
    raise SystemExit("python tomllib is required to inspect Cargo.toml") from exc

manifest = Path(sys.argv[1])
data = tomllib.loads(manifest.read_text())
unsafe_code = (
    data.get("workspace", {})
    .get("lints", {})
    .get("rust", {})
    .get("unsafe_code")
)
if unsafe_code != "forbid":
    raise SystemExit(
        f"{manifest} must keep [workspace.lints.rust] unsafe_code = \"forbid\""
    )
print("workspace lint check passed: unsafe_code = \"forbid\"")
PY

python3 "$repo_root/scripts/check-unsafe-boundaries.py"

process_signals_exception="$repo_root/crates/oxidedns-server/src/process_signals.rs"
resource_limits_exception="$repo_root/crates/oxidedns-server/src/resource_limits.rs"
mapfile -t current_unsafe_adapter_paths < <(
  python3 - "$unsafe_boundary_registry" <<'PY'
import csv
import sys
from pathlib import Path

with Path(sys.argv[1]).open(newline="", encoding="utf-8") as handle:
    for row in csv.DictReader(handle, delimiter="\t"):
        if row["status"] == "current" and not row["path"].startswith("future:"):
            print(row["path"])
PY
)

allow_attr_matches="$(
  rg --line-number --glob '*.rs' '#!?\[allow\(unsafe_code\)\]' \
    "$repo_root/crates" "$repo_root/fuzz" || true
)"

unexpected_allow_attrs=()
if [[ -n "$allow_attr_matches" ]]; then
  while IFS= read -r match; do
    absolute_path="${match%%:*}"
    relative_path="${absolute_path#"$repo_root/"}"
    allowed=0
    for allowed_path in "${current_unsafe_adapter_paths[@]}"; do
      if [[ "$relative_path" == "$allowed_path" ]]; then
        allowed=1
        break
      fi
    done
    if [[ "$allowed" -ne 1 ]]; then
      unexpected_allow_attrs+=("$match")
    fi
  done <<< "$allow_attr_matches"
fi

if [[ "${#unexpected_allow_attrs[@]}" -ne 0 ]]; then
  printf 'unexpected unsafe_code allow attributes found:\n' >&2
  printf '%s\n' "${unexpected_allow_attrs[@]}" >&2
  echo "new unsafe-capable modules require an explicit safe-Rust audit allowlist entry, dedicated adapter tests, and architecture documentation" >&2
  exit 1
fi

echo "unsafe allowlist check passed: only audited registry adapter modules may opt into unsafe_code"

unsafe_exclude_globs=()
for adapter_path in "${current_unsafe_adapter_paths[@]}"; do
  unsafe_exclude_globs+=(--glob "!$adapter_path")
done
unsafe_matches="$(
  rg --line-number --glob '*.rs' "${unsafe_exclude_globs[@]}" \
    '\bunsafe\s*(\{|fn|impl|trait|extern)' \
    "$repo_root/crates" "$repo_root/fuzz" || true
)"

if [[ -n "$unsafe_matches" ]]; then
  printf 'first-party unsafe construct candidates found:\n%s\n' "$unsafe_matches" >&2
  exit 1
fi

if ! rg --quiet 'libc::signal\(signal, libc::SIG_IGN\)' "$process_signals_exception"; then
  echo "signal disposition unsafe exception changed unexpectedly: $process_signals_exception" >&2
  exit 1
fi

if ! rg --quiet 'libc::getrlimit\(libc::RLIMIT_NOFILE' "$resource_limits_exception"; then
  echo "resource-limit unsafe exception changed unexpectedly: $resource_limits_exception" >&2
  exit 1
fi

adapter_absolute_paths=()
for adapter_path in "${current_unsafe_adapter_paths[@]}"; do
  adapter_absolute_paths+=("$repo_root/$adapter_path")
done
python3 - "${adapter_absolute_paths[@]}" <<'PY'
import sys
from pathlib import Path

failures = []
for filename in sys.argv[1:]:
    path = Path(filename)
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if "unsafe {" not in line:
            continue
        context = "\n".join(lines[max(0, index - 4):index])
        if "SAFETY:" not in context:
            failures.append(f"{path}:{index + 1}: unsafe block lacks preceding SAFETY rationale")

if failures:
    raise SystemExit("\n".join(failures))

print("unsafe rationale check passed: audited unsafe blocks have SAFETY comments")
PY

echo "first-party unsafe scan passed: only audited registry adapter exceptions found"

if command -v cargo-geiger >/dev/null 2>&1; then
  echo "cargo-geiger available; retain transitive unsafe enumeration with scripts/capture-unsafe-dependency-evidence.sh"
else
  echo "cargo-geiger not installed; run scripts/capture-unsafe-dependency-evidence.sh after installing cargo-geiger for release-review transitive unsafe enumeration"
fi
