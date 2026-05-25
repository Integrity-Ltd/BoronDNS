#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_manifest="$repo_root/Cargo.toml"

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

allowed_exception="$repo_root/crates/oxidedns-server/src/process_signals.rs"

unsafe_matches="$(
  rg --line-number --glob '*.rs' '\bunsafe\s*(\{|fn|impl|trait|extern)' \
    "$repo_root/crates" "$repo_root/fuzz" \
    --glob '!crates/oxidedns-server/src/process_signals.rs' || true
)"

if [[ -n "$unsafe_matches" ]]; then
  printf 'first-party unsafe construct candidates found:\n%s\n' "$unsafe_matches" >&2
  exit 1
fi

if ! rg --quiet 'libc::signal\(signal, libc::SIG_IGN\)' "$allowed_exception"; then
  echo "signal disposition unsafe exception changed unexpectedly: $allowed_exception" >&2
  exit 1
fi

echo "first-party unsafe scan passed: only audited POSIX signal-disposition exception found"

if command -v cargo-geiger >/dev/null 2>&1; then
  echo "cargo-geiger available; run cargo geiger for transitive dependency unsafe enumeration"
else
  echo "cargo-geiger not installed; transitive dependency unsafe enumeration remains a release-review task"
fi
