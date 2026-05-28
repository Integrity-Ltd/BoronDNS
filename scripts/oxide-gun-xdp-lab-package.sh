#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/oxide-gun-xdp-lab-package.sh EVIDENCE_DIR

Validates an OxideGun XDP lab evidence directory, writes a SHA-256 manifest
inside it, and creates a tar.gz package under target/oxide-gun-xdp-evidence-packages.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi
if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

evidence_dir="$1"
if [[ ! -d "$evidence_dir" ]]; then
    echo "evidence directory does not exist: $evidence_dir" >&2
    exit 1
fi

required_files=(
    command.txt
    config.toml
    evidence-summary.json
    ip-link-after.json
    ip-link-before.json
    metadata.txt
    oxide-gun.jsonl
    summary.json
    preflight/summary.json
)
for required in "${required_files[@]}"; do
    if [[ ! -f "$evidence_dir/$required" ]]; then
        echo "required evidence file is missing: $evidence_dir/$required" >&2
        exit 1
    fi
done

command -v find >/dev/null
command -v python3 >/dev/null
command -v sha256sum >/dev/null
command -v tar >/dev/null

python3 - "$evidence_dir/evidence-summary.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    evidence = json.load(handle)

preflight = evidence.get("preflight", {})
failures = evidence.get("threshold_failures", [])
if failures:
    raise SystemExit(f"threshold_failures is not empty: {failures!r}")
if not evidence.get("oxide_gun"):
    raise SystemExit("oxide_gun summary is missing from evidence-summary.json")
if not preflight:
    raise SystemExit("preflight summary is missing from evidence-summary.json")
print(
    "evidence_scope="
    f"{preflight.get('evidence_scope', 'unknown')} "
    "saturation_claim_allowed="
    f"{preflight.get('saturation_claim_allowed', False)}"
)
PY

manifest="$evidence_dir/artifact-manifest.sha256"
(
    cd "$evidence_dir"
    find . -type f \
        ! -name artifact-manifest.sha256 \
        ! -name '*.tar.gz' \
        -print0 \
        | sort -z \
        | xargs -0 sha256sum
) >"$manifest"

package_dir="$repo_root/target/oxide-gun-xdp-evidence-packages"
mkdir -p "$package_dir"
evidence_name="$(basename "$evidence_dir")"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
package="$package_dir/${evidence_name}-${timestamp}.tar.gz"
tar -C "$(dirname "$evidence_dir")" -czf "$package" "$(basename "$evidence_dir")"
sha256sum "$package" >"$package.sha256"

printf 'oxide-gun XDP lab evidence package: %s\n' "$package"
printf 'oxide-gun XDP lab evidence package sha256: %s.sha256\n' "$package"
