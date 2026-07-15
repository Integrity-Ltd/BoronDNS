#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${BORONDNS_COVERAGE_EVIDENCE_DIR:-$repo_root/target/evidence/coverage-$$}"
mkdir -p "$artifact_dir"

for candidate in "${CARGO_HOME:-$HOME/.cargo}/bin" /cache/cargo/bin; do
    if [[ -x "$candidate/cargo-llvm-cov" ]]; then
        PATH="$candidate:$PATH"
    fi
done
export PATH

missing=()
for tool in cargo python3 rustc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required tool for coverage evidence: %s\n' "${missing[*]}" >&2
    exit 1
fi
if ! cargo llvm-cov --version >/dev/null 2>&1; then
    printf 'missing required cargo subcommand: cargo llvm-cov\n' >&2
    printf 'install with: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked\n' >&2
    exit 1
fi

{
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'repo_root=%s\n' "$repo_root"
    printf 'commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cargo=%s\n' "$(cargo --version)"
    printf 'cargo_llvm_cov=%s\n' "$(cargo llvm-cov --version)"
    if command -v rustup >/dev/null 2>&1; then
        rustup component list --installed | grep -E '^llvm-tools|^rust-src' || true
    fi
} >"$artifact_dir/tool-versions.env"

summary_json="$artifact_dir/coverage-summary.json"
coverage_log="$artifact_dir/cargo-llvm-cov.log"
case "$artifact_dir" in
"$repo_root"/*) cargo_artifact_dir="${artifact_dir#"$repo_root"/}" ;;
*) cargo_artifact_dir="$artifact_dir" ;;
esac
cargo_summary_json="$cargo_artifact_dir/coverage-summary.json"

cd "$repo_root"
{
    printf '$ cargo llvm-cov --workspace --summary-only --json --output-path %q -- --test-threads=1\n\n' "$cargo_summary_json"
    cargo llvm-cov \
        --workspace \
        --summary-only \
        --json \
        --output-path "$cargo_summary_json" \
        -- \
        --test-threads=1
} >"$coverage_log" 2>&1

python3 - "$summary_json" "$artifact_dir" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
artifact_dir = Path(sys.argv[2])
payload = json.loads(summary_path.read_text(encoding="utf-8"))
data = payload.get("data") or []
if not data:
    raise SystemExit("coverage summary does not contain data")

report = data[0]
totals = report.get("totals", {})
total_lines = totals.get("lines", {})
overall_percent = float(total_lines.get("percent", 0.0))

overall_min = 70.0
parser_min = 85.0
parser_files = {
    "crates/borondns-core/src/dns.rs": "DNS message parser, EDNS options, RR-type decoders, and DNS Cookie computation",
    "crates/borondns-core/src/axfr.rs": "AXFR/IXFR transfer stream parser",
    "crates/borondns-core/src/tsig.rs": "TSIG verifier",
    "crates/borondns-server/src/lib.rs": "XoT TLS/X.509 handling",
}

files = {}
for entry in report.get("files", []):
    filename = str(entry.get("filename", ""))
    summary = entry.get("summary", {})
    lines = summary.get("lines", {})
    for suffix in parser_files:
        if filename.endswith(suffix):
            files[suffix] = {
                "filename": filename,
                "count": int(lines.get("count", 0)),
                "covered": int(lines.get("covered", 0)),
                "percent": float(lines.get("percent", 0.0)),
            }

missing = sorted(set(parser_files) - set(files))
if missing:
    raise SystemExit(f"coverage summary missing parser/XoT files: {missing}")

with (artifact_dir / "coverage-summary.env").open("w", encoding="utf-8") as out:
    out.write(f"overall_line_coverage_percent={overall_percent:.6f}\n")
    out.write(f"overall_line_coverage_min_percent={overall_min:.6f}\n")
    out.write(f"overall_lines_count={int(total_lines.get('count', 0))}\n")
    out.write(f"overall_lines_covered={int(total_lines.get('covered', 0))}\n")
    out.write(f"parser_line_coverage_min_percent={parser_min:.6f}\n")
    for suffix, values in files.items():
        key = suffix.replace("/", "_").replace(".", "_").replace("-", "_")
        out.write(f"{key}_line_coverage_percent={values['percent']:.6f}\n")

with (artifact_dir / "coverage-files.tsv").open("w", encoding="utf-8") as out:
    out.write("file\tcovered_lines\ttotal_lines\tline_coverage_percent\tsrs_scope\n")
    for suffix, scope in parser_files.items():
        values = files[suffix]
        out.write(
            f"{suffix}\t{values['covered']}\t{values['count']}\t"
            f"{values['percent']:.6f}\t{scope}\n"
        )

with (artifact_dir / "coverage-traceability.tsv").open("w", encoding="utf-8") as out:
    out.write("requirement\tstatus\tartifact\tnote\n")
    overall_status = "pass" if overall_percent >= overall_min else "fail"
    out.write(
        "ODS-NFR-MAINT-007\t"
        f"{overall_status}\tcoverage-summary.env; coverage-summary.json\t"
        f"Overall first-party line coverage is {overall_percent:.3f}%, threshold {overall_min:.1f}%.\n"
    )
    for suffix, scope in parser_files.items():
        values = files[suffix]
        status = "pass" if values["percent"] >= parser_min else "fail"
        out.write(
            "ODS-NFR-MAINT-007\t"
            f"{status}\tcoverage-files.tsv\t"
            f"{scope} coverage in {suffix} is {values['percent']:.3f}%, threshold {parser_min:.1f}%.\n"
        )

failures = []
if overall_percent < overall_min:
    failures.append(
        f"overall line coverage {overall_percent:.3f}% is below {overall_min:.1f}%"
    )
for suffix, values in files.items():
    if values["percent"] < parser_min:
        failures.append(
            f"{suffix} line coverage {values['percent']:.3f}% is below {parser_min:.1f}%"
        )

if failures:
    for failure in failures:
        print(f"coverage_failure={failure}", file=sys.stderr)
    raise SystemExit(1)
PY

cat "$artifact_dir/coverage-summary.env"
printf 'coverage_evidence_dir=%s\n' "$artifact_dir"
