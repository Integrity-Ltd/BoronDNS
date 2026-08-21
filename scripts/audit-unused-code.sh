#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${BORONDNS_UNUSED_CODE_AUDIT_DIR:-$repo_root/target/evidence/unused-code-$$}"
mkdir -p "$artifact_dir"

run_and_capture() {
    local name="$1"
    shift
    local log="$artifact_dir/$name.log"

    {
        printf '$'
        printf ' %q' "$@"
        printf '\n\n'
        "$@"
    } >"$log" 2>&1
}

require_cargo_subcommand() {
    local subcommand="$1"
    if ! cargo "$subcommand" --version >/dev/null 2>&1; then
        printf 'missing required cargo subcommand: cargo %s\n' "$subcommand" >&2
        printf 'install with: cargo install cargo-%s\n' "$subcommand" >&2
        exit 1
    fi
}

require_cargo_subcommand bloat
require_cargo_subcommand machete

{
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'repo_root=%s\n' "$repo_root"
    printf 'commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cargo=%s\n' "$(cargo --version)"
    printf 'cargo_bloat=%s\n' "$(cargo bloat --version)"
    printf 'cargo_machete=%s\n' "$(cargo machete --version)"
} >"$artifact_dir/tool-versions.env"

run_and_capture strict-unused-lints env \
    RUSTFLAGS="-Dunused -Ddead_code -Dunreachable_pub -Dunused_crate_dependencies" \
    cargo check --workspace --lib --bins --tests

run_and_capture cargo-machete cargo machete --with-metadata --skip-target-dir
run_and_capture cargo-bloat-crates-json cargo bloat --release -p borondns-cli --bin borondns \
    --crates -n 0 --message-format json
run_and_capture cargo-bloat-crates-table cargo bloat --release -p borondns-cli --bin borondns \
    --crates -n 40
run_and_capture cargo-bloat-symbols cargo bloat --release -p borondns-cli --bin borondns \
    -n 80 --wide

python3 - "$artifact_dir/cargo-bloat-crates-json.log" "$artifact_dir/linked-crates.tsv" <<'PY'
import json
import sys

log_path, out_path = sys.argv[1:3]
text = open(log_path, encoding="utf-8").read()
start = text.find("{")
if start < 0:
    raise SystemExit("cargo bloat JSON output was not found")

payload = json.loads(text[start:])
crates = payload.get("crates", [])
required = {"borondns", "borondns_core", "borondns_server"}
observed = {entry.get("name") for entry in crates}
missing = sorted(required - observed)
if missing:
    raise SystemExit(f"first-party crates missing from linked binary evidence: {missing}")

with open(out_path, "w", encoding="utf-8") as out:
    out.write("crate\ttext_bytes\n")
    for entry in crates:
        out.write(f"{entry['name']}\t{entry['size']}\n")
PY

{
    printf 'evidence\tstatus\tartifact\tnote\n'
    printf 'compiler-unused-lints\tpass\tstrict-unused-lints.log\t-Dunused -Ddead_code -Dunreachable_pub -Dunused_crate_dependencies passed for workspace libraries, binaries, and tests; examples and benches remain covered by the ordinary all-target compiler gates.\n'
    printf 'unused-dependencies\tpass\tcargo-machete.log\tcargo machete did not find unused manifest dependencies.\n'
    printf 'linked-binary-crates\tpass\tlinked-crates.tsv\tcargo bloat release-binary crate attribution includes first-party crates that reached the linked borondns binary.\n'
    printf 'linked-binary-symbols\tinformational\tcargo-bloat-symbols.log\tTop linked symbols are retained for release review and dependency-size inspection.\n'
} >"$artifact_dir/unused-code-traceability.tsv"

printf 'unused_code_audit_dir=%s\n' "$artifact_dir"
