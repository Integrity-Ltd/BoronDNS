#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${OXIDEDNS_CLI_EVIDENCE_DIR:-$repo_root/target/cli-evidence}"
mkdir -p "$evidence_dir"

run_capture() {
    local name="$1"
    shift
    local stdout="$evidence_dir/$name.stdout"
    local stderr="$evidence_dir/$name.stderr"
    local status_file="$evidence_dir/$name.status"

    set +e
    "$@" >"$stdout" 2>"$stderr"
    local status=$?
    set -e

    printf '%s\n' "$status" >"$status_file"
    if ((status != 0)); then
        printf 'CLI evidence command failed (%s), status=%s\n' "$name" "$status" >&2
        sed -n '1,80p' "$stderr" >&2
        exit "$status"
    fi
}

require_text() {
    local path="$1"
    local needle="$2"
    if ! grep -F -- "$needle" "$path" >/dev/null 2>&1; then
        printf '%s missing required text: %s\n' "$path" "$needle" >&2
        exit 1
    fi
}

cd "$repo_root"

repo_relative_path() {
    local path="$1"
    realpath --relative-to="$repo_root" "$path"
}

example_config_path="$(repo_relative_path "$evidence_dir/example-config.stdout")"
redaction_config="$evidence_dir/dump-redaction-input.toml"
cat >"$redaction_config" <<'EOF'
[server]
listen_udp = ["127.0.0.1:5300"]
listen_tcp = ["127.0.0.1:5300"]
health = "127.0.0.1:8080"

[[zones]]
name = "example.test."
primaries = ["192.0.2.53:53"]
tsig_key = "transfer-key."

[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret = "c2VjcmV0LWtleQ=="
EOF
redaction_config_path="$(repo_relative_path "$redaction_config")"

run_capture version-long cargo run -q -p oxidedns-cli -- --version
run_capture version-short cargo run -q -p oxidedns-cli -- -V
run_capture help-long cargo run -q -p oxidedns-cli -- --help
run_capture help-short cargo run -q -p oxidedns-cli -- -h
run_capture example-config cargo run -q -p oxidedns-cli -- --example-config
run_capture example-config-validate cargo run -q -p oxidedns-cli -- \
    --validate-config "$example_config_path"
run_capture checked-in-config-validate cargo run -q -p oxidedns-cli -- \
    --validate-config config/oxidedns.example.toml
run_capture checked-in-config-dump cargo run -q -p oxidedns-cli -- \
    --dump-config config/oxidedns.example.toml
run_capture redacted-config-dump cargo run -q -p oxidedns-cli -- \
    --dump-config "$redaction_config_path"

require_text "$evidence_dir/version-long.stdout" "oxidedns 0.1.0"
require_text "$evidence_dir/version-long.stdout" "build commit:"
require_text "$evidence_dir/version-long.stdout" "rustc:"
require_text "$evidence_dir/version-short.stdout" "oxidedns 0.1.0"

require_text "$evidence_dir/help-long.stdout" "--version"
require_text "$evidence_dir/help-long.stdout" "--help"
require_text "$evidence_dir/help-long.stdout" "--example-config"
require_text "$evidence_dir/help-long.stdout" "/etc/oxidedns-secondary/config.toml"
require_text "$evidence_dir/help-short.stdout" "--validate-config"

require_text "$evidence_dir/example-config.stdout" "[server]"
require_text "$evidence_dir/example-config.stdout" "[[zones]]"
require_text "$evidence_dir/example-config-validate.stdout" "configuration ok"
require_text "$evidence_dir/checked-in-config-validate.stdout" "configuration ok"
require_text "$evidence_dir/checked-in-config-dump.stdout" "[server]"
require_text "$evidence_dir/redacted-config-dump.stdout" "secret = \"<redacted>\""
if grep -F -- "c2VjcmV0LWtleQ==" "$evidence_dir/redacted-config-dump.stdout" >/dev/null 2>&1; then
    printf 'redacted config dump leaked TSIG secret material\n' >&2
    exit 1
fi

cat >"$evidence_dir/README.md" <<EOF
# OxideDNS CLI Evidence

Captured CLI invocation outputs for SRS process-lifecycle requirements:

- ODS-IF-PROC-002: --version and -V
- ODS-IF-PROC-003: --help and -h
- ODS-IF-PROC-004: --example-config plus validation
- ODS-IF-CONF-009: --dump-config redacted effective configuration output
- ODS-IF-CONF-010: --validate-config checked-in configuration validation

Each command stores stdout, stderr, and exit status in this directory.
EOF

printf 'CLI evidence captured in %s\n' "$evidence_dir"
