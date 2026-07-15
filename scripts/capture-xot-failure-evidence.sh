#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_XOT_FAILURE_EVIDENCE_DIR:-$repo_root/target/evidence/xot-failure-$timestamp}"
logs_dir="$evidence_dir/logs"
summary_tsv="$evidence_dir/xot-failure-summary.tsv"
env_file="$evidence_dir/xot-failure-env.env"

missing=()
for tool in cargo rustc date git uname; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping XoT failure evidence: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

mkdir -p "$logs_dir"

git_status_output=""
git_status_ok=1
if ! git_status_output="$(git -C "$repo_root" status --porcelain)"; then
    git_status_ok=0
fi

{
    printf 'captured_at_utc=%s\n' "$timestamp"
    printf 'source_commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD)"
    if [[ "$git_status_ok" != 1 ]]; then
        printf 'dirty_checkout=unknown\n'
    elif [[ -z "$git_status_output" ]]; then
        printf 'dirty_checkout=no\n'
    else
        printf 'dirty_checkout=yes\n'
    fi
    printf 'host=%s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf 'kernel=%s\n' "$(uname -a)"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cargo=%s\n' "$(cargo --version)"
    if command -v openssl >/dev/null 2>&1; then
        printf 'openssl=%s\n' "$(openssl version)"
    else
        printf 'openssl=not-installed\n'
    fi
} >"$env_file"

printf 'case\trequirements\tcovered_behavior\tresult\tlog\n' >"$summary_tsv"

failed=0

run_case() {
    local name="$1"
    local requirements="$2"
    local covered_behavior="$3"
    local test_filter="$4"
    local log_file="$logs_dir/$name.log"

    printf 'running %s\n' "$name"
    set +e
    (
        cd "$repo_root"
        cargo test -p oxidedns-server "$test_filter" -- --nocapture
    ) >"$log_file" 2>&1
    local status=$?
    set -e

    if ((status == 0)); then
        printf '%s\t%s\t%s\tpassed\t%s\n' \
            "$name" "$requirements" "$covered_behavior" "${log_file#"$evidence_dir"/}" \
            >>"$summary_tsv"
    else
        printf '%s\t%s\t%s\tfailed\t%s\n' \
            "$name" "$requirements" "$covered_behavior" "${log_file#"$evidence_dir"/}" \
            >>"$summary_tsv"
        failed=1
        printf 'case %s failed, tail follows:\n' "$name" >&2
        tail -120 "$log_file" >&2 || true
    fi
}

run_case \
    "handshake-no-cleartext-fallback" \
    "ODS-FR-XOT-005;ODS-NEG-016" \
    "TLS handshake failure is reported as XoT failure and does not retry the primary over cleartext TCP." \
    "refresh_xot_handshake_failure_does_not_retry_cleartext"

run_case \
    "certificate-name-mismatch" \
    "ODS-FR-XOT-003;ODS-FR-XOT-005" \
    "Certificate name mismatch aborts before any DNS transfer query is sent." \
    "refresh_xot_rejects_certificate_name_mismatch_before_query"

run_case \
    "missing-dot-alpn" \
    "ODS-FR-XOT-002;ODS-FR-XOT-005" \
    "Missing negotiated dot ALPN aborts before any DNS transfer query is sent and emits the ALPN failure log event." \
    "refresh_xot_rejects_missing_dot_alpn_before_query"

run_case \
    "tls12-only-primary" \
    "ODS-FR-XOT-001;ODS-FR-XOT-005" \
    "TLS 1.2-only primaries fail the TLS profile before AXFR is sent." \
    "refresh_xot_rejects_tls12_only_primary_before_query"

run_case \
    "untrusted-certificate" \
    "ODS-FR-XOT-003;ODS-FR-XOT-005" \
    "Untrusted XoT certificate aborts before any DNS transfer query is sent." \
    "refresh_xot_rejects_untrusted_certificate_before_query"

run_case \
    "expired-certificate" \
    "ODS-FR-XOT-003;ODS-FR-XOT-005" \
    "Expired XoT certificate aborts before any DNS transfer query is sent." \
    "refresh_xot_rejects_expired_certificate_before_query"

run_case \
    "mtls-client-certificate" \
    "ODS-FR-XOT-004" \
    "Configured client certificate is presented and mTLS XoT AXFR publishes the transferred serial." \
    "refresh_xot_uses_configured_client_certificate"

run_case \
    "missing-mtls-client-certificate" \
    "ODS-FR-XOT-004;ODS-FR-XOT-005" \
    "mTLS primary requiring a client certificate rejects the transfer before any DNS query is sent." \
    "refresh_xot_rejects_missing_client_certificate_before_query"

run_case \
    "missing-trust-anchor-file" \
    "ODS-FR-XOT-003;ODS-CFG-001" \
    "Runtime validation rejects XoT trust anchor paths that cannot be read." \
    "runtime_config_validation_rejects_missing_xot_trust_anchor_file"

run_case \
    "malformed-trust-anchor-file" \
    "ODS-FR-XOT-003;ODS-CFG-001" \
    "Runtime validation rejects malformed XoT trust anchor PEM files." \
    "runtime_config_validation_rejects_malformed_xot_trust_anchor_file"

if ((failed != 0)); then
    printf 'XoT failure evidence failed; artifacts retained at %s\n' "$evidence_dir" >&2
    exit 1
fi

printf 'XoT failure evidence captured at %s\n' "$evidence_dir"
