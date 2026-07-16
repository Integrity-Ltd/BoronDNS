#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
artifact_dir="${BORONDNS_PRIMARY_MATRIX_ARTIFACT_DIR:-$repo_root/target/evidence/primary-matrix-$run_id}"
summary_tsv="$artifact_dir/primary-matrix-summary.tsv"
traceability_tsv="$artifact_dir/primary-matrix-traceability.tsv"

mkdir -p "$artifact_dir"

cat >"$summary_tsv" <<'EOF'
primary	capability	script	status	exit_code	artifact_dir
EOF

cat >"$traceability_tsv" <<'EOF'
requirement_family	primary	capability	evidence
BDS-FR-AXFR	BIND	axfr	bind-axfr/primary-version.txt; bind-axfr/axfr-traceability.tsv
BDS-FR-TSIG	BIND	tsig_axfr	bind-tsig-axfr/primary-version.txt; bind-tsig-axfr/bind-tsig-axfr-summary.env
BDS-FR-NOTIFY	BIND	notify_refresh	bind-notify-refresh/primary-version.txt; bind-notify-refresh/bind-notify-traceability.tsv
BDS-FR-IXFR	BIND	ixfr_refresh	bind-ixfr-refresh/primary-version.txt; bind-ixfr-refresh/bind-ixfr-refresh-summary.env
BDS-FR-AXFR	NSD	axfr	nsd-axfr/primary-version.txt; nsd-axfr/axfr-traceability.tsv
BDS-FR-TSIG	NSD	tsig_axfr	nsd-tsig-axfr/primary-version.txt; nsd-tsig-axfr/nsd-tsig-axfr-summary.env
BDS-FR-NOTIFY	NSD	notify_refresh	nsd-notify-refresh/primary-version.txt; nsd-notify-refresh/nsd-notify-traceability.tsv
BDS-FR-AXFR	Knot	axfr	knot-axfr/primary-version.txt; knot-axfr/axfr-traceability.tsv
BDS-FR-TSIG	Knot	tsig_axfr	knot-tsig-axfr/primary-version.txt; knot-tsig-axfr/knot-tsig-axfr-summary.env
BDS-FR-NOTIFY	Knot	notify_refresh	knot-notify-refresh/primary-version.txt; knot-notify-refresh/knot-notify-traceability.tsv
BDS-FR-IXFR	Knot	ixfr_refresh	knot-ixfr-refresh/primary-version.txt; knot-ixfr-refresh/knot-ixfr-refresh-summary.env
BDS-FR-PROV	PowerDNS	catalog_tsig	powerdns-postgres-catalog-tsig/primary-version.txt; powerdns-postgres-catalog-tsig/powerdns-postgres-catalog-tsig-traceability.tsv
EOF

failures=0
skips=0

run_case() {
    local primary="$1"
    local capability="$2"
    local case_name="$3"
    local env_name="$4"
    local script="$5"
    local case_dir="$artifact_dir/$case_name"
    local output="$case_dir/output.log"
    local status outcome

    mkdir -p "$case_dir"
    printf 'running %s %s via %s\n' "$primary" "$capability" "$script"
    set +e
    env "$env_name=$case_dir" "$repo_root/$script" >"$output" 2>&1
    status=$?
    set -e

    if grep -qi '^skipping ' "$output"; then
        outcome="skipped"
        skips=$((skips + 1))
    elif ((status == 0)); then
        outcome="passed"
    else
        outcome="failed"
        failures=$((failures + 1))
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$primary" "$capability" "$script" "$outcome" "$status" "$case_dir" >>"$summary_tsv"

    if [[ "$outcome" != "passed" ]]; then
        printf '%s %s %s (exit %s); see %s\n' "$primary" "$capability" "$outcome" "$status" "$output" >&2
    fi
}

run_case "BIND" "axfr" "bind-axfr" "BORONDNS_BIND_AXFR_ARTIFACT_DIR" "scripts/interop-bind-axfr.sh"
run_case "BIND" "tsig_axfr" "bind-tsig-axfr" "BORONDNS_BIND_TSIG_AXFR_ARTIFACT_DIR" "scripts/interop-bind-tsig-axfr.sh"
run_case "BIND" "notify_refresh" "bind-notify-refresh" "BORONDNS_BIND_NOTIFY_ARTIFACT_DIR" "scripts/interop-bind-notify-refresh.sh"
run_case "BIND" "ixfr_refresh" "bind-ixfr-refresh" "BORONDNS_BIND_IXFR_ARTIFACT_DIR" "scripts/interop-bind-ixfr-refresh.sh"
run_case "NSD" "axfr" "nsd-axfr" "BORONDNS_NSD_AXFR_ARTIFACT_DIR" "scripts/interop-nsd-axfr-docker.sh"
run_case "NSD" "tsig_axfr" "nsd-tsig-axfr" "BORONDNS_NSD_TSIG_AXFR_ARTIFACT_DIR" "scripts/interop-nsd-tsig-axfr-docker.sh"
run_case "NSD" "notify_refresh" "nsd-notify-refresh" "BORONDNS_NSD_NOTIFY_ARTIFACT_DIR" "scripts/interop-nsd-notify-refresh-docker.sh"
run_case "Knot" "axfr" "knot-axfr" "BORONDNS_KNOT_AXFR_ARTIFACT_DIR" "scripts/interop-knot-axfr-docker.sh"
run_case "Knot" "tsig_axfr" "knot-tsig-axfr" "BORONDNS_KNOT_TSIG_AXFR_ARTIFACT_DIR" "scripts/interop-knot-tsig-axfr-docker.sh"
run_case "Knot" "notify_refresh" "knot-notify-refresh" "BORONDNS_KNOT_NOTIFY_ARTIFACT_DIR" "scripts/interop-knot-notify-refresh-docker.sh"
run_case "Knot" "ixfr_refresh" "knot-ixfr-refresh" "BORONDNS_KNOT_IXFR_ARTIFACT_DIR" "scripts/interop-knot-ixfr-refresh-docker.sh"
run_case "PowerDNS" "catalog_tsig" "powerdns-postgres-catalog-tsig" "BORONDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR" "scripts/interop-powerdns-postgres-catalog-tsig-docker.sh"

if ((failures > 0 || skips > 0)); then
    printf 'primary matrix incomplete failures=%s skips=%s artifact_dir=%s\n' "$failures" "$skips" "$artifact_dir" >&2
    exit 1
fi

printf 'primary matrix passed cases=12 artifact_dir=%s\n' "$artifact_dir"
