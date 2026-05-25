#!/usr/bin/env bash
set -euo pipefail

require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        printf 'missing required file: %s\n' "$path" >&2
        exit 66
    fi
}

require_text() {
    local path="$1"
    local needle="$2"
    if ! grep -F "$needle" "$path" >/dev/null 2>&1; then
        printf '%s missing required text: %s\n' "$path" "$needle" >&2
        exit 1
    fi
}

security_policy="SECURITY.md"
architecture_doc="docs/architecture.md"

require_file "$security_policy"
require_file "$architecture_doc"

for needle in \
    "ODS-NFR-SEC-007" \
    "ODS-NFR-MAINT-008" \
    "security@integrity.hu" \
    "72 hours" \
    "30 days" \
    "90 days" \
    "CVE" \
    "recognized CNA" \
    "MITRE direct" \
    "coordinated disclosure window" \
    "Sigstore/Cosign" \
    "cosign verify-blob" \
    "OpenPGP" \
    "public signing" \
    "rotated at least annually" \
    "reviewed for every release candidate"; do
    require_text "$security_policy" "$needle"
done

for needle in \
    "ODS-NFR-MAINT-008" \
    "ODS-VER-015" \
    "Sigstore/Cosign" \
    "Architecture Owner" \
    "Release engineer" \
    "CI scheduler" \
    "Third-party security specialist" \
    "held by DT" \
    "release notes"; do
    require_text "$architecture_doc" "$needle"
done

require_text "README.md" "SECURITY.md"
require_text "README.md" "docs/architecture.md"
require_text "docs/README.md" "architecture.md"

printf 'Security policy check passed: %s, %s\n' "$security_policy" "$architecture_doc"
