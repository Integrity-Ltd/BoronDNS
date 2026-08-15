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

reject_text() {
    local path="$1"
    local needle="$2"
    if grep -F "$needle" "$path" >/dev/null 2>&1; then
        printf '%s contains obsolete policy promise: %s\n' "$path" "$needle" >&2
        exit 1
    fi
}

security_policy="SECURITY.md"
architecture_doc="docs/architecture.md"

require_file "$security_policy"
require_file "$architecture_doc"

for needle in \
    "BDS-NFR-MAINT-008" \
    "security@integrity.hu" \
    "public-beta software" \
    "Historical prereleases; not maintained" \
    "no maintenance branches" \
    "does not promise hotfixes, backports, rebuilt artifacts" \
    "not a support contract or service-level agreement" \
    "do not promise acknowledgement" \
    "no automatic embargo or fixed disclosure window" \
    "CVE" \
    "A CVE is not promised" \
    "Official public release artifacts are cryptographically signed" \
    "Release-specific instructions"; do
    require_text "$security_policy" "$needle"
done

for needle in \
    "within 72 hours" \
    "30 days for severity" \
    "90 days for severity" \
    "default coordinated disclosure window" \
    "recognized CNA" \
    "MITRE direct assignment"; do
    reject_text "$security_policy" "$needle"
done

for needle in \
    "BDS-NFR-MAINT-008" \
    "BDS-VER-015" \
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
