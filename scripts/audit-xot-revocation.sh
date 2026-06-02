#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
from pathlib import Path
import re
import sys

repo_root = Path(sys.argv[1])

runtime_sources: dict[Path, str] = {}
for path in sorted((repo_root / "crates").glob("*/src/**/*.rs")):
    if path.relative_to(repo_root).as_posix().endswith("/src/tests.rs"):
        continue
    text = path.read_text(encoding="utf-8")
    marker = "\n#[cfg(test)]\nmod tests"
    if marker in text:
        text = text.split(marker, 1)[0]
    runtime_sources[path.relative_to(repo_root)] = text

lock_text = (repo_root / "Cargo.lock").read_text(encoding="utf-8")
package_names = re.findall(r'^name = "([^"]+)"$', lock_text, flags=re.MULTILINE)

failures: list[str] = []

print("xot_revocation_audit=started")
print("requirement=ODS-FR-XOT-012")
print("runtime_source_files:")
for path in runtime_sources:
    print(f"  {path}")

xot_source = runtime_sources.get(Path("crates/oxidedns-server/src/transfer.rs"), "")
required_fragments = [
    ("tokio-rustls client connector", "TlsConnector"),
    ("rustls client config", "ClientConfig"),
    ("local root trust store", "RootCertStore"),
    ("configured PEM trust anchors", "load_pem_certs_for_primary"),
    ("XoT client config builder", "build_xot_client_config"),
]

print()
print("check=xot_tls_stack")
missing_fragments = [label for label, fragment in required_fragments if fragment not in xot_source]
if missing_fragments:
    print("status=failed")
    for label in missing_fragments:
        print(f"  missing={label}")
    failures.append("XoT TLS stack evidence missing")
else:
    print("status=passed")
    print("evidence=XoT uses tokio-rustls/rustls with configured PEM trust anchors and local RootCertStore.")

revocation_patterns = [
    re.compile(r"\bocsp\b", re.IGNORECASE),
    re.compile(r"\bcrl\b", re.IGNORECASE),
    re.compile(r"\brevocation\b", re.IGNORECASE),
    re.compile(r"\bCertificateRevocationList\b"),
]

print()
print("check=no_first_party_crl_ocsp_revocation_code")
source_matches: list[str] = []
for path, text in runtime_sources.items():
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in revocation_patterns:
            if pattern.search(line):
                source_matches.append(f"{path}:{line_number}: {line.strip()}")

if source_matches:
    print("status=failed")
    for match in source_matches:
        print(f"  {match}")
    failures.append("first-party runtime revocation code was found")
else:
    print("status=passed")
    print("evidence=No first-party runtime source references OCSP, CRL, or revocation APIs.")

blocked_packages = {
    "ocsp",
    "crl",
    "openssl",
    "native-tls",
    "reqwest",
    "ureq",
    "isahc",
    "curl",
}
package_matches = [
    name for name in package_names if name.lower() in blocked_packages or "ocsp" in name.lower()
]

print()
print("check=no_revocation_or_http_client_dependency")
if package_matches:
    print("status=failed")
    for name in package_matches:
        print(f"  package={name}")
    failures.append("revocation or standalone HTTP/TLS client dependency was found")
else:
    print("status=passed")
    print("evidence=No OCSP/CRL, OpenSSL/native-tls, or standalone HTTP-client crate appears in Cargo.lock.")

print()
print("ocsp_stapling_posture")
print("status=not_supported_by_current_client_path")
print("evidence=No first-party rustls client call requests or consumes OCSP stapling data; under ODS-FR-XOT-012 this reduces the implementation posture to no revocation checking.")

if failures:
    print()
    print("xot_revocation_audit=failed")
    for failure in failures:
        print(f"failure={failure}")
    raise SystemExit(1)

print()
print("xot_revocation_audit=passed")
PY
