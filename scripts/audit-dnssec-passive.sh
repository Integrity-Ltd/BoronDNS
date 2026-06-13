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
    relative = path.relative_to(repo_root).as_posix()
    if relative.endswith("/src/tests.rs"):
        continue
    if (
        "/src/tests/" in relative
        or "/src/config_tests/" in relative
        or "/src/dns_tests/" in relative
        or "/src/zone_image_tests/" in relative
    ):
        continue
    text = path.read_text(encoding="utf-8")
    marker = "\n#[cfg(test)]\nmod tests"
    if marker in text:
        text = text.split(marker, 1)[0]
    runtime_sources[path.relative_to(repo_root)] = text

lock_text = (repo_root / "Cargo.lock").read_text(encoding="utf-8")
package_names = re.findall(r'^name = "([^"]+)"$', lock_text, flags=re.MULTILINE)

failures: list[str] = []

print("dnssec_passive_audit=started")
print("requirement=ODS-FR-DNSSEC-013")
print("runtime_source_files:")
for path in runtime_sources:
    print(f"  {path}")

zone_text = runtime_sources.get(Path("crates/oxidedns-core/src/zone.rs"), "")
zone_image_text = runtime_sources.get(Path("crates/oxidedns-core/src/zone_image.rs"), "")
axfr_text = runtime_sources.get(Path("crates/oxidedns-core/src/axfr.rs"), "")
dns_text = runtime_sources.get(Path("crates/oxidedns-core/src/dns.rs"), "")

required_fragments = [
    ("transfer RRSIG RDATA validation only", "RecordType::Rrsig as u16 =>", axfr_text),
    ("transfer DNSKEY RDATA validation only", "RecordType::Dnskey as u16 => validate_dnskey_rdata", axfr_text),
    ("transfer NSEC RDATA validation only", "RecordType::Nsec as u16 => validate_nsec_rdata", axfr_text),
    ("transfer NSEC3 RDATA validation only", "RecordType::Nsec3 as u16 => validate_nsec3_rdata", axfr_text),
    (
        "DO-bit driven augmentation",
        "image.augment_lookup_plan_with_dnssec_ascii_lowercase_hint",
        dns_text,
    ),
    ("RRSIGs selected from stored RRsets", "add_rrsig_augmentations", zone_image_text),
    (
        "DNSSEC records pushed from stored RRsets",
        "fn push_authority_rrset(",
        zone_image_text,
    ),
    ("non-DO suppression path", "is_dnssec_proof_or_signature_type", zone_text + dns_text),
]

print()
print("check=passive_dnssec_serving_surface")
missing = [label for label, fragment, text in required_fragments if fragment not in text]
if missing:
    print("status=failed")
    for label in missing:
        print(f"  missing={label}")
    failures.append("passive DNSSEC serving evidence missing")
else:
    print("status=passed")
    print("evidence=DNSSEC code validates transferred RDATA, selects stored proof/signature RRsets, and suppresses augmentation when DO=0.")

dnssec_rr_patterns = [
    r"RecordType::Rrsig",
    r"RecordType::Nsec3Param",
    r"RecordType::Nsec3",
    r"RecordType::Nsec",
    r"RecordType::Dnskey",
    r"RecordType::Ds",
]
construction_patterns = [
    re.compile(rf"rr_type\s*:\s*{pattern}") for pattern in dnssec_rr_patterns
] + [
    re.compile(rf"Rrset::new\([^)]*{pattern}", re.DOTALL) for pattern in dnssec_rr_patterns
]

print()
print("check=no_first_party_dnssec_record_generation")
construction_matches: list[str] = []
for path, text in runtime_sources.items():
    for pattern in construction_patterns:
        for match in pattern.finditer(text):
            line_number = text[: match.start()].count("\n") + 1
            line = text.splitlines()[line_number - 1].strip()
            construction_matches.append(f"{path}:{line_number}: {line}")

if construction_matches:
    print("status=failed")
    for match in construction_matches:
        print(f"  {match}")
    failures.append("first-party runtime DNSSEC record construction was found")
else:
    print("status=passed")
    print("evidence=No production source constructs DNSSEC ResourceRecord or Rrset values with fixed DNSSEC RR types.")

forbidden_terms = [
    re.compile(r"\bDNSSEC[A-Za-z0-9_]*(Signer|Signing|Validator|Validation|Key|Rollover)\b"),
    re.compile(r"\b(sign|verify|validate)_dnssec\b", re.IGNORECASE),
    re.compile(r"\bon[_-]?the[_-]?fly[_-]?sign", re.IGNORECASE),
    re.compile(r"\brfc5011\b", re.IGNORECASE),
    re.compile(r"\bkey[_-]?rollover\b", re.IGNORECASE),
    re.compile(r"\bzone[_-]?signing[_-]?key\b", re.IGNORECASE),
    re.compile(r"\bkey[_-]?signing[_-]?key\b", re.IGNORECASE),
]

print()
print("check=no_dnssec_signing_validation_or_rollover_surface")
term_matches: list[str] = []
for path, text in runtime_sources.items():
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in forbidden_terms:
            if pattern.search(line):
                term_matches.append(f"{path}:{line_number}: {line.strip()}")

if term_matches:
    print("status=failed")
    for match in term_matches:
        print(f"  {match}")
    failures.append("DNSSEC signing/validation/rollover surface terms were found")
else:
    print("status=passed")
    print("evidence=No first-party runtime source exposes DNSSEC signing, signature validation, DNSSEC key management, or RFC 5011 rollover surfaces.")

blocked_packages = {
    "trust-dns-resolver",
    "trust-dns-server",
    "trust-dns-proto",
    "hickory-resolver",
    "hickory-server",
    "hickory-dnssec",
}
package_matches = [name for name in package_names if name.lower() in blocked_packages]

print()
print("check=no_dnssec_signer_validator_dependency")
if package_matches:
    print("status=failed")
    for name in package_matches:
        print(f"  package={name}")
    failures.append("DNSSEC signer/validator dependency was found")
else:
    print("status=passed")
    print("evidence=No DNSSEC signer, validator, resolver, or authoritative-server framework crate appears in Cargo.lock.")

if failures:
    print()
    print("dnssec_passive_audit=failed")
    for failure in failures:
        print(f"failure={failure}")
    raise SystemExit(1)

print()
print("dnssec_passive_audit=passed")
PY
