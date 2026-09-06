#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "docs" / "engineering-mvp-scope.md"
CHECK = ROOT / "scripts" / "check.sh"
EVIDENCE = ROOT / "scripts" / "engineering-mvp-evidence.sh"
PLAN = ROOT / "docs" / "implementation-plan.md"
GAPS = ROOT / "docs" / "release-acceptance-gap-register.md"
LEDGER = ROOT / "docs" / "verification-ledger.md"
READINESS = ROOT / "docs" / "engineering-mvp-readiness.md"
RELEASE_GUIDE = ROOT / "docs" / "release-evidence-guide.md"
HANDOFF_SCRIPTS = [
    ROOT / "scripts" / "capture-benchmark-handoff.sh",
    ROOT / "scripts" / "capture-info-verbosity-handoff.sh",
    ROOT / "scripts" / "capture-release-handoff.sh",
    ROOT / "scripts" / "capture-reproducible-build-handoff.sh",
    ROOT / "scripts" / "capture-soak-handoff.sh",
]

REQUIRED_SCOPE_REFERENCES = [
    "implemented-feature-scope.md",
    "release-evidence-guide.md",
    "release-acceptance-gap-register.md",
    "scripts/check.sh",
    "scripts/engineering-mvp-evidence.sh",
    "BDS-VER-008",
]

FORBIDDEN_CHECK_COMMANDS = [
    "--duration 86400",
    "--duration 24h",
    "--duration 24H",
    "--iterations 1000",
    "scripts/capture-info-verbosity-handoff.sh",
    "scripts/capture-benchmark-handoff.sh",
    "scripts/capture-soak-handoff.sh",
    "scripts/capture-reproducible-build-handoff.sh",
    "scripts/capture-release-handoff.sh",
]

REQUIRED_EVIDENCE_COMMANDS = [
    "scripts/check-security-policy.sh",
    "scripts/capture-cli-evidence.sh",
    "scripts/capture-log-evidence.sh",
    "scripts/capture-signal-evidence.sh",
    "scripts/capture-health-metrics-evidence.sh",
    "scripts/capture-malformed-query-evidence.sh",
    "scripts/capture-portability-evidence.sh",
    "scripts/capture-resource-evidence.sh",
    "scripts/capture-coverage-evidence.sh",
    "scripts/capture-interface-compatibility-evidence.sh",
    "scripts/audit-unused-code.sh",
    "scripts/check-functional-requirement-references.py",
]

FORBIDDEN_EVIDENCE_RUN_COMMANDS = [
    "./scripts/check.sh",
    "cargo check --manifest-path fuzz/Cargo.toml",
    "scripts/audit-invariants.sh",
    "scripts/audit-readonly-runtime.sh",
    "scripts/audit-spoof-evidence.py",
    "scripts/audit-log-fields.py",
    "scripts/audit-log-lazy-formatting.py",
    "scripts/capture-unsafe-dependency-evidence.sh",
    "scripts/perf-smoke.sh",
    "scripts/interop-negative-responses.sh",
    "scripts/interop-notify-negative.sh",
    "scripts/interop-tcp-truncation-retry.sh",
    "scripts/interop-edns-behavior.sh",
    "scripts/interop-dns-cookie-dig.sh",
    "scripts/interop-ixfr-notimp-fallback.sh",
    "scripts/interop-unknown-rr.sh",
    "scripts/interop-unknown-rr-bad-transfer.sh",
    "scripts/interop-bind-ixfr-refresh.sh",
    "scripts/interop-dnssec-serve.sh",
    "scripts/interop-dnssec-nsec3-serve.sh",
    "scripts/interop-rrl-udp.sh",
    "scripts/interop-bind-axfr.sh",
    "scripts/interop-bind-tsig-axfr.sh",
    "scripts/interop-bind-notify-refresh.sh",
]

FORBIDDEN_HANDOFF_PHRASES = [
    "local project MVP",
    "project MVP in this repository",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def main() -> None:
    scope = normalized(SCOPE)
    for reference in REQUIRED_SCOPE_REFERENCES:
        require(reference in scope, f"{SCOPE}: missing reference: {reference}")

    plan = normalized(PLAN)
    require(
        "implemented-feature-scope.md" in plan,
        f"{PLAN}: missing implemented-feature reference",
    )

    gaps = normalized(GAPS)
    require(
        "BDS-VER-008" in gaps,
        f"{GAPS}: missing release milestone reference",
    )

    ledger = normalized(LEDGER)
    require(
        "release-acceptance-gap-register.md" in ledger,
        f"{LEDGER}: missing acceptance register reference",
    )

    readiness = normalized(READINESS)
    require(
        "BDS-VER-008" in readiness,
        f"{READINESS}: missing release milestone reference",
    )
    require(
        "implemented-feature-scope.md" in readiness,
        f"{READINESS}: missing implemented-feature reference",
    )

    for path in [CHECK, EVIDENCE]:
        script = path.read_text(encoding="utf-8")
        for command in FORBIDDEN_CHECK_COMMANDS:
            require(
                command not in script,
                f"{path}: release-candidate profile must not run {command}",
            )
    check = CHECK.read_text(encoding="utf-8")
    require(
        "scripts/fuzz-campaign.sh --dry-run" in check,
        f"{CHECK}: expected only dry-run fuzz campaign wiring in local checks",
    )
    evidence = EVIDENCE.read_text(encoding="utf-8")
    for command in REQUIRED_EVIDENCE_COMMANDS:
        require(
            command in evidence,
            f"{EVIDENCE}: release-candidate evidence profile must include {command}",
        )
    require(
        "timeout --preserve-status" in evidence,
        f"{EVIDENCE}: release-candidate evidence commands must have a timeout guard",
    )
    require(
        "deferred-not-run.txt" in evidence,
        f"{EVIDENCE}: broader release/operations commands must be recorded as deferred",
    )
    run_lines = [
        line.strip()
        for line in evidence.splitlines()
        if line.strip().startswith("run_and_capture ")
    ]
    for command in FORBIDDEN_EVIDENCE_RUN_COMMANDS:
        for line in run_lines:
            require(
                command not in line,
                f"{EVIDENCE}: release-candidate evidence profile must not run {command}",
            )

    release_guide = normalized(RELEASE_GUIDE)
    for reference in [
        "scripts/engineering-mvp-evidence.sh",
        "scripts/release-evidence-snapshot.sh",
        "deferred-not-run.txt",
        "BORONDNS_EVIDENCE_RUN_INTEROP=1",
        "BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1",
    ]:
        require(
            reference in release_guide,
            f"{RELEASE_GUIDE}: missing evidence profile reference: {reference}",
        )

    for path in HANDOFF_SCRIPTS:
        script = path.read_text(encoding="utf-8")
        for phrase in FORBIDDEN_HANDOFF_PHRASES:
            require(
                phrase not in script,
                f"{path}: stale release-candidate handoff phrase: {phrase}",
            )
        require(
            "release-candidate setup artifact" in script,
            f"{path}: generated handoff README must name release-candidate setup",
        )

    print("engineering_mvp_scope_check=passed")


if __name__ == "__main__":
    main()
