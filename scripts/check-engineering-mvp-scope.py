#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "docs" / "engineering-mvp-scope.md"
CHECK = ROOT / "scripts" / "check.sh"
EVIDENCE = ROOT / "scripts" / "engineering-mvp-evidence.sh"
PLAN = ROOT / "docs" / "implementation-plan.md"
GAPS = ROOT / "docs" / "mvp-gap-register.md"
LEDGER = ROOT / "docs" / "verification-ledger.md"

REQUIRED_SCOPE_PHRASES = [
    "not the SRS",
    "must not require completed long-running evidence",
    "24-hour fuzz campaigns",
    "30-day soak execution",
    "Reference Hardware/Profile benchmark campaigns",
    "not Engineering MVP deliverables",
    "not Engineering MVP evidence",
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
    "scripts/capture-unsafe-dependency-evidence.sh",
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def main() -> None:
    scope = normalized(SCOPE)
    for phrase in REQUIRED_SCOPE_PHRASES:
        require(phrase in scope, f"{SCOPE}: missing required phrase: {phrase}")

    plan = normalized(PLAN)
    require(
        "Engineering MVP must not require completed long-running evidence" in plan,
        f"{PLAN}: missing Engineering MVP long-running evidence exclusion",
    )

    gaps = normalized(GAPS)
    require(
        "Long-running evidence is out of Engineering MVP scope" in gaps,
        f"{GAPS}: missing long-running evidence scope statement",
    )

    ledger = normalized(LEDGER)
    require(
        "completed long-running evidence is not an Engineering MVP requirement" in ledger,
        f"{LEDGER}: missing Engineering MVP long-running evidence note",
    )
    require(
        "block Engineering MVP when the missing evidence is explicitly deferred" in ledger,
        f"{LEDGER}: missing Engineering MVP interpretation for Partial ledger rows",
    )

    for path in [CHECK, EVIDENCE]:
        script = path.read_text(encoding="utf-8")
        for command in FORBIDDEN_CHECK_COMMANDS:
            require(
                command not in script,
                f"{path}: Engineering MVP profile must not run {command}",
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
            f"{EVIDENCE}: Engineering MVP evidence profile must include {command}",
        )
    require(
        "timeout --preserve-status" in evidence,
        f"{EVIDENCE}: Engineering MVP evidence commands must have a timeout guard",
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
                f"{EVIDENCE}: Engineering MVP evidence profile must not run {command}",
            )

    print("engineering_mvp_scope_check=passed")


if __name__ == "__main__":
    main()
