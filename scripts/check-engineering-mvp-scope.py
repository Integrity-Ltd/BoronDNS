#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "docs" / "engineering-mvp-scope.md"
CHECK = ROOT / "scripts" / "check.sh"
PLAN = ROOT / "docs" / "implementation-plan.md"
GAPS = ROOT / "docs" / "mvp-gap-register.md"
LEDGER = ROOT / "docs" / "verification-ledger.md"

REQUIRED_SCOPE_PHRASES = [
    "not the SRS",
    "must not require completed long-running evidence",
    "24-hour fuzz campaigns",
    "30-day soak execution",
    "Reference Hardware/Profile benchmark campaigns",
    "scaffolding only",
]

FORBIDDEN_CHECK_COMMANDS = [
    "--duration 86400",
    "--duration 24h",
    "--duration 24H",
    "--iterations 1000",
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

    check = CHECK.read_text(encoding="utf-8")
    for command in FORBIDDEN_CHECK_COMMANDS:
        require(
            command not in check,
            f"{CHECK}: Engineering MVP check profile must not run {command}",
        )
    require(
        "scripts/fuzz-campaign.sh --dry-run" in check,
        f"{CHECK}: expected only dry-run fuzz campaign wiring in local checks",
    )

    print("engineering_mvp_scope_check=passed")


if __name__ == "__main__":
    main()
