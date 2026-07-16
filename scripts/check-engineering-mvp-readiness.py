#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "engineering-mvp-readiness.md"

REQUIRED_FILES = [
    "scripts/check.sh",
    "scripts/engineering-mvp-evidence.sh",
    "docs/engineering-mvp-scope.md",
    "docs/mvp-gap-register.md",
    "docs/evidence-command-catalog.md",
    "docs/verification-ledger.md",
    "docs/implementation-plan.md",
    "docs/operator-deployment-guide.md",
    "config/borondns.example.toml",
]

REQUIRED_PHRASES = [
    "# Release Candidate Readiness",
    "not full SRS `BDS-VER-008` release acceptance",
    "scripts/check.sh",
    "scripts/engineering-mvp-evidence.sh",
    "bounded local preflight profile",
    "deferred-not-run.txt",
    "Do not call the release candidate ready",
    "docs/mvp-gap-register.md",
    "docs/evidence-command-catalog.md",
    "remaining SRS acceptance gaps",
]

FORBIDDEN_PHRASES = [
    "full SRS acceptance is complete",
    "BDS-VER-008 is complete",
    "30-day soak completed",
    "24-hour fuzz campaigns completed",
    "Reference Hardware/Profile benchmarks completed",
    "signed release artifacts completed",
    "external operator acceptance completed",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def main() -> None:
    require(DOC.is_file(), f"missing release-candidate readiness document: {DOC}")
    text = normalized(DOC)

    for path in REQUIRED_FILES:
        require((ROOT / path).exists(), f"{DOC}: references missing path: {path}")
        require(path in text, f"{DOC}: missing required reference: {path}")

    for phrase in REQUIRED_PHRASES:
        require(phrase in text, f"{DOC}: missing required phrase: {phrase}")

    lowered = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        require(
            phrase.lower() not in lowered,
            f"{DOC}: forbidden readiness overclaim: {phrase}",
        )

    print(f"engineering_mvp_readiness_check=passed path={DOC.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
