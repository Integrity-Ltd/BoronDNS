#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "engineering-mvp-readiness.md"

REQUIRED_FILES = [
    "scripts/check.sh",
    "scripts/engineering-mvp-evidence.sh",
    "docs/engineering-mvp-scope.md",
    "docs/release-acceptance-gap-register.md",
    "docs/evidence-command-catalog.md",
    "docs/verification-ledger.md",
    "docs/implementation-plan.md",
    "docs/operator-deployment-guide.md",
    "config/borondns.example.toml",
]

REQUIRED_REFERENCES = [
    "# Release Candidate Readiness",
    "BDS-VER-008",
    "scripts/check.sh",
    "scripts/engineering-mvp-evidence.sh",
    "deferred-not-run.txt",
    "docs/release-acceptance-gap-register.md",
    "docs/evidence-command-catalog.md",
    "scripts/release-preflight-container.sh",
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
        reference = Path(path).name if path.startswith("docs/") else path
        require(reference in text, f"{DOC}: missing required reference: {path}")

    for reference in REQUIRED_REFERENCES:
        require(reference in text, f"{DOC}: missing reference: {reference}")

    lowered = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        require(
            phrase.lower() not in lowered,
            f"{DOC}: forbidden readiness overclaim: {phrase}",
        )

    print(f"engineering_mvp_readiness_check=passed path={DOC.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
