#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/ci.yml")
REQUIRED_TEXT = [
    "push:",
    "branches:",
    "- main",
    "pull_request:",
    "schedule:",
    "cron:",
    "workflow_dispatch:",
    "permissions:",
    "contents: read",
    "ubuntu-24.04",
    "rustup component add llvm-tools-preview",
    "cargo install cargo-deny --locked",
    "cargo install cargo-bloat --locked",
    "cargo install cargo-machete --locked",
    "cargo install cargo-llvm-cov --locked",
    "cargo install cargo-geiger --locked",
    "./scripts/check.sh",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = repo_root / WORKFLOW
    if not workflow_path.is_file():
        fail(f"missing CI workflow: {WORKFLOW}")

    text = workflow_path.read_text(encoding="utf-8")
    for required in REQUIRED_TEXT:
        if required not in text:
            fail(f"{WORKFLOW} missing required text: {required}")

    if text.count("cron:") != 1:
        fail(f"{WORKFLOW} must define exactly one scheduled weekly workflow")

    print(f"ci_workflow_check=passed path={WORKFLOW}")


if __name__ == "__main__":
    main()
