#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path


HEADER = ["category", "element", "stability", "since", "evidence", "change_policy", "notes"]
REQUIRED_CATEGORIES = {
    "configuration",
    "environment",
    "cli",
    "exit-code",
    "signal",
    "health",
    "metric",
    "log-field",
    "network-role",
}
REQUIRED_ELEMENTS = {
    ("configuration", "[interfaces].dns"),
    ("configuration", "[interfaces].transfer"),
    ("configuration", "[interfaces].mgmt"),
    ("environment", "ODS_<SECTION>_<KEY>"),
    ("cli", "serve"),
    ("cli", "--validate-config"),
    ("cli", "--dump-config"),
    ("cli", "--example-config"),
    ("cli", "--version|-V"),
    ("exit-code", "78"),
    ("signal", "SIGTERM"),
    ("signal", "SIGINT"),
    ("signal", "SIGHUP"),
    ("health", "/livez"),
    ("health", "/readyz"),
    ("health", "/healthz"),
    ("health", "/metrics"),
    ("metric", "oxidedns_secondary_build_info"),
    ("metric", "oxidedns_secondary_query_duration_seconds"),
    ("log-field", "timestamp"),
    ("log-field", "message"),
    ("network-role", "dns"),
    ("network-role", "transfer"),
    ("network-role", "mgmt"),
}
ALLOWED_STABILITY = {"stable", "deprecated", "additive"}
ALLOWED_CHANGE_POLICY = {"major", "minor-additive", "patch-compatible"}


def fail(message: str) -> None:
    raise SystemExit(message)


def read_baseline(path: Path) -> dict[tuple[str, str], dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != HEADER:
            fail(f"{path} must use TSV header: {HEADER}")
        rows = list(reader)

    baseline: dict[tuple[str, str], dict[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        key = (row["category"], row["element"])
        if key in baseline:
            fail(f"{path}:{row_number}: duplicate interface row {key}")
        for field in HEADER:
            if not row[field]:
                fail(f"{path}:{row_number}: {field} is required")
            if "TBD" in row[field]:
                fail(f"{path}:{row_number}: {field} contains TBD")
        if row["stability"] not in ALLOWED_STABILITY:
            fail(f"{path}:{row_number}: invalid stability {row['stability']}")
        if row["change_policy"] not in ALLOWED_CHANGE_POLICY:
            fail(f"{path}:{row_number}: invalid change_policy {row['change_policy']}")
        baseline[key] = row
    return baseline


def check_policy(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for required in (
        "ODS-NFR-MAINT-006",
        "ODS-IF-CONF-002",
        "semantic",
        "major version",
        "deprecation",
        "release notes",
        "configuration schema",
        "command-line",
        "process exit codes",
        "metric names",
        "health endpoint",
    ):
        if required not in text:
            fail(f"{path} missing required policy text: {required}")


def check_current_baseline(path: Path, baseline: dict[tuple[str, str], dict[str, str]]) -> None:
    categories = {category for category, _element in baseline}
    missing_categories = REQUIRED_CATEGORIES - categories
    if missing_categories:
        fail(f"{path} missing interface categories: {sorted(missing_categories)}")

    missing_elements = REQUIRED_ELEMENTS - set(baseline)
    if missing_elements:
        fail(f"{path} missing required interface elements: {sorted(missing_elements)}")
    forbidden_elements = {
        ("configuration", "[interfaces].notify"),
        ("configuration", "[interface].notify"),
        ("network-role", "notify"),
    }
    present_forbidden = forbidden_elements & set(baseline)
    if present_forbidden:
        fail(f"{path} exposes forbidden MVP interface roles: {sorted(present_forbidden)}")


def check_three_role_docs(repo_root: Path) -> None:
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    if "[interfaces].notify" in readme:
        fail("README.md must not describe [interfaces].notify as a supported listener")
    if "accepts authorized NOTIFY on the DNS listeners" not in readme:
        fail("README.md must state that NOTIFY is accepted on DNS listeners")

    srs = (repo_root / "docs" / "OxideDNS-Secondary-SRS-v0.9.1.md").read_text(
        encoding="utf-8"
    )
    if "with `dns`, `mgmt`, `transfer`, and `notify` sub-keys" in srs:
        fail("SRS v0.9.1 still exposes notify as an active [interfaces] sub-key")
    if "ODS-IF-NET-008 (optional `interface.notify`)" in srs:
        fail("SRS v0.9.1 still describes ODS-IF-NET-008 as optional interface.notify")
    if "new `interface.notify`" in srs:
        fail("SRS v0.9.1 audit history still claims interface.notify was added")
    if "Add optional `interface.notify`" in srs:
        fail("SRS v0.9.1 C.5 still asks to add optional interface.notify")
    if "MUST NOT expose a fourth `notify` role" not in srs:
        fail("SRS v0.9.1 must preserve the ODS-IF-NET-008 three-role clarification")


def check_previous_diff(
    previous_path: Path,
    current: dict[tuple[str, str], dict[str, str]],
    major_release: bool,
) -> None:
    previous = read_baseline(previous_path)
    removed = sorted(set(previous) - set(current))
    if removed and not major_release:
        fail(
            "interface elements removed without OXIDEDNS_INTERFACE_MAJOR_RELEASE=1: "
            + ", ".join(f"{category}:{element}" for category, element in removed)
        )

    breaking = sorted(
        key for key, row in current.items() if row["change_policy"] == "major" and key not in previous
    )
    if breaking and not major_release:
        fail(
            "new major-policy interface elements require explicit release-note review "
            "or OXIDEDNS_INTERFACE_MAJOR_RELEASE=1: "
            + ", ".join(f"{category}:{element}" for category, element in breaking)
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        default="docs/interface-stability-baseline.tsv",
        help="Current interface stability baseline TSV",
    )
    parser.add_argument(
        "--policy",
        default="docs/interface-compatibility-policy.md",
        help="Interface compatibility policy document",
    )
    parser.add_argument(
        "--previous",
        default=None,
        help="Optional previous release baseline TSV for release-diff checks",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    baseline_path = (repo_root / args.baseline).resolve()
    policy_path = (repo_root / args.policy).resolve()
    current = read_baseline(baseline_path)
    check_policy(policy_path)
    check_current_baseline(baseline_path, current)
    check_three_role_docs(repo_root)

    if args.previous:
        import os

        major_release = os.environ.get("OXIDEDNS_INTERFACE_MAJOR_RELEASE") == "1"
        check_previous_diff(Path(args.previous), current, major_release)

    print(f"interface_compatibility_check=passed rows={len(current)}")


if __name__ == "__main__":
    main()
