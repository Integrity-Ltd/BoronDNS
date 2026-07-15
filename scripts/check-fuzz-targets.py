#!/usr/bin/env python3
"""Check that fuzz sources, Cargo bins, and long-campaign defaults stay in sync."""

from __future__ import annotations

import re
import os
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fuzz" / "Cargo.toml"
TARGET_DIR = ROOT / "fuzz" / "fuzz_targets"
TWO_HOST = ROOT / "scripts" / "fuzz-soak-two-host-campaign.sh"
CHECK_SH = ROOT / "scripts" / "check.sh"
RUNBOOK = ROOT / "docs" / "two-host-fuzz-soak-campaign.md"


def fail(message: str) -> None:
    print(f"fuzz target parity check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def duplicate_values(values: list[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


ASSIGNMENT_HEADER = [
    "host",
    "target",
    "duration_seconds",
    "remote_evidence_dir",
    "systemd_unit",
    "remote_command_file",
]
SAMPLER_HEADER = [
    "host",
    "remote_sample_dir",
    "systemd_unit",
    "remote_command_file",
    "deadline_epoch_seconds",
]


def stable_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def sampler_errors(lines: list[str], assignment_slots: list[str]) -> list[str]:
    rows = [line.split("\t") for line in lines]
    if not rows or rows[0] != SAMPLER_HEADER:
        return ["generated host-samplers.tsv has an invalid header"]
    expected_hosts = stable_unique(assignment_slots)
    actual_hosts = [row[0] for row in rows[1:] if len(row) == len(SAMPLER_HEADER)]
    errors: list[str] = []
    if len(actual_hosts) != len(rows) - 1:
        errors.append("generated sampler assignment has an invalid column count")
    duplicates = duplicate_values(actual_hosts)
    if duplicates:
        errors.append(f"generated sampler repeats physical hosts: {', '.join(duplicates)}")
    if actual_hosts != expected_hosts:
        errors.append(
            "generated sampler physical host order drift: "
            f"actual={actual_hosts!r} expected={expected_hosts!r}"
        )
    return errors


def assignment_errors(
    lines: list[str], hosts: list[str], targets: list[str], repeat: int
) -> list[str]:
    errors: list[str] = []
    rows = [line.split("\t") for line in lines]
    if not rows or rows[0] != ASSIGNMENT_HEADER:
        return ["generated assignments.tsv has an invalid header"]
    expected_targets = targets * repeat
    if len(rows) - 1 != len(expected_targets):
        errors.append(
            "generated assignment count differs from target-repeat algorithm: "
            f"actual={len(rows) - 1} expected={len(expected_targets)}"
        )
        return errors
    for index, row in enumerate(rows[1:]):
        if len(row) != len(ASSIGNMENT_HEADER):
            errors.append(f"generated assignment row {index} has {len(row)} columns")
            continue
        expected_host = hosts[index % len(hosts)]
        if row[0] != expected_host:
            errors.append(
                f"generated assignment host distribution drift at row {index}: "
                f"actual={row[0]!r} expected={expected_host!r}"
            )
        if row[1] != expected_targets[index]:
            errors.append(
                f"generated assignment target order drift at row {index}: "
                f"actual={row[1]!r} expected={expected_targets[index]!r}"
            )
    return errors


def check_generated_assignments(
    source_names: list[str], hosts: list[str], repeat: int
) -> None:
    with tempfile.TemporaryDirectory(prefix="oxidedns-fuzz-parity-") as temporary:
        plan = Path(temporary) / "plan"
        command = [
            str(TWO_HOST),
            "plan",
            "--evidence-dir",
            str(plan),
            "--campaign-id",
            "fuzz-parity-check",
            "--duration",
            "1",
            "--target-repeat",
            str(repeat),
        ]
        for host in hosts:
            command.extend(("--host", host))
        for target in source_names:
            command.extend(("--target", target))
        environment = os.environ.copy()
        environment["OXIDEDNS_CAMPAIGN_TEST_ALLOW_DIRTY"] = "1"
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            fail(f"could not generate assignment parity fixture: {result.stderr.strip()}")
        lines = (plan / "assignments.tsv").read_text(encoding="utf-8").splitlines()
        if errors := assignment_errors(lines, hosts, source_names, repeat):
            fail(errors[0])
        sampler_lines = (plan / "host-samplers.tsv").read_text(encoding="utf-8").splitlines()
        if errors := sampler_errors(sampler_lines, hosts):
            fail(errors[0])
        mutated = list(lines)
        first = mutated[1].split("\t")
        first[0] = "host0-mutation"
        mutated[1] = "\t".join(first)
        if not any(
            "host distribution drift" in error
            for error in assignment_errors(mutated, hosts, source_names, repeat)
        ):
            fail("assignment parity self-test did not reject a host0 mutation")
        if len(stable_unique(hosts)) > 1:
            mutated_sampler = list(sampler_lines)
            second = mutated_sampler[2].split("\t")
            second[0] = stable_unique(hosts)[0]
            mutated_sampler[2] = "\t".join(second)
            if not any(
                "repeats physical hosts" in error
                for error in sampler_errors(mutated_sampler, hosts)
            ):
                fail("sampler parity self-test did not reject a duplicate physical host")


def runbook_errors(runbook: str, source_names: list[str]) -> list[str]:
    errors: list[str] = []
    runbook_targets_match = re.search(
        r"^Current targets:\n\n(?P<body>(?:- `[^`]+`\n)+)", runbook, re.M
    )
    if runbook_targets_match is None:
        return ["could not parse Current targets from the two-host runbook"]
    runbook_names = re.findall(
        r"^- `([^`]+)`$", runbook_targets_match.group("body"), re.M
    )
    if sorted(runbook_names) != source_names:
        errors.append(
            "two-host runbook targets differ from fuzz sources: "
            f"runbook={sorted(runbook_names)!r} sources={source_names!r}"
        )

    preflight_names = re.findall(
        r"^cargo \+nightly fuzz check ([A-Za-z0-9_-]+)$", runbook, re.M
    )
    if duplicates := duplicate_values(preflight_names):
        errors.append(f"duplicate runbook fuzz preflight targets: {', '.join(duplicates)}")
    if sorted(preflight_names) != source_names:
        errors.append(
            "two-host runbook fuzz preflight targets differ from fuzz sources: "
            f"preflight={sorted(preflight_names)!r} sources={source_names!r}"
        )

    weighted_launch = re.search(
        r"scripts/fuzz-soak-two-host-campaign\.sh launch \\\n(?P<body>(?:  .*\n)+?)```",
        runbook,
    )
    if weighted_launch is None:
        errors.append("could not parse weighted two-host fuzz launch command")
        return errors
    launch_body = weighted_launch.group("body")
    repeat_match = re.search(r"--target-repeat ([1-9][0-9]*)", launch_body)
    launch_hosts = re.findall(r"--host ([A-Za-z0-9_.-]+)", launch_body)
    if repeat_match is None or not launch_hosts:
        errors.append("weighted fuzz launch is missing target repeat or hosts")
        return errors
    expected_repeated_services = len(source_names) * int(repeat_match.group(1))
    distribution = Counter(
        launch_hosts[index % len(launch_hosts)]
        for index in range(expected_repeated_services)
    )
    expected_first_host_services = distribution.get("oxidedns-1", 0)
    expected_second_host_services = distribution.get("oxidegun-1", 0)
    if set(distribution) != {"oxidedns-1", "oxidegun-1"}:
        errors.append(f"weighted fuzz launch has unexpected hosts: {sorted(distribution)!r}")
    if f"current {len(source_names)}-target set" not in runbook.replace("nine", "9"):
        errors.append("two-host runbook target-count prose is stale")
    if f"launches {expected_repeated_services} fuzz" not in runbook:
        errors.append(
            "two-host runbook repeated-service count is stale: "
            f"expected={expected_repeated_services}"
        )
    if f"about {expected_first_host_services} instances on the 48-core" not in runbook:
        errors.append(
            "two-host runbook first-host service distribution is stale: "
            f"expected={expected_first_host_services}"
        )
    if f"and {expected_second_host_services}\ninstances on the 72-core" not in runbook:
        errors.append(
            "two-host runbook second-host service distribution is stale: "
            f"expected={expected_second_host_services}"
        )
    return errors


def check_runbook_mutation_regressions(runbook: str, source_names: list[str]) -> None:
    preflight_mutation = runbook.replace(
        f"cargo +nightly fuzz check {source_names[-1]}\n", "", 1
    )
    if not any("preflight targets differ" in error for error in runbook_errors(preflight_mutation, source_names)):
        fail("runbook parity self-test did not reject a missing fuzz preflight target")

    expected_repeated_services = len(source_names) * 15
    expected_first_host_services = expected_repeated_services * 2 // 5
    distribution_mutation = runbook.replace(
        f"about {expected_first_host_services} instances on the 48-core",
        f"about {expected_first_host_services + 1} instances on the 48-core",
        1,
    )
    if not any("first-host service distribution" in error for error in runbook_errors(distribution_mutation, source_names)):
        fail("runbook parity self-test did not reject a stale host distribution")

    host_weight_mutation = runbook.replace("  --host oxidegun-1 \\\n", "", 1)
    if not any(
        "service distribution" in error
        for error in runbook_errors(host_weight_mutation, source_names)
    ):
        fail("runbook parity self-test did not reject changed launch host weighting")


def main() -> None:
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    bins = manifest.get("bin", [])
    manifest_names = [entry.get("name", "") for entry in bins]
    manifest_paths = [entry.get("path", "") for entry in bins]
    if duplicates := duplicate_values(manifest_names):
        fail(f"duplicate Cargo bin names: {', '.join(duplicates)}")
    if duplicates := duplicate_values(manifest_paths):
        fail(f"duplicate Cargo bin paths: {', '.join(duplicates)}")

    source_names = sorted(path.stem for path in TARGET_DIR.glob("*.rs"))
    expected_paths = sorted(f"fuzz_targets/{name}.rs" for name in source_names)
    if sorted(manifest_names) != source_names:
        fail(
            "Cargo bin names differ from fuzz source files: "
            f"manifest={sorted(manifest_names)!r} sources={source_names!r}"
        )
    if sorted(manifest_paths) != expected_paths:
        fail(
            "Cargo bin paths differ from fuzz source files: "
            f"manifest={sorted(manifest_paths)!r} expected={expected_paths!r}"
        )

    campaign = TWO_HOST.read_text(encoding="utf-8")
    match = re.search(r"^default_targets=\(\n(?P<body>.*?)^\)\n", campaign, re.M | re.S)
    if match is None:
        fail("could not parse default_targets from two-host campaign")
    campaign_names = [line.strip() for line in match.group("body").splitlines() if line.strip()]
    if duplicates := duplicate_values(campaign_names):
        fail(f"duplicate two-host campaign targets: {', '.join(duplicates)}")
    if sorted(campaign_names) != source_names:
        fail(
            "two-host defaults differ from fuzz sources: "
            f"campaign={sorted(campaign_names)!r} sources={source_names!r}"
        )

    runbook = RUNBOOK.read_text(encoding="utf-8")
    if errors := runbook_errors(runbook, source_names):
        fail(errors[0])
    check_runbook_mutation_regressions(runbook, source_names)
    weighted_launch = re.search(
        r"scripts/fuzz-soak-two-host-campaign\.sh launch \\\n(?P<body>(?:  .*\n)+?)```",
        runbook,
    )
    if weighted_launch is None:
        fail("could not parse weighted launch for generated assignment parity")
    launch_body = weighted_launch.group("body")
    launch_hosts = re.findall(r"--host ([A-Za-z0-9_.-]+)", launch_body)
    repeat_match = re.search(r"--target-repeat ([1-9][0-9]*)", launch_body)
    if not launch_hosts or repeat_match is None:
        fail("weighted launch lacks hosts or target repeat for assignment parity")
    check_generated_assignments(source_names, launch_hosts, int(repeat_match.group(1)))

    check_lines = {
        line.strip()
        for line in CHECK_SH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required_checks = (
        "cargo check --manifest-path fuzz/Cargo.toml",
        "cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings",
        "cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check",
    )
    for required_check in required_checks:
        if required_check not in check_lines:
            fail(f"scripts/check.sh is missing required fuzz gate: {required_check}")

    print(f"fuzz target parity check passed: targets={len(source_names)}")


if __name__ == "__main__":
    main()
