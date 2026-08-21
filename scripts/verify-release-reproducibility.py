#!/usr/bin/env python3
"""Validate current-commit reproducible-build evidence before release signing."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import re


MAX_EVIDENCE_FILE_BYTES = 1024 * 1024
ARTIFACTS = ("borondns", "boron-gun")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"release reproducibility verification failed: {message}")


def read_regular(root: Path, name: str) -> str:
    path = root / name
    if path.is_symlink() or not path.is_file():
        fail(f"missing regular evidence file: {name}")
    if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        fail(f"oversized evidence file: {name}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        fail(f"non-UTF-8 evidence file {name}: {error}")


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            fail("malformed reproducible-build summary")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in values:
            fail("invalid or duplicate reproducible-build summary key")
        values[key] = value
    return values


def parse_tsv(text: str, expected_header: list[str], label: str) -> list[dict[str, str]]:
    rows = list(csv.DictReader(text.splitlines(), delimiter="\t"))
    if not text.endswith("\n") or not rows or list(rows[0]) != expected_header:
        fail(f"invalid {label} header or framing")
    if any(
        None in row
        or any(
            value is None or "\n" in value or "\r" in value
            for value in row.values()
        )
        for row in rows
    ):
        fail(f"malformed {label} row")
    return rows


def canonical_positive(value: str) -> bool:
    return value.isascii() and value.isdigit() and not value.startswith("0")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("expected_commit")
    parser.add_argument("--require-artifacts", action="store_true")
    parser.add_argument("--release-borondns", type=Path)
    parser.add_argument("--release-boron-gun", type=Path)
    arguments = parser.parse_args()
    release_paths = {
        "borondns": arguments.release_borondns,
        "boron-gun": arguments.release_boron_gun,
    }
    if any(path is not None for path in release_paths.values()):
        if not arguments.require_artifacts or any(
            path is None for path in release_paths.values()
        ):
            fail("release binary binding requires both release binaries and artifacts")
    if not COMMIT_RE.fullmatch(arguments.expected_commit):
        fail("expected commit must be a full lowercase Git object ID")
    root = arguments.evidence_dir
    if root.is_symlink() or not root.is_dir():
        fail("evidence root must be a real directory")

    summary = parse_env(read_regular(root, "reproducible-build-summary.env"))
    expected_summary = {
        "reproducible_build_status": "true",
        "artifact_match": "true",
        "release_eligible": "true",
        "dirty_source_override": "0",
        "artifact_count": "2",
        "matched_artifact_count": "2",
        "target_triple": "x86_64-unknown-linux-musl",
        "commit": arguments.expected_commit,
    }
    if set(summary) != set(expected_summary) | {"source_date_epoch", "evidence_dir"}:
        fail("summary contains missing or unexpected fields")
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            fail(f"summary {key} is not {expected!r}")
    if not canonical_positive(summary["source_date_epoch"]):
        fail("summary source_date_epoch is not a canonical positive integer")
    if not summary["evidence_dir"]:
        fail("summary evidence_dir is empty")

    comparison_header = [
        "artifact", "target", "profile", "builder_a_sha256", "builder_b_sha256",
        "builder_a_size_bytes", "builder_b_size_bytes", "match",
        "evidence_path_a", "evidence_path_b",
    ]
    comparisons = parse_tsv(
        read_regular(root, "comparison.tsv"), comparison_header, "comparison"
    )
    if len(comparisons) != 2 or {row["artifact"] for row in comparisons} != set(ARTIFACTS):
        fail("comparison must contain exactly both release artifacts")
    comparison_by_artifact = {row["artifact"]: row for row in comparisons}
    for artifact, row in comparison_by_artifact.items():
        if (
            row["target"] != "x86_64-unknown-linux-musl"
            or row["profile"] != "release"
            or row["match"] != "true"
            or row["builder_a_sha256"] != row["builder_b_sha256"]
            or not SHA256_RE.fullmatch(row["builder_a_sha256"])
            or row["builder_a_size_bytes"] != row["builder_b_size_bytes"]
            or not canonical_positive(row["builder_a_size_bytes"])
            or row["evidence_path_a"] != f"artifacts/a/{artifact}"
            or row["evidence_path_b"] != f"artifacts/b/{artifact}"
        ):
            fail(f"comparison row is invalid for {artifact}")

    manifest_header = [
        "artifact", "builder", "target", "profile", "features", "commit",
        "rust_version", "build_command", "sha256", "size_bytes", "evidence_path",
    ]
    manifest = parse_tsv(
        read_regular(root, "artifact-manifest.tsv"), manifest_header, "artifact manifest"
    )
    expected_pairs = {(artifact, builder) for artifact in ARTIFACTS for builder in ("a", "b")}
    if len(manifest) != 4 or {(row["artifact"], row["builder"]) for row in manifest} != expected_pairs:
        fail("artifact manifest must contain exactly two builders for both artifacts")
    rust_versions = {row["rust_version"] for row in manifest}
    if len(rust_versions) != 1 or not next(iter(rust_versions)).startswith("rustc 1.96.1 "):
        fail("artifact manifest has an inconsistent or unpinned Rust version")
    for row in manifest:
        artifact, builder = row["artifact"], row["builder"]
        comparison = comparison_by_artifact[artifact]
        features = "" if artifact == "borondns" else "xdp"
        package = "borondns-cli" if artifact == "borondns" else "boron-gun"
        feature_suffix = "" if not features else f" --features {features}"
        command_suffix = (
            " build --locked --release --target-dir <builder-target-dir> "
            "--target x86_64-unknown-linux-musl "
            f"-p {package}{feature_suffix}"
        )
        if (
            row["target"] != "x86_64-unknown-linux-musl"
            or row["profile"] != "release"
            or row["features"] != features
            or row["commit"] != arguments.expected_commit
            or not row["build_command"].startswith("/")
            or not row["build_command"].endswith(command_suffix)
            or row["sha256"] != comparison[f"builder_{builder}_sha256"]
            or row["size_bytes"] != comparison[f"builder_{builder}_size_bytes"]
            or row["evidence_path"] != f"artifacts/{builder}/{artifact}"
        ):
            fail(f"artifact manifest row is inconsistent for {artifact}/{builder}")
        if arguments.require_artifacts:
            artifact_path = root / row["evidence_path"]
            if artifact_path.is_symlink() or not artifact_path.is_file():
                fail(f"missing reproducible artifact: {row['evidence_path']}")
            if artifact_path.stat().st_size != int(row["size_bytes"]):
                fail(f"artifact size mismatch: {row['evidence_path']}")
            if file_sha256(artifact_path) != row["sha256"]:
                fail(f"artifact digest mismatch: {row['evidence_path']}")

    for artifact, release_path in release_paths.items():
        if release_path is None:
            continue
        if release_path.is_symlink() or not release_path.is_file():
            fail(f"missing regular shipped release binary: {artifact}")
        comparison = comparison_by_artifact[artifact]
        release_size = release_path.stat().st_size
        release_digest = file_sha256(release_path)
        for builder in ("a", "b"):
            if (
                release_size != int(comparison[f"builder_{builder}_size_bytes"])
                or release_digest != comparison[f"builder_{builder}_sha256"]
            ):
                fail(f"shipped release binary differs from builder {builder}: {artifact}")

    print(f"release_reproducibility=passed commit={arguments.expected_commit}")


if __name__ == "__main__":
    main()
