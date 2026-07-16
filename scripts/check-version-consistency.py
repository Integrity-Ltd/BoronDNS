#!/usr/bin/env python3
"""Check BoronDNS release-version consistency across excluded crates and locks."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def workspace_version() -> str:
    cargo = load_toml(ROOT / "Cargo.toml")
    return cargo["workspace"]["package"]["version"]


def check_equal(errors: list[str], label: str, actual: str | None, expected: str) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected}, found {actual}")


def dependency_version(manifest: dict, dependency: str) -> str | None:
    value = manifest.get("dependencies", {}).get(dependency)
    if isinstance(value, dict):
        version = value.get("version")
        return version if isinstance(version, str) else None
    if isinstance(value, str):
        return value
    return None


def lock_package_version(lock_path: Path, package_name: str) -> str | None:
    lock = load_toml(lock_path)
    for package in lock.get("package", []):
        if package.get("name") == package_name:
            version = package.get("version")
            return version if isinstance(version, str) else None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tag",
        help="Optional release tag version without leading v; must match workspace version.",
    )
    args = parser.parse_args()

    expected = workspace_version()
    errors: list[str] = []
    if args.tag is not None:
        check_equal(errors, "release tag", args.tag, expected)

    for manifest_path, dependencies in [
        ("crates/borondns-cli/Cargo.toml", ["borondns-core", "borondns-server"]),
        ("crates/borondns-server/Cargo.toml", ["borondns-core"]),
    ]:
        manifest = load_toml(ROOT / manifest_path)
        for dependency in dependencies:
            check_equal(
                errors,
                f"{manifest_path} dependency {dependency}",
                dependency_version(manifest, dependency),
                expected,
            )

    for manifest_path in [
        "crates/boron-gun-ebpf/Cargo.toml",
        "crates/borondns-server-ebpf/Cargo.toml",
    ]:
        manifest = load_toml(ROOT / manifest_path)
        check_equal(
            errors,
            f"{manifest_path} package version",
            manifest.get("package", {}).get("version"),
            expected,
        )

    for package in ["boron-gun", "borondns-cli", "borondns-core", "borondns-server"]:
        check_equal(
            errors,
            f"Cargo.lock package {package}",
            lock_package_version(ROOT / "Cargo.lock", package),
            expected,
        )

    for lock_path, package in [
        ("fuzz/Cargo.lock", "borondns-core"),
        ("crates/boron-gun-ebpf/Cargo.lock", "boron-gun-ebpf"),
        ("crates/borondns-server-ebpf/Cargo.lock", "borondns-server-ebpf"),
    ]:
        check_equal(
            errors,
            f"{lock_path} package {package}",
            lock_package_version(ROOT / lock_path, package),
            expected,
        )

    if errors:
        for error in errors:
            print(f"version_consistency_error={error}", file=sys.stderr)
        return 1

    print(f"version_consistency_check=passed version={expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
