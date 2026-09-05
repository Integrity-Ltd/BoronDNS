#!/usr/bin/env python3
"""Validate the complete unsigned release handoff and simulated signed asset plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--reproducibility-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    with (ROOT / "Cargo.toml").open("rb") as handle:
        version = tomllib.load(handle)["workspace"]["package"]["version"]
    prefix = f"borondns-{version}-x86_64-unknown-linux-musl"
    names = [
        f"{prefix}.tar.xz",
        f"{prefix}.bin",
        f"{prefix}-boron-gun.bin",
        f"borondns_{version}-1_amd64.deb",
        f"borondns-{version}-1.x86_64.rpm",
        f"{prefix}-docker-image.tar.xz",
        f"{prefix}-docker-image.manifest.txt",
        f"{prefix}-borondns.cdx.json",
        f"{prefix}-boron-gun.cdx.json",
        f"{prefix}-docker-image.cdx.json",
        f"{prefix}-sbom-manifest.tsv",
    ]
    dist = args.dist.resolve(strict=True)
    assets = [dist / name for name in names]
    missing = [path.name for path in assets if not path.is_file() or path.stat().st_size == 0]
    if missing:
        raise SystemExit(f"missing or empty release assets: {missing}")

    for document in (path for path in assets if path.name.endswith(".cdx.json")):
        data = json.loads(document.read_text(encoding="utf-8"))
        if data.get("bomFormat") != "CycloneDX":
            raise SystemExit(f"invalid CycloneDX document: {document.name}")
    for archive in (path for path in assets if path.name.endswith(".tar.xz")):
        with tarfile.open(archive, mode="r:xz") as tar:
            if not tar.getmembers():
                raise SystemExit(f"empty release archive: {archive.name}")

    evidence = args.reproducibility_evidence.resolve(strict=True)
    for relative in (
        "reproducible-build-summary.env",
        "comparison.tsv",
        "artifact-manifest.tsv",
        "artifacts/a/borondns",
        "artifacts/a/boron-gun",
        "artifacts/b/borondns",
        "artifacts/b/boron-gun",
    ):
        path = evidence / relative
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"missing reproducibility evidence: {relative}")

    output = args.output
    if output.exists():
        raise SystemExit(f"refusing to reuse handoff output: {output}")
    output.mkdir(parents=True)
    for asset in assets:
        shutil.copyfile(asset, output / asset.name)
    handoff_lines = [f"{digest(output / name)}  {name}\n" for name in names]
    (output / "release-handoff.sha256").write_text("".join(handoff_lines), encoding="utf-8")

    unsigned_names = names + ["release-handoff.sha256"]
    published_names = unsigned_names + ["release-handoff.sha256.sigstore.json"]
    if len(unsigned_names) != 12 or len(published_names) != 13:
        raise SystemExit("release publication asset cardinality changed")
    if len(set(published_names)) != len(published_names):
        raise SystemExit("release publication asset names collide")
    (output / "published-asset-plan.txt").write_text(
        "".join(f"{name}\n" for name in published_names), encoding="utf-8"
    )
    print(
        "release_asset_preflight=passed "
        f"unsigned={len(unsigned_names)} published={len(published_names)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
