#!/usr/bin/env python3
"""Collect upstream license/notice texts for the locked release dependency graph.

This inventory deliberately includes build dependencies and whole upstream notice
files: it is not a claim that every listed component survives linker elimination.
No license texts are synthesized from SPDX identifiers.
"""

import argparse
import hashlib
import html
import json
import os
import subprocess
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SUPPLEMENTS = {
    ("aya-obj", "0.2.1"): "aya-obj-0.2.1-LICENSE-MIT",
    ("asn1-rs-impl", "0.2.0"): "asn1-rs-impl-0.2.0-LICENSE-MIT",
}


def selected_packages(metadata, roots):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    pending = []
    for root in roots:
        matches = [
            p["id"]
            for p in packages.values()
            if p["name"] == root and not p.get("source")
        ]
        if len(matches) != 1:
            raise ValueError(f"missing or ambiguous release package: {root}")
        pending.extend(matches)
    seen = set()
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        seen.add(identity)
        for dependency in nodes[identity]["deps"]:
            if any(k["kind"] != "dev" for k in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return [packages[identity] for identity in seen]


def package_entry(package):
    root = Path(package["manifest_path"]).parent.resolve()
    declared = package.get("license_file")
    paths = set()
    license_paths = set()
    for path in root.rglob("*"):
        name = path.name.lower()
        prefixes = ("license", "licence", "copying", "copyright", "notice")
        is_license = name.startswith(prefixes) or any(
            parent.lower().startswith(prefixes)
            for parent in path.relative_to(root).parts[:-1]
        )
        # Some upstream packages put author/attribution details in their README.
        if is_license or (path.parent == root and name.startswith("readme")):
            if path.is_symlink():
                raise ValueError(
                    f"symlink in license inventory: {package['name']}/{path.relative_to(root)}"
                )
            if path.is_file():
                paths.add(path)
                if is_license:
                    license_paths.add(path)
    if declared:
        path = root / declared
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(f"unsafe declared license path: {package['name']}")
        if not path.is_file():
            raise ValueError(f"missing declared license file: {package['name']}")
        paths.add(path)
        license_paths.add(path)
    supplement = SUPPLEMENTS.get((package["name"], package["version"]))
    core_error = (package["name"], package["version"], package.get("license")) == (
        "core-error",
        "0.0.0",
        "MIT OR Apache-2.0",
    )
    if not license_paths and not supplement and not core_error:
        raise ValueError(
            f"no upstream license file for {package['name']} {package['version']}; review required"
        )
    documents = []
    for path in sorted(paths):
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        if path in license_paths and not text.strip():
            raise ValueError(
                f"empty license document: {package['name']}/{path.relative_to(root)}"
            )
        documents.append(
            (path.relative_to(root).as_posix(), text, hashlib.sha256(raw).hexdigest())
        )
    if supplement:
        raw = (REPO / "packaging/licenses" / supplement).read_bytes()
        documents.append(
            (
                "upstream repository/" + supplement,
                raw.decode("utf-8"),
                hashlib.sha256(raw).hexdigest(),
            )
        )
    if core_error:
        # This specific published crate omits license files and declares the
        # Apache alternative in Cargo.toml. Retain its exact manifest/author
        # declaration and the unmodified standard Apache text; no invented MIT
        # copyright holder or silent general SPDX fallback.
        for name, path in (
            ("published Cargo.toml", root / "Cargo.toml"),
            ("Apache-2.0 license option", REPO / "LICENSE-APACHE"),
        ):
            raw = path.read_bytes()
            documents.append(
                (name, raw.decode("utf-8"), hashlib.sha256(raw).hexdigest())
            )
    return {
        key: package.get(key) or "not declared"
        for key in ("name", "version", "source", "repository", "license")
    } | {"documents": documents}


def render(entries, runtime, target):
    escape = html.escape
    output = [
        '<!doctype html><html lang="en"><meta charset="utf-8">',
        "<title>BoronDNS third-party notices</title>",
        "<style>body{max-width:90ch;margin:2em auto;padding:0 1em}pre{white-space:pre-wrap}</style>",
        "<h1>BoronDNS third-party notices</h1>",
        (
            f"<p>Release target: {escape(target)}. Includes BoronDNS (af-xdp), BoronGun (xdp), "
            "their transitive normal/build dependencies, and Rust runtime notices. "
            "Build dependencies and feature-unified metadata may conservatively include code "
            "not present in the final binaries. Development-only dependencies, BoronGen, "
            "separately built eBPF objects and container base-image software are not part of "
            "this binary inventory.</p>"
        ),
        (
            "<p>Upstream SPDX declarations identify the offered licenses; they do not replace "
            "the reproduced license and attribution texts. Project licenses are distributed "
            "separately as LICENSE-MIT and LICENSE-APACHE.</p>"
        ),
    ]
    for entry in sorted(entries, key=lambda p: (p["name"], p["version"], p["source"])):
        output.append(f"<h2>{escape(entry['name'])} {escape(entry['version'])}</h2>")
        for key in ("source", "repository", "license"):
            output.append(f"<p>{key}: {escape(entry[key])}</p>")
        for name, text, digest in entry["documents"]:
            output.append(
                f"<h3>{escape(name)}</h3><p>SHA-256: {digest}</p><pre>{escape(text)}</pre>"
            )
    output.append(
        f"<h2>Rust runtime and bundled components</h2><pre>{escape(runtime)}</pre></html>\n"
    )
    return "\n".join(output)


class RuntimeText(HTMLParser):
    """Keep all text of rustc's shipped library copyright inventory, without scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_starttag(self, tag, attrs):
        if tag in ("p", "pre", "h1", "h2", "h3", "li", "br"):
            self.parts.append("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    args = parser.parse_args()
    repo = REPO
    metadata = json.loads(
        subprocess.check_output(
            [
                args.cargo,
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                args.target,
                "--manifest-path",
                str(repo / "Cargo.toml"),
                "--features",
                "borondns-cli/af-xdp,boron-gun/xdp",
            ],
            text=True,
        )
    )
    selected = selected_packages(metadata, ["borondns-cli", "boron-gun"])
    entries = [package_entry(p) for p in selected if p.get("source")]
    if not entries:
        raise ValueError("empty third-party release dependency graph")
    sysroot = Path(
        subprocess.check_output([args.rustc, "--print", "sysroot"], text=True).strip()
    )
    runtime = sysroot / "share/doc/rust/COPYRIGHT-library.html"
    if not runtime.is_file():
        raise ValueError(
            "Rust library copyright inventory is missing; install the pinned rust-docs component"
        )
    reader = RuntimeText()
    reader.feed(runtime.read_text(encoding="utf-8"))
    runtime_text = "".join(reader.parts)
    if "musl" in args.target:
        runtime_text += "\n\nmusl libc COPYRIGHT\n" + (
            repo / "packaging/licenses/musl-COPYRIGHT"
        ).read_text(encoding="utf-8")
    runtime_identity = subprocess.check_output([args.rustc, "--version"], text=True)
    args.output.write_text(
        render(entries, runtime_identity + runtime_text, args.target), encoding="utf-8"
    )
    print(
        f"third-party notices: {len(entries)} dependency packages, Rust runtime; {args.output.name}"
    )


if __name__ == "__main__":
    main()
