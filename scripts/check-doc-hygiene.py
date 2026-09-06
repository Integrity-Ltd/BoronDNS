#!/usr/bin/env python3
"""Check documentation navigation, local links, and known stale identifiers.

Requirements, configuration, source ownership, and release security have their
own focused checks. This check deliberately does not pin editorial sentences.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
NUMBERED_HEADING = re.compile(r"^## ([0-9]+)\. ")
INLINE_LINK = re.compile(r"!?(?<!\\)\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+[\"'][^\n]*[\"'])?\)")
REFERENCE_LINK = re.compile(r"^ {0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)", re.MULTILINE)
STALE_IDENTIFIERS = (
    "RustDNS", "OxydeDNS", "catalog-zone-mvp-rfc9432.md",
    "health.livez_timeout_ms", "BORONDNS_HEALTH_LIVEZ_TIMEOUT_MS",
    "query.processing_timeout_ms", "borondns_dnssec_nsec3_cap_exceeded_total",
)
SOURCE_STALE_IDENTIFIERS = ("rds_environment", "RDS environment", "unrecognised_rds", "unrecognized_rds")
# Preserve the earlier guard against a retired DNSSEC evidence expectation.
SCRIPT_STALE_CONTRACTS = ("did not set response DO bit", "set response DO bit")
REQUIRED_REFERENCES = {
    "README.md": (
        "docs/operator-deployment-guide.md", "docs/README.md",
        "docs/implemented-feature-scope.md", "SECURITY.md", "CONTRIBUTING.md",
    ),
    "docs/README.md": (
        "operator-deployment-guide.md", "architecture.md", "test-plan.md",
        "BoronDNS-Secondary-SRS-v1.0.0.md", "release-evidence-guide.md",
        "verification-ledger.md", "rfc-compliance-assertions.md",
        "appendix-a-traceability-matrix.md", "project-decision-register.md",
    ),
}


def current_doc_paths() -> list[Path]:
    # Include new guides, but not ignored, machine-specific lab notebooks.
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    paths = {
        ROOT / name for name in result.stdout.split("\0")
        if name.endswith(".md") and (
            "/" not in name or name.startswith(("docs/", "packaging/", "fuzz/"))
        )
    }
    return sorted(path for path in paths if path.is_file())


def prose_only(text: str) -> str:
    """Ignore fenced examples when inspecting Markdown structure and links."""
    lines = []
    fence_char = ""
    fence_length = 0
    for line in text.splitlines():
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if not fence_char:
                fence_char, fence_length = marker[0], len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_length:
                fence_char, fence_length = "", 0
            lines.append("")
        elif fence_char:
            lines.append("")
        else:
            lines.append(line)
    return "\n".join(lines)


def heading_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    for line in prose_only(text).splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", line)
        if match:
            label = re.sub(r"<[^>]*>", "", match.group(1)).lower()
            slug = re.sub(r"[^\w\- ]", "", label).replace(" ", "-")
            candidate = slug
            occurrence = 0
            while candidate in anchors:
                occurrence += 1
                candidate = f"{slug}-{occurrence}"
            anchors.add(candidate)
        for explicit in re.finditer(r'<(?:a|h[1-6])\s+[^>]*(?:id|name)=["\']([^"\']+)["\']', line):
            anchors.add(explicit.group(1))
    return anchors


def link_errors(path: Path, text: str) -> list[str]:
    errors = []
    prose = prose_only(text)
    # Inline code may deliberately show a non-existent example link.
    prose = re.sub(r"(`+).*?\1", "", prose)
    targets = [m.group(1) for m in INLINE_LINK.finditer(prose)]
    targets.extend(m.group(1) for m in REFERENCE_LINK.finditer(prose))
    for target in targets:
        target = target.removeprefix("<").removesuffix(">")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.path.startswith("/"):
            continue
        destination = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
        if not destination.is_relative_to(ROOT):
            errors.append(f"link leaves repository: {target}")
        elif not destination.exists():
            errors.append(f"broken local link: {target}")
        elif parsed.fragment and destination.suffix == ".md":
            anchors = heading_anchors(destination.read_text(encoding="utf-8"))
            if unquote(parsed.fragment) not in anchors:
                errors.append(f"unknown heading in link: {target}")
    return errors


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors = link_errors(path, text)
    if not re.search(r"^# ", prose_only(text), re.MULTILINE):
        errors.append("missing document title")
    numbered: set[str] = set()
    for line in prose_only(text).splitlines():
        match = NUMBERED_HEADING.match(line)
        if match:
            if match.group(1) in numbered:
                errors.append(f"duplicate numbered section: {match.group(1)}")
            numbered.add(match.group(1))
    for identifier in STALE_IDENTIFIERS:
        if identifier in text:
            errors.append(f"stale identifier: {identifier}")
    relative = path.relative_to(ROOT).as_posix()
    for reference in REQUIRED_REFERENCES.get(relative, ()):
        if reference not in text:
            errors.append(f"missing navigation reference: {reference}")
    return errors


def main() -> int:
    violations = []
    paths = current_doc_paths()
    for path in paths:
        violations.extend(f"{path.relative_to(ROOT)}: {error}" for error in check_doc(path))
    # Every top-level guide should be discoverable from the documentation index.
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    for path in paths:
        if path.parent != ROOT / "docs":
            continue
        if path.name != "README.md" and f"({path.name})" not in index:
            violations.append(f"docs/README.md: missing link to {path.name}")
    sources = [
        path for directory in ("crates", "config")
        for path in (ROOT / directory).rglob("*")
        if path.is_file() and path.suffix in {".rs", ".toml"} and "target" not in path.parts
    ]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for identifier in SOURCE_STALE_IDENTIFIERS:
            if identifier in text:
                violations.append(f"{path.relative_to(ROOT)}: stale identifier: {identifier}")
    for path in (ROOT / "scripts").iterdir():
        if path.suffix not in {".py", ".sh"} or path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in SCRIPT_STALE_CONTRACTS:
            if phrase in text:
                violations.append(f"{path.relative_to(ROOT)}: stale evidence contract: {phrase}")
    if violations:
        for violation in violations:
            print(f"doc_hygiene=failed {violation}", file=sys.stderr)
        return 1
    print(f"doc_hygiene=passed docs={len(paths)} sources={len(sources)} links=checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
