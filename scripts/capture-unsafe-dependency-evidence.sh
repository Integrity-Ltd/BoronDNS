#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${OXIDEDNS_UNSAFE_DEPENDENCY_EVIDENCE_DIR:-$repo_root/target/evidence/unsafe-dependencies-$$}"
mkdir -p "$artifact_dir"

if ! cargo geiger --version >/dev/null 2>&1; then
    printf 'missing required cargo subcommand: cargo geiger\n' >&2
    printf 'install with: cargo install cargo-geiger\n' >&2
    exit 1
fi

manifest_for_package() {
    local package="$1"
    local project_manifest="/project/crates/$package/Cargo.toml"
    local host_manifest="$repo_root/crates/$package/Cargo.toml"

    if cargo metadata --manifest-path "$host_manifest" --no-deps --format-version 1 >/dev/null 2>&1; then
        printf '%s\n' "$host_manifest"
    elif cargo metadata --manifest-path "$project_manifest" --no-deps --format-version 1 >/dev/null 2>&1; then
        printf '%s\n' "$project_manifest"
    else
        printf 'failed to resolve cargo metadata manifest for package: %s\n' "$package" >&2
        exit 1
    fi
}

run_geiger_json() {
    local root="$1"
    local manifest="$2"
    local json_out="$artifact_dir/$root-geiger.json"
    local stderr_out="$artifact_dir/$root-geiger.stderr"
    local target_dir="$artifact_dir/$root-target"

    {
        printf '$ CARGO_TARGET_DIR=%q cargo geiger --manifest-path %q --locked --all-targets --all-dependencies --output-format Json\n\n' "$target_dir" "$manifest"
    } >"$artifact_dir/$root-geiger.command"

    set +e
    CARGO_TARGET_DIR="$target_dir" cargo geiger \
        --manifest-path "$manifest" \
        --locked \
        --all-targets \
        --all-dependencies \
        --output-format Json \
        >"$json_out" \
        2>"$stderr_out"
    local geiger_status=$?
    set -e

    printf '%s\n' "$geiger_status" >"$artifact_dir/$root-geiger.exit-status"
    if [[ "$geiger_status" -ne 0 && ! -s "$json_out" ]]; then
        printf 'cargo geiger failed before producing JSON evidence for %s; see %s\n' "$root" "$stderr_out" >&2
        return "$geiger_status"
    fi
}

{
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'repo_root=%s\n' "$repo_root"
    printf 'commit=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    printf 'rustc=%s\n' "$(rustc --version)"
    printf 'cargo=%s\n' "$(cargo --version)"
    printf 'cargo_geiger=%s\n' "$(cargo geiger --version)"
} >"$artifact_dir/tool-versions.env"

root_packages="${OXIDEDNS_GEIGER_ROOT_PACKAGES:-oxidedns-cli}"
printf 'root_package\tmanifest\n' >"$artifact_dir/geiger-roots.tsv"
for package in $root_packages; do
    manifest="$(manifest_for_package "$package")"
    printf '%s\t%s\n' "$package" "$manifest" >>"$artifact_dir/geiger-roots.tsv"
    run_geiger_json "$package" "$manifest"
done

python3 - "$artifact_dir" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

artifact_dir = Path(sys.argv[1])
first_party = {"oxidedns-cli", "oxidedns-core", "oxidedns-server"}
expected_first_party = {"oxidedns-cli": 0, "oxidedns-core": 0, "oxidedns-server": 20}


def unsafe_total(used: dict[str, dict[str, int]]) -> int:
    return sum(bucket.get("unsafe_", 0) for bucket in used.values())


def unsafe_breakdown(used: dict[str, dict[str, int]]) -> str:
    return ",".join(
        f"{name}={counts.get('unsafe_', 0)}" for name, counts in sorted(used.items())
    )


package_rows: list[dict[str, object]] = []
first_party_rows: list[dict[str, object]] = []
not_scanned: list[tuple[str, str]] = []
stderr_warnings: list[tuple[str, str]] = []
packages_seen: set[str] = set()

for json_path in sorted(artifact_dir.glob("*-geiger.json")):
    root = json_path.name.removesuffix("-geiger.json")
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"failed to parse {json_path}: {exc}") from exc

    for path in payload.get("used_but_not_scanned_files", []):
        not_scanned.append((root, path))

    stderr_path = artifact_dir / f"{root}-geiger.stderr"
    if stderr_path.exists():
        for line in stderr_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Failed to ") or "warning" in line.lower():
                stderr_warnings.append((root, line))
    exit_status_path = artifact_dir / f"{root}-geiger.exit-status"
    if exit_status_path.exists():
        exit_status = exit_status_path.read_text(encoding="utf-8", errors="replace").strip()
        if exit_status and exit_status != "0":
            stderr_warnings.append(
                (
                    root,
                    f"cargo geiger exited with status {exit_status}; JSON evidence was retained and parsed",
                )
            )

    for entry in payload.get("packages", []):
        package_id = entry["package"]["id"]
        name = package_id["name"]
        version = package_id["version"]
        source = package_id.get("source")
        source_name = "workspace" if source is None else next(iter(source))
        used = entry["unsafety"]["used"]
        total = unsafe_total(used)
        row = {
            "root": root,
            "name": name,
            "version": version,
            "source": source_name,
            "unsafe_total": total,
            "breakdown": unsafe_breakdown(used),
            "forbids_unsafe": entry["unsafety"].get("forbids_unsafe"),
        }
        package_rows.append(row)
        packages_seen.add(name)
        if name in first_party:
            first_party_rows.append(row)

missing_first_party = sorted(first_party - packages_seen)
if missing_first_party:
    raise SystemExit(f"first-party crates missing from cargo-geiger evidence: {missing_first_party}")

for name, expected in expected_first_party.items():
    observed = {int(row["unsafe_total"]) for row in first_party_rows if row["name"] == name}
    if not observed:
        raise SystemExit(f"missing first-party cargo-geiger row for {name}")
    if any(value != expected for value in observed):
        raise SystemExit(
            f"unexpected first-party unsafe count for {name}: "
            f"observed={sorted(observed)} expected={expected}"
        )

package_rows.sort(key=lambda row: (-int(row["unsafe_total"]), str(row["name"])))
with (artifact_dir / "geiger-packages.tsv").open("w", encoding="utf-8") as out:
    out.write("root\tpackage\tversion\tsource\tunsafe_total\tunsafe_breakdown\tforbids_unsafe\n")
    for row in package_rows:
        out.write(
            f"{row['root']}\t{row['name']}\t{row['version']}\t{row['source']}\t"
            f"{row['unsafe_total']}\t{row['breakdown']}\t{row['forbids_unsafe']}\n"
        )

with (artifact_dir / "first-party-geiger.tsv").open("w", encoding="utf-8") as out:
    out.write("root\tpackage\tunsafe_total\tunsafe_breakdown\texpected_current_count\n")
    for row in sorted(first_party_rows, key=lambda row: (str(row["root"]), str(row["name"]))):
        out.write(
            f"{row['root']}\t{row['name']}\t{row['unsafe_total']}\t"
            f"{row['breakdown']}\t{expected_first_party[row['name']]}\n"
        )

with (artifact_dir / "geiger-not-scanned.tsv").open("w", encoding="utf-8") as out:
    out.write("root\tpath\n")
    for root, path in not_scanned:
        out.write(f"{root}\t{path}\n")

with (artifact_dir / "geiger-warnings.tsv").open("w", encoding="utf-8") as out:
    out.write("root\tmessage\n")
    for root, message in stderr_warnings:
        out.write(f"{root}\t{message}\n")

unique_packages = {(row["name"], row["version"], row["source"]) for row in package_rows}
total_unsafe = sum(int(row["unsafe_total"]) for row in package_rows)
packages_with_unsafe = sum(1 for row in package_rows if int(row["unsafe_total"]) > 0)
completeness = "partial" if not_scanned or stderr_warnings else "complete"

with (artifact_dir / "geiger-summary.env").open("w", encoding="utf-8") as out:
    out.write(f"geiger_package_rows={len(package_rows)}\n")
    out.write(f"geiger_unique_packages={len(unique_packages)}\n")
    out.write(f"geiger_packages_with_unsafe={packages_with_unsafe}\n")
    out.write(f"geiger_total_unsafe_items={total_unsafe}\n")
    out.write(f"geiger_not_scanned_files={len(not_scanned)}\n")
    out.write(f"geiger_warning_lines={len(stderr_warnings)}\n")
    out.write(f"geiger_completeness_status={completeness}\n")

with (artifact_dir / "unsafe-dependency-traceability.tsv").open("w", encoding="utf-8") as out:
    out.write("requirement_id\tevidence\tartifact\tnote\n")
    out.write(
        "ODS-INV-006\tcargo-geiger retained enumeration\tgeiger-packages.tsv\t"
        "Transitive dependency unsafe counts are retained for release review; "
        "geiger-summary.env records whether the scanner completed without caveats.\n"
    )
    out.write(
        "ODS-NFR-SEC-001\tfirst-party safe-Rust posture\tfirst-party-geiger.tsv\t"
        "First-party package-level unsafe counts are checked against the current audited "
        "POSIX adapter posture; scripts/audit-safe-rust.sh remains the source-level gate.\n"
    )
    out.write(
        "ODS-NFR-MAINT-003\tunsafe review inputs\tgeiger-warnings.tsv; geiger-not-scanned.tsv\t"
        "Scanner warnings and unscanned files are retained so release review can avoid "
        "overclaiming cargo-geiger completeness.\n"
    )

with (artifact_dir / "README.md").open("w", encoding="utf-8") as out:
    out.write("# OxideDNS Unsafe Dependency Evidence\n\n")
    out.write(
        "This directory retains `cargo geiger` output for release review. It is "
        "not, by itself, an acceptance claim: first-party source-level unsafe "
        "gating remains enforced by `scripts/audit-safe-rust.sh`, and any "
        "scanner caveats are listed in `geiger-warnings.tsv` and "
        "`geiger-not-scanned.tsv`.\n\n"
    )
    out.write("Primary artifacts:\n\n")
    for name in [
        "tool-versions.env",
        "geiger-roots.tsv",
        "*-geiger.exit-status",
        "geiger-summary.env",
        "geiger-packages.tsv",
        "first-party-geiger.tsv",
        "geiger-warnings.tsv",
        "geiger-not-scanned.tsv",
        "unsafe-dependency-traceability.tsv",
    ]:
        out.write(f"- `{name}`\n")

print(f"geiger_completeness_status={completeness}")
print(f"geiger_unique_packages={len(unique_packages)}")
print(f"geiger_total_unsafe_items={total_unsafe}")
PY

printf 'unsafe_dependency_evidence_dir=%s\n' "$artifact_dir"
