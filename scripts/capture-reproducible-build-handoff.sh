#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_REPRODUCIBLE_BUILD_HANDOFF_DIR:-$repo_root/target/evidence/reproducible-build-handoff-$timestamp}"

commit="$(git -C "$repo_root" rev-parse HEAD)"
short_commit="$(git -C "$repo_root" rev-parse --short=8 HEAD)"
branch="$(git -C "$repo_root" branch --show-current)"
dirty_status="$(git -C "$repo_root" status --short)"
if [[ -n "$dirty_status" ]]; then
  dirty="yes"
else
  dirty="no"
fi
commit_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD)"
commit_timestamp="$(date -u -d "@$commit_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
rust_version="$(rustc --version 2>/dev/null || printf 'missing-rustc')"
cargo_version="$(cargo --version 2>/dev/null || printf 'missing-cargo')"
target_triple="$(rustc -vV 2>/dev/null | awk -F': ' '/^host:/ { print $2 }' || true)"
target_triple="${target_triple:-unknown}"
sha256_tool="sha256sum"
if ! command -v "$sha256_tool" >/dev/null 2>&1; then
  sha256_tool="shasum -a 256"
fi

file_hash() {
  local path="$1"
  if [[ -f "$repo_root/$path" ]]; then
    $sha256_tool "$repo_root/$path" | awk '{ print $1 }'
  else
    printf 'missing'
  fi
}

cargo_lock_sha256="$(file_hash Cargo.lock)"
rust_toolchain_sha256="$(file_hash rust-toolchain.toml)"

mkdir -p "$evidence_dir"

cat >"$evidence_dir/reproducible-build-env.env" <<EOF
OXIDEDNS_REPRODUCIBLE_BUILD_CREATED_UTC=$timestamp
OXIDEDNS_REPRODUCIBLE_BUILD_REPO_ROOT=$repo_root
OXIDEDNS_REPRODUCIBLE_BUILD_COMMIT=$commit
OXIDEDNS_REPRODUCIBLE_BUILD_SHORT_COMMIT=$short_commit
OXIDEDNS_REPRODUCIBLE_BUILD_BRANCH=$branch
OXIDEDNS_REPRODUCIBLE_BUILD_DIRTY=$dirty
OXIDEDNS_REPRODUCIBLE_BUILD_COMMIT_EPOCH=$commit_epoch
OXIDEDNS_REPRODUCIBLE_BUILD_COMMIT_TIMESTAMP=$commit_timestamp
OXIDEDNS_REPRODUCIBLE_BUILD_RUST_VERSION=$rust_version
OXIDEDNS_REPRODUCIBLE_BUILD_CARGO_VERSION=$cargo_version
OXIDEDNS_REPRODUCIBLE_BUILD_TARGET=$target_triple
OXIDEDNS_REPRODUCIBLE_BUILD_CARGO_LOCK_SHA256=$cargo_lock_sha256
OXIDEDNS_REPRODUCIBLE_BUILD_RUST_TOOLCHAIN_SHA256=$rust_toolchain_sha256
SOURCE_DATE_EPOCH=$commit_epoch
OXIDEDNS_BUILD_COMMIT=$short_commit
OXIDEDNS_BUILD_RUST_VERSION=$rust_version
OXIDEDNS_BUILD_TIMESTAMP=$commit_timestamp
EOF

if command -v cargo >/dev/null 2>&1; then
  cargo metadata --locked --format-version 1 >"$evidence_dir/cargo-metadata.locked.json"
else
  printf 'cargo is not available; cargo metadata was not captured\n' \
    >"$evidence_dir/cargo-metadata.locked.json"
fi

cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_artifact	local_mvp_status	later_release_ops_action
ODS-NFR-MAINT-005	reproducible-build-runbook.md; artifact-manifest-template.tsv; comparison-template.tsv	setup-ready	run at least two independent clean builds from the same commit/toolchain and record bit-identical artifact comparison
ODS-NFR-MAINT-008	artifact-manifest-template.tsv; release-engineer-signoff.md	setup-ready	sign accepted artifacts after the reproducible-build comparison is complete
ODS-NFR-OBS-006	reproducible-build-env.env	setup-ready	build with fixed OXIDEDNS_BUILD_* values so embedded build-info labels remain deterministic
ODS-INV-009	reproducible-build-runbook.md; cargo-metadata.locked.json	setup-ready	confirm all executable release inputs come from the static source tree, lockfile, and build workflow
ODS-VER-002	requirements-traceability.tsv	setup-ready	retain completed build evidence against the requirement IDs in release evidence
ODS-VER-009	requirements-traceability.tsv	setup-ready	carry completed reproducible-build artifact paths into the traceability matrix or release ledger
ODS-VER-008	release-engineer-signoff.md	setup-ready	attach completed reproducible-build comparison before final MVP acceptance
ODS-VER-010	release-notes-snippet.md	setup-ready	publish build command, artifact digests, comparison result, and evidence paths in release notes
ODS-VER-015	release-engineer-signoff.md	setup-ready	record responsible release engineer and independent builder scopes/signatures
EOF

cat >"$evidence_dir/artifact-manifest-template.tsv" <<'EOF'
artifact	target	profile	commit	rust_version	build_command	sha256	size_bytes	builder	evidence_path	notes
EOF

cat >"$evidence_dir/comparison-template.tsv" <<'EOF'
artifact	target	profile	builder_a_sha256	builder_b_sha256	match	evidence_path_a	evidence_path_b	notes
EOF

cat >"$evidence_dir/release-notes-snippet.md" <<'EOF'
## Reproducible Build Evidence Summary

- Reproducible build handoff or completed artifact path:
- Build command:
- Fixed build environment:
- Cargo.lock and cargo metadata evidence:
- Artifact manifest:
- Independent builder comparison:
- Bit-identical result:
- Signed artifact manifest:
- Release engineer:
- Deferred execution rationale, if any:
EOF

cat >"$evidence_dir/release-engineer-signoff.md" <<'EOF'
# OxideDNS Reproducible Build Release Engineer Sign-off

- Release:
- Evidence snapshot:
- Reproducible-build evidence directory:
- Release engineer:
- Independent builder A:
- Independent builder B:
- Source commit:
- Rust toolchain:
- Target triple:
- Artifact manifest:
- Comparison result:
- Signed artifact manifest:
- Exceptions or accepted deviations:
- Signature:
- Date UTC:
EOF

cat >"$evidence_dir/reproducible-build-runbook.md" <<EOF
# OxideDNS Reproducible Build Runbook

This is the local MVP setup artifact for ODS-NFR-MAINT-005. It does not claim
that two independent bit-identical builds have already happened.

## Fixed Inputs

- Source commit: \`$commit\`
- Source branch at handoff capture: \`$branch\`
- Dirty checkout at handoff capture: \`$dirty\`
- Cargo lockfile: \`Cargo.lock\`
- Cargo.lock SHA256: \`$cargo_lock_sha256\`
- Rust toolchain: \`rust-toolchain.toml\`
- rust-toolchain.toml SHA256: \`$rust_toolchain_sha256\`
- Cargo metadata snapshot: \`cargo-metadata.locked.json\`
- Target triple: \`$target_triple\`
- SOURCE_DATE_EPOCH: \`$commit_epoch\`
- OXIDEDNS_BUILD_COMMIT: \`$short_commit\`
- OXIDEDNS_BUILD_RUST_VERSION: \`$rust_version\`
- OXIDEDNS_BUILD_TIMESTAMP: \`$commit_timestamp\`

The server binary embeds build commit, Rust version, and build timestamp for
\`ODS-NFR-OBS-006\`. Builders must set the \`OXIDEDNS_BUILD_*\` values above, or the
default wall-clock build timestamp in \`crates/oxidedns-server/build.rs\` will make
otherwise equivalent builds differ.

## Build Command

\`\`\`sh
export SOURCE_DATE_EPOCH=$commit_epoch
export OXIDEDNS_BUILD_COMMIT=$short_commit
export OXIDEDNS_BUILD_RUST_VERSION='$rust_version'
export OXIDEDNS_BUILD_TIMESTAMP=$commit_timestamp
cargo build --locked --release -p oxidedns-cli
\`\`\`

## Independent Builder Procedure

1. Start from a clean checkout of \`$commit\` in two independent environments.
2. Confirm \`git status --short\` is empty in both environments.
3. Confirm \`rustc --version\`, \`cargo --version\`, and target triple match.
4. Run \`cargo metadata --locked --format-version 1\` and retain the output.
5. Run the fixed build command above.
6. Record each produced artifact in \`artifact-manifest-template.tsv\` with:
   artifact path, target, profile, commit, Rust version, exact build command,
   SHA256, size, builder, and evidence path.
7. Compare matching artifact digests in \`comparison-template.tsv\`.
8. A \`match=false\` row is not accepted reproducible-build evidence; retain
   the row with root-cause notes and block MVP acceptance until resolved or
   explicitly deferred by the project.
9. After bit-identical artifacts are accepted, sign the release artifact
   manifest through the release-signing process.

Suggested digest command:

\`\`\`sh
$sha256_tool target/release/oxidedns
\`\`\`

## Non-Goals

- This handoff does not run production release builds.
- This handoff does not sign artifacts.
- This handoff does not prove reproducibility until two independent completed
  manifests and a matching comparison are attached.
EOF

cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Reproducible Build Handoff

Created UTC: $timestamp

This directory is the local project MVP setup artifact for later
release/operations execution of reproducible-build verification. It does not
claim that two independent bit-identical builds have completed.

Artifacts:

- \`reproducible-build-env.env\`
- \`cargo-metadata.locked.json\`
- \`requirements-traceability.tsv\`
- \`artifact-manifest-template.tsv\`
- \`comparison-template.tsv\`
- \`reproducible-build-runbook.md\`
- \`release-notes-snippet.md\`
- \`release-engineer-signoff.md\`
EOF

printf 'reproducible_build_handoff_dir=%s\n' "$evidence_dir"
