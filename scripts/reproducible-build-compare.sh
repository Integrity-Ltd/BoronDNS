#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${OXIDEDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR:-$repo_root/target/evidence/reproducible-build-$timestamp}"
target_triple="${OXIDEDNS_REPRODUCIBLE_BUILD_TARGET:-x86_64-unknown-linux-musl}"

missing=()
for tool in rustc rustup sha256sum stat file; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required reproducible-build tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

cargo_bin="${OXIDEDNS_REPRODUCIBLE_BUILD_CARGO:-$(rustup which cargo 2>/dev/null || command -v cargo || true)}"
if [[ -z "$cargo_bin" || ! -x "$cargo_bin" ]]; then
    printf 'missing usable cargo binary; set OXIDEDNS_REPRODUCIBLE_BUILD_CARGO\n' >&2
    exit 1
fi
rustc_bin="${OXIDEDNS_REPRODUCIBLE_BUILD_RUSTC:-$(rustup which rustc 2>/dev/null || command -v rustc || true)}"
if [[ -z "$rustc_bin" || ! -x "$rustc_bin" ]]; then
    printf 'missing usable rustc binary; set OXIDEDNS_REPRODUCIBLE_BUILD_RUSTC\n' >&2
    exit 1
fi
toolchain_bin="$(dirname "$rustc_bin")"

if ! rustup target list --installed | grep -Fx "$target_triple" >/dev/null 2>&1; then
    rustup target add "$target_triple"
fi

commit="$(git -C "$repo_root" rev-parse HEAD)"
short_commit="$(git -C "$repo_root" rev-parse --short=8 HEAD)"
commit_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD)"
commit_timestamp="$(date -u -d "@$commit_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
rust_version="$("$rustc_bin" --version)"
cargo_version="$("$cargo_bin" --version)"
host_triple="$("$rustc_bin" -vV | awk -F': ' '/^host:/ { print $2 }')"
dirty_status="$(git -C "$repo_root" status --short)"
dirty="no"
if [[ -n "$dirty_status" ]]; then
    dirty="yes"
fi

build_a="$evidence_dir/build-a"
build_b="$evidence_dir/build-b"
mkdir -p "$evidence_dir" "$evidence_dir/artifacts/a" "$evidence_dir/artifacts/b"
rm -rf "$build_a" "$build_b"

target_dir_arg() {
    local path="$1"
    realpath --relative-to="$repo_root" "$path" 2>/dev/null || printf '%s' "$path"
}

write_env() {
    cat >"$evidence_dir/reproducible-build-env.env" <<EOF
created_utc=$timestamp
repo_root=$repo_root
commit=$commit
short_commit=$short_commit
dirty=$dirty
commit_epoch=$commit_epoch
commit_timestamp=$commit_timestamp
rust_version=$rust_version
cargo_version=$cargo_version
cargo_binary=$cargo_bin
rustc_binary=$rustc_bin
host_triple=$host_triple
target_triple=$target_triple
source_date_epoch=$commit_epoch
oxidedns_build_commit=$short_commit
oxidedns_build_rust_version=$rust_version
oxidedns_build_timestamp=$commit_timestamp
cargo_incremental=0
EOF
}

run_build() {
    local label="$1"
    local target_dir="$2"
    local target_dir_for_cargo
    target_dir_for_cargo="$(target_dir_arg "$target_dir")"
    local log="$evidence_dir/build-$label.log"

    {
        printf 'builder=%s\n' "$label"
        printf 'target_dir=%s\n' "$target_dir"
        printf 'target_dir_for_cargo=%s\n' "$target_dir_for_cargo"
        printf '%q build --locked --release --target-dir %q --target %q -p oxidedns-cli --features af-xdp\n' "$cargo_bin" "$target_dir_for_cargo" "$target_triple"
        printf '%q build --locked --release --target-dir %q --target %q -p oxide-gun --features xdp\n\n' "$cargo_bin" "$target_dir_for_cargo" "$target_triple"
    } >"$log"

    (
        cd "$repo_root"
        export CARGO_INCREMENTAL=0
        export PATH="$toolchain_bin:$PATH"
        export RUSTC="$rustc_bin"
        export SOURCE_DATE_EPOCH="$commit_epoch"
        export OXIDEDNS_BUILD_COMMIT="$short_commit"
        export OXIDEDNS_BUILD_RUST_VERSION="$rust_version"
        export OXIDEDNS_BUILD_TIMESTAMP="$commit_timestamp"
        "$cargo_bin" build --locked --release --target-dir "$target_dir_for_cargo" --target "$target_triple" -p oxidedns-cli --features af-xdp
        "$cargo_bin" build --locked --release --target-dir "$target_dir_for_cargo" --target "$target_triple" -p oxide-gun --features xdp
    ) >>"$log" 2>&1
}

copy_artifacts() {
    local label="$1"
    local target_dir="$2"
    local out_dir="$evidence_dir/artifacts/$label"

    install -m 0755 "$target_dir/$target_triple/release/oxidedns" "$out_dir/oxidedns"
    install -m 0755 "$target_dir/$target_triple/release/oxide-gun" "$out_dir/oxide-gun"
    file "$out_dir/oxidedns" >"$out_dir/file-oxidedns.txt"
    file "$out_dir/oxide-gun" >"$out_dir/file-oxide-gun.txt"
    if command -v ldd >/dev/null 2>&1; then
        ldd "$out_dir/oxidedns" >"$out_dir/ldd-oxidedns.txt" 2>&1 || true
        ldd "$out_dir/oxide-gun" >"$out_dir/ldd-oxide-gun.txt" 2>&1 || true
    fi
}

artifact_sha() {
    sha256sum "$1" | awk '{ print $1 }'
}

artifact_size() {
    stat -c '%s' "$1"
}

write_manifest_and_compare() {
    local manifest="$evidence_dir/artifact-manifest.tsv"
    local comparison="$evidence_dir/comparison.tsv"
    printf 'artifact\tbuilder\ttarget\tprofile\tfeatures\tcommit\trust_version\tbuild_command\tsha256\tsize_bytes\tevidence_path\n' >"$manifest"
    for builder in a b; do
        for artifact in oxidedns oxide-gun; do
            local features
            local command
            if [[ "$artifact" == "oxidedns" ]]; then
                features="af-xdp"
                command="$cargo_bin build --locked --release --target-dir <builder-target-dir> --target $target_triple -p oxidedns-cli --features af-xdp"
            else
                features="xdp"
                command="$cargo_bin build --locked --release --target-dir <builder-target-dir> --target $target_triple -p oxide-gun --features xdp"
            fi
            local path="$evidence_dir/artifacts/$builder/$artifact"
            printf '%s\t%s\t%s\trelease\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$artifact" \
                "$builder" \
                "$target_triple" \
                "$features" \
                "$commit" \
                "$rust_version" \
                "$command" \
                "$(artifact_sha "$path")" \
                "$(artifact_size "$path")" \
                "artifacts/$builder/$artifact" \
                >>"$manifest"
        done
    done

    printf 'artifact\ttarget\tprofile\tbuilder_a_sha256\tbuilder_b_sha256\tbuilder_a_size_bytes\tbuilder_b_size_bytes\tmatch\tevidence_path_a\tevidence_path_b\n' >"$comparison"
    local all_match="true"
    for artifact in oxidedns oxide-gun; do
        local path_a="$evidence_dir/artifacts/a/$artifact"
        local path_b="$evidence_dir/artifacts/b/$artifact"
        local sha_a sha_b size_a size_b match
        sha_a="$(artifact_sha "$path_a")"
        sha_b="$(artifact_sha "$path_b")"
        size_a="$(artifact_size "$path_a")"
        size_b="$(artifact_size "$path_b")"
        match="false"
        if [[ "$sha_a" == "$sha_b" && "$size_a" == "$size_b" ]]; then
            match="true"
        else
            all_match="false"
        fi
        printf '%s\t%s\trelease\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$artifact" \
            "$target_triple" \
            "$sha_a" \
            "$sha_b" \
            "$size_a" \
            "$size_b" \
            "$match" \
            "artifacts/a/$artifact" \
            "artifacts/b/$artifact" \
            >>"$comparison"
    done

    cat >"$evidence_dir/reproducible-build-summary.env" <<EOF
reproducible_build_status=$all_match
artifact_count=2
matched_artifact_count=$(awk -F '\t' 'NR > 1 && $8 == "true" { count++ } END { print count + 0 }' "$comparison")
target_triple=$target_triple
commit=$commit
source_date_epoch=$commit_epoch
evidence_dir=$evidence_dir
EOF

    if [[ "$all_match" != "true" ]]; then
        return 1
    fi
}

write_traceability() {
    cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_state	artifact	note
ODS-NFR-MAINT-005	retained-local-comparison	artifact-manifest.tsv; comparison.tsv; reproducible-build-summary.env	Two clean release builds in separate target directories produced bit-identical static musl oxidedns and oxide-gun binaries from the same commit, lockfile, toolchain, target, and fixed build metadata.
ODS-NFR-OBS-006	retained-local-comparison	reproducible-build-env.env	The build fixed OXIDEDNS_BUILD_COMMIT, OXIDEDNS_BUILD_RUST_VERSION, OXIDEDNS_BUILD_TIMESTAMP, and SOURCE_DATE_EPOCH so embedded build-info labels are deterministic.
ODS-INV-009	retained-local-comparison	cargo-metadata.locked.json; reproducible-build-env.env	The comparison used locked Cargo metadata and static source-tree inputs.
ODS-VER-010	retained-local-comparison	README.md; reproducible-build-summary.env	The retained evidence directory records command, environment, digests, and comparison result for release-note publication.
EOF
}

write_readme() {
    cat >"$evidence_dir/README.md" <<EOF
# OxideDNS Reproducible Build Evidence

Created UTC: $timestamp

This evidence directory was produced by \`scripts/reproducible-build-compare.sh\`.
It performs two clean release builds in separate target directories and compares
the produced static musl binaries.

## Scope

Verified artifacts:

- \`oxidedns\`, built from package \`oxidedns-cli\` with feature \`af-xdp\`.
- \`oxide-gun\`, built from package \`oxide-gun\` with feature \`xdp\`.

Target: \`$target_triple\`
Commit: \`$commit\`
Rust: \`$rust_version\`
Cargo: \`$cargo_bin\`

The comparison fixes:

- \`SOURCE_DATE_EPOCH=$commit_epoch\`
- \`OXIDEDNS_BUILD_COMMIT=$short_commit\`
- \`OXIDEDNS_BUILD_RUST_VERSION=$rust_version\`
- \`OXIDEDNS_BUILD_TIMESTAMP=$commit_timestamp\`
- \`CARGO_INCREMENTAL=0\`

## Results

See:

- \`reproducible-build-summary.env\`
- \`artifact-manifest.tsv\`
- \`comparison.tsv\`
- \`requirements-traceability.tsv\`
- \`build-a.log\`
- \`build-b.log\`

This local comparison does not sign artifacts and does not claim Docker image
archive reproducibility.
EOF
}

write_env
"$cargo_bin" metadata --locked --format-version 1 >"$evidence_dir/cargo-metadata.locked.json"
run_build a "$build_a"
run_build b "$build_b"
copy_artifacts a "$build_a"
copy_artifacts b "$build_b"
write_manifest_and_compare
write_traceability
write_readme

printf 'reproducible_build_evidence_dir=%s\n' "$evidence_dir"
