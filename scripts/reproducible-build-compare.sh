#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/package-common.sh"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${BORONDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR:-$repo_root/target/evidence/reproducible-build-$timestamp}"
target_triple="${BORONDNS_REPRODUCIBLE_BUILD_TARGET:-x86_64-unknown-linux-musl}"
allow_dirty_non_release="${BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE:-0}"
[[ "$allow_dirty_non_release" == 0 || "$allow_dirty_non_release" == 1 ]] || {
    printf 'BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE must be 0 or 1\n' >&2
    exit 1
}

source_commit="$(git -C "$repo_root" rev-parse HEAD)" || {
    printf 'failed to determine source commit\n' >&2
    exit 1
}
dirty_status=""
if ! dirty_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no)"; then
    printf 'failed to determine source-tree cleanliness\n' >&2
    exit 1
fi

verify_source_identity() {
    local boundary="$1"
    local actual_commit actual_status
    actual_commit="$(git -C "$repo_root" rev-parse HEAD)" || {
        printf 'failed to determine source commit at %s\n' "$boundary" >&2
        return 1
    }
    actual_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no)" || {
        printf 'failed to determine source status at %s\n' "$boundary" >&2
        return 1
    }
    if [[ "$actual_commit" != "$source_commit" || "$actual_status" != "$dirty_status" ]]; then
        printf 'source identity changed during reproducible-build comparison at %s\n' "$boundary" >&2
        printf 'expected_commit=%s actual_commit=%s\n' "$source_commit" "$actual_commit" >&2
        return 1
    fi
}

verify_source_identity "initial preflight"
dirty="no"
release_eligible="true"
if [[ -n "$dirty_status" ]]; then
    dirty="yes"
    release_eligible="false"
    if [[ "$allow_dirty_non_release" != 1 ]]; then
        printf 'refusing reproducible-build comparison from dirty or untracked source:\n%s\n' \
            "$dirty_status" >&2
        printf 'use BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE=1 only for explicitly non-release diagnostics\n' >&2
        exit 1
    fi
    printf 'warning: dirty-source override enabled; evidence will be non-release and non-passing\n' >&2
fi

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

cargo_bin="${BORONDNS_REPRODUCIBLE_BUILD_CARGO:-$(rustup which cargo 2>/dev/null || command -v cargo || true)}"
if [[ -z "$cargo_bin" || ! -x "$cargo_bin" ]]; then
    printf 'missing usable cargo binary; set BORONDNS_REPRODUCIBLE_BUILD_CARGO\n' >&2
    exit 1
fi
rustc_bin="${BORONDNS_REPRODUCIBLE_BUILD_RUSTC:-$(rustup which rustc 2>/dev/null || command -v rustc || true)}"
if [[ -z "$rustc_bin" || ! -x "$rustc_bin" ]]; then
    printf 'missing usable rustc binary; set BORONDNS_REPRODUCIBLE_BUILD_RUSTC\n' >&2
    exit 1
fi
cargo_bin="$(realpath -e "$cargo_bin")"
rustc_bin="$(realpath -e "$rustc_bin")"
toolchain_bin="$(dirname "$rustc_bin")"
toolchain_root="$(dirname "$toolchain_bin")"

if ! rustup target list --installed | grep -Fx "$target_triple" >/dev/null 2>&1; then
    rustup target add "$target_triple"
fi

commit="$source_commit"
short_commit="${commit:0:12}"
commit_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD)"
commit_timestamp="$(date -u -d "@$commit_epoch" '+%Y-%m-%dT%H:%M:%SZ')"
rust_version="$("$rustc_bin" --version)"
cargo_version="$("$cargo_bin" --version)"
host_triple="$("$rustc_bin" -vV | awk -F': ' '/^host:/ { print $2 }')"
build_a="$evidence_dir/build-a"
build_b="$evidence_dir/build-b"
evidence_parent="$(dirname "$evidence_dir")"
mkdir -p "$evidence_parent"
if ! mkdir "$evidence_dir"; then
    printf 'refusing to reuse an existing reproducible-build evidence destination: %s\n' "$evidence_dir" >&2
    printf 'choose a fresh BORONDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR so stale success cannot survive a failed rerun\n' >&2
    exit 1
fi
mkdir "$evidence_dir/artifacts" "$evidence_dir/artifacts/a" "$evidence_dir/artifacts/b"
hermetic_home="$evidence_dir/hermetic-home"
hermetic_cargo_home="$evidence_dir/hermetic-cargo-home"
mkdir -m 0700 "$hermetic_home" "$hermetic_cargo_home"

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
borondns_build_commit=$short_commit
borondns_build_rust_version=$rust_version
borondns_build_timestamp=$commit_timestamp
cargo_incremental=0
EOF
}

run_build() {
    local label="$1"
    local target_dir="$2"
    local target_dir_for_cargo
    target_dir_for_cargo="$(target_dir_arg "$target_dir")"
    local release_encoded_rustflags
    release_encoded_rustflags="$(package_release_encoded_rustflags \
        "$repo_root" "$hermetic_cargo_home" "$target_dir" "$toolchain_root")"
    local log="$evidence_dir/build-$label.log"

    verify_source_identity "before build $label"
    {
        printf 'builder=%s\n' "$label"
        printf 'target_dir=%s\n' "$target_dir"
        printf 'target_dir_for_cargo=%s\n' "$target_dir_for_cargo"
        printf '%q build --locked --release --target-dir %q --target %q -p borondns-cli\n' "$cargo_bin" "$target_dir_for_cargo" "$target_triple"
        printf '%q build --locked --release --target-dir %q --target %q -p boron-gun --features xdp\n\n' "$cargo_bin" "$target_dir_for_cargo" "$target_triple"
    } >"$log"

    (
        cd "$repo_root"
        env -i HOME="$hermetic_home" CARGO_HOME="$hermetic_cargo_home" \
            PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \
            CARGO_ENCODED_RUSTFLAGS="$release_encoded_rustflags" \
            SOURCE_DATE_EPOCH="$commit_epoch" CARGO_INCREMENTAL=0 \
            BORONDNS_BUILD_COMMIT="$short_commit" \
            BORONDNS_BUILD_RUST_VERSION="$rust_version" \
            BORONDNS_BUILD_TIMESTAMP="$commit_timestamp" \
            "$cargo_bin" build --locked --release --target-dir "$target_dir_for_cargo" \
            --target "$target_triple" -p borondns-cli
        env -i HOME="$hermetic_home" CARGO_HOME="$hermetic_cargo_home" \
            PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \
            CARGO_ENCODED_RUSTFLAGS="$release_encoded_rustflags" \
            SOURCE_DATE_EPOCH="$commit_epoch" CARGO_INCREMENTAL=0 \
            BORONDNS_BUILD_COMMIT="$short_commit" \
            BORONDNS_BUILD_RUST_VERSION="$rust_version" \
            BORONDNS_BUILD_TIMESTAMP="$commit_timestamp" \
            "$cargo_bin" build --locked --release --target-dir "$target_dir_for_cargo" \
            --target "$target_triple" -p boron-gun --features xdp
    ) >>"$log" 2>&1
    verify_source_identity "after build $label"
}

copy_artifacts() {
    local label="$1"
    local target_dir="$2"
    local out_dir="$evidence_dir/artifacts/$label"

    install -m 0755 "$target_dir/$target_triple/release/borondns" "$out_dir/borondns"
    install -m 0755 "$target_dir/$target_triple/release/boron-gun" "$out_dir/boron-gun"
    file "$out_dir/borondns" >"$out_dir/file-borondns.txt"
    file "$out_dir/boron-gun" >"$out_dir/file-boron-gun.txt"
    if command -v ldd >/dev/null 2>&1; then
        ldd "$out_dir/borondns" >"$out_dir/ldd-borondns.txt" 2>&1 || true
        ldd "$out_dir/boron-gun" >"$out_dir/ldd-boron-gun.txt" 2>&1 || true
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
    local logical_cargo_bin="/build/rust-toolchain/bin/cargo"
    printf 'artifact\tbuilder\ttarget\tprofile\tfeatures\tcommit\trust_version\tbuild_command\tsha256\tsize_bytes\tevidence_path\n' >"$manifest"
    for builder in a b; do
        for artifact in borondns boron-gun; do
            local features
            local command
            if [[ "$artifact" == "borondns" ]]; then
                features=""
                command="$logical_cargo_bin build --locked --release --target-dir <builder-target-dir> --target $target_triple -p borondns-cli"
            else
                features="xdp"
                command="$logical_cargo_bin build --locked --release --target-dir <builder-target-dir> --target $target_triple -p boron-gun --features xdp"
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
    local artifact_match="true"
    for artifact in borondns boron-gun; do
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
            artifact_match="false"
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

    local reproducible_status="$artifact_match"
    [[ "$release_eligible" == true ]] || reproducible_status=false
    cat >"$evidence_dir/reproducible-build-summary.env" <<EOF
reproducible_build_status=$reproducible_status
artifact_match=$artifact_match
release_eligible=$release_eligible
dirty_source_override=$allow_dirty_non_release
artifact_count=2
matched_artifact_count=$(awk -F '\t' 'NR > 1 && $8 == "true" { count++ } END { print count + 0 }' "$comparison")
target_triple=$target_triple
commit=$commit
source_date_epoch=$commit_epoch
evidence_dir=$evidence_dir
EOF

    if [[ "$artifact_match" != "true" ]]; then
        return 1
    fi
}

write_traceability() {
    cat >"$evidence_dir/requirements-traceability.tsv" <<'EOF'
requirement_id	evidence_state	artifact	note
BDS-NFR-MAINT-005	retained-local-comparison	artifact-manifest.tsv; comparison.tsv; reproducible-build-summary.env	Two builds in separate target directories are compared; reproducible-build-summary.env is authoritative for artifact match, source cleanliness, and release eligibility.
BDS-NFR-OBS-006	retained-local-comparison	reproducible-build-env.env	The build fixed BORONDNS_BUILD_COMMIT, BORONDNS_BUILD_RUST_VERSION, BORONDNS_BUILD_TIMESTAMP, and SOURCE_DATE_EPOCH so embedded build-info labels are deterministic.
BDS-INV-009	retained-local-comparison	cargo-metadata.locked.json; reproducible-build-env.env	The comparison used locked Cargo metadata and static source-tree inputs.
BDS-VER-010	retained-local-comparison	README.md; reproducible-build-summary.env	The retained evidence directory records command, environment, digests, and comparison result for release-note publication.
EOF
}

write_readme() {
    cat >"$evidence_dir/README.md" <<EOF
# BoronDNS Reproducible Build Evidence

Created UTC: $timestamp

This evidence directory was produced by \`scripts/reproducible-build-compare.sh\`.
It performs two clean release builds in separate target directories and compares
the produced static musl binaries.

## Scope

Verified artifacts:

- \`borondns\`, built from package \`borondns-cli\` with feature \`af-xdp\`.
- \`boron-gun\`, built from package \`boron-gun\` with feature \`xdp\`.

Target: \`$target_triple\`
Commit: \`$commit\`
Rust: \`$rust_version\`
Cargo: \`$cargo_bin\`
Dirty source: \`$dirty\`
Release eligible: \`$release_eligible\`

The comparison fixes:

- \`SOURCE_DATE_EPOCH=$commit_epoch\`
- \`BORONDNS_BUILD_COMMIT=$short_commit\`
- \`BORONDNS_BUILD_RUST_VERSION=$rust_version\`
- \`BORONDNS_BUILD_TIMESTAMP=$commit_timestamp\`
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
    if [[ "$release_eligible" != true ]]; then
        cat >>"$evidence_dir/README.md" <<'EOF'

## Non-release dirty-source diagnostic

This run used the explicit dirty-source override. It is intentionally marked
`reproducible_build_status=false` and `release_eligible=false` even if the two
diagnostic artifact digests match. It must not be used as release provenance.
EOF
    fi
}

verify_source_identity "before evidence initialization"
write_env
verify_source_identity "before locked metadata capture"
env -i HOME="$hermetic_home" CARGO_HOME="$hermetic_cargo_home" \
    PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \
    "$cargo_bin" metadata --locked --format-version 1 \
    >"$evidence_dir/cargo-metadata.locked.json"
verify_source_identity "after locked metadata capture"
run_build a "$build_a"
run_build b "$build_b"
verify_source_identity "before artifact capture"
copy_artifacts a "$build_a"
copy_artifacts b "$build_b"
verify_source_identity "after artifact capture"
write_manifest_and_compare
write_traceability
write_readme
verify_source_identity "terminal publication"

printf 'reproducible_build_evidence_dir=%s\n' "$evidence_dir"
if [[ "$release_eligible" != true ]]; then
    printf 'dirty-source diagnostic evidence is never valid release provenance: %s\n' "$evidence_dir" >&2
    exit 2
fi
