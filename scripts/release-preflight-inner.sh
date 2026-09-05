#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" == 0 ]] || {
    printf 'release preflight container must run as root\n' >&2
    exit 1
}
[[ -n "${BORONDNS_PREFLIGHT_EXPECTED_COMMIT:-}" ]] || {
    printf 'missing BORONDNS_PREFLIGHT_EXPECTED_COMMIT\n' >&2
    exit 1
}
[[ -n "${BORONDNS_PREFLIGHT_WORKSPACE:-}" ]] || {
    printf 'missing BORONDNS_PREFLIGHT_WORKSPACE\n' >&2
    exit 1
}
[[ -f /source.bundle ]] || {
    printf 'missing read-only release source bundle at /source.bundle\n' >&2
    exit 1
}

work_root="$BORONDNS_PREFLIGHT_WORKSPACE"
repo_root="$work_root/source"
[[ -d "$work_root" && ! -L "$work_root" ]] || {
    printf 'invalid release preflight workspace: %s\n' "$work_root" >&2
    exit 1
}
cleanup_workspace_permissions() {
    local status=$?
    trap - EXIT
    chmod -R u+rwX,go+rX "$work_root" 2>/dev/null || status=74
    exit "$status"
}
trap cleanup_workspace_permissions EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
git -c advice.detachedHead=false clone --quiet /source.bundle "$repo_root"
actual_commit="$(git -C "$repo_root" rev-parse HEAD)"
[[ "$actual_commit" == "$BORONDNS_PREFLIGHT_EXPECTED_COMMIT" ]] || {
    printf 'preflight clone commit mismatch: expected=%s actual=%s\n' \
        "$BORONDNS_PREFLIGHT_EXPECTED_COMMIT" "$actual_commit" >&2
    exit 1
}
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no)" ]]

docker info >/dev/null 2>&1 || {
    printf 'host Docker daemon is unavailable inside release preflight container\n' >&2
    exit 1
}

cd "$repo_root"
cargo_path="$(realpath -e "$(rustup which cargo)")"
rustc_path="$(realpath -e "$(rustup which rustc)")"
evidence="$work_root/reproducibility"
release_target="$work_root/release-target"

python3 scripts/check-version-consistency.py
python3 scripts/check-release-signing-policy.py
scripts/test-package-publication-recovery.sh

BORONDNS_REPRODUCIBLE_BUILD_CARGO="$cargo_path" \
    BORONDNS_REPRODUCIBLE_BUILD_RUSTC="$rustc_path" \
    BORONDNS_REPRODUCIBLE_BUILD_EVIDENCE_DIR="$evidence" \
    scripts/reproducible-build-compare.sh
python3 scripts/verify-release-reproducibility.py \
    --require-artifacts "$evidence" "$actual_commit"

rm -rf target/dist "$release_target"
mkdir -p "$release_target"
CARGO="$cargo_path" RUSTC="$rustc_path" CARGO_TARGET_DIR="$release_target" \
    scripts/package-installer.sh

shopt -s nullglob
release_borondns=(target/dist/borondns-*-x86_64-unknown-linux-musl.bin)
release_boron_gun=(target/dist/borondns-*-x86_64-unknown-linux-musl-boron-gun.bin)
[[ "${#release_borondns[@]}" == 1 && "${#release_boron_gun[@]}" == 1 ]]
for builder in a b; do
    cmp -- "$evidence/artifacts/$builder/borondns" "${release_borondns[0]}"
    cmp -- "$evidence/artifacts/$builder/boron-gun" "${release_boron_gun[0]}"
done

scripts/test-installer-docker.sh
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
    BORONDNS_DEB_BORONDNS_BIN="${release_borondns[0]}" \
    BORONDNS_DEB_BORON_GUN_BIN="${release_boron_gun[0]}" scripts/package-deb.sh
scripts/test-deb-package-docker.sh
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
    BORONDNS_RPM_BORONDNS_BIN="${release_borondns[0]}" \
    BORONDNS_RPM_BORON_GUN_BIN="${release_boron_gun[0]}" scripts/package-rpm.sh
scripts/test-rpm-package-docker.sh
CARGO="$cargo_path" RUSTC="$rustc_path" scripts/package-docker-image.sh
scripts/test-docker-image.sh
CARGO="$cargo_path" RUSTC="$rustc_path" BORONDNS_SBOM_DOCKER=1 scripts/package-sbom.sh

ldd "${release_borondns[0]}" >"$work_root/borondns.ldd" 2>&1 || true
grep -Eiq 'not a dynamic executable|statically linked' "$work_root/borondns.ldd"
"${release_borondns[0]}" --version
ldd "${release_boron_gun[0]}" >"$work_root/boron-gun.ldd" 2>&1 || true
grep -Eiq 'not a dynamic executable|statically linked' "$work_root/boron-gun.ldd"
"${release_boron_gun[0]}" --version

python3 scripts/validate-release-preflight.py \
    --dist target/dist --reproducibility-evidence "$evidence" \
    --output "$work_root/validated-handoff"
[[ -z "$(git status --porcelain=v1 --untracked-files=all --ignored=no)" ]]

printf 'release_preflight=passed\n'
printf 'release_preflight_commit=%s\n' "$actual_commit"
printf 'release_preflight_unsigned_assets=12\n'
printf 'release_preflight_published_asset_plan=13\n'
