#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/package-common.sh"
# Release artifact modes must not depend on a caller's permissive umask.
umask 022
target_triple="${BORONDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
dist_dir="${BORONDNS_DIST_DIR:-$repo_root/target/dist}"
package_name="${BORONDNS_PACKAGE_NAME:-borondns}"
package_require_safe_component BORONDNS_PACKAGE_NAME "$package_name" '^[a-z0-9][a-z0-9._-]*$'
package_require_safe_component BORONDNS_PACKAGE_TARGET "$target_triple" '^[A-Za-z0-9][A-Za-z0-9._-]*$'

allow_dynamic="${BORONDNS_PACKAGE_ALLOW_DYNAMIC:-0}"
allow_dirty_non_release="${BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE:-0}"
[[ "$allow_dynamic" == 0 || "$allow_dynamic" == 1 ]] || {
    printf 'BORONDNS_PACKAGE_ALLOW_DYNAMIC must be 0 or 1\n' >&2
    exit 1
}
[[ "$allow_dirty_non_release" == 0 || "$allow_dirty_non_release" == 1 ]] || {
    printf 'BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE must be 0 or 1\n' >&2
    exit 1
}
if [[ "$allow_dynamic" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then
    printf 'dynamic-link SBOM override is forbidden in GitHub Actions release paths\n' >&2
    exit 1
fi
if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then
    printf 'dirty-source SBOM override is forbidden in GitHub Actions release paths\n' >&2
    exit 1
fi

source_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
    printf 'SBOM packaging requires a Git-bound source checkout\n' >&2
    exit 1
}
source_epoch="$(git -C "$repo_root" show -s --format=%ct "$source_commit" 2>/dev/null)" || {
    printf 'cannot determine SBOM source timestamp\n' >&2
    exit 1
}
[[ "$source_epoch" =~ ^[0-9]+$ ]] || {
    printf 'SBOM source timestamp is invalid\n' >&2
    exit 1
}
# cargo-cyclonedx writes fixed paths in the source tree. Take the workspace
# lock before snapshotting Git status, otherwise one concurrent invocation can
# record another invocation's temporary output as its source identity and fail
# after the writer cleans it up.
cyclonedx_default_lock_root="$(git -C "$repo_root" rev-parse --absolute-git-dir 2>/dev/null)" || {
    printf 'cannot determine SBOM workspace lock root\n' >&2
    exit 1
}
cyclonedx_lock_root="$(package_canonical_output_root BORONDNS_CYCLONEDX_LOCK_ROOT \
    "${BORONDNS_CYCLONEDX_LOCK_ROOT:-$cyclonedx_default_lock_root}")"
cyclonedx_workspace_lock_fd=""
package_acquire_publication_lock "$cyclonedx_lock_root" "cyclonedx-workspace" \
    cyclonedx_workspace_lock_fd
[[ -n "$cyclonedx_workspace_lock_fd" ]]
cyclonedx_workspace_lock_held=1
source_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no 2>/dev/null)" || {
    printf 'cannot determine SBOM source status\n' >&2
    exit 1
}
source_clean=1
release_eligible=1
if [[ "$allow_dynamic" == 1 ]]; then
    release_eligible=0
    printf 'warning: dynamic-link SBOM override enabled; outputs are non-release diagnostics\n' >&2
fi
if [[ -n "$source_status" ]]; then
    source_clean=0
    release_eligible=0
    if [[ "$allow_dirty_non_release" != 1 ]]; then
        printf 'refusing SBOM packaging from dirty or untracked source:\n%s\n' "$source_status" >&2
        exit 1
    fi
    printf 'warning: dirty-source SBOM override enabled; outputs are non-release diagnostics\n' >&2
fi

verify_source_identity() {
    local boundary="$1"
    local actual_commit actual_status
    actual_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || {
        printf 'cannot resolve SBOM source at %s\n' "$boundary" >&2
        return 1
    }
    actual_status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all --ignored=no 2>/dev/null)" || {
        printf 'cannot determine SBOM source status at %s\n' "$boundary" >&2
        return 1
    }
    if [[ "$actual_commit" != "$source_commit" || "$actual_status" != "$source_status" ]]; then
        printf 'SBOM source changed at %s\n' "$boundary" >&2
        return 1
    fi
}

cargo_bin="${CARGO:-}"
rustc_bin="${RUSTC:-}"
[[ -n "$cargo_bin" ]] || cargo_bin="$(command -v cargo 2>/dev/null || true)"
[[ -n "$rustc_bin" ]] || rustc_bin="$(command -v rustc 2>/dev/null || true)"
[[ -n "$cargo_bin" && -n "$rustc_bin" ]] || {
    printf 'missing required SBOM Rust tools: cargo rustc\n' >&2
    exit 1
}
cargo_bin="$(realpath -e "$cargo_bin")"
rustc_bin="$(realpath -e "$rustc_bin")"
[[ -x "$cargo_bin" && -f "$cargo_bin" && -x "$rustc_bin" && -f "$rustc_bin" ]] || {
    printf 'selected SBOM Rust tools must be executable regular files\n' >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || {
    printf 'missing required SBOM tool: python3\n' >&2
    exit 1
}
env RUSTC="$rustc_bin" "$cargo_bin" cyclonedx --help >/dev/null 2>&1 || {
    printf 'missing cargo-cyclonedx; install with: cargo install --locked cargo-cyclonedx --version 0.5.9\n' >&2
    exit 1
}

version="$(env RUSTC="$rustc_bin" "$cargo_bin" metadata --no-deps --locked --format-version 1 \
    --manifest-path "$repo_root/Cargo.toml" |
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
package_require_safe_component package-version "$version" '^[0-9][A-Za-z0-9.+-]*$'
commit="${source_commit:0:12}"
source_date_epoch="$source_epoch"
archive_root="$package_name-$version-$target_triple"
if [[ "$source_clean" != 1 ]]; then
    archive_root="$archive_root-nonrelease-dirty"
elif [[ "$allow_dynamic" == 1 ]]; then
    archive_root="$archive_root-nonrelease-dynamic"
fi
docker_archive_root="$archive_root"
package_require_safe_component archive-root "$archive_root"
image_ref="${BORONDNS_DOCKER_IMAGE_REF:-$package_name:$version}"
if [[ "$source_clean" != 1 ]]; then
    image_ref="$(package_nonrelease_docker_image_ref "$image_ref")"
elif [[ "$allow_dynamic" == 1 ]]; then
    image_ref="$(package_nonrelease_dynamic_docker_image_ref "$image_ref")"
else
    package_require_clean_docker_image_ref "$image_ref"
fi
dist_dir="$(package_canonical_output_root BORONDNS_DIST_DIR "$dist_dir")"
sbom_manifest="$(package_safe_child_path "$dist_dir" "$archive_root-sbom-manifest.tsv" 'SBOM manifest')"
borondns_sbom="$(package_safe_child_path "$dist_dir" "$archive_root-borondns.cdx.json" 'BoronDNS SBOM')"
boron_gun_sbom="$(package_safe_child_path "$dist_dir" "$archive_root-boron-gun.cdx.json" 'BoronGun SBOM')"
docker_sbom="$(package_safe_child_path "$dist_dir" "$archive_root-docker-image.cdx.json" 'Docker SBOM')"
image_manifest="$(package_safe_child_path "$dist_dir" "$docker_archive_root-docker-image.manifest.txt" 'Docker image manifest')"
docker_mode="${BORONDNS_SBOM_DOCKER:-auto}"
generated_borondns="$repo_root/crates/borondns-cli/borondns_bin.cdx.json"
generated_boron_gun="$repo_root/crates/boron-gun/boron-gun_bin.cdx.json"
case "$docker_mode" in
1 | true | yes | 0 | false | no | auto) ;;
*)
    printf 'invalid BORONDNS_SBOM_DOCKER=%s; use auto, 1, or 0\n' "$docker_mode" >&2
    exit 1
    ;;
esac
run_root=""
run_sbom_manifest=""
run_borondns_sbom=""
run_boron_gun_sbom=""
run_docker_sbom=""
package_publication_initialized=0
cyclonedx_generated_paths_owned=0
generated_borondns_owned=0
generated_boron_gun_owned=0

unused_generated_retention_path() {
    local generated="$1" attempt retained
    for ((attempt = 0; attempt < 128; attempt++)); do
        retained="$cyclonedx_lock_root/.${generated##*/}.borondns-remove.$$.$RANDOM.$attempt"
        if [[ ! -e "$retained" && ! -L "$retained" ]]; then
            printf '%s\n' "$retained"
            return 0
        fi
    done
    printf 'could not allocate retained cargo-cyclonedx output under %s\n' \
        "$cyclonedx_lock_root" >&2
    return 1
}

retain_generated_output() {
    local generated="$1" label="$2" retained expected status=0 parent parent_identity
    expected="${PACKAGE_PUBLICATION_FILE_IDENTITIES[$generated]:-}"
    [[ -n "$expected" ]] || return 1
    retained="$(unused_generated_retention_path "$generated")" || return 1
    package_move_captured_publication_artifact "$generated" "$retained" \
        "$cyclonedx_lock_root" "$label retained cleanup" || status=$?
    if ((status != 0 && PACKAGE_LAST_MOVE_COMMITTED == 0)); then
        parent="${generated%/*}"
        [[ -n "$parent" ]] || parent=/
        parent_identity="$(
            package_retained_quarantine_parent_identity "$generated" "$expected" file
        )" || true
        if [[ -n "$parent_identity" ]]; then
            printf '%s could not move its exact inode into the Git metadata quarantine; retained the source pathname for privileged/manual reconciliation (cross-filesystem moves are not weakened to copy-and-unlink): path=%q identity=%q parent=%q parent_identity=%q\n' \
                "$label" "$generated" "$expected" "$parent" "$parent_identity" >&2
        else
            printf '%s could not move its exact inode into the Git metadata quarantine and the source could not be revalidated; preserving the source parent namespace without claiming an exact object identity: %s\n' \
                "$label" "$parent" >&2
        fi
    fi
    if ((PACKAGE_LAST_MOVE_COMMITTED == 1)); then
        package_append_verified_retained_removal_quarantine \
            "$retained" "$expected" file "$label" || return 1
    fi
    ((status == 0)) || return "$status"
    ((PACKAGE_LAST_MOVE_COMMITTED == 1))
}

cleanup_generated() {
    [[ "${cyclonedx_workspace_lock_held:-0}" == 1 &&
        "${cyclonedx_generated_paths_owned:-0}" == 1 ]] || return 0
    local cleanup_failed=0
    if [[ "$generated_borondns_owned" == 1 ]]; then
        package_begin_mutation_critical || return 1
        if retain_generated_output "$generated_borondns" "generated BoronDNS SBOM"; then
            generated_borondns_owned=0
            package_end_mutation_critical
        else
            if ((PACKAGE_LAST_MOVE_COMMITTED == 1)); then
                generated_borondns_owned=0
            fi
            package_end_mutation_critical
            cleanup_failed=1
        fi
    fi
    if [[ "$generated_boron_gun_owned" == 1 ]]; then
        package_begin_mutation_critical || return 1
        if retain_generated_output "$generated_boron_gun" "generated BoronGun SBOM"; then
            generated_boron_gun_owned=0
            package_end_mutation_critical
        else
            if ((PACKAGE_LAST_MOVE_COMMITTED == 1)); then
                generated_boron_gun_owned=0
            fi
            package_end_mutation_critical
            cleanup_failed=1
        fi
    fi
    if [[ "$generated_borondns_owned" == 0 && "$generated_boron_gun_owned" == 0 ]]; then
        cyclonedx_generated_paths_owned=0
    fi
    ((cleanup_failed == 0))
}

claim_generated_paths() {
    local generated
    cyclonedx_generated_paths_owned=1
    for generated in "$generated_borondns" "$generated_boron_gun"; do
        if [[ -e "$generated" || -L "$generated" ]]; then
            printf 'refusing to replace pre-existing cargo-cyclonedx workspace output: %s\n' \
                "$generated" >&2
            return 1
        fi
        package_begin_mutation_critical || return 1
        if ! package_create_owned_publication_file "$generated" \
            "cargo-cyclonedx workspace output"; then
            package_end_mutation_critical
            return 1
        fi
        if [[ "$generated" == "$generated_borondns" ]]; then
            generated_borondns_owned=1
        else
            generated_boron_gun_owned=1
        fi
        if declare -F package_owned_file_transition_hook >/dev/null 2>&1; then
            package_owned_file_transition_hook after-create "$generated" \
                "${PACKAGE_PUBLICATION_FILE_IDENTITIES[$generated]}" || true
        fi
        package_end_mutation_critical
    done
}

cleanup_failed_publication() {
    local status=$?
    trap - EXIT
    package_begin_signal_cleanup
    cleanup_generated || status=74
    if [[ "$package_publication_initialized" == 1 ]]; then
        package_cleanup_publication "$status" || status=$?
    elif [[ -n "$run_root" && (-e "$run_root" || -L "$run_root") ]]; then
        if ! package_capture_cleanup_root "$run_root" "SBOM package run root" ||
            ! package_remove_captured_cleanup_root "$run_root" "SBOM package run root"; then
            status=74
        fi
    fi
    exit "$status"
}
trap cleanup_failed_publication EXIT
trap 'package_signal_handler 130' INT
trap 'package_signal_handler 143' TERM
trap 'package_signal_handler 129' HUP

# Arm EXIT ownership before allocating the private tree. A chosen pathname plus
# atomic mkdir lets the trap identify every successfully created root even when
# termination arrives before the next shell command.
for run_root_attempt in {1..128}; do
    run_root="$dist_dir/.${archive_root}.sbom-package.$$.$RANDOM.$run_root_attempt"
    if mkdir -m 0700 -- "$run_root" 2>/dev/null; then
        break
    fi
    run_root=""
done
[[ -n "$run_root" && -d "$run_root" && ! -L "$run_root" ]] || {
    printf 'cannot allocate private SBOM package run root under %s\n' "$dist_dir" >&2
    exit 1
}
run_sbom_manifest="$run_root/$(basename "$sbom_manifest")"
run_borondns_sbom="$run_root/$(basename "$borondns_sbom")"
run_boron_gun_sbom="$run_root/$(basename "$boron_gun_sbom")"
run_docker_sbom="$run_root/$(basename "$docker_sbom")"
package_publication_reset "$run_root"
package_publication_initialized=1
# package_publication_reset clears transaction root bindings, while the
# workspace root descriptor and flock remain held. Re-register that exact Git
# metadata root so generated fixed-path outputs can be moved into a Git-ignored
# terminal quarantine without leaving the source worktree dirty.
package_acquire_publication_lock "$cyclonedx_lock_root" "cyclonedx-workspace" \
    cyclonedx_workspace_lock_fd

# The global canonical image-reference lock prevents another target or output
# root from retagging the daemon image while its manifest is being authenticated
# and scanned. The per-output Docker lock protects the matching manifest file.
docker_image_lock_fd=""
docker_publication_lock_fd=""
if [[ "$docker_mode" != 0 && "$docker_mode" != false && "$docker_mode" != no ]]; then
    package_acquire_docker_image_lock "$image_ref" docker_image_lock_fd
    package_acquire_publication_lock "$dist_dir" "$docker_archive_root-docker" docker_publication_lock_fd
    [[ -n "$docker_image_lock_fd" && -n "$docker_publication_lock_fd" ]]
fi
sbom_publication_lock_fd=""
package_acquire_publication_lock "$dist_dir" "$archive_root-sbom" sbom_publication_lock_fd
[[ -n "$sbom_publication_lock_fd" ]]
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        return 1
    fi
}

cargo_cyclonedx_version() {
    env RUSTC="$rustc_bin" "$cargo_bin" cyclonedx -V 2>/dev/null || printf 'cargo-cyclonedx unknown'
}

syft_version_line() {
    syft version 2>/dev/null | awk -F: '
        /^Version:/ {
            gsub(/^[ \t]+/, "", $2)
            printf "syft %s", $2
            found = 1
            exit
        }
        END { if (!found) printf "syft unknown" }
    '
}

require_json_sbom() {
    local file="$1" expected_name="$2" expected_spec="${3:-}"
    python3 - "$file" "$expected_name" "$expected_spec" <<'PY'
import json, sys
path, expected, expected_spec = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
if data.get("bomFormat") != "CycloneDX":
    raise SystemExit(f"{path}: expected CycloneDX bomFormat")
if expected_spec and data.get("specVersion") != expected_spec:
    raise SystemExit(f"{path}: expected CycloneDX specVersion {expected_spec}")
component = data.get("metadata", {}).get("component", {})
if expected and component.get("name") != expected:
    raise SystemExit(f"{path}: expected metadata component {expected}, got {component.get('name')!r}")
PY
}

normalize_sbom() {
    local file="$1" artifact="$2"
    python3 - "$file" "$package_name" "$version" "$target_triple" "$artifact" \
        "$commit" "$source_date_epoch" "$repo_root" <<'PY'
import datetime, json, pathlib, sys, uuid
path, package, version, target, artifact, commit, epoch, source_root = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

# cargo-cyclonedx identifies workspace path dependencies with absolute file
# URIs. Preserve their relationships while replacing the checkout-specific
# prefix with a stable public build location.
source_root = str(pathlib.Path(source_root).resolve())
source_uri = pathlib.Path(source_root).as_uri()
logical_root = "/build/borondns"
logical_uri = "file:///build/borondns"

def normalize_paths(value):
    if isinstance(value, dict):
        return {key: normalize_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_paths(item) for item in value]
    if isinstance(value, str):
        return value.replace(source_uri, logical_uri).replace(source_root, logical_root)
    return value

data = normalize_paths(data)
identity = f"{package}:{version}:{target}:{artifact}:{commit}"
data["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
metadata = data.setdefault("metadata", {})
timestamp = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
metadata["timestamp"] = timestamp.isoformat().replace("+00:00", "Z")
encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
if source_root in encoded or source_uri in encoded:
    raise SystemExit(f"{path}: checkout path remained after SBOM normalization")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(encoded)
    handle.write("\n")
PY
}

write_sha256() {
    local file="$1"
    (cd "$(dirname "$file")" && sha256_file "$(basename "$file")" >"$(basename "$file").sha256")
}

docker_scan_identity() {
    local manifest_image_id current_tag_id count
    command -v docker >/dev/null 2>&1 || {
        printf 'Docker SBOM requires docker to authenticate the immutable image ID\n' >&2
        return 1
    }
    [[ -f "$image_manifest" && ! -L "$image_manifest" ]] || {
        printf 'Docker SBOM requires the immutable image manifest from package-docker-image.sh: %s\n' "$image_manifest" >&2
        return 1
    }
    count="$(awk -F= '$1 == "image_id" { count += 1 } END { print count + 0 }' "$image_manifest")"
    [[ "$count" == 1 ]] || {
        printf 'Docker image manifest must contain exactly one image_id\n' >&2
        return 1
    }
    manifest_image_id="$(awk -F= '$1 == "image_id" { print substr($0, index($0, "=") + 1); exit }' "$image_manifest")"
    [[ "$manifest_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        printf 'Docker image manifest contains an invalid immutable image ID\n' >&2
        return 1
    }
    local expected_key expected_value actual_value
    for expected_key in version target commit source_clean release_eligible dirty_source_override dynamic_link_override; do
        case "$expected_key" in
        version) expected_value="$version" ;;
        target) expected_value="$target_triple" ;;
        commit) expected_value="$commit" ;;
        source_clean) expected_value="$source_clean" ;;
        release_eligible) expected_value="$release_eligible" ;;
        dirty_source_override) expected_value="$allow_dirty_non_release" ;;
        dynamic_link_override) expected_value="$allow_dynamic" ;;
        esac
        count="$(awk -F= -v key="$expected_key" '$1 == key { count += 1 } END { print count + 0 }' "$image_manifest")"
        [[ "$count" == 1 ]] || {
            printf 'Docker image manifest must contain exactly one %s\n' "$expected_key" >&2
            return 1
        }
        actual_value="$(awk -F= -v key="$expected_key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$image_manifest")"
        [[ "$actual_value" == "$expected_value" ]] || {
            printf 'Docker image manifest %s does not match the SBOM source identity\n' "$expected_key" >&2
            return 1
        }
    done
    current_tag_id="$(docker image inspect --format '{{.Id}}' "$image_ref")" || return 1
    [[ "$current_tag_id" == "$manifest_image_id" ]] || {
        printf 'Docker image tag drifted before SBOM scan: expected=%s actual=%s\n' \
            "$manifest_image_id" "$current_tag_id" >&2
        return 1
    }
    printf '%s\n' "$manifest_image_id"
}

verify_source_identity "before SBOM generation"
claim_generated_paths

(
    cd "$repo_root"
    export SOURCE_DATE_EPOCH="$source_date_epoch"
    env RUSTC="$rustc_bin" "$cargo_bin" metadata --locked --format-version 1 \
        --manifest-path "$repo_root/Cargo.toml" >/dev/null
    env RUSTC="$rustc_bin" "$cargo_bin" cyclonedx \
        --manifest-path "$repo_root/Cargo.toml" --format json --describe binaries \
        --target "$target_triple" --features boron-gun/xdp --spec-version 1.5
)

[[ -f "$generated_borondns" && -f "$generated_boron_gun" ]] || {
    printf 'missing generated Rust SBOM output\n' >&2
    exit 1
}
package_require_publication_file_identity "$generated_borondns" "generated BoronDNS SBOM"
package_require_publication_file_identity "$generated_boron_gun" "generated BoronGun SBOM"
install -m 0644 "$generated_borondns" "$run_borondns_sbom"
install -m 0644 "$generated_boron_gun" "$run_boron_gun_sbom"
normalize_sbom "$run_borondns_sbom" borondns
normalize_sbom "$run_boron_gun_sbom" boron-gun
require_json_sbom "$run_borondns_sbom" borondns 1.5
require_json_sbom "$run_boron_gun_sbom" boron-gun 1.5
write_sha256 "$run_borondns_sbom"
write_sha256 "$run_boron_gun_sbom"
if declare -F package_sbom_generated_hook >/dev/null 2>&1; then
    package_sbom_generated_hook before-cleanup "$generated_borondns" "$generated_boron_gun"
fi
cleanup_generated
# package_acquire_publication_lock caches one root-directory descriptor as the
# lifetime authority for that inode. Keep this lock through terminal SBOM
# publication: explicitly unlocking a cached descriptor would make a later
# same-root acquisition look held while allowing a second publisher to enter.

docker_sbom_status=skipped
docker_image_id=""
case "$docker_mode" in
1 | true | yes)
    command -v syft >/dev/null 2>&1 || {
        printf 'BORONDNS_SBOM_DOCKER=%s requires syft\n' "$docker_mode" >&2
        exit 1
    }
    docker_image_id="$(docker_scan_identity)"
    syft "$docker_image_id" -o cyclonedx-json >"$run_docker_sbom"
    normalize_sbom "$run_docker_sbom" docker-image
    require_json_sbom "$run_docker_sbom" ""
    write_sha256 "$run_docker_sbom"
    docker_sbom_status=created
    ;;
0 | false | no) docker_sbom_status=disabled ;;
auto)
    if command -v syft >/dev/null 2>&1 && command -v docker >/dev/null 2>&1 &&
        docker image inspect "$image_ref" >/dev/null 2>&1; then
        docker_image_id="$(docker_scan_identity)"
        syft "$docker_image_id" -o cyclonedx-json >"$run_docker_sbom"
        normalize_sbom "$run_docker_sbom" docker-image
        require_json_sbom "$run_docker_sbom" ""
        write_sha256 "$run_docker_sbom"
        docker_sbom_status=created
    fi
    ;;
esac

{
    printf 'artifact\tformat\tsource\tfeatures\tpath\tsha256\ttool\n'
    printf 'borondns\tCycloneDX 1.5 JSON\tCargo.lock+cargo metadata\t%s\t%s\t%s\t%s\n' \
        'borondns-cli/default,boron-gun/xdp' "$(basename "$borondns_sbom")" \
        "$(sha256_file "$run_borondns_sbom" | awk '{print $1}')" "$(cargo_cyclonedx_version)"
    printf 'boron-gun\tCycloneDX 1.5 JSON\tCargo.lock+cargo metadata\t%s\t%s\t%s\t%s\n' \
        'borondns-cli/default,boron-gun/xdp' "$(basename "$boron_gun_sbom")" \
        "$(sha256_file "$run_boron_gun_sbom" | awk '{print $1}')" "$(cargo_cyclonedx_version)"
    if [[ "$docker_sbom_status" == created ]]; then
        printf 'docker-image\tCycloneDX JSON\t%s\t%s\t%s\t%s\t%s\n' "$docker_image_id" \
            'container image package scan' "$(basename "$docker_sbom")" \
            "$(sha256_file "$run_docker_sbom" | awk '{print $1}')" "$(syft_version_line)"
    else
        printf 'docker-image\tskipped\t%s\t%s\t-\t-\t%s\n' "$image_ref" \
            "BORONDNS_SBOM_DOCKER=$docker_mode" "$docker_sbom_status"
    fi
    printf '# package=%s\n' "$package_name"
    printf '# version=%s\n' "$version"
    printf '# target=%s\n' "$target_triple"
    printf '# commit=%s\n' "$commit"
    printf '# source_clean=%s\n' "$source_clean"
    printf '# release_eligible=%s\n' "$release_eligible"
    printf '# dirty_source_override=%s\n' "$allow_dirty_non_release"
    printf '# dynamic_link_override=%s\n' "$allow_dynamic"
    printf '# source_date_epoch=%s\n' "$source_date_epoch"
    printf '# generated_at=%s\n' "$(
        python3 - "$source_epoch" <<'PY'
import datetime, sys
print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
    )"
} >"$run_sbom_manifest"

verify_source_identity "terminal publication"
cleanup_generated
package_publish_candidate "$run_borondns_sbom" "$borondns_sbom" "$dist_dir" 'BoronDNS SBOM'
package_publish_candidate "$run_borondns_sbom.sha256" "$borondns_sbom.sha256" "$dist_dir" 'BoronDNS SBOM checksum'
package_publish_candidate "$run_boron_gun_sbom" "$boron_gun_sbom" "$dist_dir" 'BoronGun SBOM'
package_publish_candidate "$run_boron_gun_sbom.sha256" "$boron_gun_sbom.sha256" "$dist_dir" 'BoronGun SBOM checksum'
if [[ "$docker_sbom_status" == created ]]; then
    package_publish_candidate "$run_docker_sbom" "$docker_sbom" "$dist_dir" 'Docker SBOM'
    package_publish_candidate "$run_docker_sbom.sha256" "$docker_sbom.sha256" "$dist_dir" 'Docker SBOM checksum'
else
    package_remove_destination "$docker_sbom" "$dist_dir" 'obsolete Docker SBOM'
    package_remove_destination "$docker_sbom.sha256" "$dist_dir" 'obsolete Docker SBOM checksum'
fi
package_publish_candidate "$run_sbom_manifest" "$sbom_manifest" "$dist_dir" 'SBOM manifest'
package_commit_publication
package_remove_captured_cleanup_root "$run_root" "SBOM package run root"
PACKAGE_PUBLICATION_RETAIN_ROOT=""
printf 'created %s\n' "$borondns_sbom" "$borondns_sbom.sha256" "$boron_gun_sbom" "$boron_gun_sbom.sha256"
if [[ "$docker_sbom_status" == created ]]; then
    printf 'created %s\n' "$docker_sbom" "$docker_sbom.sha256"
else
    printf 'docker SBOM %s for %s\n' "$docker_sbom_status" "$image_ref"
fi
printf 'created %s\n' "$sbom_manifest"
if [[ "$source_clean" != 1 ]]; then
    printf 'dirty-source SBOM diagnostic completed; output is not release-eligible\n' >&2
    exit 2
fi
