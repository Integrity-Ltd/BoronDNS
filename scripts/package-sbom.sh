#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple="${OXIDEDNS_PACKAGE_TARGET:-x86_64-unknown-linux-musl}"
dist_dir="${OXIDEDNS_DIST_DIR:-$repo_root/target/dist}"
package_name="${OXIDEDNS_PACKAGE_NAME:-oxidedns}"
version="$(cargo metadata --no-deps --locked --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["packages"][0]["version"])')"
commit="$(git -C "$repo_root" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct 2>/dev/null || date -u +%s)}"
archive_root="$package_name-$version-$target_triple"
sbom_manifest="$dist_dir/$archive_root-sbom-manifest.tsv"
oxidedns_sbom="$dist_dir/$archive_root-oxidedns.cdx.json"
oxide_gun_sbom="$dist_dir/$archive_root-oxide-gun.cdx.json"
docker_sbom="$dist_dir/$archive_root-docker-image.cdx.json"
image_ref="${OXIDEDNS_DOCKER_IMAGE_REF:-$package_name:$version}"
docker_mode="${OXIDEDNS_SBOM_DOCKER:-auto}"
generated_oxidedns="$repo_root/crates/oxidedns-cli/oxidedns_bin.cdx.json"
generated_oxide_gun="$repo_root/crates/oxide-gun/oxide-gun_bin.cdx.json"

missing=()
for tool in cargo python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'missing required SBOM tools: %s\n' "${missing[*]}" >&2
    exit 1
fi

if ! cargo cyclonedx --help >/dev/null 2>&1; then
    printf 'missing cargo-cyclonedx; install with: cargo install --locked cargo-cyclonedx --version 0.5.9\n' >&2
    exit 1
fi

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
    cargo cyclonedx -V 2>/dev/null || printf 'cargo-cyclonedx unknown'
}

syft_version_line() {
    syft version 2>/dev/null | awk -F: '
		/^Version:/ {
			gsub(/^[ \t]+/, "", $2)
			printf "syft %s", $2
			found = 1
			exit
		}
		END {
			if (!found) {
				printf "syft unknown"
			}
		}
	'
}

require_json_sbom() {
    local file="$1"
    local expected_name="$2"
    local expected_spec="${3:-}"
    python3 - "$file" "$expected_name" "$expected_spec" <<'PY'
import json
import sys

path, expected, expected_spec = sys.argv[1], sys.argv[2], sys.argv[3]
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
    local file="$1"
    local artifact="$2"
    python3 - "$file" "$package_name" "$version" "$target_triple" "$artifact" "$commit" "$source_date_epoch" <<'PY'
import datetime
import json
import sys
import uuid

path, package, version, target, artifact, commit, epoch = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

identity = f"{package}:{version}:{target}:{artifact}:{commit}"
data["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
metadata = data.setdefault("metadata", {})
timestamp = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
metadata["timestamp"] = timestamp.isoformat().replace("+00:00", "Z")

with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
}

write_sha256() {
    local file="$1"
    (
        cd "$(dirname "$file")"
        sha256_file "$(basename "$file")" >"$(basename "$file").sha256"
    )
}

cleanup_generated() {
    rm -f "$generated_oxidedns" "$generated_oxide_gun"
}
trap cleanup_generated EXIT

mkdir -p "$dist_dir"
cleanup_generated
rm -f \
    "$sbom_manifest" \
    "$oxidedns_sbom" "$oxidedns_sbom.sha256" \
    "$oxide_gun_sbom" "$oxide_gun_sbom.sha256" \
    "$docker_sbom" "$docker_sbom.sha256"

(
    cd "$repo_root"
    export SOURCE_DATE_EPOCH="$source_date_epoch"
    cargo metadata --locked --format-version 1 >/dev/null
    cargo cyclonedx \
        --manifest-path Cargo.toml \
        --format json \
        --describe binaries \
        --target "$target_triple" \
        --features oxidedns-cli/af-xdp,oxide-gun/xdp \
        --spec-version 1.5
)

[[ -f "$generated_oxidedns" ]] || {
    printf 'missing generated OxideDNS SBOM: %s\n' "$generated_oxidedns" >&2
    exit 1
}
[[ -f "$generated_oxide_gun" ]] || {
    printf 'missing generated OxideGun SBOM: %s\n' "$generated_oxide_gun" >&2
    exit 1
}

install -m 0644 "$generated_oxidedns" "$oxidedns_sbom"
install -m 0644 "$generated_oxide_gun" "$oxide_gun_sbom"
normalize_sbom "$oxidedns_sbom" oxidedns
normalize_sbom "$oxide_gun_sbom" oxide-gun
require_json_sbom "$oxidedns_sbom" oxidedns 1.5
require_json_sbom "$oxide_gun_sbom" oxide-gun 1.5
write_sha256 "$oxidedns_sbom"
write_sha256 "$oxide_gun_sbom"

docker_sbom_status="skipped"
case "$docker_mode" in
1 | true | yes)
    if ! command -v syft >/dev/null 2>&1; then
        printf 'OXIDEDNS_SBOM_DOCKER=%s requires syft\n' "$docker_mode" >&2
        exit 1
    fi
    syft "$image_ref" -o cyclonedx-json >"$docker_sbom"
    normalize_sbom "$docker_sbom" docker-image
    require_json_sbom "$docker_sbom" ""
    write_sha256 "$docker_sbom"
    docker_sbom_status="created"
    ;;
0 | false | no)
    docker_sbom_status="disabled"
    ;;
auto)
    if command -v syft >/dev/null 2>&1 && command -v docker >/dev/null 2>&1 && docker image inspect "$image_ref" >/dev/null 2>&1; then
        syft "$image_ref" -o cyclonedx-json >"$docker_sbom"
        normalize_sbom "$docker_sbom" docker-image
        require_json_sbom "$docker_sbom" ""
        write_sha256 "$docker_sbom"
        docker_sbom_status="created"
    fi
    ;;
*)
    printf 'invalid OXIDEDNS_SBOM_DOCKER=%s; use auto, 1, or 0\n' "$docker_mode" >&2
    exit 1
    ;;
esac

{
    printf 'artifact\tformat\tsource\tfeatures\tpath\tsha256\ttool\n'
    printf 'oxidedns\tCycloneDX 1.5 JSON\tCargo.lock+cargo metadata\t%s\t%s\t%s\t%s\n' \
        'oxidedns-cli/af-xdp,oxide-gun/xdp' \
        "$(basename "$oxidedns_sbom")" \
        "$(sha256_file "$oxidedns_sbom" | awk '{print $1}')" \
        "$(cargo_cyclonedx_version)"
    printf 'oxide-gun\tCycloneDX 1.5 JSON\tCargo.lock+cargo metadata\t%s\t%s\t%s\t%s\n' \
        'oxidedns-cli/af-xdp,oxide-gun/xdp' \
        "$(basename "$oxide_gun_sbom")" \
        "$(sha256_file "$oxide_gun_sbom" | awk '{print $1}')" \
        "$(cargo_cyclonedx_version)"
    if [[ "$docker_sbom_status" == "created" ]]; then
        printf 'docker-image\tCycloneDX JSON\t%s\t%s\t%s\t%s\t%s\n' \
            "$image_ref" \
            'container image package scan' \
            "$(basename "$docker_sbom")" \
            "$(sha256_file "$docker_sbom" | awk '{print $1}')" \
            "$(syft_version_line)"
    else
        printf 'docker-image\tskipped\t%s\t%s\t%s\t%s\t%s\n' \
            "$image_ref" \
            "OXIDEDNS_SBOM_DOCKER=$docker_mode" \
            '-' \
            '-' \
            "$docker_sbom_status"
    fi
    printf '# package=%s\n' "$package_name"
    printf '# version=%s\n' "$version"
    printf '# target=%s\n' "$target_triple"
    printf '# commit=%s\n' "$commit"
    printf '# source_date_epoch=%s\n' "$source_date_epoch"
    printf '# generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$sbom_manifest"

printf 'created %s\n' "$oxidedns_sbom"
printf 'created %s\n' "$oxidedns_sbom.sha256"
printf 'created %s\n' "$oxide_gun_sbom"
printf 'created %s\n' "$oxide_gun_sbom.sha256"
if [[ "$docker_sbom_status" == "created" ]]; then
    printf 'created %s\n' "$docker_sbom"
    printf 'created %s\n' "$docker_sbom.sha256"
else
    printf 'docker SBOM %s for %s\n' "$docker_sbom_status" "$image_ref"
fi
printf 'created %s\n' "$sbom_manifest"
