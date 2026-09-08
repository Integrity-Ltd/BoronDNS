#!/usr/bin/env bash
# Shared by the native builders and their container lifecycle tests. Keep this
# dependency-light: the minimal Debian/RPM builder images need no Python/Cargo.

native_package_version() {
    local root="$1" version key tag tags
    # Read only the workspace.package section, not the first version key in
    # the file. Fail closed on missing, duplicate, or unsupported declarations.
    version="$(awk '
        /^[[:space:]]*\[/ { workspace = ($0 ~ /^[[:space:]]*\[workspace\.package\][[:space:]]*(#.*)?$/) }
        workspace && /^[[:space:]]*version[[:space:]]*=/ {
            if ($0 !~ /^[[:space:]]*version[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*(#.*)?$/) {
                print "invalid declaration"
                next
            }
            sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/, "")
            sub(/"[[:space:]]*(#.*)?$/, "")
            print
        }
    ' "$root/Cargo.toml")" || return 1
    if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
        printf 'native package version: expected one numeric workspace.package.version in Cargo.toml\n' >&2
        return 1
    fi
    for key in BORONDNS_DEB_VERSION BORONDNS_RPM_VERSION; do
        if [[ -v "$key" && "${!key}" != "$version" ]]; then
            printf 'native package version: %s=%s does not match Cargo.toml %s\n' "$key" "${!key}" "$version" >&2
            return 1
        fi
    done
    if [[ -v BORONDNS_RELEASE_TAG ]]; then
        native_package_check_tag "$BORONDNS_RELEASE_TAG" "$version" || return 1
    fi
    if [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
        native_package_check_tag "${GITHUB_REF#refs/tags/}" "$version" || return 1
    fi
    if [[ "${GITHUB_REF_TYPE:-}" == tag ]]; then
        native_package_check_tag "${GITHUB_REF_NAME:-}" "$version" || return 1
    fi
    # Source archives legitimately have no Git metadata. Only inspect this
    # checkout, never a parent directory containing an unrelated repository.
    if [[ -e "$root/.git" ]]; then
        tags="$(git -C "$root" tag --points-at HEAD --list 'v[0-9]*')" || return 1
        while IFS= read -r tag; do
            [[ -z "$tag" ]] || native_package_check_tag "$tag" "$version" || return 1
        done <<<"$tags"
    fi
    printf '%s\n' "$version"
}

native_package_check_tag() {
    local tag="$1" version="$2"
    if [[ "$tag" != "v$version" ]]; then
        printf 'native package version: tag %s does not match Cargo.toml v%s\n' "$tag" "$version" >&2
        return 1
    fi
}

native_package_check_binary_version() {
    local binary="$1" name="$2" version="$3" output first_line
    output="$("$binary" --version)" || {
        printf 'native package version: cannot read version from %s\n' "$binary" >&2
        return 1
    }
    first_line="${output%%$'\n'*}"
    if [[ "$first_line" != "$name $version" ]]; then
        printf 'native package version: %s reports %s; expected %s %s\n' "$binary" "$first_line" "$name" "$version" >&2
        return 1
    fi
}

# Native packages reuse the inventory generated alongside the installer binary.
# Source-archive/custom binary builders must supply it explicitly; silently
# packaging only the project's own licenses is not an acceptable fallback.
native_package_notices() {
    local binary="$1" notices
    notices="${BORONDNS_PACKAGE_NOTICES:-${binary%.bin}/THIRD-PARTY-NOTICES.html}"
    [[ -f "$notices" && ! -L "$notices" && -s "$notices" ]] || {
        printf 'native package notices: missing nonempty regular THIRD-PARTY-NOTICES.html; build the installer first or set BORONDNS_PACKAGE_NOTICES\n' >&2
        return 1
    }
    printf '%s\n' "$notices"
}
