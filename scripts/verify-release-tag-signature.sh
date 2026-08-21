#!/usr/bin/env bash
set -euo pipefail

readonly expected_fingerprint="E72382CD34A6DBC21070BAB1A0F90CBE53C07CA9"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
readonly trusted_key="$repo_root/.github/release-signers/tibor-dravecz.asc"

if (($# < 1 || $# > 2)); then
    printf 'usage: %s TAG [EXPECTED_COMMIT]\n' "$0" >&2
    exit 64
fi

readonly tag="$1"
readonly expected_commit="${2:-}"
if [[ ! "$tag" =~ ^v[0-9][0-9A-Za-z.-]*$ ]]; then
    printf 'release tag is not a canonical v-prefixed version: %s\n' "$tag" >&2
    exit 64
fi
[[ -f "$trusted_key" && ! -L "$trusted_key" ]] || {
    printf 'trusted Tibor release-signing key is missing or unsafe\n' >&2
    exit 66
}
[[ "$(git -C "$repo_root" cat-file -t "refs/tags/$tag")" == tag ]] || {
    printf 'release ref is not an annotated tag object: %s\n' "$tag" >&2
    exit 65
}

gnupg_home="$(mktemp -d)"
readonly gnupg_home
chmod 0700 "$gnupg_home"
cleanup() {
    find "$gnupg_home" -depth -mindepth 1 -delete
    rmdir "$gnupg_home"
}
trap cleanup EXIT

GNUPGHOME="$gnupg_home" gpg --batch --quiet --import "$trusted_key"
imported_fingerprint="$({
    GNUPGHOME="$gnupg_home" gpg --batch --with-colons --list-keys
} | awk -F: '$1 == "fpr" { print $10; exit }')"
readonly imported_fingerprint
[[ "$imported_fingerprint" == "$expected_fingerprint" ]] || {
    printf 'trusted release-signing key fingerprint mismatch\n' >&2
    exit 65
}

verification_output="$(
    GNUPGHOME="$gnupg_home" git -C "$repo_root" \
        -c gpg.program=gpg verify-tag --raw "$tag" 2>&1
)" || {
    printf '%s\n' "$verification_output" >&2
    exit 65
}
valid_fingerprints="$(
    awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 }' <<<"$verification_output"
)"
readonly verification_output valid_fingerprints
[[ "$valid_fingerprints" == "$expected_fingerprint" ]] || {
    printf 'release tag signature is not exclusively from the trusted Tibor key\n' >&2
    exit 65
}

peeled_commit="$(git -C "$repo_root" rev-parse "refs/tags/$tag^{commit}")"
readonly peeled_commit
if [[ -n "$expected_commit" && "$peeled_commit" != "$expected_commit" ]]; then
    printf 'release tag commit mismatch: expected=%s actual=%s\n' \
        "$expected_commit" "$peeled_commit" >&2
    exit 65
fi
printf 'release_tag_signature=verified tag=%s commit=%s fingerprint=%s\n' \
    "$tag" "$peeled_commit" "$expected_fingerprint"
