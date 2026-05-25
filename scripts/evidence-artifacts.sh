#!/usr/bin/env bash

list_primary_version_artifacts() {
    local repo_root="$1"
    local interop_root="$repo_root/target/interop"

    [[ -d "$interop_root" ]] || return 0
    find "$interop_root" -path '*/primary-version.txt' -type f | sort
}

capture_new_primary_version_artifacts() {
    local repo_root="$1"
    local snapshot_dir="$2"
    local run_name="$3"
    local before_file="$4"
    local interop_root="$repo_root/target/interop"
    local index="$snapshot_dir/interop-primary-versions/INDEX.tsv"

    [[ -d "$interop_root" ]] || return 0
    mkdir -p "$snapshot_dir/interop-primary-versions"

    while IFS= read -r artifact; do
        if grep -Fx -- "$artifact" "$before_file" >/dev/null 2>&1; then
            continue
        fi

        local relative_artifact="${artifact#"$interop_root"/}"
        local snapshot_artifact="interop-primary-versions/$run_name/$relative_artifact"
        local destination="$snapshot_dir/$snapshot_artifact"
        mkdir -p "$(dirname "$destination")"
        cp -p "$artifact" "$destination"
        printf '%s\t%s\n' "$artifact" "$snapshot_artifact" >>"$index"
    done < <(find "$interop_root" -path '*/primary-version.txt' -type f | sort)
}
