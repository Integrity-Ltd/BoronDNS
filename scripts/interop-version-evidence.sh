#!/usr/bin/env bash

write_primary_version_header() {
    local implementation="$1"
    local profile="$2"
    local transport="$3"
    local security="$4"
    shift 4

    printf 'test_timestamp_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'primary_implementation=%s\n' "$implementation"
    printf 'configuration_profile=%s\n' "$profile"
    printf 'transfer_transport=%s\n' "$transport"
    printf 'transfer_security=%s\n' "$security"
    for artifact in "$@"; do
        printf 'configuration_artifact=%s\n' "$artifact"
        if [[ -f "$artifact" ]] && command -v sha256sum >/dev/null 2>&1; then
            printf 'configuration_artifact_sha256=%s  %s\n' "$(sha256sum "$artifact" | awk '{ print $1 }')" "$artifact"
        fi
    done
}

record_bind_primary_version() {
    local workdir="$1"
    local profile="$2"
    local transport="$3"
    local security="$4"
    shift 4

    {
        write_primary_version_header "BIND 9" "$profile" "$transport" "$security" "$@"
        printf 'primary_host_os_begin\n'
        uname -a
        if [[ -f /etc/os-release ]]; then
            cat /etc/os-release
        fi
        printf 'primary_host_os_end\n'
        printf 'version_command=%s\n' "named -V"
        printf 'version_output_begin\n'
        if ! named -V; then
            printf 'named -V failed; falling back to named -v\n'
            named -v
        fi
        printf 'version_output_end\n'
    } >"$workdir/primary-version.txt" 2>&1
}

record_docker_primary_version() {
    local workdir="$1"
    local container="$2"
    local implementation="$3"
    local image="$4"
    local package="$5"
    local profile="$6"
    local transport="$7"
    local security="$8"
    local version_command="$9"
    shift 9
    local version_ready="no"

    for _ in {1..80}; do
        if docker exec "$container" sh -c "$version_command" >/dev/null 2>&1; then
            version_ready="yes"
            break
        fi
        sleep 0.25
    done

    if [[ "$version_ready" != "yes" ]]; then
        printf 'primary version command did not become available: %s\n' "$version_command" >&2
        return 1
    fi

    {
        write_primary_version_header "$implementation" "$profile" "$transport" "$security" "$@"
        printf 'container_image=%s\n' "$image"
        printf 'container_image_id=%s\n' "$(docker inspect --format '{{.Image}}' "$container")"
        printf 'container_id=%s\n' "$(docker inspect --format '{{.Id}}' "$container")"
        printf 'package=%s\n' "$package"
        printf 'version_command=%s\n' "$version_command"
        printf 'os_release_begin\n'
        docker exec "$container" sh -c 'cat /etc/os-release'
        printf 'os_release_end\n'
        printf 'package_versions_begin\n'
        if ! docker exec "$container" sh -c "apk info -vv $package"; then
            printf 'package_version_command_failed=%s\n' "apk info -vv $package"
        fi
        printf 'package_versions_end\n'
        printf 'version_output_begin\n'
        docker exec "$container" sh -c "$version_command"
        printf 'version_output_end\n'
    } >"$workdir/primary-version.txt" 2>&1
}
