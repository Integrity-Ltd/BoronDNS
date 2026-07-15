#!/usr/bin/env bash

# shellcheck source=scripts/campaign-env.sh
if ! declare -F campaign_acquire_private_lock >/dev/null 2>&1; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/campaign-env.sh"
fi

OXIDEDNS_INTEROP_ALPINE_BASE_IMAGE_EXPECTED='alpine:3.22@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6'
image_setup_absolute_deadline_nanoseconds=""

interop_image_private_lock_root() {
    # Docker tags are daemon-global, so the coordinating namespace must not
    # split when callers have different session runtime or temporary roots.
    local root
    root="/tmp/oxidedns-interop-image-locks-$(id -u)"
    if [[ ! -e "$root" ]]; then
        mkdir -m 0700 "$root" 2>/dev/null || true
    fi
    campaign_require_owned_real_directory "$root" "interop image lock root" || return 1
    local mode
    mode="$(stat -c %a "$root")" || return 1
    (((8#$mode & 077) == 0)) || {
        printf 'interop image lock root is not private: %s\n' "$root" >&2
        return 1
    }
    printf '%s\n' "$root"
}

interop_image_recipe_sha256() {
    local name="$1" base_image="$2"
    shift 2
    {
        printf 'schema=1\n'
        printf 'name=%s\n' "$name"
        printf 'base_image=%s\n' "$base_image"
        printf 'packages='
        printf '%s ' "$@"
        printf '\n'
    } | sha256sum | awk '{ print $1 }'
}

interop_inspect_authenticated_image() {
    local output_variable="$1" command_deadline="$2" tag="$3" recipe_sha256="$4" base_image="$5" packages_text="$6"
    local inspected parsed_image_id recipe_label base_label packages_label
    [[ "$output_variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    case "$output_variable" in
    output_variable | command_deadline | tag | recipe_sha256 | base_image | \
        packages_text | inspected | parsed_image_id | recipe_label | base_label | packages_label)
        return 1
        ;;
    esac
    if ! campaign_run_before_deadline_capture inspected "$command_deadline" \
        docker image inspect --format \
        '{{.Id}}{{printf "\t"}}{{index .Config.Labels "io.oxidedns.interop.recipe-sha256"}}{{printf "\t"}}{{index .Config.Labels "io.oxidedns.interop.base-image"}}{{printf "\t"}}{{index .Config.Labels "io.oxidedns.interop.packages"}}' \
        "$tag" 2>/dev/null; then
        return 1
    fi
    IFS=$'\t' read -r parsed_image_id recipe_label base_label packages_label <<<"$inspected"
    [[ "$parsed_image_id" =~ ^sha256:[0-9a-f]{64}$ && "$recipe_label" == "$recipe_sha256" &&
        "$base_label" == "$base_image" && "$packages_label" == "$packages_text" ]] || return 1
    # Return the immutable local content ID, never the mutable tag that was
    # authenticated. A concurrent retag therefore cannot redirect a scenario.
    printf -v "$output_variable" '%s' "$parsed_image_id"
}

_ensure_alpine_interop_image() {
    local name="$1"
    shift
    local packages=("$@")
    local package
    local inspect_timeout="${OXIDEDNS_INTEROP_DOCKER_INSPECT_TIMEOUT_SECONDS:-30}"
    local build_timeout="${OXIDEDNS_INTEROP_DOCKER_BUILD_TIMEOUT_SECONDS:-900}"
    local setup_timeout="${OXIDEDNS_INTEROP_DOCKER_SETUP_TIMEOUT_SECONDS:-960}"
    local deadline_nanoseconds absolute_deadline_nanoseconds build_dir=""
    local maximum_timeout=2147483647
    local base_image="${OXIDEDNS_INTEROP_ALPINE_BASE_IMAGE:-$OXIDEDNS_INTEROP_ALPINE_BASE_IMAGE_EXPECTED}"

    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || {
        printf 'invalid Docker interop image name: %s\n' "$name" >&2
        return 1
    }
    [[ "$base_image" == "$OXIDEDNS_INTEROP_ALPINE_BASE_IMAGE_EXPECTED" ]] || {
        printf 'unsupported Docker interop Alpine base image: %s\n' "$base_image" >&2
        return 1
    }

    command -v timeout >/dev/null 2>&1 || {
        printf 'missing required Docker image setup timeout tool: timeout\n' >&2
        return 1
    }
    require_bounded_docker_timeout() {
        local label="$1" value="$2"
        [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
            printf 'invalid Docker image %s timeout: %s\n' "$label" "$value" >&2
            return 1
        }
        # shellcheck disable=SC2071
        if ((${#value} > ${#maximum_timeout})) ||
            { ((${#value} == ${#maximum_timeout})) && [[ "$value" > "$maximum_timeout" ]]; }; then
            printf 'Docker image %s timeout exceeds supported maximum %s: %s\n' \
                "$label" "$maximum_timeout" "$value" >&2
            return 1
        fi
    }
    require_bounded_docker_timeout inspect "$inspect_timeout" || return 1
    require_bounded_docker_timeout build "$build_timeout" || return 1
    require_bounded_docker_timeout 'absolute setup' "$setup_timeout" || return 1
    command -v python3 >/dev/null 2>&1 || {
        printf 'missing required Docker image monotonic deadline runtime: python3\n' >&2
        return 1
    }
    local now_nanoseconds
    now_nanoseconds="$(campaign_monotonic_nanoseconds)" || return 1
    [[ "$now_nanoseconds" =~ ^[0-9]+$ ]] || return 1
    ((setup_timeout <= (9223372036854775807 - now_nanoseconds) / 1000000000)) || {
        printf 'Docker image monotonic setup deadline exceeds signed 64-bit time\n' >&2
        return 1
    }
    ((setup_timeout >= 2)) || {
        printf 'Docker image absolute setup timeout must reserve at least one second for safe cleanup\n' >&2
        return 1
    }
    absolute_deadline_nanoseconds=$((now_nanoseconds + setup_timeout * 1000000000))
    local cleanup_reserve_seconds=5
    ((setup_timeout > cleanup_reserve_seconds)) || cleanup_reserve_seconds=1
    deadline_nanoseconds=$((absolute_deadline_nanoseconds - cleanup_reserve_seconds * 1000000000))
    image_setup_absolute_deadline_nanoseconds="$absolute_deadline_nanoseconds"

    remaining_timeout() {
        campaign_deadline_remaining_seconds "$deadline_nanoseconds" "$1"
    }

    for package in "${packages[@]}"; do
        [[ "$package" =~ ^[A-Za-z0-9_.+-]+$ ]] || {
            printf 'invalid Alpine package name for %s image: %s\n' "$name" "$package" >&2
            return 1
        }
    done
    local packages_text="${packages[*]}" recipe_sha256 tag command_timeout command_deadline image_id lock_root
    recipe_sha256="$(interop_image_recipe_sha256 "$name" "$base_image" "${packages[@]}")" || return 1
    tag="oxidedns-interop-alpine-$name:recipe-${recipe_sha256:0:20}"

    command_deadline="$(campaign_deadline_capped "$deadline_nanoseconds" "$inspect_timeout")" || return 1
    if interop_inspect_authenticated_image image_id "$command_deadline" "$tag" "$recipe_sha256" \
        "$base_image" "$packages_text"; then
        printf '%s\n' "$image_id"
        return 0
    fi

    lock_root="$(interop_image_private_lock_root)" || return 1
    campaign_acquire_private_lock "$lock_root" "interop-image:$recipe_sha256" \
        "interop image $name build lock" "$deadline_nanoseconds" \
        "$absolute_deadline_nanoseconds" || return 1
    campaign_assert_private_lock "$deadline_nanoseconds" \
        "$absolute_deadline_nanoseconds" || return 1

    command_deadline="$(campaign_deadline_capped "$deadline_nanoseconds" "$inspect_timeout")" || return 1
    if interop_inspect_authenticated_image image_id "$command_deadline" "$tag" "$recipe_sha256" \
        "$base_image" "$packages_text"; then
        printf '%s\n' "$image_id"
        return 0
    fi

    campaign_prepare_private_temporary_tree "${TMPDIR:-/tmp}" oxidedns-interop-builds \
        interop_image_build_context build_dir "$deadline_nanoseconds" \
        "$absolute_deadline_nanoseconds" || {
        printf 'cannot create descriptor-bound Docker image build context\n' >&2
        return 1
    }
    image_setup_build_dir="$build_dir"
    {
        printf 'FROM %s\n' "$base_image"
        printf 'LABEL io.oxidedns.interop.recipe-sha256="%s"\n' "$recipe_sha256"
        printf 'LABEL io.oxidedns.interop.base-image="%s"\n' "$base_image"
        printf 'LABEL io.oxidedns.interop.packages="%s"\n' "$packages_text"
        printf 'RUN set -eu; for attempt in 1 2 3 4 5; do apk add --no-cache'
        for package in "${packages[@]}"; do
            printf ' %s' "$package"
        done
        # shellcheck disable=SC2016
        printf ' && exit 0; sleep $((attempt * 3)); done; exit 1\n'
    } >"$build_dir/Dockerfile"

    local status=1 attempt
    for attempt in 1 2 3 4 5; do
        campaign_assert_private_lock "$deadline_nanoseconds" \
            "$absolute_deadline_nanoseconds" || return 1
        command_deadline="$(campaign_deadline_capped "$deadline_nanoseconds" "$build_timeout")" || break
        if campaign_run_before_deadline "$command_deadline" \
            docker build --pull -t "$tag" "$build_dir" >&2; then
            status=0
            break
        fi
        command_timeout="$(remaining_timeout "$((attempt * 5))")" || break
        sleep "$command_timeout"
    done
    ((status == 0)) || {
        printf 'failed to build Docker interop image: %s\n' "$tag" >&2
        return "$status"
    }
    campaign_assert_private_lock "$deadline_nanoseconds" \
        "$absolute_deadline_nanoseconds" || return 1
    command_deadline="$(campaign_deadline_capped "$deadline_nanoseconds" "$inspect_timeout")" || return 1
    interop_inspect_authenticated_image image_id "$command_deadline" "$tag" "$recipe_sha256" \
        "$base_image" "$packages_text" || {
        printf 'built Docker interop image lacks its authenticated recipe labels: %s\n' "$tag" >&2
        return 1
    }
    printf '%s\n' "$image_id"
}

ensure_alpine_interop_image() (
    # A scenario may be launched by a runner that already owns its evidence
    # lock. Keep the image-build broker state local to this helper subshell;
    # inherited descriptors remain open until this short-lived child exits,
    # while the caller's broker variables and lock remain untouched.
    campaign_lock_control_fd=""
    campaign_lock_response_fd=""
    campaign_lock_pid=""
    campaign_lock_label=""
    image_setup_build_dir=""
    image_setup_absolute_deadline_nanoseconds=""
    # Invoked indirectly by the EXIT trap below.
    # shellcheck disable=SC2329
    cleanup_image_setup() {
        local status=$? cleanup_status=0
        trap - EXIT
        trap '' INT TERM HUP
        if declare -F interop_image_cleanup_started_hook >/dev/null 2>&1; then
            interop_image_cleanup_started_hook
        fi
        if [[ -n "$image_setup_build_dir" ]]; then
            if [[ -n "$image_setup_absolute_deadline_nanoseconds" ]]; then
                campaign_remove_private_temporary_tree "$image_setup_build_dir" \
                    interop_image_build_context "Docker image build context" \
                    "$image_setup_absolute_deadline_nanoseconds" || cleanup_status=74
            else
                printf 'Docker image setup has no absolute deadline for build-context cleanup; retaining bound context: %s\n' \
                    "$image_setup_build_dir" >&2
                cleanup_status=74
            fi
        fi
        if [[ -n "${campaign_lock_pid:-}" ]]; then
            if [[ -n "$image_setup_absolute_deadline_nanoseconds" ]]; then
                campaign_release_private_lock "$image_setup_absolute_deadline_nanoseconds" || cleanup_status=74
            else
                # No deadline means setup failed before the broker could be
                # safely enrolled in the bounded cleanup protocol.
                [[ -z "${campaign_lock_control_fd:-}" ]] || exec {campaign_lock_control_fd}>&-
                [[ -z "${campaign_lock_response_fd:-}" ]] || exec {campaign_lock_response_fd}<&-
                campaign_lock_control_fd=""
                campaign_lock_response_fd=""
                campaign_lock_pid=""
                campaign_lock_label=""
                cleanup_status=74
            fi
        fi
        ((status != 0 || cleanup_status == 0)) || status="$cleanup_status"
        exit "$status"
    }
    trap cleanup_image_setup EXIT
    _ensure_alpine_interop_image "$@"
)

ensure_alpine_bind_image() {
    ensure_alpine_interop_image bind bind bind-tools
}

ensure_alpine_knot_image() {
    ensure_alpine_interop_image knot knot
}

ensure_alpine_nsd_image() {
    ensure_alpine_interop_image nsd nsd
}

ensure_alpine_nsd_notify_image() {
    ensure_alpine_interop_image nsd-notify gcompat libgcc nsd python3
}

ensure_alpine_packet_torture_image() {
    ensure_alpine_interop_image packet-torture python3 wireshark-common
}
