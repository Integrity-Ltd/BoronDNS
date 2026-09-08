#!/usr/bin/env bash
# Sourced by the direct and detached physical benchmark launchers.
physical_validate_inputs() {
    local suffix name value
    for suffix in SERVER_SSH PLAYER_SSH INTERFACE TARGET_IP SOURCE_IP; do
        name="BORONDNS_PHYSICAL_$suffix"
        value="${!name:-}"
        if [[ -z "${value//[[:space:]]/}" ]]; then
            printf 'set %s explicitly for the reserved benchmark link\n' "$name" >&2
            return 64
        fi
    done
    if [[ "${BORONDNS_PHYSICAL_PLAYER_TOOL:-kxdpgun}" == boron-gun ]]; then
        for suffix in SOURCE_MAC TARGET_MAC; do
            name="BORONDNS_PHYSICAL_$suffix"
            value="${!name:-}"
            if [[ ! "$value" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
                printf 'set %s explicitly to the verified link MAC (xx:xx:xx:xx:xx:xx)\n' "$name" >&2
                return 64
            fi
        done
    fi
}
