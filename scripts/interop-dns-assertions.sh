#!/usr/bin/env bash

# Shared DNS response assertions for retained interop evidence.  `dig +short`
# deliberately omits the response header, so an empty value cannot distinguish
# REFUSED from SERVFAIL, NXDOMAIN, or a successful NODATA response.

dns_output_has_rcode() {
    local output="$1"
    local expected_rcode="$2"
    grep -Eq "status: ${expected_rcode}," <<<"$output"
}

dig_until_rcode() {
    local output_file="$1"
    local expected_rcode="$2"
    local attempts="$3"
    local retry_delay="$4"
    shift 4

    local output=""
    local attempt
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if output="$(dig "$@" +noall +comments +answer 2>&1)" &&
            dns_output_has_rcode "$output" "$expected_rcode"; then
            printf '%s\n' "$output" >"$output_file"
            return 0
        fi
        printf '%s\n' "$output" >"$output_file"
        if ((attempt < attempts)); then
            sleep "$retry_delay"
        fi
    done
    return 1
}
