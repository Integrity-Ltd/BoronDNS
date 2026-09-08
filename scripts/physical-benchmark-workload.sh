#!/usr/bin/env bash
# Shared by the physical wrapper and its local, fake-SSH regression tests.
# Uses the wrapper's ssh_control and explicitly selected host/path variables.
# These variables are the caller's interface, including prepared_* outputs.
# shellcheck disable=SC2154,SC2034

snapshot_physical_workload() {
    workload_querydb="$ssh_control_dir/querydb"
    workload_manifest="$ssh_control_dir/workload.json"
    # A campaign owns one immutable trace snapshot, not a mutable player default.
    ssh_control "$server_ssh" "head -c 67108865 '$stage_abs/querydb'" >"$workload_querydb"
    python3 "$workload_verifier" manifest "$workload_querydb" \
        --policy "$workload_policy" --output "$workload_manifest"
    chmod 400 "$workload_querydb" "$workload_manifest"
    ssh_control "$server_ssh" "umask 077; mkdir -p '$out_abs/workload'; cat > '$out_abs/workload/querydb'" <"$workload_querydb"
    ssh_control "$server_ssh" "cat > '$out_abs/workload/manifest.json'; chmod 400 '$out_abs/workload/querydb' '$out_abs/workload/manifest.json'" <"$workload_manifest"
    ssh_control "$server_ssh" "sha256sum '$out_abs/workload/querydb'" >"$ssh_control_dir/server-querydb.sha256"
    [[ "$(cut -d ' ' -f 1 "$ssh_control_dir/server-querydb.sha256")" == "$(sha256sum "$workload_querydb" | cut -d ' ' -f 1)" ]] || {
        printf 'server workload snapshot hash mismatch\n' >&2
        return 1
    }
}

stage_player_querydb() {
    local run_abs="$1" id="$2"
    prepared_player_remote_dir="$(ssh_control "$player_ssh" "mktemp -d '$player_workdir_abs/.borondns-physical-${id}.XXXXXXXX'")"
    prepared_player_run_dir="${prepared_player_remote_dir##*/}"
    prepared_player_row_id="$id"
    ssh_control "$player_ssh" "cat > '$prepared_player_remote_dir/querydb'" <"$workload_querydb"
    ssh_control "$player_ssh" "cat > '$prepared_player_remote_dir/manifest.json'" <"$workload_manifest"
    ssh_control "$player_ssh" "cat > '$prepared_player_remote_dir/verify-workload.py'; chmod 400 '$prepared_player_remote_dir/querydb' '$prepared_player_remote_dir/manifest.json'" <"$workload_verifier"
    ssh_control "$player_ssh" "sha256sum '$prepared_player_remote_dir/querydb'" >"$ssh_control_dir/player-querydb.sha256"
    [[ "$(cut -d ' ' -f 1 "$ssh_control_dir/player-querydb.sha256")" == "$(sha256sum "$workload_querydb" | cut -d ' ' -f 1)" ]] || {
        printf 'player workload snapshot hash mismatch\n' >&2
        return 1
    }
    ssh_control "$server_ssh" "cat > '$run_abs/player-querydb.sha256'" <"$ssh_control_dir/player-querydb.sha256"
    ssh_control "$server_ssh" "cat > '$run_abs/workload-manifest.json'" <"$workload_manifest"
}

prepare_player_workload() {
    local run_abs="$1" id="$2" port="$3" status=0
    stage_player_querydb "$run_abs" "$id"
    # Probe from the actual source host/address, before perf and timed traffic.
    ssh_control "$player_ssh" "python3 '$prepared_player_remote_dir/verify-workload.py' probe '$prepared_player_remote_dir/querydb' --manifest '$prepared_player_remote_dir/manifest.json' --target '$target_ip' --port '$port' --source '$source_ip' --output '$prepared_player_remote_dir/probe.json'" || status="$?"
    ssh_control "$player_ssh" "cat '$prepared_player_remote_dir/probe.json'" >"$ssh_control_dir/probe.json" || status=1
    ssh_control "$server_ssh" "cat > '$run_abs/workload-probe.json'" <"$ssh_control_dir/probe.json"
    if [[ "$status" != 0 ]]; then
        printf 'workload preflight failed; no timed load started (row %s)\n' "$id" >&2
        return "$status"
    fi
    refresh_server_packet_baseline "$run_abs" "$interface"
}

refresh_server_packet_baseline() {
    local run_abs="$1" interface="$2"
    # The server-start baseline predates the probes. Reset packet counters so
    # successful preflight traffic is not reported as load-generator traffic.
    ssh_control "$server_ssh" bash -s -- "$run_abs" "$interface" <<'REMOTE'
set -euo pipefail
run_abs="$1"
interface="$2"
# Initial cp preserves /proc's read-only mode. These exact, run-owned files
# are deliberately refreshed, so allow their owner to replace the contents.
chmod u+w "$run_abs/server-proc-net-dev-before.txt" \
    "$run_abs/server-proc-net-snmp-before.txt" \
    "$run_abs/server-proc-net-softnet-before.txt"
cp /proc/net/dev "$run_abs/server-proc-net-dev-before.txt"
cp /proc/net/snmp "$run_abs/server-proc-net-snmp-before.txt"
cp /proc/net/softnet_stat "$run_abs/server-proc-net-softnet-before.txt"
ethtool -S "$interface" >"$run_abs/server-ethtool-stats-before.txt" 2>&1 || true
tc -s qdisc show dev "$interface" >"$run_abs/server-tc-qdisc-before.txt" 2>&1 || true
REMOTE
}
