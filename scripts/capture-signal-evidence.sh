#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${OXIDEDNS_SIGNAL_EVIDENCE_DIR:-$repo_root/target/signal-evidence}"
mkdir -p "$evidence_dir"

require_text() {
  local path="$1"
  local needle="$2"
  if ! grep -F -- "$needle" "$path" >/dev/null 2>&1; then
    printf '%s missing required text: %s\n' "$path" "$needle" >&2
    exit 1
  fi
}

write_config() {
  local config="$1"
  cat >"$config" <<'EOF'
[server]
listen_udp = ["127.0.0.1:0"]
listen_tcp = ["127.0.0.1:0"]
log_level = "info"
log_format = "logfmt"

[limits]
axfr_timeout_secs = 1
graceful_shutdown_secs = 1

[[zones]]
name = "example.test."
primaries = ["127.0.0.1:9"]
EOF
}

wait_for_running() {
  local pid="$1"
  local stderr="$2"
  for _ in $(seq 1 100); do
    if grep -F -- "zone remains in LOADING state" "$stderr" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      printf 'OxideDNS exited before becoming observable\n' >&2
      sed -n '1,120p' "$stderr" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  printf 'OxideDNS did not emit running-state evidence\n' >&2
  sed -n '1,120p' "$stderr" >&2 || true
  return 1
}

wait_for_exit() {
  local pid="$1"
  local name="$2"
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      wait "$pid"
      return $?
    fi
    sleep 0.05
  done
  printf 'OxideDNS did not exit after %s\n' "$name" >&2
  kill -KILL "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  return 124
}

run_signal_exit_capture() {
  local name="$1"
  local signal="$2"
  local config="$evidence_dir/$name.toml"
  local stdout="$evidence_dir/$name.stdout"
  local stderr="$evidence_dir/$name.stderr"
  local status_file="$evidence_dir/$name.status"
  write_config "$config"

  "$repo_root/target/debug/oxidedns" serve --config "$config" >"$stdout" 2>"$stderr" &
  local pid=$!
  wait_for_running "$pid" "$stderr"

  kill "-$signal" "$pid"
  set +e
  wait_for_exit "$pid" "$signal"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$status_file"
  if (( status != 0 )); then
    printf 'OxideDNS exited with status %s after %s\n' "$status" "$signal" >&2
    sed -n '1,120p' "$stderr" >&2 || true
    exit "$status"
  fi
  require_text "$stderr" "signal=$signal"
}

run_sighup_capture() {
  local config="$evidence_dir/sighup.toml"
  local stdout="$evidence_dir/sighup.stdout"
  local stderr="$evidence_dir/sighup.stderr"
  local status_file="$evidence_dir/sighup.status"
  local observation_file="$evidence_dir/sighup.observation"
  write_config "$config"

  "$repo_root/target/debug/oxidedns" serve --config "$config" >"$stdout" 2>"$stderr" &
  local pid=$!
  wait_for_running "$pid" "$stderr"

  kill -HUP "$pid"
  sleep 0.2
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    printf 'OxideDNS exited after SIGHUP\n' >&2
    wait "$pid" || true
    exit 1
  fi
  printf 'alive_after_sighup=true\n' >"$observation_file"

  kill -TERM "$pid"
  set +e
  wait_for_exit "$pid" "SIGTERM after SIGHUP"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$status_file"
  if (( status != 0 )); then
    printf 'OxideDNS exited with status %s after SIGTERM following SIGHUP\n' "$status" >&2
    sed -n '1,120p' "$stderr" >&2 || true
    exit "$status"
  fi
  require_text "$stderr" "signal=SIGTERM"
}

run_closed_consumers_capture() {
  local config="$evidence_dir/closed-consumers.toml"
  local status_file="$evidence_dir/closed-consumers.status"
  local observation_file="$evidence_dir/closed-consumers.observation"
  write_config "$config"

  "$repo_root/target/debug/oxidedns" serve --config "$config" \
    > >(head -c 0 >/dev/null) \
    2> >(head -c 0 >/dev/null) &
  local pid=$!

  sleep 1.2
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    printf 'OxideDNS exited after stdout/stderr consumers closed\n' >&2
    wait "$pid" || true
    exit 1
  fi
  printf 'alive_after_closed_stdout_stderr=true\n' >"$observation_file"

  kill -TERM "$pid"
  set +e
  wait_for_exit "$pid" "SIGTERM after closed consumers"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$status_file"
  if (( status != 0 )); then
    printf 'OxideDNS exited with status %s after closed consumers\n' "$status" >&2
    exit "$status"
  fi
}

signal_mask() {
  local status="$1"
  local prefix="$2"
  awk -v prefix="$prefix" '$1 == prefix { print $2 }' "$status"
}

assert_mask_has_signal() {
  local mask_hex="$1"
  local signal_number="$2"
  local name="$3"
  local mask=$((16#$mask_hex))
  local bit=$((1 << (signal_number - 1)))
  if (( (mask & bit) == 0 )); then
    printf '%s missing from mask 0x%s\n' "$name" "$mask_hex" >&2
    exit 1
  fi
}

assert_mask_lacks_signal() {
  local mask_hex="$1"
  local signal_number="$2"
  local name="$3"
  local mask=$((16#$mask_hex))
  local bit=$((1 << (signal_number - 1)))
  if (( (mask & bit) != 0 )); then
    printf '%s unexpectedly present in mask 0x%s\n' "$name" "$mask_hex" >&2
    exit 1
  fi
}

run_linux_disposition_capture() {
  local config="$evidence_dir/linux-dispositions.toml"
  local stdout="$evidence_dir/linux-dispositions.stdout"
  local stderr="$evidence_dir/linux-dispositions.stderr"
  local status_file="$evidence_dir/linux-dispositions.status"
  local proc_status="$evidence_dir/linux-dispositions.proc-status"
  local summary="$evidence_dir/linux-dispositions.summary"
  write_config "$config"

  "$repo_root/target/debug/oxidedns" serve --config "$config" >"$stdout" 2>"$stderr" &
  local pid=$!
  wait_for_running "$pid" "$stderr"
  cp "/proc/$pid/status" "$proc_status"

  local ignored caught
  ignored="$(signal_mask "$proc_status" "SigIgn:")"
  caught="$(signal_mask "$proc_status" "SigCgt:")"
  assert_mask_has_signal "$ignored" 1 "SIGHUP"
  assert_mask_has_signal "$ignored" 13 "SIGPIPE"
  assert_mask_has_signal "$caught" 2 "SIGINT"
  assert_mask_has_signal "$caught" 15 "SIGTERM"
  assert_mask_lacks_signal "$caught" 1 "SIGHUP"
  assert_mask_lacks_signal "$caught" 3 "SIGQUIT"
  assert_mask_lacks_signal "$caught" 10 "SIGUSR1"
  assert_mask_lacks_signal "$caught" 12 "SIGUSR2"
  assert_mask_lacks_signal "$caught" 13 "SIGPIPE"
  {
    printf 'SigIgn=%s\n' "$ignored"
    printf 'SigCgt=%s\n' "$caught"
    printf 'SIGHUP_ignored=true\n'
    printf 'SIGPIPE_ignored=true\n'
    printf 'SIGINT_caught=true\n'
    printf 'SIGTERM_caught=true\n'
    printf 'SIGHUP_SIGQUIT_SIGUSR1_SIGUSR2_SIGPIPE_not_caught=true\n'
  } >"$summary"

  kill -TERM "$pid"
  set +e
  wait_for_exit "$pid" "SIGTERM after disposition capture"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$status_file"
  if (( status != 0 )); then
    printf 'OxideDNS exited with status %s after disposition capture\n' "$status" >&2
    sed -n '1,120p' "$stderr" >&2 || true
    exit "$status"
  fi
}

cd "$repo_root"
cargo build -q -p oxidedns-cli

run_signal_exit_capture sigterm SIGTERM
run_signal_exit_capture sigint SIGINT
run_sighup_capture
run_closed_consumers_capture
if [[ "$(uname -s)" == "Linux" ]]; then
  run_linux_disposition_capture
else
  cat >"$evidence_dir/linux-dispositions.skipped" <<'EOF'
Linux /proc signal-disposition capture skipped because this host is not Linux.
EOF
fi

cat >"$evidence_dir/README.md" <<'EOF'
# OxideDNS Signal Evidence

Captured process-signal evidence for SRS signal-interface requirements:

- SIGTERM exits successfully after initiating graceful drain.
- SIGINT exits successfully through the same shutdown path.
- SIGHUP is ignored; the process remains alive and then exits cleanly on SIGTERM.
- Closed stdout/stderr consumers do not terminate the process through SIGPIPE.
- On Linux, `/proc/<pid>/status` is retained and checked for the expected
  `SigIgn` and `SigCgt` masks: SIGHUP and SIGPIPE ignored, SIGINT/SIGTERM
  caught, and SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2/SIGPIPE not caught.

Each runtime capture stores generated config, stdout/stderr where applicable,
exit status, and concise observation files.
EOF

printf 'Signal evidence captured in %s\n' "$evidence_dir"
