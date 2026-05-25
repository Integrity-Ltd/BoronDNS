#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${OXIDEDNS_LOG_EVIDENCE_DIR:-$repo_root/target/log-evidence}"
mkdir -p "$evidence_dir"

require_text() {
  local path="$1"
  local needle="$2"
  if ! grep -F -- "$needle" "$path" >/dev/null 2>&1; then
    printf '%s missing required text: %s\n' "$path" "$needle" >&2
    exit 1
  fi
}

run_runtime_capture() {
  local name="$1"
  local format="$2"
  local max_entry_length_bytes="${3:-}"
  local ready_needle="${4:-zone remains in LOADING state}"
  local config="$evidence_dir/runtime-$name.toml"
  local stdout="$evidence_dir/runtime-$name.stdout"
  local stderr="$evidence_dir/runtime-$name.stderr"
  local status_file="$evidence_dir/runtime-$name.status"

  cat >"$config" <<EOF
[server]
log_level = "info"
log_format = "$format"

[interfaces]
dns = ["127.0.0.1:0"]
transfer = ["127.0.0.1:0"]

[health]
bind_address = "127.0.0.1"
bind_port = 0
EOF

  if [[ -n "$max_entry_length_bytes" ]]; then
    cat >>"$config" <<EOF

[logging]
max_entry_length_bytes = $max_entry_length_bytes
EOF
  fi

  cat >>"$config" <<'EOF'
[limits]
axfr_timeout_secs = 1
graceful_shutdown_secs = 1

[[zones]]
name = "example.test."
primaries = ["127.0.0.1:9"]
EOF

  "$repo_root/target/debug/oxidedns" serve --config "$config" >"$stdout" 2>"$stderr" &
  local pid=$!
  local ready=0
  for _ in $(seq 1 100); do
    if grep -F -- "$ready_needle" "$stderr" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.05
  done

  if (( ready != 1 )); then
    printf 'OxideDNS did not emit expected runtime log for %s capture\n' "$name" >&2
    sed -n '1,120p' "$stderr" >&2 || true
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    exit 1
  fi

  kill -TERM "$pid"
  set +e
  wait "$pid"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$status_file"
  if (( status != 0 )); then
    printf 'OxideDNS exited with status %s during %s log capture\n' "$status" "$name" >&2
    sed -n '1,120p' "$stderr" >&2 || true
    exit "$status"
  fi
}

cd "$repo_root"
cargo build -q -p oxidedns-cli

run_runtime_capture json json
run_runtime_capture logfmt logfmt
run_runtime_capture logfmt-limited logfmt 128 "truncated=true"

require_text "$evidence_dir/runtime-json.stderr" '"category":"startup"'
require_text "$evidence_dir/runtime-json.stderr" '"message":"OxideDNS runtime initialized"'
require_text "$evidence_dir/runtime-json.stderr" '"udp_listeners":1'
require_text "$evidence_dir/runtime-json.stderr" '"tcp_listeners":1'
require_text "$evidence_dir/runtime-json.stderr" '"message":"AXFR failed"'
require_text "$evidence_dir/runtime-json.stderr" '"zone":"example.test."'
require_text "$evidence_dir/runtime-json.stderr" '"primary":"127.0.0.1:9"'
require_text "$evidence_dir/runtime-json.stderr" '"signal":"SIGTERM"'

grep '^timestamp=' "$evidence_dir/runtime-logfmt.stderr" >"$evidence_dir/runtime-logfmt.records"
require_text "$evidence_dir/runtime-logfmt.stderr" 'category=configuration_warning'
require_text "$evidence_dir/runtime-logfmt.stderr" 'message="OxideDNS runtime initialized"'
require_text "$evidence_dir/runtime-logfmt.stderr" 'udp_listeners=1'
require_text "$evidence_dir/runtime-logfmt.stderr" 'tcp_listeners=1'
require_text "$evidence_dir/runtime-logfmt.stderr" 'message="AXFR failed"'
require_text "$evidence_dir/runtime-logfmt.stderr" 'zone=example.test.'
require_text "$evidence_dir/runtime-logfmt.stderr" 'primary=127.0.0.1:9'
require_text "$evidence_dir/runtime-logfmt.stderr" 'signal=SIGTERM'

grep -E '^(timestamp=|message=)' "$evidence_dir/runtime-logfmt-limited.stderr" \
  >"$evidence_dir/runtime-logfmt-limited.records"
require_text "$evidence_dir/runtime-logfmt-limited.records" 'truncated=true'
require_text "$evidence_dir/runtime-logfmt-limited.records" '...<truncated>'
if ! awk 'length($0) > 128 { print; failed = 1 } END { exit failed }' \
  "$evidence_dir/runtime-logfmt-limited.records"; then
  printf 'bounded logfmt runtime records exceeded 128 bytes\n' >&2
  exit 1
fi

cat >"$evidence_dir/README.md" <<'EOF'
# OxideDNS Log Evidence

Captured short runtime sessions for SRS structured logging requirements:

- JSON runtime logs with canonical startup, listener, transfer-failure, zone, and signal fields.
- logfmt runtime logs with canonical `timestamp`, `level`, `target`, `message`, and event fields.
- bounded logfmt runtime logs proving configured end-to-end truncation remains parseable and within `logging.max_entry_length_bytes`.
- Bootstrap records remain JSON before the configured runtime logger is applied.

Each runtime capture stores the generated config, stdout, stderr, and exit status.
This capture is representative stream evidence; it does not replace static review
of every log-emission site or long-running production log collection.
EOF

printf 'Log evidence captured in %s\n' "$evidence_dir"
