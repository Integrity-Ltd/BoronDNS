#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in cargo curl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done
if (( ${#missing[@]} > 0 )); then
  printf 'skipping health/metrics evidence: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${OXIDEDNS_HEALTH_METRICS_EVIDENCE_DIR:-$repo_root/target/health-metrics-evidence}"
mkdir -p "$evidence_dir"

cleanup() {
  if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" >/dev/null 2>&1; then
    kill -TERM "$oxidedns_pid" >/dev/null 2>&1 || true
    wait "$oxidedns_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_text() {
  local path="$1"
  local needle="$2"
  if ! grep -F -- "$needle" "$path" >/dev/null 2>&1; then
    printf '%s missing required text: %s\n' "$path" "$needle" >&2
    exit 1
  fi
}

require_http_code() {
  local meta="$1"
  local expected="$2"
  local actual
  actual="$(awk -F= '$1 == "http_code" { print $2 }' "$meta")"
  if [[ "$actual" != "$expected" ]]; then
    printf '%s expected HTTP %s, got %s\n' "$meta" "$expected" "${actual:-<missing>}" >&2
    exit 1
  fi
}

require_time_under() {
  local meta="$1"
  local threshold="$2"
  awk -F= -v threshold="$threshold" '
    $1 == "time_total" {
      if (($2 + 0) <= threshold) {
        found = 1
      } else {
        printf "%s time_total %.6f exceeded %.6f\n", FILENAME, $2, threshold > "/dev/stderr"
        exit 1
      }
    }
    END {
      if (!found) {
        printf "%s missing time_total\n", FILENAME > "/dev/stderr"
        exit 1
      }
    }
  ' "$meta"
}

capture_request() {
  local name="$1"
  local path="$2"
  shift 2
  curl -sS \
    -o "$evidence_dir/$name.body" \
    -D "$evidence_dir/$name.headers" \
    -w 'http_code=%{http_code}\ntime_total=%{time_total}\n' \
    "$@" \
    "http://127.0.0.1:$health_port$path" \
    >"$evidence_dir/$name.meta"
}

cd "$repo_root"
cargo build -q -p oxidedns-cli

read -r dns_port health_port < <(
  python3 - <<'PY'
import socket
sockets = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

cat >"$evidence_dir/oxidedns.toml" <<EOF
[server]
log_level = "info"
log_format = "logfmt"

[interfaces]
dns = ["127.0.0.1:$dns_port"]

[health]
bind_address = "127.0.0.1"
bind_port = $health_port
metrics_rate_limit_per_minute = 3
metrics_rate_limit_idle_seconds = 300

[limits]
axfr_timeout_secs = 1
graceful_shutdown_secs = 1

[[zones]]
name = "example.test."
primaries = ["127.0.0.1:9"]
EOF

"$repo_root/target/debug/oxidedns" serve --config "$evidence_dir/oxidedns.toml" \
  >"$evidence_dir/oxidedns.stdout" \
  2>"$evidence_dir/oxidedns.stderr" &
oxidedns_pid=$!

for _ in $(seq 1 100); do
  if grep -F -- "health listener bound" "$evidence_dir/oxidedns.stderr" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$oxidedns_pid" >/dev/null 2>&1; then
    printf 'OxideDNS exited before health listener bound\n' >&2
    sed -n '1,120p' "$evidence_dir/oxidedns.stderr" >&2 || true
    exit 1
  fi
  sleep 0.05
done
require_text "$evidence_dir/oxidedns.stderr" "health listener bound"

capture_request livez /livez
capture_request readyz /readyz
capture_request healthz /healthz
capture_request metrics-plain /metrics
capture_request metrics-gzip /metrics -H 'Accept-Encoding: gzip'
capture_request metrics-third /metrics
capture_request metrics-rate-limited /metrics
for index in $(seq -w 1 10); do
  capture_request "metrics-burst-$index" /metrics
done
capture_request livez-after-metrics-limit /livez
capture_request readyz-after-metrics-limit /readyz

require_http_code "$evidence_dir/livez.meta" 200
require_http_code "$evidence_dir/readyz.meta" 503
require_http_code "$evidence_dir/healthz.meta" 503
require_http_code "$evidence_dir/metrics-plain.meta" 200
require_http_code "$evidence_dir/metrics-gzip.meta" 200
require_http_code "$evidence_dir/metrics-third.meta" 200
require_http_code "$evidence_dir/metrics-rate-limited.meta" 429
for index in $(seq -w 1 10); do
  require_http_code "$evidence_dir/metrics-burst-$index.meta" 429
done
require_http_code "$evidence_dir/livez-after-metrics-limit.meta" 200
require_http_code "$evidence_dir/readyz-after-metrics-limit.meta" 503

for meta in \
  "$evidence_dir/livez.meta" \
  "$evidence_dir/readyz.meta" \
  "$evidence_dir/healthz.meta" \
  "$evidence_dir/livez-after-metrics-limit.meta" \
  "$evidence_dir/readyz-after-metrics-limit.meta"; do
  require_time_under "$meta" 1.0
done

require_text "$evidence_dir/livez.body" '"status":"alive"'
require_text "$evidence_dir/readyz.body" '"status":"not-ready"'
require_text "$evidence_dir/readyz.body" '"reason":"loading"'
require_text "$evidence_dir/healthz.body" '"status":"not-ready"'
require_text "$evidence_dir/metrics-plain.body" 'oxidedns_secondary_build_info{version="'
require_text "$evidence_dir/metrics-plain.body" 'oxidedns_zones_total 1'
require_text "$evidence_dir/metrics-gzip.headers" 'content-encoding: gzip'
require_text "$evidence_dir/metrics-gzip.headers" 'vary: accept-encoding'
require_text "$evidence_dir/metrics-rate-limited.headers" 'retry-after:'
require_text "$evidence_dir/metrics-rate-limited.body" '"error":"rate_limited"'
for index in $(seq -w 1 10); do
  require_text "$evidence_dir/metrics-burst-$index.headers" 'retry-after:'
  require_text "$evidence_dir/metrics-burst-$index.body" '"error":"rate_limited"'
done
require_text "$evidence_dir/livez-after-metrics-limit.body" '"status":"alive"'
require_text "$evidence_dir/readyz-after-metrics-limit.body" '"status":"not-ready"'

{
  printf 'request\thttp_code\ttime_total\tretry_after\n'
  for name in metrics-rate-limited $(seq -f 'metrics-burst-%02g' 1 10); do
    code="$(awk -F= '$1 == "http_code" { print $2 }' "$evidence_dir/$name.meta")"
    time_total="$(awk -F= '$1 == "time_total" { print $2 }' "$evidence_dir/$name.meta")"
    retry_after="$(awk 'tolower($1) == "retry-after:" { print $2; exit }' "$evidence_dir/$name.headers" | tr -d '\r')"
    printf '%s\t%s\t%s\t%s\n' "$name" "$code" "$time_total" "$retry_after"
  done
} >"$evidence_dir/metrics-rate-limit-burst.tsv"

{
  printf 'health_port=%s\n' "$health_port"
  printf 'dns_port=%s\n' "$dns_port"
  printf 'probe_timing_threshold_seconds=1.0\n'
  printf 'metrics_rate_limit_per_minute=3\n'
  printf 'livez_status=200\n'
  printf 'readyz_loading_status=503\n'
  printf 'healthz_loading_status=503\n'
  printf 'metrics_plain_status=200\n'
  printf 'metrics_gzip_status=200\n'
  printf 'metrics_rate_limited_status=429\n'
  printf 'metrics_rate_limit_burst_requests=10\n'
  printf 'metrics_rate_limit_burst_status=429\n'
  printf 'probes_after_metrics_rate_limit=available\n'
} >"$evidence_dir/summary.env"

cat >"$evidence_dir/README.md" <<'EOF'
# OxideDNS Health and Metrics Evidence

Captured retained HTTP evidence for SRS health and metrics requirements:

- `/livez` returns HTTP 200 with liveness JSON while the zone is loading.
- `/readyz` and `/healthz` return HTTP 503 with loading readiness JSON before
  any zone is ACTIVE.
- Probe timings are retained in curl metadata and checked under a conservative
  one-second local threshold; focused Rust tests cover the stricter 100 ms SRS
  health-probe bound.
- `/metrics` returns Prometheus text with build/configured-zone evidence.
- `/metrics` returns gzip output when requested.
- `/metrics` is per-source rate limited with HTTP 429 and `Retry-After`, while
  `/livez` and `/readyz` remain available after the metrics limiter is hit.
- A retained repeated scrape burst records status, timing, and `Retry-After`
  values for ten additional over-limit `/metrics` requests from the same
  source.

Each request stores response body, headers, and curl metadata.
EOF

printf 'Health/metrics evidence captured in %s\n' "$evidence_dir"
