#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in cargo curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done
if ((${#missing[@]} > 0)); then
    printf 'skipping resource evidence: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${BORONDNS_RESOURCE_EVIDENCE_DIR:-$repo_root/target/evidence/resource-$$}"
sample_seconds="${BORONDNS_RESOURCE_IDLE_SAMPLE_SECONDS:-3}"
max_tcp_connections=32
max_concurrent_transfers=1
fd_bound=$((2 * (max_tcp_connections + max_concurrent_transfers + 100)))
mkdir -p "$evidence_dir"

if ! [[ "$sample_seconds" =~ ^[1-9][0-9]*$ ]]; then
    printf 'BORONDNS_RESOURCE_IDLE_SAMPLE_SECONDS must be a positive integer: %s\n' "$sample_seconds" >&2
    exit 1
fi

cleanup() {
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" >/dev/null 2>&1; then
        kill -TERM "$borondns_pid" >/dev/null 2>&1 || true
        wait "$borondns_pid" >/dev/null 2>&1 || true
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

cd "$repo_root"
cargo build --release -q -p borondns-cli

binary="$repo_root/target/release/borondns"
binary_bytes="$(stat -c '%s' "$binary")"
binary_mib="$(awk -v bytes="$binary_bytes" 'BEGIN { printf "%.3f", bytes / 1048576 }')"

{
    printf 'artifact\tbytes\tmib\tnote\n'
    printf 'target/release/borondns\t%s\t%s\tRelease binary size; not an OCI image size claim.\n' "$binary_bytes" "$binary_mib"
} >"$evidence_dir/binary-size.tsv"

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

cat >"$evidence_dir/borondns.toml" <<EOF
[server]
log_level = "info"
log_format = "logfmt"
zone_cache_directory = "$evidence_dir/zone-cache"

[interfaces]
dns = ["127.0.0.1:$dns_port"]

[health]
bind_address = "127.0.0.1"
bind_port = $health_port

[limits]
axfr_timeout_secs = 1
max_tcp_connections = $max_tcp_connections
max_concurrent_transfers = $max_concurrent_transfers
graceful_shutdown_secs = 1
zsm_initial_retry_secs = 60
zsm_initial_retry_max_secs = 60
zsm_loading_warning_threshold_secs = 60

[[zones]]
name = "resource.test."
primaries = ["127.0.0.1:9"]
EOF

"$binary" serve --config "$evidence_dir/borondns.toml" \
    >"$evidence_dir/borondns.stdout" \
    2>"$evidence_dir/borondns.stderr" &
borondns_pid=$!

for _ in $(seq 1 100); do
    if grep -F -- "health listener bound" "$evidence_dir/borondns.stderr" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$borondns_pid" >/dev/null 2>&1; then
        printf 'BoronDNS exited before health listener bound\n' >&2
        sed -n '1,160p' "$evidence_dir/borondns.stderr" >&2 || true
        exit 1
    fi
    sleep 0.05
done
require_text "$evidence_dir/borondns.stderr" "health listener bound"

curl -fsS "http://127.0.0.1:$health_port/livez" >"$evidence_dir/livez.json"
curl -sS -o "$evidence_dir/readyz.json" -w 'http_code=%{http_code}\n' \
    "http://127.0.0.1:$health_port/readyz" >"$evidence_dir/readyz.meta"
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$evidence_dir/metrics.txt"
require_text "$evidence_dir/livez.json" '"status":"alive"'
require_text "$evidence_dir/readyz.json" '"status":"not-ready"'
require_text "$evidence_dir/readyz.meta" 'http_code=503'
require_text "$evidence_dir/metrics.txt" 'borondns_secondary_build_info'

cp "/proc/$borondns_pid/status" "$evidence_dir/proc-status-before.txt"
cp "/proc/$borondns_pid/limits" "$evidence_dir/proc-limits.txt"
fd_count="$({ find "/proc/$borondns_pid/fd" -maxdepth 1 -type l -print 2>/dev/null || true; } | wc -l | tr -d ' ')"
printf 'fd_count=%s\nfd_formula_bound=%s\n' "$fd_count" "$fd_bound" >"$evidence_dir/fd-count.env"
if ((fd_count > fd_bound)); then
    printf 'runtime fd count %s exceeds SRS formula bound %s\n' "$fd_count" "$fd_bound" >&2
    exit 1
fi

python3 - "$borondns_pid" "$sample_seconds" >"$evidence_dir/idle-cpu.env" <<'PY'
import os
import sys
import time

pid = sys.argv[1]
sample_seconds = int(sys.argv[2])
hertz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])


def ticks():
    text = open(f"/proc/{pid}/stat", encoding="ascii").read()
    after = text[text.rfind(")") + 2 :].split()
    return int(after[11]) + int(after[12])


start_ticks = ticks()
start = time.monotonic()
time.sleep(sample_seconds)
end_ticks = ticks()
end = time.monotonic()
elapsed = end - start
cpu_seconds = (end_ticks - start_ticks) / hertz
cpu_pct_one_core = (cpu_seconds / elapsed) * 100 if elapsed else 0.0

print(f"sample_seconds={sample_seconds}")
print(f"elapsed_seconds={elapsed:.6f}")
print(f"cpu_seconds={cpu_seconds:.6f}")
print(f"cpu_pct_one_core={cpu_pct_one_core:.6f}")
print("note=short zero-query smoke sample; not the full 1000-zone 5-minute BDS-NFR-RES-006 benchmark")
PY

cp "/proc/$borondns_pid/status" "$evidence_dir/proc-status-after.txt"

rss_kib="$(awk '/^VmRSS:/ { print $2; found = 1 } END { if (!found) print 0 }' "$evidence_dir/proc-status-after.txt")"
cpu_pct="$(awk -F= '$1 == "cpu_pct_one_core" { print $2 }' "$evidence_dir/idle-cpu.env")"

{
    printf 'evidence\tstatus\tartifact\treview_note\n'
    printf 'BDS-NFR-RES-001\tsmoke\tbinary-size.tsv\tRelease binary size is retained as a proxy input; published OCI image size still requires release packaging evidence.\n'
    printf 'BDS-NFR-RES-004\tbounded-runtime\tfd-count.env; proc-limits.txt\tRuntime file-descriptor count %s is below the configured formula bound %s for this smoke profile.\n' "$fd_count" "$fd_bound"
    printf 'BDS-NFR-RES-006\tsmoke\tidle-cpu.env; proc-status-before.txt; proc-status-after.txt\tShort zero-query CPU sample recorded %.6f percent of one core with RSS %s KiB; full 1000-zone 5-minute acceptance benchmark remains open.\n' "$cpu_pct" "$rss_kib"
} >"$evidence_dir/resource-traceability.tsv"

{
    printf 'release_binary_bytes=%s\n' "$binary_bytes"
    printf 'release_binary_mib=%s\n' "$binary_mib"
    printf 'fd_count=%s\n' "$fd_count"
    printf 'fd_formula_bound=%s\n' "$fd_bound"
    printf 'rss_kib_after=%s\n' "$rss_kib"
    printf 'idle_cpu_pct_one_core=%s\n' "$cpu_pct"
} >"$evidence_dir/resource-summary.env"

printf 'resource_evidence_dir=%s\n' "$evidence_dir"
