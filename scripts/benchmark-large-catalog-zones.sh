#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in cargo docker python3 rustc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping large catalog benchmark: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping large catalog benchmark: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_dir="${OXIDEDNS_LARGE_BENCH_DIR:-$repo_root/target/evidence/large-catalog-benchmark-$timestamp}"
workdir="${OXIDEDNS_LARGE_BENCH_WORKDIR:-/tmp/oxidedns-large-catalog-bench-$timestamp}"
bind_container="oxidedns-large-bench-bind-$$"
bind_image="$(ensure_alpine_bind_image)"

target_rss_mib="${OXIDEDNS_LARGE_BENCH_TARGET_RSS_MIB:-$((8 * 1024))}"
zone_count="${OXIDEDNS_LARGE_BENCH_ZONES:-128}"
big_zone_count="${OXIDEDNS_LARGE_BENCH_BIG_ZONES:-16}"
small_names="${OXIDEDNS_LARGE_BENCH_SMALL_NAMES:-1000}"
names_per_gib="${OXIDEDNS_LARGE_BENCH_NAMES_PER_GIB:-700000}"
txt_bytes="${OXIDEDNS_LARGE_BENCH_TXT_BYTES:-1024}"
address_records_per_name="${OXIDEDNS_LARGE_BENCH_ADDRESS_RECORDS_PER_NAME:-1}"
duration="${OXIDEDNS_LARGE_BENCH_DURATION_SECONDS:-60}"
warmup_duration="${OXIDEDNS_LARGE_BENCH_WARMUP_SECONDS:-10}"
transport="${OXIDEDNS_LARGE_BENCH_TRANSPORT:-tcp}"
server_cpus="${OXIDEDNS_LARGE_BENCH_SERVER_CPUS:-4}"
client_threads="${OXIDEDNS_LARGE_BENCH_CLIENT_THREADS:-16}"
client_window="${OXIDEDNS_LARGE_BENCH_CLIENT_WINDOW:-64}"
response_timeout_ms="${OXIDEDNS_LARGE_BENCH_RESPONSE_TIMEOUT_MS:-1000}"
pipeline_timing_enabled="${OXIDEDNS_LARGE_BENCH_PIPELINE_TIMING_ENABLED:-true}"
perf_stat_enabled="${OXIDEDNS_LARGE_BENCH_PERF_STAT:-true}"
perf_record_enabled="${OXIDEDNS_LARGE_BENCH_PERF_RECORD:-false}"
perf_frequency="${OXIDEDNS_LARGE_BENCH_PERF_FREQUENCY:-99}"
enforce_rss_target="${OXIDEDNS_LARGE_BENCH_ENFORCE_RSS_TARGET:-true}"
keep_workdir="${OXIDEDNS_LARGE_BENCH_KEEP_WORKDIR:-false}"
retain_zone_files="${OXIDEDNS_LARGE_BENCH_RETAIN_ZONE_FILES:-false}"
tmp_cleanup="${OXIDEDNS_LARGE_BENCH_TMP_CLEANUP:-true}"
tsig_name="${OXIDEDNS_LARGE_BENCH_TSIG_NAME:-bench-key.}"
tsig_secret="${OXIDEDNS_LARGE_BENCH_TSIG_SECRET:-c2VjcmV0LWxhcmdlLWJlbmNoLWtleQ==}"

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

require_nonnegative_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s must be a non-negative integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

require_boolean() {
    local name="$1"
    local value="$2"
    case "$value" in
    true | false) ;;
    *)
        printf '%s must be true or false, got %q\n' "$name" "$value" >&2
        exit 64
        ;;
    esac
}

for pair in \
    "OXIDEDNS_LARGE_BENCH_TARGET_RSS_MIB:$target_rss_mib" \
    "OXIDEDNS_LARGE_BENCH_ZONES:$zone_count" \
    "OXIDEDNS_LARGE_BENCH_BIG_ZONES:$big_zone_count" \
    "OXIDEDNS_LARGE_BENCH_SMALL_NAMES:$small_names" \
    "OXIDEDNS_LARGE_BENCH_NAMES_PER_GIB:$names_per_gib" \
    "OXIDEDNS_LARGE_BENCH_TXT_BYTES:$txt_bytes" \
    "OXIDEDNS_LARGE_BENCH_ADDRESS_RECORDS_PER_NAME:$address_records_per_name" \
    "OXIDEDNS_LARGE_BENCH_DURATION_SECONDS:$duration" \
    "OXIDEDNS_LARGE_BENCH_SERVER_CPUS:$server_cpus" \
    "OXIDEDNS_LARGE_BENCH_CLIENT_THREADS:$client_threads" \
    "OXIDEDNS_LARGE_BENCH_CLIENT_WINDOW:$client_window" \
    "OXIDEDNS_LARGE_BENCH_RESPONSE_TIMEOUT_MS:$response_timeout_ms" \
    "OXIDEDNS_LARGE_BENCH_PERF_FREQUENCY:$perf_frequency"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
require_nonnegative_integer OXIDEDNS_LARGE_BENCH_WARMUP_SECONDS "$warmup_duration"

for pair in \
    "OXIDEDNS_LARGE_BENCH_PIPELINE_TIMING_ENABLED:$pipeline_timing_enabled" \
    "OXIDEDNS_LARGE_BENCH_PERF_STAT:$perf_stat_enabled" \
    "OXIDEDNS_LARGE_BENCH_PERF_RECORD:$perf_record_enabled" \
    "OXIDEDNS_LARGE_BENCH_ENFORCE_RSS_TARGET:$enforce_rss_target" \
    "OXIDEDNS_LARGE_BENCH_KEEP_WORKDIR:$keep_workdir" \
    "OXIDEDNS_LARGE_BENCH_RETAIN_ZONE_FILES:$retain_zone_files" \
    "OXIDEDNS_LARGE_BENCH_TMP_CLEANUP:$tmp_cleanup"; do
    require_boolean "${pair%%:*}" "${pair#*:}"
done

case "$transport" in
udp | tcp) ;;
*)
    printf 'OXIDEDNS_LARGE_BENCH_TRANSPORT must be udp or tcp, got %q\n' "$transport" >&2
    exit 64
    ;;
esac

if ((big_zone_count > zone_count)); then
    printf 'OXIDEDNS_LARGE_BENCH_BIG_ZONES must be <= OXIDEDNS_LARGE_BENCH_ZONES\n' >&2
    exit 64
fi

if [[ "$tmp_cleanup" == "true" ]]; then
    find /tmp -maxdepth 1 -user "$(id -u)" -type d -name 'oxidedns-large-catalog-bench-*' \
        ! -name "$(basename "$workdir")" -mtime +0 -exec rm -rf {} + 2>/dev/null || true
fi

target_gib=$(((target_rss_mib + 1023) / 1024))
target_names=$((target_gib * names_per_gib))
small_zone_count=$((zone_count - big_zone_count))
small_total_names=$((small_zone_count * small_names))
if [[ -n "${OXIDEDNS_LARGE_BENCH_BIG_NAMES:-}" ]]; then
    big_names="$OXIDEDNS_LARGE_BENCH_BIG_NAMES"
    require_positive_integer OXIDEDNS_LARGE_BENCH_BIG_NAMES "$big_names"
elif ((big_zone_count == 0)); then
    big_names="$small_names"
else
    remaining_names=$((target_names > small_total_names ? target_names - small_total_names : big_zone_count))
    big_names=$(((remaining_names + big_zone_count - 1) / big_zone_count))
fi

mkdir -p "$artifact_dir" "$workdir" "$workdir/zones" "$repo_root/target/benchmark-tools"

now_ns() {
    date +%s%N
}

record_phase() {
    local name="$1"
    local started_ns="$2"
    local finished_ns="$3"
    local duration_ms=$(((finished_ns - started_ns) / 1000000))
    printf '%s\t%s\t%s\t%s\n' "$name" "$started_ns" "$finished_ns" "$duration_ms" >>"$phase_metrics_file"
    printf 'benchmark_phase name=%s duration_ms=%s\n' "$name" "$duration_ms" | tee -a "$artifact_dir/phase-events.log"
}

metric_value() {
    local metric="$1"
    local path="$2"
    awk -v metric="$metric" '$1 == metric { print $2; exit }' "$path"
}

metric_sum() {
    local metric="$1"
    local path="$2"
    awk -v metric="$metric" '$1 ~ "^" metric "(\\{|$)" { sum += $2 } END { print sum + 0 }' "$path"
}

append_resource_sample() {
    local rss=""
    local vsz=""
    local threads=""
    local cpu=""
    local fd_count=""

    if ! read -r rss vsz threads cpu < <(ps -o rss=,vsz=,nlwp=,pcpu= -p "$oxidedns_pid"); then
        return 0
    fi
    fd_count="$({ find "/proc/$oxidedns_pid/fd" -maxdepth 1 -type l -print 2>/dev/null || true; } | wc -l)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$oxidedns_pid" "$rss" "$vsz" "$threads" "$fd_count" "$cpu"
}

phase_metrics_file="$artifact_dir/benchmark-phases.tsv"
printf 'phase\tstart_unix_ns\tend_unix_ns\tduration_ms\n' >"$phase_metrics_file"
benchmark_started_ns="$(now_ns)"
phase_started_ns="$benchmark_started_ns"

cleanup() {
    local status=$?
    if [[ -n "${resource_sampler_pid:-}" ]] && kill -0 "$resource_sampler_pid" 2>/dev/null; then
        kill "$resource_sampler_pid" 2>/dev/null || true
        wait "$resource_sampler_pid" 2>/dev/null || true
    fi
    for pid_var in perf_record_pid perf_stat_pid oxidedns_pid; do
        local pid="${!pid_var:-}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if docker ps -a --format '{{.Names}}' | grep -Fx "$bind_container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- $bind_container logs ----" >&2
            docker logs "$bind_container" >&2 || true
        fi
        docker rm -f "$bind_container" >/dev/null 2>&1 || true
    fi
    if [[ -n "${oxidedns_pid:-}" ]] && ! kill -0 "$oxidedns_pid" 2>/dev/null; then
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if ((status != 0)); then
        for log in "$artifact_dir"/named.log "$artifact_dir"/oxidedns.log "$artifact_dir"/client.log; do
            [[ -f "$log" ]] || continue
            echo "---- ${log##*/} ----" >&2
            tail -160 "$log" >&2
        done
    fi
    if [[ "$retain_zone_files" == "true" ]]; then
        mkdir -p "$artifact_dir/generated-zones"
        cp -a "$workdir/zones"/. "$artifact_dir/generated-zones"/ 2>/dev/null || true
    fi
    if [[ "$keep_workdir" != "true" ]]; then
        rm -rf "$workdir"
    else
        printf 'workdir=%s\n' "$workdir" >"$artifact_dir/workdir.env"
    fi
}
trap cleanup EXIT

read -r bind_port dns_port health_port < <(
    python3 - <<'PY'
import socket

sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

cat >"$artifact_dir/run.env" <<EOF
date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
target_rss_mib=$target_rss_mib
target_gib=$target_gib
zone_count=$zone_count
big_zone_count=$big_zone_count
small_zone_count=$small_zone_count
big_names=$big_names
small_names=$small_names
txt_bytes=$txt_bytes
address_records_per_name=$address_records_per_name
transport=$transport
duration_seconds=$duration
warmup_seconds=$warmup_duration
server_cpus=$server_cpus
client_threads=$client_threads
client_window=$client_window
response_timeout_ms=$response_timeout_ms
pipeline_timing_enabled=$pipeline_timing_enabled
perf_stat_enabled=$perf_stat_enabled
perf_record_enabled=$perf_record_enabled
perf_frequency=$perf_frequency
expected_active_zones=$((zone_count + 1))
bind_port=$bind_port
dns_port=$dns_port
health_port=$health_port
workdir=$workdir
EOF

python3 - "$workdir" "$zone_count" "$big_zone_count" "$big_names" "$small_names" "$txt_bytes" "$address_records_per_name" "$tsig_name" "$tsig_secret" <<'PY'
import pathlib
import sys

workdir = pathlib.Path(sys.argv[1])
zone_count = int(sys.argv[2])
big_zone_count = int(sys.argv[3])
big_names = int(sys.argv[4])
small_names = int(sys.argv[5])
txt_bytes = int(sys.argv[6])
address_records_per_name = int(sys.argv[7])
tsig_name = sys.argv[8]
tsig_secret = sys.argv[9]
zones_dir = workdir / "zones"
catalog = "catalog.perf.test."


def txt_rdata_text(size):
    if size <= 0:
        return ""
    remaining = size
    chunks = []
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    while remaining > 0:
        chunk_len = min(250, remaining)
        chunks.append('"' + (alphabet * ((chunk_len // len(alphabet)) + 1))[:chunk_len] + '"')
        remaining -= chunk_len
    return " ".join(chunks)


txt_payload = txt_rdata_text(txt_bytes)

named = [
    f'key "{tsig_name}" {{',
    "    algorithm hmac-sha256;",
    f'    secret "{tsig_secret}";',
    "};",
    "",
    "options {",
    '    directory "/work";',
    "    listen-on port 5353 { any; };",
    "    listen-on-v6 { none; };",
    "    recursion no;",
    "    dnssec-validation no;",
    "    minimal-responses no;",
    "    notify no;",
    "    request-ixfr no;",
    '    pid-file "/work/named.pid";',
    '    session-keyfile "/work/session.key";',
    "};",
    "",
]


def zone_stanza(name, filename):
    return [
        f'zone "{name.rstrip(".")}" IN {{',
        "    type primary;",
        f'    file "/work/zones/{filename}";',
        "    allow-query { any; };",
        f'    allow-transfer {{ key "{tsig_name}"; }};',
        "    notify no;",
        "};",
        "",
    ]


named.extend(zone_stanza(catalog, "catalog.perf.test.zone"))
for zone_index in range(zone_count):
    zone = f"zone{zone_index:05}.perf.test."
    named.extend(zone_stanza(zone, f"{zone}zone"))

(workdir / "named.conf").write_text("\n".join(named), encoding="utf-8")

with (zones_dir / "catalog.perf.test.zone").open("w", encoding="utf-8") as handle:
    handle.write("$ORIGIN catalog.perf.test.\n$TTL 60\n")
    handle.write("@ IN SOA ns.catalog.perf.test. hostmaster.catalog.perf.test. (2026052601 3600 600 86400 60)\n")
    handle.write("@ IN NS ns.catalog.perf.test.\n")
    handle.write("ns IN A 127.0.0.1\n")
    handle.write('version IN TXT "2"\n')
    for zone_index in range(zone_count):
        handle.write(f"z{zone_index:05}.zones IN PTR zone{zone_index:05}.perf.test.\n")

total_owner_names = 0
total_rrs = 0
for zone_index in range(zone_count):
    zone = f"zone{zone_index:05}.perf.test."
    names = big_names if zone_index < big_zone_count else small_names
    total_owner_names += names
    with (zones_dir / f"{zone}zone").open("w", encoding="utf-8") as handle:
        handle.write(f"$ORIGIN {zone}\n$TTL 300\n")
        handle.write(f"@ IN SOA ns.{zone} hostmaster.{zone} (2026052601 3600 600 86400 300)\n")
        handle.write(f"@ IN NS ns.{zone}\n")
        handle.write("ns IN A 127.0.0.1\n")
        total_rrs += 3
        for name_index in range(names):
            label = f"host{name_index:08}"
            for address_index in range(address_records_per_name):
                address_ordinal = (name_index * address_records_per_name) + address_index
                handle.write(f"{label} IN A 192.0.{(address_ordinal // 256) % 256}.{address_ordinal % 256}\n")
                total_rrs += 1
            if txt_payload:
                handle.write(f"{label} IN TXT {txt_payload}\n")
                total_rrs += 1

summary = [
    "metric\tvalue",
    f"catalog_zone\t{catalog}",
    f"zone_count\t{zone_count}",
    f"big_zone_count\t{big_zone_count}",
    f"big_names_per_zone\t{big_names}",
    f"small_names_per_zone\t{small_names}",
    f"total_owner_names\t{total_owner_names}",
    f"total_member_rrs\t{total_rrs}",
    f"txt_payload_bytes\t{txt_bytes}",
    f"address_records_per_name\t{address_records_per_name}",
]
(workdir / "zone-generation-summary.tsv").write_text("\n".join(summary) + "\n", encoding="utf-8")
PY

cp "$workdir/named.conf" "$artifact_dir/named.conf"
cp "$workdir/zone-generation-summary.tsv" "$artifact_dir/zone-generation-summary.tsv"
phase_finished_ns="$(now_ns)"
record_phase "generate_zone_files" "$phase_started_ns" "$phase_finished_ns"
phase_started_ns="$phase_finished_ns"

cat >"$workdir/oxidedns.toml" <<EOF
[server]
listen_udp = ["127.0.0.1:$dns_port"]
listen_tcp = ["127.0.0.1:$dns_port"]
health = "127.0.0.1:$health_port"
log_level = "warn"
log_format = "json"

[query]
any_response = "minimal"

[cookie]
policy = "disabled"

[rrl]
enabled = false

[metrics]
pipeline_timing_enabled = $pipeline_timing_enabled
zone_shape_enabled = true

[limits]
max_udp_payload = 1232
max_concurrent_transfers = $server_cpus
axfr_timeout_secs = 3600
ixfr_timeout_secs = 3600
max_transfer_ingest_bytes = $((target_rss_mib * 1024 * 1024 * 4))
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600
zsm_initial_retry_max_secs = 3600

[[catalog_zones]]
name = "catalog.perf.test."
class = "IN"
primaries = ["127.0.0.1:$bind_port"]
notify_sources = ["127.0.0.1"]
tsig_key = "$tsig_name"
serve_catalog_zone = false

[[tsig_keys]]
name = "$tsig_name"
algorithm = "hmac-sha256"
secret = "$tsig_secret"
EOF
cp "$workdir/oxidedns.toml" "$artifact_dir/oxidedns.toml"

docker run -d --name "$bind_container" \
    -p "127.0.0.1:$bind_port:5353/tcp" \
    -v "$workdir:/work:rw" \
    "$bind_image" \
    sh -c 'named-checkconf -z /work/named.conf >/work/named-checkconf.out 2>&1 && named -g -c /work/named.conf -n 1' \
    >/dev/null

expected_bind_loaded_zones=$((zone_count + 1))
for _ in {1..240}; do
    if [[ -f "$workdir/named-checkconf.out" ]] &&
        awk -v expected="$expected_bind_loaded_zones" '/^zone .*: loaded serial / { count++ } END { exit(count >= expected ? 0 : 1) }' \
            "$workdir/named-checkconf.out"; then
        break
    fi
    sleep 0.5
done
if ! awk -v expected="$expected_bind_loaded_zones" '/^zone .*: loaded serial / { count++ } END { exit(count >= expected ? 0 : 1) }' \
    "$workdir/named-checkconf.out"; then
    echo "BIND did not load generated benchmark zones" >&2
    exit 1
fi
docker logs "$bind_container" >"$artifact_dir/named.log" 2>&1 || true
cp "$workdir/named-checkconf.out" "$artifact_dir/named-checkconf.out"
phase_finished_ns="$(now_ns)"
record_phase "bind_start_and_zone_check" "$phase_started_ns" "$phase_finished_ns"
phase_started_ns="$phase_finished_ns"

rustc --edition=2024 -O "$repo_root/tools/dns-load-client.rs" -o "$repo_root/target/benchmark-tools/dns-load-client"
(
    cd "$repo_root"
    RUSTFLAGS="${OXIDEDNS_LARGE_BENCH_RUSTFLAGS:--C force-frame-pointers=yes}" \
        cargo build --locked --release -p oxidedns-cli
)
phase_finished_ns="$(now_ns)"
record_phase "build_binaries" "$phase_started_ns" "$phase_finished_ns"
phase_started_ns="$phase_finished_ns"

server_cmd=("$repo_root/target/release/oxidedns" serve --config "$workdir/oxidedns.toml")
server_affinity="not-applied"
if command -v taskset >/dev/null 2>&1; then
    server_cmd=(taskset -c "0-$((server_cpus - 1))" "${server_cmd[@]}")
    server_affinity="0-$((server_cpus - 1))"
fi
printf 'server_command=' >"$artifact_dir/server-command.txt"
printf ' %q' "${server_cmd[@]}" >>"$artifact_dir/server-command.txt"
printf '\nserver_affinity=%s\n' "$server_affinity" >>"$artifact_dir/server-command.txt"
printf 'server_affinity=%s\n' "$server_affinity" >>"$artifact_dir/run.env"

"${server_cmd[@]}" >"$artifact_dir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready_deadline="${OXIDEDNS_LARGE_BENCH_READY_TIMEOUT_SECONDS:-3600}"
ready=0
for _ in $(seq 1 "$ready_deadline"); do
    if curl -fsS "http://127.0.0.1:$health_port/readyz" >"$artifact_dir/readyz-first.json" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if ((ready != 1)); then
    echo "OxideDNS did not become ready for large catalog benchmark" >&2
    exit 1
fi

expected_active_zones=$((zone_count + 1))
active_zones=0
for _ in $(seq 1 "$ready_deadline"); do
    if curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-before.prom" 2>/dev/null; then
        active_zones="$(metric_value oxidedns_zones_active "$artifact_dir/metrics-before.prom")"
        active_zones="${active_zones:-0}"
        if ((active_zones >= expected_active_zones)); then
            break
        fi
    fi
    sleep 1
done
if ((active_zones < expected_active_zones)); then
    printf 'OxideDNS only reached %s active zones; expected %s for loaded catalog benchmark\n' \
        "$active_zones" "$expected_active_zones" >&2
    exit 1
fi
printf 'active_zones_after_load=%s\n' "$active_zones" >>"$artifact_dir/run.env"
phase_finished_ns="$(now_ns)"
record_phase "oxidedns_startup_to_ready" "$phase_started_ns" "$phase_finished_ns"
phase_started_ns="$phase_finished_ns"

curl -fsS "http://127.0.0.1:$health_port/readyz" >"$artifact_dir/readyz-before.json"
cp "/proc/$oxidedns_pid/status" "$artifact_dir/proc-status-before.txt"
if [[ -e "/proc/$oxidedns_pid/smaps_rollup" ]]; then
    cp "/proc/$oxidedns_pid/smaps_rollup" "$artifact_dir/smaps-rollup-before.txt" \
        2>"$artifact_dir/smaps-rollup-before.stderr" || true
fi

rss_kib="$(awk '/VmRSS:/ { print $2; exit }' "/proc/$oxidedns_pid/status")"
rss_mib=$(((rss_kib + 1023) / 1024))
printf 'rss_mib_after_load=%s\n' "$rss_mib" >>"$artifact_dir/run.env"
if ((rss_mib < target_rss_mib)); then
    message="OxideDNS RSS after catalog load was ${rss_mib} MiB, below target ${target_rss_mib} MiB"
    if [[ "$enforce_rss_target" == "true" ]]; then
        printf '%s\n' "$message" >&2
        exit 1
    fi
    printf 'warning=%q\n' "$message" >>"$artifact_dir/run.env"
fi

resource_samples_file="$artifact_dir/resource-samples.tsv"
printf 'timestamp_unix\tpid\trss_kib\tvsz_kib\tthreads\tfd_count\tcpu_percent\n' >"$resource_samples_file"
append_resource_sample >>"$resource_samples_file"
{
    while sleep 1; do
        kill -0 "$oxidedns_pid" 2>/dev/null || break
        append_resource_sample
    done
} >>"$resource_samples_file" &
resource_sampler_pid=$!

if ((warmup_duration > 0)); then
    "$repo_root/target/benchmark-tools/dns-load-client" \
        --transport "$transport" \
        --server 127.0.0.1 \
        --port "$dns_port" \
        --threads "$client_threads" \
        --duration "$warmup_duration" \
        --window "$client_window" \
        --names "$big_names" \
        --zones "$zone_count" \
        --big-zones "$big_zone_count" \
        --big-names "$big_names" \
        --small-names "$small_names" \
        --timeout-ms "$response_timeout_ms" \
        --random | tee "$artifact_dir/warmup-client.log"
fi
curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-after-warmup.prom"
phase_finished_ns="$(now_ns)"
record_phase "warmup_serve" "$phase_started_ns" "$phase_finished_ns"
phase_started_ns="$phase_finished_ns"

start_perf_record() {
    if [[ "$perf_record_enabled" != "true" ]] || ! command -v perf >/dev/null 2>&1; then
        return 0
    fi
    perf record -F "$perf_frequency" -g -p "$oxidedns_pid" -o "$artifact_dir/perf.data" -- sleep "$duration" \
        >"$artifact_dir/perf-record.stdout" 2>"$artifact_dir/perf-record.stderr" &
    # shellcheck disable=SC2034 # consumed later through indirect pid_var lookup.
    perf_record_pid=$!
}

start_perf_stat() {
    if [[ "$perf_stat_enabled" != "true" ]] || ! command -v perf >/dev/null 2>&1; then
        return 0
    fi
    perf stat -x, -o "$artifact_dir/perf-stat.csv" -p "$oxidedns_pid" -- sleep "$duration" \
        >"$artifact_dir/perf-stat.stdout" 2>"$artifact_dir/perf-stat.stderr" &
    # shellcheck disable=SC2034 # consumed later through indirect pid_var lookup.
    perf_stat_pid=$!
}

start_perf_record
start_perf_stat

"$repo_root/target/benchmark-tools/dns-load-client" \
    --transport "$transport" \
    --server 127.0.0.1 \
    --port "$dns_port" \
    --threads "$client_threads" \
    --duration "$duration" \
    --window "$client_window" \
    --names "$big_names" \
    --zones "$zone_count" \
    --big-zones "$big_zone_count" \
    --big-names "$big_names" \
    --small-names "$small_names" \
    --timeout-ms "$response_timeout_ms" \
    --random | tee "$artifact_dir/client.log"
phase_finished_ns="$(now_ns)"
record_phase "measured_serve" "$phase_started_ns" "$phase_finished_ns"
phase_started_ns="$phase_finished_ns"

for pid_var in perf_record_pid perf_stat_pid; do
    pid="${!pid_var:-}"
    if [[ -n "$pid" ]]; then
        wait "$pid" || true
    fi
done

if [[ -f "$artifact_dir/perf.data" ]] && command -v perf >/dev/null 2>&1; then
    perf script -i "$artifact_dir/perf.data" >"$artifact_dir/perf.script" 2>"$artifact_dir/perf-script.stderr" || true
    if command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
        inferno-collapse-perf "$artifact_dir/perf.script" >"$artifact_dir/perf.folded" 2>"$artifact_dir/inferno-collapse.stderr" || true
        if [[ -s "$artifact_dir/perf.folded" ]]; then
            inferno-flamegraph "$artifact_dir/perf.folded" >"$artifact_dir/flamegraph.svg" 2>"$artifact_dir/inferno-flamegraph.stderr" || true
        fi
    fi
fi

curl -fsS "http://127.0.0.1:$health_port/metrics" >"$artifact_dir/metrics-after.prom"
awk '$1 ~ /^oxidedns_zone_shape_/ { print }' "$artifact_dir/metrics-after.prom" \
    >"$artifact_dir/zone-shape.prom"
cp "/proc/$oxidedns_pid/status" "$artifact_dir/proc-status-after.txt"
if [[ -e "/proc/$oxidedns_pid/smaps_rollup" ]]; then
    cp "/proc/$oxidedns_pid/smaps_rollup" "$artifact_dir/smaps-rollup-after.txt" \
        2>"$artifact_dir/smaps-rollup-after.stderr" || true
fi
docker logs "$bind_container" >"$artifact_dir/named.log" 2>&1 || true
phase_finished_ns="$(now_ns)"
record_phase "final_capture" "$phase_started_ns" "$phase_finished_ns"

summary="$(tail -1 "$artifact_dir/client.log")"
summary_value() {
    local key="$1"
    tr ' ' '\n' <<<"$summary" | awk -F= -v key="$key" '$1 == key { print $2; exit }'
}

responses_per_second="$(summary_value responses_per_second)"
sent_per_second="$(summary_value sent_per_second)"
latency_us_p50="$(summary_value latency_us_p50)"
latency_us_p99="$(summary_value latency_us_p99)"
latency_us_p999="$(summary_value latency_us_p999)"
dropped="$(summary_value dropped)"
errors="$(summary_value errors)"
rss_after_kib="$(awk '/VmRSS:/ { print $2; exit }' "/proc/$oxidedns_pid/status")"
rss_after_mib=$(((rss_after_kib + 1023) / 1024))
zone_shape_rrsets="$(metric_sum oxidedns_zone_shape_rrsets "$artifact_dir/metrics-after.prom")"
zone_shape_rdata_records="$(metric_sum oxidedns_zone_shape_rdata_records "$artifact_dir/metrics-after.prom")"
zone_shape_single_rdata_rrsets="$(metric_sum oxidedns_zone_shape_single_rdata_rrsets "$artifact_dir/metrics-after.prom")"
zone_shape_multi_rdata_rrsets="$(metric_sum oxidedns_zone_shape_multi_rdata_rrsets "$artifact_dir/metrics-after.prom")"
zone_shape_spilled_rdata_rrsets="$(metric_sum oxidedns_zone_shape_spilled_rdata_rrsets "$artifact_dir/metrics-after.prom")"
zone_shape_rdata_payload_bytes="$(metric_sum oxidedns_zone_shape_rdata_payload_bytes "$artifact_dir/metrics-after.prom")"
zone_shape_name_key_logical_bytes="$(metric_sum oxidedns_zone_shape_name_key_logical_bytes "$artifact_dir/metrics-after.prom")"
zone_shape_name_key_unique_bytes="$(metric_sum oxidedns_zone_shape_name_key_unique_bytes "$artifact_dir/metrics-after.prom")"
zone_shape_name_key_deduplicated_bytes="$(metric_sum oxidedns_zone_shape_name_key_deduplicated_bytes "$artifact_dir/metrics-after.prom")"

cat >"$artifact_dir/benchmark-results.tsv" <<EOF
metric	value	unit
transport	$transport	protocol
zone_count	$zone_count	zones
big_zone_count	$big_zone_count	zones
big_names_per_zone	$big_names	names
small_names_per_zone	$small_names	names
txt_payload_bytes	$txt_bytes	bytes
address_records_per_name	$address_records_per_name	records
target_rss_mib	$target_rss_mib	MiB
rss_mib_after_load	$rss_mib	MiB
rss_mib_after_run	$rss_after_mib	MiB
server_cpus	$server_cpus	cpus
server_affinity	$server_affinity	cpus
client_threads	$client_threads	threads
client_window	$client_window	queries_per_thread
duration_seconds	$duration	seconds
warmup_seconds	$warmup_duration	seconds
sent_per_second	$sent_per_second	qps
responses_per_second	$responses_per_second	qps
latency_us_p50	$latency_us_p50	microseconds
latency_us_p99	$latency_us_p99	microseconds
latency_us_p999	$latency_us_p999	microseconds
dropped	$dropped	responses
errors	$errors	responses
pipeline_timing_enabled	$pipeline_timing_enabled	boolean
perf_stat_enabled	$perf_stat_enabled	boolean
perf_record_enabled	$perf_record_enabled	boolean
zone_shape_rrsets	$zone_shape_rrsets	rrsets
zone_shape_rdata_records	$zone_shape_rdata_records	records
zone_shape_single_rdata_rrsets	$zone_shape_single_rdata_rrsets	rrsets
zone_shape_multi_rdata_rrsets	$zone_shape_multi_rdata_rrsets	rrsets
zone_shape_spilled_rdata_rrsets	$zone_shape_spilled_rdata_rrsets	rrsets
zone_shape_rdata_payload_bytes	$zone_shape_rdata_payload_bytes	bytes
zone_shape_name_key_logical_bytes	$zone_shape_name_key_logical_bytes	bytes
zone_shape_name_key_unique_bytes	$zone_shape_name_key_unique_bytes	bytes
zone_shape_name_key_deduplicated_bytes	$zone_shape_name_key_deduplicated_bytes	bytes
EOF

awk -F'\t' 'NR > 1 { printf "phase_%s_duration_ms\t%s\tmilliseconds\n", $1, $4 }' \
    "$phase_metrics_file" >>"$artifact_dir/benchmark-results.tsv"

cat >"$artifact_dir/README.md" <<EOF
# OxideDNS Large Catalog Benchmark

This artifact was generated by \`scripts/benchmark-large-catalog-zones.sh\`.

The harness generates an RFC 9432 catalog zone and \`$zone_count\` catalog
member zones, serves them from BIND with mandatory TSIG-authenticated AXFR,
starts OxideDNS on CPU affinity \`$server_affinity\`, waits until every catalog
member is ACTIVE, then drives randomized \`$transport\` A queries across the
large/small zone mix.

Phase timings are recorded in \`benchmark-phases.tsv\` and folded into
\`benchmark-results.tsv\` as \`phase_*_duration_ms\` rows. The important split is
\`phase_oxidedns_startup_to_ready_duration_ms\` for catalog transfer/load time
and \`phase_measured_serve_duration_ms\` plus \`client.log\` for query-serving
throughput and latency.

The benchmark enables pipeline timing metrics by default and can collect Linux
\`perf stat\` plus optional \`perf record\` data. If \`inferno-collapse-perf\`
and \`inferno-flamegraph\` are installed, a \`flamegraph.svg\` is produced from
the recorded samples.

Zone-shape metrics are retained in \`zone-shape.prom\` and summarized into
\`benchmark-results.tsv\`. They expose RRset/RDATA cardinality, SmallVec spill
counts, payload bytes, and canonical-name key interning savings so memory-layout
tuning can be tied to the loaded catalog shape.

This is a local optimization harness. It is intentionally not part of
\`scripts/check.sh\` or the Engineering MVP evidence path.
EOF

printf 'large_catalog_benchmark_dir=%s\n' "$artifact_dir"
printf 'capability_summary transport=%s zones=%s big_names=%s small_names=%s rss_mib_after_load=%s responses_per_second=%s latency_us_p50=%s latency_us_p99=%s latency_us_p999=%s dropped=%s errors=%s\n' \
    "$transport" "$zone_count" "$big_names" "$small_names" "$rss_mib" "$responses_per_second" "$latency_us_p50" "$latency_us_p99" "$latency_us_p999" "$dropped" "$errors"
