#!/usr/bin/env bash
set -euo pipefail

for tool in cargo curl dig git journalctl python3 sha256sum systemctl systemd-run; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 69
    fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_dir="${BORON_LOAD_ARTIFACT_DIR:-$repo_root/target/evidence/boron-gen-bounded-load-$timestamp}"
workdir="$(mktemp -d -t "boron-gen-bounded-load-$timestamp-XXXXXX")"
unit_suffix="${timestamp,,}-$$"
generator_unit="boron-gen-load-$unit_suffix.service"
server_unit="borondns-load-$unit_suffix.service"

profile="${BORON_LOAD_PROFILE:-registry-nsec3}"
zones="${BORON_LOAD_ZONES:-1}"
names_per_zone="${BORON_LOAD_NAMES_PER_ZONE:-10000}"
nsec3_records_per_zone="${BORON_LOAD_NSEC3_RECORDS_PER_ZONE:-$names_per_zone}"
records_per_name="${BORON_LOAD_RECORDS_PER_NAME:-4}"
origin="${BORON_LOAD_ORIGIN:-load.borongen.}"
catalog_origin="${BORON_LOAD_CATALOG_ORIGIN:-catalog.borongen.}"
generator_listen="${BORON_LOAD_GENERATOR_LISTEN:-127.0.0.1:15353}"
dns_listen="${BORON_LOAD_DNS_LISTEN:-127.0.0.1:15300}"
health_listen="${BORON_LOAD_HEALTH_LISTEN:-127.0.0.1:18081}"
message_bytes="${BORON_LOAD_MESSAGE_BYTES:-60000}"
transfer_bytes="${BORON_LOAD_MAX_TRANSFER_BYTES:-25769803776}"
transfer_messages="${BORON_LOAD_MAX_TRANSFER_MESSAGES:-1000000}"
ready_timeout="${BORON_LOAD_READY_TIMEOUT_SECONDS:-7200}"
hold_seconds="${BORON_LOAD_HOLD_SECONDS:-60}"
query_packets="${BORON_LOAD_QUERY_PACKETS:-10000}"
query_target_qps="${BORON_LOAD_QUERY_TARGET_QPS:-20000}"
expected_outcome="${BORON_LOAD_EXPECT_OUTCOME:-ready}"
server_memory_high="${BORON_LOAD_MEMORY_HIGH:-30G}"
server_memory_max="${BORON_LOAD_MEMORY_MAX:-32G}"
generator_memory_high="${BORON_GEN_MEMORY_HIGH:-768M}"
generator_memory_max="${BORON_GEN_MEMORY_MAX:-1G}"
tsig_name="boron-gen-load-key."
tsig_secret="Ym9yb24tZ2VuLWJvdW5kZWQtbG9hZC10ZXN0LWtleQ=="

mkdir -p "$artifact_dir"
chmod 700 "$workdir" "$artifact_dir"

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer, got %q\n' "$name" "$value" >&2
        exit 64
    fi
}

for pair in \
    "BORON_LOAD_ZONES:$zones" \
    "BORON_LOAD_NAMES_PER_ZONE:$names_per_zone" \
    "BORON_LOAD_NSEC3_RECORDS_PER_ZONE:$nsec3_records_per_zone" \
    "BORON_LOAD_RECORDS_PER_NAME:$records_per_name" \
    "BORON_LOAD_MESSAGE_BYTES:$message_bytes" \
    "BORON_LOAD_MAX_TRANSFER_BYTES:$transfer_bytes" \
    "BORON_LOAD_MAX_TRANSFER_MESSAGES:$transfer_messages" \
    "BORON_LOAD_READY_TIMEOUT_SECONDS:$ready_timeout" \
    "BORON_LOAD_HOLD_SECONDS:$hold_seconds" \
    "BORON_LOAD_QUERY_PACKETS:$query_packets"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done
if ! [[ "$query_target_qps" =~ ^[0-9]+$ ]]; then
    printf 'BORON_LOAD_QUERY_TARGET_QPS must be a non-negative integer, got %q\n' \
        "$query_target_qps" >&2
    exit 64
fi

case "$profile" in
registry-nsec3 | mixed | large-rrset) ;;
*)
    printf 'BORON_LOAD_PROFILE must be registry-nsec3, mixed, or large-rrset\n' >&2
    exit 64
    ;;
esac

case "$expected_outcome" in
ready | contained-oom) ;;
*)
    printf 'BORON_LOAD_EXPECT_OUTCOME must be ready or contained-oom\n' >&2
    exit 64
    ;;
esac

generator_host="${generator_listen%:*}"
generator_port="${generator_listen##*:}"
dns_host="${dns_listen%:*}"
dns_port="${dns_listen##*:}"
health_host="${health_listen%:*}"
health_port="${health_listen##*:}"
for pair in \
    "generator port:$generator_port" \
    "DNS port:$dns_port" \
    "health port:$health_port"; do
    require_positive_integer "${pair%%:*}" "${pair#*:}"
done

resource_sampler_pid=""
cleanup() {
    local status=$?
    if [[ -n "$resource_sampler_pid" ]] && kill -0 "$resource_sampler_pid" 2>/dev/null; then
        kill "$resource_sampler_pid" 2>/dev/null || true
        wait "$resource_sampler_pid" 2>/dev/null || true
    fi
    for unit in "$server_unit" "$generator_unit"; do
        systemctl --user show "$unit" >"$artifact_dir/${unit%.service}-unit-final.txt" 2>&1 || true
        journalctl --user-unit "$unit" --no-pager >"$artifact_dir/${unit%.service}.log" 2>&1 || true
        cgroup_path="$(systemctl --user show "$unit" -p ControlGroup --value 2>/dev/null || true)"
        if [[ -n "$cgroup_path" && -r "/sys/fs/cgroup$cgroup_path/memory.events" ]]; then
            cp "/sys/fs/cgroup$cgroup_path/memory.events" \
                "$artifact_dir/${unit%.service}-memory.events" || true
            cp "/sys/fs/cgroup$cgroup_path/memory.pressure" \
                "$artifact_dir/${unit%.service}-memory.pressure" || true
        fi
        systemctl --user stop "$unit" >/dev/null 2>&1 || true
        systemctl --user reset-failed "$unit" >/dev/null 2>&1 || true
    done
    printf '%s\n' "$status" >"$artifact_dir/exit-status"
    if ((status == 0)); then
        rm -rf -- "$workdir"
    else
        printf 'bounded load failed; retained workdir: %s\n' "$workdir" >&2
        printf '%s\n' "$workdir" >"$artifact_dir/retained-workdir"
    fi
}
trap cleanup EXIT INT TERM

python3 - \
    "$generator_host" "$generator_port" \
    "$dns_host" "$dns_port" \
    "$health_host" "$health_port" <<'PY'
import socket
import sys

gen_host, gen_port, dns_host, dns_port, health_host, health_port = sys.argv[1:]
checks = [
    ("generator TCP", socket.SOCK_STREAM, gen_host, int(gen_port)),
    ("generator UDP", socket.SOCK_DGRAM, gen_host, int(gen_port)),
    ("BoronDNS TCP", socket.SOCK_STREAM, dns_host, int(dns_port)),
    ("BoronDNS UDP", socket.SOCK_DGRAM, dns_host, int(dns_port)),
    ("health TCP", socket.SOCK_STREAM, health_host, int(health_port)),
]
for label, kind, host, port in checks:
    sock = socket.socket(socket.AF_INET, kind)
    try:
        if kind == socket.SOCK_STREAM:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError as error:
        raise SystemExit(f"{label} address {host}:{port} is unavailable: {error}")
    finally:
        sock.close()
PY

if [[ "$(stat -fc %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
    echo "cgroup v2 is required" >&2
    exit 69
fi
if ! systemctl is-active --quiet systemd-oomd.service; then
    echo "system systemd-oomd.service must be active" >&2
    exit 69
fi
if ! systemd-run --user --scope --quiet \
    -p MemoryHigh=24M \
    -p MemoryMax=32M \
    -p MemorySwapMax=0 \
    -p ManagedOOMMemoryPressure=kill \
    -p ManagedOOMMemoryPressureLimit=80% \
    true; then
    echo "the user manager cannot create a memory-bounded cgroup" >&2
    exit 69
fi

cargo build --locked --release -p boron-gen -p boron-gun -p borondns-cli
generator_binary="$repo_root/target/release/boron-gen"
load_binary="$repo_root/target/release/boron-gun"
server_binary="$repo_root/target/release/borondns"
git -C "$repo_root" rev-parse HEAD >"$artifact_dir/source-commit.txt"
git -C "$repo_root" status --short >"$artifact_dir/source-status.txt"
git -C "$repo_root" diff --binary HEAD >"$artifact_dir/source-diff.patch"
while IFS= read -r -d '' source_path; do
    sha256sum "$repo_root/$source_path"
done < <(
    git -C "$repo_root" ls-files -z --modified --others --exclude-standard
) >"$artifact_dir/source-files.sha256"
sha256sum "$generator_binary" "$load_binary" "$server_binary" >"$artifact_dir/binaries.sha256"

"$generator_binary" manifest \
    --profile "$profile" \
    --origin "$origin" \
    --catalog-origin "$catalog_origin" \
    --zones "$zones" \
    --names-per-zone "$names_per_zone" \
    --records-per-name "$records_per_name" \
    --nsec3-records-per-zone "$nsec3_records_per_zone" \
    >"$artifact_dir/scenario-manifest.json"

cat >"$workdir/borondns.toml" <<EOF
[server]
log_level = "info"
log_format = "json"

[interfaces]
dns = [{ address = "$dns_host:$dns_port", name = "bounded-load" }]
mgmt = ["$health_host:$health_port"]
transfer = ["127.0.0.1:0"]

[health]
bind_address = "$health_host"
bind_port = $health_port
metrics_rate_limit_per_minute = 10000

[transfer]
require_tsig = true

[limits]
axfr_timeout_secs = 31536000
ixfr_timeout_secs = 31536000
tcp_connect_timeout_secs = 30
max_concurrent_transfers = 1
max_transfer_ingest_bytes = $transfer_bytes
max_transfer_ingest_messages = $transfer_messages
zsm_loading_warning_threshold_secs = 31536000

[rrl]
# The bounded query probe runs from loopback and measures the loaded-zone
# lookup path, not response-rate limiting. Keep RRL enabled for every other
# source while exempting only the local harness client.
allowlist = ["127.0.0.0/8"]

[tsig]
fudge_seconds = 300

[[tsig_keys]]
name = "$tsig_name"
algorithm = "hmac-sha256"
secret = "$tsig_secret"

[[catalog_zones]]
name = "$catalog_origin"
primaries = ["$generator_host:$generator_port"]
notify_sources = ["$generator_host"]
tsig_key = "$tsig_name"
max_member_zones = $zones
EOF
chmod 600 "$workdir/borondns.toml"
"$server_binary" --validate-config "$workdir/borondns.toml" \
    >"$artifact_dir/config-validation.txt"

systemd-run --user \
    --unit "$generator_unit" \
    --service-type exec \
    -p "MemoryHigh=$generator_memory_high" \
    -p "MemoryMax=$generator_memory_max" \
    -p MemorySwapMax=0 \
    -p OOMPolicy=stop \
    -p ManagedOOMMemoryPressure=kill \
    -p ManagedOOMMemoryPressureLimit=80% \
    -p Restart=no \
    --setenv "BORON_GEN_TSIG_SECRET=$tsig_secret" \
    "$generator_binary" serve \
    --listen "$generator_listen" \
    --message-bytes "$message_bytes" \
    --max-connections 2 \
    --profile "$profile" \
    --origin "$origin" \
    --catalog-origin "$catalog_origin" \
    --zones "$zones" \
    --names-per-zone "$names_per_zone" \
    --records-per-name "$records_per_name" \
    --nsec3-records-per-zone "$nsec3_records_per_zone" \
    --tsig-name "$tsig_name" \
    --json-logs

for _ in {1..100}; do
    if systemctl --user is-active --quiet "$generator_unit"; then
        break
    fi
    sleep 0.1
done
systemctl --user is-active --quiet "$generator_unit"

systemd-run --user \
    --unit "$server_unit" \
    --service-type exec \
    -p "MemoryHigh=$server_memory_high" \
    -p "MemoryMax=$server_memory_max" \
    -p MemorySwapMax=0 \
    -p OOMPolicy=stop \
    -p ManagedOOMMemoryPressure=kill \
    -p ManagedOOMMemoryPressureLimit=80% \
    -p Restart=no \
    -p LimitNOFILE=1048576 \
    "$server_binary" --config "$workdir/borondns.toml" serve

printf 'unix_seconds\tmemory_current\tmemory_peak\tmemory_high\tmemory_max\tn_restarts\tactive_state\tsub_state\n' \
    >"$artifact_dir/resource-samples.tsv"
(
    while true; do
        values="$(systemctl --user show "$server_unit" \
            -p MemoryCurrent \
            -p MemoryPeak \
            -p MemoryHigh \
            -p MemoryMax \
            -p NRestarts \
            -p ActiveState \
            -p SubState 2>/dev/null || true)"
        value_of() {
            local field="$1"
            awk -F= -v field="$field" '$1 == field { print $2 }' <<<"$values"
        }
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(date +%s)" \
            "$(value_of MemoryCurrent)" \
            "$(value_of MemoryPeak)" \
            "$(value_of MemoryHigh)" \
            "$(value_of MemoryMax)" \
            "$(value_of NRestarts)" \
            "$(value_of ActiveState)" \
            "$(value_of SubState)" \
            >>"$artifact_dir/resource-samples.tsv"
        sleep 5
    done
) &
resource_sampler_pid=$!

deadline=$((SECONDS + ready_timeout))
while ((SECONDS < deadline)); do
    if ! systemctl --user is-active --quiet "$server_unit"; then
        if [[ "$expected_outcome" == "contained-oom" ]]; then
            server_result="$(systemctl --user show "$server_unit" -p Result --value)"
            server_status="$(systemctl --user show "$server_unit" -p ExecMainStatus --value)"
            if [[ "$server_result" != "oom-kill" || "$server_status" != "9" ]]; then
                printf 'BoronDNS stopped, but not through the expected contained OOM: result=%s status=%s\n' \
                    "$server_result" "$server_status" >&2
                exit 1
            fi
            if ! systemctl --user is-active --quiet "$generator_unit"; then
                echo "BoronGen did not survive the contained BoronDNS OOM" >&2
                exit 1
            fi
            python3 - \
                "$artifact_dir/scenario-manifest.json" \
                "$artifact_dir/run-summary.json" \
                "$server_memory_high" \
                "$server_memory_max" \
                "$server_result" \
                "$server_status" \
                "$(systemctl --user show "$server_unit" -p MemoryPeak --value)" \
                "$(systemctl --user show "$generator_unit" -p MemoryPeak --value)" \
                "$SECONDS" <<'PY'
import json
import sys

(
    manifest_path,
    output_path,
    memory_high,
    memory_max,
    server_result,
    server_status,
    server_memory_peak,
    generator_memory_peak,
    elapsed_seconds,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)
summary = {
    "status": "contained_oom_as_expected",
    "scenario": manifest,
    "server_result": server_result,
    "server_exit_status": int(server_status),
    "generator_survived": True,
    "observed": {
        "server_memory_peak_bytes": int(server_memory_peak),
        "generator_memory_peak_bytes": int(generator_memory_peak),
        "elapsed_seconds": int(elapsed_seconds),
    },
    "containment": {
        "cgroup_version": 2,
        "memory_high": memory_high,
        "memory_max": memory_max,
        "memory_swap_max": 0,
        "systemd_oomd_required": True,
    },
}
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
PY
            printf 'contained BoronDNS OOM completed as expected; evidence: %s\n' "$artifact_dir"
            exit 0
        fi
        echo "BoronDNS bounded unit stopped before readiness" >&2
        exit 1
    fi
    if curl --fail --silent --show-error \
        "http://$health_host:$health_port/readyz" \
        >"$artifact_dir/readyz.txt" 2>"$artifact_dir/readyz-errors.log"; then
        if [[ "$expected_outcome" != "ready" ]]; then
            printf 'BoronDNS became ready instead of producing expected outcome %s\n' \
                "$expected_outcome" >&2
            exit 1
        fi
        break
    fi
    sleep 2
done
if ((SECONDS >= deadline)); then
    echo "timed out waiting for BoronDNS readiness" >&2
    exit 1
fi

curl --fail --silent --show-error \
    "http://$health_host:$health_port/metrics" \
    >"$artifact_dir/metrics-at-ready.prom"

if [[ "$zones" == "1" ]]; then
    first_member_origin="$origin"
else
    first_member_origin="z0000000000000000.$origin"
fi
negative_name="boron-gen-negative.$first_member_origin"
dig "@$dns_host" \
    -p "$dns_port" \
    "$negative_name" \
    A \
    +tcp \
    +dnssec \
    +noall \
    +comments \
    +authority \
    >"$artifact_dir/dnssec-negative-query.txt"
if ! grep -q 'status: NXDOMAIN' "$artifact_dir/dnssec-negative-query.txt"; then
    echo "published member zone did not return NXDOMAIN for the negative lookup probe" >&2
    exit 1
fi
if [[ "$profile" == "registry-nsec3" ]] &&
    ! grep -q '[[:space:]]NSEC3[[:space:]]' "$artifact_dir/dnssec-negative-query.txt"; then
    echo "registry-nsec3 member did not exercise the NSEC3 denial lookup path" >&2
    exit 1
fi

query_payload_hex="$(
    python3 - "$negative_name" <<'PY'
import struct
import sys

name = sys.argv[1]
labels = name.rstrip(".").split(".")
qname = b"".join(bytes([len(label.encode("ascii"))]) + label.encode("ascii") for label in labels)
qname += b"\x00"
header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 1)
question = qname + struct.pack("!HH", 1, 1)
opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
print((header + question + opt).hex())
PY
)"
"$load_binary" \
    --target "$dns_host:$dns_port" \
    --query-payload-hex "$query_payload_hex" \
    --max-packets "$query_packets" \
    --target-qps "$query_target_qps" \
    --recv-mode process \
    --log-format json \
    --flush-interval-ms 0 \
    --response-timeout-ms 2000 \
    >"$artifact_dir/query-load-summary.json"
python3 - "$artifact_dir/query-load-summary.json" "$query_packets" <<'PY'
import json
import sys

path, expected_text = sys.argv[1:]
expected = int(expected_text)
with open(path, encoding="utf-8") as source:
    summary = json.load(source)
if summary.get("record_type") != "summary":
    raise SystemExit("BoronGun did not emit a summary record")
if summary.get("tx_packets_total") != expected:
    raise SystemExit(
        f"BoronGun sent {summary.get('tx_packets_total')} packets, expected {expected}"
    )
minimum_responses = (expected * 99 + 99) // 100
if summary.get("rx_dns_responses_total", 0) < minimum_responses:
    raise SystemExit(
        "BoronGun DNS response count fell below the 99% local-load threshold"
    )
if summary.get("nxdomain_total", 0) < minimum_responses:
    raise SystemExit("BoronGun NXDOMAIN count fell below the 99% local-load threshold")
if summary.get("errors_total") != 0:
    raise SystemExit(f"BoronGun reported {summary.get('errors_total')} errors")
PY

sleep "$hold_seconds"

curl --fail --silent --show-error \
    "http://$health_host:$health_port/metrics" \
    >"$artifact_dir/metrics-after-hold.prom"

python3 - \
    "$artifact_dir/metrics-after-hold.prom" \
    "$profile" \
    "$query_packets" <<'PY'
import sys

metrics_path, profile, expected_text = sys.argv[1:]
expected = int(expected_text)
metrics = {}
with open(metrics_path, encoding="utf-8") as source:
    for raw_line in source:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, value = line.rsplit(None, 1)
        metrics[name] = float(value)

if metrics.get("borondns_rrl_responses_dropped_total", 0) != 0:
    raise SystemExit("loopback lookup probe unexpectedly exercised RRL drops")
if profile == "registry-nsec3":
    metric = (
        'borondns_secondary_query_duration_seconds_count'
        '{query_category="dnssec_augmented"}'
    )
    if metrics.get(metric, 0) < expected:
        raise SystemExit(
            "DNSSEC-augmented query metric did not account for the bounded load probe"
        )
PY

if [[ "$profile" == "registry-nsec3" ]]; then
    journalctl --user-unit "$server_unit" --no-pager \
        >"$artifact_dir/publication-journal-at-ready.log"
    if ! grep -E \
        '"nsec3_indexed_groups":1.*"nsec3_fallback_groups":0' \
        "$artifact_dir/publication-journal-at-ready.log" \
        >"$artifact_dir/nsec3-index-validation.txt"; then
        echo "published member did not compile the indexed NSEC3 lookup path" >&2
        exit 1
    fi
fi

systemctl --user is-active --quiet "$server_unit"
systemctl --user is-active --quiet "$generator_unit"

python3 - \
    "$artifact_dir/scenario-manifest.json" \
    "$artifact_dir/run-summary.json" \
    "$server_memory_high" \
    "$server_memory_max" \
    "$(systemctl --user show "$server_unit" -p MemoryPeak --value)" \
    "$(systemctl --user show "$generator_unit" -p MemoryPeak --value)" \
    "$SECONDS" <<'PY'
import json
import sys

(
    manifest_path,
    output_path,
    memory_high,
    memory_max,
    server_memory_peak,
    generator_memory_peak,
    elapsed_seconds,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)
with open(
    output_path.rsplit("/", 1)[0] + "/query-load-summary.json",
    encoding="utf-8",
) as source:
    query_probe = json.load(source)
summary = {
    "status": "ready_and_held",
    "scenario": manifest,
    "observed": {
        "server_memory_peak_bytes": int(server_memory_peak),
        "generator_memory_peak_bytes": int(generator_memory_peak),
        "elapsed_seconds": int(elapsed_seconds),
        "query_probe": query_probe,
    },
    "containment": {
        "cgroup_version": 2,
        "memory_high": memory_high,
        "memory_max": memory_max,
        "memory_swap_max": 0,
        "systemd_oomd_required": True,
    },
}
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(summary, output, indent=2, sort_keys=True)
    output.write("\n")
PY

printf 'bounded BoronGen load completed; evidence: %s\n' "$artifact_dir"
