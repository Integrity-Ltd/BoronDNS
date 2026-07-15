#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/prepare-knot-comparison-benchmark.sh querydb --zone ZONEFILE --out DIR [--limit N] [--shuffle]
  scripts/prepare-knot-comparison-benchmark.sh trace --querydb QUERYDB --out DIR
  scripts/prepare-knot-comparison-benchmark.sh stage-knot-primary --zone ZONEFILE --out DIR [--zone-name NAME] [--knot-address IP] [--knot-port PORT] [--borondns-address IP] [--borondns-port PORT] [--health-address IP] [--health-port PORT] [--workers N] [--udp-runtime tokio|dedicated] [--udp-batch-size N] [--limit N] [--shuffle]
  scripts/prepare-knot-comparison-benchmark.sh normalize-borondns --artifact DIR --out TSV
  scripts/prepare-knot-comparison-benchmark.sh normalize-kxdpgun --log LOG --duration SEC --out TSV

The querydb, trace, and stage-knot-primary modes prepare one query mix for both
kxdpgun and the BoronDNS dns-load-client. The normalize modes write comparable
throughput rows.
EOF
}

die() {
    printf '%s\n' "$*" >&2
    exit 64
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mode="${1:-}"
shift || true

case "$mode" in
querydb | trace | stage-knot-primary | normalize-borondns | normalize-kxdpgun) ;;
*)
    usage
    exit 64
    ;;
esac

zone_file=""
zone_name=""
querydb=""
artifact=""
log_file=""
out=""
limit="0"
duration=""
shuffle="false"
knot_address="127.0.0.1"
knot_port="5301"
borondns_address="127.0.0.1"
borondns_port="5300"
health_address="127.0.0.1"
health_port="8080"
workers="1"
udp_runtime="dedicated"
udp_batch_size="32"
while (($# > 0)); do
    case "$1" in
    --zone)
        zone_file="${2:-}"
        shift 2
        ;;
    --zone-name)
        zone_name="${2:-}"
        shift 2
        ;;
    --querydb)
        querydb="${2:-}"
        shift 2
        ;;
    --artifact)
        artifact="${2:-}"
        shift 2
        ;;
    --log)
        log_file="${2:-}"
        shift 2
        ;;
    --duration)
        duration="${2:-}"
        shift 2
        ;;
    --out)
        out="${2:-}"
        shift 2
        ;;
    --limit)
        limit="${2:-}"
        shift 2
        ;;
    --shuffle)
        shuffle="true"
        shift
        ;;
    --knot-address)
        knot_address="${2:-}"
        shift 2
        ;;
    --knot-port)
        knot_port="${2:-}"
        shift 2
        ;;
    --borondns-address)
        borondns_address="${2:-}"
        shift 2
        ;;
    --borondns-port)
        borondns_port="${2:-}"
        shift 2
        ;;
    --health-address)
        health_address="${2:-}"
        shift 2
        ;;
    --health-port)
        health_port="${2:-}"
        shift 2
        ;;
    --workers)
        workers="${2:-}"
        shift 2
        ;;
    --udp-runtime)
        udp_runtime="${2:-}"
        shift 2
        ;;
    --udp-batch-size)
        udp_batch_size="${2:-}"
        shift 2
        ;;
    *)
        die "unsupported argument: $1"
        ;;
    esac
done

case "$mode" in
querydb)
    [[ -f "$zone_file" ]] || die "--zone must name a zone file"
    [[ -n "$out" ]] || die "--out is required"
    [[ "$limit" =~ ^[0-9]+$ ]] || die "--limit must be a non-negative integer"
    mkdir -p "$out"
    python3 - "$zone_file" "$out/querydb" "$limit" "$shuffle" <<'PY'
import random
import sys
from pathlib import Path

zone = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
limit = int(sys.argv[3])
shuffle = sys.argv[4] == "true"
allowed = {"NS", "DS", "A", "AAAA", "PTR", "MX", "SOA", "DNSKEY"}
rows = set()
origin = ""
last_owner = ""
paren_depth = 0

def fqdn(name: str) -> str:
    if name == "@":
        return origin or "."
    if name.endswith("."):
        return name
    if origin:
        return f"{name}.{origin}"
    return f"{name}."

for raw in zone.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = raw.split(";", 1)[0].strip()
    if paren_depth > 0:
        paren_depth += line.count("(") - line.count(")")
        paren_depth = max(paren_depth, 0)
        continue
    if not line:
        continue
    parts = line.split()
    if len(parts) >= 2 and parts[0].upper() == "$ORIGIN":
        origin = parts[1] if parts[1].endswith(".") else parts[1] + "."
        continue
    if line.startswith("$"):
        continue
    owner = parts[0]
    if owner.upper() in {"IN"} or owner.isdigit():
        owner = last_owner
    else:
        last_owner = owner
    rrtype = ""
    for token in parts:
        upper = token.upper()
        if upper in allowed:
            rrtype = upper
            break
    if not owner or rrtype not in allowed:
        paren_depth += line.count("(") - line.count(")")
        paren_depth = max(paren_depth, 0)
        continue
    rows.add(f"{fqdn(owner)} {rrtype}")
    paren_depth += line.count("(") - line.count(")")
    paren_depth = max(paren_depth, 0)

rows = list(rows)
if shuffle:
    random.SystemRandom().shuffle(rows)
else:
    rows.sort()
if limit:
    rows = rows[:limit]
if not rows:
    raise SystemExit("no comparable query rows generated")
out.write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
    cat >"$out/README.md" <<EOF
# Knot Comparison Query Mix

Generated from \`$zone_file\`.

Files:
- \`querydb\`: kxdpgun text input, \`qname qtype [flags]\`.

For DNSSEC DO queries, append \` D\` to selected rows before running both
kxdpgun and BoronDNS trace conversion.
EOF
    printf 'querydb=%s\n' "$out/querydb"
    ;;
trace)
    [[ -f "$querydb" ]] || die "--querydb must name a kxdpgun query file"
    [[ -n "$out" ]] || die "--out is required"
    mkdir -p "$out"
    python3 - "$querydb" "$out/query-trace.tsv" <<'PY'
import sys
from pathlib import Path

querydb = Path(sys.argv[1])
out = Path(sys.argv[2])
rows = ["# qname qtype qclass edns label"]
for line_no, raw in enumerate(querydb.read_text(encoding="utf-8").splitlines(), start=1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split()
    if len(parts) < 2:
        raise SystemExit(f"{querydb}:{line_no}: expected qname qtype [flags]")
    edns = "none"
    if len(parts) >= 3:
        flag = parts[2].upper()
        if flag == "E":
            edns = "edns"
        elif flag == "D":
            edns = "do"
        else:
            raise SystemExit(f"{querydb}:{line_no}: unsupported kxdpgun flag {parts[2]}")
    rows.append(f"{parts[0]} {parts[1]} IN {edns} knot_querydb")
out.write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
    printf 'query_trace=%s\n' "$out/query-trace.tsv"
    ;;
stage-knot-primary)
    [[ -f "$zone_file" ]] || die "--zone must name a zone file"
    [[ -n "$out" ]] || die "--out is required"
    [[ "$limit" =~ ^[0-9]+$ ]] || die "--limit must be a non-negative integer"
    [[ "$knot_port" =~ ^[0-9]+$ ]] || die "--knot-port must be an integer"
    [[ "$borondns_port" =~ ^[0-9]+$ ]] || die "--borondns-port must be an integer"
    [[ "$health_port" =~ ^[0-9]+$ ]] || die "--health-port must be an integer"
    [[ "$workers" =~ ^[0-9]+$ ]] || die "--workers must be a positive integer"
    [[ "$udp_batch_size" =~ ^[0-9]+$ ]] || die "--udp-batch-size must be a positive integer"
    ((workers > 0)) || die "--workers must be positive"
    ((udp_batch_size > 0)) || die "--udp-batch-size must be positive"
    case "$udp_runtime" in
    tokio | dedicated) ;;
    *) die "--udp-runtime must be tokio or dedicated" ;;
    esac
    mkdir -p "$out"
    python3 - "$zone_file" "$out" "$zone_name" "$limit" "$shuffle" "$knot_address" "$knot_port" "$borondns_address" "$borondns_port" "$health_address" "$health_port" "$workers" "$udp_runtime" "$udp_batch_size" "$repo_root" <<'PY'
import random
import shutil
import stat
import sys
from pathlib import Path

zone = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
zone_name_arg = sys.argv[3].strip()
limit = int(sys.argv[4])
shuffle = sys.argv[5] == "true"
knot_address = sys.argv[6]
knot_port = sys.argv[7]
borondns_address = sys.argv[8]
borondns_port = sys.argv[9]
health_address = sys.argv[10]
health_port = sys.argv[11]
workers = int(sys.argv[12])
udp_runtime = sys.argv[13]
udp_batch_size = int(sys.argv[14])
repo_root = Path(sys.argv[15])

allowed = {"NS", "DS", "A", "AAAA", "PTR", "MX", "SOA", "DNSKEY"}
rows = set()
origin = ""
last_owner = ""
soa_owner = ""
paren_depth = 0

def absolute_zone_name(name: str) -> str:
    name = name.strip()
    if not name:
        return name
    return name if name.endswith(".") else f"{name}."

def fqdn(name: str) -> str:
    if name == "@":
        return origin or "."
    if name.endswith("."):
        return name
    if origin:
        return f"{name}.{origin}"
    return f"{name}."

for raw in zone.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = raw.split(";", 1)[0].strip()
    if paren_depth > 0:
        paren_depth += line.count("(") - line.count(")")
        paren_depth = max(paren_depth, 0)
        continue
    if not line:
        continue
    parts = line.split()
    if len(parts) >= 2 and parts[0].upper() == "$ORIGIN":
        origin = absolute_zone_name(parts[1])
        continue
    if line.startswith("$"):
        continue
    owner = parts[0]
    if owner.upper() in {"IN"} or owner.isdigit():
        owner = last_owner
    else:
        last_owner = owner
    rrtype = ""
    for token in parts:
        upper = token.upper()
        if upper in allowed:
            rrtype = upper
            break
    if not owner or rrtype not in allowed:
        paren_depth += line.count("(") - line.count(")")
        paren_depth = max(paren_depth, 0)
        continue
    qname = fqdn(owner)
    rows.add(f"{qname} {rrtype}")
    if rrtype == "SOA" and not soa_owner:
        soa_owner = qname
    paren_depth += line.count("(") - line.count(")")
    paren_depth = max(paren_depth, 0)

zone_name = absolute_zone_name(zone_name_arg) or origin or soa_owner
if not zone_name:
    raise SystemExit("could not infer zone name; pass --zone-name")

rows = list(rows)
if shuffle:
    random.SystemRandom().shuffle(rows)
else:
    rows.sort()
if limit:
    rows = rows[:limit]
if not rows:
    raise SystemExit("no comparable query rows generated")

out.mkdir(parents=True, exist_ok=True)
(out / "knot").mkdir(exist_ok=True)
(out / "knot" / "run").mkdir(exist_ok=True)
(out / "knot" / "db").mkdir(exist_ok=True)
(out / "evidence").mkdir(exist_ok=True)
shutil.copyfile(zone, out / "primary.zone")

(out / "querydb").write_text("\n".join(rows) + "\n", encoding="utf-8")
trace_rows = ["# qname qtype qclass edns label"]
for row in rows:
    parts = row.split()
    edns = "none"
    if len(parts) >= 3:
        flag = parts[2].upper()
        if flag == "E":
            edns = "edns"
        elif flag == "D":
            edns = "do"
        else:
            raise SystemExit(f"unsupported kxdpgun flag {parts[2]}")
    trace_rows.append(f"{parts[0]} {parts[1]} IN {edns} knot_primary")
(out / "query-trace.tsv").write_text("\n".join(trace_rows) + "\n", encoding="utf-8")

knot_conf = f"""server:
    rundir: "{out / 'knot' / 'run'}"
    listen: {knot_address}@{knot_port}

log:
  - target: stderr
    any: info

database:
    storage: "{out / 'knot' / 'db'}"

template:
  - id: default
    storage: "{out}"
    file: "primary.zone"

acl:
  - id: transfer_acl
    address: 0.0.0.0/0
    action: transfer

zone:
  - domain: {zone_name}
    acl: transfer_acl
"""
(out / "knot.conf").write_text(knot_conf, encoding="utf-8")

borondns_conf = f"""[server]
log_level = "info"
log_format = "json"

[interfaces]
dns = [{{ address = "{borondns_address}:{borondns_port}", name = "bench0" }}]
mgmt = ["{health_address}:{health_port}"]
transfer = ["{borondns_address}:0"]

[health]
bind_address = "{health_address}"
bind_port = {health_port}
metrics_rate_limit_per_minute = 60000

[metrics]
hot_path_detail = "reduced"
pipeline_timing_enabled = false
zone_shape_enabled = false

[cookie]
policy = "disabled"

[rrl]
enabled = false

[limits]
udp_runtime = "{udp_runtime}"
udp_batch_size = {udp_batch_size}
udp_reuseport_workers = {workers}
axfr_timeout_secs = 30
ixfr_timeout_secs = 30
zsm_min_interval_secs = 60
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 5
graceful_shutdown_secs = 5

[[zones]]
name = "{zone_name}"
class = "IN"
primaries = ["{knot_address}:{knot_port}"]
notify_sources = ["{knot_address}"]
"""
(out / "borondns.toml").write_text(borondns_conf, encoding="utf-8")

runbook = f"""#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

: "${{KNOTD:=knotd}}"
: "${{KNOTC:=knotc}}"
: "${{DIG:=dig}}"
: "${{CURL:=curl}}"
: "${{BORONDNS_BIN:={repo_root / 'target' / 'release' / 'borondns'}}}"
: "${{LOAD_CLIENT:={repo_root / 'target' / 'benchmark-tools' / 'dns-load-client'}}}"
: "${{BENCH_ARTIFACT:=evidence/borondns-idle-after-knot-transfer}}"
: "${{RUN_IDLE_BENCHMARK:=true}}"
: "${{BENCH_DURATION:=15}}"
: "${{BENCH_THREADS:=8}}"
: "${{BENCH_WINDOW:=64}}"
: "${{BENCH_UDP_SOCKETS_PER_THREAD:=1}}"
: "${{BENCH_TRANSPORT:=udp}}"
: "${{BENCH_BIND:=127.0.0.1:0}}"
: "${{BENCH_NETWORK_DEVICE:=lo}}"

cleanup() {{
    local status=$?
    if [[ -n "${{borondns_pid:-}}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
    fi
    if [[ -n "${{knot_pid:-}}" ]] && kill -0 "$knot_pid" 2>/dev/null; then
        kill "$knot_pid" 2>/dev/null || true
        wait "$knot_pid" 2>/dev/null || true
    fi
    exit "$status"
}}
trap cleanup EXIT

mkdir -p knot/run knot/db evidence

"$KNOTC" -c knot.conf conf-check
"$BORONDNS_BIN" --validate-config borondns.toml

"$KNOTD" -c knot.conf -v >knot.log 2>&1 &
knot_pid=$!

for _ in {{1..120}}; do
    if "$DIG" "@{knot_address}" -p "{knot_port}" "{zone_name}" SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
"$DIG" "@{knot_address}" -p "{knot_port}" "{zone_name}" AXFR +time=5 +tries=1 >primary-axfr.out

"$BORONDNS_BIN" serve --config borondns.toml >borondns.log 2>&1 &
borondns_pid=$!

for _ in {{1..180}}; do
    ready="$("$CURL" -fsS "http://{health_address}:{health_port}/readyz" 2>/dev/null || true)"
    if [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]]; then
        break
    fi
    sleep 0.25
done
if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "BoronDNS did not become ready after Knot AXFR" >&2
    exit 1
fi

"$DIG" "@{borondns_address}" -p "{borondns_port}" "{zone_name}" SOA +time=2 +tries=1 +short >borondns-soa-before-knot-stop.out

kill "$knot_pid"
wait "$knot_pid" 2>/dev/null || true
unset knot_pid

"$DIG" "@{borondns_address}" -p "{borondns_port}" "{zone_name}" SOA +time=2 +tries=1 +short >borondns-soa-after-knot-stop.out

echo "Knot has been stopped. BoronDNS is serving the transferred zone from its in-memory snapshot."
if [[ "$RUN_IDLE_BENCHMARK" == "true" ]]; then
    mkdir -p "$BENCH_ARTIFACT/network"
    rustc --edition=2024 -O "{repo_root / 'tools' / 'dns-load-client.rs'}" -o "$LOAD_CLIENT"
    cp /proc/net/dev "$BENCH_ARTIFACT/network/proc-net-dev-before.txt" 2>/dev/null || true
    "$CURL" -fsS "http://{health_address}:{health_port}/metrics" >"$BENCH_ARTIFACT/metrics-before.prom" || true
    "$LOAD_CLIENT" \
        --transport "$BENCH_TRANSPORT" \
        --server "{borondns_address}" \
        --port "{borondns_port}" \
        --bind "$BENCH_BIND" \
        --threads "$BENCH_THREADS" \
        --udp-sockets-per-thread "$BENCH_UDP_SOCKETS_PER_THREAD" \
        --duration "$BENCH_DURATION" \
        --window "$BENCH_WINDOW" \
        --trace query-trace.tsv | tee "$BENCH_ARTIFACT/client.log"
    cp /proc/net/dev "$BENCH_ARTIFACT/network/proc-net-dev-after.txt" 2>/dev/null || true
    "$CURL" -fsS "http://{health_address}:{health_port}/metrics" >"$BENCH_ARTIFACT/metrics-after.prom" || true
    cat >"$BENCH_ARTIFACT/run.env" <<EOF
zone_name={zone_name}
knot_primary={knot_address}:{knot_port}
borondns_server={borondns_address}:{borondns_port}
bench_transport=$BENCH_TRANSPORT
bench_duration_seconds=$BENCH_DURATION
bench_threads=$BENCH_THREADS
bench_window=$BENCH_WINDOW
bench_udp_sockets_per_thread=$BENCH_UDP_SOCKETS_PER_THREAD
bench_bind=$BENCH_BIND
bench_network_device=$BENCH_NETWORK_DEVICE
query_trace=$PWD/query-trace.tsv
querydb=$PWD/querydb
EOF
    python3 - "$BENCH_ARTIFACT" "$BENCH_NETWORK_DEVICE" <<'BENCH_PY'
import math
import re
import sys
from pathlib import Path

artifact = Path(sys.argv[1])
device = sys.argv[2]
summary = {{}}
for line in (artifact / "client.log").read_text(encoding="utf-8", errors="ignore").splitlines():
    if not line.startswith("dns_load_client_summary "):
        continue
    for key, value in re.findall(r"([a-zA-Z0-9_]+)=([^ ]+)", line):
        summary[key] = value

def read_dev(path):
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        if name.strip() != device:
            continue
        values = rest.split()
        return {{
            "rx_bytes": int(values[0]),
            "rx_packets": int(values[1]),
            "tx_bytes": int(values[8]),
            "tx_packets": int(values[9]),
        }}
    return {{}}

before = read_dev(artifact / "network" / "proc-net-dev-before.txt")
after = read_dev(artifact / "network" / "proc-net-dev-after.txt")
deltas = {{key: after.get(key, 0) - before.get(key, 0) for key in set(before) | set(after)}}
duration = float(summary.get("duration_seconds", "nan"))
responses = float(summary.get("responses_per_second", "nan"))

def rate_bytes(key):
    if duration > 0 and key in deltas:
        return deltas[key] / duration
    return math.nan

rx_bps = rate_bytes("rx_bytes")
tx_bps = rate_bytes("tx_bytes")
sum_bps = rx_bps + tx_bps if not math.isnan(rx_bps) and not math.isnan(tx_bps) else math.nan

def fmt(value):
    return "" if math.isnan(value) else f"{{value:.6f}}"

metrics = {{
    "duration_seconds": summary.get("duration_seconds", ""),
    "sent": summary.get("sent", ""),
    "received": summary.get("received", ""),
    "responses_per_second": summary.get("responses_per_second", ""),
    "sent_per_second": summary.get("sent_per_second", ""),
    "errors": summary.get("errors", ""),
    "dropped": summary.get("dropped", ""),
    "latency_us_p50": summary.get("latency_us_p50", ""),
    "latency_us_p99": summary.get("latency_us_p99", ""),
    "latency_us_p999": summary.get("latency_us_p999", ""),
    "network_device": device,
    "network_rx_bytes_delta": str(deltas.get("rx_bytes", "")),
    "network_tx_bytes_delta": str(deltas.get("tx_bytes", "")),
    "network_rx_packets_delta": str(deltas.get("rx_packets", "")),
    "network_tx_packets_delta": str(deltas.get("tx_packets", "")),
    "network_rx_gbps": fmt(rx_bps * 8 / 1_000_000_000),
    "network_tx_gbps": fmt(tx_bps * 8 / 1_000_000_000),
    "network_sum_gbps": fmt(sum_bps * 8 / 1_000_000_000),
    "network_rx_gigabytes_per_second": fmt(rx_bps / 1_000_000_000),
    "network_tx_gigabytes_per_second": fmt(tx_bps / 1_000_000_000),
    "network_sum_gigabytes_per_second": fmt(sum_bps / 1_000_000_000),
    "network_rx_bytes_per_response": fmt(rx_bps / responses) if responses > 0 else "",
    "network_tx_bytes_per_response": fmt(tx_bps / responses) if responses > 0 else "",
    "network_sum_bytes_per_response": fmt(sum_bps / responses) if responses > 0 else "",
    "network_throughput_scope": "loopback-summed-not-wire-rate" if device == "lo" else "interface-counter",
}}
with (artifact / "benchmark-results.tsv").open("w", encoding="utf-8") as handle:
    handle.write("metric\\tvalue\\tunit\\n")
    for key, value in metrics.items():
        handle.write(f"{{key}}\\t{{value}}\\t\\n")
with (artifact / "network" / "proc-net-dev-delta.tsv").open("w", encoding="utf-8") as handle:
    handle.write("metric\\tdelta\\n")
    for key, value in sorted(deltas.items()):
        handle.write(f"{{key}}\\t{{value}}\\n")
BENCH_PY
    echo "BoronDNS idle benchmark artifact: $BENCH_ARTIFACT"
else
    echo "RUN_IDLE_BENCHMARK=false; BoronDNS readiness after Knot stop was verified but no load run was executed."
fi
"""
runbook_path = out / "runbook.sh"
runbook_path.write_text(runbook, encoding="utf-8")
runbook_path.chmod(runbook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

readme = f"""# Knot Primary Comparison Stage

This directory stages one benchmark zone with Knot as the primary and BoronDNS
as a secondary.

Files:
- `primary.zone`: copied source zone.
- `knot.conf`: Knot primary config serving `primary.zone` on `{knot_address}@{knot_port}`.
- `borondns.toml`: BoronDNS secondary config transferring `{zone_name}` from Knot and serving on `{borondns_address}:{borondns_port}`.
- `querydb`: kxdpgun input generated from the zone.
- `query-trace.tsv`: equivalent BoronDNS load-client trace.
- `runbook.sh`: validates configs, starts Knot, waits for BoronDNS transfer readiness, stops Knot, and can run a direct load-client benchmark while BoronDNS serves the transferred snapshot.

Use `querydb` unchanged for the Knot/kxdpgun reference run. Use
`query-trace.tsv` for BoronDNS runs so both implementations see the same query
mix.
"""
(out / "README.md").write_text(readme, encoding="utf-8")
PY
    printf 'stage=%s\n' "$out"
    printf 'knot_config=%s\n' "$out/knot.conf"
    printf 'borondns_config=%s\n' "$out/borondns.toml"
    printf 'querydb=%s\n' "$out/querydb"
    printf 'query_trace=%s\n' "$out/query-trace.tsv"
    printf 'runbook=%s\n' "$out/runbook.sh"
    ;;
normalize-borondns)
    [[ -d "$artifact" ]] || die "--artifact must name an BoronDNS benchmark artifact directory"
    [[ -n "$out" ]] || die "--out is required"
    python3 - "$artifact/benchmark-results.tsv" "$out" <<'PY'
import csv
import math
import sys
from pathlib import Path

results = Path(sys.argv[1])
out = Path(sys.argv[2])
values = {}
with results.open(encoding="utf-8") as handle:
    for row in csv.DictReader(handle, delimiter="\t"):
        values[row["metric"]] = row["value"]

def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan

def fmt(value):
    return "" if math.isnan(value) else f"{value:.6f}"

if "network_rx_gbps" not in values:
    delta_path = results.parent / "network" / "proc-net-dev-delta.tsv"
    if delta_path.exists():
        deltas = {}
        with delta_path.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                deltas[row["metric"]] = row["delta"]
        duration = number(values.get("duration_seconds"))
        qps = number(values.get("responses_per_second"))
        rx = number(deltas.get("rx_bytes"))
        tx = number(deltas.get("tx_bytes"))
        if duration > 0:
            rx_bps = rx / duration if not math.isnan(rx) else math.nan
            tx_bps = tx / duration if not math.isnan(tx) else math.nan
            sum_bps = rx_bps + tx_bps if not math.isnan(rx_bps) and not math.isnan(tx_bps) else math.nan
            values["network_rx_gbps"] = fmt(rx_bps * 8 / 1_000_000_000)
            values["network_tx_gbps"] = fmt(tx_bps * 8 / 1_000_000_000)
            values["network_sum_gbps"] = fmt(sum_bps * 8 / 1_000_000_000)
            values["network_rx_gigabytes_per_second"] = fmt(rx_bps / 1_000_000_000)
            values["network_tx_gigabytes_per_second"] = fmt(tx_bps / 1_000_000_000)
            values["network_sum_gigabytes_per_second"] = fmt(sum_bps / 1_000_000_000)
            values["network_rx_bytes_per_response"] = fmt(rx_bps / qps) if qps > 0 else ""
            values["network_tx_bytes_per_response"] = fmt(tx_bps / qps) if qps > 0 else ""
            values["network_sum_bytes_per_response"] = fmt(sum_bps / qps) if qps > 0 else ""
            scope = "loopback-summed-not-wire-rate" if values.get("network_device") == "lo" else "interface-counter"
            values["network_throughput_scope"] = scope
fields = [
    "implementation", "artifact", "qps", "responses_per_second", "duration_seconds",
    "rx_gbps", "tx_gbps", "sum_gbps", "rx_gigabytes_per_second",
    "tx_gigabytes_per_second", "sum_gigabytes_per_second",
    "rx_bytes_per_response", "tx_bytes_per_response", "sum_bytes_per_response",
    "drops_or_lost", "errors", "throughput_scope",
]
row = {
    "implementation": "borondns",
    "artifact": str(results.parent),
    "qps": values.get("responses_per_second", ""),
    "responses_per_second": values.get("responses_per_second", ""),
    "duration_seconds": values.get("duration_seconds", ""),
    "rx_gbps": values.get("network_rx_gbps", ""),
    "tx_gbps": values.get("network_tx_gbps", ""),
    "sum_gbps": values.get("network_sum_gbps", ""),
    "rx_gigabytes_per_second": values.get("network_rx_gigabytes_per_second", ""),
    "tx_gigabytes_per_second": values.get("network_tx_gigabytes_per_second", ""),
    "sum_gigabytes_per_second": values.get("network_sum_gigabytes_per_second", ""),
    "rx_bytes_per_response": values.get("network_rx_bytes_per_response", ""),
    "tx_bytes_per_response": values.get("network_tx_bytes_per_response", ""),
    "sum_bytes_per_response": values.get("network_sum_bytes_per_response", ""),
    "drops_or_lost": values.get("dropped", ""),
    "errors": values.get("errors", ""),
    "throughput_scope": values.get("network_throughput_scope", ""),
}
with out.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
PY
    printf 'normalized=%s\n' "$out"
    ;;
normalize-kxdpgun)
    [[ -f "$log_file" ]] || die "--log must name a kxdpgun log file"
    [[ -n "$duration" ]] || die "--duration is required for kxdpgun normalization"
    [[ -n "$out" ]] || die "--out is required"
    python3 - "$log_file" "$duration" "$out" <<'PY'
import csv
import re
import sys
from pathlib import Path

log = Path(sys.argv[1])
duration = float(sys.argv[2])
out = Path(sys.argv[3])
text = log.read_text(encoding="utf-8", errors="ignore")

def last(pattern, default=""):
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    return matches[-1] if matches else default

queries = float(last(r"total queries:\s+(\d+)", "0"))
responses = float(last(r"total replies:\s+(\d+)", "0"))
avg_reply = float(last(r"average DNS reply size:\s+(\d+)", "0"))
l2_bps = float(last(r"average L2 throughput:\s+(\d+)\s+bps", "0"))
l1_bps = float(last(r"average L1 throughput:\s+(\d+)\s+bps", "0"))
errors = sum(float(v) for v in re.findall(r"errors\s+(\d+)", text))
lost = sum(float(v) for v in re.findall(r"lost\s+(\d+)", text))

fields = [
    "implementation", "artifact", "qps", "responses_per_second", "duration_seconds",
    "rx_gbps", "tx_gbps", "sum_gbps", "rx_gigabytes_per_second",
    "tx_gigabytes_per_second", "sum_gigabytes_per_second",
    "rx_bytes_per_response", "tx_bytes_per_response", "sum_bytes_per_response",
    "drops_or_lost", "errors", "throughput_scope",
]
row = {
    "implementation": "kxdpgun-target",
    "artifact": str(log),
    "qps": f"{queries / duration:.6f}",
    "responses_per_second": f"{responses / duration:.6f}",
    "duration_seconds": f"{duration:.6f}",
    "rx_gbps": f"{l2_bps / 1_000_000_000:.6f}",
    "tx_gbps": "",
    "sum_gbps": f"{l1_bps / 1_000_000_000:.6f}",
    "rx_gigabytes_per_second": f"{l2_bps / 8 / 1_000_000_000:.6f}",
    "tx_gigabytes_per_second": "",
    "sum_gigabytes_per_second": f"{l1_bps / 8 / 1_000_000_000:.6f}",
    "rx_bytes_per_response": f"{avg_reply:.6f}",
    "tx_bytes_per_response": "",
    "sum_bytes_per_response": "",
    "drops_or_lost": f"{lost:.0f}",
    "errors": f"{errors:.0f}",
    "throughput_scope": "kxdpgun-received-l2-l1",
}
with out.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
PY
    printf 'normalized=%s\n' "$out"
    ;;
esac
