#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping NSD NOTIFY Docker interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping NSD NOTIFY Docker interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
workdir="$repo_root/target/interop/nsd-notify-refresh-$$"
container="oxidedns-nsd-notify-refresh-$$"
artifact_dir="${OXIDEDNS_NSD_NOTIFY_ARTIFACT_DIR:-}"
mkdir -p "$workdir"

copy_failure_artifacts() {
    if [[ -z "$artifact_dir" ]]; then
        return
    fi

    mkdir -p "$artifact_dir"
    rm -rf "$artifact_dir/workdir"
    cp -a "$workdir" "$artifact_dir/workdir"
}

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if [[ -n "${notify_proxy_pid:-}" ]] && kill -0 "$notify_proxy_pid" 2>/dev/null; then
        kill "$notify_proxy_pid" 2>/dev/null || true
        wait "$notify_proxy_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        docker logs "$container" >"$workdir/nsd-container.log" 2>&1 || true
        if ((status != 0)); then
            echo "---- nsd container logs ----" >&2
            cat "$workdir/nsd-container.log" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if ((status != 0)); then
        copy_failure_artifacts
        [[ -f "$workdir/notify-proxy.log" ]] && {
            echo "---- notify-proxy.log ----" >&2
            tail -120 "$workdir/notify-proxy.log" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -120 "$workdir/oxidedns.log" >&2
        }
    fi
}
trap cleanup EXIT

read -r nsd_port notify_port oxidedns_dns_port oxidedns_health_port < <(
    python3 - <<'PY'
import socket

sockets = []
for _ in range(4):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

host_notify_address="$(
    python3 - <<'PY'
import socket

for target in (("1.1.1.1", 53), ("8.8.8.8", 53)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(target)
        print(sock.getsockname()[0])
        break
    except OSError:
        pass
    finally:
        sock.close()
PY
)"
if [[ -z "$host_notify_address" ]]; then
    host_notify_address="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
fi
if [[ -z "$host_notify_address" ]]; then
    host_notify_address="172.17.0.1"
fi

zone_file="$workdir/alpha.test.zone"
nsd_conf="$workdir/nsd.conf"
notify_proxy="$workdir/notify-proxy.py"
notify_proxy_log="$workdir/notify-proxy.log"
oxidedns_conf="$workdir/oxidedns.toml"
metrics_out="$workdir/metrics.txt"
summary_tsv="$workdir/nsd-notify-refresh-summary.tsv"
traceability_tsv="$workdir/nsd-notify-traceability.tsv"

write_zone() {
    local serial="$1"
    local www_addr="$2"
    cat >"$zone_file" <<EOF
\$ORIGIN alpha.test.
\$TTL 3600
@ IN SOA ns1.alpha.test. hostmaster.alpha.test. (
    $serial ; serial
    60      ; refresh
    30      ; retry
    300     ; expire
    300     ; minimum
)
  IN NS ns1.alpha.test.
  IN NS ns2.alpha.test.
ns1 IN A 127.0.0.1
ns2 IN A 127.0.0.2
www IN A $www_addr
mail IN A 192.0.2.20
alias IN CNAME www.alpha.test.
txt IN TXT "nsd notify interop fixture"
_sip._tcp IN SRV 10 20 5060 www.alpha.test.
EOF
}

write_zone 2026052401 192.0.2.10

cat >"$nsd_conf" <<EOF
server:
    do-ip4: yes
    do-ip6: no
    ip-address: 0.0.0.0@5353
    hide-version: yes
    verbosity: 1
    database: "/tmp/nsd.db"
    pidfile: "/tmp/nsd.pid"
    zonesdir: "/work"

remote-control:
    control-enable: yes
    control-interface: /tmp/nsd.control.sock

zone:
    name: "alpha.test."
    zonefile: "/work/alpha.test.zone"
    notify: $host_notify_address@$notify_port NOKEY
    notify-retry: 1
    provide-xfr: 0.0.0.0/0 NOKEY
EOF

cat >"$notify_proxy" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

listen_port = int(sys.argv[1])
target_port = int(sys.argv[2])
log_path = sys.argv[3]


def log(message):
    with open(log_path, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", listen_port))

while True:
    packet, peer = sock.recvfrom(4096)
    if len(packet) < 12:
        log(f"short_packet bytes={len(packet)} peer={peer}")
        continue
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    opcode = (flags >> 11) & 0x0F
    log(
        "notify_from_nsd "
        f"peer={peer[0]}:{peer[1]} qid={qid} opcode={opcode} "
        f"qd={qdcount} an={ancount} ns={nscount} ar={arcount}"
    )
    forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward.settimeout(2)
    forward.sendto(packet, ("127.0.0.1", target_port))
    try:
        response, _ = forward.recvfrom(4096)
        if len(response) >= 4:
            _, response_flags = struct.unpack("!HH", response[:4])
            log(f"response_from_oxidedns rcode={response_flags & 0x0F} bytes={len(response)}")
        else:
            log(f"short_response_from_oxidedns bytes={len(response)}")
    except TimeoutError:
        log("response_from_oxidedns timeout")
PY

cargo build -p oxidedns-cli >/dev/null
if ! docker run -d --name "$container" \
    -p "127.0.0.1:$nsd_port:5353/tcp" \
    -p "127.0.0.1:$nsd_port:5353/udp" \
    -v "$workdir:/work:rw" \
    alpine:latest \
    sh -c 'apk add --no-cache gcompat libgcc nsd python3 >/dev/null && nsd-checkzone alpha.test. /work/alpha.test.zone >/dev/null && nsd-checkconf /work/nsd.conf && exec nsd -d -c /work/nsd.conf' \
    >/dev/null; then
    echo "skipping NSD NOTIFY Docker interop: failed to start Alpine/NSD container" >&2
    exit 0
fi
record_docker_primary_version "$workdir" "$container" "NSD" "alpine:latest" "nsd" "nsd-notify-refresh" "udp-notify+tcp-axfr" "none" "nsd -v" "$workdir/nsd.conf" "$workdir/alpha.test.zone"

for _ in {1..120}; do
    if dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

primary_soa="$(dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short)"
if [[ "$primary_soa" != *"2026052401"* ]]; then
    echo "NSD NOTIFY primary did not answer initial SOA serial" >&2
    exit 1
fi

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

[rrl]
enabled = false

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
notify_dedup_secs = 1
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$nsd_port"]
notify_sources = ["127.0.0.1"]
EOF

python3 "$notify_proxy" "$notify_port" "$oxidedns_dns_port" "$notify_proxy_log" >"$workdir/notify-proxy.stderr" 2>&1 &
notify_proxy_pid=$!
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=""
for _ in {1..100}; do
    if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after initial NSD AXFR" >&2
    exit 1
fi

initial_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$initial_soa" != *"2026052401"* ]]; then
    echo "OxideDNS did not serve initial SOA serial from NSD" >&2
    exit 1
fi

write_zone 2026052402 192.0.2.42
docker exec "$container" nsd-checkzone alpha.test. /work/alpha.test.zone >/dev/null
docker exec "$container" nsd-control -c /work/nsd.conf reload alpha.test >/dev/null
docker exec "$container" nsd-control -c /work/nsd.conf notify alpha.test >/dev/null

primary_updated_soa=""
for _ in {1..80}; do
    primary_updated_soa="$(dig "@127.0.0.1" -p "$nsd_port" alpha.test. SOA +time=1 +tries=1 +short)"
    if [[ "$primary_updated_soa" == *"2026052402"* ]]; then
        break
    fi
    sleep 0.1
done

if [[ "$primary_updated_soa" != *"2026052402"* ]]; then
    echo "NSD primary did not publish updated SOA serial" >&2
    exit 1
fi

updated_answer=""
for _ in {1..120}; do
    updated_answer="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
    if [[ "$updated_answer" == *"192.0.2.42"* ]]; then
        break
    fi
    sleep 0.1
done

if [[ "$updated_answer" != *"www.alpha.test."* ]] || [[ "$updated_answer" != *"192.0.2.42"* ]]; then
    echo "OxideDNS did not publish updated A response after NSD NOTIFY" >&2
    exit 1
fi
updated_address="$(awk '/www[.]alpha[.]test[.]/ { print $NF; exit }' <<<"$updated_answer")"

updated_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$updated_soa" != *"2026052402"* ]]; then
    echo "OxideDNS did not publish updated SOA serial after NSD NOTIFY" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
for expected in \
    'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052402' \
    'oxidedns_notify_messages_received_total' \
    'oxidedns_notify_refresh_actions_total{action="signalled"}'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "OxideDNS metrics missing expected NSD NOTIFY evidence: $expected" >&2
        exit 1
    fi
done

notify_received="$(awk '$1 == "oxidedns_notify_messages_received_total" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_received" ]] || ((notify_received < 1)); then
    echo "OxideDNS metrics did not record NSD NOTIFY receipt" >&2
    exit 1
fi

notify_signalled="$(awk '$1 == "oxidedns_notify_refresh_actions_total{action=\"signalled\"}" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_signalled" ]] || ((notify_signalled < 1)); then
    echo "OxideDNS metrics did not record NSD NOTIFY refresh signal" >&2
    exit 1
fi

if ! grep -q "notify_from_nsd .* opcode=4" "$notify_proxy_log"; then
    echo "NSD NOTIFY proxy did not observe an NSD NOTIFY packet" >&2
    exit 1
fi

if ! grep -q "response_from_oxidedns rcode=0" "$notify_proxy_log"; then
    echo "NSD NOTIFY proxy did not observe a successful OxideDNS NOTIFY response" >&2
    exit 1
fi

if ! grep 'accepted NOTIFY' "$workdir/oxidedns.log" | grep -q 'alpha.test.'; then
    echo "OxideDNS log missing accepted NSD NOTIFY event" >&2
    exit 1
fi

{
    printf 'primary\tinitial_primary_soa\tinitial_oxidedns_soa\tupdated_primary_soa\tupdated_oxidedns_soa\tnotify_received\tnotify_signalled\tupdated_address\n'
    printf 'NSD\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$primary_soa" \
        "$initial_soa" \
        "$primary_updated_soa" \
        "$updated_soa" \
        "$notify_received" \
        "$notify_signalled" \
        "$updated_address"
} >"$summary_tsv"

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_state	runtime_case	artifacts	review_note
ODS-FR-NOTIFY-001	retained-real-primary	nsd_udp_notify_reception	notify-proxy.log; primary-version.txt	The NSD primary emits OPCODE=4 NOTIFY packets observed by the forwarding proxy and OxideDNS receives them on the DNS listener.
ODS-FR-NOTIFY-006	retained-real-primary	nsd_notify_response	notify-proxy.log	The forwarding proxy observes a successful OxideDNS NOTIFY response with RCODE=0 for NSD-generated NOTIFY.
ODS-FR-NOTIFY-007	retained-real-primary	nsd_refresh_signal	metrics.txt; nsd-notify-refresh-summary.tsv	OxideDNS metrics record real-primary NOTIFY receipt and refresh-signalled actions, and the served zone advances from serial 2026052401 to 2026052402.
ODS-FR-NOTIFY-010	retained-real-primary	nsd_notify_logging	oxidedns.log	OxideDNS emits an accepted NOTIFY log for the real-primary NSD message, including source, zone, and refresh action.
ODS-FR-ZSM-003	retained-real-primary	nsd_notify_triggered_refresh	nsd-notify-refresh-summary.tsv; metrics.txt	The accepted real-primary NOTIFY triggers the refresh path and OxideDNS republishes the updated SOA serial and A record.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$workdir/primary-version.txt" "$artifact_dir/primary-version.txt"
    cp "$nsd_conf" "$artifact_dir/nsd.conf"
    cp "$zone_file" "$artifact_dir/alpha.test.zone"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
    cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
    cp "$notify_proxy_log" "$artifact_dir/notify-proxy.log"
    cp "$metrics_out" "$artifact_dir/metrics.txt"
    cp "$summary_tsv" "$artifact_dir/nsd-notify-refresh-summary.tsv"
    cp "$traceability_tsv" "$artifact_dir/nsd-notify-traceability.tsv"
fi

echo "NSD NOTIFY refresh Docker interop passed"
