#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in named named-checkconf named-checkzone rndc dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping BIND NOTIFY interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi
ulimit -n 65536 2>/dev/null || true

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
template_file="$repo_root/tests/interop/bind/named-notify.conf.template"
bind_cache_parent="/var/cache/bind/oxidedns-interop"
if [[ -d "$bind_cache_parent" && -w "$bind_cache_parent" ]]; then
    work_parent="$bind_cache_parent"
else
    work_parent="${TMPDIR:-/tmp}/oxidedns-interop"
fi
mkdir -p "$work_parent"
chmod 1777 "$work_parent"
workdir="$work_parent/bind-notify-refresh-$$"
artifact_dir="${OXIDEDNS_BIND_NOTIFY_ARTIFACT_DIR:-}"
mkdir -p "$workdir"
chmod 0777 "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if [[ -n "${named_pid:-}" ]] && kill -0 "$named_pid" 2>/dev/null; then
        kill "$named_pid" 2>/dev/null || true
        wait "$named_pid" 2>/dev/null || true
    fi
    if [[ -n "${proxy_pid:-}" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid" 2>/dev/null || true
        wait "$proxy_pid" 2>/dev/null || true
    fi
    if ((status != 0)); then
        [[ -f "$workdir/named.log" ]] && {
            echo "---- named.log ----" >&2
            tail -120 "$workdir/named.log" >&2
        }
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

read -r bind_port rndc_port notify_port oxidedns_dns_port oxidedns_health_port < <(
    python3 - <<'PY'
import socket

sockets = []
for _ in range(5):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

zone_file="$workdir/alpha.test.zone"
named_conf="$workdir/named.conf"
rndc_conf="$workdir/rndc.conf"
oxidedns_conf="$workdir/oxidedns.toml"
notify_proxy="$workdir/notify-proxy.py"
notify_proxy_log="$workdir/notify-proxy.log"
rndc_secret="dG9wc2VjcmV0"
metrics_out="$workdir/metrics.txt"
summary_tsv="$workdir/bind-notify-refresh-summary.tsv"
traceability_tsv="$workdir/bind-notify-traceability.tsv"

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
txt IN TXT "bind notify interop fixture"
_sip._tcp IN SRV 10 20 5060 www.alpha.test.
EOF
    chmod 0644 "$zone_file"
    named-checkzone alpha.test. "$zone_file" >/dev/null
}

write_zone 2026052401 192.0.2.10

python3 - "$template_file" "$named_conf" "$workdir" "$bind_port" "$rndc_port" "$zone_file" "$notify_port" "$rndc_secret" <<'PY'
from pathlib import Path
import sys

template, output, workdir, port, rndc_port, zonefile, oxidedns_port, secret = sys.argv[1:]
text = Path(template).read_text()
text = text.replace("__WORKDIR__", workdir)
text = text.replace("__PORT__", port)
text = text.replace("__RNDC_PORT__", rndc_port)
text = text.replace("__ZONEFILE__", zonefile)
text = text.replace("__OXIDEDNS_PORT__", oxidedns_port)
text = text.replace("__RNDC_SECRET__", secret)
Path(output).write_text(text)
PY
chmod 0644 "$named_conf"

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
sock.bind(("127.0.0.1", listen_port))


def question_end(packet):
    offset = 12
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            return offset + 4
        offset += length


def notify_response(packet, qid):
    end = question_end(packet)
    flags = 0x8000 | 0x0400 | (4 << 11)
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + packet[12:end]

while True:
    packet, peer = sock.recvfrom(4096)
    if len(packet) < 12:
        log(f"short_packet bytes={len(packet)} peer={peer}")
        continue
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    opcode = (flags >> 11) & 0x0F
    log(
        "notify_from_bind "
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

python3 "$notify_proxy" "$notify_port" "$oxidedns_dns_port" "$notify_proxy_log" &
proxy_pid=$!

cat >"$rndc_conf" <<EOF
key "rndc-key" {
    algorithm hmac-sha256;
    secret "$rndc_secret";
};

options {
    default-server 127.0.0.1;
    default-port $rndc_port;
    default-key "rndc-key";
};
EOF

named-checkconf -z "$named_conf" >/dev/null
record_bind_primary_version "$workdir" "bind-notify-refresh" "udp-notify+tcp-axfr" "none" "$named_conf" "$workdir/alpha.test.zone" "$rndc_conf"

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

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
primaries = ["127.0.0.1:$bind_port"]
notify_sources = ["127.0.0.1"]
EOF

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

live=0
for _ in {1..100}; do
    if curl -fsS "http://127.0.0.1:$oxidedns_health_port/livez" >/dev/null 2>&1; then
        live=1
        break
    fi
    sleep 0.1
done
if ((live != 1)); then
    echo "OxideDNS did not become live before starting BIND" >&2
    exit 1
fi

named -g -c "$named_conf" -n 1 >"$workdir/named.log" 2>&1 &
named_pid=$!

for _ in {1..50}; do
    if dig "@127.0.0.1" -p "$bind_port" alpha.test. SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

primary_soa="$(dig "@127.0.0.1" -p "$bind_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$primary_soa" != *"2026052401"* ]]; then
    echo "BIND NOTIFY primary did not answer initial SOA serial" >&2
    exit 1
fi

ready=""
for _ in {1..100}; do
    if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after initial BIND AXFR" >&2
    exit 1
fi

initial_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$initial_soa" != *"2026052401"* ]]; then
    echo "OxideDNS did not serve initial SOA serial" >&2
    exit 1
fi

# BIND can keep the initial NOTIFY retry queued for a few seconds even after
# OxideDNS has refreshed. Let that stale retry and the server dedup window drain
# before reloading the zone, otherwise the updated NOTIFY may be deduplicated
# behind the stale serial in tight soak loops.
sleep 6

write_zone 2026052402 192.0.2.42
rndc -c "$rndc_conf" reload alpha.test >/dev/null
rndc -c "$rndc_conf" notify alpha.test >/dev/null

updated_answer=""
for _ in {1..120}; do
    updated_answer="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.alpha.test. A +norecurse +noall +answer)"
    if [[ "$updated_answer" == *"192.0.2.42"* ]]; then
        break
    fi
    sleep 0.1
done

if [[ "$updated_answer" != *"www.alpha.test."* ]] || [[ "$updated_answer" != *"192.0.2.42"* ]]; then
    echo "OxideDNS did not publish updated A response after BIND NOTIFY" >&2
    exit 1
fi
updated_address="$(awk '/www[.]alpha[.]test[.]/ { print $NF; exit }' <<<"$updated_answer")"

updated_soa="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$updated_soa" != *"2026052402"* ]]; then
    echo "OxideDNS did not publish updated SOA serial after BIND NOTIFY" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
if [[ "$metrics" != *'oxidedns_zone_soa_serial{zone="alpha.test."} 2026052402'* ]]; then
    echo "OxideDNS metrics missing updated BIND NOTIFY SOA serial" >&2
    exit 1
fi

notify_received="$(awk '$1 == "oxidedns_notify_messages_received_total" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_received" ]] || ((notify_received < 1)); then
    echo "OxideDNS metrics did not record BIND NOTIFY receipt" >&2
    exit 1
fi

notify_signalled="$(awk '$1 == "oxidedns_notify_refresh_actions_total{action=\"signalled\"}" { print $2 }' <<<"$metrics")"
if [[ -z "$notify_signalled" ]] || ((notify_signalled < 1)); then
    echo "OxideDNS metrics did not record BIND NOTIFY refresh signal" >&2
    exit 1
fi

if ! grep -q "notify_from_bind .* opcode=4" "$notify_proxy_log"; then
    echo "BIND NOTIFY proxy did not observe a BIND NOTIFY packet" >&2
    exit 1
fi

if ! grep -q "response_from_oxidedns rcode=0" "$notify_proxy_log"; then
    echo "BIND NOTIFY proxy did not observe a successful OxideDNS NOTIFY response" >&2
    exit 1
fi

if ! grep 'accepted NOTIFY' "$workdir/oxidedns.log" | grep -q 'alpha.test.'; then
    echo "OxideDNS log missing accepted BIND NOTIFY event" >&2
    exit 1
fi

{
    printf 'primary\tinitial_primary_soa\tinitial_oxidedns_soa\tupdated_oxidedns_soa\tnotify_received\tnotify_signalled\tupdated_address\n'
    printf 'BIND\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$primary_soa" \
        "$initial_soa" \
        "$updated_soa" \
        "$notify_received" \
        "$notify_signalled" \
        "$updated_address"
} >"$summary_tsv"

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_state	runtime_case	artifacts	review_note
ODS-FR-NOTIFY-001	retained-real-primary	bind_udp_notify_reception	notify-proxy.log; primary-version.txt	The BIND primary emits OPCODE=4 NOTIFY packets observed by the forwarding proxy and OxideDNS receives them on the DNS listener.
ODS-FR-NOTIFY-006	retained-real-primary	bind_notify_response	notify-proxy.log	The forwarding proxy observes a successful OxideDNS NOTIFY response with RCODE=0 for BIND-generated NOTIFY.
ODS-FR-NOTIFY-007	retained-real-primary	bind_refresh_signal	metrics.txt; bind-notify-refresh-summary.tsv	OxideDNS metrics record real-primary NOTIFY receipt and refresh-signalled actions, and the served zone advances from serial 2026052401 to 2026052402.
ODS-FR-NOTIFY-010	retained-real-primary	bind_notify_logging	oxidedns.log	OxideDNS emits an accepted NOTIFY log for the real-primary BIND message, including source, zone, and refresh action.
ODS-FR-ZSM-003	retained-real-primary	bind_notify_triggered_refresh	bind-notify-refresh-summary.tsv; metrics.txt	The accepted real-primary NOTIFY triggers the refresh path and OxideDNS republishes the updated SOA serial and A record.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$workdir/primary-version.txt" "$artifact_dir/primary-version.txt"
    cp "$named_conf" "$artifact_dir/named.conf"
    cp "$zone_file" "$artifact_dir/alpha.test.zone"
    cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
    cp "$workdir/named.log" "$artifact_dir/named.log"
    cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
    cp "$notify_proxy_log" "$artifact_dir/notify-proxy.log"
    cp "$metrics_out" "$artifact_dir/metrics.txt"
    cp "$summary_tsv" "$artifact_dir/bind-notify-refresh-summary.tsv"
    cp "$traceability_tsv" "$artifact_dir/bind-notify-traceability.tsv"
fi

echo "BIND NOTIFY refresh interop passed"
