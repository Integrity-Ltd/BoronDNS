#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl dig; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping DNS Cookie dig interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/dns-cookie-dig-$$"
artifact_dir="${BORONDNS_DNS_COOKIE_ARTIFACT_DIR:-}"
rm -rf "$workdir"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
    fi
    if [[ -n "${primary_pid:-}" ]] && kill -0 "$primary_pid" 2>/dev/null; then
        kill "$primary_pid" 2>/dev/null || true
        wait "$primary_pid" 2>/dev/null || true
    fi
    if ((status != 0)); then
        [[ -f "$workdir/fake-primary.log" ]] && {
            echo "---- fake-primary.log ----" >&2
            tail -100 "$workdir/fake-primary.log" >&2
        }
        [[ -f "$workdir/fake-primary.stderr" ]] && {
            echo "---- fake-primary.stderr ----" >&2
            tail -100 "$workdir/fake-primary.stderr" >&2
        }
        [[ -f "$workdir/borondns.log" ]] && {
            echo "---- borondns.log ----" >&2
            tail -100 "$workdir/borondns.log" >&2
        }
        [[ -f "$workdir/no-cookie-dig.out" ]] && {
            echo "---- no-cookie-dig.out ----" >&2
            cat "$workdir/no-cookie-dig.out" >&2
        }
        [[ -f "$workdir/first-dig.out" ]] && {
            echo "---- first-dig.out ----" >&2
            cat "$workdir/first-dig.out" >&2
        }
        [[ -f "$workdir/second-dig.out" ]] && {
            echo "---- second-dig.out ----" >&2
            cat "$workdir/second-dig.out" >&2
        }
        [[ -f "$workdir/invalid-cookie-dig.out" ]] && {
            echo "---- invalid-cookie-dig.out ----" >&2
            cat "$workdir/invalid-cookie-dig.out" >&2
        }
        [[ -f "$workdir/strict-borondns.log" ]] && {
            echo "---- strict-borondns.log ----" >&2
            tail -100 "$workdir/strict-borondns.log" >&2
        }
        [[ -f "$workdir/strict-client-only-badcookie-dig.out" ]] && {
            echo "---- strict-client-only-badcookie-dig.out ----" >&2
            cat "$workdir/strict-client-only-badcookie-dig.out" >&2
        }
        [[ -f "$workdir/strict-shared-previous-cookie-dig.out" ]] && {
            echo "---- strict-shared-previous-cookie-dig.out ----" >&2
            cat "$workdir/strict-shared-previous-cookie-dig.out" >&2
        }
        [[ -f "$workdir/strict-invalid-server-cookie-badcookie-dig.out" ]] && {
            echo "---- strict-invalid-server-cookie-badcookie-dig.out ----" >&2
            cat "$workdir/strict-invalid-server-cookie-badcookie-dig.out" >&2
        }
        [[ -f "$workdir/strict-valid-server-cookie-dig.out" ]] && {
            echo "---- strict-valid-server-cookie-dig.out ----" >&2
            cat "$workdir/strict-valid-server-cookie-dig.out" >&2
        }
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

read -r primary_port borondns_dns_port borondns_health_port < <(
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

fake_primary="$workdir/fake-primary.py"
primary_log="$workdir/fake-primary.log"
borondns_conf="$workdir/borondns.toml"
strict_borondns_conf="$workdir/strict-borondns.toml"
summary_env="$workdir/dns-cookie-summary.env"
strict_summary_env="$workdir/strict-dns-cookie-summary.env"
traceability_tsv="$workdir/dns-cookie-traceability.tsv"
cookie_old_secret="00112233445566778899aabbccddeeff"
cookie_new_secret="ffeeddccbbaa99887766554433221100"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "alpha.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252


def log(message):
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_name(packet, offset):
    labels = []
    consumed = 0
    while True:
        length = packet[offset]
        offset += 1
        consumed += 1
        if length == 0:
            return ".".join(labels) + ".", consumed
        label = packet[offset:offset + length].decode("ascii")
        labels.append(label)
        offset += length
        consumed += length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass


def rr(owner, rrtype, rdata, ttl=300):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata():
    return b"".join([
        name_wire("ns1.alpha.test."),
        name_wire("hostmaster.alpha.test."),
        struct.pack("!IIIII", 2026052401, 60, 30, 300, 300),
    ])


def axfr_response(qid):
    soa = rr(ZONE, SOA, soa_rdata())
    answers = [
        soa,
        rr(ZONE, NS, name_wire("ns1.alpha.test.")),
        rr("ns1.alpha.test.", A, bytes([127, 0, 0, 1])),
        rr("www.alpha.test.", A, bytes([192, 0, 2, 10])),
        soa,
    ]
    question = name_wire(ZONE) + struct.pack("!HH", AXFR, IN)
    return struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def handle_tcp(conn):
    with conn:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
        query = read_exact(conn, length)
        qid = struct.unpack("!H", query[:2])[0]
        qname, qtype, qclass = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 0, 0, 0, 0)
        else:
            log("TCP AXFR served")
            response = axfr_response(qid)
        conn.sendall(struct.pack("!H", len(response)) + response)


def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()
    log(f"READY port={PORT}")
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY

cat >"$borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "debug"

[cookie]
policy = "lenient"
server_secret = "$cookie_old_secret"

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

python3 "$fake_primary" "$primary_port" "$primary_log" >"$workdir/fake-primary.stderr" 2>&1 &
primary_pid=$!

for _ in {1..50}; do
    if grep -q READY "$primary_log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

cargo build -p borondns-cli >/dev/null
"$repo_root/target/debug/borondns" serve --config "$borondns_conf" >"$workdir/borondns.log" 2>&1 &
borondns_pid=$!

ready=""
for _ in {1..100}; do
    if ready="$(curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != *'"status":"ready"'* ]]; then
    echo "BoronDNS did not become ready after fake-primary AXFR" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse +nocookie +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/no-cookie-dig.out"

if ! grep -q "www.alpha.test." "$workdir/no-cookie-dig.out" || ! grep -q "192.0.2.10" "$workdir/no-cookie-dig.out"; then
    echo "dig +nocookie did not receive expected answer from BoronDNS" >&2
    exit 1
fi

if grep -q "COOKIE:" "$workdir/no-cookie-dig.out"; then
    echo "BoronDNS included a COOKIE option in a no-cookie response" >&2
    exit 1
fi

client_cookie="0102030405060708"
dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$client_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/first-dig.out"

if ! grep -q "www.alpha.test." "$workdir/first-dig.out" || ! grep -q "192.0.2.10" "$workdir/first-dig.out"; then
    echo "dig +cookie did not receive expected answer from BoronDNS" >&2
    exit 1
fi

response_cookie="$(awk '/COOKIE:/ {print $3; exit}' "$workdir/first-dig.out")"
if [[ ! "$response_cookie" =~ ^${client_cookie}[0-9a-fA-F]{32}$ ]]; then
    echo "BoronDNS response did not contain echoed client cookie plus RFC9018 server cookie" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$response_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/second-dig.out"

if ! grep -q "www.alpha.test." "$workdir/second-dig.out" || ! grep -q "192.0.2.10" "$workdir/second-dig.out"; then
    echo "dig valid-server-cookie retry did not receive expected answer from BoronDNS" >&2
    exit 1
fi

invalid_response_cookie="${client_cookie}0000000000000000"
dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$invalid_response_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/invalid-cookie-dig.out"

if ! grep -q "www.alpha.test." "$workdir/invalid-cookie-dig.out" || ! grep -q "192.0.2.10" "$workdir/invalid-cookie-dig.out"; then
    echo "dig invalid-server-cookie query did not receive expected lenient answer from BoronDNS" >&2
    exit 1
fi

invalid_retry_cookie="$(awk '/COOKIE:/ {print $3; exit}' "$workdir/invalid-cookie-dig.out")"
if [[ ! "$invalid_retry_cookie" =~ ^${client_cookie}[0-9a-fA-F]{32}$ ]]; then
    echo "BoronDNS invalid-server-cookie response did not contain a refreshed RFC9018 server cookie" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
for expected in \
    'borondns_dns_cookie_queries_total{case="no_cookie"} 1' \
    'borondns_dns_cookie_queries_total{case="client_only"} 1' \
    'borondns_dns_cookie_queries_total{case="valid_server"} 1' \
    'borondns_dns_cookie_queries_total{case="invalid_server"} 1' \
    'borondns_dns_cookie_queries_by_prefix_total{source_prefix="127.0.0.0/24",case="no_cookie"} 1' \
    'borondns_dns_cookie_queries_by_prefix_total{source_prefix="127.0.0.0/24",case="client_only"} 1' \
    'borondns_dns_cookie_queries_by_prefix_total{source_prefix="127.0.0.0/24",case="valid_server"} 1' \
    'borondns_dns_cookie_queries_by_prefix_total{source_prefix="127.0.0.0/24",case="invalid_server"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        printf 'missing expected metric: %s\n' "$expected" >&2
        exit 1
    fi
done

if ! grep -q "DNS Cookie shared Server Secret configured" "$workdir/borondns.log"; then
    echo "BoronDNS log did not record configured DNS Cookie startup fingerprint event" >&2
    exit 1
fi

kill "$borondns_pid" 2>/dev/null || true
wait "$borondns_pid" 2>/dev/null || true
borondns_pid=""

cat >"$strict_borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "debug"

[cookie]
policy = "strict"
server_secret = "$cookie_new_secret"
previous_server_secret = "$cookie_old_secret"

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

"$repo_root/target/debug/borondns" serve --config "$strict_borondns_conf" >"$workdir/strict-borondns.log" 2>&1 &
borondns_pid=$!

ready=""
for _ in {1..100}; do
    if ready="$(curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != *'"status":"ready"'* ]]; then
    echo "strict BoronDNS did not become ready after fake-primary AXFR" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$response_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/strict-shared-previous-cookie-dig.out"

if ! grep -q "www.alpha.test." "$workdir/strict-shared-previous-cookie-dig.out" || ! grep -q "192.0.2.10" "$workdir/strict-shared-previous-cookie-dig.out"; then
    echo "strict staged-rollover instance did not accept server cookie from previous shared secret" >&2
    exit 1
fi

strict_shared_response_cookie="$(awk '/COOKIE:/ {print $3; exit}' "$workdir/strict-shared-previous-cookie-dig.out")"
if [[ ! "$strict_shared_response_cookie" =~ ^${client_cookie}[0-9a-fA-F]{32}$ ]]; then
    echo "strict staged-rollover response did not contain a refreshed server cookie" >&2
    exit 1
fi
if [[ "$strict_shared_response_cookie" == "$response_cookie" ]]; then
    echo "strict staged-rollover response did not refresh the previous-secret cookie with the current shared secret" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$client_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/strict-client-only-badcookie-dig.out"

if ! grep -q "BADCOOKIE" "$workdir/strict-client-only-badcookie-dig.out"; then
    echo "strict client-only cookie query did not receive BADCOOKIE" >&2
    exit 1
fi

strict_response_cookie="$(awk '/COOKIE:/ {print $3; exit}' "$workdir/strict-client-only-badcookie-dig.out")"
if [[ ! "$strict_response_cookie" =~ ^${client_cookie}[0-9a-fA-F]{32}$ ]]; then
    echo "strict BADCOOKIE response did not contain a retry server cookie" >&2
    exit 1
fi

strict_invalid_response_cookie="${client_cookie}0000000000000000"
dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$strict_invalid_response_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/strict-invalid-server-cookie-badcookie-dig.out"

if ! grep -q "BADCOOKIE" "$workdir/strict-invalid-server-cookie-badcookie-dig.out"; then
    echo "strict invalid-server-cookie query did not receive BADCOOKIE" >&2
    exit 1
fi

strict_invalid_retry_cookie="$(awk '/COOKIE:/ {print $3; exit}' "$workdir/strict-invalid-server-cookie-badcookie-dig.out")"
if [[ ! "$strict_invalid_retry_cookie" =~ ^${client_cookie}[0-9a-fA-F]{32}$ ]]; then
    echo "strict invalid-server-cookie BADCOOKIE response did not contain a retry server cookie" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A \
    +norecurse "+cookie=$strict_response_cookie" +noall +comments +answer +time=1 +tries=1 \
    >"$workdir/strict-valid-server-cookie-dig.out"

if ! grep -q "www.alpha.test." "$workdir/strict-valid-server-cookie-dig.out" || ! grep -q "192.0.2.10" "$workdir/strict-valid-server-cookie-dig.out"; then
    echo "strict valid-server-cookie retry did not receive expected answer from BoronDNS" >&2
    exit 1
fi

strict_metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
for expected in \
    'borondns_dns_cookie_queries_total{case="client_only"} 1' \
    'borondns_dns_cookie_queries_total{case="valid_server"} 4' \
    'borondns_dns_cookie_queries_total{case="invalid_server"} 1' \
    'borondns_dns_cookie_badcookie_responses_total 2' \
    'borondns_dns_cookie_badcookie_responses_by_prefix_total{source_prefix="127.0.0.0/24"} 2'; do
    if [[ "$strict_metrics" != *"$expected"* ]]; then
        printf 'strict metrics missing expected line: %s\n' "$expected" >&2
        exit 1
    fi
done

if ! grep -q "DNS Cookie BADCOOKIE response emitted" "$workdir/strict-borondns.log"; then
    echo "strict BoronDNS log did not record BADCOOKIE emission" >&2
    exit 1
fi

cat >"$summary_env" <<EOF
client_cookie=$client_cookie
response_cookie_bytes=$((${#response_cookie} / 2))
no_cookie_response=1
client_only_cookie_response=1
valid_server_cookie_response=1
invalid_server_cookie_lenient_response=1
EOF

cat >"$strict_summary_env" <<EOF
client_cookie=$client_cookie
strict_response_cookie_bytes=$((${#strict_response_cookie} / 2))
strict_shared_previous_cookie_accepted=1
strict_shared_previous_response_cookie_bytes=$((${#strict_shared_response_cookie} / 2))
strict_client_only_badcookie=1
strict_invalid_server_cookie_badcookie=1
strict_valid_server_cookie_response=1
strict_valid_server_cookie_metric_count=4
strict_badcookie_metric_count=2
EOF

cat >"$traceability_tsv" <<EOF
requirement	artifact	evidence
ODS-FR-COOKIE-003	no-cookie-dig.out	no COOKIE option emitted when client omits COOKIE
ODS-FR-COOKIE-004	first-dig.out	client-cookie-only query receives RFC9018 server cookie
ODS-FR-COOKIE-005	second-dig.out	valid server-cookie retry receives authoritative answer
ODS-FR-COOKIE-004	strict-shared-previous-cookie-dig.out	staged rollover instance accepts a Server Cookie produced by another instance with the previous configured shared secret and refreshes it with the current secret
ODS-FR-COOKIE-006	invalid-cookie-dig.out	lenient invalid-server-cookie query receives answer plus refreshed cookie
ODS-FR-COOKIE-006	strict-client-only-badcookie-dig.out	strict client-cookie-only query receives BADCOOKIE plus retry cookie
ODS-FR-COOKIE-006	strict-invalid-server-cookie-badcookie-dig.out	strict invalid-server-cookie query receives BADCOOKIE plus retry cookie
ODS-FR-COOKIE-008	borondns.toml; strict-borondns.toml	lenient and strict cookie policies configured through static TOML
ODS-FR-COOKIE-010	borondns.log; strict-borondns.log	startup fingerprint and BADCOOKIE emission logs retained
ODS-FR-COOKIE-011	metrics.txt; strict-metrics.txt	global and source-prefix cookie metrics retained
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$workdir/fake-primary.stderr" "$artifact_dir/fake-primary.stderr"
    cp "$workdir/borondns.log" "$artifact_dir/borondns.log"
    cp "$borondns_conf" "$artifact_dir/borondns.toml"
    cp "$workdir/strict-borondns.log" "$artifact_dir/strict-borondns.log"
    cp "$strict_borondns_conf" "$artifact_dir/strict-borondns.toml"
    cp "$workdir/no-cookie-dig.out" "$artifact_dir/no-cookie-dig.out"
    cp "$workdir/first-dig.out" "$artifact_dir/first-dig.out"
    cp "$workdir/second-dig.out" "$artifact_dir/second-dig.out"
    cp "$workdir/invalid-cookie-dig.out" "$artifact_dir/invalid-cookie-dig.out"
    cp "$workdir/strict-client-only-badcookie-dig.out" "$artifact_dir/strict-client-only-badcookie-dig.out"
    cp "$workdir/strict-shared-previous-cookie-dig.out" "$artifact_dir/strict-shared-previous-cookie-dig.out"
    cp "$workdir/strict-invalid-server-cookie-badcookie-dig.out" "$artifact_dir/strict-invalid-server-cookie-badcookie-dig.out"
    cp "$workdir/strict-valid-server-cookie-dig.out" "$artifact_dir/strict-valid-server-cookie-dig.out"
    cp "$summary_env" "$artifact_dir/dns-cookie-summary.env"
    cp "$strict_summary_env" "$artifact_dir/strict-dns-cookie-summary.env"
    cp "$traceability_tsv" "$artifact_dir/dns-cookie-traceability.tsv"
    printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
    printf '%s\n' "$strict_metrics" >"$artifact_dir/strict-metrics.txt"
fi

printf 'DNS Cookie dig interop passed response_cookie_bytes=%s cases=no_cookie,client_only,valid_server,invalid_server shared_previous_rollover=1 strict_badcookie=2\n' "$((${#response_cookie} / 2))"
