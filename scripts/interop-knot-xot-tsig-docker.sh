#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo openssl timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping Knot XoT+TSIG Docker interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping Knot XoT+TSIG Docker interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"
zone_file="$repo_root/tests/interop/bind/alpha.test.zone"
tsig_secret="dG9wc2VjcmV0"
workdir="$repo_root/target/interop/knot-xot-tsig-$$"
container="borondns-knot-xot-tsig-$$"
server_name="primary.alpha.test"
artifact_dir="${BORONDNS_KNOT_XOT_TSIG_ARTIFACT_DIR:-}"
traceability_tsv="$workdir/knot-xot-tsig-traceability.tsv"
knot_conf_redacted="$workdir/knot.conf.redacted"
knot_image="$(ensure_alpine_knot_image)"
rm -rf "$workdir"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
    fi
    if ((status != 0)) && [[ -f "$workdir/borondns.log" ]]; then
        echo "---- borondns log ----" >&2
        sed -n '1,220p' "$workdir/borondns.log" >&2 || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- knot container logs ----" >&2
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r knot_tls_port borondns_dns_port borondns_health_port < <(
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

cp "$zone_file" "$workdir/alpha.test.zone"

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 2 \
    -subj "/CN=BoronDNS test CA" \
    -keyout "$workdir/ca.key" \
    -out "$workdir/ca.crt" \
    >/dev/null 2>&1

openssl req \
    -newkey rsa:2048 \
    -nodes \
    -subj "/CN=$server_name" \
    -keyout "$workdir/server.key" \
    -out "$workdir/server.csr" \
    >/dev/null 2>&1

cat >"$workdir/server.ext" <<EOF
subjectAltName=DNS:$server_name
extendedKeyUsage=serverAuth
EOF

openssl x509 \
    -req \
    -in "$workdir/server.csr" \
    -CA "$workdir/ca.crt" \
    -CAkey "$workdir/ca.key" \
    -CAcreateserial \
    -days 2 \
    -out "$workdir/server.crt" \
    -extfile "$workdir/server.ext" \
    >/dev/null 2>&1

chmod 0644 "$workdir/ca.crt" "$workdir/server.crt"
chmod 0600 "$workdir/ca.key" "$workdir/server.key"

cat >"$workdir/knot.conf" <<EOF
server:
    rundir: "/tmp"
    listen-tls: 0.0.0.0@853
    cert-file: "/work/server.crt"
    key-file: "/work/server.key"
    user: root:root

log:
  - target: stderr
    any: info

database:
    storage: "/tmp/knot-db"

template:
  - id: default
    storage: "/work"
    file: "%s.zone"

key:
  - id: transfer-key.
    algorithm: hmac-sha256
    secret: $tsig_secret

acl:
  - id: transfer_acl
    key: transfer-key.
    action: transfer

zone:
  - domain: alpha.test.
    acl: transfer_acl
EOF
sed "s/$tsig_secret/<redacted-tsig-secret>/g" "$workdir/knot.conf" >"$knot_conf_redacted"

set +e
knot_probe="$(
    docker run --rm \
        -v "$workdir:/work:ro" \
        "$knot_image" \
        sh -c 'knotd -V && knotc -c /work/knot.conf conf-check' \
        2>&1
)"
knot_probe_status=$?
set -e

if ((knot_probe_status != 0)); then
    if [[ "$knot_probe" == *"listen-tls"* ]] || [[ "$knot_probe" == *"cert-file"* ]] || [[ "$knot_probe" == *"key-file"* ]] || [[ "$knot_probe" == *"unknown"* ]]; then
        echo "skipping Knot XoT+TSIG Docker interop: Alpine/Knot package does not accept TLS/XoT server configuration" >&2
        printf '%s\n' "$knot_probe" >&2
        exit 0
    fi
    echo "Knot XoT+TSIG configuration probe failed" >&2
    printf '%s\n' "$knot_probe" >&2
    exit 1
fi

if ! docker run -d --name "$container" \
    -p "127.0.0.1:$knot_tls_port:853/tcp" \
    -v "$workdir:/work:ro" \
    "$knot_image" \
    sh -c 'mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check && knotd -c /work/knot.conf -v' \
    >/dev/null; then
    echo "skipping Knot XoT+TSIG Docker interop: failed to start Alpine/Knot container" >&2
    exit 0
fi
record_docker_primary_version "$workdir" "$container" "Knot DNS" "$knot_image" "knot" "knot-xot-tsig" "tls-xot-axfr" "tls-alpn-dot+tsig-hmac-sha256" "knotd -V" "$knot_conf_redacted" "$zone_file"

alpn_probe=""
for _ in {1..120}; do
    if ! docker ps --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        echo "Knot XoT+TSIG container exited before serving TLS" >&2
        exit 1
    fi
    alpn_probe="$(
        timeout 3 openssl s_client \
            -connect "127.0.0.1:$knot_tls_port" \
            -servername "$server_name" \
            -alpn dot \
            -CAfile "$workdir/ca.crt" \
            </dev/null 2>&1 || true
    )"
    if [[ "$alpn_probe" == *"ALPN protocol: dot"* ]]; then
        break
    fi
    sleep 0.25
done

if [[ "$alpn_probe" != *"ALPN protocol: dot"* ]]; then
    echo "skipping Knot XoT+TSIG Docker interop: Knot TLS listener did not negotiate ALPN dot" >&2
    printf '%s\n' "$alpn_probe" >&2
    exit 0
fi
printf '%s\n' "$alpn_probe" >"$workdir/alpn-probe.txt"
openssl x509 -in "$workdir/server.crt" -noout -subject -issuer -dates -ext subjectAltName \
    >"$workdir/server-certificate.txt"

set +e
dig "@127.0.0.1" \
    -p "$knot_tls_port" \
    +tls \
    "+tls-ca=$workdir/ca.crt" \
    "+tls-hostname=$server_name" \
    alpha.test. AXFR +nocmd +time=2 +tries=1 >"$workdir/unsigned-xot-axfr.out" 2>&1
unsigned_status=$?
set -e
unsigned_axfr="$(cat "$workdir/unsigned-xot-axfr.out")"
if ((unsigned_status == 0)) && [[ "$unsigned_axfr" == *"www.alpha.test."* ]]; then
    echo "Knot XoT+TSIG primary unexpectedly allowed unsigned XoT AXFR" >&2
    exit 1
fi

dig "@127.0.0.1" \
    -p "$knot_tls_port" \
    -y "hmac-sha256:transfer-key.:$tsig_secret" \
    +tls \
    "+tls-ca=$workdir/ca.crt" \
    "+tls-hostname=$server_name" \
    alpha.test. AXFR +nocmd +time=2 +tries=1 >"$workdir/signed-xot-axfr.out"
signed_axfr="$(cat "$workdir/signed-xot-axfr.out")"
if [[ "$signed_axfr" != *"www.alpha.test."* ]] || [[ "$signed_axfr" != *"alias.alpha.test."* ]]; then
    echo "Knot XoT+TSIG primary signed XoT AXFR did not include expected fixture records" >&2
    exit 1
fi

borondns_conf="$workdir/borondns.toml"
cat >"$borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "info"

[rrl]
enabled = false

[limits]
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret = "$tsig_secret"

[[zones]]
name = "alpha.test."
class = "IN"
notify_sources = ["127.0.0.1"]
tsig_key = "transfer-key."

[[zones.transfer_primaries]]
addr = "127.0.0.1:$knot_tls_port"
transport = "xot"
server_name = "$server_name"
trust_anchors = ["$workdir/ca.crt"]
EOF

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

printf '%s\n' "$ready" >"$workdir/readyz.json"
if [[ "$ready" != *'"status":"ready"'* ]]; then
    echo "BoronDNS did not become ready after Knot XoT+TSIG AXFR" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" www.alpha.test. A +norecurse +noall +answer \
    >"$workdir/borondns-answer-a.out"
answer_a="$(cat "$workdir/borondns-answer-a.out")"
if [[ "$answer_a" != *"www.alpha.test."* ]] || [[ "$answer_a" != *"192.0.2.10"* ]]; then
    echo "BoronDNS did not serve expected A response after Knot XoT+TSIG AXFR" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" alias.alpha.test. A +norecurse +noall +answer \
    >"$workdir/borondns-answer-cname.out"
answer_cname="$(cat "$workdir/borondns-answer-cname.out")"
if [[ "$answer_cname" != *"alias.alpha.test."* ]] || [[ "$answer_cname" != *"www.alpha.test."* ]] || [[ "$answer_cname" != *"192.0.2.10"* ]]; then
    echo "BoronDNS did not serve expected CNAME-chain response after Knot XoT+TSIG AXFR" >&2
    exit 1
fi

dig "@127.0.0.1" -p "$borondns_dns_port" alpha.test. SOA +tcp +time=1 +tries=1 +short \
    >"$workdir/borondns-tcp-soa.out"
tcp_soa="$(cat "$workdir/borondns-tcp-soa.out")"
if [[ "$tcp_soa" != *"2026052401"* ]]; then
    echo "BoronDNS did not serve expected TCP SOA response after Knot XoT+TSIG AXFR" >&2
    exit 1
fi

metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
printf '%s\n' "$metrics" >"$workdir/metrics.txt"
for expected in \
    'borondns_zones_active 1' \
    'borondns_zone_soa_serial{zone="alpha.test."} 2026052401' \
    'borondns_transfer_sessions_started_total{protocol="axfr"} 1' \
    'borondns_transfer_sessions_completed_total{protocol="axfr"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "BoronDNS metrics missing expected line after Knot XoT+TSIG AXFR: $expected" >&2
        exit 1
    fi
done

if grep -E 'ConnectTcp|TlsHandshake|XotAlpn|did not negotiate ALPN dot' "$workdir/borondns.log" >/dev/null 2>&1; then
    echo "BoronDNS log contains an XoT connection failure" >&2
    exit 1
fi

if grep -F "$tsig_secret" "$workdir/borondns.log" >/dev/null 2>&1; then
    echo "BoronDNS log leaked TSIG secret" >&2
    exit 1
fi

if grep -E 'BEGIN .*PRIVATE KEY|master secret|traffic secret|session key' "$workdir/borondns.log" >/dev/null 2>&1; then
    echo "BoronDNS log leaked TLS key material" >&2
    exit 1
fi

for expected_log in \
    'xot_tls_session_established' \
    'tls_version' \
    'cipher_suite' \
    'xot_tls_session_closed' \
    'bytes_in' \
    'bytes_out'; do
    if ! grep -F "$expected_log" "$workdir/borondns.log" >/dev/null 2>&1; then
        echo "BoronDNS XoT+TSIG log missing expected field or event: $expected_log" >&2
        exit 1
    fi
done

cat >"$workdir/knot-xot-tsig-summary.env" <<EOF
alpn_dot_negotiated=1
unsigned_xot_axfr_rejected=1
signed_xot_axfr_succeeded=1
borondns_ready_after_xot_tsig_axfr=1
borondns_served_transferred_a=1
borondns_served_transferred_cname=1
borondns_served_transferred_tcp_soa=1
borondns_transfer_metrics_checked=1
borondns_xot_failure_absence_checked=1
borondns_xot_established_log_checked=1
borondns_xot_closed_log_checked=1
tsig_secret_redaction_checked=1
borondns_tls_key_material_absence_checked=1
EOF

cat >"$traceability_tsv" <<'EOF'
requirement	status	case	artifacts	note
ODS-FR-XOT-001	retained-real-primary	knot_xot_tsig_axfr_tls	primary-version.txt; alpn-probe.txt; borondns.log; knot-xot-tsig-summary.env	BoronDNS successfully transfers TSIG-authenticated AXFR over TLS from a real Knot primary; logs retain negotiated TLS version and cipher-suite fields for release review.
ODS-FR-XOT-002	retained-real-primary	knot_xot_tsig_cipher_observed	borondns.log; alpn-probe.txt	The BoronDNS XoT+TSIG session log records the negotiated cipher suite; broader prohibited-suite rejection remains covered by release TLS-matrix review.
ODS-FR-XOT-003	retained-real-primary	knot_xot_tsig_port_override	borondns.toml.redacted; primary-version.txt	The primary uses an explicit per-primary XoT port override in configuration rather than cleartext TCP.
ODS-FR-XOT-004	retained-real-primary	knot_xot_tsig_alpn_dot	alpn-probe.txt; borondns.log; knot-xot-tsig-summary.env	Knot and BoronDNS negotiate ALPN dot; missing-ALPN abort behavior remains covered by focused tests.
ODS-FR-XOT-005	retained-real-primary	knot_xot_tsig_certificate_validation	server-certificate.txt; ca.crt; borondns.toml.redacted; readyz.json	BoronDNS trusts the configured CA and validates the SAN/SNI-bound real-primary certificate before publishing the transferred zone.
ODS-FR-XOT-006	retained-real-primary	knot_xot_tsig_no_cleartext_fallback	borondns.log; metrics.txt; knot-xot-tsig-summary.env	The retained log has no XoT connection or TLS failure markers and transfer metrics show the TLS AXFR completed without cleartext fallback.
ODS-FR-XOT-008	retained-real-primary	knot_xot_tsig_required	unsigned-xot-axfr.out; signed-xot-axfr.out; knot-xot-tsig-summary.env	The real primary rejects unsigned XoT AXFR and accepts HMAC-SHA256 TSIG over XoT; retained BoronDNS artifacts prove publication from the signed transfer.
ODS-FR-XOT-011	retained-real-primary	knot_xot_tsig_session_logging	borondns.log; knot-xot-tsig-summary.env	BoronDNS logs XoT TLS session establishment with version/cipher and session close with byte counters while retaining TLS key-material and TSIG-secret redaction evidence.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$workdir/primary-version.txt" "$artifact_dir/primary-version.txt"
    cp "$knot_conf_redacted" "$artifact_dir/knot.conf.redacted"
    sed "s/$tsig_secret/<redacted-tsig-secret>/g" "$borondns_conf" >"$artifact_dir/borondns.toml.redacted"
    cp "$workdir/alpha.test.zone" "$artifact_dir/alpha.test.zone"
    cp "$workdir/ca.crt" "$artifact_dir/ca.crt"
    cp "$workdir/server.crt" "$artifact_dir/server.crt"
    cp "$workdir/server-certificate.txt" "$artifact_dir/server-certificate.txt"
    cp "$workdir/alpn-probe.txt" "$artifact_dir/alpn-probe.txt"
    cp "$workdir/borondns.log" "$artifact_dir/borondns.log"
    cp "$workdir/readyz.json" "$artifact_dir/readyz.json"
    cp "$workdir/metrics.txt" "$artifact_dir/metrics.txt"
    cp "$workdir/unsigned-xot-axfr.out" "$artifact_dir/unsigned-xot-axfr.out"
    cp "$workdir/signed-xot-axfr.out" "$artifact_dir/signed-xot-axfr.out"
    cp "$workdir/borondns-answer-a.out" "$artifact_dir/borondns-answer-a.out"
    cp "$workdir/borondns-answer-cname.out" "$artifact_dir/borondns-answer-cname.out"
    cp "$workdir/borondns-tcp-soa.out" "$artifact_dir/borondns-tcp-soa.out"
    cp "$workdir/knot-xot-tsig-summary.env" "$artifact_dir/knot-xot-tsig-summary.env"
    cp "$traceability_tsv" "$artifact_dir/knot-xot-tsig-traceability.tsv"
fi

echo "Knot Docker XoT+TSIG AXFR interop passed"
