#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo openssl timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping BIND XoT catalog-zone Docker interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping BIND XoT catalog-zone Docker interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"
# shellcheck source=scripts/interop-dns-assertions.sh
source "$repo_root/scripts/interop-dns-assertions.sh"

run_id="$$"
workdir="$repo_root/target/interop/bind-xot-catalog-zone-docker-$run_id"
container="borondns-bind-xot-catalog-$run_id"
artifact_dir="${BORONDNS_BIND_XOT_CATALOG_DOCKER_ARTIFACT_DIR:-}"
server_name="primary.catalog.example"
tsig_name="transfer-key."
tsig_secret="dG9wc2VjcmV0"
rndc_secret="YmluZC14b3QtY2F0YWxvZw=="
rm -rf "$workdir"
mkdir -p "$workdir"
chmod 0777 "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- BIND container logs ----" >&2
            docker logs "$container" >&2 || true
            [[ -f "$workdir/borondns.log" ]] && {
                echo "---- borondns.log ----" >&2
                tail -180 "$workdir/borondns.log" >&2
            }
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r bind_plain_port bind_tls_port rndc_port borondns_dns_port borondns_health_port < <(
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

catalog_zone="$workdir/catalog.example.zone"
member_zone="$workdir/member.example.zone"
named_conf="$workdir/named.conf"
rndc_conf="$workdir/rndc.conf"
borondns_conf="$workdir/borondns.toml"
named_conf_redacted="$workdir/named.conf.redacted"
rndc_conf_redacted="$workdir/rndc.conf.redacted"
borondns_conf_redacted="$workdir/borondns.toml.redacted"
traceability_tsv="$workdir/bind-xot-catalog-zone-traceability.tsv"
summary_tsv="$workdir/bind-xot-catalog-zone-summary.tsv"
bind_image="$(ensure_alpine_bind_image)"

redact_config() {
    local src="$1"
    local dst="$2"
    sed \
        -e "s/$tsig_secret/<redacted-tsig-secret>/g" \
        -e "s/$rndc_secret/<redacted-rndc-secret>/g" \
        "$src" >"$dst"
}

write_catalog_zone() {
    local serial="$1"
    local include_member="$2"
    cat >"$catalog_zone" <<EOF
\$ORIGIN catalog.example.
\$TTL 1
@ IN SOA ns.catalog.example. hostmaster.catalog.example. (
    $serial ; serial
    1       ; refresh
    1       ; retry
    30      ; expire
    1       ; minimum
)
  IN NS ns.catalog.example.
ns IN A 127.0.0.1
version IN TXT "2"
EOF
    if [[ "$include_member" == "yes" ]]; then
        cat >>"$catalog_zone" <<'EOF'
m1.zones IN PTR member.example.
EOF
    fi
}

write_member_zone() {
    local serial="$1"
    local address="$2"
    cat >"$member_zone" <<EOF
\$ORIGIN member.example.
\$TTL 60
@ IN SOA ns.member.example. hostmaster.member.example. (
    $serial ; serial
    60      ; refresh
    30      ; retry
    300     ; expire
    60      ; minimum
)
  IN NS ns.member.example.
ns IN A 127.0.0.1
www IN A $address
txt IN TXT "bind xot catalog member fixture"
EOF
}

write_catalog_zone 2026052601 no
write_member_zone 2026052601 192.0.2.88
cp "$catalog_zone" "$workdir/catalog-initial.zone"
cp "$member_zone" "$workdir/member-initial.zone"

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
# Alpine BIND drops privileges before opening TLS material; the generated
# test-only server key must be readable by the daemon user inside the container.
chmod 0644 "$workdir/server.key"

cat >"$named_conf" <<EOF
key "rndc-key" {
    algorithm hmac-sha256;
    secret "$rndc_secret";
};

key "$tsig_name" {
    algorithm hmac-sha256;
    secret "$tsig_secret";
};

tls xot-tls {
    key-file "/work/server.key";
    cert-file "/work/server.crt";
};

controls {
    inet 127.0.0.1 port $rndc_port allow { 127.0.0.1; } keys { "rndc-key"; };
};

options {
    directory "/work";
    listen-on port 5353 { any; };
    listen-on port 853 tls xot-tls { any; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    pid-file "/work/named.pid";
    session-keyfile "/work/session.key";
};

zone "catalog.example." IN {
    type primary;
    file "/work/catalog.example.zone";
    allow-query { any; };
    allow-transfer port 853 transport tls { key "$tsig_name"; };
    notify no;
};

zone "member.example." IN {
    type primary;
    file "/work/member.example.zone";
    allow-query { any; };
    allow-transfer port 853 transport tls { key "$tsig_name"; };
    notify no;
};
EOF

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

redact_config "$named_conf" "$named_conf_redacted"
redact_config "$rndc_conf" "$rndc_conf_redacted"

set +e
bind_probe="$(
    docker run --rm \
        -v "$workdir:/work:rw" \
        "$bind_image" \
        sh -c 'named -V && named-checkconf -z /work/named.conf' \
        2>&1
)"
bind_probe_status=$?
set -e
if ((bind_probe_status != 0)); then
    if [[ "$bind_probe" == *"unknown option"* || "$bind_probe" == *"expected"* || "$bind_probe" == *"tls"* || "$bind_probe" == *"transport"* ]]; then
        echo "skipping BIND XoT catalog-zone Docker interop: packaged BIND does not accept XoT configuration" >&2
        printf '%s\n' "$bind_probe" >&2
        exit 0
    fi
    echo "BIND XoT catalog configuration probe failed" >&2
    printf '%s\n' "$bind_probe" >&2
    exit 1
fi

if ! docker run -d --name "$container" \
    -p "127.0.0.1:$bind_plain_port:5353/tcp" \
    -p "127.0.0.1:$bind_plain_port:5353/udp" \
    -p "127.0.0.1:$bind_tls_port:853/tcp" \
    -v "$workdir:/work:rw" \
    "$bind_image" \
    sh -c 'named-checkconf -z /work/named.conf && named -g -c /work/named.conf -n 1' \
    >/dev/null; then
    echo "skipping BIND XoT catalog-zone Docker interop: failed to start Alpine/BIND container" >&2
    exit 0
fi

record_docker_primary_version \
    "$workdir" \
    "$container" \
    "BIND 9" \
    "$bind_image" \
    "bind" \
    "bind-xot-catalog-zone" \
    "tls-xot-catalog-refresh" \
    "tls-alpn-dot+tsig-hmac-sha256" \
    "named -V" \
    "$named_conf_redacted" \
    "$rndc_conf_redacted" \
    "$workdir/catalog-initial.zone" \
    "$workdir/member-initial.zone"

alpn_probe=""
for _ in {1..120}; do
    if ! docker ps --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        echo "BIND XoT container exited before serving TLS" >&2
        exit 1
    fi
    alpn_probe="$(
        timeout 3 openssl s_client \
            -connect "127.0.0.1:$bind_tls_port" \
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
    echo "skipping BIND XoT catalog-zone Docker interop: BIND TLS listener did not negotiate ALPN dot" >&2
    printf '%s\n' "$alpn_probe" >&2
    exit 0
fi
printf '%s\n' "$alpn_probe" >"$workdir/alpn-probe.txt"
openssl x509 -in "$workdir/server.crt" -noout -subject -issuer -dates -ext subjectAltName \
    >"$workdir/server-certificate.txt"

set +e
dig "@127.0.0.1" \
    -p "$bind_plain_port" \
    -y "hmac-sha256:$tsig_name:$tsig_secret" \
    catalog.example. AXFR +tcp +time=2 +tries=1 >"$workdir/plain-signed-axfr.out" 2>&1
plain_status=$?
set -e
plain_axfr="$(cat "$workdir/plain-signed-axfr.out")"
if ((plain_status == 0)) && [[ "$plain_axfr" == *"version.catalog.example."* ]]; then
    echo "BIND unexpectedly allowed signed catalog AXFR on plain TCP despite transport tls policy" >&2
    exit 1
fi
sed -i "s/$tsig_secret/<redacted-tsig-secret>/g" "$workdir/plain-signed-axfr.out"

dig "@127.0.0.1" \
    -p "$bind_tls_port" \
    -y "hmac-sha256:$tsig_name:$tsig_secret" \
    +tls \
    "+tls-ca=$workdir/ca.crt" \
    "+tls-hostname=$server_name" \
    catalog.example. AXFR +tcp +time=2 +tries=1 >"$workdir/tls-signed-catalog-axfr.out"
tls_catalog_axfr="$(cat "$workdir/tls-signed-catalog-axfr.out")"
if [[ "$tls_catalog_axfr" != *"version.catalog.example."* ]] || [[ "$tls_catalog_axfr" != *'"2"'* ]]; then
    echo "BIND XoT signed catalog AXFR did not include expected fixture records" >&2
    exit 1
fi
sed -i "s/$tsig_secret/<redacted-tsig-secret>/g" "$workdir/tls-signed-catalog-axfr.out"

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
zsm_max_interval_secs = 2
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[tsig_keys]]
name = "$tsig_name"
algorithm = "hmac-sha256"
secret = "$tsig_secret"

[[catalog_zones]]
name = "catalog.example."
class = "IN"
notify_sources = ["127.0.0.1"]
tsig_key = "$tsig_name"
serve_catalog_zone = false

[[catalog_zones.transfer_primaries]]
addr = "127.0.0.1:$bind_tls_port"
transport = "xot"
server_name = "$server_name"
trust_anchors = ["$workdir/ca.crt"]
EOF
redact_config "$borondns_conf" "$borondns_conf_redacted"

cargo build -p borondns-cli >/dev/null
"$repo_root/target/debug/borondns" serve --config "$borondns_conf" >"$workdir/borondns.log" 2>&1 &
borondns_pid=$!

catalog_acquired=false
for _ in {1..120}; do
    if grep -F '"message":"AXFR completed","zone":"catalog.example."' "$workdir/borondns.log" >/dev/null 2>&1; then
        catalog_acquired=true
        break
    fi
    sleep 0.1
done
if [[ "$catalog_acquired" != "true" ]]; then
    echo "BoronDNS did not acquire the initial hidden BIND XoT catalog zone" >&2
    exit 1
fi

metrics_initial="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
printf '%s\n' "$metrics_initial" >"$workdir/metrics-initial.txt"
if [[ "$metrics_initial" != *'borondns_zone_soa_serial{zone="catalog.example."} 2026052601'* ]] ||
    [[ "$metrics_initial" != *'borondns_zones_active 0'* ]]; then
    echo "BoronDNS initial XoT metrics did not retain the hidden catalog without counting it active" >&2
    exit 1
fi

ready_status="$(curl -sS -o "$workdir/readyz-initial.json" -w '%{http_code}' "http://127.0.0.1:$borondns_health_port/readyz")"
ready="$(<"$workdir/readyz-initial.json")"
if [[ "$ready_status" != "503" || "$ready" != *'"status":"not-ready"'* ]]; then
    echo "BoronDNS became ready before the BIND XoT catalog produced an active member zone" >&2
    exit 1
fi

if ! dig_until_rcode "$workdir/catalog-hidden.out" REFUSED 20 0.1 \
    "@127.0.0.1" -p "$borondns_dns_port" version.catalog.example. TXT +norecurse +time=1 +tries=1; then
    echo "BoronDNS did not REFUSE the hidden BIND XoT catalog zone query" >&2
    exit 1
fi

if ! dig_until_rcode "$workdir/member-before.out" REFUSED 20 0.1 \
    "@127.0.0.1" -p "$borondns_dns_port" www.member.example. A +norecurse +time=1 +tries=1; then
    echo "BoronDNS did not REFUSE member.example before BIND XoT catalog assignment" >&2
    exit 1
fi

write_catalog_zone 2026052602 yes
cp "$catalog_zone" "$workdir/catalog-added.zone"
docker exec "$container" named-checkzone catalog.example. /work/catalog.example.zone >/dev/null
docker exec "$container" rndc -c /work/rndc.conf reload catalog.example. >/dev/null

member_added=""
for _ in {1..100}; do
    if member_added="$(dig "@127.0.0.1" -p "$borondns_dns_port" www.member.example. A +norecurse +time=1 +tries=1 +short)"; then
        if [[ "$member_added" == "192.0.2.88" ]]; then
            break
        fi
    fi
    sleep 0.25
done
printf '%s\n' "$member_added" >"$workdir/member-added.out"
if [[ "$member_added" != "192.0.2.88" ]]; then
    echo "BoronDNS did not serve the BIND XoT catalog-added member zone" >&2
    exit 1
fi

ready_status="$(curl -sS -o "$workdir/readyz-after-add.json" -w '%{http_code}' "http://127.0.0.1:$borondns_health_port/readyz")"
ready="$(<"$workdir/readyz-after-add.json")"
if [[ "$ready_status" != "200" || "$ready" != *'"status":"ready"'* ]]; then
    echo "BoronDNS did not become ready after the first BIND XoT catalog member became active" >&2
    exit 1
fi

metrics_after_add="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
printf '%s\n' "$metrics_after_add" >"$workdir/metrics-after-add.txt"
if [[ "$metrics_after_add" != *'borondns_zones_active 1'* ]]; then
    echo "BoronDNS XoT metrics did not count exactly one published active member after catalog add" >&2
    exit 1
fi

write_catalog_zone 2026052603 no
cp "$catalog_zone" "$workdir/catalog-removed.zone"
docker exec "$container" named-checkzone catalog.example. /work/catalog.example.zone >/dev/null
docker exec "$container" rndc -c /work/rndc.conf reload catalog.example. >/dev/null

if ! dig_until_rcode "$workdir/member-removed.out" REFUSED 100 0.25 \
    "@127.0.0.1" -p "$borondns_dns_port" www.member.example. A +norecurse +time=1 +tries=1; then
    echo "BoronDNS did not REFUSE the BIND XoT catalog member after removal" >&2
    exit 1
fi
member_removed="REFUSED"

metrics_after_remove="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
printf '%s\n' "$metrics_after_remove" >"$workdir/metrics-after-remove.txt"
if [[ "$metrics_after_remove" != *'borondns_zones_active 0'* ]]; then
    echo "BoronDNS XoT metrics after catalog removal did not return to zero published active zones" >&2
    exit 1
fi
docker logs "$container" >"$workdir/named.log" 2>&1 || true

{
    printf 'primary\ttransport\tinitial_catalog_serial\tadded_catalog_serial\tremoved_catalog_serial\tmember_added_answer\tmember_removed_answer\n'
    printf 'bind\txot+tsig\t2026052601\t2026052602\t2026052603\t%s\t%s\n' "$member_added" "${member_removed:-<empty>}"
} >"$summary_tsv"

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_method	scenario	artifacts	rationale
ODS-VER-003	retained-real-primary	bind_xot_catalog_zone	alpn-probe.txt; tls-signed-catalog-axfr.out; bind-xot-catalog-zone-summary.tsv	BIND 9 serves an RFC 9432 catalog over XoT with ALPN dot and TSIG, and BoronDNS consumes it as a secondary.
ODS-FR-XOT-008	retained-real-primary	bind_xot_catalog_tsig	plain-signed-axfr.out; tls-signed-catalog-axfr.out; borondns.toml.redacted	BIND denies plain TCP transfer while XoT+TSIG transfer succeeds and BoronDNS configures both protections.
ODS-FR-PROV-006	retained-real-primary	bind_xot_catalog_live_update	catalog-added.zone; catalog-removed.zone; member-added.out; member-removed.out	Live catalog updates from BIND are reconciled while BoronDNS remains running.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    for artifact in \
        named.conf.redacted rndc.conf.redacted borondns.toml.redacted named.log borondns.log primary-version.txt \
        alpn-probe.txt server-certificate.txt plain-signed-axfr.out tls-signed-catalog-axfr.out \
        catalog-initial.zone catalog-added.zone catalog-removed.zone member-initial.zone \
        catalog-hidden.out member-before.out member-added.out member-removed.out metrics-initial.txt metrics-after-add.txt metrics-after-remove.txt \
        readyz-initial.json readyz-after-add.json \
        bind-xot-catalog-zone-summary.tsv bind-xot-catalog-zone-traceability.tsv; do
        cp "$workdir/$artifact" "$artifact_dir/$artifact"
    done
fi

echo "BIND Docker XoT catalog-zone live interop passed"
