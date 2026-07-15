#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping BIND catalog-zone Docker interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping BIND catalog-zone Docker interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"
# shellcheck source=scripts/interop-dns-assertions.sh
source "$repo_root/scripts/interop-dns-assertions.sh"

workdir="$repo_root/target/interop/bind-catalog-zone-docker-$$"
container="oxidedns-bind-catalog-$$"
artifact_dir="${OXIDEDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR:-}"
rm -rf "$workdir"
mkdir -p "$workdir"
chmod 0777 "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- BIND container logs ----" >&2
            docker logs "$container" >&2 || true
            [[ -f "$workdir/oxidedns.log" ]] && {
                echo "---- oxidedns.log ----" >&2
                tail -160 "$workdir/oxidedns.log" >&2
            }
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r bind_port rndc_port oxidedns_dns_port oxidedns_health_port < <(
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

rndc_secret="Y2F0YWxvZy1pbnRlcm9wLXNlY3JldA=="
tsig_name="transfer-key."
tsig_secret="dG9wc2VjcmV0"
catalog_zone="$workdir/catalog.example.zone"
member_zone="$workdir/member.example.zone"
named_conf="$workdir/named.conf"
rndc_conf="$workdir/rndc.conf"
oxidedns_conf="$workdir/oxidedns.toml"
summary_tsv="$workdir/bind-catalog-zone-summary.tsv"
traceability_tsv="$workdir/bind-catalog-zone-traceability.tsv"
catalog_hidden_out="$workdir/catalog-hidden.out"
member_added_out="$workdir/member-added.out"
member_removed_out="$workdir/member-removed.out"
metrics_initial_out="$workdir/metrics-initial.txt"
metrics_after_add_out="$workdir/metrics-after-add.txt"
metrics_after_remove_out="$workdir/metrics-after-remove.txt"
readyz_initial_out="$workdir/readyz-initial.json"
readyz_after_add_out="$workdir/readyz-after-add.json"
bind_image="$(ensure_alpine_bind_image)"

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
txt IN TXT "catalog member fixture"
EOF
}

write_catalog_zone 2026052501 no
write_member_zone 2026052501 192.0.2.77
cp "$catalog_zone" "$workdir/catalog-initial.zone"
cp "$member_zone" "$workdir/member-initial.zone"

cat >"$named_conf" <<EOF
key "rndc-key" {
    algorithm hmac-sha256;
    secret "$rndc_secret";
};

key "$tsig_name" {
    algorithm hmac-sha256;
    secret "$tsig_secret";
};

controls {
    inet 127.0.0.1 port $rndc_port allow { 127.0.0.1; } keys { "rndc-key"; };
};

options {
    directory "/work";
    listen-on port 5353 { any; };
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
    allow-transfer { key "$tsig_name"; };
    notify no;
};

zone "member.example." IN {
    type primary;
    file "/work/member.example.zone";
    allow-query { any; };
    allow-transfer { key "$tsig_name"; };
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

if ! docker run -d --name "$container" \
    -p "127.0.0.1:$bind_port:5353/tcp" \
    -p "127.0.0.1:$bind_port:5353/udp" \
    -v "$workdir:/work:rw" \
    "$bind_image" \
    sh -c 'named-checkconf -z /work/named.conf && named -g -c /work/named.conf -n 1' \
    >/dev/null; then
    echo "skipping BIND catalog-zone Docker interop: failed to start Alpine/BIND container" >&2
    exit 0
fi

record_docker_primary_version \
    "$workdir" \
    "$container" \
    "BIND 9" \
    "$bind_image" \
    "bind" \
    "bind-docker-catalog-zone" \
    "tcp-axfr+catalog-refresh" \
    "none" \
    "named -V" \
    "$named_conf" \
    "$rndc_conf" \
    "$workdir/catalog-initial.zone" \
    "$workdir/member-initial.zone"

for _ in {1..120}; do
    if dig "@127.0.0.1" -p "$bind_port" catalog.example. SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

primary_catalog_soa="$(dig "@127.0.0.1" -p "$bind_port" catalog.example. SOA +tcp +time=1 +tries=1 +short)"
if [[ "$primary_catalog_soa" != *"2026052501"* ]]; then
    echo "BIND catalog primary did not answer initial catalog SOA serial" >&2
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
zsm_max_interval_secs = 2
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[catalog_zones]]
name = "catalog.example."
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

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

catalog_acquired=false
for _ in {1..120}; do
    if grep -F '"message":"AXFR completed","zone":"catalog.example."' "$workdir/oxidedns.log" >/dev/null 2>&1; then
        catalog_acquired=true
        break
    fi
    sleep 0.1
done
if [[ "$catalog_acquired" != "true" ]]; then
    echo "OxideDNS did not acquire the initial hidden catalog zone" >&2
    exit 1
fi

metrics_initial="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics_initial" >"$metrics_initial_out"
if [[ "$metrics_initial" != *'oxidedns_zone_soa_serial{zone="catalog.example."} 2026052501'* ]] ||
    [[ "$metrics_initial" != *'oxidedns_zones_active 0'* ]]; then
    echo "OxideDNS initial metrics did not retain the hidden catalog without counting it active" >&2
    exit 1
fi

ready_status="$(curl -sS -o "$readyz_initial_out" -w '%{http_code}' "http://127.0.0.1:$oxidedns_health_port/readyz")"
ready="$(<"$readyz_initial_out")"
if [[ "$ready_status" != "503" || "$ready" != *'"status":"not-ready"'* ]]; then
    echo "OxideDNS became ready before the catalog produced an active member zone" >&2
    exit 1
fi

if ! dig_until_rcode "$catalog_hidden_out" REFUSED 20 0.1 \
    "@127.0.0.1" -p "$oxidedns_dns_port" version.catalog.example. TXT +norecurse +time=1 +tries=1; then
    echo "OxideDNS did not REFUSE the hidden catalog zone query" >&2
    exit 1
fi

member_before_out="$workdir/member-before.out"
if ! dig_until_rcode "$member_before_out" REFUSED 20 0.1 \
    "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1; then
    echo "OxideDNS did not REFUSE member.example before the catalog listed it" >&2
    exit 1
fi

write_catalog_zone 2026052502 yes
cp "$catalog_zone" "$workdir/catalog-added.zone"
docker exec "$container" named-checkzone catalog.example. /work/catalog.example.zone >/dev/null
docker exec "$container" rndc -c /work/rndc.conf reload catalog.example. >/dev/null

member_added=""
for _ in {1..80}; do
    if member_added="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1 +short)"; then
        if [[ "$member_added" == "192.0.2.77" ]]; then
            break
        fi
    fi
    sleep 0.25
done
printf '%s\n' "$member_added" >"$member_added_out"
if [[ "$member_added" != "192.0.2.77" ]]; then
    echo "OxideDNS did not serve the catalog-added member zone" >&2
    exit 1
fi

ready_status="$(curl -sS -o "$readyz_after_add_out" -w '%{http_code}' "http://127.0.0.1:$oxidedns_health_port/readyz")"
ready="$(<"$readyz_after_add_out")"
if [[ "$ready_status" != "200" || "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after the first catalog member became active" >&2
    exit 1
fi

metrics_after_add="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics_after_add" >"$metrics_after_add_out"
for expected in \
    'oxidedns_zones_active 1' \
    'oxidedns_zone_soa_serial{zone="catalog.example."} 2026052502' \
    'oxidedns_zone_soa_serial{zone="member.example."} 2026052501'; do
    if [[ "$metrics_after_add" != *"$expected"* ]]; then
        echo "OxideDNS metrics after catalog add missing expected line: $expected" >&2
        exit 1
    fi
done

write_catalog_zone 2026052503 no
cp "$catalog_zone" "$workdir/catalog-removed.zone"
docker exec "$container" named-checkzone catalog.example. /work/catalog.example.zone >/dev/null
docker exec "$container" rndc -c /work/rndc.conf reload catalog.example. >/dev/null

if ! dig_until_rcode "$member_removed_out" REFUSED 80 0.25 \
    "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1; then
    echo "OxideDNS did not REFUSE the member zone after catalog removal" >&2
    exit 1
fi
member_removed="REFUSED"

metrics_after_remove="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics_after_remove" >"$metrics_after_remove_out"
if [[ "$metrics_after_remove" != *'oxidedns_zones_active 0'* ]]; then
    echo "OxideDNS metrics after catalog removal did not return to zero published active zones" >&2
    exit 1
fi
if [[ "$metrics_after_remove" == *'oxidedns_zone_soa_serial{zone="member.example."}'* ]]; then
    echo "OxideDNS metrics still reported the removed catalog member zone" >&2
    exit 1
fi

docker logs "$container" >"$workdir/named.log" 2>&1 || true

{
    printf 'primary\tinitial_catalog_serial\tadded_catalog_serial\tremoved_catalog_serial\tmember_added_answer\tmember_removed_answer\n'
    printf 'bind\t2026052501\t2026052502\t2026052503\t%s\t%s\n' "$member_added" "${member_removed:-<empty>}"
} >"$summary_tsv"

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_method	scenario	artifacts	rationale
RFC9432-CATALOG-MVP-001	retained-real-primary	bind_catalog_transfer	catalog-initial.zone; primary-version.txt; metrics-initial.txt; readyz-initial.json	OxideDNS transfers a real BIND-served RFC 9432 catalog zone and records the catalog SOA serial while remaining not-ready until a published member is active.
RFC9432-CATALOG-MVP-002	retained-real-primary	bind_catalog_member_add	catalog-added.zone; member-added.out; bind-catalog-zone-summary.tsv	A live BIND catalog mutation adds member.example. while OxideDNS is running, and OxideDNS transfers and serves the member zone.
RFC9432-CATALOG-MVP-003	retained-real-primary	bind_catalog_member_remove	catalog-removed.zone; member-removed.out; metrics-after-remove.txt	A live BIND catalog mutation removes member.example. while OxideDNS is running, and OxideDNS stops serving the catalog-managed member zone.
RFC9432-CATALOG-MVP-004	retained-real-primary	catalog_query_hidden	catalog-hidden.out; oxidedns.toml	The catalog zone is transferred for management use but not served on the DNS query interface when serve_catalog_zone=false.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    for artifact in \
        named.conf rndc.conf oxidedns.toml named.log oxidedns.log primary-version.txt \
        catalog-initial.zone catalog-added.zone catalog-removed.zone member-initial.zone \
        catalog-hidden.out member-before.out member-added.out member-removed.out \
        metrics-initial.txt metrics-after-add.txt metrics-after-remove.txt \
        readyz-initial.json readyz-after-add.json \
        bind-catalog-zone-summary.tsv bind-catalog-zone-traceability.tsv; do
        cp "$workdir/$artifact" "$artifact_dir/$artifact"
    done
fi

echo "BIND Docker catalog-zone live interop passed"
