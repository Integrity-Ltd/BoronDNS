#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping PowerDNS catalog split-primaries interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping PowerDNS catalog split-primaries interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"

run_id="$$"
workdir="$repo_root/target/interop/powerdns-catalog-split-primaries-$run_id"
network="oxidedns-pdns-split-$run_id"
postgres_container="oxidedns-split-postgres-$run_id"
pdns_container="oxidedns-split-pdns-$run_id"
bind_container="oxidedns-split-bind-$run_id"
knot_container="oxidedns-split-knot-$run_id"
nsd_container="oxidedns-split-nsd-$run_id"
pdns_image="${OXIDEDNS_POWERDNS_AUTH_IMAGE:-powerdns/pdns-auth-50:latest}"
postgres_image="${OXIDEDNS_POSTGRES_IMAGE:-postgres:16-alpine}"
artifact_dir="${OXIDEDNS_POWERDNS_CATALOG_SPLIT_PRIMARIES_ARTIFACT_DIR:-}"
mkdir -p "$workdir"
chmod 0777 "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    for container in "$pdns_container" "$bind_container" "$knot_container" "$nsd_container" "$postgres_container"; do
        if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
            docker logs "$container" >"$workdir/$container.log" 2>&1 || true
            if ((status != 0)); then
                echo "---- $container logs ----" >&2
                tail -160 "$workdir/$container.log" >&2 || true
            fi
            docker rm -f "$container" >/dev/null 2>&1 || true
        fi
    done
    if ((status != 0)) && [[ -f "$workdir/oxidedns.log" ]]; then
        echo "---- oxidedns.log ----" >&2
        tail -180 "$workdir/oxidedns.log" >&2 || true
    fi
    if docker network ls --format '{{.Name}}' | grep -Fx "$network" >/dev/null 2>&1; then
        docker network rm "$network" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r pdns_port bind_port knot_port nsd_port oxidedns_dns_port oxidedns_health_port < <(
    python3 - <<'PY'
import socket

sockets = []
for _ in range(6):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

tsig_name="catalog-transfer-key."
tsig_secret="c2VjcmV0LWNhdGFsb2ctdHJhbnNmZXI="
pdns_conf="$workdir/pdns.conf"
oxidedns_conf="$workdir/oxidedns.toml"
summary_tsv="$workdir/powerdns-catalog-split-primaries-summary.tsv"
traceability_tsv="$workdir/powerdns-catalog-split-primaries-traceability.tsv"
metrics_out="$workdir/metrics.txt"

write_member_zone() {
    local zone="$1"
    local address="$2"
    local marker="$3"
    cat >"$workdir/$zone.zone" <<EOF
\$ORIGIN $zone.
\$TTL 60
@ IN SOA ns.$zone. hostmaster.$zone. 2026060401 60 30 300 60
@ IN NS ns.$zone.
ns IN A 127.0.0.1
www IN A $address
txt IN TXT "$marker"
EOF
}

write_catalog_zone() {
    local catalog="$1"
    local member="$2"
    cat >"$workdir/$catalog.zone" <<EOF
\$ORIGIN $catalog.
\$TTL 60
@ IN SOA invalid. hostmaster.invalid. 2026060401 60 30 300 60
@ IN NS invalid.
version IN TXT "2"
member.zones IN PTR $member.
EOF
}

write_member_zone "bind-member.example" "192.0.2.10" "bind member fixture"
write_member_zone "knot-member.example" "192.0.2.20" "knot member fixture"
write_member_zone "nsd-member.example" "192.0.2.30" "nsd member fixture"
write_catalog_zone "catalog-bind.example" "bind-member.example"
write_catalog_zone "catalog-knot.example" "knot-member.example"
write_catalog_zone "catalog-nsd.example" "nsd-member.example"

cat >"$workdir/named.conf" <<'EOF'
options {
    directory "/work";
    listen-on port 5353 { any; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    pid-file "/work/named.pid";
    session-keyfile "/work/session.key";
};

zone "bind-member.example." IN {
    type primary;
    file "/work/bind-member.example.zone";
    allow-query { any; };
    allow-transfer { any; };
    notify no;
};
EOF

cat >"$workdir/knot.conf" <<'EOF'
server:
    rundir: "/tmp"
    listen: 0.0.0.0@5353
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

acl:
  - id: transfer_acl
    address: 0.0.0.0/0
    action: transfer

zone:
  - domain: knot-member.example.
    acl: transfer_acl
EOF

cat >"$workdir/nsd.conf" <<'EOF'
server:
    do-ip4: yes
    do-ip6: no
    ip-address: 0.0.0.0@5353
    hide-version: yes
    verbosity: 1
    database: "/tmp/nsd.db"
    pidfile: "/tmp/nsd.pid"
    zonesdir: "/work"

zone:
    name: "nsd-member.example."
    zonefile: "/work/nsd-member.example.zone"
    provide-xfr: 0.0.0.0/0 NOKEY
EOF

cat >"$pdns_conf" <<EOF
launch=gpgsql
gpgsql-host=$postgres_container
gpgsql-user=pdns
gpgsql-password=pdns
gpgsql-dbname=pdns
gpgsql-dnssec=yes
local-address=0.0.0.0
local-port=5353
primary=yes
allow-axfr-ips=
loglevel=6
EOF
chmod 644 "$workdir"/*.zone "$workdir"/*.conf

docker network create "$network" >/dev/null
docker run -d --name "$postgres_container" \
    --network "$network" \
    -e POSTGRES_PASSWORD=pdns \
    -e POSTGRES_USER=pdns \
    -e POSTGRES_DB=pdns \
    "$postgres_image" \
    >/dev/null

for _ in {1..120}; do
    if docker exec "$postgres_container" psql -U pdns -d pdns -c 'select 1' >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
if ! docker exec "$postgres_container" psql -U pdns -d pdns -c 'select 1' >/dev/null 2>&1; then
    echo "PostgreSQL did not become ready for split-primary catalog interop" >&2
    exit 1
fi

docker run --rm --entrypoint cat "$pdns_image" /usr/local/share/doc/pdns/schema.pgsql.sql |
    docker exec -i "$postgres_container" psql -U pdns -d pdns >/dev/null

pdnsutil_run() {
    docker run --rm \
        --network "$network" \
        -v "$workdir:/work:rw" \
        --entrypoint pdnsutil \
        "$pdns_image" \
        --config-dir=/work \
        "$@"
}

pdnsutil_run tsigkey import "$tsig_name" hmac-sha256 "$tsig_secret" >"$workdir/pdnsutil-tsig-import.out"
for catalog in catalog-bind.example catalog-knot.example catalog-nsd.example; do
    pdnsutil_run zone load "$catalog" "/work/$catalog.zone" >"$workdir/pdnsutil-$catalog-load.out"
    pdnsutil_run zone set-kind "$catalog" primary >"$workdir/pdnsutil-$catalog-kind.out"
    pdnsutil_run tsigkey activate "$catalog" "$tsig_name" primary >"$workdir/pdnsutil-$catalog-tsig.out"
done

docker run -d --name "$pdns_container" \
    --network "$network" \
    -p "127.0.0.1:$pdns_port:5353/tcp" \
    -p "127.0.0.1:$pdns_port:5353/udp" \
    -v "$workdir:/work:rw" \
    --entrypoint pdns_server \
    "$pdns_image" \
    --config-dir=/work \
    --daemon=no \
    --guardian=no \
    >/dev/null

docker run -d --name "$bind_container" \
    -p "127.0.0.1:$bind_port:5353/tcp" \
    -p "127.0.0.1:$bind_port:5353/udp" \
    -v "$workdir:/work:rw" \
    alpine:latest \
    sh -c 'apk add --no-cache bind bind-tools >/dev/null && named-checkconf -z /work/named.conf && named -g -c /work/named.conf -n 1' \
    >/dev/null

docker run -d --name "$knot_container" \
    -p "127.0.0.1:$knot_port:5353/tcp" \
    -p "127.0.0.1:$knot_port:5353/udp" \
    -v "$workdir:/work:ro" \
    alpine:latest \
    sh -c 'apk add --no-cache knot >/dev/null && mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check && knotd -c /work/knot.conf -v' \
    >/dev/null

docker run -d --name "$nsd_container" \
    -p "127.0.0.1:$nsd_port:5353/tcp" \
    -p "127.0.0.1:$nsd_port:5353/udp" \
    -v "$workdir:/work:ro" \
    alpine:latest \
    sh -c 'apk add --no-cache nsd >/dev/null && nsd-checkconf /work/nsd.conf && nsd -d -c /work/nsd.conf' \
    >/dev/null

record_docker_primary_version "$workdir" "$pdns_container" "PowerDNS Authoritative" "$pdns_image" "pdns-auth" "powerdns-catalog-split-primaries" "catalog-axfr-tsig" "tsig-hmac-sha256" "pdns_server --version" "$pdns_conf" "$workdir/catalog-bind.example.zone" "$workdir/catalog-knot.example.zone" "$workdir/catalog-nsd.example.zone"
record_docker_primary_version "$workdir" "$bind_container" "BIND 9" "alpine:latest" "bind" "powerdns-catalog-split-primaries-bind-member" "member-axfr" "none" "named -V" "$workdir/named.conf" "$workdir/bind-member.example.zone"
record_docker_primary_version "$workdir" "$knot_container" "Knot DNS" "alpine:latest" "knot" "powerdns-catalog-split-primaries-knot-member" "member-axfr" "none" "knotd -V" "$workdir/knot.conf" "$workdir/knot-member.example.zone"
record_docker_primary_version "$workdir" "$nsd_container" "NSD" "alpine:latest" "nsd" "powerdns-catalog-split-primaries-nsd-member" "member-axfr" "none" "nsd -v" "$workdir/nsd.conf" "$workdir/nsd-member.example.zone"

for name_port in \
    "catalog-bind.example. $pdns_port" \
    "bind-member.example. $bind_port" \
    "knot-member.example. $knot_port" \
    "nsd-member.example. $nsd_port"; do
    read -r name port <<<"$name_port"
    for _ in {1..120}; do
        if dig "@127.0.0.1" -p "$port" "$name" SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
            break
        fi
        sleep 0.25
    done
    soa="$(dig "@127.0.0.1" -p "$port" "$name" SOA +tcp +time=1 +tries=1 +short)"
    if [[ "$soa" != *"2026060401"* ]]; then
        echo "primary $name on port $port did not answer expected SOA serial" >&2
        exit 1
    fi
done

for catalog in catalog-bind.example catalog-knot.example catalog-nsd.example; do
    catalog_axfr="$(dig -y "hmac-sha256:$tsig_name:$tsig_secret" "@127.0.0.1" -p "$pdns_port" "$catalog." AXFR +tcp +time=2 +tries=1)"
    printf '%s\n' "$catalog_axfr" >"$workdir/$catalog-signed-axfr.out"
    if [[ "$catalog_axfr" != *"version.$catalog."* ]] || [[ "$catalog_axfr" != *".zones.$catalog."* ]]; then
        echo "PowerDNS catalog $catalog signed AXFR did not include RFC 9432 records" >&2
        exit 1
    fi
done

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
graceful_shutdown_secs = 2

[[catalog_zones]]
name = "catalog-bind.example."
class = "IN"
catalog_primaries = ["127.0.0.1:$pdns_port"]
member_primaries = ["127.0.0.1:$bind_port"]
catalog_tsig_key = "$tsig_name"
serve_catalog_zone = false

[[catalog_zones]]
name = "catalog-knot.example."
class = "IN"
catalog_primaries = ["127.0.0.1:$pdns_port"]
member_primaries = ["127.0.0.1:$knot_port"]
catalog_tsig_key = "$tsig_name"
serve_catalog_zone = false

[[catalog_zones]]
name = "catalog-nsd.example."
class = "IN"
catalog_primaries = ["127.0.0.1:$pdns_port"]
member_primaries = ["127.0.0.1:$nsd_port"]
catalog_tsig_key = "$tsig_name"
serve_catalog_zone = false

[[tsig_keys]]
name = "$tsig_name"
algorithm = "hmac-sha256"
secret = "$tsig_secret"
EOF

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=""
for _ in {1..160}; do
    if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.2
done
if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after split catalog/member transfers" >&2
    exit 1
fi

for expectation in \
    "bind-member.example. 192.0.2.10" \
    "knot-member.example. 192.0.2.20" \
    "nsd-member.example. 192.0.2.30"; do
    read -r zone address <<<"$expectation"
    answer="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" "www.$zone" A +norecurse +noall +answer)"
    printf '%s\n' "$answer" >"$workdir/$zone-answer.out"
    if [[ "$answer" != *"www.$zone"* ]] || [[ "$answer" != *"$address"* ]]; then
        echo "OxideDNS did not serve expected answer for $zone from split catalog/member transfer" >&2
        exit 1
    fi
done

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
for expected in \
    'oxidedns_zones_active 6' \
    'oxidedns_catalog_member_info{catalog_zone="catalog-bind.example.",zone="bind-member.example.",managed="true"} 1' \
    'oxidedns_catalog_member_info{catalog_zone="catalog-knot.example.",zone="knot-member.example.",managed="true"} 1' \
    'oxidedns_catalog_member_info{catalog_zone="catalog-nsd.example.",zone="nsd-member.example.",managed="true"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "OxideDNS metrics missing expected split-primary line: $expected" >&2
        exit 1
    fi
done

{
    printf 'catalog_backend\tmember_primary\tcatalog_zone\tmember_zone\tanswer\n'
    printf 'powerdns-postgres\tbind\tcatalog-bind.example.\tbind-member.example.\t192.0.2.10\n'
    printf 'powerdns-postgres\tknot\tcatalog-knot.example.\tknot-member.example.\t192.0.2.20\n'
    printf 'powerdns-postgres\tnsd\tcatalog-nsd.example.\tnsd-member.example.\t192.0.2.30\n'
} >"$summary_tsv"

cat >"$traceability_tsv" <<EOF
ODS-VER-SPLIT-001	retained-real-primary	powerdns_catalog_bind_member	$summary_tsv; bind-member.example.-answer.out	PowerDNS/PostgreSQL serves the RFC 9432 catalog while OxideDNS transfers the member zone from BIND.
ODS-VER-SPLIT-002	retained-real-primary	powerdns_catalog_knot_member	$summary_tsv; knot-member.example.-answer.out	PowerDNS/PostgreSQL serves the RFC 9432 catalog while OxideDNS transfers the member zone from Knot.
ODS-VER-SPLIT-003	retained-real-primary	powerdns_catalog_nsd_member	$summary_tsv; nsd-member.example.-answer.out	PowerDNS/PostgreSQL serves the RFC 9432 catalog while OxideDNS transfers the member zone from NSD.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$summary_tsv" "$traceability_tsv" "$metrics_out" "$oxidedns_conf" "$artifact_dir"/
fi

echo "PowerDNS catalog split-primaries Docker interop passed"
