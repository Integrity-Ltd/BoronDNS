#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping PowerDNS catalog member-extension interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping PowerDNS catalog member-extension interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"
# shellcheck source=scripts/interop-docker-images.sh
source "$repo_root/scripts/interop-docker-images.sh"

run_id="$$"
workdir="$repo_root/target/interop/powerdns-catalog-member-extension-$run_id"
network="borondns-pdns-ext-$run_id"
postgres_container="borondns-ext-postgres-$run_id"
pdns_container="borondns-ext-pdns-$run_id"
bind_container="borondns-ext-bind-$run_id"
knot_container="borondns-ext-knot-$run_id"
nsd_container="borondns-ext-nsd-$run_id"
pdns_image="${BORONDNS_POWERDNS_AUTH_IMAGE:-powerdns/pdns-auth-50:latest}"
postgres_image="${BORONDNS_POSTGRES_IMAGE:-postgres:16-alpine}"
artifact_dir="${BORONDNS_POWERDNS_CATALOG_MEMBER_EXTENSION_ARTIFACT_DIR:-}"
bind_image="$(ensure_alpine_bind_image)"
knot_image="$(ensure_alpine_knot_image)"
nsd_image="$(ensure_alpine_nsd_image)"
rm -rf "$workdir"
mkdir -p "$workdir"
chmod 0777 "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
    fi
    for container in "$pdns_container" "$bind_container" "$knot_container" "$nsd_container" "$postgres_container"; do
        if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
            docker logs "$container" >"$workdir/$container.log" 2>&1 || true
            if ((status != 0)); then
                echo "---- $container logs ----" >&2
                tail -160 "$workdir/$container.log" >&2 || true
            fi
            docker rm -f -v "$container" >/dev/null 2>&1 || true
        fi
    done
    if ((status != 0)) && [[ -f "$workdir/borondns.log" ]]; then
        echo "---- borondns.log ----" >&2
        tail -180 "$workdir/borondns.log" >&2 || true
    fi
    if docker network ls --format '{{.Name}}' | grep -Fx "$network" >/dev/null 2>&1; then
        docker network rm "$network" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r pdns_port bind_port knot_port nsd_port borondns_dns_port borondns_health_port < <(
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
borondns_conf="$workdir/borondns.toml"
summary_tsv="$workdir/powerdns-catalog-member-extension-summary.tsv"
traceability_tsv="$workdir/powerdns-catalog-member-extension-traceability.tsv"
metrics_out="$workdir/metrics.txt"

write_member_zone() {
    local zone="$1"
    local address="$2"
    local marker="$3"
    cat >"$workdir/$zone.zone" <<EOF
\$ORIGIN $zone.
\$TTL 60
@ IN SOA ns.$zone. hostmaster.$zone. 2026060402 60 30 300 60
@ IN NS ns.$zone.
ns IN A 127.0.0.1
www IN A $address
txt IN TXT "$marker"
EOF
}

write_member_zone "bind-member.example" "192.0.2.10" "bind member fixture"
write_member_zone "knot-member.example" "192.0.2.20" "knot member fixture"
write_member_zone "nsd-member.example" "192.0.2.30" "nsd member fixture"

cat >"$workdir/catalog-ext.example.zone" <<EOF
\$ORIGIN catalog-ext.example.
\$TTL 60
@ IN SOA invalid. hostmaster.invalid. 2026060402 60 30 300 60
@ IN NS invalid.
version IN TXT "2"
bind.zones IN PTR bind-member.example.
primaries.ext.bind.zones IN A 127.0.0.1
_udns-xfr.bind.zones IN TXT "transport=tcp;port=$bind_port;mode=axfr_ixfr"
knot.zones IN PTR knot-member.example.
primaries.ext.knot.zones IN A 127.0.0.1
_udns-xfr.knot.zones IN TXT "transport=tcp;port=$knot_port;mode=axfr_ixfr"
nsd.zones IN PTR nsd-member.example.
primaries.ext.nsd.zones IN A 127.0.0.1
_udns-xfr.nsd.zones IN TXT "transport=tcp;port=$nsd_port;mode=axfr_ixfr"
EOF

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
    --tmpfs /var/lib/postgresql/data:rw,nosuid,size=256m \
    -e PGDATA=/var/lib/postgresql/data/pgdata \
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
    echo "PostgreSQL did not become ready for member-extension catalog interop" >&2
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
pdnsutil_run zone load "catalog-ext.example" "/work/catalog-ext.example.zone" >"$workdir/pdnsutil-catalog-load.out"
pdnsutil_run zone set-kind "catalog-ext.example" primary >"$workdir/pdnsutil-catalog-kind.out"
pdnsutil_run tsigkey activate "catalog-ext.example" "$tsig_name" primary >"$workdir/pdnsutil-catalog-tsig.out"

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
    "$bind_image" \
    sh -c 'named-checkconf -z /work/named.conf && named -g -c /work/named.conf -n 1' \
    >/dev/null

docker run -d --name "$knot_container" \
    -p "127.0.0.1:$knot_port:5353/tcp" \
    -p "127.0.0.1:$knot_port:5353/udp" \
    -v "$workdir:/work:ro" \
    "$knot_image" \
    sh -c 'mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check && knotd -c /work/knot.conf -v' \
    >/dev/null

docker run -d --name "$nsd_container" \
    -p "127.0.0.1:$nsd_port:5353/tcp" \
    -p "127.0.0.1:$nsd_port:5353/udp" \
    -v "$workdir:/work:ro" \
    "$nsd_image" \
    sh -c 'nsd-checkconf /work/nsd.conf && nsd -d -c /work/nsd.conf' \
    >/dev/null

record_docker_primary_version "$workdir" "$pdns_container" "PowerDNS Authoritative" "$pdns_image" "pdns-auth" "powerdns-catalog-member-extension" "catalog-axfr-tsig" "tsig-hmac-sha256" "pdns_server --version" "$pdns_conf" "$workdir/catalog-ext.example.zone"
record_docker_primary_version "$workdir" "$bind_container" "BIND 9" "$bind_image" "bind" "powerdns-catalog-member-extension-bind-member" "member-axfr" "none" "named -V" "$workdir/named.conf" "$workdir/bind-member.example.zone"
record_docker_primary_version "$workdir" "$knot_container" "Knot DNS" "$knot_image" "knot" "powerdns-catalog-member-extension-knot-member" "member-axfr" "none" "knotd -V" "$workdir/knot.conf" "$workdir/knot-member.example.zone"
record_docker_primary_version "$workdir" "$nsd_container" "NSD" "$nsd_image" "nsd" "powerdns-catalog-member-extension-nsd-member" "member-axfr" "none" "nsd -v" "$workdir/nsd.conf" "$workdir/nsd-member.example.zone"

for name_port in \
    "catalog-ext.example. $pdns_port" \
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
    if [[ "$soa" != *"2026060402"* ]]; then
        echo "primary $name on port $port did not answer expected SOA serial" >&2
        exit 1
    fi
done

catalog_axfr="$(dig -y "hmac-sha256:$tsig_name:$tsig_secret" "@127.0.0.1" -p "$pdns_port" "catalog-ext.example." AXFR +tcp +time=2 +tries=1)"
printf '%s\n' "$catalog_axfr" >"$workdir/catalog-ext-signed-axfr.out"
for expected in "version.catalog-ext.example." "primaries.ext.bind.zones.catalog-ext.example." "_udns-xfr.nsd.zones.catalog-ext.example."; do
    if [[ "$catalog_axfr" != *"$expected"* ]]; then
        echo "PowerDNS catalog signed AXFR did not include expected member-extension record $expected" >&2
        exit 1
    fi
done

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

[[catalog_zones]]
name = "catalog-ext.example."
class = "IN"
catalog_primaries = ["127.0.0.1:$pdns_port"]
member_primaries = ["127.0.0.1:9"]
catalog_tsig_key = "$tsig_name"
serve_catalog_zone = false
member_transfer_extensions = true

[catalog_zones.member_transfer_policy]
unsigned_axfr = "allow-legacy-private"

[[tsig_keys]]
name = "$tsig_name"
algorithm = "hmac-sha256"
secret = "$tsig_secret"
EOF

cargo build -p borondns-cli >/dev/null
"$repo_root/target/debug/borondns" serve --config "$borondns_conf" >"$workdir/borondns.log" 2>&1 &
borondns_pid=$!

ready=""
for _ in {1..180}; do
    if ready="$(curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.2
done
if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "BoronDNS did not become ready after member-extension catalog transfers" >&2
    exit 1
fi

for expectation in \
    "bind-member.example. 192.0.2.10" \
    "knot-member.example. 192.0.2.20" \
    "nsd-member.example. 192.0.2.30"; do
    read -r zone address <<<"$expectation"
    answer="$(dig "@127.0.0.1" -p "$borondns_dns_port" "www.$zone" A +norecurse +noall +answer)"
    printf '%s\n' "$answer" >"$workdir/$zone-answer.out"
    if [[ "$answer" != *"www.$zone"* ]] || [[ "$answer" != *"$address"* ]]; then
        echo "BoronDNS did not serve expected answer for $zone from member-extension catalog transfer" >&2
        exit 1
    fi
done

metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
printf '%s\n' "$metrics" >"$metrics_out"
for expected in \
    'borondns_zones_active 4' \
    'borondns_catalog_member_info{catalog_zone="catalog-ext.example.",zone="bind-member.example.",managed="true"} 1' \
    'borondns_catalog_member_info{catalog_zone="catalog-ext.example.",zone="knot-member.example.",managed="true"} 1' \
    'borondns_catalog_member_info{catalog_zone="catalog-ext.example.",zone="nsd-member.example.",managed="true"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "BoronDNS metrics missing expected member-extension line: $expected" >&2
        exit 1
    fi
done

{
    printf 'catalog_backend\tmember_primary\tcatalog_zone\tmember_zone\tanswer\n'
    printf 'powerdns-postgres\tbind\tcatalog-ext.example.\tbind-member.example.\t192.0.2.10\n'
    printf 'powerdns-postgres\tknot\tcatalog-ext.example.\tknot-member.example.\t192.0.2.20\n'
    printf 'powerdns-postgres\tnsd\tcatalog-ext.example.\tnsd-member.example.\t192.0.2.30\n'
} >"$summary_tsv"

cat >"$traceability_tsv" <<EOF
BDS-VER-CATEXT-001	retained-real-primary	powerdns_catalog_bind_member_extension	$summary_tsv; bind-member.example.-answer.out	PowerDNS/PostgreSQL serves one RFC 9432 catalog with per-member transfer metadata while BoronDNS transfers the member zone from BIND.
BDS-VER-CATEXT-002	retained-real-primary	powerdns_catalog_knot_member_extension	$summary_tsv; knot-member.example.-answer.out	PowerDNS/PostgreSQL serves one RFC 9432 catalog with per-member transfer metadata while BoronDNS transfers the member zone from Knot.
BDS-VER-CATEXT-003	retained-real-primary	powerdns_catalog_nsd_member_extension	$summary_tsv; nsd-member.example.-answer.out	PowerDNS/PostgreSQL serves one RFC 9432 catalog with per-member transfer metadata while BoronDNS transfers the member zone from NSD.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$summary_tsv" "$traceability_tsv" "$metrics_out" "$borondns_conf" "$artifact_dir"/
fi

echo "PowerDNS catalog member-extension Docker interop passed"
