#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping PowerDNS/PostgreSQL catalog TSIG interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping PowerDNS/PostgreSQL catalog TSIG interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/interop-version-evidence.sh
source "$repo_root/scripts/interop-version-evidence.sh"

run_id="$$"
workdir="$repo_root/target/interop/powerdns-postgres-catalog-tsig-$run_id"
network="oxidedns-pdns-catalog-$run_id"
postgres_container="oxidedns-pdns-postgres-$run_id"
pdns_container="oxidedns-pdns-auth-$run_id"
pdns_image="${OXIDEDNS_POWERDNS_AUTH_IMAGE:-powerdns/pdns-auth-50:latest}"
postgres_image="${OXIDEDNS_POSTGRES_IMAGE:-postgres:16-alpine}"
artifact_dir="${OXIDEDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR:-}"
rm -rf "$workdir"
mkdir -p "$workdir"
chmod 755 "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$pdns_container" >/dev/null 2>&1; then
        docker logs "$pdns_container" >"$workdir/pdns.log" 2>&1 || true
        if ((status != 0)); then
            echo "---- PowerDNS logs ----" >&2
            tail -180 "$workdir/pdns.log" >&2 || true
            [[ -f "$workdir/oxidedns.log" ]] && {
                echo "---- oxidedns.log ----" >&2
                tail -180 "$workdir/oxidedns.log" >&2
            }
        fi
        docker rm -f -v "$pdns_container" >/dev/null 2>&1 || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$postgres_container" >/dev/null 2>&1; then
        docker logs "$postgres_container" >"$workdir/postgres.log" 2>&1 || true
        docker rm -f -v "$postgres_container" >/dev/null 2>&1 || true
    fi
    if docker network ls --format '{{.Name}}' | grep -Fx "$network" >/dev/null 2>&1; then
        docker network rm "$network" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

read -r pdns_port oxidedns_dns_port oxidedns_health_port < <(
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

tsig_name="transfer-key."
tsig_secret="c2VjcmV0LXRzaWcta2V5LTEyMzQ="
catalog_zone="$workdir/catalog.example.zone"
member_zone="$workdir/member.example.zone"
pdns_conf="$workdir/pdns.conf"
oxidedns_conf="$workdir/oxidedns.toml"
catalog_unsigned_axfr_out="$workdir/catalog-unsigned-axfr.out"
catalog_signed_axfr_out="$workdir/catalog-signed-axfr.out"
catalog_after_add_axfr_out="$workdir/catalog-after-add-axfr.out"
catalog_after_remove_axfr_out="$workdir/catalog-after-remove-axfr.out"
catalog_hidden_out="$workdir/catalog-hidden.out"
member_before_out="$workdir/member-before.out"
member_added_out="$workdir/member-added.out"
member_updated_out="$workdir/member-updated.out"
member_removed_out="$workdir/member-removed.out"
metrics_after_add_out="$workdir/metrics-after-add.txt"
metrics_after_update_out="$workdir/metrics-after-update.txt"
metrics_after_remove_out="$workdir/metrics-after-remove.txt"
summary_tsv="$workdir/powerdns-postgres-catalog-tsig-summary.tsv"
traceability_tsv="$workdir/powerdns-postgres-catalog-tsig-traceability.tsv"

cat >"$catalog_zone" <<'EOF'
$ORIGIN catalog.example.
$TTL 60
@ IN SOA invalid. hostmaster.invalid. 1 3600 600 604800 60
@ IN NS invalid.
EOF

cat >"$member_zone" <<'EOF'
$ORIGIN member.example.
$TTL 60
@ IN SOA ns.member.example. hostmaster.member.example. 2026052501 60 30 300 60
@ IN NS ns.member.example.
ns IN A 127.0.0.1
www IN A 192.0.2.88
txt IN TXT "powerdns postgres catalog member fixture"
EOF
chmod 644 "$catalog_zone" "$member_zone"

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
chmod 644 "$pdns_conf"

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
    echo "PostgreSQL did not become ready for PowerDNS interop" >&2
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
pdnsutil_run zone load catalog.example /work/catalog.example.zone >"$workdir/pdnsutil-catalog-load.out"
pdnsutil_run zone set-kind catalog.example producer >"$workdir/pdnsutil-catalog-kind.out"
pdnsutil_run tsigkey activate catalog.example "$tsig_name" producer >"$workdir/pdnsutil-catalog-tsig.out"
pdnsutil_run zone load member.example /work/member.example.zone >"$workdir/pdnsutil-member-load.out"
pdnsutil_run zone set-kind member.example primary >"$workdir/pdnsutil-member-kind.out"
pdnsutil_run tsigkey activate member.example "$tsig_name" primary >"$workdir/pdnsutil-member-tsig.out"

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

record_docker_primary_version \
    "$workdir" \
    "$pdns_container" \
    "PowerDNS Authoritative" \
    "$pdns_image" \
    "pdns-auth" \
    "powerdns-postgres-catalog-tsig" \
    "tcp-axfr+catalog-refresh" \
    "tsig-hmac-sha256" \
    "pdns_server --version" \
    "$pdns_conf" \
    "$catalog_zone" \
    "$member_zone"

for _ in {1..120}; do
    if dig "@127.0.0.1" -p "$pdns_port" catalog.example. SOA +tcp +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

catalog_unsigned_axfr="$(dig "@127.0.0.1" -p "$pdns_port" catalog.example. AXFR +tcp +time=2 +tries=1 2>&1 || true)"
printf '%s\n' "$catalog_unsigned_axfr" >"$catalog_unsigned_axfr_out"
if [[ "$catalog_unsigned_axfr" == *"version.catalog.example."* ]]; then
    echo "PowerDNS allowed unsigned catalog AXFR despite TSIG-only policy" >&2
    exit 1
fi

catalog_signed_axfr="$(dig -y "hmac-sha256:$tsig_name:$tsig_secret" "@127.0.0.1" -p "$pdns_port" catalog.example. AXFR +tcp +time=2 +tries=1)"
printf '%s\n' "$catalog_signed_axfr" >"$catalog_signed_axfr_out"
if [[ "$catalog_signed_axfr" != *'version.catalog.example.'* ]] || [[ "$catalog_signed_axfr" == *'.zones.catalog.example.'* ]]; then
    echo "PowerDNS initial signed catalog AXFR did not have the expected empty catalog shape" >&2
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
primaries = ["127.0.0.1:$pdns_port"]
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

ready=""
for _ in {1..120}; do
    if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done
if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready after PowerDNS TSIG catalog transfer" >&2
    exit 1
fi

catalog_hidden="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" version.catalog.example. TXT +norecurse +time=1 +tries=1)"
printf '%s\n' "$catalog_hidden" >"$catalog_hidden_out"
if [[ "$catalog_hidden" == *'"2"'* ]]; then
    echo "OxideDNS served the PowerDNS catalog zone despite serve_catalog_zone=false" >&2
    exit 1
fi

member_before="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1 +short)"
printf '%s\n' "$member_before" >"$member_before_out"
if [[ -n "$member_before" ]]; then
    echo "OxideDNS served PowerDNS member.example before catalog assignment" >&2
    exit 1
fi

pdnsutil_run catalog set member.example catalog.example >"$workdir/pdnsutil-catalog-add.out"
pdnsutil_run zone increase-serial catalog.example >"$workdir/pdnsutil-catalog-add-serial.out"
pdnsutil_run catalog list-members catalog.example >"$workdir/pdnsutil-catalog-members-added.out"
if ! grep -Fx 'member.example' "$workdir/pdnsutil-catalog-members-added.out" >/dev/null; then
    echo "PowerDNS did not list member.example after catalog assignment" >&2
    exit 1
fi

catalog_after_add_axfr=""
for _ in {1..120}; do
    catalog_after_add_axfr="$(dig -y "hmac-sha256:$tsig_name:$tsig_secret" "@127.0.0.1" -p "$pdns_port" catalog.example. AXFR +tcp +time=2 +tries=1 2>&1 || true)"
    if [[ "$catalog_after_add_axfr" == *'.zones.catalog.example.'* ]] && [[ "$catalog_after_add_axfr" == *'PTR	member.example.'* || "$catalog_after_add_axfr" == *'PTR member.example.'* ]]; then
        break
    fi
    sleep 0.25
done
printf '%s\n' "$catalog_after_add_axfr" >"$catalog_after_add_axfr_out"
if [[ "$catalog_after_add_axfr" != *'.zones.catalog.example.'* ]] || [[ "$catalog_after_add_axfr" != *'member.example.'* ]]; then
    echo "PowerDNS signed catalog AXFR did not publish member.example after catalog assignment" >&2
    exit 1
fi

member_added=""
for _ in {1..120}; do
    member_added="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1 +short)"
    if [[ "$member_added" == "192.0.2.88" ]]; then
        break
    fi
    sleep 0.25
done
printf '%s\n' "$member_added" >"$member_added_out"
if [[ "$member_added" != "192.0.2.88" ]]; then
    echo "OxideDNS did not serve the PowerDNS catalog-added member zone" >&2
    exit 1
fi

metrics_after_add="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics_after_add" >"$metrics_after_add_out"
if [[ "$metrics_after_add" != *'oxidedns_zone_soa_serial{zone="member.example."} 2026052501'* ]]; then
    echo "OxideDNS metrics after PowerDNS catalog add missing member SOA serial" >&2
    exit 1
fi

pdnsutil_run rrset replace member.example www.member.example A 60 "192.0.2.99" >"$workdir/pdnsutil-member-update-rrset.out"
pdnsutil_run zone increase-serial member.example >"$workdir/pdnsutil-member-update-serial.out"
pdnsutil_run zone list member.example >"$workdir/pdnsutil-member-after-update.out"
if ! grep -F 'www.member.example' "$workdir/pdnsutil-member-after-update.out" | grep -F '192.0.2.99' >/dev/null; then
    echo "PowerDNS member.example did not contain updated www A record" >&2
    exit 1
fi

member_updated=""
for _ in {1..120}; do
    member_updated="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1 +short)"
    if [[ "$member_updated" == "192.0.2.99" ]]; then
        break
    fi
    sleep 0.25
done
printf '%s\n' "$member_updated" >"$member_updated_out"
if [[ "$member_updated" != "192.0.2.99" ]]; then
    echo "OxideDNS did not refresh the PowerDNS member-zone record update" >&2
    exit 1
fi

metrics_after_update="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics_after_update" >"$metrics_after_update_out"
if [[ "$metrics_after_update" != *'oxidedns_zone_soa_serial{zone="member.example."} 2026052502'* ]]; then
    echo "OxideDNS metrics after PowerDNS member update missing incremented SOA serial" >&2
    exit 1
fi

pdnsutil_run catalog set member.example >"$workdir/pdnsutil-catalog-remove.out"
pdnsutil_run zone increase-serial catalog.example >"$workdir/pdnsutil-catalog-remove-serial.out"
pdnsutil_run catalog list-members catalog.example >"$workdir/pdnsutil-catalog-members-removed.out"
if grep -Fx 'member.example' "$workdir/pdnsutil-catalog-members-removed.out" >/dev/null; then
    echo "PowerDNS still lists member.example after catalog removal" >&2
    exit 1
fi

catalog_after_remove_axfr=""
for _ in {1..120}; do
    catalog_after_remove_axfr="$(dig -y "hmac-sha256:$tsig_name:$tsig_secret" "@127.0.0.1" -p "$pdns_port" catalog.example. AXFR +tcp +time=2 +tries=1 2>&1 || true)"
    if [[ "$catalog_after_remove_axfr" == *'version.catalog.example.'* ]] && [[ "$catalog_after_remove_axfr" != *'.zones.catalog.example.'* ]]; then
        break
    fi
    sleep 0.25
done
printf '%s\n' "$catalog_after_remove_axfr" >"$catalog_after_remove_axfr_out"
if [[ "$catalog_after_remove_axfr" != *'version.catalog.example.'* ]] || [[ "$catalog_after_remove_axfr" == *'.zones.catalog.example.'* ]]; then
    echo "PowerDNS signed catalog AXFR still published member.example after catalog removal" >&2
    exit 1
fi

member_removed="192.0.2.88"
for _ in {1..120}; do
    member_removed="$(dig "@127.0.0.1" -p "$oxidedns_dns_port" www.member.example. A +norecurse +time=1 +tries=1 +short)"
    if [[ -z "$member_removed" ]]; then
        break
    fi
    sleep 0.25
done
printf '%s\n' "$member_removed" >"$member_removed_out"
if [[ -n "$member_removed" ]]; then
    echo "OxideDNS still served the PowerDNS catalog member after removal" >&2
    exit 1
fi

metrics_after_remove="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
printf '%s\n' "$metrics_after_remove" >"$metrics_after_remove_out"
if [[ "$metrics_after_remove" == *'oxidedns_zone_soa_serial{zone="member.example."}'* ]]; then
    echo "OxideDNS metrics still reported removed PowerDNS catalog member zone" >&2
    exit 1
fi

docker logs "$pdns_container" >"$workdir/pdns.log" 2>&1 || true
docker logs "$postgres_container" >"$workdir/postgres.log" 2>&1 || true

{
    printf 'primary\tbackend\ttransfer_security\tmember_added_answer\tmember_updated_answer\tmember_removed_answer\n'
    printf 'powerdns\tpostgres\t%s\t%s\t%s\t%s\n' "tsig-hmac-sha256" "$member_added" "$member_updated" "${member_removed:-<empty>}"
} >"$summary_tsv"

cat >"$traceability_tsv" <<'EOF'
requirement_id	evidence_method	scenario	artifacts	rationale
RFC9432-CATALOG-MVP-010	retained-real-primary	powerdns_postgres_catalog_producer	primary-version.txt; pdnsutil-catalog-members-added.out	PowerDNS Authoritative with PostgreSQL/gpgsql generates RFC 9432 catalog membership using producer-zone metadata.
RFC9432-CATALOG-MVP-011	retained-real-primary	powerdns_catalog_tsig	catalog-unsigned-axfr.out; catalog-signed-axfr.out; pdns.log	Unsigned catalog AXFR is denied and TSIG-signed catalog AXFR succeeds.
RFC9432-CATALOG-MVP-012	retained-real-primary	powerdns_catalog_member_add	member-added.out; metrics-after-add.txt; powerdns-postgres-catalog-tsig-summary.tsv	OxideDNS remains running while a PowerDNS catalog assignment adds member.example. and then transfers and serves that member zone.
RFC9432-CATALOG-MVP-013	retained-real-primary	powerdns_member_zone_update	member-updated.out; metrics-after-update.txt; pdnsutil-member-after-update.out; powerdns-postgres-catalog-tsig-summary.tsv	OxideDNS remains running while the PowerDNS PostgreSQL-backed member zone changes, detects the incremented SOA serial, refreshes the zone, and serves the updated record.
RFC9432-CATALOG-MVP-014	retained-real-primary	powerdns_catalog_member_remove	member-removed.out; metrics-after-remove.txt; powerdns-postgres-catalog-tsig-summary.tsv	OxideDNS remains running while a PowerDNS catalog assignment is removed and then stops serving the catalog-managed member zone.
EOF

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    for artifact in \
        pdns.conf oxidedns.toml catalog.example.zone member.example.zone \
        primary-version.txt pdns.log postgres.log \
        catalog-unsigned-axfr.out catalog-signed-axfr.out catalog-after-add-axfr.out \
        catalog-after-remove-axfr.out catalog-hidden.out \
        member-before.out member-added.out member-updated.out member-removed.out \
        metrics-after-add.txt metrics-after-update.txt metrics-after-remove.txt \
        pdnsutil-tsig-import.out pdnsutil-catalog-load.out pdnsutil-catalog-kind.out \
        pdnsutil-catalog-tsig.out pdnsutil-member-load.out pdnsutil-member-kind.out \
        pdnsutil-member-tsig.out pdnsutil-catalog-add.out pdnsutil-catalog-remove.out \
        pdnsutil-member-update-rrset.out pdnsutil-member-update-serial.out \
        pdnsutil-member-after-update.out \
        pdnsutil-catalog-add-serial.out pdnsutil-catalog-remove-serial.out \
        pdnsutil-catalog-members-added.out pdnsutil-catalog-members-removed.out \
        powerdns-postgres-catalog-tsig-summary.tsv \
        powerdns-postgres-catalog-tsig-traceability.tsv; do
        cp "$workdir/$artifact" "$artifact_dir/$artifact"
    done
fi

echo "PowerDNS/PostgreSQL catalog TSIG live interop passed"
