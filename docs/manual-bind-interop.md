# Manual BIND Interop Smoke

This runbook is the shortest human-operated check that OxideDNS can load a
zone from a real BIND primary and serve it over UDP and TCP. It complements
`cargo test --workspace`: the point is to exercise a real primary server and
the operator-facing commands, not only in-process tests.

## Scope

The smoke run verifies:

- BIND answers SOA and AXFR for the fixture zone.
- OxideDNS starts with a generated config and reaches `/readyz`.
- OxideDNS serves transferred `A`, `CNAME`, and TCP `SOA` answers.
- OxideDNS metrics expose the active transferred zone and AXFR counters.
- The retained artifact directory records BIND version, generated configs,
  logs, query outputs, metrics, and AXFR traceability.

This is not a full SRS release acceptance run. It does not replace long fuzz,
soak, Reference Hardware/Profile performance, third-party security audit, or
external operator acceptance.

## Containerized BIND Primary

Prerequisites:

```bash
docker --version
dig -v
cargo --version
curl --version
python3 --version
```

Run:

```bash
OXIDEDNS_BIND_DOCKER_AXFR_ARTIFACT_DIR=target/evidence/manual-bind-axfr \
  scripts/interop-bind-axfr-docker.sh
```

The script starts BIND 9 inside an Alpine container and runs the local
debug-build OxideDNS binary on loopback. This is intentionally easy to run from
a developer checkout while still using a real primary implementation.

Expected final line:

```text
BIND Docker AXFR interop passed
```

Useful retained files:

- `primary-version.txt`: BIND image/package/version details.
- `named.conf` and `alpha.test.zone`: primary configuration and fixture.
- `oxidedns.toml`: generated OxideDNS configuration.
- `primary-soa.out` and `primary-axfr.out`: direct BIND checks.
- `answer-a.out`, `answer-cname.out`, `tcp-soa.out`: OxideDNS query checks.
- `metrics.txt`: management endpoint output after transfer and queries.
- `axfr-traceability.tsv`: AXFR requirement evidence map.

## Host-Installed BIND Variant

If BIND is installed directly on the host, this equivalent script avoids
Docker:

```bash
OXIDEDNS_BIND_AXFR_ARTIFACT_DIR=target/evidence/manual-bind-host-axfr \
  scripts/interop-bind-axfr.sh
```

The host variant requires `named`, `named-checkconf`, `named-checkzone`, `dig`,
`curl`, `python3`, and `cargo`.

## NOTIFY Refresh Check

After the AXFR smoke passes, use the BIND NOTIFY refresh script to check a
real-primary update path:

```bash
OXIDEDNS_BIND_NOTIFY_ARTIFACT_DIR=target/evidence/manual-bind-notify \
  scripts/interop-bind-notify-refresh.sh
```

This script requires host-installed BIND and `rndc`. It starts OxideDNS before
BIND, observes BIND-generated NOTIFY through a small UDP proxy, triggers a zone
serial/data update, and confirms OxideDNS refreshes the served answer and
metrics.

## Catalog Zone Live Check

Use the BIND catalog-zone Docker script to check the RFC 9432 catalog path with
OxideDNS running throughout the test:

```bash
OXIDEDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR=target/evidence/manual-bind-catalog \
  scripts/interop-bind-catalog-zone-docker.sh
```

The script starts BIND in Docker with `catalog.example.` and `member.example.`
as ordinary authoritative zones, starts OxideDNS with only `[[catalog_zones]]`,
verifies the catalog is not query-visible with `serve_catalog_zone = false`,
then edits and reloads the BIND catalog zone while OxideDNS keeps running. It
confirms that adding a member PTR makes OxideDNS transfer and serve
`member.example.`, and that removing the PTR makes OxideDNS stop serving that
catalog-managed member.

## PowerDNS PostgreSQL Catalog Check

The production-shape catalog check uses PowerDNS Authoritative with the gpgsql
backend and a PostgreSQL container:

```bash
OXIDEDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR=target/evidence/manual-powerdns-catalog \
  scripts/interop-powerdns-postgres-catalog-tsig-docker.sh
```

This script creates a PowerDNS RFC 9432 producer catalog with `pdnsutil`, keeps
zone data in PostgreSQL, enables TSIG-only AXFR for both the catalog and member
zone, starts OxideDNS with only `[[catalog_zones]]`, and then changes the
PowerDNS catalog assignment live. It verifies unsigned catalog AXFR is denied,
TSIG-signed catalog transfer succeeds, catalog queries stay hidden, member add
starts serving, and member removal stops serving while OxideDNS remains running.

## RRL And Source-IP Rotation

Docker is sufficient for the AXFR and basic query smoke above. It is not the
right environment for the large source-IP rotation needed by RRL scale tests.
For those tests use a VM or bare-metal host with a dedicated test source range:

```bash
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 10.0.0.1/8 dev dummy0
sudo sysctl -w net.ipv4.ip_nonlocal_bind=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
```

The project currently keeps the short RRL harness in
`scripts/interop-rrl-udp.sh` and the release-campaign scaffold in
`scripts/rrl-evidence-campaign.sh`. A larger Rust source-IP rotating harness is
future work and should cover IPv4 and IPv6.

## Future Test Harness Direction

The intended next harness layer is a separate Rust test workspace, not more
ad-hoc shell in the main server crates. The planned pieces are:

- deterministic zone-profile generation, including DNSSEC and reverse zones;
- BIND 9.20 LTS lifecycle helpers for AXFR, IXFR, NOTIFY, and TSIG;
- functional tests using an independent DNS protocol implementation;
- source-IP rotating UDP/TCP load generation for RRL;
- wrappers for `dnsperf` and `kxdpgun` on the later performance lab.

Keep that larger harness out of the Engineering MVP claim until it has its own
artifact formats, ownership, and runtime profile.
