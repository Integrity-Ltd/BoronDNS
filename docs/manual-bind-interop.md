# Real-primary interoperability checks

These scripts check BoronDNS against a running primary: initial AXFR, NOTIFY,
catalog membership, and transfers over TLS. Start with the BIND AXFR smoke;
choose the later checks for the path you changed. They are functional checks,
not throughput or long-running stability measurements.

Run them from the repository root on a test host. They build the local debug
BoronDNS binary and start temporary services. Most scripts report missing
prerequisites as `skipping ...` with exit status zero, so require the explicit
success message and retained artifacts before recording a pass.

## BIND AXFR smoke

The Docker variant needs a working Docker daemon, `dig`, `curl`, `python3`, and
`cargo`. It runs BIND 9 in an Alpine container, loads the fixture zone, and
starts BoronDNS on loopback.

```bash
BORONDNS_BIND_DOCKER_AXFR_ARTIFACT_DIR=target/evidence/manual-bind-axfr \
  scripts/interop-bind-axfr-docker.sh
```

It checks BIND SOA/AXFR, waits for BoronDNS `/readyz`, checks transferred `A`
and `CNAME` answers plus TCP `SOA`, and verifies active-zone and AXFR metrics.
The final line must be:

```text
BIND Docker AXFR interop passed
```

The artifact directory contains:

| Files | Purpose |
| --- | --- |
| `primary-version.txt` | BIND image, package, and version |
| `named.conf`, `alpha.test.zone`, `borondns.toml` | Reproduction inputs |
| `primary-soa.out`, `primary-axfr.out` | Direct checks against BIND |
| `answer-a.out`, `answer-cname.out`, `tcp-soa.out` | Answers served by BoronDNS |
| `metrics.txt`, logs | Transfer and runtime observations |
| `axfr-traceability.tsv` | Mapping to AXFR requirements |

For host-installed BIND, use the equivalent script:

```bash
BORONDNS_BIND_AXFR_ARTIFACT_DIR=target/evidence/manual-bind-host-axfr \
  scripts/interop-bind-axfr.sh
```

It needs `named`, `named-checkconf`, and `named-checkzone` in addition to
`dig`, `curl`, `python3`, and `cargo`; Docker is not required.

## NOTIFY refresh

With host-installed BIND and `rndc`:

```bash
BORONDNS_BIND_NOTIFY_ARTIFACT_DIR=target/evidence/manual-bind-notify \
  scripts/interop-bind-notify-refresh.sh
```

The script starts BoronDNS before BIND, observes BIND's NOTIFY through a UDP
proxy, changes the zone serial and data, and checks that BoronDNS refreshes
its answers and metrics.

## Live BIND catalog membership

```bash
BORONDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR=target/evidence/manual-bind-catalog \
  scripts/interop-bind-catalog-zone-docker.sh
```

BIND serves `catalog.example.` and `member.example.` with TSIG-restricted
AXFR. BoronDNS starts with only `[[catalog_zones]]`. The script adds and removes
a member PTR while BoronDNS keeps running, checking that the member becomes
queryable and then stops being served. It also checks that
`serve_catalog_zone = false` hides the catalog itself.

For the same path over XoT (zone transfer over TLS):

```bash
BORONDNS_BIND_XOT_CATALOG_DOCKER_ARTIFACT_DIR=target/evidence/manual-bind-xot-catalog \
  scripts/interop-bind-xot-catalog-zone-docker.sh
```

This variant generates a local CA and server certificate, uses ALPN `dot`,
and checks that plain TCP transfer is denied while XoT+TSIG transfer and live
catalog reconciliation succeed. It can skip when the packaged BIND lacks the
required XoT support; check its final message.

## PowerDNS PostgreSQL Catalog Check

This supplemental check uses PowerDNS Authoritative with the `gpgsql` backend
and a PostgreSQL container:

```bash
BORONDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR=target/evidence/manual-powerdns-catalog \
  scripts/interop-powerdns-postgres-catalog-tsig-docker.sh
```

The script creates an RFC 9432 producer catalog with `pdnsutil` and requires
TSIG for catalog and member AXFR. It checks unsigned-transfer rejection,
signed transfer, hidden catalog queries, live member addition/removal, and
refresh of an updated member record while BoronDNS remains running.

## Related checks

See the [evidence command catalog](evidence-command-catalog.md) for the full
primary-server matrix and artifact settings. The short RRL check is
`scripts/interop-rrl-udp.sh`; `scripts/rrl-evidence-campaign.sh` collects its
campaign evidence. Source-IP rotation at scale needs a dedicated network test
setup and is not established by the Docker AXFR checks above.
