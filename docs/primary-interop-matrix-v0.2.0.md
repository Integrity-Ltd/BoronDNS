# Primary Interop Matrix - v0.2.0 Local Release Evidence

This document records the retained local real-primary interop matrix run used to
close the v0.2.0 current-version primary evidence gap for the selected
non-XoT matrix.

Evidence directory:
`target/evidence/primary-matrix-20260614T010049Z`

Run command:

```sh
OXIDEDNS_PRIMARY_MATRIX_ARTIFACT_DIR=target/evidence/primary-matrix-20260614T010049Z \
  scripts/interop-primary-matrix.sh
```

Result: passed, 12 of 12 selected cases.

## Scope

The selected local matrix covers current-version real primary interoperability
for:

- BIND AXFR, TSIG AXFR, NOTIFY-triggered refresh, and IXFR refresh.
- NSD AXFR, TSIG AXFR, and NOTIFY-triggered refresh.
- Knot AXFR, TSIG AXFR, NOTIFY-triggered refresh, and IXFR refresh.
- PowerDNS Authoritative with PostgreSQL-backed catalog-zone TSIG transfer.

This run does not claim XoT release evidence, DNSSEC signing-authority breadth,
DNS Cookie deployment evidence, production operator acceptance, reference
hardware performance, or long-running soak acceptance. Those remain tracked as
separate closeout rows in `docs/mvp-gap-register.md`.

## Tested Versions

| Primary | Version | Runtime source | Matrix capabilities |
| --- | --- | --- | --- |
| BIND 9 | 9.20.23 stable | Arch Linux host package | AXFR; TSIG AXFR; NOTIFY refresh; IXFR refresh |
| NSD | 4.14.2 | Alpine Linux v3.24 container package | AXFR; TSIG AXFR; NOTIFY refresh |
| Knot DNS | 3.5.3 | Alpine Linux v3.24 container package | AXFR; TSIG AXFR; NOTIFY refresh; IXFR refresh |
| PowerDNS Authoritative | 5.0.5 | `powerdns/pdns-auth-50:latest`, Debian 13 container | PostgreSQL catalog zone with TSIG transfer |

## Case Results

| Primary | Capability | Script | Status | Evidence subdirectory |
| --- | --- | --- | --- | --- |
| BIND | AXFR | `scripts/interop-bind-axfr.sh` | passed | `bind-axfr/` |
| BIND | TSIG AXFR | `scripts/interop-bind-tsig-axfr.sh` | passed | `bind-tsig-axfr/` |
| BIND | NOTIFY refresh | `scripts/interop-bind-notify-refresh.sh` | passed | `bind-notify-refresh/` |
| BIND | IXFR refresh | `scripts/interop-bind-ixfr-refresh.sh` | passed | `bind-ixfr-refresh/` |
| NSD | AXFR | `scripts/interop-nsd-axfr-docker.sh` | passed | `nsd-axfr/` |
| NSD | TSIG AXFR | `scripts/interop-nsd-tsig-axfr-docker.sh` | passed | `nsd-tsig-axfr/` |
| NSD | NOTIFY refresh | `scripts/interop-nsd-notify-refresh-docker.sh` | passed | `nsd-notify-refresh/` |
| Knot | AXFR | `scripts/interop-knot-axfr-docker.sh` | passed | `knot-axfr/` |
| Knot | TSIG AXFR | `scripts/interop-knot-tsig-axfr-docker.sh` | passed | `knot-tsig-axfr/` |
| Knot | NOTIFY refresh | `scripts/interop-knot-notify-refresh-docker.sh` | passed | `knot-notify-refresh/` |
| Knot | IXFR refresh | `scripts/interop-knot-ixfr-refresh-docker.sh` | passed | `knot-ixfr-refresh/` |
| PowerDNS | Catalog TSIG | `scripts/interop-powerdns-postgres-catalog-tsig-docker.sh` | passed | `powerdns-postgres-catalog-tsig/` |

The matrix also retained:

- `primary-matrix-summary.tsv` with per-case script, status, exit code, and
  artifact directory.
- `primary-matrix-traceability.tsv` mapping selected requirement families to
  primary-version and case-specific traceability artifacts.
- Per-case `primary-version.txt` files containing primary implementation,
  configuration profile, transfer transport, transfer security, operating
  system/container source, and version command output.

## Harness Note

The NSD NOTIFY harness uses Docker port publishing for the NSD DNS listener and
a small UDP proxy for NOTIFY observation. NSD requires an IP-literal `notify`
target, while local Docker bridge gateway delivery is not reliable on every
host. The harness therefore discovers the host's routable IPv4 address for the
NSD `notify` target and retains failed workdirs when a case fails. The passing
case proves that NSD emitted an OPCODE=4 NOTIFY packet observed by the proxy and
that OxideDNS accepted the forwarded NOTIFY and refreshed from the NSD primary.
