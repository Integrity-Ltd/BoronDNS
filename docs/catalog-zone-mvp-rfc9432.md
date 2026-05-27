# Catalog Zone Engineering MVP Based on RFC 9432

Status: implemented Engineering MVP scope with explicit release-acceptance gaps

OxideDNS supports an Engineering MVP subset of DNS Catalog Zones as described
by RFC 9432. A configured catalog zone is transferred from trusted primaries in
the same way as ordinary secondary zones. OxideDNS then reads member-zone PTR
records under `zones.<catalog-zone>` and creates in-memory secondary service for
those member zones.

This feature has moved beyond the earlier static-zone-only scope: `[[zones]]`
remains supported for explicit zones, and `[[catalog_zones]]` is the supported
way to let a trusted primary publish the served zone set. The remaining
implementation gap is the catalog member-zone resource bound tracked as
`ODS-NFR-SEC-013` in `docs/mvp-gap-register.md`; broader retained evidence is a
formal SRS acceptance concern.

## RFC 9432 Scope

Implemented MVP behavior:

- Catalog zones are configured explicitly by the operator.
- Catalog zones are fetched over AXFR/IXFR from configured transfer primaries.
- The catalog schema version must be the RFC 9432 value `2`.
- Member zones are discovered from single-PTR member nodes directly below
  `zones.<catalog-zone>`.
- Unsupported catalog RRs and unsupported properties are ignored.
- Member zones inherit the catalog zone transfer primaries, transfer transport,
  TSIG key, NOTIFY source policy, transfer source binding, and transfer limits.
- Adding a member PTR schedules transfer of the new member zone.
- Removing a member PTR removes catalog-managed in-memory service for that
  member zone.
- Duplicate member zones or malformed required catalog data cause OxideDNS to
  leave the previous applied catalog membership unchanged.

Out of MVP scope:

- Per-member custom transfer settings from catalog properties.
- Catalog migration state beyond replacing the previous in-memory membership
  set for the configured catalog.
- Persistent catalog or member-zone state across process restarts.
- Primary-side catalog generation.

## Configuration

Catalog zones use the same primary and TSIG wiring as ordinary zones:

```toml
[[catalog_zones]]
name = "catalog.example."
class = "IN"
primaries = ["192.0.2.53:53"]
notify_sources = ["192.0.2.53"]
tsig_key = "transfer-key."
serve_catalog_zone = false
```

`serve_catalog_zone` controls whether the catalog zone itself is visible on the
DNS query interface. The default is `false`, because RFC 9432 treats catalog
zones as management data for authoritative-server farms, not as data intended
for recursive lookup. With the default, OxideDNS still transfers and processes
the catalog zone but does not answer authoritative DNS queries for that catalog
apex or names below it.

Catalog member zones are served on the DNS query interface after they transfer
successfully. They do not need `[[zones]]` entries.

## Operational Model

On startup OxideDNS inserts configured catalog zones into the zone-state
machine and starts transfer attempts. Once a catalog transfer succeeds,
member-zone refresh requests are queued. Member zones start in LOADING, become
ACTIVE after a successful transfer, and follow the same SOA-driven refresh and
expiry rules as statically configured zones.

Catalog transfers must be TSIG-authenticated. A catalog producer controls the
set of zones an OxideDNS instance serves, so OxideDNS rejects `[[catalog_zones]]`
entries without `tsig_key`. XoT plus tight source-address allowlisting should
be used where catalog confidentiality is also required; TSIG authenticates the
transfer but does not encrypt the catalog contents.

For ordinary static zones, `[transfer].require_tsig = true` enables fail-closed
startup validation for missing `tsig_key` references. Earlier SRS drafts used
the illustrative name `zones.require_tsig`; the implemented schema keeps this
as process-wide transfer policy under `[transfer]` because TOML reserves
`[[zones]]` for the zone array itself.

Configuration remains static for the catalog zone definitions themselves.
Changing the set of configured catalogs, their primaries, TSIG references, or
the `serve_catalog_zone` policy requires a process restart. The member-zone set
inside a catalog is dynamic and follows successful catalog transfers.

The current implementation does not yet expose the `ODS-NFR-SEC-013`
catalog-member resource bound (`max_member_zones` or equivalent). Until that
gap is closed, operators should treat catalog producers as trusted capacity
inputs and constrain catalog size at the producer or deployment boundary. The
release gap is tracked in `docs/mvp-gap-register.md`.

## Observability

Catalog membership changes are visible through structured logs and metrics.
When a newly observed member PTR is accepted for catalog-managed service,
OxideDNS emits `category=transfer`, `event=catalog_member_added`,
`catalog_zone=<catalog>`, and `zone=<member>`. Removed member zones emit
`event=catalog_member_removed`.

The `/metrics` endpoint exposes
`oxidedns_catalog_member_info{catalog_zone="...",zone="...",managed="..."} 1`
for the current catalog membership known to the process. `managed="true"`
means OxideDNS created dynamic secondary service for the member. `managed="false"`
means the catalog listed the zone, but a static `[[zones]]` entry already owns
that zone and the static configuration remains authoritative.

Member zones also appear in the normal per-zone metrics after they are inserted
into the zone-state machine. Use `oxidedns_secondary_zone_state`,
`oxidedns_secondary_zone_loading_seconds`,
`oxidedns_secondary_zone_soa_serial`, and the transfer counters to confirm that
a catalog member was discovered, transferred, and became ACTIVE.

## PowerDNS Primary Pattern

For an internal PowerDNS plus PostgreSQL primary, publish one RFC 9432 catalog
zone from PowerDNS and configure OxideDNS as a secondary for that catalog. Zone
creation then becomes:

1. Create or update the real authoritative zone in PowerDNS.
2. Add or remove the matching member PTR in the catalog zone.
3. Allow PowerDNS to notify OxideDNS for the catalog zone, or wait for the next
   SOA-driven catalog refresh.
4. OxideDNS transfers the catalog, schedules member transfers, and begins
   serving successfully transferred member zones externally.

The catalog zone itself can remain internal management data by leaving
`serve_catalog_zone = false`.
