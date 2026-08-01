# Catalog Zone Support Based on RFC 9432

Status: implemented Engineering MVP scope with explicit release-acceptance gaps

BoronDNS supports a bounded subset of DNS Catalog Zones as described
by RFC 9432. A configured catalog zone is transferred from trusted primaries in
the same way as ordinary secondary zones. BoronDNS then reads member-zone PTR
records under `zones.<catalog-zone>` and creates in-memory secondary service for
those member zones.

This feature has moved beyond the earlier static-zone-only scope: `[[zones]]`
remains supported for explicit zones, and `[[catalog_zones]]` is the supported
way to let a trusted primary publish the served zone set. The remaining work is
broader retained release evidence against production catalog producers and
deployment profiles.

## RFC 9432 Scope

Implemented behavior in the current Engineering MVP:

- Catalog zones are configured explicitly by the operator.
- Catalog zones are fetched over AXFR/IXFR from configured transfer primaries.
- The catalog schema version must be the RFC 9432 value `2`.
- Member zones are discovered from single-PTR member nodes directly below
  `zones.<catalog-zone>`.
- Unsupported catalog RRs and unsupported properties are ignored.
- Member zones inherit the catalog zone transfer primaries, transfer transport,
  TSIG key, NOTIFY source policy, transfer source binding, and transfer limits
  by default.
- Operators can split catalog-transfer and member-transfer policy with
  `catalog_primaries`/`catalog_transfer_primaries`, `catalog_tsig_key`,
  `member_primaries`/`member_transfer_primaries`, and `member_tsig_key`. This
  lets BoronDNS transfer the RFC 9432 catalog from a managed PowerDNS publisher
  while transferring member zones from BIND, Knot, NSD, PowerDNS, or customer
  primaries selected by the catalog group.
- Operators can opt in to per-member transfer metadata with
  `member_transfer_extensions = true`. BoronDNS then accepts BIND-compatible
  `primaries.ext.<member-node>` A/AAAA records, a common
  `primaries.ext.<member-node>` TXT TSIG key-name reference, and
  BoronDNS-specific extension TXT records for transfer transport and NOTIFY
  source policy.
- Adding a member PTR schedules transfer of the new member zone.
- Removing a member PTR removes catalog-managed in-memory service for that
  member zone.
- Duplicate member zones or malformed required catalog data cause BoronDNS to
  leave the previous applied catalog membership unchanged.
- Malformed member PTR RRsets and malformed member PTR RDATA make the candidate
  catalog version broken under RFC 9432; BoronDNS does not partially apply the
  remaining member list from that candidate version.
- BoronDNS accepts structurally valid catalog member names by RFC 9432 §4.1,
  including the RFC example names `example.com.`, `example.net.`, and
  `example.org.` and other IANA Special-Use names. These names are not
  malformed merely because they are special-use names.
- Incoming member zones that clash with existing configured catalog zones,
  already-applied catalog members, or static zones are ignored and logged per
  RFC 9432 §5.2.

Outside this Engineering MVP catalog slice:

- Catalog migration state beyond replacing the previous in-memory membership
  set for the configured catalog.
- Persistent catalog or member-zone state across process restarts.
- Optional product-specific member-name allow-list or deny-list policy. The
  default catalog profile follows RFC 9432 member-name semantics rather than
  silently rejecting IANA Special-Use names or wildcard labels.
- Carrying plaintext TSIG secrets, XoT trust anchors, client certificates, or
  client keys inside the catalog. Catalog data carries references only. TSIG
  secrets and TLS trust/client material remain local startup configuration or
  reloadable filesystem secret-store snapshots.

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
for recursive lookup. With the default, BoronDNS still transfers and processes
the catalog zone but does not answer authoritative DNS queries for that catalog
apex or names below it.

Catalog member zones are served on the DNS query interface after they transfer
successfully. They do not need `[[zones]]` entries.

Per-member transfer metadata is disabled by default. Enable it only for catalog
profiles whose producer is allowed to choose member-zone transfer targets:

```toml
[[catalog_zones]]
name = "catalog.example."
catalog_primaries = ["192.0.2.10:53"]
member_primaries = ["203.0.113.53:53"] # fallback if a member has no override
catalog_tsig_key = "catalog-transfer-key."
member_tsig_key = "fallback-member-key."
member_transfer_extensions = true
```

With that switch enabled, a member node such as
`a.zones.catalog.example.` can override the fallback member transfer policy
with records like:

```text
a.zones.catalog.example. PTR member.example.
primaries.ext.a.zones.catalog.example. A 198.51.100.53
primaries.ext.a.zones.catalog.example. TXT "member-key."
_udns-xfr.a.zones.catalog.example. TXT "transport=tcp;port=5300"
_udns-notify.a.zones.catalog.example. TXT "source=198.51.100.54"
```

Malformed extension data rejects only the member transfer override. The member
PTR remains an RFC 9432 catalog member, and BoronDNS falls back to static member
policy for newly added members or retains the last valid plan for already
managed members. Multiple distinct TSIG key-name TXT values for one member are
treated as unsafe because BoronDNS uses one TSIG key per transferred zone.

For XoT member overrides, the catalog TXT can set `transport=xot`, `port`, and
`server_name`, but the TLS trust/client material still has to be available
through inherited static configuration or a named XoT profile from
`[secret_store]`.

## Operational Model

On startup BoronDNS inserts configured catalog zones into the zone-state
machine and starts transfer attempts. Once a catalog transfer succeeds,
member-zone refresh requests are queued. Member zones start in LOADING, become
ACTIVE after a successful transfer, and follow the same SOA-driven refresh and
expiry rules as statically configured zones.

Catalog transfers must be TSIG-authenticated. A catalog producer controls the
set of zones an BoronDNS instance serves, so BoronDNS rejects `[[catalog_zones]]`
entries without `tsig_key` or `catalog_tsig_key`. XoT plus tight
source-address allowlisting should be used where catalog confidentiality is also
required; TSIG authenticates the transfer but does not encrypt the catalog
contents.

Catalog member transfers inherit `member_tsig_key` when set, otherwise
`tsig_key`, and are therefore TSIG-authenticated by default. For legacy customer
primary deployments that can only serve private-network AXFR without TSIG/XoT,
operators may set
`catalog_zones.member_transfer_policy.unsigned_axfr = "allow-legacy-private"`.
That local policy disables the catalog-key fallback for member transfers when
`member_tsig_key` is unset. BoronDNS rejects unsigned member AXFR plans whose
primary address is not private, including catalog-advertised primary overrides.
The policy does not relax the mandatory TSIG requirement for the catalog
transfer itself. If a member advertises an explicit TSIG key name in the
extension records, BoronDNS still treats that as an authenticated transfer
reference and fails closed if the key material is unavailable.

For ordinary static zones, `[transfer].require_tsig = true` enables fail-closed
startup validation for missing `tsig_key` references. The unsupported
illustrative name `zones.require_tsig` is intentionally not part of the schema;
the implemented schema keeps this as process-wide transfer policy under
`[transfer]` because TOML reserves `[[zones]]` for the zone array itself.

Configuration remains static for the catalog zone definitions themselves.
Changing the set of configured catalogs, their catalog/member primaries, TSIG
reference fields, or the `serve_catalog_zone` policy requires a process restart.
The member-zone set inside a catalog is dynamic and follows successful catalog
transfers. When `[secret_store]` is configured, new or rotated TSIG keys and
named XoT profiles can be loaded from the filesystem snapshot and then used by
catalog member references without restarting BoronDNS.

When several configured catalogs list the same member zone, the already-applied
instance keeps its transfer and NOTIFY policy. A later clashing instance is
ignored and logged, as required by RFC 9432 section 5.2; catalog-name ordering
does not replace an existing instance. If the owning catalog removes the
member, BoronDNS removes that instance. A catalog whose earlier listing was
ignored must subsequently publish a new change (or be retransferred) before its
instance can be accepted; ownership does not move automatically from stale
clash state.

Changing the member-node Unique identifier while retaining the same PTR target
is a remove/reset/re-add operation under RFC 9432 section 5.4. BoronDNS discards
the old transfer plan, refresh/NOTIFY state, and active snapshot, then starts the
renamed member in LOADING with a new plan generation. This prevents state tied
to the old member node from leaking into the replacement instance.

The useful mental model is:

- TOML says which catalogs this process trusts and what local policy applies.
- The transferred catalog says which member zones should exist.
- Optional extension records can name where those members transfer from.
- The local secret store supplies the actual TSIG and XoT secret material by
  reference.

Each `[[catalog_zones]]` entry has a `max_member_zones` cap, defaulting to
10,000 per `BDS-NFR-SEC-013`. If a catalog lists more member zones than the
configured cap, BoronDNS accepts the deterministic first `N` members after
canonical ordering, drops the excess, and emits
`event=catalog_member_limit_exceeded` with the configured limit, observed member
count, and dropped count. Operators should size this cap with the memory and
capacity limits of the deployment.

## Observability

Catalog membership changes are visible through structured logs and metrics.
When a newly observed member PTR is accepted for catalog-managed service,
BoronDNS emits `category=transfer`, `event=catalog_member_added`,
`catalog_zone=<catalog>`, and `zone=<member>`. Removed member zones emit
`event=catalog_member_removed`.

The `/metrics` endpoint exposes
`borondns_catalog_member_info{catalog_zone="...",zone="...",managed="..."} 1`
for the current catalog membership known to the process. `managed="true"`
means BoronDNS created dynamic secondary service for the member. `managed="false"`
means the catalog listed the zone, but a static `[[zones]]` entry already owns
that zone and the static configuration remains authoritative.

Member zones also appear in the normal per-zone metrics after they are inserted
into the zone-state machine. Use `borondns_secondary_zone_state`,
`borondns_secondary_zone_loading_seconds`,
`borondns_secondary_zone_soa_serial`, and the transfer counters to confirm that
a catalog member was discovered, transferred, and became ACTIVE.

## PowerDNS Primary Pattern

For an internal PowerDNS plus PostgreSQL primary, publish one RFC 9432 catalog
zone from PowerDNS and configure BoronDNS as a secondary for that catalog. If
PowerDNS is also the content primary, the legacy inherited `primaries`/`tsig_key`
shape is enough. If PowerDNS is only the management/catalog publisher, configure
the catalog with split transfer policy so catalog transfers point to PowerDNS
and member transfers point to the content primary group.

Zone creation then becomes:

1. Create or update the real authoritative zone in PowerDNS.
2. Add or remove the matching member PTR in the catalog zone for the relevant
   transfer-policy group.
3. Allow PowerDNS to notify BoronDNS for the catalog zone, or wait for the next
   SOA-driven catalog refresh.
4. BoronDNS transfers the catalog, schedules member transfers, and begins
   serving successfully transferred member zones externally.

The catalog zone itself can remain internal management data by leaving
`serve_catalog_zone = false`.
