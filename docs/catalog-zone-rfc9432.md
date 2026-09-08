# Catalog zones

BoronDNS uses RFC 9432 version 2 catalogs to discover secondary zones. You
configure which catalogs to trust; a successful catalog transfer adds or removes
member zones without editing `[[zones]]` or restarting the server. Members
become available for queries after their own transfers succeed.

## Configure a catalog

For a primary that publishes both the catalog and its member zones:

```toml
[[catalog_zones]]
name = "catalog.example."
class = "IN"
primaries = ["192.0.2.53:53"]
notify_sources = ["192.0.2.53"]
tsig_key = "transfer-key."
serve_catalog_zone = false
```

The TSIG key must exist in the local key configuration or secret-store snapshot.
Catalog transfers always require TSIG: the catalog controls which zones this
server will serve. TSIG authenticates data but does not encrypt it; use XoT when
the transfer also needs confidentiality.

### Catalog authority

A configured catalog publisher is trusted to provision any valid zone name,
including `.` and single-label TLDs. There is no per-catalog namespace allowlist.
Static/catalog ownership conflicts are still filtered, and query selection uses
the most-specific visible zone: an allowed root zone does not replace a more
specific local zone. Keep catalogs from mutually untrusted administrators on
separate server instances if their provisioning authority must be isolated.

Enabling member-transfer extensions grants additional network authority. There
is no general destination, port, or TLS-name allowlist for authenticated member
transfers. A catalog can change the destination and select `server_name` within
an existing XoT profile; the profile's certificate verification and client
credentials remain in use. TSIG authenticates transferred data, not permission
to contact a destination. Enable extensions only for trusted provisioning
administrators, and use network egress policy when destinations must be bounded.
The private-address check for legacy unsigned TCP is not a general egress policy.

`serve_catalog_zone` defaults to `false`. BoronDNS transfers and processes the
catalog but hides its management records from ordinary DNS queries. Its member
zones remain independently visible. Set this option to `true` only if the
catalog itself should be served.

If the catalog publisher and content primaries differ, use separate policies:

```toml
[[catalog_zones]]
name = "catalog.example."
catalog_primaries = ["192.0.2.10:53"]
member_primaries = ["203.0.113.53:53"]
catalog_tsig_key = "catalog-transfer-key."
member_tsig_key = "member-transfer-key."
```

Use `catalog_transfer_primaries` and `member_transfer_primaries` for structured
transfer targets, including XoT. Do not mix shared `primaries`/`transfer_primaries`
with the split catalog/member primary fields.

Member transfers use `member_tsig_key` when set, otherwise the shared
`tsig_key`. `catalog_tsig_key` applies only to the catalog; it is not a member
key fallback. The configured transfer, source binding, NOTIFY policy, and limits
apply unless a supported member override changes them.

## Catalog updates and errors

BoronDNS reads one PTR per member node directly below `zones.<catalog>` and
requires schema version `2`. Unknown records and unsupported properties are
ignored. The following rules determine whether an update changes service:

| Catalog change | Result |
| --- | --- |
| Add a valid member PTR | Schedule the member's initial transfer |
| Remove a member PTR | Remove that catalog-managed zone from service |
| Invalid version, malformed member PTR, or duplicate member target | Reject the candidate membership; retain the previously applied membership |
| Member conflicts with a static zone, configured catalog, or already-applied catalog member | Ignore and log the incoming member |
| Change a member's unique node identifier but keep its PTR target | Remove/reset the old instance and load a new one |
| Exceed `max_member_zones` | Keep the deterministic first eligible members in canonical order and log the excess |

Member-name validation follows RFC 9432 §4.1. IANA Special-Use names such as
`example.com.` are valid member names; they are not rejected merely because
they are reserved for a particular use. Name clashes follow RFC 9432 §5.2:
an existing instance keeps its ownership and transfer policy.

If an owning catalog removes a member, another catalog's previously ignored
listing does not automatically take ownership. That other catalog must publish
a new change or be retransferred. Changing the unique identifier follows the
reset behavior in RFC 9432 §5.4, including discarding the old snapshot and
refresh/NOTIFY state.

`max_member_zones` defaults to 10,000 per catalog and must be positive. Choose
it for the deployment's memory capacity. Excess entries produce
`event=catalog_member_limit_exceeded` with the limit, observed member count,
and dropped count.

## Optional member transfer overrides

`member_transfer_extensions = true` lets the trusted catalog producer choose
member transfer targets. It is disabled by default. Enable it only where that
producer is permitted to direct outbound transfers.

For member node `a.zones.catalog.example.`, these records override the
configured member policy:

```text
a.zones.catalog.example. PTR member.example.
primaries.ext.a.zones.catalog.example. A 198.51.100.53
primaries.ext.a.zones.catalog.example. TXT "member-key."
_udns-xfr.ext.a.zones.catalog.example. TXT "transport=tcp;port=5300"
_udns-notify.ext.a.zones.catalog.example. TXT "source=198.51.100.54"
```

The `primaries.ext` A/AAAA records and TXT key-name reference use the
BIND-compatible form. The transfer/NOTIFY TXT properties are BoronDNS
extensions. All custom properties belong below `ext`; legacy extension owners
outside `ext` are ignored. The `_udns-*` labels are retained wire-format names
from the original control-plane integration, not a separate DNS server or
telemetry feature.

Malformed extensions do not invalidate the member PTR. For a new member,
BoronDNS uses its configured fallback policy; an existing member retains its
last valid transfer plan. Several distinct TSIG names for one member are
rejected as an override because one transfer uses one key. An explicit key
reference with unavailable secret material fails closed.

An XoT override may specify `transport=xot`, `port`, and `server_name`. TLS
trust and client credentials must still come from inherited local configuration
or a named XoT profile in `[secret_store]`. Catalogs carry references, never
plaintext TSIG secrets or TLS key material.

## Legacy unsigned member transfers

For private-network primaries that cannot authenticate AXFR, local policy can
allow unsigned member transfers:

```toml
[catalog_zones.member_transfer_policy]
unsigned_axfr = "allow-legacy-private"
```

Place this subtable under the relevant `[[catalog_zones]]` entry. When
`member_tsig_key` is unset, this option disables the shared `tsig_key` fallback
for members. Unsigned TCP member plans must use private primary addresses,
including addresses supplied through member overrides. An explicitly configured
member key still requires authentication.

The catalog transfer remains TSIG-authenticated. For static zones,
`[transfer].require_tsig = true` is the separate process-wide option that
rejects missing zone TSIG references at startup.

## Restarts and observation

Catalog definitions and their configured transfer policy are startup settings.
Changing them requires a restart. Catalog membership changes dynamically through
successful transfers. A configured filesystem secret store can load rotated
TSIG keys and XoT profiles without restarting. Validated last-good snapshots
support restart recovery; arbitrary catalog policy and cross-catalog migration
state are not a separate persistent database.

Watch `event=catalog_member_added`, `event=catalog_member_removed`, and
`event=catalog_member_name_clash` in transfer logs. The metric
`borondns_catalog_member_info{catalog_zone="...",zone="...",managed="..."} 1`
lists known membership. `managed="true"` means the catalog created the dynamic
secondary; `managed="false"` identifies a listing owned by static configuration.

Use `borondns_secondary_zone_state`,
`borondns_secondary_zone_loading_seconds`, and
`borondns_secondary_zone_soa_serial` with transfer counters to distinguish
discovery, loading, active service, and expiry. A member listed in a catalog is
not necessarily ready to answer.

For a PowerDNS catalog publisher, create/update the member zone on its content
primary, update the corresponding catalog PTR, then notify BoronDNS for the
catalog or wait for its SOA refresh. BoronDNS discovers the change and schedules
member transfers. The publisher and content primary may be the same server or
separate groups using the split configuration above.
