![BoronDNS](docs/assets/borondns-banner.png)

# BoronDNS

BoronDNS is a secondary-only authoritative DNS server. It loads zone data from
configured primary DNS servers over AXFR or IXFR, keeps the active zone state in
memory, and serves authoritative answers over UDP and TCP.

It is **not** a recursive resolver, forwarder, primary DNS server, or zone-file
loader. It never originates zone data — it only re-serves what it transfers from
a primary.

Network listeners are split into three roles, configured under `[interfaces]`:

- `dns` — UDP/TCP query sockets; these also receive authorized inbound NOTIFY.
- `transfer` — outbound source addresses used when pulling transfers from primaries.
- `mgmt` — the operator-facing management interface for health and metrics.

BoronDNS accepts authorized NOTIFY on the DNS listeners; there is no separate
NOTIFY listener role.

## Features

- Incremental zone transfer (IXFR) with automatic full-transfer (AXFR) fallback.
- Outbound zone transfer over TLS (XoT).
- Passive DNSSEC serving — serves the RRSIG/NSEC/NSEC3 records received from the
  primary; BoronDNS never signs.
- Response Rate Limiting (RRL) and DNS Cookies for UDP abuse mitigation.
- RFC 9432 catalog zones, with opt-in member-transfer extensions.
- Reloadable, filesystem-backed TSIG / XoT secret snapshots.
- Broad EDNS(0) handling with bounded Extended DNS Error (EDE) diagnostics.
- Opt-in CHAOS-class identification (`version.bind` / `hostname.bind`).
- UDP / XDP data-plane tuning controls.

The exact boundaries of each slice are defined in
[Implemented feature scope](docs/implemented-feature-scope.md); adjacent features
are not implied unless that document names them.

## Project Status

BoronDNS is now tracked as a **release-candidate secondary server**, not as a
minimal local milestone. It is not yet a final formal SRS acceptance build: the
remaining closeout work is tracked in the
[SRS acceptance gap register](docs/mvp-gap-register.md). That register separates
implemented behavior and retained evidence from the release artifacts,
operator sign-off, and formal decisions still needed before an `ODS-VER-008`
acceptance claim.

The current release-candidate scope is wider than a minimal static-zone
secondary. Retained feature slices stay in scope exactly as bounded in
[Implemented feature scope](docs/implemented-feature-scope.md):
IXFR with AXFR fallback, outbound XoT transfers, passive DNSSEC serving, RRL,
DNS Cookies, RFC 9432 catalog zones, bounded EDE diagnostics, and opt-in CHAOS
identification. Adjacent features are not implied unless that scope document
names them.

## Start Here

- New checkout or deployment setup: [DevOps getting started](docs/devops-getting-started.md)
- Detailed operations reference: [Operator deployment guide](docs/operator-deployment-guide.md)
- Current release scope: [Release-candidate scope](docs/engineering-mvp-scope.md)
- Retained implemented feature slices: [Implemented feature scope](docs/implemented-feature-scope.md)
- Verification status: [Verification ledger](docs/verification-ledger.md)
- Full requirements: [BoronDNS Secondary SRS v0.9.1](docs/BoronDNS-Secondary-SRS-v0.9.1.md)
- External SRS review handling: [SRS review disposition](docs/srs-review-disposition.md)

## Quick Local Commands

Requires a Rust toolchain; `rust-toolchain.toml` selects the channel automatically
via rustup (MSRV is `1.95`). See
[DevOps getting started](docs/devops-getting-started.md) for full setup and release
builds. Each line below is an independent mode, not a sequence:

```bash
# Validate the config and exit (non-zero on error).
cargo run -p borondns-cli -- --validate-config config/borondns.example.toml
# Print the effective config with secrets redacted.
cargo run -p borondns-cli -- --dump-config config/borondns.example.toml
# Print a fresh annotated example config to stdout.
cargo run -p borondns-cli -- --example-config
# Run the server.
cargo run -p borondns-cli -- --config config/borondns.example.toml serve
# Run the local lint + test gate.
./scripts/check.sh
```

The checked-in example uses high DNS ports so it can run without root. For a real
deployment, copy it and replace the example primary addresses, zone names, TSIG
keys, XoT files, listener addresses, and management bind address. At least one
static secondary zone or catalog zone must be configured before service startup.

When no config path is supplied, `borondns` reads
`/etc/borondns-secondary/config.toml`. Top-level `--config` or
`BORONDNS_CONFIG` can override the path for validation, config dumping,
`check-config`, and `serve`. Mode-specific paths, such as `serve --config
path/to/config.toml`, remain supported and take precedence.

## Workspace

- `borondns-core`: configuration, DNS wire parsing, AXFR/IXFR parsing, TSIG, and
  in-memory zone state.
- `borondns-server`: runtime, listeners, transfers, reloadable secret snapshots,
  health, metrics, RRL, XoT, packet-I/O adapters, and graceful shutdown.
- `borondns-cli`: command-line entrypoint.
- `oxide-gun`: BoronDNS test-tool DNS load generator with portable UDP self-tests
  and an explicit Linux AF_XDP backend for lab hosts.

The workspace targets Rust 1.95, Rust 2024 edition, and Cargo resolver 3.

## Documentation Map

- [Architecture](docs/architecture.md)
- [Test plan](docs/test-plan.md)
- [Release evidence guide](docs/release-evidence-guide.md)
- [Debian 12 beta VM profile](docs/debian12-beta-vm-profile.md)
- [Operational SLO guide](docs/operational-slos.md)
- [Manual BIND interop smoke](docs/manual-bind-interop.md)
- [DNS client benchmark](docs/dns-client-benchmark.md)
- [OxideGun load generator](docs/oxide-gun.md)
- [Catalog Zone support based on RFC 9432](docs/catalog-zone-rfc9432.md)
- [Implementation plan](docs/implementation-plan.md)
- [Implemented feature scope](docs/implemented-feature-scope.md)
- [SRS acceptance gap register](docs/mvp-gap-register.md)
- [SRS review disposition](docs/srs-review-disposition.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Release notes template](docs/release-notes-template.md)
- [v0.2.0 release notes draft](docs/release-notes-v0.2.0-draft.md)
- [Specification document index](docs/README.md)

## License

BoronDNS is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
