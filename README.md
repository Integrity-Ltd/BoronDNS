![OxideDNS](docs/assets/oxidedns-banner.png)

# OxideDNS

OxideDNS is a secondary-only authoritative DNS server. It loads zone data from
configured primary DNS servers over AXFR or IXFR, keeps the active zone state in
memory, and serves authoritative DNS answers over UDP and TCP.
It uses separate DNS, transfer, and management interface roles. OxideDNS accepts authorized NOTIFY on the DNS listeners.

The project is currently aimed at an Engineering MVP: a working, testable
secondary server with clear operating boundaries. It is not yet a final SRS
release-acceptance build.

The implemented Engineering MVP is wider than a minimal static-zone secondary
server. Retained feature slices stay in scope exactly as bounded in
[Implemented feature scope](docs/implemented-feature-scope.md), with
release-acceptance evidence gaps tracked separately.

## Start Here

- New checkout or deployment setup: [DevOps getting started](docs/devops-getting-started.md)
- Detailed operations reference: [Operator deployment guide](docs/operator-deployment-guide.md)
- Current implementation target: [Engineering MVP scope](docs/engineering-mvp-scope.md)
- Retained implemented feature slices: [Implemented feature scope](docs/implemented-feature-scope.md)
- Verification status: [Verification ledger](docs/verification-ledger.md)
- Full requirements: [OxideDNS Secondary SRS v0.9.1](docs/OxideDNS-Secondary-SRS-v0.9.1.md)
- External SRS review handling: [SRS review disposition](docs/srs-review-disposition.md)

## Quick Local Commands

```bash
cargo run -p oxidedns-cli -- --validate-config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- --dump-config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- --example-config
cargo run -p oxidedns-cli -- serve --config config/oxidedns.example.toml
./scripts/check.sh
```

The checked-in example uses high DNS ports so it can run without root. For a real
deployment, copy it and replace the example primary addresses, zone names, TSIG
keys, XoT files, listener addresses, and management bind address.

When no config path is supplied, `oxidedns` reads
`/etc/oxidedns-secondary/config.toml`. `OXIDEDNS_CONFIG` can override the path
for validation, config dumping, `check-config`, and `serve`.

## Workspace

- `oxidedns-core`: configuration, DNS wire parsing, AXFR/IXFR parsing, TSIG, and
  in-memory zone state.
- `oxidedns-server`: runtime, listeners, transfers, health, metrics, RRL, XoT,
  and graceful shutdown.
- `oxidedns-cli`: command-line entrypoint.
- `oxide-gun`: OxideDNS test-tool DNS load generator with portable UDP self-tests
  and an explicit Linux AF_XDP backend for lab hosts.

The workspace targets Rust 1.95, Rust 2024 edition, and Cargo resolver 3.

## Documentation Map

- [Architecture](docs/architecture.md)
- [Test plan](docs/test-plan.md)
- [Manual BIND interop smoke](docs/manual-bind-interop.md)
- [DNS client benchmark](docs/dns-client-benchmark.md)
- [OxideGun load generator](docs/oxide-gun.md)
- [Catalog Zone support based on RFC 9432](docs/catalog-zone-rfc9432.md)
- [Implementation plan](docs/implementation-plan.md)
- [Implemented feature scope](docs/implemented-feature-scope.md)
- [MVP gap register](docs/mvp-gap-register.md)
- [SRS review disposition](docs/srs-review-disposition.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Release notes template](docs/release-notes-template.md)
- [Specification document index](docs/README.md)

## License

OxideDNS is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
