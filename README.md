# OxideDNS

OxideDNS is the working Rust project for the secondary-only authoritative DNS server described by Tibor's OxideDNS-Secondary SRS package.

The implementation is targeting the local Engineering MVP: a deployable
secondary-authoritative DNS server with deterministic local checks, short
runtime evidence, and explicit separation from later SRS release-acceptance
evidence.

## Source Documents

Normative order:

1. [Software Requirements Specification v0.7](docs/OxideDNS-Secondary-SRS-v0.7.md)
2. [Software Development Specification / SBVR rules](docs/OxideDNS-Secondary-SBVR-v0.1.md)
3. [Executive Summary v0.1](docs/OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md)
4. Raw mailbox messages and attachment exports are intentionally not versioned in this repository.

Implementation planning:

- [Engineering MVP and SRS acceptance implementation plan](docs/implementation-plan.md)
- [Engineering MVP scope](docs/engineering-mvp-scope.md)
- [Engineering MVP and SRS acceptance gap register](docs/mvp-gap-register.md)
- [Verification ledger](docs/verification-ledger.md)
- [Test Plan](docs/test-plan.md)
- [Architecture and release governance scaffold](docs/architecture.md)
- [Security policy](SECURITY.md)

## Workspace

- `oxidedns-core`: configuration, DNS wire parsing, EDNS handling, AXFR parsing, and in-memory zone-state foundations.
- `oxidedns-server`: runtime for loading configuration, initial AXFR, and UDP/TCP authoritative DNS serving.
- `oxidedns-cli`: command-line entrypoint.

## Current Commands

```bash
cargo run -p oxidedns-cli -- --validate-config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- --dump-config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- --example-config
cargo run -p oxidedns-cli -- check-config --config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- serve --config config/oxidedns.example.toml
./scripts/check.sh
./scripts/perf-smoke.sh
```

When the config path is omitted, `oxidedns` uses `/etc/oxidedns-secondary/config.toml`; `OXIDEDNS_CONFIG` can override that path for `--validate-config`, `--dump-config`, `check-config`, and `serve`.

The workspace targets Rust 1.95 with the Rust 2024 edition and Cargo resolver 3.

The `serve` command validates configuration, performs AXFR and IXFR refresh
attempts from configured primaries using OS-random query IDs, binds configured
UDP/TCP DNS listeners and management listeners, and parses DNS queries. It
accepts authorized NOTIFY on the DNS listeners and emits authoritative responses
from active in-memory zone snapshots. The current Engineering MVP path includes
EDNS0
OPT handling, NSID responses, RFC 9018 DNS Cookie behavior, UDP truncation, TCP
keepalive advertisement, default-off response padding, configurable ANY-query
minimisation, authorized NOTIFY-triggered refresh, SOA REFRESH/RETRY/EXPIRE
scheduling foundations, TSIG-signed transfer and NOTIFY paths, DNSSEC serving of
transferred records, UDP response-rate limiting, and XoT TLS transport.

Long-running fuzz campaigns, Reference Hardware/Profile benchmarks, 30-day soak
execution, production-depth log profiling, external operator acceptance,
independent reproducible-build comparison, and signed release artifacts are
later SRS acceptance work, not Engineering MVP requirements.

## License

OxideDNS is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
