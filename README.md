# OxideDNS

OxideDNS is the working Rust project for the secondary-only authoritative DNS server described by Tibor's 2026-05-23 specification package.

The implementation is currently in early Alpha work: it establishes the workspace, configuration surface, zone-state model, CLI entrypoints, documentation layout, and initial DNS protocol behavior.

## Source Documents

Normative order from the email:

1. [Software Requirements Specification](docs/OxideDNS-Secondary-SRS-v0.1.md)
2. [Software Development Specification / SBVR rules](docs/OxideDNS-Secondary-SBVR-v0.1.md)
3. [Executive Summary](docs/OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md)
4. Raw mailbox messages and attachment exports are intentionally not versioned in this repository.

Implementation planning:

- [MVP and Alpha implementation plan](docs/implementation-plan.md)

## Workspace

- `oxidedns-core`: configuration, DNS wire parsing, EDNS handling, AXFR parsing, and in-memory zone-state foundations.
- `oxidedns-server`: runtime for loading configuration, initial AXFR, and UDP/TCP authoritative DNS serving.
- `oxidedns-cli`: command-line entrypoint.

## Current Commands

```bash
cargo run -p oxidedns-cli -- check-config --config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- serve --config config/oxidedns.example.toml
./scripts/check.sh
```

The workspace targets Rust 1.95 with the Rust 2024 edition and Cargo resolver 3.

The `serve` command currently validates configuration, performs AXFR attempts from configured primaries, binds configured UDP/TCP listeners, parses DNS queries, and emits authoritative responses from active in-memory zone snapshots. EDNS0 OPT parsing, UDP truncation, TCP keepalive advertisement, default-off response padding, configurable ANY-query minimisation, authorized NOTIFY-triggered AXFR refresh, and preliminary SOA REFRESH/RETRY/EXPIRE scheduling are partially implemented. IXFR, SOA-poll refresh checks, scheduling jitter, TSIG, XoT, DNSSEC record serving, RRL, and full query semantics are tracked by the specification but are not complete yet.

## License

OxideDNS is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
