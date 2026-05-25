# OxideDNS

OxideDNS is the working Rust project for the secondary-only authoritative DNS server described by Tibor's OxideDNS-Secondary SRS package.

The implementation is currently in early Alpha work: it establishes the workspace, configuration surface, zone-state model, CLI entrypoints, documentation layout, and initial DNS protocol behavior.

## Source Documents

Normative order:

1. [Software Requirements Specification v0.7](docs/OxideDNS-Secondary-SRS-v0.7.md)
2. [Software Development Specification / SBVR rules](docs/OxideDNS-Secondary-SBVR-v0.1.md)
3. [Executive Summary v0.1](docs/OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md)
4. Raw mailbox messages and attachment exports are intentionally not versioned in this repository.

Implementation planning:

- [Engineering MVP and SRS acceptance implementation plan](docs/implementation-plan.md)
- [Engineering MVP and SRS acceptance gap register](docs/mvp-gap-register.md)
- [Verification ledger](docs/verification-ledger.md)

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
./scripts/release-evidence-snapshot.sh
```

When the config path is omitted, `oxidedns` uses `/etc/oxidedns-secondary/config.toml`; `OXIDEDNS_CONFIG` can override that path for `--validate-config`, `--dump-config`, `check-config`, and `serve`.

The workspace targets Rust 1.95 with the Rust 2024 edition and Cargo resolver 3.

The `serve` command currently validates configuration, performs AXFR and IXFR refresh attempts from configured primaries using OS-random query IDs, binds configured UDP/TCP listeners, parses DNS queries, and emits authoritative responses from active in-memory zone snapshots. EDNS0 OPT parsing, NSID responses, RFC 9018 DNS Cookie learning/validation with lenient or strict policy, UDP truncation, TCP keepalive advertisement, default-off response padding, configurable ANY-query minimisation, authorized NOTIFY-triggered refresh, preliminary SOA REFRESH/RETRY/EXPIRE scheduling, TSIG-signed transfer and NOTIFY paths, DNSSEC augmentation for served records, UDP response-rate limiting, and initial XoT TLS transport are partially implemented. SRS v0.7 adds immediate Alpha/MVP pressure for complete DNS Cookies, expanded interface/CLI behavior, stronger verification governance, and additional NFR evidence; `--validate-config`, redacted `--dump-config`, `--example-config`, and initial sysexits-style CLI exit mapping are now implemented, while the remaining gaps are tracked before further MVP claims.

## License

OxideDNS is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
