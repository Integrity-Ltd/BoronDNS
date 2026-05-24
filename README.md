# OxideDNS

OxideDNS is the working Rust project for the secondary-only authoritative DNS server described by Tibor's 2026-05-23 specification package.

The initial implementation is intentionally a skeleton: it establishes the workspace, configuration surface, zone-state model, CLI entrypoints, and documentation layout before implementing protocol behavior.

## Source Documents

Normative order from the email:

1. [Software Requirements Specification](docs/OxideDNS-Secondary-SRS-v0.1.md)
2. [Software Development Specification / SBVR rules](docs/OxideDNS-Secondary-SBVR-v0.1.md)
3. [Executive Summary](docs/OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md)
4. Raw mailbox messages and attachment exports are intentionally not versioned in this repository.

## Workspace

- `oxidedns-core`: configuration, DNS vocabulary, and in-memory zone-state foundations.
- `oxidedns-server`: runtime shell for loading configuration and eventually serving DNS.
- `oxidedns-cli`: command-line entrypoint.

## Current Commands

```bash
cargo run -p oxidedns-cli -- check-config --config config/oxidedns.example.toml
cargo run -p oxidedns-cli -- serve --config config/oxidedns.example.toml
./scripts/check.sh
```

The workspace targets Rust 1.95 with the Rust 2024 edition and Cargo resolver 3.

The `serve` command currently validates configuration and starts the runtime skeleton. DNS query serving, AXFR/IXFR, NOTIFY, TSIG, XoT, EDNS0, DNSSEC record serving, and RRL are tracked by the specification but not implemented in this first project slice.

## License

OxideDNS is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
