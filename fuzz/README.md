# Fuzzing

This directory uses `cargo-fuzz` conventions and starts MVP parser coverage with
the `dns_datagram` target.

Run a compile check with a nightly cargo on `PATH`, without executing a long
fuzzing campaign:

```sh
cargo fuzz check dns_datagram
```

Or, without a nightly toolchain or `cargo-fuzz` installed:

```sh
cargo check --manifest-path fuzz/Cargo.toml
```

The target exercises public `oxidedns-core` DNS parser and datagram handling APIs:
`Header::parse`, `Question::parse`, and `answer_datagram` against an empty
`ZoneStore`.
