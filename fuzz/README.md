# Fuzzing

This directory uses `cargo-fuzz` conventions and starts MVP parser coverage with
these targets:

- `dns_datagram`: DNS header/question parsing and ordinary datagram response
  construction.
- `transfer_stream`: AXFR and IXFR response-stream parsing from TCP-style
  length-prefixed chunks.

Run a compile check with a nightly cargo on `PATH`, without executing a long
fuzzing campaign:

```sh
cargo fuzz check dns_datagram
cargo fuzz check transfer_stream
```

Or, without a nightly toolchain or `cargo-fuzz` installed:

```sh
cargo check --manifest-path fuzz/Cargo.toml
```

The target exercises public `oxidedns-core` DNS parser and datagram handling APIs:
`Header::parse`, `Question::parse`, and `answer_datagram` against an empty
`ZoneStore`.

The transfer target exercises `parse_axfr_response` and `parse_ixfr_response`
against a fixed current `alpha.test.` zone snapshot.
