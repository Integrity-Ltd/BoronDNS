# Fuzzing

This directory uses `cargo-fuzz` conventions and starts MVP parser coverage with
these targets:

- `dns_datagram`: DNS header/question parsing and ordinary datagram response
  construction.
- `transfer_stream`: AXFR and IXFR response-stream parsing from TCP-style
  length-prefixed chunks.
- `tsig_message`: TSIG record detection, MAC extraction, request/response
  verification, TSIG error responses, and TCP response-stream TSIG chaining.
- `notify_edns_datagram`: NOTIFY request handling and EDNS OPT parsing against
  a populated `alpha.test.` zone, including shaped packets with fuzzed SOA and
  EDNS option payloads.

Run a compile check with a nightly cargo on `PATH`, without executing a long
fuzzing campaign:

```sh
cargo fuzz check dns_datagram
cargo fuzz check transfer_stream
cargo fuzz check tsig_message
cargo fuzz check notify_edns_datagram
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

The TSIG target exercises public `oxidedns-core::tsig` APIs for raw and shaped DNS
messages. The NOTIFY/EDNS target exercises public datagram answering APIs with
authorization and acceptance hooks while varying UDP/TCP answer options.
