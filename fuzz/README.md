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
- `zone_image_datagram`: raw and shaped query packets through the `ZoneImage`
  response path against a populated `zoneimage.test.` zone, including direct
  answers, CNAME, DNAME synthesis, wildcard owner substitution, referrals with
  glue, answer-section additionals, basic DNSSEC augmentation, QTYPE=ANY,
  EDNS, opaque unknown records, and malformed known-name RDATA records that
  must be copied opaquely without panicking.

Run a compile check with a nightly cargo on `PATH`, without executing a long
fuzzing campaign:

```sh
cargo fuzz check dns_datagram
cargo fuzz check transfer_stream
cargo fuzz check tsig_message
cargo fuzz check notify_edns_datagram
cargo fuzz check zone_image_datagram
```

Or, without a nightly toolchain or `cargo-fuzz` installed:

```sh
cargo check --manifest-path fuzz/Cargo.toml
```

For retained local evidence, use the short campaign runner from the repository
root. It defaults to all known fuzz targets for 10 seconds per target and writes
logs, artifacts, command lines, `campaign-summary.tsv`, and
tool-version/config records under `target/fuzz-evidence/<timestamp>/`:

```sh
scripts/fuzz-campaign.sh
```

Select targets and duration explicitly when needed:

```sh
scripts/fuzz-campaign.sh --duration 60 dns_datagram tsig_message
scripts/fuzz-campaign.sh --target transfer_stream --target notify_edns_datagram
scripts/fuzz-campaign.sh --target zone_image_datagram
scripts/fuzz-campaign.sh --toolchain nightly --target zone_image_datagram
scripts/fuzz-campaign.sh --toolchain nightly --sanitizer address --target dns_datagram
```

Check the planned commands without starting a fuzzing run:

```sh
scripts/fuzz-campaign.sh --dry-run --duration 1 --target dns_datagram
scripts/fuzz-campaign.sh --dry-run --toolchain nightly --target zone_image_datagram
```

The retained `campaign-summary.tsv` is the release/operations handoff index for
longer runs. Each row records target, status, exit status, duration, log path,
artifact directory, and command file, so a 24-hour campaign can be attached to
release notes without scraping individual logs.

Generated cargo-fuzz corpus files under `fuzz/corpus/` are ignored by default.
Promote minimized regression inputs into a tracked fixture intentionally rather
than committing the auto-grown local corpus wholesale.

If the default `cargo` on `PATH` is a wrapper that cannot see the repository's
real filesystem path, either use `--toolchain nightly` so the runner prepends
the rustup-selected cargo directory for cargo-fuzz's inner build, or set
`CARGO` to the absolute cargo binary for the intended toolchain.

The target exercises public `oxidedns-core` DNS parser and datagram handling APIs:
`Header::parse`, `Question::parse`, and `answer_datagram` against an empty
`ZoneStore`.

The transfer target exercises `parse_axfr_response` and `parse_ixfr_response`
against a fixed current `alpha.test.` zone snapshot.

The TSIG target exercises public `oxidedns-core::tsig` APIs for raw and shaped DNS
messages. The NOTIFY/EDNS target exercises public datagram answering APIs with
authorization and acceptance hooks while varying UDP/TCP answer options. The
ZoneImage target exercises the same datagram API with a static compiled image,
raw fuzz input, shaped qname/qtype/EDNS queries, compression-eligible records,
synthesized DNAME and wildcard answers, referral/glue and additional section
composition, DNSSEC proof/signature augmentation, and malformed known-name
RDATA that should safely fall back to opaque copying.
