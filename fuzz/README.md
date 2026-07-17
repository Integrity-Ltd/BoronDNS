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
- `catalog_zone`: RFC 9432 catalog-zone member parsing plus the uDNS transfer
  extension records for member primaries, TSIG key names, XoT/TCP transfer
  hints, and NOTIFY source overrides.
- `zone_store_state`: stateful sequences of publication, hiding, showing,
  expiry, replacement, and removal. It checks query visibility, readiness
  aggregates, exact control metadata, and the cached active count after every
  transition.
- `zone_store_concurrent`: four persistent-worker adversarial publication,
  visibility, expiry, and removal sequences against shared zones. Reusing the
  workers bounds sanitizer thread bookkeeping across multi-day campaigns while
  retaining real concurrent mutation. The target checks the cached active count
  and published/control views after all four workers complete each input.
- `server_lifecycle`: bounded state-machine sequences through the real server
  refresh registry, transfer-plan generations, catalog-style add/remove and
  reassignment, catalog/scheduled/control-plane/NOTIFY dequeue validation,
  validation-to-spawn remove/readd boundaries, request coalescing/overflow,
  attempt success/failure/drop, and
  expiry/scheduler transitions. Expensive full-capacity overflow probes are
  bounded per input so repeated equivalent opcodes cannot become multi-second
  slow units. The target checks that removed zones cannot be recreated by stale
  work and that queue/plan/store/registry invariants agree.

Run a compile check with a nightly cargo on `PATH`, without executing a long
fuzzing campaign:

```sh
cargo fuzz check dns_datagram
cargo fuzz check transfer_stream
cargo fuzz check tsig_message
cargo fuzz check notify_edns_datagram
cargo fuzz check zone_image_datagram
cargo fuzz check catalog_zone
cargo fuzz check zone_store_state
cargo fuzz check zone_store_concurrent
cargo fuzz check server_lifecycle
```

The repository gate runs `scripts/check-fuzz-targets.py` before this compile
check. It requires every `fuzz_targets/*.rs` source to have one matching Cargo
binary and one matching default entry in the two-host long campaign, preventing
new targets from silently falling out of continuous or soak coverage.

Or, without a nightly toolchain or `cargo-fuzz` installed:

```sh
cargo check --manifest-path fuzz/Cargo.toml
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
```

For retained local evidence, use the short campaign runner from the repository
root. It defaults to all known fuzz targets for 10 seconds per target and writes
logs, artifacts, isolated per-run corpus directories, command lines, `campaign-summary.tsv`, and
tool-version/config records under `target/fuzz-evidence/<timestamp>/`:

```sh
scripts/fuzz-campaign.sh
```

When `CARGO_TARGET_DIR` is unset, the runner creates a private mode-0700 build
tree beneath `${TMPDIR:-/var/tmp}/borondns-fuzz-builds-<uid>/`. It captures the
parent and tree device/inode identities and removes only that exact automatic
tree on every normal or failed exit, after retaining the build-artifact hashes.
It does not sweep older `/var/tmp` roots. An explicitly supplied
`CARGO_TARGET_DIR` remains caller-owned and is never removed by the runner.

The runner applies an outer wall-clock timeout as well as libFuzzer's
`-max_total_time`, so a target that blocks inside one input cannot strand the
campaign indefinitely. The outer limit is the requested duration plus a
default 1800-second build/start grace; use
`BORONDNS_FUZZ_WALL_CLOCK_GRACE_SECONDS` and
`BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS` to tighten it for prebuilt smoke
tests.

When Cargo is not explicitly overridden, the runner selects the installed
`nightly` rustup toolchain because cargo-fuzz sanitizer instrumentation requires
nightly compiler options. `--toolchain` and `CARGO_TOOLCHAIN` can select a
different compatible nightly toolchain explicitly.

Select targets and duration explicitly when needed:

```sh
scripts/fuzz-campaign.sh --duration 60 dns_datagram tsig_message
scripts/fuzz-campaign.sh --target transfer_stream --target notify_edns_datagram
scripts/fuzz-campaign.sh --target zone_image_datagram
scripts/fuzz-campaign.sh --target catalog_zone
scripts/fuzz-campaign.sh --target zone_store_state
scripts/fuzz-campaign.sh --target zone_store_concurrent
scripts/fuzz-campaign.sh --target server_lifecycle
scripts/fuzz-campaign.sh --toolchain nightly --target zone_image_datagram
scripts/fuzz-campaign.sh --toolchain nightly --sanitizer address --target dns_datagram
```

Each explicit target may appear only once. Duplicate target arguments are
rejected before Cargo target or evidence directories are created, so summary
and metadata counts always describe a unique exact target set.

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
The campaign runner uses an isolated corpus directory under the evidence root
for each target, which avoids shared-corpus races when multiple target instances
run in parallel. Promote minimized regression inputs into a tracked fixture
intentionally rather than committing the auto-grown local corpus wholesale.

If the default `cargo` on `PATH` is a wrapper that cannot see the repository's
real filesystem path, either use `--toolchain nightly` so the runner prepends
the rustup-selected cargo directory for cargo-fuzz's inner build, or set
`CARGO` to the absolute cargo binary for the intended toolchain.

The target exercises public `borondns-core` DNS parser and datagram handling APIs:
`Header::parse`, `Question::parse`, and `answer_datagram` against an empty
`ZoneStore`.

The transfer target exercises `parse_axfr_response` and `parse_ixfr_response`
against a fixed current `alpha.test.` zone snapshot.

The TSIG target exercises public `borondns-core::tsig` APIs for raw and shaped DNS
messages. The NOTIFY/EDNS target exercises public datagram answering APIs with
authorization and acceptance hooks while varying UDP/TCP answer options. The
ZoneImage target exercises the same datagram API with a static compiled image,
raw fuzz input, shaped qname/qtype/EDNS queries, compression-eligible records,
synthesized DNAME and wildcard answers, referral/glue and additional section
composition, DNSSEC proof/signature augmentation, and malformed known-name
RDATA that should safely fall back to opaque copying. The catalog target
constructs catalog `ZoneSnapshot` values with shaped and malformed PTR/TXT/A/AAAA
extension RRsets and calls the public catalog parser. The ZoneStore state target
drives bounded adversarial lifecycle sequences and asserts visibility and
aggregate-state invariants after every transition.
The concurrent ZoneStore target runs the same lifecycle boundary through four
shared worker threads and validates that cached readiness state converges to
the authoritative published metadata.
