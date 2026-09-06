# Fuzzing BoronDNS

The fuzz workspace uses `cargo-fuzz` to exercise DNS parsing, transfer handling,
query answers, catalog input, and concurrent server state. Use the campaign
runner when results need to be retained; use individual targets for focused
development.

## Targets

| Target | What it exercises |
| --- | --- |
| `dns_datagram` | Header/question parsing and datagram answers against an empty zone store |
| `transfer_stream` | AXFR/IXFR parsing and up to 64 modeled IXFR generations, comparing incremental snapshots and compiled images with fresh rebuilds |
| `tsig_message` | TSIG detection, MAC extraction, verification, error responses, and chained TCP transfer signatures |
| `notify_edns_datagram` | NOTIFY authorization/handling and EDNS parsing against a populated zone |
| `zone_image_datagram` | Compiled-image answers, CNAME/DNAME, wildcards, referrals/glue, additional records, DNSSEC denial, EDNS, unknown records, and malformed RDATA; compares answer plans with the snapshot oracle |
| `catalog_zone` | Catalog PTR membership and member transfer extensions, including malformed names, primaries, TSIG references, XoT hints, and NOTIFY overrides |
| `zone_store_state` | Publication, visibility, expiry, replacement, and removal; checks control metadata, readiness, and active counts after each transition |
| `zone_store_concurrent` | The same shared-store lifecycle under four persistent worker threads; checks published/control views and cached counts after each input |
| `server_lifecycle` | Refresh plans, queueing/coalescing, catalog reassignment, stale-work rejection, attempt completion, and expiry/scheduler transitions |

Persistent workers in `zone_store_concurrent` bound sanitizer thread bookkeeping
during long campaigns. The lifecycle target bounds expensive overflow probes
per input. These targets deliberately stress invariants beyond isolated parser
calls.

## Check that targets compile

With nightly Rust and `cargo-fuzz` installed, run from the repository root:

```sh
cargo +nightly fuzz check dns_datagram
cargo +nightly fuzz check transfer_stream
cargo +nightly fuzz check tsig_message
cargo +nightly fuzz check notify_edns_datagram
cargo +nightly fuzz check zone_image_datagram
cargo +nightly fuzz check catalog_zone
cargo +nightly fuzz check zone_store_state
cargo +nightly fuzz check zone_store_concurrent
cargo +nightly fuzz check server_lifecycle
```

These commands compile targets without starting a campaign. Without
`cargo-fuzz`, an ordinary Rust check still catches source/build errors:

```sh
cargo check --manifest-path fuzz/Cargo.toml
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
```

`scripts/check-fuzz-targets.py` checks that every source target has a Cargo binary
and a default assignment in the two-host campaign. New targets need all three.

## Run a short campaign

The runner defaults to all targets, ten seconds per target, and the installed
`nightly` rustup toolchain:

```sh
scripts/fuzz-campaign.sh
scripts/fuzz-campaign.sh --duration 60 dns_datagram tsig_message
scripts/fuzz-campaign.sh --target transfer_stream --target server_lifecycle
scripts/fuzz-campaign.sh --toolchain nightly --sanitizer address --target zone_image_datagram
```

A target may appear only once. `--duration` is the per-target execution time;
compilation is bounded separately. Inspect commands without executing them:

```sh
scripts/fuzz-campaign.sh --dry-run --duration 1 --target dns_datagram
scripts/fuzz-campaign.sh --list-targets
```

The default campaign requires a clean tracked source tree. For a development
diagnostic against uncommitted changes, set
`BORONDNS_FUZZ_ALLOW_DIRTY_NON_RELEASE=1`. This override is rejected in CI/release
contexts and marks the result ineligible as release evidence. Dry runs are also
non-release evidence. A completed dirty-source diagnostic exits with status 2
even when its individual target runs pass.

## Time and resource bounds

Each target build has a 3600-second default timeout, controlled by
`BORONDNS_FUZZ_BUILD_TIMEOUT_SECONDS`. Execution uses an outer wall-clock
deadline because libFuzzer's CPU-time limit can stretch under host contention.
A verified deadline completion counts as success; an earlier nonzero exit or
crash artifact counts as failure. `BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS`
controls the final termination grace period.

When `CARGO_TARGET_DIR` is unset, the runner creates a private mode-0700 build
tree under `$TMPDIR` (or `/var/tmp`). It retains build hashes and removes only
that exact automatic tree on normal or failed exit, checking its recorded
identity before cleanup. An explicitly supplied `CARGO_TARGET_DIR` is
caller-owned and is never removed.

Each target gets an isolated corpus inside the evidence directory, avoiding
shared-corpus races between runs. For long campaigns, use the resource-bounded
[two-host procedure](../docs/two-host-fuzz-soak-campaign.md) on designated test
hosts. A timeout alone is not a memory or CPU limit.

## Read and preserve results

The default output is `target/fuzz-evidence/<timestamp>/`. Keep the directory
intact: it contains logs, artifacts, corpus inputs, commands, tool/config
identities, and `campaign-summary.tsv`. The summary is the index for each
target's status, exit code, execution duration, log, and artifacts.

A passing campaign applies to the recorded source, target set, sanitizer, and
duration; it does not establish that all inputs are safe. Investigate any crash,
minimize its input, and add a regression fixture with the fix. Generated
`fuzz/corpus/` files are ignored; do not commit an automatically grown corpus
wholesale.

If `cargo` on `PATH` is a wrapper that cannot see the real repository path,
`--toolchain nightly` selects rustup's Cargo for the inner build. Alternatively
set `CARGO` to the intended absolute executable; the caller then owns toolchain
selection.
