# BoronDNS v0.9.1 Two-Host Fuzz Evidence

This document records the final 24-hour fuzz campaign executed from the
published `v0.9.1` tag. The raw collected evidence remains outside Git under
`target/evidence/fuzz-soak-two-host-bdn-v0.9.1-20260822-24h-b/`.

## Campaign identity

- Campaign: `bdn-v0.9.1-20260822-24h-b`
- Source commit: `534db1470866d9a34ef05785b7d31582b671c73b`
- Source tag: `v0.9.1`
- Toolchain: `nightly-2026-06-12`
- Sanitizer: AddressSanitizer
- Hosts: `odns-dns1` and `oxidegun-1`
- Scheduled duration: 86,400 seconds per target instance
- Execution: two instances of each of the nine checked-in fuzz targets, split
  across the two hosts
- Run interval: 2026-08-22 through 2026-08-23 UTC
- Evidence collected and validated: 2026-08-25 UTC

## Result

All 18 fuzz target instances completed their full scheduled duration with exit
status zero. Both host samplers also completed. The campaign's saved immutable
collector classified every target, both samplers, and both remote snapshots as
`complete`.

The last libFuzzer counters retained in the 18 logs total at least
6,505,132,495 executions. This is a conservative lower bound because each log
records periodic counters rather than a separate final aggregate counter.
Review found no AddressSanitizer, LeakSanitizer, undefined-runtime, crash,
out-of-memory, timeout, or libFuzzer error marker.

Validated remote snapshot commitments:

| Host | Snapshot classification | Snapshot SHA-256 |
| --- | --- | --- |
| `odns-dns1` | `complete` | `f9a4cf37c6a0ce183836d9cc05b949f2e9ae630a66ade6cdaf32a9967d6b0ab4` |
| `oxidegun-1` | `complete` | `68a732a58ee4fcd4227cfb97ce41de1f017d2a1a4ecb30894f1f5ea3659e400b` |

## Resource sampling

The authenticated one-minute samplers retained 1,407 samples from
`odns-dns1` and 1,373 samples from `oxidegun-1`.

| Host | Peak active units | Peak matching processes | Peak aggregate CPU | Peak aggregate RSS | Minimum available memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| `odns-dns1` | 9 | 61 | 940.8% | 9,248,488 KiB | 754,809,532 KiB |
| `oxidegun-1` | 9 | 57 | 976.4% | 9,504,652 KiB | 111,535,404 KiB |

The observed resource envelope contains no memory-exhaustion indication. These
figures describe this campaign workload and are not general production sizing
limits.

## Release disposition

This campaign closes the planned v0.9.1 24-hour two-host fuzz evidence item for
the 1.0 public-beta decision. Narrow fixes made after v0.9.1 retain focused
regression tests and the ordinary release gate; this record does not claim that
the v0.9.1 binaries contained those later fixes.
