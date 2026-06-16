# Two-Host Fuzz and Soak Campaign

Status: prepared release/operations runbook. Do not run this campaign on the
physical hosts while UDP/XDP benchmark or tuning jobs are active.

This campaign uses the two lab hosts as general compute first and NIC hardware
only for the explicit XDP lane. Most fuzz and soak coverage should run on local
loopback or in-process targets so the 25G link remains reserved for packet-I/O
experiments.

## Hosts

Default SSH targets:

- `oxidedns-1`
- `oxidegun-1`

Both targets are expected to use the `codex` user through SSH aliases or
`codex@host` targets, as described in
`docs/local-physical-ssh-setup.md`.

## Campaign Lanes

### Fuzz Lane

Existing target owner: `fuzz/README.md` and `scripts/fuzz-campaign.sh`.

Current targets:

- `dns_datagram`
- `transfer_stream`
- `tsig_message`
- `notify_edns_datagram`
- `zone_image_datagram`
- `catalog_zone`

Use the two-host helper to prepare a manifest:

```sh
scripts/fuzz-soak-two-host-campaign.sh plan --duration 86400 --sanitizer address
```

The manifest is written under
`target/evidence/fuzz-soak-two-host-<timestamp>/` and records the target split,
remote commands, systemd unit names, status command, collect command, duration,
toolchain, and remote evidence root. It does not start work unless `launch` is
used:

```sh
scripts/fuzz-soak-two-host-campaign.sh launch --duration 86400 --sanitizer address
```

`launch` installs one systemd service per fuzz target on the assigned host, with
unit names recorded in `assignments.tsv`. This makes later inspection explicit:

```sh
ssh oxidedns-1 'systemctl status oxidedns-fuzz-<campaign>-<n>-<target>.service'
ssh oxidedns-1 'journalctl -u oxidedns-fuzz-<campaign>-<n>-<target>.service --no-pager -n 200'
```

Check and collect later with the commands written in the manifest:

```sh
scripts/fuzz-soak-two-host-campaign.sh status --evidence-dir target/evidence/fuzz-soak-two-host-<timestamp>
scripts/fuzz-soak-two-host-campaign.sh collect --evidence-dir target/evidence/fuzz-soak-two-host-<timestamp>
```

For CPU-saturating campaigns, repeat the target set and weight the host list.
With the current six-target set, the 2:3 host weighting below launches 90 fuzz
services, which is about 36 instances on the 48-core `oxidedns-1` host and 54
instances on the 72-core `oxidegun-1` host. That is the preferred 70%-80% CPU
campaign shape when the servers are otherwise idle:

```sh
scripts/fuzz-soak-two-host-campaign.sh launch \
  --remote-repo /home/codex/oxidedns-fuzz \
  --duration 86400 \
  --target-repeat 15 \
  --sampler-interval 60 \
  --sanitizer address \
  --host oxidedns-1 \
  --host oxidegun-1 \
  --host oxidedns-1 \
  --host oxidegun-1 \
  --host oxidegun-1
```

The helper gives each repeated target instance a unique evidence directory and
installs one sampler service per physical host. Sampler output is retained under
`host/<host>/host-samples.tsv` and records active fuzz units, matching process
count, aggregate CPU, aggregate RSS, load averages, and available memory.

For formal SRS fuzz evidence, retain at least one 24-hour run per parser target.
The two-host split reduces wall-clock time but does not reduce per-target
duration.

### Sanitizer Lane

Sanitizers are useful, but they should be staged by expected signal:

- **ASan**: high value for fuzz. It can catch memory-safety defects in unsafe
  islands, FFI boundaries, allocator misuse, and C dependencies that safe Rust
  panic checks do not cover. Use it for the long fuzz lane when the toolchain and
  host support it. `cargo-fuzz` commonly defaults to address sanitization, but
  the campaign helper records the mode explicitly when `--sanitizer address` is
  passed.
- **Miri**: high value for focused Rust UB checks in small test sets. It is not a
  soak or throughput tool and may not support all network, thread, or OS paths.
  Run it as a targeted preflight for crates or tests that exercise unsafe code.
- **TSan**: lower priority until there is a concrete concurrency suspect. It can
  be noisy and expensive, and async/runtime code often needs careful filtering.
- **MSan/UBSan**: defer unless a C/FFI-heavy dependency path becomes important.
  MSan requires fully instrumented dependencies to be useful.

Recommended order before long runs:

```sh
cargo +nightly fuzz check dns_datagram
cargo +nightly fuzz check transfer_stream
cargo +nightly fuzz check tsig_message
cargo +nightly fuzz check notify_edns_datagram
cargo +nightly fuzz check zone_image_datagram
cargo +nightly fuzz run --sanitizer address dns_datagram -- -max_total_time=60
cargo +nightly miri test -p oxidedns-core
```

If Miri cannot run a crate because of unsupported OS operations, record the
failure as a tooling limitation and narrow to specific tests instead of treating
that as product evidence.

### Soak Lane

Existing evidence schema owner: `scripts/capture-soak-handoff.sh`.

The current soak tooling creates schemas and report templates; it is not yet a
long-running executor. Before starting a production-representative soak, create
the handoff artifacts:

```sh
scripts/capture-soak-handoff.sh
```

Prepared execution shape:

- run OxideDNS as a service or supervised process on each host;
- use loopback or same-host synthetic primaries by default;
- run steady query and transfer churn locally, not over the physical NIC;
- sample `/metrics`, `/readyz`, RSS, fd count, thread count, and process status
  at a fixed cadence;
- append anomalies to `operational-events.tsv`;
- retain weekly summaries and a final report.

The first executor should be narrow: start one server, one local synthetic
primary/corpus, one local client workload, and one sampler. Expand to catalog
zone churn, transfer failures, restart/recovery, and multi-primary cases only
after the simple loop is stable.

### XDP Lane

XDP belongs in a separate lane because it requires privileges, queue/NIC state,
MTU constraints, and cleanup. Use existing local XDP smoke tools first:

```sh
scripts/oxide-gun-xdp-pkexec-tests.sh
scripts/oxidedns-af-xdp-veth-smoke.sh
```

Physical NIC XDP soak should wait until UDP/XDP tuning stabilizes. It should
run with explicit start/stop windows and should not overlap with fuzz or CPU
soak jobs that would perturb performance evidence.

## Evidence to Retain

For each host and campaign:

- `campaign.env`
- `assignments.tsv`
- remote `campaign-summary.tsv` files
- per-target fuzz logs and crash artifacts
- `tool-versions.txt`
- `git rev-parse HEAD` and `git status --short`
- host metadata: `uname -a`, `lscpu`, `free -h`, `df -h`, kernel command line,
  and Rust toolchain versions
- collected soak TSVs and weekly/final reports when the soak lane is active

Failures should be treated as useful evidence. Preserve the generated input,
target log tail, command file, host, commit, and sanitizer/toolchain mode before
minimizing or rerunning.

## Completed Runs

### 2026-06-12 24-hour ASan fuzz campaign

Campaign ID: `20260612T090724Z`

Remote evidence root:
`/home/codex/oxidedns-fuzz/target/evidence/fuzz-soak-two-host-20260612T090724Z/`

Result: passed. No `crash-*`, `oom-*`, or `timeout-*` artifacts were present on
either host at final collection time.

Scope:

| Host | Targets | Result |
| --- | --- | --- |
| `oxidedns-1` | `dns_datagram`, `transfer_stream`, `zone_image_datagram` | `passed`, exit `0`, `86400` seconds each |
| `oxidegun-1` | `notify_edns_datagram`, `tsig_message` | `passed`, exit `0`, `86400` seconds each |

Tooling:

- sanitizer: `address`
- cargo toolchain: `nightly`
- cargo: `1.98.0-nightly (fe63976b2 2026-06-11)`
- rustc nightly: `1.98.0-nightly (b30f3df3b 2026-06-11)`
- cargo-fuzz: `0.13.2`
- repository commit on both hosts:
  `2e772f7080f80c2f1f23d9d7ef101a23dfa1b93b`
- remote worktrees: clean at final metadata collection

Host metadata at final check:

| Host | Kernel | CPU | CPUs | Memory | Root disk |
| --- | --- | --- | ---: | ---: | --- |
| `oxidedns-1` | `7.0.0-22-generic` | Intel Xeon Gold 6246 @ 3.30GHz | 48 | 373Gi | 438G total, 368G free |
| `oxidegun-1` | `7.0.0-22-generic` | Intel Xeon Gold 6140 @ 2.30GHz | 72 | 123Gi | 878G total, 818G free |

Interpretation: this is first-pass stability evidence for the listed fuzz
targets under one 24-hour ASan-backed campaign. It does not prove parser or
protocol correctness outside the paths and inputs exercised by the fuzz targets.

### 2026-06-14 24-hour ASan fuzz campaign

Campaign ID: `20260614T003811Z`

Remote evidence root:
`/home/codex/oxidedns-fuzz/target/evidence/fuzz-soak-two-host-20260614T003811Z/`

Collected local evidence:
`target/evidence/fuzz-soak-two-host-20260614T003811Z/remotes/`

Result: passed. All 75 systemd fuzz services completed with `status=passed`,
exit `0`, and `86400` seconds in their `campaign-summary.tsv` files. No
sanitizer, panic, crash, leak, OOM, or timeout markers were found in the
collected fuzz logs, and no crash/leak/OOM/timeout artifact files were present.

Scope:

| Host | Targets | Services | Result |
| --- | --- | ---: | --- |
| `oxidedns-1` | `dns_datagram`, `transfer_stream` | 30 | 30/30 passed |
| `oxidegun-1` | `notify_edns_datagram`, `tsig_message`, `zone_image_datagram` | 45 | 45/45 passed |

Fuzz executions:

| Target | Services | Total runs |
| --- | ---: | ---: |
| `dns_datagram` | 15 | 52,027,636,728 |
| `notify_edns_datagram` | 15 | 29,198,863,544 |
| `transfer_stream` | 15 | 13,669,358,647 |
| `zone_image_datagram` | 15 | 8,234,059,310 |
| `tsig_message` | 15 | 1,231,338,807 |
| **Total** | **75** | **104,361,257,036** |

Tooling:

- sanitizer: `address`
- cargo toolchain: `nightly`
- cargo: `1.98.0-nightly (fe63976b2 2026-06-11)`
- rustc nightly: `1.98.0-nightly (b30f3df3b 2026-06-11)`
- cargo-fuzz: `0.13.2`
- repository commit on both hosts:
  `1d586131cf17150a21f51a836c81b08a8492d9b9`

Host metadata:

| Host | Kernel | CPU | CPUs | Memory | Peak active fuzz units |
| --- | --- | --- | ---: | ---: | ---: |
| `oxidedns-1` | `7.0.12-borondns1` | Intel Xeon Gold 6246 @ 3.30GHz | 48 | 373Gi | 30 |
| `oxidegun-1` | `7.0.0-22-generic` | Intel Xeon Gold 6140 @ 2.30GHz | 72 | 123Gi | 45 |

Interpretation: this post-v0.2.0-readiness campaign provides retained
24-hour ASan evidence for the five fuzz targets that existed at campaign start.
It remains fuzz evidence only; the 30-day production-representative soak is a
separate release-acceptance lane.

## Scheduling Guidance

Run order after UDP/XDP tuning:

1. Short compile/preflight on both hosts.
2. One-hour fuzz smoke per target to shake out toolchain and environment issues.
3. 24-hour ASan-backed fuzz campaign per target, split across the two hosts.
4. Loopback soak executor once implemented and stable.
5. Privileged XDP smoke/soak only in a dedicated window.

Do not mix these with performance comparison runs unless the campaign explicitly
records that host contention was intentional.
