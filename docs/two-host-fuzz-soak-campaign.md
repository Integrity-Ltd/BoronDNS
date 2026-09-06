# Two-host fuzz campaigns

Use this runbook to plan, supervise, and collect a bounded fuzz campaign on the
two lab hosts. Use [the large-surface soak](large-surface-soak.md) for repeated
live-server interoperability scenarios. Neither campaign should overlap a QPS
comparison: CPU contention would change the benchmark.

## Before launching

The controller and both remote checkouts must be clean at the same commit.
The helper records the commit, toolchain, sanitizer, and tool hashes in a saved
plan; it does not update a remote branch for you. Remote hosts need systemd,
the selected Rust toolchain, cargo-fuzz, and the privileges used by the generated
service setup. Verify non-interactive SSH access before planning a run.

The default SSH aliases are `borondns-1` and `oxidegun-1`; the lab also uses
`oxidedns-1` for the DNS host. Check your aliases and pass `--host` explicitly
when they differ. The default remote checkout is `/home/codex/borondns`.

Current targets:

- `dns_datagram`
- `transfer_stream`
- `tsig_message`
- `notify_edns_datagram`
- `zone_image_datagram`
- `catalog_zone`
- `zone_store_state`
- `zone_store_concurrent`
- `server_lifecycle`

Their scope and corpus instructions live in [the fuzz guide](../fuzz/README.md).
On the intended compute host, check the target set before committing to a long
run:

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
cargo +nightly fuzz run --sanitizer address dns_datagram -- -max_total_time=60
```

ASan is the usual long-campaign sanitizer. Miri can help with selected unsafe
Rust tests, but unsupported OS operations are tooling limitations, and Miri is
not a soak or throughput tool. Add other sanitizer runs when the suspected
failure calls for them.

## Plan, launch, and inspect

To inspect the proposed assignments without starting remote services:

```sh
scripts/fuzz-soak-two-host-campaign.sh plan --duration 86400 --sanitizer address
```

The plan is saved under
`target/evidence/fuzz-soak-two-host-<timestamp>/`. It contains
`campaign.env`, `assignments.tsv`, exact remote commands, systemd unit names,
and the collection validator.

To create a plan and start its services:

```sh
scripts/fuzz-soak-two-host-campaign.sh launch --duration 86400 --sanitizer address
```

Duration is per target, not a shared budget. Setup and compilation add time.
The host sampler starts before the fuzz services; each target gets a separate
attempt directory and Cargo build directory.

Use the evidence directory printed by the command:

```sh
campaign='target/evidence/fuzz-soak-two-host-<timestamp>'
scripts/fuzz-soak-two-host-campaign.sh status --evidence-dir "$campaign"
scripts/fuzz-soak-two-host-campaign.sh collect --evidence-dir "$campaign"
```

For a specific service, copy its host and unit name from `assignments.tsv`:

```sh
ssh borondns-1 'systemctl status "borondns-fuzz-<campaign>-<n>-<target>.service"'
ssh borondns-1 'journalctl -u "borondns-fuzz-<campaign>-<n>-<target>.service" --no-pager -n 200'
```

If launch stops partway through, use the saved plan:

```sh
scripts/fuzz-soak-two-host-campaign.sh resume --evidence-dir "$campaign"
```

Resume preserves active services and finalized successful attempts. It gives an
incomplete or failed setup a new attempt directory. It cannot extend the
plan's sampler deadline; if there is too little time for a full target run, a
new campaign is needed.

## Optional repeated-target campaign

Repeated hosts are assignment slots, not extra machines. Nine targets with
15 repeats give 135 fuzz services. The 2:3 schedule below produces these
assignments:

| Host | Fuzz services | Logical CPUs in the lab |
| --- | ---: | ---: |
| `borondns-1` | 54 | 48 |
| `oxidegun-1` | 81 | 72 |

These are lab-specific counts, not a promised CPU-utilization level. Choose
concurrency from available memory and observed build/runtime load.

```sh
scripts/fuzz-soak-two-host-campaign.sh launch \
  --remote-repo /home/codex/borondns-fuzz \
  --duration 86400 \
  --target-repeat 15 \
  --sampler-interval 60 \
  --sanitizer address \
  --host borondns-1 \
  --host oxidegun-1 \
  --host borondns-1 \
  --host oxidegun-1 \
  --host oxidegun-1
```

There is one sampler and one collection pass per physical host. Repeating a
target adds independent instances; it does not change the duration of each one.

## Accepting the evidence

Collection validates the source/tool identities, manifests, target durations,
and sampler coverage before replacing an earlier local collection. Its status
file is `remotes/<host>.collection-status.tsv`.

| Classification | Meaning |
| --- | --- |
| Complete | Every planned target and the host sampler have valid terminal evidence covering the required windows. |
| Incomplete | Required attempts, completion markers, or coverage are missing. A running service alone is not proof of completion. |
| Invalid | Evidence contradicts the plan, has malformed records, changed files, failed hashes, or unexpected entities. |

Read the terminal target summaries and inspect failure artifacts even when
service exit statuses look normal. Preserve the triggering input, target log,
command, commit, sanitizer, and tool versions before minimizing a failure.

Retain the complete plan and collected tree, including:

- Per-attempt `campaign-summary.tsv`, `campaign-completed.env`, fuzz logs,
  crash/OOM/timeout artifacts, and `artifact-manifest.sha256`.
- `config.txt`, `tool-versions.txt`, and `build-artifacts.sha256`.
- Host and process samples under `host/<host>/attempts/attempt.*/`.
- Systemd journals in `remotes/<host>.journal/`.

A SHA-256 record ties the classification to the collected tree and detects
accidental corruption or mismatched copies. It is not a signature: a process
that can rewrite all evidence, status, and checksum files can also replace that
record. Keep a separately protected copy if that threat matters.

## Time limits and resource limits

The default duration is 86,400 seconds, sample interval 60 seconds, and fuzz
build timeout 3,600 seconds. Target execution uses a wall-clock deadline rather
than libFuzzer CPU time. Local watchdogs use `CLOCK_BOOTTIME`, so suspend does
not replenish their budget. Systemd provides an additional runtime limit.

The sampler's absolute deadline is plan creation plus duration, one hour, and
a setup reserve of `max(600, 30 × target instances)` seconds. Resume retains
that deadline. Allow time for final probes, evidence hashing, and collection;
a 24-hour fuzz window does not mean results arrive exactly 24 hours after
launch.

Useful overrides:

| Setting | Default / purpose |
| --- | --- |
| `BORONDNS_FUZZ_BUILD_TIMEOUT_SECONDS` | 3,600 seconds per build. |
| `BORONDNS_FUZZ_PREFLIGHT_TIMEOUT_SECONDS` | Bounds tool and source preflights; see the runner for its allowed range. |
| `BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS` | Grace before hard-killing an expired target. |
| `BORONDNS_CAMPAIGN_COLLECTION_TIMEOUT_SECONDS` | 10,800 seconds per host collection. |
| `BORONDNS_CAMPAIGN_COLLECTION_MAX_ENTRIES` | 100,000 filesystem entries. |
| `BORONDNS_CAMPAIGN_COLLECTION_MAX_DEPTH` | 64 directory levels. |
| `BORONDNS_CAMPAIGN_COLLECTION_MAX_FILE_BYTES` | 2 GiB per file. |
| `BORONDNS_CAMPAIGN_COLLECTION_MAX_TOTAL_BYTES` | 64 GiB per host. |

Collection limits have hard maxima: one day, 1,000,000 entries, depth 128,
16 GiB per file, and 1 TiB total. Exceeding a limit fails collection without
publishing a partial replacement. SSH/copy operations also have bounded
connection and command timeouts.

## Cleanup and interrupted cleanup

After collecting, remove inactive service definitions and reconcile their build
roots:

```sh
scripts/fuzz-soak-two-host-campaign.sh cleanup --evidence-dir "$campaign"
```

Cleanup verifies the exact unit definition, executable identity, inactivity,
and build-root ownership before changing anything. A foreign or active service,
symlink, missing identity, or systemd probe error stops cleanup. Remote
evidence is retained.

Build roots writable by the campaign user are quarantined by identity; they
are not recursively deleted after a pathname check. A `cleanup_retained`
message names the retained tree and its
`.borondns-retained-cleanup-*.env` journal. Preserve both for inspection.
`cleanup_prepared_verified` means an interrupted rename was verified; it does
not mean the tree was deleted.

For a direct `scripts/fuzz-campaign.sh` invocation, an unset
`CARGO_TARGET_DIR` selects a private automatic tree beneath
`${TMPDIR:-/var/tmp}/borondns-fuzz-builds-<uid>/`. Explicit build roots remain
the caller's responsibility. Interrupted automatic-root cleanup may retain
data for privileged reconciliation. Never delete a retained tree based only on
a name or journal: after its live owner exits, that journal is evidence, not
deletion authority.

The implementation of locks, immutable runners, descriptor-based tool
snapshots, collection transactions, and cleanup identities is in
[the campaign wrapper](../scripts/fuzz-soak-two-host-campaign.sh) and
[shared campaign helpers](../scripts/campaign-env.sh).

## Historical results

These campaigns tested their recorded commits and target sets. They do not
certify the current source or targets added later.

| Campaign | Commit | Scope | Recorded result |
| --- | --- | --- | --- |
| `20260612T090724Z` | `2e772f7080f80c2f1f23d9d7ef101a23dfa1b93b` | Five targets, one 24-hour instance each. | All passed, exit 0; no crash, OOM, or timeout artifacts at final collection. |
| `20260614T003811Z` | `1d586131cf17150a21f51a836c81b08a8492d9b9` | Five targets × 15, each 24 hours. | 75/75 passed, exit 0; no sanitizer, panic, crash, leak, OOM, or timeout markers in collected evidence. |

Both used ASan, cargo-fuzz 0.13.2, Cargo
`1.98.0-nightly (fe63976b2 2026-06-11)`, and rustc
`1.98.0-nightly (b30f3df3b 2026-06-11)`.

June 12 assigned `dns_datagram`, `transfer_stream`, and
`zone_image_datagram` to `borondns-1`, with `notify_edns_datagram` and
`tsig_message` on `oxidegun-1`. June 14 assigned 30 services
(`dns_datagram`, `transfer_stream`) to the first host and 45 services
(the other three targets) to the second.

| June 14 target | Instances | Executions |
| --- | ---: | ---: |
| `dns_datagram` | 15 | 52,027,636,728 |
| `notify_edns_datagram` | 15 | 29,198,863,544 |
| `transfer_stream` | 15 | 13,669,358,647 |
| `zone_image_datagram` | 15 | 8,234,059,310 |
| `tsig_message` | 15 | 1,231,338,807 |
| Total | 75 | 104,361,257,036 |

| Host | CPU / logical CPUs | RAM | June 12 kernel | June 14 kernel |
| --- | --- | ---: | --- | --- |
| `borondns-1` | Xeon Gold 6246, 3.30 GHz / 48 | 373 GiB | `7.0.0-22-generic` | `7.0.12-borondns1` |
| `oxidegun-1` | Xeon Gold 6140, 2.30 GHz / 72 | 123 GiB | `7.0.0-22-generic` | `7.0.0-22-generic` |

At the June 12 final check, root disks had 368 GiB free of 438 GiB on
`borondns-1` and 818 GiB free of 878 GiB on `oxidegun-1`; both worktrees
were clean.

Remote evidence roots:

- `/home/codex/borondns-fuzz/target/evidence/fuzz-soak-two-host-20260612T090724Z/`
- `/home/codex/borondns-fuzz/target/evidence/fuzz-soak-two-host-20260614T003811Z/`

The June 14 local collection was
`target/evidence/fuzz-soak-two-host-20260614T003811Z/remotes/`.
See [release evidence](release-evidence-guide.md) for the release-specific decision;
neither this runner nor the soak runner imposes a fixed 30-day prerequisite.
