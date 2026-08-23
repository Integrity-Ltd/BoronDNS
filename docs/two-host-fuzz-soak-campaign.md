# Two-Host Fuzz and Soak Campaign

Status: prepared release/operations runbook. Do not run this campaign on the
physical hosts while UDP/XDP benchmark or tuning jobs are active.

This campaign uses the two lab hosts as general compute first and NIC hardware
only for the explicit XDP lane. Most fuzz and soak coverage should run on local
loopback or in-process targets so the 25G link remains reserved for packet-I/O
experiments.

## Hosts

Default SSH targets:

- `borondns-1`
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
- `zone_store_state`
- `zone_store_concurrent`
- `server_lifecycle`

For a direct local `scripts/fuzz-campaign.sh` run, an unset
`CARGO_TARGET_DIR` selects a fresh private tree below
`${TMPDIR:-/var/tmp}/borondns-fuzz-builds-<uid>/`. The runner removes only the
descriptor-created and prepublication-journaled device/inode identity on every
exit after writing retained artifact hashes; pathname replacement is retained
and reported. Its journal is staged from an open `O_TMPFILE`, durably publishes
an allocating intent before `mkdir`, then records preparing/ready identity and
an exact removing quarantine before either rename. Generic same-UID cleanup
retains the exact quarantined inode instead of unlinking a pathname that can be
replaced after validation. Once live descriptor/socket authority is gone, a
later creator treats the journal as evidence and performs no destructive
recovery; privileged/manual reconciliation is required. Live owners,
replacements, renamed-away targets, and ambiguous identities are also retained. Explicit
caller build roots are preserved. The two-host services instead use their
planned explicit per-attempt roots described below. Because those roots and
their parent are owned by the campaign UID, authenticated cleanup performs an
exact whole-tree quarantine even when invoked through sudo; it never treats
privilege as authority to recursively delete a same-UID-writable namespace.
Before that rename, cleanup publishes an exact
`.borondns-retained-cleanup-<root>.<pid>.<nonce>.env` mapping with the original path,
preallocated quarantine path, and parent/object device, inode, and owner. It
advances from `prepared` to `retained` only after revalidating the quarantined
inode and emits `cleanup_retained` in the remote log. The retained tree remains
available for privileged reconciliation; the same-UID journal is evidence and
must not be treated as post-exit deletion authority. Retries allocate new
journal/quarantine names and retain all previous mappings. If a crash leaves
the journal at `prepared` after the rename, verification reports
`cleanup_prepared_verified` only when the original is absent and the exact
recorded quarantine identity and type still match; this is evidence, never
destructive authority.

Use the two-host helper to prepare a manifest:

```sh
scripts/fuzz-soak-two-host-campaign.sh plan --duration 86400 --sanitizer address
```

The manifest is written under
`target/evidence/fuzz-soak-two-host-<timestamp>/` and records the target split,
remote commands, systemd unit names, status command, collect command, duration,
toolchain, remote evidence root, and an executable copy of the strict collection
validator. That validator is part of the immutable plan manifest; management
rejects a copied validator that differs from the current semantic reference
even if an operator recomputes the plan manifest. Collection executes the exact
saved copy, so validation cannot switch implementations between planning and
evidence classification. The plan does not start work unless `launch` is used:

```sh
scripts/fuzz-soak-two-host-campaign.sh launch --duration 86400 --sanitizer address
```

`launch` first installs each physical host's sampler and waits until its first
authenticated sample has been published. Only then does it install one systemd
service per fuzz target on the assigned host, with unit names recorded in
`assignments.tsv`. This makes later inspection explicit:

```sh
ssh borondns-1 'systemctl status borondns-fuzz-<campaign>-<n>-<target>.service'
ssh borondns-1 'journalctl -u borondns-fuzz-<campaign>-<n>-<target>.service --no-pager -n 200'
```

Check and collect later with the commands written in the manifest:

```sh
scripts/fuzz-soak-two-host-campaign.sh status --evidence-dir target/evidence/fuzz-soak-two-host-<timestamp>
scripts/fuzz-soak-two-host-campaign.sh collect --evidence-dir target/evidence/fuzz-soak-two-host-<timestamp>
```

After collection, remove only the campaign's verified inactive systemd units and
owned `/var/tmp` build roots while retaining remote evidence:

```sh
scripts/fuzz-soak-two-host-campaign.sh cleanup --evidence-dir target/evidence/fuzz-soak-two-host-<timestamp>
```

Cleanup fails closed when systemd cannot report state, a unit is active, its
loaded fragment or `ExecStart` does not identify the exact campaign attempt, or
the build tree is symlinked, has the wrong owner, or falls outside the exact
campaign root. Cleanup acquires the same private target or sampler lock used by
launch/resume and completes every unit, runner, and build-root preflight before
the first removal. It removes the atomically published fragment and confirms a
`not-found` reload before deleting the immutable root-owned runner and build
tree. If `daemon-reload` fails, those dependencies remain available for an
identity-checked retry. Abandoned same-filesystem fragment staging files are
removed only under the exact campaign unit identity. Cleanup never removes the
retained remote evidence tree.

Plans are staged and published with a no-replace rename plus a `plan-complete`
marker, so a destination that reappears during publication fails closed. Their
canonical base64 scalar metadata is parsed without shell execution. Planning
requires a clean source checkout, rejects distinct host names that canonicalize
to the same evidence identifier, and remote target and sampler runners recheck
the exact recorded commit plus a clean worktree before evidence writes. Plan
paths and ancestors must be real and owned, the immutable plan tree must not be
group/world writable, and management commands execute a regenerated private
command copy derived from the validated semantic plan. Local plan and runner
locks live under a dedicated `.borondns-campaign-locks` mode-0700 directory;
their parent must be owned by the campaign user and must not be group/world
writable. Each lock is opened without following symlinks and its live descriptor
is checked for regular-file type, owner, link count, and mode before locking.
Remote locks use the same descriptor-validated broker and live in a
runner-owned mode-0700 directory; no shell redirection opens a checked path a
second time. Every protected mutation sends an acknowledged broker heartbeat;
broker death therefore aborts rather than silently releasing exclusivity.
The broker also binds an abstract Unix-socket authority derived from the
canonical lock root and namespace. That kernel-held authority survives visible
lock-path unlink or replacement and prevents a second cooperating broker from
entering the same critical section until the first process exits.
Collection status changes perform the same live heartbeat immediately before
publication. Evidence, journal, and classification files use a per-host
transaction directory: an interrupted uncommitted generation is rolled back on
the next collect, while an atomically committed generation is retained.
Systemd fragments are staged as root in the unit directory and atomically
renamed. `ExecStart` points to a root-owned mode-0555 runner beneath a
root-owned parent, with a root-owned identity sidecar binding its SHA-256,
device, and inode. The `scp` collection fallback copies into a
fresh staging destination so stale evidence cannot survive a refresh. Initial
launch refuses an already-active target or sampler unit name; a reused campaign
id therefore cannot silently leave an older process running under the new unit
definition. If a multi-host launch stops partway through, run
`resume --evidence-dir <plan>`; active jobs and jobs with fully finalized
terminal evidence are left untouched. A partial setup or incomplete attempt is
retained under its immutable attempt directory and resume creates a new attempt
rather than overwriting it.

Fuzz services inherit already-open descriptors for the plan-authenticated
Cargo, rustc, and cargo-fuzz executables. The runner hashes those descriptors
again immediately before use and keeps a root-system-only command search path,
so adjacent replacement in the campaign user's Cargo directory cannot change
the executed tool. Host sampling reads each unit's cgroup and retains a process
row only when `/proc/<pid>/stat` has the same start time before and after the
sample; ordinary unit exit is an empty sample, not a sampler failure.

For CPU-saturating campaigns, repeat the target set and weight the host list.
With the current nine-target set, the 2:3 host weighting below launches 135 fuzz
services, which is about 54 instances on the 48-core `borondns-1` host and 81
instances on the 72-core `oxidegun-1` host. That is the preferred 70%-80% CPU
campaign shape when the servers are otherwise idle:

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

The repeated `--host` values are an ordered assignment-slot schedule, not five
distinct machines: two slots select `borondns-1` and three select
`oxidegun-1`. Target services preserve that exact 2:3 round-robin weighting.
Sampler installation, status, and collection derive the stable first-occurrence
physical host list, so each actual host receives exactly one sampler and one
collection pass.

The helper gives each repeated target instance a unique root containing owned
`attempt.*` directories and installs one sampler service per physical host.
Sampler output is retained under `host/<host>/attempts/attempt.*/` and records
active fuzz units, matching process count, aggregate CPU, aggregate RSS, load
averages, and available memory. Each process row carries the exact sample UTC
and epoch key; validation rejects orphan keys, duplicate PIDs within one sample,
and count, two-decimal CPU, or integer RSS totals that differ from the host row.
The same PID may legitimately recur at a later sample epoch. Target and sampler setup can be retried after a
transient systemd installation or start failure: the failed attempt remains
immutable and a fresh attempt receives the new runner and evidence. Resume
accepts target completion only when `campaign-summary.tsv` has the exact header
and one matching passed terminal row. That row records the actual target start
and end epochs; collection requires the authenticated sampler rows to begin no
later than target start and end no earlier than target end.
`campaign-completed.env` records matching summary and artifact-manifest hashes,
every referenced path is contained and non-symlinked, and the strict
artifact-manifest verification succeeds. The completion marker is atomically
published only after final artifact manifests and successful cleanup of an
automatic build root; cleanup failure leaves the evidence incomplete. Automatic
root cleanup also fails closed when the captured root's original pathname is absent:
absence cannot distinguish deletion from a rename-away, so it is never accepted
as proof that the build inode was removed. Sampler completion likewise requires
an exact `sampler-completed.env` plus a terminal
zero-active-unit sample at or after the authenticated deadline. Sampler metadata
binds the interval, absolute deadline, start timestamp, and start epoch; every
sample carries a matching epoch. Collection rejects late starts, non-monotonic
epochs, gaps beyond the interval plus the bounded per-unit probe budget, early
completion, and terminal samples that do not cover the deadline. A valid
`sampler-hard-stop.env` is retained as terminal failure evidence. Header-only,
unfinalized, or otherwise partial evidence is never classified as complete. The
hard-stop UTC must fall between the authenticated sampler start and its derived
terminal reserve. If host or process sample TSVs are present, collection
validates both files' exact schemas, chronology, sample-key membership, and
aggregates; a header-only host file therefore requires an empty process-detail
file. A future/pre-start marker
or malformed published sample is rejected even though hard-stop evidence is
not a successful campaign classification. The
plan authenticates one absolute sampler
deadline, derived from `created_utc + duration + one hour + the 600-second
target-setup reserve`, in both
`campaign.env` and each physical-host sampler assignment. Every initial or
resumed sampler attempt receives that same deadline; resume refuses metadata
that would extend it. The sampler writes the hard-stop marker before exiting
nonzero if fuzz units remain active. A systemd probe error is distinct from an
inactive unit: it writes the exact terminal three-line marker ending in
`probe_failed=1` and can never publish sampler completion merely because the
number of units successfully classified as active was zero.
Remote waits and child watchdogs use one absolute `CLOCK_BOOTTIME` deadline and
timerfd-based expiry, so host suspend consumes rather than replenishes the
budget. After expiry they send process-group `SIGKILL` and poll pidfd/`WNOHANG`
only through a separate bounded termination tail (five seconds by default,
configurable with `BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS`, hard
maximum 30). If an uninterruptible process cannot be reaped in that tail, the
supervisor returns 125 promptly, reports that `SIGKILL` remains pending, and
leaves kernel reparenting to recover the orphan rather than entering an
unbounded `waitpid`. Process-group membership enumeration runs in a separate
pidfd-owned scan worker under the same tail's absolute timerfd. A blocked procfs
walk, an inventory beyond Linux `pid_max`, or an incomplete result therefore
fails with 125 without extending the tail or releasing the unreaped leader's
numeric process-group authority. Once an EXIT finalizer begins, repeated INT, TERM, and HUP are ignored
to prevent re-entry during cleanup or terminal marker publication.
The collector supplies the exact ordered sampler unit identities from the
authenticated assignment plan. `fuzz-units.txt` must equal that canonical,
unique list byte-for-line; evidence cannot add invented or duplicate units to
increase its own cadence or terminal allowance.

Sampler sleep is capped to the remaining authenticated schedule. Its first
row may take one bounded probe pass over the authenticated unit allowlist; the
collector uses that same derived allowance instead of an unrelated two-second
limit. At the
deadline it performs one bounded terminal probe pass, using ten seconds per
allowlisted unit plus five seconds of finalization reserve, so an inactive host
deterministically records its final sample at or after the deadline. Evidence
outside that derived terminal window is rejected. Each target is built under
an independent timeout and then fuzzed to an authenticated wall-clock
deadline. This avoids libFuzzer CPU-time duration drift when many workers
share a host. `BORONDNS_FUZZ_BUILD_TIMEOUT_SECONDS` controls the default
3600-second build bound and `BORONDNS_FUZZ_WALL_CLOCK_KILL_AFTER_SECONDS`
controls the final kill grace.
Every rustup, Git, and tool-version preflight is independently hard bounded;
`BORONDNS_FUZZ_PREFLIGHT_TIMEOUT_SECONDS` and
`BORONDNS_FUZZ_PREFLIGHT_KILL_AFTER_SECONDS` control that bound. Target and
sampler units also carry a plan-derived `RuntimeMaxSec`: target units receive
campaign duration plus one hour, while sampler units additionally receive the
600-second setup reserve and their derived terminal-probe reserve. Both use a
fixed `TimeoutStopSec=30`, providing an authenticated systemd backstop if a
runner-level timeout path fails.

All controller SSH, rsync, and scp paths set connection and keepalive bounds and
also run under command-specific wall-clock limits. The defaults can be tuned
with the `BORONDNS_CAMPAIGN_SSH_*`, `BORONDNS_CAMPAIGN_REMOTE_*_TIMEOUT_SECONDS`,
and `BORONDNS_CAMPAIGN_RSYNC_IDLE_TIMEOUT_SECONDS` environment variables.
Read-only status and collection still validate saved commands against their
manifest-bound tool digests, but do not require the controller's current Rust
or cargo-fuzz binaries to retain the same digest for the lifetime of a remote
campaign.

Process samples are derived only from each planned fuzz unit's `MainPID` and
descendants. They retain PID, resource counters, elapsed time, and command name,
but never full argv, so unrelated same-UID processes and command-line secrets
cannot enter campaign evidence.

Each target attempt also gets a freshly created, runner-owned
`CARGO_TARGET_DIR` under `/var/tmp/borondns-fuzz-<campaign>/`, outside both the
checkout's ignored `target/` and `fuzz/target/` trees. The runner refuses a
symlink, wrong owner, or non-empty build directory before invoking Cargo.
`config.txt` and `tool-versions.txt` record the selected paths and the hashes of
the exact Cargo, rustc, and cargo-fuzz bytes executed, rather than only the
rustup proxy. All three executables are opened, copied through those pinned
descriptors into one private execution directory, and then invoked only from
that snapshot. The staged inodes and digests are rechecked immediately before
and after every invocation. For a concrete rustup compiler, the adjacent
dynamic-library, sysroot, sanitizer, and build-std tree is likewise copied
(using a filesystem reflink when available), checked against source hashes on
both sides of the copy, and bound to a retained tree digest. Thus concurrent
selected-path or compiler-runtime replacement, or a different `cargo-fuzz`
adjacent to the selected Cargo, cannot change the tools used while leaving
apparently valid evidence.
`build-artifacts.sha256` and `artifact-manifest.sha256` retain the resulting
build and evidence hashes. Evidence-manifest and summary paths are relative to
the attempt root, so a collected attempt remains independently verifiable after
the remote host or its original absolute path is gone.

The per-host sampler setup lock remains held through unit publication,
daemon-reload, start, and an exact post-start identity check. Concurrent resume
commands therefore cannot create competing sampler attempts or race to replace
the same unit definition. The sampler itself flocks its attempt-directory file
descriptor, leaving no stale lock pathname that could obstruct crash recovery.

Collection snapshots every regular remote file and directory before and after
transfer. Symlinks and special nodes are rejected; rsync is instructed not to
preserve them, and the scp fallback is protected by the same remote and local
tree scans. The copied staging tree must have the exact same content snapshot as
both remote snapshots, which turns concurrent mutation into a failed collection
instead of mixed evidence. A strict local validator then checks node types,
source commit and clean-source provenance, completion markers, all manifest
hashes and coverage, relative-path containment, target summaries, and every
sampler row. Fuzz validation also requires the authenticated SHA-256 identities
of Cargo, rustc, and cargo-fuzz, in addition to the toolchain selector and
sanitizer. A completed target must cover at least duration minus one second in
the integer wall-clock epochs, must have a nonzero wall interval, and its
monotonic nanoseconds must remain within the explicit two-second
timestamp-capture tolerance of that wall interval. Zero-wall and implausibly
large monotonic claims are rejected even when completion hashes are recomputed;
long setup and terminal manifest work remain outside the measured target
window. Every host must match the plan and therefore each other. Remote jobs
run from a detached clone of the authenticated commit whose source tree and
containing build entry are root-owned and non-writable by the campaign UID;
only the separate Cargo target directory remains runner-owned. Edits,
chmod-and-revert, or entry replacement by the service account therefore cannot
contaminate evidence after preflight. Soak validation requires the exact authenticated
timeout, kill-after, cycle-sleep, sample interval, and allow-skip policy; a
fail-on-skip plan rejects any skipped terminal row. It also bounds the last
scenario activity before the authenticated deadline by one scenario timeout,
kill grace, cycle sleep, and timestamp resolution, preventing a live sampler
from masking a stopped scenario runner. Only that validated staging tree
replaces an older collection. Its whole-tree snapshot digest remains in the
status record. A separate
`remotes/<host>.collection-status.tsv.commit` record binds both that digest and
the SHA-256 of the exact status bytes with the explicit
`unprivileged-sha256` scheme, and is promoted atomically last. Publication
checks evidence before and after promotion and uses content- and
identity-bound promotion for both status objects; readers verify the commit,
exact status bytes, and a fresh evidence-tree digest before acceptance.
Status reads use non-following, nonblocking descriptor opens and require one
current-UID, single-link regular inode whose device, inode, size, mode, owner,
mtime, and ctime remain stable through the read. Status is capped at 8 MiB and
the one-line commit at 1 KiB; both reads and hashes share the collection's
absolute deadline. Sparse growth, FIFOs, and post-open pathname swaps fail
closed instead of consuming unbounded memory or time.

This unkeyed record detects independent corruption, classification-only edits,
and evidence/status drift. It is deliberately not authenticity against a
hostile process with the campaign UID: that process can coordinate a rewrite
of evidence, status, and commit. Formal hostile-same-UID authenticity requires
a signature key or root-owned commit state outside the campaign UID's writable
namespace. Paths containing whitespace or shell
metacharacters require rsync; the legacy scp fallback fails closed for them.
`remotes/<host>.collection-status.tsv` records complete, incomplete, or invalid
classification explicitly. Collected unit journals live in the sibling
`remotes/<host>.journal/` directory so they do not alter the validated remote
evidence tree. Status walks immutable `attempt.*` directories and reports
summaries and samples at their actual paths.
One validated `CLOCK_BOOTTIME` deadline covers each host's snapshot, copy,
validation, journal capture, and publication while the collection lock is held.
The local snapshot and validator share explicit entry, depth, per-file, and
total-byte limits and stream file hashes through non-following descriptors.
Aggregate bytes are charged from the bytes actually streamed, and inventory
identity, size, modification time, and change time must remain stable through
each hash.
Defaults are 10,800 seconds, 100,000 entries, depth 64, 2 GiB per file, and
64 GiB total. Operators may lower them with
`BORONDNS_CAMPAIGN_COLLECTION_TIMEOUT_SECONDS`,
`BORONDNS_CAMPAIGN_COLLECTION_MAX_ENTRIES`,
`BORONDNS_CAMPAIGN_COLLECTION_MAX_DEPTH`,
`BORONDNS_CAMPAIGN_COLLECTION_MAX_FILE_BYTES`, and
`BORONDNS_CAMPAIGN_COLLECTION_MAX_TOTAL_BYTES`; hard maxima are 86,400 seconds,
1,000,000 entries, depth 128, 16 GiB per file, and 1 TiB total. Invalid,
overflowing, exhausted, or exceeded budgets fail closed without publishing.
The authenticated plan supplies the exact target-instance set, per-target
duration, and sampler identity expected on each physical host. Missing entities
remain incomplete and extra entities are invalid; a complete subset can never
make a host complete. Evidence, journal, status, and status-commit replacements are staged and
published as one rollback-safe bundle, so repeated collection is supported.
Same-process recovery receives the same absolute collection deadline. Its live
transaction inventory is descriptor/identity-bound, capped at 64 direct
entries, and fail-retained on deadline or cap exhaustion; recovery never uses
an unbounded pathname `find` over transaction state.
Each physical host has a collection lock spanning both remote snapshots,
validation, and publication. Final promotion uses no-replace renames, so a
destination that reappears despite the lock fails closed instead of nesting or
overwriting another collector's bundle.
Status destinations must be owned regular files and are never followed through
symlinks. Active-unit resume checks likewise fail closed on systemctl errors and
verify the exact loaded fragment plus executable path from `ExecStart` before
trusting a same-name service; wrapper and suffix matches are rejected. Cleanup
performs the same loaded identity check. Status continues across all physical
hosts after a probe error but returns nonzero once any SSH or remote probe failed.

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
cargo +nightly fuzz check catalog_zone
cargo +nightly fuzz check zone_store_state
cargo +nightly fuzz check zone_store_concurrent
cargo +nightly fuzz check server_lifecycle
cargo +nightly fuzz run --sanitizer address dns_datagram -- -max_total_time=60
cargo +nightly miri test -p borondns-core
```

If Miri cannot run a crate because of unsupported OS operations, record the
failure as a tooling limitation and narrow to specific tests instead of treating
that as product evidence.

### Soak Lane

The current long-running executor is `scripts/large-surface-soak.sh`, with
two-host systemd orchestration in `scripts/large-surface-soak-campaign.sh`.
See `docs/large-surface-soak.md` for launch, resume, status, collection, bounded
scenario cleanup, and retained-evidence behavior. The handoff helper remains
useful when preparing the separate single-resident-process soak lane:

```sh
scripts/capture-soak-handoff.sh
```

Prepared execution shape:

- run BoronDNS as a service or supervised process on each host;
- use loopback or same-host synthetic primaries by default;
- run steady query and transfer churn locally, not over the physical NIC;
- sample `/metrics`, `/readyz`, RSS, fd count, thread count, and process status
  at a fixed cadence;
- append anomalies to `operational-events.tsv`;
- retain weekly summaries and a final report.

For the single-resident-process lane, start narrowly with one server, one local
synthetic primary/corpus, one local client workload, and one sampler. Expand to
catalog-zone churn, transfer failures, restart/recovery, and multi-primary cases
only after the simple loop is stable. The large-surface executor is the broad
repeated scenario-cycle lane and does not replace this narrower RSS/FD-growth
measurement.

### XDP Lane

XDP belongs in a separate lane because it requires privileges, queue/NIC state,
MTU constraints, and cleanup. Use existing local XDP smoke tools first:

```sh
scripts/boron-gun-xdp-pkexec-tests.sh
scripts/borondns-af-xdp-veth-smoke.sh
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
`/home/codex/borondns-fuzz/target/evidence/fuzz-soak-two-host-20260612T090724Z/`

Result: passed. No `crash-*`, `oom-*`, or `timeout-*` artifacts were present on
either host at final collection time.

Scope:

| Host | Targets | Result |
| --- | --- | --- |
| `borondns-1` | `dns_datagram`, `transfer_stream`, `zone_image_datagram` | `passed`, exit `0`, `86400` seconds each |
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
| `borondns-1` | `7.0.0-22-generic` | Intel Xeon Gold 6246 @ 3.30GHz | 48 | 373Gi | 438G total, 368G free |
| `oxidegun-1` | `7.0.0-22-generic` | Intel Xeon Gold 6140 @ 2.30GHz | 72 | 123Gi | 878G total, 818G free |

Interpretation: this is first-pass stability evidence for the listed fuzz
targets under one 24-hour ASan-backed campaign. It does not prove parser or
protocol correctness outside the paths and inputs exercised by the fuzz targets.

### 2026-06-14 24-hour ASan fuzz campaign

Campaign ID: `20260614T003811Z`

Remote evidence root:
`/home/codex/borondns-fuzz/target/evidence/fuzz-soak-two-host-20260614T003811Z/`

Collected local evidence:
`target/evidence/fuzz-soak-two-host-20260614T003811Z/remotes/`

Result: passed. All 75 systemd fuzz services completed with `status=passed`,
exit `0`, and `86400` seconds in their `campaign-summary.tsv` files. No
sanitizer, panic, crash, leak, OOM, or timeout markers were found in the
collected fuzz logs, and no crash/leak/OOM/timeout artifact files were present.

Scope:

| Host | Targets | Services | Result |
| --- | --- | ---: | --- |
| `borondns-1` | `dns_datagram`, `transfer_stream` | 30 | 30/30 passed |
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
| `borondns-1` | `7.0.12-borondns1` | Intel Xeon Gold 6246 @ 3.30GHz | 48 | 373Gi | 30 |
| `oxidegun-1` | `7.0.0-22-generic` | Intel Xeon Gold 6140 @ 2.30GHz | 72 | 123Gi | 45 |

Interpretation: this post-v0.2.0-readiness campaign provides retained
24-hour ASan evidence for the five fuzz targets that existed at campaign start.
It remains fuzz evidence. The release decision combines it with additional
independent 24-hour rounds and targeted resource evidence; no separate fixed
No fixed 30-day soak is required for the 1.0 public beta; release evidence uses
risk-selected bounded campaigns, including independent 24-hour fuzz rounds.

## Scheduling Guidance

Run order after UDP/XDP tuning:

1. Short compile/preflight on both hosts.
2. One-hour fuzz smoke per target to shake out toolchain and environment issues.
3. 24-hour ASan-backed fuzz campaign per target, split across the two hosts.
4. Loopback soak executor once implemented and stable.
5. Privileged XDP smoke/soak only in a dedicated window.

Do not mix these with performance comparison runs unless the campaign explicitly
records that host contention was intentional.
