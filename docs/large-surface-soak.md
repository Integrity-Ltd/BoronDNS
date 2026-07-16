# Large-Surface Soak Campaign

Status: long-running release/operations evidence lane.

The large-surface soak repeatedly exercises retained real-primary and protocol
interop scenarios under systemd supervision. It is intended to keep the broad
secondary-DNS surface hot over long wall-clock windows:

- AXFR and IXFR refresh paths;
- NOTIFY handling;
- TSIG-gated transfer paths;
- XoT and XoT+TSIG transfer paths where the available primary package supports
  XoT;
- RFC 9432 catalog zones;
- extended catalog member transfer metadata;
- catalog member add/remove and split-primary updates;
- BIND, NSD, Knot, and PowerDNS/PostgreSQL primary scenarios;
- DNSSEC serving, NSEC3 negative proof handling, EDNS, DNS Cookies, TCP
  truncation retry, RRL, CHAOS TXT, unknown RR handling, and bad-transfer
  rejection paths.

The campaign runner is `scripts/large-surface-soak.sh`. The two-host systemd
wrapper is `scripts/large-surface-soak-campaign.sh`.

For a direct local run, leaving `CARGO_TARGET_DIR` unset creates a private
mode-0700 tree below `${TMPDIR:-/var/tmp}/borondns-large-builds-<uid>/`. Its
parent and target are created and opened descriptor-relative without following
symlinks, their identities are journaled before the path is published, and a
prepublication failure rolls the exact empty inode back. Only that exact
automatic tree is removed on every exit after artifact manifests are written.
A durable mode-0600 journal records `allocating`, `preparing`, `ready`, and
schema-3 `removing` phases. Journal bytes are written and fsynced in an
`O_TMPFILE`; initial publication links that exact open inode with
`linkat(AT_EMPTY_PATH)`, while replacement keeps the descriptor open through
exchange and retains the displaced entry. The allocating intent and its parent
are fsynced before `mkdir`; later phases bind the owner boot ID, PID/starttime,
parent, and tree identities. Removing is durable before the tree rename and
records the exact random quarantine name. Creation is serialized by a per-UID
family lock. Automatic cleanup in a same-UID-writable namespace ends at the
exact no-replace quarantine rename; it does not unlink or recursively delete by
pathname. After live descriptor/socket authority disappears, disk journals are
evidence only: a later creator reports them for privileged exact reconciliation
and never uses them to delete, overwrite, restore, or promote.

The one intentionally fail-closed crash window is a SIGKILL after the fsynced
allocating intent and `mkdir`, but before the preparing journal can bind the new
inode. Recovery prints the exact retained `target=` and `intent=` paths and
does not claim or delete the unknown inode. An operator must first verify the
reported tree, capture its current device/inode with
`campaign_capture_cleanup_identity`, hold an authenticated private campaign
lock, and remove it with `campaign_remove_captured_cleanup_object`. Rerunning
the normal prepare step then clears the now-targetless allocating intent. Do
not unlink either path solely because its name resembles an automatic root.
An explicit caller `CARGO_TARGET_DIR` is never removed. The
two-host wrapper continues to use explicit planned build roots so collection
and authenticated campaign cleanup can manage them separately.

Remote `cleanup` preallocates the planned build root's exact quarantine name
and durably publishes a unique
`.borondns-retained-cleanup-<root>.<pid>.<nonce>.env` in its parent
before the no-replace rename. The journal records `prepared` before mutation
and `retained` only after the quarantine still matches the captured
device/inode/owner. Cleanup output therefore says `cleanup_retained` and
`identity-quarantined`; it never describes that retained tree as cleaned or
deleted. Use `campaign_verify_retained_cleanup_journal` to check the recorded
identity during operator reconciliation. If a crash leaves `phase=prepared`
after the rename, the verifier emits `cleanup_prepared_verified` only when the
original is absent and the exact recorded quarantine identity and type still
match; it never authorizes deletion. A later cleanup attempt uses a fresh
journal and quarantine name, preserving every earlier mapping. The journal is same-UID evidence, not
destructive authority after the cleanup process exits.

Interop primary images use an exact Alpine 3.22 manifest digest. Their cache
tag is derived from the scenario name, pinned base, and ordered package recipe;
the same values are stored as image labels and must match on inspection. A
missing, foreign, or partially labelled tag is rebuilt, and each scenario is
given the resulting immutable local `sha256:` image ID. Concurrent builds are
serialized by the descriptor-held campaign lock broker, including when the
owner shell is paused. Because image tags are Docker-daemon-global, every
caller for the same UID uses one canonical lock root under `/tmp`, independent
of `XDG_RUNTIME_DIR` and `TMPDIR`. The broker holds an abstract Unix-socket
authority derived from the canonical lock root and namespace in addition to
the descriptor-validated evidence file. Replacing or unlinking the visible
lock path cannot create a second authority while the first broker lives;
heartbeats prove that the broker and authority are still live. Temporary Docker build
contexts use the same descriptor-created, identity-bound cleanup contract, and
a cleanup failure changes an otherwise successful image setup into a failure.

## Evidence Shape

Each host writes:

- `soak.env`: evidence schema, selected duration, scenario timeout, cycle sleep, sample interval,
  scenario set, original start epoch, and absolute campaign deadline;
- `host-info.txt`: kernel, CPU, memory, disk, Docker, and command-line metadata;
- `tool-versions.txt`: Rust, Docker, dig, curl, OpenSSL, and Python versions;
- `scenario-results.tsv`: an append-only row per scenario attempt with cycle,
  scenario-local attempt number, status, exit status, timestamps, artifact
  directory, and log path;
- `soak-summary.env`: aggregate pass/skip/fail counters and per-scenario pass
  counts;
- `resource-sampler-attempts/attempt-*/resource-samples.tsv`: load, memory,
  Docker container count, and process RSS samples with wall-clock epochs;
- `resource-sampler-attempts/attempt-*/process-samples.tsv`: sampled BoronDNS,
  Cargo/Rust, Docker, and primary process rows, each bound to an exact resource
  sample UTC and epoch. Validation rejects orphan sample keys, duplicate PIDs
  within an epoch, and process-count or RSS aggregates that differ from the
  corresponding resource row;
- `scenarios/cycle-*/<scenario>/attempts/attempt-*/`: immutable logs,
  attempt-start metadata, interruption markers, and scenario-specific artifacts.

The local campaign wrapper also collects systemd journals for each host unit
under `remotes/<host>.journal/`, outside the strictly validated remote evidence
tree.

## Launch

Create only a manifest:

```sh
scripts/large-surface-soak-campaign.sh plan --duration 2592000
```

Install prerequisites and launch the full 30-day campaign on the default two
hosts:

```sh
scripts/large-surface-soak-campaign.sh launch \
  --duration 2592000 \
  --install-prereqs
```

Check status:

```sh
scripts/large-surface-soak-campaign.sh status \
  --evidence-dir target/evidence/large-surface-soak-<campaign-id>
```

Collect evidence:

```sh
scripts/large-surface-soak-campaign.sh collect \
  --evidence-dir target/evidence/large-surface-soak-<campaign-id>
```

After collection, remove only verified inactive campaign units and owned build
roots while retaining remote evidence:

```sh
scripts/large-surface-soak-campaign.sh cleanup \
  --evidence-dir target/evidence/large-surface-soak-<campaign-id>
```

Cleanup fails closed on a systemctl error, active or ambiguous state,
fragment/`ExecStart` mismatch, symlink, ownership mismatch, or unexpected build
root. It holds the campaign's existing private launch/resume lock, completes
all identity and build-root checks before mutation, removes the fragment,
verifies the post-reload unit is `not-found`, and only then removes the
root-owned runner and build root. Cleanup is idempotent after a reload failure
because the exact runner remains available for retry. Known same-filesystem
fragment staging files from an interrupted atomic publication are safely
reconciled under the campaign lock.

Resume an interrupted or failed campaign from its saved plan:

```sh
scripts/large-surface-soak-campaign.sh resume \
  --evidence-dir target/evidence/large-surface-soak-<campaign-id>
```

`status` reports `unit_identity=exact` only after applying the same complete
canonical fragment-schema and root-owned runner validation used by launch,
resume, and cleanup. Drift in service directives such as `User`, working
directory, supplementary groups, limits, or kill mode is therefore a mismatch
even when `ExecStart` itself is unchanged.

Resume refuses missing or malformed remote `scenario-results.tsv`, an already
active unit, local campaign-parameter overrides, and a reused non-empty evidence
directory without resumable results. The saved plan supplies the original
duration, scenarios, timeouts, and other campaign parameters. Existing attempt
rows and sampler attempts are retained; they are never truncated by resume. A
failed attempt is retried at the same cycle/scenario with the next attempt
number. The retained tree must have an exact bijection between canonical
`scenario-results.tsv` rows and `scenarios/**/attempts/attempt-*` directories;
an unledgered or missing attempt fails closed. An attempt directory whose start
metadata was published before an
interruption but has no result row is atomically classified as `interrupted`,
then retried in a fresh directory. Result rows are published by same-directory
atomic replacement. Resume can remove exactly one torn non-newline tail only
when its cycle, scenario, attempt, and timestamp match the sole unrecorded
`attempt-started.env`; arbitrary malformed rows still fail closed. Resume
constructs a fresh safe remote runner from the saved manifest, so plans created
before the resume command was added do not reuse their older destructive launch
script. It refuses a campaign whose `campaign-completed.env` marker shows that
it already finished normally. The initial runner records the kernel boot ID and
one absolute `CLOCK_BOOTTIME` deadline. Normal `--resume` is accepted only on
that same boot and reuses the exact saved deadline, so realtime rollback cannot
replenish the campaign and suspend time still counts. Cross-boot release resume
fails closed because a local wall clock cannot securely reconstruct the prior
monotonic budget. `--resume-cross-boot-diagnostic` is an explicit non-release
escape hatch: it credits none of the earlier active time and starts a fresh
full-duration window while retaining prior attempts. Its completion marker is
labelled `non-release-diagnostic`, and collection rejects it as release
evidence. Realtime remains only human-readable UTC evidence; it cannot
replenish or freeze live sampler, scenario, cycle-sleep, final-wait, or
TERM-to-KILL budgets. The runner caps each scenario's soft timeout
to the remaining monotonic campaign budget; only the configured hard-kill grace
and post-command cleanup may finish after the deadline. It checks the remaining
budget before allocating an attempt directory. If the deadline is exhausted in
the narrow race after allocation but before command execution, the runner
removes the still-empty attempt rather than leaving unledgered evidence.

All child-command watchdogs and protocol waits use the same absolute
`CLOCK_BOOTTIME` basis, implemented with timerfd rather than relative GNU
`timeout` accounting. Suspend therefore consumes the remaining budget instead
of replenishing it. On expiry, process-group `SIGKILL` and pidfd/`WNOHANG`
polling continue only through a separate termination tail: five seconds by
default, configurable with
`BORONDNS_CAMPAIGN_DEADLINE_TERMINATION_TAIL_SECONDS`, with a hard maximum of
30. If an uninterruptible process cannot be reaped by then, the supervisor
returns 125 with `SIGKILL` still pending and relies on kernel reparenting
instead of blocking in `waitpid`. Process-group membership enumeration runs in
a separate pidfd-owned worker under that same absolute tail timerfd. A blocked
procfs walk, an inventory beyond Linux `pid_max`, or an incomplete result fails
with 125 without extending the tail or releasing the unreaped leader's numeric
process-group authority. EXIT finalizers ignore repeated INT, TERM, and HUP once
cleanup or evidence publication starts, preventing signal re-entry from
leaving a partially published terminal state.

Historical `failed` and `interrupted` rows remain evidence, but do not prevent
terminal success after a later numbered attempt for that exact cycle/scenario
passes. An unresolved latest failure or interruption still prevents
`campaign-completed.env`. Scenario ordering cannot advance past an unresolved
attempt, so a partial cycle resumes at its exact next scenario rather than
skipping to a new cycle.
Collection authenticates the Docker cleanup timeout from the campaign plan and
requires every scenario attempt to start at or after the captured campaign
start and strictly before its deadline. An end timestamp may exceed the
deadline only by the plan-derived hard-kill and six bounded Docker
list/removal operations (including their timeout kill grace); later evidence is
invalid rather than a completed soak cycle.

Every systemd attempt creates a detached source clone at the authenticated
commit under a root-owned, non-writable parent. The clone itself is root-owned
and non-writable by the campaign UID. Its ignored, root-owned `target` symlink
is pinned to a fresh mode-0700 directory beneath the separate runner-owned
`targets/` tree, so existing interop work and binary paths remain usable
without making source writable. Each run uses that exact empty
`CARGO_TARGET_DIR` under `/var/tmp/borondns-large-<campaign>/<host>/`. The
attempt records that exact path plus Cargo/Rust tool paths
and hashes for the exact rustup-selected Cargo and rustc executables, not their
proxy shims. Those two digests are authenticated in the plan, rechecked before
launch and throughout the run, recorded in `soak.env`, and required again by
collection validation. On exit it writes `build-artifacts.sha256` and
`artifact-manifest.sha256`; a symlinked, wrong-owner, or non-empty build
directory is rejected before any build. Initial launch also refuses an
already-active unit with the planned name. Reuse of a campaign id therefore
cannot rewrite an active definition and return success while the older runner
continues executing.

The systemd fragment itself is root-staged and atomically renamed. Its
`ExecStart` wrapper is root-owned, mode 0555, beneath a root-owned parent, and a
root-owned sidecar binds SHA-256, device, and inode for every resume, status,
and cleanup identity check.

The completion marker is the last artifact published. Before creating it, the
runner strictly validates every retained result row, including its exact schema,
scenario membership, monotonic attempt sequence, status/exit consistency, and
contained artifact and log paths. It also requires one supervised final sampler
attempt whose typed resource/process sample schemas begin with the campaign,
remain within the authenticated cadence (including across explicitly retained
sampler attempts), and include a sample at or after the absolute deadline. A
sampler crash writes a failure marker and fails the service; absent, truncated,
malformed, or cadence-gapped sampling cannot satisfy the strict collector. The
runner also requires the final retained scenario activity to fall within a
bounded terminal gap derived from the authenticated scenario timeout, kill
grace, cycle sleep, and timestamp resolution. A sampler that continues while
the scenario runner is stopped therefore cannot turn an inactive campaign into
completed evidence. The runner then atomically publishes the summary and hash
manifests and must successfully remove any automatic build root before
publishing completion. A malformed retained row, sampler failure, stale
terminal scenario activity, automatic-root cleanup failure, or other failed
finalization leaves no completion marker. The source commit and clean state are
checked again at terminal publication, so the attempt remains visibly
incomplete instead of being misclassified as successful.

Current soak evidence is explicitly schema 2 in both `soak.env` and
`campaign-completed.env`; completion also requires `status=passed`. The
collector keeps a narrow read-only compatibility path for genuinely legacy
metadata that has been explicitly migrated to `evidence_schema=1`, whose
completion marker must carry the same schema label. Mere schema absence is not
legacy provenance and fails closed. A schema-2 campaign with a missing status
is likewise invalid, so a current partial marker cannot be accepted through
the compatibility path.

Automatic-root cleanup is identity-bound and fail-closed. In particular, a
missing original pathname is not treated as successful deletion because the
captured inode may merely have been renamed elsewhere; completion remains
unpublished and the retained cleanup identity is reported for recovery.
Privileged recursive deletion additionally requires every directory-entry
boundary to be proven non-writable by the campaign UID through mode bits and
ACL state. Root ownership alone is insufficient; an explicit access ACL or any
unproven boundary retains the entire quarantined root.

Campaign plans are published atomically with a `plan-complete` marker and use a
strict base64 scalar metadata format that management commands parse without
executing. Plan paths and their ancestors must be real, owned directories, and
the immutable plan tree must not be group/world writable. Management commands
regenerate a private command copy from the validated semantic plan and execute
that pinned copy, rather than trusting a saved command file after validation.
Each plan also manifests an executable copy of the strict collection validator.
Management rejects semantic drift in that copy even after a manifest recompute,
and collection executes the exact plan copy rather than a mutable checkout
validator.
Planning also refuses dirty local checkouts and host names whose canonical
evidence identifiers collide, records the exact commit, and every initial,
resumed, and service-runner launch requires the remote checkout to be clean at
that commit; the launcher never pulls a moving branch. Local plan and runner
locks live under a dedicated `.borondns-campaign-locks` mode-0700 directory;
their parent must be owned by the campaign user and must not be group/world
writable. Lock files are opened without following symlinks and verified through
the live descriptor before locking. Remote locks use the same descriptor broker
in a runner-owned mode-0700 directory, removing any path-check then
shell-redirection race. Scenario-result and evidence-manifest paths
are relative to the host evidence root, making the retained copy portable.
Every mutation boundary requires an acknowledged heartbeat from the lock
broker, so an unexpectedly terminated broker fails closed. Prerequisite setup
does not persistently add the campaign account to the Docker group; the unit's
temporary `SupplementaryGroups=docker` grant is sufficient for the bounded
run. Resource process
sampling is limited to the soak runner and descendants and records no argv.
The service inherits already-open descriptors for the authenticated Cargo and
rustc executables and re-hashes them immediately before use. A root-owned,
read-only command directory places an exact `cargo -> /proc/self/fd/7` binding
first on the otherwise system-only command search path; its resolved inode and
digest are checked before every scenario. Sampler and interruption terminal markers
are published by same-directory atomic rename, and resume repairs only a
schema-prefix final marker that is provably torn.
Collection writes to a fresh staging directory, rejects remote or local
symlinks and special nodes, and compares content snapshots taken before
transfer, after transfer, and from the local copy. Concurrent mutation or a
copy mismatch fails without replacing the preceding collection. The copied
tree then undergoes strict local schema, path, source-commit,
completion-marker, and full-manifest verification before publication.
The validator-approved whole-tree digest is embedded in the status record. A
separate `remotes/<host>.collection-status.tsv.commit` record binds that digest
and the SHA-256 of the exact status bytes under the explicit
`unprivileged-sha256` scheme, and is promoted last. The publisher checks the
evidence around promotion and uses captured content and inode identity for the
status and commit renames. Consumers verify both status bytes and a fresh tree
digest before accepting the generation.
Status reads use non-following, nonblocking descriptor opens and require one
current-UID, single-link regular inode whose device, inode, size, mode, owner,
mtime, and ctime remain stable through the read. Status is capped at 8 MiB and
the one-line commit at 1 KiB; both reads and hashes share the collection's
absolute deadline. Sparse growth, FIFOs, and post-open pathname swaps fail
closed instead of consuming unbounded memory or time.

This unkeyed commit detects independent corruption, classification-only edits,
and evidence/status drift, but it is not authenticity against a hostile
same-UID process. Such a process can coordinate a rewrite of evidence, status,
and commit. Formal authenticity for that threat requires a signature key or
root-owned state outside the campaign UID's writable namespace.
`remotes/<host>.collection-status.tsv` records complete, incomplete, or invalid
classification. If launch stops partway through, `resume`
leaves active hosts alone and resumes hosts with valid results.
The copied host must match the authenticated plan's exact ordered, unique
scenario list and duration. Its captured deadline must equal start plus that
duration, and completed evidence cannot predate the deadline. Evidence, journal,
and non-symlink status and status-commit destinations are staged under a
per-host transaction.
Same-process recovery receives the same absolute collection deadline and
enumerates the live descriptor-bound transaction with a hard 64-entry direct
child cap. Deadline or cap exhaustion retains the transaction and fails;
recovery never performs an unbounded pathname `find` over transaction state.
An atomic commit marker distinguishes a fully published generation. During a
live transaction, the transaction directory and every identity/decision marker
remain open by descriptor. Marker descriptors are created with exclusive,
non-following, nonblocking opens and retained by a small broker; the shell never
reopens a marker pathname before checking authority. Marker decisions use the immutable creation-time
payload retained in process memory; the descriptor only proves that the marker
pathname still names the created inode, because same-UID writers can modify a
regular file through another open descriptor. The transaction records the device/inode/type identity
of every original and promoted evidence, journal, status, and status-commit object before any
rename. A crash loses that authority, so durable transaction files never
authorize automatic rollback, promotion, overwrite, or deletion; the exact
transaction is retained for privileged inspection. Live cleanup logically
removes old objects by exact quarantine rename and retains them instead of
performing a racy post-validation unlink. Each
host collection holds a
private lock from the first remote snapshot through no-replace
evidence/journal/status/status-commit publication; a destination that reappears during
promotion is a hard failure. Active-unit resume checks also
fail closed on systemctl errors and verify the exact loaded fragment and
executable path from `ExecStart`; wrapper or suffix matches are rejected. Cleanup
applies the same loaded identity check before removing a fragment or build tree.
Status still visits every planned host when one probe fails, but returns nonzero
afterward so monitoring cannot mistake an unreachable host for success.
The same validated absolute `CLOCK_BOOTTIME` deadline covers all phases for one
host. Local traversal defaults to 100,000 entries, depth 64, 2 GiB per file,
64 GiB total, and a 10,800-second deadline. The
`BORONDNS_CAMPAIGN_COLLECTION_TIMEOUT_SECONDS`,
`BORONDNS_CAMPAIGN_COLLECTION_MAX_ENTRIES`,
`BORONDNS_CAMPAIGN_COLLECTION_MAX_DEPTH`,
`BORONDNS_CAMPAIGN_COLLECTION_MAX_FILE_BYTES`, and
`BORONDNS_CAMPAIGN_COLLECTION_MAX_TOTAL_BYTES` overrides may only reduce or
raise those values within the documented hard maxima of 86,400 seconds,
1,000,000 entries, depth 128, 16 GiB per file, and 1 TiB total.
It also validates the exact fragment, root-owned runner, and identity sidecar;
a foreign same-name unit is an identity failure.

With `--install-prereqs`, the enabled and active states of `docker`, `named`,
and `bind9` are atomically recorded in a root-owned file before package or
service mutation. Cleanup replays that record idempotently, verifies the
restored states, and publishes a root-owned restoration marker before deleting
the build root. Interrupted setup and partial restoration therefore remain
retryable, and cleanup retains the state record until restoration verifies.

## Interpretation

This campaign is a broad scenario-cycle soak. It provides long-running evidence
that the implemented interop and protocol surfaces continue to pass under
repeated setup, transfer, catalog mutation, query validation, and teardown.

It is intentionally not the same as a single resident BoronDNS process serving
one stable workload for 30 days. Treat the single-process RSS/FD growth soak as
a companion lane when closing the strict BDS-NFR-REL-003 memory-growth target.

Scenario self-skips are recorded as `skipped` by default because some XoT
coverage depends on the primary package in the host/container distribution. Use
`--fail-on-skip` for a release gate that requires every selected primary feature
to be available. Strict two-host collection binds this policy and every planned
timeout/sampling interval to `soak.env`; evidence from an allow-skip run cannot
satisfy a fail-on-skip plan.

Failures are evidence. Preserve the scenario artifact directory, command log,
systemd journal, host metadata, and resource samples before minimizing or
rerunning.

Each scenario first receives `SIGTERM` at `--scenario-timeout`. If it has not
exited after `--scenario-kill-after` (30 seconds by default), the timeout process
group is hard-killed so one wedged scenario cannot stall the campaign forever.
Docker run/create operations receive a unique runner-owned label through a
temporary CLI wrapper. The label is persisted before the scenario starts and a
reconciliation marker is published after cleanup. After every scenario,
including a hard timeout, the
runner reconciles and removes containers, networks, and volumes carrying that
label so daemon-owned resources cannot leak into a resumed cycle. If Docker
reconciliation itself fails, the scenario log names the ownership label and a
`docker-cleanup-failure.env` artifact retains both the primary scenario exit
status and the cleanup exit status. Before a resumed runner advances to another
cycle, it retries bounded reconciliation for every unresolved retained label.
This includes an active label left by a stop, crash, or SIGKILL before the
interrupted runner could write cleanup-failure evidence.
If any retry still fails, resume stops without running a scenario and writes an
explicit, timeout-bounded `docker-cleanup-recovery.sh` command beside each
failure evidence file. All labels are attempted before resume fails. Cleanup
reconciliation still runs after the campaign deadline; deadline rejection is
applied only after retained resources are reconciled or recovery commands are
written.
