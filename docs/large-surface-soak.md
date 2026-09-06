# Large-surface soak

This campaign repeatedly runs live-primary and protocol scenarios under systemd
supervision. It exercises setup, transfer, query validation, catalog changes, and
teardown over a chosen duration. Use it to find failures across repeated
operations; use a separate long-lived server process when investigating gradual
RSS or file-descriptor growth.

The local executor is [`large-surface-soak.sh`](../scripts/large-surface-soak.sh).
The two-host wrapper is
[`large-surface-soak-campaign.sh`](../scripts/large-surface-soak-campaign.sh).
For parser fuzzing, use the [two-host fuzz runbook](two-host-fuzz-soak-campaign.md).

## Coverage and prerequisites

The default scenario set covers BIND, NSD, Knot, and PowerDNS/PostgreSQL
primaries; AXFR, IXFR, NOTIFY, TSIG, and supported XoT combinations; catalog
membership and split primaries; DNSSEC/NSEC3 answers; negative answers; EDNS,
Cookies, RRL, truncation, CHAOS TXT, unknown types, and invalid transfers.

Some primary packages lack the XoT features a scenario needs. Such a scenario
is recorded as skipped by default. Use `--fail-on-skip` when every selected
feature must be exercised; an allow-skip run cannot satisfy that plan.

The controller and remote checkouts must be clean at the recorded commit.
Defaults are SSH hosts `borondns-1` and `oxidegun-1`, remote checkout
`/home/codex/borondns-fuzz`, and a 24-hour duration. Pass `--host` if your
lab uses `oxidedns-1` instead. Verify your SSH aliases before planning a run.
Avoid overlapping CPU-heavy fuzz jobs or physical-link benchmarks.

The hosts need Docker, primary-server tools, Rust, and the privileges required
to install the generated systemd services. `--install-prereqs` installs
Docker, BIND, dnsutils, curl, and OpenSSL. It records the prior enabled/active
states of `docker`, `named`, and `bind9` for restoration during cleanup.
It does not add the campaign account permanently to the Docker group.

## Launch and monitor

Inspect a plan without starting services:

```sh
scripts/large-surface-soak-campaign.sh plan --duration 86400
```

Create a plan, install prerequisites, and launch:

```sh
scripts/large-surface-soak-campaign.sh launch \
  --duration 86400 \
  --install-prereqs
```

Use the evidence directory printed by the wrapper for subsequent operations:

```sh
campaign='target/evidence/large-surface-soak-<campaign-id>'
scripts/large-surface-soak-campaign.sh status --evidence-dir "$campaign"
scripts/large-surface-soak-campaign.sh collect --evidence-dir "$campaign"
```

The saved plan fixes the source commit, host list, duration, scenarios,
timeouts, sampling interval, and skip policy. Status checks the loaded service
definition and runner identity, not just the unit name. An SSH or systemd probe
error returns a failure even if other hosts remain reachable.

| Option | Default | Purpose |
| --- | ---: | --- |
| `--duration` | 86,400 s | Campaign window. |
| `--scenario NAME` | Full default set | Repeat to select scenarios; use `--help` and the runner's scenario list. |
| `--scenario-timeout` | 1,800 s | Soft limit for one scenario, capped by the remaining campaign window. |
| `--scenario-kill-after` | 30 s | Grace before hard kill. |
| `--docker-cleanup-timeout` | 30 s | Bound for each owned Docker cleanup operation. |
| `--cycle-sleep` | 5 s | Delay between complete cycles. |
| `--sample-interval` | 60 s | Resource sample cadence. |
| `--fail-on-skip` | Off | Require all selected scenarios to run successfully. |

The runner uses an absolute `CLOCK_BOOTTIME` deadline: suspend counts toward
the window and wall-clock changes do not extend it. Hard-kill grace, Docker
reconciliation, and evidence finalization may finish after the scenario window.
A watchdog that cannot reap a killed process within its bounded termination
tail returns 125 and reports the pending kill.

## Resume without replacing evidence

```sh
scripts/large-surface-soak-campaign.sh resume --evidence-dir "$campaign"
```

Resume uses the saved plan, leaves active services alone, and preserves earlier
attempts and samples. It retries the unresolved cycle/scenario with the next
attempt number. A later successful attempt may resolve an earlier failed or
interrupted one; the failure remains in the ledger.

Ordinary resume requires the same boot and the original deadline. It refuses
a completed campaign, missing or malformed attempt records, inconsistent
service identity, or changed parameters. The direct runner's
`--resume-cross-boot-diagnostic` option starts a fresh duration without
crediting earlier time; its result is marked `non-release-diagnostic` and
does not count as release evidence.

Before running another scenario, resume reconciles Docker objects left by
interrupted attempts. Each attempt has a unique ownership label. If any
label cannot be reconciled, resume stops and writes a bounded
`docker-cleanup-recovery.sh` next to the failure evidence. Inspect and use
that exact recovery command rather than deleting all Docker resources.

## Read and retain the results

| File | What it records |
| --- | --- |
| `soak.env` | Schema, source, selected scenarios, timing, skip policy, and deadline. |
| `host-info.txt`, `tool-versions.txt` | Host, disk, memory, tool, and command context. |
| `scenario-results.tsv` | Every attempt's cycle, scenario, result, exit status, times, and relative artifact path. |
| `soak-summary.env` | Aggregate counts and per-scenario passes. |
| `scenarios/cycle-*/<scenario>/attempts/attempt-*/` | Immutable logs, start markers, interruption records, and scenario artifacts. |
| `resource-sampler-attempts/attempt-*/` | Resource and process samples, including load and RSS. |
| `campaign-completed.env` | Terminal status and manifest binding; absence means completion is unproven. |
| `remotes/<host>.journal/` | Collected unit journals, separate from the validated evidence tree. |
| `remotes/<host>.collection-status.tsv` | Complete, incomplete, or invalid collection classification. |

A completed current-format run uses evidence schema 2 and
`status=passed`. Collection verifies every planned scenario, attempt,
timestamp, manifest, sample, and completion marker before publishing a local
copy. It checks remote snapshots before and after transfer to reject changing
or mixed evidence. A failed collection leaves the previous copy available.

Completion requires activity across the intended window, not merely a live
resource sampler. Header-only logs, missing entities, unresolved latest
failures, and invalid markers do not constitute a passed soak. Legacy
schema-1 evidence must be explicitly marked as such; missing schema metadata
does not make an artifact legacy.

The checksum record attached to a collection detects accidental corruption and
evidence/status drift. It is unkeyed SHA-256, not a signature or protection
against a process that can rewrite the entire collection. Preserve a protected
copy when independent evidence custody is required.

The collection defaults are a three-hour limit per host, 100,000 entries,
depth 64, 2 GiB per file, and 64 GiB total. The
`BORONDNS_CAMPAIGN_COLLECTION_*` overrides and hard maxima are listed in
the [fuzz runbook](two-host-fuzz-soak-campaign.md#time-limits-and-resource-limits).
Oversized, changing, symlinked, or malformed trees fail validation rather than
being published partially.

## Cleanup and retained build trees

After collection:

```sh
scripts/large-surface-soak-campaign.sh cleanup --evidence-dir "$campaign"
```

Cleanup verifies inactivity, the exact unit and runner, and ownership of the
planned build root. It removes the service definition, reloads systemd, then
reconciles dependencies. If reload or restoration fails, the remaining
identities and state record are retained for a checked retry. Remote evidence
is never removed by campaign cleanup.

A build root writable by the campaign account is quarantined rather than
recursively deleted after a pathname check. The log reports
`cleanup_retained` and `identity-quarantined`, with an exact
`.borondns-retained-cleanup-*.env` mapping. Keep that journal and tree for
inspection. `cleanup_prepared_verified` verifies an interrupted rename; it
does not authorize deletion.

Direct local runs with no `CARGO_TARGET_DIR` allocate a private automatic
tree under `${TMPDIR:-/var/tmp}/borondns-large-builds-<uid>/`.
Explicit caller build roots are preserved. Automatic roots are tracked by
owner/device/inode and may be retained after a crash, missing pathname, or
identity mismatch. A later process cannot use an old journal as deletion
authority; inspect the reported target and intent before privileged
reconciliation.

Container image caches are keyed by the scenario, pinned Alpine 3.22 base
digest, and package recipe. Scenarios use the inspected immutable image ID;
a cache label mismatch triggers a rebuild. Docker resources are reconciled by
their exact attempt ownership labels after success, failure, timeout, or
interruption.

Detailed locking, tool snapshot, transaction, and identity rules are maintained
with their implementations in [shared helpers](../scripts/campaign-env.sh)
and [the wrapper](../scripts/large-surface-soak-campaign.sh). They should not
be duplicated into operational instructions.

## What a passed campaign means

A pass shows that the selected scenarios kept completing under repeated
setup, transfer, catalog changes, and teardown for the recorded commit and
environment. It does not measure one resident process's long-term memory
growth, guarantee behavior outside the scenario set, or replace performance
measurements.

Use a separate resident-process RSS/FD campaign when evaluating
`BDS-NFR-REL-003`. Neither runner imposes a fixed 30-day release prerequisite.
Preserve failures with their scenario directory, command log, unit journal,
host context, and resource samples before narrowing or rerunning them.
