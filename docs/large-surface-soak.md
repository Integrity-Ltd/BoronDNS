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

## Evidence Shape

Each host writes:

- `soak.env`: selected duration, scenario timeout, cycle sleep, sample interval,
  and scenario set;
- `host-info.txt`: kernel, CPU, memory, disk, Docker, and command-line metadata;
- `tool-versions.txt`: Rust, Docker, dig, curl, OpenSSL, and Python versions;
- `scenario-results.tsv`: one row per scenario attempt with cycle, status, exit
  status, timestamps, artifact directory, and log path;
- `soak-summary.env`: aggregate pass/skip/fail counters and per-scenario pass
  counts;
- `resource-samples.tsv`: load, memory, Docker container count, and process RSS
  samples;
- `process-samples.tsv`: sampled OxideDNS, Cargo/Rust, Docker, and primary
  process rows;
- `scenarios/cycle-*/<scenario>/`: retained logs and scenario-specific artifacts
  produced by the underlying interop script.

The local campaign wrapper also collects systemd journals for each host unit
under `remotes/<host>/journal/`.

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

## Interpretation

This campaign is a broad scenario-cycle soak. It provides long-running evidence
that the implemented interop and protocol surfaces continue to pass under
repeated setup, transfer, catalog mutation, query validation, and teardown.

It is intentionally not the same as a single resident OxideDNS process serving
one stable workload for 30 days. Treat the single-process RSS/FD growth soak as
a companion lane when closing the strict ODS-NFR-REL-003 memory-growth target.

Scenario self-skips are recorded as `skipped` by default because some XoT
coverage depends on the primary package in the host/container distribution. Use
`--fail-on-skip` for a release gate that requires every selected primary feature
to be available.

Failures are evidence. Preserve the scenario artifact directory, command log,
systemd journal, host metadata, and resource samples before minimizing or
rerunning.
