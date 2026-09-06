# BoronGen two-host large-memory campaign — July 2026

This July 28–30 campaign established several large-zone publication and query
results, but coordinator failures and two capacity failures prevented a clean
campaign pass. The results below are historical engineering evidence for the
recorded binaries. Use the [BoronGen guide](boron-gen.md) for new runs.

## Identity and preservation

The campaign ran on `oxidedns-1`, with physical-NIC query load generated from
`oxidegun-1`, under campaign ID `twohost-20260728T1630Z`. The BoronDNS,
BoronGen, and BoronGun binaries identify source commit
`1476480c4eb5ba6f0c5a6816df82c37d3c8e456c`. Later rows used a repaired
external coordinator from the controlling workstation rather than the
coordinator at that server-binary commit. This report did not record a separate
coordinator commit ID, so the binary commit alone does not identify every
script used by later rows.

The complete remote evidence tree was copied without deletion to:

```text
target/evidence/boron-gen-large-memory-twohost-20260728T1630Z
```

It contains 1,126 regular files and 46,084,177 bytes. A checksum dry-run
reported no difference from the remote tree. With `LC_ALL=C`, the sorted
relative-path/content digest of both trees is:

```text
1f1c8fa6ad4be82a63eee7e7b1790ad4a2f8020cfb5232b0ea8513fff24a2f85
```

The campaign's four summary objects also match
`campaign-summary.sha256`. That manifest records absolute remote paths, so it
is not directly relocatable; verification of the local copy used the recorded
digests against the corresponding local basenames.

The campaign completed at `2026-07-30T08:56:04Z`. The external coordinator
completed four seconds later. Both hosts returned to their idle memory
baselines and retained no load processes.

## Result disposition

`ready_and_held` means publication, correctness, quiescence, physical-NIC
performance measurement, hold, and cleanup all completed. A row that reached
readiness but lost its external coordinator is useful publication evidence,
but it is not a successful campaign row and supplies no accepted QPS result.

| Row | Scenario | Peak BoronDNS memory | Campaign result | Engineering disposition |
| --- | --- | ---: | --- | --- |
| 01 | 10,000,000-member RRset | 3.94 GiB | `ready_and_held` | Valid publication and performance result |
| 02 | 100,000,000-member RRset | 40.40 GiB | `harness_failed` | Publication and quiescence valid; external performance request timed out during the pre-repair coordinator outage |
| 03 | 5,000,000 mixed names × 32 records | 91.43 GiB | `ready_and_held` | Valid publication and performance result |
| 04 | 128 catalog members × 100,000 names | 115.61 GiB | `harness_failed` | All 128 zones ready and quiescent; external performance request timed out during the pre-repair coordinator outage |
| 05 | 512 catalog members × 100,000 names | 450.39 GiB | `harness_failed` | Incomplete capacity result: 503 zones active and 9 loading when the service stopped; 2,678,899 `memory.high` events, no cgroup OOM |
| 06 | 10,000,000 names plus 100,000,000 NSEC3 records | 383.69 GiB | `harness_failed` | Publication and quiescence valid; external performance request timed out during the pre-repair coordinator outage |
| 07 | 1,000,000-name balanced registry | 12.04 GiB | `harness_failed` | Publication and quiescence valid; external performance request timed out during the pre-repair coordinator outage |
| 08 | 10,000,000-name balanced registry | 116.41 GiB | `ready_and_held` | Valid publication and performance result |
| 09 | 20,000,000-name balanced registry | 238.78 GiB | `ready_and_held` | Valid publication and performance result |
| 10 | 40,000,000-name balanced registry | 475.44 GiB | `ready_and_held` | Valid publication and performance result |
| 11 | 50,000,000-name balanced registry | 574.75 GiB | `ready_and_held` | Valid publication; performance result is noisy and requires confirmation |
| 12 | 60,000,000-name balanced registry | 680.00 GiB | `contained_oom_unexpected` | Real capacity failure under a requested `ready` outcome; containment passed |

Rows 02, 04, 06, and 07 support publication claims only. Row 05 does not
establish that the 512-member shape can publish. Row 12 failed the requested
readiness outcome even though its cgroup containment worked.

## Accepted performance observations

| Scenario | Median responses/s | Median p99 |
| --- | ---: | ---: |
| 10,000,000-member RRset | 133,631 | 740.8 µs |
| 5,000,000 mixed names × 32 records | 83,722 | 1,099.7 µs |
| Balanced registry, 10,000,000 names | 65,839 | 1,372.9 µs |
| Balanced registry, 20,000,000 names | 66,873 | 1,381.7 µs |
| Balanced registry, 40,000,000 names | 64,682 | 1,438.4 µs |
| Balanced registry, 50,000,000 names | 41,953 | 2,217.1 µs |

The 10M through 40M balanced-registry rows are effectively flat: the 40M
median is 1.76% below the 10M median and its p99 is 4.77% higher. The 50M
median is 36.28% below 10M, but its repetitions were 41,953, 60,171, and
40,657 responses/s. That spread is too large to treat the median as a stable
size cliff without a focused repeat using fixed offered-load steps and more
repetitions.

## Sixty-million-name capacity boundary

The row-12 manifest describes 546,000,008 retained member snapshot records.
BoronGen completed the 546,000,009-record member AXFR while retaining only a
6.4 MiB peak. BoronDNS continued constructing the publishable representation
but never became ready.

The server reached its exact 680 GiB `MemoryMax` after 30,467 seconds. Final
cgroup counters were:

```text
high 2406185
max 19
oom 1
oom_kill 1
oom_group_kill 0
```

Swap was disabled for the unit. There was no panic, assertion failure,
segmentation fault, or restart. The OOM remained inside the dedicated
BoronDNS cgroup, BoronGen survived until harness cleanup, and the host
recovered normally. This proves containment but also proves that this positive
scenario does not fit under the chosen 680 GiB limit.

## Follow-up recorded after the campaign

The subsequent harness revision added structured transfer, ZoneImage-build,
zone-store publication, and publication-temporary-release phases and joined
them to the nearest cgroup memory sample. A bounded local negative run reached
the exact 512 MiB server limit, returned `contained_oom_as_expected`, and left
the separately bounded generator alive.

The revised campaign matrix added a 55M positive probe, an independent
contained-OOM row, and exact scenario selection. Aggregate open-loop QPS steps
were added to the performance runner. The proposed focused remote repeat was:

```text
scenarios: 40M, 50M, 55M, contained-OOM
offered QPS: 30,000; 45,000; 60,000
repetitions per QPS step: 5
```

This report contains no results for that proposed repeat. It also does not
resolve the missing performance measurements in rows 02, 04, 06, and 07, or
the stopped service in row 05. New results need a separate campaign ID and
source record; they cannot change the disposition of these frozen attempts.
