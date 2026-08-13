# Large-zone IXFR scaling — August 2026

## Conclusion

BoronDNS no longer rebuilds a complete installed zone for every small IXFR.
Validated RRset deltas now update copy-on-write shards, shape counters, and
NSEC/NSEC3 order indexes. Large zones publish the result as an atomic overlay
over their compact query image; response plans whose dependencies are unchanged
remain reusable.

This changes large-zone catch-up from a zone-size problem into primarily a
delta-size problem. A BoronGen primary advanced 1,000 RRsets every 100 ms. The
secondary polled every two seconds, received about 20 generations (20,000 RRset
replacements) per IXFR, and completed 77 consecutive transfers in 0.262–1.014 s
(mean 0.353 s) against a 9,101,008-record DNSSEC registry-shaped zone. It
recorded no failed IXFR and no post-load AXFR fallback. The secondary therefore
caught up faster than the tested change cadence, including during two-host UDP
saturation load.

The remaining limitation is query throughput while a very large signed overlay
is active. Reusing clean compact response plans raised median remote QPS from
33,328 to 44,814, but the static compact image reached 70,639 QPS. DNSSEC
negative answers still need the current SOA serial together with current denial
proofs and therefore fall back to snapshot composition. A future hybrid
composer could reuse clean immutable proof chunks while taking only the dirty
SOA from the overlay; that optimization is not required for IXFR catch-up
correctness.

## Implemented path

1. RFC 1995 delete/add sequences are validated and reduced to exact affected
   RRsets rather than flattened into a complete record vector.
2. `ZoneSnapshot` stores large zones in copy-on-write RRset shards, with exact
   dirty-RRset tracking bounded independently of record count.
3. Owner/record/RRset counts and shape histograms are adjusted from the delta.
4. NSEC canonical-name and NSEC3 hash order indexes are structurally shared and
   updated only for affected denial records.
5. `compact`, `sharded`, and `auto` publication strategies preserve the compact
   hot path for ordinary zones and select overlays for large zones.
6. The published overlay holds one immutable generation and atomically replaces
   the previous generation; queries never observe partially applied deltas.
7. Exact dependency checks reuse old compact response plans when every
   referenced RRset is clean. Owner topology, DNAME, and denial-index changes
   conservatively disable reuse.
8. A dirty-owner threshold schedules bounded background compaction so overlay
   state does not grow without limit.
9. Differential tests compare compact and sharded answers, snapshots, and zone
   images across add, replace, delete, multi-generation, and DNSSEC changes.
10. BoronGen generates deterministic changed IXFR on the fly, including missed
    generations and bounded AXFR fallback, without materializing zone history.

## Focused in-process measurements

The original implementation established the failure mode: a one-record change
to 50,000,000 base records spent 475.721 s in IXFR processing and 504.468 s in
publication, or 980.190 s total, with a 90.455 GiB peak. The delta size had
little effect because both phases walked or rebuilt the whole zone.

Current measurements use replace-only deltas, which exercise deletion
validation and addition without changing owner count. `publication` is the
atomic overlay publication after the updated snapshot has been constructed.

| Base records | Changed RRsets | IXFR process | Publication | Combined | Peak HWM | Notes |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1,000,000 | 1,000 | 0.237 s median | 0.0024 s median | 0.239 s | 1.12 GiB | Five latest sharded runs with eight lookup workers |
| 10,000,000 | 1,000 | 0.162 s | 0.018 s | 0.180 s | 10.46 GiB | Eight lookup workers; one focused row |
| 50,000,000 | 1,000 | 0.211 s | 0.077 s | 0.288 s | 49.64 GiB | Isolated cgroup row |

The 50M updated path completed about 3,406 times faster than the old 980.190 s
measurement even though the new workload replaced 1,000 RRsets rather than
adding one record. Peak memory was 45.1% lower. Cold loading remains whole-zone
work: the focused row spent 186.117 s building its base snapshot and 390.052 s
compiling the initial compact query image. That cost occurs at initial transfer
or deliberate compaction, not on every small IXFR.

The 10M lookup workers measured 8.399 million lookups/s before IXFR and 8.168
million/s after publication, a 2.75% difference in one short sample. IXFR and
publication themselves sustained 8.432 and 8.326 million lookups/s. This
in-process probe tests contention and publication semantics, not network DNS
packet rate.

## Two-host continuous-churn measurements

`oxidedns-1` ran BoronDNS and BoronGen under cgroup v2/systemd-oomd containment.
`oxidegun-1` sent queries over the physical 25 Gbit/s interconnect. The large
profile contained 1,000,000 generated names, 1,000,000 ordered NSEC3 records,
structural RRSIGs, and 9,101,008 snapshot records (8,051,006 RRsets).

| Workload | Zone size | IXFR workload | Median QPS | Result |
| --- | ---: | --- | ---: | --- |
| Static compact baseline | 9.10M records | none | 70,639 | Baseline |
| Early overlay path | 9.10M records | continuous | 33,328 | Every DO response fell back to snapshot composition |
| Clean-plan reuse | 9.10M records | 1,000 RRsets/100 ms; ~20 generations/poll | 44,814 | 34.5% above early overlay; 36.6% below static |

The final large run produced QPS repetitions of 43,297, 44,880, and 44,814.
Peak BoronDNS memory was 14,597,816,320 bytes; BoronGen peaked at 6,352,896
bytes. The generator's bounded memory confirms that the primary did not hide a
materialized multi-million-record zone or IXFR journal. Saturation caused UDP
receive-buffer drops, which are recorded in the evidence; there were no client
decode errors, softnet drops, memory errors, or IXFR failures.

Clean immutable image plans served 640 of 769 classified DNSSEC load queries;
the 128 negative proofs and one SOA query used the current snapshot. This 83.2%
image-hit result explains both the improvement over the initial overlay and the
remaining gap to the static image.

## Small-zone control

Auto mode intentionally retains compact rebuilding for zones below the default
1,000,000-RRset threshold.

At roughly 9,100 records, rebuilding after 10 changed RRsets took 0.0268–0.0501
s (mean 0.0379 s). Five remote baseline repetitions averaged 65,479 QPS; five
continuous-churn repetitions averaged 65,119 QPS, a 0.55% difference and well
inside run-to-run variation. This is the “rebuild is fast enough” control: no
measurable small-zone QPS regression was observed.

A larger 91,108-record control with 2,000 replacements per poll spent about
0.35 s rebuilding every two seconds and measured 6.7% lower median QPS. That is
a useful policy boundary, not a neutral control; operators can lower the auto
threshold when their update cadence makes compact rebuild duty material.

## Correctness and fuzzing

Unit and differential tests cover deletion of absent data, TTL and class
conflicts, multi-generation serial chaining, owner addition/removal, dirty
response dependencies, CNAME/DNAME/delegation behavior, NSEC and NSEC3 changes,
and compact-versus-overlay response equivalence.

The `transfer_stream` fuzz target also turns arbitrary input into up to 64
valid IXFR generations across a 32-owner model. After every generation it
compares the incremental snapshot and compiled image with an independent fresh
rebuild. A 300-second remote diagnostic campaign completed 59,096 executions
with no crash artifact (coverage 3,285; feature count 16,335). Because the
campaign ran before the implementation commit, the evidence is correctly
labelled non-release diagnostic; a clean-source release campaign remains part
of the release gate.

A follow-up `zone_image_datagram` campaign exposed two stale assumptions in its
test oracle: it compared pre-DNSSEC plans with DO=1 production responses and
treated nonempty TCP Keepalive options as well formed. Production correctly
failed closed with SERVFAIL for an unprovable NSEC3 closest encloser and FORMERR
for malformed Keepalive. Both inputs are retained as regression seeds and the
oracle now applies DNSSEC augmentation and the transport-specific EDNS rule.
The corrected 180-second campaign completed 1,517,444 executions with no crash
artifact (coverage 3,331; feature count 6,688).

## Operational interpretation

The measured large workload does not show an inherent inability to catch up
with frequent small changes. The operative admission condition is:

```text
mean IXFR transfer + validation + publication time < mean interval represented by the transfer
```

Headroom must also cover primary latency, TSIG, competing zone transfers, CPU
saturation, and bursts large enough to exceed the retained generation window.
If the primary cannot supply the requested serial or the configured window is
exceeded, RFC-compatible AXFR fallback still costs a complete transfer and
publication. Operators should therefore alert on IXFR duration, generations
per response, repeated AXFR fallback, and a serial lag that grows over
successive polls.

## Environment and evidence

- Remote server: `oxidedns-1`, 48 logical CPUs, approximately 750 GiB RAM.
- Remote client: `oxidegun-1`, physical `198.18.0.1` ↔ `198.18.0.2` 25 Gbit/s
  path.
- Large churn containment: `MemoryHigh=48G`, `MemoryMax=64G`, swap disabled,
  cgroup v2 and active systemd-oomd.
- Focused 50M containment: `MemoryHigh=200G`, `MemoryMax=250G`, swap disabled.
- Large churn evidence:
  `target/evidence/ixfr-twohost-large-churn-r4/` on `oxidedns-1` and
  `target/evidence/ixfr-twohost-large-churn-r4-coordinator/` locally.
- Differential fuzz evidence:
  `/home/codex/borondns-private-fuzz-evidence/ixfr-differential-20260813-a/`
  on `oxidedns-1`.
- Reproduction entrypoints: `scripts/benchmark-ixfr-scaling.sh`,
  `scripts/run-ixfr-scaling-matrix.sh`, and
  `crates/borondns-core/examples/ixfr_scaling_bench.rs`.
