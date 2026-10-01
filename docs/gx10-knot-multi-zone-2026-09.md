# Multi-zone scaling: BoronDNS and Knot DNS

Results through October 1, 2026. These measurements use a development worktree
based on `4cdf7a64`, not the released v1.0.1 binary. The serving-layout features
remain experimental and disabled by default.

## October 1: fresh four-size comparison

The accepted staged-query/queue-group BoronDNS artifact and unchanged Knot DNS
3.6.0 artifact were measured on both GX10s with the same deterministic portfolio
at 1k, 10k, 100k and one million member zones. The direct ConnectX-7 link was
verified at **200 Gbit/s**, with 20 queues and the established ten fast
application cores / ten slower IRQ cores. These GX10 results do not use the
older 25G oxidedns/oxidegun pair.

Each server/size used one fresh process, recovering its existing complete
dataset offline, followed by hot, Zipf and uniform traffic in that order.
There was one 30-second measured window after ten seconds of warm-up for each
distribution. Offered rates were fixed before measurement using earlier
operating points; they differed between servers. This is a fresh comparison of
passing loads and failures, not a new search for either server's maximum.

QPS below means positive replies received per second, in millions. Loss and
cold timeouts are shown as BoronDNS / Knot. A passing window requires offered
QPS at least 99% of target, bulk loss below 0.01%, no unexpected classes or
sampled content/checksum errors, and no cold-probe errors.

| Member zones | Workload | BoronDNS M QPS | Knot M QPS | Difference at tested points | Loss % B / K | Cold timeouts B / K | Result |
| ---: | --- | ---: | ---: | ---: | --- | --- | --- |
| 1,000 | Hot | 22.002 | 21.254 | +3.5% | 0 / 0.000005 | 0 / 0 | Both pass |
| 1,000 | Zipf | 22.002 | 18.501 | +18.9% | 0.000078 / 0.000058 | 0 / 0 | Both pass |
| 1,000 | Uniform | 22.002 | 15.999 | +37.5% | 0.000281 / 0.002401 | 0 / 0 | Both pass |
| 10,000 | Hot | 22.002 | 19.249 | +14.3% | 0.000175 / 0.000011 | 0 / 0 | Both pass |
| 10,000 | Zipf | 22.002 | 13.004 | +69.2% | 0.000674 / 0 | 0 / 0 | Both pass |
| 10,000 | Uniform | 22.002 | 9.501 | +131.6% | 0.000300 / 0.000313 | 0 / 0 | Both pass |
| 100,000 | Hot | 24.009 | 18.993 | +26.4% | 0.000016 / 0 | 0 / 0 | Both pass |
| 100,000 | Zipf | 22.988 | 6.001 | — | 0.003482 / 0.000018 | 1 / 0 | BoronDNS failed |
| 100,000 | Uniform | 22.988 | 6.001 | +283.1% | 0.000267 / 0.000403 | 0 / 0 | Both pass |
| 1,000,000 | Hot | 19.743 | 17.007 | +16.1% | 0 / 0 | 0 / 0 | Both pass |
| 1,000,000 | Zipf | 15.004 | 5.500 | +172.8% | 0 / 0.000193 | 0 / 0 | Both pass |
| 1,000,000 | Uniform | 15.004 | 3.500 | +328.7% | 0 / 0 | 0 / 0 | Both pass |

The 100k Zipf failure is retained: low bulk loss did not compensate for its
single cold-probe timeout. It was not repeated. Thus 23M across distributions
remains an earlier pilot result, not a repeatable zero-timeout operating point
established by this cohort. All 24 windows had correct sampled content and no
unexpected DNS classifications. Of 61,785 independent cold probes, one timed
out. The audit recalculated QPS/loss from raw packet totals and verified binary
identity, warm-up coverage, CPU placement, memory events, stable publications,
host-local clocks, maintenance journals and restoration.

BoronDNS's higher passing uniform loads come with higher memory and recovery
costs. Memory here is **cgroup anonymous memory before traffic**, including
packet buffers, not total RSS or zone storage alone. Readiness is catalog/member
recovery; post-load I/O settling is additional. These startup observations are
single samples with already-existing disk caches, not fresh AXFR timings.

| Member zones | BoronDNS anon GiB | Knot anon GiB | BoronDNS ready s | Knot ready s |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 0.688 | 0.634 | 1.03 | 3.19 |
| 10,000 | 0.890 | 0.679 | 3.59 | 3.21 |
| 100,000 | 3.001 | 1.124 | 13.73 | 7.59 |
| 1,000,000 | 24.364 | 5.566 | 351.47 | 69.92 |

The frozen BoronDNS artifact is
`ed4fb9f94f85e895420bdff40a8e13bb488ce9b5f176777681d3291272f98a0b`;
Knot is
`dc2103fca92d3c63f959c245f6b4d9737ee932aa30a47dc2b2bf52371b95b89d`.
The [24 raw result rows](gx10-knot-comparison-2026-10.csv) retain offered rates,
targets, positive rates, losses, cold-probe counts, successful-probe p99,
memory/startup observations and evidence labels. Cold p99 is sampled at each
server's different offered load and is not a matched-rate bulk latency result.

Transport differences remain: BoronDNS computes IPv4 UDP checksums and uses
4,096 software RX/TX/completion entries; this Knot setup omits the optional
IPv4 UDP checksum and uses 8,192 entries. Both use native AF_XDP zero-copy and
the same hardware/IRQ split, with ten BoronDNS group owners versus twenty Knot
query threads on the ten fast cores. The tested source is experimental, based
on `4cdf7a64`; the results are not released v1.0.1 performance guarantees.

Two harness interruptions are preserved in the private evidence. After the
completed 1k Knot measurements, the extra restoration verifier compared the
current RSS key with a pre-reboot capture. The frozen restorer itself had
restored correctly. A red/green test now requires verification against the same
baseline as the restorer and still rejects real setting drift; explicit checks
confirmed restoration before continuing. Those six completed windows were not
replayed. The first 100k Knot source was an unfilled cache and was stopped
before traffic; the complete cache from the accepted earlier uniform cohort
was then used. Scheduled maintenance was allowed to finish before admission.

Raw evidence is retained under `relative-reuse-oct1-*` in operator bundle
`borondns-gx10-knot-scaling-20260927.TWLypG`, with the serial runner
`run_oct1_comparison.py`, recovered completed 1k Knot metadata, and
`audit_oct1_comparison.py`. Both hosts ended idle, with XDP detached, exact NIC
settings restored, MTU 9000 and compaction policy 20. This matrix does not cover
changed IXFR, active refresh, negative answers, DNSSEC or fallback-heavy traffic.

## Earlier measurements and architectural investigations

Journal-gate limitation found on October 1: the two hosts' wall clocks differ
by about 12 seconds. Earlier journal checks used server timestamps for both
hosts, so their requester-side “quiet” classifications are not definitive.
Packet counts, content checks and measured QPS are unchanged, but those checks
alone do not exclude requester maintenance near a window boundary. The new
changed-IXFR canary records each host's own guard-window timestamps and checks
for clock steps. Future controlled comparisons must use those host-local gates.

## What the current comparison shows

### Queue-group owner: 23M across distributions; 24M hot accepted

The off-by-default `experimental-xdp-group-loop` feature replaces independent
queue tasks with one owner per configured CPU group. Each owner services its
queues round-robin with bounded RX/DNS/TX turns, persistent reply bookkeeping,
and per-queue kick retries. It uses the existing DNS/policy handler and direct
response writer. It does not remove the incoming DNS payload copy or change
the answer layout. With no CPU groups configured, the existing path remains.

Remote checks passed: 1,580 workspace tests (three privileged tests ignored),
553 baseline AF_XDP tests, 488 default-server tests, Clippy and formatting.
The final group-enabled server suite passed 569 tests with three ignored.
New unit cases cover staged-frame reclamation, retained batch bookkeeping,
round-robin visitation and retry state. Physical-link measurements below are
the performance evidence; the unit cases alone are not.

A subsequent review caught an error-path retry-rate bug in the prototype:
delivery errors such as `EHOSTUNREACH` kept the queue alive without setting a
retry deadline. A busy sibling could therefore drive a failed syscall on every
turn. A red/green regression now covers five such errno values; retryable
failures preserve pending ownership and observe the existing 1 ms deadline.
This is correctness hardening, not a measured QPS improvement.

The same review found that an empty-ring observation could clear a newer
readiness notification without rechecking the ring. The retry timer bounded
the resulting wait, but did not make the edge handling correct. The group path
now rechecks an empty ring under the current readiness token before clearing
it. Nonempty batches still perform one ring operation; metrics count an empty
attempt and its recheck separately. Four remote UnixStream/helper tests cover
the arrival race, empty/re-arm behavior, single-call progress, and preservation
of real errno/partial-admission state. They do not exercise AF_XDP descriptors.

The first two-queue COPY/veth integration attempt on the physical server caused
a kernel panic and reboot on its `6.17.0-1014-nvidia` kernel. Persisted crash
logs show `xsk_destruct_skb` called from `packet_rcv`, reached through
`__xsk_generic_xmit`/`sendto`. This is consistent with a
[reported AF_XDP completion-bookkeeping defect](https://lists.debian.org/debian-kernel/2025/10/msg00280.html);
the exact vendor patch status and full root cause remain unverified.

The server recovered, and the fixture is now quarantined to explicitly opted-in
disposable VMs: a network namespace alone does not isolate kernel crashes. A
subsequent run passed in an Ubuntu Noble KVM guest with kernel
`6.8.0-142-generic`, two vCPUs, 4 GiB of RAM and an 8 GiB qcow2 overlay. The
official 2026-09-26 arm64 cloud image was authenticated with Ubuntu's cloud-image
keyring; its SHA-256 was
`1d6bffe64b848468ac97f821d369a4846d983de1800ccf6b5ec8853e85cefc55`.

The guest test exercised actual AF_XDP COPY-mode rings over two veth queues.
Four idle/publication phases returned all 80 expected replies with no checksum
or content errors. The two queue workers processed 32 and 48 packets,
respectively, proving both made progress, and shutdown completed normally. The
guest was then shut down cleanly and its overlay passed `qemu-img check`.

That VM result is real-ring correctness evidence, not a ConnectX-7 zero-copy
performance result. The candidate was subsequently measured on the two GX10s'
direct ConnectX-7 link in zero-copy mode. A server reboot had invalidated the
old RSS-port calibration, so candidate ports were first classified empirically
at both ends with `SO_INCOMING_NAPI_ID`. The selected 20 ports each reach a
different requester queue and server queue. A 1M-QPS hot/Zipf/uniform smoke
then passed with zero loss, zero content/checksum errors and all 20 queues
active.

The same-source release artifacts were:

- OFF: `390a7621a0ba228f905e1fce4a6244231bedbd81880ca981a9e15f9fcbb0ffda`
- ON: `69dea09b85d5653b8df4b578f23cdd92af0d92b7a33429d7c95c759beed5fb9d`

Both include query preparation and keep the previously rejected dense-layout,
static-redirect and conditional-wakeup experiments disabled. Fresh-process
OFF/ON/ON/OFF runs at 100k zones, uniform traffic and 21M target QPS all
passed. Three had zero bulk loss; the fourth lost 0.0000102%. All 10,294 cold
probes succeeded and there were no content or transport errors. The original
fourth cell was deferred before traffic while `fwupd-refresh` was due, then
run once under a new evidence label after the maintenance window cleared.

Capacity separation under the same calibration was decisive:

| Variant | 22M | 23M | 24M |
| --- | --- | --- | --- |
| Independent queue tasks | 0.25835% loss, 2 cold timeouts; fail | not run after failure | not run |
| Queue-group owner | 0.0000485% loss, no cold errors; pass | zero loss, no cold errors; pass | 0.02746% loss, 13 cold timeouts; fail |

The queue-group owner therefore establishes a clean 23M operating point, at
least 4.5% above the rate where the current independent-task control already
fails. It also preserves the shared 21M operating point without a detectable
throughput or successful-cold-probe latency penalty. This is a Boron OFF/ON
comparison, not a new matched Knot run.

An additional architectural review found that batches containing the same DNS
question (apart from the transaction ID) were deliberately sent through the
serial reference handler. This was an old benchmark heuristic, not a protocol
or policy requirement. It made concentrated hot traffic substantially more
expensive even though the staged path still prepares, applies policy to and
serializes every request independently. A red/green dispatch regression now
requires repeated requests to use staged serving whenever the normal batch
eligibility rules allow it. A functional regression also compares all eight
independent responses, including their transaction IDs, with the serial path.

The candidate artifact is
`ed4fb9f94f85e895420bdff40a8e13bb488ce9b5f176777681d3291272f98a0b`.
It has the same queue-group, query-preparation and response-writer features as
the accepted ON artifact; only the repeated-query dispatch rule differs. The
full remote gate passed 1,580 workspace tests with three ignored, 553 AF_XDP
tests with two ignored, 488 default-server tests with one ignored, Clippy and
formatting. A 1M hot/Zipf/uniform wire smoke then passed with zero loss or
errors.

At 100k zones, the old serial-dispatch artifact collapsed at a 23M hot target:
20.633M positive QPS, 10.248% loss and 100 cold timeouts. The staged-dispatch
candidate delivered 22.988M positive QPS at the same target (+11.4%), with
0.000102% loss and no cold timeout. It also passed fresh-process 23M uniform
and Zipf guards with loss below 0.00013% and all 5,149 cold probes successful.
Hot traffic subsequently passed at 24M with 24.009M positive QPS, 0.000217%
loss and 2,574 successful cold probes. These are fixed-rate pilots, not a
matched repetition cohort.

The bounded ascent stopped at 25M: bulk traffic still delivered 24.999M
positive QPS with 0.00251% loss, but one of 2,555 cold probes timed out. The
window had no XSK redirect drops or TX-full events; `rx_out_of_buffer` rose by
16,921 over roughly one billion received packets. The 26M step was therefore
not attempted. The accepted hot point is 24M, while the cross-distribution
point remains 23M because the earlier 24M uniform failure has no corresponding
fix and was not replayed.

Directional 18M instrumentation supports the dispatch diagnosis. Relative to
the old hot serial-path sample, the new hot staged-path sample used 1,162
versus 1,866 cycles per query (-37.7%) and 4,726 versus 6,407 instructions
(-26.2%). LLC misses also fell by 49.2%; dTLB misses were essentially flat
(+1.3%). Instrumentation changes timing, so these counters are diagnostic and
are not capacity evidence.

AF_XDP socket busy polling was also tested as an off-by-default experimental
branch, using `SO_PREFER_BUSY_POLL=1`, a 20 microsecond busy-poll budget and a
64-packet socket budget. It did not improve this topology. With the established
ten queue-group owners, the 24M uniform window lost 0.02322% and timed out 16 of
2,272 cold probes; the server recorded 6.20M XSK drops. Giving all 20 queues
their own owner and enabling the documented NAPI IRQ-deferral controls was much
worse: positive QPS fell to 20.014M, loss reached 16.64%, and 122 of 281 cold
probes timed out. The controls were restored to their original zero values and
both hosts were returned to the resting state. These variants are rejected and
must not be replayed without a new mechanism that changes queue ownership or
polling semantics.

A publication-bound worker-local cache of complete fused-answer descriptors was
then tested. It retained all parsing, policy and response-writing stages and
used O(1) epoch invalidation on every directory publication. The full remote
gate and 1M hot/Zipf/uniform wire smokes passed, but the decisive 24M uniform
window regressed badly: 23.817M positive QPS, 0.7994% loss and 66 of 1,336 cold
probes timed out. During the window, XSK drops rose by 321,685 and
`rx_out_of_buffer` by 5,971,851. The likely mechanism is duplicated random
answer storage across ten owners increasing LLC and memory pressure more than
the removed dependent hash-table access saved. The artifact
`abf5b05fa846e024057772bc08e196959101b1bb424c5188675179fe5288b9e8` is
negative evidence only; the source prototype was removed and must not be
repeated without a non-duplicating layout.

A shared compact-layout follow-up combined dense inline answers with shorter
fused lookup keys. Its first 24-byte key bound was an invalid benchmark fit:
the real 100k corpus uses a 30-byte wire owner plus the two-byte RR type key.
Every request therefore fell back to the ordinary resolver, yielding only
14.473M positive QPS at the 24M uniform target, 39.72% loss and 123 of 265
cold-probe timeouts. The boundary is now derived from a corpus-shaped test:
32 bytes admits every benchmark key exactly, while longer production names
continue to use the complete ordinary resolver.

The corrected artifact is
`0de20feb5a3bb478a875c0c2463a05e331f2deb37a8a1869281c02fab41823f2`.
Its common `(key, answer)` entry is exactly 128 bytes, down from 160 bytes for
the dense-answer-only layout. At an instrumented 18M uniform rate it reduced
cycles/query from 1,463 to 1,405 (-3.9%), LLC misses from 2.95 to 2.57 (-12.9%)
and dTLB misses from 11.50 to 11.25 (-2.2%), with essentially unchanged
instructions. The uninstrumented 24M window also improved over the queue-group
baseline, but still failed: loss fell from 0.02746% to 0.01902%, while 14 of
2,310 cold probes timed out. It is a directional locality improvement, not a
new accepted capacity point.

A second non-duplicating layout moved the incarnation guard and dense answers
out of the hash table into parallel contiguous vectors, reducing the hot
key-to-index entry to 48 bytes. The added dependent vector access outweighed
the smaller probe: at the same instrumented 18M uniform rate cycles rose from
1,405 to 1,481 (+5.4%), LLC misses from 2.57 to 3.77 (+46.5%) and dTLB misses
from 11.25 to 12.02 (+6.9%). That prototype was rejected before a 24M attempt
and removed from the source. Its immutable negative-evidence binary is
`dfaf0f9f71d76c1a4bbe923a71c07851b02a7c087d672664730f2fb281c76587`.

A narrower compact-A representation kept the successful single-table layout
and stored a common A RRset as one TTL plus up to eight IPv4 addresses. The
wire writer reconstructs the ordinary 16-byte records; ineligible answers use
the unchanged template or ordinary resolver. Together with the 32-byte fused
key this reduces the common `(key, answer)` entry from 128 to 96 bytes. The
feature remains experimental and disabled by default.

The artifact was
`542f374eebfdb6e6687e7b5b3064a1e41b9054503a248b6933362fe772e97f03`.
At the instrumented 18M uniform point it used 1,437 cycles, 4,818
instructions, 2.29 LLC misses and 11.64 dTLB misses per query. Compared with
the preceding 128-byte layout, that is lower LLC pressure but 2.3% more cycles
and 3.5% more dTLB misses. Its uninstrumented 24M result was the best failed
uniform result in this series: 24.007M positive QPS and 0.00867% loss, but four
of 2,499 cold probes timed out. It does not establish a 24M operating point.

At the accepted 23M point, an instrumented diagnostic reported about 1,430
cycles and 4,680 instructions per query. It is diagnostic evidence only: the
instrumentation made that window fail the bulk-loss gate. At 24M the normal
candidate had no XSK redirect drops and only one TX-full event, but accumulated
197,068 `rx_out_of_buffer` events. Almost the entire redirect deficit was on
RX queues 4 and 9, which share one slow interrupt core under the benchmark's
required split between interrupt and application cores.

Three bounded follow-ups were rejected:

- yielding after 32 active rounds instead of 8 produced 0.03150% loss and ten
  cold timeouts at 24M;
- moving queue 4/9 interrupts onto their fast application owners produced
  7.819% loss and 123 cold timeouts;
- increasing the server hardware RX ring from 2,048 to 4,096 produced 0.02861%
  loss, 18 cold timeouts and 202,875 `rx_out_of_buffer` events.

Four later diagnostics tested the IRQ-queue hypothesis rather than changing
DNS lookup again. Omitting requester/server queue 9 removed the cold timeouts,
but redistributed its traffic across the remaining queues and increased bulk
loss to 0.03032%. Confining RSS to queues 10–19 gave every application owner
one active and one inactive queue, but left five IRQ cores handling two active
queues each. At a 24M target the requester offered only 21.55M and the server
returned about 14.4M QPS, with roughly 33% loss. Increasing the useful-work
budget for a lone active sibling and then retiring idle siblings within each
work slice changed positive throughput by less than 0.6%; both scheduler
prototypes were removed.

Finally, queues 4 and 9 were tested with adaptive coalescing disabled and
forced to either 32 microseconds/64 frames or 128 microseconds/256 frames. The
two 24M windows lost 0.01977% and 0.01729%, with ten and seven cold timeouts,
respectively. The latter also added 123,575 `rx_out_of_buffer` events. The
harness restored and byte-compared the original per-queue adaptive settings
after each run. Neither coalescing direction improved on the compact-A result.

These failures were not replayed. They place the remaining 24M ceiling in the
mlx5 IRQ/NAPI ingress path on this hardware rather than in DNS lookup or the
group loop. The 32-round binary is retained only as rejected negative evidence;
the source returned to the tested eight-round policy. See the
[raw result rows](gx10-xdp-group-2026-10.csv). Broader mixed-zone and
changed-IXFR interaction guards remain open before promotion.

### Listener-specialized redirect: no capacity gain

The next off-by-default prototype, `experimental-static-redirect`, supplies
immutable listener settings when loading the eBPF object. The old configuration
map remains available for old objects and old loaders. The server and separately
built eBPF crate each have an explicit feature; neither default is changed.

On GX10, 3,060 wire-free kernel test-run checks passed against the control,
specialized candidate and candidate with the legacy loader. Cases cover both
address families, truncation, IPv4 options/fragments, IPv6 extension-header
deferral, address/port mismatches, wildcard listeners, port zero and empty versus
populated XSK maps. The specialized candidate also passes after invalidating its
legacy configuration map, proving it uses the frozen settings. These tests use
a disposable network namespace and veth, not the physical benchmark link.

The rebuilt default object is byte-identical to the frozen campaign object.
For the benchmark's IPv4 listener, the candidate has 165 displayed translated
instructions versus 199 for the control, and 888 versus 1,112 JIT bytes. This
is **not a measured CPU or QPS improvement**. Inspection also corrected an
earlier hypothesis: the kernel already inlines the control's array lookup;
there is no configuration-map helper call to eliminate in its loaded program.
The candidate removes that inline lookup and some unreachable paths, but still
performs configuration loads and comparisons. An initial whole-struct volatile
read caused unnecessary spills; field-at-a-time reads reduced that overhead.

Remote workspace tests, baseline fused-core/default-server tests, Clippy and
formatting passed. The privileged test is intentionally ignored in ordinary
workspace runs and was executed separately. A 1k-zone hot/Zipf/uniform smoke at
1M passed with zero bulk loss and successful sparse pre/post checks.

The normal-release, object-only OFF/ON/ON/OFF comparison at 100k uniform/24M
then failed the advancement gate:

| Object | Bulk loss, run 1 / run 2 | Cold timeouts | Accepted runs |
| --- | --- | --- | --- |
| Control | 0.000703% / 0.001841% | 0 / 1 | 1/2 |
| Listener-specialized | 0.008332% / 0.009768% | 4 / 2 | 0/2 |

Both variants used the same server executable and differed only in the frozen
redirect-object path. All four runs used fresh processes, achieved the offered
rate and passed content/steering, host-local quiet, resource and restoration
checks. There were 10,163 cold probes in total, with seven timeouts and no wrong
answers or non-timeout transport errors. Bulk loss alone passed, but the
unchanged acceptance rule also requires zero cold errors. No measured failure
was replayed. See the [four raw-count rows](gx10-static-redirect-2026-10.csv).

The candidate **does not establish a reliable 24M operating point** and remains
disabled. The smaller generated program was not an end-to-end improvement in
this comparison. This closed the redirect experiment and led to the queue-group
packet-processing loop described above, rather than more redirect variants or
small index changes.

### Conditional wakeups: fewer syscalls, still no reliable 24M point

The next off-by-default prototype, `experimental-xdp-conditional-wakeup`,
uses the kernel's needs-wakeup flags instead of unconditionally waking an
active driver. It reads bounded, read-only mappings of the producer-ring
headers; it does not access descriptors or rely on private dependency layouts.
An outstanding failed wake still takes the existing explicit recovery path.

Revision 1 applied this only to TX. Same-source normal-release OFF/ON/ON/OFF
runs at 100k zones used the declared 22M/24M/26M ladder. All four passed 22M,
but all stopped at 24M because of cold timeouts, so none attempted 26M. At
24M, ON issued about **83% fewer TX kicks**, yet both ON runs still failed.
The reduction in syscalls is not a demonstrated throughput gain.

Revision 2 also makes FILL wakeups conditional. It rechecks the receive-side
flag even when no new buffers were admitted, preserving progress when buffers
are already published but the driver has gone idle. The fixed 24M comparison
retained the same query-preparation, serving layout and hardware configuration:

| Variant | Bulk loss, run 1 / run 2 | Cold timeouts | Accepted runs |
| --- | --- | --- | --- |
| OFF | 0.01012% / 0.00396% | 3 / 3 | 0/2 |
| TX+FILL conditional | 0.00166% / 0.00921% | 0 / 5 | 1/2 |

The candidate therefore **does not establish a reliable 24M operating point**
and remains disabled. No capacity failure was replayed; the first r2 control
waited about 100 seconds for firmware maintenance before traffic. Both
revisions passed separate hot/Zipf/uniform 1M smoke tests and sparse pre/post
queries, but these do not replace higher-rate or small-zone acceptance guards.
The final source passed 1,569 workspace tests plus one existing ignored test,
baseline fused-core and default-server tests, Clippy, formatting and the
safe-Rust audit. Five new tests cover wake decisions and mapping validation.

The [conditional-wakeup rows](gx10-conditional-wakeup-2026-10.csv) retain both
revisions' results. Packet/loss figures describe the 30-second measurement;
`window_*` metrics also include warmup, and `snapshot_*` counters cover the
separately stated surrounding interval. They must not be treated as synchronized
packet-loss attribution.

A separate diagnostic profiled kernel cycles on the ten slow cores during r2
ON at 24M. It recorded about 28,000 samples, with no lost samples. **35.88%**
of sampled self cycles were attributed to the BoronDNS XDP redirect program,
**27.00%** to `mlx5e_xsk_skb_from_cqe_linear`, and **6.78%** to batched RX WQE
allocation. These are shares of sampled slow-core kernel work, not total
server CPU or a predicted speedup. The instrumented window itself failed
(0.05794% bulk loss, three cold timeouts) and is not capacity evidence.

The redirect object in the configured runtime path matches the frozen stage
object, SHA256 `2db0f3bd024522c6ed95e598cc452fa72daf95fbe93dbc0caf5bf7cd4712866a`.
Its disassembly confirms a per-packet configuration-map lookup and repeated
byte assembly for header fields. A shorter redirect parser was already tried
in the September single-zone campaign without repeatable QPS gains; that
history must not be presented as a new idea. The next architectural hypothesis
was immutable per-listener configuration specialization, tested against the
current object while preserving all redirect/PASS decisions. Its failed
capacity comparison is described above.

### Query preparation: lower CPU cost, no demonstrated capacity advantage yet

The off-by-default `experimental-query-preparation` removes two repeated steps:
fallback lookup preparation for batches where every query already has a fused
answer, and a second TSIG walk when completed metadata validation proves that
the exact packet is an ordinary unsigned query. It retains policy checks and
the pinned fallback selector; signed, malformed and unsupported queries keep
the existing path. These two changes were measured together, not separately.

Same-source OFF/ON/ON/OFF CPU profiles at 7M uniform QPS show:

| Zones | OFF cycles/query | ON cycles/query | Change |
| --- | ---: | ---: | ---: |
| 1,000 | 1,896.62 | 1,690.49 | −10.87% |
| 100,000 | 2,100.22 | 1,899.85 | −9.54% |

Instructions/query fell about 14.3% at both sizes. Anonymous memory was
essentially unchanged; LLC misses rose about 3%, so this is less work rather
than evidence of a better cache layout. All 20,620 cold probes passed. Seven
windows had zero bulk loss; the first small-zone control lost 0.000366%.
Counters ran at 100%, and host-local quiet and restoration gates passed.
Dense-answer, direct-bucket and refresh experiments were disabled in both builds.

Normal release binaries then ran at higher load, without profiling:

| 100k uniform offered rate | Control | Query preparation |
| --- | --- | --- |
| 20M QPS | 2/2 pass | 2/2 pass |
| 22M QPS | 2/2 pass | 2/2 pass |
| 24M QPS | 1/2 pass | 0/2 pass |
| 26M QPS | First control failed; second stopped at 24M | Not attempted after 24M failures |

Each process followed the declared ascending 22M/24M/26M ladder and stopped
at its first failure. At 24M, ON bulk loss was 0.01313%/0.01149%, with 3/8
cold timeouts; OFF loss was 0.00576%/0.18975%, with 0/30 timeouts. The first
control's 26M run lost 10.90% and had 87 cold timeouts. These remain failures
under the unchanged <0.01% bulk-loss and zero-cold-error acceptance rule.
The fourth 20M control was blocked by firmware maintenance **before traffic**;
its empty partial and restoration records were retained, and only that
unmeasured cell was resumed after maintenance. No measured window was replayed.

Thus **22M is a repeated accepted point for both versions**, not proof that
query preparation raised maximum throughput. It is also not a new matched
Knot ceiling comparison. The candidate separately passed three normal-release
guards at 1k uniform/17M and three at single-zone hot/26M; all 7,723 small-zone
cold probes passed. Those different corpora are not a retention denominator.

See the [query-preparation measurements](gx10-query-preparation-2026-10.csv)
for all CPU, fixed-rate, ladder and guard rows, including failures and binary
identities. Regression gates passed remotely: 1,564 workspace tests plus one
existing ignored test, baseline fused-core and default-server tests, Clippy
and formatting. Larger mixed portfolios, current changed-IXFR/QPS interaction
and broader fallback performance still need validation before promotion.

#### Why the investigation moved into queue ownership

Saved 24M telemetry separates two effects. The control had server RX-ring-full
drops; the optimized runs had none and queued every received packet for a reply.
This does not prove every offered query reached the server or every reply
reached the requester. A separate, explicitly instrumented 24M diagnostic
sampled NIC, XDP socket and CPU counters on both hosts. It also failed
acceptance (0.01045% bulk loss, five cold timeouts); it does not replace any
capacity result.

Across approximately 18.2 seconds, the server recorded 23,375
`rx_out_of_buffer` events and about 1.6 million transmitted global pause
frames. Across its own approximately 18.0-second sample, the requester recorded
about 4.8 seconds of received-pause duration. Samples took 10–86ms each. Neither
host's sampled XDP sockets showed queue-full/fill-empty increases. These
driver counters indicate receive-buffer pressure and link backpressure, not
an exact attribution or count of lost DNS packets. See the Linux kernel's
[mlx5 counter definitions](https://www.kernel.org/doc/html/v6.4/networking/device_drivers/ethernet/mellanox/mlx5/counters.html).

This motivated the conditional-wakeup experiment described above. The default
adapter explicitly kicks TX after every admitted batch;
the 24M surrounding windows recorded about 15 million kicks and 60 million
completion dequeues over roughly 40 seconds of warmup plus traffic. Its ring
API does not expose the kernel needs-wakeup flag. The prototype adds a bounded
header view, but its syscall reduction did not clear the capacity gate. The
[AF_XDP documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-use-need-wakeup-bind-flag)
describes the conditional wakeup protocol. Any change must retain low-rate
progress, transient-error recovery, completion-pressure handling and shutdown
semantics. Increasing buffers or suppressing pause alone would not establish
an architectural improvement.

### Earlier layout experiments

Two recent query-layout experiments **did not meet their advancement threshold**.
The newer `experimental-direct-buckets` replaces each exact-answer map with a
directly addressed four-probe front table and an exact overflow map. First
candidate digests are read across the batch before full-key resolution. It
preserves all eligible entries, including hash collisions and deletion holes.

At 100k zones and 7M offered uniform QPS, same-source OFF/ON/ON/OFF mean CPU cost
fell from 2,113.44 to 2,069.30 cycles/query (**2.09%**), below the declared 5%
screen. LLC misses fell 10.76% and dTLB misses 11.85%, but instructions rose
0.38% and anonymous memory rose **3.22%**. These measured cache improvements
did not produce a proportionate CPU reduction. The main lookup symbol's lower
self share also excludes a new separate resolution function; it must not be
presented as the total lookup speedup.

All 10,308 cold probes passed. Three windows had zero bulk loss; the second ON
window lost 3 of 210,010,624 packets (0.00000143%). Counters ran at 100%, samples
reported no losses, and host-local quiet checks and all twelve restoration
steps passed. Both builds kept dense-answer and refresh experiments disabled.
The [four direct-bucket rows](gx10-direct-buckets-2026-10.csv) retain raw counts,
counter results, memory and binary identities. This candidate stays off and is
not advancing under this screen. Small-zone, publication-cost, million-zone
and near-capacity performance remain unproven; the fixed-rate CPU screen is not
a direct measurement of maximum QPS.

The preceding
`experimental-dense-answers` retains up to 64 body bytes inline and moves
65–128-byte bodies to shared storage, reducing the key/value size bound from
216 to 160 bytes. In a same-source OFF/ON/ON/OFF comparison at 100k zones and
7M offered uniform QPS, mean cycles/query fell from 2,111.10 to 2,078.94
(**1.52%**), below the predeclared 5% screen. Instructions rose 0.13%; LLC misses
fell 2.58% and dTLB misses 0.91%. Mean anonymous memory fell only 0.88%, not
26%: the smaller buckets are one part of the process. Exact lookup remained
about 23% of self-cycle samples in the candidate.

All four instrumented windows had zero bulk loss and all 10,310 cold probes
passed. Counters ran at 100%, samples reported no losses, and all host-local
quiet gates and twelve restoration steps passed. The last OFF process waited
about 80 seconds for scheduled firmware maintenance **before traffic**. No
measured window was repeated. Offline readiness was 26.4/14.0 seconds OFF and
13.9/13.9 seconds ON; that first-load difference does not establish a startup
improvement. See the [four dense-answer rows](gx10-dense-answers-2026-10.csv).

Both builds retained fused r7, direct writing and directory sharding, with
freshness batching and refresh pull disabled in both. The corpus uses four-A
(64-byte) templates, so these measurements exercise inline storage, not overflow
answers. The feature remains off and is not advancing to capacity testing;
small-zone, longer-answer and publication-cost acceptance is unproven. This is
not a higher QPS ceiling or a new Knot comparison.

The preceding slice removes the periodic refresh admission ceiling without raising
queue or transfer-task bounds. With durable batching enabled in both builds,
the off-by-default `experimental-refresh-pull` comparison completed four fresh
100k-zone processes in OFF/ON/ON/OFF order. **All four sustained 15M offered QPS
with zero bulk loss and all 10,297 cold probes passing.** This establishes
delivery at that operating point, not a higher query-throughput ceiling.

The difference was refresh cadence. Successive stored observation pairs with
the newer observation inside a measured window averaged **97.66–97.67 seconds
OFF versus 59.11–59.60 seconds ON**. ON p99 was 66 seconds and maximum 67 seconds,
consistent with the configured 60-second refresh and ±10% jitter; OFF p99 and
maximum were 104 seconds. Each stopped cache contained valid proofs for all
100,000 members and their catalog. The final proof timestamp spread was
103 seconds OFF and 65–66 seconds ON. There were 43,622–67,494 retained interval
samples per ON run: compaction can remove earlier pairs, so this is not a
complete per-zone interval history or a hard refresh-deadline guarantee.

Mean write traffic rose from 0.163 MB/s OFF to 0.490 MB/s ON while both retained
22 threads. Faster scheduling does more background work; it is not free CPU/I/O.
Fresh loading took 192/211 seconds OFF and 184/223 seconds ON, which does not
establish a loading-speed improvement. All host-local quiet gates, unchanged
serial/transfer checks, content checks and twelve restoration steps passed.
An earlier attempt stopped for maintenance before traffic; the final OFF cell
also needed an inode preflight resolved before loading. Only that unmeasured
cell was resumed, after archiving the earlier unmeasured cache. Completed
measurements were not repeated. See the
[four dispatcher-pull rows](gx10-refresh-pull-2026-10.csv).

Both features remain experimental. Current-candidate small-zone guards, changed
IXFR workloads, higher-rate tests and mixed million-zone comparisons remain
open; this refresh-cadence result is not a new Knot performance comparison.
The measured r1 binaries precede a subsequent dispatcher fix for queued
follow-ups to an already-running zone. That fix prevents those blocked requests
from stranding unrelated free slots; its regression coverage is separate from
these performance measurements. Do not attribute the r1 numbers to an unmeasured
later binary.

The new off-by-default freshness group-commit prototype completed a same-source
OFF/ON/ON/OFF comparison at **100k zones, SOA refresh 60 seconds and 15M offered
QPS**. Both ON processes delivered **15.0036M positive QPS with zero loss**;
OFF lost 0.01347% and 0.00472%, so only one OFF process passed the 0.01% bulk
gate. All **10,297 cold probes passed**. This is a fixed-rate comparison, not a
new maximum QPS result, and does not measure changed IXFR or Knot.

Across the approximately 44-second surrounding snapshot windows, group commit
reduced mean write-byte rate from **5.84 MB/s to 0.171 MB/s (97.1%)**, and mean
write-operation rate from **1,453/s to 38.7/s (97.3%)**. These are cgroup block-I/O
counters, not counts of application `fsync` calls. Server thread counts were
197/223 OFF and 22/22 ON; query-worker scheduler wait fell from roughly
1.12–1.25 seconds per worker to 0.33–0.38 seconds. Host-local clock/maintenance
gates, unchanged serial/transfer checks, content/checksum checks and all twelve
restoration steps passed. See the [four raw rows](gx10-freshness-batching-2026-10.csv).

Post-run cache inspection found valid freshness proofs for all 100,000 members
plus the catalog in every cell, with 101 sampled exact cache bindings checked
per cell. The saved proofs contained 45,056–46,080 observations timestamped
inside each approximately 44-second window. Their oldest timestamps were
about 100 seconds before the window end in **both** variants. Code inspection
explains a separate scheduling limit: the one-second scheduler admits at most
the 1,024-slot refresh channel's available capacity per tick. Thus **60 seconds
is the configured SOA refresh, not an achieved full-population refresh period**.
This comparison did not remove that shared admission ceiling; meeting the
configured cadence at this scale requires another change and fresh measurement.

The tradeoff remains open: fresh loading took **233/291 seconds OFF versus
279/417 seconds ON**. These four observations do not establish why loading
varied. The prototype also needs retired-identity reclamation, changed-update
validation, small-zone guards and higher-rate measurement before default
enablement. It reduces background persistence work without omitting durability;
it does not yet demonstrate a higher quiet-query ceiling. The implementation
and limits are described under
[experimental freshness group commit](memory-io-data-plane-design.md#experimental-freshness-group-commit).

The first controlled **100k-zone active-refresh control failed at 15M offered
QPS**, before changed IXFR was enabled: 0.05944% bulk loss and four cold-probe
timeouts. It used the current architecture, the portfolio's extra churn record,
and 60-second SOA polling. There were no transfers or serial changes during the
window. The sequence stopped; no churn-on comparison is accepted. This limits
the quiet/offline operating points below: they do not establish sustained QPS
under ordinary refresh activity.

The current combined architecture also passes three fresh-process **million-zone
uniform runs at 15M offered QPS**, averaging **15.0035M positive QPS**. Three
interleaved Knot runs pass their declared 3.5M target, averaging **3.5002M**.
All 15,472 independent cold probes pass. Neither target is a measured ceiling;
their ratio is not a maximum-throughput speedup. See the
[million-zone comparison](#one-million-zones), including memory and startup costs.

The combined fused-index, direct-writer and smaller-directory-shard candidate
now passes three fresh-process **100k-zone uniform runs at 19M offered QPS**:
18.993M mean positive QPS, maximum bulk loss 0.002830%, and all 7,720 independent
cold probes successful. At the same offered rate, the same-source
authority-batching baseline delivered about 15.18M QPS with roughly 20% loss;
all three baseline runs failed. That overloaded delivery rate is not an
accepted baseline capacity. All six processes restored their benchmark settings,
and recorded maintenance, firmware-notifier and Ubuntu Pro gates passed.

The same candidate also passed three isolated 1k-zone/17M guards (7,722 cold
probes, no errors). These are operating points, not measured ceilings: do not
divide 19M by the 17M guard to infer scaling retention. A separate DO=1 fallback
profile on unsigned zones passed the predeclared 2% CPU non-regression screen
at both sizes (+0.10% cycles at 100k, +0.73% at 1k; 20,656 cold probes, no errors).
This is not signed-zone denial coverage. The isolated million-zone operating
points now pass, but current-candidate mixed million-zone and update-heavy
network validation remain open.

The six raw capacity records are retained in `directory-uniform-19m.json` under
the private campaign evidence directory, with individual packet totals,
binary hashes, process identities and failed baseline outcomes. Candidate:
`1a9703668e8f2e99e475c005855500dfd78fa35ac0a91d781c101c503f558a63`;
baseline: `3706ddf0445604eaffa641e9ff837ad7fac9a3afdb64f6a9b74c0292f1c488a2`.

The directory slice reduces copy-on-write granularity in the main zone directory.
At 100k zones, it cut fused publication means by **71.5% without a pinned reader**
and **65.1% with one**, passing the existing publication-cost screen. A matched
query profile was essentially unchanged (−0.3% cycles/query), with zero bulk
loss and 10,311 successful cold probes. This addresses the measured publication
penalty, not the earlier high-rate timeouts.
Its normal build also passed the explicitly revised small/mixed guard protocol
below, with 46,342 successful cold probes; a midnight-maintenance failure is
retained separately rather than relabelled as a pass.
See [smaller publication shards](#smaller-publication-shards).

The preceding architectural slice writes eligible responses directly into AF_XDP
frames. Its same-source 100k-zone profile used **5.77% fewer cycles/query** than
the fused r7 baseline, with all four windows and 10,312 cold probes passing.
This is a CPU-cost result, not a higher QPS operating point or a new Knot
comparison. See [transport-owned response writing](#transport-owned-response-writing).

An earlier higher-rate experiment showed a substantial separation, but was not
fully accepted: at an offered 18M QPS over 100k zones, fused r7 averaged
**18.002M positive QPS**, versus **15.001M** for authority batching. Fusion
passed the strict gate on two of three fresh processes; the third had one
independent cold-probe timeout despite very low bulk loss. All three baseline
processes failed, losing 16.66–16.70%. The failed candidate repetition remains
failed; this is not a validated 18M operating point or a new Knot comparison.
See [the detailed result](#fused-r7-normal-release-validation).

The earlier fixed-rate comparison passed **15.004M positive QPS at 100k zones**
on all three fresh processes for both authority batching and the newer inline
fused candidate. This does **not** establish a throughput advantage for fusion:
both builds reached the offered rate. All 15,444 cold probes passed. The fused
candidate also passed three 1k-zone 17M guards, averaging 17.007M positive QPS;
its operating-point retention is 88.22%, not a ratio of measured ceilings.
Its separate matched profile showed 8.52% lower cycles/query, discussed below.
Newer revisions have since reached a 24.26% matched CPU-cost reduction and
repeated small/mixed guards. The newer directory change passes the publication
microbenchmark screen, but update-heavy network validation remains outstanding;
do not attach that percentage to the earlier 15M throughput row.

The previous experimental authority-batching comparison passed three fresh-process
uniform runs at **13.996M positive QPS on 100k zones**, while preserving
**17.007M on 1k zones**: **82.30% retention**. This is a higher validated operating
point, not an exact maximum. The same-source baseline passed two of three 14M
offered runs; its third lost 0.01559% and one cold probe. All three candidate
runs had zero bulk loss and all 7,723 cold probes passed. See the
[raw candidate and baseline windows](gx10-authority-batching-2026-09.csv), which
also retain the separate failed hot guard described below.

The earlier matched BoronDNS/Knot comparison established these operating points:

| Server | 1k zones | 100k zones | Retained QPS |
| --- | ---: | ---: | ---: |
| BoronDNS, packed serving | 17.007M | 13.004M | 76.46% |
| Knot DNS 3.6.0 | 16.000M | 6.001M | 37.50% |

Each cell passed on three fresh processes. All **30,907 independent cold probes
passed**. The [12 measured windows](gx10-uniform-capacity-2026-09.csv) include
packet totals, duration, loss, binary hashes and evidence labels.

These are repeated **1M-grid operating points**, not exact ceilings. BoronDNS's
18M and Knot's 17M small-zone pilots failed repetition, so both used the
predeclared one-step fallback. BoronDNS 14M and Knot 7M failed the large-zone
searches. Failed points remain in the evidence; they are not averaged into the
accepted rows.

The result is specific to this uniform workload and size range. It does not
establish an all-workload, all-hardware or million-zone win. The 13M result uses
isolated uniform traffic; the separate mixed-workload result below is 12M.

## Other validated operating points

The same packed binary passed three fresh-process repetitions of these guards:

| Workload | Mean positive QPS | Maximum bulk loss |
| --- | ---: | ---: |
| Single-zone anchor | 26.007M | 0.002936% |
| 1k hot / Zipf / uniform | 20.000M / 16.000M / 13.504M | 0% |
| 100k hot / Zipf / uniform, in that order | 18.993M / 10.000M / 11.998M | 0.001366% |

All **46,343 cold probes passed** across the multi-zone windows. The single-name
anchor has no separate cold-name probe stream. It uses a different zone and
answer size, so 26M is not a retention denominator.

The mixed sequence matters: the earlier staged-only build passed isolated 12M
uniform runs but then lost 1.69% after hot and Zipf traffic. A same-process
diagnostic found 5.58% more uniform cycles/query after that transition, without
a comparable increase in instructions. The packed build did not reproduce the
12M failure in three mixed sequences. This establishes those operating points,
not the root cause or universal removal of workload-history effects.

### One million zones

The current fused r7 + direct-writer + smaller-directory-shard build and Knot
3.6.0 completed a separate isolated-uniform comparison, in B/K/K/B/B/K order:

| Server | Mean positive QPS | Maximum bulk loss | Successful cold probes |
| --- | ---: | ---: | ---: |
| Current experimental BoronDNS | 15.0035M | 0.002296% | 7,723 |
| Knot DNS 3.6.0 | 3.5002M | 0% | 7,749 |

Each row has three fresh processes. All eighteen restoration steps and all
recorded background-maintenance gates passed. The third Boron process waited
for a scheduled firmware refresh before starting traffic; no measured run was
retried. [Six raw operating-point records](gx10-million-uniform-2026-09.csv)
include packet totals, durations, hashes, memory and evidence labels.

These used offline recovery of the same existing benchmark datasets, not fresh
AXFR loads. Boron recovery took 315–340 seconds and used about 24.4 GiB of
cgroup anonymous memory before traffic; Knot took 61–63 seconds and used about
5.6 GiB. This remains a substantial memory/startup tradeoff, not an across-the-board
win. Boron computes IPv4 UDP checksums; Knot omits them in this setup, as described
in the configuration comparison below.

Both rates were fixed in advance. They establish accepted operating points,
not either server's ceiling or a 4.3× maximum-capacity advantage. The older
Knot mixed cohort's third-process Zipf failure remains failed. This isolated
cohort does not establish performance under workload transitions or updates.

A preceding single current-candidate profile at 7M offered passed with zero
bulk loss and 2,578 successful cold probes. It measured about 2,227 cycles/query;
fused exact lookup accounted for 27.4% of sampled cycles. This identifies a
remaining optimization target, not a controlled speedup or capacity result.

The older packed candidate passed three fresh million-zone AXFR loads:

| Workload | Mean positive QPS | Maximum bulk loss |
| --- | ---: | ---: |
| Hot | 19.743M | 0.0001621% |
| Zipf | 8.000M | 0% |
| Uniform | 7.000M | 0% |

All **23,190 cold probes passed**. Loading took 79.34, 84.99 and 79.52 minutes.
The raw audit verified distinct server processes, packet classifications,
CPU placement, bounded global scrapes, pinned artifact, memory/compaction
checks and host restoration. These are fixed operating points, not ceilings.

The selected-query r2 binary—not the packed candidate—passed three fresh
million-zone AXFR loads at **19.743M hot, 8.000M Zipf and 6.001M uniform QPS**.
All 23,197 cold probes passed; maximum bulk loss was 0.0000433%.

Its 1k denominators were fixed guards, not measured ceilings. Do not combine
that million-zone row with the newer packed binary's 1k results to calculate
retention. The new 7M uniform point versus the earlier 6M point validates a
higher offered load for the combined staged-and-packed build; it does not
isolate packing's effect. At that point a passing comparable Knot million-zone
cohort was missing; the newer isolated comparison above fills only the uniform
operating-point portion of that gap.

## Why the architecture changed

### Changed-IXFR fixture validation

BoronGen's portfolio profile now optionally adds serial-coded churn A records
without changing its existing host-answer corpus. A remote 1k-zone canary used
one changed RRset per zone per second, five-second SOA refreshes, and the current
normal experimental BoronDNS binary. During the surrounding approximately
44-second transfer observation interval, 7,988 IXFR sessions completed, with no
AXFR starts or transfer failures. Flat and nested sample zones served advancing
SOA serials and matching changed A data.

The 30-second query window delivered 999,999 QPS at 1M offered, with zero bulk
loss and all 2,583 cold probes successful. Checksums/content, restoration and
host-local maintenance gates passed. This proves the fixture and live-update
path at small scale, not large-zone update capacity or absence of update-related
QPS loss. A churn-on/churn-off large-portfolio comparison remains outstanding.
Private evidence: `relative-cap0-churn-c2-result.json` and
`portfolio-churn-canary-protocol.md`; earlier setup/clock-gate failures are retained.

The subsequent 100k-zone OFF/ON/ON/OFF experiment stopped on its first OFF
window. “OFF” disables serial advancement, not SOA polling or durability. Both
modes were to use the same extra record, 60-second refresh interval and 15M
offered rate. After loading and three refresh periods, the control delivered
14.9947M positive QPS but lost 267,535 of 450,111,808 packets, exceeding the
0.01% limit. Four of 2,499 cold probes timed out. All 34 sampled zones remained
at serial 1; transfer counters did not advance. Host-local maintenance gates
and restoration passed. The remaining three instances were not launched.

The surrounding 44.31-second server observation recorded 286,281,728 bytes of
writes and 72,430 write operations. Query workers each accumulated 1.22–1.32
seconds of scheduler wait; receive-ring drops appeared across all 20 queues.
There was no cgroup memory-pressure or CPU-throttling event. Code inspection
shows that an unchanged SOA confirmation still writes and syncs a per-zone
freshness file, renames it, and syncs the cache directory. Durable-refresh I/O
and scheduling are therefore a concrete architectural investigation target,
not a proven exclusive cause. This run does not isolate their cost from the
primary process or the changed corpus layout, and no rate reduction was tried.
Private evidence: `relative-cap0-churn-large-r2-off-0-result.json` and
`portfolio-churn-large-r1-protocol.md`.

### Lookup and publication work

Profiles showed increasing memory-access cost as queries spread across more
zones. The changes shorten lookup paths and overlap independent reads:

| Change | Purpose |
| --- | --- |
| Compact direct-answer descriptors | Avoid general graph/plan construction for eligible positive answers. |
| Serving directory and selected-query handoff | Keep short keys and serving metadata together; avoid rechecking an already established query/image relationship. |
| Bounded staged serving | Prepare up to eight independent requests under one initial directory publication before answering them. |
| Packed serving block | Place a zone's direct descriptors and eligible answer bodies in one allocation. |
| Soft AF_XDP time slice | Let the paired queue task run between receive batches, including when traffic stays continuously ready. |
| Idle refresh-scheduler hints | Skip unchanged full-population status scans when nothing is due. |

There is no response cache. Authentication, cookies, rate limiting and response
sizing still run per packet. Unsupported direct answers retain the ordinary
resolver. Initial batch authority selection shares one publication; cross-zone
fallback keeps the existing resolver semantics rather than becoming a
transactional whole-batch snapshot.

At 100k zones and 7M offered uniform QPS, matched packed-off/on **A/B/B/A**
profiles measured:

| Counter per query | Feature off | Feature on | Change |
| --- | ---: | ---: | ---: |
| cycles | 3,536.65 | 3,240.95 | −8.36% |
| instructions | 6,822.68 | 6,839.30 | +0.24% |
| LLC load misses | 8.72 | 7.14 | −18.15% |
| dTLB load misses | 11.38 | 10.87 | −4.45% |

All four instrumented windows passed, with 10,312 cold probes and no errors.
These counters isolate the packing change; they are not capacity measurements.

Packing duplicates eligible wire bodies because the general wire storage
remains available for fallbacks. Pre-window anonymous memory averaged about
25 MB higher at 100k zones. That includes allocator/process variation and is
not exact per-zone storage accounting. Publication cost and broader memory
tradeoffs still need evaluation.

A flat authority-table experiment saved only 2.12% cycles, below its predeclared
5% target. It was archived rather than retained or advanced to capacity sweeps.
Earlier fixed-batch-yield variants and the first staged-serving revision also
failed small-zone guards and were rejected.

Two later experiments—directory-owned direct handles and batched authority
probes—initially appeared not to improve cycles/query. Those conclusions are
invalid: their shortened build feature lists enabled staged lookup in the core
crate but omitted the server's staged packet path, so they did not exercise the
intended changes. Raw results are retained as misconfigured diagnostics, not
evidence to accept or reject either architecture. The server's packed feature
now requires its staged feature, with compile-time checks guarding the dependency.
The accepted campaigns above explicitly enabled server staging; they are not
affected by this experiment-build error. The corrected comparisons below
provide the evidence for evaluating these two candidates.

With that wiring corrected, the batched-authority candidate passed its profile
gate. At 100k zones and 7M offered uniform QPS, matched A/B/B/A cycles/query fell
from 3,225.29 to 3,005.64 (−6.81%). Instructions rose 1.75%, LLC misses 4.37%,
and dTLB misses 1.41%. All four windows passed, with 10,312 error-free cold
probes; named profiles confirmed server staging executed in both variants.
These symbol-bearing, instrumented runs isolate CPU cost, not capacity. The
normal release then passed its first 26M anchor and 1k-zone
20M/16M/13.5M pilot, but the 100k-zone 19M-hot guard had one cold-probe timeout
and stopped. Bulk loss was 0.00287%; NIC receive out-of-buffer counters rose
16,027. No DNS-content errors or memory-limit events were observed. The cause
is unresolved. A fixed OFF/ON/ON/OFF diagnostic at the same hot target passed
all four windows and 10,296 cold probes, without receive-buffer exhaustion; it
did not reproduce or explain the failure. It does not replace that failed guard.

The candidate separately passed three isolated uniform guards at both 1k/17M
and 100k/13M, with 15,446 error-free cold probes, before the fixed 14M comparison
reported above. Its higher uniform point is established, but the mixed-workload
campaign, broader workload coverage and release readiness are not cleared.

At one million zones, a further matched A/B/B/A profile at 6M offered uniform
QPS reduced cycles/query from 3,772.32 to 3,444.19 (−8.70%). Instructions rose
1.70%, LLC misses 3.71%, and dTLB misses 0.72%. All four windows and 10,318 cold
probes passed. Each fresh process recovered the same persisted zone set in
about fifteen minutes; this was not a fresh AXFR test. This extends the measured
CPU-cost benefit to a larger working set, but is not yet a higher million-zone
throughput claim.

The normal authority-batching release also passed three fresh-process,
one-million-zone uniform guards at **7.000M positive QPS**, with zero bulk loss
and all **7,734 cold probes** passing. Recovery from the same offline cache took
896, 838 and 838 seconds. These unprofiled guards preserve the previous 7M
operating point; they do not establish a higher ceiling or repeat fresh AXFR.

### Further architectural experiments

Authority batching overlaps independent lookups, but does not remove their
memory accesses: the million-zone profile used fewer cycles despite slightly
more instructions and cache misses. The next hypothesis is to shorten the
dependent path from authority-directory entry, through the zone image header,
to the compact answer table and wire body.

The directory-owned compact serving handle has now been re-evaluated with the
corrected feature stack, on top of authority batching. At 100k zones and 7M
offered uniform QPS, OFF/ON/ON/OFF cycles/query changed from 3,038.20 to 3,057.54
(+0.64%); LLC misses fell 6.27% and dTLB misses fell 2.12%. All four windows and
10,310 cold probes passed. It failed the predeclared 5% CPU improvement gate
and was removed, with source and raw evidence archived. Fewer misses alone did
not make the larger directory-owned handle faster. This is a valid rejection
of that implementation on the tested batched baseline, unlike the first,
misconfigured experiment.

A shard-local serving-page prototype was also tested. It kept directory entries
within 64 bytes and copied at most one 64 KiB payload page per replacement,
while preserving old readers and excluding dirty IXFR overlays. It duplicated
eligible image data into pages. The second ON window lost 0.03236% of packets,
so the comparison stopped after OFF/ON/ON; there is no completed A/B/B/A result.
The OFF window used 3,011.66 cycles/query; ON used 3,359.30 and 3,350.25, with
about 156–162 MB more anonymous memory and more dTLB misses. All 7,734 cold
probes passed. This prototype was archived and removed, not advanced to capacity
testing. Sampled machine code confirmed its inlined page path really executed.

The results argue against merely adding another serving-data layer. Further
work needs to eliminate stages of the authority-to-answer lookup, while keeping
authority, visibility, expiry and overlay validity in one immutable publication.
A direct answer must never bypass a more-specific child zone, and incremental
updates must not copy an entire serving dataset. These are design constraints,
not a claim that a replacement architecture has already been validated.

A fused exact-answer index subsequently removed both the authority suffix
search and the per-zone lookup for eligible leaf zones. Publication tests
covered child-zone shadowing, expiry, frozen batches and dirty IXFR updates.
The scalar prototype used 7.41% fewer instructions but 23.46% more cycles/query.
A second revision restored phased batch lookups: it used 6.74% fewer
instructions, but still 8.01% more cycles and 21.82% more LLC misses than its
matched baseline, with about 88 MB more anonymous memory. Both full A/B/B/A
comparisons passed their packet/content gates, including 10,311 and 10,312
cold probes respectively. Neither passed the CPU-improvement gate; both were
archived, and the feature was removed. No higher capacity is claimed from them.

Inspection of the second revision's saved machine code found a remaining
dependency: compact response construction still loaded the old zone image's
RDATA slice before calling a shared writer, although the template-answer arm
did not use that slice. Samples clustered around this load and call; response
construction accounted for 18.41% of self-cycle samples versus 4.60% in the
matched baseline. This identifies an avoidable image access, not a measured
recoverable percentage or proof that it explains the entire regression.
A third revision tested a self-contained, template-only answer handoff. Its
serializer had no image argument, and machine-code inspection confirmed the
unnecessary load was gone. Both comparison builds used this handoff; only
fused lookup differed. At the same fixed 100k/7M A/B/B/A, fusion still increased
cycles/query from 2,970.02 to 3,220.12 (**8.42%**), despite 6.73% fewer
instructions. LLC misses rose 7.30%, dTLB misses fell 1.91%, and anonymous
memory increased about 83 MB. All four windows and 10,311 cold probes passed.
The largest ON self-cycle share moved to the body-copy routine (24.07%, with
22.01% attributed through compact response construction). This suggests body
access/locality remains costly, but does not establish its exact cause or a
recoverable gain. The prototype and handoff change were archived and removed.
No capacity campaign followed. The unwanted image read alone therefore does
not explain the fused design's loss; earlier failed measurements remain valid.

A fourth revision stores answer bodies up to 128 bytes inside the exact-match
entry, instead of in a separate allocation. Larger answers retain the existing
resolver. Its matched 100k/7M A/B/B/A passed the CPU gate: cycles/query fell
from 2,968.12 to 2,715.26 (**8.52%**), instructions fell 6.57%, LLC misses fell
5.88% and dTLB misses fell 12.92%. All four windows and 10,312 cold probes
passed. Anonymous memory increased about 119 MB. Both builds used detached
serialization, so this is fusion versus batching, not an isolated r3/r4
body-layout comparison.

The candidate remains experimental and has **not** passed its QPS guard cohort.
Its second 1k-zone mixed sequence lost 0.08206% during uniform traffic and two
cold probes timed out. Ubuntu Pro's metering job overlapped that window,
consuming 2.336 seconds of CPU; serving-thread scheduling delays rose to
76–188 ms each and all twenty receive queues recorded drops. This is evidence
of host interference, not permission to count the failed run as passing or
proof that the candidate cannot regress. A separate old/new/new/old 1k-zone
diagnostic then passed all twelve hot/Zipf/uniform windows and all 30,891 cold
probes, with no Ubuntu Pro service activity in either host's window journals.
It did not reproduce the failure; it does not replace the failed guard cohort.
Subsequent isolated 1k/17M guards passed on three fresh processes, with 7,723
error-free cold probes and maximum bulk loss 0.002610%. A fixed 100k/15M
old/new/new/old/old/new comparison then passed all six processes and all 15,444
cold probes. The old build averaged 15.003636M positive QPS with zero bulk loss;
the new build averaged 15.003630M with maximum loss 0.000100%. No Ubuntu Pro
activity was recorded in either host's measured-window journals. All eighteen
restoration steps passed, and the saved raw audit was independently reproduced.
Evidence is in `inline-small-17m-audit.json` and `inline-uniform-15m.json`.
These establish the same higher operating point for **both** builds, not an
incremental QPS win from fusion or clearance of the failed mixed cohort.
The publication-cost check below subsequently failed its screening gate.
Million-zone and complete mixed/fallback checks remain outstanding.

In the two fused profile windows, exact lookup still accounted for 30.98% and
31.93% of self-cycle samples; body copying accounted for 3.47% and 3.37%.
This prioritizes reducing the remaining lookup hashing and dependent accesses
over further body-copy tuning. Sample shares are not recoverable speedup
estimates. Any replacement must retain exact key checks, publication validity,
fallback behavior and bounded update costs.

### Publication cost: inline fusion is not yet acceptable

A separate remote microbenchmark used BoronGen's 23-record member portfolio,
with the same name seed and nesting. At each size it ran batching/fusion/fusion/
batching in fresh processes pinned to fast core 5. Each process performed 128
distinct replacements with no retained reader, then another 128 while a reader
held the previous directory. Updates advanced the SOA and changed one A record;
the held reader kept its old serial while a new reader saw the new serial.

| Zones | Reader state | Batching mean publication | Fusion mean publication |
| --- | --- | ---: | ---: |
| 1k | No retained reader | 9.50 µs | 15.78 µs |
| 1k | Previous directory retained | 6.45 µs | 13.42 µs |
| 100k | No retained reader | 70.61 µs | 111.41 µs |
| 100k | Previous directory retained | 65.51 µs | 130.80 µs |

Every condition exceeded the predeclared 25% mean-cost screening limit. At
100k with a retained reader, mean run-level p99 rose from 78.77 to 194.06 µs,
also exceeding the 2× p99 limit. Post-load RSS increased about 120.5 MB at 100k.
All serial, affinity and resource checks passed; the raw audit was reproduced.

These are in-memory publication timings, **not full IXFR latency**: snapshot
generation and compilation were outside the publication timer, and the probe
excluded catalogs, parsing, journaling, disk commit and concurrent queries.
The two reader phases run in a fixed order, so their difference alone does not
isolate reader retention from cache/allocation history. There are two samples
per build/size, not a statistical confidence claim. Evidence and sorted timing
samples are in `publication-probe-results.json` in the private evidence directory.

Fusion remains an unaccepted experiment. Its copy-on-write answer maps duplicate
ownership-bearing serving metadata alongside inline answers; cloning a map
clones those references too. This is a concrete next design target, not a
profile-based attribution of the whole measured penalty. A replacement must
reduce publication work as well as query-side memory dependencies.

A fifth revision removes those per-answer references entirely: entries contain
an incarnation token and inline bytes. The directory's immutable contents prove
eligibility. An explicit default-provider API can consume that proof; custom
providers and sizing fallbacks still use the original pinned directory. Remote
validation passed 1,524 workspace tests (one existing ignored), default/batching
core tests, formatting and Clippy. Subsequent focused tests also covered an
alternate custom image and cookie/EDNS/transport policy equivalence.

Its matched 100k/7M A/B/B/A reduced cycles/query from 2,976.00 to 2,583.39
(**13.19%**), instructions by 11.54% and dTLB misses by 16.71%. All four windows
and 10,310 cold probes passed, with all twelve restoration steps successful.
Anonymous memory increased about 111 MB. This is a CPU-cost result, not a new
QPS ceiling or a controlled r4/r5 comparison. Evidence:
`serving-fused-r5-abba-audit.json`.

Publication remained outside the screening limits: at 100k, batching/fusion
means were 70.38/96.03 µs without a retained reader and 66.20/108.12 µs with
one. The pinned p99 ratio was 2.60×. All eight publication cells passed their
correctness/resource checks; `publication-r5-results.json` retains the samples.
This revision remains experimental and unaccepted. Removing per-answer ownership
did not eliminate the table-copy and directory-reference work on updates.

Two further changes share unchanged descendant bookkeeping and reuse one keyed
name hash for shard selection and exact lookup. Full keys are still compared;
forced-collision, binary/maximum-length name and frozen-publication tests pass.
The latter revision passed 1,529 workspace tests (one existing ignored), default
and batching core checks, formatting and Clippy. Its fixed 100k/7M A/B/B/A
reduced cycles/query from 2,972.08 to 2,250.96 (**24.26%**), instructions by
14.16% and dTLB misses by 14.20%; LLC misses rose 8.08%. All four windows and
10,311 cold probes passed, with twelve successful restoration steps. Anonymous
memory increased about 108 MB. This again demonstrates CPU cost, not peak QPS.
Evidence: `serving-fused-r7-abba-audit.json`.

Publication screening still failed. At 100k, batching/fusion means were
70.31/92.17 µs without a retained reader and 64.95/110.10 µs with one; the
pinned p99 ratio was 3.06×. All eight cells passed correctness/resource checks.
The unchanged screen and raw samples remain in `publication-r7-results.json`.
Normal-release validation below does not resolve the publication penalty or
replace update-under-load and million-zone measurements.

Only a correctly exercised, equivalent implementation with measured CPU/QPS
gains, small-zone guards and acceptable memory/publication costs can advance.
Another rate sweep alone would not validate either architectural hypothesis.

### Fused r7 normal-release validation

The original nine-process guard cohort stopped on its third 26M single-zone
anchor (0.0340% bulk loss). Both hosts recorded a firmware-notifier restart
storm during that window; serving-worker runqueue delays were 30–84 ms.
This is evidence of interference, not proof of its sole cause. That cohort
remains failed; its remaining cases were not automatically retried.

A separately declared old/new/new/old anchor diagnostic then passed all four
26M windows, with no recorded Ubuntu Pro or firmware-notifier activity.
Both builds averaged 26.007M QPS. All twelve restoration steps passed.
On that evidence, the two previously unrun small/mixed cases were completed
and audited separately from the failed original anchor:

- Three 1k-zone hot/Zipf/uniform sequences passed at 20M/16M/13.5M.
- Three 100k-zone sequences passed at 19M/10M/12M.
- All 46,345 cold probes passed, with eighteen successful restoration steps.
- Three isolated 1k-zone 17M runs then passed, averaging 17.006688M QPS,
  with zero bulk loss, 7,722 successful cold probes and nine restoration steps.

The fixed 100k-zone 18M comparison used OFF/ON/ON/OFF/OFF/ON, unchanged workload
and NIC settings, normal release binaries, and no concurrent profiling/builds:

| Build | Mean positive QPS | Bulk loss across repetitions | Cold timeouts | Strict passes |
| --- | ---: | --- | ---: | ---: |
| Authority batching r2 | 15.000510M | 16.6955%, 16.6596%, 16.6595% | 321 / 1,702 probes | 0/3 |
| Fused r7 | 18.001649M | 0%, 0%, 0.0001304% | 1 / 7,703 probes | 2/3 |

The candidate improves delivered throughput by about 20% at this offered load,
but **18M is not an accepted three-process operating point**. Its final run
missed 704 bulk responses on requester queue 5 and one cold probe timed out.
No wrong DNS contents/classifications were reported. Server counters over the
surrounding interval showed equal RX/queued-TX totals, no AF_XDP parse/delivery
errors or socket drops, and no NIC out-of-buffer events. Worker scheduling
delays were 0.48–2.98 ms; memory-limit events were zero. These aggregate counters
do not locate the lost probe or establish requester-side causation. Both
background-activity checks passed. The timeout remains unresolved, and no
automatic retry or lower-rate replacement was run.

All eighteen restoration steps passed, including failed runs. The raw six-window
re-audit is `audit_inline_r7_outcome.py`; individual results are
`relative-reuse-inline-r7-u18-{off,on}-{index}-audit.json` in the private evidence
directory. The original full-acceptance file was deliberately not produced.
The separate guard evidence is `inline-r7-anchor-diagnostic.json`,
`inline-r7-revised-guards-audit.json` and `inline-r7-small-17m-audit.json`.
Do not divide the 18M result by the fixed 17M small-zone guard to claim a
maximum-QPS retention ratio. No new Knot or million-zone result is implied.

### Transport-owned response writing

The off-by-default `experimental-response-writer` feature now connects the core
writer to the server and AF_XDP transport. It adds a bounded
caller-buffer API at the existing post-policy fused-answer branch. It shares
the ordinary wire/EDNS serializer and returns an explicit written length or
an owned fallback. Insufficient capacity leaves the destination unchanged;
fallback remains bound to the original publication. RRL now shares a borrowed
send/slip/drop decision with its existing owned-response API, preserving the
same accounting rather than exempting direct-written replies.

The transport lends a mutable receive-frame payload for one synchronous batch
callback. A typed completion identifies the frame, batch epoch and initialized
length; TX validates it before rewriting IP/UDP headers and checksums. RRL runs
before completion: drop sends nothing, slip uses the ordinary truncated response
without accounting twice. TSIG retains the owned signing path. Standard UDP,
small directories, repeated-query batches and pipeline-timing diagnostics keep
their existing paths. This is not a claim that every query becomes allocation-free.

The core write, borrowed-RRL and frame-output tests were observed failing before
implementation. Remote validation passed **1,537 workspace tests** (one existing
ignored), 792 default-core tests plus the spec test, 488 default-server tests
(one existing ignored), fused-core tests, formatting and Clippy. Coverage
includes buffer-fit boundaries, mixed-case names, cookies, EDNS errors/options,
truncation, TLS padding, frozen fallback, another-store rejection, policy/metric
equivalence, IPv4/IPv6 wire checksums, stale completion rejection and owned
fallback after abandoning a reply buffer. The server regression explicitly
requires a direct-path hit; the usual one-record fixture was ineligible because
it uses the existing Records fallback rather than a compact template.

The fixed 100k-zone, 7M offered-QPS comparison used fresh processes in
OFF/ON/ON/OFF order. Both builds retain fused lookup; only ON enables direct
reply writing. Mean cycles/query fell from **2,247.73 to 2,117.94 (−5.77%)**,
and instructions fell 6.65%. Both ON runs were below both OFF runs and had zero
bulk loss. All four passed the loss/content/checksum gates, all **10,312 cold
probes passed**, and all twelve host/policy restoration steps passed. UA and
firmware-notifier activity checks were clean. LLC and dTLB misses increased
5.46% and 6.79%, respectively; memory usage was about 3.20 GB in both builds.

Runtime samples include the new writer and frame-buffer path. Inspected machine
code has no allocator call in the bounded serializer and no second DNS payload
copy in frame completion; the remaining copy into the frame is intentional.
These observations do not prove the whole request lifecycle is allocation-free.
The profile passes the declared 5% CPU gate. Normal-build validation then
passed its first 26M single-zone anchor but **failed** the first 1k-zone 20M hot
window: bulk loss was 0.000334%, and two of 2,536 independent cold probes timed
out. The campaign stopped before the remaining mixed phases or any 19M
large-zone test. The low bulk loss does not override the failed cold-probe gate.

A separate OFF/ON/ON/OFF hot-load diagnostic captured the independent probe
flow on the requester. All 10,299 captured request/reply pairs passed content
replay, with no probe timeout. Requester NIC counters establish that the probes
return through RX queue 5, which also held all 2,005 missing bulk replies in
the original failure. Server receive/transmit totals matched, including the
probes on server queue 1. This suggests investigating the shared requester
receive path, but does not prove the cause or clear the original failure.
The diagnostic capture used tcpdump's default promiscuous mode; possible NIC
perturbation is another reason not to treat those runs as throughput acceptance.
Future captures use non-promiscuous mode. No normal-build cohort is accepted.

The earlier publication-cost failure and r7
18M cold-probe timeout remain unresolved. Exact lookup still accounts for
about 22% of candidate self-cycle samples, making its memory layout and
incremental publication the next substantial architectural target.

Private evidence: `response-writer-r1-protocol.md`,
`response-writer-r1-abba-audit.json`, `response-writer-direct-assembly.log`,
and `response-writer-transport-green-r4-build.log`. Source overlay:
`response-writer-transport-r1-source.tar.gz`.

| Profile binary | SHA-256 |
| --- | --- |
| Fused baseline, writer OFF | `0f820d2e2c516757c4574a0ef91d3cdae85e95827c8ff93d531a58f11b1d881f` |
| Direct writer ON | `af520e3199759835b4ff8f3a205f67d4b578f21310bfb705b174a2f8e28b74cd` |

Normal release binaries: OFF
`8437b7a8cc12cd5e9def9350067f78529b09f34308cfbfddf4307f7efad706da`;
ON `48f965bfb32a7625012e3fec1159cc5c2692bccec06997184381c7fdba036625`.
Private evidence includes `writer-normal-r1-protocol.md`,
`writer-path-diagnostic.json`, the original failed guard's partial report,
and four probe PCAPs with content-replay audits.

## Rejected publication-tree experiment

A 16×16×16 ownership tree replaced the fused index's 64×64 grouping while
preserving its 4,096 maps, hash/equality rules and answer bytes. The structural
regression first failed on the old layout, then passed; remote workspace,
default/fused-core, formatting and Clippy checks also passed.

The same-source baseline/fused/tree publication comparison still failed the
existing cost screen. At 100k zones, the tree reduced fused publication means
from 95.79 to 94.14 µs without a pinned reader and from 111.95 to 106.80 µs
with one. The non-fused means were 69.68 and 64.88 µs. These small reductions
did not justify adding a query pointer lookup, so the prototype was archived
and removed before a query benchmark. No QPS result is attributed to it.

A separate diagnostic retained 671 cycle samples whose call stacks included
the update phase, excluding initial population. Atomic reference increments
accounted for 32.81% of those self samples, decrements 8.35%, and memcpy 14.90%.
The stacks point predominantly to the main zone-directory insertion path,
not just the fused-index groups. This phase also includes snapshot preparation
and cleanup: these are sample shares, not exact publication-time percentages.
The main directory copies origin/suffix map shards containing other zones'
keys and ownership references. Reducing that copy granularity is the next
architectural candidate; no benefit is claimed before measurement.

Evidence: private `publication-tree-r1-results.json`,
`fused-tree-r1-source.tar.gz`, and `publication-phase-r1-{record,report}.log`.
The retained source was restored byte-for-byte for the affected files and
passed the remote workspace/default/fused tests and Clippy again.

## Smaller publication shards

The off-by-default `experimental-directory-shards` feature replaces each main
directory's 256 flat map shards with 4,096 maps in 64 ownership groups. Updating
one zone copies a smaller map and its group; publication clones 64 root owners
per index instead of 256. The fused-answer index, descendant bookkeeping and
small-directory shortcut are unchanged. Ordinary indexed fallbacks gain one
pointer lookup, so they still need a separate performance guard.

A 10k-zone regression first failed on the old layout, copying 46 unrelated
origin keys. It passes the new <=16 bound. Additional regressions preserve
untouched maps and old roots, including initially shared empty maps. Remote
workspace tests passed (1,540 passed, one existing ignored test), as did
standalone-feature, fused-only and default core tests, formatting and Clippy.

The same-source four-way comparison used the original directory, fused lookup,
smaller directory shards, and both together. Each size ran that order followed
by its reverse, with 128 publications per reader condition per cell. Means:

| Zones / reader | Original | Fused | Smaller shards | Both |
| --- | ---: | ---: | ---: | ---: |
| 1k / unpinned | 9.47 µs | 13.38 µs | 6.34 µs | 10.23 µs |
| 1k / pinned | 6.51 µs | 10.39 µs | 3.63 µs | 7.41 µs |
| 100k / unpinned | 72.21 µs | 94.47 µs | 14.93 µs | 26.89 µs |
| 100k / pinned | 65.89 µs | 111.77 µs | 6.66 µs | 39.00 µs |

The combined design passes the unchanged screen against the original baseline:
mean <=1.25x and p99 <=2x in all four conditions. Fusion still adds cost relative
to smaller shards alone; that is not hidden by this comparison. The probe changes
actual A data and SOA serials and checks old/current serials. It excludes network
transfer, IXFR parsing, journal writes, durable commit and concurrent query load.

A separate two-host OFF/ON/ON/OFF query profile enabled fused lookup and the
direct writer in both builds, changing only directory sharding. At 100k zones
and 7M offered uniform QPS, cycles/query averaged 2,115.41 versus 2,109.00
(−0.30%). This passed the predeclared 2% non-regression screen, not the separate
5% CPU-improvement screen. All four windows had zero bulk loss; all 10,311 cold
probes and 12 restoration checks passed, with no UA/firmware activity during
measurement. Mean anonymous memory rose by 15,456,256 bytes (about 14.7 MiB).

This is not a new capacity point, a full IXFR result, or clearance of the earlier
cold-probe failures. Subsequent dedicated DO=1 fallback guards and isolated
100k/19M and million-zone operating points are summarized at the top of this
report. Update-heavy network validation remains outstanding.

Private evidence: `directory-shards-protocol.md`,
`publication-directory-r1-results.json`, `directory-r1-abba-audit.json`, and
`directory-shards-green-r2-build.log`. The six-file source overlay is
`directory-shards-r1-source.tar.gz`, SHA-256
`1a44c386dd9dd8c81f78403f43a2b3d4ad29d0a7b5101dee9f34bbc10c06abd8`.
Query binary hashes: OFF
`a48ee5869d7dc94972bdffe3b1af7bff9c59ffd6162f774283c9dd4911c948a3`;
ON `4de1e3c194988439f93ce0aa995ca41f7e5665f855e8d578005a2e2634c56320`.

### Normal release guards

The first normal-build cohort stopped at its third single-zone 26M anchor:
25.806M positive QPS and 0.775% loss. During that window the server's scheduled
midnight log rotation consumed 43.6 CPU-seconds, host disk reads rose about
2.05 GiB, and the AF_XDP receive queues overflowed. Several query workers
accumulated nearly one second of scheduling delay. This is strong evidence of
background interference, not proof of exclusive causality or a code regression.
The failed cohort and raw loss remain recorded.

Read-only maintenance checks now cover known heavy jobs before and after each
test, with timer lookahead to avoid starting a window across scheduled work.
No host service was disabled or retuned. A separate, fixed OFF/ON/ON/OFF anchor
comparison then passed all four windows: 26.007194M OFF and 26.007166M ON mean
positive QPS. All maintenance, UA and firmware checks were quiet.

An explicit revised protocol retained the first two passing repetitions,
included both candidate anchor windows from that matched comparison, and ran
only the two previously unexecuted small/mixed sequences:

| Workload | Mean positive QPS | Fresh processes |
| --- | ---: | ---: |
| Single-zone anchor | 26.007M | 4 |
| 1k hot / Zipf / uniform | 20.000M / 16.000M / 13.504M | 3 |
| 100k hot / Zipf / uniform | 18.993M / 10.000M / 11.998M | 3 |

All 46,342 independent cold probes passed. The ten accepted candidate processes
passed content/checksum, resource, background-activity and 30 restoration checks.
Maximum bulk loss was 0.001732% for the anchor, 0.000118% for the small sequences,
and zero for the 100k sequences. These validate existing operating points, not
a new maximum or a new Knot comparison. The original cohort remains failed;
the revised report explicitly includes its maintenance-overlapped failure.
The older writer/r7 cold timeouts have not been explained or retroactively cleared.

Private evidence: `directory-anchor-diagnostic-protocol.md`,
`directory-anchor-diagnostic.json`, `directory-r1-revised-guards-audit.json`,
and `directory-anchor-failure-journal{1,2}.log`. Normal candidate SHA-256:
`1a9703668e8f2e99e475c005855500dfd78fa35ac0a91d781c101c503f558a63`;
matched OFF: `1910d2ef08e082ccfef409a632df698a6eb45a66dfbf92362e306b7e96c9ead5`.

## Setup and acceptance rules

The [original campaign report](gx10-multi-zone-benchmark-2026-09.md) describes
the hardware, portfolio, seeds and query schedules. The current comparison uses:

- Two ASUS GX10/GB10 hosts and their dedicated **200 Gbit/s ConnectX-7 link**,
  not the earlier 25G oxide pair. Generation and serving run on separate hosts.
- Ten fast cores for serving, twenty native zero-copy AF_XDP queues and ten
  slower cores for IRQs. MTU is 1,500 during measurement.
- BoronGen's 23-record member-zone portfolio, with one percent nested zones.
  The queried answers contain 121 DNS bytes.
- Fixed-width shuffled names, calibrated source ports and unchanged per-size
  corpora. The requester must achieve at least 99% of the requested rate.
- Thirty seconds of measurement after ten seconds of warm-up. Accepted points
  require three fresh processes, bulk loss below 0.01%, no unexpected DNS
  classes, no cold-probe errors and successful sampled answer/checksum checks.
- Verified artifact identity, CPU placement, memory-event limits and host
  restoration. Warm-up classifications must cover all twenty queues.
- Bounded global-only metrics, a post-load I/O quiet gate, and temporary
  `vm.compaction_proactiveness=0`, restored to 20 afterward. This setting is a
  benchmark control, not a production tuning recommendation.

The current 1k/100k comparison recovers existing offline datasets in fresh
processes; it does not repeat AXFR. The million-zone validation uses fresh AXFR
and persistence directories. Quiet-serving SOA refresh is 7,200 seconds.

Important differences remain:

| Setting | BoronDNS | Knot |
| --- | --- | --- |
| Query execution | Ten single-worker runtimes, two queue tasks each | Twenty OS query threads |
| Optional IPv4 UDP checksum | Computed | Omitted |
| Software RX/TX/completion ring entries | 4,096 | 8,192 |
| Fill-ring entries / UMEM per queue | 8,192 / 16,384 × 2,048 bytes | Same |

Loading, persistence and refresh scheduling also differ. A stable process and
cgroup write count does not prove that all unrelated kernel work has stopped.
The selected hot name changes with zone count; hot-name ratios are not a
constant-object cache experiment.

Bulk counts do not prove unique delivery or inspect every answer. Independent
cold probes and checksum/content checks provide sampled coverage. These
results do not cover every DNSSEC, negative-answer, response-size or RRL
workload.

## Failures and comparison limits

Knot returned unexpected REFUSED/NXDOMAIN responses in several overloaded
zero-copy runs, including the rejected 18M small-zone calibration. They are
excluded from accepted throughput.

A separate instrumented diagnostic observed duplicate frame addresses within
receive batches and question bytes changing before those sampled buffers were
released. This is evidence of a receive-buffer lifetime/ownership problem in
the tested stack, not proof that Knot rather than the kernel/driver caused it.
Copy-mode diagnostics changed timing and throughput and are not substitute
capacity results. The accepted comparison uses the original, unmodified Knot
binary and requires zero unexpected classes.

The older Knot million-zone cohorts failed repetition: one lost 0.6225% at
6M Zipf; another lost 1.853% at 17.5M hot and timed out four cold probes.
An `inode_switch_wbs_work_fn` CPU-hog warning overlapped one failure.
Writeback contention is a hypothesis, not a demonstrated cause. Neither cohort
establishes an accepted million-zone row.

A further fixed-rate cohort after storage reclamation also stopped: its third
5.75M Zipf window lost 1.0833%, with no cold-probe errors. The failed window
had 1,467 fast-core system ticks versus 848/847 in the two passing windows,
while Knot's own system CPU changed much less. NIC out-of-buffer counters rose
by 1,868,197. There was no matching writeback-hog warning in that interval.
This points to a need for targeted host/kernel profiling, not another blind
capacity retry; it does not identify a kernel function or establish causation.

Earlier full per-zone metrics scrapes produced multi-gigabyte responses and
disturbed measurements. Those curves must not be mixed with the newer
global-only protocol. Likewise, original compaction-policy-20 runs without
complete warm-up classification are historical context, not current baselines.

## Validation and evidence

### Refresh follow-up: starvation fix and matched common-load test

The first 100k-zone, 60-second-refresh run stopped before QPS measurement:
162 members remained loading after the 30-minute deadline. A deterministic
test reproduced scheduler starvation when recurring due work filled the queue.

A subsequent scheduler change indexes refresh, expiry and warning deadlines,
updates only changed entries, and selects oldest due refreshes up to available
queue capacity. It passed 1,510 workspace tests and 487 default-feature server
tests (one pre-existing ignored test in each suite), formatting and Clippy.
The fixed build loaded all 100k members in about 226 seconds. It then failed
the separate I/O-quiet gate because ongoing freshness persistence kept writing.
Both attempts restored the hosts; neither produced refresh-QPS results.

That follow-up binary is `relative-packed-deadlines-release`, SHA-256
`38713678c5843f545823c16aca7712d04bac022b1b8a24e5271f2f58648f65ce`.
It is **not** the binary used in the throughput tables above. Its quiet-serving
guards passed on nine fresh processes: the same 26M anchor, 1k 20M/16M/13.5M
and 100k mixed 19M/10M/12M points, with all 46,342 cold probes successful.
Separate isolated uniform guards retained 17M at 1k and 13M at 100k on three
fresh processes each, with zero bulk loss and all 15,446 cold probes successful.
Their measured means were 17.006687M and 13.003827M (76.4630% retained).

The revised protocol observes active refresh and persistence for at least
180 seconds after loading, identically on both servers, rather than requiring
zero writes. Each of three fresh instances per server then runs six fixed
5M uniform windows. All [36 raw-count windows](gx10-active-refresh-2026-09.csv)
are retained, including Knot's two loss outliers:

| Server | Windows below 0.01% loss | Maximum loss | Cold probes, all successful |
| --- | ---: | ---: | ---: |
| BoronDNS, packed + deadline indexes | 18/18 | 0.0001014% | 46,470 |
| Knot 3.6.0 | 16/18 | 0.145883% | 46,455 |

The other rejected Knot window lost 0.093674%. Neither server returned an
unexpected DNS class or failed a sampled content/checksum check. All six
instances passed the raw safety, identity and restoration audits. The balanced
B/K/K/B/B/K sequence paused before the fifth instance for an inode-budget
failure; only reproducible older caches were reclaimed, and the unstarted
instance received a new label. No measured window was retried.

This is a **common-load consistency result**, not a refresh-capacity ceiling
or proof of the loss outliers' cause. Boron wrote about 4.19 MB/s during each
pre-traffic observation; Knot ranged from about 67 B/s to 1.01 MB/s. Persistence
implementations and durability work differ, so these are not storage-efficiency
ratios. Boron's post-traffic scan found all 100,001 zones, including the catalog,
had a success after the recorded cutoff. There is no matching Knot observer;
neither QPS nor this once-per-window-set check proves absence of refresh backlog.
Memory/update costs and fallback-heavy performance remain to be evaluated.

### Packed throughput candidate

All Cargo builds and DNS load tests ran on the remote hosts. The packed source
passed **1,508 workspace tests**, with one pre-existing ignored test, plus 792
default-core tests, formatting and Clippy. Regression coverage includes packed
bounds/alignment/cloning, binary and long names, publication changes, TSIG,
cookies, RRL, DNSSEC/fallbacks and malformed requests. The local harness now has
169 passing tests, including control-socket path validation, refresh observation
timing, raw audits and safe continuation after a pre-load resource rejection.

Binary SHA-256:

| Binary | SHA-256 |
| --- | --- |
| Packed candidate | `d68518573dd576804ec7b5ca6c5cd07768f74d3053eb32f8fb89727b60fcfe9f` |
| Matched packed-off reference | `50b5ec5c3e058301b1420d8449b1c3dd2baa792a83ace17f877e7b9413d7e5d4` |
| Earlier selected-query r2 | `e27340453ad2efaa8f7fc696241f06cb659d1f25fe29ae78c0c3a0d5cdaad078` |
| Knot 3.6.0 | `dc2103fca92d3c63f959c245f6b4d9737ee932aa30a47dc2b2bf52371b95b89d` |

The candidate enables `af-xdp`, `experimental-compact-serving`,
`experimental-serving-directory`, `experimental-xdp-time-turn`,
`experimental-selected-query`, `experimental-staged-serving` and
`experimental-packed-serving`. The matched reference differs only by omitting
the last feature.

Private raw evidence lives in
`~/.local/state/borondns-gx10-knot-scaling-20260927.TWLypG/`:

| Evidence | Contents |
| --- | --- |
| `packed-capacity-calibration.md`, `audit_uniform_capacity.py` | Current uniform comparison, searches, failed repetitions and raw audit |
| `packed-serving-results.md`, `audit_packed_cohort.py` | Matched profiles, small guards and mixed-workload repetitions |
| `serving-handle-protocol.md`, `serving-handle-abba-audit.json`, `run_serving_handle.py` | First direct-handle cohort; invalid architectural conclusion because server staging was disabled |
| `batch-authority-protocol.md`, `batch-authority-abba-audit.json`, `run_batch_authority.py` | First authority-wave cohort; same feature-coverage failure, pending corrected comparison |
| `batch-authority-r2-abba-audit.json`, `run_batch_authority_r2.py` | Corrected staged-path A/B/B/A; 6.81% lower cycles, not capacity evidence |
| `authority-hot-diagnostic.json`, `authority-hot-diagnostic-protocol.md` | Matched hot-load diagnostic; did not reproduce the earlier timeout |
| `authority-uniform-guards-audit.json`, `authority-uniform-14m.json`, `authority-uniform-14m-protocol.md` | Same-candidate small/large guards and fixed 14M matched comparison, including the baseline failure |
| `authority-million-profile-audit.json`, `authority-million-profile-protocol.md`, `run_authority_million_profile.py` | Correctly staged million-zone A/B/B/A; 8.70% lower cycles, not capacity evidence |
| `authority-million-7m-audit.json`, `run_authority_million_guard.py` | Three unprofiled million-zone 7M guards; zero loss and 7,734 error-free cold probes |
| `serving-handle-r2-abba-audit.json`, `serving-handle-r2-protocol.md` | Correctly staged handle on top of batching; +0.64% cycles, rejected and removed |
| `serving-pages-protocol.md`, `relative-reuse-pages-r1-on-20-partial.json` | Paged prototype stopped on packet loss after OFF/ON/ON; rejected and removed |
| `fused-serving-protocol.md`, `serving-fused-r1-abba-audit.json`, `serving-fused-r2-abba-audit.json` | Scalar and batched fused-index comparisons; fewer instructions but more cycles, both rejected |
| `staged-serving-results.md`, `flat-directory-results.md` | Earlier candidates and rejected results |
| `relative-cap0-sqr2-million-fixed-complete.json` | Accepted earlier million-zone build |
| `relative-cap0-packed-million-fixed-complete.json` | Accepted packed million-zone cohort; audited with `audit_global_capacity.py` and separate zero-timeout/raw-probe checks |
| `knot-rx-audit-results.md`, `knot-writeback-contention.md` | Unresolved Knot-stack diagnostics |
| `report-before-consolidation-20260930.md` | Full earlier chronology, historical curves and evidence references |
| `matched-refresh-protocol.md`, `refresh-deadline-results.md` | Two stopped pre-traffic refresh attempts, scheduler reproduction/fix and required protocol revision |
| `active-refresh-protocol.md`, `active-refresh-cohort.json` | Completed six-instance active-refresh comparison; all windows retained |
| `deadlines-guards-audit.json` | New scheduler's nine-process quiet-serving regression guards |
| `deadlines-uniform-guards-audit.json` | New scheduler's repeated 17M/13M uniform regression guards |

The CSV is a public extract, not the entire private harness or an independent
replication. Relevant harnesses pin binaries and frozen configuration adapters;
changing those requires a new comparison.

The isolated million-zone uniform comparison and the October 1 mixed pilot
matrix above provide usable Knot comparison evidence. Repeated mixed-workload
acceptance, fallback-heavy performance and update/publication costs remain open;
the stated correctness and configuration limitations still apply.
