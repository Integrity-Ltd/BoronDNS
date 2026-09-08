# Knot comparison tuning record — June 2026

These are the June 5–7, 2026 lab measurements, grouped by the question each
experiment tested. Use the [comparison runbook](knot-comparison-benchmark.md)
for current instructions. The results apply to the recorded binaries,
requesters, host roles, and query mix; they are not current release throughput.

Artifact timestamps in the tables expand to
`physical-udp-knot-comparison-<timestamp>`. Other artifact names are written
in full. “Unlabelled” means the original notes supplied no artifact identifier;
no source hash or provenance has been inferred for those rows. Approximate
values retain the precision of the original notes.

Historical server `xdp.tx_wakeup_interval` values above 1 are retained only
as experiment settings. Current BoronDNS requires 1. The AF_XDP dependency
uses `XDP_USE_NEED_WAKEUP` without exposing the kernel ring flag, so each
non-empty TX enqueue must be kicked.

## Results at a glance

| Question | Recorded answer |
| --- | --- |
| Could the socket path approach 4.8M offered QPS? | Yes on the forward host: about 99.96% replies after combined qdisc/buffer tuning. The same settings failed badly with host roles reversed. |
| What limited the reverse socket path? | Receive/CPU work and empty polling; the stable recorded point was 4.25M. More buffer, IRQ/RPS, and affinity changes did not recover 4.8M. |
| Were AF_XDP losses always server losses? | No. Queue-count mistakes, requester RX starvation, and unflushed requester TX descriptors each distorted early comparisons. |
| Did a win against packaged Knot imply a win against source-built Knot? | No. Source-built 3.5.4 with server zero-copy reversed the packaged-3.5.3 result. |
| What was selected for the historical source-built comparison? | Server batch 512, requester batch 64 and final drain 2000 ms, with the then-valid server wakeup interval 8. Repeated margins were small. |
| Did the response-ownership prototypes help? | Buffer reuse, direct-to-frame composition, separate TX frames, and borrowed RX payloads were rejected or showed no clear gain. |

“Reply %” is received replies divided by the requester's recorded sends.
Offered rates and retained responses/s are different measurements. A 100%
row at a lower actual offered rate is not a higher-capacity result.

## Socket path: building the forward profile

The early rows used the 48-logical-CPU, 25G server. Values below are
approximate unless given as integer counters. The eventual combined candidate
was 48 unbound workers, batch 64, `fq limit=50000`, `flow_limit=500`,
16 MiB receive ceiling/8 MiB requested buffer, and 64 MiB send ceiling/
32 MiB requested buffer. The intermediate trials explain why that combination
was selected.

| Trial | Recorded result |
| --- | --- |
| 16 workers pinned to sibling-free even CPUs; 3M offered | 2.33M replies/s / 77.6% became 2.69M / 89.7%; an initial 4 MiB combined socket buffer was worse than default |
| Stable recvmmsg layout; skip disabled RRL work | At 3M: 2.87M / 95.8%; at 3.5M: 3.09M / 88.3% |
| 24 pinned workers, counters off, park, 2 MiB RX/TX; 4.5M | 4.45M / 98.97%; no RX errors, ~231k `SndbufErrors`; send-only 4 MiB and batch 16/32/64 did not resolve loss |
| 32–36 unbound workers | Best: 36 workers, spin, 2 MiB buffers, 4.46M / 99.12% at 4.5M; repeats 98.4–99.1%; 4.6M gave 98.74%. 40 workers and single-socket/sibling placement were worse |
| `txqueuelen=5000`; 36 workers, batch 8, off/spin, 2 MiB buffers | At 4.5M: Knot 4.42M / 98.35%, BoronDNS 4.47M / 99.40%; manual repeats ~99.7%. Below 99% at 4.6M; collapse at 4.75M |
| TX ring 1024→4096 | Default queue ~98.7%; larger ring plus queue length 5000 was worse than queue length alone |
| Child `pfifo_fast`→`fq limit 10000` | At 4.5M: `fq` 4.48M / 99.65%, restored control 4.44M / 98.65%; matched Knot 4.35M / 96.80%, BoronDNS 4.49M / 99.86% |
| Repeat `fq` | 99.60%, 99.84%; adding queue length 5000 gave 99.73%. Cleanup restored `pfifo_fast:48`, queue length 1000 |
| Higher-rate `fq` sweep | Above 99% at 4.6M/4.65M; ~98.2% at 4.7M, ~96.5% at 4.75M. 40 workers beat 32/36 at 4.7M (~99.0%), but missed 4.75M and collapsed at 4.8M |
| 40-worker buffer/batch trials | RX 4 MiB: ~97.5% at 4.7M; TX 4 MiB roughly neutral there, ~98.4% at 4.75M. Batch 16 beat 4/8 at 4.7M (99.33%), but stayed below 98% at 4.75M |
| Same-artifact 4.7M and worker follow-up | Knot 94.82%, BoronDNS 99.29%; noisy 40/44/48 sweep selected 44 at 99.14%, then 98.26% at 4.75M |
| 48 workers at 4.75M: batch 32/64/128 | 98.66% / 98.96% / 98.57%. Matched batch-64 row: Knot 92.21%, BoronDNS 98.72%; 4.8M gave 95.54%; queue length 5000 gave 98.31% |
| Socket samples at 4.75M | RX/TX queues and `skmem` write/drop occupancy stayed zero despite ~2.77M `SndbufErrors`: transient loss was not visible between 100 ms samples |
| Send ceiling 4→16 MiB; request 8 MiB | Observed `tb4194304`→`tb16777216`; one row 99.02%, no RX errors, ~231k send errors; unsampled repeats 97.92%, 97.52% |
| Send ceiling 32 MiB; request 16 MiB | 48 workers: 99.04%, 156 RX errors, ~228k send errors; 40/44 workers worse; 4.8M 90.96%. Matched committed-harness row: Knot 92.06%, BoronDNS 95.90% |
| Send ceiling 64 MiB; request 32 MiB | 4.75M repeats 98.47%, 99.22%, no RX errors, ~362k/185k send errors; 4.8M 95.16%, ~1.16M send errors |
| `fq flow_limit` 100→1000→10000 | At 4.75M: limit 1000 gave 97.05%/99.05%, ~699k/216k drops; 10000 gave 98.16%/97.83%, ~433k/942k drops |
| `fq limit` 10000→50000→200000 | Limit 50000: 4.75M 98.42%/99.37%; 4.8M 98.12%, no RX errors, ~445k drops. Matched 4.8M: Knot 91.34%, BoronDNS 97.83%. Limit 200000: 97.33%, ~629k drops |
| `20260605T191048Z`: 10-second, three-repeat 4.8M batch | 96.45%, 97.42%, 97.87%; ~1.69M/1.15M/1.02M qdisc/send drops and occasional RX errors |
| `20260605T204230Z`: `flow_limit=500` | 4.8M: 99.70%, ~55k qdisc/send errors, 63 RX errors, ~9k `flows_plimit` |
| `20260605T204346Z`: same tuning, paired | BoronDNS 98.65%, Knot 90.32%; BoronDNS loss shifted to ~129k RX errors |
| `20260605T204624Z`: receive ceiling 16 MiB, request 8 MiB | 4.8M: 99.50% with the 32 MiB send request and flow limit 500 |
| `20260605T204808Z`: three repeats | 99.87%, 99.96%, 99.97%; ~4k/6k/7k qdisc drops, low RX loss |
| `20260605T205029Z`: paired confirmation | Knot 88.35%, BoronDNS 99.96%; BoronDNS ~1.5k qdisc drops, ~7.5k RX errors, ~1.5k `flows_plimit` |
| `20260605T204713Z`: same-tuning outlier | Both implementations well below their normal rates; retained as noisy, not the passing comparison |

## Socket path: alternatives that did not improve 4.8M

Unless stated otherwise these trials used 48 workers, batch 64,
`fq limit=50000`, and a 32 MiB requested send buffer. Lower loss in one
counter often meant loss had moved elsewhere.

| Artifact/trial | Result and disposition |
| --- | --- |
| `20260605T191333Z`: 36/40/44/48 workers | 93.91% / 96.39% / 97.11% / 98.48%; fewer workers traded send drops for RX errors; 48 still had ~359k send errors |
| `20260605T203222Z`: 52/56/60/64 workers | 93.40% / 92.44% / 95.70% / 94.19%; oversubscription added large RX loss |
| `20260605T191533Z`: batch 48/56/64/80 | 97.08% / 98.44% / 98.86% / 97.06%; retained 64 |
| `20260605T192656Z`: socket pacing 8/9/10/11/12M bytes/s | 96.44% / 97.60% / 97.30% / 97.08% / 97.25%; below unpaced control |
| `20260605T203429Z`: pacing 14/16/20/24M bytes/s | 96.66% / 98.12% / 97.85% / 97.91%; 16M had no RX errors but ~449k qdisc/send drops |
| `20260605T203858Z`: `fq nopacing` | 98.42%, ~359k qdisc/send errors, tiny RX loss; cleanup restored `pfifo_fast` |
| `20260605T193038Z`: reduced-counter send diagnostic | 543778 send syscalls, 22435263 accepted datagrams, no partial calls or WouldBlock retries; instrumentation lowered reply rate to 93.45% with ~1.45M RX errors |
| `20260605T193659Z`, `20260605T193803Z`: TX rings 4096/8192 | 96.86% / 95.65%; send drops ~194k/88k, RX errors ~144k/372k, softnet time-squeeze 403/618; restored ring 1024 |
| `20260605T194231Z`: `fq_codel` | 97.29%; ~203k qdisc drops, ~182k RX errors, 1268 time-squeeze events |
| `20260605T194318Z`: `pfifo_fast` control | 86.36%, ~3.27M qdisc/send errors |
| `20260605T203018Z`: `fq quantum=initial_quantum=1514` | 96.86%, ~465k send errors, ~219k RX errors and elevated time-squeeze |
| kxdpgun batch 1/5/20 at 4.75M, unlabelled | 93.95% / 97.11% / 97.88%; retained requester batch 10 |
| RX batch 64, TX batch 32, unlabelled | 98.21%, 97.39% at 4.75M; 3.0M–3.4M send errors; split rejected |
| WouldBlock retries 256→64/512, unlabelled | At 4.75M: 64 gave 97.46% with few RX errors; 512 gave 98.91%; no clear improvement |
| Borrowed zone lookup, unlabelled | 97.63%, 98.84%, 98.39%; profiling row 98.54% with 1.6%–1.7% clone/drop samples |
| `20260605T200338Z`: borrowed lookup | 98.28%; kept ownership cleanup as neutral for the transport boundary |
| GRO/coalescing, unlabelled | GRO off: 98.35%; fixed zero-usec/one-frame coalescing: ~74%; fixed RX/TX 16 µs, 256 frames: 96.57%; retained adaptive coalescing/GRO |
| CPU pinning, unlabelled | CPUs 0–47: 98.04%; 24 NIC-local even CPUs 0,2,…,46: 73.85%, ~6.21M RX errors and no send errors |
| `20260605T194518Z`: IRQ/XPS-order pinning | 96.17%, ~905k qdisc/send errors, little RX loss; baseline had 48 queues, even RSS, RPS off, irqbalance inactive, IRQ/XPS order 0,2,…,46,1,3,…,47 |
| `20260605T195012Z`, `20260605T195103Z`: skip unused metric timestamp | 98.00%, 98.68%; retained as small cleanup, not a loss fix |
| `20260605T200945Z`: symbolized profile | Refcount bucket gone; `recv_batch_linux` largest userspace bucket; empty-poll error destruction visible |
| `20260605T201401Z`: map EAGAIN/EWOULDBLOCK to empty batch | 98.17%, ~428k qdisc/send errors; retained cleanup |
| `20260605T201614Z`: follow-up profile | Error-drop bucket gone; `recv_batch_linux` ~9.9% |
| `20260605T202558Z`, `20260605T202640Z`: prebound receive buffers/headers | 97.10%, 97.64%, RX errors in both and elevated time-squeeze in first; retained caller-owned inbound layout |

## Socket path: reversing the host roles

Here `oxidegun-1` served `198.18.0.2` and `borondns-1` generated load
from `198.18.0.1`. The stage/query files were mirrored, Knot was installed
and disabled as a service on the reversed server, stale generic XDP was
detached, and its zero-handle `mq` root was normalized to `mq 8001:` with
`pfifo_fast` children.

| Artifact/trial | Result |
| --- | --- |
| `20260605T211343Z`: forward tuning, 48 workers, 4.8M | Knot 97.41%; BoronDNS 51.22%, ~9.54M `RcvbufErrors`, no send errors/qdisc drops |
| `20260605T211502Z`: 56/63/64/72 workers | Best 72 workers: 89.37% |
| `20260605T211616Z`: receive ceiling 64 MiB | 61.02% |
| `20260605T211704Z`: batch 128 | 87.69% |
| `20260605T211826Z`: all-CPU pinning | 88.94% |
| `20260605T211910Z`: 72-worker rate sweep | 4.0M/4.25M ~99.998%; 4.5M 92.38%; 4.75M 58.83% |
| `20260605T212028Z`: bracket | 4.35M 96.58%; 4.40M 71.19% |
| `20260605T214542Z`: 72 workers in completion-IRQ CPU order | 4.35M 91.03%; 4.40M 95.45%; 4.50M 75.38%; 4.8M 90.71% |
| `20260605T214657Z`: 63 workers on 63 completion-IRQ CPUs | 4.25M 98.99%; 4.35M 86.21%; 4.50M 92.32%; 4.8M 81.37% |
| `20260605T214824Z`: RX ring 4096 | 4.50M 98.80%; lower rates regressed; 4.8M 88.85% |
| `20260605T214943Z`: `adaptive-rx off rx-usecs 0 rx-frames 1` | RX errors disappeared but traffic fell to ~15.8M packets/5 s; reply rate ~77–79% |
| `20260605T215114Z`: RPS over CPUs 0–71 | 4.25M 89.28%; 4.8M 67.17%; new softnet drops/time-squeeze |
| `20260605T221215Z`, `20260605T221553Z`: perf | Too intrusive for QPS comparison; syscall return, recvmmsg, kernel UDP enqueue/receive and send work dominated |
| Reduced-counter observations | ~3 datagrams per successful recvmmsg; counters themselves depressed rate |
| `20260605T222216Z`: 72-worker, 4.35M diagnostic | All workers active, max/mean within ~6.3%; ~5.73M successful receive syscalls and ~103.8M empty polls/5 s |
| `20260605T222310Z`: park | Worse than spin |
| `20260605T222548Z`: short-spin then yield | Worse; experiment rejected |

The recorded server had 63 combined queues, four-tuple UDP RSS, completion
IRQs for `0000:19:00.0` spread over CPUs `0,2,...,70,1,3,...,53`,
RPS disabled, and per-queue XPS. The retained baseline restored RX ring 1024
and adaptive RX coalescing. The evidence pointed to receive-loop cost rather
than reuseport imbalance; it motivated the AF_XDP work.

## AF_XDP: initial server and requester corrections

The 630k-packet BoronGun trials below used requester wakeup interval 4.
They preceded the removal of an unconditional server TX `poll_write`.

| Artifact | Server setting / positive replies |
| --- | --- |
| `knot-xdp-oxidegun-wakeup4-630k-20260606T011511Z` | Knot reference: 591585 |
| `oxidegun-xdp-serverwakeup4-shortknot-latency-630k-20260606T012743Z` | Wakeup 4: 570479 |
| `oxidegun-xdp-serverwakeup8-shortknot-latency-630k-20260606T012840Z` | Wakeup 8: 592332 |
| `oxidegun-xdp-serverwakeup8-repeat-latency-630k-20260606T012916Z` | Wakeup 8 repeat: 571061 |
| `oxidegun-xdp-serverwakeup1-shortknot-latency-630k-20260606T012946Z` | Same-binary wakeup 1: 574223 |
| `oxidegun-xdp-nocounters-serverwakeup1-630k-20260606T013355Z` | Counter-free redirect objects, wakeup 1: 579837 |
| `knot-xdp-nocounters-oxidegun-wakeup4-630k-20260606T013446Z` | Same counter-free requester, Knot: 607583 |
| `oxidegun-xdp-nocounters-serverwakeup8-630k-20260606T013549Z` | Counter-free, wakeup 8: 572831 |
| `oxidegun-xdp-rxdrain2-nocounters-630k-20260606T014722Z` | RX drains 2: 574681 |
| `oxidegun-xdp-rxdrain4-nocounters-630k-20260606T014806Z` | RX drains 4: 567271 |

Unused redirect counters were removed; RX drain passes stayed at 1.
After removing unconditional server TX polling, kxdpgun copy-mode rows were:

| Artifact / offered rate | Knot responses/s | BoronDNS responses/s | Reply % / setting |
| --- | ---: | ---: | --- |
| `20260606T015447Z` / 630k | 629869 | 629848 | Both 99.998413%; wakeup 1 |
| `20260606T015652Z` / 900k | 899740 | 899751 | Both 99.998422%; wakeup 1 |
| `20260606T015741Z` / 1.2M | 1199750 | 1199614 | Wakeup 1 |
| `20260606T015831Z` / 1.2M | — | 1199627 | Wakeup 4 |
| `20260606T015903Z` / 1.2M | — | 1199799 | Wakeup 8 |
| `20260606T015938Z` / 1.2M | 1199613 | 1199624 | Both 99.998417%; wakeup 8 |

The first project-requester runs found that an explicit 53000–53062 source-port
range disabled prebuilt templates and capped sending at one 4096-descriptor
TX-ring fill per queue. The requester also needed TX polling on zero-descriptor
sends. Sleeping through paced waits then starved reply drain:

| Artifact/trial | Result |
| --- | --- |
| `20260606T021325Z`: Knot XDP | 13.255288% replies |
| `20260606T021449Z`: requester RX drains 64 | 12.183415% replies |
| RX drain during paced waits; `20260606T022205Z`, 900k | Knot 891911/s at 100.000000%; BoronDNS 891732/s at 99.999114% |
| `20260606T022319Z`, 1.2M | Knot 1183863/s, BoronDNS 1184869/s; both 100.000000% |

RX drain during pacing was kept. The requester added
`send_duration_seconds` so final drain time did not dilute measured rates.

## AF_XDP: reverse queue counts and locating loss

The reverse server had 63 RX queues; its requester had 48. The server needed
all queues reachable by RSS, independent of the requester's queue count.

| Artifact/trial | Result |
| --- | --- |
| `20260606T022927Z`: requester assumed 63 queues | Failed because requester queue 48 did not exist |
| `20260606T023020Z`: requester 48, server only 48 | Artificial ~75% ceiling; RSS still reached unbound server queues |
| `20260606T023338Z`: server 63; requested 1.2M | Knot 1187197/s at 100.000000%; BoronDNS 1185281/s at 99.942922% |
| `20260606T023606Z`: server batch 512, wakeup 1 | BoronDNS 1186135/s at 100.000000% |
| `20260606T024404Z`: auto-queue check | Retained `boron_gun_effective_queue_count=48` |
| `20260606T023643Z`: requested 1.5M | Knot 1478476/s at 99.992577%; BoronDNS 1476928/s at 100.000000% |
| `20260606T023745Z`: requested 2M | Knot 1966958/s at 99.878854%; BoronDNS 1965472/s at 99.991203% |
| `20260606T023846Z`: requested 2.5M | Effectively tied; Knot slightly ahead on rate and reply percentage |
| `20260606T025324Z`: reduced metrics | Server RX/TX admissions both 7407616; no parse errors, empty TX sends, or poll_write calls; 7407330 completions at scrape. Requester sent 7408640, received 7406592 |
| `20260606T025426Z`: batch 192 | 2452906/s at 99.990927% |
| `20260606T025459Z`: batch 224 | 2449503/s at 99.977184% |
| `20260606T030335Z`: final drain 3000 ms | 2454002/s at 99.995237%; 353 unanswered of 7410688 |
| `20260606T030430Z`: final drain 5000 ms | 2452074/s at 99.977453%; longer drain did not resolve the tail |
| `20260606T031149Z`: requester queue statistics | 7398982 replies from 7406592 sends; some queues received none, others ~2× their own sends |
| Cross-queue reply redirect prototype | Zero replies; rejected. The result was consistent with XSKMAP requiring the XSK's hardware RX queue |

Both NICs used MTU 1500 during these successful native-XDP tests and returned
to 9000 afterward. MTU explained failed setup elsewhere, but not this small
loss tail.

| Artifact/trial | Result |
| --- | --- |
| `20260606T034145Z`: per-target ports, server only 48 queues | 77.083247%; still failed to cover the 63-queue server |
| `20260606T034338Z`: 63 queues, wakeup 1 | Knot 2456673/s at 99.998824%; BoronDNS 2454930/s at 99.942036% |
| `20260606T035249Z`: transport counters retained with metrics off | 793 unanswered matched NIC `rx_out_of_buffer`; server RX/TX admissions both 12332263 |
| `20260606T041346Z`: jumbo-MTU zero-copy | Bind failed with EINVAL |
| `20260606T041857Z`: MTU 1500 calibration | 495049/s, 100.000000%; 512 source-port metrics. Old 48-port list reached only 27 server workers, up to 3 ports/worker |
| `20260606T042049Z`: list reaching 48 distinct workers | Knot 2456814/s at 99.999400%; BoronDNS 2454059/s at 99.898743%; distinct workers alone did not help |
| `20260606T042816Z`: single-port substitution | Invalid: local Knot primary could not bind TCP 5301; BoronDNS stayed LOADING |
| `20260606T043500Z`: prior list after cleanup fix | Knot 2455879/s at 100.000000%; BoronDNS 2457000/s at 99.994033%; ports 53496/53501 lost 736 replies, matching `rx_out_of_buffer` |
| `20260606T043655Z`: UMEM 32768 alone | 99.979601% |
| `20260606T043819Z`: ring 8192 alone | BoronDNS-only 100.000000%; paired `20260606T043912Z` fell to 99.988168% |
| `20260606T044042Z`: ring 8192 + UMEM 32768 | BoronDNS-only 99.999951% |
| `20260606T044138Z`: same capacity, Knot first | BoronDNS 99.932622% |
| `20260606T044354Z`: same capacity, BoronDNS first | BoronDNS 99.985772%; Knot 99.998395% |
| `20260606T044810Z`, `20260606T044913Z`: refill immediately after TX completion drain | Baseline 4096 rings: 99.990393%; 8192/32768: 99.991437%; prototype rejected |
| `20260606T045650Z`: per-worker counters | 2455876/s, 99.960788%; RX/TX admissions both 12328220; 27/63 workers active, 256000–772096 packets/worker |
| `20260606T050523Z`: paired run | Knot completed; following BoronDNS row could not start primary on TCP 5301 |
| `20260606T050912Z`: targeted row cleanup | Knot 2457197/s, 100.000000%; BoronDNS wakeup 8: 2454981/s, 99.998044% |
| `20260606T051026Z`: opposite order | BoronDNS 2456094/s, 99.972494%; Knot 100.000000% |
| `20260606T051129Z`: wakeup 4 | 99.932661% |
| `20260606T051211Z`: wakeup 16 | BoronDNS-only 100.000000%; paired `20260606T051259Z`: BoronDNS 99.974414%, Knot 99.997892% |
| `20260606T052125Z`: no explicit fill wakeups | 2455605/s, 99.983648% |
| `20260606T052209Z`: fill wakeup interval 16 | 2454457/s, 99.885465%, 2068 parse errors |
| `20260606T052254Z`: normal fill behavior plus new counters | 2454423/s, 99.929599%; fill-wakeup/counter experiment rejected |

Recorded-PID cleanup and row-local cleanup were kept to prevent failed
benchmark processes retaining ports or XDP state. AF_XDP transport counters
were retained even with metrics `off`. Their “sent” value means TX-ring
admission, not delivery; kick failures have the separate
`borondns_af_xdp_tx_delivery_failures_total` counter.

## Calibrated source-port lists

Lists are specific to host role, server target port, NIC RSS state, and
requester queue order. They are retained for reproducibility, not as defaults
for another host.

The reverse selection from `20260606T041857Z` used 48 requester queues and
48 server workers, one port per active queue/worker:

```text
53321,53072,53133,53397,53243,53132,53310,53105,53082,53036,53453,53204,53118,53410,53000,53113,53088,53125,53185,53342,53208,53399,53110,53095,53244,53130,53358,53327,53111,53305,53426,53163,53487,53401,53299,53345,53206,53152,53015,53349,53061,53364,53296,53199,53220,53237,53020,53052
```

| Reverse artifact/order | Result |
| --- | --- |
| `20260606T052658Z`: BoronDNS only | 2456483/s, 100.000000%; 48 active workers, 256000–258048 packets/worker |
| `20260606T052751Z`: Knot first | Knot 2457093/s, 99.983058%; BoronDNS 2454219/s, 100.000000% |
| `20260606T052910Z`: BoronDNS first | BoronDNS 2456797/s, 100.000000%; Knot 2454823/s, 99.980519% |

Forward BoronDNS calibration `20260606T053738Z` measured 495954/s at
100.000000%. It selected 63 requester queues and 48 server workers, at most
two ports per server worker:

```text
53079,53159,53262,53600,53099,53376,53726,53248,53105,53432,53288,53225,53360,53073,53408,53588,53399,53603,53628,53244,53445,53401,53685,53409,53040,53167,53353,53533,53122,53653,53642,53058,53170,53032,53130,53345,53046,53044,53349,53140,53336,53421,53505,53548,53001,53410,53644,53116,53351,53295,53368,53017,53270,53626,53061,53087,53711,53388,53165,53300,53530,53254,53544
```

Forward Knot port-5301 calibration `20260606T053906Z` measured 496257/s at
100.000000%, selecting 63 requester queues:

```text
53007,53089,53029,53011,53136,53075,53015,53003,53143,53076,53008,53004,53157,53094,53026,53054,53024,53081,53021,53052,53010,53078,53141,53006,53013,53073,53138,53001,53031,53091,53152,53051,53016,53084,53151,53005,53009,53077,53142,53055,53019,53087,53148,53048,53028,53088,53155,53002,53014,53074,53035,53000,53139,53072,53012,53050,53145,53082,53022,53053,53158,53093,53025
```

At requested 1.2M, both forward orders returned 100.000000%:
`20260606T054454Z` measured Knot 1186767/s and BoronDNS 1186917/s;
`20260606T054612Z` measured BoronDNS 1187820/s and Knot 1186803/s.

## Forward requester: pacing and TX completion

The calibrated forward list worked at lower rates, but early requested-2.5M
rows often sent only about 2M actual QPS. These trials separated that requester
limit from server DNS cost.

| Artifact/trial | Result |
| --- | --- |
| `20260606T055210Z`: requested 1.8M | Both 100.000000%; Knot 1770170/s, BoronDNS 1768573/s |
| Wakeup 1/4/16 at 1.8M, unlabelled | BoronDNS 1769056 / 1767983 / 1769979 responses/s |
| `20260606T054110Z`: requested 2.5M | Knot 2002643/s at 99.344390%; BoronDNS 1915610/s at 98.907538%. Actual requester rates ~2.02M and ~1.94M |
| `20260606T054357Z`: 48-port/48-queue requester | Perfect server balance, only 76.973998% replies |
| `20260606T054928Z`: absolute-deadline pacer | Server queued 12200233 replies, but both servers retained only ~60%; requester RX starved |
| `20260606T055048Z`: RX drains 64 with that pacer | 63.255592% |
| `20260606T060112Z`: pace-wait fraction 0.875 | 1957581/s, 97.625263% |
| `20260606T060137Z`: fraction 0.75 | 1956853/s, 95.454946% |
| `20260606T060202Z`: fraction 0.625 | 1907030/s, 89.960603% |
| `20260606T055803Z`: requester batch 512 | 1953259/s, 98.507922% |
| `20260606T055828Z`: requester batch 256 | 1944505/s, 98.810773% |
| `20260606T060423Z`: final drain 3000 ms | 1960352/s, 98.841880% |
| `20260606T060449Z`: server ring/UMEM 8192/32768 | 1931262/s, 98.401731% |
| `20260606T060944Z`: elapsed-aware pacer, minimum drain fraction 0.5 | 1951746/s, 94.338649%; rejected |
| `20260606T061009Z`: minimum drain fraction 0.25 | 1872723/s, 90.398396%; rejected |
| `20260606T061301Z`: weight calibration `053738Z` with `054110Z` TX counts | Modeled maximum server weight 344064→299008; 1984720/s, 99.161520% |
| `20260606T061429Z`: reweight from previous row | 1963786/s, 99.082266% |
| `20260606T062221Z`: first weighted list, NIC counters | 1974391/s, 99.080636%; requester submitted 10017792, PHY TX 9925696, server RX/TX admissions 9925692. Submission–PHY gap 92096 matched 92100 unanswered; no PHY discards/oversize |
| `20260606T062634Z`: requester completion counters | 1956164/s, 99.205756%; 9912320 submissions, 9577445 dequeued completions, 334875 outstanding, PHY TX 9833596 |
| `20260606T063620Z`: bounded final TX kick/dequeue | 1996807/s, 99.998747%; submissions 10054656, PHY TX 10054662, server RX 10054530, 126 unanswered |
| `20260606T063825Z`: same-requester pair | Knot 1998934/s, BoronDNS 1970490/s; both 100.000000% |
| `20260606T063946Z`: server wakeup 16 | 1997976/s, 100.000000% |
| `20260606T064033Z`: wakeup 32 | 1980765/s |
| `20260606T063730Z`: reweight cleaned list | 1950940/s, 100.000000%; worse |
| `20260606T064300Z`: wakeup 16, Knot first | Knot 1976298/s; BoronDNS 1982288/s; both 100.000000% |
| `20260606T064408Z`: wakeup 16, BoronDNS first | BoronDNS 1975927/s; Knot 1950136/s; both 100.000000% |

The final requester flush was kept: it removed the earlier 80k–90k missing
requests from the denominator. TX-completion lag was larger than that gap, so
completion counts remained a frame-reclamation signal rather than a physical
TX counter. The relative paced-wait design stayed; shortening its default 1.0
wait fraction or using deadline catch-up starved RX.

## Reverse receive path: fill capacity and full-batch refill

With the requester flush fixed, reverse losses correlated with server
RX/fill shortage.

| Artifact/trial | Result |
| --- | --- |
| `20260606T064802Z`: ring/UMEM 4096/16384 | Knot 2456713/s, 99.982406%; BoronDNS 2452517/s, 99.906255%. All 12322816 requester TX packets completed; server `rx_xsk_buff_alloc_err=6846`, `rx_out_of_buffer=9289` |
| `20260606T065117Z`: 8192/32768, wakeup 16 | Knot 2457188/s, 99.988122%; BoronDNS 2454751/s, 99.991690%. 1024 unanswered matched `rx_out_of_buffer` |
| Larger 16384/65536 capacity, unlabelled | 2453818/s, 99.997662%; no rate improvement |
| `20260606T071132Z`: refill before returning a full RX batch | BoronDNS-only 2456286/s, 100.000000% |
| `20260606T071226Z`: same change, Knot first | Knot 2458300/s, 99.998444%; BoronDNS 2456011/s, 100.000000% |
| `20260606T070302Z`: reverse list recalibration | Confirmed prior list already used one port per requester queue/active server worker |
| `20260606T070416Z`: new 48-port list | 2454957/s, 100.000000%; slightly worse |
| Server limited to 48 workers, unlabelled | Invalid for the list: traffic reached queues above 47; 87.494803% |
| `20260606T072347Z`: only calibrated 48 sparse queues, sorted | 2454072/s, 100.000000% |
| `20260606T072440Z`: sparse queues in source-port order | 2455770/s, 100.000000%; retained contiguous 63-queue profile |
| `20260606T070506Z`: wakeup 32 | 2453259/s, 99.969691% |
| Workstation `target-cpu=native` build | Failed on Intel reverse host with Illegal instruction |
| Explicit `target-cpu=skylake-avx512`, unlabelled | Compatible but 2453199/s, 99.969088%; no gain |
| `20260606T071525Z`: forward replay with `064300Z` list and refill change | 2015954/s, 100.000000% |

Full-batch refill was kept. It exposed spare UMEM frames while userspace
composed the current batch. MTU remained a setup requirement: successful native
rows used 1500 and restored 9000; these losses instead tracked RX-fill counters.

## Zero-copy: requester bursts and forward port repairs

| Artifact/trial | Result |
| --- | --- |
| `20260606T073704Z`: reverse requester zero-copy forced, batch 1024 | Knot 2447952/s, 99.813565%; BoronDNS 1946130/s, 79.431881%. All requester TX completed, but server RX 9851056, `rx_xsk_xdp_drop=2299123`, plus pause frames |
| `20260606T073956Z`: requester batch 64, Knot first | Knot 2359830/s, 99.990240%; BoronDNS 2369759/s, 100.000000% |
| `20260606T085700Z`: BoronDNS first, old requester | BoronDNS 2369246/s, 99.999460%; Knot 2364411/s, 100.000000% |
| `20260606T085831Z`: repeat | BoronDNS 2368449/s, 99.995138%; Knot 2370729/s, 100.000000% |
| `20260606T090123Z`: rebuilt requester, BoronDNS first | BoronDNS 2363658/s; Knot 2362726/s; both 100.000000% |
| `20260606T090249Z`: rebuilt requester, Knot first | Knot 2363575/s; BoronDNS 2370320/s; both 100.000000% |

The rebuilt requester plus batch 64 was selected for reverse zero-copy rows.
The rate margin was small, despite both recorded orders returning all replies.

Forward zero-copy experiments used the 48-server/63-requester queue shape:

| Artifact/trial | Result |
| --- | --- |
| `20260606T080632Z`: 48 calibrated sparse requester queues | 2288619/s, 100.000000%; server workers tightly spread at 236224–241984 packets |
| `20260606T080851Z`: 56 queues | 2317499/s, 100.000000% |
| `20260606T080942Z`: 60 queues | 2321292/s, 100.000000% |
| `20260606T075217Z`: Knot reference | 2349033/s, 100.000000% |
| `20260606T082354Z`: earlier 63-flow high-rate list, capacity 8192/32768 | BoronDNS-only 2404179/s, 100.000000% |
| `20260606T082449Z`: Knot first | Knot 2341327/s; BoronDNS 2400687/s; both 100.000000% |
| `20260606T082612Z`: BoronDNS first | BoronDNS 2393526/s, 99.997862%; Knot 2401280/s, 100.000000%. Requester queues 5/41 each missed 128 replies; both mapped to server worker 40 |
| `20260606T083657Z`: replace queue-5 port 53727→53087; BoronDNS first | BoronDNS 2398763/s; Knot 2397750/s; both 100.000000% |
| `20260606T084306Z`: repaired list, Knot first | Knot 2367847/s; BoronDNS 2402461/s; both 100.000000% |
| More aggressive repairs, unlabelled | Cleared loss but lowered BoronDNS to 2.30–2.34M responses/s |
| `20260606T085330Z`: selector repair 53727→53205 | BoronDNS 2326578/s; Knot 2362108/s; both 100.000000% |

The forward selection kept 8192/32768 capacity and the queue-5 repair to
53087. Port weighting, not simply the number of active workers, mattered.
All these successful native-XDP rows used MTU 1500; there was no evidence
that multi-buffer or further MTU work would help these small packets.

## Packaged Knot versus source-built Knot

The recorded Ubuntu Knot 3.5.3 package reported `XDP support: libxdp` but
rejected `xdp.zero-copy`. Its rows omitted that option and retained
`knot-version.txt` plus `server-bpftool-net-*-benchmark.txt`.
The source build at `/home/codex/knot-xdp-3.5.4/sbin/knotd` reported
`--enable-xdp=yes`, `XDP support: libxdp`, and accepted `zero-copy: on`.

The packaged comparison used BoronDNS commit `acd8c7fb`, rebuilt BoronGun,
the high-rate port list, forced requester zero-copy, server 8192/32768,
batch 1024, and wakeup 16.

| Artifact/order | BoronDNS responses/s | Knot responses/s | Result |
| --- | ---: | ---: | --- |
| `20260606T191956Z`, BoronDNS first | 2399795 | 2337671 | Both 100.000000%, packaged Knot |
| `20260606T192112Z`, Knot first | 2402522 | 2331951 | Both 100.000000%, packaged Knot |
| `20260606T191530Z`, untuned default port list | — | — | Order-sensitive loss |
| `20260606T191831Z`, low-rate calibration list | — | — | Lossless but slower than Knot |
| `20260606T194258Z`, BoronDNS first | 2328733 | 2345938 | Both 100.000000%, source-built Knot |
| `20260606T194416Z`, Knot first | 2325380 | 2366863 | Both 100.000000%, source-built Knot |

The source-built result reversed the packaged comparison. Subsequent tuning
therefore used source-built Knot with zero-copy enabled.

## Source-built comparison: repeated rows and profiling

The repeat wrapper tested both run orders at requested 2.5M:

| Artifact/order | BoronDNS responses/s | Knot responses/s | Reply result |
| --- | ---: | ---: | --- |
| `20260606T200457Z`, BoronDNS first | 2356012 | 2399713 | No loss noted |
| `20260606T200627Z`, BoronDNS first | 2346111 | 2400083 | BoronDNS 99.998909%; qdisc, softnet and requester PHY drops zero |
| `20260606T200541Z`, Knot first | 2405783 | 2367680 | Both 100.000000% |
| `20260606T200713Z`, Knot first | 2404190 | 2390959 | Both 100.000000% |
| Four-row average | 2378024 | 2389609 | Not a lossless, order-independent win |

Process-PID perf missed the worker threads. System-wide `cpu-clock` on the
unstripped binary at `/home/codex/borondns-tools/xdp-profile/borondns`
captured 22458 samples in `20260606T201444Z`. Most CPUs were idle.
Visible worker costs were `DomainName::parse_with_ascii_lowercase`,
`udp::handle_udp_datagram`, `af_xdp::write_udp_ip_response`,
`af_xdp::parse_udp_ip_frame`, ZoneImage lookup, hashing, and allocation/free.
That row missed 128 requester replies despite equal server RX/TX-admission
counts, so the next experiments tested transport/drain settings.

| Artifact/trial | Result |
| --- | --- |
| `20260606T201657Z`: final requester drain 1000→2000 ms | Reply loss cleared; BoronDNS still narrowly behind |
| `20260606T201900Z`, `20260606T201948Z`, `20260606T202045Z`, `20260606T202143Z`: server batch 1024, wakeup 8, drain 2000 ms | All 100.000000%; BoronDNS average 2395169/s, Knot 2389879/s, but BoronDNS lost the Knot-first average |
| `20260606T202300Z`: batch 512, Knot first | Knot 2354014/s; BoronDNS 2394584/s |
| `20260606T202348Z`: batch 512, BoronDNS first | BoronDNS 2404016/s; Knot 2398056/s |
| `20260606T202500Z`: repeat, BoronDNS first | BoronDNS 2406179/s; Knot 2401377/s |
| `20260606T202558Z`: repeat, Knot first | Knot 2396931/s; BoronDNS 2401565/s |
| RX-readiness wait in final drain; `20260606T203907Z`, `20260606T203953Z`, `20260606T204220Z`, `20260606T204306Z` | Reducing drain back to 1000 ms still returned 100.000000% in both orders; throughput stayed within the same noisy band |

All four batch-512 comparison rows returned 100.000000% with no
requester/server PHY discards or softnet drops. The historical selection was
server batch 512, wakeup 8, requester drain 2000 ms. RX-readiness waiting was
kept as a measurement-quality fix, not claimed as a server-rate improvement.

## Source-built comparison: rejected optimization prototypes

The symbolized `20260606T210427Z` row used commit `136a4a9d` and measured
2403738/s at 100.000000%. System-wide CPU-clock captured 240256 samples, none
lost. Idle CPUs dominated; worker costs remained DNS name parsing, malloc/
cfree, UDP dispatch, frame parse/rewrite, ZoneImage lookup, and hashing.

| Artifact/trial | Recorded result / decision |
| --- | --- |
| `20260606T210755Z`: server batch 384 | 2290696/s, 100.000000% |
| `20260606T210824Z`: batch 640 | 2329985/s, 100.000000% |
| `20260606T210855Z`: batch 768 | 2402146/s, 100.000000%; no demonstrated improvement over 512 |
| `20260606T210954Z`: `LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2` | 2331010/s, 100.000000%; rejected |
| `20260606T213040Z`: reusable direct-answer buffers, BoronDNS first | BoronDNS 2365876/s; Knot 2393271/s; both 100.000000% |
| `20260606T213130Z`: buffer reuse, Knot first | Knot 2403218/s; BoronDNS 2399560/s; both 100.000000%; prototype rejected |
| `20260606T224214Z`: direct-to-frame, BoronDNS first | BoronDNS 2319432/s; Knot 2400236/s; both 100.000000% |
| `20260606T224312Z`: direct-to-frame, Knot first | Knot 2371387/s; BoronDNS 2322708/s; both 100.000000%; prototype rejected |
| `20260606T233413Z`: fixed 65-byte DNS answer | BoronDNS 2330077/s, 99.996705%; Knot 2400926/s, 100.000000% |
| `20260606T233500Z`: fixed answer, other order | Knot 2366292/s; BoronDNS 2390161/s; both 100.000000%; no clear higher ceiling |
| `20260606T233726Z`: system perf on both servers | Captured both rows successfully |
| `20260606T234106Z`: process-PID perf | No samples from either server |
| `20260606T233949Z`: symbolized BoronDNS profile | Name parsing, dispatch, malloc/free, child lookup, IPv4 response rewrite, frame parse |
| `20260607T003449Z`: separate TX frame, BoronDNS first | BoronDNS 2290109/s; Knot 2316556/s; both 100.000000% |
| `20260607T003547Z`: separate TX frame, Knot first | Knot 2400258/s; BoronDNS 2349159/s; both 100.000000%; rejected |
| `20260607T004311Z`: borrowed RX payload, BoronDNS first | BoronDNS 2361280/s; Knot 2389869/s; both 100.000000% |
| `20260607T004358Z`: borrowed RX payload, Knot first | Knot 2367170/s; BoronDNS 2399427/s; both 100.000000%; no clear gain |

The buffer-reuse prototype recycled caller-owned response buffers while
retaining the fallback composer. Direct-to-frame composition copied the request
aside and wrote an answer into the RX UMEM frame. Separate-frame TX allocated
a reply frame, copied headers/data, returned RX early, and fell back to
same-frame rewrite on allocation failure. Borrowed RX parsed directly from
retained UMEM rather than copying into `UdpInbound`. These candidates passed
their local tests/builds before physical comparison; none was kept as a proven
throughput gain.

The fixed-answer diagnostic used
`BORONDNS_BENCH_AF_XDP_FIXED_RESPONSE=1` in that experimental binary. It
bypassed DNS parsing/lookup, RRL, cookies, TSIG, and normal composition, patched
the query ID into a one-record answer with minimal OPT, and retained normal
UDP/IP rewrite. It was not production DNS behavior. Its limited improvement
suggested transport/requester orchestration dominated this profile.
The legacy environment activation has since been removed; setting this
variable in current builds does not bypass normal DNS handling.
Knot's system profile exposed `knot_xdp_recv`, `knot_xdp_send`,
`knot_xdp_reply_alloc`, lookup and packet assembly. Its
prepare/receive/reply-allocate/receive-finish/send/send-finish lifecycle
motivated the separate-frame experiment above.

Final transport sweeps on the restored same-frame baseline were also mixed:

| Trial/artifact | Result |
| --- | --- |
| RX drain 1; wakeup 1/4/8/16, unlabelled | 2400911 / 2401046 / 2350451 / 2398508 responses/s; all 100.000000% |
| Wakeup 4; RX drain 1 | 2402028/s, 99.996804% |
| Wakeup 4; RX drain 2 | 2405111/s, 99.999468% |
| Wakeup 4; RX drain 4 | 2401901/s, 99.996804% |
| Wakeup 4; RX drain 8 | 2346102/s, 99.990184% |
| `20260607T005018Z`: drain 2/wakeup 4, BoronDNS first | BoronDNS 2401846/s, 99.997869%; Knot 2398198/s, 100.000000% |
| `20260607T005117Z`: same, Knot first | Knot 2374210/s, 100.000000%; BoronDNS 2398918/s, 99.998400% |

Those higher-rate settings spent reply percentage and were not selected.
Current wakeup validation has since superseded the historical cadence axis.

## Original reference profile and measurement semantics

The comparison design was based on the then-recorded Knot response-rate
benchmark: two directly connected 40GbE servers, AMD EPYC 7702P, Intel XL710,
SMT disabled, 64 cores/queues/threads for UDP, 16 for TCP, 15-second UDP
windows, and `CFLAGS="-O2 -g -DNDEBUG"`. Its source workflow used a
controller, target, and player; server threads were pinned, connection tracking
disabled, and Knot used reuseport, socket affinity, and minimal responses.

The source-derived NOERROR mix selected unique NS, DS, A, AAAA, PTR, MX, SOA,
and DNSKEY records. The recorded player command was:

```bash
sudo kxdpgun -t "$duration" -p "$PORT" -b 10 -Q "$rate" -i "$querydb" "$target" $KXDPGUN_OPTS
```

Recorded kxdpgun behavior: XDP send/receive; threads detected from combined
NIC queues; aggregate QPS divided across threads; affinity default `0s1`;
UDP batch 10; source ports 2000–65535; `--local ip/prefix` for source
rotation; query input `qname qtype [flags]`, with E for EDNS and D for
EDNS+DO. It counted replies/rcodes without fully matching every response to
its query. Plain logs carried average reply size and L2/L1 throughput; L1
added 20 bytes/packet. The recorded JSON output lacked those throughput fields.

## Historical configuration inventory

These example names use the `BORONDNS_PHYSICAL_` prefix unless written
in full. They record what the experiments controlled, not current defaults.

| Group | Recorded settings |
| --- | --- |
| Placement/NUMA | `WORKER_CPUS="0,2,4,..."`; `SERVER_PREFIX="numactl --interleave=all"` |
| Socket buffers | `SOCKET_BUFFER_BYTES=4194304`; `SOCKET_RECEIVE_BUFFER_BYTES=2097152`; `SOCKET_SEND_BUFFER_BYTES=4194304` |
| Host ceilings | `SERVER_RMEM_MAX=16777216`; `SERVER_WMEM_MAX=33554432` or `67108864` |
| Socket pacing | `SOCKET_MAX_PACING_RATE_BYTES_PER_SECOND=75000000`; plural sweep `SOCKET_MAX_PACING_RATES_BYTES_PER_SECOND="9000000 12000000"` |
| TX queues | `SERVER_TXQUEUELEN=5000`; `SERVER_TX_RING=4096`; `SERVER_TX_QDISC=fq` or `fq_codel`/`pfifo_fast` |
| fq | `SERVER_TX_FQ_LIMIT=50000` (default 10000); `SERVER_TX_FQ_FLOW_LIMIT=1000`; `SERVER_TX_FQ_QUANTUM=1514`; `SERVER_TX_FQ_INITIAL_QUANTUM=1514`; `SERVER_TX_FQ_PACING=nopacing` or `pacing` |
| UDP batch | `UDP_BATCH_SIZES="16 32 64"`; `staged` preserved the stage value |
| Detached socket repeat | `WORKERS=48`, `RATES="4750000 4800000"`, `UDP_BATCH_SIZES=64`, `SERVER_TX_QDISC=fq`, `SERVER_TX_FQ_LIMIT=50000`; started with `scripts/physical-udp-detached-batch.sh start` |
| Profiling | `SERVER_BIN=target/profiling/borondns`; `PERF_RECORD=true`; `PERF_SCOPE=process\|system`; `PERF_EVENT=cpu-clock`; `PERF_REPORT_TIMEOUT=30s`; `PERF_REPORT_CHILDREN=false` |
| Socket samples | `SOCKET_SAMPLE=true`; `SOCKET_SAMPLE_INTERVAL=0.25`; retained `ss -u -n -m` |
| References | `INCLUDE_KNOT=true`; `INCLUDE_KNOT_XDP=true`; `KNOT_BIN=/path/to/knotd` |
| Server XDP | `BORONDNS_UDP_BACKENDS="std af_xdp"`; `XDP_MODE=drv`; `XDP_ZERO_COPY=require`; `XDP_QUEUE_ID=0`; `XDP_RING_SIZE=8192`; `XDP_UMEM_FRAME_COUNT=32768`; `XDP_BATCH_SIZE=1024`; `XDP_RX_DRAIN_PASSES=1` |
| Historical wakeup | `XDP_TX_WAKEUP_INTERVAL=8`; now superseded by required value 1 |
| XDP binding | `XDP_REDIRECT_OBJECT`; sparse `XDP_QUEUE_IDS=0,1,...`; `XDP_RUN_AS_USER=codex`; `XDP_MTU=1500` |
| Knot XDP | `KNOT_XDP_ZERO_COPY=__omit__` or `on`; `KNOT_XDP_RING_SIZE=2048`; `KNOT_XDP_RUN_AS_USER=codex:codex` |
| Busy polling | `KNOT_XDP_BUSYPOLL_BUDGET`, `KNOT_XDP_BUSYPOLL_TIMEOUT`, `SERVER_NAPI_DEFER_HARD_IRQS`, `SERVER_GRO_FLUSH_TIMEOUT` |
| Requester mode | `KXDPGUN_MODE=auto\|copy\|generic`; `PLAYER_MTU=1500`; legacy `KXDPGUN_MTU=1500` |
| Order/readiness | `COMPARISON_RUN_ORDER=knot-first\|borondns-first`; `BORONDNS_READY_ATTEMPTS=180` at 250 ms (45 seconds); larger-run example 1200 (five minutes) |
| Repeat helper | `scripts/physical-xdp-source-knot-profile.sh`; `BORONDNS_SOURCE_KNOT_REPEATS=N`; `BORONDNS_SOURCE_KNOT_ORDERS="borondns-first knot-first"` |
| Requester | `PLAYER_TOOL=kxdpgun\|boron-gun`; `BORON_GUN_BIN`; `BORON_GUN_XDP_REDIRECT_OBJECT`; `BORON_GUN_QUEUE_COUNT=__auto__`; `BORON_GUN_XDP_BATCH_SIZE=64` |
| Recorded binaries | `$player_workdir/xdp-template-slice/boron-gun`; `$player_workdir/xdp-template-slice/boron-gun-xdp.bpf.o` |
| Link MACs | Source `b8:59:9f:4b:73:2c`; target `1c:34:da:60:67:00` |
| Port/queue lists | `BORON_GUN_SOURCE_PORT_LIST`, target-specific `BORON_GUN_KNOT_SOURCE_PORT_LIST`/`BORON_GUN_BORONDNS_SOURCE_PORT_LIST` and matching `*_QUEUE_LIST`; auto ports started at 53000 |
| Requester timing | Diagnostic `BORON_GUN_XDP_PACE_WAIT_FRACTION=0.875`; `BORON_GUN_RESPONSE_TIMEOUT_MS=1000` |

Source-port selection used `scripts/select-boron-gun-source-ports.py` with
`--existing-list`, `--requester-only`, `--requester-weight-log`,
`--server-exact`, or `--repair-existing --repair-server-worker`.
Its paired `queue_list`/`source_port_list` outputs needed physical
validation. Supporting files included `metrics-after.prom`, BoronGun JSON
in `kxdpgun.log`, `host/player-link-tuning.txt`,
`server-link-tuning.txt`, and `server-tx-qdisc-after.txt`.
