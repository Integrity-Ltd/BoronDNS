# BoronDNS Reference Verification Profile

This is the hardware and workload baseline for the SRS quantitative performance
and resource targets. It is a test definition, not a claim that a release has
met those targets. Measurements on other hosts remain useful engineering
results; state their differences before comparing them with this baseline.

The [SRS](BoronDNS-Secondary-SRS-v1.0.0.md) section 5 owns the targets and
Appendix E points here for the profile. The [test plan](test-plan.md) owns
cadence. Release engineers collect results and the Architecture Owner reviews
them under the [verification roles](architecture.md#verification-responsibility-allocation).

## Reference Hardware Profile

| Component | Baseline |
| --- | --- |
| CPU | Dual Intel Xeon Gold 6230R: 26 physical cores / 52 threads per socket, 2.10 GHz base, up to 4.00 GHz turbo, AVX-512, 35.75 MB L3 per socket. |
| Memory | 192 GiB DDR4-2933 ECC, using all six memory channels per socket. |
| NUMA allocation | One socket for BoronDNS: 26 physical cores and 96 GiB RAM. The other socket handles the host/management workload. |
| Query network | Dedicated 25 Gbit/s interface, attached by SR-IOV VF or NIC passthrough. Reference NIC classes: Intel E810 (`ice`) or Mellanox ConnectX-5/6 (`mlx5`). |
| Management network | Separate host interface for operator access and monitoring; 1 Gbit/s is sufficient for this profile. It may also carry transfers. |
| Transfer network | Optional separate outbound interface for AXFR, IXFR, SOA polling, and XoT. |
| OS and kernel | Ubuntu 24.04 LTS or RHEL 9-compatible userspace with the selected Linux 6.x LTS kernel. Record the actual kernel; a distribution default that differs is a profile deviation. |
| Runtime | containerd 1.7+ with runc. Record another runtime as a deviation, rather than inferring equivalent performance. |
| Storage | NVMe SSD for the zone cache, OS/images, collected logs, and benchmark artifacts. |

Reserve the assigned CPU cores and memory node for the server during measurement.
Record IRQ affinity, SMT use, CPU frequency policy, container limits, socket
buffers, and backlog tuning. Use PTP or NTP and record clock skew; the profile's
cross-host clock-skew target is below 100 ms. Use a monotonic clock for durations.

The reference query path uses the standard UDP backend and does not use XDP.
The official binary includes AF_XDP as an experimental opt-in backend, but an
AF_XDP result is a separate variant and must identify the NIC, driver, queue
configuration, and copy/zero-copy mode.

### Server Configuration

The example configuration is a starting point, not a tuned benchmark setup.
Current defaults use `limits.udp_backend = "std"`,
`udp_runtime = "tokio"`, one reuseport worker, and batch size 1. A run intended
to use all assigned cores must record its chosen worker/runtime/affinity settings;
a one-worker result does not establish host-wide capacity.

The `BDS-NFR-PERF-001` baseline enables metrics with a 10-second scrape interval,
uses `info` logging, and keeps RRL accounting enabled. Retain the full redacted
effective configuration, including RRL rates and source-prefix distribution,
cookie policy, publication strategy, and socket settings. Record slips, drops,
and errors as well as successful answers so limiting cannot be mistaken for
useful throughput.

The supported secondary profile also requires a writable
`server.zone_cache_directory`. Transfers persist validated last-good checkpoints
and incremental journals there; query serving does not access the filesystem.
Record the cache filesystem/mount options and whether measurements cover warm
queries, AXFR/IXFR persistence, restart restoration, or a combination. Turning
off persistence changes the tested deployment and must be stated as a deviation.

## Reference Query Mix

### Zone Corpus

The unsigned baseline has 100,000 records in the following data mix, plus the
required apex SOA. Include apex NS records in the NS allocation and record the
actual total RR count.

| Type | Count | Share of data records |
| --- | ---: | ---: |
| A | 50,000 | 50% |
| AAAA | 25,000 | 25% |
| MX | 10,000 | 10% |
| NS | 5,000 | 5% |
| TXT | 5,000 | 5% |
| SRV | 5,000 | 5% |

Use two-, three-, and four-label names below one apex, deeper delegation names,
and approximately 100 wildcard owners. Retain the generator seed or corpus
digest so the same data can be reconstructed.

For the `BDS-NFR-PERF-008` DNSSEC variant, sign the same data with NSEC denial
records. Record the signing algorithm (Ed25519 or RSA-SHA-256), key size where
applicable, and resulting total record count and response sizes. NSEC3 is a
separate performance variant: record its hash parameters, including iterations
and salt, plus the server's configured NSEC3 iteration cap.

### Query Distribution

| Property | Baseline |
| --- | --- |
| QNAME | Zipfian: about 80% of queries target the top 5% of names. Record the exact Zipf parameter. |
| QTYPE | 60% A, 25% AAAA, 5% MX, 5% NS, 5% TXT/SRV weighted by corpus presence. |
| Sources | At least 100,000 simulated addresses across IPv4 /24 and IPv6 /56 prefixes; no single address generates more than 0.01% of volume. Record both address and prefix distribution. |
| EDNS | OPT payload size 1232, DO=0. DNSSEC variants use DO=1. |
| Cookies | No COOKIE option in baseline traffic. Cookie variants separately test client-cookie-only, valid-server-cookie, and invalid-server-cookie requests. |

### Named Variants

| Variant | Workload and requirement |
| --- | --- |
| Baseline | UDP, no query TSIG, DO=0. `BDS-NFR-PERF-001..003`. |
| TCP-pipelined | Same name/type distribution, 32 in-flight queries per connection, 1,000 source connections. `BDS-NFR-PERF-006`. |
| TSIG-load | Controlled HMAC-SHA256 signed NOTIFY traffic. `BDS-NFR-PERF-007`. |
| DNSSEC-augmented | NSEC-signed corpus and DO=1. `BDS-NFR-PERF-008`. |
| Cookie-enabled | Baseline/no-cookie and the three cookie cases above, reported separately. |

AXFR ingestion (`BDS-NFR-PERF-004`) and process initialization
(`BDS-NFR-PERF-005`) use the scenarios defined by those requirements. IXFR
scaling and simultaneous query load are additional engineering scenarios; they
must not be mislabeled as the TCP target in `BDS-NFR-PERF-006`.

## Verification Recordkeeping

Retain the following for each claimed performance or resource result:

- release, commit, binary digest, build features, and software/tool versions;
- hardware, NIC/driver, NUMA/CPU allocation, limits, and tuning;
- full redacted configuration and the primary version/configuration where used;
- workload variant, corpus identity, generator seed, and command line;
- warm-up, measurement duration, offered load, completed QPS, errors/loss, and
  latency distributions, with in-process and end-to-end timings distinguished;
- resource samples, logs, metric snapshots, and generated summaries;
- each asserted requirement, measured value, profile deviation, and the reviewer's
  assessment of that deviation.

`scripts/capture-benchmark-handoff.sh` creates report formats and TSV schemas.
It does not execute the benchmark. See
[DNS Client Benchmark](dns-client-benchmark.md) for exploratory commands and the
[release evidence guide](release-evidence-guide.md) for retention and review.
Public release notes may link to canonical evidence instead of copying its tables.

Redact TSIG keys, TLS private keys, cookie secrets, and sensitive zone data before
sharing evidence; follow [SECURITY.md](../SECURITY.md) for a suspected vulnerability.

## Profile Changes

Review a change that affects conformance together with the SRS target it supports.
Historical measurements retain their original profile and configuration. Do not
silently compare a new workload or backend with an older result as if only the
server version changed.
