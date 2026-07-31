# BoronGen large-zone primary

BoronGen is the internal deterministic primary used to feed very large catalog
and member zones to BoronDNS without materialized zone files. Its design and
non-claims are owned by
[`boron-gen-design.md`](boron-gen-design.md).

Build and inspect a small default scenario:

```sh
cargo build --release -p boron-gen
cargo run -p boron-gen -- manifest \
  --profile registry-nsec3 \
  --names-per-zone 1000 \
  --nsec3-records-per-zone 1000
```

Start an unsigned local primary:

```sh
cargo run -p boron-gen -- serve \
  --listen 127.0.0.1:15353 \
  --profile registry-nsec3 \
  --origin load.borongen. \
  --catalog-origin catalog.borongen. \
  --names-per-zone 1000 \
  --nsec3-records-per-zone 1000
```

Catalog transfers in BoronDNS require TSIG. Supply the secret through the
environment so it does not appear in the process command line:

```sh
export BORON_GEN_TSIG_SECRET='c2VjcmV0LWZvci1hLXRlc3Q='
cargo run -p boron-gen -- serve \
  --listen 127.0.0.1:15353 \
  --tsig-name transfer-key. \
  --profile registry-nsec3 \
  --zones 16 \
  --names-per-zone 100000 \
  --nsec3-records-per-zone 100000
```

The same address and port serve UDP SOA polling and TCP SOA, AXFR, and
unchanged single-SOA IXFR responses. AXFR uses bounded messages and awaits each
TCP write, so increasing the generated corpus does not increase BoronGen's
retained zone memory.

The initial NSEC3 mode produces a sorted and fully linked synthetic hash ring.
It exercises BoronDNS denial-range indexing and lookup but does not claim that
the hashes are SHA-1 preimages of the ordinary generated owner names. Generated
RRSIG RDATA is structurally valid load-test material, not a cryptographic
signature.

Before using a corpus larger than the conservative production default, raise
both BoronDNS's configured transfer byte allowance and transfer message-count
allowance deliberately. Large runs belong in the checked systemd/cgroup harness
and should advance through calibrated sizes before the 32 GiB stage.

The bounded end-to-end harness builds both binaries, validates the generated
BoronDNS configuration, requires cgroup v2 and an active systemd-oomd, starts
separate transient units for BoronGen and BoronDNS, waits for readiness, and
retains manifests, binary SHA-256 hashes, source commit/status, logs, metrics,
the tracked source diff, hashes of every modified or untracked source file,
cgroup events, and memory samples. A
successful `registry-nsec3` run also makes a DNSSEC NXDOMAIN query and requires
an NSEC3 authority proof, exercising the compiled denial lookup rather than
only transfer parsing. It then uses BoronGun to issue a bounded UDP load against
that same DNSSEC NXDOMAIN path and requires at least 99% matching NXDOMAIN
responses with no client errors. Loopback alone is allowlisted from RRL in the
generated test configuration so this probe measures zone lookup rather than
intentional rate-limit drops. `BORON_LOAD_QUERY_PACKETS` and
`BORON_LOAD_QUERY_TARGET_QPS` control the probe. For `registry-nsec3`, the
harness also requires the publication log to report one indexed NSEC3 group
with no fallback group and requires the DNSSEC-augmented query metric to cover
the load:

```sh
BORON_LOAD_NAMES_PER_ZONE=1000000 \
BORON_LOAD_NSEC3_RECORDS_PER_ZONE=1000000 \
BORON_LOAD_MEMORY_HIGH=30G \
BORON_LOAD_MEMORY_MAX=32G \
scripts/boron-gen-bounded-load.sh
```

The harness defaults to `MemorySwapMax=0`, `OOMPolicy=stop`,
`ManagedOOMMemoryPressure=kill`, and an 80% systemd-oomd pressure limit. A
contained OOM or oomd kill is retained as a failed readiness test.

Allocator-containment testing is an explicit, separate outcome. Use a corpus
known not to fit, set the soft and hard limits equal so `MemoryHigh` throttling
does not turn the test into a long stall, and request the negative outcome:

```sh
BORON_LOAD_NAMES_PER_ZONE=100000 \
BORON_LOAD_NSEC3_RECORDS_PER_ZONE=100000 \
BORON_LOAD_MEMORY_HIGH=512M \
BORON_LOAD_MEMORY_MAX=512M \
BORON_LOAD_EXPECT_OUTCOME=contained-oom \
scripts/boron-gen-bounded-load.sh
```

This mode succeeds only when BoronDNS ends with systemd result `oom-kill` and
signal 9 while the independently bounded BoronGen unit remains active. Its
summary status is `contained_oom_as_expected`; it never claims service
readiness. The serialized 750 GiB campaign includes the same negative contract
as a distinct final row; positive capacity rows continue to request `ready`
and cannot be converted into containment passes after an OOM.

Focused follow-up campaigns can select exact serialized rows without changing
their definitions:

```sh
BORON_CAMPAIGN_SCENARIOS=10-registry-balanced-40m,11-registry-balanced-50m,12-registry-balanced-55m \
scripts/boron-gen-large-memory-campaign.sh plan
```

The query-performance runner normally drives an unlimited saturation load.
Set `BORON_GEN_PERF_TARGET_QPS_STEPS` to a strictly increasing comma-separated
list to run open-loop offered-load steps against the same published image.
Each step receives `BORON_GEN_PERF_REPETITIONS` measured repetitions. External
two-host coordination can impose the same list with
`BORON_COORD_TARGET_QPS_STEPS_OVERRIDE`; the effective and requested policies
are retained in the performance evidence.

The large-memory wrapper can set the server UDP data-plane configuration with
`BORON_CAMPAIGN_UDP_BATCH_SIZE`, `BORON_CAMPAIGN_UDP_REUSEPORT_WORKERS`,
`BORON_CAMPAIGN_UDP_RUNTIME`, `BORON_CAMPAIGN_UDP_IDLE_STRATEGY`,
`BORON_CAMPAIGN_UDP_SOCKET_RECEIVE_BUFFER_BYTES`, and
`BORON_CAMPAIGN_UDP_SOCKET_SEND_BUFFER_BYTES`. The bounded harness records the
effective values in `udp-settings.env`. Query evidence includes Linux UDP
receive-buffer/memory errors and softnet drops for every repetition, while the
bounded evidence records process and cgroup NUMA locality after quiescence and
after performance. Keep tuning explicit for a campaign so a size curve does
not silently mix data-plane profiles.

The `large-rrset` profile verifies that ZoneImage publication and AXFR are not
mistakenly capped by the 16-bit DNS message section count. A 65,536-record
RRset crosses the former implementation boundary while remaining small enough
for a bounded local publication test:

```sh
BORON_LOAD_PROFILE=large-rrset \
BORON_LOAD_NAMES_PER_ZONE=1 \
BORON_LOAD_NSEC3_RECORDS_PER_ZONE=1 \
BORON_LOAD_RECORDS_PER_NAME=65536 \
BORON_LOAD_EXPECT_OUTCOME=ready \
scripts/boron-gen-bounded-load.sh
```

The complete RRset cannot be encoded in one classic DNS response: UDP reports
truncation and DNS over TCP has a 65,535-octet message limit. The test therefore
uses publication readiness and negative-query probes to distinguish storage
and transfer support from ordinary response wire capacity.
