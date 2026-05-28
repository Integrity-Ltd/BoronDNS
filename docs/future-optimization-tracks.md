# Future Optimization Tracks

This document owns the detailed design constraints for future OxideDNS server
optimization tracks that remain outside the current Engineering MVP runtime.
SRS Appendix C.6 records the formal scope exclusion and re-entry pointers; this
companion records the engineering detail, unsafe-boundary expectations, and
benchmark entry conditions.

The implementation-level plan for the combined memory-layout, response
composition, benchmark, tuning, and packet-I/O data-plane track is
`docs/memory-io-data-plane-design.md`. This document keeps only the formal
deferred-track boundary and promotion constraints.

These tracks are not hidden Engineering MVP requirements. They become current
requirements only when a later SRS revision explicitly promotes the track and
the relevant unsafe-boundary/dependency rows are moved from `deferred` to
`current`.

## XDP/eBPF Kernel Bypass

Future deployment may attach an XDP program to the OxideDNS server DNS query
interface and use AF_XDP or another audited packet-I/O backend for packets that
need userspace processing. The current OxideDNS server runtime uses Tokio
UDP/TCP sockets and has no server XDP/eBPF or AF_XDP packet backend.

The `oxide-gun` crate has an AF_XDP backend for Linux lab load generation. That
backend is test-tool scope only and does not satisfy or activate this OxideDNS
server optimization track.

Entry condition for re-evaluation: benchmarks of the current implementation
show that the kernel socket path, rather than zone lookup or response assembly,
prevents OxideDNS from meeting the relevant performance target, or a deployment
profile with dedicated XDP-capable hardware becomes a standard target.

Architectural constraints for any future implementation:

- Keep packet I/O behind a documented adapter boundary so DNS parsing, lookup,
  and response-composition code can stay independent of the backend.
- Preserve the DNS/transfer/management interface split. Any NIC-name attachment
  detail belongs in the adapter/deployment profile, not in query logic.
- Cover packet-size and path-MTU behavior explicitly for the bypass path instead
  of relying on the ordinary kernel UDP socket behavior.
- Runtime loading of operator-supplied eBPF programs remains prohibited by
  ODS-INV-009. Any kernel-side program must be a versioned project artifact.
- First-party unsafe code and unsafe-prone dependencies must remain confined to
  the registry-listed packet-I/O adapter boundary and carry `/// # Safety` /
  `// SAFETY:` rationale plus backend fault evidence before production use.

The concrete eBPF userspace library choice, such as Aya versus a libbpf-based
crate, is deliberately not fixed. Selection belongs to the future promotion
change after capability, maintenance, and safety review.

## Packed-Binary Zone Store

Future work may replace the current memory-resident snapshot store with an
NSD-style packed-binary layout for better cache locality and lower per-record
overhead. One possible shape is a contiguous per-zone arena built at transfer
ingestion time, with lookup indexes storing integer offsets into the arena
rather than heap object pointers. Zone replacement would still publish a
complete arena plus index snapshot atomically.

Entry condition for re-evaluation: Engineering MVP benchmarking shows that
cache misses on zone lookup are a significant fraction of query latency at
target load, or that per-record memory overhead exceeds the ODS-NFR-RES-002
target.

Architectural constraints for any future implementation:

- Keep the zone store behind a documented lookup/publish boundary so packed
  storage can substitute without changing query-processing or transfer
  protocol code.
- Separate AXFR/IXFR ingestion from query serving. Ingestion builds a complete
  replacement store instance; query serving reads only published immutable
  snapshots.
- Preserve ODS-INV-003 atomic publication: no query may observe partially built
  or mixed-generation zone data.
- Keep per-record memory overhead in benchmark output so the entry condition can
  be evaluated against measured data.

Pre-computing NSEC/NSEC3 denial-of-existence material at ingestion time may be
evaluated independently of the packed arena layout. That optimization still
needs lookup-equivalence tests and DNSSEC proof-selection tests before
promotion.

## Pre-Baked Response Cache

Future work may add an in-process cache of serialized authoritative DNS
responses ready to send on the wire. At minimum, the key would include fields
that affect response composition, such as QNAME, QTYPE, and the EDNS DO bit. On
a hit, the server could copy the cached packet, patch the QID, update any
time-sensitive fields allowed by the cache policy, and send it without ordinary
zone lookup and response assembly.

Entry condition for re-evaluation: Engineering MVP benchmarking shows that
response assembly, such as name compression, RR serialization, and EDNS OPT
construction, accounts for a significant fraction of per-query CPU time at
target load.

Architectural constraints for any future implementation:

- Separate response assembly from the send path so a cached buffer can be
  substituted transparently.
- Purge all cached responses for a zone when that zone refreshes or is
  de-provisioned.
- Key cached responses on the DO-bit value; DO=0 and DO=1 responses differ in
  DNSSEC material and must not share entries.
- Respect TTL decay and DNSSEC validity. A cache must not serve a response whose
  TTL or RRSIG validity has fallen below the configured policy floor.
- Keep the first implementation eligible for disabling at runtime and covered
  by differential tests against the uncached response path.

The initial response-cache promotion may be restricted to unsigned responses if
that gives a safer validation path.
