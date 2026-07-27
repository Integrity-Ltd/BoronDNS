# BoronGen deterministic large-zone primary

Status: implementation contract for the internal large-scale test tool

## Purpose

BoronGen is an internal synthetic authoritative primary for exercising
BoronDNS transfer, compilation, DNSSEC denial-index, query, and memory behavior
at sizes that are impractical to materialize in BIND-style zone files.

BoronGen is not a general-purpose authoritative server and is not a DNSSEC
validity oracle. Small generated corpora remain subject to independent transfer
and parser checks. DNSSEC validity testing continues to use genuinely signed
zones from interoperable authoritative implementations.

## Required properties

- A scenario is a pure function of its configuration, seed, zone index, owner
  index, RR index, and serial.
- Catalog zones and member zones are generated without retaining their records.
- AXFR records are produced incrementally into bounded DNS messages and written
  under TCP backpressure.
- After a transfer, the process retains only the scenario configuration,
  counters, serial, and bounded per-connection buffers.
- SOA polling returns the stable configured serial. IXFR for the unchanged
  serial returns the single current SOA, so a filled secondary does not require
  another full transfer.
- Concurrent connections are bounded. Configuration and aggregate record-count
  arithmetic are checked before the listener starts; per-record/message
  wire-size arithmetic remains checked while streaming and fails the affected
  request without growing beyond the configured message bound.
- Catalog and member transfers can use the same TSIG key. Every AXFR message is
  signed in the initial implementation, which gives a valid TCP TSIG chain
  without retaining unsigned messages between signatures.
- A machine-readable manifest records the exact scenario and expected record
  counts.

## Synthetic NSEC3 contract

The large-scale NSEC3 profile emits a strictly increasing sequence of 20-byte
owner hashes. Every record's `next hashed owner name` is the next emitted hash,
and the final record points to the first. The resulting ring is correctly
ordered, fully linked, and suitable for BoronDNS's NSEC3 range indexing,
binary-search lookup, and denial-response performance paths.

The hashes are generated directly across the 160-bit namespace. They are not
claimed to be SHA-1 preimages of the generated ordinary owner names. RRSIG
records are structurally valid opaque load-test data, not cryptographic
signatures. The manifest and startup log must identify both properties.

This mode avoids an in-memory or on-disk `O(number of names)` hash sort. A
separate small-corpus validity mode may later calculate real NSEC3 hashes, sort
them, and use genuine signing.

## Initial content profiles

- `registry-nsec3`: delegation-shaped NS, glue, sampled DS, NSEC3, and optional
  structurally valid RRSIG records.
- `mixed`: deterministic A, AAAA, TXT, multi-record RRsets, and optional
  structural RRSIG data.
- `large-rrset`: a configurable number of A records at each generated owner,
  plus optional structural RRSIG data.

All profiles include one apex SOA and NS RRset. NSEC3 profiles also include an
apex NSEC3PARAM record.

## Protocol scope

The first implementation serves UDP and TCP SOA, TCP AXFR, and the unchanged
single-SOA IXFR response. It serves an RFC 9432 version 2 catalog zone and its
formula-derived member zones. NOTIFY, serial advancement, changed IXFR
histories, XoT, and per-member catalog transfer overrides are follow-up work.

## Resource-safety layers

1. BoronGen validates configuration and checked record-count arithmetic before
   binding.
2. DNS messages, query frames, concurrent connections, and output buffers have
   explicit limits.
3. BoronDNS retains its transfer byte limit and gains a configurable transfer
   message-count limit; neither protection is silently disabled.
4. Large local runs use a dedicated transient systemd unit with cgroup v2
   controls. The planned 32 GiB test uses `MemoryHigh` below `MemoryMax`,
   enables systemd-oomd pressure handling where supported, and sets `OOMPolicy`
   so failure remains confined to the test unit.
5. Runs increase through calibrated steps before the 32 GiB target. A generated
   manifest and cgroup memory-event snapshots are retained with the evidence.

The cgroup is the final containment boundary for allocator exhaustion. It does
not turn allocation failure inside BoronDNS into a recoverable zone-build
error. Default readiness runs treat an OOM as failure. The harness's explicit
`contained-oom` outcome is a negative containment test and passes only if the
BoronDNS unit is OOM-killed while the separately bounded generator survives;
it is never labelled as successful publication.

## Validation gates

- Unit tests prove deterministic owner/RDATA generation and exact counts.
- NSEC3 tests prove strict owner ordering, exact next-hash linkage, and wrap.
- Message tests prove configured and DNS/TCP frame bounds.
- Small unsigned and TSIG AXFR streams parse through BoronDNS's production
  transfer parser.
- Small generated corpora are independently inspected with standard DNS tools.
- BoronGen RSS remains approximately constant while transferring successively
  larger corpora at fixed concurrency.
- A published `registry-nsec3` corpus answers a DNSSEC NXDOMAIN probe with
  NSEC3 authority records through the immutable zone-image semantic path.
- A bounded BoronGun UDP probe drives the same DNSSEC NXDOMAIN path, requires
  matching responses, and records achieved throughput and latency in the run
  evidence. The gate also requires indexed NSEC3 publication with no fallback
  group and matching DNSSEC-augmented query accounting. Only the loopback
  harness client is exempted from RRL.
- The `large-rrset` profile proves publication and transfer beyond the former
  65,535-member implementation boundary. It separately verifies that oversized
  ordinary query responses follow DNS message limits instead of treating the
  section-count width as a zone-storage limit.
- A deliberately undersized cgroup proves that allocator exhaustion remains
  confined to BoronDNS and does not kill BoronGen or destabilize the host.
- Only after the current fuzz campaign is complete, collected, and its terminal
  status is explicitly dispositioned does the local load test advance to the
  final 32 GiB-capped stage. The load result must not be presented as evidence
  that a non-clean fuzz campaign passed.

## BoronDNS large-transfer prerequisite

BoronDNS admits 4,096 messages per AXFR/IXFR session by default. At the
DNS-over-TCP frame limit this is only about 256 MiB of wire data. The
`limits.max_transfer_ingest_messages` setting provides a configurable,
validated message-count allowance alongside the existing byte allowance. The
default remains conservative; the test configuration opts into the larger
value explicitly.
