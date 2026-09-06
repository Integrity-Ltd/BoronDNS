# Release Scope

BoronDNS 1.0 is a secondary-authoritative DNS server. The current feature list,
with source and test references, is in
[Implemented Feature Scope](implemented-feature-scope.md). This file keeps its
older `engineering-mvp` name so existing scripts and links continue to work.

The server includes UDP/TCP queries, AXFR/IXFR acquisition, NOTIFY, TSIG,
outbound XoT, catalog zones, passive DNSSEC, DNS Cookies, RRL, and operational
interfaces. AF_XDP is included in the official binary as an experimental,
opt-in backend. Recursion, primary-server operation, UPDATE, DNSSEC signing,
and encrypted client-query listeners are outside the server's scope.

## Local Verification

Run `scripts/check.sh` for the regular quality gate. It covers deterministic
tests, static analysis, documentation checks, short runtime checks, and fuzz
build/dry-run wiring. It does not launch long campaigns.

`scripts/engineering-mvp-evidence.sh` collects a smaller evidence set with
per-command timeouts. It records omitted work in `deferred-not-run.txt`.
[Evidence Command Catalog](evidence-command-catalog.md) lists both profiles.

## Release Evidence

Local verification is not the SRS `BDS-VER-008` release-acceptance decision.
Use the [release evidence guide](release-evidence-guide.md) to collect the
checks relevant to the candidate and review the
[acceptance register](release-acceptance-gap-register.md) before tagging.

Several independent 24-hour fuzz campaigns formed part of the 1.0 validation
plan. Later releases select fuzz, interoperability, performance, and extended
runtime checks according to what changed. No fixed 30-day campaign is required.
Reference Hardware/Profile benchmark claims need measurements from that profile;
optional external reviews need an actual review record.

Record the tested commit, tools, command, result, and artifact location. A
generated runbook or empty report template is preparation, not a completed run.
Older results can support a release when their relevance and intervening changes
are explained; they do not establish a result for untested code or hardware.
