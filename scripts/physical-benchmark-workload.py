#!/usr/bin/env python3
"""Bounded benchmark workload checks, not a full DNS correctness validator.

Positive policy requires authoritative NOERROR and an answer of the requested
type (following CNAMEs). Mixed policy accepts authoritative NOERROR or NXDOMAIN;
it does not prescribe their distribution. Probes sample at most 32 queries.
Load-generator RCODE summaries cannot establish answer content or AA flags.
"""

import argparse
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import struct
import time
from pathlib import Path

MAX_FILE_BYTES = 64 * 1024 * 1024
TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "HINFO": 13,
    "MX": 15,
    "TXT": 16,
    "RP": 17,
    "AAAA": 28,
    "LOC": 29,
    "SRV": 33,
    "NAPTR": 35,
    "DNAME": 39,
    "DS": 43,
    "SSHFP": 44,
    "RRSIG": 46,
    "NSEC": 47,
    "DNSKEY": 48,
    "NSEC3": 50,
    "NSEC3PARAM": 51,
    "TLSA": 52,
    "SMIMEA": 53,
    "CDS": 59,
    "CDNSKEY": 60,
    "OPENPGPKEY": 61,
    "CSYNC": 62,
    "ZONEMD": 63,
    "SVCB": 64,
    "HTTPS": 65,
    "ANY": 255,
    "URI": 256,
    "CAA": 257,
}
RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def read_bounded(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("input exceeds 64 MiB")
    return data


def encode_name(name):
    if name == ".":
        return b"\0"
    labels = name.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63 or any(
            value <= 32 or value >= 127 or value == 92 for value in raw
        ):
            raise ValueError("invalid or unsupported DNS name label")
        encoded.extend(bytes([len(raw)]) + raw)
    encoded.append(0)
    if len(encoded) > 255:
        raise ValueError("DNS name exceeds 255 wire octets")
    return bytes(encoded)


def queries(data):
    for number, line in enumerate(data.decode("ascii").splitlines(), 1):
        line = re.split(r"[;#]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2:
            raise ValueError(f"query line {number}: expected name and type only")
        name, kind = fields
        # No master-file escapes or implicit origins: the manifest is explicit.
        if name.endswith(".."):
            raise ValueError(f"query line {number}: empty label")
        name = name.lower().rstrip(".") + "."
        encode_name(name)
        kind = kind.upper()
        match = re.fullmatch(r"TYPE([0-9]+)", kind)
        value = int(match.group(1)) if match else TYPES.get(kind)
        if value is None or not 1 <= value <= 65535:
            raise ValueError(f"query line {number}: unsupported query type {kind}")
        yield {"name": name, "type": value}


def make_manifest(path, policy):
    if policy not in ("positive", "mixed"):
        raise ValueError("unknown workload policy")
    data = read_bounded(path)
    count = sum(1 for _ in queries(data))
    if not count:
        raise ValueError("query database is empty")
    size = min(32, count)
    selected = (
        {index * (count - 1) // (size - 1) for index in range(size)}
        if size > 1
        else {0}
    )
    samples = [
        dict(query, index=index)
        for index, query in enumerate(queries(data))
        if index in selected
    ]
    return {
        "schema_version": 1,
        "sha256": hashlib.sha256(data).hexdigest(),
        "query_count": count,
        "policy": policy,
        "samples": samples,
    }


def decode_name(packet, offset):
    labels = []
    end = None
    visited = set()
    wire_length = 1
    while True:
        if offset >= len(packet) or offset in visited:
            raise ValueError("truncated or cyclic DNS name")
        visited.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated compression pointer")
            target = ((length & 63) << 8) | packet[offset + 1]
            if target >= offset or target < 12:
                raise ValueError("invalid DNS compression pointer")
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        offset += 1
        if not length:
            return b".".join(labels).lower() + b".", end if end is not None else offset
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset : offset + length])
        wire_length += length + 1
        if wire_length > 255:
            raise ValueError("expanded DNS name exceeds 255 octets")
        offset += length


def parse_response(packet, identifier, query):
    if len(packet) < 12:
        raise ValueError("short DNS header")
    got_id, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    if (
        got_id != identifier
        or not flags & 0x8000
        or flags & 0x7800
        or flags & 0x0200
        or qd != 1
    ):
        raise ValueError(
            "mismatched ID, non-response, opcode, truncation, or question count"
        )
    name, offset = decode_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("truncated question")
    kind, qclass = struct.unpack_from("!HH", packet, offset)
    offset += 4
    if name != query["name"].encode("ascii") or kind != query["type"] or qclass != 1:
        raise ValueError("response question does not match query")
    answers = []
    extended_rcode = 0
    seen_opt = False
    for index in range(an + ns + ar):
        owner, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated RR header")
        rrtype, rrclass, ttl, size = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        end = offset + size
        if end > len(packet):
            raise ValueError("truncated RR data")
        target = None
        if rrtype in (2, 5, 12, 39):
            target, name_end = decode_name(packet, offset)
            if name_end != end:
                raise ValueError("invalid name RDATA length")
        if (rrtype == 1 and size != 4) or (rrtype == 28 and size != 16):
            raise ValueError("invalid address RDATA length")
        if rrtype == 41:
            if seen_opt or index < an + ns or owner != b".":
                raise ValueError("invalid or duplicate OPT")
            seen_opt = True
            extended_rcode = (ttl >> 24) << 4
            cursor = offset
            while cursor < end:
                if cursor + 4 > end:
                    raise ValueError("truncated EDNS option")
                length = struct.unpack_from("!H", packet, cursor + 2)[0]
                cursor += 4 + length
                if cursor > end:
                    raise ValueError("truncated EDNS option data")
        if index < an:
            answers.append((owner, rrtype, rrclass, target))
        offset = end
    if offset != len(packet):
        raise ValueError("trailing bytes after DNS message")
    aliases = {}
    for owner, rrtype, rrclass, target in answers:
        if rrtype == 5 and rrclass == 1:
            aliases.setdefault(owner, []).append(target)
    reachable = {name}
    pending = [name]
    while pending:
        for target in aliases.get(pending.pop(), ()):
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    has_requested_answer = any(
        owner in reachable and rrclass == 1 and (rrtype == kind or kind == 255)
        for owner, rrtype, rrclass, _ in answers
    )
    rcode = (flags & 15) | extended_rcode
    return {
        "rcode": RCODES.get(rcode, f"RCODE{rcode}"),
        "aa": bool(flags & 0x0400),
        "answer_count": an,
        "has_requested_answer": has_requested_answer,
        "response_bytes": len(packet),
    }


def probe(path, manifest, target, port, source):
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a JSON object")
    actual = make_manifest(path, manifest.get("policy"))
    if manifest != actual:
        raise ValueError(
            "query database or manifest changed (hash, policy, or samples mismatch)"
        )
    target_ip = ipaddress.ip_address(target)
    source_ip = ipaddress.ip_address(source)
    if source_ip.version != target_ip.version or not 1 <= port <= 65535:
        raise ValueError("source/target family or port mismatch")
    family = socket.AF_INET if target_ip.version == 4 else socket.AF_INET6
    observations = []
    deadline = time.monotonic() + 30
    for query in actual["samples"]:
        observation = dict(query)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("30-second total probe budget exhausted")
            identifier = secrets.randbelow(65536)
            packet = (
                struct.pack("!6H", identifier, 0, 1, 0, 0, 0)
                + encode_name(query["name"])
                + struct.pack("!HH", query["type"], 1)
            )
            with socket.socket(family, socket.SOCK_DGRAM) as connection:
                connection.settimeout(min(1, remaining))
                connection.bind((str(source_ip), 0))
                connection.connect((str(target_ip), port))
                started = time.monotonic()
                connection.send(packet)
                response = connection.recv(65535)
                observation.update(parse_response(response, identifier, query))
                observation["elapsed_seconds"] = round(time.monotonic() - started, 6)
            allowed = (
                {"NOERROR"}
                if actual["policy"] == "positive"
                else {"NOERROR", "NXDOMAIN"}
            )
            observation["passed"] = (
                observation["aa"] and observation["rcode"] in allowed
            )
            if actual["policy"] == "positive":
                observation["passed"] = (
                    observation["passed"] and observation["has_requested_answer"]
                )
            if not observation["passed"]:
                observation["error"] = "response does not satisfy workload policy"
        except (OSError, ValueError) as error:
            observation.update(passed=False, error=str(error))
        observations.append(observation)
    passed = all(item["passed"] for item in observations)
    return {
        "schema_version": 1,
        "passed": passed,
        "status": "sampled-pass" if passed else "failed",
        "sha256": actual["sha256"],
        "query_count": actual["query_count"],
        "policy": actual["policy"],
        "target": target,
        "port": port,
        "source": source,
        "observations": observations,
        "limitation": "Deterministic sample only; mixed policy does not specify a response distribution.",
    }


def classify(log, player, policy):
    report = {"schema_version": 1, "player": player, "policy": policy, "rcodes": {}}
    if player == "boron-gun":
        report.update(
            passed=True,
            status="unverified",
            validation="unverified",
            limitation="BoronGun count-mode positive_total counts matched packets, not DNS positive answers; sampled preflight only.",
        )
        return report
    totals = re.findall(r"total replies:\s*([0-9,]+)", log, re.IGNORECASE)
    counts = re.findall(r"responded\s+([A-Z0-9_]+):\s*([0-9,]+)", log, re.IGNORECASE)
    # A single run is required: concatenated runs could hide contradictory data.
    rcodes = {}
    duplicate = False
    for code, count in counts:
        code = code.upper()
        duplicate |= code in rcodes
        rcodes[code] = int(count.replace(",", ""))
    total = int(totals[0].replace(",", "")) if len(totals) == 1 else 0
    allowed = {"NOERROR"} if policy == "positive" else {"NOERROR", "NXDOMAIN"}
    passed = (
        total > 0 and bool(rcodes) and not duplicate and sum(rcodes.values()) == total
    )
    passed = passed and all(
        code in allowed or count == 0 for code, count in rcodes.items()
    )
    report.update(
        passed=passed,
        status="rcode-pass" if passed else "failed",
        validation="rcode-only",
        total_replies=total,
        rcodes=rcodes,
        limitation="RCODE-only validation; answer content and AA are checked only by sampled preflight.",
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    manifest_parser = commands.add_parser("manifest")
    manifest_parser.add_argument("querydb", type=Path)
    manifest_parser.add_argument(
        "--policy", choices=("positive", "mixed"), default="positive"
    )
    probe_parser = commands.add_parser("probe")
    probe_parser.add_argument("querydb", type=Path)
    probe_parser.add_argument("--manifest", type=Path, required=True)
    probe_parser.add_argument("--target", required=True)
    probe_parser.add_argument("--port", type=int, default=53)
    probe_parser.add_argument("--source", required=True)
    classify_parser = commands.add_parser("classify")
    classify_parser.add_argument("log", type=Path)
    classify_parser.add_argument(
        "--player", choices=("kxdpgun", "boron-gun"), required=True
    )
    classify_parser.add_argument(
        "--policy", choices=("positive", "mixed"), default="positive"
    )
    for child in (manifest_parser, probe_parser, classify_parser):
        child.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            report = make_manifest(args.querydb, args.policy)
        elif args.command == "probe":
            report = probe(
                args.querydb,
                json.loads(read_bounded(args.manifest)),
                args.target,
                args.port,
                args.source,
            )
        else:
            report = classify(
                read_bounded(args.log).decode("utf-8", errors="replace"),
                args.player,
                args.policy,
            )
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {
            "schema_version": 1,
            "passed": False,
            "status": "failed",
            "error": str(error),
        }
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if report.get("passed", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
