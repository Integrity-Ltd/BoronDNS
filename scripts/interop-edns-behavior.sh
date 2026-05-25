#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'skipping EDNS behavior interop: missing %s\n' "${missing[*]}" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/edns-behavior-$$"
artifact_dir="${OXIDEDNS_EDNS_BEHAVIOR_ARTIFACT_DIR:-}"
mkdir -p "$workdir"

cleanup() {
  local status=$?
  if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
    kill "$oxidedns_pid" 2>/dev/null || true
    wait "$oxidedns_pid" 2>/dev/null || true
  fi
  if [[ -n "${primary_pid:-}" ]] && kill -0 "$primary_pid" 2>/dev/null; then
    kill "$primary_pid" 2>/dev/null || true
    wait "$primary_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    [[ -f "$workdir/fake-primary.log" ]] && { echo "---- fake-primary.log ----" >&2; tail -120 "$workdir/fake-primary.log" >&2; }
    [[ -f "$workdir/client.log" ]] && { echo "---- client.log ----" >&2; tail -160 "$workdir/client.log" >&2; }
    [[ -f "$workdir/oxidedns.log" ]] && { echo "---- oxidedns.log ----" >&2; tail -160 "$workdir/oxidedns.log" >&2; }
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

read -r primary_port oxidedns_dns_port oxidedns_health_port < <(
  python3 - <<'PY'
import socket

sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)

fake_primary="$workdir/fake-primary.py"
client="$workdir/client.py"
primary_log="$workdir/fake-primary.log"
client_log="$workdir/client.log"
summary_tsv="$workdir/edns-summary.tsv"
traceability_tsv="$workdir/edns-traceability.tsv"
oxidedns_conf="$workdir/oxidedns.toml"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "edns.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252
LARGE_RRSET = 96


def log(message):
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_name(packet, offset):
    labels = []
    consumed = 0
    while True:
        length = packet[offset]
        offset += 1
        consumed += 1
        if length == 0:
            return ".".join(labels) + ".", consumed
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
        consumed += length


def parse_question(packet):
    qname, name_len = parse_name(packet, 12)
    offset = 12 + name_len
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return qname, qtype, qclass


def rr(owner, rrtype, rdata, ttl=300):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052501):
    return b"".join([
        name_wire("ns1.edns.test."),
        name_wire("hostmaster.edns.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata(), ttl=3600)
    records = [
        soa,
        rr(ZONE, NS, name_wire("ns1.edns.test.")),
        rr("ns1.edns.test.", A, bytes([127, 0, 0, 1])),
        rr("www.edns.test.", A, bytes([192, 0, 2, 10])),
    ]
    for index in range(LARGE_RRSET):
        records.append(rr("large.edns.test.", A, bytes([192, 0, 2, index + 1])))
    records.append(soa)
    return records


def axfr_response(qid):
    answers = zone_records()
    question = name_wire(ZONE) + struct.pack("!HH", AXFR, IN)
    return struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)


def read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def handle_tcp(conn):
    with conn:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
        query = read_exact(conn, length)
        qid = struct.unpack("!H", query[:2])[0]
        qname, qtype, qclass = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 0, 0, 0, 0)
        else:
            log(f"TCP AXFR served records={len(zone_records())}")
            response = axfr_response(qid)
        conn.sendall(struct.pack("!H", len(response)) + response)


def main():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, PORT))
    tcp.listen()
    log(f"READY port={PORT}")
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY

cat >"$client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
SUMMARY_PATH = sys.argv[3]
TRACEABILITY_PATH = sys.argv[4]
A = 1
IN = 1
OPT = 41
EDNS_NSID = 3
EDNS_TCP_KEEPALIVE = 11
EDNS_PADDING = 12
UNKNOWN_OPTION = 65001
SERVER_MAX_UDP_PAYLOAD = 700
NSID_VALUE = b"edns-node"


def log(message):
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def option(code, data=b""):
    return struct.pack("!HH", code, len(data)) + data


def opt_record(payload=4096, version=0, do=False, options=b"", owner=b"\x00"):
    ttl = (version << 16) | (0x8000 if do else 0)
    return owner + struct.pack("!HHIH", OPT, payload, ttl, len(options)) + options


def query_packet(
    qid,
    qname,
    *,
    payload=None,
    version=0,
    do=False,
    options=b"",
    duplicate_opt=False,
    opt_in_answer=False,
):
    question = name_wire(qname) + struct.pack("!HH", A, IN)
    answers = b""
    additionals = b""
    ancount = 0
    arcount = 0
    if payload is not None:
        opt = opt_record(payload, version, do, options)
        if opt_in_answer:
            answers += opt
            ancount = 1
        else:
            additionals += opt
            arcount = 1
            if duplicate_opt:
                additionals += opt
                arcount = 2
    return struct.pack("!HHHHHH", qid, 0x0100, 1, ancount, 0, arcount) + question + answers + additionals


def udp_exchange(packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(packet, (HOST, PORT))
        return sock.recvfrom(4096)[0]
    finally:
        sock.close()


def tcp_exchange(packet):
    with socket.create_connection((HOST, PORT), timeout=2.0) as tcp:
        tcp.sendall(struct.pack("!H", len(packet)) + packet)
        header = tcp.recv(2)
        if len(header) != 2:
            raise AssertionError("short TCP length prefix")
        length = struct.unpack("!H", header)[0]
        data = bytearray()
        while len(data) < length:
            chunk = tcp.recv(length - len(data))
            if not chunk:
                raise AssertionError("short TCP response")
            data.extend(chunk)
        return bytes(data)


def skip_name(packet, offset):
    consumed = 0
    jumped = False
    seen = set()
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise AssertionError("compression loop")
            seen.add(pointer)
            if not jumped:
                consumed += 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if not jumped:
            consumed += 1
        if length == 0:
            return consumed
        offset += length
        if not jumped:
            consumed += length


def parse_records(packet, offset, count):
    records = []
    for _ in range(count):
        offset += skip_name(packet, offset)
        rrtype, rrclass, ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlen]
        offset += rdlen
        records.append({"type": rrtype, "class": rrclass, "ttl": ttl, "rdata": rdata})
    return records, offset


def parse_options(rdata):
    parsed = {}
    offset = 0
    while offset < len(rdata):
        code, length = struct.unpack("!HH", rdata[offset:offset + 4])
        offset += 4
        parsed.setdefault(code, []).append(rdata[offset:offset + length])
        offset += length
    return parsed


def response_summary(packet):
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    for _ in range(qdcount):
        offset += skip_name(packet, offset) + 4
    answers, offset = parse_records(packet, offset, ancount)
    authorities, offset = parse_records(packet, offset, nscount)
    additionals, offset = parse_records(packet, offset, arcount)
    if offset != len(packet):
        raise AssertionError(f"response trailing bytes offset={offset} len={len(packet)}")
    opt = next((record for record in additionals if record["type"] == OPT), None)
    base_rcode = flags & 0x000F
    ext_rcode = 0 if opt is None else (opt["ttl"] >> 24) & 0xFF
    return {
        "id": qid,
        "flags": flags,
        "rcode": (ext_rcode << 4) | base_rcode,
        "tc": bool(flags & 0x0200),
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
        "opt": opt,
        "opt_options": {} if opt is None else parse_options(opt["rdata"]),
        "bytes": len(packet),
    }


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_active():
    deadline = time.monotonic() + 10
    packet = query_packet(0x4001, "www.edns.test.")
    while time.monotonic() < deadline:
        try:
            summary = response_summary(udp_exchange(packet))
            if summary["rcode"] == 0 and summary["answers"]:
                log("active zone query succeeded")
                return
        except (OSError, AssertionError):
            pass
        time.sleep(0.05)
    raise AssertionError("OxideDNS did not publish active edns.test zone")


def record(rows, case, summary, detail):
    rows.append(
        f"{case}\t{summary['rcode']}\t{int(summary['tc'])}\t{summary['bytes']}\t"
        f"{int(summary['opt'] is not None)}\t{detail}"
    )
    log(
        f"{case} rcode={summary['rcode']} tc={int(summary['tc'])} "
        f"bytes={summary['bytes']} opt={int(summary['opt'] is not None)} {detail}"
    )


def assert_payload_boundary(rows, qid, advertised_payload, expected_ceiling, case):
    summary = response_summary(udp_exchange(query_packet(qid, "large.edns.test.", payload=advertised_payload)))
    require(summary["rcode"] == 0 and summary["tc"], summary)
    require(summary["bytes"] <= expected_ceiling, summary)
    require(summary["opt"] is not None, f"{case} response missed OPT")
    record(
        rows,
        case,
        summary,
        f"advertised={advertised_payload} applied_ceiling<={expected_ceiling}",
    )


def main():
    wait_active()
    rows = ["case\trcode\ttc\tresponse_bytes\topt_present\tdetail"]

    valid_unknown = response_summary(udp_exchange(query_packet(
        0x4101,
        "www.edns.test.",
        payload=4096,
        options=option(UNKNOWN_OPTION, b"abc"),
    )))
    require(valid_unknown["rcode"] == 0, valid_unknown)
    require(valid_unknown["opt"] is not None, "valid EDNS response missed OPT")
    require(valid_unknown["opt"]["class"] == SERVER_MAX_UDP_PAYLOAD, valid_unknown)
    require(valid_unknown["opt"]["ttl"] & 0x00FF_FFFF == 0, valid_unknown)
    require(UNKNOWN_OPTION not in valid_unknown["opt_options"], valid_unknown)
    record(rows, "valid_edns_unknown_option", valid_unknown, "response_opt_class=700 unknown_option_echoed=0")

    badvers = response_summary(udp_exchange(query_packet(0x4102, "www.edns.test.", payload=4096, version=1)))
    require(badvers["rcode"] == 16, badvers)
    require(badvers["opt"] is not None, "BADVERS response missed OPT")
    require(((badvers["opt"]["ttl"] >> 16) & 0xFF) == 0, badvers)
    record(rows, "badvers_version_1", badvers, "extended_rcode=16 response_version=0")

    do_cleared = response_summary(udp_exchange(query_packet(0x4103, "www.edns.test.", payload=4096, do=True)))
    require(do_cleared["rcode"] == 0, do_cleared)
    require(do_cleared["opt"] is not None, "DO response missed OPT")
    require(do_cleared["opt"]["ttl"] & 0x8000 == 0, do_cleared)
    record(rows, "do_query_without_dnssec_aug_clears_response_do", do_cleared, "response_do=0")

    assert_payload_boundary(rows, 0x4104, 256, 512, "payload_floor_512")
    assert_payload_boundary(rows, 0x4105, 512, 512, "payload_exact_floor_512")
    assert_payload_boundary(rows, 0x4106, 699, 699, "payload_below_server_max_699")
    assert_payload_boundary(rows, 0x4107, 700, SERVER_MAX_UDP_PAYLOAD, "payload_exact_server_max_700")
    assert_payload_boundary(rows, 0x4108, 701, SERVER_MAX_UDP_PAYLOAD, "payload_above_server_max_701")
    assert_payload_boundary(rows, 0x4109, 4096, SERVER_MAX_UDP_PAYLOAD, "payload_large_server_max_700")

    no_edns = response_summary(udp_exchange(query_packet(0x4110, "large.edns.test.")))
    require(no_edns["rcode"] == 0 and no_edns["tc"], no_edns)
    require(no_edns["bytes"] <= 512, no_edns)
    require(no_edns["opt"] is None, no_edns)
    record(rows, "non_edns_512_no_opt", no_edns, "response_opt=0")

    udp_keepalive = response_summary(udp_exchange(query_packet(
        0x4111,
        "www.edns.test.",
        payload=4096,
        options=option(EDNS_TCP_KEEPALIVE),
    )))
    require(udp_keepalive["rcode"] == 0, udp_keepalive)
    require(EDNS_TCP_KEEPALIVE not in udp_keepalive["opt_options"], udp_keepalive)
    record(rows, "udp_keepalive_ignored", udp_keepalive, "keepalive_option_echoed=0")

    tcp_keepalive = response_summary(tcp_exchange(query_packet(
        0x4112,
        "www.edns.test.",
        payload=4096,
        options=option(EDNS_TCP_KEEPALIVE),
    )))
    require(tcp_keepalive["rcode"] == 0, tcp_keepalive)
    keepalive_values = tcp_keepalive["opt_options"].get(EDNS_TCP_KEEPALIVE, [])
    require(keepalive_values == [struct.pack("!H", 50)], tcp_keepalive)
    record(rows, "tcp_keepalive_advertised", tcp_keepalive, "timeout_100ms_units=50")

    padding = response_summary(udp_exchange(query_packet(
        0x4113,
        "www.edns.test.",
        payload=4096,
        options=option(EDNS_PADDING),
    )))
    require(padding["rcode"] == 0, padding)
    require(EDNS_PADDING in padding["opt_options"], padding)
    require(padding["bytes"] % 32 == 0, padding)
    record(rows, "configured_padding_aligns", padding, "block_size=32")

    nsid_empty = response_summary(udp_exchange(query_packet(
        0x4114,
        "www.edns.test.",
        payload=4096,
        options=option(EDNS_NSID),
    )))
    require(nsid_empty["opt_options"].get(EDNS_NSID) == [NSID_VALUE], nsid_empty)
    record(rows, "nsid_empty_request", nsid_empty, "nsid=edns-node")

    nsid_nonempty = response_summary(udp_exchange(query_packet(
        0x4115,
        "www.edns.test.",
        payload=4096,
        options=option(EDNS_NSID, b"bad"),
    )))
    require(nsid_nonempty["opt_options"].get(EDNS_NSID) == [NSID_VALUE], nsid_nonempty)
    record(rows, "nsid_nonempty_request", nsid_nonempty, "nsid=edns-node")

    malformed = response_summary(udp_exchange(query_packet(
        0x4116,
        "www.edns.test.",
        payload=4096,
        options=struct.pack("!HH", UNKNOWN_OPTION, 4) + b"x",
    )))
    require(malformed["rcode"] == 1, malformed)
    record(rows, "malformed_option_formerr", malformed, "rcode=FORMERR")

    duplicate = response_summary(udp_exchange(query_packet(
        0x4117,
        "www.edns.test.",
        payload=4096,
        duplicate_opt=True,
    )))
    require(duplicate["rcode"] == 1, duplicate)
    record(rows, "duplicate_opt_formerr", duplicate, "rcode=FORMERR")

    misplaced = response_summary(udp_exchange(query_packet(
        0x4118,
        "www.edns.test.",
        payload=4096,
        opt_in_answer=True,
    )))
    require(misplaced["rcode"] == 1, misplaced)
    record(rows, "answer_section_opt_formerr", misplaced, "rcode=FORMERR")

    with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
        handle.write("\n".join(rows) + "\n")

    traceability = """requirement_id\tevidence_state\truntime_case\tartifacts\treview_note
ODS-FR-EDNS-001\tretained-runtime\tvalid_edns_unknown_option; malformed_option_formerr\tedns-summary.tsv; client.log\tValid OPT option parsing succeeds, while an option whose length exceeds remaining RDATA returns FORMERR.
ODS-FR-EDNS-002\tretained-runtime\tduplicate_opt_formerr\tedns-summary.tsv; client.log\tA query carrying two OPT records returns FORMERR.
ODS-FR-EDNS-003\tretained-runtime\tanswer_section_opt_formerr\tedns-summary.tsv; client.log\tAn OPT record outside the additional section returns FORMERR.
ODS-FR-EDNS-004\tretained-runtime\tbadvers_version_1\tedns-summary.tsv; client.log\tEDNS VERSION=1 returns extended RCODE BADVERS with response VERSION=0.
ODS-FR-EDNS-005\tretained-runtime\tpayload_floor_512; payload_exact_floor_512\tedns-summary.tsv; client.log\tAdvertised UDP payload sizes below or equal to 512 are bounded to the 512-octet floor and truncate the large response within that size.
ODS-FR-EDNS-006\tretained-runtime\tpayload_below_server_max_699; payload_exact_server_max_700; payload_above_server_max_701; payload_large_server_max_700\tedns-summary.tsv; oxidedns.toml\tAdvertised UDP payload sizes below, equal to, and above configured max_udp_payload=700 are bounded to min(client, configured max) and truncate within that ceiling.
ODS-FR-EDNS-007\tretained-runtime\tvalid_edns_unknown_option; non_edns_512_no_opt\tedns-summary.tsv; client.log\tResponses include OPT only when the query contained OPT.
ODS-FR-EDNS-008\tretained-runtime\tvalid_edns_unknown_option\tedns-summary.tsv; oxidedns.toml\tThe response OPT owner/type are parsed, class equals configured max_udp_payload=700, VERSION=0, and Z bits are clear.
ODS-FR-EDNS-009\tretained-runtime-plus-support\tdo_query_without_dnssec_aug_clears_response_do\tedns-summary.tsv; crates/oxidedns-core/src/dns.rs DNSSEC DO tests\tA DO=1 query without DNSSEC augmentation receives response DO=0; DNSSEC-augmented DO behavior remains covered by DNSSEC unit/runtime evidence.
ODS-FR-EDNS-010\tretained-runtime\tbadvers_version_1\tedns-summary.tsv\tBADVERS uses the response OPT extended-RCODE field for RCODE 16.
ODS-FR-EDNS-011\tretained-runtime\tudp_keepalive_ignored; tcp_keepalive_advertised\tedns-summary.tsv\tThe keepalive option is ignored over UDP and recognized over TCP.
ODS-FR-EDNS-012\tretained-runtime\ttcp_keepalive_advertised\tedns-summary.tsv; oxidedns.toml\tThe TCP keepalive response advertises tcp_idle_timeout_secs=5 as 50 units of 100 ms.
ODS-FR-EDNS-013\tretained-runtime\tconfigured_padding_aligns\tedns-summary.tsv; oxidedns.toml\tWith edns_padding_block_size=32 and a padding request, the response contains a padding option and the DNS message length is 32-byte aligned.
ODS-FR-EDNS-014\tretained-runtime\tvalid_edns_unknown_option\tedns-summary.tsv\tAn unknown EDNS option is ignored and not echoed while the query still succeeds.
ODS-FR-EDNS-015\tretained-runtime\tnon_edns_512_no_opt\tedns-summary.tsv\tA non-EDNS large UDP answer is truncated to at most 512 octets and contains no response OPT.
ODS-FR-EDNS-016\tretained-runtime\tnsid_empty_request; nsid_nonempty_request\tedns-summary.tsv; oxidedns.toml\tConfigured NSID is returned for both empty and non-empty NSID request data.
ODS-FR-EDNS-017\tretained-runtime-plus-support\tnsid_empty_request; nsid_nonempty_request\tedns-summary.tsv; oxidedns.toml; crates/oxidedns-core/src/config.rs::parses_configured_nsid\tThe retained config sets nsid=edns-node; default-empty suppression remains covered by focused unit tests.
"""
    with open(TRACEABILITY_PATH, "w", encoding="utf-8") as handle:
        handle.write(traceability)
    print(f"edns_behavior_cases={len(rows) - 1}")


if __name__ == "__main__":
    main()
PY

cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"
log_format = "logfmt"
nsid = "edns-node"

[rrl]
enabled = false

[limits]
max_udp_payload = 700
max_concurrent_transfers = 1
tcp_idle_timeout_secs = 5
edns_padding_block_size = 32
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600
graceful_shutdown_secs = 2

[[zones]]
name = "edns.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

cargo build -p oxidedns-cli >/dev/null

python3 "$fake_primary" "$primary_port" "$primary_log" &
primary_pid=$!

for _ in {1..100}; do
  if grep -q "READY" "$primary_log" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if ! grep -q "READY" "$primary_log" 2>/dev/null; then
  echo "fake EDNS primary did not become ready" >&2
  exit 1
fi

"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=0
for _ in {1..200}; do
  if curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.05
done
if (( ready != 1 )); then
  echo "OxideDNS did not become ready during EDNS behavior interop" >&2
  exit 1
fi

client_summary="$(python3 "$client" "$oxidedns_dns_port" "$client_log" "$summary_tsv" "$traceability_tsv")"
metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
  'oxidedns_zones_active 1' \
  'oxidedns_queries_truncated_total 7'; do
  if [[ "$metrics" != *"$expected"* ]]; then
    echo "metrics missing expected EDNS behavior line: $expected" >&2
    exit 1
  fi
done

if [[ -n "$artifact_dir" ]]; then
  mkdir -p "$artifact_dir"
  cp "$primary_log" "$artifact_dir/fake-primary.log"
  cp "$client_log" "$artifact_dir/client.log"
  cp "$workdir/oxidedns.log" "$artifact_dir/oxidedns.log"
  cp "$oxidedns_conf" "$artifact_dir/oxidedns.toml"
  cp "$summary_tsv" "$artifact_dir/edns-summary.tsv"
  cp "$traceability_tsv" "$artifact_dir/edns-traceability.tsv"
  printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
fi

printf '%s\n' "$client_summary"
