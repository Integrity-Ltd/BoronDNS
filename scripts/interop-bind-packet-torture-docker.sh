#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in cargo docker python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping BIND packet torture interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping BIND packet torture interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/interop/bind-packet-torture-$$"
artifact_dir="${OXIDEDNS_BIND_PACKET_TORTURE_ARTIFACT_DIR:-}"
bind_container="oxidedns-bind-torture-$$"
oxide_container="oxidedns-oxide-torture-$$"
client_container="oxidedns-dumpcap-client-$$"
oxide_image_ref="${OXIDEDNS_BIND_PACKET_TORTURE_IMAGE_REF:-oxidedns:bind-packet-torture}"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    for container in "$client_container" "$oxide_container" "$bind_container"; do
        if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
            if ((status != 0)); then
                echo "---- $container logs ----" >&2
                docker logs "$container" >&2 || true
            fi
            docker rm -f "$container" >/dev/null 2>&1 || true
        fi
    done
    if ((status != 0)); then
        for log in "$workdir"/named.log "$workdir"/oxidedns.log "$workdir"/client.log "$workdir"/diff.txt; do
            [[ -f "$log" ]] || continue
            echo "---- ${log##*/} ----" >&2
            tail -160 "$log" >&2
        done
    fi
    if [[ -n "$artifact_dir" ]]; then
        mkdir -p "$artifact_dir"
        cp -a "$workdir"/. "$artifact_dir"/
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

read -r bind_port oxidedns_dns_port oxidedns_health_port < <(
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

cat >"$workdir/named.conf" <<'EOF'
options {
    directory "/work";
    listen-on port 5353 { any; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    minimal-responses no;
    notify no;
    request-ixfr no;
    pid-file "/work/named.pid";
    session-keyfile "/work/session.key";
};

zone "torture.test" IN {
    type primary;
    file "/work/torture.test.zone";
    allow-query { any; };
    allow-transfer { any; };
    notify no;
};

zone "long.torture.test" IN {
    type primary;
    file "/work/long.torture.test.zone";
    allow-query { any; };
    allow-transfer { any; };
    notify no;
};
EOF

cat >"$workdir/torture.test.zone" <<'EOF'
$ORIGIN torture.test.
$TTL 300
@ 3600 IN SOA ns1.torture.test. hostmaster.torture.test. (
    2026052601 60 30 300 300 )
@ 300 IN NS ns1.torture.test.
@ 300 IN NS ns2.torture.test.
ns1 300 IN A 192.0.2.1
ns1 300 IN AAAA 2001:db8::1
ns2 300 IN A 192.0.2.2
ns2 300 IN AAAA 2001:db8::2

apex-a 300 IN A 192.0.2.10
apex-a 300 IN A 192.0.2.11
v6 300 IN AAAA 2001:db8:1::10
txt-short 300 IN TXT "short text"
txt-long 300 IN TXT "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "cccccccccccccccccccccccccccccccc"
hinfo 300 IN HINFO "RFC8482" "OxideDNS"
alias 300 IN CNAME apex-a.torture.test.
ptr-target 300 IN PTR apex-a.torture.test.
@ 300 IN MX 10 mail.torture.test.
mail 300 IN A 192.0.2.25
mail 300 IN AAAA 2001:db8:1::25
_sip._tcp 300 IN SRV 10 20 5060 sip.torture.test.
sip 300 IN A 192.0.2.30
sip 300 IN AAAA 2001:db8:1::30
naptr 300 IN NAPTR 100 50 "s" "SIP+D2U" "" _sip._udp.torture.test.
_sip._udp 300 IN SRV 10 10 5060 sip.torture.test.
dname 300 IN DNAME target.torture.test.
target 300 IN A 192.0.2.40
tlsa 300 IN TLSA 3 1 1 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
uri 300 IN URI 10 1 "https://example.invalid/path?query=value"
caa 300 IN CAA 0 issue "ca.example.invalid"
dschild 300 IN NS ns.dschild.torture.test.
ns.dschild 300 IN A 192.0.2.60
ns.dschild 300 IN AAAA 2001:db8:1::60
dschild 300 IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
dnskey 300 IN DNSKEY 257 3 8 AwEAAXN1YmplY3R0b2NoYW5nZQ==
svc-target 300 IN A 192.0.2.55
svc-target 300 IN AAAA 2001:db8:1::55
svc 300 IN SVCB 1 svc-target.torture.test. alpn="h2,h3" port=8443 ipv4hint=192.0.2.55 ipv6hint=2001:db8:1::55
https 300 IN HTTPS 1 svc-target.torture.test. alpn="h2" port=443 ipv4hint=192.0.2.55
opaque 300 IN TYPE65280 \# 0
opaque 300 IN TYPE65280 \# 4 C00C00FF
opaque 300 IN TYPE65280 \# 13 4361736553656E736974697665
future 300 IN TYPE65000 \# 4 01020304
l63-abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc 300 IN A 192.0.2.63
EOF

cat >"$workdir/long.torture.test.zone" <<'EOF'
$ORIGIN long.torture.test.
$TTL 300
@ 3600 IN SOA ns1.long.torture.test. hostmaster.long.torture.test. (
    2026052602 60 30 300 300 )
@ 300 IN NS ns1.long.torture.test.
ns1 300 IN A 192.0.2.101
deep-label-01.deep-label-02.deep-label-03.deep-label-04.deep-label-05 300 IN A 192.0.2.105
wild 300 IN TXT "wildcard-control"
*.wild 300 IN A 192.0.2.200
EOF

cat >"$workdir/oxidedns.toml" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"
log_format = "json"

[rrl]
enabled = false

[query]
any_response = "full"

[limits]
max_udp_payload = 4096
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 1
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "torture.test."
class = "IN"
primaries = ["127.0.0.1:$bind_port"]
notify_sources = ["127.0.0.1"]

[[zones]]
name = "long.torture.test."
class = "IN"
primaries = ["127.0.0.1:$bind_port"]
notify_sources = ["127.0.0.1"]
EOF

cat >"$workdir/client.py" <<'PY'
#!/usr/bin/env python3
import ipaddress
import json
import socket
import struct
import sys
import time

BIND_PORT = int(sys.argv[1])
OXIDE_PORT = int(sys.argv[2])
SUMMARY = sys.argv[3]
DIFF = sys.argv[4]
LOG = sys.argv[5]
HOST = "127.0.0.1"
IN = 1

TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "HINFO": 13,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "NAPTR": 35,
    "DNAME": 39,
    "DS": 43,
    "DNSKEY": 48,
    "TLSA": 52,
    "SVCB": 64,
    "HTTPS": 65,
    "URI": 256,
    "CAA": 257,
    "TYPE65000": 65000,
    "TYPE65280": 65280,
}

QUERIES = [
    ("torture.test.", "SOA"),
    ("torture.test.", "NS"),
    ("apex-a.torture.test.", "A"),
    ("v6.torture.test.", "AAAA"),
    ("txt-short.torture.test.", "TXT"),
    ("txt-long.torture.test.", "TXT"),
    ("hinfo.torture.test.", "HINFO"),
    ("alias.torture.test.", "A"),
    ("alias.torture.test.", "CNAME"),
    ("ptr-target.torture.test.", "PTR"),
    ("torture.test.", "MX"),
    ("_sip._tcp.torture.test.", "SRV"),
    ("naptr.torture.test.", "NAPTR"),
    ("below.dname.torture.test.", "A"),
    ("dname.torture.test.", "DNAME"),
    ("tlsa.torture.test.", "TLSA"),
    ("uri.torture.test.", "URI"),
    ("caa.torture.test.", "CAA"),
    ("dschild.torture.test.", "DS"),
    ("dnskey.torture.test.", "DNSKEY"),
    ("svc.torture.test.", "SVCB"),
    ("https.torture.test.", "HTTPS"),
    ("opaque.torture.test.", "TYPE65280"),
    ("future.torture.test.", "TYPE65000"),
    ("l63-abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc.torture.test.", "A"),
    ("deep-label-01.deep-label-02.deep-label-03.deep-label-04.deep-label-05.long.torture.test.", "A"),
    ("name.wild.long.torture.test.", "A"),
    ("missing.torture.test.", "A"),
    ("txt-short.torture.test.", "AAAA"),
]


def log(message):
    with open(LOG, "a", encoding="utf-8") as handle:
        print(message, file=handle, flush=True)


def name_wire(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise AssertionError(f"label too long: {label}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_name(packet, offset):
    labels = []
    consumed = 0
    jumped = False
    seen = set()
    while True:
        if offset >= len(packet):
            raise AssertionError("name offset outside packet")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise AssertionError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise AssertionError("compression pointer loop")
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
            return (".".join(labels) + "." if labels else "."), consumed
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
        if not jumped:
            consumed += length


def parse_character_strings(rdata):
    values = []
    offset = 0
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        values.append(rdata[offset:offset + length].hex())
        offset += length
    if offset != len(rdata):
        raise AssertionError("bad character-string rdata")
    return values


def parse_svcb_params(rdata, offset):
    params = []
    while offset < len(rdata):
        key, length = struct.unpack("!HH", rdata[offset:offset + 4])
        offset += 4
        value = rdata[offset:offset + length]
        offset += length
        params.append((key, value.hex()))
    return tuple(params)


def canonical_rdata(packet, rrtype, rdata, rdata_offset):
    if rrtype == TYPES["A"]:
        return str(ipaddress.IPv4Address(rdata))
    if rrtype == TYPES["AAAA"]:
        return str(ipaddress.IPv6Address(rdata))
    if rrtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"], TYPES["DNAME"]):
        name, _ = parse_name(packet, rdata_offset)
        return name
    if rrtype == TYPES["SOA"]:
        mname, used = parse_name(packet, rdata_offset)
        rname, used2 = parse_name(packet, rdata_offset + used)
        values = struct.unpack("!IIIII", packet[rdata_offset + used + used2:rdata_offset + used + used2 + 20])
        return (mname, rname, values)
    if rrtype == TYPES["MX"]:
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = parse_name(packet, rdata_offset + 2)
        return (preference, exchange)
    if rrtype == TYPES["SRV"]:
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = parse_name(packet, rdata_offset + 6)
        return (priority, weight, port, target)
    if rrtype == TYPES["NAPTR"]:
        order, preference = struct.unpack("!HH", rdata[:4])
        offset = 4
        fields = []
        for _ in range(3):
            length = rdata[offset]
            offset += 1
            fields.append(rdata[offset:offset + length].hex())
            offset += length
        replacement, _ = parse_name(packet, rdata_offset + offset)
        return (order, preference, tuple(fields), replacement)
    if rrtype in (TYPES["TXT"], TYPES["HINFO"]):
        return tuple(parse_character_strings(rdata))
    if rrtype == TYPES["DS"]:
        key_tag, algorithm, digest_type = struct.unpack("!HBB", rdata[:4])
        return (key_tag, algorithm, digest_type, rdata[4:].hex())
    if rrtype == TYPES["DNSKEY"]:
        flags, protocol, algorithm = struct.unpack("!HBB", rdata[:4])
        return (flags, protocol, algorithm, rdata[4:].hex())
    if rrtype == TYPES["TLSA"]:
        usage, selector, matching_type = struct.unpack("!BBB", rdata[:3])
        return (usage, selector, matching_type, rdata[3:].hex())
    if rrtype == TYPES["URI"]:
        priority, weight = struct.unpack("!HH", rdata[:4])
        return (priority, weight, rdata[4:].hex())
    if rrtype == TYPES["CAA"]:
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii")
        value = rdata[2 + tag_len:].hex()
        return (flags, tag, value)
    if rrtype in (TYPES["SVCB"], TYPES["HTTPS"]):
        priority = struct.unpack("!H", rdata[:2])[0]
        target, used = parse_name(packet, rdata_offset + 2)
        return (priority, target, parse_svcb_params(rdata, 2 + used))
    return rdata.hex()


def build_query(qid, qname, qtype):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + name_wire(qname)
        + struct.pack("!HH", qtype, IN)
    )


def exchange(port, packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(packet, (HOST, port))
        response, _ = sock.recvfrom(8192)
        return response
    finally:
        sock.close()


def parse_response(packet):
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    questions = []
    for _ in range(qdcount):
        qname, used = parse_name(packet, offset)
        offset += used
        qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
        offset += 4
        questions.append((qname, qtype, qclass))
    sections = []
    for count in (ancount, nscount, arcount):
        records = []
        for _ in range(count):
            owner, used = parse_name(packet, offset)
            offset += used
            rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata_offset = offset
            rdata = packet[offset:offset + rdlength]
            offset += rdlength
            records.append((owner, rrtype, rrclass, ttl, canonical_rdata(packet, rrtype, rdata, rdata_offset)))
        sections.append(tuple(sorted(records, key=repr)))
    return {
        "id": qid,
        "rcode": flags & 0xF,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "ra": bool(flags & 0x0080),
        "questions": tuple(questions),
        "answers": sections[0],
        "authorities": sections[1],
        "additionals": sections[2],
    }


def comparable(parsed):
    return {
        "rcode": parsed["rcode"],
        "aa": parsed["aa"],
        "tc": parsed["tc"],
        "questions": parsed["questions"],
        "answers": parsed["answers"],
        "authorities": parsed["authorities"],
        "additionals": parsed["additionals"],
    }


def positive_required_additionals(cmp, bind_reference, qtype):
    if not cmp["answers"]:
        return cmp["additionals"]

    target_names = set()
    if qtype == TYPES["NS"]:
        target_names.update(record[4] for record in bind_reference["answers"])
    elif qtype == TYPES["MX"]:
        target_names.update(record[4][1] for record in bind_reference["answers"])
    elif qtype == TYPES["SRV"]:
        target_names.update(record[4][3] for record in bind_reference["answers"])
    elif qtype in (TYPES["SVCB"], TYPES["HTTPS"]):
        target_names.update(record[4][1] for record in bind_reference["answers"] if record[4][1] != ".")
    elif qtype == TYPES["NAPTR"]:
        target_names.update(record[4][3] for record in bind_reference["answers"])

    if not target_names:
        return tuple()

    return tuple(
        sorted(
            (
                record
                for record in cmp["additionals"]
                if record[0] in target_names and record[1] in (TYPES["A"], TYPES["AAAA"])
            ),
            key=repr,
        )
    )


def comparable_for_qtype(parsed, bind_reference, qtype):
    cmp = comparable(parsed)
    if cmp["answers"]:
        cmp["authorities"] = tuple()
        cmp["additionals"] = positive_required_additionals(cmp, bind_reference, qtype)
    return cmp


def main():
    failures = []
    with open(SUMMARY, "w", encoding="utf-8") as summary:
        print("qname\tqtype\trcode\tanswers\tauthorities\tadditionals\tstatus", file=summary)
        for index, (qname, qtype_name) in enumerate(QUERIES, start=1):
            qtype = TYPES[qtype_name]
            qid = 0x5000 + index
            packet = build_query(qid, qname, qtype)
            bind = parse_response(exchange(BIND_PORT, packet))
            oxide = parse_response(exchange(OXIDE_PORT, packet))
            bind_cmp = comparable(bind)
            oxide_cmp = comparable_for_qtype(oxide, bind_cmp, qtype)
            bind_cmp = comparable_for_qtype(bind, bind_cmp, qtype)
            status = "match" if bind_cmp == oxide_cmp else "mismatch"
            print(
                f"{qname}\t{qtype_name}\t{oxide['rcode']}\t{len(oxide['answers'])}\t"
                f"{len(oxide['authorities'])}\t{len(oxide['additionals'])}\t{status}",
                file=summary,
            )
            log(f"{status} qname={qname} qtype={qtype_name}")
            if status != "match":
                failures.append((qname, qtype_name, bind_cmp, oxide_cmp))
            time.sleep(0.02)
    if failures:
        with open(DIFF, "w", encoding="utf-8") as diff:
            for qname, qtype_name, bind_cmp, oxide_cmp in failures:
                print(f"### {qname} {qtype_name}", file=diff)
                print("BIND:", file=diff)
                print(json.dumps(bind_cmp, indent=2, sort_keys=True, default=str), file=diff)
                print("OxideDNS:", file=diff)
                print(json.dumps(oxide_cmp, indent=2, sort_keys=True, default=str), file=diff)
        raise SystemExit(f"{len(failures)} packet-content comparison mismatches")
    with open(DIFF, "w", encoding="utf-8") as diff:
        print("all packet-content comparisons matched", file=diff)


if __name__ == "__main__":
    main()
PY
chmod +x "$workdir/client.py"

if ! docker run -d --name "$bind_container" \
    -p "127.0.0.1:$bind_port:5353/tcp" \
    -p "127.0.0.1:$bind_port:5353/udp" \
    -v "$workdir:/work:rw" \
    alpine:latest \
    sh -c 'apk add --no-cache bind bind-tools >/dev/null && named-checkconf -z /work/named.conf && named -g -c /work/named.conf -n 1' \
    >/dev/null; then
    echo "skipping BIND packet torture interop: failed to start Alpine/BIND container" >&2
    exit 0
fi

for _ in {1..120}; do
    if python3 - "$bind_port" <<'PY' >/dev/null 2>&1; then
import socket
import struct
import sys

port = int(sys.argv[1])
query = (
    struct.pack("!HHHHHH", 0xB100, 0x0100, 1, 0, 0, 0)
    + b"\x07torture\x04test\x00"
    + struct.pack("!HH", 6, 1)
)
sock = socket.create_connection(("127.0.0.1", port), timeout=1)
sock.sendall(struct.pack("!H", len(query)) + query)
length = struct.unpack("!H", sock.recv(2))[0]
response = sock.recv(length)
if struct.pack("!I", 2026052601) not in response:
    raise SystemExit(1)
PY
        break
    fi
    sleep 0.25
done

if ! python3 - "$bind_port" <<'PY' >"$workdir/bind-ready-soa.txt"; then
import socket
import struct
import sys

port = int(sys.argv[1])
query = (
    struct.pack("!HHHHHH", 0xB101, 0x0100, 1, 0, 0, 0)
    + b"\x07torture\x04test\x00"
    + struct.pack("!HH", 6, 1)
)
sock = socket.create_connection(("127.0.0.1", port), timeout=1)
sock.sendall(struct.pack("!H", len(query)) + query)
length = struct.unpack("!H", sock.recv(2))[0]
response = sock.recv(length)
print(response.hex())
if struct.pack("!I", 2026052601) not in response:
    raise SystemExit(1)
PY
    echo "BIND packet torture primary did not serve expected SOA" >&2
    cat "$workdir/bind-ready-soa.txt" >&2
    exit 1
fi

OXIDEDNS_DIST_DIR="$workdir/dist" \
    OXIDEDNS_DOCKER_IMAGE_REF="$oxide_image_ref" \
    "$repo_root/scripts/package-docker-image.sh" >/dev/null

docker run -d \
    --name "$oxide_container" \
    --network host \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 128 \
    --memory 256m \
    -v "$workdir/oxidedns.toml:/etc/oxidedns-secondary/config.toml:ro" \
    "$oxide_image_ref" \
    serve --config /etc/oxidedns-secondary/config.toml \
    >"$workdir/oxidedns-container-id.txt"

ready=""
for _ in {1..120}; do
    if ready="$(
        docker exec "$oxide_container" \
            wget -qO- "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null
    )"; then
        [[ "$ready" == "ready" || "$ready" == *'"status":"ready"'* ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != "ready" && "$ready" != *'"status":"ready"'* ]]; then
    echo "OxideDNS did not become ready for packet torture comparison" >&2
    exit 1
fi

docker logs "$oxide_container" >"$workdir/oxidedns.log" 2>&1 || true

docker run --rm \
    --name "$client_container" \
    --network host \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v "$workdir:/work:rw" \
    alpine:latest \
    sh -c "apk add --no-cache python3 wireshark-common >/dev/null; \
        dumpcap -i lo -f 'udp and (port $bind_port or port $oxidedns_dns_port)' -w /work/dns-torture.pcapng -q >/work/dumpcap.log 2>&1 & \
        cap_pid=\$!; sleep 0.4; \
        python3 /work/client.py '$bind_port' '$oxidedns_dns_port' /work/summary.tsv /work/diff.txt /work/client.log; \
        sleep 0.4; kill \$cap_pid >/dev/null 2>&1 || true; wait \$cap_pid >/dev/null 2>&1 || true"

docker logs "$bind_container" >"$workdir/named.log" 2>&1 || true
docker logs "$oxide_container" >"$workdir/oxidedns.log" 2>&1 || true
docker exec "$oxide_container" \
    wget -qO- "http://127.0.0.1:$oxidedns_health_port/metrics" \
    >"$workdir/metrics.txt"

if [[ ! -s "$workdir/dns-torture.pcapng" ]]; then
    echo "dumpcap did not retain packet capture output" >&2
    exit 1
fi

grep -F $'\tmatch' "$workdir/summary.tsv" >/dev/null
if grep -F $'\tmismatch' "$workdir/summary.tsv" >/dev/null; then
    echo "BIND/OxideDNS packet-content mismatch detected" >&2
    exit 1
fi

printf 'BIND packet torture interop passed: %s\n' "$workdir/summary.tsv"
