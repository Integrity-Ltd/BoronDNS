#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in docker dig curl python3 cargo awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping Knot DNSSEC Docker interop: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "skipping Knot DNSSEC Docker interop: Docker daemon is unavailable" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/interop-version-evidence.sh"
zone_file="$repo_root/tests/interop/knot/alpha-dnssec.test.zone"
template_file="$repo_root/tests/interop/knot/knot-dnssec.conf.template"
workdir="$repo_root/target/interop/knot-dnssec-$$"
container="oxidedns-knot-dnssec-$$"
mkdir -p "$workdir"

cleanup() {
    local status=$?
    if [[ -n "${oxidedns_pid:-}" ]] && kill -0 "$oxidedns_pid" 2>/dev/null; then
        kill "$oxidedns_pid" 2>/dev/null || true
        wait "$oxidedns_pid" 2>/dev/null || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- knot container logs ----" >&2
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if ((status != 0)); then
        [[ -f "$workdir/dnssec-client.log" ]] && {
            echo "---- dnssec-client.log ----" >&2
            tail -120 "$workdir/dnssec-client.log" >&2
        }
        [[ -f "$workdir/oxidedns.log" ]] && {
            echo "---- oxidedns.log ----" >&2
            tail -120 "$workdir/oxidedns.log" >&2
        }
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

read -r knot_port oxidedns_dns_port oxidedns_health_port < <(
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

cp "$zone_file" "$workdir/alpha.test.zone"
cp "$template_file" "$workdir/knot.conf"

set +e
knot_probe="$(
    docker run --rm \
        -v "$workdir:/work" \
        alpine:latest \
        sh -c 'apk add --no-cache knot >/dev/null && mkdir -p /tmp/knot-db && knotc -c /work/knot.conf conf-check' \
        2>&1
)"
knot_probe_status=$?
set -e

if ((knot_probe_status != 0)); then
    echo "skipping Knot DNSSEC Docker interop: Alpine/Knot rejected DNSSEC signing configuration" >&2
    printf '%s\n' "$knot_probe" >&2
    exit 0
fi

if ! docker run -d --name "$container" \
    -p "127.0.0.1:$knot_port:5353/tcp" \
    -p "127.0.0.1:$knot_port:5353/udp" \
    -v "$workdir:/work" \
    alpine:latest \
    sh -c 'apk add --no-cache knot >/dev/null && mkdir -p /tmp/knot-db && knotd -c /work/knot.conf -v' \
    >/dev/null; then
    echo "skipping Knot DNSSEC Docker interop: failed to start Alpine/Knot container" >&2
    exit 0
fi
record_docker_primary_version "$workdir" "$container" "Knot DNS" "alpine:latest" "knot" "knot-dnssec" "tcp-axfr" "dnssec-signed-primary" "knotd -V" "$workdir/knot.conf" "$zone_file"

for _ in {1..120}; do
    if dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +time=1 +tries=1 +short >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

primary_soa="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. SOA +time=1 +tries=1 +short)"
signed_serial="$(awk '{ print $3; exit }' <<<"$primary_soa")"
if [[ -z "$signed_serial" ]] || ((signed_serial <= 2026052404)); then
    echo "skipping Knot DNSSEC Docker interop: Knot did not publish a DNSSEC-signed SOA serial" >&2
    echo "SOA response: $primary_soa" >&2
    exit 0
fi

primary_axfr="$(dig "@127.0.0.1" -p "$knot_port" alpha.test. AXFR +time=3 +tries=1)"
for rrtype in DNSKEY RRSIG NSEC3 NSEC3PARAM; do
    if ! awk -v rrtype="$rrtype" '$4 == rrtype { found = 1 } END { exit(found ? 0 : 1) }' <<<"$primary_axfr"; then
        echo "skipping Knot DNSSEC Docker interop: Knot AXFR did not include $rrtype after signing" >&2
        exit 0
    fi
done

nsec3_owner="$(awk '$4 == "NSEC3" { print $1; exit }' <<<"$primary_axfr")"
if [[ -z "$nsec3_owner" ]]; then
    echo "skipping Knot DNSSEC Docker interop: could not identify an NSEC3 owner in Knot AXFR" >&2
    exit 0
fi

dnssec_client="$workdir/dnssec-client.py"
cat >"$dnssec_client" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
NSEC3_OWNER = sys.argv[3]
LOG_PATH = sys.argv[4]

A = 1
NS = 2
AAAA = 28
SOA = 6
DS = 43
RRSIG = 46
DNSKEY = 48
NSEC3 = 50
OPT = 41


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


def query(qid, qname, qtype, payload=None, do=False):
    packet = bytearray()
    packet.extend(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1 if payload else 0))
    packet.extend(name_wire(qname))
    packet.extend(struct.pack("!HH", qtype, 1))
    if payload:
        ttl = 0x8000 if do else 0
        packet.extend(b"\x00")
        packet.extend(struct.pack("!HHIH", OPT, payload, ttl, 0))
    return bytes(packet)


def parse_name(packet, offset):
    labels = []
    consumed = 0
    jumped = False
    seen = set()
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("compression loop")
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
            return ".".join(labels) + ".", consumed
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
        if not jumped:
            consumed += length


def skip_questions(packet, offset, count):
    for _ in range(count):
        _, consumed = parse_name(packet, offset)
        offset += consumed + 4
    return offset


def parse_records(packet, offset, count):
    records = []
    for _ in range(count):
        owner, consumed = parse_name(packet, offset)
        offset += consumed
        rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlength]
        offset += rdlength
        records.append({"owner": owner, "type": rrtype, "class": rrclass, "ttl": ttl, "rdata": rdata})
    return records, offset


def exchange(qid, qname, qtype, payload=None, do=False, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(query(qid, qname, qtype, payload=payload, do=do), (HOST, PORT))
    packet, _ = sock.recvfrom(8192)
    header = struct.unpack("!HHHHHH", packet[:12])
    rid, flags, qdcount, ancount, nscount, arcount = header
    if rid != qid:
        raise AssertionError(f"mismatched qid: got {rid} expected {qid}")
    offset = skip_questions(packet, 12, qdcount)
    answers, offset = parse_records(packet, offset, ancount)
    authorities, offset = parse_records(packet, offset, nscount)
    additionals, offset = parse_records(packet, offset, arcount)
    opt_ttls = [record["ttl"] for record in additionals if record["type"] == OPT]
    summary = {
        "flags": flags,
        "rcode": flags & 0x000F,
        "tc": bool(flags & 0x0200),
        "ad": bool(flags & 0x0020),
        "cd": bool(flags & 0x0010),
        "answer_types": [record["type"] for record in answers],
        "authority_types": [record["type"] for record in authorities],
        "additional_types": [record["type"] for record in additionals],
        "answer_owners": [record["owner"] for record in answers],
        "authority_owners": [record["owner"] for record in authorities],
        "additional_owners": [record["owner"] for record in additionals],
        "opt_ttls": opt_ttls,
        "size": len(packet),
    }
    log(f"{qname} type={qtype} do={int(do)} payload={payload} summary={summary}")
    return summary


def has_response_do(summary):
    return bool(summary["opt_ttls"] and summary["opt_ttls"][0] & 0x8000)


positive_do = exchange(0xA001, "www.alpha.test.", A, payload=4096, do=True)
if positive_do["rcode"] != 0 or positive_do["tc"]:
    raise AssertionError(f"positive DO response failed: {positive_do}")
if A not in positive_do["answer_types"] or RRSIG not in positive_do["answer_types"]:
    raise AssertionError(f"positive DO did not include A and covering RRSIG: {positive_do}")
if not has_response_do(positive_do):
    raise AssertionError(f"positive DO response did not copy query DO bit: {positive_do}")
if positive_do["ad"] or positive_do["cd"]:
    raise AssertionError(f"positive DO response set AD/CD unexpectedly: {positive_do}")

positive_non_do = exchange(0xA002, "www.alpha.test.", A, payload=4096, do=False)
if positive_non_do["rcode"] != 0 or A not in positive_non_do["answer_types"]:
    raise AssertionError(f"positive non-DO response failed: {positive_non_do}")
if RRSIG in positive_non_do["answer_types"] or has_response_do(positive_non_do):
    raise AssertionError(f"positive non-DO response leaked DNSSEC augmentation: {positive_non_do}")

wildcard_do = exchange(0xA008, "wildcard-hit.alpha.test.", A, payload=4096, do=True)
if wildcard_do["rcode"] != 0 or wildcard_do["tc"]:
    raise AssertionError(f"wildcard positive DO response failed: {wildcard_do}")
if wildcard_do["answer_types"] != [A] or wildcard_do["answer_owners"] != ["wildcard-hit.alpha.test."]:
    raise AssertionError(f"wildcard positive DO did not synthesize the requested owner A RR: {wildcard_do}")
if NSEC3 not in wildcard_do["authority_types"] or RRSIG not in wildcard_do["authority_types"]:
    raise AssertionError(f"wildcard positive DO lacked NSEC3/RRSIG exact-name absence proof: {wildcard_do}")
if not has_response_do(wildcard_do):
    raise AssertionError(f"wildcard positive DO response did not copy query DO bit: {wildcard_do}")

nxdomain_do = exchange(0xA003, "missing.mail.alpha.test.", A, payload=4096, do=True)
if nxdomain_do["rcode"] != 3:
    raise AssertionError(f"NXDOMAIN DO did not return NXDOMAIN: {nxdomain_do}")
if SOA not in nxdomain_do["authority_types"] or NSEC3 not in nxdomain_do["authority_types"] or RRSIG not in nxdomain_do["authority_types"]:
    raise AssertionError(f"NXDOMAIN DO lacked SOA/NSEC3/RRSIG proof material: {nxdomain_do}")
if not has_response_do(nxdomain_do):
    raise AssertionError(f"NXDOMAIN DO response did not copy query DO bit: {nxdomain_do}")

nodata_do = exchange(0xA004, "www.alpha.test.", AAAA, payload=4096, do=True)
if nodata_do["rcode"] != 0 or nodata_do["answer_types"]:
    raise AssertionError(f"NODATA DO did not return empty NOERROR answer: {nodata_do}")
if SOA not in nodata_do["authority_types"] or NSEC3 not in nodata_do["authority_types"] or RRSIG not in nodata_do["authority_types"]:
    raise AssertionError(f"NODATA DO lacked SOA/NSEC3/RRSIG proof material: {nodata_do}")

signed_referral_do = exchange(0xA009, "www.signed-child.alpha.test.", A, payload=4096, do=True)
if signed_referral_do["rcode"] != 0 or signed_referral_do["answer_types"]:
    raise AssertionError(f"signed-child referral DO did not return empty NOERROR answer: {signed_referral_do}")
if NS not in signed_referral_do["authority_types"] or DS not in signed_referral_do["authority_types"] or RRSIG not in signed_referral_do["authority_types"]:
    raise AssertionError(f"signed-child referral DO lacked NS/DS/RRSIG authority proof: {signed_referral_do}")
if NSEC3 in signed_referral_do["authority_types"]:
    raise AssertionError(f"signed-child referral DO unexpectedly used NSEC3 no-DS proof: {signed_referral_do}")
if not has_response_do(signed_referral_do):
    raise AssertionError(f"signed-child referral DO response did not copy query DO bit: {signed_referral_do}")

unsigned_referral_do = exchange(0xA00A, "www.unsigned-child.alpha.test.", A, payload=4096, do=True)
if unsigned_referral_do["rcode"] != 0 or unsigned_referral_do["answer_types"]:
    raise AssertionError(f"unsigned-child referral DO did not return empty NOERROR answer: {unsigned_referral_do}")
if NS not in unsigned_referral_do["authority_types"] or NSEC3 not in unsigned_referral_do["authority_types"] or RRSIG not in unsigned_referral_do["authority_types"]:
    raise AssertionError(f"unsigned-child referral DO lacked NS/NSEC3/RRSIG no-DS proof: {unsigned_referral_do}")
if DS in unsigned_referral_do["authority_types"]:
    raise AssertionError(f"unsigned-child referral DO unexpectedly included DS proof: {unsigned_referral_do}")
if not has_response_do(unsigned_referral_do):
    raise AssertionError(f"unsigned-child referral DO response did not copy query DO bit: {unsigned_referral_do}")

dnskey = exchange(0xA005, "alpha.test.", DNSKEY, payload=4096, do=False)
if DNSKEY not in dnskey["answer_types"] or RRSIG in dnskey["answer_types"]:
    raise AssertionError(f"direct non-DO DNSKEY query did not serve only transferred DNSKEY records: {dnskey}")

nsec3_do = exchange(0xA006, NSEC3_OWNER, NSEC3, payload=4096, do=True)
if nsec3_do["rcode"] != 0 or NSEC3 not in nsec3_do["answer_types"] or RRSIG not in nsec3_do["answer_types"]:
    raise AssertionError(f"direct NSEC3 DO query did not serve NSEC3 plus covering RRSIG: {nsec3_do}")
if not has_response_do(nsec3_do):
    raise AssertionError(f"direct NSEC3 DO response did not copy query DO bit: {nsec3_do}")

nsec3_non_do = exchange(0xA007, NSEC3_OWNER, NSEC3, payload=4096, do=False)
if nsec3_non_do["answer_types"] != [NSEC3]:
    raise AssertionError(f"direct non-DO NSEC3 query did not suppress covering RRSIG: {nsec3_non_do}")
if has_response_do(nsec3_non_do):
    raise AssertionError(f"direct non-DO NSEC3 query failed to copy cleared query DO bit: {nsec3_non_do}")

print("Knot signed-primary DNSSEC runtime interop passed")
PY

oxidedns_conf="$workdir/oxidedns.toml"
cat >"$oxidedns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$oxidedns_dns_port"]
listen_tcp = ["127.0.0.1:$oxidedns_dns_port"]
health = "127.0.0.1:$oxidedns_health_port"
log_level = "info"

[rrl]
enabled = false

[limits]
max_udp_payload = 1232
axfr_timeout_secs = 5
ixfr_timeout_secs = 5
zsm_min_interval_secs = 60
zsm_initial_retry_secs = 1
zsm_initial_retry_max_secs = 2
graceful_shutdown_secs = 2

[[zones]]
name = "alpha.test."
class = "IN"
primaries = ["127.0.0.1:$knot_port"]
notify_sources = ["127.0.0.1"]
EOF

cargo build -p oxidedns-cli >/dev/null
"$repo_root/target/debug/oxidedns" serve --config "$oxidedns_conf" >"$workdir/oxidedns.log" 2>&1 &
oxidedns_pid=$!

ready=""
for _ in {1..100}; do
    if ready="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/readyz" 2>/dev/null)"; then
        [[ "$ready" == "ready" ]] && break
    fi
    sleep 0.1
done

if [[ "$ready" != "ready" ]]; then
    echo "OxideDNS did not become ready after Knot signed AXFR" >&2
    exit 1
fi

client_summary="$(python3 "$dnssec_client" 127.0.0.1 "$oxidedns_dns_port" "$nsec3_owner" "$workdir/dnssec-client.log")"
echo "$client_summary"

metrics="$(curl -fsS "http://127.0.0.1:$oxidedns_health_port/metrics")"
for expected in \
    'oxidedns_zones_active 1' \
    "oxidedns_zone_soa_serial{zone=\"alpha.test.\"} $signed_serial" \
    'oxidedns_transfer_sessions_started_total{protocol="axfr"} 1' \
    'oxidedns_transfer_sessions_completed_total{protocol="axfr"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "OxideDNS metrics missing expected line after Knot signed AXFR: $expected" >&2
        exit 1
    fi
done

echo "Knot Docker signed-primary DNSSEC interop passed"
