#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in python3 cargo curl awk find; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing+=("$tool")
    fi
done

if ((${#missing[@]} > 0)); then
    printf 'skipping read-only runtime audit: missing %s\n' "${missing[*]}" >&2
    exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$repo_root/target/readonly-runtime/$$"
artifact_dir="${BORONDNS_READONLY_RUNTIME_ARTIFACT_DIR:-}"
container_mode="${BORONDNS_READONLY_RUNTIME_CONTAINER:-0}"
container_image="${BORONDNS_READONLY_RUNTIME_CONTAINER_IMAGE:-debian:trixie-slim}"
primary_container_image="${BORONDNS_READONLY_RUNTIME_PRIMARY_IMAGE:-rust:1.94.1-bookworm}"
container=""
primary_container=""
container_network=""
container_summary="container_readonly_rootfs=not_requested"
mkdir -p "$workdir"

stop_borondns() {
    if [[ -n "${borondns_pid:-}" ]] && kill -0 "$borondns_pid" 2>/dev/null; then
        kill "$borondns_pid" 2>/dev/null || true
        wait "$borondns_pid" 2>/dev/null || true
    fi
    borondns_pid=""
}

cleanup() {
    local status=$?
    stop_borondns
    if [[ -n "$container" ]] && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Fx "$container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- container borondns logs ----" >&2
            docker logs "$container" >&2 || true
        fi
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$primary_container" ]] && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Fx "$primary_container" >/dev/null 2>&1; then
        if ((status != 0)); then
            echo "---- container fake-primary logs ----" >&2
            docker logs "$primary_container" >&2 || true
        fi
        docker rm -f "$primary_container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$container_network" ]] && docker network inspect "$container_network" >/dev/null 2>&1; then
        docker network rm "$container_network" >/dev/null 2>&1 || true
    fi
    if [[ -n "${primary_pid:-}" ]] && kill -0 "$primary_pid" 2>/dev/null; then
        kill "$primary_pid" 2>/dev/null || true
        wait "$primary_pid" 2>/dev/null || true
    fi
    chmod -R u+w "$workdir" 2>/dev/null || true
    if ((status != 0)); then
        [[ -f "$workdir/fake-primary.log" ]] && {
            echo "---- fake-primary.log ----" >&2
            tail -120 "$workdir/fake-primary.log" >&2
        }
        [[ -f "$workdir/client.log" ]] && {
            echo "---- client.log ----" >&2
            tail -120 "$workdir/client.log" >&2
        }
        [[ -f "$workdir/borondns.log" ]] && {
            echo "---- borondns.log ----" >&2
            tail -120 "$workdir/borondns.log" >&2
        }
        [[ -f "$workdir/strace.log" ]] && {
            echo "---- strace.log ----" >&2
            tail -120 "$workdir/strace.log" >&2
        }
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

container_enabled() {
    case "$container_mode" in
    0 | false | False | FALSE | no | No | NO | "")
        return 1
        ;;
    1 | true | True | TRUE | yes | Yes | YES | required | Required | REQUIRED | auto | Auto | AUTO)
        return 0
        ;;
    *)
        echo "invalid BORONDNS_READONLY_RUNTIME_CONTAINER value: $container_mode" >&2
        exit 2
        ;;
    esac
}

container_required() {
    case "$container_mode" in
    1 | true | True | TRUE | yes | Yes | YES | required | Required | REQUIRED)
        return 0
        ;;
    *)
        return 1
        ;;
    esac
}

skip_container_audit() {
    local reason="$1"
    if container_required; then
        echo "read-only container runtime audit required but unavailable: $reason" >&2
        exit 1
    fi
    container_summary="container_readonly_rootfs=skipped container_skip_reason=$reason"
}

read -r primary_port borondns_dns_port borondns_health_port < <(
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
borondns_conf="$workdir/borondns.toml"
container_borondns_conf="$workdir/container-borondns.toml"
proc_status="$workdir/proc-status.txt"
readonly_tmp="$workdir/readonly-tmp"
mkdir "$readonly_tmp"
chmod 0555 "$readonly_tmp"

cat >"$fake_primary" <<'PY'
#!/usr/bin/env python3
import socket
import struct
import sys
import threading

HOST = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
ZONE = "readonly.test."
IN = 1
A = 1
NS = 2
SOA = 6
AXFR = 252


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
    return qname, qtype, qclass, packet[12:offset + 4]


def rr(owner, rrtype, rdata, ttl=60):
    return b"".join([
        name_wire(owner),
        struct.pack("!HHIH", rrtype, IN, ttl, len(rdata)),
        rdata,
    ])


def soa_rdata(serial=2026052502):
    return b"".join([
        name_wire("ns1.readonly.test."),
        name_wire("hostmaster.readonly.test."),
        struct.pack("!IIIII", serial, 60, 30, 300, 60),
    ])


def zone_records():
    soa = rr(ZONE, SOA, soa_rdata())
    return [
        soa,
        rr(ZONE, NS, name_wire("ns1.readonly.test.")),
        rr("ns1.readonly.test.", A, bytes([127, 0, 0, 1])),
        rr("www.readonly.test.", A, bytes([192, 0, 2, 25])),
        soa,
    ]


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
        qname, qtype, qclass, question = parse_question(query)
        if qname.lower() != ZONE or qtype != AXFR or qclass != IN:
            response = struct.pack("!HHHHHH", qid, 0x8004, 1, 0, 0, 0) + question
        else:
            answers = zone_records()
            log(f"TCP AXFR served records={len(answers)}")
            response = struct.pack("!HHHHHH", qid, 0x8000, 1, len(answers), 0, 0) + question + b"".join(answers)
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

PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]


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


query = (
    struct.pack("!HHHHHH", 0x7025, 0x0100, 1, 0, 0, 0)
    + name_wire("www.readonly.test.")
    + struct.pack("!HH", 1, 1)
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.sendto(query, ("127.0.0.1", PORT))
response, _ = sock.recvfrom(2048)
qid, flags, qdcount, ancount = struct.unpack("!HHHH", response[:8])
if qid != 0x7025:
    raise AssertionError(f"mismatched qid={qid}")
if flags & 0x000F:
    raise AssertionError(f"unexpected rcode={flags & 0x000F}")
if qdcount != 1 or ancount != 1:
    raise AssertionError(f"unexpected counts qd={qdcount} an={ancount}")
summary = f"udp_query_answered=1 response_bytes={len(response)}"
log(summary)
print(summary)
PY

cat >"$borondns_conf" <<EOF
[server]
listen_udp = ["127.0.0.1:$borondns_dns_port"]
listen_tcp = ["127.0.0.1:$borondns_dns_port"]
health = "127.0.0.1:$borondns_health_port"
log_level = "warn"
log_format = "plain"

[rrl]
enabled = false

[health]
max_connections = 8

[limits]
max_tcp_connections = 16
udp_reuseport_workers = 1
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "readonly.test."
class = "IN"
primaries = ["127.0.0.1:$primary_port"]
EOF

cargo build -p borondns-cli >/dev/null

python3 "$fake_primary" "$primary_port" "$primary_log" "0.0.0.0" &
primary_pid=$!

for _ in {1..100}; do
    if grep -q "READY" "$primary_log" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
if ! grep -q "READY" "$primary_log" 2>/dev/null; then
    echo "fake readonly primary did not become ready" >&2
    exit 1
fi

borondns_cmd=("$repo_root/target/debug/borondns" serve --config "$borondns_conf")
trace_status="not_available"
if command -v strace >/dev/null 2>&1; then
    trace_status="captured"
    # Keep the traced server as this shell's direct child so `$!`, shutdown,
    # thread accounting, and the no-child-process assertion all target the
    # server rather than strace's supervisor process.
    TMPDIR="$readonly_tmp" strace -D -f -e trace=%file -o "$workdir/strace.log" "${borondns_cmd[@]}" >"$workdir/borondns.log" 2>&1 &
else
    TMPDIR="$readonly_tmp" "${borondns_cmd[@]}" >"$workdir/borondns.log" 2>&1 &
fi
borondns_pid=$!

ready=0
for _ in {1..200}; do
    if curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.05
done
if ((ready != 1)); then
    echo "BoronDNS did not become ready during read-only runtime audit" >&2
    exit 1
fi

if [[ ! -d "/proc/$borondns_pid/task" ]]; then
    echo "BoronDNS /proc task view is unavailable during read-only runtime audit" >&2
    exit 1
fi
thread_count="$(find "/proc/$borondns_pid/task" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

child_pids=()
if [[ -d /proc ]]; then
    while IFS= read -r status_file; do
        pid="$(awk '/^Pid:/ { print $2 }' "$status_file" 2>/dev/null || true)"
        ppid="$(awk '/^PPid:/ { print $2 }' "$status_file" 2>/dev/null || true)"
        if [[ -n "$pid" && "$ppid" == "$borondns_pid" ]]; then
            child_pids+=("$pid")
        fi
    done < <(find /proc -mindepth 2 -maxdepth 2 -path '/proc/[0-9]*/status' -print 2>/dev/null)
fi
child_process_count="${#child_pids[@]}"
{
    printf 'borondns_pid=%s\n' "$borondns_pid"
    printf 'thread_count=%s\n' "$thread_count"
    printf 'child_process_count=%s\n' "$child_process_count"
    for child_pid in "${child_pids[@]}"; do
        printf 'child_pid=%s\n' "$child_pid"
    done
} >"$proc_status"
if ((child_process_count > 0)); then
    echo "BoronDNS spawned child processes during read-only runtime audit" >&2
    cat "$proc_status" >&2
    exit 1
fi

client_summary="$(python3 "$client" "$borondns_dns_port" "$client_log")"
metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
for expected in \
    'borondns_zones_active 1' \
    'borondns_secondary_queries_total{zone="readonly.test."} 1' \
    'borondns_secondary_query_responses_total{zone="readonly.test.",rcode="NOERROR"} 1'; do
    if [[ "$metrics" != *"$expected"* ]]; then
        echo "metrics missing expected read-only runtime line: $expected" >&2
        exit 1
    fi
done

write_intent_findings=0
if [[ "$trace_status" == "captured" ]]; then
    if grep -E 'open(at)?\(.*O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)|creat\(|mkdir|mkdirat|rename|renameat|unlink|unlinkat|rmdir' "$workdir/strace.log" >"$workdir/write-intent.log"; then
        write_intent_findings="$(wc -l <"$workdir/write-intent.log" | tr -d ' ')"
    fi
    if ((write_intent_findings > 0)); then
        echo "runtime file write intent observed under strace" >&2
        cat "$workdir/write-intent.log" >&2
        exit 1
    fi
fi

run_container_audit() {
    local container_client_log="$workdir/container-client.log"
    local container_metrics_file="$workdir/container-metrics.txt"
    local container_proc_status="$workdir/container-proc-status.txt"
    local container_inspect="$workdir/container-inspect.json"
    local container_mountinfo="$workdir/container-mountinfo.txt"
    local container_probe="$workdir/container-readonly-probe.txt"
    local container_log="$workdir/container-borondns.log"
    local container_pid
    local container_ready=0
    local container_thread_count
    local container_child_process_count
    local container_client_summary
    local container_metrics
    local docker_readonly
    local image_id
    local primary_container_ip
    local child_pids=()

    container_summary="container_readonly_rootfs=skipped container_skip_reason=not_requested"
    container_enabled || return 0

    if ! command -v docker >/dev/null 2>&1; then
        skip_container_audit "docker_missing"
        return 0
    fi
    if ! docker info >/dev/null 2>&1; then
        skip_container_audit "docker_daemon_unavailable"
        return 0
    fi
    if ! docker image inspect "$container_image" >/dev/null 2>&1; then
        skip_container_audit "container_image_missing"
        return 0
    fi
    if ! docker image inspect "$primary_container_image" >/dev/null 2>&1; then
        skip_container_audit "primary_container_image_missing"
        return 0
    fi

    stop_borondns
    container="borondns-readonly-runtime-$$"
    primary_container="borondns-readonly-primary-$$"
    container_network="borondns-readonly-runtime-$$"
    if ! docker network create "$container_network" >/dev/null; then
        skip_container_audit "container_network_create_failed"
        return 0
    fi
    if ! docker run -d --name "$primary_container" \
        --network "$container_network" \
        -v "$fake_primary:/work/fake-primary.py:ro" \
        -v "$workdir:/work/out" \
        "$primary_container_image" \
        python3 /work/fake-primary.py 5353 /work/out/container-fake-primary.log 0.0.0.0 \
        >/dev/null; then
        skip_container_audit "primary_container_start_failed"
        return 0
    fi
    for _ in {1..100}; do
        if grep -q "READY" "$workdir/container-fake-primary.log" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done
    if ! grep -q "READY" "$workdir/container-fake-primary.log" 2>/dev/null; then
        echo "container fake readonly primary did not become ready" >&2
        exit 1
    fi
    primary_container_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$primary_container")"
    if [[ -z "$primary_container_ip" ]]; then
        skip_container_audit "primary_container_ip_unavailable"
        return 0
    fi

    cat >"$container_borondns_conf" <<EOF
[server]
listen_udp = ["0.0.0.0:$borondns_dns_port"]
listen_tcp = ["0.0.0.0:$borondns_dns_port"]
health = "0.0.0.0:$borondns_health_port"
log_level = "warn"
log_format = "plain"

[rrl]
enabled = false

[health]
max_connections = 8

[limits]
max_tcp_connections = 16
udp_reuseport_workers = 1
max_concurrent_transfers = 1
zsm_min_interval_secs = 3600
zsm_initial_retry_secs = 3600

[[zones]]
name = "readonly.test."
class = "IN"
primaries = ["$primary_container_ip:5353"]
EOF
    image_id="$(docker image inspect --format '{{.Id}}' "$container_image")"
    if ! docker run -d --name "$container" \
        --read-only \
        --network "$container_network" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        -p "127.0.0.1:$borondns_dns_port:$borondns_dns_port/udp" \
        -p "127.0.0.1:$borondns_dns_port:$borondns_dns_port/tcp" \
        -p "127.0.0.1:$borondns_health_port:$borondns_health_port/tcp" \
        -e TMPDIR=/tmp \
        -v "$repo_root/target/debug/borondns:/usr/local/bin/borondns:ro" \
        -v "$container_borondns_conf:/etc/borondns/borondns.toml:ro" \
        "$container_image" \
        /usr/local/bin/borondns serve --config /etc/borondns/borondns.toml \
        >/dev/null; then
        skip_container_audit "container_start_failed"
        return 0
    fi

    docker inspect "$container" >"$container_inspect"
    docker_readonly="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")"
    if [[ "$docker_readonly" != "true" ]]; then
        echo "container did not start with read-only root filesystem" >&2
        exit 1
    fi

    for _ in {1..200}; do
        if curl -fsS "http://127.0.0.1:$borondns_health_port/readyz" >/dev/null 2>&1; then
            container_ready=1
            break
        fi
        sleep 0.05
    done
    if ((container_ready != 1)); then
        echo "containerized BoronDNS did not become ready during read-only runtime audit" >&2
        exit 1
    fi

    container_pid="$(docker inspect --format '{{.State.Pid}}' "$container")"
    if [[ -z "$container_pid" || "$container_pid" == "0" || ! -d "/proc/$container_pid/task" ]]; then
        echo "containerized BoronDNS /proc task view is unavailable during read-only runtime audit" >&2
        exit 1
    fi
    cp "/proc/$container_pid/mountinfo" "$container_mountinfo"
    container_thread_count="$(find "/proc/$container_pid/task" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

    while IFS= read -r status_file; do
        pid="$(awk '/^Pid:/ { print $2 }' "$status_file" 2>/dev/null || true)"
        ppid="$(awk '/^PPid:/ { print $2 }' "$status_file" 2>/dev/null || true)"
        if [[ -n "$pid" && "$ppid" == "$container_pid" ]]; then
            child_pids+=("$pid")
        fi
    done < <(find /proc -mindepth 2 -maxdepth 2 -path '/proc/[0-9]*/status' -print 2>/dev/null)
    container_child_process_count="${#child_pids[@]}"
    {
        printf 'container=%s\n' "$container"
        printf 'container_pid=%s\n' "$container_pid"
        printf 'thread_count=%s\n' "$container_thread_count"
        printf 'child_process_count=%s\n' "$container_child_process_count"
        for child_pid in "${child_pids[@]}"; do
            printf 'child_pid=%s\n' "$child_pid"
        done
    } >"$container_proc_status"
    if ((container_child_process_count > 0)); then
        echo "containerized BoronDNS spawned child processes during read-only runtime audit" >&2
        cat "$container_proc_status" >&2
        exit 1
    fi

    if docker exec "$container" sh -c 'touch /tmp/borondns-readonly-runtime-probe' >"$container_probe" 2>&1; then
        echo "container accepted a write to /tmp under read-only root filesystem" >&2
        cat "$container_probe" >&2
        exit 1
    fi

    container_client_summary="$(python3 "$client" "$borondns_dns_port" "$container_client_log")"
    container_client_summary="container_${container_client_summary// / container_}"
    container_metrics="$(curl -fsS "http://127.0.0.1:$borondns_health_port/metrics")"
    for expected in \
        'borondns_zones_active 1' \
        'borondns_secondary_queries_total{zone="readonly.test."} 1' \
        'borondns_secondary_query_responses_total{zone="readonly.test.",rcode="NOERROR"} 1'; do
        if [[ "$container_metrics" != *"$expected"* ]]; then
            echo "container metrics missing expected read-only runtime line: $expected" >&2
            exit 1
        fi
    done
    printf '%s\n' "$container_metrics" >"$container_metrics_file"
    docker logs "$container" >"$container_log" 2>&1 || true
    container_summary="container_readonly_rootfs=1 container_readyz=1 ${container_client_summary} container_child_processes=${container_child_process_count} container_thread_count=${container_thread_count} container_write_probe=denied container_image=${container_image} container_image_id=${image_id}"
}

run_container_audit

summary="readonly_tmp=1 readyz=1 ${client_summary} child_processes=${child_process_count} thread_count=${thread_count} strace=${trace_status} write_intent_findings=${write_intent_findings} ${container_summary}"
printf '%s\n' "$summary"

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    cp "$primary_log" "$artifact_dir/fake-primary.log"
    cp "$client_log" "$artifact_dir/client.log"
    cp "$workdir/borondns.log" "$artifact_dir/borondns.log"
    cp "$proc_status" "$artifact_dir/proc-status.txt"
    cp "$borondns_conf" "$artifact_dir/borondns.toml"
    if [[ -f "$container_borondns_conf" ]]; then
        cp "$container_borondns_conf" "$artifact_dir/container-borondns.toml"
    fi
    printf '%s\n' "$summary" >"$artifact_dir/readonly-runtime-summary.env"
    printf '%s\n' "$metrics" >"$artifact_dir/metrics.txt"
    if [[ -f "$workdir/container-client.log" ]]; then
        cp "$workdir/container-client.log" "$artifact_dir/container-client.log"
    fi
    if [[ -f "$workdir/container-metrics.txt" ]]; then
        cp "$workdir/container-metrics.txt" "$artifact_dir/container-metrics.txt"
    fi
    if [[ -f "$workdir/container-borondns.log" ]]; then
        cp "$workdir/container-borondns.log" "$artifact_dir/container-borondns.log"
    fi
    if [[ -f "$workdir/container-fake-primary.log" ]]; then
        cp "$workdir/container-fake-primary.log" "$artifact_dir/container-fake-primary.log"
    fi
    if [[ -f "$workdir/container-proc-status.txt" ]]; then
        cp "$workdir/container-proc-status.txt" "$artifact_dir/container-proc-status.txt"
    fi
    if [[ -f "$workdir/container-inspect.json" ]]; then
        cp "$workdir/container-inspect.json" "$artifact_dir/container-inspect.json"
    fi
    if [[ -f "$workdir/container-mountinfo.txt" ]]; then
        cp "$workdir/container-mountinfo.txt" "$artifact_dir/container-mountinfo.txt"
    fi
    if [[ -f "$workdir/container-readonly-probe.txt" ]]; then
        cp "$workdir/container-readonly-probe.txt" "$artifact_dir/container-readonly-probe.txt"
    fi
    if [[ -f "$workdir/strace.log" ]]; then
        cp "$workdir/strace.log" "$artifact_dir/strace.log"
    fi
    if [[ -f "$workdir/write-intent.log" ]]; then
        cp "$workdir/write-intent.log" "$artifact_dir/write-intent.log"
    fi
fi
