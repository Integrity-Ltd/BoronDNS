"""Validate wildcard NSEC3 answers after a real signed AXFR, on loopback only.

Run explicitly with --binary /absolute/path/to/borondns. Requires BIND named,
dnssec-keygen, dnssec-signzone, dig and delv on PATH; no tools are auto-installed.
Uses fresh test-only keys, an explicit example.test trust anchor and signatures
valid at the host's current clock. Retains logs/fixtures in a private temp dir.
On AppArmor hosts, use --work-parent with a test-user-writable directory under
/var/cache/bind (do not disable the host's named policy). Use ulimit -n 65536
before running, consistent with BoronDNS's supported descriptor budget.
Default mode tests compact serving after AXFR. --ixfr updates and re-signs the
primary zone and requires an incremental journal before checking dirty-overlay
answers. --opt-out adds omitted-delegation/ENT cases and requires the primary and
secondary validator classifications to agree, including legitimate insecurity.
This is bounded scenario coverage, not general DNSSEC compliance certification.
Missing prerequisites fail rather than silently skip.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument(
        "--ixfr",
        action="store_true",
        help="also validate a signed incremental overlay after primary reload",
    )
    parser.add_argument(
        "--opt-out",
        action="store_true",
        help="permit intentional Opt-Out insecurity and test omitted delegations",
    )
    parser.add_argument(
        "--work-parent", type=Path, help="parent allowed by named's host sandbox"
    )
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for tool in ("named", "dnssec-keygen", "dnssec-signzone", "dig", "delv"):
        if shutil.which(tool) is None:
            raise SystemExit(f"missing required tool: {tool}")
    if os.geteuid() == 0:
        raise SystemExit("run as an unprivileged test user")
    work = Path(
        tempfile.mkdtemp(prefix="borondns-nsec3-validation-", dir=args.work_parent)
    )
    print(f"evidence={work}", flush=True)
    processes = []
    logs = []

    def run(command, label, check=True):
        result = subprocess.run(
            command,
            cwd=work,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        (work / f"{label}.log").write_text(result.stdout)
        if check and result.returncode:
            raise AssertionError(
                f"{label} failed ({result.returncode}): {result.stdout}"
            )
        return result

    def start(command, label):
        log = (work / f"{label}.log").open("w")
        logs.append(log)
        process = subprocess.Popen(
            command, cwd=work, stdout=log, stderr=subprocess.STDOUT
        )
        processes.append(process)
        return process

    def wait_soa(port, process, serial="2026090801"):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(
                    f"server exited: {process.returncode}; inspect {work}"
                )
            result = run(
                [
                    "dig",
                    "@127.0.0.1",
                    "-p",
                    str(port),
                    "example.test.",
                    "SOA",
                    "+short",
                    "+time=1",
                    "+tries=1",
                ],
                f"ready-{port}",
                check=False,
            )
            if result.returncode == 0 and serial in result.stdout:
                return
            time.sleep(0.1)
        raise AssertionError(f"SOA readiness deadline exceeded: {port}")

    reserved = []
    try:
        for _ in range(3):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            reserved.append(sock)
        primary_port, dns_port, health_port = [
            sock.getsockname()[1] for sock in reserved
        ]
    finally:
        for sock in reserved:
            sock.close()

    try:
        ksk = run(
            [
                "dnssec-keygen",
                "-q",
                "-a",
                "ECDSAP256SHA256",
                "-f",
                "KSK",
                "example.test.",
            ],
            "keygen-ksk",
        ).stdout.strip()
        zsk = run(
            ["dnssec-keygen", "-q", "-a", "ECDSAP256SHA256", "example.test."],
            "keygen-zsk",
        ).stdout.strip()
        records = [
            "$ORIGIN example.test.",
            "$TTL 300",
            "@ IN SOA ns hostmaster 2026090801 60 10 3600 300",
            "@ IN NS ns",
            "ns IN A 127.0.0.1",
            "* IN A 192.0.2.20",
            "alias-lower IN CNAME deep.missing.example.test.",
            "alias-mixed IN CNAME deep.MiSsInG.ExAmPlE.TeSt.",
        ] + [f'anchor-{i} IN TXT "x"' for i in range(32)]
        if args.ixfr:
            records.extend(
                [
                    "*.a IN CNAME deep.missing.b.example.test.",
                    "*.b IN A 192.0.2.80",
                    "alias-chain IN CNAME deep.missing.a.example.test.",
                    "negative IN CNAME missing.anchor-0.example.test.",
                    "dname IN DNAME target.example.test.",
                    "www.target IN A 192.0.2.81",
                    "www.dname IN A 192.0.2.1",
                    "child.branch IN NS ns.example.test.",
                ]
            )
        (work / "unsigned.zone").write_text("\n".join(records) + "\n")
        signing_command = [
            "dnssec-signzone",
            "-n",
            "1",
            "-S",
            "-3",
            "-",
            "-H",
            "1",
            "-o",
            "example.test.",
            "-f",
            "signed.zone",
            "unsigned.zone",
            ksk,
            zsk,
        ]
        if args.opt_out:
            signing_command.insert(1, "-A")
        run(signing_command, "signzone")
        key_line = next(
            line
            for line in (work / f"{ksk}.key").read_text().splitlines()
            if not line.startswith(";") and "DNSKEY" in line
        )
        flags, protocol, algorithm, *key_parts = key_line.split("DNSKEY", 1)[1].split()
        key = "".join(key_parts)
        (work / "anchor.conf").write_text(
            f'trust-anchors {{ "example.test." static-key {flags} {protocol} {algorithm} "{key}"; }};\n'
        )
        (work / "named.conf").write_text(f'''
options {{
    directory "{work}";
    listen-on port {primary_port} {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    recursion no;
    dnssec-validation no;
    pid-file "{work}/named.pid";
    session-keyfile "{work}/session.key";
}};
controls {{ }};
zone "example.test." {{ type primary; file "signed.zone"; allow-transfer {{ 127.0.0.1; }};
    ixfr-from-differences yes; max-ixfr-ratio unlimited;
    notify explicit; also-notify {{ 127.0.0.1 port {dns_port}; }};
}};
''')
        primary = start(
            ["named", "-g", "-n", "1", "-c", str(work / "named.conf")], "named"
        )
        wait_soa(primary_port, primary)
        (work / "cache").mkdir()
        (work / "borondns.toml").write_text(f'''
[server]
listen_udp = ["127.0.0.1:{dns_port}"]
listen_tcp = ["127.0.0.1:{dns_port}"]
health = "127.0.0.1:{health_port}"
zone_cache_directory = "{work}/cache"
[zone_publication]
strategy = "sharded"
sharded_rrset_threshold = 1
overlay_compaction_dirty_owner_threshold = 0
[rrl]
enabled = false
[limits]
graceful_shutdown_secs = 1
[[zones]]
name = "example.test."
class = "IN"
primaries = ["127.0.0.1:{primary_port}"]
notify_sources = ["127.0.0.1"]
''')
        server = start(
            [str(binary), "serve", "--config", str(work / "borondns.toml")], "borondns"
        )
        wait_soa(dns_port, server)
        if args.ixfr:
            shutil.copy2(work / "signed.zone", work / "signed-before-ixfr.zone")
            records = [line.replace("2026090801", "2026090802") for line in records]
            records.append('anchor-new IN TXT "changed"')
            (work / "unsigned.zone").write_text("\n".join(records) + "\n")
            run(signing_command, "signzone-ixfr")
            primary.send_signal(signal.SIGHUP)
            wait_soa(primary_port, primary, "2026090802")
            wait_soa(dns_port, server, "2026090802")
            assert list((work / "cache").glob("*.bdj")), (
                "expected an incremental journal, not only AXFR replacement"
            )
            with urllib.request.urlopen(
                f"http://127.0.0.1:{health_port}/metrics", timeout=5
            ) as response:
                metrics = response.read().decode()
            (work / "metrics-after-ixfr.txt").write_text(metrics)
        outcomes = []
        queries = [
            (name, "A")
            for name in (
                "deep.missing.example.test.",
                "deep.MiSsInG.ExAmPlE.TeSt.",
                "alias-lower.example.test.",
                "alias-mixed.example.test.",
            )
        ]
        if args.ixfr:
            queries.extend(
                [
                    ("deep.missing.b.example.test.", "A"),
                    ("alias-chain.example.test.", "A"),
                    ("negative.example.test.", "A"),
                    ("www.dname.example.test.", "A"),
                    ("deep.missing.b.example.test.", "AAAA"),
                ]
            )
        if args.opt_out:
            queries.extend(
                [
                    ("child.branch.example.test.", "DS"),
                    ("missing.branch.example.test.", "A"),
                    ("branch.example.test.", "A"),
                ]
            )
        for name, kind in queries:
            for backend, port in (("primary", primary_port), ("borondns", dns_port)):
                label = f"{backend}-{name}-{kind}"
                run(
                    [
                        "dig",
                        "@127.0.0.1",
                        "-p",
                        str(port),
                        name,
                        kind,
                        "+dnssec",
                        "+nocookie",
                        "+time=2",
                        "+tries=1",
                    ],
                    f"wire-{label}",
                )
                result = run(
                    [
                        "delv",
                        "@127.0.0.1",
                        "-p",
                        str(port),
                        "-a",
                        str(work / "anchor.conf"),
                        "+root=example.test.",
                        "+vtrace",
                        name,
                        kind,
                    ],
                    f"validation-{label}",
                    check=False,
                )
                lines = result.stdout.splitlines()
                classification = "bogus-or-error"
                if result.returncode == 0:
                    if any(
                        line
                        in ("; fully validated", "; negative response, fully validated")
                        for line in lines
                    ):
                        classification = "secure"
                    elif any(
                        line.startswith(
                            (
                                "; unsigned answer",
                                "; negative response, unsigned answer",
                            )
                        )
                        for line in lines
                    ):
                        classification = "insecure"
                outcomes.append(
                    {
                        "backend": backend,
                        "name": name,
                        "type": kind,
                        "exit": result.returncode,
                        "classification": classification,
                    }
                )
        report = {
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "signer": run(["dnssec-signzone", "-V"], "signer-version").stdout.strip(),
            "validator": run(["delv", "-v"], "validator-version").stdout.strip(),
            "signed_zone_sha256": hashlib.sha256(
                (work / "signed.zone").read_bytes()
            ).hexdigest(),
            "clock_unix": time.time(),
            "outcomes": outcomes,
        }
        (work / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
        allowed = {"secure", "insecure"} if args.opt_out else {"secure"}
        assert all(result["classification"] in allowed for result in outcomes), (
            f"DNSSEC validation failed; inspect {work}"
        )
        assert all(
            outcomes[index]["classification"] == outcomes[index + 1]["classification"]
            for index in range(0, len(outcomes), 2)
        ), "primary/secondary validation classes differ"
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
