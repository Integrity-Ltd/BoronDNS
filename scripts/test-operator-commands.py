#!/usr/bin/env python3
"""Bounded loopback CLI/daemon/BoronGen/BIND integration; use prebuilt binaries."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(check, message):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.05)
    raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--borondns", required=True, type=Path)
    parser.add_argument("--boron-gen", required=True, type=Path)
    args = parser.parse_args()
    checkzone = shutil.which("named-checkzone")
    if checkzone is None:
        raise SystemExit("named-checkzone is required for dump interoperability")
    dns, gen = str(args.borondns.resolve()), str(args.boron_gen.resolve())
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("BORONDNS_", "BORON_GEN_"))}
    # Public fixture key, not a credential.
    env["BORON_GEN_TSIG_SECRET"] = "dG9wc2VjcmV0"
    with tempfile.TemporaryDirectory(prefix="borondns-operator-e2e-") as directory:
        root = Path(directory)
        sock = root / "control.sock"
        primary_port, dns_port = free_port(), free_port()
        zone = "load.borongen."
        config = root / "config.toml"
        config.write_text(f'''[server]
operator_socket = "{sock}"
listen_udp = ["127.0.0.1:{dns_port}"]
listen_tcp = ["127.0.0.1:{dns_port}"]
zone_cache_directory = "{root / 'cache'}"
log_format = "plain"
[limits]
max_tcp_connections = 16
max_concurrent_transfers = 2
graceful_shutdown_secs = 1
[transfer]
require_tsig = true
[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret = "dG9wc2VjcmV0"
[[zones]]
name = "{zone}"
primaries = ["127.0.0.1:{primary_port}"]
tsig_key = "transfer-key."
''')
        processes = []
        with (root / "primary.log").open("wb") as primary_log, (root / "server.log").open("wb") as server_log:
            try:
                processes.append(subprocess.Popen([
                    gen, "serve", "--listen", f"127.0.0.1:{primary_port}",
                    "--profile", "mixed", "--zones", "1", "--names-per-zone", "100",
                    "--records-per-name", "2", "--structural-rrsigs", "false",
                ], env=env, stdout=primary_log, stderr=subprocess.STDOUT))

                def primary_ready():
                    assert processes[0].poll() is None, "BoronGen exited"
                    try:
                        with socket.create_connection(("127.0.0.1", primary_port), timeout=0.2):
                            return True
                    except OSError:
                        return False

                wait_for(primary_ready, "BoronGen did not start")
                server = subprocess.Popen([dns, "serve", "--config", str(config)], env=env,
                                          stdout=server_log, stderr=subprocess.STDOUT)
                processes.append(server)

                def command(action, name=zone, check=True):
                    return subprocess.run([dns, "zone", "--socket", str(sock), action, name],
                                          env=env, capture_output=True, text=True, check=check, timeout=10)

                def active():
                    assert server.poll() is None, "BoronDNS exited"
                    if not sock.exists():
                        return False
                    result = command("show", check=False)
                    return result.returncode == 0 and json.loads(result.stdout)["state"] == "active"

                wait_for(active, "zone did not become active")
                shown = json.loads(command("show", zone.upper().rstrip(".")).stdout)
                assert shown["serial"] == 1 and shown["records"] > 100
                dumped = command("dump").stdout
                assert len(dumped.splitlines()) == shown["records"]
                zone_file = root / "dump.zone"
                zone_file.write_text(dumped)
                checked = subprocess.run([checkzone, zone, str(zone_file)], capture_output=True,
                                         text=True, timeout=10)
                assert checked.returncode == 0, checked.stdout + checked.stderr
                assert command("show", "missing.test.", check=False).returncode != 0
                assert json.loads(command("refresh").stdout)["status"] == "queued"
                wait_for(lambda: "SOA poll matched the current zone serial" in (root / "server.log").read_text(),
                         "ordinary refresh did not confirm current serial")
                before = (root / "server.log").read_text().count("AXFR completed")
                assert json.loads(command("retransfer").stdout)["status"] == "queued"
                wait_for(lambda: (root / "server.log").read_text().count("AXFR completed") > before,
                         "same-serial retransfer did not complete AXFR")
                assert json.loads(command("show").stdout)["serial"] == 1
                assert sorted(command("dump").stdout.splitlines()) == sorted(dumped.splitlines())
                server.terminate()
                assert server.wait(timeout=5) == 0
                assert not sock.exists(), "shutdown left the operator socket behind"
                assert b"\x1b" not in (root / "server.log").read_bytes()
                print(f"operator_commands_e2e=passed records={shown['records']} bind_dump=passed signed_retransfer=passed cleanup=passed")
            except BaseException:
                for log in ["server.log", "primary.log"]:
                    print(f"{log}:\n{(root / log).read_text(errors='replace')[-12000:]}")
                raise
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)


if __name__ == "__main__":
    main()
