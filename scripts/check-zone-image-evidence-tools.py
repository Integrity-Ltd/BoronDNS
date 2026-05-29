#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPARATOR = REPO_ROOT / "scripts" / "compare-zone-image-benchmarks.py"
ZONE_IMAGE_GATE = REPO_ROOT / "scripts" / "zone-image-evidence-gate.sh"
DNS_CLIENT_BENCHMARK = REPO_ROOT / "scripts" / "benchmark-dns-clients.sh"


BASE_RESULTS = {
    "git_revision": "0123456789ab",
    "git_dirty": "true",
    "kernel_version": "Linux 6.0.0-test x86_64 GNU/Linux",
    "rustc_version": "rustc 1.99.0-test",
    "cargo_version": "cargo 1.99.0-test",
    "build_profile": "release",
    "server_bin_sha256": "a" * 64,
    "client_bin_sha256": "b" * 64,
    "remote_client_bin_sha256": "none",
    "transport": "udp",
    "records_configured": "1000",
    "stress_candidates_configured": "128",
    "server_threads": "4",
    "client_threads": "4",
    "client_window": "16",
    "listen_address": "127.0.0.1",
    "client_server": "127.0.0.1",
    "client_bind": "127.0.0.1:0",
    "client_mode": "local",
    "remote_client_ssh": "none",
    "remote_client_local_arch": "none",
    "remote_client_remote_arch": "none",
    "remote_client_local_host_id": "none",
    "remote_client_remote_host_id": "none",
    "remote_client_same_host": "none",
    "remote_client_allow_arch_mismatch": "none",
    "require_non_loopback_device": "false",
    "network_snapshot_dir": "network",
    "network_rx_packets_delta": "60000",
    "network_tx_packets_delta": "70000",
    "duration_seconds": "1",
    "query_mode": "trace",
    "trace_queries": "3",
    "pipeline_timing_enabled": "false",
    "dropped": "0",
    "errors": "0",
    "responses_per_second": "100000",
    "latency_us_p50": "100.0",
    "latency_us_p99": "200.0",
    "latency_us_p999": "300.0",
}


def write_tsv(path: Path, rows: dict[str, str]) -> None:
    path.write_text(
        "metric\tvalue\n" + "".join(f"{key}\t{value}\n" for key, value in rows.items()),
        encoding="utf-8",
    )


def read_tsv(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        if header[:2] != ["metric", "value"]:
            raise SystemExit(f"{path}: unexpected TSV header")
        for line in handle:
            fields = line.rstrip("\n").split("\t")
            if len(fields) >= 2:
                rows[fields[0]] = fields[1]
    return rows


def update_results(root: Path, updates: dict[str, str]) -> None:
    path = root / "benchmark-results.tsv"
    rows = read_tsv(path)
    rows.update(updates)
    write_tsv(path, rows)


def write_network_deltas(
    path: Path,
    *,
    good: bool = True,
    dropped: bool = False,
    low_packets: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if low_packets:
        rx_packets = 100
        tx_packets = 120
        rx_bytes = 6400
        tx_bytes = 7680
    else:
        rx_packets = 60000 if good else 0
        tx_packets = 70000 if good else 0
        rx_bytes = 3840000 if good else 0
        tx_bytes = 4480000 if good else 0
    rx_drop = 1 if dropped else 0
    path.write_text(
        "\n".join(
            [
                "metric\tbefore\tafter\tdelta\tunit",
                f"rx_bytes\t0\t{rx_bytes}\t{rx_bytes}\tcount",
                f"rx_packets\t0\t{rx_packets}\t{rx_packets}\tcount",
                "rx_errs\t0\t0\t0\tcount",
                f"rx_drop\t0\t{rx_drop}\t{rx_drop}\tcount",
                f"tx_bytes\t0\t{tx_bytes}\t{tx_bytes}\tcount",
                f"tx_packets\t0\t{tx_packets}\t{tx_packets}\tcount",
                "tx_errs\t0\t0\t0\tcount",
                "tx_drop\t0\t0\t0\tcount",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_artifact(
    root: Path,
    *,
    zone_image: bool,
    network_device: str,
    good_network: bool = True,
    dropped_network: bool = False,
    low_network_packets: bool = False,
    require_non_loopback_device: bool | None = None,
    direct_hits: int = 900,
    semantic_hits: int = 300,
    fallbacks: int = 0,
    summary_rx_packets_delta: int | None = None,
    summary_tx_packets_delta: int | None = None,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    results = dict(BASE_RESULTS)
    results["network_device"] = network_device
    if network_device not in {"lo", "unknown", ""}:
        results["listen_address"] = "192.0.2.10"
        results["client_server"] = "192.0.2.10"
        results["client_bind"] = "0.0.0.0:0"
        results["client_mode"] = "ssh"
        results["remote_client_ssh"] = "bench-client.example.net"
        results["remote_client_local_arch"] = "x86_64"
        results["remote_client_remote_arch"] = "x86_64"
        results["remote_client_local_host_id"] = "local-host"
        results["remote_client_remote_host_id"] = "remote-host"
        results["remote_client_same_host"] = "false"
        results["remote_client_allow_arch_mismatch"] = "false"
        results["remote_client_bin_sha256"] = results["client_bin_sha256"]
        results["require_non_loopback_device"] = "true"
    if require_non_loopback_device is not None:
        results["require_non_loopback_device"] = (
            "true" if require_non_loopback_device else "false"
        )
    if low_network_packets:
        results["network_rx_packets_delta"] = "100"
        results["network_tx_packets_delta"] = "120"
    elif not good_network:
        results["network_rx_packets_delta"] = "0"
        results["network_tx_packets_delta"] = "0"
    else:
        results["network_rx_packets_delta"] = "60000"
        results["network_tx_packets_delta"] = "70000"
    if summary_rx_packets_delta is not None:
        results["network_rx_packets_delta"] = str(summary_rx_packets_delta)
    if summary_tx_packets_delta is not None:
        results["network_tx_packets_delta"] = str(summary_tx_packets_delta)
    results["zone_image_serve_enabled"] = "true" if zone_image else "false"
    if zone_image:
        total_hits = direct_hits + semantic_hits
        results["responses_per_second"] = "160000"
        results["latency_us_p50"] = "70.0"
        results["latency_us_p99"] = "160.0"
        results["latency_us_p999"] = "240.0"
        results["zone_image_serve_hits"] = str(total_hits)
        results["zone_image_serve_direct_hits"] = str(direct_hits)
        results["zone_image_serve_semantic_hits"] = str(semantic_hits)
        results["zone_image_serve_fallbacks"] = str(fallbacks)
    else:
        results["zone_image_serve_hits"] = "0"
        results["zone_image_serve_direct_hits"] = "0"
        results["zone_image_serve_semantic_hits"] = "0"
        results["zone_image_serve_fallbacks"] = "0"
    write_tsv(root / "benchmark-results.tsv", results)
    (root / "query-trace.tsv").write_text(
        "host000000.perf.test. A IN none hot_positive\n"
        "host000001.perf.test. A IN edns edns_positive\n"
        "missing.perf.test. A IN none rcode=NXDOMAIN answers=0 nxdomain\n",
        encoding="utf-8",
    )
    write_network_deltas(
        root / "network" / "proc-net-dev-delta.tsv",
        good=good_network,
        dropped=dropped_network,
        low_packets=low_network_packets,
    )


def run_compare(
    current: Path,
    zone_image: Path,
    output: Path,
    *,
    require_non_loopback: bool = False,
    require_direct_and_semantic: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(COMPARATOR),
        "--current",
        str(current),
        "--zone-image",
        str(zone_image),
        "--min-qps-ratio",
        "1.25",
        "--max-p50-ratio",
        "0.80",
        "--output",
        str(output),
    ]
    if require_non_loopback:
        command.append("--require-non-loopback")
    if require_direct_and_semantic:
        command.append("--require-direct-and-semantic")
    return subprocess.run(command, text=True, capture_output=True, check=False)


def assert_status(
    name: str,
    result: subprocess.CompletedProcess[str],
    *,
    expected_success: bool,
) -> None:
    if expected_success and result.returncode != 0:
        raise SystemExit(
            f"{name}: expected success, got {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    if not expected_success and result.returncode == 0:
        raise SystemExit(f"{name}: expected failure\nstdout:\n{result.stdout}")


def assert_output_contains(path: Path, needle: str) -> None:
    text = path.read_text(encoding="utf-8")
    if needle not in text:
        raise SystemExit(f"{path} did not contain expected text: {needle}")


def run_gate_preflight(temp: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "OXIDEDNS_ZONE_IMAGE_GATE_DIR": str(temp / "gate-preflight"),
            "OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK": "true",
            "OXIDEDNS_BENCH_LISTEN_ADDRESS": "192.0.2.10",
            "OXIDEDNS_BENCH_CLIENT_SERVER": "192.0.2.10",
            "OXIDEDNS_BENCH_NETWORK_DEVICE": "enp1s0",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", str(ZONE_IMAGE_GATE)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def run_benchmark_preflight(temp: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR": str(temp / "benchmark-preflight"),
            "OXIDEDNS_BENCH_CLIENT_MODE": "ssh",
            "OXIDEDNS_BENCH_REMOTE_CLIENT_SSH": "bench-client.example.net",
            "OXIDEDNS_BENCH_LISTEN_ADDRESS": "192.0.2.10",
            "OXIDEDNS_BENCH_CLIENT_SERVER": "192.0.2.10",
            "OXIDEDNS_BENCH_NETWORK_DEVICE": "enp1s0",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", str(DNS_CLIENT_BENCHMARK)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def run_benchmark_local_preflight(temp: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR": str(temp / "benchmark-local-preflight"),
            "OXIDEDNS_BENCH_PREFLIGHT_ONLY": "true",
            "OXIDEDNS_BENCH_CLIENT_MODE": "local",
            "OXIDEDNS_BENCH_LISTEN_ADDRESS": "127.0.0.1",
            "OXIDEDNS_BENCH_CLIENT_SERVER": "127.0.0.1",
            "OXIDEDNS_BENCH_NETWORK_DEVICE": "lo",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", str(DNS_CLIENT_BENCHMARK)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def existing_non_loopback_device() -> str:
    for path in sorted(Path("/sys/class/net").iterdir()):
        if path.name != "lo":
            return path.name
    return "lo"


def local_host_identity() -> str:
    boot_id = Path("/proc/sys/kernel/random/boot_id")
    if boot_id.is_file():
        return boot_id.read_text(encoding="utf-8").strip()
    return os.uname().nodename


def install_fake_arch_ssh(
    temp: Path,
    remote_arch: str,
    *,
    remote_host_identity: str = "remote-test-host",
) -> str:
    fakebin = temp / "fakebin"
    fakebin.mkdir(exist_ok=True)
    ssh = fakebin / "ssh"
    ssh.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "last_arg=${!#}",
                "case \"$last_arg\" in",
                "  true) exit 0 ;;",
                f"  'uname -m') printf '%s\\n' {remote_arch!r}; exit 0 ;;",
                f"  *boot_id*) printf '%s\\n' {remote_host_identity!r}; exit 0 ;;",
                "  *) exit 0 ;;",
                "esac",
                "",
            ]
        ),
        encoding="utf-8",
    )
    ssh.chmod(0o755)
    scp = fakebin / "scp"
    scp.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    scp.chmod(0o755)
    return f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}"


def assert_stderr_contains(name: str, result: subprocess.CompletedProcess[str], needle: str) -> None:
    if needle not in result.stderr:
        raise SystemExit(
            f"{name}: stderr did not contain {needle!r}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="zone-image-evidence-tools-") as temp_name:
        temp = Path(temp_name)

        loop_current = temp / "loop-current"
        loop_zone = temp / "loop-zone"
        write_artifact(loop_current, zone_image=False, network_device="lo")
        write_artifact(loop_zone, zone_image=True, network_device="lo")
        output = temp / "loop-comparison.tsv"
        result = run_compare(loop_current, loop_zone, output)
        assert_status("loopback regular comparison", result, expected_success=True)
        assert_output_contains(output, "network_counter_deltas_checked\tfalse")

        output = temp / "loop-physical-comparison.tsv"
        result = run_compare(loop_current, loop_zone, output, require_non_loopback=True)
        assert_status("loopback physical comparison rejection", result, expected_success=False)
        assert_output_contains(output, "network_counter_deltas_checked\ttrue")
        assert_output_contains(output, "network_device='lo' does not satisfy --require-non-loopback")

        nic_current = temp / "nic-current"
        nic_zone = temp / "nic-zone"
        write_artifact(nic_current, zone_image=False, network_device="enp1s0")
        write_artifact(nic_zone, zone_image=True, network_device="enp1s0")
        output = temp / "nic-comparison.tsv"
        result = run_compare(
            nic_current,
            nic_zone,
            output,
            require_non_loopback=True,
            require_direct_and_semantic=True,
        )
        assert_status("physical comparison", result, expected_success=True)
        assert_output_contains(output, "network_counter_deltas_checked\ttrue")
        assert_output_contains(output, "direct_and_semantic_checked\ttrue")
        assert_output_contains(output, "min_network_packets_per_response\t0.250")
        assert_output_contains(output, "current_network_rx_packets_delta\t60000")
        assert_output_contains(output, "current_network_tx_bytes_delta\t4480000")
        assert_output_contains(output, "zone_image_network_tx_packets_delta\t70000")
        assert_output_contains(output, "zone_image_network_rx_drop_delta\t0")
        assert_output_contains(output, "client_mode\tssh")
        assert_output_contains(output, "remote_client_ssh\tbench-client.example.net")
        assert_output_contains(output, "remote_client_local_arch\tx86_64")
        assert_output_contains(output, "remote_client_remote_arch\tx86_64")
        assert_output_contains(output, "remote_client_local_host_id\tlocal-host")
        assert_output_contains(output, "remote_client_remote_host_id\tremote-host")
        assert_output_contains(output, "remote_client_same_host\tfalse")
        assert_output_contains(output, f"client_bin_sha256\t{'b' * 64}")
        assert_output_contains(output, f"remote_client_bin_sha256\t{'b' * 64}")

        other_nic_zone = temp / "other-nic-zone"
        write_artifact(other_nic_zone, zone_image=True, network_device="enp2s0")
        output = temp / "other-nic-comparison.tsv"
        result = run_compare(nic_current, other_nic_zone, output, require_non_loopback=True)
        assert_status("physical comparison network mismatch rejection", result, expected_success=False)
        assert_output_contains(
            output,
            "network_device differs: current='enp1s0' zone_image='enp2s0'",
        )

        weak_provenance_zone = temp / "weak-provenance-zone"
        write_artifact(
            weak_provenance_zone,
            zone_image=True,
            network_device="enp1s0",
            require_non_loopback_device=False,
        )
        output = temp / "weak-provenance-comparison.tsv"
        result = run_compare(
            nic_current,
            weak_provenance_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison weak provenance rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "zone_image artifact did not record require_non_loopback_device=true",
        )

        local_client_zone = temp / "local-client-zone"
        write_artifact(
            local_client_zone,
            zone_image=True,
            network_device="enp1s0",
        )
        local_rows = dict(BASE_RESULTS)
        local_rows.update(
            {
                "network_device": "enp1s0",
                "listen_address": "192.0.2.10",
                "client_server": "192.0.2.10",
                "client_bind": "0.0.0.0:0",
                "require_non_loopback_device": "true",
                "network_rx_packets_delta": "60000",
                "network_tx_packets_delta": "70000",
                "zone_image_serve_enabled": "true",
                "zone_image_serve_hits": "1200",
                "zone_image_serve_direct_hits": "900",
                "zone_image_serve_semantic_hits": "300",
                "zone_image_serve_fallbacks": "0",
            }
        )
        write_tsv(local_client_zone / "benchmark-results.tsv", local_rows)
        output = temp / "local-client-comparison.tsv"
        result = run_compare(
            nic_current,
            local_client_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison local-client rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "metric client_mode differs: current='ssh' zone_image='local'",
        )
        assert_output_contains(
            output,
            "zone_image client_mode='local' does not satisfy --require-non-loopback",
        )

        other_remote_zone = temp / "other-remote-zone"
        write_artifact(other_remote_zone, zone_image=True, network_device="enp1s0")
        other_remote_rows = dict(BASE_RESULTS)
        other_remote_rows.update(
            {
                "network_device": "enp1s0",
                "listen_address": "192.0.2.10",
                "client_server": "192.0.2.10",
                "client_bind": "0.0.0.0:0",
                "client_mode": "ssh",
                "remote_client_ssh": "other-client.example.net",
                "require_non_loopback_device": "true",
                "network_rx_packets_delta": "60000",
                "network_tx_packets_delta": "70000",
                "zone_image_serve_enabled": "true",
                "zone_image_serve_hits": "1200",
                "zone_image_serve_direct_hits": "900",
                "zone_image_serve_semantic_hits": "300",
                "zone_image_serve_fallbacks": "0",
                "responses_per_second": "160000",
                "latency_us_p50": "70.0",
                "latency_us_p99": "160.0",
                "latency_us_p999": "240.0",
            }
        )
        write_tsv(other_remote_zone / "benchmark-results.tsv", other_remote_rows)
        output = temp / "other-remote-comparison.tsv"
        result = run_compare(
            nic_current,
            other_remote_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison remote-client mismatch rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "metric remote_client_ssh differs: current='bench-client.example.net' zone_image='other-client.example.net'",
        )

        arch_override_zone = temp / "arch-override-zone"
        write_artifact(arch_override_zone, zone_image=True, network_device="enp1s0")
        update_results(
            arch_override_zone,
            {"remote_client_allow_arch_mismatch": "true"},
        )
        output = temp / "arch-override-comparison.tsv"
        result = run_compare(
            nic_current,
            arch_override_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison arch-override rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "physical NIC promotion requires architecture override disabled",
        )

        arch_mismatch_zone = temp / "arch-mismatch-zone"
        write_artifact(arch_mismatch_zone, zone_image=True, network_device="enp1s0")
        update_results(
            arch_mismatch_zone,
            {"remote_client_remote_arch": "aarch64"},
        )
        output = temp / "arch-mismatch-comparison.tsv"
        result = run_compare(
            nic_current,
            arch_mismatch_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison arch-mismatch rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "zone_image remote client architecture mismatch: local='x86_64' remote='aarch64'",
        )

        same_host_zone = temp / "same-host-zone"
        write_artifact(same_host_zone, zone_image=True, network_device="enp1s0")
        update_results(
            same_host_zone,
            {
                "remote_client_remote_host_id": "local-host",
                "remote_client_same_host": "true",
            },
        )
        output = temp / "same-host-comparison.tsv"
        result = run_compare(
            nic_current,
            same_host_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison same-host rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "physical NIC promotion requires a distinct remote client host",
        )

        weak_build_zone = temp / "weak-build-zone"
        write_artifact(weak_build_zone, zone_image=True, network_device="enp1s0")
        update_results(weak_build_zone, {"server_bin_sha256": "unknown"})
        output = temp / "weak-build-comparison.tsv"
        result = run_compare(
            nic_current,
            weak_build_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison weak-build-provenance rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "zone_image benchmark provenance server_bin_sha256='unknown'",
        )

        remote_digest_mismatch_zone = temp / "remote-digest-mismatch-zone"
        write_artifact(
            remote_digest_mismatch_zone,
            zone_image=True,
            network_device="enp1s0",
        )
        update_results(
            remote_digest_mismatch_zone,
            {"remote_client_bin_sha256": "c" * 64},
        )
        output = temp / "remote-digest-mismatch-comparison.tsv"
        result = run_compare(
            nic_current,
            remote_digest_mismatch_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison remote-digest-mismatch rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "zone_image remote client binary digest mismatch",
        )

        direct_only_zone = temp / "direct-only-zone"
        write_artifact(
            direct_only_zone,
            zone_image=True,
            network_device="enp1s0",
            direct_hits=1200,
            semantic_hits=0,
        )
        output = temp / "direct-only-comparison.tsv"
        result = run_compare(
            nic_current,
            direct_only_zone,
            output,
            require_direct_and_semantic=True,
        )
        assert_status("direct/semantic coverage rejection", result, expected_success=False)
        assert_output_contains(
            output,
            "ZoneImage artifact did not record any semantic-plan served hits",
        )

        fallback_zone = temp / "fallback-zone"
        write_artifact(
            fallback_zone,
            zone_image=True,
            network_device="enp1s0",
            fallbacks=1,
        )
        output = temp / "fallback-comparison.tsv"
        result = run_compare(nic_current, fallback_zone, output)
        assert_status("fallback rejection", result, expected_success=False)
        assert_output_contains(output, "ZoneImage artifact recorded 1 fallbacks")

        background_only_zone = temp / "background-only-zone"
        write_artifact(
            background_only_zone,
            zone_image=True,
            network_device="enp1s0",
            low_network_packets=True,
        )
        output = temp / "background-only-comparison.tsv"
        result = run_compare(
            nic_current,
            background_only_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison low-packet-counter rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "zone_image network counter rx_packets delta 100 is below",
        )

        bad_counter_zone = temp / "bad-counter-zone"
        write_artifact(
            bad_counter_zone,
            zone_image=True,
            network_device="enp1s0",
            good_network=False,
        )
        output = temp / "bad-counter-comparison.tsv"
        result = run_compare(nic_current, bad_counter_zone, output, require_non_loopback=True)
        assert_status("physical comparison zero-counter rejection", result, expected_success=False)
        assert_output_contains(
            output,
            "zone_image network counter rx_packets delta must be positive",
        )

        dropped_counter_zone = temp / "dropped-counter-zone"
        write_artifact(
            dropped_counter_zone,
            zone_image=True,
            network_device="enp1s0",
            dropped_network=True,
        )
        output = temp / "dropped-counter-comparison.tsv"
        result = run_compare(nic_current, dropped_counter_zone, output, require_non_loopback=True)
        assert_status("physical comparison drop-counter rejection", result, expected_success=False)
        assert_output_contains(output, "zone_image network counter rx_drop delta is 1")

        stale_summary_zone = temp / "stale-summary-zone"
        write_artifact(
            stale_summary_zone,
            zone_image=True,
            network_device="enp1s0",
            summary_rx_packets_delta=42,
        )
        output = temp / "stale-summary-comparison.tsv"
        result = run_compare(
            nic_current,
            stale_summary_zone,
            output,
            require_non_loopback=True,
        )
        assert_status(
            "physical comparison stale summary rejection",
            result,
            expected_success=False,
        )
        assert_output_contains(
            output,
            "zone_image benchmark summary network_rx_packets_delta=42 does not match",
        )

        result = run_benchmark_local_preflight(temp)
        assert_status(
            "local benchmark preflight-only success",
            result,
            expected_success=True,
        )
        if "dns_client_benchmark_preflight=passed" not in result.stdout:
            raise SystemExit(
                "local benchmark preflight-only success: missing preflight marker\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        if "network_device=lo" not in result.stdout:
            raise SystemExit(
                "local benchmark preflight-only success: missing network device\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        if (temp / "benchmark-local-preflight").exists():
            raise SystemExit("local benchmark preflight-only created artifact directory")

        result = run_benchmark_local_preflight(
            temp,
            OXIDEDNS_BENCH_PREFLIGHT_ONLY="maybe",
        )
        assert_status(
            "benchmark invalid-preflight-only rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "benchmark invalid-preflight-only rejection",
            result,
            "OXIDEDNS_BENCH_PREFLIGHT_ONLY must be true or false",
        )

        result = run_gate_preflight(
            temp,
            OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY="maybe",
        )
        assert_status(
            "physical gate invalid-preflight-only rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate invalid-preflight-only rejection",
            result,
            "OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY must be true or false",
        )

        fake_matching_ssh_path = install_fake_arch_ssh(temp, os.uname().machine)
        server_nic = existing_non_loopback_device()
        result = run_gate_preflight(
            temp,
            OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY="true",
            OXIDEDNS_BENCH_CLIENT_MODE="ssh",
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH="bench-client.example.net",
            OXIDEDNS_BENCH_NETWORK_DEVICE=server_nic,
            PATH=fake_matching_ssh_path,
        )
        assert_status(
            "physical gate preflight-only success",
            result,
            expected_success=True,
        )
        if "zone_image_evidence_gate_preflight=passed" not in result.stdout:
            raise SystemExit(
                "physical gate preflight-only success: missing preflight marker\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        if not (temp / "gate-preflight.preflight.env").is_file():
            raise SystemExit("physical gate preflight-only did not retain preflight output")
        preflight_text = (temp / "gate-preflight.preflight.env").read_text(
            encoding="utf-8"
        )
        if "dns_client_benchmark_preflight=passed" not in preflight_text:
            raise SystemExit("physical gate preflight output missing benchmark marker")

        result = run_gate_preflight(
            temp,
            OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY="true",
            OXIDEDNS_BENCH_CLIENT_MODE="ssh",
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH="bench-client.example.net",
            OXIDEDNS_BENCH_NETWORK_DEVICE="definitely-missing-nic0",
            PATH=fake_matching_ssh_path,
        )
        assert_status(
            "physical gate missing-nic preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate missing-nic preflight rejection",
            result,
            "network_device=definitely-missing-nic0 does not exist",
        )

        result = run_gate_preflight(temp, OXIDEDNS_BENCH_CLIENT_MODE="local")
        assert_status(
            "physical gate local-client preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate local-client preflight rejection",
            result,
            "requires OXIDEDNS_BENCH_CLIENT_MODE=ssh",
        )

        result = run_gate_preflight(temp, OXIDEDNS_BENCH_CLIENT_MODE="ssh")
        assert_status(
            "physical gate missing-remote preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate missing-remote preflight rejection",
            result,
            "requires OXIDEDNS_BENCH_REMOTE_CLIENT_SSH",
        )

        result = run_gate_preflight(
            temp,
            OXIDEDNS_BENCH_CLIENT_MODE="ssh",
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH="bench-client.example.net",
            OXIDEDNS_ZONE_IMAGE_GATE_SSH_CONNECT_TIMEOUT_SECONDS="0",
        )
        assert_status(
            "physical gate invalid-ssh-timeout preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate invalid-ssh-timeout preflight rejection",
            result,
            "OXIDEDNS_ZONE_IMAGE_GATE_SSH_CONNECT_TIMEOUT_SECONDS must be a positive integer",
        )

        result = run_gate_preflight(
            temp,
            OXIDEDNS_BENCH_CLIENT_MODE="ssh",
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH="bench-client.example.net",
            OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH="maybe",
        )
        assert_status(
            "physical gate invalid-arch-override preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate invalid-arch-override preflight rejection",
            result,
            "OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH must be true or false",
        )

        fake_ssh_path = install_fake_arch_ssh(temp, "definitely-remote-arch")
        result = run_gate_preflight(
            temp,
            OXIDEDNS_BENCH_CLIENT_MODE="ssh",
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH="bench-client.example.net",
            PATH=fake_ssh_path,
        )
        assert_status(
            "physical gate arch-mismatch preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate arch-mismatch preflight rejection",
            result,
            "remote benchmark client architecture mismatch",
        )

        result = run_benchmark_preflight(
            temp,
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS="0",
        )
        assert_status(
            "ssh benchmark invalid-timeout preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "ssh benchmark invalid-timeout preflight rejection",
            result,
            "OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS must be a positive integer",
        )

        result = run_benchmark_preflight(
            temp,
            OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH="maybe",
        )
        assert_status(
            "ssh benchmark invalid-arch-override preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "ssh benchmark invalid-arch-override preflight rejection",
            result,
            "OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH must be true or false",
        )

        result = run_benchmark_preflight(
            temp,
            PATH=fake_ssh_path,
        )
        assert_status(
            "ssh benchmark arch-mismatch preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "ssh benchmark arch-mismatch preflight rejection",
            result,
            "remote benchmark client architecture mismatch",
        )

        fake_same_host_ssh_path = install_fake_arch_ssh(
            temp,
            os.uname().machine,
            remote_host_identity=local_host_identity(),
        )
        result = run_gate_preflight(
            temp,
            OXIDEDNS_BENCH_CLIENT_MODE="ssh",
            OXIDEDNS_BENCH_REMOTE_CLIENT_SSH="bench-client.example.net",
            PATH=fake_same_host_ssh_path,
        )
        assert_status(
            "physical gate same-host preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "physical gate same-host preflight rejection",
            result,
            "appears to resolve to the local server host",
        )

        result = run_benchmark_preflight(
            temp,
            OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE="true",
            PATH=fake_same_host_ssh_path,
        )
        assert_status(
            "ssh benchmark same-host preflight rejection",
            result,
            expected_success=False,
        )
        assert_stderr_contains(
            "ssh benchmark same-host preflight rejection",
            result,
            "appears to resolve to the local server host",
        )

    print("zone_image_evidence_tools_check=passed")


if __name__ == "__main__":
    main()
