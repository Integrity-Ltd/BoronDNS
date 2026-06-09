use std::process::Command;

use anyhow as _;
use clap as _;
use serde as _;
use time as _;
use toml as _;

fn oxide_gun() -> Command {
    Command::new(env!("CARGO_BIN_EXE_oxide-gun"))
}

#[test]
fn version_flag_prints_package_version() {
    let output = oxide_gun()
        .arg("--version")
        .output()
        .expect("oxide-gun --version runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert_eq!(
        stdout.trim(),
        concat!("oxide-gun ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn self_test_outputs_summary_json() {
    let output = oxide_gun()
        .args([
            "--self-test",
            "--max-packets",
            "4",
            "--target-qps",
            "1000",
            "--flush-interval-ms",
            "0",
        ])
        .output()
        .expect("oxide-gun self-test runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let summary: serde_json::Value = serde_json::from_str(stdout.trim()).expect("summary json");
    assert_eq!(summary["record_type"], "summary");
    assert_eq!(summary["summary"], true);
    assert_eq!(summary["backend"], "std_udp_socket");
    assert_eq!(summary["recv_mode"], "process");
    assert_eq!(summary["drop_implementation"], "none");
    assert_eq!(summary["tx_packets_total"], 4);
    assert_eq!(summary["rx_dns_responses_total"], 4);
    assert_eq!(summary["positive_total"], 4);
    assert_eq!(summary["errors_total"], 0);
    assert_eq!(summary["query_pool_size"], 1);
    assert_eq!(summary["source_strategy"], "os_assigned_udp_socket");
    assert!(summary["latency_p50_us"].is_number());
}

#[test]
fn print_config_accepts_cli_overrides() {
    let output = oxide_gun()
        .args([
            "--print-config",
            "--target",
            "127.0.0.1:5300",
            "--qname",
            "www.example.test.",
            "--qtype",
            "TYPE65400",
            "--qname-template",
            "host{}.example.test.",
            "--qname-count",
            "3",
            "--query-select",
            "sequential",
            "--recv-mode",
            "drop",
            "--max-packets",
            "9",
            "--queue-count",
            "4",
            "--queue-list",
            "0,2,3,7",
            "--xdp-redirect-object",
            "/tmp/oxide-gun-xdp.bpf.o",
            "--xdp-reply-tracking",
            "count",
            "--xdp-batch-size",
            "1024",
            "--xdp-rx-drain-passes",
            "16",
            "--xdp-tx-wakeup-interval",
            "4",
            "--xdp-pace-wait-fraction",
            "0.75",
            "--xdp-umem-frame-count",
            "16384",
            "--xdp-tx-ring-size",
            "4096",
            "--xdp-rx-ring-size",
            "4096",
            "--xdp-fill-ring-size",
            "4096",
            "--xdp-completion-ring-size",
            "4096",
        ])
        .output()
        .expect("oxide-gun print-config runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("address = \"127.0.0.1:5300\""));
    assert!(stdout.contains("qname = \"www.example.test.\""));
    assert!(stdout.contains("qtype = \"TYPE65400\""));
    assert!(stdout.contains("qname_template = \"host{}.example.test.\""));
    assert!(stdout.contains("qname_count = 3"));
    assert!(stdout.contains("select = \"sequential\""));
    assert!(stdout.contains("mode = \"drop\""));
    assert!(stdout.contains("max_packets = 9"));
    assert!(stdout.contains("queue_count = 4"));
    assert!(stdout.contains("queue_list = ["));
    assert!(stdout.contains("    7,"));
    assert!(stdout.contains("redirect_object = \"/tmp/oxide-gun-xdp.bpf.o\""));
    assert!(stdout.contains("reply_tracking = \"count\""));
    assert!(stdout.contains("batch_size = 1024"));
    assert!(stdout.contains("rx_drain_passes = 16"));
    assert!(stdout.contains("tx_wakeup_interval = 4"));
    assert!(stdout.contains("pace_wait_fraction = 0.75"));
    assert!(stdout.contains("umem_frame_count = 16384"));
    assert!(stdout.contains("tx_ring_size = 4096"));
    assert!(stdout.contains("rx_ring_size = 4096"));
    assert!(stdout.contains("fill_ring_size = 4096"));
    assert!(stdout.contains("completion_ring_size = 4096"));
}
