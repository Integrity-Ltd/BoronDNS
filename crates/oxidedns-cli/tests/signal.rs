#![cfg(unix)]

use std::{
    fs,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow as _;
use clap as _;
use getrandom as _;
use oxidedns_core as _;
use oxidedns_server as _;
use rcgen as _;
use time as _;
use tokio as _;
use tracing as _;
use tracing_subscriber as _;

#[test]
fn serve_exits_successfully_on_sigterm() {
    serve_exits_successfully_on_signal("-TERM");
}

#[test]
fn serve_exits_successfully_on_sigint() {
    serve_exits_successfully_on_signal("-INT");
}

#[test]
fn serve_ignores_sighup() {
    let config_path = write_test_config();
    let mut child = spawn_server(&config_path);

    wait_until_running(&mut child, Duration::from_millis(150));
    send_signal("-HUP", child.id());
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        child.try_wait().expect("poll child after SIGHUP").is_none(),
        "oxidedns should continue running after SIGHUP"
    );

    send_signal("-TERM", child.id());
    let status = wait_for_exit(&mut child, Duration::from_secs(2), "-TERM after SIGHUP");
    assert!(
        status.success(),
        "oxidedns should exit successfully after SIGTERM, got {status}"
    );

    let _ = fs::remove_file(config_path);
}

#[test]
fn serve_survives_closed_stdout_and_stderr_consumers() {
    let config_path = write_test_config();
    let mut child = spawn_server(&config_path);

    drop(child.stdout.take());
    drop(child.stderr.take());
    wait_until_running(&mut child, Duration::from_millis(150));
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        child
            .try_wait()
            .expect("poll child after closing standard stream consumers")
            .is_none(),
        "oxidedns should continue running after stdout/stderr consumers close"
    );

    send_signal("-TERM", child.id());
    let status = wait_for_exit(
        &mut child,
        Duration::from_secs(2),
        "-TERM after closed standard streams",
    );
    assert!(
        status.success(),
        "oxidedns should exit successfully after SIGTERM, got {status}"
    );

    let _ = fs::remove_file(config_path);
}

#[cfg(target_os = "linux")]
#[test]
fn serve_installs_only_required_signal_dispositions_and_handlers() {
    let config_path = write_test_config();
    let mut child = spawn_server(&config_path);

    wait_until_running(&mut child, Duration::from_millis(150));
    let status =
        fs::read_to_string(format!("/proc/{}/status", child.id())).expect("read child proc status");
    let ignored = sig_ign_mask(&status);
    assert_signal_ignored(ignored, 1, "SIGHUP");
    assert_signal_ignored(ignored, 13, "SIGPIPE");

    let caught = sig_cgt_mask(&status);
    assert_signal_caught(caught, 2, "SIGINT");
    assert_signal_caught(caught, 15, "SIGTERM");
    assert_signal_not_caught(caught, 1, "SIGHUP");
    assert_signal_not_caught(caught, 3, "SIGQUIT");
    assert_signal_not_caught(caught, 10, "SIGUSR1");
    assert_signal_not_caught(caught, 12, "SIGUSR2");
    assert_signal_not_caught(caught, 13, "SIGPIPE");

    send_signal("-TERM", child.id());
    let status = wait_for_exit(
        &mut child,
        Duration::from_secs(2),
        "-TERM after SigIgn check",
    );
    assert!(
        status.success(),
        "oxidedns should exit successfully after SIGTERM, got {status}"
    );

    let _ = fs::remove_file(config_path);
}

fn serve_exits_successfully_on_signal(signal: &str) {
    let config_path = write_test_config();
    let mut child = spawn_server(&config_path);

    wait_until_running(&mut child, Duration::from_millis(150));
    send_signal(signal, child.id());

    let status = wait_for_exit(&mut child, Duration::from_secs(2), signal);
    assert!(
        status.success(),
        "oxidedns should exit successfully after {signal}, got {status}"
    );

    let _ = fs::remove_file(config_path);
}

fn spawn_server(config_path: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("serve")
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidedns serve")
}

fn send_signal(signal: &str, pid: u32) {
    let status = Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .expect("send signal");
    assert!(status.success(), "kill {signal} should succeed");
}

fn write_test_config() -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("oxidedns-signal-{unique}.toml"));
    fs::write(
        &path,
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]

            [limits]
            axfr_timeout_secs = 1
            graceful_shutdown_secs = 1
            # Keep the integration fixture below constrained CI/sandbox
            # RLIMIT_NOFILE values. Production defaults intentionally require
            # a higher supervisor limit and are covered by the resource-limit
            # unit tests.
            max_tcp_connections = 16

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    )
    .expect("write test config");
    path
}

#[cfg(target_os = "linux")]
fn sig_ign_mask(status: &str) -> u128 {
    signal_mask(status, "SigIgn:")
}

#[cfg(target_os = "linux")]
fn sig_cgt_mask(status: &str) -> u128 {
    signal_mask(status, "SigCgt:")
}

#[cfg(target_os = "linux")]
fn signal_mask(status: &str, prefix: &str) -> u128 {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("{prefix} status line"))
        .trim();
    u128::from_str_radix(value, 16).unwrap_or_else(|_| panic!("parse {prefix} mask"))
}

#[cfg(target_os = "linux")]
fn assert_signal_ignored(mask: u128, signal_number: u32, name: &str) {
    let bit = 1_u128 << (signal_number - 1);
    assert!(
        mask & bit != 0,
        "{name} should be ignored in SigIgn mask {mask:#x}"
    );
}

#[cfg(target_os = "linux")]
fn assert_signal_caught(mask: u128, signal_number: u32, name: &str) {
    let bit = 1_u128 << (signal_number - 1);
    assert!(
        mask & bit != 0,
        "{name} should be caught in SigCgt mask {mask:#x}"
    );
}

#[cfg(target_os = "linux")]
fn assert_signal_not_caught(mask: u128, signal_number: u32, name: &str) {
    let bit = 1_u128 << (signal_number - 1);
    assert!(
        mask & bit == 0,
        "{name} should not be caught in SigCgt mask {mask:#x}"
    );
}

fn wait_until_running(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("poll child") {
            Some(status) => panic!("oxidedns exited before signal with {status}"),
            None if Instant::now() >= deadline => return,
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration, signal: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            panic!("oxidedns did not exit after {signal}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
