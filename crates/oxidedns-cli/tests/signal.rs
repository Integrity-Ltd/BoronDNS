#![cfg(unix)]

use std::{
    fs,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn serve_exits_successfully_on_sigterm() {
    serve_exits_successfully_on_signal("-TERM");
}

#[test]
fn serve_exits_successfully_on_sigint() {
    serve_exits_successfully_on_signal("-INT");
}

fn serve_exits_successfully_on_signal(signal: &str) {
    let config_path = write_test_config();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxidedns"))
        .arg("serve")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidedns serve");

    wait_until_running(&mut child, Duration::from_millis(150));
    let status = Command::new("kill")
        .arg(signal)
        .arg(child.id().to_string())
        .status()
        .expect("send signal");
    assert!(status.success(), "kill {signal} should succeed");

    let status = wait_for_exit(&mut child, Duration::from_secs(2), signal);
    assert!(
        status.success(),
        "oxidedns should exit successfully after {signal}, got {status}"
    );

    let _ = fs::remove_file(config_path);
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

            [limits]
            axfr_timeout_secs = 1
            graceful_shutdown_secs = 1

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#,
    )
    .expect("write test config");
    path
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
