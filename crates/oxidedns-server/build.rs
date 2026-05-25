use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=OXIDEDNS_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=OXIDEDNS_BUILD_RUST_VERSION");
    println!("cargo:rerun-if-env-changed=OXIDEDNS_BUILD_TIMESTAMP");

    let commit = std::env::var("OXIDEDNS_BUILD_COMMIT")
        .ok()
        .unwrap_or_else(|| command_output("git", &["rev-parse", "--short=8", "HEAD"]));
    let rust_version = std::env::var("OXIDEDNS_BUILD_RUST_VERSION")
        .ok()
        .unwrap_or_else(|| command_output("rustc", &["--version"]));
    let build_timestamp = std::env::var("OXIDEDNS_BUILD_TIMESTAMP")
        .ok()
        .unwrap_or_else(|| command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]));

    println!("cargo:rustc-env=OXIDEDNS_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=OXIDEDNS_BUILD_RUST_VERSION={rust_version}");
    println!("cargo:rustc-env=OXIDEDNS_BUILD_TIMESTAMP={build_timestamp}");
}

fn command_output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}
