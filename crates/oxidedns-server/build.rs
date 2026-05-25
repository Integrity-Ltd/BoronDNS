use std::process::Command;

fn main() {
    emit_git_rerun_paths();
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

fn emit_git_rerun_paths() {
    let Some(head_path) = command_output_optional(
        "git",
        &["rev-parse", "--path-format=absolute", "--git-path", "HEAD"],
    ) else {
        return;
    };
    println!("cargo:rerun-if-changed={head_path}");

    if let Ok(head) = std::fs::read_to_string(&head_path)
        && let Some(ref_name) = head.trim().strip_prefix("ref: ")
        && let Some(ref_path) = command_output_optional(
            "git",
            &[
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                ref_name,
            ],
        )
    {
        println!("cargo:rerun-if-changed={ref_path}");
    }

    if let Some(packed_refs_path) = command_output_optional(
        "git",
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "packed-refs",
        ],
    ) {
        println!("cargo:rerun-if-changed={packed_refs_path}");
    }
}

fn command_output(command: &str, args: &[&str]) -> String {
    command_output_optional(command, args).unwrap_or_else(|| "unknown".to_owned())
}

fn command_output_optional(command: &str, args: &[&str]) -> Option<String> {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}
