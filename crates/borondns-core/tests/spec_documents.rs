use std::path::PathBuf;

use arc_swap as _;
use base64 as _;
use borondns_core as _;
use hmac as _;
use libc as _;
use serde as _;
use sha1 as _;
use sha2 as _;
use siphasher as _;
use smallvec as _;
use subtle as _;
use thiserror as _;
use toml as _;
use tracing as _;
use url as _;
use zeroize as _;

#[test]
fn expected_spec_documents_are_checked_in() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    for path in [
        "docs/BoronDNS-Secondary-SRS-v1.0.0.md",
    ] {
        assert!(repo_root.join(path).exists(), "missing {path}");
    }
}
