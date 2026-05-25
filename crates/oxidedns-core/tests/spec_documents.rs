use std::path::PathBuf;

#[test]
fn expected_spec_documents_are_checked_in() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    for path in [
        "docs/OxideDNS-Secondary-SRS-v0.9.md",
        "docs/OxideDNS-Secondary-SBVR-v0.1.md",
        "docs/OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md",
    ] {
        assert!(repo_root.join(path).exists(), "missing {path}");
    }
}
