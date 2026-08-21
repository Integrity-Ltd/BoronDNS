#!/usr/bin/env python3
"""Reject release workflow drift that weakens artifact provenance.

The checker deliberately accepts a small, block-style YAML subset. GitHub
Actions still receives the workflow through actionlint, while this gate rejects
YAML tags, anchors, aliases, merges, explicit keys, and flow collections. With
those alternate node spellings excluded, every accepted ``uses`` key is an
ordinary block mapping that this module can inventory without constructing or
executing YAML tags.
"""

from pathlib import Path
import hashlib
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release-installer.yml"
PACKAGE_INSTALLER = ROOT / "scripts" / "package-installer.sh"
PACKAGE_DOCKER_IMAGE = ROOT / "scripts" / "package-docker-image.sh"
REPRODUCIBLE_BUILD = ROOT / "scripts" / "reproducible-build-compare.sh"
RELEASE_API_SUPERVISOR = ROOT / "scripts" / "release-api-supervisor.py"
RELEASE_REPRODUCIBILITY_VERIFIER = (
    ROOT / "scripts" / "verify-release-reproducibility.py"
)
DOCKER_ARCHIVE_VERIFIER = ROOT / "scripts" / "verify-docker-archive.py"
RELEASE_TAG_VERIFIER = ROOT / "scripts" / "verify-release-tag-signature.sh"
EXPECTED_RELEASE_HELPER_SHA256 = {
    RELEASE_API_SUPERVISOR: "410d34b680adc816efe7e217e95f2b8573e816087c3bd71d8bd3e88fc3937b44",
    RELEASE_REPRODUCIBILITY_VERIFIER: "08aff22afc106a84646aa25b7af684de9e30580ab4c757a8abd641c26607993b",
    DOCKER_ARCHIVE_VERIFIER: "e461cb8aadf7b3fea389e3210e3a49ad69f0cbb33a8216a69a9710b421ba3923",
    RELEASE_TAG_VERIFIER: "645eb1af3a62a647c1f4c197d487e24d7ed49e4c097268178cd6646f3e3bac1b",
}
DOCKERFILE = ROOT / "packaging" / "docker" / "Dockerfile"
INSTALLER_README = ROOT / "packaging" / "installer" / "README.install.md"
RUST_TOOLCHAIN = ROOT / "rust-toolchain.toml"
QUICK_START_DOCS = (
    ROOT / "docs" / "devops-getting-started.md",
    ROOT / "docs" / "operator-deployment-guide.md",
)
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_SYFT_LINUX_AMD64_SHA256 = (
    "20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716"
)
EXPECTED_ALPINE_BASE_IMAGE = (
    "alpine:3.22@sha256:"
    "7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6"
)
USES_KEY_RE = re.compile(
    r'''^(?P<indent>[ ]*)(?:-\s+)?(?:uses|'uses'|"uses")[ ]*:[ ]*(?P<value>.*?)[ ]*$'''
)
BLOCK_SCALAR_RE = re.compile(r"^[>|](?:[+-]?[1-9]?|[1-9]?[+-]?)?(?:\s+#.*)?$")
BLOCK_SCALAR_HEADER_RE = re.compile(
    r":[ ]*[>|](?:[+-]?[1-9]?|[1-9]?[+-]?)?(?:\s+#.*)?$"
)
ESCAPED_QUOTED_MAPPING_KEY_RE = re.compile(
    r'''^\s*(?:-\s+)?"(?:[^"\\]|\\.)*\\(?:[^"\\]|\\.)*"\s*:'''
)
FLOW_COLLECTION_RE = re.compile(
    r"^\s*(?:(?:-\s*)|(?:[^:#]+:\s*))?[\[{]"
)
NODE_DECORATION_RE = re.compile(
    r"(?:^\s*(?:-\s*)?(?:!\S+|&\S+|\*\S+)(?:\s|$)|:\s*(?:!\S+|&\S+|\*\S+)(?:\s|$))"
)
EXPLICIT_OR_MERGE_KEY_RE = re.compile(
    r"^\s*(?:-\s*)?(?:\?|<<\s*:)(?:\s|$)"
)
UNSAFE_CONTEXT_KEY_RE = re.compile(
    r'''^\s*(?:defaults|'defaults'|"defaults"|container|'container'|"container"|services|'services'|"services")\s*:'''
)
UNSAFE_ENV_KEY_RE = re.compile(
    r'''^\s*(?:BASH_ENV|'BASH_ENV'|"BASH_ENV"|ENV|'ENV'|"ENV"|SHELLOPTS|'SHELLOPTS'|"SHELLOPTS"|LD_PRELOAD|'LD_PRELOAD'|"LD_PRELOAD"|LD_LIBRARY_PATH|'LD_LIBRARY_PATH'|"LD_LIBRARY_PATH"|PATH|'PATH'|"PATH")\s*:'''
)
JOB_CONTINUE_ON_ERROR_RE = re.compile(
    r'''^ {4}(?:continue-on-error|'continue-on-error'|"continue-on-error")\s*:'''
)

SECURE_SHELL = (
    "/usr/bin/env -u BASH_ENV -u ENV /usr/bin/bash "
    "--noprofile --norc -euo pipefail {0}"
)
CLEAN_TREE_COMMAND = (
    'if ! /usr/bin/git status --porcelain=v1 --untracked-files=all --ignored=no '
    '>"$git_status_file"; then'
)
EXPECTED_IDENTITY = (
    '--certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/'
    'workflows/release-installer.yml@refs/tags/$tag"'
)
EXPECTED_ACTIONS = {
    "actions/checkout": "93cb6efe18208431cddfb8368fd83d5badbf9bfd",
    "actions/upload-artifact": "330a01c490aca151604b8cf639adc76d48f6c5d4",
    "actions/download-artifact": "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
    "sigstore/cosign-installer": "6f9f17788090df1f26f669e9d70d6ae9567deba6",
}
VERIFY_ACTIONS = [
    f"actions/checkout@{EXPECTED_ACTIONS['actions/checkout']}",
]
PACKAGE_ACTIONS = [
    f"actions/checkout@{EXPECTED_ACTIONS['actions/checkout']}",
    f"actions/upload-artifact@{EXPECTED_ACTIONS['actions/upload-artifact']}",
]
SIGN_ACTIONS = [
    f"sigstore/cosign-installer@{EXPECTED_ACTIONS['sigstore/cosign-installer']}",
    f"actions/download-artifact@{EXPECTED_ACTIONS['actions/download-artifact']}",
]
VERIFY_STEPS = [
    "Checkout",
    "Verify clean source checkout",
    "Record verified source commit",
    "Install shell tools",
    "Install continuous verification tools",
    "Check release tag matches Cargo version",
    "Verify Tibor-signed annotated release tag",
    "Continuous verification gate",
    "Verify Continuous gate preserved clean source",
]
PACKAGE_STEPS = [
    "Checkout verified source",
    "Verify packaging source commit",
    "Install packaging tools",
    "Verify packaging source remained clean",
    "Verify current-commit reproducible release binaries",
    "Build installer",
    "Docker installer smoke",
    "Build Docker image archive",
    "Docker image smoke",
    "Generate release SBOMs",
    "Verify static binaries",
    "Verify packaged source remained clean",
    "Prepare authenticated release handoff",
    "Upload authenticated release handoff",
]
SIGN_STEPS = [
    "Install Cosign",
    "Download authenticated release handoff",
    "Create GitHub release",
]
EXPECTED_RUNNER = "ubuntu-24.04"
EXPECTED_RUST_TOOLCHAIN = '[toolchain]\nchannel = "1.96.1"\n'


def rust_toolchain_errors(text: str) -> list[str]:
    return [] if text == EXPECTED_RUST_TOOLCHAIN else [
        "rust-toolchain.toml must pin the exact reviewed Rust 1.96.1 release"
    ]
EXPECTED_GLOBAL_ENV = [
    '  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"',
    '  RUST_TOOLCHAIN_VERSION: "1.96.1"',
    '  CARGO_CYCLONEDX_VERSION: "0.5.9"',
    '  SYFT_VERSION: "v1.45.1"',
    f'  SYFT_LINUX_AMD64_SHA256: "{EXPECTED_SYFT_LINUX_AMD64_SHA256}"',
    '  ACTIONLINT_VERSION: "1.7.12"',
    '  ACTIONLINT_LINUX_AMD64_SHA256: "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
    '  SHELLCHECK_VERSION: "0.11.0"',
    '  SHELLCHECK_LINUX_AMD64_SHA256: "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"',
    '  CARGO_DENY_VERSION: "0.19.8"',
    '  CARGO_LLVM_COV_VERSION: "0.8.7"',
    '  CARGO_BLOAT_VERSION: "0.12.1"',
    '  CARGO_MACHETE_VERSION: "0.9.2"',
    '  CARGO_FUZZ_VERSION: "0.13.2"',
]
# Fingerprint each job's complete metadata before ``steps``. This closes the
# build-contamination surface around job-level environment, container, service,
# permissions, dependencies, outputs, and runner selection.
JOB_PREAMBLE_SHA256 = {
    "verify-source": "85b00bc2269e362628312ce758a8911440774302421a0fa61d1ec23dd3b28298",
    "package-release": "4dee321456a61c936875be9c59e2a44990bea035c2a6c820abef3bc0f1070d05",
    "sign-release": "99dea3126c8a28ba76977a429f3f7258b1e7412e54fb0011c0308d0a2987a62c",
}
# Filled from the reviewed workflow below. These fingerprints make every job an
# exact executable surface: any step metadata, action input, or shell-body
# change must be reviewed together with this policy and its mutation fixtures.
VERIFY_STEP_SHA256 = {
    "Checkout": "b0495f7d6653c379fc61ffc839a5cd74c75cae6cdc2d97dc46f6df7e8fbc6d0d",
    "Verify clean source checkout": "d21ec3586293bde9e484f1a3720becf77ea9cbe22df05a27b9c05c3109742af8",
    "Record verified source commit": "7420c3820884d1daeca7c6cf74634fed5d9abd987a898cb584ca0dad24052eae",
    "Install shell tools": "487017346ec77bc2546e85372dfd6abe526433144ea61bd1915e365c0da5d3b5",
    "Install continuous verification tools": "9d8d84eaa975df462f38d24886bc08dd87470f41d18c0818eccd06eda763fd35",
    "Check release tag matches Cargo version": "be3ed9134c708925b7d7df3edaa69aca5e40628730ad8bef67564532e12a4db5",
    "Verify Tibor-signed annotated release tag": "f5dd4479db59cbd41bb70d39b4f3742aed52cebc8ded15533b0a1770a8ae9a5f",
    "Continuous verification gate": "15db06eb26cb9bffb6fb7b67a970f3c24337ca5e02c78b15c5270270ac571cff",
    "Verify Continuous gate preserved clean source": "4afc7667d5ecb7cdd4504e2d3110b1d0a2178564883dddfc4bfa6b581662b19f",
}
PACKAGE_STEP_SHA256 = {
    "Checkout verified source": "7eca7f77d7449358104f62e3fa7d337dfeed951c5769e0e1718fbfda313ae250",
    "Verify packaging source commit": "cb5e0c0c712eb7f630af958cbf4aa76a5cc10254739e7a55adf1286c177aabf9",
    "Install packaging tools": "a210c8088ed7b9e159304de155aeee896a58b9cb5142bfbcf13ca3aee3fad699",
    "Verify packaging source remained clean": "705cfaa3e56b23bb439822adbd25857c6cca9da30ad9d80b65f653dd1da0546a",
    "Verify current-commit reproducible release binaries": "660eb4119df55ed93038cd24c3ec754fc4cab85e9fe55d0a020c54aee1c91503",
    "Build installer": "a19e5a8a4448a1af99905d319d426c80d80ed01d864764f6f350fbf71125565b",
    "Docker installer smoke": "68a9c54f99158c2f5113d94c9fb49ae666a239bd2e609e054e567b047dd02aff",
    "Build Docker image archive": "d2ac592c0f3558bd33984484af24ec4a10ca59090211d01d613839f12b005440",
    "Docker image smoke": "ccc458342967f6faafeec9490118cfd80dab5d74d1f5922193327596e7c1dce7",
    "Generate release SBOMs": "ae56cdfcbd898d778cd3eb1d0260607dbb9934434b79e93e81166d5c95d845e9",
    "Verify static binaries": "fea7d7f36c7e4caf00f1872ecadca06ae46f4955e81b4a314ae61e025b041c52",
    "Verify packaged source remained clean": "9dfb112f73616187228d34cea7c993bc3eb919cceafe26a55927cc006e7c25cc",
    "Prepare authenticated release handoff": "8f8d25ec7f7a470a19384aed83ca07fe1a5e34b4e78b3218b7e30df7d9339236",
    "Upload authenticated release handoff": "034888e5028cbbd3c8c53a62fd919f820c75ae9231d920671db88b1b46c114da",
}
SIGN_STEP_SHA256 = {
    "Install Cosign": "51172e5bd450b07a61dccbfca6f6b00c347b56724724a93bcee6c9bb90f82f33",
    "Download authenticated release handoff": "d3b6101b9f58903ade81d0db162303e4c5a4e7a65600664860f12ee58476033e",
    "Create GitHub release": "e40cc264364b4df30e46359b286780882393f89e5db2c08c667ef813e71520f5",
}
PACKAGE_TARGET_CONTRACT_SHA256 = "8f990500695c059482b5c5db0dab9209628119d98985d3fa0ba49586fb439681"


def _yaml_scalar(value: str) -> str:
    value = re.sub(r"\s+#.*$", "", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def block_scalar_content_lines(text: str) -> set[int]:
    """Return zero-based lines that YAML treats as block-scalar content."""
    lines = text.splitlines()
    content_lines: set[int] = set()
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#") or BLOCK_SCALAR_HEADER_RE.search(line) is None:
            continue
        base_indent = len(line) - len(line.lstrip(" "))
        for continuation_index in range(index + 1, len(lines)):
            continuation = lines[continuation_index]
            if not continuation.strip():
                content_lines.add(continuation_index)
                continue
            indentation = len(continuation) - len(continuation.lstrip(" "))
            if indentation <= base_indent:
                break
            content_lines.add(continuation_index)
    return content_lines


def structural_yaml_errors(text: str) -> list[str]:
    """Reject alternate YAML node forms before doing line-based inventory."""
    errors: list[str] = []
    scalar_lines = block_scalar_content_lines(text)
    for index, line in enumerate(text.splitlines()):
        if index in scalar_lines or not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            errors.append(f"release workflow uses tab indentation at line {index + 1}")
        if ESCAPED_QUOTED_MAPPING_KEY_RE.search(line):
            errors.append(
                "release workflow uses an escaped quoted mapping key at "
                f"line {index + 1}; use a literal block key"
            )
        if (
            FLOW_COLLECTION_RE.search(line)
            or NODE_DECORATION_RE.search(line)
            or EXPLICIT_OR_MERGE_KEY_RE.search(line)
        ):
            errors.append(
                "release workflow uses unsupported YAML tags, aliases, merges, "
                f"explicit keys, or flow collections at line {index + 1}"
            )
        if UNSAFE_CONTEXT_KEY_RE.search(line):
            errors.append(
                "release workflow must not override defaults.run, containers, or "
                f"services (line {index + 1})"
            )
        if UNSAFE_ENV_KEY_RE.search(line):
            errors.append(
                "release workflow must not override security-sensitive shell or loader "
                f"environment (line {index + 1})"
            )
        if JOB_CONTINUE_ON_ERROR_RE.search(line):
            errors.append(
                f"release jobs must not use continue-on-error (line {index + 1})"
            )
    return errors


def workflow_uses(text: str) -> list[str]:
    """Inventory every accepted block-style ``uses`` mapping."""
    scalar_lines = block_scalar_content_lines(text)
    actions: list[str] = []
    for index, line in enumerate(text.splitlines()):
        if index in scalar_lines or line.lstrip().startswith("#"):
            continue
        match = USES_KEY_RE.match(line)
        if match is None:
            continue
        value = match.group("value").strip()
        if not value or BLOCK_SCALAR_RE.fullmatch(value):
            actions.append(value)
        else:
            actions.append(_yaml_scalar(value))
    return actions


def job_blocks(text: str) -> tuple[dict[str, str], list[str]]:
    """Extract ordinary two-space job mappings from the constrained document."""
    errors: list[str] = []
    jobs_match = re.search(r"^jobs:[ ]*$", text, re.MULTILINE)
    if jobs_match is None:
        return {}, ["release workflow must contain one literal jobs mapping"]
    if len(re.findall(r"^jobs:[ ]*$", text, re.MULTILINE)) != 1:
        errors.append("release workflow must contain exactly one literal jobs mapping")
    tail = text[jobs_match.end() :]
    starts = list(re.finditer(r"^  (?P<name>[A-Za-z0-9_-]+):[ ]*$", tail, re.MULTILINE))
    blocks: dict[str, str] = {}
    seen: set[str] = set()
    for index, match in enumerate(starts):
        name = match.group("name")
        if name in seen:
            errors.append(f"release workflow contains duplicate job {name}")
        seen.add(name)
        end = len(tail) if index + 1 == len(starts) else starts[index + 1].start()
        blocks[name] = tail[match.start() : end]
    return blocks, errors


def mapping_block_lines(text: str, key: str, indent: int) -> list[str] | None:
    prefix = " " * indent
    match = re.search(rf"^{re.escape(prefix + key)}:[ ]*$", text, re.MULTILINE)
    if match is None:
        return None
    lines: list[str] = []
    for line in text[match.end() :].splitlines():
        if not line.strip():
            continue
        line_indent = len(line) - len(line.lstrip(" "))
        if line_indent <= indent:
            break
        lines.append(line.rstrip())
    return lines


def named_step(text: str, name: str) -> tuple[int, str] | None:
    match = re.search(
        rf"^(?P<indent>[ ]*)- name: {re.escape(name)}[ ]*$", text, re.MULTILINE
    )
    if match is None:
        return None
    next_step = re.search(
        rf"^{re.escape(match.group('indent'))}- name: ",
        text[match.end() :],
        re.MULTILINE,
    )
    end = len(text) if next_step is None else match.end() + next_step.start()
    return match.start(), text[match.start() : end]


def named_steps(text: str) -> list[str]:
    return re.findall(r"^ {6}- name: ([^\n]+?)[ ]*$", text, re.MULTILINE)


def step_blocks(text: str) -> list[str]:
    """Return every ordinary top-level step, including unnamed steps."""
    steps_header = re.search(r"^    steps:[ ]*$", text, re.MULTILINE)
    if steps_header is None:
        return []
    tail = text[steps_header.end() :]
    starts = list(re.finditer(r"^      -(?: [^\n]+)?$", tail, re.MULTILINE))
    blocks: list[str] = []
    for index, match in enumerate(starts):
        end = len(tail) if index + 1 == len(starts) else starts[index + 1].start()
        blocks.append(tail[match.start() : end].rstrip())
    return blocks


def step_name(step: str) -> str | None:
    match = re.match(r"^      - name: ([^\n]+?)[ ]*(?:\n|$)", step)
    return None if match is None else match.group(1)


def step_fingerprint(step: str) -> str:
    return hashlib.sha256(step.rstrip().encode("utf-8")).hexdigest()


def job_preamble_fingerprint(block: str) -> str | None:
    """Fingerprint all job metadata through the literal ``steps`` key."""
    steps_header = re.search(r"^    steps:[ ]*$", block, re.MULTILINE)
    if steps_header is None:
        return None
    preamble = block[: steps_header.end()].rstrip()
    return hashlib.sha256(preamble.encode("utf-8")).hexdigest()


def exact_job_runner(block: str) -> bool:
    return re.findall(r"^    runs-on:[ ]*([^\n]+?)[ ]*$", block, re.MULTILINE) == [
        EXPECTED_RUNNER
    ]


def exact_step_surface_errors(
    block: str,
    expected_names: list[str],
    expected_fingerprints: dict[str, str],
    job_name: str,
) -> list[str]:
    steps = step_blocks(block)
    names = [step_name(step) for step in steps]
    errors: list[str] = []
    if names != expected_names:
        errors.append(
            f"{job_name} must contain exactly its reviewed named step inventory"
        )
    for step in steps:
        name = step_name(step)
        expected = expected_fingerprints.get(name or "")
        if expected is None or step_fingerprint(step) != expected:
            errors.append(
                f"{job_name} step body drifted from its exact reviewed form: "
                f"{name or '<unnamed>'}"
            )
    return errors


def mandatory_run_step(text: str, name: str, command: str) -> tuple[int, str] | None:
    """Return a gate only when its shell, command, and metadata are exact."""
    step = named_step(text, name)
    if step is None:
        return None
    _, body = step
    lines = [line.rstrip() for line in body.splitlines() if line.strip()]
    if not lines:
        return None
    indent = lines[0][: len(lines[0]) - len(lines[0].lstrip(" "))]
    expected = [
        f"{indent}- name: {name}",
        f"{indent}  shell: {SECURE_SHELL}",
        f"{indent}  run: {command}",
    ]
    return step if lines == expected else None


def ordered_named_steps(text: str, names: list[str]) -> bool:
    offsets: list[int] = []
    for name in names:
        step = named_step(text, name)
        if step is None:
            return False
        offsets.append(step[0])
    return offsets == sorted(offsets) and len(set(offsets)) == len(offsets)


def policy_errors(text: str) -> tuple[list[str], list[str]]:
    errors = structural_yaml_errors(text)
    actions = workflow_uses(text)
    blocks, block_errors = job_blocks(text)
    errors.extend(block_errors)

    expected_jobs = {"verify-source", "package-release", "sign-release"}
    if set(blocks) != expected_jobs:
        errors.append(
            "release workflow must contain exactly verify-source, package-release, and sign-release"
        )
    verify = blocks.get("verify-source", "")
    package = blocks.get("package-release", "")
    sign = blocks.get("sign-release", "")

    if mapping_block_lines(text, "env", 0) != EXPECTED_GLOBAL_ENV:
        errors.append("global release environment drifted from its exact reviewed form")

    for job_name, block in (
        ("verify-source", verify),
        ("package-release", package),
        ("sign-release", sign),
    ):
        if not exact_job_runner(block):
            errors.append(f"{job_name} must run exactly on {EXPECTED_RUNNER}")
        if job_preamble_fingerprint(block) != JOB_PREAMBLE_SHA256[job_name]:
            errors.append(f"{job_name} job metadata drifted from its exact reviewed form")

    verify_outputs = mapping_block_lines(verify, "outputs", 4)
    if verify_outputs != [
        "      source_commit: ${{ steps.source-commit.outputs.commit }}",
        "      rustc_sha256: ${{ steps.source-commit.outputs.rustc-sha256 }}",
        "      cargo_sha256: ${{ steps.source-commit.outputs.cargo-sha256 }}",
    ]:
        errors.append("verify-source must expose only its exact verified source commit and toolchain identities")
    package_outputs = mapping_block_lines(package, "outputs", 4)
    if package_outputs != [
        "      handoff_manifest_sha256: ${{ steps.prepare-handoff.outputs.manifest-sha256 }}",
        "      signing_inputs_manifest_sha256: ${{ steps.prepare-handoff.outputs.signing-inputs-manifest-sha256 }}",
    ]:
        errors.append("package-release must expose only the authenticated handoff manifest SHA")
    sign_env = mapping_block_lines(sign, "env", 4)
    if sign_env != [
        "      EXPECTED_HANDOFF_MANIFEST_SHA256: ${{ needs.package-release.outputs.handoff_manifest_sha256 }}",
        "      EXPECTED_SIGNING_INPUTS_MANIFEST_SHA256: ${{ needs.package-release.outputs.signing_inputs_manifest_sha256 }}",
    ]:
        errors.append(
            "sign-release job environment must contain only the expected handoff manifest SHA"
        )

    for job_name, block in (("verify-source", verify), ("package-release", package)):
        permissions = mapping_block_lines(block, "permissions", 4)
        if permissions != ["      contents: read"]:
            errors.append(f"{job_name} must have only job-scoped contents: read")
    sign_permissions = mapping_block_lines(sign, "permissions", 4)
    if sign_permissions != ["      contents: write", "      id-token: write"]:
        errors.append(
            "sign-release must have only job-scoped contents: write and id-token: write"
        )
    top_permissions = re.search(r"^permissions:[ ]*:", text, re.MULTILINE)
    if top_permissions is not None or re.search(r"^permissions:[ ]*$", text, re.MULTILINE):
        errors.append("release workflow permissions must be scoped to individual jobs")

    if re.findall(r"^    needs:[ ]*([^\n]+?)[ ]*$", package, re.MULTILINE) != [
        "verify-source"
    ]:
        errors.append("package-release must depend only on verify-source")
    if re.findall(r"^    needs:[ ]*([^\n]+?)[ ]*$", sign, re.MULTILINE) != [
        "package-release"
    ]:
        errors.append("sign-release must depend only on package-release")
    if (
        re.search(
            r"^    if: startsWith\(github\.ref, 'refs/tags/'\)[ ]*$",
            sign,
            re.MULTILINE,
        )
        is None
    ):
        errors.append("sign-release must run only for tag refs")

    verify_actions = workflow_uses(verify)
    package_actions = workflow_uses(package)
    sign_actions = workflow_uses(sign)
    if verify_actions != VERIFY_ACTIONS:
        errors.append("verify-source action inventory must contain only checkout")
    if package_actions != PACKAGE_ACTIONS:
        errors.append("package-release action inventory must be checkout then upload-artifact")
    if sign_actions != SIGN_ACTIONS:
        errors.append(
            "privileged sign-release action inventory must be cosign-installer then download-artifact"
        )
    if actions != VERIFY_ACTIONS + PACKAGE_ACTIONS + SIGN_ACTIONS:
        errors.append("release workflow action inventory contains an unexpected or missing action")
    for action in actions:
        if "@" not in action:
            errors.append(f"third-party release action lacks a revision: {action}")
            continue
        revision = action.rsplit("@", 1)[1]
        if not FULL_SHA_RE.fullmatch(revision):
            errors.append(
                f"third-party release action must use a full 40-hex commit pin: {action}"
            )

    errors.extend(
        exact_step_surface_errors(
            verify, VERIFY_STEPS, VERIFY_STEP_SHA256, "verify-source"
        )
    )
    errors.extend(
        exact_step_surface_errors(
            package, PACKAGE_STEPS, PACKAGE_STEP_SHA256, "package-release"
        )
    )
    errors.extend(
        exact_step_surface_errors(sign, SIGN_STEPS, SIGN_STEP_SHA256, "sign-release")
    )

    final_verify_step = named_step(verify, "Verify Continuous gate preserved clean source")
    final_head_pin = '          test "$(/usr/bin/git rev-parse HEAD)" = "$GITHUB_SHA"\n'
    if final_verify_step is None or final_head_pin not in final_verify_step[1]:
        errors.append(
            "verify-source final clean-tree gate must pin HEAD to GITHUB_SHA in the same shell"
        )

    handoff_requirements = (
        'source_commit: ${{ steps.source-commit.outputs.commit }}',
        'rustc_sha256: ${{ steps.source-commit.outputs.rustc-sha256 }}',
        'cargo_sha256: ${{ steps.source-commit.outputs.cargo-sha256 }}',
        'ref: ${{ needs.verify-source.outputs.source_commit }}',
        'test "$(/usr/bin/git rev-parse HEAD)" = "${{ needs.verify-source.outputs.source_commit }}"',
        'test "$(/usr/bin/sha256sum "$verified_rustc" | /usr/bin/awk \'{print $1}\')" = "${{ needs.verify-source.outputs.rustc_sha256 }}"',
        'test "$(/usr/bin/sha256sum "$verified_cargo" | /usr/bin/awk \'{print $1}\')" = "${{ needs.verify-source.outputs.cargo_sha256 }}"',
        'handoff_manifest_sha256: ${{ steps.prepare-handoff.outputs.manifest-sha256 }}',
        'signing_inputs_manifest_sha256: ${{ steps.prepare-handoff.outputs.signing-inputs-manifest-sha256 }}',
        'scripts/reproducible-build-compare.sh',
        'scripts/verify-release-reproducibility.py',
        '--require-artifacts "$evidence" "${{ needs.verify-source.outputs.source_commit }}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/a/borondns" "${release_borondns[0]}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/b/borondns" "${release_borondns[0]}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/a/boron-gun" "${release_boron_gun[0]}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/b/boron-gun" "${release_boron_gun[0]}"',
        "test \"${#assets[@]}\" -eq 16",
        'LC_ALL=C /usr/bin/sha256sum -- "${assets[@]##*/}" > release-handoff.sha256',
        'LC_ALL=C /usr/bin/sha256sum -- "${signing_inputs[@]}" > signing-inputs.sha256',
        'name: borondns-release-handoff-${{ github.sha }}',
        "EXPECTED_HANDOFF_MANIFEST_SHA256: ${{ needs.package-release.outputs.handoff_manifest_sha256 }}",
        "EXPECTED_SIGNING_INPUTS_MANIFEST_SHA256: ${{ needs.package-release.outputs.signing_inputs_manifest_sha256 }}",
        'printf \'%s  %s\\n\' "$EXPECTED_HANDOFF_MANIFEST_SHA256" release-handoff.sha256 | /usr/bin/sha256sum -c --strict -',
        "/usr/bin/sha256sum -c --strict release-handoff.sha256",
        "/usr/bin/sha256sum -c --strict signing-inputs.sha256",
        'python3 verify-release-reproducibility.py --require-artifacts \\\n'
        '              --release-borondns "${release_borondns[0]}" \\\n'
        '              --release-boron-gun "${release_boron_gun[0]}" \\\n'
        '              . "$GITHUB_SHA"',
        '/usr/bin/sha256sum -c --strict "$checksum"',
        'cosign_path="$authenticated_tools/cosign"',
        '"$cosign_path" sign-blob --yes --bundle "$asset.sigstore.json" "$asset"',
        'gh_path="$authenticated_tools/gh"',
        'declare -A authenticated_asset_sha256 authenticated_asset_size',
        'declare -A signed_bundle_sha256 signed_bundle_size bundle_subject',
        '"$cosign_path" verify-blob --bundle "$bundle" \\\n'
        '              --certificate-oidc-issuer "$certificate_issuer" \\\n'
        '              --certificate-identity "$certificate_identity" "$asset"',
        'version_without_build="${version%%+*}"',
        'if [[ "$version_without_build" == *-* ]]; then',
        '-F "prerelease=$release_prerelease" -f "make_latest=false"',
        '-F "prerelease=$release_prerelease" -f "make_latest=$release_make_latest"',
        'run_supervised_release_command 120 "$gh_path" api --method POST',
        '"repos/$GITHUB_REPOSITORY/releases"',
        'test "${#release_assets[@]}" -eq 34',
        'release_upload_base="https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets"',
        'test "$release_upload_url" = "$release_upload_base{?name,label}"',
        '"$release_upload_base" -f "name=$asset" --input "$asset"',
        'expected_asset_sha256="${authenticated_asset_sha256[$asset]}"',
        "--jq '[.name, .state, .size, .digest] | @tsv'",
        'test "$uploaded_name" = "$asset"',
        'test "$uploaded_state" = uploaded',
        'test "$uploaded_size" = "$expected_asset_size"',
        'test "$uploaded_digest" = "sha256:$expected_asset_sha256"',
        'run_supervised_release_command 120 "$gh_path" api --method PATCH',
        "test \"$(/usr/bin/wc -l < release-handoff.sha256)\" -eq 16",
        "test \"$(/usr/bin/wc -l < signing-inputs.sha256)\" -eq 9",
        "test \"$(/usr/bin/find . -type f -print | /usr/bin/wc -l)\" -eq 27",
    )
    for required in handoff_requirements:
        if required not in text:
            errors.append(f"authenticated release handoff invariant missing: {required}")
    if "artifact-digest" in text or "HANDOFF_ARTIFACT_DIGEST" in text:
        errors.append(
            "release workflow must not claim an artifact digest that download-artifact cannot compare"
        )
    release_step = named_step(sign, "Create GitHub release")
    release_repo_bindings = (
        '            "repos/$GITHUB_REPOSITORY/releases" \\\n',
        '          release_upload_base="https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets"\n',
        '              "$release_upload_base" -f "name=$asset" --input "$asset" \\\n',
        '            "repos/$GITHUB_REPOSITORY/releases/$release_id" -F draft=false \\\n',
    )
    if release_step is None or any(
        release_step[1].count(binding) != 1 for binding in release_repo_bindings
    ):
        errors.append("release publication API calls must bind to GITHUB_REPOSITORY")
    remote_tag_guard = (
        '          peel_remote_tag "$release_response_file"\n'
        '          tag_object_sha="$(<"$release_response_file")"\n'
        '          test "$tag_object_sha" = "$GITHUB_SHA"\n\n'
        '          release_cleanup_pending=1\n'
        '          : >"$release_response_file"\n'
        '          run_supervised_release_command 120 "$gh_path" api --method POST \\\n'
        '            "repos/$GITHUB_REPOSITORY/releases" \\\n'
    )
    if (
        release_step is None
        or release_step[1].count(
            '          run_supervised_release_command 120 "$gh_path" api --method GET \\\n'
        )
        != 2
        or '"repos/$GITHUB_REPOSITORY/git/ref/tags/$tag"' not in release_step[1]
        or '"repos/$GITHUB_REPOSITORY/git/tags/$tag_object_sha"' not in release_step[1]
        or remote_tag_guard not in release_step[1]
    ):
        errors.append(
            "release publication must peel the authenticated remote tag immediately before API-first draft creation"
        )
    post_create_tag_guard = (
        '          if peel_remote_tag "$release_response_file"; then\n'
        '            post_create_tag_sha="$(<"$release_response_file")"\n'
        '          fi\n'
        '          if test "$post_create_tag_sha" != "$GITHUB_SHA"; then\n'
    )
    release_cleanup_contract = (
        '          release_cleanup_pending=0\n',
        '          release_cleanup_running=0\n',
        '          release_supervisor="$PWD/release-api-supervisor.py"\n',
        '          release_supervisor_pid=""\n',
        '          release_spawn_critical=0\n',
        '          release_pending_signal_status=0\n',
        '          release_id=""\n',
        '          release_upload_base=""\n',
        '          release_publish_attempted=0\n',
        '          release_transaction_marker="<!-- borondns-release-transaction ',
        '          release_response_file="$(/usr/bin/mktemp ',
        '          bounded_cleanup_api() {\n',
        '            /usr/bin/timeout --preserve-status --signal=TERM --kill-after=1s 1s \\\n',
        '          stop_release_supervisor() {\n',
        '          run_supervised_release_command() {\n',
        '            release_spawn_critical=1\n',
        '              --termination-grace-seconds 2 --authority-fd "$release_authority_fd" \\\n',
        '            release_supervisor_pid=$!\n',
        '            release_spawn_critical=0\n',
        '            printf \'%s\\n\' "$authority_token" >&"$release_authority_fd"\n',
        '          cleanup_pending_release() {\n',
        '            trap - EXIT\n',
        "            trap '' INT TERM HUP\n",
        '              local cleanup_id="$release_id" release_candidates="" release_record=""\n',
        '                if ! release_candidates="$(bounded_cleanup_api --method GET \\\n',
        '                  "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate \\\n',
        '                    if test "$candidate_draft" = true && test "$candidate_tag" = "$tag" && \\\n',
        '                      test "$candidate_marker" = "$release_transaction_marker"; then\n',
        '                  if test "$owned_match_count" -eq 0; then\n',
        '                  elif test "$owned_match_count" -ne 1; then\n',
        '              if [[ "$cleanup_id" =~ ^[1-9][0-9]*$ ]] && ! release_record="$(bounded_cleanup_api --method GET \\\n',
        '                if test "$observed_id" != "$cleanup_id" || test "$observed_tag" != "$tag" || \\\n',
        '                  test "$observed_marker" != "$release_transaction_marker" || \\\n',
        '                  { test "$observed_draft" != true && \\\n',
        '                    { test "$release_publish_attempted" != 1 || test "$observed_draft" != false; }; }; then\n',
        '              if [[ "$cleanup_id" =~ ^[1-9][0-9]*$ ]]; then\n',
        '                if ! bounded_cleanup_api --method DELETE \\\n',
        "printf 'critical: failed to list releases while locating incomplete draft: %s\\n'",
        "printf 'critical: no owned incomplete draft found during cleanup: %s\\n'",
        "printf 'critical: ambiguous owned incomplete drafts during cleanup: tag=%s count=%s\\n'",
        "printf 'critical: release listing returned an invalid immutable id: tag=%s id=%s\\n'",
        "printf 'critical: failed to authenticate incomplete release transaction: tag=%s id=%s\\n'",
        "printf 'critical: refusing to delete release not owned by this transaction: tag=%s id=%s\\n'",
        "printf 'critical: failed to delete incomplete release transaction: tag=%s id=%s\\n'",
        '          trap cleanup_pending_release EXIT\n',
        '          release_signal_handler() {\n',
        "          trap 'release_signal_handler 130' INT\n",
        "          trap 'release_signal_handler 143' TERM\n",
        "          trap 'release_signal_handler 129' HUP\n",
        '          $release_transaction_marker\n',
        '          release_cleanup_pending=1\n',
        '          run_supervised_release_command 120 "$gh_path" api --method POST \\\n',
        '          run_supervised_release_command 120 "$gh_path" api --method GET \\\n',
        '          peel_remote_tag "$release_response_file"\n',
        '          [[ "$release_id" =~ ^[1-9][0-9]*$ ]]\n',
        '          test "$created_draft" = true\n',
        '          test "$created_prerelease" = "$release_prerelease"\n',
        '            -F "prerelease=$release_prerelease" -f "make_latest=false" \\\n',
        '          release_upload_base="https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets"\n',
        '          test "$release_upload_url" = "$release_upload_base{?name,label}"\n',
        '          test "${#release_assets[@]}" -eq 34\n',
        '              "$release_upload_base" -f "name=$asset" --input "$asset" \\\n',
        '          run_supervised_release_command 120 "$gh_path" api --method PATCH \\\n',
        '          release_publish_attempted=1\n',
        '            -F "prerelease=$release_prerelease" -f "make_latest=$release_make_latest" \\\n',
        '          test "$published_prerelease" = "$release_prerelease"\n',
        '          release_cleanup_pending=0\n',
    )
    release_cleanup_contract_counts = {
        '          release_cleanup_pending=0\n': 2,
        '          release_supervisor_pid=""\n': 3,
        '          release_spawn_critical=0\n': 2,
        '          release_pending_signal_status=0\n': 2,
        '          release_publish_attempted=0\n': 1,
        '            -F "prerelease=$release_prerelease" -f "make_latest=false" \\\n': 1,
        '            -F "prerelease=$release_prerelease" -f "make_latest=$release_make_latest" \\\n': 1,
        '          run_supervised_release_command 120 "$gh_path" api --method POST \\\n': 1,
        '            run_supervised_release_command 600 "$gh_path" api --method POST \\\n': 1,
        '          run_supervised_release_command 120 "$gh_path" api --method GET \\\n': 2,
        '          peel_remote_tag "$release_response_file"\n': 1,
    }
    if (
        release_step is None
        or release_step[1].count(post_create_tag_guard) != 2
        or 'release tag moved during publication:' not in release_step[1]
        or 'release tag moved after publication:' not in release_step[1]
    ):
        errors.append(
            "release publication must verify the peeled remote tag before and after draft publication"
        )
    if release_step is None or any(
        release_step[1].count(marker) != release_cleanup_contract_counts.get(marker, 1)
        for marker in release_cleanup_contract
    ):
        errors.append(
            "release publication must arm one bounded, ownership-authenticated, signal-safe API-first draft transaction"
        )
    if release_step is None or "--hostname uploads.github.com" in release_step[1]:
        errors.append("release uploads must use the authenticated absolute uploads.github.com URL")
    if release_step is not None and 'releases/tags/$tag' in release_step[1]:
        errors.append("draft cleanup must not use the published-only release-by-tag endpoint")

    if "--certificate-identity-regexp" in text:
        errors.append("release verification must not accept a cross-tag identity regexp")
    if EXPECTED_IDENTITY not in text:
        errors.append("release verification must bind the certificate identity to $tag exactly")
    if "actionlint" not in verify:
        errors.append("verify-source must install actionlint for workflow validation")
    expected_syft_check = (
        "printf '%s  %s\\n' \"$SYFT_LINUX_AMD64_SHA256\" "
        '"/tmp/$syft_archive" | /usr/bin/sha256sum -c -'
    )
    if expected_syft_check not in package:
        errors.append("package-release must verify Syft with the reviewed archive SHA256")
    if "syft_${syft_version}_checksums.txt" in package or "syft-checksums.txt" in package:
        errors.append("package-release must not trust a checksum fetched with the Syft archive")
    if "$GITHUB_ENV" in text:
        errors.append("release workflow steps must not persist mutable job environment overrides")
    if "BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE" in text:
        errors.append("release workflow must never pass the non-release dirty packaging override")
    if text.count(CLEAN_TREE_COMMAND) != 5 or text.count('test ! -s "$git_status_file"') != 5:
        errors.append("every release clean-tree gate must fail closed on git status errors")
    if "scripts/" in sign or "actions/checkout@" in sign:
        errors.append("privileged sign-release must not checkout or execute repository scripts")
    pins = [action.rsplit("@", 1)[1] for action in actions if "@" in action]
    return errors, pins


def package_policy_errors(text: str) -> list[str]:
    """Require checksum preflight and both binaries from a private run target."""
    contract = re.search(
        r'^run_build_target=.*?^install -m 0755 "\$boron_gun_binary" "\$run_staging/bin/boron-gun"$',
        text,
        re.MULTILINE | re.DOTALL,
    )
    if (
        contract is None
        or hashlib.sha256(contract.group(0).encode("utf-8")).hexdigest()
        != PACKAGE_TARGET_CONTRACT_SHA256
    ):
        return [
            "package installer checksum preflight or private CARGO_TARGET_DIR contract drifted"
        ]
    errors: list[str] = []
    checksum_preflight = (
        "if ! command -v sha256sum >/dev/null 2>&1 && "
        "! command -v shasum >/dev/null 2>&1; then\n"
        '    missing+=("sha256sum-or-shasum")\n'
        "fi\n"
    )
    if text.count(checksum_preflight) != 1:
        errors.append("package installer must require one supported checksum tool")
    if 'archive_root="$package_name-$version-$target_triple"' not in text:
        errors.append("package installer archive root must include the exact target triple")
    if (
        '"$cargo_bin" metadata --no-deps --locked --format-version 1' not in text
        or '--manifest-path "$repo_root/Cargo.toml"' not in text
    ):
        errors.append("package installer metadata must use verified Cargo and the exact repository manifest")
    required = (
        'allow_dirty_non_release="${BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE:-0}"',
        'if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then',
        'source_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)"',
        'commit="${source_commit:0:12}"',
        'verify_source_identity "before build"',
        'verify_source_identity "after build"',
        'verify_source_identity "before artifact publication"',
        'verify_source_identity "terminal publication"',
        "printf 'source_clean=%s\\n' \"$source_clean\"",
        "printf 'release_eligible=%s\\n' \"$release_eligible\"",
        "printf 'dirty_source_override=%s\\n' \"$allow_dirty_non_release\"",
    )
    for marker in required:
        if text.count(marker) != 1:
            errors.append(f"package installer dirty-source boundary is missing or duplicated: {marker}")
    if text.count("status --porcelain=v1 --untracked-files=all --ignored=no") != 2:
        errors.append("package installer must check complete source status at preflight and revalidation")
    hermetic_build_prefix = (
        'env -i HOME="$run_build_home" CARGO_HOME="$run_cargo_home" \\\n'
        '        PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \\\n'
    )
    if text.count(hermetic_build_prefix) != 2:
        errors.append("package installer release builds must use the exact empty hermetic environment")
    if text.count('SOURCE_DATE_EPOCH="$source_epoch" CARGO_INCREMENTAL=0') != 2:
        errors.append("package installer release builds must use the reproducibility environment")
    if text.count('CARGO_ENCODED_RUSTFLAGS="$release_encoded_rustflags"') != 2:
        errors.append("package installer release builds must remap private build paths")
    if text.count('CARGO_TARGET_DIR="$run_build_target" "$cargo_bin" build --locked --release') != 2:
        errors.append("package installer builds must bind verified Cargo and the private target directory")
    ordered_publication_contract = (
        'verify_source_identity "before build"',
        'env -i HOME="$run_build_home" CARGO_HOME="$run_cargo_home"',
        'verify_source_identity "after build"',
        'verify_source_identity "before artifact publication"',
        'tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner',
        'package_acquire_publication_lock "$dist_dir" "$archive_root" publication_lock_fd',
        'verify_source_identity "terminal publication"',
        'package_publish_candidate "$run_staging" "$staging"',
        "package_commit_publication",
    )
    positions = [text.find(marker) for marker in ordered_publication_contract]
    if any(position < 0 for position in positions) or positions != sorted(positions) or len(set(positions)) != len(positions):
        errors.append("package installer source checks, artifact creation, lock, publication, and commit are out of reviewed order")
    return errors


def docker_package_policy_errors(script: str, dockerfile: str) -> list[str]:
    """Require the published image to use and record one reviewed base digest."""
    errors: list[str] = []
    default_assignment = (
        'alpine_base_image="${BORONDNS_DOCKER_ALPINE_BASE_IMAGE:-'
        f'{EXPECTED_ALPINE_BASE_IMAGE}'
        '}"'
    )
    dockerfile_arg = f"ARG ALPINE_BASE_IMAGE={EXPECTED_ALPINE_BASE_IMAGE}"
    for label, text, required in (
        ("Docker packaging default", script, default_assignment),
        ("Dockerfile base", dockerfile, dockerfile_arg),
        (
            "Docker build argument",
            script,
            '--build-arg "ALPINE_BASE_IMAGE=$alpine_base_image"',
        ),
        (
            "Docker packaging exact-digest guard",
            script,
            f'if [[ "$alpine_base_image" != "{EXPECTED_ALPINE_BASE_IMAGE}" ]]; then',
        ),
        ("Dockerfile FROM", dockerfile, "FROM ${ALPINE_BASE_IMAGE}"),
        ("Docker evidence base", script, "printf 'base_image=%s\\n' \"$alpine_base_image\""),
        (
            "Docker evidence digest",
            script,
            "printf 'base_image_digest=%s\\n' \"$alpine_base_digest\"",
        ),
        (
            "Docker isolated installer input",
            script,
            'docker_installer_dist_dir="${BORONDNS_DOCKER_INSTALLER_DIST_DIR:-$repo_root/target/docker-installer-input}"',
        ),
        (
            "Docker isolated installer build",
            script,
            'BORONDNS_DIST_DIR="$private_installer_dist_dir"',
        ),
        (
            "Docker installer publication separation guard",
            script,
            'Docker installer input directory must be isolated from published dist',
        ),
        (
            "Docker dirty-source override declaration",
            script,
            'allow_dirty_non_release="${BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE:-0}"',
        ),
        (
            "Docker GitHub Actions override rejection",
            script,
            'if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then',
        ),
        ("Docker pre-build source boundary", script, 'verify_source_identity "before installer build"'),
        ("Docker terminal source boundary", script, 'verify_source_identity "terminal publication"'),
        ("Docker source-clean manifest", script, "printf 'source_clean=%s\\n' \"$source_clean\""),
        ("Docker release eligibility manifest", script, "printf 'release_eligible=%s\\n' \"$release_eligible\""),
        (
            "Docker dirty override manifest",
            script,
            "printf 'dirty_source_override=%s\\n' \"$allow_dirty_non_release\"",
        ),
        ("Docker source-clean build argument", script, '--build-arg "SOURCE_CLEAN=$source_clean"'),
        ("Docker release eligibility build argument", script, '--build-arg "RELEASE_ELIGIBLE=$release_eligible"'),
        (
            "Docker supervised verified archive load",
            script,
            'package_load_verified_docker_archive "$run_image_archive"',
        ),
        ("Dockerfile source-clean argument", dockerfile, "ARG SOURCE_CLEAN=unknown"),
        ("Dockerfile release eligibility argument", dockerfile, "ARG RELEASE_ELIGIBLE=unknown"),
        ("Docker image source-clean label", dockerfile, 'io.borondns.source-clean="${SOURCE_CLEAN}"'),
        (
            "Docker image release eligibility label",
            dockerfile,
            'io.borondns.release-eligible="${RELEASE_ELIGIBLE}"',
        ),
    ):
        if text.count(required) != 1:
            errors.append(f"{label} must contain exactly its reviewed digest-pinned form")
    if "ALPINE_VERSION" in dockerfile or "BORONDNS_DOCKER_ALPINE_VERSION" in script:
        errors.append("published Docker image must not fall back to a mutable Alpine version tag")
    if 'BORONDNS_DIST_DIR="$dist_dir"' in script:
        errors.append("Docker packaging must not rebuild installer inputs in published dist")
    if script.count("status --porcelain=v1 --untracked-files=all --ignored=no") != 2:
        errors.append("Docker packaging must check complete source status at preflight and revalidation")
    if script.count('package_verify_docker_archive_bundle "$run_image_archive" "$run_image_archive.sha256"') != 2:
        errors.append("Docker private archive bundle must be verified after creation and at terminal publication")
    if script.count('package_verify_docker_archive_bundle "$image_archive" "$image_archive.sha256"') != 2:
        errors.append("Docker published archive bundle must be verified after promotion and before commit")
    if 'xz -dc "$run_image_archive" | docker load' in script:
        errors.append("Docker packaging must not load an unverified ambient archive stream")
    return errors


def require_mutation_error(text: str, label: str, needle: str) -> None:
    errors, _ = policy_errors(text)
    if not any(needle in error for error in errors):
        raise RuntimeError(f"release policy checker missed {label} mutation")


def require_actionlint_valid(text: str, label: str) -> None:
    """Prove selected bypass fixtures remain valid GitHub Actions YAML."""
    actionlint = shutil.which("actionlint")
    if actionlint is None:
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yml") as fixture:
        fixture.write(text)
        fixture.flush()
        result = subprocess.run(
            [actionlint, fixture.name],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"release policy {label} regression fixture is no longer actionlint-valid: "
            f"{result.stdout}{result.stderr}"
        )


def release_publication_run_script(text: str) -> str:
    """Extract the exact privileged publication shell from the workflow."""
    release_step = named_step(text, "Create GitHub release")
    if release_step is None:
        raise RuntimeError("release publication fixture requires its named workflow step")
    body = release_step[1]
    marker = "        run: |\n"
    if body.count(marker) != 1:
        raise RuntimeError("release publication fixture requires one literal run block")
    run = body.split(marker, 1)[1]
    lines = run.splitlines()
    if any(line and not line.startswith("          ") for line in lines):
        raise RuntimeError("release publication fixture has unexpected shell indentation")
    return "\n".join(line[10:] if line else "" for line in lines) + "\n"


def run_release_publication_recovery_regressions(text: str) -> None:
    """Execute the exact workflow shell against a stateful fake gh client."""
    script = release_publication_run_script(text)
    fake_gh_source = r'''#!/usr/bin/python3
import hashlib
import os
from pathlib import Path
import sys
import time

state = Path(os.environ["FAKE_GH_STATE"])
scenario = os.environ["FAKE_GH_SCENARIO"]
tag = os.environ["GITHUB_REF_NAME"]
expected_sha = os.environ["GITHUB_SHA"]
args = sys.argv[1:]
version = tag[1:]
version_without_build = version.split("+", 1)[0]
expected_prerelease = "true" if "-" in version_without_build else "false"
expected_create_make_latest = "false"
expected_publish_make_latest = "false" if expected_prerelease == "true" else "true"


def touch(name: str, value: str = "") -> None:
    (state / name).write_text(value, encoding="utf-8")


def exists(name: str) -> bool:
    return (state / name).exists()


def field(name: str) -> str:
    values = [value.split("=", 1)[1] for value in args if value.startswith(f"{name}=")]
    if len(values) != 1:
        raise SystemExit(68)
    return values[0]


if args and args[0] == "api":
    endpoint = next(
        (arg for arg in args if arg.startswith("repos/") or arg.startswith("https://")), ""
    )
    method = args[args.index("--method") + 1] if "--method" in args else "GET"
else:
    endpoint = ""
    method = ""

if endpoint.endswith("/releases") and method == "POST":
    if (
        field("draft") != "true"
        or field("prerelease") != expected_prerelease
        or field("make_latest") != expected_create_make_latest
    ):
        raise SystemExit(69)
    if scenario == "fail-before":
        raise SystemExit(41)
    if scenario == "preexisting-unrelated":
        raise SystemExit(42)
    body = next(value[5:] for value in args if value.startswith("body="))
    marker = body.splitlines()[0]
    touch("marker", marker)
    touch("created")
    if "hung-create" in scenario:
        touch("hung")
        touch("hung-pid", str(os.getpid()))
        time.sleep(30)
    if scenario.startswith("create-response-loss"):
        raise SystemExit(42)
    print(
        f"777\thttps://uploads.github.com/repos/{os.environ['GITHUB_REPOSITORY']}"
        f"/releases/777/assets{{?name,label}}\ttrue\t{expected_prerelease}"
    )
    raise SystemExit(0)

if endpoint.endswith("/releases/777/assets") and method == "POST":
    expected_endpoint = (
        f"https://uploads.github.com/repos/{os.environ['GITHUB_REPOSITORY']}"
        "/releases/777/assets"
    )
    if endpoint != expected_endpoint or "--hostname" in args or "?name=" in endpoint:
        raise SystemExit(65)
    if "-H" not in args or args[args.index("-H") + 1] != "Content-Type: application/octet-stream":
        raise SystemExit(66)
    asset_name = field("name")
    if "--input" not in args or Path(args[args.index("--input") + 1]).name != asset_name:
        raise SystemExit(67)
    asset_path = Path(args[args.index("--input") + 1])
    with (state / "upload-log").open("a", encoding="utf-8") as upload_log:
        upload_log.write(f"{asset_name}\n")
    touch("partial")
    if scenario == "upload-asset-mutation" and not asset_name.endswith(".sigstore.json"):
        asset_path.write_bytes(asset_path.read_bytes() + b"upload asset mutation\n")
    if scenario == "upload-bundle-mutation" and asset_name.endswith(".sigstore.json"):
        asset_path.write_bytes(asset_path.read_bytes() + b"upload bundle mutation\n")
    if "hung-upload" in scenario:
        touch("hung")
        touch("hung-pid", str(os.getpid()))
        time.sleep(30)
    if scenario in {
        "upload-failure",
        "cleanup-delete-failure",
        "known-id-tag-tamper",
        "known-id-id-tamper",
        "known-id-marker-tamper",
        "known-id-invalid-draft",
        "known-id-premature-publish",
    }:
        raise SystemExit(42)
    uploaded_name = f"renamed-{asset_name}" if scenario == "upload-name-mismatch" else asset_name
    uploaded_state = "open" if scenario == "upload-state-mismatch" else "uploaded"
    uploaded_size = asset_path.stat().st_size + (1 if scenario == "upload-size-mismatch" else 0)
    uploaded_digest = f"sha256:{hashlib.sha256(asset_path.read_bytes()).hexdigest()}"
    if scenario == "upload-digest-mismatch":
        uploaded_digest = f"sha256:{'0' * 64}"
    print(f"{uploaded_name}\t{uploaded_state}\t{uploaded_size}\t{uploaded_digest}")
    raise SystemExit(0)

if endpoint.endswith("/releases/777") and method == "PATCH":
    if (
        field("draft") != "false"
        or field("prerelease") != expected_prerelease
        or field("make_latest") != expected_publish_make_latest
    ):
        raise SystemExit(69)
    touch("published")
    if scenario in {"publish-response-loss", "publish-response-loss-tamper"}:
        raise SystemExit(42)
    print(f"777\tfalse\t{expected_prerelease}")
    raise SystemExit(0)

if "/git/ref/tags/" in endpoint:
    count_file = state / "tag-count"
    count = int(count_file.read_text(encoding="utf-8")) + 1 if count_file.exists() else 1
    count_file.write_text(str(count), encoding="utf-8")
    if scenario == "hung-post-create-tag" and count >= 2:
        touch("hung")
        touch("hung-pid", str(os.getpid()))
        time.sleep(30)
    drift = (scenario == "tag-drift" and count >= 2) or (
        scenario == "tag-drift-after-publish" and count >= 3
    )
    print(f"commit\t{'f' * 40 if drift else expected_sha}")
    raise SystemExit(0)

if endpoint.endswith(f"/releases/tags/{tag}"):
    touch("published-only-tag-lookup")
    raise SystemExit(70)

if endpoint.endswith("/releases?per_page=100") and method == "GET":
    if "--paginate" not in args:
        raise SystemExit(71)
    if "list" in scenario:
        if "hung" in scenario:
            time.sleep(30)
        raise SystemExit(43)
    if scenario == "preexisting-unrelated":
        print(f"888\ttrue\t{tag}\t<!-- unrelated release -->")
        raise SystemExit(0)
    if exists("created") and not exists("deleted"):
        marker = (state / "marker").read_text(encoding="utf-8")
        if scenario == "create-response-loss-pagination":
            print(f"888\ttrue\t{tag}\t<!-- unrelated release -->")
        print(f"777\ttrue\t{tag}\t{marker}")
        if scenario == "create-response-loss-ambiguity":
            print(f"778\ttrue\t{tag}\t{marker}")
    raise SystemExit(0)

if endpoint.endswith("/releases/777") and method == "GET":
    touch("read-attempt")
    if "read" in scenario:
        if "hung" in scenario:
            time.sleep(30)
        raise SystemExit(44)
    observed_id = "999" if scenario == "known-id-id-tamper" else "777"
    observed_tag = "v9.9.9" if scenario == "known-id-tag-tamper" else tag
    observed_marker = (state / "marker").read_text(encoding="utf-8")
    if scenario in {"known-id-marker-tamper", "publish-response-loss-tamper"}:
        observed_marker = "<!-- unrelated release -->"
    if scenario == "known-id-invalid-draft":
        observed_draft = "null"
    elif scenario == "known-id-premature-publish" or exists("published"):
        observed_draft = "false"
    else:
        observed_draft = "true"
    print(f"{observed_id}\t{observed_tag}\t{observed_marker}\t{observed_draft}")
    raise SystemExit(0)

if endpoint.endswith("/releases/888") and method == "GET":
    print(f"888\t{tag}\t<!-- unrelated release -->\ttrue")
    raise SystemExit(0)

if endpoint.endswith("/releases/777") and method == "DELETE":
    touch("delete-attempt")
    if "delete" in scenario:
        if "hung" in scenario:
            time.sleep(30)
        raise SystemExit(45)
    touch("deleted")
    raise SystemExit(0)

if endpoint.endswith("/releases/888") and method == "DELETE":
    touch("unrelated-delete-attempt")
    raise SystemExit(0)

raise SystemExit(64)
'''
    fake_cosign_source = r'''#!/usr/bin/python3
import hashlib
import os
from pathlib import Path
import sys

state = Path(os.environ["FAKE_GH_STATE"])
scenario = os.environ["FAKE_GH_SCENARIO"]
args = sys.argv[1:]

if args and args[0] == "sign-blob":
    bundle = Path(args[args.index("--bundle") + 1])
    asset = Path(args[-1])
    if scenario == "auth-to-sign-mutation" and not (state / "auth-mutated").exists():
        asset.write_bytes(asset.read_bytes() + b"auth to sign mutation\n")
        (state / "auth-mutated").touch()
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    bundle.write_text(digest + "\n", encoding="ascii")
    raise SystemExit(0)

if args and args[0] == "verify-blob":
    bundle = Path(args[args.index("--bundle") + 1])
    asset = Path(args[-1])
    expected = bundle.read_text(encoding="ascii").strip()
    actual = hashlib.sha256(asset.read_bytes()).hexdigest()
    if expected != actual:
        raise SystemExit(1)
    count_file = state / "cosign-verify-count"
    count = int(count_file.read_text(encoding="ascii")) + 1 if count_file.exists() else 1
    count_file.write_text(str(count), encoding="ascii")
    if count == 34 and scenario == "post-sign-asset-mutation":
        target = next(Path.cwd().glob("borondns-*-x86_64-unknown-linux-musl.tar.xz"))
        target.write_bytes(target.read_bytes() + b"post sign asset mutation\n")
    if count == 34 and scenario == "post-sign-bundle-mutation":
        target = next(Path.cwd().glob("borondns-*-x86_64-unknown-linux-musl.tar.xz.sigstore.json"))
        target.write_bytes(target.read_bytes() + b"post sign bundle mutation\n")
    print("Verified OK")
    raise SystemExit(0)

raise SystemExit(64)
'''
    cases = {
        "fail-before": (41, False, False, False),
        "create-response-loss": (42, True, True, True),
        "create-response-loss-pagination": (42, True, True, True),
        "create-response-loss-ambiguity": (42, True, False, False),
        "create-response-loss-list-failure": (42, True, False, False),
        "create-response-loss-read-failure": (42, True, False, False),
        "upload-failure": (42, True, True, True),
        "upload-name-mismatch": (1, True, True, True),
        "upload-state-mismatch": (1, True, True, True),
        "upload-size-mismatch": (1, True, True, True),
        "upload-digest-mismatch": (1, True, True, True),
        "auth-to-sign-mutation": (1, False, False, False),
        "post-sign-asset-mutation": (1, True, True, True),
        "post-sign-bundle-mutation": (1, True, True, True),
        "upload-asset-mutation": (1, True, True, True),
        "upload-bundle-mutation": (1, True, True, True),
        "known-id-tag-tamper": (42, True, False, False),
        "known-id-id-tamper": (42, True, False, False),
        "known-id-marker-tamper": (42, True, False, False),
        "known-id-invalid-draft": (42, True, False, False),
        "known-id-premature-publish": (42, True, False, False),
        "tag-drift": (1, True, True, True),
        "publish-response-loss": (42, True, True, True),
        "publish-response-loss-tamper": (42, True, False, False),
        "tag-drift-after-publish": (1, True, True, True),
        "cleanup-delete-failure": (42, True, True, False),
        "success": (0, True, False, False),
        "success-prerelease": (0, True, False, False),
        "success-build-metadata": (0, True, False, False),
        "preexisting-unrelated": (42, False, False, False),
    }
    with tempfile.TemporaryDirectory(prefix="borondns-release-publication-") as raw_tmp:
        tmp = Path(raw_tmp)
        runner_temp = tmp / "runner"
        handoff = tmp / "target" / "release-handoff"
        source_tools = runner_temp / "source-tools"
        source_tools.mkdir(parents=True)
        version = "0.2.0"
        prerelease_version = "0.2.0-rc.1"
        build_version = "0.2.0+build.7"
        target = "x86_64-unknown-linux-musl"

        def prepare_handoff_fixture(release_version: str) -> tuple[list[str], str, str]:
            shutil.rmtree(handoff, ignore_errors=True)
            handoff.mkdir(parents=True)
            commit = "a" * 40
            write_reproducibility_fixture(handoff, commit)
            shutil.copy2(ROOT / "scripts" / "release-api-supervisor.py", handoff)
            shutil.copy2(ROOT / "scripts" / "verify-release-reproducibility.py", handoff)
            prefix = f"borondns-{release_version}-{target}"
            tarball = f"{prefix}.tar.xz"
            binary = f"{prefix}.bin"
            boron_gun = f"{prefix}-boron-gun.bin"
            docker_image = f"{prefix}-docker-image.tar.xz"
            docker_manifest = f"{prefix}-docker-image.manifest.txt"
            borondns_sbom = f"{prefix}-borondns.cdx.json"
            boron_gun_sbom = f"{prefix}-boron-gun.cdx.json"
            docker_sbom = f"{prefix}-docker-image.cdx.json"
            sbom_manifest = f"{prefix}-sbom-manifest.tsv"
            primary_assets = (
                tarball, binary, boron_gun, docker_image, docker_manifest,
                borondns_sbom, boron_gun_sbom, docker_sbom, sbom_manifest,
            )
            for asset in primary_assets:
                (handoff / asset).write_bytes(f"fixture {asset}\n".encode())
            (handoff / binary).write_bytes(b"reproducible-borondns\n")
            (handoff / boron_gun).write_bytes(b"reproducible-boron-gun\n")
            checksummed = (
                tarball, binary, boron_gun, docker_image,
                borondns_sbom, boron_gun_sbom, docker_sbom,
            )
            for asset in checksummed:
                digest = hashlib.sha256((handoff / asset).read_bytes()).hexdigest()
                (handoff / f"{asset}.sha256").write_text(
                    f"{digest}  {asset}\n", encoding="ascii"
                )
            handoff_assets = [
                tarball, f"{tarball}.sha256", binary, f"{binary}.sha256",
                boron_gun, f"{boron_gun}.sha256", docker_image,
                f"{docker_image}.sha256", docker_manifest, borondns_sbom,
                f"{borondns_sbom}.sha256", boron_gun_sbom,
                f"{boron_gun_sbom}.sha256", docker_sbom,
                f"{docker_sbom}.sha256", sbom_manifest,
            ]
            handoff_manifest = "".join(
                f"{hashlib.sha256((handoff / asset).read_bytes()).hexdigest()}  {asset}\n"
                for asset in handoff_assets
            )
            (handoff / "release-handoff.sha256").write_text(
                handoff_manifest, encoding="ascii"
            )
            signing_inputs = (
                "release-api-supervisor.py", "verify-release-reproducibility.py",
                "reproducible-build-summary.env", "comparison.tsv",
                "artifact-manifest.tsv", "artifacts/a/borondns",
                "artifacts/a/boron-gun", "artifacts/b/borondns",
                "artifacts/b/boron-gun",
            )
            signing_manifest = "".join(
                f"{hashlib.sha256((handoff / asset).read_bytes()).hexdigest()}  {asset}\n"
                for asset in signing_inputs
            )
            (handoff / "signing-inputs.sha256").write_text(
                signing_manifest, encoding="ascii"
            )
            release_assets: list[str] = []
            for asset in (tarball, binary, boron_gun, docker_image):
                release_assets.extend(
                    (asset, f"{asset}.sha256", f"{asset}.sigstore.json",
                     f"{asset}.sha256.sigstore.json")
                )
            release_assets.extend((docker_manifest, f"{docker_manifest}.sigstore.json"))
            for asset in (borondns_sbom, boron_gun_sbom, docker_sbom):
                release_assets.extend(
                    (asset, f"{asset}.sha256", f"{asset}.sigstore.json",
                     f"{asset}.sha256.sigstore.json")
                )
            release_assets.extend(
                (sbom_manifest, f"{sbom_manifest}.sigstore.json",
                 "release-handoff.sha256", "release-handoff.sha256.sigstore.json")
            )
            if len(release_assets) != 34:
                raise RuntimeError("release publication fixture must model exactly 34 assets")
            return (
                release_assets,
                hashlib.sha256(handoff_manifest.encode()).hexdigest(),
                hashlib.sha256(signing_manifest.encode()).hexdigest(),
            )

        fake_gh = source_tools / "gh"
        fake_gh.write_text(fake_gh_source, encoding="utf-8")
        fake_gh.chmod(0o500)
        fake_cosign = source_tools / "cosign"
        fake_cosign.write_text(fake_cosign_source, encoding="utf-8")
        fake_cosign.chmod(0o500)
        executable = script.replace(
            'gh_source="$(/usr/bin/realpath -e /usr/bin/gh)"',
            'gh_source="$(/usr/bin/realpath -e "$RUNNER_TEMP/source-tools/gh")"',
            1,
        )
        if "${{" in executable:
            raise RuntimeError("release publication fixture retained an Actions expression")
        for scenario, (expected_status, created, delete_attempt, deleted) in cases.items():
            release_version = (
                prerelease_version if scenario == "success-prerelease" else
                build_version if scenario == "success-build-metadata" else version
            )
            fixture_assets, handoff_sha256, signing_inputs_sha256 = prepare_handoff_fixture(
                release_version
            )
            state = tmp / f"state-{scenario}"
            state.mkdir()
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_GH_SCENARIO": scenario,
                    "FAKE_GH_STATE": str(state),
                    "GITHUB_REF_NAME": f"v{release_version}",
                    "GITHUB_REPOSITORY": "integrity/borondns",
                    "GITHUB_RUN_ATTEMPT": "3",
                    "GITHUB_RUN_ID": "424242",
                    "GITHUB_SHA": "a" * 40,
                    "RUNNER_TEMP": str(runner_temp),
                    "RUNNER_TOOL_CACHE": str(runner_temp / "tool-cache"),
                    "EXPECTED_HANDOFF_MANIFEST_SHA256": handoff_sha256,
                    "EXPECTED_SIGNING_INPUTS_MANIFEST_SHA256": signing_inputs_sha256,
                    "PATH": f"{source_tools}:{os.environ.get('PATH', '')}",
                }
            )
            result = subprocess.run(
                ["/usr/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", executable],
                cwd=tmp,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            actual = (
                result.returncode,
                (state / "created").exists(),
                (state / "delete-attempt").exists(),
                (state / "deleted").exists(),
            )
            expected = (expected_status, created, delete_attempt, deleted)
            if actual != expected:
                raise RuntimeError(
                    f"release publication recovery fixture failed for {scenario}: "
                    f"expected={expected!r} actual={actual!r} stdout={result.stdout!r} "
                    f"stderr={result.stderr!r} state={sorted(path.name for path in state.iterdir())!r}"
                )
            if (state / "unrelated-delete-attempt").exists():
                raise RuntimeError("release cleanup deleted a pre-existing unrelated release")
            if (state / "published-only-tag-lookup").exists():
                raise RuntimeError("release cleanup used the published-only tag lookup for a draft")
            if delete_attempt and not (state / "read-attempt").exists():
                raise RuntimeError("release cleanup deleted an immutable ID without re-authenticating it")
            if scenario == "cleanup-delete-failure" and "failed to delete incomplete release transaction" not in result.stderr:
                raise RuntimeError("release cleanup failure was not reported")
            if scenario == "preexisting-unrelated" and "no owned incomplete draft found" not in result.stderr:
                raise RuntimeError("release cleanup did not report the unrelated release boundary")
            quick_diagnostics = {
                "create-response-loss-ambiguity": "critical: ambiguous owned incomplete drafts",
                "create-response-loss-list-failure": "critical: failed to list releases",
                "create-response-loss-read-failure": "critical: failed to authenticate incomplete release",
                "known-id-tag-tamper": "critical: refusing to delete release not owned by this transaction",
                "known-id-id-tamper": "critical: refusing to delete release not owned by this transaction",
                "known-id-marker-tamper": "critical: refusing to delete release not owned by this transaction",
                "known-id-invalid-draft": "critical: refusing to delete release not owned by this transaction",
                "known-id-premature-publish": "critical: refusing to delete release not owned by this transaction",
                "publish-response-loss-tamper": "critical: refusing to delete release not owned by this transaction",
            }
            if scenario in quick_diagnostics and quick_diagnostics[scenario] not in result.stderr:
                raise RuntimeError(f"release cleanup lacked critical diagnostic for {scenario}")
            if scenario.startswith("known-id-") or scenario.startswith("publish-response-loss"):
                if not (state / "read-attempt").exists():
                    raise RuntimeError(
                        f"release cleanup did not re-authenticate its immutable ID for {scenario}"
                    )
            if scenario in {"success", "success-prerelease", "success-build-metadata"}:
                uploads = (state / "upload-log").read_text(encoding="utf-8").splitlines()
                if uploads != fixture_assets:
                    raise RuntimeError(
                        "release publication did not upload the exact 34 assets through the uploads API"
                    )

        runner_cases = {
            "hung-create": (True, ""),
            "hung-upload": (True, ""),
            "hung-post-create-tag": (True, ""),
            "hung-create-list": (False, "failed to list releases while locating incomplete draft"),
            "hung-create-read": (False, "failed to authenticate incomplete release transaction"),
            "hung-upload-delete": (False, "failed to delete incomplete release transaction"),
        }
        for scenario, (deleted, diagnostic) in runner_cases.items():
            _, handoff_sha256, signing_inputs_sha256 = prepare_handoff_fixture(version)
            state = tmp / f"state-{scenario}"
            state.mkdir()
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_GH_SCENARIO": scenario,
                    "FAKE_GH_STATE": str(state),
                    "GITHUB_REF_NAME": "v0.2.0",
                    "GITHUB_REPOSITORY": "integrity/borondns",
                    "GITHUB_RUN_ATTEMPT": "3",
                    "GITHUB_RUN_ID": "424242",
                    "GITHUB_SHA": "a" * 40,
                    "RUNNER_TEMP": str(runner_temp),
                    "RUNNER_TOOL_CACHE": str(runner_temp / "tool-cache"),
                    "EXPECTED_HANDOFF_MANIFEST_SHA256": handoff_sha256,
                    "EXPECTED_SIGNING_INPUTS_MANIFEST_SHA256": signing_inputs_sha256,
                    "PATH": f"{source_tools}:{os.environ.get('PATH', '')}",
                }
            )
            process = subprocess.Popen(
                ["/usr/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", executable],
                cwd=tmp,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            # Process creation can be delayed substantially when the enclosing
            # full shell gate has just saturated a CI runner with shellcheck.
            # This is only the fixture-start observation window; production
            # command and cleanup deadlines remain unchanged and bounded.
            deadline = time.monotonic() + 10
            while not (state / "hung").exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            if not (state / "hung").exists():
                process.kill()
                raise RuntimeError(f"release runner fixture did not enter hung phase: {scenario}")
            hung_child_pid = int((state / "hung-pid").read_text(encoding="utf-8"))
            if hung_child_pid == process.pid:
                process.kill()
                raise RuntimeError(f"release runner fixture did not supervise a child: {scenario}")
            os.kill(hung_child_pid, 0)
            os.kill(process.pid, signal.SIGINT)
            int_deadline = time.monotonic() + 7.5
            while process.poll() is None and time.monotonic() < int_deadline:
                time.sleep(0.02)
            if process.poll() is None:
                os.kill(process.pid, signal.SIGTERM)
                term_deadline = time.monotonic() + 2.5
                while process.poll() is None and time.monotonic() < term_deadline:
                    time.sleep(0.02)
            killed = process.poll() is None
            if killed:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            if killed or process.returncode != 130 or (state / "deleted").exists() != deleted:
                raise RuntimeError(
                    f"release runner cancellation fixture failed for {scenario}: "
                    f"killed={killed} status={process.returncode} deleted={(state / 'deleted').exists()} "
                    f"stdout={stdout!r} stderr={stderr!r}"
                )
            if diagnostic and f"critical: {diagnostic}" not in stderr:
                raise RuntimeError(f"release runner fixture lacked cleanup diagnostic for {scenario}")
            try:
                os.kill(hung_child_pid, 0)
            except ProcessLookupError:
                pass
            else:
                os.kill(hung_child_pid, signal.SIGKILL)
                raise RuntimeError(f"release runner fixture leaked its supervised child: {scenario}")


def run_real_gh_upload_request_regression() -> None:
    """Prove that the reviewed absolute upload URL reaches uploads.github.com."""
    gh_path = shutil.which("gh")
    if gh_path is None:
        raise RuntimeError("release upload request regression requires the real gh CLI")
    endpoint = "https://uploads.github.com/repos/integrity/borondns/releases/777/assets"
    asset_name = "fixture+build.bin"
    with tempfile.TemporaryDirectory(prefix="borondns-real-gh-upload-") as raw_tmp:
        asset = Path(raw_tmp) / asset_name
        asset.write_bytes(b"fixture\n")
        environment = os.environ.copy()
        environment.update(
            {
                "ALL_PROXY": "",
                "GH_DEBUG": "api",
                "GH_TOKEN": "not-a-real-github-token",
                "HTTP_PROXY": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "NO_PROXY": "",
                "all_proxy": "",
                "http_proxy": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "no_proxy": "",
            }
        )
        result = subprocess.run(
            [
                gh_path,
                "api",
                "--method",
                "POST",
                "-H",
                "Content-Type: application/octet-stream",
                endpoint,
                "-f",
                f"name={asset_name}",
                "--input",
                str(asset),
                "--silent",
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    transcript = result.stdout + result.stderr
    if (
        f"Request to {endpoint}?name=fixture%2Bbuild.bin" not in transcript
        or "> Host: uploads.github.com" not in transcript
        or "> Authorization: token " not in transcript
    ):
        raise RuntimeError(
            "real gh did not construct the reviewed uploads.github.com request: "
            f"status={result.returncode} transcript={transcript!r}"
        )
    if "api.uploads.github.com" in transcript:
        raise RuntimeError("real gh rewrote the release upload request to api.uploads.github.com")


def run_mutation_regressions(text: str) -> None:
    checkout = re.search(
        r'''^(?P<indent>[ ]*)(?:uses|'uses'|"uses")[ ]*:[ ]*actions/checkout@[0-9a-f]{40}(?:[ ]+#.*)?$''',
        text,
        re.MULTILINE,
    )
    if checkout is None:
        raise RuntimeError("release policy regression fixture requires pinned checkout action")
    indent = checkout.group("indent")
    mutations = {
        "space before colon": f"{indent}uses : actions/checkout@v5",
        "single-quoted key": f"{indent}'uses': actions/checkout@v5",
        "double-quoted key": f'{indent}"uses" : actions/checkout@v5',
        "folded multiline scalar": f"{indent}uses: >-\n{indent}  actions/checkout@v5",
        "escaped double-quoted key": f'{indent}"\\x75ses": actions/checkout@v5',
        "tagged key": f"{indent}!!str uses: actions/checkout@v5",
        "explicit key": f"{indent}? uses\n{indent}: actions/checkout@v5",
    }
    for label, replacement in mutations.items():
        mutated = text[: checkout.start()] + replacement + text[checkout.end() :]
        require_mutation_error(mutated, label, "release workflow")

    checkout_step_end = text.find("\n\n", checkout.end())
    if checkout_step_end < 0:
        raise RuntimeError("release policy regression fixture requires complete checkout step")
    exotic_steps = {
        "anchored flow action": (
            "\n      - &evil_step { name: Anchored action, uses: actions/setup-python@v5 }"
            "\n      - *evil_step"
        ),
        "anchored block action": (
            "\n      - &evil_block\n"
            "        name: Anchored block action\n"
            "        uses: actions/setup-python@v5\n"
            "      - *evil_block"
        ),
        "tagged flow key": "\n      - { !!str uses: actions/setup-python@v5 }",
        "explicit flow key": "\n      - { ? uses : actions/setup-python@v5 }",
        "tagged flow mapping node": "\n      - !!map { uses: actions/setup-python@v5 }",
        "multiline flow mapping value": (
            "\n      - { uses:\n            actions/setup-python@v5 }"
        ),
    }
    for label, insertion in exotic_steps.items():
        mutated = text[:checkout_step_end] + insertion + text[checkout_step_end:]
        if label in {"tagged flow mapping node", "multiline flow mapping value"}:
            require_actionlint_valid(mutated, label)
        require_mutation_error(mutated, label, "unsupported YAML")

    block_header = "        run: |\n"
    scalar_text_mutated = text.replace(
        block_header,
        block_header + "          echo '- &not_a_yaml_anchor'\n",
        1,
    )
    errors, _ = policy_errors(scalar_text_mutated)
    if any("unsupported YAML" in error for error in errors):
        raise RuntimeError("release policy checker inspected anchor text inside block scalar")

    inherited_shell = text.replace(
        "    runs-on: ubuntu-24.04\n",
        '    runs-on: ubuntu-24.04\n    defaults:\n      run:\n        shell: "true {0}"\n',
        1,
    )
    require_actionlint_valid(inherited_shell, "inherited true shell")
    require_mutation_error(inherited_shell, "inherited true shell", "must not override defaults.run")
    container_job = text.replace(
        "    runs-on: ubuntu-24.04\n",
        "    runs-on: ubuntu-24.04\n    container: attacker/image:latest\n",
        1,
    )
    require_mutation_error(container_job, "job container", "must not override defaults.run")

    jobs, _ = job_blocks(text)
    for job_name in ("verify-source", "package-release", "sign-release"):
        original = jobs[job_name]
        weakened = original.replace(
            f"    runs-on: {EXPECTED_RUNNER}\n", "    runs-on: self-hosted\n", 1
        )
        mutated = text.replace(original, weakened, 1)
        require_actionlint_valid(mutated, f"self-hosted {job_name}")
        require_mutation_error(
            mutated,
            f"self-hosted {job_name}",
            f"{job_name} must run exactly on {EXPECTED_RUNNER}",
        )

    for job_name in ("verify-source", "package-release"):
        original = jobs[job_name]
        weakened = original.replace("      contents: read\n", "      contents: write\n", 1)
        require_mutation_error(
            text.replace(original, weakened, 1),
            f"privileged {job_name}",
            f"{job_name} must have only",
        )

    no_package_needs = text.replace("    needs: verify-source\n", "", 1)
    require_mutation_error(
        no_package_needs, "package job without verification", "depend only on verify-source"
    )
    no_sign_needs = text.replace("    needs: package-release\n", "", 1)
    require_mutation_error(
        no_sign_needs, "sign job without package dependency", "depend only on package-release"
    )
    no_source_output = text.replace(
        '      source_commit: ${{ steps.source-commit.outputs.commit }}\n', "", 1
    )
    require_mutation_error(
        no_source_output, "missing verified source output", "verified source commit"
    )
    final_verify_step = named_step(text, "Verify Continuous gate preserved clean source")
    if final_verify_step is None:
        raise RuntimeError("release policy fixture requires final verify-source clean gate")
    final_verify_start, final_verify_block = final_verify_step
    final_head_pin = '          test "$(/usr/bin/git rev-parse HEAD)" = "$GITHUB_SHA"\n'
    for label, weakened_pin in (
        ("removed final verify-source HEAD pin", ""),
        (
            "falsified final verify-source HEAD pin",
            '          test "$(/usr/bin/git rev-parse HEAD)" != "$GITHUB_SHA"\n',
        ),
    ):
        weakened_block = final_verify_block.replace(final_head_pin, weakened_pin, 1)
        if weakened_block == final_verify_block:
            raise RuntimeError("release policy fixture final HEAD pin was not found")
        mutation = (
            text[:final_verify_start]
            + weakened_block
            + text[final_verify_start + len(final_verify_block) :]
        )
        require_actionlint_valid(mutation, label)
        require_mutation_error(mutation, label, "final clean-tree gate must pin HEAD")
    no_checkout_ref = text.replace(
        '          ref: ${{ needs.verify-source.outputs.source_commit }}\n', "", 1
    )
    require_actionlint_valid(no_checkout_ref, "package checkout without verified ref")
    require_mutation_error(
        no_checkout_ref, "package checkout without verified ref", "package-release step body"
    )
    no_manifest_output = text.replace(
        '      handoff_manifest_sha256: ${{ steps.prepare-handoff.outputs.manifest-sha256 }}\n',
        "",
        1,
    )
    require_mutation_error(no_manifest_output, "unauthenticated handoff", "handoff invariant")
    misleading_digest = text.replace(
        '      handoff_manifest_sha256: ${{ steps.prepare-handoff.outputs.manifest-sha256 }}\n',
        '      handoff_manifest_sha256: ${{ steps.prepare-handoff.outputs.manifest-sha256 }}\n'
        '      handoff_artifact_digest: ${{ steps.upload-handoff.outputs.artifact-digest }}\n',
        1,
    )
    require_actionlint_valid(misleading_digest, "unchecked artifact digest")
    require_mutation_error(
        misleading_digest,
        "unchecked artifact digest",
        "must expose only",
    )

    static_marker = "      - name: Verify static binaries\n"
    attacker_copy = text.replace(
        static_marker,
        "      - run: cp /tmp/attacker target/dist/borondns-untrusted.bin\n\n"
        + static_marker,
        1,
    )
    require_actionlint_valid(attacker_copy, "package attacker-copy step")
    require_mutation_error(
        attacker_copy, "package attacker-copy step", "package-release must contain exactly"
    )

    packaged_clean_step = named_step(text, "Verify packaged source remained clean")
    if packaged_clean_step is None:
        raise RuntimeError("release policy fixture requires final packaged-source clean gate")
    packaged_clean_start, packaged_clean_block = packaged_clean_step
    no_packaged_clean_gate = (
        text[:packaged_clean_start]
        + text[packaged_clean_start + len(packaged_clean_block) :]
    )
    require_actionlint_valid(no_packaged_clean_gate, "missing final packaged-source clean gate")
    require_mutation_error(
        no_packaged_clean_gate,
        "missing final packaged-source clean gate",
        "package-release must contain exactly",
    )
    moved_packaged_clean_gate = no_packaged_clean_gate.replace(
        static_marker,
        packaged_clean_block + static_marker,
        1,
    )
    require_actionlint_valid(moved_packaged_clean_gate, "early packaged-source clean gate")
    require_mutation_error(
        moved_packaged_clean_gate,
        "early packaged-source clean gate",
        "must contain exactly",
    )

    continuous_run = "        run: scripts/check.sh\n"
    persistent_env = text.replace(
        continuous_run,
        "        run: |\n"
        "          scripts/check.sh\n"
        '          echo "RUSTC_WRAPPER=/tmp/attacker" >> "$GITHUB_ENV"\n',
        1,
    )
    require_actionlint_valid(persistent_env, "persistent tool override")
    require_mutation_error(
        persistent_env, "persistent tool override", "must not persist mutable job environment"
    )

    packaging_tool_line = (
        '          "$HOME/.cargo/bin/rustup" target add --toolchain '
        '"$RUST_TOOLCHAIN_VERSION" x86_64-unknown-linux-musl\n'
    )
    inline_tool_override = text.replace(
        packaging_tool_line,
        packaging_tool_line + "          export RUSTC_WRAPPER=/tmp/attacker\n",
        1,
    )
    require_actionlint_valid(inline_tool_override, "inline packaging tool override")
    require_mutation_error(
        inline_tool_override, "inline packaging tool override", "package-release step body"
    )

    absolute_checksum = (
        '          test "$(/usr/bin/sha256sum "$verified_cargo" | '
        "/usr/bin/awk '{print $1}')\" = \"${{ needs.verify-source.outputs.cargo_sha256 }}\"\n"
    )
    path_checksum = text.replace(
        absolute_checksum,
        absolute_checksum.replace("/usr/bin/sha256sum", "sha256sum", 1),
        1,
    )
    if path_checksum == text:
        raise RuntimeError("release policy fixture requires an absolute checksum gate")
    require_actionlint_valid(path_checksum, "PATH-shadowable checksum")
    require_mutation_error(
        path_checksum, "PATH-shadowable checksum", "package-release step body"
    )

    exact_cosign = (
        '            "$cosign_path" sign-blob --yes --bundle '
        '"$asset.sigstore.json" "$asset"\n'
    )
    path_cosign = text.replace(exact_cosign, exact_cosign.replace('"$cosign_path"', "cosign", 1), 1)
    if path_cosign == text:
        raise RuntimeError("release policy fixture requires authenticated absolute Cosign")
    require_actionlint_valid(path_cosign, "PATH-shadowable Cosign")
    require_mutation_error(path_cosign, "PATH-shadowable Cosign", "sign-release step body")

    exact_gh = '          run_supervised_release_command 120 "$gh_path" api --method POST \\\n'
    path_gh = text.replace(exact_gh, exact_gh.replace('"$gh_path"', "gh", 1), 1)
    if path_gh == text:
        raise RuntimeError("release policy fixture requires authenticated absolute gh")
    require_actionlint_valid(path_gh, "PATH-shadowable gh")
    require_mutation_error(path_gh, "PATH-shadowable gh", "sign-release step body")

    exact_repo_binding = '            "repos/$GITHUB_REPOSITORY/releases" \\\n'
    unbound_gh = text.replace(
        exact_repo_binding,
        '            "repos/attacker/unbound/releases" \\\n',
        1,
    )
    if unbound_gh == text:
        raise RuntimeError("release policy fixture requires explicit gh repository binding")
    require_actionlint_valid(unbound_gh, "repository-unbound gh")
    require_mutation_error(
        unbound_gh,
        "repository-unbound gh",
        "release publication API calls must bind to GITHUB_REPOSITORY",
    )

    absolute_upload_base = (
        '          release_upload_base="https://uploads.github.com/repos/'
        '$GITHUB_REPOSITORY/releases/$release_id/assets"\n'
    )
    api_prefixed_upload = text.replace(
        absolute_upload_base,
        absolute_upload_base.replace("https://uploads.github.com", "https://api.uploads.github.com"),
        1,
    )
    if api_prefixed_upload == text:
        raise RuntimeError("release policy fixture requires the absolute upload API host")
    require_actionlint_valid(api_prefixed_upload, "api-prefixed upload host")
    require_mutation_error(
        api_prefixed_upload,
        "api-prefixed upload host",
        "authenticated release handoff invariant missing",
    )

    draft_list_endpoint = (
        '                  "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate \\\n'
    )
    published_only_lookup = text.replace(
        draft_list_endpoint,
        '                  "repos/$GITHUB_REPOSITORY/releases/tags/$tag" \\\n',
        1,
    )
    if published_only_lookup == text:
        raise RuntimeError("release policy fixture requires draft-capable paginated cleanup lookup")
    require_actionlint_valid(published_only_lookup, "published-only draft cleanup lookup")
    require_mutation_error(
        published_only_lookup,
        "published-only draft cleanup lookup",
        "draft cleanup must not use the published-only release-by-tag endpoint",
    )

    exact_remote_tag_guard = '          test "$tag_object_sha" = "$GITHUB_SHA"\n'
    moved_remote_tag = text.replace(
        exact_remote_tag_guard,
        '          test "$tag_object_sha" != "$GITHUB_SHA"\n',
        1,
    )
    if moved_remote_tag == text:
        raise RuntimeError("release policy fixture requires an exact remote tag target guard")
    require_actionlint_valid(moved_remote_tag, "moved remote release tag")
    require_mutation_error(
        moved_remote_tag,
        "moved remote release tag",
        "peel the authenticated remote tag",
    )

    path_tag_api = text.replace(
        '            run_supervised_release_command 120 "$gh_path" api --method GET \\\n',
        '            run_supervised_release_command 120 gh api --method GET \\\n',
        1,
    )
    if path_tag_api == text:
        raise RuntimeError("release policy fixture requires authenticated gh for remote tag lookup")
    require_actionlint_valid(path_tag_api, "PATH-shadowable remote tag lookup")
    require_mutation_error(
        path_tag_api,
        "PATH-shadowable remote tag lookup",
        "peel the authenticated remote tag",
    )

    exact_post_create_guard = (
        '          if peel_remote_tag "$release_response_file"; then\n'
        '            post_create_tag_sha="$(<"$release_response_file")"\n'
        '          fi\n'
        '          if test "$post_create_tag_sha" != "$GITHUB_SHA"; then\n'
    )
    missing_post_create_guard = text.replace(
        exact_post_create_guard,
        '          if /usr/bin/true; then\n'
        '            post_create_tag_sha="$GITHUB_SHA"\n'
        '          fi\n'
        '          if test "$post_create_tag_sha" != "$GITHUB_SHA"; then\n',
        1,
    )
    if missing_post_create_guard == text:
        raise RuntimeError("release policy fixture requires a post-create tag guard")
    require_actionlint_valid(missing_post_create_guard, "missing post-create tag lookup")
    require_mutation_error(
        missing_post_create_guard,
        "missing post-create tag lookup",
        "verify the peeled remote tag before and after",
    )

    cleanup_mutations = (
        (
            "missing release cleanup trap",
            "          trap cleanup_pending_release EXIT\n",
            "",
        ),
        (
            "unbounded release cleanup API",
            "            /usr/bin/timeout --preserve-status --signal=TERM --kill-after=1s 1s \\\n",
            "",
        ),
        (
            "missing release ownership check",
            '                if test "$observed_id" != "$cleanup_id" || test "$observed_tag" != "$tag" || \\\n',
            '                if /usr/bin/false || test "$observed_tag" != "$tag" || \\\n',
        ),
        (
            "missing known-ID release reauthentication",
            '              if [[ "$cleanup_id" =~ ^[1-9][0-9]*$ ]] && ! release_record="$(bounded_cleanup_api --method GET \\\n',
            '              if /usr/bin/false && ! release_record="$(bounded_cleanup_api --method GET \\\n',
        ),
        (
            "missing release rollback delete",
            '                if ! bounded_cleanup_api --method DELETE \\\n',
            '                if ! /usr/bin/false \\\n',
        ),
        (
            "early release cleanup commit",
            "          release_cleanup_pending=1\n",
            "          release_cleanup_pending=0\n",
        ),
    )
    for label, exact, weakened in cleanup_mutations:
        mutation = text.replace(exact, weakened, 1)
        if mutation == text:
            raise RuntimeError(f"release policy fixture requires {label}")
        require_actionlint_valid(mutation, label)
        require_mutation_error(
            mutation,
            label,
            "ownership-authenticated, signal-safe API-first draft transaction",
        )

    global_tool_override = text.replace(
        '  CARGO_MACHETE_VERSION: "0.9.2"\n',
        '  CARGO_MACHETE_VERSION: "0.9.2"\n'
        "  RUSTC_WRAPPER: /tmp/attacker\n",
        1,
    )
    require_actionlint_valid(global_tool_override, "global tool override")
    require_mutation_error(
        global_tool_override, "global tool override", "global release environment"
    )

    syft_digest_drift = text.replace(
        EXPECTED_SYFT_LINUX_AMD64_SHA256,
        "0" * 64,
        1,
    )
    if syft_digest_drift == text:
        raise RuntimeError("release policy fixture requires reviewed Syft digest")
    require_actionlint_valid(syft_digest_drift, "Syft archive digest drift")
    require_mutation_error(
        syft_digest_drift,
        "Syft archive digest drift",
        "global release environment",
    )

    reviewed_syft_check = (
        "          printf '%s  %s\\n' \"$SYFT_LINUX_AMD64_SHA256\" "
        '"/tmp/$syft_archive" | /usr/bin/sha256sum -c -\n'
    )
    same_release_syft_check = text.replace(
        reviewed_syft_check,
        "          curl -sSfL \\\n"
        "            \"https://github.com/anchore/syft/releases/download/"
        "$SYFT_VERSION/syft_${syft_version}_checksums.txt\" \\\n"
        "            -o /tmp/syft-checksums.txt\n"
        "          (cd /tmp && grep \"  $syft_archive$\" syft-checksums.txt | sha256sum -c -)\n",
        1,
    )
    if same_release_syft_check == text:
        raise RuntimeError("release policy fixture requires exact reviewed Syft check")
    require_actionlint_valid(same_release_syft_check, "same-release Syft checksum")
    require_mutation_error(
        same_release_syft_check,
        "same-release Syft checksum",
        "must not trust a checksum fetched with the Syft archive",
    )

    package_job_override = text.replace(
        "  package-release:\n    name: Package verified x86_64 musl artifacts\n",
        "  package-release:\n"
        "    name: Package verified x86_64 musl artifacts\n"
        "    env:\n"
        "      RUSTC_WRAPPER: /tmp/attacker\n",
        1,
    )
    if package_job_override == text:
        raise RuntimeError("release policy fixture requires exact package job name")
    require_actionlint_valid(package_job_override, "package job tool override")
    require_mutation_error(
        package_job_override,
        "package job tool override",
        "package-release job metadata drifted",
    )

    sign_marker = "      - name: Create GitHub release\n"
    unnamed_execution = text.replace(
        sign_marker,
        "      - run: target/release-handoff/borondns-untrusted.bin --version\n\n"
        + sign_marker,
        1,
    )
    require_actionlint_valid(unnamed_execution, "unnamed privileged executable")
    require_mutation_error(
        unnamed_execution,
        "unnamed privileged executable",
        "sign-release must contain exactly",
    )

    publish_assignment = (
        '          sbom_manifest="borondns-$version-x86_64-unknown-linux-musl-sbom-manifest.tsv"\n'
    )
    named_execution = text.replace(
        publish_assignment,
        publish_assignment + '          "$binary" --version\n',
        1,
    )
    require_actionlint_valid(named_execution, "named privileged executable")
    require_mutation_error(
        named_execution,
        "named privileged executable",
        "step body drifted",
    )

    install_step = (
        "      - name: Install Cosign\n"
        "        uses: sigstore/cosign-installer@"
        f"{EXPECTED_ACTIONS['sigstore/cosign-installer']} # v4.1.2\n\n"
    )
    if text.count(install_step) != 1:
        raise RuntimeError("release policy fixture requires exact Cosign install step")
    install_after_verify = text.replace(install_step, "", 1).replace(
        sign_marker, install_step + sign_marker, 1
    )
    require_actionlint_valid(install_after_verify, "post-verification action")
    require_mutation_error(
        install_after_verify,
        "post-verification action",
        "cosign-installer then download-artifact",
    )

    manifest_verification = (
        "          printf '%s  %s\\n' \"$EXPECTED_HANDOFF_MANIFEST_SHA256\" "
        "release-handoff.sha256 | /usr/bin/sha256sum -c --strict -\n"
    )
    no_manifest_verification = text.replace(manifest_verification, "", 1)
    if no_manifest_verification == text:
        raise RuntimeError("release policy fixture requires manifest SHA verification")
    require_mutation_error(
        no_manifest_verification,
        "missing manifest SHA verification",
        "handoff invariant",
    )

    isolated_package = (
        '          CARGO="$verified_cargo" RUSTC="$verified_rustc" CARGO_TARGET_DIR="$release_target_dir" scripts/package-installer.sh\n'
    )
    reused_target = text.replace(
        isolated_package,
        '          CARGO="$verified_cargo" RUSTC="$verified_rustc" scripts/package-installer.sh\n',
        1,
    )
    if reused_target == text:
        raise RuntimeError("release policy fixture requires isolated release target")
    require_actionlint_valid(reused_target, "reused Cargo target")
    require_mutation_error(
        reused_target,
        "reused Cargo target",
        "package-release step body",
    )

    dirty_package_override = text.replace(
        isolated_package,
        '          BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1 CARGO="$verified_cargo" RUSTC="$verified_rustc" CARGO_TARGET_DIR="$release_target_dir" scripts/package-installer.sh\n',
        1,
    )
    if dirty_package_override == text:
        raise RuntimeError("release policy fixture requires exact installer package command")
    require_actionlint_valid(dirty_package_override, "dirty package override")
    require_mutation_error(
        dirty_package_override,
        "dirty package override",
        "must never pass the non-release dirty packaging override",
    )

    path_cargo = text.replace(
        '          RUSTC="$verified_rustc" "$verified_cargo" install --locked cargo-cyclonedx',
        '          RUSTC="$verified_rustc" cargo install --locked cargo-cyclonedx',
        1,
    )
    if path_cargo == text:
        raise RuntimeError("release policy fixture requires absolute packaging cargo")
    require_actionlint_valid(path_cargo, "PATH cargo proxy")
    require_mutation_error(
        path_cargo,
        "PATH cargo proxy",
        "package-release step body",
    )


def run_package_mutation_regressions(text: str) -> None:
    target_mutations = {
        "normal binary target reuse": (
            'binary="$run_build_target/$target_triple/release/borondns"',
            'binary="$repo_root/target/$target_triple/release/borondns"',
        ),
        "BoronGun target reuse": (
            'boron_gun_binary="$run_build_target/$target_triple/release/boron-gun"',
            'boron_gun_binary="$repo_root/target/$target_triple/release/boron-gun"',
        ),
        "normal binary staging removal": (
            'install -m 0755 "$binary" "$run_staging/bin/borondns"',
            ': # omitted normal binary staging',
        ),
        "BoronGun staging removal": (
            'install -m 0755 "$boron_gun_binary" "$run_staging/bin/boron-gun"',
            ': # omitted BoronGun staging',
        ),
    }
    for label, (expected, weakened) in target_mutations.items():
        mutated = text.replace(expected, weakened, 1)
        if mutated == text:
            raise RuntimeError(f"package policy fixture requires {label}")
        if not package_policy_errors(mutated):
            raise RuntimeError(f"package policy checker missed {label} mutation")

    checksum_preflight = (
        "if ! command -v sha256sum >/dev/null 2>&1 && "
        "! command -v shasum >/dev/null 2>&1; then\n"
        '    missing+=("sha256sum-or-shasum")\n'
        "fi\n"
    )
    without_checksum_preflight = text.replace(checksum_preflight, "", 1)
    if without_checksum_preflight == text:
        raise RuntimeError("package policy fixture requires exact checksum preflight")
    if not package_policy_errors(without_checksum_preflight):
        raise RuntimeError("package policy checker missed checksum preflight removal")

    sha256sum_only = text.replace(
        checksum_preflight,
        "if ! command -v sha256sum >/dev/null 2>&1; then\n"
        '    missing+=("sha256sum")\n'
        "fi\n",
        1,
    )
    if not package_policy_errors(sha256sum_only):
        raise RuntimeError("package policy checker accepted a one-tool checksum preflight")

    path_cargo_build = text.replace(
        '        CARGO_TARGET_DIR="$run_build_target" "$cargo_bin" build --locked --release \\\n',
        '        CARGO_TARGET_DIR="$run_build_target" cargo build --locked --release \\\n',
        1,
    )
    if path_cargo_build == text:
        raise RuntimeError("package policy fixture requires absolute cargo build")
    if not package_policy_errors(path_cargo_build):
        raise RuntimeError("package policy checker missed PATH cargo proxy mutation")

    forged_build_metadata = text.replace(
        'BORONDNS_BUILD_COMMIT="$commit"',
        'BORONDNS_BUILD_COMMIT="${BORONDNS_BUILD_COMMIT:-$commit}"',
        1,
    )
    if forged_build_metadata == text:
        raise RuntimeError("package policy fixture requires sanitized binary build metadata")
    if not package_policy_errors(forged_build_metadata):
        raise RuntimeError("package policy checker missed inherited binary build metadata")

    ambient_metadata_manifest = text.replace(
        '--manifest-path "$repo_root/Cargo.toml"',
        '--manifest-path Cargo.toml',
        1,
    )
    if ambient_metadata_manifest == text:
        raise RuntimeError("package policy fixture requires exact metadata manifest binding")
    if not package_policy_errors(ambient_metadata_manifest):
        raise RuntimeError("package policy checker missed ambient metadata workspace mutation")

    for label, marker in (
        ("empty build environment", 'env -i HOME="$run_build_home" CARGO_HOME="$run_cargo_home"'),
        ("private build HOME", 'HOME="$run_build_home"'),
        ("private Cargo HOME", 'CARGO_HOME="$run_cargo_home"'),
        ("strict build PATH", 'PATH="$toolchain_bin:/usr/bin:/bin"'),
        ("verified rustc binding", 'RUSTC="$rustc_bin"'),
    ):
        mutated = text.replace(marker, "REMOVED")
        if mutated == text or not package_policy_errors(mutated):
            raise RuntimeError(f"package policy checker missed {label} removal")

    for label, marker in (
        ("dirty-source override declaration", 'allow_dirty_non_release="${BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE:-0}"'),
        (
            "GitHub Actions dirty-source rejection",
            'if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then',
        ),
        ("pre-build source boundary", 'verify_source_identity "before build"'),
        ("post-build source boundary", 'verify_source_identity "after build"'),
        ("pre-publication source boundary", 'verify_source_identity "before artifact publication"'),
        ("terminal source boundary", 'verify_source_identity "terminal publication"'),
        ("source-clean manifest", "printf 'source_clean=%s\\n' \"$source_clean\""),
        ("release-eligibility manifest", "printf 'release_eligible=%s\\n' \"$release_eligible\""),
        (
            "dirty-source override manifest",
            "printf 'dirty_source_override=%s\\n' \"$allow_dirty_non_release\"",
        ),
        ("complete source status", "status --porcelain=v1 --untracked-files=all --ignored=no"),
    ):
        mutated = text.replace(marker, "REMOVED", 1)
        if mutated == text or not package_policy_errors(mutated):
            raise RuntimeError(f"package policy checker missed {label} removal")

    terminal = 'verify_source_identity "terminal publication"\n'
    terminal_after_commit = text.replace(terminal, "", 1).replace(
        "package_commit_publication\n", "package_commit_publication\n" + terminal, 1
    )
    if terminal_after_commit == text or not package_policy_errors(terminal_after_commit):
        raise RuntimeError("package policy checker accepted terminal source verification after commit")

    prepublication = 'verify_source_identity "before artifact publication"\n'
    prepublication_after_publish = text.replace(prepublication, "", 1).replace(
        'package_publish_candidate "$run_staging" "$staging" "$dist_dir" \'installer staging directory\'\n',
        'package_publish_candidate "$run_staging" "$staging" "$dist_dir" \'installer staging directory\'\n'
        + prepublication,
        1,
    )
    if prepublication_after_publish == text or not package_policy_errors(prepublication_after_publish):
        raise RuntimeError("package policy checker accepted pre-publication verification after publication")


def run_docker_package_mutation_regressions(script: str, dockerfile: str) -> None:
    replacement = "sha256:" + "0" * 64
    for label, mutated_script, mutated_dockerfile in (
        (
            "Docker packaging base digest drift",
            script.replace(EXPECTED_ALPINE_BASE_IMAGE, f"alpine:3.22@{replacement}", 1),
            dockerfile,
        ),
        (
            "Dockerfile base digest drift",
            script,
            dockerfile.replace(
                EXPECTED_ALPINE_BASE_IMAGE,
                f"alpine:3.22@{replacement}",
                1,
            ),
        ),
        (
            "Docker evidence digest omission",
            script.replace(
                "    printf 'base_image_digest=%s\\n' \"$alpine_base_digest\"\n",
                "",
                1,
            ),
            dockerfile,
        ),
        (
            "Docker packaging exact-digest guard weakening",
            script.replace(
                f'if [[ "$alpine_base_image" != "{EXPECTED_ALPINE_BASE_IMAGE}" ]]; then',
                'if [[ ! "$alpine_base_image" =~ @sha256:[0-9a-f]{64}$ ]]; then',
                1,
            ),
            dockerfile,
        ),
        (
            "Docker installer input published-dist reuse",
            script.replace(
                'BORONDNS_DIST_DIR="$private_installer_dist_dir"',
                'BORONDNS_DIST_DIR="$dist_dir"',
                1,
            ),
            dockerfile,
        ),
        (
            "Docker installer publication separation guard removal",
            script.replace(
                "    printf 'Docker installer input directory must be isolated from published dist: %s\\n' \"$dist_dir\" >&2\n",
                "",
                1,
            ),
            dockerfile,
        ),
        (
            "Docker GitHub Actions dirty-source rejection removal",
            script.replace(
                'if [[ "$allow_dirty_non_release" == 1 && "${GITHUB_ACTIONS:-false}" == true ]]; then',
                "if false; then",
                1,
            ),
            dockerfile,
        ),
        (
            "Docker complete source status weakening",
            script.replace(
                "status --porcelain=v1 --untracked-files=all --ignored=no",
                "status --short",
                1,
            ),
            dockerfile,
        ),
        (
            "Docker source-clean image label removal",
            script,
            dockerfile.replace('io.borondns.source-clean="${SOURCE_CLEAN}"', "REMOVED", 1),
        ),
        (
            "Docker supervised verified load removal",
            script.replace('package_load_verified_docker_archive "$run_image_archive"', "REMOVED", 1),
            dockerfile,
        ),
        (
            "Docker terminal private bundle revalidation removal",
            script.replace(
                'package_verify_docker_archive_bundle "$run_image_archive" "$run_image_archive.sha256"',
                "REMOVED",
                1,
            ),
            dockerfile,
        ),
        (
            "Docker published bundle revalidation removal",
            script.replace(
                'package_verify_docker_archive_bundle "$image_archive" "$image_archive.sha256"',
                "REMOVED",
                1,
            ),
            dockerfile,
        ),
    ):
        if mutated_script == script and mutated_dockerfile == dockerfile:
            raise RuntimeError(f"Docker release policy fixture requires {label}")
        if not docker_package_policy_errors(mutated_script, mutated_dockerfile):
            raise RuntimeError(f"Docker release policy checker missed {label}")


def reproducible_build_policy_errors(text: str) -> list[str]:
    errors: list[str] = []
    required = (
        'source_commit="$(git -C "$repo_root" rev-parse HEAD)"',
        'status --porcelain=v1 --untracked-files=all --ignored=no',
        'verify_source_identity "before build $label"',
        'verify_source_identity "after build $label"',
        'verify_source_identity "before locked metadata capture"',
        'verify_source_identity "after locked metadata capture"',
        'verify_source_identity "before artifact capture"',
        'verify_source_identity "after artifact capture"',
        'verify_source_identity "terminal publication"',
        'short_commit="${commit:0:12}"',
    )
    for marker in required:
        if marker not in text:
            errors.append(f"reproducible-build source boundary is missing: {marker}")
    if text.count('status --porcelain=v1 --untracked-files=all --ignored=no') != 2:
        errors.append("reproducible-build must use complete source status at preflight and revalidation")
    if 'commit="$source_commit"' not in text:
        errors.append("reproducible-build evidence commit must use the preflight source identity")
    hermetic_prefix = (
        'env -i HOME="$hermetic_home" CARGO_HOME="$hermetic_cargo_home" \\\n'
        '            PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \\\n'
    )
    if text.count(hermetic_prefix) != 2:
        errors.append("both reproducible artifact builds must use the exact empty hermetic environment")
    if text.count('CARGO_ENCODED_RUSTFLAGS="$release_encoded_rustflags"') != 2:
        errors.append("both reproducible artifact builds must remap private build paths")
    metadata_prefix = (
        'env -i HOME="$hermetic_home" CARGO_HOME="$hermetic_cargo_home" \\\n'
        '    PATH="$toolchain_bin:/usr/bin:/bin" RUSTC="$rustc_bin" \\\n'
    )
    if text.count(metadata_prefix) != 1:
        errors.append("locked metadata capture must use the exact empty hermetic environment")
    return errors


def run_reproducible_build_mutation_regressions(text: str) -> None:
    for label, marker in (
        ("post-build source check", 'verify_source_identity "after build $label"'),
        ("terminal source check", 'verify_source_identity "terminal publication"'),
        ("complete source status", 'status --porcelain=v1 --untracked-files=all --ignored=no'),
        ("empty build environment", 'env -i HOME="$hermetic_home" CARGO_HOME="$hermetic_cargo_home"'),
    ):
        mutated = text.replace(marker, "REMOVED", 1)
        if mutated == text or not reproducible_build_policy_errors(mutated):
            raise RuntimeError(f"reproducible-build policy checker missed {label} removal")


def installer_readme_errors(text: str) -> list[str]:
    errors: list[str] = []
    required = (
        "sudo cosign verify-blob",
        '--bundle "$install_root/$asset.sigstore.json"',
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
        '--certificate-identity "https://github.com/Integrity-Ltd/borondns/.github/'
        'workflows/release-installer.yml@refs/tags/$tag"',
        "target_triple=x86_64-unknown-linux-musl",
        'asset="borondns-${tag#v}-$target_triple.tar.xz"',
        'install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"',
        'sudo chmod 0700 "$install_root"',
        'sudo install -m 0600 "$asset" "$asset.sigstore.json" "$install_root/"',
        '  "$install_root/$asset"',
        'sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"',
        'sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"',
    )
    for value in required:
        if value not in text:
            errors.append(f"installer quick install is missing: {value}")
    allocate_at = text.find(
        'install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"'
    )
    protect_at = text.find('sudo chmod 0700 "$install_root"')
    copy_at = text.find('sudo install -m 0600 "$asset" "$asset.sigstore.json" "$install_root/"')
    verify_at = text.find("sudo cosign verify-blob")
    verify_asset_at = text.find('  "$install_root/$asset"')
    extract_at = text.find(
        'sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"'
    )
    sudo_at = text.find('sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"')
    if min(allocate_at, protect_at, copy_at, verify_at, verify_asset_at, extract_at, sudo_at) >= 0 and not (
        allocate_at < protect_at < copy_at < verify_at < verify_asset_at < extract_at < sudo_at
    ):
        errors.append(
            "installer quick install must protect, verify, extract, and execute the same archive in order"
        )
    return errors


def run_installer_readme_mutation_regressions(text: str) -> None:
    for label, needle in (
        ("protected bundle verification", '--bundle "$install_root/$asset.sigstore.json"'),
        ("exact OIDC issuer", "--certificate-oidc-issuer https://token.actions.githubusercontent.com"),
        (
            "exact tagged workflow identity",
            '--certificate-identity "https://github.com/Integrity-Ltd/borondns/.github/'
            'workflows/release-installer.yml@refs/tags/$tag"',
        ),
        (
            "fresh root-owned extraction directory",
            'install_root="$(sudo mktemp -d "/var/tmp/borondns-install-${tag#v}.XXXXXX")"',
        ),
        ("root-only extraction directory mode", 'sudo chmod 0700 "$install_root"'),
        (
            "protected archive and bundle copy",
            'sudo install -m 0600 "$asset" "$asset.sigstore.json" "$install_root/"',
        ),
        ("protected archive verification", '  "$install_root/$asset"'),
        (
            "root-owned archive extraction",
            'sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"',
        ),
        (
            "absolute root-owned installer invocation",
            'sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"',
        ),
    ):
        mutated = text.replace(needle, "REMOVED", 1)
        if mutated == text or not installer_readme_errors(mutated):
            raise RuntimeError(f"installer README checker missed {label} removal")
    reordered = text.replace(
        "sudo cosign verify-blob \\",
        'sudo tar --no-same-owner -xf "$install_root/$asset" -C "$install_root"\n'
        "sudo cosign verify-blob \\",
        1,
    )
    if not installer_readme_errors(reordered):
        raise RuntimeError("installer README checker missed verification reordering")
    wrong_root = text.replace(
        'sudo "$install_root/borondns-${tag#v}-$target_triple/install.sh"',
        'sudo "$install_root/borondns-${tag#v}/install.sh"',
        1,
    )
    if wrong_root == text or not installer_readme_errors(wrong_root):
        raise RuntimeError("installer README checker missed extracted root drift")


def wait_for_fixture(path: Path, process: subprocess.Popen[bytes], label: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError(
                f"{label} exited before its fixture marker: status={process.returncode}"
            )
        time.sleep(0.01)
    process.kill()
    process.wait()
    raise RuntimeError(f"{label} did not reach its fixture marker")


def require_process_gone(pid: int, label: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    raise RuntimeError(f"release API supervisor left a live {label}: pid={pid}")


def run_release_api_supervisor_regressions() -> None:
    """Exercise cancellation gaps, exact status, deadline, and group cleanup."""
    base = [sys.executable, str(RELEASE_API_SUPERVISOR)]
    natural = subprocess.run(
        base + ["--timeout-seconds", "3", "--", sys.executable, "-c", "raise SystemExit(37)"],
        check=False,
        timeout=10,
    )
    if natural.returncode != 37:
        raise RuntimeError(
            f"release API supervisor lost exact child status: {natural.returncode}"
        )

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        authority = root / "authority"
        command_marker = root / "authority-command-ran"
        authority_fd = os.open(authority, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            process = subprocess.Popen(
                base
                + [
                    "--timeout-seconds", "3",
                    "--authority-fd", str(authority_fd),
                    "--authority-token", "fixture-authority",
                    "--", sys.executable, "-c",
                    f"from pathlib import Path; Path({str(command_marker)!r}).touch()",
                ],
                pass_fds=(authority_fd,),
            )
            time.sleep(0.2)
            if command_marker.exists():
                process.kill()
                process.wait()
                raise RuntimeError("release command spawned before parent authority")
            process.send_signal(signal.SIGTERM)
            status = process.wait(timeout=10)
            if status != 143 or command_marker.exists():
                raise RuntimeError(
                    "release parent-authority cancellation did not return 143 without spawning"
                )
        finally:
            os.close(authority_fd)

        before_spawn_marker = root / "before-spawn"
        continuation = root / "continue"
        command_marker = root / "before-spawn-command-ran"
        environment = os.environ.copy()
        environment.update(
            {
                "BORONDNS_RELEASE_API_TEST_PHASE": "before-spawn",
                "BORONDNS_RELEASE_API_TEST_MARKER": str(before_spawn_marker),
                "BORONDNS_RELEASE_API_TEST_CONTINUE": str(continuation),
            }
        )
        process = subprocess.Popen(
            base
            + [
                "--timeout-seconds", "3", "--", sys.executable, "-c",
                f"from pathlib import Path; Path({str(command_marker)!r}).touch()",
            ],
            env=environment,
        )
        wait_for_fixture(before_spawn_marker, process, "pre-spawn signal fixture")
        process.send_signal(signal.SIGINT)
        status = process.wait(timeout=10)
        if status != 130 or command_marker.exists():
            raise RuntimeError(
                "release pre-spawn cancellation did not return 130 without spawning"
            )

        leader_file = root / "timeout-leader"
        descendant_file = root / "timeout-descendant"
        descendant_source = (
            "import os,signal,subprocess,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"open({str(descendant_file)!r},'w').write(str(os.getpid())); "
            "end=time.monotonic()+60; "
            "[(subprocess.Popen([sys.executable,'-c','import time;time.sleep(0.1)']),"
            "time.sleep(0.005)) for _ in iter(int,1) if time.monotonic()<end]"
        )
        leader_source = (
            "import os,signal,subprocess,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"open({str(leader_file)!r},'w').write(str(os.getpid())); "
            f"subprocess.Popen([sys.executable,'-c',{descendant_source!r}]); "
            "time.sleep(60)"
        )
        process = subprocess.Popen(
            base
            + [
                "--timeout-seconds", "1", "--termination-grace-seconds", "1",
                "--", sys.executable, "-c", leader_source,
            ]
        )
        wait_for_fixture(leader_file, process, "timeout leader fixture")
        wait_for_fixture(descendant_file, process, "timeout descendant fixture")
        leader_pid = int(leader_file.read_text(encoding="ascii"))
        descendant_pid = int(descendant_file.read_text(encoding="ascii"))
        status = process.wait(timeout=12)
        if status != 124:
            raise RuntimeError(f"release API timeout status is not 124: {status}")
        require_process_gone(leader_pid, "timed-out leader")
        require_process_gone(descendant_pid, "timed-out descendant")

        descendant_file = root / "orphan-descendant"
        descendant_source = (
            "import os,signal,subprocess,sys,time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"open({str(descendant_file)!r},'w').write(str(os.getpid()))\n"
            "end=time.monotonic()+60\n"
            "while time.monotonic()<end:\n"
            " subprocess.Popen([sys.executable,'-c','import time;time.sleep(0.1)'])\n"
            " time.sleep(0.005)\n"
        )
        leader_source = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',{descendant_source!r}]); "
            "time.sleep(0.2)"
        )
        process = subprocess.Popen(
            base
            + [
                "--timeout-seconds", "5", "--termination-grace-seconds", "1",
                "--", sys.executable, "-c", leader_source,
            ],
            stderr=subprocess.PIPE,
        )
        wait_for_fixture(descendant_file, process, "orphan descendant fixture")
        descendant_pid = int(descendant_file.read_text(encoding="ascii"))
        _stdout, stderr = process.communicate(timeout=12)
        if process.returncode != 125 or b"live process-group descendants" not in stderr:
            raise RuntimeError(
                "release API supervisor accepted a leader exit with live descendants"
            )
        require_process_gone(descendant_pid, "post-leader descendant")


def write_reproducibility_fixture(root: Path, commit: str) -> None:
    artifacts: dict[str, tuple[str, int]] = {}
    for artifact in ("borondns", "boron-gun"):
        payload = f"reproducible-{artifact}\n".encode()
        digest = hashlib.sha256(payload).hexdigest()
        artifacts[artifact] = (digest, len(payload))
        for builder in ("a", "b"):
            destination = root / "artifacts" / builder / artifact
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
    (root / "reproducible-build-summary.env").write_text(
        "\n".join(
            (
                "reproducible_build_status=true", "artifact_match=true",
                "release_eligible=true", "dirty_source_override=0",
                "artifact_count=2", "matched_artifact_count=2",
                "target_triple=x86_64-unknown-linux-musl", f"commit={commit}",
                "source_date_epoch=1", f"evidence_dir={root}", "",
            )
        ),
        encoding="utf-8",
    )
    comparison_rows = [
        "artifact\ttarget\tprofile\tbuilder_a_sha256\tbuilder_b_sha256\t"
        "builder_a_size_bytes\tbuilder_b_size_bytes\tmatch\tevidence_path_a\t"
        "evidence_path_b"
    ]
    manifest_rows = [
        "artifact\tbuilder\ttarget\tprofile\tfeatures\tcommit\trust_version\t"
        "build_command\tsha256\tsize_bytes\tevidence_path"
    ]
    for artifact in ("borondns", "boron-gun"):
        digest, size = artifacts[artifact]
        comparison_rows.append(
            f"{artifact}\tx86_64-unknown-linux-musl\trelease\t{digest}\t{digest}\t"
            f"{size}\t{size}\ttrue\tartifacts/a/{artifact}\tartifacts/b/{artifact}"
        )
        features = "af-xdp" if artifact == "borondns" else "xdp"
        for builder in ("a", "b"):
            manifest_rows.append(
                f"{artifact}\t{builder}\tx86_64-unknown-linux-musl\trelease\t"
                f"{features}\t{commit}\trustc 1.96.1 (fixture 1970-01-01)\t"
                f"/fixture/cargo build --locked --release --target-dir "
                f"<builder-target-dir> --target x86_64-unknown-linux-musl -p "
                f"{'borondns-cli' if artifact == 'borondns' else 'boron-gun'} "
                f"--features {features}\t{digest}\t"
                f"{size}\tartifacts/{builder}/{artifact}"
            )
    (root / "comparison.tsv").write_text("\n".join(comparison_rows) + "\n", encoding="utf-8")
    (root / "artifact-manifest.tsv").write_text(
        "\n".join(manifest_rows) + "\n", encoding="utf-8"
    )


def run_release_reproducibility_regressions() -> None:
    commit = "a" * 40
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_reproducibility_fixture(root, commit)
        release_borondns = root / "release-borondns"
        release_boron_gun = root / "release-boron-gun"
        shutil.copyfile(root / "artifacts" / "a" / "borondns", release_borondns)
        shutil.copyfile(root / "artifacts" / "a" / "boron-gun", release_boron_gun)
        command = [
            sys.executable, str(RELEASE_REPRODUCIBILITY_VERIFIER),
            "--require-artifacts",
            "--release-borondns", str(release_borondns),
            "--release-boron-gun", str(release_boron_gun),
            str(root), commit,
        ]
        valid = subprocess.run(command, check=False, capture_output=True, text=True)
        if valid.returncode != 0 or "release_reproducibility=passed" not in valid.stdout:
            raise RuntimeError(
                f"valid release reproducibility fixture failed: {valid.stdout}{valid.stderr}"
            )
        artifact = root / "artifacts" / "b" / "boron-gun"
        original = artifact.read_bytes()
        artifact.write_bytes(original + b"tamper")
        tampered = subprocess.run(command, check=False, capture_output=True, text=True)
        if tampered.returncode == 0 or "artifact size mismatch" not in tampered.stderr:
            raise RuntimeError("release reproducibility verifier accepted a changed artifact")
        artifact.write_bytes(original)
        original_release = release_borondns.read_bytes()
        release_borondns.write_bytes(original_release + b"unrelated-release-bytes")
        unrelated_release = subprocess.run(
            command, check=False, capture_output=True, text=True
        )
        if (
            unrelated_release.returncode == 0
            or "shipped release binary differs" not in unrelated_release.stderr
        ):
            raise RuntimeError(
                "release reproducibility verifier accepted an unrelated shipped binary"
            )
        release_borondns.write_bytes(original_release)
        summary = root / "reproducible-build-summary.env"
        original_summary = summary.read_text(encoding="utf-8")
        summary.write_text(
            original_summary.replace("release_eligible=true", "release_eligible=false"),
            encoding="utf-8",
        )
        ineligible = subprocess.run(command, check=False, capture_output=True, text=True)
        if ineligible.returncode == 0 or "summary release_eligible" not in ineligible.stderr:
            raise RuntimeError("release reproducibility verifier accepted ineligible evidence")
        summary.write_text(original_summary, encoding="utf-8")
        manifest = root / "artifact-manifest.tsv"
        original_manifest = manifest.read_text(encoding="utf-8")
        manifest.write_text(
            original_manifest.replace("\taf-xdp\t", "\txdp\t", 1),
            encoding="utf-8",
        )
        mismatched = subprocess.run(command, check=False, capture_output=True, text=True)
        if mismatched.returncode == 0 or "manifest row is inconsistent" not in mismatched.stderr:
            raise RuntimeError("release reproducibility verifier accepted mismatched metadata")


def run_release_binary_binding_regressions(text: str) -> None:
    bindings = (
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/a/borondns" "${release_borondns[0]}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/b/borondns" "${release_borondns[0]}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/a/boron-gun" "${release_boron_gun[0]}"',
        '/usr/bin/cmp -- "$RUNNER_TEMP/borondns-release-reproducibility/artifacts/b/boron-gun" "${release_boron_gun[0]}"',
    )
    for binding in bindings:
        if text.count(binding) != 2:
            raise RuntimeError("release workflow must bind reproduced bytes after build and at handoff")
        first = text.find(binding)
        second = text.find(binding, first + len(binding))
        mutated = text[:second] + "/usr/bin/true # removed late byte binding" + text[second + len(binding):]
        errors, _pins = policy_errors(mutated)
        if not errors:
            raise RuntimeError("release policy accepted removal of late reproduced-byte binding")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        build_a = root / "a"
        build_b = root / "b"
        release = root / "release"
        for path in (build_a, build_b, release):
            path.write_bytes(b"reproduced release bytes\n")
        for build in (build_a, build_b):
            subprocess.run(["/usr/bin/cmp", "--", str(build), str(release)], check=True)
        release.write_bytes(b"tampered release bytes\n")
        if any(
            subprocess.run(
                ["/usr/bin/cmp", "--", str(build), str(release)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0
            for build in (build_a, build_b)
        ):
            raise RuntimeError("tampered release binary survived reproduced-byte binding")


def release_helper_policy_errors() -> list[str]:
    errors: list[str] = []
    for path, expected_digest in EXPECTED_RELEASE_HELPER_SHA256.items():
        relative = path.relative_to(ROOT)
        if path.is_symlink() or not path.is_file():
            errors.append(f"release helper must be a real regular file: {relative}")
            continue
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            errors.append(
                f"release helper drifted from its reviewed implementation: {relative}"
            )
    return errors


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    package_text = PACKAGE_INSTALLER.read_text(encoding="utf-8")
    docker_package_text = PACKAGE_DOCKER_IMAGE.read_text(encoding="utf-8")
    reproducible_build_text = REPRODUCIBLE_BUILD.read_text(encoding="utf-8")
    dockerfile_text = DOCKERFILE.read_text(encoding="utf-8")
    installer_readme = INSTALLER_README.read_text(encoding="utf-8")
    rust_toolchain = RUST_TOOLCHAIN.read_text(encoding="utf-8")
    quick_start_docs = [path.read_text(encoding="utf-8") for path in QUICK_START_DOCS]
    run_mutation_regressions(text)
    run_release_api_supervisor_regressions()
    run_release_reproducibility_regressions()
    run_release_binary_binding_regressions(text)
    run_release_publication_recovery_regressions(text)
    run_real_gh_upload_request_regression()
    run_package_mutation_regressions(package_text)
    reproducibility_environment_drift = package_text.replace(
        'SOURCE_DATE_EPOCH="$source_epoch" CARGO_INCREMENTAL=0', "REMOVED", 1
    )
    if not package_policy_errors(reproducibility_environment_drift):
        raise RuntimeError("package policy accepted mismatched reproducibility metadata")
    run_docker_package_mutation_regressions(docker_package_text, dockerfile_text)
    run_reproducible_build_mutation_regressions(reproducible_build_text)
    run_installer_readme_mutation_regressions(installer_readme)
    if not rust_toolchain_errors(rust_toolchain.replace("1.96.1", "stable", 1)):
        raise RuntimeError("release policy checker missed mutable Rust toolchain mutation")
    errors, pins = policy_errors(text)
    errors.extend(package_policy_errors(package_text))
    errors.extend(docker_package_policy_errors(docker_package_text, dockerfile_text))
    errors.extend(reproducible_build_policy_errors(reproducible_build_text))
    errors.extend(installer_readme_errors(installer_readme))
    errors.extend(rust_toolchain_errors(rust_toolchain))
    errors.extend(release_helper_policy_errors())
    for path, doc in zip(QUICK_START_DOCS, quick_start_docs, strict=True):
        doc_errors = installer_readme_errors(doc)
        errors.extend(f"{path.relative_to(ROOT)}: {error}" for error in doc_errors)
    if errors:
        for error in errors:
            print(f"release signing policy error: {error}", file=sys.stderr)
        return 1
    print(
        "release signing policy check passed: "
        f"jobs=verify-source,package-release,sign-release actions={len(pins)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
