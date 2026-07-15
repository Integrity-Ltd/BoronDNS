#!/usr/bin/env python3
"""Strictly validate a copied fuzz or large-soak evidence tree."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time


SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40,64}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
UINT = re.compile(r"^[0-9]+$")
NUMBER = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
FUZZ_UNIT = re.compile(r"^oxidedns-fuzz-[A-Za-z0-9_.-]+-[0-9]+-[A-Za-z0-9_.-]+\.service$")
FUZZ_ELAPSED_TOLERANCE_NANOSECONDS = 250_000_000
FUZZ_WALL_MONOTONIC_TOLERANCE_NANOSECONDS = 2_000_000_000
FUZZ_SAMPLER_PROBE_BUDGET_SECONDS = 10
FUZZ_SAMPLER_TERMINAL_OVERHEAD_SECONDS = 5
SOAK_DOCKER_CLEANUP_COMMANDS = 6
SOAK_DOCKER_TIMEOUT_KILL_GRACE_SECONDS = 5
SOAK_TIMESTAMP_TOLERANCE_SECONDS = 2
FUZZ_SUMMARY_HEADER = [
    "target",
    "status",
    "exit_status",
    "duration_seconds",
    "started_epoch_seconds",
    "ended_epoch_seconds",
    "elapsed_nanoseconds",
    "log_path",
    "artifact_dir",
    "command_file",
]
DEFAULT_COLLECTION_TIMEOUT_SECONDS = 10_800
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
HARD_MAX_ENTRIES = 1_000_000
HARD_MAX_DEPTH = 128
HARD_MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024
HARD_MAX_TOTAL_BYTES = 1024 * 1024 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024 * 1024


class ValidationBudget:
    def __init__(
        self,
        deadline: int,
        max_entries: int,
        max_depth: int,
        max_file_bytes: int,
        max_total_bytes: int,
    ) -> None:
        self.deadline = deadline
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.entries = 0
        self.total_bytes = 0
        self.streamed_bytes = 0

    def check_deadline(self) -> None:
        if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= self.deadline:
            fail("collection validation exhausted its absolute deadline")

    def account(self, path: Path, root: Path, info: os.stat_result) -> None:
        self.check_deadline()
        self.entries += 1
        if self.entries > self.max_entries:
            fail(f"collection entry cap exceeded: {self.max_entries}")
        try:
            depth = len(path.relative_to(root).parts)
        except ValueError:
            fail(f"collection path escaped its root: {path}")
        if depth > self.max_depth:
            fail(f"collection depth cap exceeded at {path}: {self.max_depth}")
        if stat.S_ISREG(info.st_mode):
            if info.st_size > self.max_file_bytes:
                fail(f"collection file size cap exceeded: {path}")
            self.total_bytes += info.st_size
            if self.total_bytes > self.max_total_bytes:
                fail(f"collection total byte cap exceeded: {self.max_total_bytes}")

    def account_streamed(self, path: Path, amount: int) -> None:
        self.check_deadline()
        self.streamed_bytes += amount
        if self.streamed_bytes > self.max_total_bytes:
            fail(f"collection streamed byte cap exceeded while hashing {path}: {self.max_total_bytes}")


BUDGET: ValidationBudget | None = None
INVENTORY: tuple[Path, ...] = ()
INVENTORY_IDENTITIES: dict[Path, tuple[int, int, int, int, int, int]] = {}


def file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def budget() -> ValidationBudget:
    if BUDGET is None:
        raise RuntimeError("collection validation budget is not initialized")
    return BUDGET


def fail(message: str) -> None:
    raise SystemExit(f"invalid collected campaign evidence: {message}")


def regular_tree(root: Path, *, snapshot: bool = False) -> str | None:
    global INVENTORY, INVENTORY_IDENTITIES
    if not root.is_dir() or root.is_symlink() or root.resolve() != root:
        fail(f"collection root is not a canonical real directory: {root}")
    paths: list[Path] = []
    identities: dict[Path, tuple[int, int, int, int, int, int]] = {}
    digest = hashlib.sha256() if snapshot else None
    for path in root.rglob("*"):
        budget().check_deadline()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            fail(f"unsafe symlink or special node: {path}")
        if path.resolve() != path:
            fail(f"path traverses a symlink: {path}")
        info = path.lstat()
        budget().account(path, root, info)
        paths.append(path)
        identities[path] = file_identity(info)
    INVENTORY = tuple(paths)
    INVENTORY_IDENTITIES = identities
    if snapshot and os.environ.get("OXIDEDNS_COLLECTION_SNAPSHOT_TEST_PHASE") == "after-inventory":
        marker = os.environ.get("OXIDEDNS_COLLECTION_SNAPSHOT_TEST_MARKER", "")
        continuation = os.environ.get("OXIDEDNS_COLLECTION_SNAPSHOT_TEST_CONTINUE", "")
        if not marker or not continuation:
            fail("collection snapshot test hook is incomplete")
        with open(marker, "x", encoding="ascii") as output:
            output.write("ready\n")
            output.flush()
            os.fsync(output.fileno())
        while not os.path.exists(continuation):
            budget().check_deadline()
            time.sleep(0.01)
    if digest is not None:
        paths.sort(key=lambda path: os.fsencode(path.relative_to(root).as_posix()))
    for path in paths if digest is not None else ():
        mode = path.lstat().st_mode
        if digest is not None:
            relative = os.fsencode(path.relative_to(root).as_posix())
            if stat.S_ISDIR(mode):
                digest.update(b"d\0" + relative + b"\0")
            else:
                digest.update(
                    b"f\0"
                    + relative
                    + b"\0"
                    + sha256(path, charge_streamed=True).encode("ascii")
                    + b"\0"
                )
    return digest.hexdigest() if digest is not None else None


def inventoried_descendants(root: Path) -> tuple[Path, ...]:
    budget().check_deadline()
    return tuple(path for path in INVENTORY if path != root and path.is_relative_to(root))


def inventoried_children(root: Path) -> tuple[Path, ...]:
    budget().check_deadline()
    return tuple(path for path in INVENTORY if path.parent == root)


def text_lines(path: Path) -> list[str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"text metadata is not a regular file: {path}")
    if info.st_size > min(budget().max_file_bytes, MAX_TEXT_BYTES):
        fail(f"text metadata exceeds its memory bound: {path}")
    lines: list[str] = []
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(descriptor)
        fail(f"text metadata identity changed before open: {path}")
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        for raw in handle:
            budget().check_deadline()
            lines.append(raw.rstrip("\n"))
        completed = os.fstat(handle.fileno())
    after = path.lstat()
    if (
        (completed.st_dev, completed.st_ino, completed.st_size)
        != (info.st_dev, info.st_ino, info.st_size)
        or (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size)
    ):
        fail(f"text metadata changed while reading: {path}")
    return lines


def env_file(path: Path, expected_keys: set[str] | None = None) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        fail(f"missing regular metadata file: {path}")
    values: dict[str, str] = {}
    for number, raw in enumerate(text_lines(path), 1):
        if "=" not in raw:
            fail(f"malformed metadata at {path}:{number}")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in values:
            fail(f"invalid or duplicate metadata key at {path}:{number}")
        values[key] = value
    if expected_keys is not None and set(values) != expected_keys:
        fail(f"metadata keys differ from canonical schema: {path}")
    return values


def relative_path(root: Path, text: str, kind: str) -> Path:
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        fail(f"unsafe {kind} relative path: {text!r}")
    candidate = root.joinpath(*pure.parts)
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError):
        fail(f"{kind} escapes or is missing: {text!r}")
    return candidate


def sha256(path: Path, *, charge_streamed: bool = False) -> str:
    digest = hashlib.sha256()
    total = 0
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        fail(f"hash target is not a regular file: {path}")
    expected = INVENTORY_IDENTITIES.get(path)
    if expected is not None and file_identity(before) != expected:
        fail(f"hash target changed after collection inventory: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or file_identity(opened) != file_identity(before):
        os.close(descriptor)
        fail(f"hash target identity changed before open: {path}")
    with os.fdopen(descriptor, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            budget().check_deadline()
            total += len(block)
            if total > budget().max_file_bytes:
                fail(f"collection file grew beyond its size cap: {path}")
            if charge_streamed:
                budget().account_streamed(path, len(block))
            digest.update(block)
        completed = os.fstat(handle.fileno())
    after = path.lstat()
    if (
        file_identity(completed) != file_identity(before)
        or file_identity(after) != file_identity(before)
        or completed.st_size != total
        or after.st_size != total
    ):
        fail(f"hash target changed while reading: {path}")
    return digest.hexdigest()


def verify_manifest(root: Path) -> None:
    manifest = root / "artifact-manifest.sha256"
    if not manifest.is_file() or manifest.is_symlink():
        fail(f"missing artifact manifest: {manifest}")
    authenticated: set[str] = set()
    previous = ""
    for number, line in enumerate(text_lines(manifest), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.@/+:-]+)", line)
        if match is None:
            fail(f"malformed artifact manifest at {manifest}:{number}")
        expected, relative = match.groups()
        if relative <= previous or relative in authenticated:
            fail(f"noncanonical artifact manifest ordering at {manifest}:{number}")
        path = relative_path(root, relative, "artifact-manifest")
        if not path.is_file() or path.is_symlink() or sha256(path) != expected:
            fail(f"artifact manifest mismatch: {path}")
        authenticated.add(relative)
        previous = relative
    if not authenticated:
        fail(f"empty artifact manifest: {manifest}")
    root_controls = {root / "artifact-manifest.sha256", root / "campaign-completed.env"}
    actual = {
        path.relative_to(root).as_posix()
        for path in inventoried_descendants(root)
        if path.is_file() and path not in root_controls
    }
    if authenticated != actual:
        missing = sorted(actual - authenticated)
        extra = sorted(authenticated - actual)
        fail(f"artifact manifest coverage mismatch missing={missing[:3]} extra={extra[:3]}")


def rows(path: Path, header: list[str]) -> list[list[str]]:
    if not path.is_file() or path.is_symlink():
        fail(f"missing regular TSV: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle, delimiter="\t")
        try:
            actual = next(reader)
        except StopIteration:
            fail(f"empty TSV: {path}")
        if actual != header:
            fail(f"noncanonical TSV header: {path}")
        result = list(reader)
    for number, row in enumerate(result, 2):
        if len(row) != len(header):
            fail(f"wrong TSV column count at {path}:{number}")
    return result


def verify_fuzz_process_details(
    attempt: Path,
    host_rows: list[list[str]],
    process_rows: list[list[str]],
    unit_count: int,
) -> None:
    """Bind every fuzz process row to its exact host sample and aggregates."""
    host_positions: dict[tuple[str, str], int] = {}
    details: dict[tuple[str, str], list[list[str]]] = {}
    for index, row in enumerate(host_rows):
        key = (row[0], row[1])
        if key in host_positions:
            fail(f"duplicate fuzz sampler host key: {attempt}")
        host_positions[key] = index
        details[key] = []
        if int(row[2]) > unit_count:
            fail(f"fuzz sampler active-unit count exceeds its allowlist: {attempt}")

    positions: list[int] = []
    seen_pids: set[tuple[tuple[str, str], str]] = set()
    process_path = attempt / "process-samples.tsv"
    for number, row in enumerate(process_rows, 2):
        if (
            not TIMESTAMP.fullmatch(row[0])
            or not UINT.fullmatch(row[1])
            or not re.fullmatch(r"[1-9][0-9]*", row[2])
            or not NUMBER.fullmatch(row[3])
            or not NUMBER.fullmatch(row[4])
            or not UINT.fullmatch(row[5])
            or not re.fullmatch(r"[0-9:-]+", row[6])
            or not re.fullmatch(r"[!-~]{1,15}", row[7])
        ):
            fail(f"invalid sampler process row at {process_path}:{number}")
        key = (row[0], row[1])
        if key not in host_positions:
            fail(f"orphan sampler process row at {process_path}:{number}")
        require_timestamp_epoch(row[0], int(row[1]), f"sampler process row at {process_path}:{number}")
        pid_key = (key, row[2])
        if pid_key in seen_pids:
            fail(f"duplicate sampler process PID at {process_path}:{number}")
        seen_pids.add(pid_key)
        details[key].append(row)
        positions.append(host_positions[key])
    if positions != sorted(positions):
        fail(f"sampler process chronology is invalid: {attempt}")

    for row in host_rows:
        key = (row[0], row[1])
        sample_details = details[key]
        process_count = len(sample_details)
        total_cpu = sum((Decimal(detail[3]) for detail in sample_details), Decimal(0))
        total_rss = sum(int(detail[5]) for detail in sample_details)
        rendered_cpu = format(
            total_cpu.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), ".2f"
        )
        if row[3] != str(process_count) or row[4] != rendered_cpu or row[5] != str(total_rss):
            fail(f"sampler process aggregates differ from host sample: {attempt} key={key}")


def verify_soak_process_details(
    attempt: Path,
    host_rows: list[list[str]],
    process_rows: list[list[str]],
) -> None:
    """Bind every soak process row to its exact resource sample and aggregates."""
    host_positions: dict[tuple[str, str], int] = {}
    details: dict[tuple[str, str], list[list[str]]] = {}
    for index, row in enumerate(host_rows):
        key = (row[0], row[1])
        if key in host_positions:
            fail(f"duplicate resource sampler host key: {attempt}")
        host_positions[key] = index
        details[key] = []

    positions: list[int] = []
    seen_pids: set[tuple[tuple[str, str], str]] = set()
    process_path = attempt / "process-samples.tsv"
    for number, row in enumerate(process_rows, 2):
        if (
            not TIMESTAMP.fullmatch(row[0])
            or not UINT.fullmatch(row[1])
            or not re.fullmatch(r"[1-9][0-9]*", row[2])
            or not NUMBER.fullmatch(row[3])
            or not NUMBER.fullmatch(row[4])
            or not UINT.fullmatch(row[5])
            or not re.fullmatch(r"[0-9:-]+", row[6])
            or not re.fullmatch(r"[!-~]{1,15}", row[7])
        ):
            fail(f"invalid resource process sample at {process_path}:{number}")
        key = (row[0], row[1])
        if key not in host_positions:
            fail(f"orphan resource process sample at {process_path}:{number}")
        require_timestamp_epoch(row[0], int(row[1]), f"resource process sample at {process_path}:{number}")
        pid_key = (key, row[2])
        if pid_key in seen_pids:
            fail(f"duplicate resource process PID at {process_path}:{number}")
        seen_pids.add(pid_key)
        details[key].append(row)
        positions.append(host_positions[key])
    if positions != sorted(positions):
        fail(f"resource process sample chronology is invalid: {attempt}")

    for row in host_rows:
        key = (row[0], row[1])
        sample_details = details[key]
        process_count = len(sample_details)
        total_rss = sum(int(detail[5]) for detail in sample_details)
        if row[7] != str(process_count) or row[8] != str(total_rss):
            fail(f"resource process aggregates differ from host sample: {attempt} key={key}")


def directory_entities(root: Path, kind: str) -> set[str]:
    if not root.exists():
        return set()
    if not root.is_dir() or root.is_symlink():
        fail(f"{kind} root is not a real directory: {root}")
    entities: set[str] = set()
    for path in inventoried_children(root):
        if not path.is_dir() or path.is_symlink():
            fail(f"unexpected non-directory {kind} entity: {path}")
        entities.add(path.name)
    return entities


def attempt_entities(root: Path, kind: str) -> list[Path]:
    children = list(inventoried_children(root))
    if (
        len(children) != 1
        or children[0].name != "attempts"
        or not children[0].is_dir()
        or children[0].is_symlink()
    ):
        fail(f"noncanonical {kind} entity structure: {root}")
    attempts = sorted(inventoried_children(children[0]))
    for attempt in attempts:
        if (
            not attempt.is_dir()
            or attempt.is_symlink()
            or not re.fullmatch(r"attempt\.[A-Za-z0-9]+", attempt.name)
        ):
            fail(f"unexpected {kind} attempt entity: {attempt}")
    return attempts


def verify_completion(
    root: Path, target_count: int | None = None, *, soak_evidence_schema: str | None = None
) -> None:
    marker = env_file(root / "campaign-completed.env")
    expected_keys = (
        {"status", "completed_utc", "target_count", "summary_sha256", "artifact_manifest_sha256"}
        if target_count is not None
        else {"completed_utc", "completed_epoch_seconds", "deadline_epoch_seconds", "summary_sha256", "artifact_manifest_sha256"}
    )
    # Schema 1 is an explicit migration label for authenticated historical soak
    # evidence that predates the status key. Absence of a schema never proves
    # that a tree is legacy. New evidence must say `passed`; cross-boot
    # diagnostic markers are retained but deliberately rejected here.
    if target_count is None:
        if soak_evidence_schema == "2" and set(marker) == expected_keys | {"status", "evidence_schema"}:
            if marker["evidence_schema"] != "2" or marker["status"] != "passed":
                fail(f"soak completion is not release-eligible: {root}")
        elif soak_evidence_schema == "1" and set(marker) == expected_keys | {"evidence_schema"}:
            if marker["evidence_schema"] != "1":
                fail(f"legacy soak completion schema mismatch: {root}")
        else:
            fail(f"unexpected completion marker keys: {root}")
    elif set(marker) != expected_keys:
        fail(f"unexpected completion marker keys: {root}")
    if not TIMESTAMP.fullmatch(marker["completed_utc"]):
        fail(f"invalid completion timestamp: {root}")
    summary = root / ("campaign-summary.tsv" if target_count is not None else "soak-summary.env")
    if not SHA.fullmatch(marker["summary_sha256"]) or sha256(summary) != marker["summary_sha256"]:
        fail(f"completion summary hash mismatch: {root}")
    manifest = root / "artifact-manifest.sha256"
    if not SHA.fullmatch(marker["artifact_manifest_sha256"]) or sha256(manifest) != marker["artifact_manifest_sha256"]:
        fail(f"completion manifest hash mismatch: {root}")
    if target_count is not None:
        if marker["status"] != "passed" or marker["target_count"] != str(target_count):
            fail(f"fuzz completion marker does not claim exact success: {root}")
    else:
        for key in ("completed_epoch_seconds", "deadline_epoch_seconds"):
            if not UINT.fullmatch(marker[key]):
                fail(f"invalid completion epoch: {root}")
        require_timestamp_epoch(marker["completed_utc"], int(marker["completed_epoch_seconds"]), f"soak completion at {root}")
    verify_manifest(root)


def verify_fuzz_attempt(
    evidence: Path,
    expected_commit: str,
    expected_target: str,
    expected_duration: int,
    expected_toolchain: str,
    expected_sanitizer: str,
    expected_cargo_sha256: str,
    expected_rustc_sha256: str,
    expected_cargo_fuzz_sha256: str,
) -> tuple[int, int]:
    config = env_file(evidence / "config.txt")
    if config.get("source_commit") != expected_commit or config.get("source_clean") != "1":
        fail(f"fuzz source provenance mismatch: {evidence}")
    if config.get("duration_seconds") != str(expected_duration) or config.get("targets") != expected_target:
        fail(f"fuzz configuration differs from authenticated target plan: {evidence}")
    if config.get("cargo_toolchain") != expected_toolchain:
        fail(f"fuzz toolchain differs from authenticated plan: {evidence}")
    if config.get("sanitizer") != expected_sanitizer:
        fail(f"fuzz sanitizer differs from authenticated plan: {evidence}")
    for key, expected in (
        ("cargo_sha256", expected_cargo_sha256),
        ("cargo_executed_sha256", expected_cargo_sha256),
        ("rustc_sha256", expected_rustc_sha256),
        ("rustc_executed_sha256", expected_rustc_sha256),
        ("cargo_fuzz_sha256", expected_cargo_fuzz_sha256),
        ("cargo_fuzz_executed_sha256", expected_cargo_fuzz_sha256),
    ):
        if not SHA.fullmatch(expected) or config.get(key) != expected:
            fail(f"fuzz {key} differs from authenticated plan: {evidence}")
    runtime_tree_sha256 = config.get("rustc_runtime_tree_sha256")
    if not SHA.fullmatch(runtime_tree_sha256 or ""):
        fail(f"fuzz rustc runtime tree digest is invalid: {evidence}")
    if config.get("dry_run") != "0":
        fail(f"dry-run fuzz evidence cannot satisfy an authenticated campaign: {evidence}")
    summary_rows = rows(
        evidence / "campaign-summary.tsv",
        FUZZ_SUMMARY_HEADER,
    )
    if len(summary_rows) != 1:
        fail(f"remote target attempt must have one summary row: {evidence}")
    target, status, exit_status, duration, started, ended, elapsed_ns, log, artifact, command = summary_rows[0]
    if target != expected_target:
        fail(f"fuzz target identity mismatch: expected={expected_target} actual={target}")
    if status != "passed" or exit_status != "0" or duration != str(expected_duration):
        fail(f"remote target summary is not successful: {evidence}")
    if (
        not UINT.fullmatch(started)
        or not UINT.fullmatch(ended)
        or not UINT.fullmatch(elapsed_ns)
        or int(ended) < int(started)
    ):
        fail(f"remote target execution window is invalid: {evidence}")
    minimum_elapsed = expected_duration * 1_000_000_000 - FUZZ_ELAPSED_TOLERANCE_NANOSECONDS
    elapsed_ns_value = int(elapsed_ns)
    wall_seconds = int(ended) - int(started)
    minimum_wall_seconds = max(1, expected_duration - 1)
    if wall_seconds < minimum_wall_seconds:
        fail(f"remote target wall-clock window was shorter than its authenticated duration: {evidence}")
    if elapsed_ns_value < minimum_elapsed:
        fail(f"remote target execution was shorter than its authenticated duration: {evidence}")
    wall_nanoseconds = wall_seconds * 1_000_000_000
    if (
        elapsed_ns_value + FUZZ_WALL_MONOTONIC_TOLERANCE_NANOSECONDS < wall_nanoseconds
        or elapsed_ns_value > wall_nanoseconds + FUZZ_WALL_MONOTONIC_TOLERANCE_NANOSECONDS
    ):
        fail(f"remote target wall and monotonic execution windows are inconsistent: {evidence}")
    expected = (f"logs/{target}.log", f"artifacts/{target}", f"logs/{target}.command")
    if (log, artifact, command) != expected:
        fail(f"noncanonical fuzz summary paths: {evidence}")
    if not relative_path(evidence, log, "fuzz log").is_file():
        fail(f"missing fuzz log: {evidence}")
    if not relative_path(evidence, artifact, "fuzz artifact").is_dir():
        fail(f"missing fuzz artifact directory: {evidence}")
    if not relative_path(evidence, command, "fuzz command").is_file():
        fail(f"missing fuzz command: {evidence}")
    verify_completion(evidence, 1)
    return int(started), int(ended)


def fuzz_attempt_has_execution_evidence(attempt: Path) -> bool:
    """Distinguish a setup-only attempt from one that started target execution."""
    evidence = attempt / "evidence"
    if not evidence.exists():
        return False
    if not evidence.is_dir() or evidence.is_symlink():
        fail(f"fuzz attempt evidence is not a real directory: {attempt}")

    summary = evidence / "campaign-summary.tsv"
    if summary.exists() and rows(summary, FUZZ_SUMMARY_HEADER):
        return True

    logs = evidence / "logs"
    if logs.exists():
        if not logs.is_dir() or logs.is_symlink():
            fail(f"fuzz attempt logs are not a real directory: {attempt}")
        if any(path.is_file() and path.name.endswith(".log") for path in inventoried_descendants(logs)):
            return True

    artifacts = evidence / "artifacts"
    if artifacts.exists():
        if not artifacts.is_dir() or artifacts.is_symlink():
            fail(f"fuzz attempt artifacts are not a real directory: {attempt}")
        if any(path.is_file() for path in inventoried_descendants(artifacts)):
            return True

    execution_names = re.compile(r"(?:crash|timeout|sanitizer|oom|leak)", re.IGNORECASE)
    return any(path.is_file() and execution_names.search(path.name) for path in inventoried_descendants(evidence))


def timestamp_epoch(value: str, label: str) -> int:
    if not TIMESTAMP.fullmatch(value):
        fail(f"invalid timestamp for {label}: {value}")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"invalid timestamp for {label}: {value}")
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


def require_timestamp_epoch(value: str, epoch: int, label: str) -> None:
    if abs(timestamp_epoch(value, label) - epoch) > 1:
        fail(f"{label} timestamp and epoch differ")


def verify_sampler(
    attempt: Path,
    expected_commit: str,
    expected_duration: int,
    expected_interval: int,
    expected_deadline: int,
    expected_units: list[str],
    target_windows: list[tuple[int, int]],
) -> str:
    provenance = env_file(
        attempt / "sampler.env",
        {
            "source_commit",
            "source_clean",
            "sample_interval_seconds",
            "deadline_epoch_seconds",
            "started_utc",
            "started_epoch_seconds",
        },
    )
    if provenance["source_commit"] != expected_commit or provenance["source_clean"] != "1":
        fail(f"sampler source provenance mismatch: {attempt}")
    if provenance["sample_interval_seconds"] != str(expected_interval):
        fail(f"sampler interval differs from authenticated plan: {attempt}")
    if provenance["deadline_epoch_seconds"] != str(expected_deadline):
        fail(f"sampler deadline differs from authenticated plan: {attempt}")
    if not UINT.fullmatch(provenance["started_epoch_seconds"]):
        fail(f"invalid sampler start epoch: {attempt}")
    started_epoch = int(provenance["started_epoch_seconds"])
    if abs(timestamp_epoch(provenance["started_utc"], "sampler start") - started_epoch) > 1:
        fail(f"sampler start timestamp and epoch differ: {attempt}")
    if started_epoch > expected_deadline - expected_duration + 2:
        fail(f"sampler started after authenticated campaign coverage window: {attempt}")
    units_file = attempt / "fuzz-units.txt"
    if not units_file.is_file() or units_file.is_symlink():
        fail(f"sampler unit allowlist is missing: {attempt}")
    units = text_lines(units_file)
    if (
        not units
        or any(not FUZZ_UNIT.fullmatch(unit) for unit in units)
        or len(set(units)) != len(units)
        or units != expected_units
    ):
        fail(f"sampler unit allowlist differs from exact authenticated assignment set: {attempt}")
    terminal_deadline = (
        expected_deadline
        + len(units) * FUZZ_SAMPLER_PROBE_BUDGET_SECONDS
        + FUZZ_SAMPLER_TERMINAL_OVERHEAD_SECONDS
    )
    marker = attempt / "sampler-completed.env"
    hard_stop = attempt / "sampler-hard-stop.env"
    if marker.exists() and hard_stop.exists():
        fail(f"sampler has conflicting terminal markers: {attempt}")
    if hard_stop.exists():
        values = env_file(hard_stop)
        if set(values) not in (
            {"sampler_hard_stop_utc", "active_units"},
            {"sampler_hard_stop_utc", "active_units", "probe_deadline_exhausted"},
            {"sampler_hard_stop_utc", "active_units", "probe_failed"},
        ):
            fail(f"invalid sampler hard-stop schema: {attempt}")
        if not TIMESTAMP.fullmatch(values["sampler_hard_stop_utc"]) or not UINT.fullmatch(values["active_units"]):
            fail(f"invalid sampler hard-stop values: {attempt}")
        if int(values["active_units"]) > len(units):
            fail(f"sampler hard-stop active-unit count exceeds its allowlist: {attempt}")
        if "probe_deadline_exhausted" in values:
            if values["probe_deadline_exhausted"] != "1":
                fail(f"invalid sampler probe-deadline marker: {attempt}")
        elif "probe_failed" in values:
            if values["probe_failed"] != "1":
                fail(f"invalid sampler probe-failure marker: {attempt}")
        elif int(values["active_units"]) == 0:
            fail(f"sampler hard-stop without probe exhaustion requires active units: {attempt}")
        hard_stop_epoch = timestamp_epoch(values["sampler_hard_stop_utc"], "sampler hard stop")
        if not started_epoch <= hard_stop_epoch <= terminal_deadline:
            fail(f"sampler hard-stop falls outside authenticated terminal window: {attempt}")

        # A probe can fail before the first completed sample, so header-only
        # TSVs are legitimate hard-stop evidence. If either sampler TSV was
        # published, however, both must be present and every published row must
        # obey the same schema and chronology as successful sampler evidence.
        host_samples = attempt / "host-samples.tsv"
        process_samples = attempt / "process-samples.tsv"
        if host_samples.exists() or process_samples.exists():
            sample_rows = rows(
                host_samples,
                ["timestamp_utc", "epoch_seconds", "active_units", "fuzz_processes", "total_fuzz_pcpu", "total_fuzz_rss_kib", "load1", "load5", "load15", "mem_available_kib"],
            )
            epochs: list[int] = []
            for number, row in enumerate(sample_rows, 2):
                if not TIMESTAMP.fullmatch(row[0]) or not all(UINT.fullmatch(row[index]) for index in (1, 2, 3, 5, 9)) or not all(NUMBER.fullmatch(row[index]) for index in (4, 6, 7, 8)):
                    fail(f"invalid sampler data at {host_samples}:{number}")
                epoch = int(row[1])
                if abs(timestamp_epoch(row[0], "sampler hard-stop row") - epoch) > 1:
                    fail(f"sampler row timestamp and epoch differ at {host_samples}:{number}")
                epochs.append(epoch)
            if epochs:
                if epochs != sorted(set(epochs)) or not started_epoch - 1 <= epochs[0] <= started_epoch + 2:
                    fail(f"sampler hard-stop epoch sequence is invalid: {attempt}")
                max_gap = expected_interval + len(units) * 10 + 2
                if any(right - left > max_gap for left, right in zip(epochs, epochs[1:])):
                    fail(f"sampler hard-stop cadence gap exceeds authenticated bound: {attempt}")
                if epochs[-1] > hard_stop_epoch + 1:
                    fail(f"sampler samples extend beyond hard-stop marker: {attempt}")
            process_rows = rows(
                process_samples,
                ["timestamp_utc", "epoch_seconds", "pid", "pcpu", "pmem", "rss_kib", "etime", "comm"],
            )
            verify_fuzz_process_details(attempt, sample_rows, process_rows, len(units))
        return "hard-stopped"
    values = env_file(
        marker,
        {
            "status",
            "completed_utc",
            "completed_epoch_seconds",
            "active_units",
            "deadline_epoch_seconds",
            "last_sample_epoch_seconds",
        },
    )
    if (
        values["status"] != "passed"
        or values["active_units"] != "0"
        or values["deadline_epoch_seconds"] != str(expected_deadline)
        or not UINT.fullmatch(values["completed_epoch_seconds"])
        or not UINT.fullmatch(values["last_sample_epoch_seconds"])
    ):
        fail(f"invalid sampler completion marker: {attempt}")
    completed_epoch = int(values["completed_epoch_seconds"])
    if abs(timestamp_epoch(values["completed_utc"], "sampler completion") - completed_epoch) > 1:
        fail(f"sampler completion timestamp and epoch differ: {attempt}")
    if not expected_deadline <= completed_epoch <= terminal_deadline:
        fail(f"sampler completion falls outside authenticated terminal window: {attempt}")
    sample_rows = rows(
        attempt / "host-samples.tsv",
        ["timestamp_utc", "epoch_seconds", "active_units", "fuzz_processes", "total_fuzz_pcpu", "total_fuzz_rss_kib", "load1", "load5", "load15", "mem_available_kib"],
    )
    if not sample_rows:
        fail(f"sampler has no data rows: {attempt}")
    epochs: list[int] = []
    for number, row in enumerate(sample_rows, 2):
        if not TIMESTAMP.fullmatch(row[0]) or not all(UINT.fullmatch(row[index]) for index in (1, 2, 3, 5, 9)) or not all(NUMBER.fullmatch(row[index]) for index in (4, 6, 7, 8)):
            fail(f"invalid sampler data at {attempt / 'host-samples.tsv'}:{number}")
        epoch = int(row[1])
        if abs(timestamp_epoch(row[0], "sampler row") - epoch) > 1:
            fail(f"sampler row timestamp and epoch differ at {attempt / 'host-samples.tsv'}:{number}")
        epochs.append(epoch)
    if epochs != sorted(set(epochs)) or not started_epoch - 1 <= epochs[0] <= started_epoch + 2:
        fail(f"sampler epoch sequence is invalid: {attempt}")
    max_gap = expected_interval + len(units) * 10 + 2
    if any(right - left > max_gap for left, right in zip(epochs, epochs[1:])):
        fail(f"sampler cadence gap exceeds authenticated bound: {attempt}")
    if sample_rows[-1][2] != "0":
        fail(f"sampler terminal row is not inactive: {attempt}")
    if (
        not expected_deadline <= epochs[-1] <= terminal_deadline
        or values["last_sample_epoch_seconds"] != str(epochs[-1])
        or completed_epoch < epochs[-1]
    ):
        fail(f"sampler terminal sample does not cover authenticated deadline: {attempt}")
    for target_start, target_end in target_windows:
        if target_start > expected_deadline or target_end > expected_deadline:
            fail(f"fuzz target execution extends past authenticated sampler deadline: {attempt}")
        if epochs[0] > target_start or epochs[-1] < target_end:
            fail(f"sampler does not cover an authenticated fuzz target execution window: {attempt}")
    process_rows = rows(
        attempt / "process-samples.tsv",
        ["timestamp_utc", "epoch_seconds", "pid", "pcpu", "pmem", "rss_kib", "etime", "comm"],
    )
    verify_fuzz_process_details(attempt, sample_rows, process_rows, len(units))
    return "complete"


def fuzz_host(
    root: Path,
    expected_commit: str,
    expected_targets: list[str],
    expected_sampler: str | None,
    expected_duration: int,
    expected_toolchain: str,
    expected_sanitizer: str,
    expected_cargo_sha256: str,
    expected_rustc_sha256: str,
    expected_cargo_fuzz_sha256: str,
    expected_sampler_interval: int | None,
    expected_sampler_deadline: int | None,
    expected_sampler_units: list[str],
) -> str:
    classifications: list[str] = []
    target_windows: list[tuple[int, int]] = []
    expected_target_set = set(expected_targets)
    if len(expected_target_set) != len(expected_targets):
        fail("duplicate expected fuzz target instance")
    root_entities = directory_entities(root, "fuzz-host collection")
    allowed_root_entities = {"fuzz", "host"}
    if not root_entities.issubset(allowed_root_entities):
        fail(
            "unexpected fuzz-host collection entities: "
            f"{sorted(root_entities - allowed_root_entities)}"
        )
    actual_targets = directory_entities(root / "fuzz", "fuzz target")
    if actual_targets - expected_target_set:
        fail(
            "fuzz target entity mismatch "
            f"extra={sorted(actual_targets - expected_target_set)}"
        )
    for target_name in expected_targets:
        target_root = root / "fuzz" / target_name
        if target_name not in actual_targets:
            classifications.append(f"target\t{target_name}\tnone\tincomplete")
            continue
        completed = 0
        complete_attempt = "none"
        failed_attempt = "none"
        latest_attempt = "none"
        for attempt in attempt_entities(target_root, "fuzz target"):
            latest_attempt = attempt.name
            evidence = attempt / "evidence"
            if (evidence / "campaign-completed.env").exists():
                prefix, separator, expected_target = target_name.partition("-")
                if not separator or not prefix.isdigit() or not expected_target:
                    fail(f"noncanonical expected fuzz instance: {target_name}")
                target_window = verify_fuzz_attempt(
                    evidence,
                    expected_commit,
                    expected_target,
                    expected_duration,
                    expected_toolchain,
                    expected_sanitizer,
                    expected_cargo_sha256,
                    expected_rustc_sha256,
                    expected_cargo_fuzz_sha256,
                )
                target_windows.append(target_window)
                completed += 1
                complete_attempt = attempt.name
            elif fuzz_attempt_has_execution_evidence(attempt):
                failed_attempt = attempt.name
        if completed > 1:
            fail(f"multiple complete attempts for {target_root}")
        if failed_attempt != "none":
            classification = "failed"
            reported_attempt = failed_attempt
        elif completed == 1:
            classification = "complete"
            reported_attempt = complete_attempt
        else:
            classification = "incomplete"
            reported_attempt = latest_attempt
        classifications.append(
            f"target\t{target_root.name}\t{reported_attempt}\t{classification}"
        )
    actual_samplers = directory_entities(root / "host", "fuzz sampler")
    expected_samplers = set() if expected_sampler is None else {expected_sampler}
    if actual_samplers - expected_samplers:
        fail(
            "fuzz sampler entity mismatch "
            f"extra={sorted(actual_samplers - expected_samplers)}"
        )
    for sampler_name in sorted(expected_samplers):
        host_root = root / "host" / sampler_name
        if sampler_name not in actual_samplers:
            classifications.append(f"sampler\t{sampler_name}\tnone\tincomplete")
            continue
        completed = 0
        terminal = 0
        terminal_attempt = "none"
        latest_attempt = "none"
        for attempt in attempt_entities(host_root, "fuzz sampler"):
            latest_attempt = attempt.name
            if (attempt / "sampler-completed.env").exists() or (attempt / "sampler-hard-stop.env").exists():
                if expected_sampler_interval is None or expected_sampler_deadline is None:
                    fail("sampler validation lacks authenticated schedule")
                classification = verify_sampler(
                    attempt,
                    expected_commit,
                    expected_duration,
                    expected_sampler_interval,
                    expected_sampler_deadline,
                    expected_sampler_units,
                    target_windows,
                )
                terminal += 1
                completed += classification == "complete"
                terminal_attempt = attempt.name
        if completed > 1 or terminal > 1:
            fail(f"multiple terminal sampler attempts for {host_root}")
        classification = "complete" if completed == 1 else "incomplete"
        classifications.append(
            f"sampler\t{host_root.name}\t{terminal_attempt if terminal else latest_attempt}\t{classification}"
        )
    print("kind\tentity\tattempt\tclassification")
    print("\n".join(classifications))
    return "complete" if classifications and all(line.endswith("\tcomplete") for line in classifications) else "incomplete"


def verify_soak_results(
    root: Path,
    expected_scenarios: list[str],
    campaign_start: int,
    campaign_deadline: int,
    post_deadline_allowance: int,
    maximum_attempt_elapsed: int,
) -> tuple[bool, int, int | None]:
    metadata = env_file(root / "soak.env")
    evidence_schema = metadata.get("evidence_schema")
    if evidence_schema not in {"1", "2"}:
        fail(f"unsupported soak evidence schema: {root}")
    scenarios_in_metadata = metadata.get("scenarios", "").split()
    if scenarios_in_metadata != expected_scenarios:
        fail(f"soak scenario order differs from authenticated plan: {root}")
    scenarios = set(expected_scenarios)
    if len(scenarios) != len(expected_scenarios):
        fail("authenticated soak scenario list contains duplicates")
    result_rows = rows(
        root / "scenario-results.tsv",
        ["cycle", "scenario", "attempt", "status", "exit_status", "started_utc", "ended_utc", "scenario_artifact_dir", "log_path"],
    )
    expected_cycle = 1
    expected_index = 0
    expected_attempt = 1
    unresolved_failure = False
    complete_cycles = 0
    ledger_attempts: set[str] = set()
    previous_ended_epoch: int | None = None
    for number, row in enumerate(result_rows, 2):
        cycle, scenario, attempt, status, exit_status, started, ended, artifact, log = row
        if not UINT.fullmatch(cycle) or int(cycle) != expected_cycle or scenario not in scenarios:
            fail(f"invalid soak result identity at row {number}")
        if scenario != expected_scenarios[expected_index]:
            fail(f"soak scenario order drift at row {number}")
        if not UINT.fullmatch(attempt) or int(attempt) != expected_attempt:
            fail(f"soak attempt sequence drift at row {number}")
        if status not in {"passed", "skipped", "failed", "interrupted"} or not UINT.fullmatch(exit_status) or int(exit_status) > 255:
            fail(f"invalid soak result status at row {number}")
        if status in {"passed", "skipped"} and exit_status != "0":
            fail(f"inconsistent soak result status at row {number}")
        if status in {"failed", "interrupted"} and exit_status == "0":
            fail(f"inconsistent soak failure status at row {number}")
        started_epoch = timestamp_epoch(started, f"soak result start at row {number}")
        ended_epoch = timestamp_epoch(ended, f"soak result end at row {number}")
        if ended_epoch < started_epoch:
            fail(f"soak result ends before it starts at row {number}")
        if ended_epoch - started_epoch > maximum_attempt_elapsed:
            fail(f"soak result exceeds the authenticated per-attempt runtime bound at row {number}")
        if not campaign_start <= started_epoch < campaign_deadline:
            fail(f"soak result starts outside the authenticated campaign window at row {number}")
        if ended_epoch > campaign_deadline + post_deadline_allowance:
            fail(f"soak result ends beyond the authenticated post-deadline allowance at row {number}")
        if previous_ended_epoch is not None and started_epoch < previous_ended_epoch:
            fail(f"soak result chronology reverses at row {number}")
        previous_ended_epoch = ended_epoch
        expected_dir = f"scenarios/cycle-{int(cycle):04d}/{scenario}/attempts/attempt-{int(attempt):04d}"
        if artifact != expected_dir or log != f"{expected_dir}/scenario.log":
            fail(f"noncanonical soak result paths at row {number}")
        if not relative_path(root, artifact, "soak artifact").is_dir() or not relative_path(root, log, "soak log").is_file():
            fail(f"missing soak result evidence at row {number}")
        started_metadata = env_file(
            relative_path(root, f"{artifact}/attempt-started.env", "soak attempt start metadata"),
            {"cycle", "scenario", "attempt", "started_utc"},
        )
        if started_metadata != {
            "cycle": cycle,
            "scenario": scenario,
            "attempt": attempt,
            "started_utc": started,
        }:
            fail(f"soak attempt metadata differs from its result row at row {number}")
        ledger_attempts.add(artifact)
        unresolved_failure = status in {"failed", "interrupted"}
        expected_attempt += 1
        if status in {"passed", "skipped"}:
            unresolved_failure = False
            expected_attempt = 1
            expected_index += 1
            if expected_index == len(expected_scenarios):
                complete_cycles += 1
                expected_cycle += 1
                expected_index = 0
    actual_attempts: set[str] = set()
    scenarios_root = root / "scenarios"
    if scenarios_root.exists():
        for attempt_root in (
            path for path in inventoried_descendants(scenarios_root) if path.name == "attempts"
        ):
            if not attempt_root.is_dir() or attempt_root.is_symlink():
                fail(f"unsafe soak attempt root: {attempt_root}")
            for attempt_dir in inventoried_children(attempt_root):
                if not attempt_dir.is_dir() or attempt_dir.is_symlink() or not re.fullmatch(
                    r"attempt-[0-9]{4}", attempt_dir.name
                ):
                    fail(f"unexpected soak attempt entity: {attempt_dir}")
                actual_attempts.add(attempt_dir.relative_to(root).as_posix())
    if actual_attempts != ledger_attempts:
        fail(
            "soak attempt directory and result ledger mismatch "
            f"unledgered={sorted(actual_attempts - ledger_attempts)[:3]} "
            f"missing={sorted(ledger_attempts - actual_attempts)[:3]}"
        )
    return unresolved_failure, complete_cycles, previous_ended_epoch


def verify_soak_sampler(root: Path, start: int, deadline: int, interval: int) -> None:
    attempt_root = root / "resource-sampler-attempts"
    if not attempt_root.is_dir() or attempt_root.is_symlink():
        fail(f"completed soak lacks a real resource sampler attempt root: {root}")
    attempts = sorted(inventoried_children(attempt_root))
    for number, attempt in enumerate(attempts, 1):
        if not attempt.is_dir() or attempt.is_symlink() or attempt.name != f"attempt-{number:04d}":
            fail(f"unexpected resource sampler attempt entity: {attempt}")
    if not attempts:
        fail(f"completed soak lacks resource sampler attempts: {root}")
    previous_last: int | None = None
    previous_terminal: int | None = None
    completed = 0
    for number, attempt in enumerate(attempts, 1):
        metadata = env_file(
            attempt / "resource-sampler.env",
            {"started_utc", "started_epoch_seconds", "deadline_epoch_seconds", "sample_interval_seconds"},
        )
        if not TIMESTAMP.fullmatch(metadata["started_utc"]) or not UINT.fullmatch(metadata["started_epoch_seconds"]):
            fail(f"invalid resource sampler provenance: {attempt}")
        attempt_start = int(metadata["started_epoch_seconds"])
        require_timestamp_epoch(metadata["started_utc"], attempt_start, f"resource sampler start at {attempt}")
        if metadata["deadline_epoch_seconds"] != str(deadline) or metadata["sample_interval_seconds"] != str(interval):
            fail(f"resource sampler policy mismatch: {attempt}")
        sample_rows = rows(
            attempt / "resource-samples.tsv",
            ["timestamp_utc", "epoch_seconds", "load1", "load5", "load15", "mem_available_kib", "docker_containers", "oxidedns_processes", "total_oxidedns_rss_kib"],
        )
        if not sample_rows:
            fail(f"resource sampler attempt has no samples: {attempt}")
        epochs: list[int] = []
        for row_number, row in enumerate(sample_rows, 2):
            if not TIMESTAMP.fullmatch(row[0]) or not all(UINT.fullmatch(row[index]) for index in (1, 5, 6, 7, 8)) or not all(NUMBER.fullmatch(row[index]) for index in (2, 3, 4)):
                fail(f"invalid resource sample at {attempt / 'resource-samples.tsv'}:{row_number}")
            epoch = int(row[1])
            require_timestamp_epoch(row[0], epoch, f"resource sample at {attempt / 'resource-samples.tsv'}:{row_number}")
            epochs.append(epoch)
        if epochs != sorted(set(epochs)) or not attempt_start <= epochs[0] <= attempt_start + 2:
            fail(f"resource sampler start coverage mismatch: {attempt}")
        if any(right - left > interval + 2 for left, right in zip(epochs, epochs[1:])):
            fail(f"resource sampler cadence gap: {attempt}")
        if previous_last is None:
            if not start <= attempt_start <= start + 2:
                fail(f"resource sampler did not start at the campaign boundary: {attempt}")
        else:
            if previous_terminal is None or attempt_start < previous_terminal:
                fail(f"resource sampler attempt chronology reverses: {attempt}")
            if attempt_start - previous_last > interval + 2:
                fail(f"resource sampler attempts leave an unobserved gap: {attempt}")
        process_rows = rows(
            attempt / "process-samples.tsv",
            ["timestamp_utc", "epoch_seconds", "pid", "pcpu", "pmem", "rss_kib", "etime", "comm"],
        )
        verify_soak_process_details(attempt, sample_rows, process_rows)
        success = attempt / "resource-sampler-completed.env"
        failure = attempt / "resource-sampler-failed.env"
        if success.exists() == failure.exists():
            fail(f"resource sampler attempt has ambiguous terminal state: {attempt}")
        if success.exists():
            values = env_file(success, {"status", "completed_utc", "completed_epoch_seconds", "deadline_epoch_seconds", "last_sample_epoch_seconds"})
            if not UINT.fullmatch(values["completed_epoch_seconds"]):
                fail(f"invalid resource sampler completion epoch: {attempt}")
            completed_epoch = int(values["completed_epoch_seconds"])
            require_timestamp_epoch(values["completed_utc"], completed_epoch, f"resource sampler completion at {attempt}")
            if number != len(attempts) or values["status"] != "passed" or values["deadline_epoch_seconds"] != str(deadline) or values["last_sample_epoch_seconds"] != str(epochs[-1]) or epochs[-1] < deadline or completed_epoch < epochs[-1]:
                fail(f"resource sampler completion lacks deadline coverage: {attempt}")
            completed += 1
            terminal_epoch = completed_epoch
        else:
            values = env_file(failure, {"status", "failed_utc", "failed_epoch_seconds", "exit_status"})
            if values["status"] != "failed" or not UINT.fullmatch(values["exit_status"]) or int(values["exit_status"]) == 0:
                fail(f"invalid resource sampler failure marker: {attempt}")
            if not UINT.fullmatch(values["failed_epoch_seconds"]):
                fail(f"invalid resource sampler failure epoch: {attempt}")
            failed_epoch = int(values["failed_epoch_seconds"])
            require_timestamp_epoch(values["failed_utc"], failed_epoch, f"resource sampler failure at {attempt}")
            if failed_epoch < epochs[-1]:
                fail(f"resource sampler failure predates its final sample: {attempt}")
            terminal_epoch = failed_epoch
        previous_last = epochs[-1]
        previous_terminal = terminal_epoch
    if completed != 1:
        fail(f"completed soak lacks one final successful sampler attempt: {root}")


def soak_host(
    root: Path,
    expected_commit: str,
    expected_duration: int,
    expected_scenarios: list[str],
    expected_scenario_timeout: int,
    expected_scenario_kill_after: int,
    expected_docker_cleanup_timeout: int,
    expected_cycle_sleep: int,
    expected_sample_interval: int,
    expected_allow_skip: int,
    expected_cargo_sha256: str,
    expected_rustc_sha256: str,
) -> str:
    if not (root / "soak.env").exists():
        if inventoried_children(root):
            fail(f"nonempty soak evidence lacks provenance metadata: {root}")
        print("kind\tentity\tattempt\tclassification")
        print(f"soak\t{root.name}\tcurrent\tincomplete")
        return "incomplete"
    metadata = env_file(root / "soak.env")
    evidence_schema = metadata.get("evidence_schema")
    if evidence_schema not in {"1", "2"}:
        fail(f"unsupported soak evidence schema: {root}")
    if metadata.get("expected_commit") != expected_commit:
        fail(f"soak source provenance mismatch: {root}")
    if metadata.get("duration_seconds") != str(expected_duration):
        fail(f"soak duration differs from authenticated plan: {root}")
    if metadata.get("cargo_sha256") != expected_cargo_sha256:
        fail(f"soak cargo_sha256 differs from authenticated plan: {root}")
    if metadata.get("rustc_sha256") != expected_rustc_sha256:
        fail(f"soak rustc_sha256 differs from authenticated plan: {root}")
    expected_policy = {
        "scenario_timeout_seconds": str(expected_scenario_timeout),
        "scenario_kill_after_seconds": str(expected_scenario_kill_after),
        "docker_cleanup_timeout_seconds": str(expected_docker_cleanup_timeout),
        "cycle_sleep_seconds": str(expected_cycle_sleep),
        "sample_interval_seconds": str(expected_sample_interval),
        "allow_skip": str(expected_allow_skip),
    }
    for key, expected in expected_policy.items():
        if metadata.get(key) != expected:
            fail(f"soak {key} differs from authenticated plan: {root}")
    if metadata.get("scenarios", "").split() != expected_scenarios:
        fail(f"soak scenarios differ from authenticated plan: {root}")
    if len(set(expected_scenarios)) != len(expected_scenarios):
        fail("authenticated soak scenarios contain duplicates")
    start = metadata.get("start_epoch_seconds", "")
    deadline = metadata.get("deadline_epoch_seconds", "")
    if not UINT.fullmatch(start) or not UINT.fullmatch(deadline):
        fail(f"soak deadline metadata is invalid: {root}")
    if int(deadline) != int(start) + expected_duration:
        fail(f"soak deadline is not start plus authenticated duration: {root}")
    boot_keys = {"boot_id", "control_deadline_boottime_nanoseconds", "cross_boot_diagnostic"}
    if set(metadata) & boot_keys:
        if not boot_keys <= set(metadata):
            fail(f"soak boot-bound deadline metadata is incomplete: {root}")
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", metadata["boot_id"]):
            fail(f"soak boot ID is invalid: {root}")
        if not UINT.fullmatch(metadata["control_deadline_boottime_nanoseconds"]):
            fail(f"soak CLOCK_BOOTTIME deadline is invalid: {root}")
        if metadata["cross_boot_diagnostic"] != "0":
            fail(f"cross-boot diagnostic soak is not release evidence: {root}")
    resume_keys = {
        "created_utc",
        "repo_root",
        "cargo_target_dir",
        "duration_seconds",
        "start_epoch_seconds",
        "deadline_epoch_seconds",
        "scenario_timeout_seconds",
        "scenario_kill_after_seconds",
        "docker_cleanup_timeout_seconds",
        "cycle_sleep_seconds",
        "sample_interval_seconds",
        "allow_skip",
        "resume",
        "expected_commit",
        "cargo_sha256",
        "rustc_sha256",
        "scenarios",
    }
    if evidence_schema == "2":
        resume_keys.add("evidence_schema")
    resume_matches = {
        "duration_seconds",
        "start_epoch_seconds",
        "deadline_epoch_seconds",
        "scenario_timeout_seconds",
        "scenario_kill_after_seconds",
        "docker_cleanup_timeout_seconds",
        "cycle_sleep_seconds",
        "sample_interval_seconds",
        "allow_skip",
        "expected_commit",
        "cargo_sha256",
        "rustc_sha256",
        "scenarios",
    }
    if evidence_schema == "2":
        resume_matches.add("evidence_schema")
    for resume_path in sorted(
        path for path in inventoried_children(root) if path.match("soak-resume-*.env")
    ):
        match = re.fullmatch(r"soak-resume-([0-9]{8}T[0-9]{6}Z)\.env", resume_path.name)
        if match is None:
            fail(f"noncanonical soak resume metadata name: {resume_path}")
        resumed = env_file(resume_path)
        if frozenset(resumed) not in {frozenset(resume_keys), frozenset(resume_keys | boot_keys)}:
            fail(f"unexpected soak resume metadata keys: {resume_path}")
        if resumed["resume"] != "1":
            fail(f"soak resume metadata does not claim resume mode: {resume_path}")
        if boot_keys <= set(resumed):
            if resumed["cross_boot_diagnostic"] != "0":
                fail(f"cross-boot diagnostic resume is not release evidence: {resume_path}")
            for key in ("boot_id", "control_deadline_boottime_nanoseconds"):
                if resumed[key] != metadata.get(key):
                    fail(f"soak resume {key} differs from original campaign metadata: {resume_path}")
        for key in resume_matches:
            if resumed[key] != metadata.get(key):
                fail(f"soak resume {key} differs from original campaign metadata: {resume_path}")
        resume_epoch = timestamp_epoch(resumed["created_utc"], f"soak resume at {resume_path}")
        if not int(start) <= resume_epoch < int(deadline):
            fail(f"soak resume falls outside the authenticated campaign window: {resume_path}")
    unresolved_failure = False
    complete_cycles = 0
    last_scenario_ended_epoch: int | None = None
    post_deadline_allowance = (
        expected_scenario_kill_after
        + SOAK_DOCKER_CLEANUP_COMMANDS
        * (expected_docker_cleanup_timeout + SOAK_DOCKER_TIMEOUT_KILL_GRACE_SECONDS)
        + SOAK_TIMESTAMP_TOLERANCE_SECONDS
    )
    maximum_attempt_elapsed = expected_scenario_timeout + post_deadline_allowance
    if (root / "scenario-results.tsv").exists():
        unresolved_failure, complete_cycles, last_scenario_ended_epoch = verify_soak_results(
            root,
            expected_scenarios,
            int(start),
            int(deadline),
            post_deadline_allowance,
            maximum_attempt_elapsed,
        )
    elif any(path.name != "soak.env" for path in inventoried_children(root)):
        fail(f"partial soak evidence lacks scenario results: {root}")
    if (root / "campaign-completed.env").exists():
        if unresolved_failure:
            fail(f"completed soak evidence has an unresolved scenario attempt: {root}")
        if complete_cycles == 0:
            fail(f"completed soak evidence has no complete canonical scenario cycle: {root}")
        terminal_activity_max_gap = (
            expected_scenario_timeout
            + expected_scenario_kill_after
            + expected_cycle_sleep
            + SOAK_TIMESTAMP_TOLERANCE_SECONDS
        )
        if (
            last_scenario_ended_epoch is None
            or last_scenario_ended_epoch < int(deadline) - terminal_activity_max_gap
        ):
            fail(
                "completed soak terminal scenario activity gap exceeds authenticated policy: "
                f"{root} last_ended={last_scenario_ended_epoch} deadline={deadline} "
                f"maximum_gap={terminal_activity_max_gap}"
            )
        if expected_allow_skip == 0:
            result_rows = rows(
                root / "scenario-results.tsv",
                ["cycle", "scenario", "attempt", "status", "exit_status", "started_utc", "ended_utc", "scenario_artifact_dir", "log_path"],
            )
            if any(row[3] == "skipped" for row in result_rows):
                fail(f"fail-on-skip campaign contains skipped terminal evidence: {root}")
        verify_completion(root, soak_evidence_schema=evidence_schema)
        verify_soak_sampler(root, int(start), int(deadline), expected_sample_interval)
        completion = env_file(root / "campaign-completed.env")
        if completion.get("deadline_epoch_seconds") != deadline:
            fail(f"soak completion deadline differs from captured deadline: {root}")
        if int(completion.get("completed_epoch_seconds", "-1")) < int(deadline):
            fail(f"soak completion predates its deadline: {root}")
        classification = "complete"
    else:
        classification = "incomplete"
    print("kind\tentity\tattempt\tclassification")
    print(f"soak\t{root.name}\tcurrent\t{classification}")
    return classification


def main() -> None:
    global BUDGET
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("fuzz-host", "soak-host", "tree-snapshot"))
    parser.add_argument("root", type=Path)
    parser.add_argument("expected_commit", nargs="?")
    parser.add_argument("--absolute-deadline-nanoseconds", type=int)
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--expected-target", action="append", default=[])
    parser.add_argument("--expected-sampler")
    parser.add_argument("--no-sampler", action="store_true")
    parser.add_argument("--expected-duration", type=int)
    parser.add_argument("--expected-toolchain")
    parser.add_argument("--expected-sanitizer")
    parser.add_argument("--expected-cargo-sha256")
    parser.add_argument("--expected-rustc-sha256")
    parser.add_argument("--expected-cargo-fuzz-sha256")
    parser.add_argument("--expected-sampler-interval", type=int)
    parser.add_argument("--expected-sampler-deadline", type=int)
    parser.add_argument("--expected-sampler-unit", action="append", default=[])
    parser.add_argument("--expected-scenario-timeout", type=int)
    parser.add_argument("--expected-scenario-kill-after", type=int)
    parser.add_argument("--expected-docker-cleanup-timeout", type=int)
    parser.add_argument("--expected-cycle-sleep", type=int)
    parser.add_argument("--expected-sample-interval", type=int)
    parser.add_argument("--expected-allow-skip", type=int, choices=(0, 1))
    parser.add_argument("--expected-scenario", action="append", default=[])
    args = parser.parse_args()
    deadline = args.absolute_deadline_nanoseconds
    if deadline is None:
        deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + DEFAULT_COLLECTION_TIMEOUT_SECONDS * 1_000_000_000
    bounds = (
        (args.max_entries, HARD_MAX_ENTRIES, "entry"),
        (args.max_depth, HARD_MAX_DEPTH, "depth"),
        (args.max_file_bytes, HARD_MAX_FILE_BYTES, "per-file byte"),
        (args.max_total_bytes, HARD_MAX_TOTAL_BYTES, "total byte"),
    )
    if deadline <= time.clock_gettime_ns(time.CLOCK_BOOTTIME) or deadline > 9223372036854775807:
        fail("invalid or expired absolute collection deadline")
    for value, maximum, label in bounds:
        if value <= 0 or value > maximum:
            fail(f"invalid collection {label} bound: {value}")
    if args.max_file_bytes > args.max_total_bytes:
        fail("per-file collection bound exceeds total byte bound")
    BUDGET = ValidationBudget(
        deadline,
        args.max_entries,
        args.max_depth,
        args.max_file_bytes,
        args.max_total_bytes,
    )
    root = Path(os.path.abspath(args.root))
    if args.mode == "tree-snapshot":
        if args.expected_commit is not None:
            fail("tree snapshot does not accept an expected commit")
        print(regular_tree(root, snapshot=True))
        return
    if args.expected_commit is None:
        fail("campaign validation requires an expected commit")
    if not COMMIT.fullmatch(args.expected_commit):
        fail("invalid expected commit")
    regular_tree(root)
    if args.mode == "fuzz-host":
        if not args.expected_target:
            fail("fuzz validation requires expected target instances")
        if args.expected_duration is None or args.expected_duration <= 0:
            fail("fuzz validation requires a positive expected duration")
        if args.expected_toolchain is None or args.expected_sanitizer is None:
            fail("fuzz validation requires exact expected toolchain and sanitizer")
        if not all(
            value is not None and SHA.fullmatch(value)
            for value in (args.expected_cargo_sha256, args.expected_rustc_sha256, args.expected_cargo_fuzz_sha256)
        ):
            fail("fuzz validation requires exact authenticated tool binary digests")
        if args.no_sampler and args.expected_sampler is not None:
            fail("conflicting sampler expectations")
        if not args.no_sampler and args.expected_sampler is None:
            fail("fuzz validation requires --expected-sampler or --no-sampler")
        if args.no_sampler and (
            args.expected_sampler_interval is not None
            or args.expected_sampler_deadline is not None
            or args.expected_sampler_unit
        ):
            fail("sampler schedule was provided with --no-sampler")
        if args.expected_sampler is not None and (
            args.expected_sampler_interval is None
            or args.expected_sampler_interval <= 0
            or args.expected_sampler_deadline is None
            or args.expected_sampler_deadline <= args.expected_duration
        ):
            fail("fuzz sampler validation requires an authenticated interval and deadline")
        if args.expected_sampler is not None and (
            not args.expected_sampler_unit
            or len(set(args.expected_sampler_unit)) != len(args.expected_sampler_unit)
            or any(not FUZZ_UNIT.fullmatch(unit) for unit in args.expected_sampler_unit)
        ):
            fail("fuzz sampler validation requires exact unique canonical unit identities")
        classification = fuzz_host(
            root,
            args.expected_commit,
            args.expected_target,
            None if args.no_sampler else args.expected_sampler,
            args.expected_duration,
            args.expected_toolchain,
            args.expected_sanitizer,
            args.expected_cargo_sha256,
            args.expected_rustc_sha256,
            args.expected_cargo_fuzz_sha256,
            args.expected_sampler_interval,
            args.expected_sampler_deadline,
            args.expected_sampler_unit,
        )
    else:
        if args.expected_duration is None or args.expected_duration <= 0:
            fail("soak validation requires a positive expected duration")
        if not args.expected_scenario:
            fail("soak validation requires expected scenarios")
        required_positive = {
            "scenario timeout": args.expected_scenario_timeout,
            "scenario kill-after": args.expected_scenario_kill_after,
            "Docker cleanup timeout": args.expected_docker_cleanup_timeout,
            "cycle sleep": args.expected_cycle_sleep,
            "sample interval": args.expected_sample_interval,
        }
        if any(value is None or value <= 0 for value in required_positive.values()):
            fail("soak validation requires every positive authenticated timing parameter")
        if args.expected_allow_skip is None:
            fail("soak validation requires exact expected allow-skip policy")
        if not all(
            value is not None and SHA.fullmatch(value)
            for value in (args.expected_cargo_sha256, args.expected_rustc_sha256)
        ):
            fail("soak validation requires exact authenticated Rust tool digests")
        classification = soak_host(
            root,
            args.expected_commit,
            args.expected_duration,
            args.expected_scenario,
            args.expected_scenario_timeout,
            args.expected_scenario_kill_after,
            args.expected_docker_cleanup_timeout,
            args.expected_cycle_sleep,
            args.expected_sample_interval,
            args.expected_allow_skip,
            args.expected_cargo_sha256,
            args.expected_rustc_sha256,
        )
    print(f"collection_classification={classification}", file=sys.stderr)


if __name__ == "__main__":
    main()
