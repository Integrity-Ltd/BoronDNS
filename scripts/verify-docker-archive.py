#!/usr/bin/env python3
"""Verify a Docker save archive without relying on daemon-cached content."""

from __future__ import annotations

import hashlib
import json
import lzma
import pathlib
import os
import argparse
import fcntl
import select
import stat
import tempfile
import sys
import tarfile
import time
from typing import BinaryIO


DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 600
DEFAULT_MAX_MEMBERS = 100_000
MAX_MEMBERS = 100_000
DEFAULT_MAX_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
DEFAULT_MAX_RETAINED_JSON_BYTES = 64 * 1024 * 1024
MAX_RETAINED_JSON_BYTES = 64 * 1024 * 1024
MAX_SINGLE_RETAINED_JSON_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_COMPRESSED_BYTES = 16 * 1024 * 1024 * 1024
MAX_COMPRESSED_BYTES = 16 * 1024 * 1024 * 1024
DEFAULT_XZ_MEMORY_LIMIT_BYTES = 64 * 1024 * 1024
MAX_XZ_MEMORY_LIMIT_BYTES = 64 * 1024 * 1024
SIGNED_64_MAX = (1 << 63) - 1
EXTENDED_TAR_TYPES = (
    tarfile.GNUTYPE_LONGNAME,
    tarfile.GNUTYPE_LONGLINK,
    tarfile.GNUTYPE_SPARSE,
    tarfile.XHDTYPE,
    tarfile.XGLTYPE,
    tarfile.SOLARIS_XHDTYPE,
)


def fail(message: str) -> None:
    raise SystemExit(f"Docker archive verification failed: {message}")


def bounded_environment(name: str, default: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    if not raw.isascii() or not raw.isdigit() or raw.startswith("0"):
        fail(f"{name} must be a canonical positive integer")
    value = int(raw)
    if value > maximum or value > SIGNED_64_MAX:
        fail(f"{name} exceeds hard maximum {maximum}")
    return value


def collection_deadline() -> int:
    timeout = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_TIMEOUT_SECONDS",
        DEFAULT_TIMEOUT_SECONDS,
        MAX_TIMEOUT_SECONDS,
    )
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    derived = now + timeout * 1_000_000_000
    raw_absolute = os.environ.get("BORONDNS_DOCKER_ARCHIVE_DEADLINE_NS", "")
    if not raw_absolute:
        return derived
    if (
        not raw_absolute.isascii()
        or not raw_absolute.isdigit()
        or raw_absolute.startswith("0")
        or int(raw_absolute) > SIGNED_64_MAX
    ):
        fail("BORONDNS_DOCKER_ARCHIVE_DEADLINE_NS must be a signed-64 positive integer")
    # A caller may shorten the verifier's lifetime, never extend the hard cap.
    return min(derived, int(raw_absolute))


def require_before_deadline(deadline: int) -> None:
    if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= deadline:
        fail("absolute verification deadline expired")


def write_all_before_deadline(descriptor: int, payload: bytes, deadline: int) -> None:
    """Write without letting downstream backpressure escape the BOOTTIME cap."""
    original_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fcntl.fcntl(descriptor, fcntl.F_SETFL, original_flags | os.O_NONBLOCK)
    view = memoryview(payload)
    poller = select.poll()
    poller.register(descriptor, select.POLLOUT | select.POLLERR | select.POLLHUP)
    try:
        while view:
            require_before_deadline(deadline)
            try:
                written = os.write(descriptor, view)
            except BlockingIOError:
                remaining = deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                if remaining <= 0:
                    fail("absolute verification deadline expired while streaming verified bytes")
                events = poller.poll(max(1, min(1000, (remaining + 999_999) // 1_000_000)))
                if any(event & (select.POLLERR | select.POLLHUP) for _fd, event in events):
                    fail("verified archive output closed before streaming completed")
                continue
            except BrokenPipeError:
                fail("verified archive output closed before streaming completed")
            if written <= 0:
                fail("verified archive output write stalled")
            view = view[written:]
    finally:
        fcntl.fcntl(descriptor, fcntl.F_SETFL, original_flags)


class PreadXzReader:
    """Decode one descriptor-bound XZ stream with time, memory, and size caps."""

    def __init__(
        self,
        descriptor: int,
        compressed_size: int,
        deadline: int,
        memory_limit: int,
        expanded_stream_limit: int,
    ) -> None:
        self.descriptor = descriptor
        self.compressed_size = compressed_size
        self.deadline = deadline
        self.expanded_stream_limit = expanded_stream_limit
        self.compressed_offset = 0
        self.expanded_bytes = 0
        self.buffer = bytearray()
        self.eof = False
        self.decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_XZ, memlimit=memory_limit
        )

    def _compressed_chunk(self) -> bytes:
        require_before_deadline(self.deadline)
        chunk = os.pread(self.descriptor, 1024 * 1024, self.compressed_offset)
        require_before_deadline(self.deadline)
        self.compressed_offset += len(chunk)
        return chunk

    def _finish_stream(self) -> None:
        trailing = self.decoder.unused_data
        trailing_count = len(trailing)
        if any(trailing):
            fail("archive has non-padding data after its XZ stream")
        while self.compressed_offset < self.compressed_size:
            chunk = self._compressed_chunk()
            if not chunk:
                break
            trailing_count += len(chunk)
            if any(chunk):
                fail("archive has non-padding data after its XZ stream")
        if trailing_count % 4 != 0:
            fail("archive has invalid XZ stream padding")
        self.eof = True

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 1024 * 1024
        while len(self.buffer) < size and not self.eof:
            compressed = self._compressed_chunk() if self.decoder.needs_input else b""
            if not compressed and self.decoder.needs_input:
                fail("archive has a truncated XZ stream")
            try:
                expanded = self.decoder.decompress(
                    compressed, max_length=size - len(self.buffer)
                )
            except lzma.LZMAError as error:
                fail(f"XZ decompression failed within its memory limit: {error}")
            require_before_deadline(self.deadline)
            if self.expanded_bytes > self.expanded_stream_limit - len(expanded):
                fail(
                    "archive expanded tar stream exceeds hard bound "
                    f"{self.expanded_stream_limit}"
                )
            self.expanded_bytes += len(expanded)
            self.buffer.extend(expanded)
            if self.decoder.eof:
                self._finish_stream()
        payload = bytes(self.buffer[:size])
        del self.buffer[:size]
        return payload


def open_archive(path: str, max_compressed_bytes: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot safely open archive: {error}")
    archive_stat = os.fstat(descriptor)
    if (
        not stat.S_ISREG(archive_stat.st_mode)
        or archive_stat.st_uid != os.getuid()
        or archive_stat.st_nlink != 1
        or archive_stat.st_size <= 0
        or archive_stat.st_size > max_compressed_bytes
    ):
        os.close(descriptor)
        fail("archive must be one caller-owned, linked, bounded regular file")
    return descriptor, archive_stat


def stable_archive_identity(value: os.stat_result) -> tuple[int, ...]:
    """Return fields that identify the opened inode and detect content mutation.

    Access time is intentionally excluded: reading the archive may update it on
    relatime/strictatime filesystems without changing the inode or its content.
    Modification and change times remain part of the mutation boundary.
    """
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def stage_archive(
    source_fd: int, source_stat: os.stat_result, deadline: int
) -> BinaryIO:
    staged = tempfile.TemporaryFile(prefix="borondns-verified-docker-archive-")
    os.fchmod(staged.fileno(), 0)
    offset = 0
    try:
        while offset < source_stat.st_size:
            require_before_deadline(deadline)
            chunk = os.pread(source_fd, 1024 * 1024, offset)
            if not chunk:
                fail("archive changed size while staging private verification input")
            staged.write(chunk)
            offset += len(chunk)
            require_before_deadline(deadline)
        staged.flush()
        os.fsync(staged.fileno())
        if stable_archive_identity(os.fstat(source_fd)) != stable_archive_identity(
            source_stat
        ):
            fail("archive identity changed while staging private verification input")
        return staged
    except BaseException:
        staged.close()
        raise


def test_pause_after_stage(deadline: int) -> None:
    marker = os.environ.get("BORONDNS_DOCKER_ARCHIVE_TEST_STAGE_MARKER", "")
    continuation = os.environ.get("BORONDNS_DOCKER_ARCHIVE_TEST_CONTINUE", "")
    if not marker and not continuation:
        return
    if not marker or not continuation:
        fail("archive verifier stage test hook is incomplete")
    with open(marker, "x", encoding="ascii") as output:
        output.write(f"{os.getpid()}\n")
        output.flush()
        os.fsync(output.fileno())
    while not os.path.exists(continuation):
        require_before_deadline(deadline)
        time.sleep(0.01)


class BoundedTarInfo(tarfile.TarInfo):
    """Reject metadata records tarfile would otherwise expand before yielding."""

    deadline = 0
    max_member_bytes = 0

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        require_before_deadline(self.deadline)
        if self.type in EXTENDED_TAR_TYPES:
            fail("unsupported extended tar metadata record")
        if self.size < 0 or self.size > self.max_member_bytes:
            fail(f"archive member exceeds byte bound: {self.name}")
        return super()._proc_member(archive)


def canonical_member_name(name: str) -> str:
    path = pathlib.PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or str(path) != name:
        fail(f"non-canonical archive member: {name!r}")
    return name


def digest_from_blob_path(path: str) -> str | None:
    parts = pathlib.PurePosixPath(path).parts
    if len(parts) != 3 or parts[:2] != ("blobs", "sha256"):
        return None
    digest = parts[2]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        fail(f"invalid sha256 blob path: {path}")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stream-verified-archive", action="store_true")
    parser.add_argument("archive")
    arguments = parser.parse_args()
    archive_path = arguments.archive
    deadline = collection_deadline()
    max_members = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_MAX_MEMBERS", DEFAULT_MAX_MEMBERS, MAX_MEMBERS
    )
    max_member_bytes = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_MAX_MEMBER_BYTES",
        DEFAULT_MAX_MEMBER_BYTES,
        MAX_MEMBER_BYTES,
    )
    max_total_bytes = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_MAX_TOTAL_BYTES",
        DEFAULT_MAX_TOTAL_BYTES,
        MAX_TOTAL_BYTES,
    )
    max_retained_json_bytes = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_MAX_RETAINED_JSON_BYTES",
        DEFAULT_MAX_RETAINED_JSON_BYTES,
        MAX_RETAINED_JSON_BYTES,
    )
    max_compressed_bytes = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_MAX_COMPRESSED_BYTES",
        DEFAULT_MAX_COMPRESSED_BYTES,
        MAX_COMPRESSED_BYTES,
    )
    xz_memory_limit = bounded_environment(
        "BORONDNS_DOCKER_ARCHIVE_XZ_MEMORY_LIMIT_BYTES",
        DEFAULT_XZ_MEMORY_LIMIT_BYTES,
        MAX_XZ_MEMORY_LIMIT_BYTES,
    )
    members: dict[str, tuple[str, int]] = {}
    small_json: dict[str, bytearray] = {}
    manifest_payload: bytearray | None = None
    member_count = 0
    declared_total_bytes = 0
    retained_json_bytes = 0

    BoundedTarInfo.deadline = deadline
    BoundedTarInfo.max_member_bytes = max_member_bytes

    require_before_deadline(deadline)
    source_fd, source_stat = open_archive(archive_path, max_compressed_bytes)
    try:
        staged_archive = stage_archive(source_fd, source_stat, deadline)
    finally:
        os.close(source_fd)
    try:
        test_pause_after_stage(deadline)
        archive_fd = staged_archive.fileno()
        archive_stat = os.fstat(archive_fd)
        expanded_stream_limit = max_total_bytes + max_members * 1024 + 10240
        bounded_source = PreadXzReader(
            archive_fd,
            archive_stat.st_size,
            deadline,
            xz_memory_limit,
            expanded_stream_limit,
        )
        with tarfile.open(
            fileobj=bounded_source, mode="r|", tarinfo=BoundedTarInfo
        ) as archive:
            for member in archive:
                require_before_deadline(deadline)
                member_count += 1
                if member_count > max_members:
                    fail(f"archive member count exceeds hard bound {max_members}")
                name = canonical_member_name(member.name)
                if name in members:
                    fail(f"duplicate archive member: {name}")
                if member.size < 0 or member.size > max_member_bytes:
                    fail(f"archive member exceeds byte bound: {name}")
                if declared_total_bytes > max_total_bytes - member.size:
                    fail(f"archive decompressed bytes exceed hard bound {max_total_bytes}")
                declared_total_bytes += member.size
                if member.isdir():
                    members[name] = ("", member.size)
                    continue
                if not member.isfile():
                    # The verified archive is passed to a privileged Docker
                    # daemon.  Never allow link or special-file records to cross
                    # that boundary merely because manifest.json does not
                    # reference them.  Docker-save archives need only canonical
                    # directories and regular metadata/blob members.
                    fail(f"unsupported archive member type: {name}")
                source = archive.extractfile(member)
                if source is None:
                    fail(f"unreadable archive member: {name}")
                digest = hashlib.sha256()
                retained = (
                    bytearray()
                    if member.size <= MAX_SINGLE_RETAINED_JSON_BYTES
                    and (name == "manifest.json" or name.endswith(".json"))
                    else None
                )
                actual_size = 0
                while True:
                    require_before_deadline(deadline)
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    if actual_size > member.size:
                        fail(f"archive member exceeded its declared size: {name}")
                    digest.update(chunk)
                    if retained is not None:
                        if retained_json_bytes > max_retained_json_bytes - len(chunk):
                            fail(
                                "retained JSON bytes exceed hard bound "
                                f"{max_retained_json_bytes}"
                            )
                        retained_json_bytes += len(chunk)
                        retained.extend(chunk)
                if actual_size != member.size:
                    fail(f"archive member size mismatch: {name}")
                actual_digest = digest.hexdigest()
                members[name] = (actual_digest, member.size)

                blob_digest = digest_from_blob_path(name)
                if blob_digest is not None and actual_digest != blob_digest:
                    fail(f"content digest mismatch for {name}")
                if name == "manifest.json":
                    if manifest_payload is not None or retained is None:
                        fail("manifest.json is duplicated or unreasonably large")
                    manifest_payload = retained
                elif retained is not None and name.endswith(".json"):
                    small_json[name] = retained

        # tarfile stops at the end-of-archive marker. Drain the same bounded
        # decoder so compressed content hidden after that marker cannot escape
        # the XZ memory, expanded-byte, or deadline authority.
        while bounded_source.read(1024 * 1024):
            pass

        require_before_deadline(deadline)

        if manifest_payload is None:
            fail("archive is missing root manifest.json")
        try:
            manifest = json.loads(manifest_payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"manifest.json is invalid: {error}")
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            fail("archive must contain exactly one image")

        image = manifest[0]
        config_path = image.get("Config")
        layers = image.get("Layers")
        tags = image.get("RepoTags") or []
        if not isinstance(config_path, str) or not isinstance(layers, list) or not all(
            isinstance(layer, str) for layer in layers
        ):
            fail("manifest has invalid Config or Layers fields")
        if len(tags) != 1 or not isinstance(tags[0], str) or not tags[0]:
            fail("archive must contain exactly one repository tag")
        canonical_member_name(config_path)
        for layer in layers:
            canonical_member_name(layer)
        if config_path not in members or members[config_path][0] == "":
            fail(f"archive is missing regular config object: {config_path}")

        config_digest = digest_from_blob_path(config_path)
        legacy_config = False
        if config_digest is None:
            config_name = pathlib.PurePosixPath(config_path)
            if config_name.parent != pathlib.PurePosixPath(".") or not config_path.endswith(".json"):
                fail("archive has an invalid config object path")
            config_digest = config_path[:-5]
            if len(config_digest) != 64 or any(
                character not in "0123456789abcdef" for character in config_digest
            ):
                fail("archive has an invalid legacy config digest")
            if members[config_path][0] != config_digest:
                fail(f"legacy config content digest mismatch for {config_path}")
            legacy_config = True

        for layer in layers:
            if layer not in members or members[layer][0] == "":
                fail(f"archive is missing regular layer object: {layer}")
            if digest_from_blob_path(layer) is None and not legacy_config:
                fail(f"archive has a non-content-addressed layer path: {layer}")

        if legacy_config and layers:
            try:
                config = json.loads(small_json[config_path])
                diff_ids = config["rootfs"]["diff_ids"]
            except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
                fail(f"legacy config lacks rootfs diff_ids: {error}")
            if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
                fail("legacy config layer count does not match manifest")
            for layer, diff_id in zip(layers, diff_ids, strict=True):
                if not isinstance(diff_id, str) or diff_id != "sha256:" + members[layer][0]:
                    fail(f"legacy layer content digest mismatch for {layer}")

        result = f"sha256:{config_digest}\t{tags[0]}"
        if arguments.stream_verified_archive:
            offset = 0
            while offset < archive_stat.st_size:
                require_before_deadline(deadline)
                chunk = os.pread(archive_fd, 1024 * 1024, offset)
                if not chunk:
                    fail("archive changed size while streaming verified bytes")
                write_all_before_deadline(sys.stdout.fileno(), chunk, deadline)
                offset += len(chunk)
                require_before_deadline(deadline)
            if stable_archive_identity(os.fstat(archive_fd)) != stable_archive_identity(
                archive_stat
            ):
                fail("archive identity changed while streaming verified bytes")
        else:
            print(result)
    finally:
        staged_archive.close()


if __name__ == "__main__":
    main()
