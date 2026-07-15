#!/usr/bin/env python3
"""Open, validate, and hold one local campaign lock fail-closed."""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import select
import socket
import stat
import sys
import time


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("it_interval", Timespec), ("it_value", Timespec)]


def boottime_timerfd(deadline: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    create = libc.timerfd_create
    create.argtypes = [ctypes.c_int, ctypes.c_int]
    create.restype = ctypes.c_int
    settime = libc.timerfd_settime
    settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    settime.restype = ctypes.c_int
    descriptor = create(time.CLOCK_BOOTTIME, os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    specification = Itimerspec(
        Timespec(0, 0), Timespec(deadline // 1_000_000_000, deadline % 1_000_000_000)
    )
    if settime(descriptor, 1, ctypes.byref(specification), None) != 0:
        error = ctypes.get_errno()
        os.close(descriptor)
        raise OSError(error, os.strerror(error))
    return descriptor


def fail(message: str) -> None:
    print(f"campaign lock refused: {message}", file=sys.stderr)
    raise SystemExit(73)


def identity(info: os.stat_result) -> tuple[int, int, int, int]:
    """Return the path/descriptor attributes that must remain immutable."""
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_nlink)


def require_held_identity(
    *,
    path: Path,
    held_fd: int,
    expected: tuple[int, int, int, int],
    kind: int,
    owner: int,
    label: str,
) -> None:
    """Bind both the published path and held descriptor to one identity."""
    try:
        path_info = os.stat(path, follow_symlinks=False)
        held_info = os.fstat(held_fd)
    except OSError as error:
        fail(f"cannot revalidate {label}: {error}")
    if stat.S_IFMT(path_info.st_mode) != kind or stat.S_IFMT(held_info.st_mode) != kind:
        fail(f"{label} changed file type while the lock was held")
    if path_info.st_uid != owner or held_info.st_uid != owner:
        fail(f"{label} changed owner while the lock was held")
    if identity(path_info) != expected or identity(held_info) != expected:
        fail(f"{label} identity changed while the lock was held")


def main() -> None:
    if len(sys.argv) != 5:
        fail("expected LOCK_ROOT NAMESPACE LABEL ABSOLUTE_BOOTTIME_DEADLINE")
    root_text, namespace, label, deadline_text = sys.argv[1:]
    if (
        not deadline_text
        or not deadline_text.isascii()
        or not deadline_text.isdecimal()
        or deadline_text.startswith("0")
    ):
        fail(f"invalid {label} absolute deadline")
    absolute_deadline = int(deadline_text)
    if absolute_deadline > 9223372036854775807:
        fail(f"invalid {label} absolute deadline")
    if absolute_deadline <= time.clock_gettime_ns(time.CLOCK_BOOTTIME):
        fail(f"{label} absolute deadline is exhausted")
    try:
        deadline_fd = boottime_timerfd(absolute_deadline)
    except OSError as error:
        fail(f"cannot arm {label} CLOCK_BOOTTIME deadline: {error}")
    if not namespace or "\0" in namespace or "\n" in namespace:
        fail(f"invalid {label} namespace")

    root = Path(root_text)
    lexical_root = Path(os.path.abspath(os.path.normpath(root)))
    try:
        resolved_root = root.resolve(strict=True)
        root_info = root.stat()
    except OSError as error:
        fail(f"cannot inspect {label} root {root}: {error}")
    if resolved_root != lexical_root or root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
        fail(f"{label} root must be a canonical real directory: {root}")
    if root_info.st_uid != os.getuid():
        fail(f"{label} root is not owned by uid {os.getuid()}: {root}")
    if stat.S_IMODE(root_info.st_mode) & 0o022:
        fail(f"{label} root is group- or world-writable: {root}")

    # The abstract socket is the non-replaceable authority. A filesystem flock
    # alone can split if a same-UID process replaces its pathname while the old
    # inode remains locked. Abstract AF_UNIX names have kernel-enforced bind
    # uniqueness and disappear automatically when the broker exits.
    authority_digest = hashlib.sha256(
        f"{lexical_root}\0{namespace}".encode("utf-8")
    ).hexdigest()
    authority = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        authority.bind(f"\0oxidedns-campaign-{os.getuid()}-{authority_digest}")
    except OSError as error:
        authority.close()
        fail(f"another process holds {label} authority: {error}")

    lock_root = root / ".oxidedns-campaign-locks"
    try:
        os.mkdir(lock_root, 0o700)
    except FileExistsError:
        pass
    except OSError as error:
        fail(f"cannot create private {label} directory {lock_root}: {error}")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_root_fd = os.open(lock_root, directory_flags)
    except OSError as error:
        fail(f"cannot open private {label} directory {lock_root}: {error}")
    try:
        lock_root_info = os.fstat(lock_root_fd)
        if not stat.S_ISDIR(lock_root_info.st_mode):
            fail(f"private {label} path is not a directory: {lock_root}")
        if lock_root_info.st_uid != os.getuid():
            fail(f"private {label} directory has the wrong owner: {lock_root}")
        if stat.S_IMODE(lock_root_info.st_mode) != 0o700:
            fail(f"private {label} directory must have mode 0700: {lock_root}")
        lock_root_identity = identity(lock_root_info)

        digest = hashlib.sha256(namespace.encode("utf-8")).hexdigest()
        lock_name = f"{digest}.lock"
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NONBLOCK
        lock_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=lock_root_fd)
        except OSError as error:
            fail(f"cannot safely open {label} file {lock_root / lock_name}: {error}")
        try:
            lock_info = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_info.st_mode):
                fail(f"{label} is not a regular file: {lock_root / lock_name}")
            if lock_info.st_uid != os.getuid():
                fail(f"{label} has the wrong owner: {lock_root / lock_name}")
            if lock_info.st_nlink != 1:
                fail(f"{label} must not be hard-linked: {lock_root / lock_name}")
            os.fchmod(lock_fd, 0o600)
            lock_info = os.fstat(lock_fd)
            if stat.S_IMODE(lock_info.st_mode) != 0o600:
                fail(f"{label} does not have mode 0600: {lock_root / lock_name}")
            lock_identity = identity(lock_info)

            current_root_info = os.stat(lock_root, follow_symlinks=False)
            if (current_root_info.st_dev, current_root_info.st_ino) != (
                lock_root_info.st_dev,
                lock_root_info.st_ino,
            ):
                fail(f"private {label} directory changed while opening the lock")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                fail(f"another process holds {label}: {lock_root / lock_name}")

            require_held_identity(
                path=lock_root,
                held_fd=lock_root_fd,
                expected=lock_root_identity,
                kind=stat.S_IFDIR,
                owner=os.getuid(),
                label=f"private {label} directory",
            )
            require_held_identity(
                path=lock_root / lock_name,
                held_fd=lock_fd,
                expected=lock_identity,
                kind=stat.S_IFREG,
                owner=os.getuid(),
                label=f"{label} file",
            )

            print(f"locked\t{lock_root / lock_name}", flush=True)
            # The shell retains the other end of this pipe. Each mutation
            # boundary performs an acknowledged heartbeat so broker death
            # cannot silently turn a protected operation into an unlocked one.
            # EOF releases the descriptor and therefore the advisory lock on
            # every normal shell exit path.
            poller = select.poll()
            poller.register(sys.stdin.fileno(), select.POLLIN | select.POLLHUP)
            poller.register(deadline_fd, select.POLLIN)
            while True:
                events = poller.poll()
                if any(descriptor == deadline_fd for descriptor, _event in events):
                    fail(f"{label} absolute deadline expired")
                request = sys.stdin.buffer.readline()
                if not request:
                    break
                if request != b"ping\n":
                    fail(f"invalid {label} broker request")
                require_held_identity(
                    path=lock_root,
                    held_fd=lock_root_fd,
                    expected=lock_root_identity,
                    kind=stat.S_IFDIR,
                    owner=os.getuid(),
                    label=f"private {label} directory",
                )
                require_held_identity(
                    path=lock_root / lock_name,
                    held_fd=lock_fd,
                    expected=lock_identity,
                    kind=stat.S_IFREG,
                    owner=os.getuid(),
                    label=f"{label} file",
                )
                print("alive", flush=True)
        finally:
            os.close(lock_fd)
    finally:
        os.close(lock_root_fd)
        authority.close()
        os.close(deadline_fd)


if __name__ == "__main__":
    main()
