#!/usr/bin/env python3
"""Run one release API command with bounded, signal-safe process authority."""

from __future__ import annotations

import argparse
import ctypes
import os
import select
import signal
import stat
import sys
import time


MAX_TIMEOUT_SECONDS = 3600
MAX_TERMINATION_GRACE_SECONDS = 30
FINAL_REAP_SECONDS = 5
CANCEL_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
HANDLED_SIGNALS = CANCEL_SIGNALS + (signal.SIGCHLD,)


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("it_interval", Timespec), ("it_value", Timespec)]


class Sigset(ctypes.Structure):
    _fields_ = [("bits", ctypes.c_ulong * 16)]


def positive_bounded(value: str, maximum: int, label: str) -> int:
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        raise argparse.ArgumentTypeError(f"{label} must be a canonical positive integer")
    parsed = int(value)
    if parsed > maximum:
        raise argparse.ArgumentTypeError(f"{label} exceeds maximum {maximum}")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timeout-seconds",
        required=True,
        type=lambda value: positive_bounded(value, MAX_TIMEOUT_SECONDS, "timeout"),
    )
    parser.add_argument("--authority-fd", type=int)
    parser.add_argument("--authority-token")
    parser.add_argument(
        "--termination-grace-seconds",
        default="2",
        type=lambda value: positive_bounded(
            value, MAX_TERMINATION_GRACE_SECONDS, "termination grace"
        ),
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    if (arguments.authority_fd is None) != (arguments.authority_token is None):
        parser.error("authority fd and token must be supplied together")
    authority_fd = arguments.authority_fd
    if authority_fd is not None:
        if authority_fd <= 2 or not arguments.authority_token or len(arguments.authority_token) > 256:
            parser.error("invalid authority descriptor or token")
        authority_stat = os.fstat(authority_fd)
        if (
            not stat.S_ISREG(authority_stat.st_mode)
            or authority_stat.st_uid != os.getuid()
            or authority_stat.st_nlink != 1
            or authority_stat.st_mode & 0o077
        ):
            parser.error("authority descriptor must name one private caller-owned regular file")

    deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + (
        arguments.timeout_seconds * 1_000_000_000
    )
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    previous_dispositions = {
        handled_signal: signal.getsignal(handled_signal)
        for handled_signal in HANDLED_SIGNALS
    }
    for handled_signal in HANDLED_SIGNALS:
        signal.signal(handled_signal, signal.SIG_DFL)

    libc = ctypes.CDLL(None, use_errno=True)
    timerfd_create = libc.timerfd_create
    timerfd_create.argtypes = [ctypes.c_int, ctypes.c_int]
    timerfd_create.restype = ctypes.c_int
    timerfd_settime = libc.timerfd_settime
    timerfd_settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    timerfd_settime.restype = ctypes.c_int
    signalfd = libc.signalfd
    signalfd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    signalfd.restype = ctypes.c_int
    sigemptyset = libc.sigemptyset
    sigemptyset.argtypes = [ctypes.c_void_p]
    sigemptyset.restype = ctypes.c_int
    sigaddset = libc.sigaddset
    sigaddset.argtypes = [ctypes.c_void_p, ctypes.c_int]
    sigaddset.restype = ctypes.c_int

    timer_fd = timerfd_create(time.CLOCK_BOOTTIME, os.O_CLOEXEC | os.O_NONBLOCK)
    if timer_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    specification = Itimerspec(
        Timespec(0, 0),
        Timespec(deadline // 1_000_000_000, deadline % 1_000_000_000),
    )
    if timerfd_settime(timer_fd, 1, ctypes.byref(specification), None) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

    signal_set = Sigset()
    if sigemptyset(ctypes.byref(signal_set)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    for handled_signal in HANDLED_SIGNALS:
        if sigaddset(ctypes.byref(signal_set), handled_signal) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    signal_fd = signalfd(-1, ctypes.byref(signal_set), os.O_CLOEXEC | os.O_NONBLOCK)
    if signal_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

    child_pid: int | None = None
    child_reaped = False
    pid_fd: int | None = None

    def restore_signal_state() -> None:
        for restored_signal, disposition in previous_dispositions.items():
            signal.signal(restored_signal, disposition)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def consume_cancel_signal() -> int | None:
        raw_signals = os.read(signal_fd, 128 * 16)
        delivered = [
            int.from_bytes(raw_signals[offset : offset + 4], sys.byteorder)
            for offset in range(0, len(raw_signals), 128)
        ]
        return next((value for value in delivered if value in CANCEL_SIGNALS), None)

    def signal_group(delivered_signal: int) -> None:
        if child_pid is None:
            return
        try:
            os.killpg(child_pid, delivered_signal)
        except ProcessLookupError:
            pass

    def group_exists() -> bool:
        if child_pid is None:
            return False
        try:
            os.killpg(child_pid, 0)
            return True
        except ProcessLookupError:
            return False

    def reap_ready_leader() -> int | None:
        nonlocal child_reaped
        if child_reaped or not child_is_ready():
            return None
        _waited, raw_status = os.waitpid(child_pid, 0)
        child_reaped = True
        status = os.waitstatus_to_exitcode(raw_status)
        return status if status >= 0 else 128 - status

    def child_is_ready() -> bool:
        if pid_fd is None:
            return False
        poller = select.poll()
        poller.register(pid_fd, select.POLLIN)
        return bool(poller.poll(0))

    def terminate_and_reap() -> bool:
        nonlocal child_reaped
        if child_pid is None:
            return True
        signal_group(signal.SIGTERM)
        # The operation deadline stops useful work. A short, separately bounded
        # cleanup tail still gives the command a chance to terminate cleanly
        # before SIGKILL, including when the operation timer itself expired.
        grace_deadline = (
            time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            + arguments.termination_grace_seconds * 1_000_000_000
        )
        while time.clock_gettime_ns(time.CLOCK_BOOTTIME) < grace_deadline:
            reap_ready_leader()
            if child_reaped and not group_exists():
                return True
            time.sleep(0.01)
        signal_group(signal.SIGKILL)
        reap_deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + FINAL_REAP_SECONDS * 1_000_000_000
        while time.clock_gettime_ns(time.CLOCK_BOOTTIME) < reap_deadline:
            reap_ready_leader()
            if child_reaped and not group_exists():
                return True
            signal_group(signal.SIGKILL)
            time.sleep(0.01)
        return False

    def test_pause_before_spawn() -> int | None:
        if os.environ.get("BORONDNS_RELEASE_API_TEST_PHASE") != "before-spawn":
            return None
        marker = os.environ.get("BORONDNS_RELEASE_API_TEST_MARKER", "")
        continuation = os.environ.get("BORONDNS_RELEASE_API_TEST_CONTINUE", "")
        if not marker or not continuation:
            raise RuntimeError("release API supervisor test hook is incomplete")
        with open(marker, "x", encoding="ascii") as output:
            output.write(f"{os.getpid()}\n")
            output.flush()
            os.fsync(output.fileno())
        poller = select.poll()
        poller.register(timer_fd, select.POLLIN)
        poller.register(signal_fd, select.POLLIN)
        while not os.path.exists(continuation):
            events = poller.poll(10)
            if any(fd == signal_fd for fd, _event in events):
                delivered = consume_cancel_signal()
                if delivered is not None:
                    return 128 + delivered
            if any(fd == timer_fd for fd, _event in events):
                return 124
        return None

    def await_parent_authority() -> int | None:
        nonlocal authority_fd
        if authority_fd is None:
            return None
        expected = (arguments.authority_token + "\n").encode("ascii")
        poller = select.poll()
        poller.register(timer_fd, select.POLLIN)
        poller.register(signal_fd, select.POLLIN)
        while True:
            observed = os.pread(authority_fd, len(expected) + 1, 0)
            if observed == expected:
                os.close(authority_fd)
                authority_fd = None
                return None
            if observed:
                raise RuntimeError("release API parent authority token is invalid")
            events = poller.poll(10)
            if any(fd == signal_fd for fd, _event in events):
                delivered = consume_cancel_signal()
                if delivered is not None:
                    return 128 + delivered
            if any(fd == timer_fd for fd, _event in events):
                return 124

    result = 125
    try:
        paused_result = await_parent_authority()
        if paused_result is None:
            paused_result = test_pause_before_spawn()
        if paused_result is not None:
            result = paused_result
        else:
            child_pid = os.posix_spawnp(
                command[0],
                command,
                os.environ,
                setsid=True,
                setsigmask=(),
                setsigdef=HANDLED_SIGNALS,
            )
            pid_fd = os.pidfd_open(child_pid, 0)
            poller = select.poll()
            poller.register(timer_fd, select.POLLIN)
            poller.register(signal_fd, select.POLLIN)
            poller.register(pid_fd, select.POLLIN)
            while True:
                events = poller.poll()
                if any(fd == signal_fd for fd, _event in events):
                    delivered = consume_cancel_signal()
                    if delivered is not None:
                        result = 128 + delivered if terminate_and_reap() else 125
                        break
                if any(fd == timer_fd for fd, _event in events):
                    result = 124 if terminate_and_reap() else 125
                    break
                if any(fd == pid_fd for fd, _event in events):
                    status = reap_ready_leader()
                    if group_exists():
                        print(
                            "release API command exited with live process-group descendants",
                            file=sys.stderr,
                        )
                        terminate_and_reap()
                        result = 125
                    else:
                        if status is None:
                            raise RuntimeError("release API child readiness was not reapable")
                        result = status
                    break
    finally:
        if child_pid is not None and not child_reaped:
            terminate_and_reap()
        if pid_fd is not None:
            os.close(pid_fd)
        if authority_fd is not None:
            os.close(authority_fd)
        os.close(signal_fd)
        os.close(timer_fd)
        restore_signal_state()
    raise SystemExit(result)


if __name__ == "__main__":
    main()
