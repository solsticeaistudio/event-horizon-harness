"""Strict supervisor for real SIGKILL child-process experiments.

A child prints PHASE:<name> followed by newline on stdout.
This is a reusable component, NOT KVM or four-guardian evidence.
"""
from __future__ import annotations

import os
import select
import signal
import subprocess
import time
from dataclasses import dataclass


class CrashControlError(RuntimeError):
    """A crash scenario was incomplete, not a successful denial."""


@dataclass(frozen=True)
class KillObservation:
    marker: str
    pid: int
    signal: int
    exit_code: int


def wait_for_checkpoint(process: subprocess.Popen, marker: str, *, timeout: float = 20.0) -> None:
    """Require the exact one-line checkpoint before allowing process termination."""
    if not marker or any(c in marker for c in "\r\n:"):
        raise ValueError("invalid checkpoint")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if process.stdout is None:
        raise CrashControlError("missing checkpoint pipe")
    fd = process.stdout.fileno()
    deadline = time.monotonic() + timeout
    expected = ("PHASE:" + marker + "\n").encode("ascii")
    data = bytearray()
    while len(data) <= 256:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CrashControlError("checkpoint timeout; outcome unknown")
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            raise CrashControlError("checkpoint timeout; outcome unknown")
        chunk = os.read(fd, 1)
        if not chunk:
            raise CrashControlError("child exited before checkpoint")
        data.extend(chunk)
        if chunk == b"\n":
            if bytes(data) != expected:
                raise CrashControlError("unexpected checkpoint")
            if process.poll() is not None:
                raise CrashControlError("child exited before supervisor kill")
            return
    raise CrashControlError("oversized checkpoint")


def kill_at_checkpoint(process: subprocess.Popen, marker: str, *,
                       timeout: float = 20.0) -> KillObservation:
    """Send SIGKILL only after a verified checkpoint; always reap the child."""
    try:
        wait_for_checkpoint(process, marker, timeout=timeout)
        if process.poll() is not None:
            raise CrashControlError("child exited before SIGKILL")
        process.kill()
        code = process.wait(timeout=5)
        if code != -signal.SIGKILL:
            raise CrashControlError("child did not die from SIGKILL")
        return KillObservation(marker, process.pid, signal.SIGKILL, code)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def launch_crash_target(argv: list[str], *, cwd: str | None = None) -> subprocess.Popen:
    """Start an independently reaped process without inherited stdin or extra fds."""
    if not argv or not all(isinstance(x, str) and x for x in argv):
        raise ValueError("invalid process argv")
    return subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            close_fds=True, start_new_session=True, bufsize=0)
