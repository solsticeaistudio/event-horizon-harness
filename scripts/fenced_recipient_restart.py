"""Fail-closed cleanup for one supervisor-owned SIGKILLed Unix recipient.

Never delete an arbitrary /tmp socket. The operator must prove the *exact*
service child died, retain the socket's original inode, and verify that the
still-private owner-controlled path contains the same socket. A missing or
replaced inode aborts the run, never licenses a retry on another recipient.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import stat
import subprocess

from event_horizon.fenced_recipient_transport import _private_parent


class UnsafeRecipientRestart(RuntimeError):
    """The supervisor cannot prove the restart targets its original service."""


def pinned_socket_inode(path: str | Path, *, owner_uid: int | None = None) -> int:
    path = Path(path)
    _private_parent(path)
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    if type(owner_uid) is not int or owner_uid < 0:
        raise ValueError("invalid pinned service UID")
    info = os.lstat(path)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise UnsafeRecipientRestart("recipient socket identity or permissions changed")
    return info.st_ino


def remove_killed_recipient_socket(
    child: subprocess.Popen, path: str | Path, *, expected_inode: int,
    owner_uid: int | None = None,
) -> dict:
    """Remove ONLY a positively identified stale socket after confirmed SIGKILL.

    The private parent is exclusively controlled by the trusted supervisor,
    which is essential to rule out a competing path substitution during
    the lstat/unlink pair. Callers must never pass guest-controlled paths.
    """
    if (not isinstance(child, subprocess.Popen) or child.pid <= 1
            or child.returncode != -signal.SIGKILL
            or type(expected_inode) is not int or expected_inode <= 0):
        raise UnsafeRecipientRestart("original recipient has not been reaped after SIGKILL")
    path = Path(path)
    inode = pinned_socket_inode(path, owner_uid=owner_uid)
    if inode != expected_inode:
        raise UnsafeRecipientRestart("stale recipient socket inode was replaced")
    os.unlink(path)
    if os.path.lexists(path):
        raise UnsafeRecipientRestart("stale recipient socket removal not established")
    return {
        "killed_pid": child.pid,
        "signal": signal.SIGKILL,
        "exit_code": child.returncode,
        "stale_socket_inode": inode,
        "stale_socket_removed": True,
    }
