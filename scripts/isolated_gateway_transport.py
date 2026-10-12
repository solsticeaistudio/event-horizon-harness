"""Opt-in subprocess gateway transport for later Firecracker integration.

This is *transport only*: it neither authorizes effects nor claims KVM execution.
The supervisor retains the server socket and kills/reaps the independent child.
A trusted gateway handler will replace the fixed diagnostic handler in follow-up.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from event_horizon.protocol import encode_frame, read_frame


class GatewayTransportError(RuntimeError):
    pass


def start_gateway_process() -> tuple[subprocess.Popen, socket.socket]:
    """Give the worker one isolated Unix descriptor, not supervisor state."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "scripts.isolated_gateway_transport", "--child",
             "--fd", str(child.fileno())],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, pass_fds=(child.fileno(),),
            close_fds=True, start_new_session=True,
        )
        return proc, parent
    except BaseException:
        parent.close()
        raise
    finally:
        child.close()


def exchange(channel: socket.socket, message: dict) -> dict:
    """One framed request/response; never reinterpret EOF as a denial."""
    if not isinstance(message, dict):
        raise ValueError("request must be a JSON object")
    channel.settimeout(3)
    try:
        channel.sendall(encode_frame(message))
        with channel.makefile("rb") as reader:
            answer = read_frame(reader)
    except (OSError, EOFError, ValueError) as exc:
        raise GatewayTransportError("gateway channel failed; outcome unknown") from exc
    if not isinstance(answer, dict):
        raise GatewayTransportError("invalid gateway response")
    return answer


def child_main(fd: int) -> None:
    """Fixed diagnostic protocol. No capability keys or effect handler here."""
    with socket.socket(fileno=fd) as channel:
        with channel.makefile("rb") as reader:
            request = read_frame(reader)
            if not isinstance(request, dict) or set(request) != {"diagnostic"}:
                raise GatewayTransportError("unknown diagnostic command")
            if request["diagnostic"] != "ping":
                raise GatewayTransportError("unsupported diagnostic")
            channel.sendall(encode_frame({"diagnostic": "pong", "pid": os.getpid()}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--fd", type=int)
    args = parser.parse_args()
    if not args.child or args.fd is None:
        parser.error("internal worker only; use start_gateway_process")
    child_main(args.fd)


if __name__ == "__main__":
    main()
