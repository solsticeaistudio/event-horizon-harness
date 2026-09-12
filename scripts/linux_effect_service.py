"""Bounded inherited-socket service used by the Linux/KVM isolation lab."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import socket
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.protocol import ProtocolError, encode_frame, read_frame


class RecorderClient:
    def __init__(self, descriptor: int):
        self.channel = socket.socket(fileno=descriptor)
        self.channel.settimeout(2)
        self.stream = self.channel.makefile("rb")

    def append(self, event_type, payload):
        self.channel.sendall(encode_frame({"event_type": event_type, "payload": payload}))
        if read_frame(self.stream) != {"recorded": True}:
            raise RuntimeError("authoritative evidence unavailable")


def timeout(_signum, _frame):
    raise TimeoutError("effect request deadline exceeded")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listener-fd", type=int, required=True)
    parser.add_argument("--recorder-fd", type=int, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    recorder = RecorderClient(args.recorder_fd)
    gate = DatasetEffectBoundary(config, recorder)
    listener = socket.socket(fileno=args.listener_fd)
    listener.settimeout(2)
    signal.signal(signal.SIGALRM, timeout)
    for _ in range(32):
        try:
            channel, _ = listener.accept()
        except socket.timeout:
            continue
        with channel:
            channel.settimeout(2)
            signal.setitimer(signal.ITIMER_REAL, 2)
            try:
                _pid, uid, _gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != config["vm_uid"]:
                    raise PermissionError("wrong transport principal")
                with channel.makefile("rb") as stream:
                    message = read_frame(stream)
                    result = gate.execute(message, peer_uid=uid)
                channel.sendall(encode_frame(result))
            except (OSError, EOFError, TimeoutError, ProtocolError, PermissionError):
                # No permissive fallback; the observer records protocol failure.
                try:
                    recorder.append("transport.rejected", {"source": "effect-boundary"})
                except Exception:
                    return 1
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
    gate.close()
    listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
