"""Dedicated real-KVM opt-in bridge for the atomic fenced recipient.

This bridge is deliberately NOT the six historical Firecracker windows.
The protected guest sends signed requests through the existing vsock service.
The recipient runs in a separately supervised host OS process and the real
host gateway opens the authenticated Unix socket, never the recipient DB.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import threading

from event_horizon.canonical import canonical_bytes
from scripts.integrated_gateway_process_bridge import (
    BridgedGateReceiver, stage_private_recipient_runtime,
)


class FencedRecipientKvmReceiver(BridgedGateReceiver):
    """Start one trusted transactional recipient and keep it independent.

    The service remains alive across gateway subprocess restarts. All resource
    paths, credentials and fault selection belong to the trusted supervisor.
    """

    def __init__(self, channel, recorder, config, target_thread=None):
        super().__init__(channel, recorder, config, target_thread)
        self.recipient_pid = None
        self.recipient_process = None
        self.recipient_ready = threading.Event()
        self.recipient_status = None

    def _run_gateway(self):
        # Baseline runs the existing bridged host gateway. Opt-in KVM fault
        # receivers override ONLY this method; the recipient stays alive.
        return BridgedGateReceiver.run(self)

    def run(self):
        cfg = self.config
        fence = cfg["fenced_recipient"]
        path = Path(cfg["recipient_database"]).with_name("fenced-recipient-config.json")
        service_config = {
            "socket_path": fence["socket_path"],
            "recipient_database": cfg["recipient_database"],
            "recipient_id": fence["recipient_id"],
            "auth_key_hex": fence["auth_key_hex"],
        }
        service = None
        try:
            path.write_bytes(canonical_bytes(service_config))
            path.chmod(0o600)
            runtime = stage_private_recipient_runtime(path.parent)
            cmd = [sys.executable, "-E", "-u", "-m",
                   "scripts.fenced_recipient_service", "--config", str(path)]
            cmd = ["unshare", "--net", "--", "setpriv",
                   "--bounding-set=-all", "--no-new-privs", "--", *cmd]
            service = subprocess.Popen(
                cmd, cwd=runtime, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.recipient_process = service
            self.recipient_pid = service.pid
            ready, _, _ = select.select([service.stdout], [], [], 12)
            message = service.stdout.readline().strip() if ready else b""
            if message != b"READY" or service.poll() is not None:
                error = service.stderr.read(2048) if service.poll() is not None else b""
                raise RuntimeError(
                    "fenced service did not initialize independently: "
                    + repr(message) + " " + error.decode(errors="replace")
                )
            self.recipient_ready.set()
            self._run_gateway()
            if service.poll() is not None:
                raise RuntimeError("independent fenced recipient unexpectedly exited")
        except BaseException as exc:
            if self.failure is None:
                self.failure = exc
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.channel.close()
        finally:
            self.recipient_ready.set()
            if service is not None:
                if service.poll() is None:
                    service.terminate()
                    try:
                        service.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        service.kill()
                        service.wait(timeout=4)
                self.recipient_status = service.returncode
                if service.stdout is not None:
                    service.stdout.close()
                if service.stderr is not None:
                    service.stderr.close()
