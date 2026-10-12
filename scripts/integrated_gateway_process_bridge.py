"""Trusted supervisor bridge: effect-service fd -> real gateway child.

The original Firecracker guest and jailed package service keep their private
transport. Only the host supervisor forwards framed requests into a distinct
DatasetEffectBoundary process. Recorder RPC retains the host's signing key.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import threading

from event_horizon.canonical import canonical_bytes
from event_horizon.protocol import encode_frame, read_frame
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange
from scripts.run_package_isolation import GateReceiver


class BridgedGateReceiver(GateReceiver):
    def __init__(self, channel, recorder, config, target_thread=None):
        super().__init__(channel, recorder, config, target_thread)
        self.gateway_pid = None
        self.gateway_failure = None
        self.record_failure = None

    def _record_events(self, channel):
        try:
            with channel, channel.makefile("rb") as stream:
                for _ in range(128):
                    try:
                        event = read_frame(stream)
                    except EOFError:
                        break
                    if (not isinstance(event, dict)
                            or set(event) != {"event_type", "payload", "source_id"}
                            or not isinstance(event["event_type"], str)
                            or not isinstance(event["payload"], dict)
                            or event["source_id"] != "host-effect-service"):
                        raise ValueError("gateway tried to send invalid evidence")
                    written = self.recorder.append(
                        event["event_type"], event["payload"],
                        source_id="host-effect-service",
                    )
                    self.receipts.append(written["receipt"])
                    if event["event_type"] == "execution.dispatch":
                        self.dispatches += 1
                        if event["payload"].get("dispatch_count") != self.dispatches:
                            raise RuntimeError("gateway dispatch count mismatch")
                    channel.sendall(encode_frame({"recorded": True}))
        except BaseException as exc:
            self.record_failure = exc

    def run(self):
        child = None
        request_channel = None
        evidence_channel = None
        event_thread = None
        try:
            if self.target_thread is not None:
                self.target_thread.start()
            with tempfile.TemporaryDirectory(prefix="ehh-bridged-gateway-") as folder:
                path = Path(folder) / "trusted.json"
                path.write_bytes(canonical_bytes({
                    "boundary": self.config,
                    "recorder_path": str(Path(folder) / "not-used-in-bridge.jsonl"),
                }))
                path.chmod(0o600)
                child, request_channel, evidence_channel = start_effect_gateway(
                    path, recorder_bridge=True,
                )
                self.gateway_pid = child.pid
                if child.pid == os.getpid():
                    raise RuntimeError("gateway was not independently spawned")
                event_thread = threading.Thread(
                    target=self._record_events, args=(evidence_channel,), daemon=True,
                )
                event_thread.start()
                with self.channel, self.channel.makefile("rb") as stream:
                    for _ in range(24):
                        try:
                            request = read_frame(stream)
                        except EOFError:
                            break
                        if self.record_failure is not None:
                            raise RuntimeError("trusted evidence receiver failed")
                        response = exchange(request_channel, request)
                        self.channel.sendall(encode_frame(response))
        except BaseException as exc:
            self.failure = exc
        finally:
            if request_channel is not None:
                request_channel.close()
            if child is not None:
                if child.poll() is None:
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                else:
                    child.wait(timeout=5)
                if child.returncode not in (0, -9) and self.failure is None:
                    self.failure = RuntimeError("real gateway child exited unexpectedly")
                if child.stderr is not None:
                    child.stderr.close()
            if evidence_channel is not None:
                evidence_channel.close()
            if event_thread is not None:
                event_thread.join(timeout=3)
                if event_thread.is_alive() and self.failure is None:
                    self.failure = RuntimeError("gateway evidence relay failed to terminate")
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure



# Explicit import allowlist. The restricted process must not depend on
# traversing an operator's private checkout after all DAC caps are dropped.
_RECIPIENT_MODULES = {
    "scripts/__init__.py": "scripts/__init__.py",
    "scripts/kvm_effect_recipient_service.py": "scripts/kvm_effect_recipient_service.py",
    "scripts/effect_crash_recipient.py": "scripts/effect_crash_recipient.py",
    "src/event_horizon/__init__.py": "event_horizon/__init__.py",
    "src/event_horizon/canonical.py": "event_horizon/canonical.py",
}


def stage_private_recipient_runtime(control_dir: Path) -> Path:
    """Stage only required host-trusted modules under a private root-owned dir.

    The owner can traverse these files with UID 0 after setpriv removes DAC
    override capabilities. No code or resource gets exposed to the VM or
    compromised package worker.
    """
    source_root = Path(__file__).resolve().parents[1]
    runtime = control_dir / "recipient-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    for source, destination in _RECIPIENT_MODULES.items():
        original = source_root / source
        target = runtime / destination
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(original.read_bytes())
        target.chmod(0o400)
    return runtime


class RecipientBridgedGateReceiver(BridgedGateReceiver):
    """Independent durable recipient, kept alive outside gateway lifetime.

    The host alone owns the recipient config and SQLite database. A missing
    readiness acknowledgement fails this run; it cannot become a test denial.
    """

    def __init__(self, channel, recorder, config, target_thread=None,
                 *, isolated_recipient=True):
        super().__init__(channel, recorder, config, target_thread)
        self.isolated_recipient = isolated_recipient
        self.recipient_pid = None
        self.recipient_status = None
        self.recipient_ready = threading.Event()

    def run(self):
        import select
        import sys

        cfg = self.config
        path = Path(cfg["recipient_database"]).with_name("recipient-config.json")
        recipient_config = {
            "recipient_socket": cfg["recipient_socket"],
            "recipient_database": cfg["recipient_database"],
            "effect_key": cfg["recipient_effect_key"],
            "request_digest": cfg["recipient_request_digest"],
        }
        recipient = None
        try:
            path.write_bytes(canonical_bytes(recipient_config))
            path.chmod(0o600)
            # Stage a minimal runtime before privilege reduction. A root process
            # without DAC override cannot necessarily traverse /home/<user>.
            runtime = stage_private_recipient_runtime(path.parent)
            cmd = [sys.executable, "-E", "-u", "-m",
                   "scripts.kvm_effect_recipient_service", "--config", str(path)]
            if self.isolated_recipient:
                cmd = ["unshare", "--net", "--", "setpriv",
                       "--bounding-set=-all", "--no-new-privs", "--", *cmd]
            recipient = subprocess.Popen(
                cmd, cwd=runtime,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
            )
            self.recipient_pid = recipient.pid
            ready, _, _ = select.select([recipient.stdout], [], [], 12)
            if not ready:
                raise RuntimeError("independent recipient readiness deadline expired")
            line = recipient.stdout.readline().strip()
            if line != b"READY" or recipient.poll() is not None:
                error = b""
                if recipient.poll() is not None and recipient.stderr is not None:
                    error = recipient.stderr.read(2048)
                raise RuntimeError(
                    "independent recipient did not start: "
                    + repr(line) + " " + error.decode("utf-8", errors="replace")
                )
            self.recipient_ready.set()
            super().run()
            if recipient.poll() is not None:
                raise RuntimeError("recipient died while trusted gateway was active")
        except BaseException as exc:
            if self.failure is None:
                self.failure = exc
            # Never leave the guest's package worker connected to an inert
            # socket when startup failed before BridgedGateReceiver.run().
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.channel.close()
        finally:
            self.recipient_ready.set()
            if recipient is not None:
                if recipient.poll() is None:
                    recipient.terminate()
                    try:
                        recipient.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        recipient.kill()
                        recipient.wait(timeout=4)
                self.recipient_status = recipient.returncode
                if recipient.stdout is not None:
                    recipient.stdout.close()
                if recipient.stderr is not None:
                    recipient.stderr.close()
