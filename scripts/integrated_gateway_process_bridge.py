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
