"""Trusted supervisor bridge: effect-service fd -> real gateway child.

The original Firecracker guest and jailed package service keep their private
transport. Only the host supervisor forwards framed requests into a distinct
DatasetEffectBoundary process. Recorder RPC retains the host's signing key.
"""
from __future__ import annotations

import json
import os
import select
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
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.run_package_isolation import GateReceiver


class BridgedGateReceiver(GateReceiver):
    def __init__(self, channel, recorder, config, target_thread=None):
        super().__init__(channel, recorder, config, target_thread)
        self.gateway_pid = None
        self.gateway_failure = None
        self.record_failure = None
        self.event_contract = None
        self.gateway_process = None
        self.gateway_pidfd = None
        self.gateway_event_pid = None

    def _record_events(self, channel):
        try:
            with channel, channel.makefile("rb") as stream:
                for _ in range(128):
                    try:
                        event = read_frame(stream)
                    except EOFError:
                        break
                    if self.event_contract is None or self.gateway_process is None:
                        raise RuntimeError("signed gateway evidence arrived without a pinned child")
                    if self.gateway_process.poll() is not None:
                        raise RuntimeError("gateway died before evidentiary confirmation")
                    if self.gateway_pidfd is None or select.select([self.gateway_pidfd], [], [], 0)[0]:
                        raise RuntimeError("trusted gateway pidfd no longer identifies a live child")
                    self.event_contract.check(event)
                    if event["event_type"] == "fenced.recipient-confirmed":
                        from event_horizon.fenced_recipient import FencedSqliteRecipient
                        from event_horizon.canonical import digest
                        conf = self.config.get("fenced_recipient")
                        if not isinstance(conf, dict):
                            raise RuntimeError("unconfigured fenced evidence event")
                        recipient = FencedSqliteRecipient(
                            self.config["recipient_database"],
                            recipient_id=conf["recipient_id"],
                        )
                        observed = recipient.observe(
                            effect_key=self.config["recipient_effect_key"],
                            request_digest=self.config["expected_request_digest"],
                        )
                        payload = event["payload"]
                        if (observed is None or recipient.commit_count() != 1
                                or observed.receipt_digest != payload["receipt_digest"]
                                or observed.sequence != payload["commit_sequence"]
                                or observed.output_digest != digest(
                                    self.config["dataset"][
                                        self.config["fenced_output_offset"]:
                                        self.config["fenced_output_offset"] +
                                        self.config["fenced_output_length"]
                                    ])):
                            raise RuntimeError("recipient evidence cannot be independently corroborated")
                        if payload["new_effect_commit"]:
                            self.dispatches += 1
                        self.gateway_event_pid = self.gateway_process.pid
                    if event["event_type"] == "execution.completed" and self.config.get("recipient_database"):
                        from scripts.effect_crash_recipient import observed_recipient
                        snapshot = observed_recipient(Path(self.config["recipient_database"]))
                        if snapshot["count"] != 1:
                            raise RuntimeError("cannot sign completion without independent recipient commit")
                    written = self.recorder.append(
                        event["event_type"], event["payload"],
                        source_id="host-effect-service",
                    )
                    self.receipts.append(written["receipt"])
                    if event["event_type"] == "execution.dispatch":
                        self.dispatches += 1
                        if event["payload"].get("dispatch_count") != self.dispatches:
                            raise RuntimeError("gateway dispatch count mismatch")
                        self.gateway_event_pid = event["payload"]["gateway_pid"]
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
                self.gateway_process = child
                if child.pid == os.getpid():
                    raise RuntimeError("gateway was not independently spawned")
                # Linux pidfd binds supervision to this specific child lifetime,
                # preventing PID reuse from substituting a different process.
                self.gateway_pidfd = os.pidfd_open(child.pid)
                self.event_contract = GatewayEventContract(
                    gateway_pid=child.pid,
                    request_digest=self.config["expected_request_digest"],
                    request_id=self.config["expected_request_id"],
                    capability_id=self.config["expected_capability_id"],
                )
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
                        self.event_contract.begin_request(request)
                        try:
                            response = exchange(request_channel, request)
                        finally:
                            self.event_contract.end_request()
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
            if self.gateway_pidfd is not None:
                os.close(self.gateway_pidfd)
                self.gateway_pidfd = None
            if evidence_channel is not None:
                evidence_channel.close()
            if event_thread is not None:
                event_thread.join(timeout=3)
                if event_thread.is_alive() and self.failure is None:
                    self.failure = RuntimeError("gateway evidence relay failed to terminate")
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure


    # The recipient wrapper invokes this hook after its separate service is
    # ready. A crash experiment may override it without affecting the v4 path.
    _run_gateway = run



# Explicit import allowlist. The restricted process must not depend on
# traversing an operator's private checkout after all DAC caps are dropped.
_RECIPIENT_MODULES = {
    "scripts/__init__.py": "scripts/__init__.py",
    "scripts/kvm_effect_recipient_service.py": "scripts/kvm_effect_recipient_service.py",
    "scripts/effect_crash_recipient.py": "scripts/effect_crash_recipient.py",
    "scripts/fenced_recipient_service.py": "scripts/fenced_recipient_service.py",
    "src/event_horizon/fenced_recipient.py": "event_horizon/fenced_recipient.py",
    "src/event_horizon/fenced_recipient_transport.py": "event_horizon/fenced_recipient_transport.py",
    "src/event_horizon/protocol.py": "event_horizon/protocol.py",
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
        # Only the sixth-window supervisor opts into a one-shot private
        # recipient release pipe. Normal KVM recipients are unchanged.
        self.delayed_recipient_mode = False
        self.recipient_process = None
        self.delayed_release_fd = None

    def release_delayed_recipient(self):
        """Release an already-pinned in-flight request; never permit EOF commit."""
        if not self.delayed_recipient_mode or self.delayed_release_fd is None:
            raise RuntimeError("recipient has no pending trusted release")
        if self.recipient_process is None or self.recipient_process.poll() is not None:
            raise RuntimeError("recipient died before trusted release")
        fd = self.delayed_release_fd
        self.delayed_release_fd = None
        try:
            os.write(fd, b"R")
        finally:
            os.close(fd)

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
        pause_read = None
        try:
            path.write_bytes(canonical_bytes(recipient_config))
            path.chmod(0o600)
            # Stage a minimal runtime before privilege reduction. A root process
            # without DAC override cannot necessarily traverse /home/<user>.
            runtime = stage_private_recipient_runtime(path.parent)
            cmd = [sys.executable, "-E", "-u", "-m",
                   "scripts.kvm_effect_recipient_service", "--config", str(path)]
            if self.delayed_recipient_mode:
                pause_read, self.delayed_release_fd = os.pipe()
                cmd += ["--pause-before-commit-fd", str(pause_read)]
            if self.isolated_recipient:
                cmd = ["unshare", "--net", "--", "setpriv",
                       "--bounding-set=-all", "--no-new-privs", "--", *cmd]
            recipient = subprocess.Popen(
                cmd, cwd=runtime,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
                pass_fds=(() if pause_read is None else (pause_read,)),
            )
            if pause_read is not None:
                os.close(pause_read)
                pause_read = None
            self.recipient_process = recipient
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
            self._run_gateway()
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
            if pause_read is not None:
                os.close(pause_read)
            if self.delayed_release_fd is not None:
                # EOF means ABORT in the opt-in recipient; never accidental
                # commit when a failed lab run unwinds.
                os.close(self.delayed_release_fd)
                self.delayed_release_fd = None
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
