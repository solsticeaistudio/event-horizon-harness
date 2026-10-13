"""Sixth Firecracker guest/vsock experiment: commit AFTER gateway SIGKILL.

The trusted supervisor holds a PRIVATE recipient pause pipe. Only an exact
authorized guest request arms the fault. The recipient announces that it has
accepted the effect but has not entered its SQLite transaction. The supervisor
SIGKILLs the real gateway, restarts it and checks both original and fresh
capability denials while the recipient ledger is still empty. Only THEN does
the supervisor release the old request, which must commit exactly once.

This bridge alone is not KVM evidence. The separate KVM run and strict
report verifier must establish hardware guest, guardian and etcd context.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import socket
import tempfile
import threading
import time

from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from scripts.effect_crash_process_supervisor import wait_for_checkpoint
from scripts.effect_crash_recipient import observed_recipient
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.integrated_gateway_process_bridge import RecipientBridgedGateReceiver
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange, GatewayTransportError


PHASE = "inflight_before_commit"


class SixthWindowGateReceiver(RecipientBridgedGateReceiver):
    def __init__(self, channel, recorder, config, target_thread=None):
        super().__init__(channel, recorder, config, target_thread)
        if not all(config.get(k) for k in (
                "expected_request_id", "expected_request_digest",
                "expected_capability_id", "expected_recovery_capability_id",
                "recipient_socket", "recipient_database", "recipient_effect_key",
                "outcome_journal", "verification_context")):
            raise ValueError("sixth window needs pinned gateway and recipient identity")
        self.delayed_recipient_mode = True
        self.delayed_report = None
        self.crashed_gateway_pid = None
        self.recovery_gateway_pid = None
        self.original_replay = None
        self.replacement_replay = None
        # Recipient READY is not sufficient: the KVM guest must not issue
        # negative-control probes before the real gateway is initialized.
        self.gateway_ready = threading.Event()

    def _snapshot(self):
        return observed_recipient(Path(self.config["recipient_database"]))

    def _reservation(self):
        return DurableEffectJournal(self.config["outcome_journal"]).observe(
            tenant=self.config["verification_context"]["tenant"],
            environment=self.config["verification_context"]["environment"],
            capability_id=self.config["expected_capability_id"],
        )

    def _signed(self, event_type, payload):
        self.receipts.append(self.recorder.append(
            event_type, payload, source_id="host-supervisor",
        )["receipt"])

    def _run_gateway(self):
        gateway = sock = evidence = relay = None
        killed = False
        pending = None
        pending_result = {}
        try:
            if self.target_thread is not None:
                self.target_thread.start()
            with tempfile.TemporaryDirectory(prefix="ehh-sixth-gateway-") as folder:
                path = Path(folder) / "trusted.json"
                path.write_bytes(canonical_bytes({
                    "boundary": self.config,
                    "recorder_path": str(Path(folder) / "not-used.jsonl"),
                }))
                path.chmod(0o600)

                def launch(recovery=False):
                    nonlocal gateway, sock, evidence, relay
                    gateway, sock, evidence = start_effect_gateway(
                        path, recorder_bridge=True, ready_stdout=True,
                    )
                    # Do not conflate recipient readiness with gateway
                    # readiness. A cold etcd/credential initialization can
                    # outlive the guest's first three-second effect deadline.
                    # The marker originates inside the gateway after its
                    # trusted verifier + journal have been constructed.
                    readable, _, _ = select.select([gateway.stdout], [], [], 12)
                    line = gateway.stdout.readline().strip() if readable else b""
                    if line != b"READY" or gateway.poll() is not None:
                        stderr = b""
                        if gateway.poll() is not None and gateway.stderr is not None:
                            stderr = gateway.stderr.read(2048)
                        raise RuntimeError(
                            "real gateway did not reach trusted READY: "
                            + repr(line) + " " + stderr.decode("utf-8", errors="replace")
                        )
                    if gateway.pid == os.getpid():
                        raise RuntimeError("gateway not an independent process")
                    self.gateway_pid = gateway.pid
                    self.gateway_process = gateway
                    self.gateway_pidfd = os.pidfd_open(gateway.pid)
                    self.event_contract = GatewayEventContract(
                        gateway_pid=gateway.pid,
                        request_digest=self.config["expected_request_digest"],
                        request_id=self.config["expected_request_id"],
                        capability_id=self.config[
                            "expected_recovery_capability_id" if recovery
                            else "expected_capability_id"
                        ],
                    )
                    relay = threading.Thread(
                        target=self._record_events, args=(evidence,), daemon=True,
                    )
                    relay.start()

                def close_child():
                    nonlocal gateway, sock, evidence, relay
                    if sock is not None:
                        sock.close()
                        sock = None
                    if gateway is not None:
                        if gateway.poll() is None:
                            gateway.kill()
                        gateway.wait(timeout=5)
                        if gateway.stdout is not None:
                            gateway.stdout.close()
                        if gateway.stderr is not None:
                            gateway.stderr.close()
                        gateway = None
                    if relay is not None:
                        relay.join(timeout=5)
                        if relay.is_alive():
                            raise RuntimeError("sixth-window recorder relay still active")
                        relay = None
                    if evidence is not None:
                        evidence.close()
                        evidence = None
                    if self.gateway_pidfd is not None:
                        os.close(self.gateway_pidfd)
                        self.gateway_pidfd = None
                    if self.record_failure is not None:
                        raise RuntimeError("sixth-window recorder rejected child evidence") from self.record_failure

                launch()
                self.gateway_ready.set()
                self.crashed_gateway_pid = gateway.pid
                before = self._snapshot()
                if before["count"] != 0:
                    raise RuntimeError("recipient ledger not empty before first request")

                def target(message):
                    try:
                        req = ActionRequest.from_dict(message["request"])
                        return (
                            req.request_digest == self.config["expected_request_digest"]
                            and message["capability"]["claims"]["capability_id"]
                            == self.config["expected_capability_id"]
                        )
                    except (KeyError, TypeError, ValueError, AttributeError):
                        return False

                with self.channel, self.channel.makefile("rb") as stream:
                    for _ in range(24):
                        try:
                            message = read_frame(stream)
                        except EOFError:
                            break
                        if self.record_failure is not None:
                            raise RuntimeError("signing bridge already failed") from self.record_failure
                        self.event_contract.begin_request(message)
                        try:
                            if not killed and target(message):
                                if pending is not None:
                                    raise RuntimeError("second authorized target")
                                def dispatch():
                                    try:
                                        pending_result["value"] = exchange(sock, message)
                                    except BaseException as exc:
                                        pending_result["error"] = exc
                                pending = threading.Thread(target=dispatch, daemon=True)
                                pending.start()
                                # Real *recipient* checkpoint, not gateway stub.
                                wait_for_checkpoint(
                                    self.recipient_process, PHASE, timeout=9,
                                )
                                if gateway.poll() is not None or self.recipient_process.poll() is not None:
                                    raise RuntimeError("gateway/recipient not alive at inflight barrier")
                                paused = self._snapshot()
                                row = self._reservation()
                                if (paused != before or row is None
                                        or row["state"] != "possibly-committed"
                                        or row["request_digest"] != self.config["expected_request_digest"]):
                                    raise RuntimeError("no durable reservation with zero in-flight commits")
                                self._signed("recipient.inflight-observed", {
                                    "phase": PHASE,
                                    "gateway_pid": gateway.pid,
                                    "recipient_pid": self.recipient_pid,
                                    "recipient_before": before,
                                    "recipient_at_pause": paused,
                                    "journal_state": row["state"],
                                    "effect_key": self.config["recipient_effect_key"],
                                    "request_digest": self.config["expected_request_digest"],
                                })
                                # Bound to the exact child PIDFD, after
                                # receiving a genuine recipient checkpoint.
                                old_pid = gateway.pid
                                gateway.kill()
                                code = gateway.wait(timeout=5)
                                if code != -signal.SIGKILL or old_pid != self.crashed_gateway_pid:
                                    raise RuntimeError("gateway not independently SIGKILLed")
                                killed = True
                                pending.join(timeout=4)
                                if pending.is_alive() or "value" in pending_result or not isinstance(
                                        pending_result.get("error"), GatewayTransportError):
                                    raise RuntimeError("gateway did not fail closed on real SIGKILL")
                                after_kill = self._snapshot()
                                if after_kill != before or self._reservation() != row:
                                    raise RuntimeError("recipient advanced before supervisor release")
                                self._signed("gateway.delayed-sigkill-observed", {
                                    "phase": PHASE, "gateway_pid": old_pid,
                                    "signal": signal.SIGKILL, "exit_code": code,
                                    "recipient_at_kill": after_kill,
                                    "journal_state": row["state"],
                                })
                                response = {
                                    "success": False, "operation": "object.read",
                                    "resource_id": message["request"]["resource_id"],
                                    "output": None, "output_bytes": 0,
                                    "error": "gateway-killed",
                                    "effect_state": "possibly-committed",
                                }
                            else:
                                if killed and self.recovery_gateway_pid is None:
                                    raise RuntimeError("guest replay reached dead gateway")
                                response = exchange(sock, message)
                                if killed and self.original_replay is None:
                                    if response.get("success") is not False or response.get("error") != "authority-denied":
                                        raise RuntimeError("original capability replay accepted")
                                    self.original_replay = {
                                        "success": response["success"], "error": response["error"],
                                    }
                                elif killed and self.replacement_replay is None:
                                    if (response.get("success") is not False
                                            or response.get("effect_state") != "possibly-committed"
                                            or response.get("error") != "prior-effect-unknown"):
                                        raise RuntimeError("fresh signed capability escaped reservation")
                                    self.replacement_replay = {
                                        "success": response["success"],
                                        "effect_state": response["effect_state"],
                                        "error": response["error"],
                                    }
                        finally:
                            self.event_contract.end_request()
                        self.channel.sendall(encode_frame(response))
                        if killed and self.recovery_gateway_pid is None:
                            close_child()
                            launch(recovery=True)
                            self.recovery_gateway_pid = gateway.pid
                        if self.replacement_replay is not None and self.delayed_report is None:
                            # This is the crucial observation: both denials
                            # happened while the recipient STILL had 0 commits.
                            empty = self._snapshot()
                            if empty != before or self._reservation() != row:
                                raise RuntimeError("recipient commit occurred before replay fences")
                            self.release_delayed_recipient()
                            deadline = time.monotonic() + 5
                            while time.monotonic() < deadline and self._snapshot()["count"] == 0:
                                if self.recipient_process.poll() is not None:
                                    raise RuntimeError("in-flight recipient died after release")
                                time.sleep(0.02)
                            final = self._snapshot()
                            if (final["count"] != 1
                                    or final["rows_digest"] != digest([[
                                        self.config["recipient_effect_key"],
                                        self.config["expected_request_digest"],
                                    ]])
                                    or self.recipient_process.poll() is not None
                                    or self._reservation() != row):
                                raise RuntimeError("late durable commit count or reservation changed")
                            self.delayed_report = {
                                "phase": PHASE,
                                "killed_gateway_pid": self.crashed_gateway_pid,
                                "recovery_gateway_pid": self.recovery_gateway_pid,
                                "recipient_pid": self.recipient_pid,
                                "signal": signal.SIGKILL,
                                "exit_code": -signal.SIGKILL,
                                "before": before,
                                "at_pause": paused,
                                "after_kill": after_kill,
                                "before_release": empty,
                                "after_release": final,
                                "journal_state": row["state"],
                                "request_digest": self.config["expected_request_digest"],
                                "effect_key": self.config["recipient_effect_key"],
                                "original_replay": self.original_replay,
                                "replacement_replay": self.replacement_replay,
                                "recipient_release_confirmed": True,
                            }
                            self._signed("recipient.delayed-commit-observed", self.delayed_report)
                    # Guest may close without receiving a success; report is
                    # trustworthy only if all three signed observations exist.
                if not killed or self.delayed_report is None:
                    raise RuntimeError("sixth-window supervisor did not complete late commit")
                if self.dispatches != 1 or self.gateway_event_pid != self.crashed_gateway_pid:
                    raise RuntimeError("original child dispatch not independently recorded")
                close_child()
        except BaseException as exc:
            if self.failure is None:
                self.failure = exc
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.channel.close()
        finally:
            if pending is not None:
                pending.join(timeout=4)
                if pending.is_alive() and self.failure is None:
                    self.failure = RuntimeError("gateway dispatch still running")
            if sock is not None:
                sock.close()
            if gateway is not None:
                if gateway.poll() is None:
                    gateway.kill()
                gateway.wait(timeout=5)
                if gateway.stdout is not None:
                    gateway.stdout.close()
                if gateway.stderr is not None:
                    gateway.stderr.close()
            if evidence is not None:
                evidence.close()
            if relay is not None:
                relay.join(timeout=5)
                if relay.is_alive() and self.failure is None:
                    self.failure = RuntimeError("event relay not terminated")
            if self.gateway_pidfd is not None:
                os.close(self.gateway_pidfd)
                self.gateway_pidfd = None
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure
