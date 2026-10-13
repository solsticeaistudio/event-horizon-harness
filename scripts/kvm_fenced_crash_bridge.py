"""Actual Firecracker guest-triggered gateway SIGKILL, atomic fenced recipient.

Two separate opt-in windows: the gateway dies after original durable fence but
BEFORE recipient apply, or AFTER recipient's atomic commit and BEFORE its own
journal confirmation/client acknowledgement. A distinct newly signed recovery
capability is then consumed through a new gateway process and the SAME
independent recipient process.

This bridge alone is not KVM evidence: the KVM runner and strict signed
hardware report verifier must independently establish guest/guardian/etcd.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import socket
import tempfile
import threading

from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from scripts.effect_crash_process_supervisor import kill_at_checkpoint
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.isolated_effect_gateway_worker import (
    FENCED_KVM_CRASH_PHASES, start_effect_gateway,
)
from scripts.isolated_gateway_transport import exchange, GatewayTransportError
from scripts.kvm_fenced_recipient_bridge import FencedRecipientKvmReceiver


class FencedKvmCrashReceiver(FencedRecipientKvmReceiver):
    def __init__(self, channel, recorder, config, target_thread=None, *, phase: str):
        if phase not in FENCED_KVM_CRASH_PHASES:
            raise ValueError("unknown KVM fenced recipient checkpoint")
        if (not config.get("expected_recovery_capability_id")
                or not config.get("expected_signed_effect_message_digest")
                or not config.get("fenced_recipient")):
            raise ValueError("no host-pinned signed recovery/KVM target")
        super().__init__(channel, recorder, config, target_thread)
        self.phase = phase
        self.gateway_ready = threading.Event()
        self.crash_report = None
        self.recovery_report = None
        self.crashed_gateway_pid = None
        self.recovery_gateway_pid = None

    def _ledger(self):
        return FencedSqliteRecipient(
            self.config["recipient_database"],
            recipient_id=self.config["fenced_recipient"]["recipient_id"],
        )

    def _binding(self):
        ctx = self.config["verification_context"]
        return DurableEffectJournal(self.config["outcome_journal"]).observe_effect(
            tenant=ctx["tenant"], environment=ctx["environment"],
            effect_key=self.config["recipient_effect_key"],
        )

    def _run_gateway(self):
        gateway = channel = recorder_socket = relay = reader = None
        killer = None
        killed = False
        original_replay = recovery_reply = None
        killing = {}
        try:
            if self.target_thread is not None:
                self.target_thread.start()
            with tempfile.TemporaryDirectory(prefix="ehh-kvm-fenced-crash-") as folder:
                config = Path(folder) / "trusted.json"
                config.write_bytes(canonical_bytes({
                    "boundary": self.config,
                    "recorder_path": str(Path(folder) / "unused.jsonl"),
                }))
                config.chmod(0o600)

                def launch(*, recovery=False):
                    nonlocal gateway, channel, recorder_socket, relay, reader
                    gateway, channel, recorder_socket = start_effect_gateway(
                        config, recorder_bridge=True,
                        fenced_crash_phase=None if recovery else self.phase,
                        ready_stdout=True,
                    )
                    self.gateway_process = gateway
                    self.gateway_pid = gateway.pid
                    if gateway.pid == os.getpid() or gateway.pid == self.recipient_pid:
                        raise RuntimeError("recipient and gateway are not distinct processes")
                    self.gateway_pidfd = os.pidfd_open(gateway.pid)
                    ready, _, _ = select.select([gateway.stdout], [], [], 12)
                    line = gateway.stdout.readline().strip() if ready else b""
                    if line != b"READY" or gateway.poll() is not None:
                        raise RuntimeError("fenced gateway never reached trusted READY")
                    channel.settimeout(3)
                    reader = channel.makefile("rb")
                    self.event_contract = GatewayEventContract(
                        gateway_pid=gateway.pid,
                        request_digest=self.config["expected_request_digest"],
                        request_id=self.config["expected_request_id"],
                        capability_id=(
                            self.config["expected_recovery_capability_id"] if recovery
                            else self.config["expected_capability_id"]
                        ),
                        fenced_recipient_id=self.config["fenced_recipient"]["recipient_id"],
                        fenced_original_capability_id=(
                            self.config["expected_capability_id"] if recovery else None
                        ),
                    )
                    relay = threading.Thread(
                        target=self._record_events, args=(recorder_socket,), daemon=True,
                    )
                    relay.start()
                    self.gateway_ready.set()

                def close_gateway():
                    nonlocal gateway, channel, recorder_socket, relay, reader
                    if reader is not None:
                        reader.close()
                        reader = None
                    if channel is not None:
                        channel.close()
                        channel = None
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
                            raise RuntimeError("fenced gateway signed-recorder relay leaked")
                        relay = None
                    if recorder_socket is not None:
                        recorder_socket.close()
                        recorder_socket = None
                    if self.gateway_pidfd is not None:
                        os.close(self.gateway_pidfd)
                        self.gateway_pidfd = None
                    if self.record_failure is not None:
                        raise RuntimeError("gateway evidence contract failed") from self.record_failure

                def exchange_gateway(request):
                    try:
                        if channel is None or reader is None:
                            raise EOFError("no gateway")
                        channel.sendall(encode_frame(request))
                        reply = read_frame(reader)
                    except (OSError, EOFError, ValueError) as exc:
                        raise GatewayTransportError(
                            "fenced gateway channel failed; effect outcome unknown"
                        ) from exc
                    if type(reply) is not dict:
                        raise GatewayTransportError("malformed gateway reply")
                    return reply

                def signed_target(message):
                    try:
                        request = ActionRequest.from_dict(message["request"])
                        return (
                            request.request_digest == self.config["expected_request_digest"]
                            and message["capability"]["claims"]["capability_id"]
                            == self.config["expected_capability_id"]
                            and digest(message)
                            == self.config["expected_signed_effect_message_digest"]
                        )
                    except (KeyError, TypeError, ValueError, AttributeError):
                        return False

                def trigger_kill():
                    try:
                        killing["result"] = kill_at_checkpoint(
                            gateway, self.phase, timeout=12,
                        )
                    except BaseException as exc:
                        killing["error"] = exc

                launch()
                self.crashed_gateway_pid = gateway.pid
                if self._ledger().commit_count() != 0:
                    raise RuntimeError("recipient had effect before signed KVM request")
                with self.channel, self.channel.makefile("rb") as stream:
                    for _ in range(24):
                        try:
                            message = read_frame(stream)
                        except EOFError:
                            break
                        if self.record_failure is not None:
                            raise RuntimeError("supervisor signing already failed") from self.record_failure
                        is_first = not killed and signed_target(message)
                        if is_first:
                            killer = threading.Thread(target=trigger_kill, daemon=True)
                            killer.start()
                        self.event_contract.begin_request(message)
                        try:
                            try:
                                answer = exchange_gateway(message)
                            except GatewayTransportError as exc:
                                if not is_first or killer is None or killed:
                                    raise RuntimeError("unexpected gateway failure") from exc
                                killer.join(timeout=15)
                                if killer.is_alive() or "error" in killing:
                                    raise RuntimeError("supervisor SIGKILL was not established") from killing.get("error")
                                proof = killing.get("result")
                                if (proof is None or proof.pid != self.crashed_gateway_pid
                                        or proof.marker != self.phase
                                        or proof.signal != signal.SIGKILL
                                        or proof.exit_code != -signal.SIGKILL):
                                    raise RuntimeError("gateway did not die at verified SIGKILL checkpoint")
                                killed = True
                                ledger = self._ledger()
                                count = ledger.commit_count()
                                expected = 0 if self.phase == FENCED_KVM_CRASH_PHASES[0] else 1
                                bound = self._binding()
                                if (count != expected or bound is None
                                        or bound["state"] != "possibly-committed"
                                        or bound["fenced_protocol"] != "atomic-sqlite-v1"
                                        or bound["fenced_recipient_id"] !=
                                        self.config["fenced_recipient"]["recipient_id"]
                                        or bound["request_digest"] !=
                                        self.config["expected_request_digest"]
                                        or bound["capability_id"] !=
                                        self.config["expected_capability_id"]):
                                    raise RuntimeError("SIGKILL checkpoint did not preserve original fenced reservation")
                                self.crash_report = {
                                    "phase": self.phase,
                                    "killed_gateway_pid": proof.pid,
                                    "recipient_pid": self.recipient_pid,
                                    "signal": proof.signal,
                                    "exit_code": proof.exit_code,
                                    "request_digest": self.config["expected_request_digest"],
                                    "effect_key": self.config["recipient_effect_key"],
                                    "original_capability_id": bound["capability_id"],
                                    "journal_state": bound["state"],
                                    "recipient_count_after_kill": count,
                                }
                                self.receipts.append(self.recorder.append(
                                    "fenced.gateway-sigkill-observed",
                                    self.crash_report, source_id="host-supervisor",
                                )["receipt"])
                                answer = {
                                    "success": False, "operation": "object.read",
                                    "resource_id": message["request"]["resource_id"],
                                    "output": None, "output_bytes": 0,
                                    "error": "gateway-killed",
                                    "effect_state": "possibly-committed",
                                }
                        finally:
                            self.event_contract.end_request()
                        self.channel.sendall(encode_frame(answer))
                        if killed and self.recovery_gateway_pid is None:
                            close_gateway()
                            launch(recovery=True)
                            self.recovery_gateway_pid = gateway.pid
                        elif killed and original_replay is None:
                            original_replay = answer
                        elif killed and recovery_reply is None:
                            recovery_reply = answer
                if not killed or self.crash_report is None:
                    raise RuntimeError("no signed KVM guest effect triggered original crash")
                if self.recovery_gateway_pid is None or original_replay is None or recovery_reply is None:
                    raise RuntimeError("no actual KVM original replay and fresh recovery responses")
                bound = self._binding()
                ledger = self._ledger()
                observed = ledger.observe(
                    effect_key=self.config["recipient_effect_key"],
                    request_digest=self.config["expected_request_digest"],
                )
                expected_new_commit = self.phase == FENCED_KVM_CRASH_PHASES[0]
                if (ledger.commit_count() != 1 or observed is None
                        or bound is None or bound["state"] != "recipient-confirmed"
                        or bound["capability_id"] != self.config["expected_capability_id"]
                        or bound["receipt_digest"] != observed.receipt_digest
                        or original_replay.get("success") is not False
                        or original_replay.get("error") != "authority-denied"
                        or recovery_reply.get("success") is not True
                        or recovery_reply.get("output") != observed.output
                        or self.record_failure is not None):
                    raise RuntimeError("fresh signed KVM recovery did not safely resolve original effect")
                self.recovery_report = {
                    "phase": self.phase,
                    "killed_gateway_pid": self.crashed_gateway_pid,
                    "recovery_gateway_pid": self.recovery_gateway_pid,
                    "recipient_pid": self.recipient_pid,
                    "original_capability_id": bound["capability_id"],
                    "recovery_capability_id": self.config["expected_recovery_capability_id"],
                    "receipt_digest": observed.receipt_digest,
                    "output_digest": observed.output_digest,
                    "row_count": ledger.commit_count(),
                    "commit_sequence": observed.sequence,
                    "journal_state": bound["state"],
                    "new_commit_on_recovery": expected_new_commit,
                    "original_replay": {
                        "success": original_replay["success"],
                        "error": original_replay["error"],
                    },
                    "fresh_recovery": {
                        "success": recovery_reply["success"],
                        "effect_state": recovery_reply["effect_state"],
                    },
                }
                self.receipts.append(self.recorder.append(
                    "fenced.gateway-recovery-observed",
                    self.recovery_report, source_id="host-supervisor",
                )["receipt"])
                close_gateway()
        except BaseException as exc:
            if self.failure is None:
                self.failure = exc
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.channel.close()
        finally:
            if killer is not None:
                killer.join(timeout=15)
                if killer.is_alive() and self.failure is None:
                    self.failure = RuntimeError("fenced fault-controller worker not terminated")
            if reader is not None:
                reader.close()
            if channel is not None:
                channel.close()
            if gateway is not None:
                if gateway.poll() is None:
                    gateway.kill()
                gateway.wait(timeout=5)
                if gateway.stdout is not None:
                    gateway.stdout.close()
                if gateway.stderr is not None:
                    gateway.stderr.close()
            if recorder_socket is not None:
                recorder_socket.close()
            if relay is not None:
                relay.join(timeout=5)
                if relay.is_alive() and self.failure is None:
                    self.failure = RuntimeError("fenced evidence thread not terminated")
            if self.gateway_pidfd is not None:
                os.close(self.gateway_pidfd)
                self.gateway_pidfd = None
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure
