"""Real Firecracker guest-triggered lost ACK, with live recipient and gateway.

The supervisor selects a PRIVATE one-shot receipt drop at the recipient's
after-commit-before-reply checkpoint. No SIGKILL is injected. Absence of ACK
never permits dedupe-key release or a claim of non-commit. The guest must
submit a NEW guardian-signed capability and receive the ORIGINAL receipt.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import tempfile
import threading

from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange
from scripts.kvm_fenced_recipient_bridge import FencedRecipientKvmReceiver


class KvmLostAckReceiver(FencedRecipientKvmReceiver):
    """Never interrupt the independent recipient or the trusted gateway."""

    def __init__(self, channel, recorder, config, target_thread=None):
        if (not config.get("fenced_recipient")
                or not config.get("expected_recovery_capability_id")
                or not config.get("expected_signed_effect_message_digest")):
            raise ValueError("lost ACK lab requires exact pinned signed original and recovery")
        super().__init__(channel, recorder, config, target_thread)
        self.recipient_fault_phase = "drop_ack_after_commit"
        self.gateway_ready = threading.Event()
        self.ack_loss_report = None
        self.recovery_report = None

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
        child = request_channel = recorder_channel = relay = None
        try:
            if self.target_thread is not None:
                self.target_thread.start()
            with tempfile.TemporaryDirectory(prefix="ehh-kvm-lost-ack-") as folder:
                cfg = Path(folder) / "trusted.json"
                cfg.write_bytes(canonical_bytes({
                    "boundary": self.config,
                    "recorder_path": str(Path(folder) / "unused.jsonl"),
                }))
                cfg.chmod(0o600)
                child, request_channel, recorder_channel = start_effect_gateway(
                    cfg, recorder_bridge=True, ready_stdout=True,
                )
                self.gateway_process, self.gateway_pid = child, child.pid
                if child.pid in (os.getpid(), self.recipient_pid):
                    raise RuntimeError("trusted gateway and recipient are not separate")
                self.gateway_pidfd = os.pidfd_open(child.pid)
                ready, _, _ = select.select([child.stdout], [], [], 12)
                greeting = child.stdout.readline().strip() if ready else b""
                if greeting != b"READY" or child.poll() is not None:
                    raise RuntimeError("lost ACK gateway did not become ready")
                self.event_contract = GatewayEventContract(
                    gateway_pid=child.pid,
                    request_digest=self.config["expected_request_digest"],
                    request_id=self.config["expected_request_id"],
                    capability_id=self.config["expected_capability_id"],
                    fenced_recipient_id=self.config["fenced_recipient"]["recipient_id"],
                    fenced_original_capability_id=self.config["expected_capability_id"],
                )
                relay = threading.Thread(
                    target=self._record_events, args=(recorder_channel,),
                    daemon=True,
                )
                relay.start()
                self.gateway_ready.set()
                if self._ledger().commit_count():
                    raise RuntimeError("lost ACK ledger already contains the effect")
                seen = False
                original_replay = recovered_reply = None
                with self.channel, self.channel.makefile("rb") as guest_stream:
                    for _ in range(24):
                        try:
                            message = read_frame(guest_stream)
                        except EOFError:
                            break
                        if self.record_failure is not None:
                            raise RuntimeError("host signed recorder rejected gateway events")
                        self.event_contract.begin_request(message)
                        try:
                            answer = exchange(request_channel, message)
                        finally:
                            self.event_contract.end_request()
                        is_original = False
                        try:
                            request = ActionRequest.from_dict(message["request"])
                            is_original = (
                                not seen
                                and request.request_digest == self.config["expected_request_digest"]
                                and message["capability"]["claims"]["capability_id"]
                                == self.config["expected_capability_id"]
                                and digest(message)
                                == self.config["expected_signed_effect_message_digest"]
                            )
                        except (ValueError, TypeError, KeyError, AttributeError):
                            pass
                        if is_original:
                            recipient = self.recipient_process
                            if recipient is None or recipient.poll() is not None:
                                raise RuntimeError("recipient died instead of suppressing ACK")
                            ready, _, _ = select.select([recipient.stdout], [], [], 8)
                            marker = recipient.stdout.readline().strip() if ready else b""
                            if marker != b"DROPPED:drop_ack_after_commit":
                                raise RuntimeError("no independently observed post-commit ACK drop")
                            if (answer.get("success") is not False
                                    or answer.get("effect_state") != "possibly-committed"
                                    or answer.get("error") != "recipient-indeterminate"):
                                raise RuntimeError("missing ACK incorrectly treated as completed or not-started")
                            binding = self._binding()
                            ledger = self._ledger()
                            record = ledger.observe(
                                effect_key=self.config["recipient_effect_key"],
                                request_digest=self.config["expected_request_digest"],
                            )
                            if (ledger.commit_count() != 1 or record is None
                                    or binding is None or binding["state"] != "possibly-committed"
                                    or binding["capability_id"] != self.config["expected_capability_id"]
                                    or binding["request_digest"] != self.config["expected_request_digest"]):
                                raise RuntimeError("missing ACK does not have independently durable effect")
                            self.ack_loss_report = {
                                "phase": "drop_ack_after_commit",
                                "gateway_pid": child.pid,
                                "recipient_pid": recipient.pid,
                                "recipient_alive_after_drop": recipient.poll() is None,
                                "gateway_alive_after_drop": child.poll() is None,
                                "recipient_count_at_drop": 1,
                                "journal_state": binding["state"],
                                "original_capability_id": binding["capability_id"],
                                "request_digest": self.config["expected_request_digest"],
                                "effect_key": self.config["recipient_effect_key"],
                                "receipt_digest_before_ack": record.receipt_digest,
                            }
                            self.receipts.append(self.recorder.append(
                                "fenced.recipient-ack-lost-observed",
                                self.ack_loss_report, source_id="host-supervisor",
                            )["receipt"])
                            seen = True
                        elif seen and original_replay is None:
                            original_replay = answer
                        elif seen and recovered_reply is None:
                            recovered_reply = answer
                        self.channel.sendall(encode_frame(answer))
                if not seen or original_replay is None or recovered_reply is None:
                    raise RuntimeError("no guest-originated original/replay/recovery sequence")
                ledger = self._ledger()
                binding = self._binding()
                record = ledger.observe(
                    effect_key=self.config["recipient_effect_key"],
                    request_digest=self.config["expected_request_digest"],
                )
                if (child.poll() is not None or self.recipient_process.poll() is not None
                        or ledger.commit_count() != 1 or record is None
                        or binding is None or binding["state"] != "recipient-confirmed"
                        or binding["capability_id"] != self.config["expected_capability_id"]
                        or binding["receipt_digest"] != record.receipt_digest
                        or self.ack_loss_report["receipt_digest_before_ack"] != record.receipt_digest
                        or original_replay.get("error") != "authority-denied"
                        or original_replay.get("success") is not False
                        or recovered_reply.get("success") is not True
                        or recovered_reply.get("effect_state") != "completed"
                        or recovered_reply.get("output") !=
                        self.config["dataset"][self.config["fenced_output_offset"]:
                                               self.config["fenced_output_offset"] +
                                               self.config["fenced_output_length"]]
                        or self.record_failure is not None):
                    raise RuntimeError("fresh signed ACK recovery did not preserve one original commit")
                self.recovery_report = {
                    "phase": "drop_ack_after_commit",
                    "gateway_pid": child.pid,
                    "recipient_pid": self.recipient_pid,
                    "recipient_alive_after_recovery": True,
                    "gateway_alive_after_recovery": True,
                    "row_count": 1,
                    "commit_sequence": record.sequence,
                    "receipt_digest": record.receipt_digest,
                    "output_digest": record.output_digest,
                    "original_capability_id": binding["capability_id"],
                    "recovery_capability_id": self.config["expected_recovery_capability_id"],
                    "new_commit_on_recovery": False,
                    "journal_state": binding["state"],
                    "original_replay": {"success": False, "error": "authority-denied"},
                    "fresh_recovery": {"success": True, "effect_state": "completed"},
                }
                self.receipts.append(self.recorder.append(
                    "fenced.ack-recovered-observed", self.recovery_report,
                    source_id="host-supervisor",
                )["receipt"])
        except BaseException as exc:
            if self.failure is None:
                self.failure = exc
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.channel.close()
        finally:
            if request_channel is not None:
                request_channel.close()
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()
            if recorder_channel is not None:
                recorder_channel.close()
            if relay is not None:
                relay.join(timeout=5)
                if relay.is_alive() and self.failure is None:
                    self.failure = RuntimeError("ACK-loss signed relay was not reaped")
            if self.gateway_pidfd is not None:
                os.close(self.gateway_pidfd)
                self.gateway_pidfd = None
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure
