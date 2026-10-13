"""Actual KVM guest-triggered independent recipient SIGKILL/restart campaign.

Two host-supervisor-only fault windows, no guest-selected phase:
 - before_commit: recipient dies prior to SQLite effect transaction;
 - after_commit_before_reply: recipient dies with a durable commit but no ACK.
Fresh, separately signed authority is required to resolve either outcome.
The gateway stays alive: this is NOT the prior gateway-SIGKILL campaign.
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
from scripts.fenced_recipient_restart import (
    pinned_socket_inode, remove_killed_recipient_socket,
)
from scripts.fenced_recipient_service import PHASES as RECIPIENT_PHASES
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import GatewayTransportError
from scripts.kvm_fenced_recipient_bridge import FencedRecipientKvmReceiver


class KvmRecipientCrashReceiver(FencedRecipientKvmReceiver):
    """One pinned recipient process is SIGKILLed and restarted with same DB/ID."""

    def __init__(self, channel, recorder, config, target_thread=None, *, phase):
        if phase not in RECIPIENT_PHASES:
            raise ValueError("unrecognized protected recipient crash checkpoint")
        if (not config.get("expected_recovery_capability_id")
                or not config.get("expected_signed_effect_message_digest")
                or not config.get("fenced_recipient")):
            raise ValueError("recipient crash mode needs pinned signed target and fresh authority")
        super().__init__(channel, recorder, config, target_thread)
        self.recipient_fault_phase = phase
        self.phase = phase
        self.gateway_ready = threading.Event()
        self.crash_report = None
        self.recovery_report = None
        self.original_recipient_pid = None
        self.restarted_recipient_pid = None

    def _binding(self):
        ctx = self.config["verification_context"]
        return DurableEffectJournal(self.config["outcome_journal"]).observe_effect(
            tenant=ctx["tenant"], environment=ctx["environment"],
            effect_key=self.config["recipient_effect_key"],
        )

    def _ledger(self):
        return FencedSqliteRecipient(
            self.config["recipient_database"],
            recipient_id=self.config["fenced_recipient"]["recipient_id"],
        )

    def _run_gateway(self):
        child = request_sock = evidence_sock = evidence_thread = reader = None
        killer = None
        killing = {}
        killed = False
        original_replay = recovery_reply = None
        original_service = self.recipient_process
        try:
            if original_service is None or original_service.poll() is not None:
                raise RuntimeError("recipient not independently ready")
            if self.target_thread is not None:
                self.target_thread.start()
            self.original_recipient_pid = original_service.pid
            sock_path = self.config["fenced_recipient"]["socket_path"]
            socket_inode = pinned_socket_inode(sock_path)
            if self._ledger().commit_count() != 0:
                raise RuntimeError("new KVM recipient lab starts with nonempty effect ledger")
            with tempfile.TemporaryDirectory(prefix="ehh-kvm-recipient-fault-") as directory:
                cfg = Path(directory) / "gateway.json"
                cfg.write_bytes(canonical_bytes({
                    "boundary": self.config,
                    "recorder_path": str(Path(directory) / "unused.jsonl"),
                }))
                cfg.chmod(0o600)
                child, request_sock, evidence_sock = start_effect_gateway(
                    cfg, recorder_bridge=True, ready_stdout=True,
                )
                self.gateway_process = child
                self.gateway_pid = child.pid
                if child.pid in {os.getpid(), self.original_recipient_pid}:
                    raise RuntimeError("recipient, gateway, supervisor share a process identity")
                self.gateway_pidfd = os.pidfd_open(child.pid)
                readable, _, _ = select.select([child.stdout], [], [], 12)
                marker = child.stdout.readline().strip() if readable else b""
                if marker != b"READY" or child.poll() is not None:
                    raise RuntimeError("trusted KVM gateway did not become ready")
                self.event_contract = GatewayEventContract(
                    gateway_pid=child.pid,
                    request_digest=self.config["expected_request_digest"],
                    request_id=self.config["expected_request_id"],
                    capability_id=self.config["expected_capability_id"],
                    fenced_recipient_id=self.config["fenced_recipient"]["recipient_id"],
                    fenced_original_capability_id=self.config["expected_capability_id"],
                )
                evidence_thread = threading.Thread(
                    target=self._record_events, args=(evidence_sock,), daemon=True,
                )
                evidence_thread.start()
                request_sock.settimeout(5)
                reader = request_sock.makefile("rb")
                self.gateway_ready.set()

                def exchange(message):
                    try:
                        request_sock.sendall(encode_frame(message))
                        answer = read_frame(reader)
                    except (OSError, EOFError, ValueError) as exc:
                        raise GatewayTransportError(
                            "original trusted gateway unexpectedly died"
                        ) from exc
                    if type(answer) is not dict:
                        raise GatewayTransportError("malformed trusted gateway response")
                    return answer

                def is_original(message):
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

                def kill_recipient():
                    try:
                        killing["observation"] = kill_at_checkpoint(
                            original_service, self.phase, timeout=12,
                        )
                    except BaseException as exc:
                        killing["error"] = exc

                with self.channel, self.channel.makefile("rb") as guest_stream:
                    for _ in range(24):
                        try:
                            message = read_frame(guest_stream)
                        except EOFError:
                            break
                        if self.record_failure is not None:
                            raise RuntimeError("signed gateway event relay failed")
                        original = not killed and is_original(message)
                        if original:
                            killer = threading.Thread(target=kill_recipient, daemon=True)
                            killer.start()
                        self.event_contract.begin_request(message)
                        try:
                            answer = exchange(message)
                        finally:
                            self.event_contract.end_request()
                        if original:
                            if killer is None:
                                raise RuntimeError("recipient crash was not armed")
                            killer.join(timeout=15)
                            if killer.is_alive() or "error" in killing:
                                raise RuntimeError("independent recipient death not established") from killing.get("error")
                            proof = killing.get("observation")
                            if (proof is None or proof.pid != self.original_recipient_pid
                                    or proof.marker != self.phase
                                    or proof.signal != signal.SIGKILL
                                    or proof.exit_code != -signal.SIGKILL):
                                raise RuntimeError("SIGKILL did not target exact live recipient checkpoint")
                            if (answer.get("success") is not False
                                    or answer.get("effect_state") != "possibly-committed"
                                    or answer.get("error") != "recipient-indeterminate"):
                                raise RuntimeError("recipient loss incorrectly returned certainty")
                            before = self._ledger().commit_count()
                            expected_before = 0 if self.phase == "before_commit" else 1
                            binding = self._binding()
                            if (before != expected_before or binding is None
                                    or binding["capability_id"] != self.config["expected_capability_id"]
                                    or binding["request_digest"] != self.config["expected_request_digest"]
                                    or binding["fenced_protocol"] != "atomic-sqlite-v1"
                                    or binding["fenced_recipient_id"] !=
                                    self.config["fenced_recipient"]["recipient_id"]
                                    or binding["state"] != "possibly-committed"):
                                raise RuntimeError("original fenced reservation/recipient death disagree")
                            self.crash_report = {
                                "phase": self.phase,
                                "gateway_pid": self.gateway_pid,
                                "killed_recipient_pid": proof.pid,
                                "signal": proof.signal,
                                "exit_code": proof.exit_code,
                                "recipient_count_after_kill": before,
                                "effect_key": self.config["recipient_effect_key"],
                                "request_digest": self.config["expected_request_digest"],
                                "original_capability_id": binding["capability_id"],
                                "journal_state": binding["state"],
                            }
                            self.receipts.append(self.recorder.append(
                                "fenced.recipient-sigkill-observed",
                                self.crash_report, source_id="host-supervisor",
                            )["receipt"])
                            cleanup = remove_killed_recipient_socket(
                                original_service, sock_path, expected_inode=socket_inode,
                            )
                            for file in (original_service.stdout, original_service.stderr):
                                if file is not None:
                                    file.close()
                            self._launch_recipient(fault_phase=None)
                            self.restarted_recipient_pid = self.recipient_pid
                            if (self.restarted_recipient_pid == self.original_recipient_pid
                                    or self.recipient_process.poll() is not None):
                                raise RuntimeError("recipient did not restart as a distinct child")
                            self.receipts.append(self.recorder.append(
                                "fenced.recipient-restarted-observed", {
                                    "phase": self.phase,
                                    "killed_recipient_pid": proof.pid,
                                    "restarted_recipient_pid": self.restarted_recipient_pid,
                                    "gateway_pid": self.gateway_pid,
                                    "recipient_id": self.config["fenced_recipient"]["recipient_id"],
                                    "stale_socket_removed": cleanup["stale_socket_removed"],
                                    "prior_socket_inode": cleanup["stale_socket_inode"],
                                    "recipient_count_before_recovery": self._ledger().commit_count(),
                                }, source_id="host-supervisor",
                            )["receipt"])
                            killed = True
                        self.channel.sendall(encode_frame(answer))
                        if killed and not original and original_replay is None:
                            original_replay = answer
                        elif killed and not original and recovery_reply is None:
                            recovery_reply = answer

                if not killed or self.crash_report is None or self.restarted_recipient_pid is None:
                    raise RuntimeError("no actual guest-triggered recipient SIGKILL")
                row = self._ledger().observe(
                    effect_key=self.config["recipient_effect_key"],
                    request_digest=self.config["expected_request_digest"],
                )
                binding = self._binding()
                if (self._ledger().commit_count() != 1 or row is None or
                        binding is None or binding["state"] != "recipient-confirmed"
                        or binding["capability_id"] != self.config["expected_capability_id"]
                        or binding["receipt_digest"] != row.receipt_digest
                        or original_replay is None or original_replay.get("error") != "authority-denied"
                        or recovery_reply is None or recovery_reply.get("success") is not True
                        or recovery_reply.get("output") != row.output
                        or self.record_failure is not None):
                    raise RuntimeError("recipient restart violated at-most-once/fresh-capability recovery")
                self.recovery_report = {
                    "phase": self.phase,
                    "gateway_pid": self.gateway_pid,
                    "killed_recipient_pid": self.original_recipient_pid,
                    "restarted_recipient_pid": self.restarted_recipient_pid,
                    "original_capability_id": binding["capability_id"],
                    "recovery_capability_id": self.config["expected_recovery_capability_id"],
                    "receipt_digest": row.receipt_digest,
                    "output_digest": row.output_digest,
                    "commit_sequence": row.sequence,
                    "row_count": self._ledger().commit_count(),
                    "new_commit_on_recovery": self.phase == "before_commit",
                    "journal_state": binding["state"],
                    "original_replay": {
                        "success": original_replay["success"], "error": original_replay["error"],
                    },
                    "fresh_recovery": {
                        "success": recovery_reply["success"],
                        "effect_state": recovery_reply["effect_state"],
                    },
                }
                self.receipts.append(self.recorder.append(
                    "fenced.recipient-recovery-observed",
                    self.recovery_report, source_id="host-supervisor",
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
            if killer is not None:
                killer.join(timeout=15)
            if reader is not None:
                reader.close()
            if request_sock is not None:
                request_sock.close()
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()
            if evidence_sock is not None:
                evidence_sock.close()
            if evidence_thread is not None:
                evidence_thread.join(timeout=5)
                if evidence_thread.is_alive() and self.failure is None:
                    self.failure = RuntimeError("recipient crash relay thread did not stop")
            if self.gateway_pidfd is not None:
                os.close(self.gateway_pidfd)
                self.gateway_pidfd = None
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure
