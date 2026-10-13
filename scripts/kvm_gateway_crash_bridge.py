"""Opt-in real-guest bridge: SIGKILL worker, then recover with the same journal.

This module adds no shortcut to effect authorization. The independently
supervised recipient is launched by RecipientBridgedGateReceiver. Only the
trusted host can choose a checkpoint, send SIGKILL, and sign the observation.
A worker EOF is UNKNOWN until a matching kernel-observed SIGKILL is established.

A passing portable test here is not a Firecracker/KVM evidence claim.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import threading

from event_horizon.canonical import canonical_bytes
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.models import ActionRequest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from scripts.effect_crash_process_supervisor import kill_at_checkpoint
from scripts.effect_crash_recipient import observed_recipient
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.integrated_gateway_process_bridge import RecipientBridgedGateReceiver
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange, GatewayTransportError
from scripts.real_gateway_crash_checkpoints import PHASES


class KvmGatewayCrashReceiver(RecipientBridgedGateReceiver):
    """A distinct experiment; NEVER substitute for the normal v4 bridge."""

    def __init__(self, channel, recorder, config, target_thread=None,
                 *, crash_phase: str, isolated_recipient: bool = True):
        if crash_phase not in PHASES:
            raise ValueError("invalid host-selected gateway crash phase")
        if not config.get("recipient_socket") or not config.get("outcome_journal"):
            raise ValueError("crash campaign requires independent durable recipient")
        super().__init__(channel, recorder, config, target_thread,
                         isolated_recipient=isolated_recipient)
        self.crash_phase = crash_phase
        self.crash_report = None
        self.recovery_report = None
        self.crash_error = None
        self.crashed_gateway_pid = None
        self.recovery_gateway_pid = None
        self.replay_responses = []

    def _run_gateway(self):
        gateway = None
        gateway_sock = None
        witness = None
        relay = None
        kill_thread = None
        try:
            if self.target_thread is not None:
                self.target_thread.start()
            with tempfile.TemporaryDirectory(prefix="ehh-kvm-crash-bridge-") as folder:
                config_path = Path(folder) / "trusted.json"
                config_path.write_bytes(canonical_bytes({
                    "boundary": self.config,
                    "recorder_path": str(Path(folder) / "not-used.jsonl"),
                }))
                config_path.chmod(0o600)

                def launch(*, crash=False):
                    nonlocal gateway, gateway_sock, witness, relay
                    result = start_effect_gateway(
                        config_path, recorder_bridge=True,
                        crash_phase=self.crash_phase if crash else None,
                    )
                    gateway, gateway_sock, witness = result
                    self.gateway_pid = gateway.pid
                    self.gateway_process = gateway
                    if gateway.pid == os.getpid():
                        raise RuntimeError("gateway is not an independent child")
                    self.gateway_pidfd = os.pidfd_open(gateway.pid)
                    initial_cap = (self.config["expected_capability_id"] if crash
                                   else self.config["expected_recovery_capability_id"])
                    self.event_contract = GatewayEventContract(
                        gateway_pid=gateway.pid,
                        request_digest=self.config["expected_request_digest"],
                        request_id=self.config["expected_request_id"],
                        capability_id=initial_cap,
                    )
                    relay = threading.Thread(target=self._record_events, args=(witness,), daemon=True)
                    relay.start()

                def close_gateway():
                    nonlocal gateway, gateway_sock, witness, relay
                    if gateway_sock is not None:
                        gateway_sock.close()
                        gateway_sock = None
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
                            raise RuntimeError("evidence relay did not exit after gateway kill")
                        relay = None
                    if witness is not None:
                        witness.close()
                        witness = None
                    if self.gateway_pidfd is not None:
                        os.close(self.gateway_pidfd)
                        self.gateway_pidfd = None
                    if self.record_failure is not None:
                        raise RuntimeError("gateway evidence bridge rejected event") from self.record_failure

                launch(crash=True)
                self.crashed_gateway_pid = gateway.pid
                before = observed_recipient(Path(self.config["recipient_database"]))
                if before["count"] != 0:
                    raise RuntimeError("recipient was not empty before injected crash")

                outcome = {}
                def crash_worker():
                    try:
                        outcome["kill"] = kill_at_checkpoint(gateway, self.crash_phase,
                                                             timeout=10)
                    except BaseException as exc:
                        outcome["error"] = exc
                def is_authorized_target(request):
                    """Crash only on the exact pinned signed guest request.

                    The integrated KVM lab sends multiple negative controls
                    first, potentially taking longer than the crash deadline.
                    Never start the kill timer on a malformed guest attempt.
                    """
                    try:
                        candidate = ActionRequest.from_dict(request["request"])
                        claims = request["capability"]["claims"]
                        return (
                            candidate.request_digest == self.config["expected_request_digest"]
                            and claims["capability_id"] == self.config["expected_capability_id"]
                        )
                    except (KeyError, TypeError, ValueError, AttributeError):
                        return False

                sent_crash = False
                with self.channel, self.channel.makefile("rb") as stream:
                    for _ in range(24):
                        try:
                            request = read_frame(stream)
                        except EOFError:
                            break
                        if self.record_failure is not None:
                            raise RuntimeError("signed child evidence has failed")
                        if (not sent_crash and kill_thread is None
                                and is_authorized_target(request)):
                            kill_thread = threading.Thread(target=crash_worker, daemon=True)
                            kill_thread.start()
                        self.event_contract.begin_request(request)
                        try:
                            try:
                                response = exchange(gateway_sock, request)
                            except GatewayTransportError as exc:
                                if sent_crash:
                                    raise RuntimeError("gateway died twice") from exc
                                if kill_thread is None:
                                    raise RuntimeError("gateway crashed before authorized phase") from exc
                                kill_thread.join(timeout=12)
                                if kill_thread.is_alive() or "error" in outcome:
                                    raise RuntimeError("no confirmed supervisor SIGKILL") from outcome.get("error")
                                killed = outcome.get("kill")
                                if (killed is None or killed.pid != self.crashed_gateway_pid
                                        or killed.signal != signal.SIGKILL
                                        or killed.exit_code != -signal.SIGKILL
                                        or killed.marker != self.crash_phase):
                                    raise RuntimeError("gateway death is not independently attested SIGKILL")
                                sent_crash = True
                                after = observed_recipient(Path(self.config["recipient_database"]))
                                expected = 0 if self.crash_phase in PHASES[:2] else 1
                                if after["count"] != expected:
                                    raise RuntimeError("recipient commit count contradicts crash checkpoint")
                                self.crash_report = {
                                    "phase": self.crash_phase,
                                    "gateway_pid": killed.pid,
                                    "signal": killed.signal,
                                    "exit_code": killed.exit_code,
                                    "recipient_before": before,
                                    "recipient_after_kill": after,
                                    "expected_commits": expected,
                                }
                                self.receipts.append(self.recorder.append(
                                    "gateway.crash-observed",
                                    self.crash_report, source_id="host-supervisor",
                                )["receipt"])
                                # Reply only with an *ambiguous failure*, never
                                # an invented successful guest effect.
                                bound = request.get("request", {}) if isinstance(request, dict) else {}
                                response = {
                                    "success": False, "operation": "object.read",
                                    "resource_id": bound.get("resource_id", "synthetic-dataset"),
                                    "output": None, "output_bytes": 0,
                                    "error": "gateway-killed",
                                    "effect_state": "possibly-committed",
                                }
                        finally:
                            self.event_contract.end_request()
                        self.channel.sendall(encode_frame(response))
                        if sent_crash and self.recovery_gateway_pid is None:
                            close_gateway()
                            launch(crash=False)
                            self.recovery_gateway_pid = gateway.pid
                        elif sent_crash and self.recovery_gateway_pid is not None:
                            self.replay_responses.append(response)
                if not sent_crash or self.crash_report is None:
                    raise RuntimeError("no host-confirmed SIGKILL: crash run incomplete")
                if self.recovery_gateway_pid is None:
                    raise RuntimeError("gateway was not restarted")
                expected = self.crash_report["expected_commits"]
                after_recovery = observed_recipient(Path(self.config["recipient_database"]))
                if after_recovery != self.crash_report["recipient_after_kill"]:
                    raise RuntimeError("recipient ledger changed during crash recovery")
                state = DurableEffectJournal(self.config["outcome_journal"]).observe(
                    tenant=self.config["verification_context"]["tenant"],
                    environment=self.config["verification_context"]["environment"],
                    capability_id=self.config["expected_capability_id"],
                )
                expected_state = None if self.crash_phase == PHASES[0] else "possibly-committed"
                if (state["state"] if state else None) != expected_state:
                    raise RuntimeError("crashed effect journal contradicts recipient checkpoint")
                if (len(self.replay_responses) != (1 if expected_state is None else 2)
                        or self.replay_responses[0].get("success") is not False
                        or self.replay_responses[0].get("error") != "authority-denied"):
                    raise RuntimeError("consumed original capability was not denied after restart")
                if expected_state is not None and (
                        self.replay_responses[1].get("success") is not False
                        or self.replay_responses[1].get("effect_state") != "possibly-committed"
                        or self.replay_responses[1].get("error") != "prior-effect-unknown"):
                    raise RuntimeError("newly signed capability was not fenced by journal")
                self.recovery_report = {
                    "phase": self.crash_phase,
                    "killed_pid": self.crashed_gateway_pid,
                    "recovery_pid": self.recovery_gateway_pid,
                    "recipient_after_recovery": after_recovery,
                    "journal_state_after_kill": expected_state,
                    "original_replay": {
                        "success": self.replay_responses[0]["success"],
                        "error": self.replay_responses[0]["error"],
                    },
                    "replacement_replay": (None if expected_state is None else {
                        "success": self.replay_responses[1]["success"],
                        "effect_state": self.replay_responses[1]["effect_state"],
                        "error": self.replay_responses[1]["error"],
                    }),
                }
                self.receipts.append(self.recorder.append(
                    "gateway.recovery-observed", self.recovery_report,
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
            if kill_thread is not None:
                kill_thread.join(timeout=12)
                if kill_thread.is_alive() and self.failure is None:
                    self.failure = RuntimeError("crash supervisor failed to terminate")
            if gateway_sock is not None:
                gateway_sock.close()
            if gateway is not None:
                if gateway.poll() is None:
                    gateway.kill()
                gateway.wait(timeout=5)
                if gateway.stdout is not None:
                    gateway.stdout.close()
                if gateway.stderr is not None:
                    gateway.stderr.close()
            if witness is not None:
                witness.close()
            if relay is not None:
                relay.join(timeout=5)
                if relay.is_alive() and self.failure is None:
                    self.failure = RuntimeError("signing relay did not terminate")
            if self.gateway_pidfd is not None:
                os.close(self.gateway_pidfd)
                self.gateway_pidfd = None
            if self.record_failure is not None and self.failure is None:
                self.failure = self.record_failure
