"""Two distinct trusted gateway OS processes race to recover one KVM guest effect.

The ORIGINAL Firecracker guest executes once and experiences a lost recipient
ACK. The guest presents one freshly signed recovery capability; a second
separately signed, host-pinned capability is dispatched by the trusted
supervisor to a competing gateway child. The competitor is NOT a second
guest-issued request. Both gateways share the exact independently supervised
atomic recipient and durable etcd consumption domain.

This campaign covers an already committed effect only. The separate portable
Linux suite also races recovering a missing commit. Do not claim power-loss,
physical multi-host separation, or arbitrary external HTTP exactly-once.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import threading
import time

from event_horizon.canonical import digest
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.protocol import encode_frame, read_frame
from scripts.gateway_evidence_contract import GatewayEventContract
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.kvm_fenced_ack_loss_bridge import KvmLostAckReceiver


class RecoveryActor:
    """One independent gateway with its own pidfd and signed-recorder contract."""

    def __init__(self, owner, message, capability_id):
        self.owner = owner
        self.message = message
        self.capability_id = capability_id
        self.child = self.channel = self.evidence_channel = self.pidfd = None
        self.relay = None
        self.failure = None
        self.confirmed = []
        self.answer = None
        self.submitted_at = None
        self.replied_at = None

    def launch(self):
        cfg = self.owner._gateway_cfg
        self.child, self.channel, self.evidence_channel = start_effect_gateway(
            cfg, recorder_bridge=True, ready_stdout=True,
        )
        if self.child.pid in (os.getpid(), self.owner.gateway_pid, self.owner.recipient_pid):
            raise RuntimeError("recovery gateway reused trusted host/recipient identity")
        self.pidfd = os.pidfd_open(self.child.pid)
        ready, _, _ = select.select([self.child.stdout], [], [], 12)
        if (not ready or self.child.stdout.readline().strip() != b"READY"
                or self.child.poll() is not None):
            raise RuntimeError("independent recovery gateway did not start")
        self.contract = GatewayEventContract(
            gateway_pid=self.child.pid,
            request_digest=self.owner.config["expected_request_digest"],
            request_id=self.owner.config["expected_request_id"],
            capability_id=self.capability_id,
            fenced_recipient_id=self.owner.config["fenced_recipient"]["recipient_id"],
            fenced_original_capability_id=self.owner.config["expected_capability_id"],
        )
        self.relay = threading.Thread(target=self._relay, daemon=True)
        self.relay.start()

    def _relay(self):
        try:
            with self.evidence_channel.makefile("rb") as stream:
                for _ in range(64):
                    try:
                        event = read_frame(stream)
                    except EOFError:
                        break
                    if (self.child.poll() is not None or self.pidfd is None
                            or select.select([self.pidfd], [], [], 0)[0]):
                        raise RuntimeError("recovery signer event not bound to a live child")
                    self.contract.check(event)
                    if event["event_type"] == "fenced.recipient-confirmed":
                        ledger = FencedSqliteRecipient(
                            self.owner.config["recipient_database"],
                            recipient_id=self.owner.config["fenced_recipient"]["recipient_id"],
                        )
                        row = ledger.observe(
                            effect_key=self.owner.config["recipient_effect_key"],
                            request_digest=self.owner.config["expected_request_digest"],
                        )
                        if (ledger.commit_count() != 1 or row is None
                                or row.receipt_digest != event["payload"]["receipt_digest"]
                                or row.sequence != event["payload"]["commit_sequence"]
                                or event["payload"]["capability_id"] != self.capability_id
                                or event["payload"]["new_effect_commit"] is not False
                                or event["payload"]["recovery"] is not True):
                            raise RuntimeError("racer asserted unverified duplicate/new recipient commit")
                        self.confirmed.append(row.receipt_digest)
                        self.owner.dispatches = 1
                        self.owner.gateway_event_pid = self.child.pid
                    entry = self.owner.recorder.append(
                        event["event_type"], event["payload"],
                        source_id="host-effect-service",
                    )
                    self.owner.receipts.append(entry["receipt"])
                    self.evidence_channel.sendall(encode_frame({"recorded": True}))
        except BaseException as exc:
            self.failure = exc

    def execute(self, barrier):
        try:
            self.channel.settimeout(8)
            barrier.wait(timeout=12)
            self.submitted_at = time.monotonic_ns()
            self.contract.begin_request(self.message)
            try:
                self.channel.sendall(encode_frame(self.message))
                with self.channel.makefile("rb") as stream:
                    self.answer = read_frame(stream)
            finally:
                self.contract.end_request()
            self.replied_at = time.monotonic_ns()
        except BaseException as exc:
            self.failure = exc
            try:
                barrier.abort()
            except Exception:
                pass

    def close(self):
        if self.channel is not None:
            self.channel.close()
        if self.child is not None:
            if self.child.poll() is None:
                self.child.kill()
            self.child.wait(timeout=5)
            if self.child.stdout is not None:
                self.child.stdout.close()
            if self.child.stderr is not None:
                self.child.stderr.close()
        if self.evidence_channel is not None:
            self.evidence_channel.close()
        if self.relay is not None:
            self.relay.join(timeout=5)
            if self.relay.is_alive() and self.failure is None:
                self.failure = RuntimeError("recovery evidence relay was not reaped")
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


class KvmCompetingRecoveryReceiver(KvmLostAckReceiver):
    """Guest-originated lost ACK, two concurrently dispatched signed recoveries."""

    def __init__(self, channel, recorder, config, target_thread=None):
        racer = config.get("racing_message")
        if (type(racer) is not dict or set(racer) != {"request", "capability"}
                or config.get("expected_racing_capability_id")
                != racer.get("capability", {}).get("claims", {}).get("capability_id")
                or digest(racer["request"]) != config.get("expected_request_digest")
                or racer["capability"]["claims"]["capability_id"]
                == config.get("expected_recovery_capability_id")):
            raise ValueError("racing gateway requires distinct pinned signed capabilities")
        super().__init__(channel, recorder, config, target_thread)
        self.actors = []
        self.race_report = None
        self.racing_gateway_pids = []

    def _exchange_guest(self, request_channel, message):
        cap = message.get("capability", {}).get("claims", {}).get("capability_id")
        if (self.ack_loss_report is None
                or cap != self.config["expected_recovery_capability_id"]):
            return super()._exchange_guest(request_channel, message)
        if self.actors:
            raise RuntimeError("recovery race may only be dispatched once")
        if (digest(message["request"]) != self.config["expected_request_digest"]
                or message["request"] != self.config["racing_message"]["request"]):
            raise RuntimeError("racing guest recovery does not match pinned original request")
        actors = [
            RecoveryActor(self, message, self.config["expected_recovery_capability_id"]),
            RecoveryActor(self, self.config["racing_message"],
                          self.config["expected_racing_capability_id"]),
        ]
        self.actors = actors
        for actor in actors:
            actor.launch()
        if actors[0].child.pid == actors[1].child.pid:
            raise RuntimeError("competing recovery gateway processes not distinct")
        self.racing_gateway_pids = [actor.child.pid for actor in actors]
        barrier = threading.Barrier(3)
        threads = [threading.Thread(target=actor.execute, args=(barrier,), daemon=True)
                   for actor in actors]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=12)
        for thread in threads:
            thread.join(timeout=16)
            if thread.is_alive():
                raise RuntimeError("competing recovery request did not reach a bounded outcome")
        for actor in actors:
            if (actor.failure is not None or actor.child.poll() is not None
                    or actor.answer is None or actor.answer.get("success") is not True
                    or actor.answer.get("effect_state") != "completed"
                    or len(actor.confirmed) != 1):
                raise RuntimeError("two independently signed competing recoveries were not both confirmed") from actor.failure
        if (self._ledger().commit_count() != 1
                or actors[0].confirmed[0] != actors[1].confirmed[0]
                or actors[0].submitted_at is None or actors[1].submitted_at is None):
            raise RuntimeError("concurrent recovery did not converge to the same single durable receipt")
        original = self._binding()
        if (original is None or original["state"] != "recipient-confirmed"
                or original["capability_id"] != self.config["expected_capability_id"]
                or original["receipt_digest"] != actors[0].confirmed[0]):
            raise RuntimeError("competing gateways overwrote original provenance")
        self.race_report = {
            "original_gateway_pid": self.gateway_pid,
            "recovery_gateway_pids": self.racing_gateway_pids,
            "recovery_capability_ids": [a.capability_id for a in actors],
            "both_gateways_succeeded": True,
            "independent_gateway_processes": True,
            "host_dispatched_competitor": True,
            "original_guest_recovery_gateway_index": 0,
            "same_recipient_receipt": actors[0].confirmed[0],
            "durable_effect_count": 1,
            "original_capability_id": original["capability_id"],
            "original_effect_key": self.config["recipient_effect_key"],
            "gateway_requests_submitted": 2,
            "recovery_results": [
                {"success": actor.answer["success"],
                 "effect_state": actor.answer["effect_state"],
                 "output_digest": digest(actor.answer["output"])}
                for actor in actors
            ],
        }
        self.receipts.append(self.recorder.append(
            "fenced.competing-recovery-observed", self.race_report,
            source_id="host-supervisor",
        )["receipt"])
        return actors[0].answer

    def _run_gateway(self):
        try:
            super()._run_gateway()
        finally:
            for actor in self.actors:
                actor.close()
                if actor.failure is not None and self.failure is None:
                    self.failure = actor.failure
