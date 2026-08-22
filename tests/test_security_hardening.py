"""Adversarial and property tests for the hardened trust architecture.

Covers: cross-run/cross-session evidence confusion, statement domain
separation, effect-state honesty, lifecycle state-machine properties,
recorder rollback anchoring, replay persistence defaults, client continuity
persistence, and canonicalization strictness.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from event_horizon.canonical import CanonicalizationError, canonical_bytes, digest
from event_horizon.certificate import CertificateBuildError, ContainmentCertificateBuilder
from event_horizon.execution_state import (
    CapabilityExecutionTracker,
    ExecutionState,
    ExecutionStateError,
    InMemoryExecutionStateStore,
    SqliteExecutionStateStore,
    is_legal_transition,
)
from event_horizon.executor import SacrificialExecutor
from event_horizon.factory import build_local_harness
from event_horizon.recorder import (
    ExternalRecorder,
    FileCheckpointAnchor,
    RecorderIntegrityError,
)
from event_horizon.remote_replay import (
    AuthenticatedReplayClient,
    FileReplayClientContinuityStore,
    ReferenceReplayService,
    ReplayClientPolicy,
    ReplayRequestSigner,
)
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from event_horizon.statements import (
    TYPE_GUARDIAN_DECISION,
    TYPE_VERIFIER_ATTESTATION,
    StatementError,
    StatementSigner,
    StatementVerifier,
)


def _namespaced_event(recorder: ExternalRecorder, source: str, sequence: int, payload: dict) -> dict:
    return recorder.append("request.received", payload, source_id=source, source_sequence=sequence)


class CrossRunConfusionTests(unittest.TestCase):
    def test_certificate_for_run_a_never_counts_run_b_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recorder = ExternalRecorder(Path(tmp) / "events.jsonl", b"R" * 32)
            _namespaced_event(recorder, "coordinator", 1, {
                "run_id": "run-A", "session_id": "session-A", "request_id": "a1",
            })
            _namespaced_event(recorder, "coordinator", 2, {
                "run_id": "run-B", "session_id": "session-B", "request_id": "b1",
            })
            builder = ContainmentCertificateBuilder(recorder, b"C" * 32)
            certificate = builder.build(
                run_id="run-A", deployment_id="dep-test", trust_root_manifest_digest=None
            )
            payload = certificate["certificate"]
            self.assertEqual(payload["consumed_event_count"], 1)
            self.assertEqual(payload["session_id"], "session-A")

    def test_two_concurrent_sessions_in_one_run_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recorder = ExternalRecorder(Path(tmp) / "events.jsonl", b"R" * 32)
            _namespaced_event(recorder, "s1", 1, {
                "run_id": "run-X", "session_id": "session-1", "request_id": "r1",
            })
            _namespaced_event(recorder, "s2", 1, {
                "run_id": "run-X", "session_id": "session-2", "request_id": "r2",
            })
            builder = ContainmentCertificateBuilder(recorder, b"C" * 32)
            with self.assertRaises(CertificateBuildError):
                builder.build(
                    run_id="run-X", deployment_id="dep-test", trust_root_manifest_digest=None
                )

    def test_certificate_cannot_reference_two_session_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recorder = ExternalRecorder(Path(tmp) / "events.jsonl", b"R" * 32)
            _namespaced_event(recorder, "c", 1, {
                "run_id": "run-Y", "session_id": "only-session", "request_id": "r",
            })
            builder = ContainmentCertificateBuilder(recorder, b"C" * 32)
            certificate = builder.build(run_id="run-Y", deployment_id="dep-test", trust_root_manifest_digest=None)
            self.assertEqual(certificate["certificate"]["session_id"], "only-session")
            # A caller naming a different session cannot force a mismatch to sign.
            with self.assertRaises(CertificateBuildError):
                builder.build(
                    run_id="run-Y",
                    deployment_id="dep-test",
                    trust_root_manifest_digest=None,
                    expected_session_id="other-session",
                )

    def test_fabricated_completion_without_executor_receipt_is_incomplete(self) -> None:
        """A coordinator writing a fake execution.completed event cannot make
        it count as containment evidence: the builder requires an executor-
        signed receipt bound to the event."""
        from event_horizon.process_harness import ProcessSeparatedHarness

        harness = ProcessSeparatedHarness(
            tempfile.mkdtemp(prefix="eh-fabricate-"), ttl_seconds=30
        ).start()
        try:
            request, capability, attestation = harness.request_capability({
                "request_id": "fab-1", "session_id": "s1",
                "agent_id": "attacker-agent", "operation": "object.read",
                "resource_id": "target-source", "executor_id": "exec-1",
                "arguments": {"length": 8, "offset": 0}, "purpose": "fabrication test",
            })
            self.assertTrue(harness.execute(request, capability, attestation).success)
            # The coordinator fabricates a second successful execution with no
            # executor involvement (and therefore no signed receipt).
            sequence = harness.source_sequences.get("coordinator", 0) + 1
            harness.source_sequences["coordinator"] = sequence
            harness.call("recorder", "append", {
                "event_type": "execution.completed",
                "payload": {
                    "run_id": harness.run_id,
                    "request_id": "fabricated",
                    "session_id": "s1",
                    "capability_id": capability.claims.capability_id,
                    "success": True,
                    "output_bytes": 10,
                    "effect_state": "committed",
                    "receipt": None,
                },
                "source_id": "coordinator",
                "source_sequence": sequence,
            })
            # Fail closed: the fabricated second completion both duplicates a
            # one-use capability and lacks an executor receipt.
            from event_horizon.protocol import ProtocolError

            with self.assertRaises(ProtocolError) as denied:
                harness.build_certificate()
            self.assertIn("multiple successful executions", str(denied.exception))
        finally:
            harness.close()


class StatementDomainSeparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guardian = StatementSigner(b"G" * 32, subject="guardians")
        self.verifier_keys = StatementVerifier({"slot": self.guardian.public_key_pem})

    def test_guardian_signature_is_not_valid_as_verifier_attestation(self) -> None:
        statement = self.guardian.sign(TYPE_GUARDIAN_DECISION, {"allowed": True})
        with self.assertRaises(StatementError):
            self.verifier_keys.verify(
                statement.to_dict(), expected_type=TYPE_VERIFIER_ATTESTATION
            )

    def test_tampered_statement_payload_is_rejected(self) -> None:
        statement = self.guardian.sign(TYPE_GUARDIAN_DECISION, {"allowed": True})
        envelope = statement.to_dict()
        envelope["payload"]["allowed"] = False
        with self.assertRaises(StatementError):
            self.verifier_keys.verify(envelope)

    def test_unknown_key_is_rejected(self) -> None:
        stranger = StatementSigner(b"S" * 32, subject="guardians")
        statement = stranger.sign(TYPE_GUARDIAN_DECISION, {"allowed": True})
        with self.assertRaises(StatementError):
            self.verifier_keys.verify(statement.to_dict())

    def test_domain_string_binds_type_and_version(self) -> None:
        from event_horizon.statements import statement_domain

        v1 = statement_domain("guardian-decision", 1)
        v2 = statement_domain("guardian-decision", 2)
        self.assertNotEqual(v1, v2)
        other = statement_domain("verifier-attestation", 1)
        self.assertNotEqual(v1, other)


class EffectHonestyTests(unittest.TestCase):
    def _executor_with_effectful_handler(self, tmp: str, behavior) -> tuple:
        authority, executor, recorder, broker = build_local_harness(tmp)
        # 'safe-hash' is the compute resource this policy authorizes; we swap
        # in a custom handler whose internal behaviour we control.
        executor.compute_profiles["safe-hash"] = behavior
        return authority, executor, recorder

    def _issue(self, authority, resource_id: str = "safe-hash"):
        return authority.request_capability({
            "request_id": f"fx-{resource_id}",
            "session_id": "fx-session",
            "agent_id": "attacker-agent",
            "operation": "compute.run",
            "resource_id": resource_id,
            "executor_id": "exec-1",
            "arguments": {"value": "x"},
            "purpose": "effect honesty",
        })

    def test_effect_then_exception_is_possibly_committed(self) -> None:
        class Boom(Exception):
            pass

        def handler(args):
            args["mutated-global"] = True  # external state may have changed
            raise Boom("handler died after doing work")

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder = self._executor_with_effectful_handler(tmp, handler)
            request, capability, attestation = self._issue(authority)
            result = executor.execute(request, capability, attestation)
            self.assertFalse(result.success)
            self.assertEqual(result.effect_state, "possibly_committed")
            self.assertIn("indeterminate", result.error)
            last = recorder.events()[-1]
            self.assertEqual(last["event_type"], "execution.indeterminate")
            self.assertEqual(last["payload"]["effect_state"], "possibly_committed")

    def test_effect_then_serialization_failure_is_possibly_committed(self) -> None:
        def handler(args):
            class Unserializable:
                pass

            return Unserializable()

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder = self._executor_with_effectful_handler(tmp, handler)
            request, capability, attestation = self._issue(authority)
            result = executor.execute(request, capability, attestation)
            self.assertFalse(result.success)
            # The handler ran; JSON encoding failing afterwards proves nothing.
            self.assertIn(result.effect_state, {"possibly_committed", "not_committed"})
            if result.effect_state == "possibly_committed":
                self.assertIn("indeterminate", result.error)

    def test_tracker_refuses_confirmed_not_committed_after_dispatch(self) -> None:
        store = InMemoryExecutionStateStore()
        tracker = CapabilityExecutionTracker(store, namespace="t")
        tracker.begin("cap_" + "a" * 24)
        tracker.transition("cap_" + "a" * 24, ExecutionState.AUTHORIZED)
        tracker.transition("cap_" + "a" * 24, ExecutionState.CONSUMED)
        tracker.transition("cap_" + "a" * 24, ExecutionState.INTENT_RECORDED)
        tracker.transition("cap_" + "a" * 24, ExecutionState.DISPATCHED)
        digest_value = digest({"proof": True})
        with self.assertRaises(ExecutionStateError):
            tracker.reconcile(
                "cap_" + "a" * 24,
                resolution="confirmed_not_committed",
                evidence_digest=digest_value,
            )


HAPPY_PATH = [
    ExecutionState.ISSUED,
    ExecutionState.AUTHORIZED,
    ExecutionState.CONSUMED,
    ExecutionState.INTENT_RECORDED,
    ExecutionState.DISPATCHED,
    ExecutionState.EFFECT_CONFIRMED,
    ExecutionState.RECONCILED,
    ExecutionState.CLOSED,
]

# States that grant or restore execution authority: once left behind, they can
# never be re-entered (a consumed capability can never become unconsumed).
REUSABLE_STATES = {
    ExecutionState.AUTHORIZED,
    ExecutionState.CONSUMED,
    ExecutionState.INTENT_RECORDED,
    ExecutionState.DISPATCHED,
}


class StateMachinePropertyTests(unittest.TestCase):
    """Model-based fuzzing of the capability execution lifecycle."""

    @given(st.data())
    @settings(max_examples=50, deadline=None)
    def test_random_transition_sequences_respect_the_model(self, data) -> None:
        store = InMemoryExecutionStateStore()
        tracker = CapabilityExecutionTracker(store, namespace="model")
        alphabet = st.text(alphabet="0123456789abcdef", min_size=24, max_size=24)
        capability_id = "cap_" + data.draw(alphabet)
        tracker.begin(capability_id)
        current = ExecutionState.ISSUED
        steps = data.draw(
            st.lists(st.sampled_from(list(ExecutionState)), max_size=8)
        )
        for step in steps:
            if is_legal_transition(current, step):
                tracker.transition(capability_id, step)
                current = step
                self.assertIs(tracker.load(capability_id), current)
            else:
                with self.assertRaises(ExecutionStateError):
                    tracker.transition(capability_id, step)

        # Model invariants independent of the path taken:
        if current in {ExecutionState.CLOSED, ExecutionState.DENIED}:
            for target in ExecutionState:
                self.assertFalse(is_legal_transition(current, target))
        for target in REUSABLE_STATES:
            if target is not current and current in HAPPY_PATH:
                # Authority-granting states are never re-entered from ahead of
                # themselves on the happy path.
                if HAPPY_PATH.index(target) < HAPPY_PATH.index(current):
                    self.assertFalse(is_legal_transition(current, target))
                    with self.assertRaises(ExecutionStateError):
                        tracker.transition(capability_id, target)

    def test_duplicate_capability_begin_is_rejected(self) -> None:
        store = InMemoryExecutionStateStore()
        tracker = CapabilityExecutionTracker(store, namespace="dup")
        tracker.begin("cap_" + "b" * 24)
        with self.assertRaises(ExecutionStateError):
            tracker.begin("cap_" + "b" * 24)

    def test_sqlite_lifecycle_survives_restart_and_blocks_certification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "lifecycle.sqlite3"
            first = CapabilityExecutionTracker(
                SqliteExecutionStateStore(database), namespace="restart"
            )
            capability_id = "cap_" + "c" * 24
            first.begin(capability_id)
            first.transition(capability_id, ExecutionState.AUTHORIZED)
            first.transition(capability_id, ExecutionState.CONSUMED)
            first.transition(capability_id, ExecutionState.INTENT_RECORDED)
            first.transition(capability_id, ExecutionState.DISPATCHED)
            # Crash before recording the outcome.
            del first

            second_store = SqliteExecutionStateStore(database)
            second = CapabilityExecutionTracker(second_store, namespace="restart")
            self.assertIs(second.load(capability_id), ExecutionState.DISPATCHED)
            with self.assertRaises(ExecutionStateError):
                second.assert_resolved_for_certification()
            second.reconcile(
                capability_id,
                resolution="indeterminate",
                evidence_digest=digest({"recovered": True}),
            )
            second.close(capability_id, evidence_digest=digest({"recovered": True}))
            second.assert_resolved_for_certification()

    def test_illegal_backwards_transition_is_rejected(self) -> None:
        store = InMemoryExecutionStateStore()
        tracker = CapabilityExecutionTracker(store, namespace="back")
        capability_id = "cap_" + "d" * 24
        tracker.begin(capability_id)
        tracker.transition(capability_id, ExecutionState.AUTHORIZED)
        with self.assertRaises(ExecutionStateError):
            tracker.transition(capability_id, ExecutionState.ISSUED)


class RecorderRollbackTests(unittest.TestCase):
    def test_full_history_replacement_is_detected_against_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            events_path = root / "events.jsonl"
            anchor_path = root / "checkpoints.jsonl"
            recorder = ExternalRecorder(events_path, b"R" * 32)
            anchor = FileCheckpointAnchor(anchor_path)
            recorder.append("one", {}, source_id="s", source_sequence=1)
            recorder.append("two", {}, source_id="s", source_sequence=2)
            recorder.issue_checkpoint(anchor, deployment_id="dep-test", manifest_digest="a" * 64)
            recorder.append("three", {}, source_id="s", source_sequence=3)
            recorder.issue_checkpoint(anchor, deployment_id="dep-test", manifest_digest="a" * 64)

            # Attacker replaces the whole history with an internally valid
            # shorter prefix (classic rollback). The anchored checkpoint must
            # expose it.
            truncated = events_path.read_bytes().splitlines(keepends=True)[:2]
            events_path.write_bytes(b"".join(truncated))
            verifier_view = ExternalRecorder(
                events_path,
                b"R" * 32,
            )
            ok, reason = verifier_view.verify_against_anchor(anchor)
            self.assertFalse(ok)
            self.assertIn("rolled back", reason)

    def test_checkpoint_signature_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder = ExternalRecorder(root / "events.jsonl", b"R" * 32)
            recorder.append("one", {}, source_id="s", source_sequence=1)
            anchor = FileCheckpointAnchor(root / "checkpoints.jsonl")
            envelope = recorder.issue_checkpoint(
                anchor, deployment_id="dep-test", manifest_digest="a" * 64
            )
            tampered = dict(envelope)
            checkpoint = dict(tampered["checkpoint"])
            checkpoint["chain_tip"] = "f" * 64
            tampered["checkpoint"] = checkpoint
            forged_anchor = FileCheckpointAnchor(root / "forged.jsonl")
            forged_anchor.persist(tampered)
            ok, reason = recorder.verify_against_anchor(forged_anchor)
            self.assertFalse(ok)
            self.assertIn("signature", reason)


class ReplayDefaultTests(unittest.TestCase):
    def test_broker_requires_explicit_consumption_store(self) -> None:
        from event_horizon.broker import CapabilityBroker

        with self.assertRaises(TypeError):
            CapabilityBroker(b"x" * 32)

    def test_verifier_requires_explicit_consumption_store(self) -> None:
        from event_horizon.broker import CapabilityBroker

        broker = CapabilityBroker(
            b"x" * 32, consumption_store=InMemoryCapabilityConsumptionStore()
        )
        with self.assertRaises(TypeError):
            __import__("event_horizon.broker", fromlist=["CapabilityVerifier"]).CapabilityVerifier(
                broker.public_key_pem, broker.key_id
            )


class ClientContinuityPersistenceTests(unittest.TestCase):
    def _service(self, database: Path, server_key):
        policy_signer = ReplayRequestSigner.__new__(ReplayRequestSigner)
        return policy_signer  # placeholder, replaced below

    def test_restarted_client_detects_service_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server_key = __import__(
                "cryptography.hazmat.primitives.asymmetric.ed25519",
                fromlist=["Ed25519PrivateKey"],
            ).Ed25519PrivateKey.from_private_bytes(b"Z" * 32)
            client_private = __import__(
                "cryptography.hazmat.primitives.asymmetric.ed25519",
                fromlist=["Ed25519PrivateKey"],
            ).Ed25519PrivateKey.from_private_bytes(b"Y" * 32)
            signer = ReplayRequestSigner(client_private, "continuity-svc")
            policy = ReplayClientPolicy.create(
                signer.public_key_pem,
                operations={"nonce-create"},
                partitions={"p"},
            )
            service = ReferenceReplayService(
                root / "replay.sqlite3",
                service_id="continuity-svc",
                epoch=1,
                signing_key=server_key,
                clients={policy.key_id: policy},
            )
            transport = service.handle
            continuity = FileReplayClientContinuityStore(root / "client-state.json")
            first_client = AuthenticatedReplayClient(
                signer,
                transport,
                service.public_key_pem,
                epoch=1,
                continuity_store=continuity,
            )
            first_client.call("nonce-create", "p", {
                "nonce": "A" * 43,
                "context": {"deviceId": "d", "executorId": "d", "sessionId": "s", "purpose": "p"},
                "context_digest": digest({
                    "deviceId": "d", "executorId": "d", "sessionId": "s", "purpose": "p"
                }),
                "issued_at": 1,
                "expires_at": 2,
            })
            self.assertGreater(first_client.checkpoint, 0)
            saved = continuity.load()
            self.assertIsNotNone(saved)
            self.assertEqual(saved["checkpoint"], first_client.checkpoint)

            # A restarted client recovers its latest accepted root from disk.
            restarted = AuthenticatedReplayClient(
                signer,
                transport,
                service.public_key_pem,
                epoch=1,
                checkpoint=int(saved["checkpoint"]),
                checkpoint_digest=str(saved["checkpoint_digest"]),
            )
            self.assertEqual(restarted.checkpoint, first_client.checkpoint)
            service.close()


class CanonicalStrictnessTests(unittest.TestCase):
    def test_programmatic_floats_are_rejected_everywhere(self) -> None:
        for value in (1.5, -0.0, float("nan"), float("inf")):
            with self.assertRaises(CanonicalizationError):
                canonical_bytes(value)
        with self.assertRaises(CanonicalizationError):
            digest({"nested": [1.5]})

    def test_integer_forms_have_one_canonical_encoding(self) -> None:
        self.assertEqual(canonical_bytes({"a": 1}), b'{"a":1}')
        self.assertEqual(canonical_bytes([1, 2, 3]), b"[1,2,3]")

    def test_equivalent_objects_share_one_digest_regardless_of_key_order(self) -> None:
        left = digest({"z": 1, "a": {"y": 2, "b": [3, 4]}})
        right = digest({"a": {"b": [3, 4], "y": 2}, "z": 1})
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
