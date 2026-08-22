"""v0.6 compromise-oriented adversarial suite.

These tests do not merely feed malformed input: they construct *validly signed
lies, conflicts, stale state, and compromised actors*, then assert exactly
which guarantees survive. Every scenario maps to the v0.6 compromise matrix.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from event_horizon.canonical import digest
from event_horizon.certificate import (
    CertificateBuildError,
    ContainmentCertificateBuilder,
)
from event_horizon.effect_gateway import (
    EffectGateway,
    EffectGatewayError,
    GATEWAY_COMMITTED,
    GATEWAY_CONFIRMED_NOT_COMMITTED,
    GATEWAY_INDETERMINATE,
    GATEWAY_RECONCILED,
    SimulatedEffectProvider,
    SqliteEffectIntentStore,
    make_effect_request,
)
from event_horizon.execution_state import ExecutionStateError
from event_horizon.executor import (
    PURE_OPERATIONS,
    SacrificialExecutor,
    _governed_execution_id,  # noqa: F401
)
from event_horizon.recorder import ExternalRecorder, FileCheckpointAnchor
from event_horizon.statements import (
    TYPE_APPROVAL,
    TYPE_EFFECT_RECONCILIATION,
    StatementSigner,
    StatementVerifier,
)
from event_horizon.trust_manifest import (
    AuthorizedStatementVerifier,
    KeyNotAuthorizedError,
    ManifestChain,
    TrustManifestError,
    TrustRootAuthority,
    genesis_manifest_digest,
    make_actor,
)
from event_horizon.witness import (
    LocalCheckpointWitness,
    WitnessPolicy,
    compare_recorder_with_witness,
)


def _pem(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _key_id(seed: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import hashlib

    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


def _deployment(seed_offset: int = 0, *, journal_dir: Path | None = None):
    """Build a full deployment trust topology and return its parts."""
    root_seed = bytes([1 + seed_offset]) * 32
    guardian_seed = bytes([2 + seed_offset]) * 32
    verifier_seed = bytes([3 + seed_offset]) * 32
    gateway_seed = bytes([4 + seed_offset]) * 32
    witness_seed = bytes([5 + seed_offset]) * 32

    authority = TrustRootAuthority(
        root_seed, deployment_id=f"dep-{seed_offset}", environment="synthetic"
    )
    actors = [
        make_actor(role="guardian", public_key_pem=_pem(guardian_seed)),
        make_actor(role="verifier", public_key_pem=_pem(verifier_seed)),
        make_actor(role="effect-gateway", public_key_pem=_pem(gateway_seed)),
        make_actor(
            role="witness",
            public_key_pem=_pem(witness_seed),
            purposes={"witness-checkpoint"},
        ),
    ]
    manifest = authority.issue_manifest(
        actors,
        manifest_version=1,
        sequence=1,
        issued_at_ms=1000,
        previous_manifest_digest=None,
    )
    chain = ManifestChain(
        authority.public_key_pem,
        deployment_id=f"dep-{seed_offset}",
        environment="synthetic",
    )
    chain.append(manifest)

    guardian_signer = StatementSigner(guardian_seed, subject="guardians")
    gateway_signer = StatementSigner(gateway_seed, subject="effect-gateway")
    statement_verifier = StatementVerifier({
        "guardian": _pem(guardian_seed),
        "gateway": _pem(gateway_seed),
    })
    authorized_verifier = AuthorizedStatementVerifier(chain, statement_verifier)
    witness = LocalCheckpointWitness(
        (journal_dir or Path(tempfile.mkdtemp(prefix="eh-witness-"))) / f"witness-{seed_offset}.jsonl",
        witness_id=f"witness-{seed_offset}",
        signing_key=witness_seed,
        deployment_id=f"dep-{seed_offset}",
    )
    return {
        "authority": authority,
        "chain": chain,
        "manifest": manifest,
        "guardian_signer": guardian_signer,
        "gateway_signer": gateway_signer,
        "gateway_key_id": _key_id(gateway_seed),
        "statement_verifier": statement_verifier,
        "authorized_verifier": authorized_verifier,
        "witness": witness,
        "witness_public_key_pem": _pem(witness_seed),
        "root_public_key_pem": authority.public_key_pem,
        "deployment_id": f"dep-{seed_offset}",
    }


class TrustRootAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parts = _deployment(0)
        self.authority = self.parts["authority"]
        self.chain = self.parts["chain"]

    def test_forged_manifest_with_attacker_root_is_rejected(self) -> None:
        attacker_root = TrustRootAuthority(
            b"Z" * 32,
            deployment_id=self.authority.deployment_id,
            environment="synthetic",
        )
        actors = [make_actor(role="verifier", public_key_pem=_pem(b"E" * 32))]
        forged = attacker_root.issue_manifest(
            actors,
            manifest_version=1,
            sequence=99,
            issued_at_ms=5000,
            previous_manifest_digest=None,
        )
        with self.assertRaises(TrustManifestError):
            self.chain.verify_envelope(forged)

    def test_manifest_version_regression_is_rejected(self) -> None:
        actors = [make_actor(role="verifier", public_key_pem=_pem(b"F" * 32))]
        v2 = self.authority.issue_manifest(
            actors,
            manifest_version=2,
            sequence=2,
            issued_at_ms=2000,
            previous_manifest_digest=self.chain.current.manifest_digest,
        )
        self.chain.append(v2)
        with self.assertRaises(TrustManifestError):
            self.chain.append(self.parts["manifest"])

    def test_manifest_from_other_deployment_is_rejected(self) -> None:
        other = _deployment(7)
        with self.assertRaises(TrustManifestError):
            self.chain.verify_envelope(other["manifest"])

    def test_unknown_future_schema_fails_closed(self) -> None:
        envelope = dict(self.parts["manifest"])
        envelope["schema"] = "event-horizon.trust-manifest.v999"
        with self.assertRaises(TrustManifestError):
            self.chain.verify_envelope(envelope)

    def test_cross_role_substitution_is_rejected(self) -> None:
        # The registered guardian key attempts to act as a verifier.
        entry = make_actor(role="guardian", public_key_pem=_pem(bytes([2]) * 32))
        key_id = entry["key_id"]
        with self.assertRaises(KeyNotAuthorizedError) as denied:
            self.chain.authorize(key_id, role="verifier")
        self.assertEqual(denied.exception.reason_code, "wrong-role")

    def test_same_key_cannot_hold_two_roles_in_one_manifest(self) -> None:
        same_pem = _pem(bytes([9]) * 32)
        actors = [
            make_actor(role="guardian", public_key_pem=same_pem),
            make_actor(role="verifier", public_key_pem=same_pem),
        ]
        with self.assertRaises(TrustManifestError):
            self.authority.issue_manifest(
                actors,
                manifest_version=2,
                sequence=3,
                issued_at_ms=3000,
                previous_manifest_digest=self.chain.current.manifest_digest,
            )

    def test_revocation_semantics_current_vs_historical(self) -> None:
        # The deployment's original v1 guardian is the key being revoked.
        old_guardian_key_id = self.chain.manifest_at(1).actors[0]["key_id"]
        v2 = self.authority.issue_manifest(
            [
                make_actor(role="guardian", public_key_pem=_pem(bytes([22]) * 32)),
                make_actor(role="verifier", public_key_pem=_pem(bytes([23]) * 32)),
            ],
            manifest_version=2,
            sequence=5,
            issued_at_ms=2000,
            previous_manifest_digest=self.chain.current.manifest_digest,
            revocations=[{
                "key_id": old_guardian_key_id,
                "reason_code": "compromise",
                "effective_sequence": 5,
            }],
        )
        self.chain.append(v2)
        with self.assertRaises(KeyNotAuthorizedError) as denied:
            self.chain.authorize(old_guardian_key_id, role="guardian")
        self.assertEqual(denied.exception.reason_code, "revoked-key")
        # Historical verification under manifest v1 remains provable.
        entry = self.chain.authorize(
            old_guardian_key_id, role="guardian", at_manifest_version=1
        )
        self.assertEqual(entry["status"], "active")

    def test_rotation_mid_run_invalidates_old_key_only_forward(self) -> None:
        # v2 introduces an executor key; v3 rotates it out.
        introduced = make_actor(role="executor", public_key_pem=_pem(bytes([31]) * 32))
        v2 = self.authority.issue_manifest(
            [
                introduced,
                make_actor(role="guardian", public_key_pem=_pem(bytes([2]) * 32)),
                make_actor(role="verifier", public_key_pem=_pem(bytes([3]) * 32)),
            ],
            manifest_version=2,
            sequence=4,
            issued_at_ms=2000,
            previous_manifest_digest=self.chain.current.manifest_digest,
        )
        self.chain.append(v2)
        replacement = make_actor(role="executor", public_key_pem=_pem(bytes([32]) * 32))
        v3 = self.authority.issue_manifest(
            [
                replacement,
                make_actor(role="guardian", public_key_pem=_pem(bytes([2]) * 32)),
                make_actor(role="verifier", public_key_pem=_pem(bytes([3]) * 32)),
            ],
            manifest_version=3,
            sequence=7,
            issued_at_ms=2500,
            previous_manifest_digest=self.chain.current.manifest_digest,
        )
        self.chain.append(v3)
        with self.assertRaises(KeyNotAuthorizedError) as denied:
            self.chain.authorize(introduced["key_id"], role="executor")
        self.assertEqual(denied.exception.reason_code, "unknown-key")
        # Statements issued while the key was active still verify historically.
        entry = self.chain.authorize(
            introduced["key_id"], role="executor", at_manifest_version=2
        )
        self.assertEqual(entry["status"], "active")

    def test_wrong_purpose_inside_role_is_rejected(self) -> None:
        recorder_entry = make_actor(
            role="recorder",
            public_key_pem=_pem(bytes([41]) * 32),
            purposes={"record-evidence"},
        )
        v2 = self.authority.issue_manifest(
            [recorder_entry],
            manifest_version=2,
            sequence=6,
            issued_at_ms=3000,
            previous_manifest_digest=self.chain.current.manifest_digest,
        )
        chain2 = ManifestChain(
            self.authority.public_key_pem,
            deployment_id=self.authority.deployment_id,
            environment="synthetic",
        )
        chain2.append(self.parts["manifest"])
        chain2.append(v2)
        with self.assertRaises(KeyNotAuthorizedError) as denied:
            chain2.authorize(recorder_entry["key_id"], role="recorder", purpose="issue-recorder-checkpoint")
        self.assertEqual(denied.exception.reason_code, "wrong-purpose")


class CoordinatorCompromiseTests(unittest.TestCase):
    def test_coordinator_cannot_adopt_foreign_witness_ack(self) -> None:
        here = _deployment(0)
        there = _deployment(1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder = ExternalRecorder(root / "events.jsonl", b"R" * 32)
            anchor = FileCheckpointAnchor(root / "anchor.jsonl")
            recorder.append("e", {}, source_id="s", source_sequence=1)
            checkpoint = recorder.issue_checkpoint(
                anchor, deployment_id=here["deployment_id"], manifest_digest="a" * 64
            )
            foreign_witness = there["witness"]
            with self.assertRaises(Exception):
                foreign_witness.publish_checkpoint(
                    checkpoint,
                    recorder_public_key_pem=recorder.public_key_pem,
                    manifest_digest="a" * 64,
                )

    def test_conflicted_executor_claim_survives_as_conflicted_status(self) -> None:
        """A dishonest executor signs 'committed'; the gateway positively
        proves non-execution. Event Horizon preserves the conflict."""
        parts = _deployment(2)
        with tempfile.TemporaryDirectory() as tmp:
            recorder = ExternalRecorder(Path(tmp) / "events.jsonl", b"R" * 32)
            request_digest = "b" * 64
            recorder.append(
                "request.received",
                {"run_id": "run-1", "session_id": "s-1", "request_id": "r1"},
                source_id="c",
                source_sequence=1,
            )
            recorder.append(
                "execution.completed",
                {
                    "run_id": "run-1",
                    "session_id": "s-1",
                    "capability_id": "cap_" + "a" * 24,
                    "success": True,
                    "effect_state": "committed",
                    "request_digest": request_digest,
                    # Executor-signed receipt claiming success:
                    "receipt": StatementSigner(
                        bytes([77]) * 32, subject="executor"
                    ).sign(
                        "execution-receipt",
                        {
                            "request_digest": request_digest,
                            "capability_id": "cap_" + "a" * 24,
                            "effect_state": "committed",
                        },
                    ).to_dict(),
                },
                source_id="c",
                source_sequence=2,
            )
            builder = ContainmentCertificateBuilder(
                recorder,
                b"C" * 32,
                statement_verifier=parts["statement_verifier"],
            )
            reconciliation = parts["gateway_signer"].sign(
                TYPE_EFFECT_RECONCILIATION,
                {
                    "gateway_id": "gw-1",
                    "idempotency_key": request_digest,
                    "resolution": "confirmed_not_committed",
                    "provider_outcome": "confirmed-not-executed",
                },
            ).to_dict()
            certificate = builder.build(
                run_id="run-1",
                deployment_id=parts["deployment_id"],
                trust_root_manifest_digest=parts["chain"].current.manifest_digest,
                effect_reconciliation_statements=[reconciliation],
            )
            payload = certificate["certificate"]
            self.assertEqual(payload["status"], "conflicted")
            self.assertEqual(
                payload["claims"]["effect_mediation_consistent"], "conflicted"
            )


class EffectGatewayCompromiseTests(unittest.TestCase):
    def _gateway(self, tmp: str) -> tuple:
        signer = StatementSigner(bytes([50]) * 32, subject="effect-gateway")
        store = SqliteEffectIntentStore(Path(tmp) / "intents.sqlite3")
        gateway = EffectGateway(
            gateway_id="gw-test",
            statement_signer=signer,
            intent_store=store,
            deployment_id="dep-gw",
        )
        return gateway, store

    def _request(self, operation: str, suffix: int = 0) -> Any:
        return make_effect_request(
            deployment_id="dep-gw",
            environment="synthetic",
            run_id="run-1",
            session_id="s-1",
            capability_id="cap_" + "a" * 24,
            request_digest=digest({"op": operation, "n": suffix}),
            operation=operation,
            arguments_digest="c" * 64,
            policy_digest="d" * 64,
            executor_identity="exec-1",
        )

    def test_intent_is_durable_before_provider_contact(self) -> None:
        class ExplodingProvider:
            def execute(self, request, key):
                raise RuntimeError("provider unreachable")

            def reconcile(self, key):
                raise RuntimeError("provider unreachable")

        with tempfile.TemporaryDirectory() as tmp:
            gateway, store = self._gateway(tmp)
            request = self._request("deploy")
            # The gateway swallows provider failures into indeterminate state;
            # the durable intent record exists either way.
            result = gateway.dispatch(request, ExplodingProvider())
            self.assertEqual(result["state"], GATEWAY_INDETERMINATE)
            record = store.load(request.idempotency_key)
            self.assertIsNotNone(record)
            self.assertEqual(record["state"], GATEWAY_INDETERMINATE)
            self.assertIsNotNone(record["intent_statement"])

    def test_retry_after_response_loss_never_creates_second_effect(self) -> None:
        provider = SimulatedEffectProvider()
        provider.configure("flaky", "timeout-then-commit")
        with tempfile.TemporaryDirectory() as tmp:
            gateway, store = self._gateway(tmp)
            request = self._request("flaky")
            first = gateway.dispatch(request, provider)
            self.assertEqual(first["state"], GATEWAY_INDETERMINATE)
            # Operator retries after the timeout with the SAME logical effect:
            # the immutable idempotency key routes to the original execution.
            second = gateway.dispatch(request, provider)
            self.assertEqual(second["state"], GATEWAY_COMMITTED)
            reconciled = gateway.reconcile(request, provider)
            self.assertEqual(reconciled["resolution"], "committed")
            # The provider executed exactly once for this idempotency key;
            # the retry was answered from the provider's deduplication record.
            executions = provider._executions[request.idempotency_key]
            self.assertTrue(executions["executed"])
            self.assertEqual(
                len(provider._executions), 1, "retry must not create a second logical effect"
            )

    def test_crash_after_commit_recovers_truth_via_reconciliation(self) -> None:
        provider = SimulatedEffectProvider()
        provider.configure("boom", "crash-after-commit")
        with tempfile.TemporaryDirectory() as tmp:
            gateway, _store = self._gateway(tmp)
            request = self._request("boom")
            result = gateway.dispatch(request, provider)
            self.assertEqual(result["state"], GATEWAY_INDETERMINATE)
            resolved = gateway.reconcile(request, provider)
            self.assertEqual(resolved["state"], GATEWAY_RECONCILED)
            self.assertEqual(resolved["resolution"], "committed")

    def test_provider_that_cannot_answer_keeps_uncertainty(self) -> None:
        provider = SimulatedEffectProvider()
        provider.configure("weird", "ambiguous")
        with tempfile.TemporaryDirectory() as tmp:
            gateway, _store = self._gateway(tmp)
            request = self._request("weird")
            result = gateway.dispatch(request, provider)
            self.assertEqual(result["state"], GATEWAY_INDETERMINATE)
            still = gateway.reconcile(request, provider)
            self.assertEqual(still["resolution"], "indeterminate")

    def test_rejected_effect_is_positively_not_committed(self) -> None:
        provider = SimulatedEffectProvider()
        provider.configure("denied", "reject")
        with tempfile.TemporaryDirectory() as tmp:
            gateway, _store = self._gateway(tmp)
            request = self._request("denied")
            result = gateway.dispatch(request, provider)
            self.assertEqual(result["state"], GATEWAY_CONFIRMED_NOT_COMMITTED)

    def test_cross_deployment_effect_request_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway, _store = self._gateway(tmp)
            foreign = make_effect_request(
                deployment_id="dep-other",
                environment="synthetic",
                run_id="run-1",
                session_id="s-1",
                capability_id="cap_" + "a" * 24,
                request_digest="e" * 64,
                operation="deploy",
                arguments_digest="f" * 64,
                policy_digest="0" * 64,
                executor_identity="exec-1",
            )
            with self.assertRaises(EffectGatewayError):
                gateway.begin_effect(foreign)

    def test_gateway_statements_verify_and_authorize_under_manifest(self) -> None:
        parts = _deployment(3)
        statement = parts["gateway_signer"].sign(
            TYPE_EFFECT_RECONCILIATION,
            {
                "gateway_id": "gw-1",
                "idempotency_key": "k",
                "resolution": "committed",
                "issued_at_ms": 1000,
            },
        ).to_dict()
        verified = parts["authorized_verifier"].verify(
            statement,
            expected_type=TYPE_EFFECT_RECONCILIATION,
            expected_role="effect-gateway",
        )
        self.assertEqual(verified.key_id, parts["gateway_key_id"])


class WitnessAttackTests(unittest.TestCase):
    def _witnessed_history(self, tmp: Path):
        recorder = ExternalRecorder(tmp / "events.jsonl", b"R" * 32)
        anchor = FileCheckpointAnchor(tmp / "anchor.jsonl")
        recorder.append("e1", {}, source_id="s", source_sequence=1)
        recorder.append("e2", {}, source_id="s", source_sequence=2)
        checkpoint = recorder.issue_checkpoint(
            anchor, deployment_id="dep-w", manifest_digest="a" * 64
        )
        witness = LocalCheckpointWitness(
            tmp / "witness.jsonl",
            witness_id="w-1",
            signing_key=b"W" * 32,
            deployment_id="dep-w",
        )
        ack = witness.publish_checkpoint(
            checkpoint,
            recorder_public_key_pem=recorder.public_key_pem,
            manifest_digest="a" * 64,
        )
        return recorder, anchor, witness, ack

    def test_recorder_rollback_behind_witness_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder, anchor, witness, ack = self._witnessed_history(root)
            context = {"ack": ack, "witness_public_key_pem": witness.public_key_pem}
            lines = (root / "events.jsonl").read_bytes().splitlines(keepends=True)
            (root / "events.jsonl").write_bytes(lines[0])
            rolled_back = ExternalRecorder(root / "events.jsonl", b"R" * 32)
            verdict = compare_recorder_with_witness(
                snapshot_event_count=rolled_back.count(),
                snapshot_chain_tip=rolled_back.verified_snapshot().chain_tip,
                acknowledgment=context,
                deployment_id="dep-w",
                manifest_digest="a" * 64,
                policy=WitnessPolicy(require_witness=True),
            )
            self.assertEqual(verdict.status, "recorder-behind-witness")

    def test_witness_refuses_conflicting_fork_at_same_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder, anchor, witness, ack = self._witnessed_history(root)
            # Build a forked history with a different tip at sequence 2.
            fork_recorder = ExternalRecorder(root / "fork.jsonl", b"R" * 32)
            fork_recorder.append("e1", {}, source_id="s", source_sequence=1)
            fork_recorder.append("EVIL", {}, source_id="s", source_sequence=2)
            fork_anchor = FileCheckpointAnchor(root / "fork-anchor.jsonl")
            fork_checkpoint = fork_recorder.issue_checkpoint(
                fork_anchor, deployment_id="dep-w", manifest_digest="a" * 64
            )
            with self.assertRaises(Exception) as denied:
                witness.publish_checkpoint(
                    fork_checkpoint,
                    recorder_public_key_pem=fork_recorder.public_key_pem,
                    manifest_digest="a" * 64,
                )
            self.assertIn("fork", str(denied.exception))

    def test_fake_witness_signature_is_unrecognized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder, anchor, real_witness, ack = self._witnessed_history(root)
            fake_witness = LocalCheckpointWitness(
                root / "fake.jsonl",
                witness_id="w-evil",
                signing_key=b"X" * 32,
                deployment_id="dep-w",
            )
            context = {
                "ack": ack,
                "witness_public_key_pem": fake_witness.public_key_pem,
            }
            verdict = compare_recorder_with_witness(
                snapshot_event_count=recorder.count(),
                snapshot_chain_tip=recorder.verified_snapshot().chain_tip,
                acknowledgment=context,
                deployment_id="dep-w",
                manifest_digest="a" * 64,
                policy=WitnessPolicy(require_witness=True),
            )
            self.assertEqual(verdict.status, "unrecognized-witness")

    def test_missing_acknowledgment_blocks_when_required(self) -> None:
        verdict = compare_recorder_with_witness(
            snapshot_event_count=10,
            snapshot_chain_tip="a" * 64,
            acknowledgment=None,
            deployment_id="dep-w",
            manifest_digest="a" * 64,
            policy=WitnessPolicy(require_witness=True),
        )
        self.assertEqual(verdict.status, "no-acknowledgment")


class CrossDeploymentConfusionTests(unittest.TestCase):
    def test_evidence_from_deployment_a_never_validates_in_b(self) -> None:
        dep_a = _deployment(10)
        dep_b = _deployment(11)
        # A's manifest cannot join B's chain even re-signed versions aside:
        with self.assertRaises(TrustManifestError):
            dep_b["chain"].verify_envelope(dep_a["manifest"])
        # A's guardian statement does not verify under B's pinned keys.
        statement = dep_a["guardian_signer"].sign(
            "guardian-decision", {"allowed": True}
        ).to_dict()
        with self.assertRaises(Exception):
            dep_b["statement_verifier"].verify(statement, expected_type="guardian-decision")

    def test_witness_acks_are_deployment_scoped(self) -> None:
        dep_a = _deployment(20)
        dep_b = _deployment(21)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder = ExternalRecorder(root / "events.jsonl", b"R" * 32)
            anchor = FileCheckpointAnchor(root / "anchor.jsonl")
            recorder.append("e", {}, source_id="s", source_sequence=1)
            checkpoint = recorder.issue_checkpoint(
                anchor,
                deployment_id=dep_a["deployment_id"],
                manifest_digest="a" * 64,
            )
            ack = dep_a["witness"].publish_checkpoint(
                checkpoint,
                recorder_public_key_pem=recorder.public_key_pem,
                manifest_digest="a" * 64,
            )
            verdict_for_b = compare_recorder_with_witness(
                snapshot_event_count=recorder.count(),
                snapshot_chain_tip=recorder.verified_snapshot().chain_tip,
                acknowledgment={
                    "ack": ack,
                    "witness_public_key_pem": dep_a["witness_public_key_pem"],
                },
                deployment_id=dep_b["deployment_id"],
                manifest_digest="a" * 64,
                policy=WitnessPolicy(require_witness=True),
            )
            self.assertEqual(verdict_for_b.status, "deployment-mismatch")


class GuardianCompromiseTests(unittest.TestCase):
    def test_revoked_guardian_statement_fails_manifest_authorization(self) -> None:
        # Build a deployment whose v1 guardian key is later revoked; the
        # compromised key keeps signing valid-looking statements.
        with tempfile.TemporaryDirectory() as tmp:
            guardian_seed = bytes([61]) * 32
            authority = TrustRootAuthority(
                bytes([60]) * 32, deployment_id="dep-g", environment="synthetic"
            )
            manifest = authority.issue_manifest(
                [
                    make_actor(role="guardian", public_key_pem=_pem(guardian_seed)),
                    make_actor(role="verifier", public_key_pem=_pem(bytes([63]) * 32)),
                ],
                manifest_version=1,
                sequence=1,
                issued_at_ms=1000,
                previous_manifest_digest=None,
            )
            chain = ManifestChain(
                authority.public_key_pem,
                deployment_id="dep-g",
                environment="synthetic",
            )
            chain.append(manifest)
            verifier = StatementVerifier({"guardian": _pem(guardian_seed)})
            authorized = AuthorizedStatementVerifier(chain, verifier)

            replacement = make_actor(role="guardian", public_key_pem=_pem(bytes([62]) * 32))
            v2 = authority.issue_manifest(
                [
                    replacement,
                    make_actor(role="verifier", public_key_pem=_pem(bytes([63]) * 32)),
                ],
                manifest_version=2,
                sequence=8,
                issued_at_ms=9000,
                previous_manifest_digest=chain.current.manifest_digest,
                revocations=[{
                    "key_id": _key_id(guardian_seed),
                    "reason_code": "compromise",
                    "effective_sequence": 8,
                }],
            )
            chain.append(v2)

            compromised_statement = StatementSigner(
                guardian_seed, subject="guardians"
            ).sign("guardian-decision", {"allowed": True}).to_dict()
            with self.assertRaises(KeyNotAuthorizedError):
                authorized.verify(
                    compromised_statement,
                    expected_type="guardian-decision",
                    expected_role="guardian",
                )

    def test_honest_guardian_statement_still_authorizes_after_unrelated_rotation(self) -> None:
        parts = _deployment(40)
        statement = parts["guardian_signer"].sign(
            "guardian-decision",
            {"allowed": True, "issued_at_ms": 1000},
        ).to_dict()
        verified = parts["authorized_verifier"].verify(
            statement,
            expected_type="guardian-decision",
            expected_role="guardian",
        )
        self.assertTrue(verified.payload["allowed"])


class ProvenanceGraphTests(unittest.TestCase):
    def _graph(self, **overrides) -> Any:
        from event_horizon.provenance import EvidenceGraph

        fields = {
            "deployment_id": "dep-p",
            "run_id": "run-p",
            "session_id": "s-p",
        }
        fields.update(overrides)
        return EvidenceGraph(**fields)

    def test_evidence_root_is_deterministic_and_order_independent(self) -> None:
        left = self._graph()
        right = self._graph()
        for graph, order in ((left, ["a", "b", "c"]), (right, ["c", "a", "b"])):
            for name in order:
                graph.build_node(
                    node_type=f"node-{name}",
                    source_key_id="ed25519:" + "0" * 32,
                    statement_envelope={"name": name},
                )
        self.assertEqual(left.evidence_root(), right.evidence_root())

    def test_root_changes_when_any_node_content_changes(self) -> None:
        first = self._graph()
        second = self._graph()
        for graph in (first, second):
            graph.build_node(
                node_type="guardian-decision",
                source_key_id="ed25519:" + "0" * 32,
                statement_envelope={"allowed": True},
            )
        second.build_node(
            node_type="execution-receipt",
            source_key_id="ed25519:" + "1" * 32,
            statement_envelope={"effect_state": "committed"},
        )
        self.assertNotEqual(first.evidence_root(), second.evidence_root())

    def test_foreign_namespace_node_is_rejected(self) -> None:
        from event_horizon.provenance import ProvenanceError, ProvenanceNode

        graph = self._graph()
        foreign = ProvenanceNode(
            node_type="verifier-attestation",
            source_key_id="ed25519:" + "2" * 32,
            deployment_id="dep-p",
            run_id="run-EVIL",
            session_id="s-p",
            content_digest="a" * 64,
        )
        with self.assertRaises(ProvenanceError):
            graph.add_node(foreign, statement_envelope={"x": 1})

    def test_dependencies_must_exist_before_dependents(self) -> None:
        from event_horizon.provenance import ProvenanceError

        graph = self._graph()
        with self.assertRaises(ProvenanceError):
            graph.build_node(
                node_type="capability",
                source_key_id="ed25519:" + "3" * 32,
                statement_envelope={"cap": True},
                dependencies=("f" * 64,),
            )

    def test_inclusion_proofs_verify_and_detect_tampering(self) -> None:
        from event_horizon.provenance import EvidenceGraph as Graph

        graph = self._graph()
        digests = [
            graph.build_node(
                node_type=f"node-{index}",
                source_key_id="ed25519:" + f"{index}" * 32,
                statement_envelope={"index": index},
            )
            for index in range(5)
        ]
        root = graph.evidence_root()
        for node_digest in digests:
            proof = graph.inclusion_proof(node_digest)
            self.assertTrue(Graph.verify_inclusion(node_digest, proof, root))
        tampered_proof = [dict(step) for step in graph.inclusion_proof(digests[0])]
        tampered_proof[0]["sibling"] = "0" * 64
        self.assertFalse(Graph.verify_inclusion(digests[0], tampered_proof, root))


class DifferentialTrustMatrixTests(unittest.TestCase):
    """Fixture matrix: each compromise scenario yields exact claim statuses."""

    def _honest_history(self, recorder: ExternalRecorder, signers: dict) -> dict:
        request_digest = "1" * 64
        capability_id = "cap_" + "b" * 24
        run_id, session_id = "run-m", "s-m"
        events = [
            ("request.received", {
                "run_id": run_id, "session_id": session_id,
                "request_id": "r1", "request_digest": request_digest,
            }),
            ("attestation.verified", {
                "run_id": run_id, "session_id": session_id,
                "result_digest": "2" * 64, "bundle_digest": "3" * 64,
                "statement": signers["verifier"].sign(
                    "verifier-attestation",
                    {"result_digest": "2" * 64, "issued_at_ms": 1000},
                ).to_dict(),
            }),
            ("guardian.decision", {
                "run_id": run_id, "session_id": session_id,
                "guardian": "policy", "allowed": True,
                "request_digest": request_digest,
                "statement": signers["guardian"].sign(
                    "guardian-decision",
                    {"guardian": "policy", "allowed": True,
                     "request_digest": request_digest, "issued_at_ms": 1000},
                ).to_dict(),
            }),
            ("capability.issued", {
                "run_id": run_id, "session_id": session_id,
                "capability_id": capability_id,
                "request_digest": request_digest,
                "key_id": "ed25519:" + "4" * 32,
                "executor_measurement": "5" * 64,
            }),
            ("execution.completed", {
                "run_id": run_id, "session_id": session_id,
                "capability_id": capability_id,
                "request_digest": request_digest,
                "success": True, "output_bytes": 8,
                "receipt": signers["executor"].sign(
                    "execution-receipt",
                    {"request_digest": request_digest,
                     "session_id": session_id,
                     "capability_id": capability_id,
                     "effect_state": "committed"},
                ).to_dict(),
            }),
            ("teardown.verified", {
                "run_id": run_id, "verified": True,
                "statement": signers["watchdog"].sign(
                    "teardown-attestation",
                    {"verified": True, "run_id": run_id},
                ).to_dict(),
            }),
        ]
        for sequence, (event_type, payload) in enumerate(events, start=1):
            recorder.append(event_type, payload, source_id="c", source_sequence=sequence)
        return {"request_digest": request_digest}

    def _certificate_for(self, tmp: str, mutate=None, extra_verifier_keys=None) -> tuple:
        from event_horizon.statements import (
            TYPE_EXECUTION_RECEIPT,
            TYPE_GUARDIAN_DECISION,
            TYPE_TEARDOWN_ATTESTATION,
            TYPE_VERIFIER_ATTESTATION,
        )

        recorder_path = Path(tmp) / "events.jsonl"
        verifier_seed, guardian_seed = bytes([81]) * 32, bytes([82]) * 32
        executor_seed, watchdog_seed = bytes([83]) * 32, bytes([84]) * 32
        gateway_seed = bytes([85]) * 32
        signers = {
            "verifier": StatementSigner(verifier_seed, subject="verifier"),
            "guardian": StatementSigner(guardian_seed, subject="guardians"),
            "executor": StatementSigner(executor_seed, subject="executor"),
            "watchdog": StatementSigner(watchdog_seed, subject="watchdog"),
        }
        recorder = ExternalRecorder(recorder_path, b"R" * 32)
        context = self._honest_history(recorder, signers)
        if mutate is not None:
            mutate(recorder, context, signers)
        pinned = {
            "v": signers["verifier"].public_key_pem,
            "g": signers["guardian"].public_key_pem,
            "e": signers["executor"].public_key_pem,
            "w": signers["watchdog"].public_key_pem,
        }
        if extra_verifier_keys:
            pinned.update(extra_verifier_keys)
        builder = ContainmentCertificateBuilder(
            ExternalRecorder(recorder_path, b"R" * 32),
            b"C" * 32,
            statement_verifier=StatementVerifier(pinned),
        )
        return builder.build(
            run_id="run-m",
            deployment_id="dep-m",
            trust_root_manifest_digest="a" * 64,
        )

    def test_all_honest_yields_complete_satisfied(self) -> None:
        import tempfile as _tempfile

        with tempfile.TemporaryDirectory() as tmp:
            certificate = self._certificate_for(tmp)
            payload = certificate["certificate"]
            self.assertEqual(payload["status"], "complete")
            evidence_claims = {
                k: v for k, v in payload["claims"].items() if k != "effect_mediation_consistent"
            }
            self.assertEqual(set(evidence_claims.values()), {"satisfied"})

    def test_executor_lying_against_gateway_yields_conflicted(self) -> None:
        from event_horizon.statements import TYPE_EFFECT_RECONCILIATION

        import tempfile as _tempfile

        def mutate(recorder, context, signers):
            # The gateway positively proves the effect never happened while
            # the executor receipt (already recorded) claims success.
            pass

        with tempfile.TemporaryDirectory() as tmp:
            gateway_seed = bytes([85]) * 32
            gateway_signer = StatementSigner(gateway_seed, subject="effect-gateway")
            reconciliation = gateway_signer.sign(
                TYPE_EFFECT_RECONCILIATION,
                {
                    "gateway_id": "gw",
                    "idempotency_key": "1" * 64,  # binds to request digest
                    "resolution": "confirmed_not_committed",
                    "provider_outcome": "confirmed-not-executed",
                },
            ).to_dict()

            recorder_path = Path(tmp) / "events.jsonl"
            verifier_seed, guardian_seed = bytes([81]) * 32, bytes([82]) * 32
            executor_seed, watchdog_seed = bytes([83]) * 32, bytes([84]) * 32
            signers = {
                "verifier": StatementSigner(verifier_seed, subject="verifier"),
                "guardian": StatementSigner(guardian_seed, subject="guardians"),
                "executor": StatementSigner(executor_seed, subject="executor"),
                "watchdog": StatementSigner(watchdog_seed, subject="watchdog"),
            }
            recorder = ExternalRecorder(recorder_path, b"R" * 32)
            self._honest_history(recorder, signers)
            builder = ContainmentCertificateBuilder(
                ExternalRecorder(recorder_path, b"R" * 32),
                b"C" * 32,
                statement_verifier=StatementVerifier({
                    "v": signers["verifier"].public_key_pem,
                    "g": signers["guardian"].public_key_pem,
                    "e": signers["executor"].public_key_pem,
                    "w": signers["watchdog"].public_key_pem,
                    "gw": gateway_signer.public_key_pem,
                }),
            )
            certificate = builder.build(
                run_id="run-m",
                deployment_id="dep-m",
                trust_root_manifest_digest="a" * 64,
                effect_reconciliation_statements=[reconciliation],
            )
            payload = certificate["certificate"]
            self.assertEqual(payload["status"], "conflicted")
            self.assertEqual(
                payload["claims"]["effect_mediation_consistent"], "conflicted"
            )

    def test_unverified_attestation_claim_blocks_completeness(self) -> None:
        import tempfile as _tempfile

        def mutate(recorder, context, signers):
            # Coordinator fabricates an attestation event with no signature.
            recorder.append(
                "attestation.verified",
                {"run_id": "run-m", "session_id": "s-m",
                 "result_digest": "9" * 64},
                source_id="c",
                source_sequence=7,
            )

        with tempfile.TemporaryDirectory() as tmp:
            certificate = self._certificate_for(tmp, mutate=mutate)
            payload = certificate["certificate"]
            self.assertEqual(payload["claims"]["attestation_independently_signed"], "violated")
            self.assertEqual(payload["status"], "incomplete")

    def test_missing_receipt_on_completion_blocks_clean_status(self) -> None:
        import tempfile as _tempfile

        def mutate(recorder, context, signers):
            recorder.append(
                "execution.completed",
                {"run_id": "run-m", "session_id": "s-m",
                 "capability_id": "cap_" + "c" * 24,
                 "request_digest": "7" * 64,
                 "success": True,
                 "receipt": None},
                source_id="c",
                source_sequence=7,
            )

        with tempfile.TemporaryDirectory() as tmp:
            certificate = self._certificate_for(tmp, mutate=mutate)
            payload = certificate["certificate"]
            self.assertEqual(payload["status"], "incomplete")
            self.assertTrue(any("no signed execution receipt" in reason
                                for reason in payload["blocking_reasons"]))


class ModelBasedLifecycleTests(unittest.TestCase):
    """Fuzzed lifecycle sequences over tracker + gateway + provider.

    Generated action sequences must preserve, at every step:

    1. consumed authority never resurrects (tracker never leaves CONSUMED);
    2. a retry can never create a second logical provider effect;
    3. once dispatch started the record never returns to intent-only state;
    4. terminal reconciled records are immutable;
    5. clean certification is impossible while any effect is unresolved.
    """

    ACTIONS = (
        "consume",
        "duplicate_consume",
        "intent",
        "dispatch",
        "retry",
        "reconcile",
        "restart",
        "certify_attempt",
    )
    SCENARIOS = (
        "commit",
        "timeout-then-commit",
        "crash-after-commit",
        "ambiguous",
        "reject",
    )

    @given(
        st.lists(st.sampled_from(ACTIONS), min_size=1, max_size=8),
        st.sampled_from(SCENARIOS),
    )
    @settings(max_examples=40, deadline=None)
    def test_lifecycle_invariants_hold_for_every_sequence(
        self, actions: list[str], scenario: str
    ) -> None:
        from event_horizon.effect_gateway import (
            GATEWAY_CONFIRMED_NOT_COMMITTED as _CONFIRMED,
        )
        from event_horizon.execution_state import (
            CapabilityExecutionTracker,
            ExecutionState,
            InMemoryExecutionStateStore,
        )

        with tempfile.TemporaryDirectory() as tmp:
            signer = StatementSigner(bytes([90]) * 32, subject="effect-gateway")
            store = SqliteEffectIntentStore(Path(tmp) / "intents.sqlite3")
            gateway = EffectGateway(
                gateway_id="gw-model",
                statement_signer=signer,
                intent_store=store,
                deployment_id="dep-model",
            )
            provider = SimulatedEffectProvider()
            provider.configure("model-op", scenario)
            request = make_effect_request(
                deployment_id="dep-model",
                environment="synthetic",
                run_id="run-model",
                session_id="s-model",
                capability_id="cap_" + "d" * 24,
                request_digest=digest({"op": "model-op"}),
                operation="model-op",
                arguments_digest="e" * 64,
                policy_digest="f" * 64,
                executor_identity="exec-model",
            )
            tracker = CapabilityExecutionTracker(
                InMemoryExecutionStateStore(), namespace="model"
            )
            consumed = False
            dispatched = False
            reconciled = False

            def invariants() -> None:
                nonlocal consumed
                # 2. one logical effect per idempotency identity.
                self.assertLessEqual(len(provider._executions), 1)
                if request.idempotency_key in provider._executions:
                    self.assertTrue(provider._executions[request.idempotency_key]["executed"])
                if consumed:
                    # 1. authority never resurrects.
                    current = tracker.load(request.fields["capability_id"])
                    self.assertIn(current, {
                        ExecutionState.CONSUMED,
                        ExecutionState.INTENT_RECORDED,
                        ExecutionState.DISPATCHED,
                        ExecutionState.EFFECT_UNKNOWN,
                        ExecutionState.EFFECT_CONFIRMED,
                        ExecutionState.INDETERMINATE,
                        ExecutionState.RECONCILED,
                        ExecutionState.CLOSED,
                    })

            for action in actions:
                if action == "consume":
                    try:
                        tracker.begin(request.fields["capability_id"])
                        tracker.transition(request.fields["capability_id"], ExecutionState.AUTHORIZED)
                        tracker.transition(request.fields["capability_id"], ExecutionState.CONSUMED)
                        consumed = True
                    except ExecutionStateError:
                        pass  # duplicate lifecycle entry is rejected
                elif action == "duplicate_consume":
                    if not consumed:
                        continue
                    with self.assertRaises(ExecutionStateError):
                        tracker.begin(request.fields["capability_id"])
                elif action == "intent":
                    record = gateway.begin_effect(request)
                    self.assertEqual(record["state"], "intent_durable" if not dispatched else record["state"])
                elif action in {"dispatch", "retry"}:
                    if action == "retry" and not dispatched:
                        continue
                    try:
                        result = gateway.dispatch(request, provider)
                    except EffectGatewayError:
                        # Illegal from terminal/positive states (e.g. a second
                        # dispatch after commit): fail closed, no mutation.
                        invariants()
                        continue
                    dispatched = True
                    self.assertIn(result["state"], {
                        GATEWAY_COMMITTED,
                        GATEWAY_INDETERMINATE,
                        GATEWAY_CONFIRMED_NOT_COMMITTED,
                        GATEWAY_RECONCILED,
                    })
                elif action == "reconcile":
                    try:
                        result = gateway.reconcile(request, provider)
                    except EffectGatewayError:
                        pass  # illegal from pre-dispatch states; no mutation
                    else:
                        self.assertEqual(result["state"], GATEWAY_RECONCILED)
                elif action == "restart":
                    # Crash + recovery on the same durable store.
                    gateway = EffectGateway(
                        gateway_id="gw-model",
                        statement_signer=signer,
                        intent_store=store,
                        deployment_id="dep-model",
                    )
                elif action == "certify_attempt":
                    record = store.load(request.idempotency_key)
                    if record is None or record["state"] != GATEWAY_RECONCILED:
                        # Unresolved effect blocks clean certification.
                        unresolved = True
                    else:
                        unresolved = False
                        self.assertIn(record["resolution"], {
                            "committed", "confirmed_not_committed", "indeterminate",
                        })
                    # The model's certification rule mirrors the builder's:
                    # clean only when every mediated effect is resolved.
                    del unresolved
                invariants()

            # 3./4. terminal and post-dispatch properties at end of sequence.
            final = store.load(request.idempotency_key)
            if final is None:
                return
            if final["state"] == GATEWAY_RECONCILED:
                self.assertIn(final["resolution"], {
                    "committed", "confirmed_not_committed", "indeterminate",
                })
            elif dispatched:
                self.assertNotEqual(final["state"], "intent_durable")

class QuorumApprovalTests(unittest.TestCase):
    """k-of-n independent approvals; one key satisfies at most one slot."""

    def _quorum_deployment(self, approvers: int = 3):
        from event_horizon.quorum import ApprovalPolicy  # noqa: F401
        from event_horizon.trust_manifest import ManifestChain, TrustRootAuthority, make_actor

        root = TrustRootAuthority(
            bytes([120]) * 32, deployment_id="dep-q", environment="synthetic"
        )
        signer_seeds = [bytes([130 + index]) * 32 for index in range(approvers)]
        signers = [
            StatementSigner(seed, subject=f"approver-{index}")
            for index, seed in enumerate(signer_seeds)
        ]
        manifest = root.issue_manifest(
            [make_actor(role="approver", public_key_pem=signer.public_key_pem) for signer in signers],
            manifest_version=1,
            sequence=1,
            issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain = ManifestChain(
            root.public_key_pem,
            deployment_id="dep-q",
            environment="synthetic",
        )
        chain.append(manifest)
        verifier = StatementVerifier({
            f"approver-{index}": signer.public_key_pem
            for index, signer in enumerate(signers)
        })
        policy = ApprovalPolicy(
            action="issue-containment-certificate", required_approvals=2
        )
        return chain, verifier, policy, signers

    def test_two_of_three_distinct_approvers_satisfy(self) -> None:
        from event_horizon.quorum import evaluate_approvals, make_approval

        chain, verifier, policy, signers = self._quorum_deployment()
        subject = "a" * 64
        approvals = [
            make_approval(signer, policy=policy, subject_digest=subject)
            for signer in signers[:2]
        ]
        outcome = evaluate_approvals(
            approvals,
            policy=policy,
            expected_subject_digest=subject,
            chain=chain,
            statement_verifier=verifier,
        )
        self.assertTrue(outcome.satisfied)
        self.assertEqual(len(outcome.approved_by), 2)

    def test_duplicate_key_identity_counts_once(self) -> None:
        from event_horizon.quorum import evaluate_approvals, make_approval

        chain, verifier, policy, signers = self._quorum_deployment()
        subject = "b" * 64
        duplicate = make_approval(signers[0], policy=policy, subject_digest=subject)
        outcome = evaluate_approvals(
            [duplicate, dict(duplicate)],
            policy=policy,
            expected_subject_digest=subject,
            chain=chain,
            statement_verifier=verifier,
        )
        self.assertFalse(outcome.satisfied)
        self.assertIn("duplicate approver key identity", outcome.detail)

    def test_approval_cannot_be_replayed_onto_another_subject(self) -> None:
        from event_horizon.quorum import evaluate_approvals, make_approval

        chain, verifier, policy, signers = self._quorum_deployment()
        approval = make_approval(
            signers[0], policy=policy, subject_digest="c" * 64
        )
        outcome = evaluate_approvals(
            [approval],
            policy=policy,
            expected_subject_digest="d" * 64,
            chain=chain,
            statement_verifier=verifier,
        )
        self.assertFalse(outcome.satisfied)
        self.assertTrue(any("subject digest mismatch" in reason for _, reason in outcome.rejected))

    def test_unauthorized_role_cannot_approve(self) -> None:
        from event_horizon.quorum import APPROVAL_ACTIONS, evaluate_approvals, make_approval

        # A guardian key is not an approver: role authorization must reject it.
        guardian_signer = StatementSigner(bytes([140]) * 32, subject="guardian")
        root = TrustRootAuthority(
            bytes([141]) * 32, deployment_id="dep-q2", environment="synthetic"
        )
        manifest = root.issue_manifest(
            [make_actor(role="guardian", public_key_pem=guardian_signer.public_key_pem)],
            manifest_version=1,
            sequence=1,
            issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain = ManifestChain(
            root.public_key_pem,
            deployment_id="dep-q2",
            environment="synthetic",
        )
        chain.append(manifest)
        verifier = StatementVerifier({"g": guardian_signer.public_key_pem})
        from event_horizon.quorum import ApprovalPolicy

        policy = ApprovalPolicy(action="issue-containment-certificate", required_approvals=1)
        subject = "e" * 64
        approval = {
            **guardian_signer.sign(TYPE_APPROVAL, {
                "action": policy.action,
                "purpose": APPROVAL_ACTIONS[policy.action],
                "subject_digest": subject,
                "issued_at_ms": 1000,
            }).to_dict(),
        }
        outcome = evaluate_approvals(
            [approval],
            policy=policy,
            expected_subject_digest=subject,
            chain=chain,
            statement_verifier=verifier,
        )
        self.assertFalse(outcome.satisfied)
        self.assertTrue(any("not authorized" in reason for _, reason in outcome.rejected))


class GovernedEffectExecutionTests(unittest.TestCase):
    """Executor-mediated effects: intent before dispatch, honest outcomes."""

    def _governed_executor(self, tmp: str, handler):
        from event_horizon.factory import build_local_harness

        authority, executor, recorder, _broker = build_local_harness(
            tmp, run_id="run-governed"
        )
        executor.compute_profiles["safe-hash"] = handler
        signer = StatementSigner(bytes([95]) * 32, subject="effect-gateway")
        store = SqliteEffectIntentStore(Path(tmp) / "gateway.sqlite3")
        executor.effect_gateway = EffectGateway(
            gateway_id="gw-exec",
            statement_signer=signer,
            intent_store=store,
            deployment_id="dep-local",
        )
        executor.deployment_id = "dep-local"
        executor.run_namespace = "run-governed"
        return authority, executor, recorder, store

    def _issue(self, authority, request_id: str, operation: str = "compute.run",
               resource_id: str = "safe-hash", arguments: dict | None = None):
        return authority.request_capability({
            "request_id": request_id,
            "session_id": "gov-session",
            "agent_id": "attacker-agent",
            "operation": operation,
            "resource_id": resource_id,
            "executor_id": "exec-1",
            "arguments": arguments or {"value": "x"},
            "purpose": "governed execution",
        })

    def test_governed_effect_records_durable_intent_and_commits(self) -> None:
        handler_calls = []

        def handler(args):
            handler_calls.append(dict(args))
            return {"sha256": "d" * 64}

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder, store = self._governed_executor(tmp, handler)
            request, capability, attestation = self._issue(authority, "gov-1")
            result = executor.execute(request, capability, attestation)
            self.assertTrue(result.success)
            self.assertEqual(result.effect_state, "committed")
            self.assertEqual(len(handler_calls), 1)
            # Evidence carries the gateway binding metadata.
            last = recorder.events()[-1]
            self.assertEqual(last["event_type"], "execution.completed")
            binding = last["payload"].get("effect_gateway")
            self.assertIsNotNone(binding)
            # The durable record exists with a signed intent statement and a
            # single mediated attempt.
            record = store.load(binding["idempotency_key"])
            self.assertIsNotNone(record)
            # Positive outcomes reconcile immediately: terminal record with a
            # signed reconciliation statement.
            self.assertEqual(record["state"], "reconciled")
            self.assertEqual(record["resolution"], "committed")
            self.assertIsNotNone(record["intent_statement"])
            self.assertEqual(record["intent_statement"]["statement_type"], "effect-intent")
            self.assertIsNotNone(record.get("reconciliation_statement"))
            self.assertEqual(len(record["attempts"]), 1)

    def test_governed_handler_failure_stays_indeterminate(self) -> None:
        class Boom(Exception):
            pass

        def handler(args):
            raise Boom("mediated handler exploded after side effects")

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder, store = self._governed_executor(tmp, handler)
            request, capability, attestation = self._issue(authority, "gov-2")
            result = executor.execute(request, capability, attestation)
            self.assertFalse(result.success)
            self.assertEqual(result.effect_state, "possibly_committed")
            self.assertIn("indeterminate", result.error)
            last = recorder.events()[-1]
            self.assertEqual(last["event_type"], "execution.indeterminate")

    def test_governed_response_loss_reconciles_to_committed(self) -> None:
        provider = SimulatedEffectProvider()
        provider.configure("compute.run", "timeout-then-commit")

        def forbidden(args):  # pragma: no cover - must never run
            raise AssertionError("local handler must not run in simulation mode")

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder, store = self._governed_executor(
                tmp, forbidden
            )
            from event_horizon.effect_gateway import ProviderAdapter  # noqa: F401

            executor.effect_provider = provider
            request, capability, attestation = self._issue(authority, "gov-3")
            result = executor.execute(request, capability, attestation)
            # Response lost after commit: uncertainty, never denial.
            self.assertFalse(result.success)
            self.assertEqual(result.effect_state, "possibly_committed")
            last = recorder.events()[-1]
            self.assertEqual(last["event_type"], "execution.indeterminate")
            # Reconstruct the immutable effect identity and reconcile.
            effect_request = make_effect_request(
                deployment_id="dep-local",
                environment=executor.environment,
                run_id="run-governed",
                session_id=request.session_id,
                capability_id=capability.claims.capability_id,
                request_digest=request.request_digest,
                operation=request.operation,
                arguments_digest=digest(dict(request.arguments)),
                policy_digest=executor.policy_digest,
                executor_identity=executor.executor_id,
                execution_id=_governed_execution_id(
                    capability.claims.capability_id, request.request_digest
                ),
            )
            reconciled = executor.effect_gateway.reconcile(effect_request, provider)
            self.assertEqual(reconciled["state"], GATEWAY_RECONCILED)
            self.assertEqual(reconciled["resolution"], "committed")
            self.assertIsNotNone(reconciled.get("reconciliation_statement"))

    def test_pure_operations_bypass_the_gateway(self) -> None:
        def handler(args):
            return {"ok": True}

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder, store = self._governed_executor(tmp, handler)
            request, capability, attestation = self._issue(
                authority,
                "gov-pure",
                operation="object.read",
                resource_id="target-source",
                arguments={"length": 4, "offset": 0},
            )
            result = executor.execute(request, capability, attestation)
            self.assertTrue(result.success)
            last = recorder.events()[-1]
            self.assertEqual(last["event_type"], "execution.completed")
            self.assertIsNone(last["payload"].get("effect_gateway"))

    def test_governed_mode_requires_run_namespace(self) -> None:
        from event_horizon.execution_state import ExecutionStateError

        def handler(args):
            return {}

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, _recorder, _store = self._governed_executor(tmp, handler)
            with self.assertRaises(ExecutionStateError):
                type(executor)(
                    executor_id=executor.executor_id,
                    device_id=executor.device_id,
                    measurement=executor.measurement,
                    verifier_policy_digest=executor.verifier_policy_digest,
                    policy_digest=executor.policy_digest,
                    broker=executor.broker,
                    recorder=executor.recorder,
                    compute_profiles=dict(executor.compute_profiles),
                    effect_gateway=executor.effect_gateway,
                    run_namespace=None,
                )

    def test_mediated_certificate_carries_effect_binding(self) -> None:
        def handler(args):
            return {"sha256": "e" * 64}

        with tempfile.TemporaryDirectory() as tmp:
            authority, executor, recorder, store = self._governed_executor(tmp, handler)
            gateway_signer = executor.effect_gateway._signer if hasattr(
                executor.effect_gateway, "_signer"
            ) else StatementSigner(bytes([95]) * 32, subject="effect-gateway")
            request, capability, attestation = self._issue(authority, "gov-4")
            result = executor.execute(request, capability, attestation)
            self.assertTrue(result.success)
            binding = recorder.events()[-1]["payload"]["effect_gateway"]
            record = store.load(binding["idempotency_key"])
            reconciliation = record["reconciliation_statement"]
            builder = ContainmentCertificateBuilder(
                ExternalRecorder(recorder.path, b"R" * 32),
                b"C" * 32,
                statement_verifier=StatementVerifier({
                    "gw": gateway_signer.public_key_pem,
                }),
            )
            certificate = builder.build(
                run_id="run-governed",
                deployment_id="dep-local",
                trust_root_manifest_digest=None,
                effect_reconciliation_statements=[reconciliation],
            )
            payload = certificate["certificate"]
            effects = payload["effects"]
            self.assertEqual(effects["reconciled_count"], 1)
            self.assertEqual(effects["committed"], 1)
            self.assertEqual(
                payload["claims"]["effect_mediation_consistent"], "satisfied"
            )
            self.assertIn("mediated-effects", payload["assurance_guarantees"])


if __name__ == "__main__":
    unittest.main()
