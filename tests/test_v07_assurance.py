"""v0.7 assurance-integrity adversarial suite.

Phase 1: logical-effect identity versus effect fingerprint.
"""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from event_horizon.canonical import digest
from event_horizon.certificate import ContainmentCertificateBuilder
from event_horizon.effect_gateway import (
    EffectGateway,
    EffectGatewayError,
    EffectIdentityCollision,
    GATEWAY_COMMITTED,
    GATEWAY_INDETERMINATE,
    SimulatedEffectProvider,
    SqliteEffectIntentStore,
    make_effect_request,
)
from event_horizon.executor import (
    _governed_effect_id,
    _governed_execution_id,
)
from event_horizon.recorder import ExternalRecorder, FileCheckpointAnchor
from event_horizon.statements import StatementSigner, StatementVerifier
from event_horizon.trust_manifest import (
    KeyNotAuthorizedError,
    ManifestChain,
    TrustRootAuthority,
    historical_trust,
    make_actor,
)
from event_horizon.verification_bundle import build_bundle, verify_bundle
from event_horizon.witness import LocalCheckpointWitness
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _pem(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _key_id(seed: bytes) -> str:
    import hashlib

    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


def _request(**overrides):
    """Build a governed effect request with deterministic identity parts."""
    fields = {
        "deployment_id": "dep-id",
        "environment": "synthetic",
        "run_id": "run-1",
        "session_id": "s-1",
        "capability_id": "cap_" + "a" * 24,
        "request_digest": "1" * 64,
        "operation": "transfer",
        "arguments_digest": digest({"amount": 10}),
        "policy_digest": "2" * 64,
        "executor_identity": "exec-1",
        "execution_id": _governed_execution_id("cap_" + "a" * 24, "1" * 64),
        "effect_id": _governed_effect_id("cap_" + "a" * 24, "1" * 64),
        "provider_scope": "payments-primary",
    }
    fields.update(overrides)
    return make_effect_request(
        deployment_id=fields["deployment_id"],
        environment=fields["environment"],
        run_id=fields["run_id"],
        session_id=fields["session_id"],
        capability_id=fields["capability_id"],
        request_digest=fields["request_digest"],
        operation=fields["operation"],
        arguments_digest=fields["arguments_digest"],
        policy_digest=fields["policy_digest"],
        executor_identity=fields["executor_identity"],
        execution_id=fields["execution_id"],
        effect_id=fields["effect_id"],
        provider_scope=fields["provider_scope"],
    )


class EffectIdentityTests(unittest.TestCase):
    def _gateway(self, tmp: str) -> EffectGateway:
        signer = StatementSigner(bytes([7]) * 32, subject="effect-gateway")
        store = SqliteEffectIntentStore(Path(tmp) / "intents.sqlite3")
        return EffectGateway(
            gateway_id="gw-id",
            statement_signer=signer,
            intent_store=store,
            deployment_id="dep-id",
        )

    def test_retry_of_same_logical_effect_reuses_identity_and_executes_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            provider = SimulatedEffectProvider()
            request = _request()
            first = gateway.dispatch(request, provider)
            self.assertEqual(first["state"], GATEWAY_COMMITTED)
            second = gateway.dispatch(request, provider)  # operator retry
            self.assertEqual(second["state"], GATEWAY_COMMITTED)
            self.assertEqual(
                first["idempotency_key"], second["idempotency_key"]
            )
            # Exactly one logical provider effect for this identity.
            self.assertEqual(len(provider._executions), 1)

    def test_identical_operation_twice_is_two_distinct_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            provider = SimulatedEffectProvider()
            # Same operation + same canonical arguments (same fingerprint),
            # but a fresh logical identity: a genuinely new intended effect.
            first_request = _request()
            second_request = _request(
                execution_id=_governed_execution_id("cap_" + "b" * 24, "1" * 64),
                effect_id=_governed_effect_id("cap_" + "b" * 24, "1" * 64),
                capability_id="cap_" + "b" * 24,
                request_digest="3" * 64,
            )
            self.assertNotEqual(
                first_request.idempotency_key, second_request.idempotency_key
            )
            self.assertEqual(first_request.fingerprint, second_request.fingerprint)
            gateway.dispatch(first_request, provider)
            gateway.dispatch(second_request, provider)
            self.assertEqual(len(provider._executions), 2)

    def test_same_identity_with_changed_arguments_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            provider = SimulatedEffectProvider()
            original = _request()
            gateway.dispatch(original, provider)
            attacker = _request(arguments_digest=digest({"amount": 9999}))
            self.assertEqual(attacker.idempotency_key, original.idempotency_key)
            with self.assertRaises(EffectIdentityCollision):
                gateway.dispatch(attacker, provider)
            # The durable record still binds the ORIGINAL semantics only.
            record = gateway.status(original)
            self.assertEqual(record["fingerprint"], original.fingerprint)

    def test_same_identity_with_changed_bound_context_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            provider = SimulatedEffectProvider()
            original = _request()
            gateway.begin_effect(original)
            # Same logical identity, different underlying authorization target.
            forged = _request(request_digest="4" * 64)
            self.assertEqual(forged.idempotency_key, original.idempotency_key)
            with self.assertRaises(EffectIdentityCollision):
                gateway.begin_effect(forged)

    def test_cross_provider_scope_is_a_different_logical_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            provider = SimulatedEffectProvider()
            primary = _request(provider_scope="payments-primary")
            failover = _request(provider_scope="payments-failover")
            self.assertNotEqual(primary.idempotency_key, failover.idempotency_key)
            gateway.dispatch(primary, provider)
            # The failover scope is a separate identity at a separate
            # provider; it is never silently deduplicated against primary.
            result = gateway.dispatch(failover, provider)
            self.assertIn(result["state"], {GATEWAY_COMMITTED, GATEWAY_INDETERMINATE})

    def test_cross_deployment_reuse_never_shares_identity(self) -> None:
        signer = StatementSigner(bytes([8]) * 32, subject="effect-gateway")
        with tempfile.TemporaryDirectory() as tmp:
            other_gateway = EffectGateway(
                gateway_id="gw-other",
                statement_signer=signer,
                intent_store=SqliteEffectIntentStore(Path(tmp) / "other.sqlite3"),
                deployment_id="dep-other",
            )
            foreign = _request(deployment_id="dep-other")
            with self.assertRaises(EffectGatewayError):
                other_gateway.begin_effect(_request())
            # And even if identities were identical, the deployment field is
            # part of the key, so no cross-deployment sharing can occur.
            local = _request()
            self.assertNotEqual(local.idempotency_key, foreign.idempotency_key)

    def test_concurrent_duplicate_dispatch_yields_one_provider_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            provider = SimulatedEffectProvider()
            request = _request()
            barrier = threading.Barrier(6, timeout=10)

            def dispatch(_: int):
                barrier.wait()
                try:
                    return gateway.dispatch(request, provider)
                except EffectGatewayError:
                    return None

            with ThreadPoolExecutor(max_workers=6) as pool:
                outcomes = list(pool.map(dispatch, range(6)))
            committed = [
                outcome for outcome in outcomes
                if outcome is not None and outcome["state"] == GATEWAY_COMMITTED
            ]
            self.assertGreaterEqual(len(committed), 1)
            self.assertEqual(len(outcomes), 6)
            # At most one logical provider effect where the provider supports
            # idempotency — regardless of how many racing dispatches ran.
            self.assertEqual(len(provider._executions), 1)


class AntiBackdatingTests(unittest.TestCase):
    """Phase 2: post-compromise signature backdating must fail closed."""

    GUARDIAN_SEED = bytes([151]) * 32

    def _world(self, tmp: str) -> dict:
        root = TrustRootAuthority(
            bytes([150]) * 32, deployment_id="dep-h", environment="synthetic"
        )
        guardian_signer = StatementSigner(self.GUARDIAN_SEED, subject="guardians")
        witness = LocalCheckpointWitness(
            Path(tmp) / "witness.jsonl",
            witness_id="w-bd",
            signing_key=bytes([152]) * 32,
            deployment_id="dep-h",
        )
        recorder = ExternalRecorder(Path(tmp) / "events.jsonl", b"R" * 32)
        anchor = FileCheckpointAnchor(Path(tmp) / "anchor.jsonl")
        manifest_v1 = root.issue_manifest(
            [make_actor(role="guardian", public_key_pem=guardian_signer.public_key_pem)],
            manifest_version=1,
            sequence=1,
            issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain = ManifestChain(
            root.public_key_pem,
            deployment_id="dep-h",
            environment="synthetic",
        )
        chain.append(manifest_v1)
        return {
            "root": root,
            "chain": chain,
            "guardian_seed": self.GUARDIAN_SEED,
            "guardian_signer": guardian_signer,
            "witness": witness,
            "recorder": recorder,
            "anchor": anchor,
            "tmp": tmp,
        }

    def _statement(self, world: dict, *, issued_at_ms: int | None = None) -> dict:
        payload = {"allowed": True}
        if issued_at_ms is not None:
            payload["issued_at_ms"] = issued_at_ms
        return world["guardian_signer"].sign("guardian-decision", payload).to_dict()

    def _observe(self, world: dict, *, statement_envelope: dict, manifest_version: int) -> dict:
        """Embed the statement into a witnessed checkpoint under the given
        trust state, returning a structured pre-revocation observation."""
        record = world["recorder"].append(
            "guardian.decision",
            {"statement": statement_envelope},
            source_id="c",
        )
        manifest_digest = world["chain"].manifest_at(manifest_version).manifest_digest
        checkpoint_envelope = world["recorder"].issue_checkpoint(
            world["anchor"],
            deployment_id="dep-h",
            manifest_digest=manifest_digest,
        )
        ack = world["witness"].publish_checkpoint(
            checkpoint_envelope,
            recorder_public_key_pem=world["recorder"].public_key_pem,
            manifest_digest=manifest_digest,
        )
        return {
            "kind": "witnessed_recorder_checkpoint",
            "checkpoint_sequence": ack["checkpoint_sequence"],
            "event_hash": record["event_hash"],
            "ack": ack,
            "witness_public_key_pem": world["witness"].public_key_pem,
        }

    def test_active_witnessed_then_revoked_remains_historically_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            statement = self._statement(world)
            observation = self._observe(
                world, statement_envelope=statement, manifest_version=1
            )
            # Later rotation revokes the guardian key.
            v2 = world["root"].issue_manifest(
                [make_actor(role="guardian", public_key_pem=_pem(bytes([153]) * 32))],
                manifest_version=2,
                sequence=5,
                issued_at_ms=2000,
                previous_manifest_digest=world["chain"].current.manifest_digest,
                revocations=[{
                    "key_id": _key_id(self.GUARDIAN_SEED),
                    "reason_code": "compromise",
                    "effective_sequence": 5,
                }],
            )
            world["chain"].append(v2)
            verifier = StatementVerifier({
                "g": world["guardian_signer"].public_key_pem
            })
            verifier.verify(statement, expected_type="guardian-decision")
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                purpose="approve-request",
                manifest_version=1,
                signature_valid=True,
                observation=observation,
            )
            self.assertTrue(verdict.historically_trusted, verdict.reason)
            self.assertTrue(verdict.statement_observed_before_revocation)

    def test_revoked_signer_cannot_backdate_claim_to_old_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            v2 = world["root"].issue_manifest(
                [make_actor(role="guardian", public_key_pem=_pem(bytes([153]) * 32))],
                manifest_version=2,
                sequence=5,
                issued_at_ms=2000,
                previous_manifest_digest=world["chain"].current.manifest_digest,
                revocations=[{
                    "key_id": _key_id(self.GUARDIAN_SEED),
                    "reason_code": "compromise",
                    "effective_sequence": 5,
                }],
            )
            world["chain"].append(v2)
            # Attacker forges a fresh statement and labels it as issued under
            # the still-trusted manifest v1.
            backdated = self._statement(world)
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                manifest_version=1,
                signature_valid=True,
                observation=None,
            )
            self.assertFalse(verdict.historically_trusted)
            self.assertEqual(verdict.reason, "statement-existence-unobserved")

    def test_post_revocation_checkpoint_does_not_establish_existence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            v2 = world["root"].issue_manifest(
                [make_actor(role="guardian", public_key_pem=_pem(bytes([153]) * 32))],
                manifest_version=2,
                sequence=5,
                issued_at_ms=2000,
                previous_manifest_digest=world["chain"].current.manifest_digest,
                revocations=[{
                    "key_id": _key_id(self.GUARDIAN_SEED),
                    "reason_code": "compromise",
                    "effective_sequence": 5,
                }],
            )
            world["chain"].append(v2)
            # The attacker records an alleged old statement into a NEW
            # checkpoint and gets it acknowledged under the current (post-
            # revocation) trust state.
            forged = self._statement(world)
            late_observation = self._observe(
                world, statement_envelope=forged, manifest_version=2
            )
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                manifest_version=1,
                signature_valid=True,
                observation=late_observation,
            )
            self.assertFalse(verdict.historically_trusted)
            self.assertEqual(verdict.reason, "observed-at-or-after-revocation")

    def test_retired_but_not_compromised_keeps_historical_validity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            statement = self._statement(world)
            observation = self._observe(
                world, statement_envelope=statement, manifest_version=1
            )
            # Orderly retirement (no compromise, no revocation).
            v2 = world["root"].issue_manifest(
                [
                    make_actor(
                        role="guardian",
                        public_key_pem=world["guardian_signer"].public_key_pem,
                        status="retired",
                    )
                ],
                manifest_version=2,
                sequence=4,
                issued_at_ms=2000,
                previous_manifest_digest=world["chain"].current.manifest_digest,
            )
            world["chain"].append(v2)
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                manifest_version=1,
                signature_valid=True,
                observation=observation,
            )
            self.assertTrue(verdict.historically_trusted, verdict.reason)

    def test_forged_old_timestamp_is_irrelevant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            ancient = self._statement(world, issued_at_ms=1)
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                manifest_version=1,
                signature_valid=True,
                observation=None,
            )
            self.assertFalse(verdict.historically_trusted)
            self.assertEqual(verdict.reason, "statement-existence-unobserved")

    def test_stale_manifest_claim_without_prior_inclusion_is_insufficient(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            statement = self._statement(world)
            verifier = StatementVerifier({"g": world["guardian_signer"].public_key_pem})
            verifier.verify(statement, expected_type="guardian-decision")
            # Signature valid + claimed manifest exists, but no independent
            # inclusion evidence: strong historical claims are unavailable.
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                manifest_version=1,
                signature_valid=True,
                observation=None,
            )
            self.assertFalse(verdict.historically_trusted)

    def test_observation_from_unknown_or_untrusted_witness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            world = self._world(tmp)
            fake_witness = LocalCheckpointWitness(
                Path(tmp) / "fake.jsonl",
                witness_id="evil",
                signing_key=bytes([154]) * 32,
                deployment_id="dep-h",
            )
            statement = self._statement(world)
            observation = {
                "kind": "witnessed_recorder_checkpoint",
                "checkpoint_sequence": 1,
                "event_hash": "a" * 64,
                "ack": {"forged": True},
                "witness_public_key_pem": fake_witness.public_key_pem,
            }
            verdict = historical_trust(
                world["chain"],
                key_id=_key_id(self.GUARDIAN_SEED),
                role="guardian",
                manifest_version=1,
                signature_valid=True,
                observation=observation,
            )
            self.assertFalse(verdict.historically_trusted)
            self.assertEqual(verdict.reason, "observation-unverifiable")


class AssuranceInflationTests(unittest.TestCase):
    """A certificate must never claim more than the evidence justifies."""

    def test_local_witness_cannot_satisfy_independence_facts(self) -> None:
        from event_horizon.assurance import derive_profile, normalize_facts

        # A same-host witness signs acknowledgments declaring its own
        # dependence; the facts must reflect that honestly.
        with tempfile.TemporaryDirectory() as tmp:
            ab = AntiBackdatingTests.__new__(AntiBackdatingTests)
            world = ab._world(tmp)
            statement = ab._statement(world)
            observation = ab._observe(
                world, statement_envelope=statement, manifest_version=1
            )
            independence = observation["ack"]["independence"]
            self.assertFalse(independence["administrative"])
            self.assertFalse(independence["storage"])
            facts = normalize_facts({
                "authenticated_sources": True,
                "namespace_complete": True,
                "replay_durable": True,
                "history_witnessed": True,
                "witness_administratively_independent": independence["administrative"],
                "witness_storage_independent": independence["storage"],
            })
            self.assertEqual(derive_profile(facts), "WITNESSED_HISTORY")

    def test_caller_cannot_request_an_assurance_profile(self) -> None:
        builder = ContainmentCertificateBuilder(
            ExternalRecorder(Path(tempfile.mkdtemp()) / "e.jsonl", b"R" * 32),
            b"C" * 32,
        )
        with self.assertRaises(TypeError):
            builder.build(  # type: ignore[call-arg]
                run_id="r",
                deployment_id="d",
                assurance_profile="HIGH_ASSURANCE",
            )

    def test_observed_mediation_without_enforcement_stays_downgraded(self) -> None:
        from event_horizon.assurance import derive_profile, normalize_facts

        facts = normalize_facts({
            "authenticated_sources": True,
            "namespace_complete": True,
            "effect_mediated": True,
            "effects_reconciled": True,
            "effect_mediation_enforced": False,
        })
        self.assertEqual(derive_profile(facts), "GOVERNED_EFFECTS")
        # Enforcement alone is insufficient for INDEPENDENT_CONTROL_PLANE: it
        # also requires independently witnessed history and an independent
        # witness.
        enforced = dict(facts)
        enforced["effect_mediation_enforced"] = True
        self.assertEqual(derive_profile(enforced), "GOVERNED_EFFECTS")
        full = dict(enforced)
        full.update({
            "replay_durable": True,
            "history_witnessed": True,
            "witness_administratively_independent": True,
            "witness_storage_independent": True,
            "keys_independently_administered": True,
            "provider_receipts_authenticated": True,
            "manifest_authorized_sources": True,
            "quorum_approval_present": True,
        })
        self.assertEqual(derive_profile(full), "HIGH_ASSURANCE")


class VerificationBundleTests(unittest.TestCase):
    """Offline third-party verification of a self-contained evidence bundle."""

    def _harvest_bundle(self) -> tuple:
        from event_horizon.process_harness import ProcessSeparatedHarness

        harness = ProcessSeparatedHarness(
            tempfile.mkdtemp(prefix="eh-bundle-"), ttl_seconds=30
        ).start()
        try:
            request, capability, attestation = harness.request_capability({
                "request_id": "bundle-1", "session_id": "bs-1",
                "agent_id": "attacker-agent", "operation": "object.read",
                "resource_id": "target-source", "executor_id": "exec-1",
                "arguments": {"length": 8, "offset": 0}, "purpose": "bundle test",
            })
            self.assertTrue(harness.execute(request, capability, attestation).success)
            harness.teardown_executor()
            certificate = harness.build_certificate()
            witnessed = harness.publish_witness_checkpoint()
            trusted_dir = Path(harness.workdir) / "trusted-control"
            manifest_env = json.loads((trusted_dir / "trust-manifest.json").read_text())
            policy_statement = json.loads(
                (trusted_dir / "deployment-policy.json").read_text()
            )
            journal_path = Path(harness.workdir) / "witness" / "acknowledgments.jsonl"
            conflicts = [
                json.loads(line)
                for line in journal_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and json.loads(line).get("statement_type") == "witness-conflict"
            ]
            bundle = build_bundle(
                certificate=certificate,
                trust_manifest_envelopes=[manifest_env],
                deployment_policy_statement=policy_statement,
                witness_acknowledgments=[witnessed["acknowledgment"]],
                witness_conflicts=conflicts,
                recorder_checkpoints=[witnessed["checkpoint"]],
            )
            root_pem = harness.deployment_root_public_key_pem
            witness_pem = harness.service_info["witness"]["public_key_pem"]
            return bundle, root_pem, [witness_pem]
        finally:
            harness.close()

    def test_complete_bundle_verifies_offline(self) -> None:
        bundle, root_pem, witness_pems = self._harvest_bundle()
        report = verify_bundle(
            bundle, trusted_root_public_key_pem=root_pem,
            trusted_witness_public_keys_pem=witness_pems,
        ).to_dict()
        self.assertTrue(report["cryptographic_validity"], report["detail"])
        self.assertTrue(report["historical_trust_validity"])
        self.assertTrue(report["namespace_integrity"])
        self.assertEqual(report["evidence_completeness"], "complete")
        self.assertEqual(report["history_status"], "witnessed")
        self.assertEqual(report["mediation_status"], "not-mediated")
        self.assertEqual(report["independence_status"], "local-only")
        self.assertEqual(report["conflicts"], [])
        self.assertEqual(report["profile"], "WITNESSED_HISTORY")
        self.assertTrue(report["assurance_facts"]["history_witnessed"])

    def test_bundle_without_witness_cannot_support_witnessed_claim(self) -> None:
        bundle, root_pem, witness_pems = self._harvest_bundle()
        stripped = dict(bundle)
        stripped["witness_acknowledgments"] = []
        report = verify_bundle(
            stripped, trusted_root_public_key_pem=root_pem,
            trusted_witness_public_keys_pem=witness_pems,
        ).to_dict()
        self.assertIn("conflicted-evidence", report["history_status"])

    def test_substituted_witness_key_is_rejected(self) -> None:
        bundle, root_pem, _witness_pems = self._harvest_bundle()
        outsider = Ed25519PrivateKey.from_private_bytes(b"\x71" * 32).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        report = verify_bundle(
            bundle, trusted_root_public_key_pem=root_pem,
            trusted_witness_public_keys_pem=[outsider],
        ).to_dict()
        self.assertIn("conflicted-evidence", report["history_status"])

    def test_missing_manifest_chain_breaks_historical_validity(self) -> None:
        bundle, _root_pem, _pems = self._harvest_bundle()
        root = TrustRootAuthority(bytes([200]) * 32, deployment_id="dep-x",
                                  environment="synthetic")
        stripped = dict(bundle)
        stripped["trust_manifest_envelopes"] = []
        report = verify_bundle(
            stripped, trusted_root_public_key_pem=root.public_key_pem,
            trusted_witness_public_keys_pem=[],
        ).to_dict()
        self.assertFalse(report["historical_trust_validity"])


if __name__ == "__main__":
    unittest.main()
