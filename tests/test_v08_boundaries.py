"""v0.8 enforced-boundaries adversarial suite.

Covers: purpose-scoped RPC authorization, root→intermediate delegated
authority (with widening attempts), and the reference authenticated provider
service driven end-to-end through the Effect Gateway over HTTP.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from event_horizon.canonical import digest
from event_horizon.effect_gateway import (
    EffectGateway,
    GATEWAY_COMMITTED,
    GATEWAY_INDETERMINATE,
    GATEWAY_RECONCILED,
    SqliteEffectIntentStore,
    make_effect_request,
)
from event_horizon.reference_provider import (
    ReferenceProviderCore,
    ReferenceProviderServer,
)
from event_horizon.statements import StatementSigner, StatementVerifier
from event_horizon.trust_manifest import (
    IntermediateAuthority,
    KeyNotAuthorizedError,
    ManifestChain,
    TrustManifestError,
    TrustRootAuthority,
    issue_authority_grant,
    make_actor,
)

import json
import urllib.request


def _pem(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


class PurposeScopedRpcTests(unittest.TestCase):
    """Cross-purpose authorization fails closed at the receiving service."""

    def test_purpose_binding_rejects_wrong_purpose(self) -> None:
        from event_horizon.protected_boundary import (
            ProtectedRequestSigner,
            ProtectedRequestVerifier,
            SqliteAuthorizationReplayStore,
        )
        from event_horizon.protocol import ProtocolError

        with tempfile.TemporaryDirectory() as tmp:
            signer = ProtectedRequestSigner(
                bytes([9]) * 32, "certificate-signer", lifetime_ms=5_000
            )
            store = SqliteAuthorizationReplayStore(
                Path(tmp) / "replay.sqlite3",
                namespace="p",
                audience="certificate-signer",
            )
            verifier = ProtectedRequestVerifier(
                signer.public_key_pem, signer.key_id, "certificate-signer", store
            )
            envelope = {
                "type": "build",
                "request_id": "r1",
                "deadline_ms": 9_999_999_999_999,
                "body": {},
            }
            # Signed for certificate-signer.build only.
            authorization = signer.authorize(envelope, purpose="certificate-signer.build")
            verifier.authorize(
                envelope, authorization, expected_purpose="certificate-signer.build"
            )
            # Replaying that same signature for a DIFFERENT purpose fails.
            other_envelope = {
                "type": "rotate",
                "request_id": "r2",
                "deadline_ms": 9_999_999_999_999,
                "body": {},
            }
            forged = dict(authorization)
            forged["request_digest"] = __import__(
                "event_horizon.canonical", fromlist=["digest"]
            ).digest(other_envelope)
            with self.assertRaises(ProtocolError) as denied:
                verifier.authorize(
                    other_envelope, forged, expected_purpose="certificate-signer.rotate"
                )
            self.assertEqual(denied.exception.code, "authorization_purpose")


class DelegatedAuthorityTests(unittest.TestCase):
    """Root blast-radius reduction: intermediate cannot exceed its grant."""

    ROOT_SEED = bytes([60]) * 32
    INTERMEDIATE_SEED = bytes([61]) * 32

    def _hierarchy(self, *, allowed_roles=None, may_replace_witness=False,
                   max_sequence=50):
        root = TrustRootAuthority(self.ROOT_SEED, deployment_id="dep-r", environment="synthetic")
        grant = issue_authority_grant(
            root,
            _pem(self.INTERMEDIATE_SEED),
            grant_id="grant-1",
            allowed_roles=allowed_roles or ["guardian", "verifier", "recorder"],
            may_replace_witness=may_replace_witness,
            max_manifest_sequence=max_sequence,
            issued_at_ms=1000,
        )
        intermediate = IntermediateAuthority(
            self.INTERMEDIATE_SEED,
            deployment_id="dep-r",
            environment="synthetic",
            grant=grant,
        )
        chain = ManifestChain(
            root.public_key_pem,
            deployment_id="dep-r",
            environment="synthetic",
            authority_grant=grant,
        )
        return root, grant, intermediate, chain

    def test_intermediate_rotates_within_grant(self) -> None:
        _root, _grant, intermediate, chain = self._hierarchy()
        v1 = intermediate.issue_manifest(
            [make_actor(role="guardian", public_key_pem=_pem(bytes([62]) * 32))],
            manifest_version=1,
            sequence=1,
            issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain.append(v1)
        v2 = intermediate.issue_manifest(
            [make_actor(role="guardian", public_key_pem=_pem(bytes([63]) * 32))],
            manifest_version=2,
            sequence=2,
            issued_at_ms=2000,
            previous_manifest_digest=chain.current.manifest_digest,
        )
        chain.append(v2)
        self.assertEqual(chain.version, 2)
        # Runtime verification needed ONLY the offline root's public key.
        self.assertIsNotNone(chain.current)

    def test_intermediate_cannot_authorize_role_outside_grant(self) -> None:
        _root, _grant, intermediate, chain = self._hierarchy(
            allowed_roles=["guardian"]
        )
        v1 = intermediate.issue_manifest(
            [make_actor(role="guardian", public_key_pem=_pem(bytes([64]) * 32))],
            manifest_version=1, sequence=1, issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain.append(v1)
        with self.assertRaises(KeyNotAuthorizedError) as denied:
            chain.append(intermediate.issue_manifest(
                [make_actor(role="witness", public_key_pem=_pem(bytes([65]) * 32),
                            purposes={"witness-checkpoint"})],
                manifest_version=2, sequence=2, issued_at_ms=2000,
                previous_manifest_digest=chain.current.manifest_digest,
            ))
        self.assertEqual(denied.exception.reason_code, "role-outside-grant")

    def test_intermediate_cannot_replace_witness_without_authority(self) -> None:
        witness_a = make_actor(role="witness", public_key_pem=_pem(bytes([70]) * 32))
        _root, _grant, intermediate, chain = self._hierarchy(
            allowed_roles=["guardian", "verifier", "recorder", "witness"],
            may_replace_witness=False,
        )
        v1 = intermediate.issue_manifest(
            [witness_a, make_actor(role="guardian", public_key_pem=_pem(bytes([71]) * 32))],
            manifest_version=1, sequence=1, issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain.append(v1)
        with self.assertRaises(KeyNotAuthorizedError) as denied:
            chain.append(intermediate.issue_manifest(
                [
                    make_actor(role="witness", public_key_pem=_pem(bytes([72]) * 32)),
                    make_actor(role="guardian", public_key_pem=_pem(bytes([71]) * 32)),
                ],
                manifest_version=2, sequence=2, issued_at_ms=2000,
                previous_manifest_digest=chain.current.manifest_digest,
            ))
        self.assertEqual(denied.exception.reason_code, "witness-replacement-forbidden")

    def test_intermediate_sequence_beyond_grant_fails_closed(self) -> None:
        _root, _grant, intermediate, chain = self._hierarchy(max_sequence=3)
        v1 = intermediate.issue_manifest(
            [make_actor(role="guardian", public_key_pem=_pem(bytes([73]) * 32))],
            manifest_version=1, sequence=1, issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        chain.append(v1)
        with self.assertRaises(KeyNotAuthorizedError):
            chain.append(intermediate.issue_manifest(
                [make_actor(role="guardian", public_key_pem=_pem(bytes([74]) * 32))],
                manifest_version=2, sequence=99, issued_at_ms=2000,
                previous_manifest_digest=chain.current.manifest_digest,
            ))

    def test_root_signature_no_longer_accepted_under_delegation(self) -> None:
        root, _grant, _intermediate, chain = self._hierarchy()
        # The root itself signs a manifest; under delegation this must fail.
        directly_signed = root.issue_manifest(
            [make_actor(role="guardian", public_key_pem=_pem(bytes([75]) * 32))],
            manifest_version=1, sequence=1, issued_at_ms=1000,
            previous_manifest_digest=None,
        )
        with self.assertRaises(KeyNotAuthorizedError):
            chain.verify_envelope(directly_signed)


class HttpProviderAdapterTests(unittest.TestCase):
    """Gateway → reference provider over HTTP; ambiguity handled honestly."""

    class _HttpAdapter:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def _post(self, path: str, body: dict):
            request = urllib.request.Request(
                self.base_url + path,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        def execute(self, effect_request, idempotency_key: str):
            status, body = self._post("/execute", {
                "idempotency_key": idempotency_key,
                "effect_id": effect_request["effect_id"],
                "effect_fingerprint": digest({
                    "operation": effect_request["operation"],
                    "arguments_digest": effect_request["arguments_digest"],
                }),
                "operation": effect_request["operation"],
                "request_digest": effect_request["request_digest"],
            })
            if status == 504:
                raise TimeoutError("provider response lost")
            if status == 409:
                from event_horizon.effect_gateway import EffectIdentityCollision

                raise EffectIdentityCollision(body.get("error", "collision"))
            return status, body

        def reconcile(self, idempotency_key: str):
            status, body = self._post("/reconcile", {"idempotency_key": idempotency_key})
            return status, body

    def _gateway(self, tmp: str):
        signer = StatementSigner(bytes([20]) * 32, subject="effect-gateway")
        return EffectGateway(
            gateway_id="gw-http",
            statement_signer=signer,
            intent_store=SqliteEffectIntentStore(Path(tmp) / "intents.sqlite3"),
            deployment_id="dep-hp",
        )

    def _request(self, operation: str, n: int):
        return make_effect_request(
            deployment_id="dep-hp", environment="synthetic", run_id="run-1",
            session_id="s-1", capability_id="cap_" + "a" * 24,
            request_digest=digest({"op": operation, "n": n}),
            operation=operation, arguments_digest="b" * 64,
            policy_digest="c" * 64, executor_identity="exec-1",
        )

    def _run_provider_adapter(self, result: tuple):
        from event_horizon.effect_gateway import (
            PROVIDER_COMMITTED,
            PROVIDER_CONFIRMED_NOT_EXECUTED,
            PROVIDER_UNKNOWN,
            ProviderResult,
        )

        status, body = result
        if status == 504:
            raise TimeoutError("lost")
        state = {
            "committed": PROVIDER_COMMITTED,
            "confirmed-not-executed": PROVIDER_CONFIRMED_NOT_EXECUTED,
        }.get(str(body.get("state")), PROVIDER_UNKNOWN)
        receipt = body.get("receipt")
        return ProviderResult(
            state=state,
            receipt_digest=(
                digest(receipt["provider_transaction_id"]) if receipt else None
            ),
            detail=dict(body),
            evidence_class=str(body.get("evidence_class", "unverified_adapter_report")),
            provider_receipt_envelope=receipt,
        )

    def test_response_loss_reconciles_to_single_authenticated_commit(self) -> None:
        core = ReferenceProviderCore(
            provider_id="ref-provider",
            signing_key=bytes([30]) * 32,
            scenario_for_operation={"flaky": "commit-lose-response"},
        )
        server = ReferenceProviderServer(core)
        server.start()
        try:
            adapter = self._HttpAdapter(server.base_url)
            wrapped = type("W", (), {
                "execute": lambda s, r, k: self._run_provider_adapter(adapter.execute(r, k)),
                "reconcile": lambda s, k: self._run_provider_adapter(adapter.reconcile(k)),
            })()
            with tempfile.TemporaryDirectory() as tmp:
                gateway = self._gateway(tmp)
                request = self._request("flaky", 1)
                first = gateway.dispatch(request, wrapped)
                self.assertEqual(first["state"], GATEWAY_INDETERMINATE)
                reconciled = gateway.reconcile(request, wrapped)
                self.assertEqual(reconciled["state"], GATEWAY_RECONCILED)
                self.assertEqual(reconciled["resolution"], "committed")
                # Exactly one authoritative transaction exists at the provider.
                self.assertEqual(len(core.records), 1)
                statement = reconciled["reconciliation_statement"]
                self.assertEqual(
                    statement["payload"]["provider_evidence_class"],
                    "provider_authenticated_receipt",
                )
        finally:
            server.stop()

    def test_changed_content_under_same_identity_is_rejected_by_provider(self) -> None:
        core = ReferenceProviderCore(provider_id="ref", signing_key=bytes([31]) * 32)
        server = ReferenceProviderServer(core)
        server.start()
        try:
            adapter = self._HttpAdapter(server.base_url)
            request = self._request("deploy", 7)
            fp = digest({"operation": "deploy", "arguments_digest": "b" * 64})
            status, body = adapter.execute(request.to_dict(), request.idempotency_key)
            self.assertEqual(status, 200)
            attacker_fp = digest({"operation": "deploy", "arguments_digest": "d" * 64})
            # Forge at the transport layer: same immutable identity, changed
            # semantic content. The provider must refuse (409), not fork.
            status2, body2 = adapter._post(
                "/execute",
                {
                    "idempotency_key": request.idempotency_key,
                    "effect_id": request.effect_id,
                    "effect_fingerprint": attacker_fp,
                    "operation": "deploy",
                    "request_digest": request.fields["request_digest"],
                },
            )
            self.assertEqual(status2, 409)
            self.assertIn("different content", body2["error"])
        finally:
            server.stop()

    def test_unreachable_provider_stays_indeterminate_forever(self) -> None:
        core = ReferenceProviderCore(
            provider_id="ref-down",
            signing_key=bytes([32]) * 32,
            scenario_for_operation={"stuck": "unavailable"},
        )
        # No server started: transport is dead from the gateway's view.
        adapter = self._HttpAdapter("http://127.0.0.1:1")
        wrapped = type("W", (), {
            "execute": lambda s, r, k: (_ for _ in ()).throw(TimeoutError("down")),
            "reconcile": lambda s, k: (_ for _ in ()).throw(TimeoutError("down")),
        })()
        del core, adapter
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self._gateway(tmp)
            request = self._request("stuck", 2)
            first = gateway.dispatch(request, wrapped)
            self.assertEqual(first["state"], GATEWAY_INDETERMINATE)
            with self.assertRaises(TimeoutError):
                gateway.reconcile(request, wrapped)
            # Still indeterminate after repeated reconciliation attempts.
            with self.assertRaises(TimeoutError):
                gateway.reconcile(request, wrapped)


class DeploymentBoundaryTests(unittest.TestCase):
    """Credential inventory + high-assurance fail-closed gate."""

    def test_executor_holding_provider_credential_fails_inventory(self) -> None:
        from event_horizon.deployment import (
            CredentialBinding,
            verify_credential_inventory,
        )

        bindings = [
            CredentialBinding("provider-api-token", "effect-gateway", "provider access"),
            CredentialBinding("witness-signing-key", "witness", "checkpoint signing"),
            CredentialBinding("recorder-signing-key", "recorder", "chain receipts"),
        ]
        clean = verify_credential_inventory({
            "executor": "",
            "effect-gateway": "provider-api-token",
            "witness": "witness-signing-key",
            "recorder": "recorder-signing-key",
        }, bindings)
        self.assertTrue(clean["clean"], clean["violations"])

        leak = verify_credential_inventory({
            "executor": "provider-api-token",
            "effect-gateway": "provider-api-token",
            "witness": "witness-signing-key",
            "recorder": "recorder-signing-key",
        }, bindings)
        self.assertFalse(leak["clean"])
        self.assertTrue(any("executor" in v and "provider-api-token" in v
                            for v in leak["violations"]))

    def test_coordinator_with_witness_key_fails_inventory(self) -> None:
        from event_horizon.deployment import (
            CredentialBinding,
            verify_credential_inventory,
        )

        bindings = [
            CredentialBinding("witness-signing-key", "witness", "checkpoint signing"),
        ]
        report = verify_credential_inventory(
            {"coordinator": "witness-signing-key", "witness": "witness-signing-key"},
            bindings,
        )
        self.assertFalse(report["clean"])

    def test_high_assurance_mode_fails_closed_on_missing_boundary(self) -> None:
        from event_horizon.deployment import (
            DeploymentBoundaryError,
            assert_high_assurance_requirements,
        )

        # Development mode tolerates absent boundaries.
        assert_high_assurance_requirements({}, mode="development")
        # High assurance must fail loudly, not silently downgrade.
        with self.assertRaises(DeploymentBoundaryError) as denied:
            assert_high_assurance_requirements({"replay_durable": True}, mode="high_assurance")
        self.assertIn("provider_credentials_gateway_only", str(denied.exception))
        # All observed requirements present → passes.
        full = {
            "provider_credentials_gateway_only": True,
            "executor_provider_route_denied": True,
            "witness_storage_independent": True,
            "manifest_enforced_end_to_end": True,
            "root_offline_from_runtime": True,
        }
        assert_high_assurance_requirements(full, mode="high_assurance")

    def test_network_policy_declared_vs_observed(self) -> None:
        from event_horizon.deployment import summarize_network_policy

        declared = {
            "executor->effect_gateway": "allow",
            "executor->provider": "deny",
            "gateway->provider": "allow",
        }
        honest_probes = {
            "executor->effect_gateway": True,
            "executor->provider": False,   # blocked as intended
            "gateway->provider": True,
        }
        good = summarize_network_policy(declared, honest_probes)
        self.assertTrue(good["enforced"])
        self.assertEqual(good["violations"], [])

        leaky_probes = dict(honest_probes)
        leaky_probes["executor->provider"] = True  # bypass path exists!
        bad = summarize_network_policy(declared, leaky_probes)
        self.assertFalse(bad["enforced"])
        self.assertTrue(any("executor->provider" in v for v in bad["violations"]))


if __name__ == "__main__":
    unittest.main()
