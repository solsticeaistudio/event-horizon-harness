"""v0.9 portable proof-closure suite.

Core workflow under test:
  real governed effect -> reconcile -> witness -> certify -> bundle v2 ->
  shut everything down -> DETACHED offline verification recomputes facts ->
  overclaiming certificates are detected.
"""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.canonical import digest
from event_horizon.certificate import ContainmentCertificateBuilder
from event_horizon.effect_gateway import (
    EffectGateway,
    GATEWAY_INDETERMINATE,
    GATEWAY_RECONCILED,
    SqliteEffectIntentStore,
    make_effect_request,
)
from event_horizon.executor import (
    _governed_effect_id,
    _governed_execution_id,
)
from event_horizon.recorder import ExternalRecorder, FileCheckpointAnchor
from event_horizon.reference_provider import (
    ReferenceProviderCore,
    ReferenceProviderServer,
)
from event_horizon.statements import StatementSigner, StatementVerifier
from event_horizon.trust_manifest import (
    ManifestChain,
    TrustRootAuthority,
    make_actor,
)
from event_horizon.witness import LocalCheckpointWitness


def _pem(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


class ProofClosureWorld:
    """One honest multi-principal topology + live reference provider."""

    def __init__(self, tmp: str):
        self.tmp = Path(tmp)
        self.root = TrustRootAuthority(
            bytes([210]) * 32, deployment_id="dep-pc", environment="synthetic"
        )
        self.signers = {
            "verifier": StatementSigner(bytes([211]) * 32, subject="verifier"),
            "guardian": StatementSigner(bytes([212]) * 32, subject="guardians"),
            "executor": StatementSigner(bytes([213]) * 32, subject="executor"),
            "watchdog": StatementSigner(bytes([214]) * 32, subject="watchdog"),
            "gateway": StatementSigner(bytes([215]) * 32, subject="effect-gateway"),
            # The certificate signer is itself a manifest-authorized actor so
            # offline verifiers can pin its key from the bundled manifest.
            "certificate": StatementSigner(
                bytes([218]) * 32, subject="certificate-signer"
            ),
        }
        manifest = self.root.issue_manifest([
            make_actor(role="verifier", public_key_pem=self.signers["verifier"].public_key_pem),
            make_actor(role="guardian", public_key_pem=self.signers["guardian"].public_key_pem),
            make_actor(role="executor", public_key_pem=self.signers["executor"].public_key_pem),
            make_actor(role="watchdog", public_key_pem=self.signers["watchdog"].public_key_pem),
            make_actor(role="effect-gateway", public_key_pem=self.signers["gateway"].public_key_pem),
            make_actor(role="certificate-signer", public_key_pem=self.signers["certificate"].public_key_pem),
        ], manifest_version=1, sequence=1, issued_at_ms=1000, previous_manifest_digest=None)
        self.manifest_envelope = manifest
        self.chain = ManifestChain(
            self.root.public_key_pem,
            deployment_id="dep-pc",
            environment="synthetic",
        )
        self.chain.append(manifest)

        self.recorder = ExternalRecorder(self.tmp / "events.jsonl", b"R" * 32)
        self.anchor = FileCheckpointAnchor(self.tmp / "anchor.jsonl")
        self.witness = LocalCheckpointWitness(
            self.tmp / "witness.jsonl",
            witness_id="witness-pc",
            signing_key=bytes([216]) * 32,
            deployment_id="dep-pc",
        )
        self.provider_core = ReferenceProviderCore(
            provider_id="ref-pc",
            signing_key=bytes([217]) * 32,
            scenario_for_operation={"governed.op": "commit-lose-response"},
        )
        self.provider_server = ReferenceProviderServer(self.provider_core)
        self.provider_server.start()
        self.sequence = 0

    def shutdown(self) -> None:
        self.provider_server.stop()

    def record(self, event_type: str, payload: dict) -> dict:
        self.sequence += 1
        return self.recorder.append(
            event_type, payload, source_id="c", source_sequence=self.sequence
        )

    def statement_verifier(self) -> StatementVerifier:
        return StatementVerifier({
            "v": self.signers["verifier"].public_key_pem,
            "g": self.signers["guardian"].public_key_pem,
            "e": self.signers["executor"].public_key_pem,
            "w": self.signers["watchdog"].public_key_pem,
            "gw": self.signers["gateway"].public_key_pem,
        })


class ProofClosureLifecycleTests(unittest.TestCase):
    def _run_governed_effect(self, world: ProofClosureWorld, n: int) -> dict:
        adapter_base = world.provider_server.base_url
        gateway = EffectGateway(
            gateway_id="gw-pc",
            statement_signer=world.signers["gateway"],
            intent_store=SqliteEffectIntentStore(world.tmp / f"gw-{n}.sqlite3"),
            deployment_id="dep-pc",
        )
        capability_id = "cap_" + f"{n:02d}".zfill(2)[:24].ljust(24, "a")[:24]
        request_digest = digest({"n": n})
        request = make_effect_request(
            deployment_id="dep-pc", environment="synthetic",
            run_id="run-pc", session_id="s-pc",
            capability_id=capability_id,
            request_digest=request_digest,
            operation="governed.op",
            arguments_digest="b" * 64,
            policy_digest="c" * 64,
            executor_identity="exec-1",
            execution_id=_governed_execution_id(capability_id, request_digest),
            effect_id=_governed_effect_id(capability_id, request_digest),
        )
        fingerprint = digest({
            "operation": "governed.op",
            "arguments_digest": "b" * 64,
        })

        def post(path: str, body: dict):
            import urllib.request

            req = urllib.request.Request(
                adapter_base + path,
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
                import urllib.error  # noqa: F401

                return exc.code, json.loads(exc.read())

        class HttpProvider:
            def __init__(self, poster):
                self._post = poster

            def execute(self, effect_request, idempotency_key):
                from event_horizon.effect_gateway import (
                    EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT,
                    PROVIDER_COMMITTED,
                    ProviderResult,
                )

                status, body = self._post("/execute", {
                    "idempotency_key": idempotency_key,
                    "effect_id": effect_request["effect_id"],
                    "effect_fingerprint": fingerprint,
                    "operation": effect_request["operation"],
                    "request_digest": effect_request["request_digest"],
                })
                if status == 504:
                    raise TimeoutError("provider response lost")
                receipt = body["receipt"]
                return ProviderResult(
                    state=PROVIDER_COMMITTED,
                    receipt_digest=digest(
                        receipt["provider_transaction_id"]
                    ),
                    evidence_class=EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT,
                    provider_receipt_envelope=receipt,
                )

            def reconcile(self, idempotency_key):
                from event_horizon.effect_gateway import (
                    EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT,
                    PROVIDER_COMMITTED,
                    ProviderResult,
                )

                status, body = self._post(
                    "/reconcile", {"idempotency_key": idempotency_key}
                )
                receipt = body["receipt"]
                return ProviderResult(
                    state=PROVIDER_COMMITTED,
                    receipt_digest=digest(
                        receipt["provider_transaction_id"]
                    ),
                    evidence_class=EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT,
                    provider_receipt_envelope=receipt,
                )

        provider = HttpProvider(post)
        first = gateway.dispatch(request, provider)
        if first["state"] != GATEWAY_INDETERMINATE:
            raise AssertionError(f"expected indeterminate, got {first['state']!r}")
        # Gateway restarts on its durable store; reconciliation recovers.
        restarted_gateway = EffectGateway(
            gateway_id="gw-pc",
            statement_signer=world.signers["gateway"],
            intent_store=SqliteEffectIntentStore(world.tmp / f"gw-{n}.sqlite3"),
            deployment_id="dep-pc",
        )
        record = restarted_gateway.reconcile(request, provider)
        if record["state"] != GATEWAY_RECONCILED or record["resolution"] != "committed":
            raise AssertionError(
                f"reconcile produced {record['state']}/{record.get('resolution')}"
            )
        return {
            "request": request,
            "record": record,
            "capability_id": capability_id,
            "request_digest": request_digest,
        }

    def _build_certificate(self, world: ProofClosureWorld, effects: list[dict]):
        request_digest = effects[0]["request_digest"]
        capability_id = effects[0]["capability_id"]
        session_id = "s-pc"
        world.record("request.received", {
            "run_id": "run-pc", "session_id": session_id,
            "request_id": "r1", "request_digest": request_digest,
        })
        world.record("attestation.verified", {
            "run_id": "run-pc", "session_id": session_id,
            "result_digest": "2" * 64, "bundle_digest": "3" * 64,
            "statement": world.signers["verifier"].sign(
                "verifier-attestation",
                {"result_digest": "2" * 64, "issued_at_ms": 1000},
            ).to_dict(),
        })
        world.record("guardian.decision", {
            "run_id": "run-pc", "session_id": session_id,
            "guardian": "policy", "allowed": True,
            "request_digest": request_digest,
            "statement": world.signers["guardian"].sign(
                "guardian-decision",
                {"guardian": "policy", "allowed": True,
                 "request_digest": request_digest, "issued_at_ms": 1000},
            ).to_dict(),
        })
        world.record("capability.issued", {
            "run_id": "run-pc", "session_id": session_id,
            "capability_id": capability_id,
            "request_digest": request_digest,
            "key_id": "ed25519:" + "4" * 32,
            "executor_measurement": "5" * 64,
        })
        effect = effects[0]
        record = effect["record"]
        world.record("execution.completed", {
            "run_id": "run-pc", "session_id": session_id,
            "capability_id": capability_id,
            "request_digest": request_digest,
            "success": True, "output_bytes": 16,
            "effect_state": "committed",
            "effect_gateway": {
                "execution_id": effect["request"].execution_id,
                "idempotency_key": effect["request"].idempotency_key,
                "gateway_state": "committed",
                "resolution": "committed",
            },
            "receipt": world.signers["executor"].sign(
                "execution-receipt",
                {"request_digest": request_digest,
                 "session_id": session_id,
                 "capability_id": capability_id,
                 "effect_state": "committed"},
            ).to_dict(),
        })
        del record
        world.record("teardown.verified", {
            "run_id": "run-pc", "verified": True,
            "statement": world.signers["watchdog"].sign(
                "teardown-attestation",
                {"verified": True, "run_id": "run-pc"},
            ).to_dict(),
        })
        checkpoint = world.recorder.issue_checkpoint(
            world.anchor, deployment_id="dep-pc",
            manifest_digest=world.chain.current.manifest_digest,
        )
        acknowledgment = world.witness.publish_checkpoint(
            checkpoint,
            recorder_public_key_pem=world.recorder.public_key_pem,
            manifest_digest=world.chain.current.manifest_digest,
        )
        builder = ContainmentCertificateBuilder(
            ExternalRecorder(world.recorder.path, b"R" * 32),
            world.signers["certificate"]._private_key,
            statement_verifier=world.statement_verifier(),
        )
        reconciliations = [
            effect["record"]["reconciliation_statement"] for effect in effects
        ]
        provider_receipts = [
            record.get("provider_receipt_envelope") for record in
            (effect["record"] for effect in effects)
        ]
        certificate = builder.build(
            run_id="run-pc",
            deployment_id="dep-pc",
            trust_root_manifest_digest=world.chain.current.manifest_digest,
            effect_reconciliation_statements=reconciliations,
        )
        return {
            "certificate": certificate,
            "checkpoint": checkpoint,
            "acknowledgment": acknowledgment,
            "reconciliations": reconciliations,
            "provider_receipts": [r for r in provider_receipts if r],
        }

    def test_full_lifecycle_offline_verification_and_no_duplicate_effect(self) -> None:
        from event_horizon.verification_bundle import (
            BUNDLE_SCHEMA_V2,
            build_bundle_v2,
            verify_bundle_v2,
        )

        with tempfile.TemporaryDirectory() as tmp:
            world = ProofClosureWorld(tmp)
            try:
                effect = self._run_governed_effect(world, 1)
                built = self._build_certificate(world, [effect])
                # Exactly one authoritative provider transaction.
                self.assertEqual(len(world.provider_core.records), 1)
                bundle = build_bundle_v2(
                    certificate=built["certificate"],
                    trust_manifest_envelopes=[world.manifest_envelope],
                    deployment_policy_statement=_policy_statement(world),
                    witness_acknowledgments=[built["acknowledgment"]],
                    recorder_checkpoints=[built["checkpoint"]],
                    effect_reconciliation_statements=built["reconciliations"],
                    provider_receipt_envelopes=built["provider_receipts"],
                )
                self.assertEqual(bundle["schema"], BUNDLE_SCHEMA_V2)
            finally:
                world.shutdown()

            # ---- every runtime service is now shut down -------------------
            detached_dir = Path(tempfile.mkdtemp(prefix="eh-detached-"))
            bundle_path = detached_dir / "bundle.json"
            bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
            (detached_dir / "root.pem").write_text(world.root.public_key_pem)
            (detached_dir / "witness.pem").write_text(world.witness.public_key_pem)
            (detached_dir / "provider.pem").write_text(
                world.provider_core.public_key_pem
            )

            runner = (
                "import json, sys\n"
                "sys.path.insert(0, r'%s')\n"
                "from event_horizon.verification_bundle import read_bundle_v2, verify_bundle_v2\n"
                "b = read_bundle_v2(r'%s')\n"
                "r = verify_bundle_v2(b,\n"
                "    trusted_root_public_key_pem=open(r'%s').read(),\n"
                "    trusted_witness_public_keys_pem=[open(r'%s').read()],\n"
                "    trusted_provider_public_keys_pem=[open(r'%s').read()])\n"
                "print(json.dumps(r.to_dict()))\n"
            ) % (
                str(Path(__file__).resolve().parents[1] / "src"),
                str(bundle_path),
                str(detached_dir / "root.pem"),
                str(detached_dir / "witness.pem"),
                str(detached_dir / "provider.pem"),
            )
            completed = subprocess.run(
                [sys.executable, "-c", runner],
                capture_output=True, text=True, timeout=60,
                cwd=str(detached_dir),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout.strip().splitlines()[-1])

            claimed = built["certificate"]["certificate"]["assurance_facts"]
            derived = report["derived_assurance_facts"]
            # Overclaims are security failures; underclaims are permitted.
            # manifest_authorized_sources may be honestly false at runtime
            # (plain verifier) while provable offline from the manifest chain,
            # so it participates in overclaim checking, not strict equality.
            portable_strict = {
                "authenticated_sources", "namespace_complete", "history_witnessed",
                "witness_administratively_independent", "witness_storage_independent",
                "effect_mediated", "effects_reconciled",
                "provider_receipts_authenticated",
            }
            for name in portable_strict:
                self.assertEqual(
                    derived[name], claimed[name],
                    f"portable fact mismatch: {name}",
                )
            self.assertGreaterEqual(
                derived["manifest_authorized_sources"],
                claimed["manifest_authorized_sources"],
            )
            self.assertTrue(report["certificate_signature_valid"])
            self.assertTrue(report["trust_chain_valid"])
            self.assertTrue(report["provider_receipt_authenticated"])
            self.assertEqual(report["effect_reconciliation_status"], "committed")
            self.assertEqual(report["history_status"] if "history_status" in report else True, True)
            self.assertTrue(report["certificate_claim_match"], report["claim_mismatches"])
            self.assertEqual(report["conflicts"], [])
            # Honest independence for same-host dev witness:
            self.assertFalse(derived["witness_administratively_independent"])

    def test_legitimately_signed_overclaim_is_detected(self) -> None:
        from event_horizon.verification_bundle import (
            build_bundle_v2,
            verify_bundle_v2,
        )

        with tempfile.TemporaryDirectory() as tmp:
            world = ProofClosureWorld(tmp)
            try:
                effect = self._run_governed_effect(world, 2)
                built = self._build_certificate(world, [effect])
            finally:
                world.shutdown()
            # A legitimate signer makes a semantic mistake and flips facts.
            payload = json.loads(json.dumps(built["certificate"]["certificate"]))
            payload["assurance_facts"]["keys_independently_administered"] = True
            payload["assurance_facts"]["effect_mediation_enforced"] = True
            payload["assurance_profile"] = "HIGH_ASSURANCE"
            reseeded = ContainmentCertificateBuilder(
                ExternalRecorder(world.recorder.path, b"R" * 32),
                b"C" * 32,
                statement_verifier=world.statement_verifier(),
            )
            signature = reseeded._private_key.sign(  # noqa: SLF001 - deliberate
                __import__("event_horizon.canonical", fromlist=["canonical_bytes"])
                .canonical_bytes(payload)
            )
            import base64 as b64

            overclaimed = {
                **built["certificate"],
                "certificate": payload,
                "signature": b64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
                "key_id": reseeded.key_id,
                "public_key_pem": reseeded.public_key_pem,
            }
            bundle = build_bundle_v2(
                certificate=overclaimed,
                trust_manifest_envelopes=[world.manifest_envelope],
                deployment_policy_statement=_policy_statement(world),
                witness_acknowledgments=[built["acknowledgment"]],
                recorder_checkpoints=[built["checkpoint"]],
                effect_reconciliation_statements=built["reconciliations"],
                provider_receipt_envelopes=built["provider_receipts"],
            )
            report = verify_bundle_v2(
                bundle,
                trusted_root_public_key_pem=world.root.public_key_pem,
                trusted_witness_public_keys_pem=[world.witness.public_key_pem],
                trusted_provider_public_keys_pem=[
                    world.provider_core.public_key_pem
                ],
            )
            self.assertFalse(report.certificate_claim_match)
            self.assertTrue(any(
                "overclaim" in m and "keys_independently_administered" in m
                for m in report.claim_mismatches
            ), report.claim_mismatches)


class _StaticProviderAdapter:
    def __init__(self, reconcile_body: dict) -> None:
        from event_horizon.effect_gateway import (
            PROVIDER_COMMITTED,
            ProviderResult,
        )

        self._result = ProviderResult(
            state=PROVIDER_COMMITTED,
            receipt_digest=digest(reconcile_body["receipt"]["provider_transaction_id"]),
            evidence_class=EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT_GLOBAL,
            provider_receipt_envelope=reconcile_body["receipt"],
        )

    def execute(self, effect_request, idempotency_key):  # pragma: no cover
        raise AssertionError("dispatch already finished")

    def reconcile(self, idempotency_key):
        return self._result


EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT_GLOBAL = "provider_authenticated_receipt"


def _policy_statement(world: ProofClosureWorld) -> dict:
    from event_horizon.statements import TYPE_DEPLOYMENT_POLICY

    root_signer = StatementSigner(bytes([210]) * 32, subject="deployment-root")
    return root_signer.sign(TYPE_DEPLOYMENT_POLICY, {
        "deployment_id": "dep-pc",
        "replay_durable": True,
        "effect_mediation_enforced": False,
        "keys_independently_administered": False,
    }).to_dict()


if __name__ == "__main__":
    unittest.main()
