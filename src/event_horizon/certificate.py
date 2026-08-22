from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .execution_state import ExecutionStateError
from .recorder import ExternalRecorder
from .statements import (
    TYPE_EXECUTION_RECEIPT,
    TYPE_GUARDIAN_DECISION,
    TYPE_TEARDOWN_ATTESTATION,
    TYPE_VERIFIER_ATTESTATION,
    StatementError,
    StatementVerifier,
)


CERTIFICATE_SCHEMA = "event-horizon.containment-certificate.v0.5"

CLAIM_SATISFIED = "satisfied"
CLAIM_VIOLATED = "violated"
CLAIM_UNKNOWN = "unknown"

# Required evidence classes for proof-of-completeness: a "complete" certificate
# must contain at least one event of every class, every consumed event must be
# bound to this run's namespace, and every security claim must be derivable.
REQUIRED_EVENT_CLASSES = {
    "request.received",
    "attestation.verified",
    "guardian.decision",
    "capability.issued",
    "execution.completed",
    "teardown.verified",
}

_NAMESPACE_EVENTS = frozenset({
    "request.received",
    "attestation.verified",
    "guardian.decision",
    "request.denied",
    "request.rejected",
    "capability.issued",
    "execution.completed",
    "execution.denied",
    "execution.indeterminate",
})


class CertificateBuildError(ValueError):
    pass


def _claim(value: bool | None) -> str:
    if value is True:
        return CLAIM_SATISFIED
    if value is False:
        return CLAIM_VIOLATED
    return CLAIM_UNKNOWN


def _merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"event-horizon:empty-evidence").hexdigest()
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1])).hexdigest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


class ContainmentCertificateBuilder:
    """Signs containment conclusions derived exclusively from verified evidence.

    The builder resolves every claim from one atomic verified recorder
    snapshot filtered to a single ``run_id`` namespace. It verifies independent
    source signatures (verifier, guardians, teardown watchdog) against pinned
    trust anchors and never accepts caller-supplied truth assertions. If
    evidence cannot prove a claim, the claim is ``unknown`` and the certificate
    status becomes ``incomplete`` with explicit blocking reasons.
    """

    ENVELOPE_FIELDS = frozenset({
        "certificate", "signature", "algorithm", "key_id", "public_key_pem",
    })
    _SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")

    def __init__(
        self,
        recorder: ExternalRecorder,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        key_id: str | None = None,
        *,
        statement_verifier: StatementVerifier | None = None,
        execution_tracker_namespace: str | None = None,
        tracker_store: Any = None,
    ):
        self.recorder = recorder
        self.statement_verifier = statement_verifier
        self._tracker = None
        if tracker_store is not None:
            from .execution_state import CapabilityExecutionTracker

            self._tracker = CapabilityExecutionTracker(
                tracker_store,
                namespace=execution_tracker_namespace or "certification",
            )
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes):
            if len(signing_key) < 32:
                raise ValueError("certificate signing seed must be at least 32 bytes")
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise TypeError("unsupported certificate signing key")
        self._public_key = self._private_key.public_key()
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        actual_key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
        if key_id is not None and key_id != actual_key_id:
            raise ValueError("certificate key_id does not match the signing key")
        self.key_id = actual_key_id

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    # ------------------------------------------------------------------ build

    def build(
        self,
        *,
        run_id: str,
        expected_session_id: str | None = None,
        checkpoint_anchor: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(run_id, str) or not run_id or len(run_id.encode("utf-8")) > 256:
            raise CertificateBuildError("run_id must be a non-empty bounded string")
        snapshot = self.recorder.verified_snapshot()

        checkpoint_envelope = None
        if checkpoint_anchor is not None:
            anchored_ok, anchored_reason = self.recorder.verify_against_anchor(checkpoint_anchor)
            if not anchored_ok:
                raise CertificateBuildError(
                    f"recorder history failed checkpoint continuity: {anchored_reason}"
                )
            checkpoint_envelope = checkpoint_anchor.load_latest()

        events = [
            event for event in snapshot.events
            if isinstance(event.get("payload"), dict)
            and event["payload"].get("run_id") == run_id
        ]

        session_ids = {
            event["payload"].get("session_id")
            for event in events
            if event["payload"].get("session_id") is not None
        }
        if not events:
            raise CertificateBuildError(
                f"run namespace {run_id!r} has no recorded evidence; "
                "refusing to certify an unknown execution"
            )
        if len(session_ids) > 1:
            raise CertificateBuildError(
                f"run namespace {run_id!r} spans multiple sessions: {sorted(session_ids)!r}"
            )
        derived_session_id = next(iter(session_ids)) if session_ids else None
        if expected_session_id is not None and expected_session_id != derived_session_id:
            raise CertificateBuildError(
                "requested session identity does not match the run's authoritative session"
            )

        blocking: list[str] = []
        claims: dict[str, str] = {}

        requests = [e for e in events if e["event_type"] == "request.received"]
        attestations = [e for e in events if e["event_type"] == "attestation.verified"]
        decisions = [e for e in events if e["event_type"] == "guardian.decision"]
        issued = [e for e in events if e["event_type"] == "capability.issued"]
        completed = [e for e in events if e["event_type"] == "execution.completed"]
        denied_executions = [e for e in events if e["event_type"] == "execution.denied"]
        indeterminate = [e for e in events if e["event_type"] == "execution.indeterminate"]
        teardown_events = [e for e in events if e["event_type"] == "teardown.verified"]
        veto_count = sum(
            1 for event in decisions if event["payload"].get("allowed") is False
        )

        # --- claim derivation -------------------------------------------------
        claims["requests_recorded"] = _claim(len(requests) > 0)

        verifier_ok = self._verify_embedded_statements(
            attestations, TYPE_VERIFIER_ATTESTATION, blocking, "attestation.verified"
        )
        claims["attestation_independently_signed"] = _claim(
            verifier_ok if attestations else None
        )

        guardian_ok = self._verify_embedded_statements(
            decisions, TYPE_GUARDIAN_DECISION, blocking, "guardian.decision"
        )
        completed_request_digests = {
            event["payload"].get("request_digest")
            for event in completed
            if event["payload"].get("request_digest")
        }
        self._verify_execution_receipts(completed, blocking)
        vetoed_request_digests = {
            event["payload"].get("request_digest")
            for event in decisions
            if event["payload"].get("allowed") is False
        }
        # Denials are correct containment behavior; they only invalidate the
        # quorum claim when a request that was nevertheless executed carries a
        # veto, or when an executed request lacks any approving decision.
        executed_with_veto = sorted(completed_request_digests & vetoed_request_digests)
        unapproved_executions = sorted(
            digest_value
            for digest_value in completed_request_digests
            if not any(
                event["payload"].get("allowed") is True
                and event["payload"].get("request_digest") == digest_value
                for event in decisions
            )
        )
        if not completed:
            claims["guardian_quorum_without_veto"] = CLAIM_UNKNOWN
        elif executed_with_veto or unapproved_executions or guardian_ok is False:
            claims["guardian_quorum_without_veto"] = CLAIM_VIOLATED
            if executed_with_veto:
                blocking.append(f"executed requests carried guardian vetoes: {executed_with_veto!r}")
            if unapproved_executions:
                blocking.append(f"executed requests lack approving guardian decisions: {unapproved_executions!r}")
        else:
            claims["guardian_quorum_without_veto"] = (
                CLAIM_SATISFIED if guardian_ok else CLAIM_UNKNOWN
            )

        claims["capability_issued"] = _claim(len(issued) > 0)

        completed_by_capability: dict[str, int] = {}
        for event in completed:
            capability_id = event["payload"].get("capability_id")
            completed_by_capability[capability_id] = completed_by_capability.get(capability_id, 0) + 1
        duplicate_effects = sorted(
            capability for capability, count in completed_by_capability.items() if count > 1
        )
        if duplicate_effects:
            raise CertificateBuildError(
                f"one-use capabilities produced multiple successful executions: {duplicate_effects!r}"
            )
        claims["single_execution_per_capability"] = _claim(len(completed) > 0)

        claims["no_indeterminate_outcomes"] = (
            _claim(False) if indeterminate else (_claim(None) if not completed else CLAIM_SATISFIED)
        )
        if indeterminate:
            blocking.append(
                f"{len(indeterminate)} execution(s) ended indeterminate; effect reconciliation "
                "evidence is required before containment can be claimed"
            )

        teardown_claim_value: bool | None = None
        if teardown_events:
            teardown_ok = self._verify_teardown_statement(teardown_events, blocking)
            latest = teardown_events[-1]["payload"]
            if teardown_ok and latest.get("verified") is True:
                teardown_claim_value = True
            elif latest.get("verified") is False:
                teardown_claim_value = False
            else:
                teardown_claim_value = None
        claims["teardown_attested"] = _claim(teardown_claim_value)

        violations = [
            event for event in events if event["event_type"] == "egress.violation"
        ]
        claims["no_evidence_of_unauthorized_egress"] = (
            CLAIM_SATISFIED if not violations else CLAIM_VIOLATED
        ) if events else CLAIM_UNKNOWN

        # --- completeness ------------------------------------------------------
        present_classes = {
            event_type for event_type in (
                "request.received", "attestation.verified", "guardian.decision",
                "capability.issued", "execution.completed", "teardown.verified",
            ) if any(e["event_type"] == event_type for e in events)
        }
        missing_classes = sorted(REQUIRED_EVENT_CLASSES - present_classes)
        if missing_classes:
            blocking.append(f"missing required evidence classes: {missing_classes!r}")
        if denied_executions and not completed:
            blocking.append("all executions were denied; no successful contained execution exists")

        unresolved_claims = sorted(name for name, value in claims.items() if value != CLAIM_SATISFIED)
        if unresolved_claims:
            blocking.append(f"claims not fully satisfied: {unresolved_claims!r}")

        if self._tracker is not None:
            try:
                self._tracker.assert_resolved_for_certification()
            except ExecutionStateError as exc:
                blocking.append(str(exc))

        status = "complete" if not blocking else "incomplete"

        evidence_root = _merkle_root([event["event_hash"] for event in events])

        payload = {
            "schema": CERTIFICATE_SCHEMA,
            "run_id": run_id,
            "session_id": derived_session_id,
            "created_at": time.time_ns() // 1_000_000,
            "status": status,
            "claims": dict(sorted(claims.items())),
            "blocking_reasons": sorted(blocking),
            "evidence_root": evidence_root,
            "consumed_event_count": len(events),
            "event_chain_valid": snapshot.chain_valid,
            "event_chain_tip": snapshot.chain_tip,
            "total_event_count": snapshot.event_count,
            "recorder_checkpoint": checkpoint_envelope,
            "completed_actions": len(completed),
            "denied_transitions": sum(1 for event in events if event["event_type"] in {
                "request.denied", "execution.denied", "request.rejected",
            }),
            "evidence": {
                "attestation": {
                    "result_digests": sorted({
                        digest_value
                        for digest_value in (
                            [event["payload"].get("result_digest") for event in attestations]
                            + [
                                event["payload"].get("evidence", {}).get("attestation_result_digest")
                                for event in decisions
                            ]
                        )
                        if isinstance(digest_value, str) and digest_value
                    }),
                    "bundle_digests": sorted({
                        bundle
                        for bundle in (
                            [event["payload"].get("bundle_digest") for event in attestations]
                            + [
                                event["payload"].get("evidence", {}).get("bundle_digest")
                                for event in decisions
                            ]
                        )
                        if isinstance(bundle, str) and bundle
                    }),
                    "statement_key_id": self._statement_key_id(attestations),
                },
                "guardians": {
                    "decision_count": len(decisions),
                    "veto_count": veto_count,
                    "statement_key_id": self._statement_key_id(decisions),
                },
                "capabilities": {
                    "ids": sorted({
                        event["payload"].get("capability_id") for event in issued
                        if event["payload"].get("capability_id")
                    }),
                    "signer_key_ids": sorted({
                        event["payload"].get("key_id") for event in issued
                        if event["payload"].get("key_id")
                    }),
                    "request_digests": sorted({
                        event["payload"].get("request_digest") for event in issued
                        if event["payload"].get("request_digest")
                    }),
                    "policy_digests": sorted({
                        event["payload"].get("policy_digest") for event in issued
                        if event["payload"].get("policy_digest")
                    }),
                    "executor_measurements": sorted({
                        event["payload"].get("executor_measurement") for event in issued
                        if event["payload"].get("executor_measurement")
                    }),
                },
                "executions": {
                    "completed_capability_ids": sorted(completed_by_capability),
                    "denied_request_ids": sorted({
                        event["payload"].get("request_id") for event in denied_executions
                        if event["payload"].get("request_id")
                    }),
                    "indeterminate_request_ids": sorted({
                        event["payload"].get("request_id") for event in indeterminate
                        if event["payload"].get("request_id")
                    }),
                },
                "teardown": {
                    "verified": teardown_claim_value,
                    "statement_key_id": self._statement_key_id(teardown_events),
                },
                "recorder": {
                    "event_count": snapshot.event_count,
                    "chain_tip": snapshot.chain_tip,
                    "chain_valid": snapshot.chain_valid,
                    "key_id": getattr(self.recorder, "key_id", "unavailable"),
                },
            },
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(payload))
        ).rstrip(b"=").decode("ascii")
        return {
            "certificate": payload,
            "signature": signature,
            "algorithm": "Ed25519",
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
        }

    # ------------------------------------------------------- statement checks

    @staticmethod
    def _statement_key_id(events: list[dict[str, Any]]) -> str | None:
        for event in events:
            statement = event["payload"].get("statement")
            if isinstance(statement, Mapping):
                key_id = statement.get("key_id")
                if isinstance(key_id, str):
                    return key_id
        return None

    def _verify_embedded_statements(
        self,
        events: list[dict[str, Any]],
        expected_type: str,
        blocking: list[str],
        label: str,
    ) -> bool | None:
        if self.statement_verifier is None:
            if events:
                blocking.append(
                    f"{label} statements cannot be authenticated: no trusted statement keys configured"
                )
            return None
        if not events:
            return None
        results = []
        for index, event in enumerate(events):
            statement = event["payload"].get("statement")
            try:
                self.statement_verifier.verify(statement, expected_type=expected_type)
                results.append(True)
            except (StatementError, TypeError, ValueError):
                blocking.append(f"{label}[{index}] carries an invalid source statement signature")
                results.append(False)
        return all(results)

    def _verify_teardown_statement(
        self,
        events: list[dict[str, Any]],
        blocking: list[str],
    ) -> bool | None:
        if self.statement_verifier is None:
            if events:
                blocking.append(
                    "teardown statements cannot be authenticated: no trusted statement keys configured"
                )
            return None
        if not events:
            return None
        results = []
        for index, event in enumerate(events):
            statement = event["payload"].get("statement")
            try:
                self.statement_verifier.verify(statement, expected_type=TYPE_TEARDOWN_ATTESTATION)
                results.append(True)
            except (StatementError, TypeError, ValueError):
                blocking.append(f"teardown.verified[{index}] carries an invalid watchdog statement")
                results.append(False)
        return all(results)

    def _verify_execution_receipts(
        self,
        completed: list[dict[str, Any]],
        blocking: list[str],
    ) -> bool | None:
        """Completed executions must carry executor-signed receipts whose
        fields bind to the recorded event. A coordinator cannot fabricate a
        successful execution by writing an unsigned event."""
        if self.statement_verifier is None:
            return None
        results = []
        for index, event in enumerate(completed):
            receipt = event["payload"].get("receipt")
            if not isinstance(receipt, Mapping):
                blocking.append(
                    f"execution.completed[{index}] carries no signed execution receipt"
                )
                results.append(False)
                continue
            try:
                statement = self.statement_verifier.verify(
                    receipt, expected_type=TYPE_EXECUTION_RECEIPT
                )
            except (StatementError, TypeError, ValueError):
                blocking.append(
                    f"execution.completed[{index}] carries an invalid execution receipt"
                )
                results.append(False)
                continue
            payload = event["payload"]
            bound_fields = (
                statement.payload.get("capability_id") == payload.get("capability_id"),
                statement.payload.get("request_digest") == payload.get("request_digest"),
                statement.payload.get("session_id") == payload.get("session_id"),
            )
            if not all(bound_fields):
                blocking.append(
                    f"execution.completed[{index}] receipt does not bind to the recorded event"
                )
                results.append(False)
                continue
            results.append(True)
        return all(results) if results else None
        results = []
        for index, event in enumerate(events):
            statement = event["payload"].get("statement")
            try:
                self.statement_verifier.verify(statement, expected_type=TYPE_TEARDOWN_ATTESTATION)
                results.append(True)
            except (StatementError, TypeError, ValueError):
                blocking.append(f"teardown.verified[{index}] carries an invalid watchdog statement")
                results.append(False)
        return all(results)

    # ------------------------------------------------------------ verification

    @staticmethod
    def verify(
        certificate: dict[str, Any],
        *,
        public_key_pem: str | None = None,
        expected_key_id: str | None = None,
    ) -> bool:
        """Verify authenticity against an independently supplied trust anchor.

        At least one of ``public_key_pem`` or ``expected_key_id`` must come from
        trusted configuration outside the certificate. The embedded public key
        is metadata and is never sufficient by itself for authoritative success.
        """
        if public_key_pem is None and expected_key_id is None:
            return False
        return ContainmentCertificateBuilder._verify_with_anchor(
            certificate,
            public_key_pem=public_key_pem,
            expected_key_id=expected_key_id,
        )

    @staticmethod
    def verify_self_consistency(certificate: dict[str, Any]) -> bool:
        """Check artifact self-consistency without establishing signer trust."""
        try:
            embedded_pem = certificate["public_key_pem"]
            embedded_key_id = certificate["key_id"]
        except (KeyError, TypeError):
            return False
        return ContainmentCertificateBuilder._verify_with_anchor(
            certificate,
            public_key_pem=embedded_pem,
            expected_key_id=embedded_key_id,
        )

    @staticmethod
    def _verify_with_anchor(
        certificate: dict[str, Any],
        *,
        public_key_pem: str | None,
        expected_key_id: str | None,
    ) -> bool:
        try:
            if not isinstance(certificate, dict) or set(certificate) != ContainmentCertificateBuilder.ENVELOPE_FIELDS:
                return False
            if certificate["algorithm"] != "Ed25519":
                return False
            payload = certificate["certificate"]
            if not isinstance(payload, dict):
                return False
            embedded_pem = certificate["public_key_pem"]
            if not isinstance(embedded_pem, str):
                return False
            trusted_pem = public_key_pem if public_key_pem is not None else embedded_pem
            if not isinstance(trusted_pem, str):
                return False
            public_key = serialization.load_pem_public_key(trusted_pem.encode("ascii"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            raw_public = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            actual_key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
            embedded_key = serialization.load_pem_public_key(embedded_pem.encode("ascii"))
            if not isinstance(embedded_key, Ed25519PublicKey):
                return False
            embedded_raw = embedded_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            embedded_key_id = f"ed25519:{hashlib.sha256(embedded_raw).hexdigest()[:32]}"
            if embedded_key_id != actual_key_id:
                return False
            if certificate.get("key_id") != actual_key_id:
                return False
            if expected_key_id is not None and actual_key_id != expected_key_id:
                return False
            if not isinstance(certificate["signature"], str) or ContainmentCertificateBuilder._SIGNATURE.fullmatch(certificate["signature"]) is None:
                return False
            padding = "=" * (-len(certificate["signature"]) % 4)
            signature = base64.b64decode(
                certificate["signature"] + padding,
                altchars=b"-_",
                validate=True,
            )
            if len(signature) != 64:
                return False
            public_key.verify(signature, canonical_bytes(payload))
            return True
        except (
            binascii.Error,
            InvalidSignature,
            KeyError,
            TypeError,
            UnicodeError,
            UnsupportedAlgorithm,
            ValueError,
        ):
            return False

    def write(self, path: str | Path, **kwargs: Any) -> dict[str, Any]:
        result = self.build(**kwargs)
        Path(path).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        return result
