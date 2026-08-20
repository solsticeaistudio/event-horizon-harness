from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .component_ids import EXECUTOR_ATTESTATION_GUARDIAN
from .recorder import ExternalRecorder


class ContainmentCertificateBuilder:
    ENVELOPE_FIELDS = frozenset({
        "certificate", "signature", "algorithm", "key_id", "public_key_pem",
    })
    _SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")

    def __init__(
        self,
        recorder: ExternalRecorder,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        key_id: str | None = None,
    ):
        self.recorder = recorder
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

    def build(
        self,
        *,
        run_id: str,
        session_id: str,
        assertions: dict[str, bool],
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        valid, tip = self.recorder.verify()
        events = self.recorder.events()
        denied = sum(1 for event in events if event["event_type"] in {"request.denied", "execution.denied", "request.rejected"})
        completed = sum(1 for event in events if event["event_type"] == "execution.completed")
        attestation_decisions = [
            event for event in events
            if event["event_type"] == "guardian.decision"
            and event["payload"].get("guardian") == EXECUTOR_ATTESTATION_GUARDIAN
        ]
        attestation_digests = sorted({
            event["payload"].get("evidence", {}).get("bundle_digest")
            for event in attestation_decisions
            if event["payload"].get("evidence", {}).get("bundle_digest")
        })
        attestation_result_digests = sorted({
            event["payload"].get("evidence", {}).get("attestation_result_digest")
            for event in attestation_decisions
            if event["payload"].get("evidence", {}).get("attestation_result_digest")
        })
        capability_events = [event for event in events if event["event_type"] == "capability.issued"]
        required_evidence = {
            "attestation", "capability", "policy", "image", "recorder", "teardown", "egress"
        }
        if evidence is None:
            evidence = {
                "attestation": {
                    "result_digests": attestation_result_digests,
                    "bundle_digests": attestation_digests,
                },
                "capability": {
                    "ids": sorted({event["payload"].get("capability_id") for event in capability_events}),
                    "signer_key_ids": sorted({event["payload"].get("key_id") for event in capability_events}),
                    "request_digests": sorted({event["payload"].get("request_digest") for event in capability_events}),
                },
                "policy": {
                    "digests": sorted({event["payload"].get("policy_digest") for event in capability_events}),
                },
                "image": {
                    "digests": sorted({event["payload"].get("executor_measurement") for event in capability_events}),
                },
                "recorder": {
                    "event_count": len(events),
                    "chain_tip": tip,
                    "chain_valid": valid,
                    "key_id": getattr(self.recorder, "key_id", "unavailable"),
                },
                "teardown": {"verified": bool(assertions.get("teardown_verified", False))},
                "egress": {"unauthorized_egress": not assertions.get("no_unauthorized_egress", False)},
            }
        if not isinstance(evidence, dict) or set(evidence) != required_evidence:
            raise ValueError("certificate evidence must contain every required evidence domain")
        if any(not isinstance(evidence[name], dict) for name in required_evidence):
            raise ValueError("certificate evidence domains must be objects")
        payload = {
            "schema": "event-horizon.containment-certificate.v0.4",
            "run_id": run_id,
            "session_id": session_id,
            "created_at": time.time(),
            "event_count": len(events),
            "event_chain_valid": valid,
            "event_chain_tip": tip,
            "completed_actions": completed,
            "denied_transitions": denied,
            "attestation_bundle_digests": attestation_digests,
            "attestation_result_digests": attestation_result_digests,
            "evidence": evidence,
            "assertions": dict(sorted(assertions.items())),
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
