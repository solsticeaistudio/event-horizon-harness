from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.canonical import canonical_bytes
from event_horizon.certificate import ContainmentCertificateBuilder
from event_horizon.recorder import ExternalRecorder


class CertificateTrustAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository_root = Path(__file__).resolve().parents[1]
        self.recorder = ExternalRecorder(self.root / "events.jsonl", b"R" * 32)
        self.recorder.append(
            "request.received",
            {
                "run_id": "legitimate-run",
                "session_id": "legitimate-session",
                "request_id": "req-1",
                "request_digest": "a" * 64,
            },
            source_id="coordinator",
        )
        self.legitimate = ContainmentCertificateBuilder(self.recorder, b"L" * 32)
        self.attacker_private = Ed25519PrivateKey.from_private_bytes(b"A" * 32)
        self.attacker = ContainmentCertificateBuilder(self.recorder, self.attacker_private)
        self.certificate = self.legitimate.build(
            run_id="legitimate-run", deployment_id="dep-test", trust_root_manifest_digest=None
        )

    def _write(self, name: str, value: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _run_cli(self, certificate: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(self.repository_root / "scripts" / "verify_certificate.py"),
                str(certificate),
                *arguments,
            ],
            cwd=self.repository_root,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_valid_certificate_requires_and_accepts_external_trusted_key(self) -> None:
        self.assertFalse(ContainmentCertificateBuilder.verify(self.certificate))
        self.assertTrue(ContainmentCertificateBuilder.verify(
            self.certificate,
            public_key_pem=self.legitimate.public_key_pem,
            expected_key_id=self.legitimate.key_id,
        ))

    def test_forged_certificate_with_attacker_key_is_rejected(self) -> None:
        # The attacker controls a builder (its own key) and signs a certificate
        # over the same recorded evidence. The artifact is internally
        # consistent but is not signed by the trusted anchor, so authoritative
        # verification must reject it.
        forged = self.attacker.build(
            run_id="legitimate-run", deployment_id="dep-test", trust_root_manifest_digest=None
        )
        self.assertTrue(ContainmentCertificateBuilder.verify_self_consistency(forged))
        self.assertFalse(ContainmentCertificateBuilder.verify(
            forged,
            public_key_pem=self.legitimate.public_key_pem,
            expected_key_id=self.legitimate.key_id,
        ))

    def test_wrong_trusted_key_is_rejected(self) -> None:
        self.assertFalse(ContainmentCertificateBuilder.verify(
            self.certificate,
            public_key_pem=self.attacker.public_key_pem,
        ))

    def test_internally_consistent_embedded_key_substitution_is_rejected(self) -> None:
        substituted = copy.deepcopy(self.certificate)
        substituted["public_key_pem"] = self.attacker.public_key_pem
        substituted["key_id"] = self.attacker.key_id
        substituted["signature"] = base64.urlsafe_b64encode(
            self.attacker_private.sign(canonical_bytes(substituted["certificate"]))
        ).rstrip(b"=").decode("ascii")
        self.assertTrue(ContainmentCertificateBuilder.verify_self_consistency(substituted))
        self.assertFalse(ContainmentCertificateBuilder.verify(
            substituted,
            public_key_pem=self.legitimate.public_key_pem,
            expected_key_id=self.legitimate.key_id,
        ))

    def test_externally_pinned_key_id_mismatch_is_rejected(self) -> None:
        self.assertFalse(ContainmentCertificateBuilder.verify(
            self.certificate,
            expected_key_id="ed25519:" + "0" * 32,
        ))
        self.assertTrue(ContainmentCertificateBuilder.verify(
            self.certificate,
            expected_key_id=self.legitimate.key_id,
        ))

    def test_cli_valid_certificate_uses_external_key(self) -> None:
        certificate_path = self._write("valid.json", self.certificate)
        key_path = self.root / "trusted-signer.pem"
        key_path.write_text(self.legitimate.public_key_pem, encoding="ascii")
        result = self._run_cli(
            certificate_path,
            "--trusted-key",
            str(key_path),
            "--trusted-key-id",
            self.legitimate.key_id,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("containment certificate: VERIFIED", result.stdout)

    def test_cli_missing_trust_anchor_fails_closed(self) -> None:
        result = self._run_cli(self._write("missing-anchor.json", self.certificate))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("external trust anchor required", result.stdout)
        self.assertNotIn("VERIFIED", result.stdout)

    def test_official_cli_rejects_forged_attacker_certificate(self) -> None:
        forged = self.attacker.build(
            run_id="legitimate-run", deployment_id="dep-test", trust_root_manifest_digest=None
        )
        certificate_path = self._write("forged.json", forged)
        key_path = self.root / "trusted-signer.pem"
        key_path.write_text(self.legitimate.public_key_pem, encoding="ascii")
        result = self._run_cli(certificate_path, "--trusted-key", str(key_path))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("INVALID", result.stdout)
        self.assertNotIn("VERIFIED", result.stdout)

    def test_unknown_run_namespace_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            self.legitimate.build(
                run_id="no-such-run", deployment_id="dep-test", trust_root_manifest_digest=None
            )

    def test_caller_cannot_supply_truth_assertions(self) -> None:
        with self.assertRaises(TypeError):
            self.legitimate.build(
                run_id="legitimate-run",
                assertions={"teardown_verified": True},  # type: ignore[call-arg]
            )


if __name__ == "__main__":
    unittest.main()
