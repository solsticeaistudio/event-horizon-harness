"""Portable signature/boot/receipt negative tests. NEVER physical power evidence."""
from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_horizon.powercut_proof import prepare, create_external_statement, verify


BEFORE = "11111111-1111-4111-8111-111111111111"
AFTER = "22222222-2222-4222-8222-222222222222"


class PowercutEvidenceContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ehh-boot-proof-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.db = self.root / "recipient.sqlite"
        self.pre = self.root / "preflight.json"
        self.event_log = self.root / "external-controller.log"
        self.event_log.write_text(
            "Power controller reports target outlet OFF, then outlet ON; "
            "portable synthetic fixture only, not physical evidence."
        )
        private = Ed25519PrivateKey.generate()
        self.private_path = self.root / "external.key"
        self.public_path = self.root / "external.pub"
        self.private_path.write_bytes(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.private_path.chmod(0o600)
        self.public_path.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        self.statement = self.root / "statement.json"
        self.receipt = prepare(
            database=self.db, preflight_path=self.pre,
            recipient_id="durable-external-recipient", boot_id=BEFORE,
        )
        create_external_statement(
            preflight_path=self.pre, event_log_path=self.event_log,
            controller_id="independent-fixture-controller",
            boot_id_after=AFTER, private_key_path=self.private_path,
            statement_path=self.statement,
        )

    def run_verify(self, **overrides):
        config = dict(
            preflight_path=self.pre, statement_path=self.statement,
            event_log_path=self.event_log,
            controller_public_key=self.public_path,
            database=self.db, boot_id=AFTER,
        )
        config.update(overrides)
        return verify(**config)

    def test_boot_separated_positive_receipt_preserved(self):
        result = self.run_verify()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["witness_signature_verified"])
        self.assertEqual(result["final_durable_row_count"], 1)
        self.assertEqual(result["receipt_digest"], self.receipt["receipt_digest"])
        self.assertEqual(result["hardware_power_measurement"],
                         "not-verified-by-software")
        self.assertIn("operator-attested", result["scope"])

    def test_same_boot_cannot_verify(self):
        with self.assertRaises(ValueError):
            self.run_verify(boot_id=BEFORE)

    def test_no_or_altered_original_recipient_row_is_not_success(self):
        self.db.rename(self.root / "lost.sqlite")
        with self.assertRaises(ValueError):
            self.run_verify()
        (self.root / "lost.sqlite").rename(self.db)
        with sqlite3.connect(self.db) as db:
            db.execute(
                "UPDATE effects SET receipt_digest = ?",
                ("f" * 64,),
            )
        with self.assertRaises(Exception):
            self.run_verify()

    def test_changed_external_controller_log_denied(self):
        self.event_log.write_text("Forged alternative external power-control sequence.")
        with self.assertRaises(ValueError):
            self.run_verify()

    def test_modified_signed_statement_denied(self):
        from event_horizon.canonical import canonical_bytes, strict_json_loads
        signed = strict_json_loads(self.statement.read_bytes())
        signed["statement"]["controller_id"] = "forged-controller"
        self.statement.write_bytes(canonical_bytes(signed))
        with self.assertRaises(Exception):
            self.run_verify()

    def test_substituted_external_witness_key_denied(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        path = self.root / "wrong.pub"
        path.write_bytes(other)
        with self.assertRaises(Exception):
            self.run_verify(controller_public_key=path)

    def test_original_preflight_cannot_be_replayed_as_fresh(self):
        with self.assertRaises(ValueError):
            prepare(database=self.db, preflight_path=self.root / "second.json",
                    recipient_id="durable-external-recipient", boot_id=BEFORE)

    def test_no_mutation_when_verifier_fails(self):
        with self.assertRaises(ValueError):
            self.run_verify(boot_id=BEFORE)
        # The verifier must not issue any new recipient apply operation.
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
