"""Regression coverage for the signed CRL, including same-second ordering."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.hsm_backend import HSMKeyInfo
from event_horizon.key_management import KeyManager, KeyManagementError, KeyRevocation


class WorkingHSM:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.info = HSMKeyInfo(
            key_id="fixture-hsm", label="crl-key",
            public_key_pem=self.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
            created_at="2026-10-09T00:00:00Z",
        )

    def initialize(self):
        return None

    def get_public_key(self, label):
        return self.info

    def sign_ed25519(self, label, data):
        if label != "crl-key":
            raise RuntimeError("wrong HSM label")
        return self.key.sign(data)


class SignedRevocationChainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = KeyManager(
            recorder=Mock(), db_path=Path(self.temp.name) / "crl.sqlite3",
        )
        self.addCleanup(self.manager.close)

    def issue(self, number=3):
        return [self.manager.generate_key(f"test-{n}").key_id for n in range(number)]

    def test_zero_one_two_three_and_four_signed_revocations(self):
        self.assertTrue(self.manager.check_revocation_chain())
        keys = self.issue(4)
        previous = None
        for index, key in enumerate(keys):
            rev = self.manager.revoke_key_with_crl(key)
            self.assertTrue(self.manager.verify_revocation(rev))
            self.assertEqual(rev.previous_revocation_digest, previous)
            self.assertEqual(len(self.manager.get_revocation_list()), index + 1)
            self.assertTrue(self.manager.check_revocation_chain())
            self.assertTrue(self.manager.is_revoked(key))
            previous = self.manager._revocation_link(rev.signature)
        self.assertEqual(
            [r.key_id for r in self.manager.get_revocation_list()], keys
        )
        self.manager.close()
        self.manager = KeyManager(
            recorder=Mock(), db_path=Path(self.temp.name) / "crl.sqlite3",
        )
        self.assertTrue(self.manager.check_revocation_chain())

    def test_tampered_signature_and_link_are_rejected(self):
        keys = self.issue(3)
        for key in keys:
            self.manager.revoke_key_with_crl(key)
        db = self.manager._db
        db.execute(
            "UPDATE revocations SET previous_revocation_digest = ? WHERE key_id = ?",
            ("f" * 32, keys[1]),
        )
        db.commit()
        self.assertFalse(self.manager.check_revocation_chain())
        db.execute(
            "UPDATE revocations SET previous_revocation_digest = "
            "(SELECT substr(lower(hex(zeroblob(16))),1,32)) WHERE key_id = ?",
            (keys[1],),
        )
        db.commit()
        self.assertFalse(self.manager.check_revocation_chain())

    def test_corrupted_existing_chain_cannot_accept_new_entries(self):
        keys = self.issue(3)
        self.manager.revoke_key_with_crl(keys[0])
        self.manager.revoke_key_with_crl(keys[1])
        db = self.manager._db
        db.execute("UPDATE revocations SET signature = 'bad' WHERE key_id = ?", (keys[0],))
        db.commit()
        with self.assertRaisesRegex(KeyManagementError, "revocation chain is invalid"):
            self.manager.revoke_key_with_crl(keys[2])
        self.assertFalse(self.manager.is_revoked(keys[2]))
        self.assertEqual(len(self.manager.get_revocation_list()), 2)

    def test_signer_outage_rolls_back_both_key_and_chain(self):
        key = self.issue(1)[0]
        with patch.object(self.manager, "_sign", side_effect=RuntimeError("signer offline")):
            with self.assertRaisesRegex(RuntimeError, "signer offline"):
                self.manager.revoke_key_with_crl(key)
        self.assertFalse(self.manager.is_revoked(key))
        self.assertEqual(self.manager.get_revocation_list(), [])
        self.assertTrue(self.manager.check_revocation_chain())

    def test_duplicate_crl_revocation_refused(self):
        key = self.issue(1)[0]
        self.manager.revoke_key_with_crl(key)
        with self.assertRaisesRegex(KeyManagementError, "not active"):
            self.manager.revoke_key_with_crl(key)
        self.assertTrue(self.manager.check_revocation_chain())
        self.assertEqual(len(self.manager.get_revocation_list()), 1)

    def test_hsm_crl_signature_verifies_against_hsm_not_software(self):
        with tempfile.TemporaryDirectory() as d:
            hsm = WorkingHSM()
            manager = KeyManager(
                recorder=Mock(), db_path=Path(d) / "hsm-crl.sqlite3",
                hsm_backend=hsm, hsm_key_label="crl-key",
            )
            try:
                rev = manager.revoke_key_with_crl("fixture-hsm")
                self.assertTrue(manager.verify_revocation(rev))
                self.assertTrue(manager.check_revocation_chain())
            finally:
                manager.close()


if __name__ == "__main__":
    unittest.main()
