"""Portable evidence verifier tests; fake hosts NEVER constitute hardware proof."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.two_host_evidence import (
    PHASES, ROLES, sign_payload, verify_bundle, verify_signed,
    make_payload, load_and_verify_bundle,
)
from scripts.two_host_campaign import (
    _write_exclusive, _safe_key, recipient_snapshot, journal_snapshot,
)

RUN = "8a8f596e-72ee-475d-b64b-f5ae3498f3be"
SHA = "a" * 40
EFFECT = "b" * 64
REQUEST = "c" * 64
OUTPUT = "d" * 64
RECEIPT = "e" * 64
RECIPIENT = "owned-hp-recipient"
BOOT = "11111111-1111-4111-8111-111111111111"


def recipient_state():
    return {
        "status": "positive", "row_count": 1,
        "receipt_digest": RECEIPT, "sequence": 1,
        "output_digest": OUTPUT,
    }


def gateway_state(phase):
    positive = phase != "disconnected"
    return {
        "journal": {
            "status": "positive",
            "original_capability_id": "cap-original-signed",
            "state": "recipient-confirmed", "receipt_digest": RECEIPT,
            "request_digest": REQUEST, "recipient_id": RECIPIENT,
            "output_digest": OUTPUT,
        },
        "transport": {
            "status": "positive" if positive else "indeterminate",
            "receipt_digest": RECEIPT if positive else None,
            "sequence": 1 if positive else None,
            "output_digest": OUTPUT if positive else None,
        },
    }


class TwoHostEvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.gateway_key = Ed25519PrivateKey.generate()
        self.recipient_key = Ed25519PrivateKey.generate()
        self.pinned = {
            "gateway_public": self.gateway_key.public_key(),
            "recipient_public": self.recipient_key.public_key(),
        }
        self.artifacts = {}
        for role in ROLES:
            for phase in PHASES:
                payload = make_payload(
                    role=role, phase=phase,
                    run_id=RUN, source_revision=SHA,
                    effect_key=EFFECT, request_digest=REQUEST,
                    recipient_id=RECIPIENT,
                    machine_id_hash=("f" if role == "gateway" else "1") * 64,
                    boot_id=BOOT,
                    kernel_release="6.8.0-lab",
                    environment_hint="wsl2" if role == "gateway" else "linux",
                    snapshot=gateway_state(phase) if role == "gateway"
                    else recipient_state(),
                )
                self.artifacts[(role, phase)] = sign_payload(
                    payload, self.gateway_key if role == "gateway"
                    else self.recipient_key,
                )

    def verify(self, artifacts=None, **kwargs):
        return verify_bundle(
            observations=self.artifacts if artifacts is None else artifacts,
            **(self.pinned | kwargs),
        )

    def altered(self, role, phase, callback, *, resign=True):
        obj = copy.deepcopy(self.artifacts)
        item = obj[(role, phase)]
        callback(item["payload"])
        if resign:
            key = self.gateway_key if role == "gateway" else self.recipient_key
            obj[(role, phase)] = sign_payload(item["payload"], key)
        return obj

    def test_correct_signed_six_stages_preserve_original_receipt(self):
        result = self.verify()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["recipient_row_count"], 1)
        self.assertEqual(result["receipt_digest"], RECEIPT)
        self.assertEqual(result["original_capability_id"], "cap-original-signed")
        self.assertTrue(result["distinct_reported_machine_identities"])
        self.assertFalse(result["signed_fresh_recovery_verified"])
        self.assertFalse(result["actual_network_disconnect_cause_verified"])
        self.assertFalse(result["physical_independence_hardware_attested"])
        self.assertFalse(result["physical_power_cut_proven"])
        self.assertFalse(result["cross_host_gateway_failover_proven"])

    def test_missing_observation_is_not_success(self):
        broken = copy.deepcopy(self.artifacts)
        broken.pop(("recipient", "disconnected"))
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_same_host_machine_identity_rejected(self):
        broken = self.altered(
            "recipient", "before",
            lambda x: x.update(machine_id_hash="f" * 64),
        )
        for phase in ("disconnected", "recovered"):
            broken[("recipient", phase)] = sign_payload(
                {**broken[("recipient", phase)]["payload"],
                 "machine_id_hash": "f" * 64},
                self.recipient_key,
            )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_same_witness_key_not_two_hosts(self):
        with self.assertRaises(ValueError):
            self.verify(recipient_public=self.gateway_key.public_key())

    def test_wrong_trusted_public_key_rejected(self):
        with self.assertRaises(ValueError):
            self.verify(gateway_public=Ed25519PrivateKey.generate().public_key())

    def test_signature_tamper_cannot_be_reinterpreted(self):
        broken = self.altered(
            "recipient", "recovered",
            lambda x: x["snapshot"].update(receipt_digest="9" * 64),
            resign=False,
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_recipient_row_mutation_rejected_even_with_valid_signature(self):
        broken = self.altered(
            "recipient", "disconnected",
            lambda x: x["snapshot"].update(receipt_digest="9" * 64),
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_cannot_hide_a_second_effect_row(self):
        # Schema checks reject anything besides a single committed row.
        with self.assertRaises(ValueError):
            make_payload(
                role="recipient", phase="recovered", run_id=RUN,
                source_revision=SHA, effect_key=EFFECT,
                request_digest=REQUEST, recipient_id=RECIPIENT,
                machine_id_hash="1" * 64, boot_id=BOOT,
                kernel_release="Linux", environment_hint="linux",
                snapshot={**recipient_state(), "row_count": 2},
            )

    def test_gateway_original_authority_cannot_change(self):
        broken = self.altered(
            "gateway", "recovered",
            lambda x: x["snapshot"]["journal"].update(
                original_capability_id="forged-new-original",
            ),
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_gateway_never_connected_not_accepted(self):
        broken = self.altered(
            "gateway", "before",
            lambda x: x["snapshot"]["transport"].update(
                status="indeterminate", receipt_digest=None,
                sequence=None, output_digest=None,
            ),
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_gateway_never_disconnected_not_accepted(self):
        broken = self.altered(
            "gateway", "disconnected",
            lambda x: x["snapshot"]["transport"].update(
                status="positive", receipt_digest=RECEIPT,
                sequence=1, output_digest=OUTPUT,
            ),
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_changed_boot_between_stages_rejected(self):
        broken = self.altered(
            "recipient", "recovered",
            lambda x: x.update(
                boot_id="22222222-2222-4222-8222-222222222222"
            ),
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_mismatched_source_revision_rejected(self):
        broken = self.altered(
            "gateway", "recovered",
            lambda x: x.update(source_revision="b" * 40),
        )
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_extra_unsigned_fields_are_not_accepted(self):
        broken = copy.deepcopy(self.artifacts)
        broken[("gateway", "before")]["payload"]["injected_ok"] = True
        with self.assertRaises(ValueError):
            self.verify(broken)

    def test_file_integrity_and_pinned_public_keys(self):
        from cryptography.hazmat.primitives import serialization
        with tempfile.TemporaryDirectory(prefix="ehh-two-host-unit-") as root:
            directory = Path(root)
            paths = {}
            for (role, phase), obj in self.artifacts.items():
                path = directory / f"{role}.{phase}.json"
                path.write_bytes(canonical_bytes(obj))
                paths[(role, phase)] = path
            pub_a = directory / "gateway.pub"
            pub_b = directory / "recipient.pub"
            for pub, key in ((pub_a, self.gateway_key), (pub_b, self.recipient_key)):
                pub.write_bytes(key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ))
            output = load_and_verify_bundle(
                paths=paths, gateway_pub=pub_a, recipient_pub=pub_b,
            )
            self.assertEqual(output["status"], "PASS")
            self.assertEqual(len(output["original_artifacts_sha256"]), 6)
            # Reformat valid JSON: not canonical original bytes, must fail.
            paths[("gateway", "before")].write_text(
                json.dumps(self.artifacts[("gateway", "before")], indent=2),
            )
            with self.assertRaises(ValueError):
                load_and_verify_bundle(
                    paths=paths, gateway_pub=pub_a, recipient_pub=pub_b,
                )


class HostReadOnlyObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ehh-two-host-observe-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.database = self.root / "recipient.sqlite"
        self.journal_path = self.root / "journal.sqlite"
        self.recipient = FencedSqliteRecipient(
            self.database, recipient_id=RECIPIENT,
        )
        self.journal = DurableEffectJournal(self.journal_path)

    def test_readonly_recipient_snapshot_checks_original_receipt(self):
        inserted = self.recipient.apply(
            effect_key=EFFECT, request_digest=REQUEST,
            output={"data": "owned"},
        )
        result = recipient_snapshot(
            database=self.database, effect_key=EFFECT,
            request_digest=REQUEST, recipient_id=RECIPIENT,
        )
        self.assertEqual(result["row_count"], 1)
        self.assertEqual(result["receipt_digest"], inserted.receipt_digest)
        self.assertEqual(result["output_digest"], inserted.output_digest)

    def test_lost_database_cannot_be_recreated_by_capture(self):
        before_size = self.database.stat().st_size
        self.database.rename(self.root / "preserved.sqlite")
        with self.assertRaises(Exception):
            recipient_snapshot(
                database=self.database, effect_key=EFFECT,
                request_digest=REQUEST, recipient_id=RECIPIENT,
            )
        self.assertFalse(self.database.exists())
        self.assertGreater(before_size, 0)

    def test_corrupt_recipient_result_fail_closed(self):
        self.recipient.apply(
            effect_key=EFFECT, request_digest=REQUEST, output="owned",
        )
        with sqlite3.connect(self.database) as conn:
            conn.execute("UPDATE effects SET receipt_digest=?", ("f" * 64,))
        with self.assertRaises(ValueError):
            recipient_snapshot(
                database=self.database, effect_key=EFFECT,
                request_digest=REQUEST, recipient_id=RECIPIENT,
            )

    def test_gateway_observer_reads_original_reservation(self):
        self.journal.reserve_fenced(
            tenant="default", environment="synthetic", effect_key=EFFECT,
            capability_id="cap-original", request_digest=REQUEST,
            claims_digest="f" * 64, recipient_id=RECIPIENT,
            output_digest=OUTPUT,
        )
        result = journal_snapshot(
            effect_key=EFFECT, request_digest=REQUEST,
            recipient_id=RECIPIENT, journal_db=self.journal_path,
        )
        self.assertEqual(result["original_capability_id"], "cap-original")
        self.assertEqual(result["state"], "possibly-committed")
        self.assertEqual(result["request_digest"], REQUEST)

    def test_file_create_once_and_private_key_rejects_world_readable(self):
        key = Ed25519PrivateKey.generate()
        private = self.root / "private.pem"
        private.write_bytes(key.private_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
            format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
        ))
        private.chmod(0o600)
        self.assertIsInstance(_safe_key(private), Ed25519PrivateKey)
        private.chmod(0o644)
        with self.assertRaises(ValueError):
            _safe_key(private)
        result = self.root / "artifact.json"
        _write_exclusive(result, b"immutable")
        with self.assertRaises(FileExistsError):
            _write_exclusive(result, b"changed")
        self.assertEqual(result.read_bytes(), b"immutable")


if __name__ == "__main__":
    unittest.main()
