"""Atomic distributed effect-fence contract via deterministic etcd Txn emulation.

These are portable linearizable state-machine tests, NOT real quorum,
multi-host or hardware durability proof. Live Docker etcd tests are separate.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import tempfile
import threading
import time
import unittest

from event_horizon.authority_backends import EtcdV3CapabilityConsumptionStore
from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_outcome_journal import EffectAlreadyReserved, EffectJournalError
from event_horizon.etcd_effect_journal import EtcdFencedEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from tests.test_etcd_signed_replay import AtomicEtcd, CID


def binding(*, key="a" * 64, cap="cap-a", request="b" * 64,
            claims="c" * 64, recipient="pinned-recipient", output="d" * 64):
    return {
        "tenant": "default", "environment": "synthetic",
        "effect_key": key, "capability_id": cap,
        "request_digest": request, "claims_digest": claims,
        "recipient_id": recipient, "output_digest": output,
    }


class EtcdEffectJournalTests(unittest.TestCase):
    def setUp(self):
        self.etcd = AtomicEtcd()
        self.one = self.journal()
        self.two = self.journal()

    def journal(self):
        return EtcdFencedEffectJournal(
            self.etcd, expected_cluster_id=CID,
            namespace="e2e-consensus-journal", domain="effect-fence",
        )

    def test_first_reservation_atomically_creates_two_records(self):
        data = binding()
        self.assertTrue(self.one.reserve_fenced(**data))
        self.assertEqual(len(self.etcd.data), 2)
        observed = self.two.observe_effect(
            tenant="default", environment="synthetic", effect_key=data["effect_key"],
        )
        self.assertEqual(observed["capability_id"], data["capability_id"])
        self.assertEqual(observed["request_digest"], data["request_digest"])
        self.assertEqual(observed["fenced_recipient_id"], data["recipient_id"])
        self.assertEqual(observed["state"], "possibly-committed")
        self.assertIsNone(observed["receipt_digest"])
        self.assertEqual(self.two.observe(
            tenant="default", environment="synthetic", capability_id="cap-a",
        )["claims_digest"], data["claims_digest"])

    def test_second_identical_original_no_new_records(self):
        data = binding()
        self.assertTrue(self.one.reserve_fenced(**data))
        self.assertFalse(self.two.reserve_fenced(**data))
        self.assertEqual(len(self.etcd.data), 2)

    def test_different_original_authority_cannot_overwrite(self):
        first = binding()
        self.one.reserve_fenced(**first)
        with self.assertRaises(EffectAlreadyReserved):
            self.two.reserve_fenced(**binding(cap="fresh-signed"))
        self.assertEqual(self.one.observe_effect(
            tenant="default", environment="synthetic", effect_key=first["effect_key"],
        )["capability_id"], "cap-a")
        self.assertEqual(len(self.etcd.data), 2)

    def test_different_result_request_and_recipient_rejected(self):
        self.one.reserve_fenced(**binding())
        for changed in (
            binding(output="f" * 64), binding(request="f" * 64),
            binding(recipient="different"), binding(claims="e" * 64),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(EffectAlreadyReserved):
                    self.two.reserve_fenced(**changed)
        self.assertEqual(len(self.etcd.data), 2)

    def test_capability_id_reuse_across_effects_is_rejected(self):
        self.one.reserve_fenced(**binding())
        with self.assertRaises(EffectAlreadyReserved):
            self.two.reserve_fenced(**binding(key="f" * 64))
        self.assertEqual(len(self.etcd.data), 2)

    def test_confirm_positive_receipt_is_idempotent_across_gateways(self):
        self.one.reserve_fenced(**binding())
        args = dict(
            tenant="default", environment="synthetic", effect_key="a" * 64,
            capability_id="cap-a", request_digest="b" * 64,
            claims_digest="c" * 64, receipt_digest="e" * 64,
        )
        self.one.confirm_from_trusted_recipient(**args)
        self.two.confirm_from_trusted_recipient(**args)
        self.assertEqual(len(self.etcd.data), 2)
        observed = self.two.observe_effect(
            tenant="default", environment="synthetic", effect_key="a" * 64,
        )
        self.assertEqual(observed["state"], "recipient-confirmed")
        self.assertEqual(observed["receipt_digest"], "e" * 64)
        self.assertEqual(observed["capability_id"], "cap-a")

    def test_cannot_confirm_with_recovery_capability_or_changed_receipt(self):
        self.one.reserve_fenced(**binding())
        args = dict(
            tenant="default", environment="synthetic", effect_key="a" * 64,
            capability_id="cap-a", request_digest="b" * 64,
            claims_digest="c" * 64, receipt_digest="e" * 64,
        )
        with self.assertRaises(EffectJournalError):
            self.two.confirm_from_trusted_recipient(
                **{**args, "capability_id": "new-recovery-cap"},
            )
        self.one.confirm_from_trusted_recipient(**args)
        with self.assertRaises(EffectJournalError):
            self.two.confirm_from_trusted_recipient(
                **{**args, "receipt_digest": "f" * 64},
            )

    def test_concurrent_new_first_reservations_one_original(self):
        barrier = threading.Barrier(12)
        def attempt(n):
            barrier.wait(timeout=4)
            data = binding(cap=f"cap-{n}")
            try:
                return self.journal().reserve_fenced(**data)
            except EffectAlreadyReserved:
                return False
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(12)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(self.etcd.data), 2)

    def test_missing_index_is_never_treated_as_unreserved(self):
        self.one.reserve_fenced(**binding())
        k = self.one._cap_key("default", "synthetic", "cap-a")
        del self.etcd.data[k]
        with self.assertRaises(EffectJournalError):
            self.two.observe_effect(
                tenant="default", environment="synthetic", effect_key="a" * 64,
            )
        with self.assertRaises(EffectJournalError):
            self.two.reserve_fenced(**binding())

    def test_inconsistent_cluster_id_fails_closed(self):
        self.one.reserve_fenced(**binding())
        self.etcd.cluster_id = "999000000"
        with self.assertRaises(EffectJournalError):
            self.two.observe_effect(
                tenant="default", environment="synthetic", effect_key="a" * 64,
            )
        with self.assertRaises(EffectJournalError):
            self.two.reserve_fenced(**binding(cap="fresh"))

    def test_lost_reservation_ack_does_not_blindly_retry(self):
        self.etcd.ambiguous = True
        with self.assertRaises(EffectJournalError):
            self.one.reserve_fenced(**binding())
        self.assertEqual(len(self.etcd.data), 2)
        # The caller cannot call its first dispatch; another new, separately
        # signed capability must corroborate the original journal binding.
        with self.assertRaises(EffectAlreadyReserved):
            self.two.reserve_fenced(**binding(cap="recovery"))
        self.assertEqual(len(self.etcd.data), 2)

    def test_majority_unavailable_no_new_authorization(self):
        self.etcd.available = False
        with self.assertRaises(EffectJournalError):
            self.one.reserve_fenced(**binding())
        self.assertEqual(len(self.etcd.data), 0)

    def test_lost_confirmation_ack_keeps_original_record(self):
        self.one.reserve_fenced(**binding())
        self.etcd.ambiguous = True
        with self.assertRaises(EffectJournalError):
            self.two.confirm_from_trusted_recipient(
                tenant="default", environment="synthetic", effect_key="a" * 64,
                capability_id="cap-a", request_digest="b" * 64,
                claims_digest="c" * 64, receipt_digest="e" * 64,
            )
        row = self.one.observe_effect(
            tenant="default", environment="synthetic", effect_key="a" * 64,
        )
        self.assertEqual(row["state"], "recipient-confirmed")
        self.assertEqual(row["capability_id"], "cap-a")
        self.assertEqual(row["receipt_digest"], "e" * 64)

    def test_corrupt_existing_record_never_releases_fence(self):
        self.one.reserve_fenced(**binding())
        ek = self.one._effect_key("default", "synthetic", "a" * 64)
        value, mod, version = self.etcd.data[ek]
        self.etcd.data[ek] = ("not-base64", mod, version)
        with self.assertRaises(EffectJournalError):
            self.two.observe_effect(
                tenant="default", environment="synthetic", effect_key="a" * 64,
            )
        with self.assertRaises(EffectJournalError):
            self.two.reserve_fenced(**binding(cap="fresh"))

    def test_namespace_and_capability_collision_rejected(self):
        for namespace in ("", "../bad", "Invalid", "over/lap"):
            with self.assertRaises(ValueError):
                EtcdFencedEffectJournal(
                    self.etcd, expected_cluster_id=CID, namespace=namespace,
                )
        self.one.reserve_fenced(**binding())
        separate = EtcdFencedEffectJournal(
            self.etcd, expected_cluster_id=CID,
            namespace="different-namespace",
        )
        self.assertTrue(separate.reserve_fenced(**binding()))
        self.assertEqual(len(self.etcd.data), 4)


class SignedRecoveryAcrossConsensusJournals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ehh-consensus-fence-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.recipient = FencedSqliteRecipient(root / "business.sqlite",
                                                recipient_id="consensus-recipient")
        self.root = root
        self.etcd = AtomicEtcd()
        self.request = ActionRequest(
            "consensus-dataset", "consensus-session", "agent",
            "object.read", "synthetic-data", "exec-1",
            {"offset": 0, "length": 5}, "trusted test",
        )
        self.context = authority_context(self.request, time.time(), max_output_bytes=512)
        self.broker = CapabilityBroker(ttl_seconds=120)

    def gateway(self, cap, name):
        store = EtcdV3CapabilityConsumptionStore(
            self.etcd, expected_cluster_id=CID,
            namespace="consensus-replay", domain="external-effect",
        )
        journal = EtcdFencedEffectJournal(
            self.etcd, expected_cluster_id=CID,
            namespace="consensus-effects",
        )
        v = verify_options(self.context)
        gate = FencedEffectRecoveryGateway(
            CapabilityVerifier(self.broker.public_key_pem,
                               self.broker.key_id, store),
            ExternalRecorder(self.root / (name + ".jsonl")),
            journal, self.recipient, output_factory=lambda _: "owned-value",
        )
        return gate.execute(
            self.request, cap, v["attestation"],
            executor_measurement=v["executor_measurement"],
            device_id=v["device_id"],
            verifier_policy_digest=v["verifier_policy_digest"],
            policy_digest=v["policy_digest"],
        )

    def test_first_signed_commit_then_fresh_recovery_from_other_gateway(self):
        first = self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )
        one = self.gateway(first, "first")
        self.assertTrue(one.accepted, one.error_class)
        fresh = self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )
        two = self.gateway(fresh, "separate-gateway")
        self.assertTrue(two.accepted, two.error_class)
        self.assertEqual(self.recipient.commit_count(), 1)
        self.assertEqual(self.gateway(first, "spent").error_class, "authority-denied")
        row = EtcdFencedEffectJournal(
            self.etcd, expected_cluster_id=CID,
            namespace="consensus-effects",
        ).observe_effect(
            tenant="default", environment="synthetic",
            effect_key=digest({
                "session_id": self.request.session_id,
                "request_id": self.request.request_id,
            }),
        )
        self.assertEqual(row["capability_id"], first.claims.capability_id)
        self.assertEqual(row["state"], "recipient-confirmed")

    def test_consensus_outage_denies_first_effect(self):
        cap = self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )
        self.etcd.available = False
        denied = self.gateway(cap, "no-quorum")
        self.assertFalse(denied.accepted)
        self.assertEqual(self.recipient.commit_count(), 0)


if __name__ == "__main__":
    unittest.main()
