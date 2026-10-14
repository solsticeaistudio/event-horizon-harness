"""Live disposable three-member etcd journal acceptance, never production.

EHH_ETCD_ENDPOINT is set only by the opt-in owned etcd lab. These tests
use an actual linearizable v3 transaction on real etcd, but Docker nodes
may all share ONE physical host: no independent physical-host fault claim.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from event_horizon.authority_backends import EtcdGatewayConfig, etcd_authority
from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.canonical import digest
from event_horizon.etcd_effect_journal import EtcdFencedEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from tests.test_etcd_live import cluster_id


@unittest.skipUnless(os.environ.get("EHH_ETCD_ENDPOINT"), "owned etcd required")
class LiveConsensusEffectFences(unittest.TestCase):
    def setUp(self):
        self.endpoint = os.environ["EHH_ETCD_ENDPOINT"]
        self.cluster = os.environ.get("EHH_ETCD_CLUSTER_ID") or cluster_id(self.endpoint)
        self.config = EtcdGatewayConfig(
            endpoint=self.endpoint, allow_insecure_loopback=True,
            timeout_seconds=2.0,
        )
        self.namespace = "fence." + uuid.uuid4().hex

    def journal(self):
        return EtcdFencedEffectJournal.connect(
            self.config, expected_cluster_id=self.cluster,
            namespace=self.namespace, domain="effect-fence",
        )

    def test_real_etcd_competing_first_writers_and_receipt_confirmation(self):
        effect = "a" * 64
        def attempt(n):
            journal = self.journal()
            try:
                journal.reserve_fenced(
                    tenant="default", environment="synthetic",
                    effect_key=effect, capability_id=f"cap-{n}",
                    request_digest="b" * 64, claims_digest="c" * 64,
                    recipient_id="owned-live-recipient",
                    output_digest="d" * 64,
                )
                return True
            except Exception as exc:
                from event_horizon.effect_outcome_journal import EffectAlreadyReserved
                if isinstance(exc, EffectAlreadyReserved):
                    return False
                raise
        with ThreadPoolExecutor(max_workers=8) as pool:
            winners = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(winners), 1)
        owner = self.journal().observe_effect(
            tenant="default", environment="synthetic", effect_key=effect,
        )
        self.assertTrue(owner["capability_id"].startswith("cap-"))
        args = dict(
            tenant="default", environment="synthetic", effect_key=effect,
            capability_id=owner["capability_id"],
            request_digest="b" * 64, claims_digest="c" * 64,
            receipt_digest="e" * 64,
        )
        self.journal().confirm_from_trusted_recipient(**args)
        self.journal().confirm_from_trusted_recipient(**args)
        completed = self.journal().observe_effect(
            tenant="default", environment="synthetic", effect_key=effect,
        )
        self.assertEqual(completed["state"], "recipient-confirmed")
        self.assertEqual(completed["receipt_digest"], "e" * 64)
        self.assertEqual(completed["capability_id"], owner["capability_id"])

    def test_two_signed_gateway_instances_share_live_consensus(self):
        with tempfile.TemporaryDirectory(prefix="ehh-live-effect-fence-") as tmp:
            root = Path(tmp)
            request = ActionRequest(
                "live-etcd-effect", "live-session", "agent",
                "object.read", "synthetic-data", "exec-1",
                {"offset": 0, "length": 5}, "trusted test",
            )
            context = authority_context(
                request, time.time(), max_output_bytes=512,
            )
            options = verify_options(context)
            broker = CapabilityBroker(ttl_seconds=120)
            recipient = FencedSqliteRecipient(
                root / "recipient.sqlite", recipient_id="owned-consensus-fixture",
            )
            def run(name, token):
                replay = etcd_authority(
                    self.config, expected_cluster_id=self.cluster,
                    namespace=self.namespace, domain="signed-external-effect",
                )
                gateway = FencedEffectRecoveryGateway(
                    CapabilityVerifier(
                        broker.public_key_pem, broker.key_id, replay,
                    ),
                    ExternalRecorder(root / (name + ".jsonl")),
                    self.journal(), recipient,
                    output_factory=lambda _: "owned-value",
                )
                return gateway.execute(
                    request, token, options["attestation"],
                    executor_measurement=options["executor_measurement"],
                    device_id=options["device_id"],
                    verifier_policy_digest=options["verifier_policy_digest"],
                    policy_digest=options["policy_digest"],
                )
            original = broker.issue(
                request, **issue_options(context), max_output_bytes=512,
            )
            first = run("gateway-A", original)
            self.assertTrue(first.accepted, first.error_class)
            recovery = broker.issue(
                request, **issue_options(context), max_output_bytes=512,
            )
            second = run("gateway-B", recovery)
            self.assertTrue(second.accepted, second.error_class)
            self.assertEqual(recipient.commit_count(), 1)
            self.assertEqual(run("old-capability-replay", original).error_class,
                             "authority-denied")
            row = self.journal().observe_effect(
                tenant="default", environment="synthetic",
                effect_key=digest({
                    "session_id": request.session_id,
                    "request_id": request.request_id,
                }),
            )
            self.assertEqual(row["capability_id"], original.claims.capability_id)
            self.assertEqual(row["state"], "recipient-confirmed")
            self.assertEqual(row["receipt_digest"],
                             recipient.observe(
                                 effect_key=digest({
                                     "session_id": request.session_id,
                                     "request_id": request.request_id,
                                 }), request_digest=request.request_digest,
                             ).receipt_digest)


if __name__ == "__main__":
    unittest.main()
