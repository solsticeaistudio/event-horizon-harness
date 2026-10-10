"""Live host-gateway/etcd conformance without Firecracker, on disposable CI etcd.

Only runs when EHH_ETCD_ENDPOINT names the owned CI loopback cluster.
This checks gateway-to-real-quorum and the independent supervisor read oracle;
the opt-in KVM package lab must still be run on a real eligible Linux host.
"""
from __future__ import annotations

import copy
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock

from event_horizon.broker import CapabilityBroker
from event_horizon.canonical import digest
from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.models import ActionRequest
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.package_authority_oracle import owned_etcd_config, observe_owned_etcd


@unittest.skipUnless(os.environ.get("EHH_ETCD_ENDPOINT"), "requires owned disposable etcd")
class LivePackageEtcdAuthorityTests(unittest.TestCase):
    def test_real_quorum_host_gateway_and_linearizable_oracle(self):
        endpoint = os.environ["EHH_ETCD_ENDPOINT"]
        cluster_id = os.environ["EHH_ETCD_CLUSTER_ID"]
        gateway = owned_etcd_config(endpoint, cluster_id)
        with tempfile.TemporaryDirectory() as tmp:
            session = "ehk-" + uuid.uuid4().hex
            request = ActionRequest(
                "owned-package-read", session, "attacker-agent",
                "object.read", "synthetic-dataset", "exec-1",
                {"offset": 0, "length": 5}, "approved inert fixture",
            )
            broker = CapabilityBroker(ttl_seconds=60)
            context = authority_context(request, time.time())
            capability = broker.issue(
                request, **issue_options(context), max_output_bytes=512,
            )
            cfg = {
                "session_id": session, "vm_uid": 60001, "dataset": "hello-owned",
                "resource_id": "synthetic-dataset",
                "public_key_pem": broker.public_key_pem,
                "key_id": broker.key_id,
                "verification_context": verify_options(context),
                "decay_database": str(Path(tmp) / "decay.sqlite3"),
                "authority_backend": "etcd", "etcd_gateway": gateway,
                "etcd_cluster_id": cluster_id,
            }
            recorder = Mock()
            recorder.append.return_value = {"acknowledged": True}
            effect = DatasetEffectBoundary(cfg, recorder)
            message = {
                "request": request.canonical_payload(),
                "capability": capability.to_dict(),
            }
            try:
                forged = copy.deepcopy(message)
                forged["request"]["arguments"]["offset"] = 1
                self.assertFalse(effect.execute(forged, peer_uid=60001)["success"])
                wrong_principal = effect.execute(message, peer_uid=60000)
                self.assertFalse(wrong_principal["success"])
                changed_backend = effect.execute(
                    {**message, "authority_backend": "sqlite"}, peer_uid=60001,
                )
                self.assertFalse(changed_backend["success"])
                success = effect.execute(message, peer_uid=60001)
                self.assertTrue(success["success"], success)
                self.assertEqual(success["output"], "hello")
                replay = effect.execute(message, peer_uid=60001)
                self.assertFalse(replay["success"])
                self.assertEqual(replay["effect_state"], "not-started")
                witness = observe_owned_etcd(
                    cfg, session_id=session,
                    capability_id=capability.claims.capability_id,
                    claims_digest=digest(capability.claims.to_dict()),
                    expires_at=capability.claims.expires_at,
                )
                self.assertEqual(witness["cluster_id"], cluster_id)
                self.assertEqual(witness["record_count"], 1)
                self.assertEqual(
                    [x.args[0] for x in recorder.append.call_args_list].count("execution.completed"),
                    1,
                )
            finally:
                effect.close()


if __name__ == "__main__":
    unittest.main()
