"""Rootless test of the external host-side etcd oracle and package lab wiring.

These tests deliberately do not claim Firecracker/KVM or real quorum execution.
"""
from __future__ import annotations

import base64
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from event_horizon.authority_backends import EtcdV3CapabilityConsumptionStore
from event_horizon.broker import CapabilityBroker
from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.models import ActionRequest
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.package_authority_oracle import (
    inspect_committed_consumption, owned_etcd_config,
)
from scripts.run_package_isolation import PackageLab, main

CLUSTER = "139003440588"
PREFIX = "/event-horizon/replay/v1/ehk-abc123/external-effect/"
CAP = "cap_0123456789abcdef01234567"
BINDING = "a" * 64
EXPIRY = 2500


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def signed_record(*, binding=BINDING, expiry=EXPIRY):
    return canonical_bytes({
        "schema": "eh.capability-consumption.v1",
        "claims_digest": binding, "expires_at": expiry,
        "consumed_at": 1300,
    })


def reply(*, count=1, cluster=CLUSTER, key=None, record=None, revision="17"):
    prefix = PREFIX.encode()
    key = (prefix + CAP.encode()) if key is None else key
    record = signed_record() if record is None else record
    return {
        "header": {"cluster_id": cluster, "revision": revision, "raft_term": "2"},
        "succeeded": True,
        "responses": [{"response_range": {
            "count": str(count),
            "kvs": [] if count == 0 else [{"key": b64(key), "value": b64(record)}],
        }}],
    }


def observe(transport):
    return inspect_committed_consumption(
        transport, cluster_id=CLUSTER, session_id="ehk-abc123",
        capability_id=CAP, claims_digest=BINDING, expires_at=EXPIRY,
    )


class IndependentPackageOracleTests(unittest.TestCase):
    def test_matches_exact_linearizable_committed_record(self):
        call = Mock(return_value=reply())
        evidence = observe(call)
        self.assertEqual(evidence["record_count"], 1)
        self.assertEqual(evidence["cluster_id"], CLUSTER)
        self.assertEqual(evidence["claims_digest"], BINDING)
        self.assertTrue(evidence["record_integrity_checked"])
        payload = call.call_args.args[0]
        self.assertEqual(payload["compare"], [])
        self.assertEqual(payload["failure"], [])
        self.assertEqual(len(payload["success"]), 1)
        query = payload["success"][0]["requestRange"]
        self.assertFalse(query["serializable"])
        self.assertEqual(base64.b64decode(query["key"]), PREFIX.encode())
        self.assertEqual(base64.b64decode(query["range_end"]), PREFIX[:-1].encode() + b"0")

    def test_real_tempfile_session_underscore_is_safe_and_bound_exactly(self):
        candidate = reply(key=PREFIX.replace("ehk-abc123", "ehk-a_b123").encode()+CAP.encode())
        result = inspect_committed_consumption(lambda _: candidate, cluster_id=CLUSTER,
            session_id="ehk-a_b123", capability_id=CAP, claims_digest=BINDING, expires_at=EXPIRY)
        self.assertEqual(result["record_count"],1)
        with self.assertRaises(ValueError):
            inspect_committed_consumption(lambda _: candidate, cluster_id=CLUSTER,
                session_id="ehk-a/../b", capability_id=CAP, claims_digest=BINDING, expires_at=EXPIRY)

    def test_known_retired_fault_consumption_is_distinct_from_primary(self):
        fault = "cap_aaaaaaaaaaaaaaaaaaaaaaaa"
        candidate = reply()
        value = candidate["responses"][0]["response_range"]
        value["count"] = "2"
        value["kvs"].append({"key": b64((PREFIX + fault).encode()),
                             "value": b64(signed_record(binding="b" * 64))})
        options = dict(cluster_id=CLUSTER, session_id="ehk-abc123", capability_id=CAP,
                       claims_digest=BINDING, expires_at=EXPIRY,
                       extra_bindings={fault: ("b" * 64, EXPIRY)})
        observed = inspect_committed_consumption(lambda _: candidate, **options)
        self.assertEqual(observed["record_count"], 2)
        self.assertEqual(observed["primary_record_count"], 1)
        self.assertEqual(observed["additional_consumed_ids"], [fault])
        with self.assertRaises(ValueError): observe(lambda _: candidate)
        value["kvs"][1]["value"] = b64(signed_record(binding="c" * 64))
        with self.assertRaises(ValueError):
            inspect_committed_consumption(lambda _: candidate, **options)

    def test_oracle_rejects_missing_extra_cross_session_or_wrong_cluster(self):
        scenarios = (
            reply(count=0),
            reply(count=2),
            reply(cluster="9999"),
            reply(key=b"/event-horizon/replay/v1/ehk-other/external-effect/" + CAP.encode()),
            reply(key=PREFIX.encode() + b"cap_aaaaaaaaaaaaaaaaaaaaaaaa"),
            reply(record=signed_record(binding="b" * 64)),
            reply(record=signed_record(expiry=2600)),
            reply(revision="0"),
        )
        for candidate in scenarios:
            with self.subTest(candidate=candidate["header"], count=candidate["responses"][0]["response_range"]["count"]):
                with self.assertRaises(ValueError):
                    observe(lambda _txn: candidate)

    def test_oracle_refuses_malformed_inputs_and_base64(self):
        for candidate in (None, {}, {"header": {}}, {"header": {"cluster_id": CLUSTER}}):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                observe(lambda _txn: candidate)
        candidate = reply()
        candidate["responses"][0]["response_range"]["kvs"][0]["value"] = "***"
        with self.assertRaises(ValueError):
            observe(lambda _txn: candidate)
        with self.assertRaises(ValueError):
            inspect_committed_consumption(
                lambda _txn: reply(), cluster_id=CLUSTER, session_id="../other",
                capability_id=CAP, claims_digest=BINDING, expires_at=EXPIRY,
            )

    def test_experiment_only_accepts_owned_loopback_etcd_with_pinned_cluster(self):
        self.assertEqual(
            owned_etcd_config("http://127.0.0.1:2379", CLUSTER)["allow_insecure_loopback"], True,
        )
        for endpoint, identity in (
            ("http://remote.example:2379", CLUSTER),
            ("https://remote.example:2379", CLUSTER),
            ("http://127.0.0.1:2379", "0"),
            ("http://127.0.0.1:2379", "not-a-cluster"),
            ("http://user:password@127.0.0.1:2379", CLUSTER),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                owned_etcd_config(endpoint, identity)

    def test_package_context_binds_backend_without_exposing_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = PackageLab(
                "protected", Path(tmp) / "inert-worker", {"worker_sha256": "0" * 64},
                authority_config={
                    "authority_backend": "etcd",
                    "etcd_cluster_id": CLUSTER,
                    "etcd_gateway": owned_etcd_config("http://127.0.0.1:2379", CLUSTER),
                },
            )
            context = lab.context()
            self.assertEqual(context["authority_backend"], "etcd")
            self.assertEqual(context["etcd_cluster_id"], CLUSTER)
            self.assertNotIn("127.0.0.1", str(context))
            self.assertEqual(
                PackageLab("protected", Path(tmp) / "worker", {}).context()["authority_backend"],
                "sqlite",
            )

    def test_package_runner_requires_full_distributed_pinning_before_root_operations(self):
        for options in (
            ["--etcd-endpoint", "http://127.0.0.1:2379"],
            ["--etcd-cluster-id", CLUSTER],
        ):
            with patch("sys.argv", ["package-test", "--report", "unused.json", *options]):
                with self.assertRaises(SystemExit) as caught:
                    main()
                self.assertEqual(caught.exception.code, 2)


class HostGateToEtcdTest(unittest.TestCase):
    def test_integrated_host_gate_consumes_etcd_once_without_guest_selecting_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            now = time.time()
            request = ActionRequest(
                "package-gateway-test", "ehk-abc123", "synthetic-agent",
                "object.read", "synthetic-dataset", "executor-1",
                {"offset": 0, "length": 5}, "approved synthetic fixture",
            )
            broker = CapabilityBroker(b"package-boundary-test-only-seed-32bytes", ttl_seconds=60)
            context = authority_context(request, now)
            capability = broker.issue(
                request, **issue_options(context), max_output_bytes=512,
            )
            oracle_key = (
                f"/event-horizon/replay/v1/{request.session_id}/external-effect/"
                f"{capability.claims.capability_id}"
            ).encode()
            saved = {}
            calls = []

            def fake_etcd(transaction):
                calls.append(transaction)
                cmp = transaction["compare"]
                if not cmp:
                    # Independent read performed by host supervisor.
                    return {
                        "header": {"cluster_id": CLUSTER, "revision": str(len(calls) + 1), "raft_term": "2"},
                        "succeeded": True,
                        "responses": [{"response_range": {
                            "count": str(len(saved)),
                            "kvs": [{"key": b64(k), "value": b64(v)} for k, v in saved.items()],
                        }}],
                    }
                assert cmp[0]["target"] == "VERSION"
                key = base64.b64decode(cmp[0]["key"])
                if key not in saved:
                    saved[key] = base64.b64decode(transaction["success"][0]["requestPut"]["value"])
                    response = {"response_put": {}}
                    succeeded = True
                else:
                    response = {"response_range": {"kvs": [
                        {"key": b64(key), "value": b64(saved[key])},
                    ]}}
                    succeeded = False
                return {
                    "header": {"cluster_id": CLUSTER, "revision": str(len(calls) + 1), "raft_term": "2"},
                    "succeeded": succeeded, "responses": [response],
                }

            backend = EtcdV3CapabilityConsumptionStore(
                fake_etcd, expected_cluster_id=CLUSTER,
                namespace=request.session_id, domain="external-effect",
            )
            config = {
                "authority_backend": "etcd",
                "etcd_gateway": owned_etcd_config("http://127.0.0.1:2379", CLUSTER),
                "etcd_cluster_id": CLUSTER,
                "session_id": request.session_id,
                "vm_uid": 60001,
                "resource_id": "synthetic-dataset",
                "dataset": "hello-safe",
                "public_key_pem": broker.public_key_pem, "key_id": broker.key_id,
                "verification_context": verify_options(context),
                "decay_database": str(Path(temp) / "decay.sqlite3"),
            }
            recorder = Mock()
            with patch("event_horizon.authority_backends.etcd_authority", return_value=backend):
                gate = DatasetEffectBoundary(config, recorder)
            message = {"request": request.canonical_payload(), "capability": capability.to_dict()}
            try:
                # Synthetic worker cannot override backend via protocol fields.
                self.assertFalse(gate.execute({**message, "authority_backend": "sqlite"}, peer_uid=60001)["success"])
                accepted = gate.execute(message, peer_uid=60001)
                self.assertTrue(accepted["success"], accepted)
                self.assertEqual(accepted["output"], "hello")
                self.assertFalse(gate.execute(message, peer_uid=60001)["success"])
                self.assertEqual(list(saved), [oracle_key])
                independent = inspect_committed_consumption(
                    fake_etcd, cluster_id=CLUSTER,
                    session_id=request.session_id,
                    capability_id=capability.claims.capability_id,
                    claims_digest=digest(capability.claims.to_dict()),
                    expires_at=capability.claims.expires_at,
                )
                self.assertEqual(independent["record_count"], 1)
                self.assertEqual(
                    [x.args[0] for x in recorder.append.call_args_list].count("execution.completed"),
                    1,
                )
            finally:
                gate.close()


if __name__ == "__main__":
    unittest.main()
