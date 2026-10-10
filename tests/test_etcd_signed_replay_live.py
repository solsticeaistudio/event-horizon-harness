"""Live signed replay authority conformance against disposable three-node etcd.

RUN ONLY against explicit EHH_ETCD_ENDPOINT set by etcd-quorum CI. This
module does not provision production credentials or tolerate non-loopback
plaintext endpoints.
"""
from __future__ import annotations

import base64
import json
import os
import time
import tempfile
import unittest
import uuid
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.authority_backends import EtcdGatewayConfig
from event_horizon.canonical import digest
from event_horizon.etcd_signed_replay import EtcdSignedReplayService
from event_horizon.remote_replay import (
    AuthenticatedReplayClient, ReplayClientPolicy, ReplayRequestSigner,
    RemoteAuthorizationReplayStore, RemoteCapabilityConsumptionStore,
)
from tests.test_etcd_live import cluster_id
from event_horizon.process_harness import ProcessSeparatedHarness
from event_horizon.models import ActionRequest
from event_horizon.protocol import ProtocolError
from event_horizon.distributed_signed_evidence import STRICT_SCHEMA, verify_distributed_report
from event_horizon.intent_canonicalizer import AuthorizationDenied
from event_horizon.remote_replay import ReplayHttpServer
from event_horizon.trusted_replay_client import (
    provision_replay_client_policies, role_client_seed_path,
)

SID = "etcd-live-signed-replay"


def provision(endpoint: str | None = None, namespace: str | None = None, *, bootstrap=True):
    endpoint = endpoint or os.environ["EHH_ETCD_ENDPOINT"]
    cluster = os.environ.get("EHH_ETCD_CLUSTER_ID") or cluster_id(endpoint)
    config = EtcdGatewayConfig(
        endpoint=endpoint, allow_insecure_loopback=True, timeout_seconds=1.0,
    )
    server_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    client_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    signer = ReplayRequestSigner(client_key, SID)
    policy = ReplayClientPolicy.create(
        signer.public_key_pem,
        operations={
            "nonce-create", "nonce-consume", "nonce-inspect",
            "capability-consume", "authorization-consume",
        },
        partitions={"capabilities", "nonces", "authorizations"},
    )
    params = dict(
        expected_cluster_id=cluster,
        namespace=namespace or "signed." + uuid.uuid4().hex,
        service_id=SID, epoch=1, signing_key=server_key,
        clients={policy.key_id: policy},
    )
    service = EtcdSignedReplayService.connect(config, **params, bootstrap=bootstrap)
    client = AuthenticatedReplayClient(
        signer, service.handle, service.public_key_pem, epoch=1,
    )
    return service, client, config, params


@unittest.skipUnless(os.environ.get("EHH_ETCD_ENDPOINT"), "requires disposable etcd")
class LiveSignedReplayTests(unittest.TestCase):
    def test_real_seven_process_harness_shares_signed_authority(self):
        """Exercise Node verifier + trusted signer + protected recorder/cert.

        All protected services hit the same live etcd authority via signed
        HTTP RPC, not an in-memory reference mock. The executor receives
        neither authority key nor etcd transport configuration.
        """
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory)
            policies = provision_replay_client_policies(scope, SID)
            endpoint = self._seven_process_authority(scope, policies)
            service, server = endpoint
            server.start()
            remote = {
                "url": server.url, "service_id": SID, "epoch": 1,
                "server_public_key_pem": service.public_key_pem,
                "ca_cert_path": None, "client_cert_path": None,
                "client_key_path": None,
            }
            try:
                with ProcessSeparatedHarness(
                    scope, ttl_seconds=30.0, remote_authority=remote,
                ) as harness:
                    signed_events = []
                    authoritative_record = harness.record
                    def capture_record(*args, **kwargs):
                        signed = authoritative_record(*args, **kwargs)
                        signed_events.append(signed)
                        return signed
                    harness.record = capture_record
                    request = {
                        "request_id": "distributed-7-process",
                        "session_id": "signed-replay-session",
                        "agent_id": "attacker-agent",
                        "operation": "object.read",
                        "resource_id": "target-source",
                        "executor_id": "exec-1",
                        "arguments": {"offset": 0, "length": 64},
                        "purpose": "distributed signed authority end-to-end",
                    }
                    action, capability, attestation = harness.request_capability(request)
                    first = harness.execute(action, capability, attestation)
                    self.assertTrue(first.success, first.error)
                    replay = harness.execute(action, capability, attestation)
                    self.assertFalse(replay.success)
                    self.assertEqual(replay.effect_state, "not-started")
                    self.assertIn("replay", replay.error.lower())
                    tampered_action = ActionRequest.from_dict({
                        **action.canonical_payload(),
                        "arguments": {"offset": 1, "length": 64},
                    })
                    modified = harness.execute(
                        tampered_action, capability, attestation,
                    )
                    self.assertFalse(modified.success)
                    self.assertEqual(modified.effect_state, "not-started")
                    unsigned_mutation_denied = False
                    try:
                        harness.call(
                            "signer", "consume", {
                                "request": action.canonical_payload(),
                                "capability": capability.to_dict(),
                                "attestation": attestation,
                            }, authorize=False,
                        )
                    except ProtocolError:
                        unsigned_mutation_denied = True
                    self.assertTrue(unsigned_mutation_denied)
                    guardian_vetoed = False
                    try:
                        harness.request_capability({
                            **request, "request_id": "forbidden-distributed-op",
                            "operation": "shell.execute",
                            "resource_id": "host-root",
                            "arguments": {},
                        })
                    except AuthorizationDenied:
                        guardian_vetoed = True
                    self.assertTrue(guardian_vetoed)
                    probe = harness.root_probe()
                    self.assertFalse(probe["private_key_material_present"])
                    config = json.loads(harness.config_paths["executor"].read_text())
                    self.assertNotIn("remote_replay", config)
                    self.assertNotIn("client_seed_path", str(config))
                    self.assertNotIn("etcd", str(config))
                    # Node nonce transitions and 4 protected-role operations
                    # advance the same etcd checkpoint chain.
                    _, checkpoint, checkpoint_hash = service.checkpoint()
                    self.assertGreaterEqual(checkpoint, 10)
                    self.assertRegex(checkpoint_hash, r"^[0-9a-f]{64}$")
                    self.assertTrue(harness.call("recorder", "verify", {})["valid"])
                    pending = {**request, "request_id": "during-authority-outage"}
                    waiting_req, waiting_cap, waiting_att = harness.request_capability(pending)
                    normal_transport = service.transport
                    def deny_consensus(_body):
                        raise OSError("synthetic quorum outage at trusted authority boundary")
                    service.transport = deny_consensus
                    try:
                        unavailable = harness.execute(
                            waiting_req, waiting_cap, waiting_att,
                        )
                        self.assertFalse(unavailable.success)
                        self.assertEqual(unavailable.effect_state, "not-started")
                    finally:
                        service.transport = normal_transport
                    # Failed quorum consumption did not grant permission or
                    # dispatch, so the previously pending capability can
                    # still be used once on recovery.
                    recovered = harness.execute(
                        waiting_req, waiting_cap, waiting_att,
                    )
                    self.assertTrue(recovered.success, recovered.error)
                    recovery_replay = harness.execute(
                        waiting_req, waiting_cap, waiting_att,
                    )
                    self.assertFalse(recovery_replay.success)
                    harness.stop_role("signer")
                    harness.restart_role("signer")
                    restarted_replay = harness.execute(action, capability, attestation)
                    self.assertFalse(restarted_replay.success)
                    # Exercise the certificate's *protected* mutation endpoint,
                    # not only its unauthenticated info/verify operations.
                    teardown = harness.teardown_executor()
                    self.assertTrue(teardown["verified"])
                    certificate = harness.build_certificate(
                        run_id="distributed-quorum-harness",
                        session_id=action.session_id,
                        assertions={"teardown_verified": True},
                        mode="simulation",
                    )
                    self.assertEqual(
                        certificate["certificate"]["schema"],
                        "event-horizon.containment-certificate.v0.5",
                    )
                    self._assert_trusted_partitions_committed(service)
                    # Signed observation entries bind the assertion set to the
                    # recorder key and immutable event hash chain, independently
                    # of untrusted executor output or CI log formatting.
                    cases = {
                        "valid_effect": first.success and first.effect_state == "completed",
                        "capability_replay": not replay.success and replay.effect_state == "not-started",
                        "executor_credential_probe": (
                            not probe["private_key_material_present"]
                            and not probe["ambient_authority_environment_hits"]
                        ),
                        "authority_outage": (
                            not unavailable.success and unavailable.effect_state == "not-started"
                        ),
                        "recovery_once": recovered.success and recovered.effect_state == "completed",
                        "recovery_replay": (
                            not recovery_replay.success
                            and recovery_replay.effect_state == "not-started"
                        ),
                        "signer_restart_replay": (
                            not restarted_replay.success
                            and restarted_replay.effect_state == "not-started"
                        ),
                        "signed_certificate": (
                            certificate["certificate"]["schema"]
                            == "event-horizon.containment-certificate.v0.5"
                        ),
                        "tampered_arguments": (
                            not modified.success and modified.effect_state == "not-started"
                        ),
                        "unsigned_signer_mutation": unsigned_mutation_denied,
                        "guardian_veto": guardian_vetoed,
                    }
                    # Version 2 also signs the *observable inputs* used to
                    # judge cases, rather than only final PASS assertions.
                    config_has_authority = (
                        "remote_replay" in config
                        or "client_seed_path" in str(config)
                        or "etcd" in str(config)
                    )
                    probes = {
                        "executor_credential_probe": {
                            "private_key_material_present": probe["private_key_material_present"],
                            "ambient_authority_environment_hits": probe["ambient_authority_environment_hits"],
                            "executor_config_has_remote_replay": config_has_authority,
                        },
                        "unsigned_signer_mutation": {"denied": unsigned_mutation_denied},
                        "guardian_veto": {
                            "denied": guardian_vetoed,
                            "request_id": "forbidden-distributed-op",
                        },
                        "signed_certificate": {
                            "certificate_schema": certificate["certificate"]["schema"],
                        },
                    }
                    for case, observation in sorted(probes.items()):
                        harness.record("adversarial.probe", {
                            "case": case, "observation": observation,
                        })
                    _, authority_checkpoint, authority_digest = service.checkpoint()
                    harness.record("distributed.authority.context", {
                        "cluster_id": service.expected_cluster_id,
                        "service_id": service.service_id,
                        "epoch": service.epoch,
                        "checkpoint": authority_checkpoint,
                        "checkpoint_digest": authority_digest,
                    })
                    for case, passed in sorted(cases.items()):
                        harness.record("adversarial.observation", {
                            "case": case, "passed": passed,
                        })
                    recorder = harness.call("recorder", "verify", {})
                    self.assertTrue(recorder["valid"])
                    self.assertEqual(recorder["count"], len(signed_events))
                    report = {
                        "schema": STRICT_SCHEMA,
                        "topology": "same-host-seven-process-live-etcd",
                        "hardware_isolation_tested": False,
                        "etcd_backend_tested": True,
                        "observations": cases,
                        "passed": all(cases.values()),
                        "signed_evidence": {
                            "recorder_public_key_pem": harness.service_info["recorder"]["public_key_pem"],
                            "chain_tip": recorder["detail"],
                            "event_count": recorder["count"],
                            "events": signed_events,
                        },
                    }
                    verified = verify_distributed_report(report)
                    self.assertTrue(verified["verified"], verified)
                    self.assertTrue(verified["passed"], verified)
                    artifact_dir = os.environ.get("EHH_DISTRIBUTED_EVIDENCE_DIR")
                    if artifact_dir:
                        output = Path(artifact_dir)
                        output.mkdir(parents=True, exist_ok=True)
                        trial = os.environ.get("EHH_DISTRIBUTED_TRIAL", "local")
                        (output / f"report-{trial}.json").write_text(
                            json.dumps(report, sort_keys=True, allow_nan=False),
                            encoding="utf-8",
                        )
                    # No silent local fallback, even after trusted restart.
            finally:
                server.close()

    def _assert_trusted_partitions_committed(self, service):
        """Read actual quorum-backed record keys as an independent oracle."""
        raw = f"{service.prefix}/record/".encode("utf-8")
        end = raw[:-1] + bytes([raw[-1] + 1])
        request = urllib.request.Request(
            os.environ["EHH_ETCD_ENDPOINT"] + "/v3/kv/range",
            data=json.dumps({
                "key": base64.b64encode(raw).decode("ascii"),
                "range_end": base64.b64encode(end).decode("ascii"),
                "serializable": False,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            stored = json.loads(response.read())
        paths = {
            base64.b64decode(entry["key"]).decode("utf-8")
            for entry in stored.get("kvs", [])
        }
        required = {
            "/record/nonce/attestation.nonces/",
            "/record/capability-consume/capability.authority/",
            "/record/authorization-consume/protected.signer/",
            "/record/authorization-consume/protected.recorder/",
            "/record/authorization-consume/protected.certificate/",
        }
        for fragment in required:
            self.assertTrue(
                any(fragment in key for key in paths),
                f"missing real etcd authority state: {fragment}",
            )

    def _seven_process_authority(self, scope, policies):
        from event_horizon.authority_backends import EtcdV3TransactionTransport
        from pathlib import Path
        from event_horizon.remote_replay import ReplayHttpServer
        endpoint = os.environ["EHH_ETCD_ENDPOINT"]
        config = EtcdGatewayConfig(
            endpoint=endpoint, allow_insecure_loopback=True, timeout_seconds=2.0,
        )
        authority = EtcdSignedReplayService(
            EtcdV3TransactionTransport(config),
            expected_cluster_id=self.pinned_or_discover(endpoint),
            namespace="seven." + uuid.uuid4().hex,
            service_id=SID,
            epoch=1,
            signing_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
            clients={p.key_id: p for p in policies.values()},
            bootstrap=True,
        )
        return authority, ReplayHttpServer(authority)

    @staticmethod
    def pinned_or_discover(endpoint):
        return os.environ.get("EHH_ETCD_CLUSTER_ID") or cluster_id(endpoint)

    def test_signed_capability_nonce_and_authorization_under_real_quorum(self):
        service, client, config, params = provision()
        now = int(time.time() * 1000)
        expiry = now + 60_000
        nonce = "A" * 43
        cap = "cap_0123456789abcdef01234567"
        context = {
            "deviceId": "dev", "executorId": "exec",
            "purpose": "attestation", "sessionId": "session",
        }
        self.assertTrue(client.call("nonce-create", "nonces", {
            "nonce": nonce, "context": context,
            "context_digest": digest(context),
            "issued_at": now, "expires_at": expiry,
        })["accepted"])
        self.assertTrue(client.call("nonce-consume", "nonces", {
            "nonce": nonce, "context_digest": digest(context), "now": now,
        })["accepted"])
        self.assertFalse(client.call("nonce-consume", "nonces", {
            "nonce": nonce, "context_digest": digest(context), "now": now,
        })["accepted"])
        auth = RemoteAuthorizationReplayStore(client, partition="authorizations")
        self.assertTrue(auth.consume("A" * 43, "b" * 64, expiry, now))
        self.assertFalse(auth.consume("A" * 43, "b" * 64, expiry, now))
        # Real transport and second independently initialized replica use
        # one global ordering and token keyspace.
        replica = EtcdSignedReplayService.connect(config, **params, bootstrap=False)
        def redeem(i):
            each_client = AuthenticatedReplayClient(
                client.signer, service.handle if i % 2 else replica.handle,
                service.public_key_pem, epoch=1,
            )
            return RemoteCapabilityConsumptionStore(
                each_client, partition="capabilities",
            ).consume(cap, "a"*64, 5000, 1000)
        with ThreadPoolExecutor(max_workers=8) as pool:
            attempts = list(pool.map(redeem, range(16)))
        self.assertEqual(attempts.count(True), 1, attempts)
        self.assertEqual(attempts.count(False), 15, attempts)
        self.assertEqual(service.checkpoint(), replica.checkpoint())
        self.assertEqual(service.checkpoint()[1], 4)
        self.assertFalse(
            RemoteCapabilityConsumptionStore(client, partition="capabilities")
            .consume(cap, "a"*64, 5000, 1001)
        )


if __name__ == "__main__":
    unittest.main()
