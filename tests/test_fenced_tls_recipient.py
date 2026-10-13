"""Portable two-process mTLS recipient tests, NOT multi-host evidence."""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
import secrets
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.canonical import digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient import FencedRecipientError, FencedSqliteRecipient
from event_horizon.fenced_recipient_tls import (
    FencedTlsRecipientClient, serve_fenced_tls_recipient,
)
from event_horizon.models import ActionRequest
from event_horizon.recorder import ExternalRecorder
from event_horizon.trusted_effect_gateway import select_consumption_store
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


def certs(directory: Path):
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EHH CA")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, algorithm=None))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {"ca": str(directory / "ca.pem")}
    for name, san in (("server", "recipient.lab.test"),
                      ("client", None), ("other", None)):
        key = ed25519.Ed25519PrivateKey.generate()
        common = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        b = (x509.CertificateBuilder()
             .subject_name(common).issuer_name(ca_name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(minutes=5))
             .not_valid_after(now + dt.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                            critical=True))
        if san is not None:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),
                                critical=False)
        leaf = b.sign(ca_key, algorithm=None)
        keypath, certpath = directory / (name + ".key"), directory / (name + ".pem")
        keypath.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        keypath.chmod(0o600)
        certpath.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        result[name] = {"cert": str(certpath), "key": str(keypath),
                        "pin": hashlib.sha256(
                            leaf.public_bytes(serialization.Encoding.DER)
                        ).hexdigest()}
    return result


class RemoteRecipientTlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ehh-remote-mtls-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.material = certs(self.root)
        self.db = self.root / "recipient.sqlite"
        self.journal = DurableEffectJournal(self.root / "journal.sqlite")
        self.store = select_consumption_store(
            backend="sqlite", namespace="remote-case", domain="external-effect",
            sqlite_path=str(self.root / "replay.sqlite"),
        )
        self.addCleanup(self.store.close)
        self.key = secrets.token_bytes(32)
        self.recipient_id = "ehh-remote-fixture"
        self.request = ActionRequest(
            "remote-effect", "remote-session", "agent", "object.read",
            "synthetic-data", "exec-1", {"offset": 0, "length": 5}, "trusted test",
        )
        self.context = authority_context(
            self.request, time.time(), max_output_bytes=512,
        )
        self.broker = CapabilityBroker(ttl_seconds=120)
        self.drop = False
        self.stop = threading.Event()
        self._start()

    def _start(self):
        from queue import Queue
        ready = Queue(maxsize=1)
        fail = Queue(maxsize=1)

        def checkpoint(phase):
            if phase == "after_commit_before_reply" and self.drop:
                self.drop = False
                return True
            return False

        def run():
            try:
                serve_fenced_tls_recipient(
                    host="127.0.0.1", port=0, database=self.db,
                    recipient_id=self.recipient_id, auth_key=self.key,
                    ca_file=self.material["ca"],
                    server_cert_file=self.material["server"]["cert"],
                    server_key_file=self.material["server"]["key"],
                    client_cert_sha256=self.material["client"]["pin"],
                    ready=lambda port: ready.put(port), stop=self.stop,
                    checkpoint=checkpoint,
                )
            except BaseException as exc:
                fail.put(exc)
                ready.put(None)

        self.server = threading.Thread(target=run, daemon=True)
        self.server.start()
        self.port = ready.get(timeout=6)
        if self.port is None:
            self.fail(str(fail.get_nowait()))
        self.addCleanup(self._stop)
        self.client = self._client()

    def _stop(self):
        self.stop.set()
        self.server.join(timeout=5)
        self.assertFalse(self.server.is_alive(), "remote TLS server not reaped")

    def _client(self, **kwargs):
        args = dict(
            host="127.0.0.1", port=self.port,
            server_name="recipient.lab.test", ca_file=self.material["ca"],
            client_cert_file=self.material["client"]["cert"],
            client_key_file=self.material["client"]["key"],
            server_cert_sha256=self.material["server"]["pin"],
            recipient_id=self.recipient_id, auth_key=self.key, timeout=2,
        )
        args.update(kwargs)
        return FencedTlsRecipientClient(**args)

    def _ledger(self):
        return FencedSqliteRecipient(self.db, recipient_id=self.recipient_id)

    def _gate(self, token):
        v = verify_options(self.context)
        gateway = FencedEffectRecoveryGateway(
            CapabilityVerifier(
                self.broker.public_key_pem, self.broker.key_id, self.store
            ),
            ExternalRecorder(self.root / (
                "rec-" + token.claims.capability_id + ".jsonl"
            )),
            self.journal, self.client,
            output_factory=lambda _: "owned-value",
        )
        return gateway.execute(
            self.request, token, v["attestation"],
            executor_measurement=v["executor_measurement"],
            device_id=v["device_id"],
            verifier_policy_digest=v["verifier_policy_digest"],
            policy_digest=v["policy_digest"],
        )

    def _token(self):
        return self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )

    def test_remote_mtls_effect_and_original_receipt(self):
        key = digest("remote-effect-key")
        req = digest("remote-request")
        first = self.client.apply(
            effect_key=key, request_digest=req, output="owned-value",
        )
        again = self.client.apply(
            effect_key=key, request_digest=req, output="owned-value",
        )
        self.assertTrue(first.newly_committed)
        self.assertFalse(again.newly_committed)
        self.assertEqual(first.receipt_digest, again.receipt_digest)
        self.assertEqual(self.client.observe(
            effect_key=key, request_digest=req,
        ).receipt_digest, first.receipt_digest)
        self.assertEqual(self._ledger().commit_count(), 1)

    def test_wrong_client_identity_and_server_pin_fail_closed(self):
        other = self._client(
            client_cert_file=self.material["other"]["cert"],
            client_key_file=self.material["other"]["key"],
        )
        with self.assertRaises(FencedRecipientError):
            other.observe(effect_key=digest("key"), request_digest=digest("req"))
        badpin = self._client(server_cert_sha256="f" * 64)
        with self.assertRaises(FencedRecipientError):
            badpin.observe(effect_key=digest("key"), request_digest=digest("req"))
        wrong_hostname = self._client(server_name="not-our-server.invalid")
        with self.assertRaises(FencedRecipientError):
            wrong_hostname.observe(effect_key=digest("key"), request_digest=digest("req"))
        self.assertEqual(self._ledger().commit_count(), 0)

    def test_invalid_key_wrong_result_denied(self):
        key, req = digest("key"), digest("req")
        self.client.apply(effect_key=key, request_digest=req, output="owned-value")
        with self.assertRaises(FencedRecipientError):
            self.client.apply(effect_key=key, request_digest=req, output="changed")
        with self.assertRaises(FencedRecipientError):
            self._client(auth_key=secrets.token_bytes(32)).observe(
                effect_key=key, request_digest=req,
            )
        self.assertEqual(self._ledger().commit_count(), 1)

    def test_lost_tls_ack_preserves_durable_reservation_with_fresh_signer(self):
        self.drop = True
        original = self._token()
        first = self._gate(original)
        self.assertFalse(first.accepted)
        self.assertEqual(first.error_class, "recipient-indeterminate")
        self.assertEqual(first.effect_state, "possibly-committed")
        self.assertEqual(self._ledger().commit_count(), 1)
        key = digest({"session_id": self.request.session_id,
                      "request_id": self.request.request_id})
        binding = self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=key,
        )
        self.assertEqual(binding["state"], "possibly-committed")
        self.assertEqual(binding["capability_id"], original.claims.capability_id)
        self.assertEqual(self._gate(original).error_class, "authority-denied")
        confirmed = self._gate(self._token())
        self.assertTrue(confirmed.accepted, confirmed.error_class)
        self.assertEqual(self._ledger().commit_count(), 1)
        self.assertEqual(self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=key,
        )["capability_id"], original.claims.capability_id)

    def test_partition_returns_indeterminate_not_fabricated_rollback(self):
        self._stop()
        original = self._token()
        result = self._gate(original)
        self.assertFalse(result.accepted)
        self.assertEqual(result.error_class, "recipient-indeterminate")
        self.assertEqual(result.effect_state, "possibly-committed")
        self.assertEqual(self._gate(original).error_class, "authority-denied")
        self.assertEqual(self._ledger().commit_count(), 0)
        self.stop = threading.Event()
        self._start()
        recovered = self._gate(self._token())
        self.assertTrue(recovered.accepted, recovered.error_class)
        self.assertEqual(self._ledger().commit_count(), 1)


if __name__ == "__main__":
    unittest.main()
