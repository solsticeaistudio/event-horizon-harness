from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from event_horizon.remote_replay import ReplayRequestSigner
from scripts.serve_etcd_signed_replay import configure


class TrustedSignedEtcdServeConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.seed = self.root / "signing.seed"
        self.seed.write_bytes(bytes(range(32)))
        if os.name != "nt":
            self.seed.chmod(0o600)
        client = ReplayRequestSigner(bytes(range(32, 64)), "signed-remote-etcd")
        self.config = {
            "etcd": {
                "endpoint": "http://127.0.0.1:2379",
                "allow_insecure_loopback": True,
            },
            "cluster_id": "139003440588",
            "namespace": "test",
            "service_id": "signed-remote-etcd",
            "epoch": 1,
            "signing_seed_path": str(self.seed),
            "client_policies": [{
                "public_key_pem": client.public_key_pem,
                "operations": ["capability-consume"],
                "partitions": ["broker"],
            }],
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "server_tls": None,
        }
        self.path = self.root / "config.json"

    def write_config(self):
        self.path.write_text(json.dumps(self.config), encoding="utf-8")

    def test_valid_local_setup_uses_explicit_signed_etcd_authority(self):
        self.write_config()
        with patch("scripts.serve_etcd_signed_replay.EtcdSignedReplayService.connect") as make:
            make.return_value.handle = Mock()
            service, http = configure(self.path, bootstrap=True)
            try:
                self.assertEqual(service, make.return_value)
                self.assertEqual(make.call_args.kwargs["bootstrap"], True)
                self.assertEqual(make.call_args.kwargs["expected_cluster_id"], "139003440588")
                self.assertEqual(len(make.call_args.kwargs["clients"]), 1)
                self.assertTrue(http.url.startswith("http://127.0.0.1:"))
            finally:
                http.close()

    def test_remote_plaintext_listener_cannot_start(self):
        self.config["listen_host"] = "0.0.0.0"
        self.write_config()
        with patch("scripts.serve_etcd_signed_replay.EtcdSignedReplayService.connect") as make:
            with self.assertRaisesRegex(ValueError, "mTLS"):
                configure(self.path)
            make.assert_not_called()

    def test_restricted_private_signing_seed_enforced(self):
        if os.name == "nt":
            self.skipTest("POSIX permission check")
        self.seed.chmod(0o644)
        self.write_config()
        with self.assertRaisesRegex(RuntimeError, "permissions"):
            configure(self.path)

    def test_reject_duplicate_identity_and_unknown_config_field(self):
        self.config["client_policies"].append(self.config["client_policies"][0])
        self.write_config()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            configure(self.path)
        self.config["client_policies"].pop()
        self.config["pass_through_secret"] = "not-allowed"
        self.write_config()
        with self.assertRaisesRegex(ValueError, "fields"):
            configure(self.path)


if __name__ == "__main__":
    unittest.main()
