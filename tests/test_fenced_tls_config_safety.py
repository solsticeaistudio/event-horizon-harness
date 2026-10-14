"""Privileged remote TLS config must fail closed on mutable paths/inputs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.serve_fenced_tls_recipient import load_private_config

EXPECTED = {"auth_key_hex", "recipient_id"}


class RemoteTlsConfigSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ehh-remote-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.config = self.private / "recipient.json"
        self.good = {"auth_key_hex": "a" * 64, "recipient_id": "owned-fixture"}
        self.write()

    def write(self, body=None):
        self.config.write_text(json.dumps(
            self.good if body is None else body, sort_keys=True
        ))
        self.config.chmod(0o600)

    def test_private_regular_file_is_read(self):
        self.assertEqual(load_private_config(self.config, EXPECTED), self.good)

    def test_reject_leaf_symlink(self):
        original = self.private / "original.json"
        self.config.rename(original)
        self.config.symlink_to(original)
        with self.assertRaises((OSError, ValueError)):
            load_private_config(self.config, EXPECTED)

    def test_reject_symlink_ancestor(self):
        alias = self.root / "alias"
        alias.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            load_private_config(alias / "recipient.json", EXPECTED)

    def test_reject_writable_ancestor(self):
        self.private.chmod(0o777)
        with self.assertRaises((OSError, ValueError)):
            load_private_config(self.config, EXPECTED)

    def test_reject_group_readable_file(self):
        self.config.chmod(0o640)
        with self.assertRaises((OSError, ValueError)):
            load_private_config(self.config, EXPECTED)

    def test_reject_large_config(self):
        self.config.write_bytes(b" " * 65537)
        with self.assertRaises(ValueError):
            load_private_config(self.config, EXPECTED)

    def test_reject_nonhex_auth_key(self):
        self.write({"auth_key_hex": "g" * 64, "recipient_id": "owned-fixture"})
        with self.assertRaises(ValueError):
            load_private_config(self.config, EXPECTED)

    def test_reject_unrecognized_fields(self):
        self.write(self.good | {"unsafe_override": True})
        with self.assertRaises(ValueError):
            load_private_config(self.config, EXPECTED)


if __name__ == "__main__":
    unittest.main()
