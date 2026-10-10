"""Check the pinned Firecracker lab inputs remain versioned and reproducible."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FirecrackerAssetLockTests(unittest.TestCase):
    def test_lock_is_present_matches_recorded_experiment(self):
        lock = json.loads((ROOT / "firecracker/linux-kvm.lock.json").read_text())
        historical = json.loads(
            (ROOT / "firecracker/fixtures/wsl2-nested-kvm-run.json").read_text()
        )
        self.assertEqual(lock["firecracker_version"], "1.15.1")
        self.assertEqual(lock["firecracker_version"], historical["environment"]["firecracker_version"])
        self.assertEqual(
            lock["archive_sha256"],
            historical["supply_chain"]["firecracker_release_sha256"],
        )
        self.assertEqual(lock["kernel_sha256"], historical["evidence"]["kernel_sha256"])
        self.assertRegex(lock["archive_sha256"], r"^[a-f0-9]{64}$")
        self.assertRegex(lock["kernel_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            lock["archive_url"],
            "https://github.com/firecracker-microvm/firecracker/releases/download/"
            "v1.15.1/firecracker-v1.15.1-x86_64.tgz",
        )
        self.assertEqual(
            lock["kernel_url"],
            "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/"
            "v1.15/x86_64/vmlinux-6.1.155",
        )

    def test_lock_is_not_excluded_from_source_control(self):
        lines = (ROOT / ".gitignore").read_text().splitlines()
        self.assertNotIn("firecracker/linux-kvm.lock.json", lines)
        self.assertTrue((ROOT / "firecracker/linux-kvm.lock.json").is_file())


if __name__ == "__main__":
    unittest.main()
