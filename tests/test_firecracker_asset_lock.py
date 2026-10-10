"""Check the pinned Firecracker lab inputs remain versioned and reproducible."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
        # These are the extracted executable hashes from the pinned release,
        # as recorded in the successful Ubuntu x86_64 builder manifest.
        self.assertEqual(
            lock["firecracker_sha256"],
            "7e8b57e88c459396d4680d83dcdd8c7f72305447cb55b11f4ac98ad70a3f7825",
        )
        self.assertEqual(
            lock["jailer_sha256"],
            "4830a9b1fc6cece036d8992ff12f1fe9c5247aacad77f42c7aba683c7a08622e",
        )
        self.assertRegex(lock["firecracker_sha256"], r"^[a-f0-9]{64}$")
        self.assertRegex(lock["jailer_sha256"], r"^[a-f0-9]{64}$")
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

    def test_preparer_manifest_matches_launcher_binary_contract(self):
        from scripts.run_linux_isolation import checked_assets

        lock = json.loads((ROOT / "firecracker/linux-kvm.lock.json").read_text())
        binary_names = ("firecracker", "jailer", "vmlinux", "initramfs.cpio.gz")
        artifacts = {
            "firecracker": lock["firecracker_sha256"],
            "jailer": lock["jailer_sha256"],
            "vmlinux": lock["kernel_sha256"],
            "initramfs.cpio.gz": "a" * 64,
        }
        source_sha = hashlib.sha256(
            (ROOT / "firecracker/guest/guest_agent.c").read_bytes()
        ).hexdigest()
        manifest = {
            "asset_lock": lock,
            "artifacts": artifacts,
            "guest_source_sha256": source_sha,
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in binary_names:
                (directory / name).write_bytes(b"synthetic-test-artifact")
            (directory / "manifest.json").write_text(json.dumps(manifest))
            observed = {**artifacts, "guest_agent.c": source_sha}
            with patch(
                "scripts.run_linux_isolation.sha256_file",
                side_effect=lambda path: observed[Path(path).name],
            ):
                self.assertEqual(checked_assets(directory), manifest)
                corrupted = json.loads(json.dumps(manifest))
                corrupted["artifacts"]["firecracker"] = "b" * 64
                observed["firecracker"] = "b" * 64
                (directory / "manifest.json").write_text(json.dumps(corrupted))
                with self.assertRaisesRegex(ValueError, "firecracker is not pinned"):
                    checked_assets(directory)

    def test_lock_is_not_excluded_from_source_control(self):
        lines = (ROOT / ".gitignore").read_text().splitlines()
        self.assertNotIn("firecracker/linux-kvm.lock.json", lines)
        self.assertTrue((ROOT / "firecracker/linux-kvm.lock.json").is_file())


if __name__ == "__main__":
    unittest.main()
