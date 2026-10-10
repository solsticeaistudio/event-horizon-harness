"""Rootless operator-launcher checks; never run Docker, sudo or KVM in CI."""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run_package_etcd_lab.sh"


class PackageEtcdOperatorScriptTests(unittest.TestCase):
    def test_bash_parser_and_bad_argument_fail_before_side_effects(self):
        syntax = subprocess.run(
            ["bash", "-n", str(SCRIPT)], capture_output=True, text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        for args in (
            ("--adaptive-steps", "0"),
            ("--adaptive-steps", "5"),
            ("--adaptive-steps", "banana"),
            ("--unsupported", "1"),
            ("--adaptive-steps",),
            ("--adaptive-steps", "1", "--extra"),
        ):
            with self.subTest(args=args):
                process = subprocess.run(
                    ["bash", str(SCRIPT), *args], capture_output=True, text=True,
                    timeout=5,
                )
                self.assertEqual(process.returncode, 2, process.stderr)

    def test_launcher_is_scoped_to_owned_disposable_loopback_cluster(self):
        source = SCRIPT.read_text()
        self.assertIn("127.0.0.1:2379", source)
        self.assertIn("127.0.0.1:3379", source)
        self.assertIn("127.0.0.1:4379", source)
        self.assertIn("cluster_id", source)
        self.assertIn("docker network create", source)
        self.assertIn('docker rm -f "$id"', source)
        self.assertIn('for id in "${CONTAINERS[@]}"', source)
        self.assertIn('docker network rm "$NETWORK"', source)
        self.assertIn("sha256sum -c", source)
        self.assertIn("scripts/verify_package_isolation.py", source)
        self.assertIn("scripts/run_package_isolation.py", source)
        self.assertIn('trap cleanup EXIT', source)
        self.assertNotIn("docker system prune", source)
        self.assertNotIn("docker rm -f $(docker ps", source)


if __name__ == "__main__":
    unittest.main()
