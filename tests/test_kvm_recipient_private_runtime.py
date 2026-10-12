"""The no-capability recipient must not import from the operator's home."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from scripts.integrated_gateway_process_bridge import (
    _RECIPIENT_MODULES, stage_private_recipient_runtime,
)


class PrivateRecipientRuntimeTests(unittest.TestCase):
    def test_exact_trusted_module_allowlist_staged_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = stage_private_recipient_runtime(root)
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o700)
            found = {str(file.relative_to(runtime))
                     for file in runtime.rglob("*") if file.is_file()}
            self.assertEqual(found, set(_RECIPIENT_MODULES.values()))
            for path in runtime.rglob("*"):
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)

    def test_imports_from_private_runtime_with_host_pythonpath_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = stage_private_recipient_runtime(Path(temp))
            script = (
                "import scripts.kvm_effect_recipient_service as entry;"
                "import scripts.effect_crash_recipient as recipient;"
                "import event_horizon.canonical as canonical;"
                "print(entry.__file__);print(recipient.__file__);"
                "print(canonical.__file__)"
            )
            environment = {**os.environ, "PYTHONPATH": "/nonexistent-host-path"}
            result = subprocess.run(
                [sys.executable, "-E", "-B", "-c", script],
                cwd=runtime, env=environment,
                text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in result.stdout.splitlines():
                self.assertTrue(Path(path).resolve().is_relative_to(runtime.resolve()),
                                f"module resolved outside private runtime: {path}")


if __name__ == "__main__":
    unittest.main()
