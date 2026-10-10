"""Build guard for the minimal KVM/Firecracker guest init binary.

The ordinary CI suite must exercise the *same strict GCC flags* used by
scripts/prepare_linux_isolation.py. This prevents a source-only syntax
regression from reaching a KVM-capable user's fresh Ubuntu checkout again.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FirecrackerGuestBuildTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux" and platform.machine() == "x86_64"
        and shutil.which("gcc"),
        "requires Linux x86_64 with GCC",
    )
    def test_default_guest_builds_static_with_warnings_as_errors(self):
        guest_source = ROOT / "firecracker/guest/guest_agent.c"
        with tempfile.TemporaryDirectory(prefix="eh-firecracker-guest-build-") as tmp:
            binary = Path(tmp) / "init"
            args = [
                "gcc", "-static", "-Os", "-s", "-Wall", "-Wextra", "-Werror",
                "-Wl,--build-id=none", "-frandom-seed=event-horizon-guest-v1",
                '-DEH_SCRATCH_DEVICE="/dev/vda"', "-UEH_HAS_TPM2",
                "-o", str(binary), str(guest_source),
            ]
            subprocess.run(args, check=True, capture_output=True, text=True)
            self.assertTrue(binary.exists())
            self.assertGreater(binary.stat().st_size, 0)
            self.assertEqual(binary.read_bytes()[:4], b"\\x7fELF")


if __name__ == "__main__":
    unittest.main()
