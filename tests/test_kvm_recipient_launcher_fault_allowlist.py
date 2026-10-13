"""Regression: real KVM recipient launcher accepts private ACK-loss checkpoints.

Portable tests mock the recipient launcher, so they missed a stale allowlist in
the actual Firecracker path. This ensures both crash and transport fault names
are accepted by the very method that launches the independently supervised
recipient, and unknown/guest-supplied names fail before spawning anything.
"""
from __future__ import annotations

import io
from pathlib import Path
import threading
import unittest
from unittest import mock

from scripts.fenced_recipient_service import PHASES, TRANSPORT_FAULTS
from scripts.kvm_fenced_recipient_bridge import FencedRecipientKvmReceiver


class FencedKvmRecipientLaunchFaultTests(unittest.TestCase):
    def receiver(self):
        receiver = object.__new__(FencedRecipientKvmReceiver)
        receiver._recipient_config_path = Path("/private-owned-lab/config.json")
        receiver._recipient_runtime = Path("/private-owned-lab/stage")
        receiver.recipient_process = None
        receiver.recipient_pid = None
        receiver.recipient_ready = threading.Event()
        return receiver

    def test_all_host_owned_faults_reach_exact_recipient_launcher(self):
        for phase in (*PHASES, *TRANSPORT_FAULTS):
            with self.subTest(phase=phase):
                receiver = self.receiver()
                child = mock.Mock()
                child.pid = 45231
                child.stdout = io.BytesIO(b"READY\n")
                child.poll.return_value = None
                with (
                    mock.patch("scripts.kvm_fenced_recipient_bridge.subprocess.Popen",
                               return_value=child) as start,
                    mock.patch("scripts.kvm_fenced_recipient_bridge.select.select",
                               return_value=([child.stdout], [], [])),
                ):
                    self.assertIs(receiver._launch_recipient(fault_phase=phase), child)
                command = start.call_args.args[0]
                self.assertEqual(command[-2:], ["--lab-fault", phase])
                self.assertEqual(command[:3], ["unshare", "--net", "--"])
                self.assertEqual(receiver.recipient_pid, child.pid)
                self.assertTrue(receiver.recipient_ready.is_set())

    def test_unrecognized_fault_refused_without_spawning_process(self):
        for phase in ("arbitrary-guest-input", "drop_ack_after_commit; echo bad", ""):
            with self.subTest(phase=phase):
                receiver = self.receiver()
                with mock.patch(
                    "scripts.kvm_fenced_recipient_bridge.subprocess.Popen"
                ) as spawn:
                    with self.assertRaises(ValueError):
                        receiver._launch_recipient(fault_phase=phase)
                    spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
