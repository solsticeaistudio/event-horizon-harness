"""Real host-gateway attack campaign tests; Linux unprivileged/no Docker."""
from __future__ import annotations

import os
import socket
import unittest

from scripts.run_gateway_socket_campaign import (
    SCENARIOS, run_campaign, run_scenario,
)


@unittest.skipUnless(
    os.name == "posix" and hasattr(socket, "SO_PEERCRED"),
    "requires Linux peer-credential Unix sockets",
)
class SocketCampaignTests(unittest.TestCase):
    def test_actual_trusted_service_attack_campaign(self):
        report = run_campaign()
        self.assertEqual(report["schema"], "event-horizon.gateway-socket-campaign.v1")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual({item["scenario"] for item in report["cases"]}, set(SCENARIOS))
        for result in report["cases"]:
            with self.subTest(scenario=result["scenario"]):
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["source"], "real-unprivileged-linux-effect-service-unix-process")
                self.assertIn(result["effect_count"], (0, 1))
                self.assertLessEqual(result["replay_consumptions"], 1)

        details = {item["scenario"]: item for item in report["cases"]}
        self.assertEqual(details["positive_and_replay"]["effect_count"], 1)
        self.assertEqual(details["recorder_refuses_authorization"]["effect_count"], 0)
        self.assertEqual(details["recorder_refuses_authorization"]["replay_consumptions"], 1)
        for name in ("incorrect_unix_peer", "duplicate_json_key",
                     "oversized_header", "truncated_payload"):
            self.assertEqual(details[name]["replay_consumptions"], 0)
            self.assertEqual(details[name]["effect_count"], 0)

    def test_unapproved_target_is_rejected_before_process_spawn(self):
        with self.assertRaises(ValueError):
            run_scenario("production-aws-adapter")


if __name__ == "__main__":
    unittest.main()
