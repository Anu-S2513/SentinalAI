"""Repeatable checks for the adaptive firewall thresholds and history."""

import os
import sys
import unittest
from unittest.mock import patch


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)
sys.path.insert(0, PROJECT_ROOT)

from ai.firewall.adaptive_firewall import (
    get_firewall_action,
    reset_source_history
)


class AdaptiveFirewallTests(unittest.TestCase):
    def setUp(self):
        self.source_ip = "192.0.2.123"
        reset_source_history(self.source_ip)

    def tearDown(self):
        reset_source_history(self.source_ip)

    def test_three_suspicious_readings_block(self):
        decisions = [
            get_firewall_action("ATTACK", 0.45, self.source_ip)
            for _ in range(3)
        ]
        self.assertEqual(decisions, ["MONITOR", "MONITOR", "BLOCK"])

    def test_normal_reading_resets_suspicion(self):
        get_firewall_action("ATTACK", 0.45, self.source_ip)
        get_firewall_action("ATTACK", 0.45, self.source_ip)
        self.assertEqual(
            get_firewall_action("NORMAL", 0.10, self.source_ip),
            "ALLOW"
        )
        self.assertEqual(
            get_firewall_action("ATTACK", 0.45, self.source_ip),
            "MONITOR"
        )

    def test_old_suspicion_expires_after_the_window(self):
        with patch(
            "ai.firewall.adaptive_firewall.time.monotonic",
            side_effect=[100, 101, 102, 170]
        ):
            decisions = [
                get_firewall_action("ATTACK", 0.45, self.source_ip)
                for _ in range(4)
            ]
        self.assertEqual(decisions, ["MONITOR", "MONITOR", "BLOCK", "MONITOR"])

    def test_high_risk_attack_blocks_immediately(self):
        self.assertEqual(
            get_firewall_action("ATTACK", 0.70, self.source_ip),
            "BLOCK"
        )


if __name__ == "__main__":
    unittest.main()
