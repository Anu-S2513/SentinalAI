"""Check prediction totals and block lifecycle counts independently."""

import os
import sys
import unittest


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)
sys.path.insert(0, PROJECT_ROOT)

from ai.api.app import summarize_predictions


class DashboardStatsTests(unittest.TestCase):
    def test_recovered_rule_is_not_counted_as_active(self):
        rows = [
            {
                "timestamp": "2026-10-31 10:00:00",
                "source_ip": "192.0.2.10",
                "prediction": "ATTACK",
                "attack_probability": 0.99,
                "firewall_action": "BLOCK",
                "enforcement_status": "BLOCKED"
            },
            {
                "timestamp": "2026-10-31 10:00:03",
                "source_ip": "192.0.2.10",
                "prediction": "SYSTEM",
                "attack_probability": 0,
                "firewall_action": "UNBLOCK",
                "enforcement_status": "UNBLOCKED"
            }
        ]

        stats = summarize_predictions(rows)
        self.assertEqual(stats["total_predictions"], 1)
        self.assertEqual(stats["block_attempts"], 1)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["active_blocks"], 0)
        self.assertEqual(stats["recovered_blocks"], 1)

    def test_failed_block_is_not_counted_as_successful_or_active(self):
        rows = [{
            "timestamp": "2026-10-31 10:00:00",
            "source_ip": "192.0.2.20",
            "prediction": "ATTACK",
            "attack_probability": 0.95,
            "firewall_action": "BLOCK",
            "enforcement_status": "FAILED"
        }]

        stats = summarize_predictions(rows)
        self.assertEqual(stats["block_attempts"], 1)
        self.assertEqual(stats["blocked"], 0)
        self.assertEqual(stats["active_blocks"], 0)
        self.assertEqual(stats["failed_blocks"], 1)

    def test_current_successful_block_is_active(self):
        rows = [{
            "timestamp": "2026-10-31 10:00:00",
            "source_ip": "192.0.2.30",
            "prediction": "ATTACK",
            "attack_probability": 1.0,
            "firewall_action": "BLOCK",
            "enforcement_status": "BLOCKED"
        }]

        stats = summarize_predictions(rows)
        self.assertEqual(stats["active_blocks"], 1)
        self.assertEqual(stats["recovered_blocks"], 0)

    def test_failed_recovery_is_unknown_and_not_claimed_active(self):
        rows = [
            {
                "timestamp": "2026-10-31 10:00:00",
                "source_ip": "192.0.2.40",
                "prediction": "ATTACK",
                "attack_probability": 1.0,
                "firewall_action": "BLOCK",
                "enforcement_status": "BLOCKED"
            },
            {
                "timestamp": "2026-10-31 10:01:00",
                "source_ip": "192.0.2.40",
                "prediction": "SYSTEM",
                "firewall_action": "RECOVERY_FAILED",
                "enforcement_status": "FAILED"
            }
        ]
        stats = summarize_predictions(rows)
        self.assertEqual(stats["active_blocks"], 0)
        self.assertEqual(stats["recovery_failures"], 1)


if __name__ == "__main__":
    unittest.main()
