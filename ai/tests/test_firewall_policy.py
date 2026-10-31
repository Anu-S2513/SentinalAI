"""Safety checks for automatic firewall blocking policy."""

import os
import sys
import unittest
from unittest.mock import patch


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from ai.firewall.adaptive_firewall import get_firewall_action, reset_source_history
from ai.firewall.firewall_policy import ALLOWLIST_ENV, THRESHOLD_ENV
from ai.firewall.firewall_enforcer import block_ip, remove_block


class FirewallPolicyTests(unittest.TestCase):
    def tearDown(self):
        reset_source_history("192.0.2.123")
        reset_source_history("192.168.1.10")

    def test_trusted_network_is_monitored_but_never_auto_blocked(self):
        with patch.dict(os.environ, {ALLOWLIST_ENV: "192.168.1.0/24"}):
            self.assertEqual(
                get_firewall_action("ATTACK", 0.99, "192.168.1.10"),
                "MONITOR"
            )

    def test_configured_threshold_controls_immediate_block(self):
        with patch.dict(os.environ, {THRESHOLD_ENV: "0.90"}):
            self.assertEqual(
                get_firewall_action("ATTACK", 0.89, "192.0.2.123"),
                "MONITOR"
            )
            reset_source_history("192.0.2.123")
            self.assertEqual(
                get_firewall_action("ATTACK", 0.90, "192.0.2.123"),
                "BLOCK"
            )

    def test_invalid_threshold_disables_all_automatic_blocks(self):
        with patch.dict(os.environ, {THRESHOLD_ENV: "not-a-number"}):
            decisions = [
                get_firewall_action("ATTACK", 0.45, "192.0.2.123")
                for _ in range(4)
            ]
        self.assertEqual(decisions, ["MONITOR"] * 4)

    def test_invalid_or_loopback_source_cannot_be_auto_blocked(self):
        self.assertEqual(
            get_firewall_action("ATTACK", 1.0, "127.0.0.1"),
            "MONITOR"
        )
        self.assertEqual(
            get_firewall_action("ATTACK", 1.0, "not-an-ip"),
            "MONITOR"
        )

    def test_allowlisted_ip_never_reaches_firewall_add_command(self):
        with patch.dict(os.environ, {ALLOWLIST_ENV: "192.168.1.0/24"}), \
             patch("ai.firewall.firewall_enforcer.platform.system", return_value="Windows"), \
             patch("ai.firewall.firewall_enforcer.subprocess.run") as run_command:
            result = block_ip("192.168.1.10")
        self.assertEqual(result["status"], "FAILED")
        self.assertIn("protected", result["message"].lower())
        run_command.assert_not_called()

    def test_allowlisting_does_not_prevent_rule_cleanup(self):
        completed = type("Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()
        with patch.dict(os.environ, {ALLOWLIST_ENV: "192.168.1.0/24"}), \
             patch("ai.firewall.firewall_enforcer.platform.system", return_value="Windows"), \
             patch("ai.firewall.firewall_enforcer.subprocess.run", return_value=completed) as run_command:
            result = remove_block("192.168.1.10")
        self.assertEqual(result["status"], "UNBLOCKED")
        run_command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
