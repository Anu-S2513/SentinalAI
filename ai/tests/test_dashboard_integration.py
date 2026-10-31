"""Check prediction-log data through the API and dashboard presentation layer."""

import csv
import builtins
import io
import json
import os
import sys
import unittest
from unittest.mock import patch


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, PROJECT_ROOT)

from ai.api import app as api_module
from ai.logs.prediction_logger import FIELDNAMES


class DashboardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.prediction_file = "__sentinelai_in_memory_predictions__.csv"
        self.csv_text = ""
        self.rows = []
        self.original_isfile = os.path.isfile
        self.original_open = builtins.open
        self.patches = [
            patch.object(api_module, "PREDICTIONS_FILE", self.prediction_file),
            patch.object(api_module, "is_current_session", lambda *_: True),
            patch.object(api_module, "get_capture_status", lambda: {"status": "UNKNOWN", "age_seconds": None}),
            patch("ai.api.app.os.path.isfile", side_effect=self.mock_isfile),
            patch("builtins.open", side_effect=self.mock_open)
        ]
        for active_patch in self.patches:
            active_patch.start()

    def tearDown(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()

    def mock_isfile(self, path):
        if str(path) == self.prediction_file:
            return bool(self.csv_text)
        return self.original_isfile(path)

    def mock_open(self, path, *args, **kwargs):
        if str(path) == self.prediction_file:
            return io.StringIO(self.csv_text)
        return self.original_open(path, *args, **kwargs)

    def write_rows(self):
        file = io.StringIO()
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(self.rows)
        self.csv_text = file.getvalue()

    @staticmethod
    def row(timestamp, source_ip, prediction, action, status, details=None):
        explanation = {
            "top_attack_influences": [],
            "_enforcement": {"status": status, "message": status},
            "_event_details": details or {}
        }
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": "DATASET_SAMPLE",
            "source_port": "0",
            "destination_port": "0",
            "protocol": "TEST",
            "prediction": prediction,
            "attack_probability": "0.99" if prediction == "ATTACK" else "0",
            "firewall_action": action,
            "explanation": json.dumps(explanation),
            "enforcement_status": status,
            "enforcement_message": status,
            "firewall_rule": "SentinelAI-Block-192.0.2.123"
        }

    def test_dashboard_reports_block_schedule_and_recovery(self):
        source = "192.0.2.123"
        self.rows = [
            self.row("2026-10-31 12:00:00", source, "ATTACK", "BLOCK", "BLOCKED"),
            self.row(
                "2026-10-31 12:00:01", source, "SYSTEM",
                "RECOVERY_SCHEDULED", "SCHEDULED",
                {"due_at": "2026-10-31T12:01:00", "duration_seconds": 60}
            )
        ]
        self.write_rows()

        active = api_module.get_predictions()["predictions"][0]
        active_stats = api_module.get_stats()
        self.assertEqual(active["current_block_state"], "ACTIVE")
        self.assertEqual(active["current_recovery_state"], "SCHEDULED")
        self.assertEqual(active_stats["active_blocks"], 1)

        self.rows.append(
            self.row("2026-10-31 12:01:00", source, "SYSTEM", "UNBLOCK", "UNBLOCKED")
        )
        self.write_rows()
        recovered = api_module.get_predictions()["predictions"][0]
        recovered_stats = api_module.get_stats()
        self.assertEqual(recovered["current_block_state"], "RECOVERED")
        self.assertEqual(recovered_stats["active_blocks"], 0)
        self.assertEqual(recovered_stats["recovered_blocks"], 1)

    def test_dashboard_references_health_and_capture_is_separate(self):
        with open(api_module.DASHBOARD_INDEX, encoding="utf-8") as file:
            page = file.read()
        with open(os.path.join(PROJECT_ROOT, "dashboard", "script.js"), encoding="utf-8") as file:
            script = file.read()
        self.assertIn("/dashboard-assets/script.js", page)
        self.assertIn("async function loadHealth()", script)

        health = api_module.health_status()
        self.assertEqual(health["api_status"], "RUNNING")
        self.assertEqual(health["capture"]["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
