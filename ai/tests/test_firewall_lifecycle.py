"""Check adaptive decisions and timed firewall recovery on a reserved IP."""

import os
import sys
import time


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)
sys.path.insert(0, PROJECT_ROOT)

from ai.firewall.adaptive_firewall import (
    get_firewall_action,
    get_firewall_reason,
    reset_source_history
)
from ai.firewall.firewall_enforcer import block_ip, remove_block
from ai.logs.prediction_logger import log_prediction
from ai.firewall.self_healing import (
    get_recovery_duration,
    recovery_results,
    recovery_tasks,
    schedule_recovery
)


TEST_SOURCE_IP = "192.0.2.123"


def main():
    reset_source_history(TEST_SOURCE_IP)
    decision_records = []
    for _ in range(3):
        action = get_firewall_action("ATTACK", 0.45, TEST_SOURCE_IP)
        reason = get_firewall_reason("ATTACK", 0.45, action, TEST_SOURCE_IP)
        decision_records.append((action, reason))
    decisions = [action for action, _ in decision_records]
    expected = ["MONITOR", "MONITOR", "BLOCK"]
    if decisions != expected:
        raise AssertionError(
            f"Adaptive decisions were {decisions}; expected {expected}."
        )
    print("Adaptive test:", " -> ".join(decisions))

    reset_source_history(TEST_SOURCE_IP)
    remove_block(TEST_SOURCE_IP)  # Clean up a leftover test rule if present.
    created = block_ip(TEST_SOURCE_IP)
    if created.get("status") != "BLOCKED":
        raise RuntimeError(
            "Could not create the temporary test rule: "
            f"{created.get('message', 'Unknown firewall error')}"
        )
    print("Temporary rule:", created["status"], "—", created["message"])

    # Save the policy sequence as clearly tagged test records. The last row
    # corresponds to the temporary rule that was actually created above.
    test_packet = {
        "source_ip": TEST_SOURCE_IP,
        "destination_ip": "CONTROLLED_TEST",
        "source_port": 0,
        "destination_port": 0,
        "protocol": "TEST"
    }
    for action, reason in decision_records:
        was_blocked = action == "BLOCK" and created.get("status") == "BLOCKED"
        log_prediction(test_packet, {
            "prediction": "ATTACK",
            "attack_probability": 0.45,
            "firewall_action": action,
            "firewall_reason": reason,
            "enforcement_status": "BLOCKED" if was_blocked else "MONITORING",
            "enforcement_message": (
                created["message"] if was_blocked
                else "Controlled test observation; traffic was monitored."
            ),
            "firewall_rule": created.get("rule_name", "") if was_blocked else "",
            "explanation": {
                "plain_reason": "Controlled adaptive-firewall test record.",
                "_event_details": {"is_test_sample": True}
            }
        })

    thread = None
    try:
        quiet_period = get_recovery_duration()
        print(
            f"Quiet observation: {quiet_period} seconds. "
            "The test block stays in place while this window runs."
        )
        if not schedule_recovery(
            TEST_SOURCE_IP,
            duration=quiet_period,
            event_details={"is_test_sample": True}
        ):
            raise RuntimeError("Self-healing recovery was not scheduled.")

        thread = recovery_tasks[TEST_SOURCE_IP]
        observation_ends = time.monotonic() + quiet_period + 15
        next_progress = time.monotonic()
        while thread.is_alive() and time.monotonic() < observation_ends:
            remaining = max(0, observation_ends - time.monotonic())
            thread.join(timeout=min(1, remaining))
            if thread.is_alive() and time.monotonic() >= next_progress:
                state = recovery_results.get(TEST_SOURCE_IP, {})
                print(
                    "\rQuiet-period observation is active; block remains in place. "
                    f"Recovery status: {state.get('status', 'OBSERVING')}   ",
                    end="",
                    flush=True
                )
                next_progress = time.monotonic() + 5
        if thread.is_alive():
            print()
            raise TimeoutError("Self-healing did not finish within the configured period.")
        print()

        recovered = recovery_results.get(TEST_SOURCE_IP, {})
        if recovered.get("status") != "UNBLOCKED":
            raise AssertionError(
                "Self-healing did not remove the test rule: "
                f"{recovered.get('message', 'No recovery result')}"
            )
        print("Self-healing test:", recovered["status"], "—", recovered["message"])

        retry_decision = get_firewall_action(
            "ATTACK",
            0.45,
            TEST_SOURCE_IP
        )
        if retry_decision != "MONITOR":
            raise AssertionError(
                "Adaptive history was not cleared after recovery; "
                f"next decision was {retry_decision}."
            )
        print("Adaptive history after recovery:", retry_decision)
    finally:
        thread = recovery_tasks.get(TEST_SOURCE_IP)
        if thread and thread.is_alive():
            thread.join(timeout=10)
        remove_block(TEST_SOURCE_IP)


if __name__ == "__main__":
    main()
