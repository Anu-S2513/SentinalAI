"""Explain and optionally enforce one high-confidence dataset attack sample."""

import argparse
import os
import sys
import time

import pandas as pd


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)
sys.path.insert(0, PROJECT_ROOT)

DATASET_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "dataset",
    "processed",
    "sentinelai_training_data.csv"
)

# TEST-NET-1 is reserved for documentation and is not a real remote host.
TEST_SOURCE_IP = "192.0.2.123"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--enforce",
        action="store_true",
        help=(
            "Create a Windows Firewall rule for the reserved test IP, keep it "
            "during the configured quiet observation period, then self-heal it."
        )
    )
    args = parser.parse_args()

    if not os.path.isfile(DATASET_FILE):
        raise FileNotFoundError(
            "Attack test dataset is missing. Restore "
            "ai/dataset/processed/sentinelai_training_data.csv "
            "from your original SentinelAI project, then rerun this script."
        )

    # Delay imports with startup side effects until after validating the
    # ignored training-data file is present.
    from ai.firewall.adaptive_firewall import (
        get_firewall_action,
        get_firewall_reason
    )
    from ai.firewall.firewall_enforcer import (
        enforce_firewall_action,
        remove_block
    )
    from ai.firewall.firewall_policy import get_block_threshold
    from ai.firewall.self_healing import (
        get_recovery_duration,
        recovery_results,
        recovery_tasks,
        schedule_recovery
    )
    from ai.logs.prediction_logger import (
        log_firewall_event,
        log_prediction
    )
    from ai.predict.predict import FEATURES, model, predict_flow

    data = pd.read_csv(DATASET_FILE)
    attack_rows = data[data["Label"] != "Benign"].copy()
    if attack_rows.empty:
        raise ValueError("The dataset has no labeled attack samples.")

    missing = [feature for feature in FEATURES if feature not in attack_rows]
    if missing:
        raise ValueError(f"Dataset is missing model features: {missing}")

    features = attack_rows[FEATURES]
    probabilities = model.predict_proba(features)
    attack_index = list(model.classes_).index(1)
    predicted_classes = model.predict(features)
    eligible = [
        index for index, (label, probability) in enumerate(
            zip(predicted_classes, probabilities[:, attack_index])
        )
        if label == 1 and probability >= get_block_threshold()
    ]

    if not eligible:
        best_probability = float(probabilities[:, attack_index].max())
        raise RuntimeError(
            "No dataset attack sample reached the configured firewall "
            f"block threshold ({get_block_threshold():.0%}) "
            f"(highest model probability: {best_probability:.1%})."
        )

    eligible_rows = attack_rows.iloc[eligible].copy()
    eligible_rows["_attack_probability"] = probabilities[eligible, attack_index]

    # Prefer an SSH-Patator record, whose received-message count often gives
    # a more relatable clue than a single TCP start signal. Fall back safely
    # when a different dataset does not contain this attack family.
    easy_label_rows = eligible_rows[
        eligible_rows["Label"].astype(str).str.contains("SSH-Patator", case=False)
    ]
    selection_pool = easy_label_rows if not easy_label_rows.empty else eligible_rows
    sample_row = selection_pool.sort_values(
        ["_attack_probability", "Total Backward Packets"],
        ascending=[False, False]
    ).iloc[0]
    flow_features = {
        feature: float(sample_row[feature])
        for feature in FEATURES
    }

    # This runs the same model and SHAP explanation used by live detection.
    prediction_result = predict_flow(flow_features)
    firewall_action = get_firewall_action(
        prediction_result["prediction"],
        prediction_result["attack_probability"],
        TEST_SOURCE_IP
    )
    firewall_reason = get_firewall_reason(
        prediction_result["prediction"],
        prediction_result["attack_probability"],
        firewall_action,
        TEST_SOURCE_IP
    )

    if firewall_action != "BLOCK":
        raise RuntimeError(
            "The selected sample did not produce a BLOCK decision; "
            "no test record was written."
        )

    if args.enforce:
        enforcement = enforce_firewall_action(
            firewall_action,
            TEST_SOURCE_IP
        )
    else:
        enforcement = {
            "status": "SIMULATED",
            "message": "Dry run only; no Windows Firewall rule was created."
        }

    result = {
        **prediction_result,
        "firewall_action": firewall_action,
        "firewall_reason": firewall_reason,
        "enforcement_status": enforcement["status"],
        "enforcement_message": enforcement["message"]
    }
    if enforcement.get("rule_name"):
        result["firewall_rule"] = enforcement["rule_name"]

    packet = {
        "source_ip": TEST_SOURCE_IP,
        "destination_ip": "DATASET_SAMPLE",
        "source_port": 0,
        "destination_port": 0,
        "protocol": "TEST"
    }

    recovery_result = None
    quiet_period = None
    try:
        # Append the sample to the active session so the dashboard can show it
        # without resetting the capture session or clearing live flows.
        log_prediction(packet, result)
        if args.enforce and enforcement.get("status") == "BLOCKED":
            quiet_period = get_recovery_duration()
            if not schedule_recovery(
                TEST_SOURCE_IP,
                duration=quiet_period,
                event_details={"is_test_sample": True, "source": "attack_sample_demo"}
            ):
                raise RuntimeError("Could not start the test quiet-period observer.")
            observer = recovery_tasks[TEST_SOURCE_IP]
            deadline = time.monotonic() + quiet_period + 15
            while observer.is_alive() and time.monotonic() < deadline:
                observer.join(timeout=1)
            recovery_result = recovery_results.get(TEST_SOURCE_IP, {})
            if observer.is_alive():
                raise TimeoutError("The self-healing observation did not finish in time.")
    finally:
        if (
            args.enforce
            and enforcement.get("status") == "BLOCKED"
            and recovery_result is None
        ):
            cleanup_result = remove_block(TEST_SOURCE_IP)
            if cleanup_result.get("status") == "UNBLOCKED":
                try:
                    log_firewall_event(
                        TEST_SOURCE_IP,
                        "UNBLOCK",
                        "UNBLOCKED",
                        "Safety cleanup removed the test rule before observation completed.",
                        cleanup_result.get("rule_name", ""),
                        event_details={"is_test_sample": True}
                    )
                except Exception as error:
                    print(f"Could not log test rule cleanup: {error}")

    influences = result["explanation"].get("top_attack_influences", [])
    leading_feature = (
        influences[0].get("display_name", influences[0].get("feature"))
        if influences else "No positive SHAP feature contribution was returned"
    )

    print(f"Selected attack example: {sample_row['Label']}")
    print(f"Model prediction: {result['prediction']}")
    print(f"Attack probability: {result['attack_probability']:.1%}")
    print(f"Why it was flagged: {result['explanation'].get('plain_reason', 'No plain-language reason was returned.')}")
    print(f"Firewall decision: {firewall_action}")
    print(f"Enforcement: {enforcement['status']} — {enforcement['message']}")
    print(f"Main detail used: {leading_feature}")
    if args.enforce and enforcement.get("status") == "BLOCKED":
        print(
            f"Quiet observation period: {quiet_period} seconds; "
            "test block remained active during the observation."
        )
        print(
            "Self-healing:",
            recovery_result.get("status", "UNKNOWN"),
            "—",
            recovery_result.get("message", "No recovery result was recorded.")
        )
    print("Sample saved to the prediction log for the dashboard.")


if __name__ == "__main__":
    main()
