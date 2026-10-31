
from ai.features.flow_aggregator import process_packet
from ai.predict.predict import predict_flow
from ai.logs.prediction_logger import log_prediction
from ai.firewall.adaptive_firewall import (
    get_firewall_action,
    get_firewall_reason
)
from ai.firewall.firewall_enforcer import enforce_firewall_action
from ai.firewall.self_healing import (
    note_suspicious_activity,
    schedule_recovery
)


def analyze_packet(parsed_packet):
    """
    SentinelAI real-time detection pipeline:

    Packet
        ↓
    Flow Aggregation
        ↓
    Feature Extraction
        ↓
    Random Forest Prediction
        ↓
    SHAP Explainable AI
        ↓
    Adaptive Firewall Decision
        ↓
    Windows Firewall Enforcement
        ↓
    Self-Healing Recovery
        ↓
    Prediction Logging
    """

    # 1. Add packet to its network flow
    flow_features = process_packet(parsed_packet)

    # 2. Wait until enough packets are collected
    if flow_features is None:
        return None

    # 3. Predict and explain the network flow
    result = predict_flow(flow_features)

    # 4. Extract prediction results
    prediction = result["prediction"]
    attack_probability = result["attack_probability"]
    explanation = result["explanation"]

    # If this source is already blocked and becomes suspicious again, restart
    # its quiet-period observation window before any recovery can occur.
    if prediction == "ATTACK":
        note_suspicious_activity(parsed_packet["source_ip"])

    # 5. Adaptive firewall decision
    firewall_action = get_firewall_action(
        prediction,
        attack_probability,
        parsed_packet["source_ip"]
    )
    firewall_reason = get_firewall_reason(
        prediction,
        attack_probability,
        firewall_action,
        parsed_packet["source_ip"]
    )

    # 6. Enforce the firewall decision
    enforcement_result = enforce_firewall_action(
        firewall_action,
        parsed_packet["source_ip"]
    )

    # 7. Prepare the complete prediction result
    prediction_result = {
        "flow_features": flow_features,
        "prediction": prediction,
        "attack_probability": attack_probability,
        "explanation": explanation,
        "firewall_action": firewall_action,
        "firewall_reason": firewall_reason,
        "enforcement_status": enforcement_result["status"],
        "enforcement_message": enforcement_result["message"]
    }

    # 8. Include the firewall rule name when available
    if "rule_name" in enforcement_result:
        prediction_result["firewall_rule"] = (
            enforcement_result["rule_name"]
        )

    # 9. Log the prediction before recovery scheduling so the lifecycle log
    # remains in the correct order for the dashboard.
    log_prediction(
        parsed_packet,
        prediction_result
    )

    # 10. Schedule recovery only after a successful Windows Firewall block.
    if (
        firewall_action == "BLOCK"
        and enforcement_result["status"] == "BLOCKED"
    ):
        schedule_recovery(parsed_packet["source_ip"])

    # 11. Return the complete result
    return prediction_result
