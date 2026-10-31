
import os
import pandas as pd
import joblib


# =========================================================
# LOAD TRAINED MODEL
# =========================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

MODEL_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "models",
    "sentinelai_model.joblib"
)

model = joblib.load(MODEL_FILE)


# =========================================================
# FEATURE ORDER
# MUST MATCH THE TRAINING FEATURE ORDER
# =========================================================

FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count"
]


# =========================================================
# HUMAN-READABLE FEATURE NAMES
# =========================================================

FEATURE_NAMES = {
    "Protocol": "Network protocol",
    "Flow Duration": "Connection duration",
    "Total Fwd Packets": "Forward packet count",
    "Total Backward Packets": "Backward packet count",
    "Fwd Packets Length Total": "Forward data volume",
    "Bwd Packets Length Total": "Backward data volume",
    "Flow Bytes/s": "Data transfer rate",
    "Flow Packets/s": "Packet transfer rate",
    "Packet Length Mean": "Average packet size",
    "Packet Length Std": "Packet size variation",
    "SYN Flag Count": "TCP connection initiation flags",
    "ACK Flag Count": "TCP acknowledgement flags",
    "RST Flag Count": "TCP connection reset flags",
    "FIN Flag Count": "TCP connection termination flags"
}


# =========================================================
# PREDICT NETWORK FLOW
# =========================================================

def predict_flow(flow_features):
    """
    Classify a network flow as NORMAL or ATTACK.

    Returns:
        prediction:
            NORMAL or ATTACK

        attack_probability:
            Model-estimated probability for class 1.

        explanation:
            SHAP feature contributions and human-readable
            descriptions of the model's output.
    """

    # -----------------------------------------------------
    # 1. Validate required features
    # -----------------------------------------------------

    if not isinstance(flow_features, dict):
        raise TypeError(
            "flow_features must be a dictionary."
        )

    missing_features = [
        feature
        for feature in FEATURES
        if feature not in flow_features
    ]

    if missing_features:
        raise ValueError(
            f"Missing required features: {missing_features}"
        )

    # -----------------------------------------------------
    # 2. Validate and prepare numeric input
    # -----------------------------------------------------

    values = {}

    for feature in FEATURES:
        try:
            value = float(flow_features[feature])
        except (TypeError, ValueError):
            raise ValueError(
                f"Feature '{feature}' must be numeric."
            )

        if not pd.notna(value):
            raise ValueError(
                f"Feature '{feature}' must not be NaN."
            )

        if value == float("inf") or value == float("-inf"):
            raise ValueError(
                f"Feature '{feature}' must be finite."
            )

        values[feature] = value

    input_data = pd.DataFrame(
        [[values[feature] for feature in FEATURES]],
        columns=FEATURES
    )

    # -----------------------------------------------------
    # 3. Generate prediction
    # -----------------------------------------------------

    prediction = model.predict(input_data)[0]

    classes = list(model.classes_)

    if 0 not in classes or 1 not in classes:
        raise ValueError(
            "Expected model classes 0 (NORMAL) and 1 (ATTACK). "
            f"Found: {classes}"
        )

    # -----------------------------------------------------
    # 4. Get the probability for the ATTACK class
    # -----------------------------------------------------

    probabilities = model.predict_proba(input_data)[0]

    attack_index = classes.index(1)

    attack_probability = float(
        probabilities[attack_index]
    )

    if prediction == 0:
        result = "NORMAL"

    elif prediction == 1:
        result = "ATTACK"

    else:
        raise ValueError(
            f"Unexpected prediction label: {prediction}"
        )

    # -----------------------------------------------------
    # 5. Generate SHAP explanation
    # -----------------------------------------------------

    from ai.predict.explainable_ai import explain_flow

    explanation = explain_flow(values, prediction=result)

    # -----------------------------------------------------
    # 6. Create a clear explanation of the result
    # -----------------------------------------------------

    probability_percent = round(attack_probability * 100, 2)
    summary = explanation.get("plain_reason", "No short explanation is available.")

    # -----------------------------------------------------
    # 7. Return the complete result
    # -----------------------------------------------------

    return {
        "prediction": result,

        "attack_probability": attack_probability,

        "attack_probability_percent": probability_percent,

        "explanation": explanation,

        "human_readable_summary": summary
    }
