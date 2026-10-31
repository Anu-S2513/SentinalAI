from functools import lru_cache
import os

import numpy as np
import pandas as pd
import shap

from ai.predict.predict import model, FEATURES
from ai.predict.explanation_text import build_plain_reason


# --------------------------------------------------
# 1. Human-readable feature descriptions
# --------------------------------------------------

FEATURE_INFO = {
    "Protocol": {
        "name": "Network Protocol",
        "description": "Identifies the protocol used by this connection."
    },
    "Flow Duration": {
        "name": "Connection Duration",
        "description": "Measures how long the network flow lasted."
    },
    "Total Fwd Packets": {
        "name": "Outgoing Packet Count",
        "description": "Counts packets travelling in the forward direction."
    },
    "Total Backward Packets": {
        "name": "Incoming Packet Count",
        "description": "Counts packets travelling in the reverse direction."
    },
    "Fwd Packets Length Total": {
        "name": "Outgoing Data Volume",
        "description": "Measures the total bytes sent in the forward direction."
    },
    "Bwd Packets Length Total": {
        "name": "Incoming Data Volume",
        "description": "Measures the total bytes sent in the reverse direction."
    },
    "Flow Bytes/s": {
        "name": "Data Transfer Rate",
        "description": "Measures how many bytes are transferred per second."
    },
    "Flow Packets/s": {
        "name": "Packet Transmission Rate",
        "description": "Measures how many packets are transferred per second."
    },
    "Packet Length Mean": {
        "name": "Average Packet Size",
        "description": "Measures the average packet size in the connection."
    },
    "Packet Length Std": {
        "name": "Packet Size Variation",
        "description": "Measures variation in packet sizes."
    },
    "SYN Flag Count": {
        "name": "TCP Connection-Start Flags",
        "description": "Counts TCP packets carrying the SYN flag."
    },
    "ACK Flag Count": {
        "name": "TCP Acknowledgement Flags",
        "description": "Counts TCP packets carrying the ACK flag."
    },
    "RST Flag Count": {
        "name": "TCP Connection-Reset Flags",
        "description": "Counts TCP packets carrying the RST flag."
    },
    "FIN Flag Count": {
        "name": "TCP Connection-Finish Flags",
        "description": "Counts TCP packets carrying the FIN flag."
    }
}

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
REFERENCE_DATASET = os.path.join(
    PROJECT_ROOT,
    "ai",
    "dataset",
    "processed",
    "sentinelai_training_data.csv"
)


@lru_cache(maxsize=1)
def get_normal_traffic_reference():
    """Load compact comparison stats once from the model's labeled examples."""
    if not os.path.isfile(REFERENCE_DATASET):
        return None

    try:
        data = pd.read_csv(REFERENCE_DATASET, usecols=["Label", *FEATURES])
        normal = data[data["Label"] == "Benign"]
        attacks = data[data["Label"] != "Benign"]
        if normal.empty:
            return None

        numeric_features = [feature for feature in FEATURES if feature != "Protocol"]
        quantiles = normal[numeric_features].quantile([0.05, 0.95])
        return {
            "normal_count": int(len(normal)),
            "attack_count": int(len(attacks)),
            "quantiles": {
                feature: {
                    "low": float(quantiles.loc[0.05, feature]),
                    "high": float(quantiles.loc[0.95, feature])
                }
                for feature in numeric_features
            },
            "normal_protocol_share": normal["Protocol"].value_counts(normalize=True).to_dict(),
            "attack_protocol_share": attacks["Protocol"].value_counts(normalize=True).to_dict()
        }
    except (OSError, ValueError, KeyError, pd.errors.ParserError):
        return None


def format_measurement(feature, value):
    """Turn a model input value into a short, human-readable description."""
    number = float(value)
    rounded = f"{number:,.2f}".rstrip("0").rstrip(".")
    if feature == "Protocol":
        protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "other"}
        name = protocol_names.get(int(number), "other")
        return f"the connection used {name}"
    if feature == "Flow Duration":
        seconds = number / 1_000_000
        if seconds < 1:
            return f"the connection lasted {seconds * 1000:.0f} milliseconds"
        return f"the connection lasted {seconds:.2f} seconds"
    if feature == "Total Fwd Packets":
        return f"the connection sent {rounded} {pluralize(number, 'message', 'messages')}"
    if feature == "Total Backward Packets":
        return f"the connection received {rounded} {pluralize(number, 'reply', 'replies')}"
    if feature == "Fwd Packets Length Total":
        return f"{format_bytes(number)} of data was sent"
    if feature == "Bwd Packets Length Total":
        return f"{format_bytes(number)} of data was received"
    if feature == "Flow Bytes/s":
        return f"data moved at {format_bytes(number)}/second"
    if feature == "Flow Packets/s":
        return f"{rounded} messages moved per second"
    if feature == "Packet Length Mean":
        return f"the average message was {rounded} bytes"
    if feature == "Packet Length Std":
        return f"message sizes varied by about {rounded} bytes"
    flag_names = {
        "SYN Flag Count": "connection-start requests",
        "ACK Flag Count": "reply signals",
        "RST Flag Count": "connection resets",
        "FIN Flag Count": "connection endings"
    }
    if feature in flag_names:
        singular_names = {
            "SYN Flag Count": "connection-start request",
            "ACK Flag Count": "reply signal",
            "RST Flag Count": "connection reset",
            "FIN Flag Count": "connection ending"
        }
        count = "none" if number == 0 else rounded
        return (
            f"the connection included {count} "
            f"{pluralize(number, singular_names[feature], flag_names[feature])}"
        )
    return f"the value was {rounded}"


def pluralize(number, singular, plural):
    return singular if float(number) == 1 else plural


def format_bytes(value):
    value = max(0.0, float(value))
    if value < 1024:
        return f"{value:.0f} bytes"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"


def normal_range_sentence(feature, cutoff, high):
    number = float(cutoff)
    amount = f"{number:,.2f}".rstrip("0").rstrip(".")
    if feature == "Flow Duration":
        seconds = number / 1_000_000
        time_text = (
            f"{seconds * 1000:.0f} milliseconds"
            if seconds < 1
            else f"{seconds:.2f} seconds"
        )
        return (
            f"95% of normal connections lasted no more than {time_text}."
            if high
            else f"This was shorter than the duration of 95% of normal connections."
        )

    descriptions = {
        "Total Fwd Packets": ("sent", "messages"),
        "Total Backward Packets": ("received", "replies"),
        "Fwd Packets Length Total": ("sent", "of data"),
        "Bwd Packets Length Total": ("received", "of data"),
        "Flow Bytes/s": ("transferred per second", "of data"),
        "Flow Packets/s": ("sent per second", "messages"),
        "Packet Length Mean": ("had an average size of", "bytes"),
        "Packet Length Std": ("had message sizes vary by", "bytes"),
        "SYN Flag Count": ("had", "connection-start requests"),
        "ACK Flag Count": ("had", "reply signals"),
        "RST Flag Count": ("had", "connection resets"),
        "FIN Flag Count": ("had", "connection endings")
    }
    verb, unit = descriptions.get(feature, ("had", "of this activity"))
    shown_amount = (
        format_bytes(number)
        if feature in ("Fwd Packets Length Total", "Bwd Packets Length Total", "Flow Bytes/s")
        else amount
    )
    if feature == "Flow Bytes/s":
        shown_amount += "/second"
    if high:
        if feature == "Flow Bytes/s":
            return f"95% of normal examples moved data at no more than {format_bytes(number)}/second."
        if feature == "Flow Packets/s":
            return f"95% of normal examples sent {amount} or fewer messages per second."
        if number == 0 and feature in ("SYN Flag Count", "ACK Flag Count", "RST Flag Count", "FIN Flag Count"):
            return f"95% of normal examples had no {unit}."
        return f"95% of normal examples {verb} no more than {shown_amount} {unit}."
    return "This was lower than the value in 95% of normal examples."


def explain_feature_value(item, reference):
    """Describe the observed value and whether it differs from benign data."""
    feature = item["feature"]
    value = float(item["value"])
    observation = format_measurement(feature, value)
    if not reference:
        return f"{observation}; this detail influenced the result.", False

    if feature == "Protocol":
        key = int(value)
        normal_share = reference["normal_protocol_share"].get(key, 0.0)
        attack_share = reference["attack_protocol_share"].get(key, 0.0)
        return (
            f"{observation}. It appeared in {attack_share:.0%} of attack "
            f"examples and {normal_share:.0%} of normal examples.",
            attack_share > normal_share
        )

    bounds = reference["quantiles"].get(feature)
    if not bounds:
        return f"{observation}; this detail influenced the result.", False

    if value > bounds["high"]:
        return (
            f"{observation}. {normal_range_sentence(feature, bounds['high'], True)}",
            True
        )
    if value < bounds["low"]:
        return (
            f"{observation}. {normal_range_sentence(feature, bounds['low'], False)}",
            True
        )
    return (
        f"{observation}; this amount also appeared in normal traffic, "
        "so it was not unusual on its own.",
        False
    )


# --------------------------------------------------
# 2. Initialize the SHAP explainer
# --------------------------------------------------

explainer = shap.TreeExplainer(model)


# --------------------------------------------------
# 3. Get SHAP values for the ATTACK class
# --------------------------------------------------

def get_attack_shap_values(input_data):
    """
    Return feature contributions for class 1 (ATTACK).

    Supports common SHAP output shapes:
        (samples, features, classes)
        (samples, features)
        list of per-class arrays
    """

    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "The trained model does not contain class 1 (ATTACK)."
        )

    attack_index = classes.index(1)

    shap_output = explainer(input_data)

    # Newer SHAP versions usually return an Explanation object.
    if hasattr(shap_output, "values"):
        raw_values = shap_output.values
    else:
        raw_values = shap_output

    # Some classifier explainers return one array per class.
    if isinstance(raw_values, list):
        if attack_index >= len(raw_values):
            raise ValueError(
                "SHAP output does not contain the ATTACK class."
            )

        values = np.asarray(raw_values[attack_index])

    else:
        values = np.asarray(raw_values)

        if values.ndim == 3:
            # Shape: samples x features x classes
            if attack_index >= values.shape[2]:
                raise ValueError(
                    "SHAP output does not contain the ATTACK class."
                )

            values = values[:, :, attack_index]

        elif values.ndim != 2:
            raise ValueError(
                f"Unexpected SHAP output shape: {values.shape}"
            )

    expected_shape = (len(input_data), len(FEATURES))

    if values.shape != expected_shape:
        raise ValueError(
            f"Unexpected SHAP shape {values.shape}. "
            f"Expected {expected_shape}. "
            "Check the installed SHAP version and model output."
        )

    if not np.isfinite(values).all():
        raise ValueError("SHAP returned non-finite feature contributions.")

    return values[0]


# --------------------------------------------------
# 4. Explain an individual feature
# --------------------------------------------------

def explain_feature(feature, value, contribution):
    """
    Convert a SHAP contribution into a readable explanation.

    Positive values push the explained model output toward ATTACK.
    Negative values push it away from ATTACK.
    """

    info = FEATURE_INFO.get(
        feature,
        {
            "name": feature,
            "description": "Network flow feature."
        }
    )

    if contribution > 0:
        direction = "toward_attack"
        effect = "pushed the model output toward ATTACK"

    elif contribution < 0:
        direction = "away_from_attack"
        effect = "pushed the model output away from ATTACK"

    else:
        direction = "minimal"
        effect = "had approximately no directional influence"

    sentence = (
        f"{info['name']} {effect}. "
        f"Observed value: {value:g}. "
        f"{info['description']}"
    )

    return {
        "feature": feature,
        "display_name": info["name"],
        "description": info["description"],
        "value": float(value),
        "shap_value": float(contribution),
        "direction": direction,
        "explanation": sentence
    }


# --------------------------------------------------
# 5. Explain an entire network flow
# --------------------------------------------------

def explain_flow(flow_features, prediction=None):
    """
    Explain a network flow using SHAP feature contributions.

    The input must contain the 14 features used during training.
    """

    missing_features = [
        feature
        for feature in FEATURES
        if feature not in flow_features
    ]

    if missing_features:
        raise ValueError(
            f"Missing required features: {missing_features}"
        )

    input_values = []

    for feature in FEATURES:
        try:
            value = float(flow_features[feature])

        except (TypeError, ValueError):
            raise ValueError(
                f"Feature '{feature}' must contain a numeric value."
            ) from None

        if not np.isfinite(value):
            raise ValueError(
                f"Feature '{feature}' contains an invalid numeric value."
            )

        input_values.append(value)

    # Preserve the exact feature order used during training.
    input_data = pd.DataFrame(
        [input_values],
        columns=FEATURES
    )

    # Obtain feature contributions for ATTACK class.
    shap_values = get_attack_shap_values(input_data)

    contributions = []

    for feature, value, contribution in zip(
        FEATURES,
        input_values,
        shap_values
    ):
        item = explain_feature(
            feature,
            value,
            float(contribution)
        )

        contributions.append(item)

    # Rank features by absolute contribution magnitude.
    contributions.sort(
        key=lambda item: abs(item["shap_value"]),
        reverse=True
    )

    # Features pushing the output toward ATTACK.
    attack_influences = [
        item
        for item in contributions
        if item["shap_value"] > 0
    ]

    # Features pushing the output away from ATTACK.
    normal_influences = [
        item
        for item in contributions
        if item["shap_value"] < 0
    ]

    if prediction is None:
        prediction = "ATTACK" if int(model.predict(input_data)[0]) == 1 else "NORMAL"
    else:
        prediction = str(prediction).strip().upper()

    plain_reason = build_plain_reason({
        "top_attack_influences": attack_influences,
        "top_normal_influences": normal_influences,
        "top_features": contributions
    }, prediction)

    top_features = contributions[:5]

    return {
        "explained_class": "ATTACK",
        "method": "SHAP TreeExplainer",
        "plain_reason": plain_reason,
        "summary": plain_reason,
        "top_features": top_features,
        "top_attack_influences": attack_influences[:5],
        "top_normal_influences": normal_influences[:5],
        "feature_contributions": contributions,
        "interpretation_note": (
            "This short reason points to the main traffic detail behind the result."
        )
    }
