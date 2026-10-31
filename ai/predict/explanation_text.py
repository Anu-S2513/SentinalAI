"""Create plain-language reasons from saved model influence data."""

from functools import lru_cache
import os

import pandas as pd

from ai.predict.predict import FEATURES


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
    """Load compact comparison data once from labeled training examples."""
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


def format_number(value):
    return f"{float(value):,.2f}".rstrip("0").rstrip(".")


def pluralize(number, singular, plural):
    return singular if float(number) == 1 else plural


def format_bytes(value):
    value = max(0.0, float(value))
    if value < 1024:
        return f"{value:.0f} bytes"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"


def format_measurement(feature, value):
    number = float(value)
    rounded = format_number(number)
    if feature == "Protocol":
        name = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "other"}.get(int(number), "other")
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
    if feature == "SYN Flag Count":
        if number == 0:
            return "the connection did not try to start a network conversation"
        if number == 1:
            return "the connection tried once to start a network conversation"
        return f"the connection tried {rounded} times to start a network conversation"
    flag_names = {
        "ACK Flag Count": ("reply", "replies"),
        "RST Flag Count": ("reset", "resets"),
        "FIN Flag Count": ("connection close signal", "connection close signals")
    }
    if feature in flag_names:
        singular, plural = flag_names[feature]
        count = "none" if number == 0 else rounded
        return f"the connection included {count} {pluralize(number, singular, plural)}"
    return f"the value was {rounded}"


def normal_range_sentence(feature, cutoff, high):
    number = float(cutoff)
    amount = format_number(number)
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
            else "This was shorter than the duration of 95% of normal connections."
        )

    if feature == "Flow Bytes/s" and high:
        return f"95% of normal examples moved data at no more than {format_bytes(number)}/second."
    if feature == "Flow Packets/s" and high:
        return f"95% of normal examples sent {amount} or fewer messages per second."

    descriptions = {
        "Total Fwd Packets": ("sent", "messages"),
        "Total Backward Packets": ("received", "replies"),
        "Fwd Packets Length Total": ("sent", "of data"),
        "Bwd Packets Length Total": ("received", "of data"),
        "Packet Length Mean": ("had an average size of", "bytes"),
        "Packet Length Std": ("had message sizes vary by", "bytes"),
        "SYN Flag Count": ("made", "conversation start attempts"),
        "ACK Flag Count": ("received", "replies"),
        "RST Flag Count": ("had", "connection resets"),
        "FIN Flag Count": ("had", "connection close signals")
    }
    verb, unit = descriptions.get(feature, ("had", "of this activity"))
    shown = format_bytes(number) if feature in (
        "Fwd Packets Length Total", "Bwd Packets Length Total"
    ) else amount
    if high:
        if number == 0 and feature in (
            "SYN Flag Count", "ACK Flag Count", "RST Flag Count", "FIN Flag Count"
        ):
            return f"About 95 out of 100 normal connections had no {unit}."
        return f"About 95 out of 100 normal connections {verb} no more than {shown} {unit}."
    return "This amount was lower than what most normal connections showed."


def explain_feature_value(item, reference):
    feature = item["feature"]
    value = float(item["value"])
    observation = format_measurement(feature, value)
    if not reference:
        return f"{observation}; this detail influenced the result.", None

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
        return f"{observation}; this detail influenced the result.", None
    if value > bounds["high"]:
        return f"{observation}; {normal_range_sentence(feature, bounds['high'], True)}", True
    if value < bounds["low"]:
        return f"{observation}; {normal_range_sentence(feature, bounds['low'], False)}", True
    return (
        f"{observation}; this amount also appeared in normal traffic, "
        "so it was not unusual on its own.",
        False
    )


def build_plain_reason(explanation, prediction):
    """Build a clear explanation for both new and previously saved rows."""
    prediction = str(prediction).strip().upper()
    influence_key = "top_attack_influences" if prediction == "ATTACK" else "top_normal_influences"
    influences = explanation.get(influence_key, []) if isinstance(explanation, dict) else []
    if not influences and isinstance(explanation, dict):
        influences = [
            feature for feature in explanation.get("top_features", [])
            if (float(feature.get("shap_value", feature.get("contribution", 0))) > 0)
            == (prediction == "ATTACK")
        ]

    if not influences:
        return (
            "The model flagged the overall connection pattern as a possible threat, but no clear detail was available to explain why."
            if prediction == "ATTACK"
            else "No strong warning stood out in this traffic."
        )

    reference = get_normal_traffic_reference()
    described = []
    for item in influences[:5]:
        if not isinstance(item, dict) or "feature" not in item or "value" not in item:
            continue
        detail, unusual = explain_feature_value(item, reference)
        described.append((detail, unusual))
    if not described:
        return "The model flagged the overall connection pattern as a possible threat, but no clear detail was available to explain why."

    if prediction == "ATTACK":
        lines = ["The model flagged this as a possible threat after weighing these details:"]
        selected_details = [item for item in described if item[1] is True][:2]
        for item in described:
            if len(selected_details) >= 2:
                break
            if item not in selected_details:
                selected_details.append(item)
        for detail, unusual in selected_details:
            detail = detail.replace("; ", ". ")
            detail = detail[:1].upper() + detail[1:]
            if unusual is False and "not unusual on its own" not in detail.lower():
                detail += " This amount also appears in normal connections."
            elif unusual is None:
                detail += " A normal-traffic comparison was not available."
            lines.append(f"- {detail}")
        lines.append("These details raised the score together; no single clue proves an attack.")
        return "\n".join(lines)

    primary, _ = described[0]
    primary = primary.replace("; ", ". ")
    return f"This looked normal because {primary[:1].lower() + primary[1:]}"
