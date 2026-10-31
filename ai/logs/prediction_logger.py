
import csv
import os
import json
from datetime import datetime



PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


LOG_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "predictions.csv"
)


log_file = LOG_FILE

FIELDNAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "prediction",
    "attack_probability",
    "firewall_action",
    "explanation",
    "enforcement_status",
    "enforcement_message",
    "firewall_rule"
]

# Backward compatibility with existing code.
fieldnames = FIELDNAMES




def initialize_log():
    """
    Create the prediction log if missing and accept its existing header.

    Older log files are kept as-is. Enforcement data is stored inside
    each new row's explanation JSON when the old header lacks those columns.
    """

    os.makedirs(
        os.path.dirname(LOG_FILE),
        exist_ok=True
    )



    if not os.path.isfile(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        with open(
            LOG_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=FIELDNAMES
            )

            writer.writeheader()

        print("Prediction log initialized.")
        return

    with open(LOG_FILE, "r", newline="", encoding="utf-8-sig") as file:
        existing_fieldnames = csv.DictReader(file).fieldnames or []

    if not set(FIELDNAMES[:10]).issubset(existing_fieldnames):
        raise RuntimeError(
            "The prediction log is missing required columns. "
            "Keep a backup before replacing it with a fresh log."
        )


# ============================================================
# RESET LOG FOR A NEW MONITORING SESSION
# ============================================================

def reset_log():
    """
    Clear prediction history and initialize a fresh CSV.

    Use this function only when intentionally starting a
    new session without preserving previous prediction rows.
    """

    os.makedirs(
        os.path.dirname(LOG_FILE),
        exist_ok=True
    )

    with open(
        LOG_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()

    print("Prediction log reset successfully.")


# ============================================================
# SAVE PREDICTION AND SHAP EXPLANATION
# ============================================================

def log_prediction(packet, result):
    """
    Save the network prediction, attack probability,
    firewall decision, and SHAP explanation.

    Expected result fields:
        prediction
        attack_probability
        firewall_action
        explanation

    Expected packet fields:
        source_ip
        destination_ip
        source_port
        destination_port
        protocol
    """

    initialize_log()

    # Retrieve the SHAP explanation.
    explanation = result.get("explanation")

    if isinstance(explanation, dict):
        explanation = dict(explanation)
    else:
        explanation = {"model_explanation": explanation}

    # Keep enforcement information even when an older CSV header does not
    # include dedicated enforcement columns.
    explanation["_enforcement"] = {
        "status": result.get("enforcement_status", ""),
        "message": result.get("enforcement_message", ""),
        "rule": result.get("firewall_rule", "")
    }
    explanation["_firewall_reason"] = result.get("firewall_reason", "")

    # Serialize the explanation for CSV storage.
    if explanation is not None:
        try:
            explanation_json = json.dumps(
                explanation,
                ensure_ascii=False
            )
        except (TypeError, ValueError) as error:
            print(
                f"Warning: Could not serialize SHAP explanation: {error}"
            )
            explanation_json = ""
    else:
        explanation_json = ""

    # Prepare the prediction record.
    log_data = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "source_ip": packet.get("source_ip", ""),
        "destination_ip": packet.get("destination_ip", ""),
        "source_port": packet.get("source_port", ""),
        "destination_port": packet.get("destination_port", ""),
        "protocol": packet.get("protocol", ""),

        "prediction": result.get("prediction", ""),
        "attack_probability": result.get(
            "attack_probability",
            ""
        ),
        "firewall_action": result.get(
            "firewall_action",
            ""
        ),
        "explanation": explanation_json,
        "enforcement_status": result.get(
            "enforcement_status",
            ""
        ),
        "enforcement_message": result.get(
            "enforcement_message",
            ""
        ),
        "firewall_rule": result.get(
            "firewall_rule",
            ""
        )
    }

    # Match the existing header so older CSV files remain appendable without
    # rewriting their saved history.
    with open(
        LOG_FILE,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as existing_file:
        csv_fieldnames = csv.DictReader(existing_file).fieldnames or FIELDNAMES

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=csv_fieldnames,
            extrasaction="ignore"
        )

        writer.writerow(log_data)
        file.flush()

    if log_data["prediction"] == "SYSTEM":
        print(
            "Firewall event logged:",
            log_data["firewall_action"],
            "| Status:",
            log_data["enforcement_status"]
        )
    else:
        print(
            "Prediction logged:",
            log_data["prediction"],
            "| Firewall:",
            log_data["firewall_action"],
            "| SHAP:",
            "Available" if explanation_json else "Unavailable"
        )


def log_firewall_event(
    source_ip,
    action,
    status,
    message,
    rule_name="",
    event_details=None
):
    """Append a firewall lifecycle event without counting it as a prediction."""
    log_prediction(
        {
            "source_ip": source_ip,
            "destination_ip": "",
            "source_port": "",
            "destination_port": "",
            "protocol": "SYSTEM"
        },
        {
            "prediction": "SYSTEM",
            "attack_probability": 0,
            "firewall_action": action,
            "enforcement_status": status,
            "enforcement_message": message,
            "firewall_rule": rule_name,
            "firewall_reason": "Firewall rule lifecycle event.",
            "explanation": {
                "summary": message,
                "_event_details": event_details or {}
            }
        }
    )


# ============================================================
# INITIALIZE LOG WHEN MODULE IS IMPORTED
# ============================================================

initialize_log()
