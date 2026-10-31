
import csv
import hashlib
import os
import json
import threading
from datetime import datetime
from functools import lru_cache

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Literal

from ai.predict.predict import predict_flow
from ai.predict.explanation_text import build_plain_reason
from ai.logs.session_state import (
    get_session_started_at,
    is_current_session,
    get_capture_status
)
from ai.firewall.firewall_policy import (
    get_block_threshold,
    threshold_configuration_error
)
from ai.firewall.self_healing import (
    get_recovery_duration,
    set_recovery_duration,
    MIN_QUIET_PERIOD_SECONDS,
    MAX_QUIET_PERIOD_SECONDS
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SentinelAI ML API",
    version="1.4",
    description=(
        "AI-powered real-time network threat detection "
        "with SHAP explainability and adaptive firewall monitoring."
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

DASHBOARD_DIR = os.path.join(
    PROJECT_ROOT,
    "dashboard"
)

DASHBOARD_INDEX = os.path.join(
    DASHBOARD_DIR,
    "index.html"
)

PREDICTIONS_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "predictions.csv"
)

ACTIVE_FLOWS_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "active_flows.json"
)

FEEDBACK_FILE = os.path.join(PROJECT_ROOT, "ai", "logs", "alert_feedback.csv")
MODEL_FILE = os.path.join(PROJECT_ROOT, "ai", "models", "sentinelai_model.joblib")
feedback_lock = threading.Lock()


# ============================================================
# DASHBOARD STATIC FILES
# ============================================================

if os.path.isdir(DASHBOARD_DIR):
    app.mount(
        "/dashboard-assets",
        StaticFiles(directory=DASHBOARD_DIR),
        name="dashboard-assets"
    )


# ============================================================
# INPUT MODEL
# ============================================================

class FlowData(BaseModel):
    Protocol: int
    Flow_Duration: float
    Total_Fwd_Packets: int
    Total_Backward_Packets: int
    Fwd_Packets_Length_Total: float
    Bwd_Packets_Length_Total: float
    Flow_Bytes_per_s: float
    Flow_Packets_per_s: float
    Packet_Length_Mean: float
    Packet_Length_Std: float
    SYN_Flag_Count: int
    ACK_Flag_Count: int
    RST_Flag_Count: int
    FIN_Flag_Count: int


class AlertFeedback(BaseModel):
    record_id: str
    record_timestamp: str
    source_ip: str
    destination_ip: str
    feedback: Literal["FALSE_ALARM", "CONFIRMED_THREAT"]


class RecoveryDurationUpdate(BaseModel):
    duration_seconds: int


# ============================================================
# DASHBOARD ROUTES
# ============================================================

@app.get("/", include_in_schema=False)
def home():
    if not os.path.isfile(DASHBOARD_INDEX):
        return {
            "error": "Dashboard HTML file not found",
            "expected_path": DASHBOARD_INDEX
        }

    return FileResponse(
        DASHBOARD_INDEX,
        media_type="text/html"
    )


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
def serve_dashboard():
    if not os.path.isfile(DASHBOARD_INDEX):
        return {
            "error": "Dashboard HTML file not found",
            "expected_path": DASHBOARD_INDEX
        }

    return FileResponse(
        DASHBOARD_INDEX,
        media_type="text/html"
    )


# ============================================================
# API STATUS
# ============================================================

@app.get("/api")
def api_status():
    return {
        "message": "SentinelAI API running",
        "status": "active",
        "version": "1.4",
        "dashboard": "/",
        "documentation": "/docs",
        "features": [
            "Random Forest prediction",
            "SHAP Explainable AI",
            "Prediction history",
            "Network flow monitoring",
            "Adaptive firewall statistics",
            "Firewall enforcement status"
        ]
    }


@app.get("/api/health")
def health_status():
    """Report API availability separately from packet-capture heartbeat."""
    configuration_error = threshold_configuration_error()
    return {
        "api_status": "RUNNING",
        "capture": get_capture_status(),
        "block_threshold": get_block_threshold(),
        "firewall_policy_status": (
            "CONFIGURATION_ERROR" if configuration_error else "READY"
        ),
        "firewall_policy_message": configuration_error
    }


@app.get("/api/recovery-settings")
def recovery_settings():
    return {
        "duration_seconds": get_recovery_duration(),
        "minimum_seconds": MIN_QUIET_PERIOD_SECONDS,
        "maximum_seconds": MAX_QUIET_PERIOD_SECONDS,
        "applies_to": "new blocks"
    }


@app.put("/api/recovery-settings")
def update_recovery_settings(settings: RecoveryDurationUpdate):
    try:
        duration = set_recovery_duration(settings.duration_seconds)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {
        "saved": True,
        "duration_seconds": duration,
        "message": "Quiet observation time saved. It applies to new blocks."
    }


# ============================================================
# MANUAL MODEL PREDICTION
# NOTE: This endpoint predicts and explains a flow.
# It does not enforce a firewall rule.
# ============================================================

@app.post("/predict")
def predict(data: FlowData):
    features = {
        "Protocol": data.Protocol,
        "Flow Duration": data.Flow_Duration,
        "Total Fwd Packets": data.Total_Fwd_Packets,
        "Total Backward Packets": data.Total_Backward_Packets,
        "Fwd Packets Length Total":
            data.Fwd_Packets_Length_Total,
        "Bwd Packets Length Total":
            data.Bwd_Packets_Length_Total,
        "Flow Bytes/s": data.Flow_Bytes_per_s,
        "Flow Packets/s": data.Flow_Packets_per_s,
        "Packet Length Mean": data.Packet_Length_Mean,
        "Packet Length Std": data.Packet_Length_Std,
        "SYN Flag Count": data.SYN_Flag_Count,
        "ACK Flag Count": data.ACK_Flag_Count,
        "RST Flag Count": data.RST_Flag_Count,
        "FIN Flag Count": data.FIN_Flag_Count
    }

    return predict_flow(features)


# ============================================================
# READ PREDICTION HISTORY
# ============================================================

def read_predictions():
    predictions = []
    session_started_at = get_session_started_at()

    if not os.path.isfile(PREDICTIONS_FILE):
        return predictions

    with open(
        PREDICTIONS_FILE,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        reader = csv.DictReader(file)

        for record_index, row in enumerate(reader):
            row["record_id"] = str(record_index)

            # Ignore archived rows before parsing their larger explanation
            # payloads. Read the session marker only once per request.
            if not is_current_session(
                row.get("timestamp", ""),
                session_started_at
            ):
                continue

            # ------------------------------------------------
            # Parse SHAP explanation
            # ------------------------------------------------

            explanation_text = row.get("explanation", "")

            if explanation_text:
                try:
                    row["explanation"] = json.loads(
                        explanation_text
                    )
                except (
                    json.JSONDecodeError,
                    TypeError
                ):
                    row["explanation"] = None
            else:
                row["explanation"] = None

            explanation_data = row.get("explanation")
            enforcement_data = (
                explanation_data.get("_enforcement", {})
                if isinstance(explanation_data, dict)
                else {}
            )
            row["event_details"] = (
                explanation_data.get("_event_details", {})
                if isinstance(explanation_data, dict)
                else {}
            )

            # ------------------------------------------------
            # Parse attack probability
            # ------------------------------------------------

            try:
                row["attack_probability"] = float(
                    row.get("attack_probability") or 0
                )
            except (
                ValueError,
                TypeError
            ):
                row["attack_probability"] = 0.0

            # ------------------------------------------------
            # Normalize missing enforcement fields.
            #
            # Older CSV rows may not contain these fields.
            # Empty status means the outcome is unknown.
            # Do not assume the firewall succeeded.
            # ------------------------------------------------

            row.setdefault(
                "enforcement_status",
                ""
            )

            row.setdefault(
                "enforcement_message",
                ""
            )

            row.setdefault(
                "firewall_rule",
                ""
            )

            # Preserve these values as strings so the
            # dashboard can display the recorded status.
            row["enforcement_status"] = str(
                row.get("enforcement_status")
                or enforcement_data.get("status")
                or ""
            ).strip().upper()

            row["enforcement_message"] = str(
                row.get("enforcement_message")
                or enforcement_data.get("message")
                or ""
            )

            row["firewall_rule"] = str(
                row.get("firewall_rule")
                or enforcement_data.get("rule")
                or ""
            )

            row["firewall_reason"] = str(
                enforcement_data.get("firewall_reason")
                or (
                    row.get("explanation", {}).get("_firewall_reason", "")
                    if isinstance(row.get("explanation"), dict)
                    else ""
                )
                or ""
            )

            event_details = row.get("event_details", {})
            row["is_test_sample"] = (
                str(row.get("protocol", "")).strip().upper() == "TEST"
                or str(row.get("destination_ip", "")).strip().upper() == "DATASET_SAMPLE"
                or (
                    isinstance(event_details, dict)
                    and event_details.get("is_test_sample") is True
                )
            )

            # Normalize decision and prediction labels.
            row["firewall_action"] = str(
                row.get("firewall_action") or ""
            ).strip().upper()

            row["prediction"] = str(
                row.get("prediction") or ""
            ).strip().upper()

            if (
                isinstance(row.get("explanation"), dict)
                and row["prediction"] in ("NORMAL", "ATTACK")
            ):
                simple_reason = build_plain_reason(
                    row["explanation"],
                    row["prediction"]
                )
                row["explanation"]["plain_reason"] = simple_reason
                row["explanation"]["summary"] = simple_reason

            predictions.append(row)

    return predictions


# ============================================================
# PREDICTION HISTORY API
# ============================================================

@app.get("/api/predictions")
def get_predictions():

    if not os.path.isfile(PREDICTIONS_FILE):
        return {
            "total": 0,
            "predictions": [],
            "events": [],
            "message": (
                "Prediction history is not available yet."
            )
        }

    try:
        predictions = read_predictions()

    except (
        OSError,
        csv.Error
    ) as error:
        return {
            "total": 0,
            "predictions": [],
            "events": [],
            "error": str(error)
        }

    # Compute lifecycle state in chronological order before reversing the
    # display list. This preserves the original order for same-time events.
    current_block_states = get_current_block_states(predictions)
    # Model decisions already have their own response list. Return only
    # lifecycle rows here so the dashboard can render recovery history
    # without duplicating the full prediction log in every refresh.
    events = [
        row for row in reversed(predictions)
        if row.get("prediction") == "SYSTEM"
    ]
    predictions.reverse()
    model_predictions = []
    for row in predictions:
        if row.get("prediction") not in ("NORMAL", "ATTACK"):
            continue
        state = current_block_states.get(row.get("source_ip"), {})
        row["current_block_state"] = state.get("status", "UNKNOWN")
        row["current_recovery_state"] = state.get("recovery_state", "UNKNOWN")
        row["current_recovery_due_at"] = state.get("recovery_due_at", "")
        row["block_threshold"] = get_block_threshold()
        model_predictions.append(row)

    return {
        "total": len(model_predictions),
        "predictions": model_predictions,
        "events": events
    }


def _feedback_key(row):
    return str(row.get("record_id", ""))


@app.get("/api/feedback")
def get_alert_feedback():
    """Return the latest saved human review for each alert record."""
    if not os.path.isfile(FEEDBACK_FILE):
        return {"feedback": []}
    try:
        with feedback_lock, open(FEEDBACK_FILE, "r", newline="", encoding="utf-8-sig") as file:
            records = list(csv.DictReader(file))
        latest = {}
        for row in records:
            latest[_feedback_key(row)] = row
        return {"feedback": list(reversed(list(latest.values())))}
    except (OSError, csv.Error) as error:
        return {"feedback": [], "error": str(error)}


@app.post("/api/feedback")
def save_alert_feedback(feedback: AlertFeedback):
    """Save a review label for a real, current-session attack alert."""
    matching_alert = next((
        row for row in read_predictions()
        if row.get("record_id") == feedback.record_id
        and row.get("timestamp") == feedback.record_timestamp
        and row.get("source_ip") == feedback.source_ip
        and row.get("destination_ip") == feedback.destination_ip
        and row.get("prediction") == "ATTACK"
    ), None)
    if matching_alert is None:
        raise HTTPException(
            status_code=404,
            detail="This alert is not available in the current live session."
        )

    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    fieldnames = [
        "feedback_at", "record_id", "record_timestamp", "source_ip",
        "destination_ip", "feedback"
    ]
    try:
        with feedback_lock:
            needs_header = (
                not os.path.isfile(FEEDBACK_FILE)
                or os.path.getsize(FEEDBACK_FILE) == 0
            )
            with open(FEEDBACK_FILE, "a", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                if needs_header:
                    writer.writeheader()
                writer.writerow({
                    "feedback_at": datetime.now().isoformat(timespec="seconds"),
                    "record_id": feedback.record_id,
                    "record_timestamp": feedback.record_timestamp,
                    "source_ip": feedback.source_ip,
                    "destination_ip": feedback.destination_ip,
                    "feedback": feedback.feedback
                })
                file.flush()
    except OSError as error:
        raise HTTPException(status_code=500, detail="Could not save alert feedback.") from error

    return {"saved": True, "feedback": feedback.feedback}


def _sha256_file(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.get("/api/model-quality")
def get_model_quality(refresh: bool = False):
    """Compute/cached held-out metrics for the exact saved model and data."""
    dataset_file = os.path.join(
        PROJECT_ROOT, "ai", "dataset", "processed", "sentinelai_training_data.csv"
    )
    if not os.path.isfile(MODEL_FILE):
        return {
            "available": False,
            "message": "The saved model file is missing."
        }
    if not os.path.isfile(dataset_file):
        return {"available": False, "message": "The labeled evaluation dataset is missing."}
    try:
        if refresh:
            _cached_model_evaluation.cache_clear()
        report = _cached_model_evaluation(
            _sha256_file(MODEL_FILE),
            _sha256_file(dataset_file),
            get_block_threshold()
        )
        return {"available": True, "report": report}
    except (OSError, ValueError, KeyError, ImportError) as error:
        return {"available": False, "message": f"Could not read the model evaluation: {error}"}


@lru_cache(maxsize=2)
def _cached_model_evaluation(model_digest, dataset_digest, block_threshold):
    # Hashes form the cache key, so a changed model or dataset is evaluated again.
    from ai.train.evaluate_model import evaluate_saved_model
    return evaluate_saved_model(block_threshold=block_threshold)


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_current_block_states(predictions):
    """Track each source's latest recorded block and recovery event."""
    states = {}
    for row in sorted(predictions, key=lambda item: item.get("timestamp", "")):
        source_ip = row.get("source_ip")
        action = row.get("firewall_action")
        status = row.get("enforcement_status")
        if not source_ip:
            continue
        if action == "BLOCK" and status == "BLOCKED":
            states[source_ip] = {
                "status": "ACTIVE",
                "recovery_state": "NOT_SCHEDULED",
                "recovery_due_at": ""
            }
        elif action in ("RECOVERY_SCHEDULED", "RECOVERY_EXTENDED") and status in ("SCHEDULED", "OBSERVING"):
            states[source_ip] = {
                "status": "ACTIVE",
                "recovery_state": "OBSERVING",
                "recovery_due_at": (
                    row.get("event_details", {}).get("due_at", "")
                    if isinstance(row.get("event_details"), dict)
                    else ""
                )
            }
        elif action == "RECOVERY_FAILED" and status == "FAILED":
            details = row.get("event_details", {})
            block_retained = (
                isinstance(details, dict)
                and details.get("block_retained") is True
            )
            states[source_ip] = {
                "status": "ACTIVE" if block_retained else "UNKNOWN",
                "recovery_state": "FAILED",
                "recovery_due_at": ""
            }
        elif action == "UNBLOCK" and status == "UNBLOCKED":
            states[source_ip] = {
                "status": "RECOVERED",
                "recovery_state": "RECOVERED",
                "recovery_due_at": ""
            }
    return states


def summarize_predictions(predictions):
    """Calculate dashboard metrics with prediction and rule-state counts apart."""
    model_rows = [
        row for row in predictions
        if row.get("prediction") in ("NORMAL", "ATTACK")
    ]
    traffic_rows = predictions
    normal = sum(row.get("prediction") == "NORMAL" for row in model_rows)
    attack = sum(row.get("prediction") == "ATTACK" for row in model_rows)
    probabilities = [row.get("attack_probability", 0) for row in model_rows]
    average_probability = sum(probabilities) / len(probabilities) if probabilities else 0

    allowed = sum(row.get("firewall_action") == "ALLOW" for row in model_rows)
    monitored = sum(row.get("firewall_action") == "MONITOR" for row in model_rows)
    block_attempts = sum(row.get("firewall_action") == "BLOCK" for row in model_rows)
    successful_blocks = sum(
        row.get("firewall_action") == "BLOCK"
        and row.get("enforcement_status") == "BLOCKED"
        for row in traffic_rows
    )
    failed_blocks = sum(
        row.get("firewall_action") == "BLOCK"
        and row.get("enforcement_status") == "FAILED"
        for row in traffic_rows
    )
    recovered_blocks = sum(
        row.get("firewall_action") == "UNBLOCK"
        and row.get("enforcement_status") == "UNBLOCKED"
        for row in traffic_rows
    )
    current_states = get_current_block_states(traffic_rows)
    active_blocks = sum(
        state.get("status") == "ACTIVE" for state in current_states.values()
    )
    latest_source_actions = {}
    for row in sorted(model_rows, key=lambda item: item.get("timestamp", "")):
        if row.get("source_ip"):
            latest_source_actions[row["source_ip"]] = row.get("firewall_action")
    being_watched_sources = {
        source_ip for source_ip, action in latest_source_actions.items()
        if action == "MONITOR"
    }
    being_watched_sources.update(
        source_ip for source_ip, state in current_states.items()
        if state.get("status") == "ACTIVE"
        and state.get("recovery_state") == "OBSERVING"
    )
    recovery_failures = sum(
        state.get("recovery_state") == "FAILED"
        for state in current_states.values()
    )

    return {
        "total_predictions": len(model_rows),
        "normal_predictions": normal,
        "attack_predictions": attack,
        "average_attack_probability": round(average_probability, 4),
        "allowed": allowed,
        "monitored": monitored,
        "being_watched": len(being_watched_sources),
        "blocked": successful_blocks,
        "block_attempts": block_attempts,
        "active_blocks": active_blocks,
        "recovered_blocks": recovered_blocks,
        "failed_blocks": failed_blocks,
        "recovery_failures": recovery_failures,
        "block_threshold": get_block_threshold(),
        "firewall_policy_status": (
            "CONFIGURATION_ERROR"
            if threshold_configuration_error()
            else "READY"
        ),
        "system_status": "active"
    }


@app.get("/api/stats")
def get_stats():
    if not os.path.isfile(PREDICTIONS_FILE):
        return summarize_predictions([])

    try:
        return summarize_predictions(read_predictions())
    except (OSError, csv.Error) as error:
        result = summarize_predictions([])
        result["system_status"] = "error"
        result["error"] = str(error)
        return result


# ============================================================
# ACTIVE NETWORK FLOWS API
# ============================================================

@app.get("/api/flows")
def get_flows():

    if not os.path.isfile(ACTIVE_FLOWS_FILE):
        return {
            "total_flows": 0,
            "flows": []
        }

    try:
        with open(
            ACTIVE_FLOWS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return {
                "total_flows": len(data),
                "flows": data
            }

        if isinstance(data, dict):
            flows = data.get("flows")

            if isinstance(flows, list):
                return {
                    **data,
                    "total_flows": data.get(
                        "total_flows",
                        len(flows)
                    ),
                    "flows": flows
                }

            return data

        return {
            "total_flows": 0,
            "flows": []
        }

    except (
        OSError,
        json.JSONDecodeError
    ):
        return {
            "total_flows": 0,
            "flows": []
        }
