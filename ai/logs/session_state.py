import json
import os
from datetime import datetime


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)
SESSION_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "active_flows.json"
)
CAPTURE_STATE_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "capture_state.json"
)
CAPTURE_STALE_SECONDS = 15


def start_new_session():
    """Mark a fresh session and clear stale flows in the existing snapshot."""
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
    started_at = datetime.now().isoformat(timespec="seconds")
    with open(SESSION_FILE, "w", encoding="utf-8") as file:
        json.dump({
            "session_started_at": started_at,
            "total_flows": 0,
            "flows": []
        }, file)
    return started_at


def update_capture_status(status):
    """Write a small heartbeat file for the dashboard health check."""
    os.makedirs(os.path.dirname(CAPTURE_STATE_FILE), exist_ok=True)
    state = {
        "status": str(status).strip().upper(),
        "updated_at": datetime.now().isoformat(timespec="seconds")
    }
    temporary_file = CAPTURE_STATE_FILE + ".tmp"
    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(state, file)
    os.replace(temporary_file, CAPTURE_STATE_FILE)
    return state


def get_capture_status():
    """Report RUNNING only while capture is refreshing its heartbeat."""
    if not os.path.isfile(CAPTURE_STATE_FILE):
        return {"status": "UNKNOWN", "age_seconds": None}
    try:
        with open(CAPTURE_STATE_FILE, "r", encoding="utf-8") as file:
            state = json.load(file)
        updated_at = datetime.fromisoformat(state["updated_at"])
        age = max(0, int((datetime.now() - updated_at).total_seconds()))
        status = str(state.get("status", "UNKNOWN")).strip().upper()
        if status == "RUNNING" and age > CAPTURE_STALE_SECONDS:
            status = "STALE"
        return {"status": status, "age_seconds": age}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"status": "UNKNOWN", "age_seconds": None}


def get_session_started_at():
    """Read the active session timestamp once for a batch of predictions."""
    if not os.path.isfile(SESSION_FILE):
        return None

    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as file:
            return datetime.fromisoformat(
                json.load(file)["session_started_at"]
            )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def is_current_session(timestamp, session_started_at=None):
    """Return whether a prediction belongs to the active capture run."""
    session_started_at = (
        session_started_at
        if session_started_at is not None
        else get_session_started_at()
    )
    if session_started_at is None:
        return True

    try:
        recorded_at = datetime.fromisoformat(str(timestamp))
        return recorded_at >= session_started_at
    except (ValueError, TypeError):
        return False
