"""Recover firewall blocks only after a monitored quiet observation window."""

import json
import os
import threading
import time
from datetime import datetime, timedelta

from ai.firewall.adaptive_firewall import reset_source_history
from ai.firewall.firewall_enforcer import remove_block
from ai.logs.prediction_logger import log_firewall_event
from ai.logs.session_state import get_capture_status


DEFAULT_QUIET_PERIOD_SECONDS = 60
MIN_QUIET_PERIOD_SECONDS = 10
MAX_QUIET_PERIOD_SECONDS = 3600

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SETTINGS_FILE = os.path.join(PROJECT_ROOT, "ai", "logs", "recovery_settings.json")

recovery_tasks = {}
recovery_results = {}
recovery_states = {}
recovery_lock = threading.RLock()
recovery_condition = threading.Condition(recovery_lock)


def get_recovery_duration():
    """Return the persisted quiet-period duration, falling back safely."""
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as file:
            value = int(json.load(file).get("duration_seconds"))
        if MIN_QUIET_PERIOD_SECONDS <= value <= MAX_QUIET_PERIOD_SECONDS:
            return value
    except (OSError, ValueError, TypeError, json.JSONDecodeError, AttributeError):
        pass
    return DEFAULT_QUIET_PERIOD_SECONDS


def set_recovery_duration(duration_seconds):
    """Persist a bounded quiet period for blocks created from now on."""
    try:
        duration_seconds = int(duration_seconds)
    except (TypeError, ValueError) as error:
        raise ValueError("Recovery time must be a whole number of seconds.") from error
    if not MIN_QUIET_PERIOD_SECONDS <= duration_seconds <= MAX_QUIET_PERIOD_SECONDS:
        raise ValueError(
            f"Recovery time must be between {MIN_QUIET_PERIOD_SECONDS} and "
            f"{MAX_QUIET_PERIOD_SECONDS} seconds."
        )

    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    temporary_file = SETTINGS_FILE + ".tmp"
    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump({"duration_seconds": duration_seconds}, file)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary_file, SETTINGS_FILE)
    return duration_seconds


def _due_at(state):
    remaining = max(0, state["last_suspicious_monotonic"] + state["duration"] - time.monotonic())
    return (datetime.now() + timedelta(seconds=remaining)).isoformat(timespec="seconds")


def _log_observation(source_ip, state, action, message):
    details = dict(state["event_details"])
    details.update({
        "due_at": _due_at(state),
        "duration_seconds": state["duration"],
        "recovery_state": "OBSERVING",
        "observation_started_at": state["started_at"]
    })
    try:
        log_firewall_event(
            source_ip,
            action,
            "OBSERVING" if action == "RECOVERY_EXTENDED" else "SCHEDULED",
            message,
            event_details=details
        )
    except Exception as error:
        print(f"[SELF-HEALING] Could not log observation state: {error}")


def note_suspicious_activity(source_ip):
    """Restart the quiet period when the detector sees another threat."""
    if not source_ip:
        return False
    with recovery_condition:
        state = recovery_states.get(source_ip)
        if not state:
            return False
        state["last_suspicious_monotonic"] = time.monotonic()
        state["last_suspicious_at"] = datetime.now().isoformat(timespec="seconds")
        recovery_results[source_ip] = {
            "status": "OBSERVING",
            "message": "Suspicious activity was detected; the quiet-period timer restarted.",
            "due_at": _due_at(state)
        }
        recovery_condition.notify_all()

    _log_observation(
        source_ip,
        state,
        "RECOVERY_EXTENDED",
        "Suspicious activity was detected. The block remains in place and the quiet-period timer restarted."
    )
    return True


def schedule_recovery(source_ip, duration=None, event_details=None):
    """Start a quiet-period observer after a firewall rule was successfully placed.

    Production recovery requires a healthy packet-capture heartbeat throughout
    the window. Explicitly tagged controlled tests use a simulated quiet window.
    """
    if not source_ip:
        return False
    if duration is None:
        duration = get_recovery_duration()
    try:
        duration = float(duration)
    except (TypeError, ValueError):
        return False
    if duration < 0:
        return False

    details = dict(event_details or {})
    is_test = details.get("is_test_sample") is True
    state = {
        "duration": duration,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "last_suspicious_monotonic": time.monotonic(),
        "last_suspicious_at": datetime.now().isoformat(timespec="seconds"),
        "event_details": details,
        "is_test_sample": is_test
    }

    with recovery_condition:
        existing = recovery_tasks.get(source_ip)
        if existing and existing.is_alive():
            return False
        recovery_results.pop(source_ip, None)
        recovery_states[source_ip] = state
        recovery_results[source_ip] = {
            "status": "OBSERVING",
            "message": f"Watching for suspicious activity for {duration:g} seconds.",
            "due_at": _due_at(state)
        }
        thread = threading.Thread(
            target=_recover_source,
            args=(source_ip,),
            daemon=True,
            name=f"sentinelai-recovery-{source_ip}"
        )
        recovery_tasks[source_ip] = thread

    _log_observation(
        source_ip,
        state,
        "RECOVERY_SCHEDULED",
        f"Block remains in place while SentinelAI watches for suspicious activity for {duration:g} seconds."
    )
    thread.start()
    print(f"[SELF-HEALING] {source_ip} observed for a {duration:g}-second quiet period")
    return True


def _finish_without_unblocking(source_ip, message, event_details):
    result = {"status": "FAILED", "message": message, "block_retained": True}
    recovery_results[source_ip] = result
    try:
        log_firewall_event(
            source_ip,
            "RECOVERY_FAILED",
            "FAILED",
            message,
            event_details={**event_details, "block_retained": True}
        )
    except Exception as error:
        print(f"[SELF-HEALING] Could not log recovery hold: {error}")
    print(f"[SELF-HEALING] {source_ip} remains blocked: {message}")


def _recover_source(source_ip):
    """Unblock only after the full quiet period and healthy monitoring."""
    try:
        while True:
            with recovery_condition:
                state = recovery_states.get(source_ip)
                if not state:
                    return
                remaining = (
                    state["last_suspicious_monotonic"]
                    + state["duration"]
                    - time.monotonic()
                )
                if remaining <= 0:
                    break
                is_test = state["is_test_sample"]
                event_details = dict(state["event_details"])

            if not is_test:
                capture = get_capture_status()
                if capture.get("status") != "RUNNING":
                    _finish_without_unblocking(
                        source_ip,
                        "Traffic monitoring is unavailable, so SentinelAI kept the block in place instead of assuming the source was safe.",
                        {**event_details, "capture_status": capture.get("status", "UNKNOWN")}
                    )
                    return

            with recovery_condition:
                state = recovery_states.get(source_ip)
                if not state:
                    return
                remaining = (
                    state["last_suspicious_monotonic"]
                    + state["duration"]
                    - time.monotonic()
                )
                if remaining > 0:
                    recovery_condition.wait(timeout=min(remaining, 1.0))

        # Confirm monitoring is still healthy at the point of recovery.
        with recovery_lock:
            state = recovery_states.get(source_ip)
            if not state:
                return
            event_details = dict(state["event_details"])
            is_test = state["is_test_sample"]
        if not is_test:
            capture = get_capture_status()
            if capture.get("status") != "RUNNING":
                _finish_without_unblocking(
                    source_ip,
                    "Traffic monitoring stopped before the quiet period completed; SentinelAI kept the block in place.",
                    {**event_details, "capture_status": capture.get("status", "UNKNOWN")}
                )
                return

        result = {"status": "FAILED", "message": "Recovery did not run."}
        for attempt in range(3):
            try:
                result = remove_block(source_ip)
            except Exception as error:
                result = {"status": "FAILED", "message": str(error)}
            recovery_results[source_ip] = result
            if result.get("status") == "UNBLOCKED":
                reset_source_history(source_ip)
                try:
                    log_firewall_event(
                        source_ip,
                        "UNBLOCK",
                        "UNBLOCKED",
                        "The firewall block was removed after the full quiet period completed with no suspicious activity observed.",
                        result.get("rule_name", ""),
                        event_details={
                            **event_details,
                            "quiet_period_seconds": state["duration"],
                            "last_suspicious_at": state["last_suspicious_at"]
                        }
                    )
                except Exception as error:
                    print(f"[SELF-HEALING] Could not log recovery for {source_ip}: {error}")
                break
            if attempt < 2:
                time.sleep(1)

        if result.get("status") != "UNBLOCKED":
            try:
                log_firewall_event(
                    source_ip,
                    "RECOVERY_FAILED",
                    "FAILED",
                    result.get("message", "Firewall recovery failed; block state could not be confirmed."),
                    result.get("rule_name", ""),
                    event_details={**event_details, "block_retained": False}
                )
            except Exception as error:
                print(f"[SELF-HEALING] Could not log recovery failure for {source_ip}: {error}")
        print(f"[SELF-HEALING] {source_ip} -> {result['status']} | {result['message']}")
    finally:
        with recovery_condition:
            recovery_tasks.pop(source_ip, None)
            recovery_states.pop(source_ip, None)
