from collections import defaultdict
import time

from ai.firewall.firewall_policy import (
    get_block_threshold,
    source_ip_protection,
    threshold_configuration_error
)

HISTORY_WINDOW_SECONDS = 60


# Store behavior history for each source IP
source_history = defaultdict(
    lambda: {
        "suspicious_count": 0,
        "attack_count": 0,
        "last_probability": 0.0,
        "last_seen": 0.0
    }
)


def get_firewall_action(
    prediction,
    attack_probability,
    source_ip=None
):
    probability = float(attack_probability)
    prediction = str(prediction).strip().upper()

    block_threshold = get_block_threshold()

    # A missing or protected source must never receive an automatic block.
    if source_ip is None:
        if prediction == "ATTACK" or probability >= 0.30:
            return "MONITOR"
        return "ALLOW"

    protected, _ = source_ip_protection(source_ip)
    if protected:
        return "MONITOR" if prediction == "ATTACK" or probability >= 0.30 else "ALLOW"

    if threshold_configuration_error():
        return "MONITOR" if prediction == "ATTACK" or probability >= 0.30 else "ALLOW"

    history = source_history[source_ip]
    now = time.monotonic()

    # Discard stale evidence so old observations do not cause a later block.
    if now - history["last_seen"] > HISTORY_WINDOW_SECONDS:
        history.update({
            "suspicious_count": 0,
            "attack_count": 0
        })

    history["last_probability"] = probability
    history["last_seen"] = now

    # Confirmed high-risk attack
    if prediction == "ATTACK" and probability >= block_threshold:
        history["attack_count"] += 1
        history["suspicious_count"] += 1
        return "BLOCK"

    # Suspicious behavior
    if probability >= 0.30:
        history["suspicious_count"] += 1

        # Repeated suspicious behavior
        if history["suspicious_count"] >= 3:
            return "BLOCK"

        return "MONITOR"

    # Normal behavior
    history["suspicious_count"] = 0
    history["attack_count"] = 0
    return "ALLOW"


def reset_source_history(source_ip):
    """Clear adaptive evidence after a successful firewall recovery."""
    if source_ip:
        source_history.pop(source_ip, None)


def get_firewall_reason(prediction, attack_probability, action, source_ip=None):
    """Return the short rule-based reason for a firewall decision."""
    probability = float(attack_probability)
    prediction = str(prediction).strip().upper()
    action = str(action).strip().upper()

    if threshold_configuration_error() and action == "MONITOR":
        return "Firewall threshold is misconfigured, so traffic is monitored safely."

    if source_ip:
        protected, _ = source_ip_protection(source_ip)
        if protected and action == "MONITOR":
            return "This source is protected from automatic blocking and is monitored."

    if action == "BLOCK" and prediction == "ATTACK" and probability >= get_block_threshold():
        return "Attack risk met the immediate block threshold."

    if action == "BLOCK" and source_ip:
        count = source_history.get(source_ip, {}).get("suspicious_count", 0)
        return f"Repeated suspicious readings reached the block limit ({count})."

    if action == "MONITOR":
        return "Suspicious risk reached the monitoring threshold."

    if action == "ALLOW":
        return "Risk stayed below the monitoring and block thresholds."

    return "No saved reason is available for this firewall decision."
