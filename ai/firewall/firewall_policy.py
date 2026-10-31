"""Shared safeguards for automatic Windows Firewall rules."""

import ipaddress
import os


DEFAULT_BLOCK_THRESHOLD = 0.70
ALLOWLIST_ENV = "SENTINELAI_FIREWALL_ALLOWLIST"
THRESHOLD_ENV = "SENTINELAI_BLOCK_THRESHOLD"


def get_block_threshold():
    """Read the attack probability required for an immediate block.

    An invalid value disables automatic blocking by returning a threshold
    above 1.0. The dashboard health route reports the configuration issue.
    """
    raw_value = os.getenv(THRESHOLD_ENV, str(DEFAULT_BLOCK_THRESHOLD)).strip()
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return 1.01
    return value if 0.0 <= value <= 1.0 else 1.01


def threshold_configuration_error():
    raw_value = os.getenv(THRESHOLD_ENV)
    if raw_value is None:
        return ""
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return f"{THRESHOLD_ENV} must be a number from 0 to 1."
    if not 0.0 <= value <= 1.0:
        return f"{THRESHOLD_ENV} must be from 0 to 1."
    return ""


def source_ip_protection(source_ip):
    """Return (protected, reason) for invalid, loopback, or allowlisted IPs."""
    try:
        address = ipaddress.ip_address(str(source_ip).strip())
    except (ValueError, TypeError):
        return True, "Invalid source IP; automatic blocking was prevented."

    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return True, "Local or non-unicast source IP is protected."

    configured = os.getenv(ALLOWLIST_ENV, "")
    for entry in configured.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            # A malformed safety setting must fail closed.
            return True, f"Invalid allowlist entry '{entry}'; automatic blocking was prevented."
        if address.version == network.version and address in network:
            return True, f"Source IP is protected by {ALLOWLIST_ENV}."

    return False, ""
