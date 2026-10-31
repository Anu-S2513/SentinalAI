import platform
import subprocess
import ipaddress

from ai.firewall.firewall_policy import source_ip_protection

RULE_PREFIX = "SentinelAI-Block"


def block_ip(source_ip):
    """
    Create a Windows Firewall rule that blocks
    inbound traffic from the specified source IP.
    """

    if platform.system() != "Windows":
        return {
            "status": "FAILED",
            "message": "Real firewall enforcement currently supports Windows only."
        }

    protected, protection_reason = source_ip_protection(source_ip)
    if protected:
        return {
            "status": "FAILED",
            "message": protection_reason
        }
    if ":" in str(source_ip):
        return {
            "status": "FAILED",
            "message": "This Windows Firewall rule currently supports IPv4 sources only."
        }

    rule_name = f"{RULE_PREFIX}-{source_ip}"

    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={source_ip}",
        "enable=yes"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return {
                "status": "BLOCKED",
                "message": f"Windows Firewall rule created for {source_ip}",
                "rule_name": rule_name
            }

        return {
            "status": "FAILED",
            "message": result.stderr.strip() or result.stdout.strip()
        }

    except Exception as e:
        return {
            "status": "FAILED",
            "message": str(e)
        }


def remove_block(source_ip):
    """
    Remove the SentinelAI Windows Firewall rule
    for the specified source IP.
    """

    if platform.system() != "Windows":
        return {
            "status": "FAILED",
            "message": "Real firewall enforcement currently supports Windows only."
        }

    try:
        parsed_ip = ipaddress.ip_address(str(source_ip).strip())
    except (ValueError, TypeError):
        return {
            "status": "FAILED",
            "message": "A valid source IP is required to remove a firewall rule."
        }
    if parsed_ip.version != 4:
        return {
            "status": "FAILED",
            "message": "This Windows Firewall rule currently supports IPv4 sources only."
        }

    rule_name = f"{RULE_PREFIX}-{source_ip}"

    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return {
                "status": "UNBLOCKED",
                "message": f"Windows Firewall rule removed for {source_ip}",
                "rule_name": rule_name
            }

        return {
            "status": "FAILED",
            "message": result.stderr.strip() or result.stdout.strip()
        }

    except Exception as e:
        return {
            "status": "FAILED",
            "message": str(e)
        }


def enforce_firewall_action(action, source_ip=None):
    """
    Execute the firewall decision.

    ALLOW   -> allow traffic
    MONITOR -> no blocking action
    BLOCK   -> create a real Windows Firewall block rule
    """

    if action == "ALLOW":

        return {
            "status": "ALLOWED",
            "message": "Traffic allowed."
        }

    elif action == "MONITOR":

        return {
            "status": "MONITORING",
            "message": "Traffic is being monitored."
        }

    elif action == "BLOCK":

        return block_ip(source_ip)

    else:

        return {
            "status": "UNKNOWN",
            "message": "Unknown firewall action."
        }
