"""
Threat detection rules for identifying suspicious activities
from parsed network logs.

Current threats detected:
- Failed login attempts
- Port scanning activity
- Multiple denied connections

Each rule returns alert details and severity information.
The module is designed to support easy future expansion.
"""


def failed_login_rule(log):
    """
    Detect failed login attempts
    """
    if "failed login" in log["event"].lower():
        return {
            "detected": True,
            "severity": "MEDIUM",
            "message": "Failed login attempt detected"
        }

    return {
        "detected": False
    }


def port_scan_rule(log):
    """
    Detect port scanning activity
    """
    if "port scan" in log["event"].lower():
        return {
            "detected": True,
            "severity": "HIGH",
            "message": "Port scan detected"
        }

    return {
        "detected": False
    }


def denied_connections_rule(log):
    """
    Detect multiple denied connections
    """
    if "denied connections" in log["event"].lower():
        return {
            "detected": True,
            "severity": "MEDIUM",
            "message": "Multiple denied connections detected"
        }

    return {
        "detected": False
    }


# List of all rules (easily extendable)
ALL_RULES = [
    failed_login_rule,
    port_scan_rule,
    denied_connections_rule
]