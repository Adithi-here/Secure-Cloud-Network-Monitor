"""
Rule engine for evaluating parsed logs against
defined threat detection rules.

The engine processes log entries, applies all
available rules, and generates alerts for
detected suspicious activities.

Designed to be modular and extensible for
future advanced threat detection features.
"""

from detection.threat_rules import ALL_RULES


def evaluate_logs(logs):
    """
    Evaluate parsed logs against all threat rules
    """

    alerts = []

    for log in logs:

        for rule in ALL_RULES:

            result = rule(log)

            if result["detected"]:

                alerts.append({
                    "severity": result["severity"],
                    "message": result["message"],
                    "ip": log["ip"],
                    "device": log["device"]
                })

    return alerts