# Applies threat detection rules on parsed logs

from detection.threat_rules import ALL_RULES


def evaluate_log(log):
    """
    Runs all rules on a single log entry
    Returns list of triggered alerts
    """
    alerts = []

    for rule in ALL_RULES:
        try:
            triggered, message, severity = rule(log)

            if triggered:
                alerts.append({
                    "message": message,
                    "severity": severity,
                    "ip": log["ip"],
                    "device": log["device"]
                })

        except Exception as e:
            print(f"Rule error: {str(e)}")

    return alerts


def evaluate_logs(logs):
    """
    Runs detection on multiple logs
    """
    all_alerts = []

    for log in logs:
        results = evaluate_log(log)
        all_alerts.extend(results)

    return all_alerts


# Test run
if __name__ == "__main__":
    sample_log = {
        "date": "Apr 16",
        "time": "10:15:00",
        "device": "Router1",
        "event": "Failed login",
        "ip": "192.168.1.20"
    }

    alerts = evaluate_log(sample_log)

    for a in alerts:
        print(a)