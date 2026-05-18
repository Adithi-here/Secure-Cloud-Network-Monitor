# Defines detection rules for network threats
# Each rule is a function that returns (True/False, message, severity)

def failed_login_rule(log):
    """
    Detect failed login attempts
    """
    if "failed login" in log["event"].lower():
        return True, f"Failed login from {log['ip']}", "MEDIUM"
    return False, None, None


def port_scan_rule(log):
    """
    Detect port scanning activity
    """
    if "port scan" in log["event"].lower():
        return True, f"Port scan detected from {log['ip']}", "HIGH"
    return False, None, None


def denied_connections_rule(log):
    """
    Detect multiple denied connections
    """
    if "denied connections" in log["event"].lower():
        return True, f"Multiple denied connections from {log['ip']}", "HIGH"
    return False, None, None


# List of all rules (easily extendable)
ALL_RULES = [
    failed_login_rule,
    port_scan_rule,
    denied_connections_rule
]