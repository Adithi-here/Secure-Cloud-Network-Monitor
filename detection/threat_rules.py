"""
Threat detection rules for identifying suspicious activities
from parsed network logs.

Current threats detected:
- Failed login attempts
- Port scanning activity
- Multiple denied connections
- Brute-force login attacks
- DDoS / traffic flood attacks
- Suspicious IP correlation
- SSH brute-force attacks
- Blacklisted IP activity
- Beaconing behavior
- Device anomaly spikes
- DNS flood activity
"""

from collections import defaultdict
from datetime import timedelta


# -------------------------------------------------
# Trackers
# -------------------------------------------------
failed_login_tracker = defaultdict(list)

traffic_tracker = defaultdict(list)

suspicious_activity_tracker = defaultdict(set)

ssh_tracker = defaultdict(list)

beacon_tracker = defaultdict(list)

device_event_tracker = defaultdict(list)

dns_tracker = defaultdict(list)


# -------------------------------------------------
# Blacklisted IPs
# -------------------------------------------------
BLACKLISTED_IPS = [
    "45.33.22.11",
    "99.99.99.99"
]


# -------------------------------------------------
# Rule: Failed Login
# -------------------------------------------------
def failed_login_rule(log):

    if "failed login" in log["event"].lower():

        return {
            "detected": True,
            "severity": "MEDIUM",
            "message": "Failed login attempt detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Port Scan
# -------------------------------------------------
def port_scan_rule(log):

    if "port scan" in log["event"].lower():

        return {
            "detected": True,
            "severity": "HIGH",
            "message": "Port scan detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Denied Connections
# -------------------------------------------------
def denied_connections_rule(log):

    if "denied connections" in log["event"].lower():

        return {
            "detected": True,
            "severity": "MEDIUM",
            "message": "Multiple denied connections detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Brute Force Detection
# -------------------------------------------------
def brute_force_rule(log):

    if "failed login" not in log["event"].lower():

        return {
            "detected": False
        }

    ip = log["ip"]
    timestamp = log["timestamp"]

    failed_login_tracker[ip].append(timestamp)

    recent_attempts = []

    for attempt_time in failed_login_tracker[ip]:

        if timestamp - attempt_time <= timedelta(seconds=60):
            recent_attempts.append(attempt_time)

    failed_login_tracker[ip] = recent_attempts

    if len(recent_attempts) >= 5:

        return {
            "detected": True,
            "severity": "CRITICAL",
            "message": "Brute-force attack suspected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: DDoS Detection
# -------------------------------------------------
def ddos_rule(log):

    if "traffic request" not in log["event"].lower():

        return {
            "detected": False
        }

    ip = log["ip"]
    timestamp = log["timestamp"]

    traffic_tracker[ip].append(timestamp)

    recent_requests = []

    for request_time in traffic_tracker[ip]:

        if timestamp - request_time <= timedelta(seconds=30):
            recent_requests.append(request_time)

    traffic_tracker[ip] = recent_requests

    if len(recent_requests) >= 10:

        return {
            "detected": True,
            "severity": "CRITICAL",
            "message": "Possible DDoS / traffic flood detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Suspicious IP Correlation
# -------------------------------------------------
def suspicious_ip_correlation_rule(log):

    ip = log["ip"]
    event = log["event"].lower()

    if "failed login" in event:
        suspicious_activity_tracker[ip].add("failed_login")

    if "port scan" in event:
        suspicious_activity_tracker[ip].add("port_scan")

    if "denied connections" in event:
        suspicious_activity_tracker[ip].add("denied_connections")

    activity_count = len(suspicious_activity_tracker[ip])

    if activity_count >= 3:

        return {
            "detected": True,
            "severity": "CRITICAL",
            "message": "Coordinated multi-stage attack suspected"
        }

    if activity_count >= 2:

        return {
            "detected": True,
            "severity": "HIGH",
            "message": "Suspicious correlated attacker activity detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: SSH Brute Force
# -------------------------------------------------
def ssh_bruteforce_rule(log):

    if "ssh authentication failed" not in log["event"].lower():

        return {
            "detected": False
        }

    ip = log["ip"]
    timestamp = log["timestamp"]

    ssh_tracker[ip].append(timestamp)

    recent_attempts = []

    for attempt_time in ssh_tracker[ip]:

        if timestamp - attempt_time <= timedelta(seconds=60):
            recent_attempts.append(attempt_time)

    ssh_tracker[ip] = recent_attempts

    if len(recent_attempts) >= 4:

        return {
            "detected": True,
            "severity": "CRITICAL",
            "message": "SSH brute-force attack suspected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Blacklisted IP Detection
# -------------------------------------------------
def blacklisted_ip_rule(log):

    if log["ip"] in BLACKLISTED_IPS:

        return {
            "detected": True,
            "severity": "CRITICAL",
            "message": "Blacklisted IP detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Beaconing Detection
# -------------------------------------------------
def beaconing_rule(log):

    # Beacon-specific traffic only
    if "beacon ping" not in log["event"].lower():

        return {
            "detected": False
        }

    ip = log["ip"]
    timestamp = log["timestamp"]

    beacon_tracker[ip].append(timestamp)

    if len(beacon_tracker[ip]) < 4:

        return {
            "detected": False
        }

    intervals = []

    for i in range(1, len(beacon_tracker[ip])):

        diff = (
            beacon_tracker[ip][i]
            - beacon_tracker[ip][i - 1]
        ).seconds

        intervals.append(diff)

    # Detect repeated equal intervals
    if len(set(intervals[-3:])) == 1:

        return {
            "detected": True,
            "severity": "HIGH",
            "message": "Beaconing behavior detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: Device Anomaly Detection
# -------------------------------------------------
def device_anomaly_rule(log):

    device = log["device"]
    timestamp = log["timestamp"]

    device_event_tracker[device].append(timestamp)

    recent_events = []

    for event_time in device_event_tracker[device]:

        if timestamp - event_time <= timedelta(seconds=30):
            recent_events.append(event_time)

    device_event_tracker[device] = recent_events

    if len(recent_events) >= 15:

        return {
            "detected": True,
            "severity": "HIGH",
            "message": "Device anomaly spike detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# Rule: DNS Flood Detection
# -------------------------------------------------
def dns_flood_rule(log):

    if "dns query" not in log["event"].lower():

        return {
            "detected": False
        }

    ip = log["ip"]
    timestamp = log["timestamp"]

    dns_tracker[ip].append(timestamp)

    recent_queries = []

    for query_time in dns_tracker[ip]:

        if timestamp - query_time <= timedelta(seconds=20):
            recent_queries.append(query_time)

    dns_tracker[ip] = recent_queries

    if len(recent_queries) >= 8:

        return {
            "detected": True,
            "severity": "HIGH",
            "message": "DNS flood activity detected"
        }

    return {
        "detected": False
    }


# -------------------------------------------------
# List of All Rules
# -------------------------------------------------
ALL_RULES = [
    failed_login_rule,
    brute_force_rule,
    port_scan_rule,
    denied_connections_rule,
    ddos_rule,
    suspicious_ip_correlation_rule,
    ssh_bruteforce_rule,
    blacklisted_ip_rule,
    beaconing_rule,
    device_anomaly_rule,
    dns_flood_rule
]