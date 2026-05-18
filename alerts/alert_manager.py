"""
Alert generation module for creating and storing
security alerts detected by the monitoring system.
"""

from datetime import datetime


def generate_alert(severity, message):
    """
    Generate alert with severity and timestamp
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"[{severity}] {timestamp} - {message}"

    print(alert)

    with open("output/alerts.txt", "a") as file:
        file.write(alert + "\n")