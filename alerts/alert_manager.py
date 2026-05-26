from datetime import datetime
import os

ALERT_FILE = "alerts/alerts.txt"


def generate_alert(severity, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"[{severity}] {timestamp} - {message}"

    print(alert)

    os.makedirs("alerts", exist_ok=True)

    with open(ALERT_FILE, "a") as file:
        file.write(alert + "\n")