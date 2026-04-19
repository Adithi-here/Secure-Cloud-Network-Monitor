# This file manages alert generation.
# It saves alerts into an output file
# and prints alerts on screen.

from datetime import datetime


def generate_alert(message):
    """
    Creates one alert message with timestamp.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"[ALERT] {timestamp} - {message}"

    print(alert)

    with open("output/alerts.txt", "a") as file:
        file.write(alert + "\n")


def generate_multiple_alerts(alert_list):
    """
    Creates multiple alerts from a list.
    """

    for alert in alert_list:
        generate_alert(alert)


# Test run
if __name__ == "__main__":
    sample_alerts = [
        "Failed login attempt from 192.168.1.20",
        "Port scan detected from 10.0.0.5",
        "Multiple denied connections from 172.16.0.8"
    ]

    generate_multiple_alerts(sample_alerts)