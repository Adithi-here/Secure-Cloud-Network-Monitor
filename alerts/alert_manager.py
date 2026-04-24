# Generate and save security alerts

from datetime import datetime


def generate_alert(message):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert = f"[ALERT] {timestamp} - {message}"

        print(alert)

        with open("output/alerts.txt", "a") as file:
            file.write(alert + "\n")

        return True

    except Exception as e:
        print("ERROR:", str(e))
        return False


def generate_multiple_alerts(alert_list):
    for item in alert_list:
        generate_alert(item)


if __name__ == "__main__":
    sample_alerts = [
        "Failed login attempt from 192.168.1.20",
        "Port scan detected from 10.0.0.5"
    ]

    generate_multiple_alerts(sample_alerts)