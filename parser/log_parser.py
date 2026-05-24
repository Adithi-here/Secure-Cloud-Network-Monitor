"""
Log parser module for converting raw network logs
into structured log objects for threat analysis.

The parser performs:
- Log normalization
- Timestamp parsing
- Chronological ordering
- Structured conversion

This ensures reliable behavioral and time-based
threat correlation in the detection engine.
"""

from datetime import datetime


def parse_log_file(file_path):
    """
    Parse log file and return structured logs
    """

    logs = []

    try:

        print("\nReading log file...")

        with open(file_path, "r") as file:

            lines = file.readlines()

        for line in lines:

            try:

                parts = line.strip().split()

                # -------------------------------------------------
                # Expected Log Format:
                # YYYY-MM-DD HH:MM:SS DEVICE EVENT IP
                # -------------------------------------------------

                date = parts[0]
                time = parts[1]
                device = parts[2]
                ip = parts[-1]

                event = " ".join(parts[3:-1])

                # Convert timestamp string into datetime object
                timestamp = datetime.strptime(
                    f"{date} {time}",
                    "%Y-%m-%d %H:%M:%S"
                )

                # Store structured log object
                logs.append({
                    "timestamp": timestamp,
                    "device": device,
                    "event": event,
                    "ip": ip
                })

            except Exception:

                print(
                    f"WARNING: Skipping invalid log line -> "
                    f"{line.strip()}"
                )

        # -------------------------------------------------
        # Sort logs chronologically
        # -------------------------------------------------
        logs.sort(key=lambda x: x["timestamp"])

        print(f"SUCCESS: Parsed {len(logs)} log entries.")

        return logs

    except FileNotFoundError:

        print("ERROR: Log file not found.")
        return []

    except Exception as e:

        print("ERROR while parsing logs:")
        print(str(e))
        return []


# -------------------------------------------------
# Test Parser
# -------------------------------------------------
if __name__ == "__main__":

    parsed_logs = parse_log_file(
        "logs/sample_log.txt"
    )

    for log in parsed_logs:
        print(log)