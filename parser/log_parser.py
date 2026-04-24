# Parse raw logs into structured records

import re


def parse_log_line(line):
    pattern = r"(\w+\s+\d+)\s+(\d+:\d+:\d+)\s+(\w+)\s+(.+)\sfrom\s([\d\.]+)"

    match = re.match(pattern, line)

    if match:
        return {
            "date": match.group(1),
            "time": match.group(2),
            "device": match.group(3),
            "event": match.group(4),
            "ip": match.group(5)
        }

    return None


def parse_log_file(file_path):
    parsed_logs = []

    try:
        print("\nReading log file...")

        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()

                if line:
                    result = parse_log_line(line)

                    if result:
                        parsed_logs.append(result)

        print(f"SUCCESS: Parsed {len(parsed_logs)} log entries.")
        return parsed_logs

    except FileNotFoundError:
        print("ERROR: Log file not found.")
    except Exception as e:
        print("ERROR:", str(e))

    return []


if __name__ == "__main__":
    logs = parse_log_file("output/downloaded_sample_log.txt")

    for log in logs:
        print(log)