# This file parses raw log lines into structured records.
# It is part of the log processing module.
# Parsed output will later be used for threat detection.

import re

def parse_log_line(line):
    """
    Parses one log line and extracts:
    date, time, device, event, ip
    """

    # Regular expression for sample log format
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
    """
    Reads log file and parses all lines.
    Returns list of structured records.
    """

    parsed_logs = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            if line:
                result = parse_log_line(line)

                if result:
                    parsed_logs.append(result)

    return parsed_logs


# Test run
if __name__ == "__main__":
    logs = parse_log_file("output/downloaded_sample_log.txt")

    for log in logs:
        print(log)