# Main pipeline runner for Secure Cloud Network Monitor

import sys
import os

# Ensure project root is in Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Module imports
from cloud.s3_downloader import download_file
from parser.log_parser import parse_log_file
from alerts.alert_manager import generate_alert
from detection.rule_engine import evaluate_logs


def run_pipeline():
    try:
        print("=" * 50)
        print("Secure Cloud Network Monitoring Started")
        print("=" * 50)

        # Step 1: Download logs
        print("\n[1/3] Downloading logs...")
        if not download_file(
            "logs/sample_log.txt",
            "output/downloaded_sample_log.txt"
        ):
            print("ERROR: Failed to download logs. Exiting pipeline.")
            return

        # Step 2: Parse logs
        print("\n[2/3] Parsing logs...")
        logs = parse_log_file("output/downloaded_sample_log.txt")

        if not logs:
            print("WARNING: No valid logs found. Exiting pipeline.")
            return

        # Step 3: Threat Detection
        print("\n[3/3] Running threat detection...\n")

        alerts = evaluate_logs(logs)

        if not alerts:
            print("No threats detected.")
            return

        # Generate alerts
        for alert in alerts:
            msg = f"{alert['severity']} - {alert['message']} (Device: {alert['device']})"
            generate_alert(msg)

        print("\nSUCCESS: Pipeline completed.")

    except FileNotFoundError:
        print("ERROR: Required file not found.")
    except PermissionError:
        print("ERROR: Permission denied.")
    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))


if __name__ == "__main__":
    run_pipeline()