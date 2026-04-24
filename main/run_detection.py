# Main pipeline runner

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cloud.s3_downloader import download_file
from parser.log_parser import parse_log_file
from alerts.alert_manager import generate_alert


def run_pipeline():
    try:
        print("=" * 50)
        print("Secure Cloud Network Monitoring Started")
        print("=" * 50)

        print("\n[1/3] Downloading logs...")
        if not download_file(
            "logs/sample_log.txt",
            "output/downloaded_sample_log.txt"
        ):
            return

        print("\n[2/3] Parsing logs...")
        logs = parse_log_file("output/downloaded_sample_log.txt")

        if not logs:
            print("WARNING: No logs available.")
            return

        print("\n[3/3] Generating alerts...")

        for log in logs:
            msg = f"{log['event']} from {log['ip']} on {log['device']}"
            generate_alert(msg)

        print("\nSUCCESS: Pipeline completed.")

    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))


if __name__ == "__main__":
    run_pipeline()