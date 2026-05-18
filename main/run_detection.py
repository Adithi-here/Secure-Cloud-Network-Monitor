"""
Main pipeline runner for the Secure Cloud-Enabled
Network Monitoring System.
"""

import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from cloud.s3_downloader import download_file
from parser.log_parser import parse_log_file
from detection.rule_engine import evaluate_logs
from alerts.alert_manager import generate_alert


def run_pipeline():

    try:

        print("=" * 50)
        print("Secure Cloud Network Monitoring Started")
        print("=" * 50)

        # -------------------------------------------------
        # Step 1 - Download Logs
        # -------------------------------------------------
        print("\n[1/3] Downloading logs...")

        success = download_file(
            "logs/sample_log.txt",
            "output/downloaded_sample_log.txt"
        )

        if not success:
            print("ERROR: Failed to download logs.")
            return

        # -------------------------------------------------
        # Step 2 - Parse Logs
        # -------------------------------------------------
        print("\n[2/3] Parsing logs...")

        logs = parse_log_file(
            "output/downloaded_sample_log.txt"
        )

        if not logs:
            print("WARNING: No logs available.")
            return

        # -------------------------------------------------
        # Step 3 - Threat Detection
        # -------------------------------------------------
        print("\n[3/3] Running threat detection...")

        alerts = evaluate_logs(logs)

        if not alerts:
            print("No threats detected.")
            return

        # -------------------------------------------------
        # Generate Alerts
        # -------------------------------------------------
        print("\nGenerating alerts...\n")

        for alert in alerts:

            msg = (
                f"{alert['message']} "
                f"from {alert['ip']} "
                f"on {alert['device']}"
            )

            generate_alert(
                alert["severity"],
                msg
            )

        print("\nSUCCESS: Pipeline completed.")

    except Exception as e:

        print("\nUNEXPECTED ERROR:")
        print(str(e))


if __name__ == "__main__":
    run_pipeline()