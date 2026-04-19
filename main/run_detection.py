# Main execution file for Secure Cloud Network Monitor
# Runs complete monitoring pipeline with proper error handling

import sys
import os

# Add project root directory to Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from cloud.s3_downloader import download_file
    from parser.log_parser import parse_log_file
    from alerts.alert_manager import generate_alert
except ImportError as e:
    print("ERROR: Required project modules could not be loaded.")
    print("Reason:", e)
    print("Please check project folder structure.")
    sys.exit(1)


def run_pipeline():
    try:
        print("=" * 50)
        print("Secure Cloud Network Monitoring Pipeline Started")
        print("=" * 50)

        # Step 1: Download logs
        print("\n[1/3] Downloading logs from AWS S3...")
        download_file(
            "logs/sample_log.txt",
            "output/downloaded_sample_log.txt"
        )

        # Step 2: Parse logs
        print("\n[2/3] Parsing downloaded logs...")
        parsed_logs = parse_log_file("output/downloaded_sample_log.txt")

        if not parsed_logs:
            print("WARNING: No valid log entries found.")
            return

        print(f"SUCCESS: Parsed {len(parsed_logs)} log entries.")

        # Step 3: Generate alerts
        print("\n[3/3] Generating alerts...")

        for log in parsed_logs:
            message = f"{log['event']} from {log['ip']} on {log['device']}"
            generate_alert(message)

        print("\nSUCCESS: Monitoring pipeline completed.")

    except FileNotFoundError:
        print("ERROR: Required file not found.")
    except PermissionError:
        print("ERROR: Permission denied while accessing files.")
    except Exception as e:
        print("UNEXPECTED ERROR:", str(e))


if __name__ == "__main__":
    run_pipeline()