# Download log files from AWS S3 bucket

import boto3
from botocore.exceptions import NoCredentialsError

BUCKET_NAME = "adithi-secure-network-monitor-logs"
REGION = "ap-southeast-2"


def download_file(object_name, download_path):
    try:
        print("\nConnecting to AWS S3...")

        s3 = boto3.client("s3", region_name=REGION)

        print("Downloading file from cloud storage...")

        s3.download_file(BUCKET_NAME, object_name, download_path)

        print(f"SUCCESS: Downloaded '{object_name}'")
        return True

    except FileNotFoundError:
        print("ERROR: Local destination path invalid.")
    except NoCredentialsError:
        print("ERROR: AWS credentials missing.")
    except Exception as e:
        print("ERROR:", str(e))

    return False


if __name__ == "__main__":
    download_file("logs/sample_log.txt", "output/downloaded_sample_log.txt")