# Upload local log files to AWS S3 cloud storage

import boto3
from botocore.exceptions import NoCredentialsError

BUCKET_NAME = "adithi-secure-network-monitor-logs"
REGION = "ap-southeast-2"


def upload_file(file_path, object_name=None):
    try:
        print("\nConnecting to AWS S3...")

        s3 = boto3.client("s3", region_name=REGION)

        if object_name is None:
            object_name = file_path.split("/")[-1].split("\\")[-1]

        print("Uploading file to cloud storage...")

        s3.upload_file(file_path, BUCKET_NAME, object_name)

        print(f"SUCCESS: Uploaded '{object_name}' to bucket.")
        return True

    except FileNotFoundError:
        print("ERROR: Local file not found.")
    except NoCredentialsError:
        print("ERROR: AWS credentials missing.")
    except Exception as e:
        print("ERROR:", str(e))

    return False


if __name__ == "__main__":
    upload_file("logs/sample_log.txt", "logs/sample_log.txt")