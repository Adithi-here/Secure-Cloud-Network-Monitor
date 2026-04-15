# This file uploads local log files to AWS S3 bucket.
# It is part of the cloud storage module.

import boto3
from botocore.exceptions import NoCredentialsError

BUCKET_NAME = "adithi-secure-network-monitor-logs"

def upload_file(file_name, object_name=None):
    if object_name is None:
        object_name = file_name.split("\\")[-1]

    s3 = boto3.client("s3")

    try:
        s3.upload_file(file_name, BUCKET_NAME, object_name)
        print(f"Upload Successful: {object_name}")
    except FileNotFoundError:
        print("File not found.")
    except NoCredentialsError:
        print("AWS credentials not available.")

if __name__ == "__main__":
    upload_file("logs/sample_log.txt")