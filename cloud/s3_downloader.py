# This file downloads log files from AWS S3 bucket.
# It is part of the cloud retrieval module.
# Downloaded logs will later be parsed and checked for threats.

import boto3
from botocore.exceptions import NoCredentialsError

# Name of AWS S3 bucket
BUCKET_NAME = "adithi-secure-network-monitor-logs"

def download_file(object_name, download_path):
    """
    Downloads a file from S3 bucket to local system.

    object_name   = file name inside S3 bucket
    download_path = local destination path
    """

    # Create S3 client using local AWS credentials
    s3 = boto3.client("s3", region_name="ap-southeast-2")

    try:
        s3.download_file(BUCKET_NAME, object_name, download_path)
        print(f"Download Successful: {object_name}")

    except FileNotFoundError:
        print("Local path not found.")

    except NoCredentialsError:
        print("AWS credentials not available.")

    except Exception as e:
        print("Error:", e)


# Test run
if __name__ == "__main__":
    download_file("logs/sample_log.txt", "output/downloaded_sample_log.txt")