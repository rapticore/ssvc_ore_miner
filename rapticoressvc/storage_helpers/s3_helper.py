import json
import logging

import boto3


def get_s3_client():
    s3_client = boto3.client("s3")
    return s3_client


def upload_data_to_s3(s3_client, bucket_name, object_key, object_data):
    upload_status = False
    try:
        put_object_response = s3_client.put_object(Body=json.dumps(object_data), Bucket=bucket_name, Key=object_key)
        status_code = put_object_response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        upload_status = status_code and status_code == 200
    except Exception as e:
        logging.exception(e)
    return upload_status


def download_data_from_s3(s3_client, bucket_name, object_key):
    data = None
    try:
        get_object_response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        data_bytes = get_object_response and get_object_response.get("Body").read()
        data = json.loads(data_bytes)
    except s3_client.exceptions.NoSuchKey:
        logging.warning(f"S3 bucket {bucket_name} does not contain object {object_key}")
    except Exception as e:
        logging.exception(e)
    return data
