import json
import os

import pytest
from botocore.client import ClientError
from moto import mock_s3
from rapticoressvc.storage_helpers.s3_helper import download_data_from_s3
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.storage_helpers.s3_helper import upload_data_to_s3

BUCKET_NAME = os.environ.get("BUCKET_NAME")
REGION = os.environ.get("REGION")
OBJECT_KEY = os.environ.get("OBJECT_KEY")
OBJECT_DATA = os.environ.get("OBJECT_DATA")


@mock_s3
def test_upload_data_to_s3_without_bucket_internal():
    s3_client = get_s3_client()
    with pytest.raises(ClientError) as ex:
        s3_client.put_object(Body=json.dumps(OBJECT_DATA), Bucket=BUCKET_NAME, Key=OBJECT_KEY)
    assert ex.value.response["Error"]["Code"] == "NoSuchBucket"
    assert ex.value.response["Error"]["Message"] == "The specified bucket does not exist"


@mock_s3
def test_upload_data_to_s3_without_bucket():
    s3_client = get_s3_client()
    actual = upload_data_to_s3(s3_client, BUCKET_NAME, OBJECT_KEY, OBJECT_DATA)
    expected = False
    assert actual == expected


@mock_s3
def test_upload_data_to_s3_with_bucket():
    s3_client = get_s3_client()
    s3_client.create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    actual = upload_data_to_s3(s3_client, BUCKET_NAME, OBJECT_KEY, OBJECT_DATA)
    expected = True
    assert actual == expected


@mock_s3
def test_download_data_from_s3_incorrect_key_internal():
    test_upload_data_to_s3_with_bucket()
    s3_client = get_s3_client()
    with pytest.raises(ClientError) as ex:
        _ = s3_client.get_object(Bucket=BUCKET_NAME, Key=f'{OBJECT_KEY}--')
    assert ex.value.response["Error"]["Code"] == "NoSuchKey"
    assert ex.value.response["Error"]["Message"] == "The specified key does not exist."


@mock_s3
def test_download_data_from_s3_incorrect_key():
    test_upload_data_to_s3_with_bucket()
    s3_client = get_s3_client()
    actual = download_data_from_s3(s3_client, BUCKET_NAME, f'{OBJECT_KEY}--')
    expected = None
    assert actual == expected


@mock_s3
def test_download_data_from_s3_correct_key():
    test_upload_data_to_s3_with_bucket()
    s3_client = get_s3_client()
    actual = download_data_from_s3(s3_client, BUCKET_NAME, OBJECT_KEY)
    expected = OBJECT_DATA
    assert actual == expected
