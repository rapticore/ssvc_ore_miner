import os

from moto import mock_s3
from rapticoressvc import nvd_data_helper
from rapticoressvc.nvd_data_helper import download_nvd_record
from rapticoressvc.nvd_data_helper import get_modification_timestamps
from rapticoressvc.nvd_data_helper import get_nvd_data
from rapticoressvc.nvd_data_helper import update_modification_timestamps
from rapticoressvc.nvd_data_helper import update_nvd_data
from rapticoressvc.nvd_data_helper import update_nvd_record
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.svcc_constants import STORAGE_S3
from rapticoressvc.test.testing_helper import mock_data

TIMESTAMPS_FILE_NAME = "modification_timestamps"
MODIFICATION_TIMESTAMPS = {'a': 1, 'b': 2}
CVE = "CVE-999-123"
CVE_DATA = "some cve data"


@mock_s3
def test_modification_timestamps_s3():
    bucket_name, storage_type, region = os.environ.get("BUCKET_NAME"), os.environ.get("STORAGE_TYPE"), \
                                        os.environ.get("REGION")
    if storage_type == "s3":
        get_s3_client().create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
    update_modification_timestamps(bucket_name, TIMESTAMPS_FILE_NAME, MODIFICATION_TIMESTAMPS, storage_type)
    actual = get_modification_timestamps(bucket_name, TIMESTAMPS_FILE_NAME, storage_type)
    expected = MODIFICATION_TIMESTAMPS
    assert actual == expected


@mock_s3
def test_cve_nvd_record_s3():
    bucket_name, storage_type, region = os.environ.get("BUCKET_NAME"), os.environ.get("STORAGE_TYPE"), \
                                        os.environ.get("REGION")
    if storage_type == "s3":
        get_s3_client().create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
    cve_nvd_data = {CVE: CVE_DATA}
    s3_client = storage_type == STORAGE_S3 and get_s3_client()
    args = dict(bucket_name=bucket_name, s3_client=s3_client, storage_type=storage_type)
    update_nvd_record(cve_nvd_data, args)
    actual = download_nvd_record(CVE, args)
    expected = {CVE: CVE_DATA}
    assert actual == expected


@mock_s3
def test_update_nvd_data_s3(mocker):
    bucket_name, storage_type, region = os.environ.get("BUCKET_NAME"), os.environ.get("STORAGE_TYPE"), \
                                        os.environ.get("REGION")
    if storage_type == "s3":
        get_s3_client().create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_data(_url, "nvd_data"))
    cve_list = ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003", "CVE-2023-0012", "CVE-2023-0013", "CVE-2023-0014"]
    expected_timestamps = {
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip': "Fri, 21 Apr 2023 14:02:16 GMT",
        'CVE-2023-0001': '2023-02-18T20:41Z', 'CVE-2023-0002': '2023-02-18T20:45Z',
        'CVE-2023-0003': '2023-02-18T20:45Z', 'CVE-2023-0012': '2023-01-13T17:59Z',
        'CVE-2023-0013': '2023-01-13T18:00Z', 'CVE-2023-0014': '2023-02-09T15:15Z'}

    update_nvd_data()
    actual_timestamps = get_modification_timestamps(bucket_name, TIMESTAMPS_FILE_NAME, storage_type)
    cve_list_nvd_data = get_nvd_data(cve_list)
    assert actual_timestamps == expected_timestamps
    assert all(cve_list_nvd_data.get(cve) for cve in cve_list)
