import io
import json
import logging
import os
import zipfile
from datetime import datetime

import boto3
import requests
from nested_lookup import nested_lookup

from rapticoressvc.multi_threading_helper import run_parallel

CVE_NVD_DATA_DIRECTORY = "cve_nvd_data"


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


def upload_modification_timestamps(s3_client, bucket_name, timestamps_file_key, modification_timestamps):
    try:
        upload_status = upload_data_to_s3(s3_client, bucket_name, timestamps_file_key, modification_timestamps)
        logging.debug(f"Modification timestamps upload status: {upload_status}")
    except Exception as e:
        logging.exception(e)


def download_modification_timestamps(s3_client, bucket_name, timestamps_file_key):
    modification_timestamps = {}
    try:
        modification_timestamps = download_data_from_s3(s3_client, bucket_name, timestamps_file_key) or {}
    except Exception as e:
        logging.exception(e)
    return modification_timestamps


def download_extract_zip(url):
    response = requests.get(url)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        for zip_info in zip_file.infolist():
            with zip_file.open(zip_info) as the_file:
                file = json.loads(the_file.read())
                return file


def get_nvd_file(year):
    zip_url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
    logging.debug(f"Downloading artifact {zip_url}")
    nvd_data = download_extract_zip(zip_url)
    return nvd_data


def preprocess_nvd_data_for_upload(nvd_file):
    cve_nvd_data_map = {}
    for data in nvd_file["CVE_Items"]:
        cve_id = data["cve"]["CVE_data_meta"]["ID"]
        last_modified_date = data["lastModifiedDate"]
        impact = data["impact"]
        vector_strings = nested_lookup("vectorString", impact)
        cve_vector = vector_strings and vector_strings[0] or None
        base_scores = nested_lookup("baseScore", impact)
        cve_score = base_scores and base_scores[0] or None
        cve_nvd_data_map[cve_id] = {
            'last_modified_date': last_modified_date,
            'cve_vector': cve_vector,
            'cve_score': cve_score,
            'nvd_data': json.dumps(data),
        }
    return cve_nvd_data_map


def upload_nvd_record(cve_nvd_data, args):
    upload_status = False
    try:
        s3_client = args.get("s3_client")
        bucket_name = args.get("bucket_name")
        cve = list(cve_nvd_data.keys())[0]
        data = cve_nvd_data[cve]

        cve_key = f"{CVE_NVD_DATA_DIRECTORY}/{cve}"
        upload_status = upload_data_to_s3(s3_client, bucket_name, cve_key, data)
    except Exception as e:
        logging.exception(e)
    return upload_status


def upload_nvd_data_to_s3(s3_client, bucket_name, cve_nvd_data_map, modification_timestamps, max_workers=32):
    modified_cve_list = []
    modified_time_format = '%Y-%m-%dT%H:%MZ'

    for cve, data in cve_nvd_data_map.items():
        try:
            modified_date_new = data.pop("last_modified_date")
            modified_date_old = modification_timestamps.get(cve)
            if modified_date_new and modified_date_old and datetime.strptime(modified_date_new, modified_time_format) \
                    <= datetime.strptime(modified_date_old, modified_time_format):
                continue
            modification_timestamps[cve] = modified_date_new
            modified_cve_list.append({cve: data})
        except Exception as e:
            logging.exception(e)

    args = dict(s3_client=s3_client, bucket_name=bucket_name)
    progress_description = 'NVD data upload progress'
    upload_statuses = run_parallel(upload_nvd_record, modified_cve_list, args, max_workers, progress_description) or []

    return upload_statuses


def update_nvd_data():
    logging.info('Updating NVD data...')
    bucket_name = os.environ.get("BUCKET_NAME")
    if not bucket_name:
        logging.error(f'S3 bucket name is not configured in environment')
        return
    timestamps_file_key = f"{CVE_NVD_DATA_DIRECTORY}/modification_timestamps"
    nvd_data_years = ["2023", "2022", "2021", "2020", "2019", "2018"]

    s3_client = get_s3_client()
    modification_timestamps = download_modification_timestamps(s3_client, bucket_name, timestamps_file_key)

    for year in nvd_data_years:
        logging.debug(f'Processing NVD data for year: {year}...')
        try:
            nvd_file = get_nvd_file(year)
            cve_nvd_data_map = preprocess_nvd_data_for_upload(nvd_file)

            logging.debug(f'Uploading NVD data for year: {year}...')
            upload_statuses = upload_nvd_data_to_s3(s3_client, bucket_name, cve_nvd_data_map,
                                                    modification_timestamps)
            logging.info(f'Uploaded {len(upload_statuses)} new NVD data records for year: {year}, '
                         f'Succeeded: {upload_statuses.count(True)}, Failed: {upload_statuses.count(False)}')
        except Exception as e:
            logging.exception(e)
        upload_modification_timestamps(s3_client, bucket_name, timestamps_file_key, modification_timestamps)


def download_nvd_record(cve, args):
    logging.debug(f'Getting NVD data for CVE: {cve}')
    s3_client = args.get("s3_client")
    bucket_name = args.get("bucket_name")
    cve_key = f"{CVE_NVD_DATA_DIRECTORY}/{cve}"
    nvd_data = {cve: None}
    try:
        nvd_record = download_data_from_s3(s3_client, bucket_name, cve_key)
        nvd_data = {cve: nvd_record}
    except Exception as e:
        logging.exception(e)
    return nvd_data


def get_nvd_data(cves, max_workers=10):
    cve_nvd_map = {}
    bucket_name = os.environ.get("BUCKET_NAME")
    if not bucket_name:
        logging.error(f'S3 bucket name is not configured in environment')
        return cve_nvd_map
    try:
        cves = cves if type(cves) is list else [cves]
        s3_client = get_s3_client()
        args = dict(s3_client=s3_client, bucket_name=bucket_name)
        progress_description = 'NVD data download progress'
        cve_nvd_list = run_parallel(download_nvd_record, cves, args, max_workers, progress_description)
        cve_nvd_map = dict((key, cve_nvd_dict[key]) for cve_nvd_dict in cve_nvd_list for key in cve_nvd_dict)
    except Exception as e:
        logging.exception(e)
    return cve_nvd_map
